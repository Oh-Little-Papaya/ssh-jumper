#!/bin/bash

# SSH Jump Server Docker 端到端测试脚本
# 覆盖：镜像构建、服务启动、认证、资产可见性、会话、子节点 CRUD、客户端自动化测试

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

FAILED=0
COMPOSE="docker compose"
KEEP_TEST_ENV="${KEEP_TEST_ENV:-0}"

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_pass() { echo -e "${GREEN}[PASS]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_fail() { echo -e "${RED}[FAIL]${NC} $1"; FAILED=1; }

run_client() {
    $COMPOSE exec -T jump-client bash -lc "$1"
}

run_server() {
    $COMPOSE exec -T jump-server bash -lc "$1"
}

capture_menu_output() {
    local user="$1"
    local pass="$2"
    local wait_before_quit="${3:-3}"
    run_client "set -o pipefail; timeout 30 bash -lc \"(sleep ${wait_before_quit}; echo q) | sshpass -p '${pass}' ssh -tt -o ConnectTimeout=8 -o ConnectionAttempts=1 -o NumberOfPasswordPrompts=1 -o PreferredAuthentications=password -o PubkeyAuthentication=no -o StrictHostKeyChecking=no -p 2222 ${user}@jump-server\" 2>/dev/null || true"
}

strip_ansi() {
    sed -E 's/\x1B\[[0-9;?]*[ -/]*[@-~]//g' | tr -d '\r'
}

extract_assets_from_menu_output() {
    strip_ansi | grep -Eo 'web-server-01|api-server-01|db-server-01|cache-server-01' | sort -u || true
}

menu_has_all_assets() {
    local output="$1"
    local assets
    assets="$(echo "$output" | extract_assets_from_menu_output)"
    echo "$assets" | grep -qx "web-server-01" &&
    echo "$assets" | grep -qx "api-server-01" &&
    echo "$assets" | grep -qx "db-server-01" &&
    echo "$assets" | grep -qx "cache-server-01"
}

wait_for_assets_ready() {
    log_info "等待资产菜单稳定（admin 可见全部 4 台）..."
    local out=""
    local attempt

    for attempt in $(seq 1 10); do
        out="$(capture_menu_output "admin" "admin123" 4)"
        if menu_has_all_assets "$out"; then
            log_pass "资产菜单就绪（attempt=${attempt}）"
            return
        fi
        sleep 2
    done

    log_fail "资产菜单未就绪（未稳定看到全部资产）"
}

require_compose() {
    if ! command -v docker >/dev/null 2>&1; then
        log_fail "Docker 未安装"
        exit 1
    fi
    if ! docker info >/dev/null 2>&1; then
        log_fail "当前用户无 Docker daemon 权限，请加入 docker 组或使用有权限账号执行"
        exit 1
    fi
}

cleanup() {
    log_info "清理旧环境..."
    $COMPOSE down -v --remove-orphans 2>/dev/null || true
    docker rm -f jump-server web-server-01 api-server-01 db-server-01 cache-server-01 jump-client 2>/dev/null || true
    docker rmi -f ssh-jump-server ssh-jump-agent ssh-jump-client 2>/dev/null || true
    log_pass "清理完成"
}

cleanup_on_exit() {
    if [ "$KEEP_TEST_ENV" = "1" ]; then
        log_warn "KEEP_TEST_ENV=1，跳过测试后清理"
        return
    fi
    log_info "测试结束，自动清理环境..."
    cleanup || true
}

build_images() {
    log_info "构建镜像..."
    if [ "${NO_CACHE_BUILD:-0}" = "1" ]; then
        $COMPOSE build --no-cache
    else
        $COMPOSE build
    fi
    log_pass "镜像构建完成"
}

start_services() {
    log_info "启动服务..."
    $COMPOSE up -d
    log_info "等待容器就绪..."
    sleep 20
    $COMPOSE ps

    local running
    running="$($COMPOSE ps --status running -q | wc -l)"
    if [ "$running" -lt 6 ]; then
        log_fail "运行中的容器不足，当前: $running"
        return
    fi
    log_pass "容器启动成功 ($running)"
}

test_folly_mode() {
    log_info "检查 Folly 优化模式..."
    local logs
    logs="$($COMPOSE logs jump-server 2>&1 || true)"
    if echo "$logs" | grep -q "Performance optimization: Folly enabled"; then
        log_pass "Folly 优化已启用"
    else
        if [ "${ALLOW_FOLLY_FALLBACK:-0}" = "1" ]; then
            log_warn "未检测到 Folly 启用日志，当前按 ALLOW_FOLLY_FALLBACK=1 允许 std 回退"
        else
            log_fail "未检测到 Folly 启用日志（默认要求必须启用 Folly）"
        fi
    fi
}

test_agent_registration() {
    log_info "验证 Agent 注册..."
    sleep 8
    local logs
    logs="$($COMPOSE logs jump-server 2>&1 || true)"
    for agent in web-server-01 api-server-01 db-server-01 cache-server-01; do
        if echo "$logs" | grep -q "$agent"; then
            log_pass "Agent 已注册: $agent"
        else
            log_fail "Agent 注册缺失: $agent"
        fi
    done
}

test_authentication() {
    log_info "测试 SSH 认证..."
    local admin_out=""
    for _ in 1 2 3; do
        admin_out="$(capture_menu_output "admin" "admin123" 3)"
        if echo "$admin_out" | grep -q "web-server-01"; then
            break
        fi
        sleep 2
    done
    if echo "$admin_out" | grep -q "web-server-01"; then
        log_pass "admin 认证通过"
    else
        log_fail "admin 认证失败"
    fi

    local dev_out=""
    for _ in 1 2 3; do
        dev_out="$(capture_menu_output "developer" "dev123" 3)"
        if echo "$dev_out" | grep -q "web-server-01"; then
            break
        fi
        sleep 2
    done
    if echo "$dev_out" | grep -q "web-server-01"; then
        log_pass "developer 认证通过"
    else
        log_fail "developer 认证失败"
    fi

    local bad_auth_out
    bad_auth_out="$(run_client "set -o pipefail; timeout 15 sshpass -p 'wrongpass' ssh -tt -o ConnectTimeout=5 -o ConnectionAttempts=1 -o NumberOfPasswordPrompts=1 -o PreferredAuthentications=password -o PubkeyAuthentication=no -o StrictHostKeyChecking=no -p 2222 admin@jump-server < /dev/null 2>&1 || true")"
    if echo "$bad_auth_out" | grep -E -qi "permission denied|认证失败|authentication failed"; then
        log_pass "错误密码被拒绝"
    else
        log_fail "错误密码未明确拒绝（可能存在认证问题）"
    fi
}

test_user_asset_visibility() {
    log_info "测试用户资产可见性（默认全资产）..."

    local dev_out=""
    for _ in 1 2 3; do
        dev_out="$(capture_menu_output "developer" "dev123" 4)"
        if echo "$dev_out" | grep -q "web-server-01"; then
            break
        fi
        sleep 2
    done
    if echo "$dev_out" | grep -q "web-server-01" && echo "$dev_out" | grep -q "api-server-01" &&
       echo "$dev_out" | grep -q "db-server-01" && echo "$dev_out" | grep -q "cache-server-01"; then
        log_pass "developer 资产可见性正确"
    else
        log_fail "developer 资产可见性不符合预期"
    fi

    local ops_out=""
    for _ in 1 2 3; do
        ops_out="$(capture_menu_output "ops" "ops123" 4)"
        if echo "$ops_out" | grep -q "cache-server-01"; then
            break
        fi
        sleep 2
    done
    if echo "$ops_out" | grep -q "web-server-01" && echo "$ops_out" | grep -q "api-server-01" &&
       echo "$ops_out" | grep -q "cache-server-01" && echo "$ops_out" | grep -q "db-server-01"; then
        log_pass "ops 资产可见性正确"
    else
        log_fail "ops 资产可见性不符合预期"
    fi
}

test_nat_reverse_tunnel() {
    log_info "测试 NAT 回拨通道..."

    local before_count after_count nat_flow
    before_count="$($COMPOSE logs jump-server 2>&1 | grep -c 'Reverse tunnel established for agent' || true)"

    nat_flow="$(run_client "set -o pipefail; timeout 35 bash -lc \"(sleep 2; echo exit) | sshpass -p 'admin123' ssh -tt -o ConnectTimeout=8 -o ConnectionAttempts=1 -o StrictHostKeyChecking=no -p 2222 admin@jump-server web-server-01\" 2>/dev/null || true")"

    if echo "$nat_flow" | grep -q "连接失败"; then
        log_fail "NAT 回拨会话建立失败（连接被拒绝）"
        return
    fi

    sleep 2
    after_count="$($COMPOSE logs jump-server 2>&1 | grep -c 'Reverse tunnel established for agent' || true)"

    if [ "$after_count" -gt "$before_count" ]; then
        log_pass "检测到新的 Reverse tunnel established 日志，NAT 回拨通道有效"
    else
        log_fail "未检测到 NAT 回拨建立日志"
    fi
}

test_session_connectivity() {
    log_info "测试会话连接能力（交互 + 直连）..."

    local menu_flow
    menu_flow="$(run_client "set -o pipefail; timeout 35 bash -lc \"(sleep 1; echo 1; sleep 2; echo exit; sleep 1; echo q) | sshpass -p 'admin123' ssh -tt -o ConnectTimeout=8 -o ConnectionAttempts=1 -o StrictHostKeyChecking=no -p 2222 admin@jump-server\" 2>/dev/null || true")"
    if echo "$menu_flow" | grep -q "连接失败"; then
        log_fail "菜单连接流程失败（连接被拒绝）"
    elif echo "$menu_flow" | grep -E -q "正在连接到 .*api-server-01|root@api-server-01"; then
        log_pass "菜单连接流程通过"
    else
        log_fail "菜单连接流程失败"
    fi

    local direct_flow
    direct_flow="$(run_client "set -o pipefail; timeout 35 bash -lc \"(sleep 2; echo exit) | sshpass -p 'admin123' ssh -tt -o ConnectTimeout=8 -o ConnectionAttempts=1 -o StrictHostKeyChecking=no -p 2222 admin@jump-server web-server-01\" 2>/dev/null || true")"
    if echo "$direct_flow" | grep -q "连接失败"; then
        log_fail "直连目标流程失败（连接被拒绝）"
    elif echo "$direct_flow" | grep -E -q "正在连接到 .*web-server-01|root@web-server-01|root@"; then
        log_pass "直连目标流程通过"
    else
        log_fail "直连目标流程失败"
    fi
}

test_child_node_crud() {
    log_info "测试公网管理节点对子节点 CRUD..."
    local nodes_file="/etc/ssh_jump/child_nodes.conf"

    run_server "ssh_jump_node_tool --nodes-file ${nodes_file} --add-node edge-test-01 --name 'Edge Test 01' --public-address 203.0.113.88 --ssh-port 2222 --cluster-port 8888 --description 'docker-e2e' --enabled --meta region=test --meta owner=qa"

    if run_server "ssh_jump_node_tool --nodes-file ${nodes_file} --list-nodes | grep -q edge-test-01"; then
        log_pass "Create/List 通过"
    else
        log_fail "Create/List 失败"
    fi

    run_server "ssh_jump_node_tool --nodes-file ${nodes_file} --update-node edge-test-01 --description 'updated-desc' --disabled --meta owner=platform --remove-meta region"
    local detail
    detail="$(run_server "ssh_jump_node_tool --nodes-file ${nodes_file} --get-node edge-test-01")"
    if echo "$detail" | grep -q "updated-desc" && echo "$detail" | grep -q "disabled" && echo "$detail" | grep -q "owner=platform"; then
        log_pass "Update/Get 通过"
    else
        log_fail "Update/Get 失败"
    fi

    run_server "ssh_jump_node_tool --nodes-file ${nodes_file} --delete-node edge-test-01"
    if run_server "ssh_jump_node_tool --nodes-file ${nodes_file} --list-nodes | grep -q edge-test-01"; then
        log_fail "Delete 失败"
    else
        log_pass "Delete 通过"
    fi
}

test_client_auto_suite() {
    log_info "执行客户端自动化测试脚本..."
    if run_client "/usr/local/bin/client-test.sh auto"; then
        log_pass "client-test.sh auto 通过"
    else
        log_fail "client-test.sh auto 失败"
    fi
}

print_summary() {
    echo ""
    log_info "========================================"
    if [ "$FAILED" -eq 0 ]; then
        log_pass "Docker 端到端测试全部通过"
    else
        log_fail "Docker 端到端测试存在失败项"
    fi
    log_info "========================================"
    echo "查看日志:"
    echo "  docker compose logs -f jump-server"
    echo "  docker compose logs -f web-server-01"
    echo "停止环境:"
    echo "  docker compose down -v"
}

main() {
    require_compose
    trap cleanup_on_exit EXIT
    cleanup
    build_images
    start_services
    test_folly_mode
    test_agent_registration
    wait_for_assets_ready
    test_authentication
    test_user_asset_visibility
    test_nat_reverse_tunnel
    test_session_connectivity
    test_child_node_crud
    test_client_auto_suite
    print_summary
    exit "$FAILED"
}

main "$@"
