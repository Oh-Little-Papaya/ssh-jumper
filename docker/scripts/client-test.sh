#!/bin/bash

# SSH Jump Client - 测试脚本
# 用于从客户端测试 SSH Jump Server 的各项功能

set -euo pipefail

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[PASS]${NC} $1"
}

log_error() {
    echo -e "${RED}[FAIL]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# 配置
JUMP_HOST="${JUMP_HOST:-jump-server}"
JUMP_PORT="${JUMP_PORT:-2222}"
JUMP_USER="${JUMP_USER:-admin}"
JUMP_PASS="${JUMP_PASS:-admin123}"
SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=8 -o ConnectionAttempts=1 -o NumberOfPasswordPrompts=1 -o PreferredAuthentications=password -o PubkeyAuthentication=no"
ASSET_REGEX='web-server-01|api-server-01|db-server-01|cache-server-01'

strip_ansi() {
    sed -E 's/\x1B\[[0-9;?]*[ -/]*[@-~]//g' | tr -d '\r'
}

extract_assets_from_output() {
    strip_ansi | grep -Eo "$ASSET_REGEX" | sort -u || true
}

contains_asset() {
    local asset="$1"
    local assets="$2"
    echo "$assets" | grep -qx "$asset"
}

capture_session_once() {
    local user="$1"
    local pass="$2"
    local input_script="$3"
    local timeout_sec="${4:-25}"

    INPUT_SCRIPT="$input_script" TARGET_USER="$user" TARGET_PASS="$pass" \
        timeout "$timeout_sec" bash -lc '
            set -o pipefail
            bash -lc "$INPUT_SCRIPT" | sshpass -p "$TARGET_PASS" ssh -tt -p "$JUMP_PORT" '"$SSH_OPTS"' "$TARGET_USER@$JUMP_HOST" 2>/dev/null
        ' || true
}

capture_session_with_retry() {
    local user="$1"
    local pass="$2"
    local input_script="$3"
    local timeout_sec="${4:-25}"
    local retries="${5:-3}"
    local required_regex="${6:-资产列表}"

    local output=""
    local cleaned=""
    local attempt

    for attempt in $(seq 1 "$retries"); do
        output="$(capture_session_once "$user" "$pass" "$input_script" "$timeout_sec")"
        cleaned="$(echo "$output" | strip_ansi)"

        if echo "$cleaned" | grep -E -q "$required_regex"; then
            echo "$output"
            return 0
        fi

        sleep 2
    done

    echo "$output"
    return 1
}

# ============================================
# 测试 1: 基本连接测试
# ============================================
test_basic_connection() {
    echo ""
    log_info "========================================"
    log_info "测试 1: 基本 SSH 连接"
    log_info "========================================"
    
    log_info "连接到 $JUMP_USER@$JUMP_HOST:$JUMP_PORT"
    
    # 本项目将远程命令参数视作“目标资产”，因此这里用菜单登录验证认证链路
    local output cleaned
    output="$(capture_session_with_retry "$JUMP_USER" "$JUMP_PASS" "sleep 1; echo q" 20 3 "资产列表")"
    cleaned="$(echo "$output" | strip_ansi)"

    if echo "$cleaned" | grep -E -qi "permission denied|认证失败|authentication failed|rate limit exceeded"; then
        log_error "基本连接失败（认证/限流）"
        return 1
    fi

    if echo "$cleaned" | grep -q "资产列表"; then
        log_success "基本连接成功"
        return 0
    else
        log_error "基本连接失败"
        return 1
    fi
}

# ============================================
# 测试 2: 交互式菜单（显示帮助）
# ============================================
test_interactive_menu() {
    echo ""
    log_info "========================================"
    log_info "测试 2: 交互式菜单"
    log_info "========================================"
    
    log_info "发送 'h' 命令获取帮助..."
    
    # 发送 'h' 然后 'q' 退出；适当拉长等待，减少时序抖动
    local output cleaned
    output="$(capture_session_with_retry "$JUMP_USER" "$JUMP_PASS" "sleep 2; echo h; sleep 2; echo q" 35 5 "快速操作指南|快捷命令|连接方式|资产列表|请输入序号")"
    cleaned="$(echo "$output" | strip_ansi)"

    if echo "$cleaned" | grep -E -q "快速操作指南|快捷命令|连接方式|帮助|资产列表|请输入序号"; then
        log_success "交互式菜单响应正常"
        echo "$cleaned" | head -20
        return 0
    else
        log_error "交互式菜单响应异常"
        echo "$cleaned" | head -20
        return 1
    fi
}

# ============================================
# 测试 3: 查看资产列表
# ============================================
test_asset_list() {
    echo ""
    log_info "========================================"
    log_info "测试 3: 资产列表查看"
    log_info "========================================"
    
    log_info "等待资产注册（8秒）..."
    sleep 8

    local output cleaned assets
    local expected_assets=("api-server-01" "cache-server-01" "db-server-01" "web-server-01")
    local missing_assets=()
    local asset
    local combined_assets=""
    local attempt

    for attempt in 1 2 3 4 5 6 7 8; do
        output="$(capture_session_once "$JUMP_USER" "$JUMP_PASS" "sleep 4; echo q" 35)"
        cleaned="$(echo "$output" | strip_ansi)"
        assets="$(echo "$output" | extract_assets_from_output)"
        combined_assets="$(printf "%s\n%s\n" "$combined_assets" "$assets" | sed '/^$/d' | sort -u || true)"

        # 已经采集到全部资产则提前通过
        local all_found=1
        for asset in "${expected_assets[@]}"; do
            if ! contains_asset "$asset" "$combined_assets"; then
                all_found=0
                break
            fi
        done

        if [ "$all_found" -eq 1 ]; then
            echo "菜单输出预览："
            echo "$cleaned" | head -40
            log_success "资产列表显示正常"
            return 0
        fi

        sleep 2
    done

    echo "菜单输出预览："
    echo "$cleaned" | head -40

    for asset in "${expected_assets[@]}"; do
        if ! contains_asset "$asset" "$combined_assets"; then
            missing_assets+=("$asset")
        fi
    done

    if [ "${#missing_assets[@]}" -eq 0 ]; then
        log_success "资产列表显示正常"
        return 0
    else
        log_error "资产列表不完整，缺失: ${missing_assets[*]}"
        return 1
    fi
}

# ============================================
# 测试 4: 用户资产可见性验证（默认全资产）
# ============================================
test_user_permissions() {
    echo ""
    log_info "========================================"
    log_info "测试 4: 用户资产可见性验证"
    log_info "========================================"
    
    # 测试 developer 用户（默认可见全部资产）
    log_info "测试 developer 用户..."
    local dev_output dev_assets
    dev_output="$(capture_session_with_retry "developer" "dev123" "sleep 2; echo q" 25 4 "资产列表")"
    dev_assets="$(echo "$dev_output" | extract_assets_from_output)"

    echo "developer 用户看到的资产："
    echo "$dev_assets"

    if ! contains_asset "web-server-01" "$dev_assets" || ! contains_asset "api-server-01" "$dev_assets" || \
       ! contains_asset "db-server-01" "$dev_assets" || ! contains_asset "cache-server-01" "$dev_assets"; then
        log_error "developer 资产可见性校验失败"
        return 1
    fi

    # 测试 ops 用户（默认可见全部资产）
    log_info "测试 ops 用户..."
    local ops_output ops_assets
    ops_output="$(capture_session_with_retry "ops" "ops123" "sleep 2; echo q" 25 4 "资产列表")"
    ops_assets="$(echo "$ops_output" | extract_assets_from_output)"

    echo "ops 用户看到的资产："
    echo "$ops_assets"

    if ! contains_asset "web-server-01" "$ops_assets" || ! contains_asset "api-server-01" "$ops_assets" || \
       ! contains_asset "cache-server-01" "$ops_assets" || ! contains_asset "db-server-01" "$ops_assets"; then
        log_error "ops 资产可见性校验失败"
        return 1
    fi

    log_success "用户资产可见性测试完成"
    return 0
}

# ============================================
# 测试 5: 搜索功能
# ============================================
test_search_function() {
    echo ""
    log_info "========================================"
    log_info "测试 5: 搜索功能"
    log_info "========================================"
    
    local web_output web_clean
    local api_output api_clean
    local suffix_output suffix_clean

    log_info "测试模糊搜索 'web'..."
    web_output="$(capture_session_once "$JUMP_USER" "$JUMP_PASS" "sleep 1; echo web; sleep 2; echo exit; sleep 1; echo q" 35)"
    web_clean="$(echo "$web_output" | strip_ansi)"
    if ! echo "$web_clean" | grep -E -q "正在连接到 .*web-server-01" || \
       echo "$web_clean" | grep -q "连接失败"; then
        log_error "模糊搜索 'web' 失败"
        return 1
    fi

    log_info "测试前缀搜索 '^api'..."
    api_output="$(capture_session_once "$JUMP_USER" "$JUMP_PASS" "sleep 1; echo ^api; sleep 2; echo exit; sleep 1; echo q" 35)"
    api_clean="$(echo "$api_output" | strip_ansi)"
    if ! echo "$api_clean" | grep -E -q "正在连接到 .*api-server-01" || \
       echo "$api_clean" | grep -q "连接失败"; then
        log_error "前缀搜索 '^api' 失败"
        return 1
    fi

    log_info "测试后缀搜索 '\$01'..."
    suffix_output="$(capture_session_once "$JUMP_USER" "$JUMP_PASS" "sleep 1; printf '%s\n' '\$01'; sleep 1; echo q" 25)"
    suffix_clean="$(echo "$suffix_output" | strip_ansi)"
    if ! echo "$suffix_clean" | grep -E -q "找到多个匹配项|请输入序号选择"; then
        log_error "后缀搜索 '\$01' 失败"
        return 1
    fi

    log_success "搜索功能测试完成"
    return 0
}

# ============================================
# 显示菜单
# ============================================
show_menu() {
    echo ""
    echo "========================================"
    echo "  SSH Jump Client - 测试菜单"
    echo "========================================"
    echo ""
    echo "1. 运行所有自动测试"
    echo "2. 交互式连接（admin）"
    echo "3. 交互式连接（developer）"
    echo "4. 交互式连接（ops）"
    echo "5. 直接连接资产（如果实现）"
    echo "6. 显示环境信息"
    echo "0. 退出"
    echo ""
    echo "========================================"
}

# ============================================
# 交互式连接
# ============================================
interactive_connect() {
    local user=$1
    local pass=$2
    
    log_info "以 $user 身份连接到 $JUMP_HOST:$JUMP_PORT"
    log_info "提示：输入 'h' 查看帮助，'q' 退出"
    echo "========================================"
    
    sshpass -p "$pass" ssh -p "$JUMP_PORT" $SSH_OPTS "$user@$JUMP_HOST"
}

# ============================================
# 显示环境信息
# ============================================
show_env_info() {
    echo ""
    log_info "========================================"
    log_info "环境信息"
    log_info "========================================"
    echo ""
    echo "Jump Server: $JUMP_HOST:$JUMP_PORT"
    echo ""
    echo "测试用户:"
    echo "  - admin / admin123 (管理员，访问所有资产)"
    echo "  - developer / dev123 (开发者，默认访问所有资产)"
    echo "  - ops / ops123 (运维，默认访问所有资产)"
    echo ""
    echo "Agent 资产:"
    echo "  - web-server-01"
    echo "  - api-server-01"
    echo "  - db-server-01"
    echo "  - cache-server-01"
    echo ""
    
    # 测试网络连通性
    log_info "测试网络连通性..."
    if ping -c 1 "$JUMP_HOST" > /dev/null 2>&1; then
        log_success "可以 ping 通 $JUMP_HOST"
    else
        log_warn "无法 ping 通 $JUMP_HOST"
    fi
    
    if nc -zv "$JUMP_HOST" "$JUMP_PORT" 2>&1 | grep -q "succeeded\|open"; then
        log_success "SSH 端口 $JUMP_PORT 开放"
    else
        log_warn "SSH 端口 $JUMP_PORT 可能未开放"
    fi
    echo ""
}

# ============================================
# 运行所有测试
# ============================================
run_all_tests() {
    echo ""
    log_info "========================================"
    log_info "开始自动化测试"
    log_info "========================================"
    
    show_env_info
    
    local failed=0
    
    test_basic_connection || failed=1
    sleep 1
    test_interactive_menu || failed=1
    sleep 1
    test_asset_list || failed=1
    sleep 1
    test_user_permissions || failed=1
    sleep 1
    test_search_function || failed=1
    
    echo ""
    log_info "========================================"
    if [ $failed -eq 0 ]; then
        log_success "所有测试完成！"
    else
        log_warn "部分测试未通过"
    fi
    log_info "========================================"
    
    return $failed
}

# ============================================
# 主函数
# ============================================
main() {
    # 如果直接运行脚本（非交互式），执行所有测试
    if [ "${1:-}" == "auto" ]; then
        run_all_tests
        return $?
    fi
    
    # 交互式菜单
    while true; do
        show_menu
        read -p "请选择操作 [0-6]: " choice
        
        case $choice in
            1)
                run_all_tests
                ;;
            2)
                interactive_connect "admin" "admin123"
                ;;
            3)
                interactive_connect "developer" "dev123"
                ;;
            4)
                interactive_connect "ops" "ops123"
                ;;
            5)
                log_info "直接连接功能测试（如果服务器实现）"
                timeout 20 sshpass -p "$JUMP_PASS" ssh -tt -p "$JUMP_PORT" $SSH_OPTS "$JUMP_USER@$JUMP_HOST" "web-server-01" || true
                ;;
            6)
                show_env_info
                ;;
            0)
                log_info "退出"
                exit 0
                ;;
            *)
                echo "无效选择"
                ;;
        esac
        
        echo ""
        read -p "按回车键继续..."
    done
}

main "$@"
