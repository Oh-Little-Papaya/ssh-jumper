#!/bin/bash

# SSH Jump Server 手动测试脚本
# 用于交互式测试各项功能

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

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
    echo -e "${GREEN}[OK]${NC} $1"
}

# 菜单显示
show_menu() {
    clear
    echo "========================================"
    echo "  SSH Jump Server - 手动测试菜单"
    echo "========================================"
    echo ""
    echo "1. 启动 Docker 环境"
    echo "2. 停止 Docker 环境"
    echo "3. 查看服务状态"
    echo "4. 查看服务器日志"
    echo "5. 测试交互式连接 (admin)"
    echo "6. 测试交互式连接 (developer)"
    echo "7. 测试交互式连接 (ops)"
    echo "8. 进入测试容器"
    echo "9. 运行自动化测试"
    echo "0. 退出"
    echo ""
    echo "========================================"
}

# 启动环境
start_env() {
    log_info "启动 Docker 环境..."
    docker-compose up -d --build
    log_info "等待服务就绪 (10秒)..."
    sleep 10
    log_success "环境已启动"
    echo ""
    docker-compose ps
    read -p "按回车键继续..."
}

# 停止环境
stop_env() {
    log_info "停止 Docker 环境..."
    docker-compose down -v
    log_success "环境已停止"
    read -p "按回车键继续..."
}

# 查看状态
show_status() {
    log_info "服务状态:"
    docker-compose ps
    echo ""
    log_info "网络信息:"
    docker network inspect ssh-jumper_jump-network 2>/dev/null | grep -A5 '"Containers":' || echo "网络未创建"
    read -p "按回车键继续..."
}

# 查看日志
show_logs() {
    log_info "服务器日志 (按 Ctrl+C 退出):"
    docker-compose logs -f --tail=50 jump-server
}

# 测试交互式连接
test_connect() {
    local user=$1
    local password=$2
    
    log_info "连接到 SSH Jump Server ($user)..."
    echo "密码: $password"
    echo "提示: 可以输入 h 查看帮助，q 退出"
    echo "========================================"
    
    # 使用 sshpass 自动输入密码，或者让用户手动输入
    if command -v sshpass &> /dev/null; then
        sshpass -p "$password" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 2222 "$user@localhost"
    else
        echo "请手动输入密码: $password"
        ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 2222 "$user@localhost"
    fi
}

# 进入测试容器
enter_container() {
    log_info "进入测试容器..."
    docker-compose exec test-client sh
}

# 运行自动化测试
run_auto_test() {
    log_info "运行自动化测试..."
    bash "$SCRIPT_DIR/test.sh"
    read -p "按回车键继续..."
}

# 主循环
main() {
    while true; do
        show_menu
        read -p "请选择操作 [0-9]: " choice
        
        case $choice in
            1)
                start_env
                ;;
            2)
                stop_env
                ;;
            3)
                show_status
                ;;
            4)
                show_logs
                ;;
            5)
                test_connect "admin" "admin123"
                ;;
            6)
                test_connect "developer" "dev123"
                ;;
            7)
                test_connect "ops" "ops123"
                ;;
            8)
                enter_container
                ;;
            9)
                run_auto_test
                ;;
            0)
                log_info "退出"
                exit 0
                ;;
            *)
                echo "无效选择"
                sleep 1
                ;;
        esac
    done
}

main
