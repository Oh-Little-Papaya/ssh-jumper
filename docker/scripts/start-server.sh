#!/bin/bash
set -e

CONFIG_DIR="/etc/ssh_jump"
LOG_DIR="/var/log/ssh_jump"

echo "========================================"
echo "  SSH Jump Server - Docker"
echo "========================================"

# 确保日志目录存在
mkdir -p "$LOG_DIR"

# 生成主机密钥（如果不存在）
if [ ! -f "$CONFIG_DIR/host_key" ]; then
    echo "[INFO] 生成 RSA 主机密钥..."
    ssh-keygen -t rsa -b 4096 -f "$CONFIG_DIR/host_key" -N "" -C "ssh_jump_server"
fi

if [ ! -f "$CONFIG_DIR/host_key_ecdsa" ]; then
    echo "[INFO] 生成 ECDSA 主机密钥..."
    ssh-keygen -t ecdsa -b 521 -f "$CONFIG_DIR/host_key_ecdsa" -N "" -C "ssh_jump_server"
fi

# 设置权限（忽略错误，因为卷挂载可能不允许）
chmod 600 "$CONFIG_DIR/host_key" 2>/dev/null || true
chmod 644 "$CONFIG_DIR/host_key.pub" 2>/dev/null || true
chown -R $(id -u):$(id -g) "$LOG_DIR" 2>/dev/null || true

# 显示配置信息
echo "[INFO] 配置文件: $CONFIG_DIR/config.conf"
echo "[INFO] 日志目录: $LOG_DIR"
echo "[INFO] SSH 端口: 2222"
echo "[INFO] Agent 端口: 8888"
echo ""
echo "[INFO] 用户列表:"
grep -v "^#" "$CONFIG_DIR/users.conf" | grep "=" | cut -d'=' -f1 | sed 's/^/  - /'
echo ""
echo "[INFO] Agent Token 列表:"
grep -v "^#" "$CONFIG_DIR/agent_tokens.conf" | grep "=" | cut -d'=' -f1 | sed 's/^/  - /'
echo ""

if [ -f "$CONFIG_DIR/child_nodes.conf" ]; then
    echo "[INFO] 子节点列表:"
    grep -v "^#" "$CONFIG_DIR/child_nodes.conf" | grep "^\[node:" | sed 's/^\[node:/  - /' | sed 's/\]$//'
    echo ""
fi

# 启动服务器
echo "[INFO] 启动 SSH Jump Server..."
echo "========================================"
exec /opt/ssh_jump/ssh_jump_server -c "$CONFIG_DIR/config.conf" -v
