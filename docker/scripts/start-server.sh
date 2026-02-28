#!/bin/bash
set -e

CONFIG_DIR="/etc/ssh_jump"
LOG_DIR="/var/log/ssh_jump"
SSH_PORT="${SSH_PORT:-2222}"
AGENT_PORT="${AGENT_PORT:-8888}"
SSH_LISTEN_ADDRESS="${SSH_LISTEN_ADDRESS:-0.0.0.0}"
CLUSTER_LISTEN_ADDRESS="${CLUSTER_LISTEN_ADDRESS:-0.0.0.0}"
DEFAULT_TARGET_USER="${DEFAULT_TARGET_USER:-root}"
DEFAULT_TARGET_PASSWORD="${DEFAULT_TARGET_PASSWORD:-agent123}"
DEFAULT_TARGET_PRIVATE_KEY="${DEFAULT_TARGET_PRIVATE_KEY:-}"
DEFAULT_TARGET_KEY_PASSWORD="${DEFAULT_TARGET_KEY_PASSWORD:-}"
MAX_CONNECTIONS_PER_MINUTE="${MAX_CONNECTIONS_PER_MINUTE:-120}"

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
echo "[INFO] 启动方式: CLI 参数驱动（无配置文件）"
echo "[INFO] 日志目录: $LOG_DIR"
echo "[INFO] SSH 端口: $SSH_PORT"
echo "[INFO] Agent 端口: $AGENT_PORT"
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
SERVER_CMD=(
    /opt/ssh_jump/ssh_jump_server
    -p "$SSH_PORT"
    -a "$AGENT_PORT"
    --listen-address "$SSH_LISTEN_ADDRESS"
    --cluster-listen-address "$CLUSTER_LISTEN_ADDRESS"
    --host-key-path "$CONFIG_DIR/host_key"
    --users-file "$CONFIG_DIR/users.conf"
    --agent-token-file "$CONFIG_DIR/agent_tokens.conf"
    --permissions-file "$CONFIG_DIR/user_permissions.conf"
    --child-nodes-file "$CONFIG_DIR/child_nodes.conf"
    --default-target-user "$DEFAULT_TARGET_USER"
    --max-connections-per-minute "$MAX_CONNECTIONS_PER_MINUTE"
    -v
)

if [ -n "$DEFAULT_TARGET_PASSWORD" ]; then
    SERVER_CMD+=(--default-target-password "$DEFAULT_TARGET_PASSWORD")
fi

if [ -n "$DEFAULT_TARGET_PRIVATE_KEY" ]; then
    SERVER_CMD+=(--default-target-private-key "$DEFAULT_TARGET_PRIVATE_KEY")
fi

if [ -n "$DEFAULT_TARGET_KEY_PASSWORD" ]; then
    SERVER_CMD+=(--default-target-key-password "$DEFAULT_TARGET_KEY_PASSWORD")
fi

exec "${SERVER_CMD[@]}"
