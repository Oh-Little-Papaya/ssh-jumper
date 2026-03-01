#!/bin/bash
set -euo pipefail

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

SERVER_USERS="${SERVER_USERS:-admin:admin123,developer:dev123,ops:ops123}"
CLUSTER_SHARED_TOKEN="${CLUSTER_SHARED_TOKEN:-cluster-secret-token}"
SERVER_AGENT_TOKENS="${SERVER_AGENT_TOKENS:-}"
SERVER_PERMISSION_ALLOW_ALL="${SERVER_PERMISSION_ALLOW_ALL:-admin}"
SERVER_PERMISSION_ALLOW_PATTERN="${SERVER_PERMISSION_ALLOW_PATTERN:-developer:web-*,developer:api-*,ops:web-*,ops:db-*,ops:cache-*,ops:api-*}"
SERVER_PERMISSION_DENY_ASSET="${SERVER_PERMISSION_DENY_ASSET:-ops:db-server-01}"
SERVER_PERMISSION_MAX_SESSIONS="${SERVER_PERMISSION_MAX_SESSIONS:-admin:10,developer:3,ops:5}"
SERVER_CHILD_NODES="${SERVER_CHILD_NODES:-public-mgr-01:jump-server:2222:8888:public-mgr-01}"

echo "========================================"
echo "  SSH Jump Server - Docker"
echo "========================================"

# 确保日志目录存在
mkdir -p "$LOG_DIR"

# 设置权限（忽略错误，因为卷挂载可能不允许）
chown -R $(id -u):$(id -g) "$LOG_DIR" 2>/dev/null || true

# 显示配置信息
echo "[INFO] 启动方式: CLI 参数驱动（无配置文件）"
echo "[INFO] 日志目录: $LOG_DIR"
echo "[INFO] SSH 端口: $SSH_PORT"
echo "[INFO] Agent 端口: $AGENT_PORT"
echo ""
echo "[INFO] 用户参数: $SERVER_USERS"
echo "[INFO] 共享 Token: $CLUSTER_SHARED_TOKEN"
echo "[INFO] 额外按节点 Token(可选): ${SERVER_AGENT_TOKENS:-<none>}"
echo "[INFO] 权限参数: allow_all=$SERVER_PERMISSION_ALLOW_ALL allow_pattern=$SERVER_PERMISSION_ALLOW_PATTERN deny_asset=$SERVER_PERMISSION_DENY_ASSET max_sessions=$SERVER_PERMISSION_MAX_SESSIONS"
echo "[INFO] 子节点参数: $SERVER_CHILD_NODES"
echo ""

# 启动服务器
echo "[INFO] 启动 SSH Jump Server..."
echo "========================================"
SERVER_CMD=(
    /opt/ssh_jump/ssh_jump_server
    -p "$SSH_PORT"
    -a "$AGENT_PORT"
    --listen-address "$SSH_LISTEN_ADDRESS"
    --cluster-listen-address "$CLUSTER_LISTEN_ADDRESS"
    --default-target-user "$DEFAULT_TARGET_USER"
    --max-connections-per-minute "$MAX_CONNECTIONS_PER_MINUTE"
    -v
)

append_csv_option() {
    local option="$1"
    local csv="$2"
    [ -z "$csv" ] && return

    local IFS=','
    read -ra entries <<< "$csv"
    for entry in "${entries[@]}"; do
        entry="$(echo "$entry" | xargs)"
        [ -z "$entry" ] && continue
        SERVER_CMD+=("$option" "$entry")
    done
}

append_csv_option "--user" "$SERVER_USERS"
SERVER_CMD+=(--token "$CLUSTER_SHARED_TOKEN")
append_csv_option "--agent-token" "$SERVER_AGENT_TOKENS"
append_csv_option "--permission-allow-all" "$SERVER_PERMISSION_ALLOW_ALL"
append_csv_option "--permission-allow-pattern" "$SERVER_PERMISSION_ALLOW_PATTERN"
append_csv_option "--permission-deny-asset" "$SERVER_PERMISSION_DENY_ASSET"
append_csv_option "--permission-max-sessions" "$SERVER_PERMISSION_MAX_SESSIONS"
append_csv_option "--child-node" "$SERVER_CHILD_NODES"

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
