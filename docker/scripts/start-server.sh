#!/bin/bash
set -euo pipefail

LOG_DIR="/var/log/ssh_jump"
SSH_PORT="${SSH_PORT:-2222}"
AGENT_PORT="${AGENT_PORT:-8888}"
SSH_LISTEN_ADDRESS="${SSH_LISTEN_ADDRESS:-0.0.0.0}"
CLUSTER_LISTEN_ADDRESS="${CLUSTER_LISTEN_ADDRESS:-0.0.0.0}"
DEFAULT_TARGET_USER="${DEFAULT_TARGET_USER:-root}"
DEFAULT_TARGET_PASSWORD="${DEFAULT_TARGET_PASSWORD:-}"
DEFAULT_TARGET_PRIVATE_KEY="${DEFAULT_TARGET_PRIVATE_KEY:-}"
DEFAULT_TARGET_KEY_PASSWORD="${DEFAULT_TARGET_KEY_PASSWORD:-}"
TARGET_KNOWN_HOSTS_FILE="${TARGET_KNOWN_HOSTS_FILE:-/var/lib/ssh_jump/target_known_hosts}"
TARGET_HOST_KEY_TRUST_ON_FIRST_USE="${TARGET_HOST_KEY_TRUST_ON_FIRST_USE:-true}"
MAX_CONNECTIONS_PER_MINUTE="${MAX_CONNECTIONS_PER_MINUTE:-120}"

SERVER_USERS="${SERVER_USERS:-}"
CLUSTER_SHARED_TOKEN="${CLUSTER_SHARED_TOKEN:-}"
ADMIN_TOKEN="${ADMIN_TOKEN:-}"
SERVER_CHILD_NODES="${SERVER_CHILD_NODES:-public-mgr-01:jump-server:2222:8888:public-mgr-01}"

require_env() {
    local name="$1"
    local value="${!name:-}"
    if [ -z "$value" ]; then
        echo "[ERROR] $name is required" >&2
        exit 1
    fi
}

require_env SERVER_USERS
require_env CLUSTER_SHARED_TOKEN
require_env ADMIN_TOKEN

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
echo "[INFO] 用户参数: 已从 SERVER_USERS 加载"
echo "[INFO] 共享 Token: 已从 CLUSTER_SHARED_TOKEN 加载"
echo "[INFO] 管理 Token: 已从 ADMIN_TOKEN 加载"
echo "[INFO] 权限策略: 所有用户默认可访问全部资产"
echo "[INFO] 子节点参数: $SERVER_CHILD_NODES"
echo "[INFO] 目标 known_hosts: $TARGET_KNOWN_HOSTS_FILE"
echo "[INFO] 目标主机密钥 TOFU: $TARGET_HOST_KEY_TRUST_ON_FIRST_USE"
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
    --target-known-hosts-file "$TARGET_KNOWN_HOSTS_FILE"
    --target-host-key-trust-on-first-use "$TARGET_HOST_KEY_TRUST_ON_FIRST_USE"
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
SERVER_CMD+=(--admin-token "$ADMIN_TOKEN")
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
