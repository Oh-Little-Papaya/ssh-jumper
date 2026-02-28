#!/bin/bash
set -e

# 从环境变量获取配置
AGENT_ID="${AGENT_ID:-$(hostname)}"
AGENT_TOKEN="${AGENT_TOKEN:-default-token}"
SERVER_HOST="${SERVER_HOST:-jump-server}"
SERVER_PORT="${SERVER_PORT:-8888}"
AGENT_HOSTNAME="${AGENT_HOSTNAME:-$AGENT_ID}"
SSH_PORT="${SSH_PORT:-22}"

echo "========================================"
echo "  SSH Jump Agent - Docker"
echo "========================================"
echo "[INFO] Agent ID: $AGENT_ID"
echo "[INFO] Hostname: $AGENT_HOSTNAME"
echo "[INFO] Server: $SERVER_HOST:$SERVER_PORT"
echo "[INFO] SSH Port: $SSH_PORT"
echo "========================================"

# 启动本地的 SSH 服务（模拟目标服务器）
echo "[INFO] 启动本地 SSH 服务..."
/usr/sbin/sshd

# 等待 SSH 服务就绪
sleep 1

# 检查 SSH 服务
if pgrep -x "sshd" > /dev/null; then
    echo "[INFO] SSH 服务已启动 (端口 $SSH_PORT)"
else
    echo "[ERROR] SSH 服务启动失败"
    exit 1
fi

# 创建 Agent 配置文件
mkdir -p /etc/ssh_jump
cat > /etc/ssh_jump/agent.conf << EOF
[server]
address = $SERVER_HOST
port = $SERVER_PORT

[agent]
id = $AGENT_ID
token = $AGENT_TOKEN
hostname = $AGENT_HOSTNAME

[service]
expose = ssh:ssh:$SSH_PORT
EOF

echo "[INFO] 配置文件已创建"
echo "[INFO] 等待服务器就绪..."

# 等待服务器就绪（带重试）
for i in {1..30}; do
    if nc -z "$SERVER_HOST" "$SERVER_PORT" 2>/dev/null; then
        echo "[INFO] 服务器已就绪"
        break
    fi
    if [ $i -eq 30 ]; then
        echo "[WARN] 等待服务器超时，继续尝试..."
    fi
    sleep 1
done

echo "[INFO] 启动 SSH Jump Agent..."
echo "========================================"

# 启动 Agent
exec /opt/ssh_jump/ssh_jump_agent -c /etc/ssh_jump/agent.conf -v
