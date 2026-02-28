# SSH Jump Server 部署指南

## 系统要求

### 服务器要求

- **操作系统**: Linux (推荐 Ubuntu 20.04+/CentOS 8+)
- **CPU**: 2 核以上
- **内存**: 4GB 以上
- **磁盘**: 20GB 以上（根据会话录制需求调整）
- **网络**: 至少两个可用端口（SSH 和 Agent）

### Agent 要求

- **操作系统**: Linux (kernel >= 4.0)
- **内存**: 128MB 以上
- **网络**: 能够访问服务器 Agent 端口

## 生产环境部署

### 1. 系统准备

```bash
# 更新系统
sudo apt-get update && sudo apt-get upgrade -y

# 安装依赖
sudo apt-get install -y cmake build-essential libssh-dev libssl-dev pkg-config

# 创建运行用户
sudo useradd -r -s /bin/false sshjump

# 创建目录
sudo mkdir -p /etc/ssh_jump
sudo mkdir -p /var/log/ssh_jump
sudo mkdir -p /var/log/ssh_jump/sessions
sudo mkdir -p /opt/ssh_jump

# 设置权限
sudo chown -R sshjump:sshjump /var/log/ssh_jump
sudo chmod 750 /var/log/ssh_jump
sudo chmod 750 /var/log/ssh_jump/sessions
```

### 2. 编译安装

```bash
# 下载源码
git clone <repository-url> /tmp/ssh_jump_build
cd /tmp/ssh_jump_build

# 编译
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)

# 安装
sudo cp ssh_jump_server /opt/ssh_jump/
sudo cp ssh_jump_agent /opt/ssh_jump/
sudo chmod +x /opt/ssh_jump/*

# 创建符号链接
sudo ln -sf /opt/ssh_jump/ssh_jump_server /usr/local/bin/
sudo ln -sf /opt/ssh_jump/ssh_jump_agent /usr/local/bin/

# 清理
rm -rf /tmp/ssh_jump_build
```

### 3. 生成密钥

```bash
# 生成服务器主机密钥
sudo ssh-keygen -t rsa -b 4096 -f /etc/ssh_jump/host_key -N "" -C "ssh_jump_server"
sudo ssh-keygen -t ecdsa -b 521 -f /etc/ssh_jump/host_key_ecdsa -N "" -C "ssh_jump_server"
sudo ssh-keygen -t ed25519 -f /etc/ssh_jump/host_key_ed25519 -N "" -C "ssh_jump_server"

# 设置权限
sudo chown -R sshjump:sshjump /etc/ssh_jump
sudo chmod 600 /etc/ssh_jump/host_key*
sudo chmod 644 /etc/ssh_jump/host_key*.pub
```

### 4. 配置文件

创建主配置文件 `/etc/ssh_jump/config.conf`：

```ini
[ssh]
listen_address = 0.0.0.0
port = 2222
host_key_path = /etc/ssh_jump/host_key
auth_methods = publickey
permit_root_login = false
max_auth_tries = 3
idle_timeout = 300

[cluster]
listen_address = 0.0.0.0
port = 8888
agent_token_file = /etc/ssh_jump/agent_tokens.conf
heartbeat_interval = 30
heartbeat_timeout = 90

[assets]
permissions_file = /etc/ssh_jump/user_permissions.conf
refresh_interval = 30

[logging]
level = info
log_file = /var/log/ssh_jump/server.log
audit_log = /var/log/ssh_jump/audit.log
session_recording = true
session_path = /var/log/ssh_jump/sessions/

[security]
command_audit = true
allow_port_forwarding = false
allow_sftp = false
```

创建 Agent Token 文件 `/etc/ssh_jump/agent_tokens.conf`：

```bash
# 生成随机 token
generate_token() {
    openssl rand -hex 32
}

# 为每个 Agent 创建 token
cat << EOF | sudo tee /etc/ssh_jump/agent_tokens.conf
# Agent Token Configuration
# Generated: $(date -Iseconds)

web-server-01 = $(generate_token)
web-server-02 = $(generate_token)
db-server-01 = $(generate_token)
db-server-02 = $(generate_token)
redis-01 = $(generate_token)
redis-02 = $(generate_token)
EOF

sudo chmod 600 /etc/ssh_jump/agent_tokens.conf
sudo chown sshjump:sshjump /etc/ssh_jump/agent_tokens.conf
```

创建用户权限文件 `/etc/ssh_jump/user_permissions.conf`：

```ini
[user:admin]
allow_all = true
max_sessions = 20

[user:devops]
allowed_patterns = web-*,api-*,lb-*
max_sessions = 10
```

### 5. Systemd 服务配置

创建服务文件 `/etc/systemd/system/ssh-jump-server.service`：

```ini
[Unit]
Description=SSH Jump Server
After=network.target

[Service]
Type=simple
User=sshjump
Group=sshjump
ExecStart=/opt/ssh_jump/ssh_jump_server -c /etc/ssh_jump/config.conf
ExecReload=/bin/kill -HUP $MAINPID
KillMode=process
Restart=on-failure
RestartSec=5s

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/ssh_jump

# Resource limits
LimitNOFILE=65535
LimitNPROC=4096

[Install]
WantedBy=multi-user.target
```

创建 Agent 服务模板 `/etc/systemd/system/ssh-jump-agent@.service`：

```ini
[Unit]
Description=SSH Jump Agent for %i
After=network.target

[Service]
Type=simple
ExecStart=/opt/ssh_jump/ssh_jump_agent -c /etc/ssh_jump/agent-%i.conf
Restart=on-failure
RestartSec=10s

[Install]
WantedBy=multi-user.target
```

启动服务：

```bash
sudo systemctl daemon-reload
sudo systemctl enable ssh-jump-server
sudo systemctl start ssh-jump-server

# 查看状态
sudo systemctl status ssh-jump-server
sudo journalctl -u ssh-jump-server -f
```

### 6. 防火墙配置

```bash
# 使用 ufw (Ubuntu)
sudo ufw allow 2222/tcp comment 'SSH Jump Server'
sudo ufw allow from 10.0.0.0/8 to any port 8888 comment 'SSH Jump Agents'

# 或使用 iptables
sudo iptables -A INPUT -p tcp --dport 2222 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 8888 -s 10.0.0.0/8 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 8888 -j DROP

# 保存规则
sudo netfilter-persistent save
```

## Agent 部署

### 自动部署脚本

创建部署脚本 `/opt/ssh_jump/deploy-agent.sh`：

```bash
#!/bin/bash
set -e

# 配置
SERVER_ADDR="${1:-jump.example.com}"
SERVER_PORT="${2:-8888}"
AGENT_ID="${3:-$(hostname -s)}"
TOKEN="${4}"

if [ -z "$TOKEN" ]; then
    echo "Usage: $0 <server_addr> <server_port> <agent_id> <token>"
    exit 1
fi

# 安装
mkdir -p /opt/ssh_jump
cp ssh_jump_agent /opt/ssh_jump/
chmod +x /opt/ssh_jump/ssh_jump_agent

# 创建配置
mkdir -p /etc/ssh_jump
cat > /etc/ssh_jump/agent.conf << EOF
[server]
address = ${SERVER_ADDR}
port = ${SERVER_PORT}

[agent]
id = ${AGENT_ID}
token = ${TOKEN}
hostname = $(hostname -f)

[service]
expose = ssh:ssh:22
EOF

# 创建 systemd 服务
cat > /etc/systemd/system/ssh-jump-agent.service << 'EOF'
[Unit]
Description=SSH Jump Agent
After=network.target

[Service]
Type=simple
ExecStart=/opt/ssh_jump/ssh_jump_agent -c /etc/ssh_jump/agent.conf
Restart=on-failure
RestartSec=10s

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable ssh-jump-agent
systemctl start ssh-jump-agent

echo "Agent deployed successfully!"
```

运行部署：

```bash
chmod +x deploy-agent.sh
./deploy-agent.sh jump.example.com 8888 web-server-01 "your-token-here"
```

## 高可用部署

### 负载均衡架构

```
                    ┌─────────────────┐
                    │  Load Balancer  │
                    │   (HAProxy)     │
                    └────────┬────────┘
                             │
            ┌────────────────┼────────────────┐
            │                │                │
     ┌──────▼──────┐  ┌──────▼──────┐  ┌──────▼──────┐
     │  Jump 01    │  │  Jump 02    │  │  Jump 03    │
     │  Master     │  │  Slave      │  │  Slave      │
     └──────┬──────┘  └──────┬──────┘  └──────┬──────┘
            │                │                │
            └────────────────┼────────────────┘
                             │
                    ┌────────▼────────┐
                    │   Shared DB     │
                    │  (Redis/etcd)   │
                    └─────────────────┘
```

### HAProxy 配置示例

```haproxy
global
    maxconn 4096

defaults
    mode tcp
    timeout connect 5s
    timeout client 30s
    timeout server 30s

frontend ssh_frontend
    bind *:2222
    default_backend ssh_backend

backend ssh_backend
    balance roundrobin
    option tcp-check
    server jump01 10.0.1.10:2222 check
    server jump02 10.0.1.11:2222 check
    server jump03 10.0.1.12:2222 check

frontend agent_frontend
    bind *:8888
    default_backend agent_backend

backend agent_backend
    balance roundrobin
    option tcp-check
    server jump01 10.0.1.10:8888 check
    server jump02 10.0.1.11:8888 check
    server jump03 10.0.1.12:8888 check
```

## 监控与告警

### Prometheus 指标

服务器支持 Prometheus 格式的监控指标（需添加 exporter）：

```
# 连接数
ssh_jump_active_connections 42
ssh_jump_total_connections 1234

# Agent 状态
ssh_jump_online_agents 15
ssh_jump_offline_agents 2

# 认证统计
ssh_jump_auth_success_total 1000
ssh_jump_auth_fail_total 10
```

### 日志轮转

创建 `/etc/logrotate.d/ssh-jump-server`：

```
/var/log/ssh_jump/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0640 sshjump sshjump
    sharedscripts
    postrotate
        systemctl reload ssh-jump-server
    endscript
}

/var/log/ssh_jump/sessions/*.rec {
    daily
    rotate 90
    compress
    delaycompress
    missingok
    create 0600 sshjump sshjump
}
```

## 备份与恢复

### 需要备份的文件

```bash
# 配置文件
/etc/ssh_jump/

# 主机密钥
/etc/ssh_jump/host_key*

# 审计日志
/var/log/ssh_jump/audit.log

# 会话录制
/var/log/ssh_jump/sessions/
```

### 备份脚本

```bash
#!/bin/bash
BACKUP_DIR="/backup/ssh_jump/$(date +%Y%m%d)"
mkdir -p "$BACKUP_DIR"

# 备份配置
tar czf "$BACKUP_DIR/config.tar.gz" /etc/ssh_jump/

# 备份密钥
tar czf "$BACKUP_DIR/keys.tar.gz" /etc/ssh_jump/host_key*

# 备份日志
tar czf "$BACKUP_DIR/logs.tar.gz" /var/log/ssh_jump/

# 清理旧备份 (保留 30 天)
find /backup/ssh_jump -type d -mtime +30 -exec rm -rf {} \;
```

## 故障排查

### 常见问题

1. **无法绑定端口**
   ```bash
   # 检查端口占用
   sudo ss -tlnp | grep -E '2222|8888'
   
   # 检查 SELinux
   sudo setenforce 0  # 临时关闭测试
   ```

2. **Agent 无法连接**
   ```bash
   # 测试连通性
   telnet jump-server 8888
   
   # 检查防火墙
   sudo iptables -L -n | grep 8888
   ```

3. **认证失败**
   ```bash
   # 检查日志
   sudo tail -f /var/log/ssh_jump/server.log
   
   # 验证 token
   sudo cat /etc/ssh_jump/agent_tokens.conf
   ```

### 调试模式

```bash
# 前台运行，详细日志
sudo -u sshjump /opt/ssh_jump/ssh_jump_server -c /etc/ssh_jump/config.conf -v

# 使用 strace
sudo strace -f -e trace=network /opt/ssh_jump/ssh_jump_server -v
```
