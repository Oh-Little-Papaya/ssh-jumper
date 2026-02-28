# SSH Jump Server 配置指南

> 注意：当前版本已切换为纯命令行参数驱动，不再支持 `-c/--config`。
> 下文的 `[ssh]`、`[cluster]` 等仅代表参数逻辑分组，不代表可直接加载的配置文件。

## 参数分组

- `[ssh]` - SSH 服务器配置
- `[cluster]` - Agent 集群管理配置
- `[assets]` - 资产管理配置
- `[logging]` - 日志配置
- `[security]` - 安全配置
- `[management]` - 公网管理节点配置

## 详细配置说明

### [ssh] SSH 服务器配置

```ini
[ssh]
listen_address = 0.0.0.0
port = 2222
host_key_path = /etc/ssh_jump/host_key
auth_methods = publickey,password
permit_root_login = false
max_auth_tries = 3
idle_timeout = 300
```

| 配置项 | 类型 | 默认值 | 说明 |
|--------|------|--------|------|
| `listen_address` | string | 0.0.0.0 | SSH 服务监听地址，支持 IPv4 和 IPv6 |
| `port` | int | 2222 | SSH 服务监听端口 |
| `host_key_path` | string | /etc/ssh_jump/host_key | 主机私钥路径，用于 SSH 握手 |
| `auth_methods` | string | publickey | 认证方式，逗号分隔：publickey, password |
| `permit_root_login` | bool | false | 是否允许 root 用户登录 |
| `max_auth_tries` | int | 3 | 最大认证尝试次数 |
| `idle_timeout` | int | 300 | 空闲会话超时时间（秒）|

### [cluster] 集群管理配置

```ini
[cluster]
listen_address = 0.0.0.0
port = 8888
agent_token_file = /etc/ssh_jump/agent_tokens.conf
heartbeat_interval = 30
heartbeat_timeout = 90
reverse_tunnel_port_start = 38000
reverse_tunnel_port_end = 38199
reverse_tunnel_retries = 3
reverse_tunnel_accept_timeout_ms = 7000
```

| 配置项 | 类型 | 默认值 | 说明 |
|--------|------|--------|------|
| `listen_address` | string | 0.0.0.0 | Agent 连接监听地址 |
| `port` | int | 8888 | Agent 连接端口 |
| `agent_token_file` | string | /etc/ssh_jump/agent_tokens.conf | Agent Token 配置文件路径 |
| `heartbeat_interval` | int | 30 | 期望的心跳间隔（秒）|
| `heartbeat_timeout` | int | 90 | 心跳超时时间（秒），超时后标记为离线 |
| `reverse_tunnel_port_start` | int | 38000 | Agent 回拨端口池起始端口（需在防火墙放行） |
| `reverse_tunnel_port_end` | int | 38199 | Agent 回拨端口池结束端口 |
| `reverse_tunnel_retries` | int | 3 | 单次转发请求的回拨重试次数 |
| `reverse_tunnel_accept_timeout_ms` | int | 7000 | 每次回拨等待超时（毫秒） |

### [assets] 资产管理配置

```ini
[assets]
permissions_file = /etc/ssh_jump/user_permissions.conf
refresh_interval = 30
```

| 配置项 | 类型 | 默认值 | 说明 |
|--------|------|--------|------|
| `permissions_file` | string | /etc/ssh_jump/user_permissions.conf | 用户权限配置文件路径 |
| `refresh_interval` | int | 30 | 资产列表刷新间隔（秒）|

### [logging] 日志配置

```ini
[logging]
level = info
log_file = /var/log/ssh_jump/server.log
audit_log = /var/log/ssh_jump/audit.log
session_recording = true
session_path = /var/log/ssh_jump/sessions/
```

| 配置项 | 类型 | 默认值 | 说明 |
|--------|------|--------|------|
| `level` | string | info | 日志级别：debug, info, warn, error, fatal |
| `log_file` | string | /var/log/ssh_jump/server.log | 服务器运行日志文件路径 |
| `audit_log` | string | /var/log/ssh_jump/audit.log | 审计日志文件路径 |
| `session_recording` | bool | true | 是否启用会话录制 |
| `session_path` | string | /var/log/ssh_jump/sessions/ | 会话录制文件存储目录 |

### [security] 安全配置

```ini
[security]
command_audit = true
allow_port_forwarding = false
allow_sftp = false
max_connections_per_minute = 10
users_file = /etc/ssh_jump/users.conf
```

| 配置项 | 类型 | 默认值 | 说明 |
|--------|------|--------|------|
| `command_audit` | bool | true | 是否审计用户执行的命令 |
| `allow_port_forwarding` | bool | false | 是否允许 SSH 端口转发 |
| `allow_sftp` | bool | false | 是否允许 SFTP 连接 |
| `max_connections_per_minute` | int | 10 | 每个来源 IP 每分钟允许的新连接数 |
| `users_file` | string | /etc/ssh_jump/users.conf | 用户认证配置文件路径 |

### [management] 公网管理节点配置

```ini
[management]
child_nodes_file = /etc/ssh_jump/child_nodes.conf
```

| 配置项 | 类型 | 默认值 | 说明 |
|--------|------|--------|------|
| `child_nodes_file` | string | /etc/ssh_jump/child_nodes.conf | 子节点配置文件路径（用于管理下级公网节点） |

## 用户认证配置

用户认证配置文件用于存储用户名和密码哈希（SHA256）：

```ini
# /etc/ssh_jump/users.conf

# 管理员
admin = 240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9

# 开发者
developer = ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f
```

**生成密码哈希：**

```bash
# 生成 SHA256 哈希
echo -n 'your_password' | sha256sum

# 或使用 openssl
openssl dgst -sha256 <<< 'your_password'
```

**配置项说明：**

| 配置项 | 类型 | 说明 |
|--------|------|------|
| `username` | string | 用户名 |
| `password_hash` | string | SHA256 哈希值（64位十六进制字符串）|

**默认用户：**

如果 users.conf 文件不存在，系统会自动创建默认用户：
- 用户名: `admin`
- 密码: `admin123`

生产环境请务必修改默认密码！

## Agent Token 配置

Token 配置文件用于验证 Agent 身份，格式为 `agent_id = token`：

```ini
# /etc/ssh_jump/agent_tokens.conf

# Web 服务器
web-server-01 = ws01-secret-token
web-server-02 = ws02-secret-token

# 数据库服务器
db-server-01 = db01-secret-token
db-server-02 = db02-secret-token

# 缓存服务器
redis-01 = rd01-secret-token
redis-02 = rd02-secret-token
```

**安全建议：**
- Token 应使用强随机字符串（建议 32 字节以上）
- 定期更换 Token
- 不同 Agent 使用不同 Token
- 配置文件权限设置为 600

## 用户权限配置

权限配置文件控制用户对资产的访问权限：

```ini
# /etc/ssh_jump/user_permissions.conf

# 管理员 - 可以访问所有资产
[user:admin]
allow_all = true
max_sessions = 20

# 开发团队 - 只能访问 web 和 api 服务器
[user:developer]
allowed_patterns = web-*,api-*,app-*
max_sessions = 5

# DBA 团队 - 只能访问数据库服务器，但排除管理节点
[user:dba]
allowed_patterns = db-*,redis-*,mysql-*
denied_assets = db-admin,mysql-master
max_sessions = 10

# 运维团队 - 只能访问特定资产
[user:ops]
allowed_assets = web-server-01,web-server-02,monitor-01
max_sessions = 3

# 临时用户 - 只能访问测试环境
[user:guest]
allowed_patterns = test-*
max_sessions = 1
```

### 权限配置说明

| 配置项 | 类型 | 说明 |
|--------|------|------|
| `allow_all` | bool | 如果为 true，用户可以访问所有资产 |
| `allowed_assets` | list | 明确允许访问的资产 ID 列表，逗号分隔 |
| `allowed_patterns` | list | 允许的主机名通配符模式，支持 `*` 通配符 |
| `denied_assets` | list | 明确拒绝访问的资产 ID 列表（优先级最高）|
| `max_sessions` | int | 该用户最大并发会话数 |

### 权限匹配规则

权限检查按以下顺序进行：

1. **拒绝列表检查**：如果资产在 `denied_assets` 中，直接拒绝
2. **允许所有检查**：如果 `allow_all = true`，允许访问
3. **允许资产检查**：如果资产在 `allowed_assets` 中，允许访问
4. **模式匹配检查**：如果主机名匹配 `allowed_patterns` 中的任一模式，允许访问
5. **默认拒绝**：以上都不满足，拒绝访问

## Agent 启动参数

Agent 使用命令行参数运行：

```bash
./ssh_jump_agent \
  -s jump.example.com \
  -p 8888 \
  -i web-server-01 \
  -t ws01-secret-token \
  -n web-server-01 \
  -S ssh:ssh:22 \
  -S web:http:80
```

常用参数：
- `-s, --server` 跳板机地址（必填）
- `-p, --port` 跳板机集群端口（默认 `8888`）
- `-i, --id` Agent 唯一标识
- `-t, --token` 认证 Token（必填）
- `-n, --hostname` 显示的主机名
- `-I, --ip` 上报的本地 IP（可选）
- `-S, --service` 暴露服务，格式 `name:type:port`，可重复传递

## 环境变量

服务器支持以下环境变量：

| 变量名 | 说明 |
|--------|------|
| `SSH_JUMP_LOG_LEVEL` | 日志级别，覆盖默认日志级别 |

Agent 支持以下环境变量：

| 变量名 | 说明 |
|--------|------|
| `SSH_JUMP_SERVER` | 服务器地址 |
| `SSH_JUMP_PORT` | 服务器端口 |

## 配置热加载

目前配置不支持热加载，修改配置后需要重启服务：

```bash
# 查找进程 ID
pgrep ssh_jump_server

# 优雅重启
kill -TERM <pid>

# 重新启动
./ssh_jump_server \
  -p 2222 \
  -a 8888 \
  --listen-address 0.0.0.0 \
  --cluster-listen-address 0.0.0.0 \
  --host-key-path /etc/ssh_jump/host_key \
  --users-file /etc/ssh_jump/users.conf \
  --agent-token-file /etc/ssh_jump/agent_tokens.conf \
  --permissions-file /etc/ssh_jump/user_permissions.conf \
  --child-nodes-file /etc/ssh_jump/child_nodes.conf
```

## 配置验证

启动时使用 `-v` 参数启用详细输出，可以验证配置是否正确加载：

```bash
./ssh_jump_server \
  -p 2222 \
  -a 8888 \
  --listen-address 0.0.0.0 \
  --cluster-listen-address 0.0.0.0 \
  --host-key-path /etc/ssh_jump/host_key \
  --users-file /etc/ssh_jump/users.conf \
  --agent-token-file /etc/ssh_jump/agent_tokens.conf \
  --permissions-file /etc/ssh_jump/user_permissions.conf \
  --child-nodes-file /etc/ssh_jump/child_nodes.conf \
  -v
```

输出示例：
```
[2024-01-01 12:00:00][INFO] SSH Server: 0.0.0.0:2222
[2024-01-01 12:00:00][INFO] Cluster Manager: 0.0.0.0:8888
[2024-01-01 12:00:00][INFO] Loaded 5 agent tokens
[2024-01-01 12:00:00][INFO] Loaded 3 user permissions
```
