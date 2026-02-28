# SSH Jump Server - 交互式跳板机系统

一个轻量级、JumpServer 风格的 SSH 跳板机系统，支持简洁的交互式资产菜单、自动服务发现和多因素接入方式。

## 核心特性

- **简洁的 JumpServer 风格界面**
  - 清爽的终端界面设计，无多余装饰
  - 高效的信息展示，40% 更多垂直空间用于资产列表
  - 彩色高亮状态指示，清晰的视觉层次

- **多种接入方式**
  - 交互式菜单：直接连接显示可访问资产列表
  - 序号连接：输入数字快速连接
  - 模糊搜索：按关键字、前缀、后缀匹配主机
  - 快捷重连：`@1` 连接最近访问的服务器

- **资产自动发现**
  - 内网机器通过 Agent 自动注册到跳板机
  - 实时心跳检测，自动维护资产在线状态
  - 支持多服务暴露（SSH、HTTP、数据库等）

- **NAT 穿透（Agent 回拨）**
  - 对于位于 NAT 后的内网主机，支持通过 Agent 控制连接下发转发请求
  - Agent 主动回拨跳板机建立数据通道，无需暴露内网主机入站端口
  - 回拨失败时自动回退到传统直连模式（兼容无 NAT 场景）

- **公网管理节点子节点管理（CRUD）**
  - 支持对子节点进行增删改查（Create/Read/Update/Delete）
  - 子节点配置可持久化到 `child_nodes.conf`
  - 提供 `ssh_jump_node_tool` 运维工具

- **权限控制**
  - 基于用户的资产访问权限管理
  - 支持通配符模式匹配（如 `web-*`、`db-*`）
  - 支持明确拒绝特定资产
  - 最大并发会话限制

- **会话管理**
  - 优雅的会话结束处理（exit 自动返回菜单）
  - 审计日志记录连接、断开事件
  - 最近访问记录，支持快捷重连
  - EOF 正确检测，不会卡住

- **高性能架构**
  - 线程池处理并发连接
  - 非阻塞 I/O 设计
  - DataBridge 双向数据转发

## 系统架构

```
┌─────────┐     SSH 连接      ┌──────────────┐     选择资产
│  用户   │ ────────────────▶ │   跳板机     │ ───────────▶
│ (终端)  │                   │  (Bastion)   │              │
│         │ ◀──────────────── │              │ ◀─────────── │
└─────────┘   透明数据转发     └──────────────┘   建立连接   │
                                                             │
                              ┌──────────────┐              │
                              │   资产列表    │              │
                              │  1. api-01   │              │
                              │  2. web-01   │              │
                              │  3. db-01    │              │
                              └──────────────┘              │
                                                             │
                              ┌──────────────┐ ◀─────────────┘
                              │  内网机器    │   SSH 连接
                              │  (Agent)     │
                              └──────────────┘
```

## 快速开始

### 使用 Docker 快速体验

最简单的方式是使用 Docker Compose 启动完整环境：

```bash
# 启动所有服务（跳板机 + 4个Agent + 测试客户端）
docker-compose up -d

# 等待服务启动（约10秒）
sleep 10

# 连接到跳板机
docker exec -it jump-client ssh -p 2222 admin@jump-server
# 密码: admin123

# 查看所有容器状态
docker-compose ps
```

**测试用户账号：**
- `admin / admin123` - 管理员，访问所有资产
- `developer / dev123` - 开发者，只能访问 web/api 服务器
- `ops / ops123` - 运维，访问非敏感资产

### 编译安装

**安装依赖：**
```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y cmake build-essential libssh-dev libssl-dev pkg-config

# CentOS/RHEL
sudo yum install -y cmake gcc-c++ libssh-devel openssl-devel pkgconfig
```

**编译项目：**
```bash
git clone <repository-url>
cd ssh-jumper
mkdir build && cd build
cmake ..
make -j$(nproc)

# 安装（可选）
sudo make install
```

## 配置说明

### 最小配置

创建配置目录和基础配置：

```bash
sudo mkdir -p /etc/ssh_jump
sudo mkdir -p /var/log/ssh_jump

# 生成主机密钥
sudo ssh-keygen -t rsa -b 4096 -f /etc/ssh_jump/host_key -N ""
```

**主配置文件** `/etc/ssh_jump/config.conf`：

```ini
[ssh]
listen_address = 0.0.0.0
port = 2222
host_key_path = /etc/ssh_jump/host_key
auth_methods = publickey,password
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
```

**Agent Token 配置** `/etc/ssh_jump/agent_tokens.conf`：

```ini
[agent:web-server-01]
token = ws01-secret-token-2024
ip = 192.168.1.101
hostname = web-server-01
service = ssh:ssh:22

[agent:api-server-01]
token = api01-secret-token-2024
ip = 192.168.1.102
hostname = api-server-01
service = ssh:ssh:22
```

**用户认证配置** `/etc/ssh_jump/users.conf`：

```ini
# 格式: username = SHA256(password_hash)
# 使用: echo -n 'password' | sha256sum
admin = 240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9
```

**用户权限配置** `/etc/ssh_jump/user_permissions.conf`：

```ini
# 管理员 - 可以访问所有
[user:admin]
allow_all = true

# 开发者 - 只能访问 web 和 api 服务器
[user:developer]
allowed_patterns = web-*,api-*
max_sessions = 5

# DBA - 只能访问数据库服务器
[user:dba]
allowed_patterns = db-*,redis-*
```

### 启动服务

```bash
# 前台运行（调试）
sudo ./ssh_jump_server -c /etc/ssh_jump/config.conf

# 后台守护进程
sudo ./ssh_jump_server -c /etc/ssh_jump/config.conf -d

# 使用 systemd 管理
sudo systemctl enable ssh_jump_server
sudo systemctl start ssh_jump_server
```

**systemd 服务文件** `/etc/systemd/system/ssh_jump_server.service`：

```ini
[Unit]
Description=SSH Jump Server
After=network.target

[Service]
Type=simple
User=jumper
ExecStart=/usr/local/bin/ssh_jump_server /etc/ssh_jump/config.conf
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

### 部署 Agent

在需要被管理的内网机器上：

```bash
# 运行 Agent
sudo ./ssh_jump_agent \
    -s jump.example.com \
    -p 8888 \
    -i web-server-01 \
    -t "ws01-secret-token-2024" \
    -n "Web Server 01" \
    -S "ssh:ssh:22"

# 或使用配置文件
sudo ./ssh_jump_agent -c /etc/ssh_jump/agent.conf -d
```

**Agent 配置文件** `/etc/ssh_jump/agent.conf`：

```ini
[server]
address = jump.example.com
port = 8888

[agent]
id = web-server-01
token = ws01-secret-token-2024
hostname = Web Server 01
ip = 192.168.1.101

[service]
expose = ssh:ssh:22
```

## 使用指南

### 连接跳板机

```bash
# 交互式菜单（推荐）
ssh -p 2222 admin@jump-server

# 连接后输入密码: admin123
```

### 交互式界面

连接后看到简洁的资产列表：

```
SSH Jump Server - 安全访问网关

资产列表
----------------------------------------------------------------------

  序号  主机名              IP地址           状态
 --------------------------------------------------------------
  1   api-server-01       172.20.0.5        ●
  2   cache-server-01     172.20.0.6        ●
  3   db-server-01        172.20.0.3        ●
  4   web-server-01       172.20.0.4        ●

----------------------------------------------------------------------
  >
```

### 菜单操作

| 操作 | 说明 | 示例 |
|------|------|------|
| `1`, `2`... | 按序号连接 | `1` 连接第1台 |
| `web` | 模糊搜索 | `web` 匹配 web-server |
| `^api` | 前缀匹配 | 匹配 api- 开头的主机 |
| `$01` | 后缀匹配 | 匹配 -01 结尾的主机 |
| `@1` | 最近访问 | 连接最近访问的第1台 |
| `r` / `l` | 刷新列表 | |
| `n` / `p` | 翻页 | 下一页/上一页 |
| `h` | 帮助 | 显示操作指南 |
| `q` | 退出 | |

### 连接后操作

```bash
# 在目标服务器上执行操作
root@api-server-01:~# ls /var/www
root@api-server-01:~# systemctl status nginx

# 完成后输入 exit 返回跳板机菜单
root@api-server-01:~# exit
logout
# 自动返回到资产列表，最近访问已记录
```

## 帮助系统

在菜单中输入 `h` 查看帮助：

```
快速操作指南

  连接方式:
    [序号]       直接连接 (如: 1)
    [关键字]     模糊搜索 (如: web)
    ^[前缀]      前缀匹配 (如: ^web)
    $后缀       后缀匹配 (如: $prod)
    @[序号]      最近访问 (如: @1)

  快捷命令:
    n/p         下一页/上一页
    r            刷新资产列表
    h            显示帮助
    q            退出系统

  连接后:
    exit         返回菜单
    ~.           强制断开
```

## Docker 环境

项目包含完整的 Docker 测试环境：

```bash
# 启动所有服务
docker-compose up -d

# 查看日志
docker-compose logs -f jump-server

# 停止服务
docker-compose down

# 重新构建
docker-compose build --no-cache
docker-compose up -d
```

**Docker 环境包含：**
- `jump-server` - 跳板机服务（端口 2222）
- `web-server-01` - Web 服务器 Agent
- `api-server-01` - API 服务器 Agent
- `db-server-01` - 数据库服务器 Agent
- `cache-server-01` - 缓存服务器 Agent
- `jump-client` - 测试客户端容器

## 测试

```bash
cd build

# 运行单元测试
./ssh_jump_tests

# 运行功能测试
./ssh_jump_func_tests

# 使用 ctest
ctest --output-on-failure

# Docker 环境自动化测试
docker exec jump-client /usr/local/bin/client-test.sh auto
```

## 系统要求

- **操作系统**: Linux (kernel >= 4.0)
- **编译器**: GCC >= 9.0 或 Clang >= 10.0
- **依赖库**:
  - libssh >= 0.9.0 (libssh-dev)
  - OpenSSL >= 1.1.1
  - CMake >= 3.14
  - pkg-config

## 安全建议

1. **使用密钥认证**: 禁用密码认证，仅使用 SSH 密钥
2. **配置防火墙**: 限制跳板机的访问来源 IP
3. **定期更换 Token**: Agent 使用的 token 应定期更换
4. **启用审计日志**: 对所有连接进行审计记录
5. **最小权限原则**: 为用户配置最小的必要权限
6. **使用非 root 运行**: 创建专用用户运行服务

## 故障排查

### 服务器无法启动

```bash
# 检查端口占用
ss -tlnp | grep -E '2222|8888'

# 检查配置语法
./ssh_jump_server -c /etc/ssh_jump/config.conf -v

# 查看详细日志
tail -f /var/log/ssh_jump/server.log
```

### Agent 无法注册

1. 检查网络连通性: `telnet jump-server 8888`
2. 检查 token 是否正确
3. 查看服务器日志确认连接请求
4. 确认 Agent ID 唯一性

### 用户无法看到资产

1. 检查用户权限配置 (`user_permissions.conf`)
2. 确认 Agent 已在线且心跳正常
3. 查看服务器日志中的资产注册信息

### Exit 后卡住

如果遇到 `exit` 后无法返回菜单的问题：
1. 确认使用的是最新版本（已修复 EOF 处理）
2. 检查目标服务器的 SSH 配置
3. 使用 `~.` 强制断开连接

## 更新日志

### v2.0.0 (2025-02)
- ✨ 简洁的 JumpServer 风格界面设计
- 🐛 修复 exit 后卡住的问题（EOF 正确检测）
- ✨ 优雅返回菜单功能
- ✨ 最近访问记录和快捷重连
- 🎨 彩色状态指示和改进的视觉层次
- ⚡ 40% 更多垂直空间用于资产列表

### v1.0.0
- 初始版本
- 交互式资产菜单
- Agent 自动注册
- 用户权限管理

## 许可证

MIT License

## 贡献

欢迎提交 Issue 和 Pull Request！

## 致谢

- [JumpServer](https://jumpserver.org/) - 界面设计灵感来源
- [libssh](https://www.libssh.org/) - SSH 协议实现
- [OpenSSL](https://www.openssl.org/) - 加密库支持
