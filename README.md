# SSH Jump Server

这个项目的核心用法只有四步：
1. 安装并编译
2. 启动 `jump-server`
3. 启动 `jump-agent`
4. 用 SSH 登录跳板机并连接资产

---

## 1) 安装与编译

### Ubuntu / Debian

```bash
sudo apt-get update
sudo apt-get install -y cmake build-essential libssh-dev libssl-dev pkg-config
```

### 编译

```bash
git clone <repository-url>
cd ssh-jumper
mkdir build && cd build

# 必须启用 Folly（缺失会直接报错）
cmake -DENABLE_FOLLY=ON ..
make -j"$(nproc)"
```

如果 CMake 提示 `ENABLE_FOLLY=ON but Folly not found`，先安装 Folly 开发依赖后再重新编译。

---

## 2) 启动 jump-server

### 2.1 准备配置目录

```bash
sudo mkdir -p /etc/ssh_jump /var/log/ssh_jump
sudo ssh-keygen -t rsa -b 4096 -f /etc/ssh_jump/host_key -N ""
```

### 2.2 最小配置文件

`/etc/ssh_jump/config.conf`

```ini
[ssh]
listen_address = 0.0.0.0
port = 2222
host_key_path = /etc/ssh_jump/host_key
auth_methods = password

[cluster]
listen_address = 0.0.0.0
port = 8888
agent_token_file = /etc/ssh_jump/agent_tokens.conf
reverse_tunnel_port_start = 38000
reverse_tunnel_port_end = 38199
reverse_tunnel_retries = 3
reverse_tunnel_accept_timeout_ms = 7000

[assets]
permissions_file = /etc/ssh_jump/user_permissions.conf

[security]
users_file = /etc/ssh_jump/users.conf
max_connections_per_minute = 10
```

`/etc/ssh_jump/users.conf`

```ini
# admin123 的 SHA256
admin = 240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9
```

`/etc/ssh_jump/agent_tokens.conf`

```ini
web-server-01 = ws01-secret-token
```

`/etc/ssh_jump/user_permissions.conf`

```ini
[user:admin]
allow_all = true
```

### 2.3 启动命令

`ssh_jump_server` 默认读取 `/etc/ssh_jump/config.conf`，不强制必须 `-c`。

```bash
# 前台
./ssh_jump_server

# 指定配置
./ssh_jump_server -c /etc/ssh_jump/config.conf

# 守护进程
./ssh_jump_server -c /etc/ssh_jump/config.conf -d
```

---

## 3) 启动 jump-agent

### 3.1 命令行方式（推荐先这样测通）

```bash
./ssh_jump_agent \
  -s <jump-server-ip> \
  -p 8888 \
  -i web-server-01 \
  -t ws01-secret-token \
  -n web-server-01 \
  -S ssh:ssh:22
```

### 3.2 配置文件方式

`/etc/ssh_jump/agent.conf`

```ini
[server]
address = <jump-server-ip>
port = 8888

[agent]
id = web-server-01
token = ws01-secret-token
hostname = web-server-01

[service]
expose = ssh:ssh:22
```

启动：

```bash
./ssh_jump_agent -c /etc/ssh_jump/agent.conf
```

---

## 4) SSH 登录方式（核心）

```bash
# 交互菜单登录（推荐）
ssh -p 2222 admin@<jump-server-ip>

# 直接指定资产登录
ssh -p 2222 admin@<jump-server-ip> web-server-01
```

登录后常用输入：
- `1` / `2`：按序号连接
- `web`：模糊搜索连接
- `^api`：前缀匹配
- `$01`：后缀匹配
- `q`：退出

---

## 测试（可选）

```bash
# 单元测试
cd build
./ssh_jump_tests

# 功能测试
./ssh_jump_func_tests
```

---

## 更多文档

- 配置详解：`docs/configuration.md`
- 部署：`docs/deployment.md`
- NAT 测试矩阵：`docs/nat-test-matrix.md`
