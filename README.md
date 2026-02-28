# SSH Jump Server

轻量级 SSH 跳板机，支持：
- 交互式资产菜单
- Agent 自动注册与心跳
- NAT 回拨通道（打洞/反向隧道）
- 基于用户的资产权限控制
- 公网管理节点对子节点 CRUD

详细设计与部署文档在 `docs/`，本 README 只保留快速上手和关键配置。

## 快速开始（推荐 Docker）

```bash
# 启动完整环境（jump-server + 4 agents + jump-client）
docker compose up -d

# 连接跳板机（在客户端容器内）
docker exec -it jump-client ssh -p 2222 admin@jump-server
# 密码: admin123
```

默认测试账号：
- `admin / admin123`：访问全部资产
- `developer / dev123`：访问 web/api
- `ops / ops123`：访问 web/api/cache

## 本地编译

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y cmake build-essential libssh-dev libssl-dev pkg-config

git clone <repository-url>
cd ssh-jumper
mkdir build && cd build

# 默认启用 Folly（找不到会回退到 std）
cmake -DENABLE_FOLLY=ON ..
make -j"$(nproc)"
```

显式关闭 Folly：

```bash
cmake -DENABLE_FOLLY=OFF ..
make -j"$(nproc)"
```

## 启动方式

`ssh_jump_server` 默认读取 `/etc/ssh_jump/config.conf`，`-c` 只是覆盖默认路径。

```bash
# 使用默认配置路径
./ssh_jump_server

# 指定配置路径
./ssh_jump_server -c /etc/ssh_jump/config.conf

# 后台模式
./ssh_jump_server -c /etc/ssh_jump/config.conf -d
```

CLI 参数：
- `-c, --config <path>`
- `-p, --port <port>`
- `-a, --agent-port <port>`
- `-d, --daemon`
- `-v, --verbose`
- `-h, --help`
- `-V, --version`

## 最小配置示例

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

还需要准备：
- `/etc/ssh_jump/users.conf`
- `/etc/ssh_jump/agent_tokens.conf`
- `/etc/ssh_jump/user_permissions.conf`
- SSH 主机密钥：`/etc/ssh_jump/host_key`

## 支持的配置项

当前代码支持以下 section/key（以解析器为准）：

- `[ssh]`
  - `listen_address`
  - `port`
  - `host_key_path`
  - `auth_methods`
  - `permit_root_login`
  - `max_auth_tries`
  - `idle_timeout`
- `[cluster]`
  - `listen_address`
  - `port`
  - `agent_token_file`
  - `heartbeat_interval`
  - `heartbeat_timeout`
  - `reverse_tunnel_port_start`
  - `reverse_tunnel_port_end`
  - `reverse_tunnel_retries`
  - `reverse_tunnel_accept_timeout_ms`
- `[assets]`
  - `refresh_interval`
  - `permissions_file`
- `[logging]`
  - `level`
  - `log_file`
  - `audit_log`
  - `session_recording`
  - `session_path`
- `[security]`
  - `command_audit`
  - `allow_port_forwarding`
  - `allow_sftp`
  - `max_connections_per_minute`
  - `users_file`
  - `default_target_user`
  - `default_target_password`
  - `default_target_private_key`
  - `default_target_key_password`
- `[management]`
  - `child_nodes_file`

## 常用操作

连接方式：

```bash
# 交互菜单
ssh -p 2222 admin@<jump-host>

# 直连目标资产
ssh -p 2222 admin@<jump-host> web-server-01
```

子节点管理工具（公网管理节点）：

```bash
ssh_jump_node_tool --nodes-file /etc/ssh_jump/child_nodes.conf --list-nodes
```

## 测试

推荐完整回归：

```bash
# 端到端测试（自动构建、验证、清理）
./docker/test.sh

# 排障时保留环境
KEEP_TEST_ENV=1 ./docker/test.sh
```

其它：

```bash
# 客户端自动化脚本
docker compose exec -T jump-client bash -lc "/usr/local/bin/client-test.sh auto"

# Folly ON/OFF 对比
./docker/perf-compare.sh
```

## 文档索引

- [配置说明](docs/configuration.md)
- [快速开始](docs/quickstart.md)
- [部署指南](docs/deployment.md)
- [性能说明](docs/performance.md)
- [协议文档](docs/protocol.md)
- [NAT 测试矩阵](docs/nat-test-matrix.md)

## 故障排查

```bash
# 看服务日志
docker compose logs -f jump-server

# 看容器状态
docker compose ps

# 检查端口
ss -tlnp | grep -E '2222|8888'
```
