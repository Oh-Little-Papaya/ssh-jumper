# SSH Jump Server

`ssh_jump_server` 和 `ssh_jump_agent` 现在是纯命令行参数驱动，不再支持 `-c/--config` 配置文件启动。

## 1) 安装与编译

```bash
sudo apt-get update
sudo apt-get install -y \
  cmake build-essential ninja-build pkg-config \
  libssh-dev libssl-dev
```

```bash
git clone <repository-url>
cd ssh-jumper
cmake -S . -B build -G Ninja -DENABLE_FOLLY=ON
cmake --build build -j"$(nproc)"
```

说明:
- Folly 为必选依赖，`ENABLE_FOLLY=ON` 缺失或 Folly 未安装会直接编译失败。

## 2) 启动 jump-server

先准备运行文件:

```bash
sudo mkdir -p /etc/ssh_jump /var/log/ssh_jump
sudo ssh-keygen -t rsa -b 4096 -f /etc/ssh_jump/host_key -N ""

# 创建登录用户（写入 /etc/ssh_jump/users.conf）
./build/ssh_jump_user_tool \
  --users-file /etc/ssh_jump/users.conf \
  --create-user admin \
  --password 'ChangeMe123!'

# Agent token 文件
cat <<'EOF' | sudo tee /etc/ssh_jump/agent_tokens.conf
web-server-01 = ws01-secret-token
EOF

# 用户授权文件
cat <<'EOF' | sudo tee /etc/ssh_jump/user_permissions.conf
[user:admin]
allow_all = true
EOF
```

启动:

```bash
./build/ssh_jump_server \
  -p 2222 \
  -a 8888 \
  --listen-address 0.0.0.0 \
  --cluster-listen-address 0.0.0.0 \
  --host-key-path /etc/ssh_jump/host_key \
  --users-file /etc/ssh_jump/users.conf \
  --agent-token-file /etc/ssh_jump/agent_tokens.conf \
  --permissions-file /etc/ssh_jump/user_permissions.conf \
  --child-nodes-file /etc/ssh_jump/child_nodes.conf \
  --default-target-user root \
  --max-connections-per-minute 10
```

## 3) 启动 jump-agent

```bash
./build/ssh_jump_agent \
  -s <jump-server-ip> \
  -p 8888 \
  -i web-server-01 \
  -t ws01-secret-token \
  -n web-server-01 \
  -S ssh:ssh:22
```

## 4) SSH 登录方式

```bash
# 交互菜单
ssh -p 2222 admin@<jump-server-ip>

# 直接指定资产
ssh -p 2222 admin@<jump-server-ip> web-server-01
```

## 5) 命令行参数

`ssh_jump_server` 常用参数:
- `-p, --port`
- `-a, --agent-port`
- `--listen-address`
- `--cluster-listen-address`
- `--host-key-path`
- `--users-file`
- `--agent-token-file`
- `--permissions-file`
- `--child-nodes-file`
- `--default-target-user`
- `--default-target-password`
- `--default-target-private-key`
- `--default-target-key-password`
- `--reverse-tunnel-port-start`
- `--reverse-tunnel-port-end`
- `--reverse-tunnel-retries`
- `--reverse-tunnel-accept-timeout-ms`
- `--max-connections-per-minute`
- `-d, --daemon`
- `-v, --verbose`

`ssh_jump_agent` 常用参数:
- `-s, --server` (必填)
- `-p, --port`
- `-i, --id`
- `-t, --token` (必填)
- `-n, --hostname`
- `-I, --ip`
- `-S, --service`
- `-d, --daemon`
- `-v, --verbose`
