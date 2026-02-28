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
- `-p, --port` SSH 登录端口，默认 `2222`
- `-a, --agent-port` Agent 注册端口，默认 `8888`
- `--listen-address` SSH 监听地址，默认 `0.0.0.0`
- `--cluster-listen-address` Agent 集群监听地址，默认 `0.0.0.0`
- `--host-key-path` SSH 主机私钥路径
- `--users-file` 用户认证文件路径
- `--agent-token-file` Agent token 文件路径
- `--permissions-file` 用户权限文件路径
- `--child-nodes-file` 子节点注册文件路径
- `--default-target-user` 默认目标主机登录用户名，默认 `root`
- `--default-target-password` 默认目标主机登录密码
- `--default-target-private-key` 默认目标主机私钥路径
- `--default-target-key-password` 默认目标私钥密码
- `--reverse-tunnel-port-start` NAT 回拨端口池起始值，默认 `38000`
- `--reverse-tunnel-port-end` NAT 回拨端口池结束值，默认 `38199`
- `--reverse-tunnel-retries` NAT 回拨重试次数，默认 `3`
- `--reverse-tunnel-accept-timeout-ms` NAT 回拨 accept 超时(ms)，默认 `7000`
- `--max-connections-per-minute` 每 IP 每分钟连接上限，默认 `10`
- `-d, --daemon` 以守护进程方式运行
- `-v, --verbose` 输出调试日志

`ssh_jump_agent` 常用参数:
- `-s, --server` 跳板机地址（必填）
- `-p, --port` 跳板机 Agent 端口，默认 `8888`
- `-i, --id` Agent ID，默认自动生成
- `-t, --token` Agent 认证 token（必填）
- `-n, --hostname` 对外展示的主机名
- `-I, --ip` 上报给跳板机的内网 IP（可选，不填自动探测）
- `-S, --service` 暴露服务，格式 `name:type:port`，可重复传多个
- `-d, --daemon` 以守护进程方式运行
- `-v, --verbose` 输出调试日志
