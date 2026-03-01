# SSH Jump Server

## 功能介绍

SSH Jump Server 是一个轻量级跳板机系统，包含服务端（`ssh_jump_server`）与 Agent（`ssh_jump_agent`），用于统一接入和管理内网主机。

- 统一 SSH 入口：用户只需连接 jump-server，即可访问后端资产。
- Agent 自动接入：子节点通过共享 token 注册到集群，便于横向扩展。
- 资产目录与选择：支持交互式菜单和按资产名直连两种访问方式。
- 会话与操作审计：内置会话记录能力，便于追踪和排查问题。
- 配套管理能力：通过命令行参数和运行时管理工具完成用户与节点维护。

## 1) 安装与编译

一键安装整个项目（自动安装 Folly、编译并安装二进制）：

```bash
git clone <repository-url>
cd ssh-jumper
./scripts/install_project.sh
```

说明：
- 安装完成后可直接使用 `/usr/local/bin/ssh_jump_server` 与 `/usr/local/bin/ssh_jump_agent`。

## 2) 启动 jump-server

```bash
ssh_jump_server \
  -p 2222 \
  -a 8888 \
  --listen-address 0.0.0.0 \
  --cluster-listen-address 0.0.0.0 \
  --token cluster-secret-token \
  --default-target-user root \
  --max-connections-per-minute 10
```

说明：
- 只需要一个共享 `--token`，所有 agent 用同一 token 加入集群。
- 不传 `--user` 时自动创建 `admin/admin123`。
- 权限参数已移除，所有已配置用户默认可访问全部资产。

## 3) 启动 jump-agent

```bash
ssh_jump_agent \
  -s <jump-server-ip> \
  -p 8888 \
  -i web-server-01 \
  -t cluster-secret-token \
  -n web-server-01
```

## 4) SSH 登录

```bash
# 交互菜单
ssh -p 2222 admin@<jump-server-ip>

# 直接指定资产
ssh -p 2222 admin@<jump-server-ip> web-server-01
```

## 5) 用户与集群节点管理

用户可通过 `ssh_jump_server` 启动参数定义；
集群节点可通过运行时工具 `ssh_jump_cluster_node_tool` 进行增删改查。

### 5.1 在启动参数中定义用户

```bash
# 方式1：明文密码（启动时自动计算哈希）
ssh_jump_server \
  -p 2222 \
  -a 8888 \
  --token cluster-secret-token \
  --user admin:Admin123 \
  --user ops:Ops123456

# 方式2：直接传入密码哈希
ssh_jump_server \
  -p 2222 \
  -a 8888 \
  --token cluster-secret-token \
  --user-hash admin:PBKDF2\$100000\$<salt_hex>\$<hash_hex>
```

### 5.2 使用运行时工具管理集群节点（CRUD）

```bash
# 列表
ssh_jump_cluster_node_tool --server 127.0.0.1 --port 8888 --token cluster-secret-token --list-nodes

# 新增
ssh_jump_cluster_node_tool --server 127.0.0.1 --port 8888 --token cluster-secret-token \
  --add-node web-01 --ip 10.0.0.21 --node-token web-01-token --hostname web-server-01

# 查询
ssh_jump_cluster_node_tool --server 127.0.0.1 --port 8888 --token cluster-secret-token --get-node web-01

# 更新
ssh_jump_cluster_node_tool --server 127.0.0.1 --port 8888 --token cluster-secret-token \
  --update-node web-01 --ip 10.0.0.22 --hostname web-server-01-new

# 删除
ssh_jump_cluster_node_tool --server 127.0.0.1 --port 8888 --token cluster-secret-token --delete-node web-01
```

说明：
- 该工具直接与运行中的 `ssh_jump_server` 通信。
- 管理权限使用服务端共享 `--token`。
