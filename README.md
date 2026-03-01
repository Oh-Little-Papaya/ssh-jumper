# SSH Jump Server

## 功能介绍

SSH Jump Server 是一个轻量级跳板机系统，包含服务端（`ssh_jump_server`）与 Agent（`ssh_jump_agent`），用于统一接入和管理内网主机。

- 统一 SSH 入口：用户只需连接 jump-server，即可访问后端资产。
- Agent 自动接入：子节点通过共享 token 注册到集群，便于横向扩展。
- 资产目录与选择：支持交互式菜单和按资产名直连两种访问方式。
- 会话与操作审计：内置会话记录能力，便于追踪和排查问题。
- 配套管理工具：提供用户管理和节点管理命令行工具，方便日常运维。

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

## 5) 配套管理工具

项目提供两个命令行管理工具：
- `ssh_jump_user_tool`：用户管理（默认文件 `/etc/ssh_jump/users.conf`）
- `ssh_jump_node_tool`：子节点管理（默认文件 `/etc/ssh_jump/child_nodes.conf`）

### 5.1 用户管理工具

```bash
# 查看用户
ssh_jump_user_tool --list-users

# 创建用户
ssh_jump_user_tool --create-user ops --password 'StrongPass123'

# 创建首次登录必须改密的用户
ssh_jump_user_tool --create-user temp --password 'TempPass123' --must-change

# 禁用/启用用户
ssh_jump_user_tool --disable-user temp
ssh_jump_user_tool --enable-user temp

# 删除用户
ssh_jump_user_tool --delete-user temp
```

### 5.2 节点管理工具

```bash
# 查看所有节点
ssh_jump_node_tool --list-nodes

# 新增节点
ssh_jump_node_tool \
  --add-node web-01 \
  --name web-server-01 \
  --public-address 10.0.0.21 \
  --ssh-port 2222 \
  --cluster-port 8888 \
  --description "production web node" \
  --enabled

# 查看单个节点
ssh_jump_node_tool --get-node web-01

# 更新节点信息
ssh_jump_node_tool --update-node web-01 --public-address 10.0.0.22 --meta env=prod

# 删除节点
ssh_jump_node_tool --delete-node web-01
```
