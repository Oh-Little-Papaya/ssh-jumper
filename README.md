# SSH Jump Server

## 功能介绍

SSH Jump Server 是一个轻量级跳板机系统，包含服务端（`ssh_jump_server`）与 Agent（`ssh_jump_agent`），用于统一接入和管理内网主机。

- 统一 SSH 入口：用户只需连接 jump-server，即可访问后端资产。
- Agent 自动接入：子节点通过集群 token 注册到服务端。
- 资产目录与选择：支持交互式菜单和按资产名直连两种访问方式。
- 运行时集群管理：`ssh_jump_cluster_admin_tool` 同时支持用户和集群节点 CRUD。
- 安全增强：管理 token 与集群 token 分离、无默认弱口令、管理请求与 agent 注册负载加密传输。

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
  --admin-token admin-secret-token \
  --user admin:Admin123! \
  --default-target-user root
```

说明：
- `--token` 仅用于 Agent 注册认证。
- `--admin-token` 仅用于运行时管理接口认证（`ssh_jump_cluster_admin_tool`）。
- 启动时必须通过 `--user` 或 `--user-hash` 提供至少一个账户，不再自动创建默认 `admin/admin123`。
- 默认不限制连接并发；如需限流可设置 `--max-connections-per-minute <n>`。

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

## 5) 用户与集群节点管理（运行时 CRUD）

`ssh_jump_cluster_admin_tool` 可以直接管理用户和节点。

### 5.1 用户管理

```bash
# 列表
ssh_jump_cluster_admin_tool --server 127.0.0.1 --port 8888 --admin-token admin-secret-token --list-users

# 新增（明文密码由服务端加密保存）
ssh_jump_cluster_admin_tool --server 127.0.0.1 --port 8888 --admin-token admin-secret-token \
  --add-user ops --password 'OpsPass123' --must-change

# 查询
ssh_jump_cluster_admin_tool --server 127.0.0.1 --port 8888 --admin-token admin-secret-token --get-user ops

# 更新（改密/启用禁用/公钥）
ssh_jump_cluster_admin_tool --server 127.0.0.1 --port 8888 --admin-token admin-secret-token \
  --update-user ops --password 'NewPass456' --enabled

# 删除
ssh_jump_cluster_admin_tool --server 127.0.0.1 --port 8888 --admin-token admin-secret-token --delete-user ops
```

### 5.2 节点管理

```bash
# 列表
ssh_jump_cluster_admin_tool --server 127.0.0.1 --port 8888 --admin-token admin-secret-token --list-nodes

# 新增
ssh_jump_cluster_admin_tool --server 127.0.0.1 --port 8888 --admin-token admin-secret-token \
  --add-node web-01 --ip 10.0.0.21 --node-token web-01-token --hostname web-server-01

# 查询
ssh_jump_cluster_admin_tool --server 127.0.0.1 --port 8888 --admin-token admin-secret-token --get-node web-01

# 更新
ssh_jump_cluster_admin_tool --server 127.0.0.1 --port 8888 --admin-token admin-secret-token \
  --update-node web-01 --ip 10.0.0.22 --hostname web-server-01-new

# 删除
ssh_jump_cluster_admin_tool --server 127.0.0.1 --port 8888 --admin-token admin-secret-token --delete-node web-01
```

说明：
- 该工具直接与运行中的 `ssh_jump_server` 通信。
- 管理请求使用 `--admin-token` 加密封装后传输。
- 节点返回数据不再暴露 node token；用户返回数据不再回显公钥原文。
