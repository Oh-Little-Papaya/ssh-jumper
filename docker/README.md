# SSH Jump Server - Docker 测试环境

完整的 Docker 测试环境，用于快速体验和测试 SSH Jump Server。

## 架构概览

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Docker Network                              │
│                     (jump-network: 172.20.0.0/24)                   │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│   ┌──────────────────────┐                                         │
│   │   jump-client        │  <-- SSH 客户端（用户）                 │
│   │                      │       用于连接跳板机                     │
│   └──────────┬───────────┘                                         │
│              │ SSH 连接 (port 2222)                                 │
│              ▼                                                      │
│   ┌──────────────────────┐                                         │
│   │   jump-server        │  <-- SSH 跳板机服务器                   │
│   │                      │       端口: 2222 (SSH), 8888 (Agent)    │
│   │                      │                                         │
│   │  用户认证:            │                                         │
│   │  - 通过 .env 自定义   │                                         │
│   │  - 不提供默认密码     │                                         │
│   └──────────┬───────────┘                                         │
│              │ Agent 协议 (port 8888)                               │
│     ┌────────┼────────┬─────────┬─────────┐                        │
│     │        │        │         │         │                        │
│     ▼        ▼        ▼         ▼         ▼                        │
│  ┌──────┐┌──────┐┌──────┐ ┌──────┐ ┌──────┐                      │
│  │web-  ││api-  ││db-   │ │cache │ │      (ssh-jump-agent)        │
│  │srv01 ││srv01 ││srv01 │ │-srv01│ │       模拟目标服务器           │
│  │      ││      ││      │ │      │ │                               │
│  │ SSH: ││ SSH: ││ SSH: │ │ SSH: │ │                               │
│  │ 22   ││ 22   ││ 22   │ │ 22   │ │                               │
│  └──────┘└──────┘└──────┘ └──────┘                                 │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

## 容器说明

| 容器 | 镜像 | 说明 |
|------|------|------|
| **jump-server** | ssh-jump-server | SSH 跳板机，处理用户连接、Agent 管理、权限控制 |
| **web-server-01** | ssh-jump-agent | Web 服务器，所有用户可访问 |
| **api-server-01** | ssh-jump-agent | API 服务器，所有用户可访问 |
| **db-server-01** | ssh-jump-agent | 数据库服务器，仅 admin 可访问 |
| **cache-server-01** | ssh-jump-agent | 缓存服务器，非敏感资产 |
| **jump-client** | ssh-jump-client | SSH 客户端，用于测试 |

## 快速开始

### 一键启动

```bash
# 先创建本地环境变量文件，并把每个值替换成自己的强密码/随机 Token
cp .env.example .env
$EDITOR .env

# 启动所有服务
docker compose up -d

# 等待服务就绪（约 10 秒）
sleep 10

# 查看状态
docker compose ps
```

### 交互式连接

```bash
# 方式1：从客户端容器连接（推荐）
docker exec -it jump-client ssh -p 2222 "$JUMP_USER"@jump-server
# 密码: 使用 .env 中的 JUMP_PASS

# 方式2：从宿主机连接（如果端口映射）
ssh -p 2222 "$JUMP_USER"@localhost
# 密码: 使用 .env 中的 JUMP_PASS

# 方式3：运行自动化测试
docker exec jump-client /usr/local/bin/client-test.sh auto
```

## 新界面预览

连接后看到全新的 JumpServer 风格界面：

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

**界面特点：**
- ✨ 简洁设计，无多余装饰
- 📊 40% 更多垂直空间用于内容
- 🎨 彩色状态指示（● 在线 / ○ 离线）
- 🔍 清晰的视觉层次

## 用户凭证

Docker Compose 不再内置默认密码。请在 `.env` 中设置：

| 变量 | 说明 |
|------|------|
| `SERVER_USERS` | 服务端启动用户，格式如 `admin:<pwd>,developer:<pwd>,ops:<pwd>` |
| `JUMP_USER` / `JUMP_PASS` | 客户端默认登录用户和密码 |
| `DEVELOPER_USER` / `DEVELOPER_PASS` | 自动化测试中的 developer 用户 |
| `OPS_USER` / `OPS_PASS` | 自动化测试中的 ops 用户 |
| `CLUSTER_SHARED_TOKEN` | Agent 注册 Token |
| `ADMIN_TOKEN` | 管理 API Token |
| `AGENT_ROOT_PASSWORD` | 测试 Agent 容器中目标 SSH root 密码 |

## 测试场景

### 场景 1: 基本连接

```bash
docker exec -it jump-client ssh -p 2222 "$JUMP_USER"@jump-server
# 输入 .env 中的 JUMP_PASS
# 应该看到 4 个资产
```

### 场景 2: 序号连接

在菜单中输入 `1` 连接到 api-server-01：
```
> 1
正在连接到 api-server-01 (172.20.0.5)...
连接成功！正在建立会话...
```

### 场景 3: 模糊搜索

```
> web
# 自动匹配并连接到 web-server-01

> api
# 自动匹配并连接到 api-server-01
```

### 场景 4: 前缀/后缀匹配

```
> ^api
# 匹配以 api 开头的主机

> $01
# 匹配以 01 结尾的主机
```

### 场景 5: 最近访问

```
> @1
# 快速连接最近访问的第 1 个服务器
```

### 场景 6: 权限测试

**开发者用户 - 只能看到 web/api：**
```bash
docker exec -it jump-client ssh -p 2222 "$DEVELOPER_USER"@jump-server
# 密码: 使用 .env 中的 DEVELOPER_PASS
# 预期: 显示可访问资产
```

**运维用户 - 看不到 db：**
```bash
docker exec -it jump-client ssh -p 2222 "$OPS_USER"@jump-server
# 密码: 使用 .env 中的 OPS_PASS
# 预期: 显示可访问资产
```

### 场景 7: Exit 返回菜单

连接到资产后：
```bash
root@api-server-01:~# exit
logout
# 自动返回跳板机菜单，显示最近访问
最近: @1 api-server-01
```

## 菜单操作速查

| 命令 | 说明 |
|------|------|
| `1`-`9` | 按序号连接 |
| `web` | 模糊搜索 |
| `^api` | 前缀匹配 |
| `$01` | 后缀匹配 |
| `@1` | 最近访问 |
| `n`/`p` | 翻页 |
| `r` | 刷新列表 |
| `h` | 帮助 |
| `q` | 退出 |

**连接后：**
| 命令 | 说明 |
|------|------|
| `exit` | 返回菜单 |
| `~.` | 强制断开 |

## 常用命令

### 查看状态和日志

```bash
# 查看所有容器状态
docker compose ps

# 查看服务器日志
docker compose logs -f jump-server

# 查看 Agent 日志
docker compose logs -f web-server-01

# 查看客户端
docker compose logs -f jump-client
```

### 管理服务

```bash
# 重启服务
docker compose restart jump-server

# 重启所有 Agent
docker compose restart web-server-01 api-server-01 db-server-01 cache-server-01

# 停止所有服务
docker compose down

# 重新构建并启动
docker compose build --no-cache
docker compose up -d
```

### 进入容器调试

```bash
# 进入跳板机服务器
docker exec -it jump-server bash

# 进入某个 Agent
docker exec -it web-server-01 bash

# 进入客户端
docker exec -it jump-client bash
```

### 完整测试

```bash
# 一键执行完整 E2E（构建 + 启动 + 认证/权限/NAT 回拨/会话/子节点 CRUD）
# 默认在退出时自动清理容器与网络
./docker/test.sh

# 保留测试环境用于调试（不自动清理）
KEEP_TEST_ENV=1 ./docker/test.sh

# 强制无缓存构建
NO_CACHE_BUILD=1 ./docker/test.sh

# 仅运行客户端自动化测试
docker exec jump-client /usr/local/bin/client-test.sh auto

# 或手动测试
docker exec -it jump-client bash
/usr/local/bin/client-test.sh
```

### Folly ON/OFF 性能对比

```bash
# 在 Docker builder 镜像中对比 Folly 开关性能
./docker/perf-compare.sh

# 自定义参数
TASKS=50000 WORK=300 ROUNDS=7 ./docker/perf-compare.sh

# 保留对比镜像与构建缓存
KEEP_ARTIFACTS=1 ./docker/perf-compare.sh
```

### 子节点管理（CRUD）

在公网管理节点容器内使用 `ssh_jump_node_tool`：

```bash
# 列表
docker exec jump-server ssh_jump_node_tool --list-nodes

# 新增
docker exec jump-server ssh_jump_node_tool --add-node edge-01 \
  --name "Edge 01" --public-address 203.0.113.10 --ssh-port 2222 --cluster-port 8888

# 查询
docker exec jump-server ssh_jump_node_tool --get-node edge-01

# 更新
docker exec jump-server ssh_jump_node_tool --update-node edge-01 --description "updated" --disabled

# 删除
docker exec jump-server ssh_jump_node_tool --delete-node edge-01
```

## 配置文件

### Server 配置
- 配置目录: `docker/server-config/config.conf`
- SSH 端口: 2222
- Agent 端口: 8888
- 日志级别: debug

### Agent 配置
每个 Agent 通过环境变量配置：
- `AGENT_ID`: 唯一标识符
- `AGENT_TOKEN`: 认证令牌
- `SERVER_HOST`: 跳板机地址
- `SERVER_PORT`: 跳板机端口 (8888)
- `AGENT_HOSTNAME`: 显示名称
- `SSH_PORT`: SSH 服务端口 (22)

## 端口映射

| 服务 | 容器内端口 | 宿主机端口 | 说明 |
|------|-----------|-----------|------|
| SSH | 2222 | 2222 | 用户连接端口 |
| Agent | 8888 | 8888 | Agent 注册端口 |

## 故障排查

### 容器无法启动

```bash
# 查看详细日志
docker compose logs jump-server

# 检查端口占用
ss -tlnp | grep -E '2222|8888'

# 重新构建
docker compose down
docker compose build --no-cache
docker compose up -d
```

### Agent 无法注册

```bash
# 检查网络连通性
docker exec web-server-01 ping jump-server

# 检查 Agent 日志
docker compose logs web-server-01

# 检查服务器日志
docker compose logs jump-server | grep -i agent
```

### 用户看不到资产

1. 等待 Agent 注册（约 10-15 秒）
2. 检查用户权限配置
3. 刷新资产列表（输入 `r`）

## 更新日志

### v2.0.0 (2025-02)
- ✨ 全新简洁界面设计
- 🐛 修复 exit 后卡住的问题
- ✨ 最近访问记录功能
- 🎨 彩色状态指示

## 清理环境

```bash
# 停止并删除所有容器
docker compose down

# 删除相关镜像
docker rmi ssh-jump-server ssh-jump-agent ssh-jump-client

# 清理未使用的网络和卷
docker network prune -f
docker volume prune -f
```

## 相关链接

- [主README](../README.md) - 项目文档
- [快速开始](../docs/quickstart.md) - 快速上手指南
- [配置指南](../docs/configuration.md) - 详细配置说明
