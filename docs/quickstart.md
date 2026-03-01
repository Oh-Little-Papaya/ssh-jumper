# 快速开始指南

本指南帮助你在 5 分钟内快速启动并运行 SSH Jump Server。

## 前提条件

- Linux 系统（Ubuntu 20.04+ / CentOS 8+）
- 具有 sudo 权限的用户
- 基本的命令行知识

## 1. 安装（1 分钟）

```bash
# 安装依赖
sudo apt-get update
sudo apt-get install -y cmake build-essential libssh-dev libssl-dev pkg-config

# 克隆并编译
git clone <repository-url>
cd ssh-jumper
mkdir build && cd build
# 默认启用 Folly 优化（默认要求必须可用）
cmake -DENABLE_FOLLY=ON ..
make -j$(nproc)

# 安装到系统
sudo make install
```

## 2. 准备启动参数（1 分钟）

无需任何配置文件。你只需要准备：
- 登录用户（`--user`）
- Agent token（`--agent-token`）
- 用户权限（`--permission-*`，可选；不传默认 `allow_all=true`）

## 3. 启动服务器（1 分钟）

```bash
# 启动
sudo ./ssh_jump_server \
  -p 2222 \
  -a 8888 \
  --listen-address 0.0.0.0 \
  --cluster-listen-address 0.0.0.0 \
  --user admin:admin123 \
  --agent-token my-server:my-secret-token \
  --permission-allow-all admin \
  --default-target-user root

# 或使用守护进程模式
sudo ./ssh_jump_server \
  -p 2222 \
  -a 8888 \
  --listen-address 0.0.0.0 \
  --cluster-listen-address 0.0.0.0 \
  --user admin:admin123 \
  --agent-token my-server:my-secret-token \
  --permission-allow-all admin \
  --default-target-user root \
  -d
```

检查是否启动成功：

```bash
# 查看端口监听
ss -tlnp | grep -E '2222|8888'

# 查看日志
tail -f /var/log/ssh_jump/server.log
```

## 4. 部署 Agent（1 分钟）

在要管理的机器上：

```bash
# 复制 Agent 二进制
scp build/ssh_jump_agent user@target-server:/tmp/

# 在目标机器上运行
ssh user@target-server
sudo mv /tmp/ssh_jump_agent /usr/local/bin/
sudo chmod +x /usr/local/bin/ssh_jump_agent

# 运行 Agent
sudo ssh_jump_agent \
    -s <jump-server-ip> \
    -p 8888 \
    -i my-server \
    -t my-secret-token \
    -S "ssh:ssh:22"
```

## 5. 测试连接（1 分钟）

```bash
# 查看帮助
ssh -p 2222 admin@<jump-server-ip>

# 你应该会看到交互式资产菜单：
# ╔══════════════════════════════════════╗
# ║         可访问的资产列表            ║
# ╠══════════════════════════════════════╣
# ║  1 │ my-server    │ ● 在线          ║
# ╚══════════════════════════════════════╝
# 请选择: _
```

输入 `1` 或 `my-server` 即可连接到目标机器！

## 下一步

- [配置指南](configuration.md) - 详细配置说明
- [部署指南](deployment.md) - 生产环境部署
- [协议文档](protocol.md) - 通信协议说明

## 常见问题

**Q: 连接被拒绝？**
A: 检查防火墙：
```bash
sudo ufw allow 2222/tcp
sudo ufw allow 8888/tcp
```

**Q: Agent 无法注册？**
A: 检查 token 是否正确：
```bash
ps -ef | grep ssh_jump_server
```

**Q: 如何停止服务？**
A: 查找并终止进程：
```bash
pgrep ssh_jump_server
kill <pid>
```
