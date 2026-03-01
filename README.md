# SSH Jump Server

`ssh_jump_server` 和 `ssh_jump_agent` 现在是纯命令行参数驱动，不支持 `-c/--config` 配置文件启动。

## 1) 安装与编译

Folly 默认启用，先一键安装 Folly（含依赖）：

```bash
./scripts/install_folly.sh
```

编译项目：

```bash
git clone <repository-url>
cd ssh-jumper
sudo apt-get install -y libssh-dev
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build -j"$(nproc)"
```

说明：
- `ENABLE_FOLLY` 默认就是 `ON`，不需要额外传 `-DENABLE_FOLLY=ON`。
- 如果 Folly 不可用，配置阶段会直接失败。

## 2) 启动 jump-server

```bash
./build/ssh_jump_server \
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
./build/ssh_jump_agent \
  -s <jump-server-ip> \
  -p 8888 \
  -i web-server-01 \
  -t cluster-secret-token \
  -n web-server-01 \
  -S ssh:ssh:22
```

## 4) SSH 登录

```bash
# 交互菜单
ssh -p 2222 admin@<jump-server-ip>

# 直接指定资产
ssh -p 2222 admin@<jump-server-ip> web-server-01
```
