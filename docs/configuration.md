# SSH Jump Server 配置指南（纯命令行）

`ssh_jump_server` 与 `ssh_jump_agent` 均为纯命令行参数驱动，不读取配置文件。

## 1. 服务端参数

### 最小可用启动

```bash
./ssh_jump_server \
  -p 2222 \
  -a 8888 \
  --listen-address 0.0.0.0 \
  --cluster-listen-address 0.0.0.0 \
  --token cluster-secret-token
```

说明：
- 不传 `--user/--user-hash` 时会自动创建默认用户 `admin/admin123`。
- 权限策略固定为：所有已配置用户默认可访问全部资产。
- 主机密钥自动生成，无需提供文件路径。

### 常用参数

- `-p, --port` SSH 端口，默认 `2222`
- `-a, --agent-port` Agent 注册端口，默认 `8888`
- `--listen-address` SSH 监听地址，默认 `0.0.0.0`
- `--cluster-listen-address` Agent 集群监听地址，默认 `0.0.0.0`
- `--token` 集群共享 token（推荐）
- `--user` 用户明文密码，格式 `name:password`，可重复
- `--user-hash` 用户哈希密码，格式 `name:hash`，可重复
- 权限策略固定为默认全资产访问，无需权限参数
- `--child-node` 子节点，格式 `id:addr[:ssh[:cluster[:name]]]`，可重复
- `--default-target-user` 默认目标机登录用户名
- `--default-target-password` 默认目标机登录密码
- `--default-target-private-key` 默认目标机私钥路径
- `--default-target-key-password` 默认目标机私钥口令
- `--reverse-tunnel-port-start` NAT 回拨端口池起始值，默认 `38000`
- `--reverse-tunnel-port-end` NAT 回拨端口池结束值，默认 `38199`
- `--reverse-tunnel-retries` NAT 回拨重试次数，默认 `3`
- `--reverse-tunnel-accept-timeout-ms` NAT 回拨超时（毫秒），默认 `7000`
- `--max-connections-per-minute` 每 IP 每分钟连接上限，默认 `0`（不限流）
- `-d, --daemon` 守护进程模式
- `-v, --verbose` 调试日志

## 2. 服务端示例

```bash
./ssh_jump_server \
  -p 2222 \
  -a 8888 \
  --token cluster-secret-token \
  --user admin:admin123 \
  --user developer:dev123 \
  --user ops:ops123 \
  --default-target-user root
```

## 3. Agent 参数

```bash
./ssh_jump_agent \
  -s <jump-server-ip> \
  -p 8888 \
  -i web-server-01 \
  -t cluster-secret-token \
  -n web-server-01
```

常用参数：
- `-s, --server` 跳板机地址（必填）
- `-p, --port` 跳板机集群端口，默认 `8888`
- `-i, --id` Agent 唯一标识
- `-t, --token` Agent token（必填）
- `-n, --hostname` 展示主机名
- `-I, --ip` 上报 IP（可选）
- `-d, --daemon` 守护进程模式
- `-v, --verbose` 调试日志

## 4. 运行校验

```bash
./ssh_jump_server --help
./ssh_jump_agent --help
```

```bash
ssh -p 2222 admin@<jump-server-ip>
ssh -p 2222 admin@<jump-server-ip> web-server-01
```
