# NAT 打洞测试矩阵

## 目标

验证 `FORWARD_REQUEST` 回拨通道在不同 NAT 类型和网络限制下的可用性，并确认失败时可自动回退直连（非 NAT 场景）。

## 配置前提

服务端 `[cluster]` 建议配置固定回拨端口池（示例）：

```ini
reverse_tunnel_port_start = 38000
reverse_tunnel_port_end = 38199
reverse_tunnel_retries = 3
reverse_tunnel_accept_timeout_ms = 7000
```

并在防火墙放行该端口池的入站流量（Agent -> Jump Server）。

## NAT 类型矩阵

| 场景 | NAT 类型 | 预期结果 | 判定标准 |
|------|---------|---------|---------|
| A1 | Full Cone | 回拨成功 | `jump-server` 日志出现 `Reverse tunnel established`，会话可进入目标 |
| A2 | Restricted Cone | 回拨成功 | 同 A1 |
| A3 | Port Restricted Cone | 回拨成功 | 同 A1 |
| A4 | Symmetric NAT | 回拨成功（服务端公网可达） | 同 A1 |
| A5 | Double NAT / CGNAT | 回拨成功（允许 Agent 出站） | 同 A1 |
| A6 | Egress 限制（仅允许部分端口） | 取决于放行端口 | 放行端口池后成功；未放行时日志出现超时并回退 |

## 失败回退验证

| 场景 | 操作 | 预期结果 |
|------|------|---------|
| F1 | 阻断 Agent 到服务端回拨端口池的访问 | 回拨重试后失败并记录 `fallback=direct_connect` |
| F2 | Agent 控制连接中断 | 无回拨能力，走直连逻辑（若直连不可达则连接失败） |

## Docker 回归执行

```bash
# 完整端到端（含 NAT 回拨链路检查）
./docker/test.sh

# 测试结束自动清理（默认行为）；需要保留环境排障时再启用：
KEEP_TEST_ENV=1 ./docker/test.sh
```

## 日志关键字

- 成功：`Reverse tunnel established`
- 重试：`Reverse tunnel attempt X/Y`
- 回退：`fallback=direct_connect`
