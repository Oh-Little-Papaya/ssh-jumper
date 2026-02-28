# SSH Jump Server 性能说明

## 概览

当前版本的性能优化主线是将 Agent 转发任务调度从临时线程切换为可选的 Folly 线程池执行器。

- 构建选项: `ENABLE_FOLLY=ON|OFF`
- 默认行为: `ON`
- 关闭 Folly 时: 回退到标准库线程实现（兼容无 Folly 环境）

## 关键实现

- 转发任务入口: `submitForwardTask`（`src/cluster_manager.cpp`）
- Folly 模式: `folly::CPUThreadPoolExecutor`
- 兼容模式: `std::thread(...).detach()`

构建阶段会输出 Folly 检测结果，避免“配置为 ON 但实际未启用”的情况。

## Docker 内对比测试

项目提供了 Folly ON/OFF 同环境基准对比脚本:

```bash
./docker/perf-compare.sh
```

可选参数:

- `TASKS` 默认 `30000`
- `WORK` 默认 `200`
- `ROUNDS` 默认 `5`
- `KEEP_ARTIFACTS=1` 保留对比镜像和构建缓存（默认自动清理）

示例:

```bash
TASKS=50000 WORK=300 ROUNDS=7 ./docker/perf-compare.sh
```

## 最近一次基准结果

测试日期: 2026-02-28

测试参数: `TASKS=30000, WORK=200, ROUNDS=5`

- Folly ON
  - `AVG_MS=46.312`
  - `AVG_TPS=647783.982`
  - `P50_MS=43.229`
  - `P50_TPS=693985.306`

- Folly OFF
  - `AVG_MS=960.235`
  - `AVG_TPS=31242.348`
  - `P50_MS=1010.183`
  - `P50_TPS=29697.594`

提升对比:

1. AVG 吞吐提升: `1973.42%`
2. AVG 时延下降: `95.18%`
3. P50 吞吐提升: `2236.84%`
4. P50 时延下降: `95.72%`

## 复现实验建议

- 在同一台机器上进行 ON/OFF 对比，避免硬件差异。
- 多轮重复执行并关注中位数（P50）。
- 若要排查波动，先设置 `KEEP_ARTIFACTS=1` 保留镜像后再进入容器复查。

## 注意事项

- Folly ON/OFF 的差异主要体现在高并发任务调度路径。
- 业务真实吞吐仍受网络、目标机 SSH 服务、认证方式等因素影响。
- `tests/benchmark_forward_executor.cpp` 为微基准，用于观察调度路径变化，不等价于完整业务压测。
