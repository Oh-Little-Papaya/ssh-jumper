#!/bin/bash

# Folly ON/OFF 性能对比（Docker 内同环境）
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

TASKS="${TASKS:-30000}"
WORK="${WORK:-200}"
ROUNDS="${ROUNDS:-5}"
KEEP_ARTIFACTS="${KEEP_ARTIFACTS:-0}"

FOLLY_IMAGE="ssh-jump-builder:perf-folly"
STD_IMAGE="ssh-jump-builder:perf-std"

cleanup() {
    if [ "$KEEP_ARTIFACTS" = "1" ]; then
        echo "[INFO] KEEP_ARTIFACTS=1, 跳过清理镜像/构建缓存"
        return
    fi
    docker rmi -f "$FOLLY_IMAGE" "$STD_IMAGE" >/dev/null 2>&1 || true
    docker image prune -f >/dev/null 2>&1 || true
    docker builder prune -af >/dev/null 2>&1 || true
}
trap cleanup EXIT

build_image() {
    local mode="$1"
    local enable_folly="$2"
    local image="$3"
    echo "[INFO] 构建 ${mode} 镜像 (${image}) ..."
    docker build \
        -f docker/Dockerfile \
        --target builder \
        --build-arg PROJECT_ENABLE_FOLLY="${enable_folly}" \
        -t "${image}" \
        .
}

run_bench() {
    local mode="$1"
    local image="$2"
    echo "[INFO] 运行 ${mode} 基准测试..."
    docker run --rm "${image}" bash -lc \
        "/build/build/ssh_jump_perf_bench --tasks ${TASKS} --work ${WORK} --rounds ${ROUNDS}"
}

extract_metric() {
    local key="$1"
    local payload="$2"
    echo "$payload" | awk -F= -v k="$key" '$1==k{print $2; exit}'
}

build_image "Folly ON" "ON" "$FOLLY_IMAGE"
build_image "Folly OFF" "OFF" "$STD_IMAGE"

folly_output="$(run_bench "Folly ON" "$FOLLY_IMAGE")"
std_output="$(run_bench "Folly OFF" "$STD_IMAGE")"

echo ""
echo "========== Folly ON =========="
echo "$folly_output"
echo "========== Folly OFF ========="
echo "$std_output"
echo "==============================="

folly_avg_ms="$(extract_metric "AVG_MS" "$folly_output")"
folly_avg_tps="$(extract_metric "AVG_TPS" "$folly_output")"
folly_p50_ms="$(extract_metric "P50_MS" "$folly_output")"
folly_p50_tps="$(extract_metric "P50_TPS" "$folly_output")"

std_avg_ms="$(extract_metric "AVG_MS" "$std_output")"
std_avg_tps="$(extract_metric "AVG_TPS" "$std_output")"
std_p50_ms="$(extract_metric "P50_MS" "$std_output")"
std_p50_tps="$(extract_metric "P50_TPS" "$std_output")"

if [ -z "$folly_avg_ms" ] || [ -z "$std_avg_ms" ]; then
    echo "[ERROR] 基准输出解析失败"
    exit 1
fi

tps_gain_pct="$(awk -v on="$folly_avg_tps" -v off="$std_avg_tps" 'BEGIN{printf "%.2f", ((on/off)-1.0)*100.0}')"
latency_reduce_pct="$(awk -v on="$folly_avg_ms" -v off="$std_avg_ms" 'BEGIN{printf "%.2f", (1.0-(on/off))*100.0}')"
p50_tps_gain_pct="$(awk -v on="$folly_p50_tps" -v off="$std_p50_tps" 'BEGIN{printf "%.2f", ((on/off)-1.0)*100.0}')"
p50_latency_reduce_pct="$(awk -v on="$folly_p50_ms" -v off="$std_p50_ms" 'BEGIN{printf "%.2f", (1.0-(on/off))*100.0}')"

echo ""
echo "========== 对比结果 =========="
echo "TASKS=${TASKS}, WORK=${WORK}, ROUNDS=${ROUNDS}"
echo "AVG: Folly=${folly_avg_ms} ms / ${folly_avg_tps} tps"
echo "AVG: Std  =${std_avg_ms} ms / ${std_avg_tps} tps"
echo "AVG 吞吐提升: ${tps_gain_pct}%"
echo "AVG 时延下降: ${latency_reduce_pct}%"
echo "P50 吞吐提升: ${p50_tps_gain_pct}%"
echo "P50 时延下降: ${p50_latency_reduce_pct}%"
echo "=============================="
