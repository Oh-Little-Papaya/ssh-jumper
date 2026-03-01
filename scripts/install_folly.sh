#!/usr/bin/env bash
set -euo pipefail

FOLLY_TAG="${FOLLY_TAG:-v2024.08.19.00}"
FOLLY_PREFIX="${FOLLY_PREFIX:-/usr/local}"
BUILD_ROOT="$(mktemp -d /tmp/folly-build.XXXXXX)"

cleanup() {
    rm -rf "$BUILD_ROOT"
}
trap cleanup EXIT

if [[ "${EUID}" -eq 0 ]]; then
    SUDO=""
else
    SUDO="sudo"
fi

echo "[INFO] Installing build dependencies..."
$SUDO apt-get update
$SUDO apt-get install -y \
  build-essential ca-certificates cmake git ninja-build pkg-config \
  libboost-all-dev libevent-dev libdouble-conversion-dev \
  libgflags-dev libgoogle-glog-dev libgtest-dev libssl-dev \
  libunwind-dev libfmt-dev libsodium-dev libzstd-dev liblz4-dev \
  libsnappy-dev libjemalloc-dev zlib1g-dev libbz2-dev liblzma-dev

if [[ -f /usr/lib/x86_64-linux-gnu/libgflags.so ]] && [[ ! -e /usr/lib/x86_64-linux-gnu/libgflags_shared.so ]]; then
    echo "[INFO] Creating libgflags_shared.so compatibility symlink..."
    $SUDO ln -sf /usr/lib/x86_64-linux-gnu/libgflags.so /usr/lib/x86_64-linux-gnu/libgflags_shared.so
fi

echo "[INFO] Building Folly ${FOLLY_TAG}..."
git clone --depth 1 --branch "${FOLLY_TAG}" https://github.com/facebook/folly.git "${BUILD_ROOT}/folly"

cmake -S "${BUILD_ROOT}/folly" -B "${BUILD_ROOT}/folly/build" \
  -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX="${FOLLY_PREFIX}" \
  -DBUILD_TESTS=OFF \
  -DBUILD_BENCHMARKS=OFF \
  -DBUILD_EXAMPLES=OFF \
  -DBUILD_SHARED_LIBS=ON

cmake --build "${BUILD_ROOT}/folly/build" -j"$(nproc)"
$SUDO cmake --install "${BUILD_ROOT}/folly/build"
$SUDO ldconfig

echo "[OK] Folly installed to ${FOLLY_PREFIX}"
