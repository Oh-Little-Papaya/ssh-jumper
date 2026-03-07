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

detect_pkg_manager() {
    if command -v apt-get >/dev/null 2>&1; then
        echo "apt-get"
        return 0
    fi
    if command -v dnf >/dev/null 2>&1; then
        echo "dnf"
        return 0
    fi
    if command -v yum >/dev/null 2>&1; then
        echo "yum"
        return 0
    fi
    return 1
}

install_folly_dependencies() {
    local pkg_manager="$1"
    case "${pkg_manager}" in
        apt-get)
            $SUDO apt-get update
            $SUDO apt-get install -y \
              build-essential ca-certificates cmake git ninja-build pkg-config \
              libboost-all-dev libevent-dev libdouble-conversion-dev \
              libgflags-dev libgoogle-glog-dev libgtest-dev libssl-dev \
              libunwind-dev libfmt-dev libsodium-dev libzstd-dev liblz4-dev \
              libsnappy-dev libjemalloc-dev zlib1g-dev libbz2-dev liblzma-dev
            ;;
        dnf)
            $SUDO dnf install -y \
              gcc-c++ make ca-certificates cmake git ninja-build pkgconfig \
              boost-devel libevent-devel double-conversion-devel \
              gflags-devel glog-devel gtest-devel openssl-devel \
              libunwind-devel fmt-devel libsodium-devel libzstd-devel lz4-devel \
              snappy-devel jemalloc-devel zlib-devel bzip2-devel xz-devel
            ;;
        yum)
            $SUDO yum install -y \
              gcc-c++ make ca-certificates cmake git ninja-build pkgconfig \
              boost-devel libevent-devel double-conversion-devel \
              gflags-devel glog-devel gtest-devel openssl-devel \
              libunwind-devel fmt-devel libsodium-devel libzstd-devel lz4-devel \
              snappy-devel jemalloc-devel zlib-devel bzip2-devel xz-devel
            ;;
        *)
            echo "[ERROR] Unsupported package manager: ${pkg_manager}" >&2
            return 1
            ;;
    esac
}

PKG_MANAGER="$(detect_pkg_manager || true)"
if [[ -z "${PKG_MANAGER}" ]]; then
    echo "[ERROR] No supported package manager found (apt-get/dnf/yum)" >&2
    exit 1
fi

echo "[INFO] Installing build dependencies..."
install_folly_dependencies "${PKG_MANAGER}"

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
