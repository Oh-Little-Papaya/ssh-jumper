#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

BUILD_TYPE="${BUILD_TYPE:-Release}"
INSTALL_PREFIX="${INSTALL_PREFIX:-/usr/local}"
BUILD_DIR="${BUILD_DIR:-${PROJECT_ROOT}/build}"
PARALLEL_JOBS="${PARALLEL_JOBS:-$(nproc)}"

if [[ "${EUID}" -eq 0 ]]; then
    SUDO=""
else
    SUDO="sudo"
fi

echo "[INFO] One-click install started"
echo "[INFO] PROJECT_ROOT=${PROJECT_ROOT}"
echo "[INFO] BUILD_TYPE=${BUILD_TYPE}"
echo "[INFO] INSTALL_PREFIX=${INSTALL_PREFIX}"
echo "[INFO] BUILD_DIR=${BUILD_DIR}"

echo "[INFO] Installing Folly and its dependencies..."
FOLLY_PREFIX="${INSTALL_PREFIX}" "${SCRIPT_DIR}/install_folly.sh"

echo "[INFO] Installing project dependencies..."
$SUDO apt-get update
$SUDO apt-get install -y libssh-dev

if [[ -f /usr/lib/x86_64-linux-gnu/libgflags.so ]] && [[ ! -e /usr/lib/x86_64-linux-gnu/libgflags_shared.so ]]; then
    echo "[INFO] Creating libgflags_shared.so compatibility symlink..."
    $SUDO ln -sf /usr/lib/x86_64-linux-gnu/libgflags.so /usr/lib/x86_64-linux-gnu/libgflags_shared.so
fi

echo "[INFO] Configuring project..."
cmake -S "${PROJECT_ROOT}" -B "${BUILD_DIR}" \
  -G Ninja \
  -DCMAKE_BUILD_TYPE="${BUILD_TYPE}" \
  -DCMAKE_INSTALL_PREFIX="${INSTALL_PREFIX}" \
  -DCMAKE_PREFIX_PATH="${INSTALL_PREFIX}"

echo "[INFO] Building project..."
cmake --build "${BUILD_DIR}" -j"${PARALLEL_JOBS}"

echo "[INFO] Installing binaries..."
$SUDO cmake --install "${BUILD_DIR}"
$SUDO ldconfig

echo "[OK] Installation completed"
echo "[OK] Binaries:"
echo "  - ${INSTALL_PREFIX}/bin/ssh_jump_server"
echo "  - ${INSTALL_PREFIX}/bin/ssh_jump_agent"
echo "  - ${INSTALL_PREFIX}/bin/ssh_jump_user_tool"
echo "  - ${INSTALL_PREFIX}/bin/ssh_jump_node_tool"
echo "  - ${INSTALL_PREFIX}/bin/ssh_jump_cluster_node_tool"
