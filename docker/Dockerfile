# SSH Jump Server - Docker 构建文件
# 三个角色：Server、Agent、Client

# ============================================
# Folly 构建阶段（源码编译）
# ============================================
FROM ubuntu:22.04 AS folly-builder

ENV DEBIAN_FRONTEND=noninteractive
ARG FOLLY_TAG=v2024.08.19.00

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    cmake \
    git \
    ninja-build \
    pkg-config \
    libboost-all-dev \
    libevent-dev \
    libdouble-conversion-dev \
    libgflags-dev \
    libgoogle-glog-dev \
    libgtest-dev \
    libssl-dev \
    libunwind-dev \
    libfmt-dev \
    libsodium-dev \
    libzstd-dev \
    liblz4-dev \
    libsnappy-dev \
    libjemalloc-dev \
    zlib1g-dev \
    libbz2-dev \
    liblzma-dev \
    && if [ -f /usr/lib/x86_64-linux-gnu/libgflags.so ] && [ ! -e /usr/lib/x86_64-linux-gnu/libgflags_shared.so ]; then \
        ln -s /usr/lib/x86_64-linux-gnu/libgflags.so /usr/lib/x86_64-linux-gnu/libgflags_shared.so; \
    fi \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /tmp
RUN git clone --depth 1 --branch "${FOLLY_TAG}" https://github.com/facebook/folly.git

WORKDIR /tmp/folly
RUN cmake -S . -B build \
    -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX=/usr/local \
    -DBUILD_TESTS=OFF \
    -DBUILD_BENCHMARKS=OFF \
    -DBUILD_EXAMPLES=OFF \
    -DBUILD_SHARED_LIBS=ON && \
    cmake --build build -j"$(nproc)" && \
    cmake --install build && \
    ldconfig && \
    rm -rf /tmp/folly

# ============================================
# 项目构建阶段
# ============================================
FROM folly-builder AS builder

ENV DEBIAN_FRONTEND=noninteractive
ENV PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:/usr/local/lib/x86_64-linux-gnu/pkgconfig:/usr/local/share/pkgconfig
ARG PROJECT_ENABLE_FOLLY=ON

RUN apt-get update && apt-get install -y --no-install-recommends \
    libssh-dev \
    && rm -rf /var/lib/apt/lists/*

# 复制源代码
WORKDIR /build
COPY . .

# 编译项目（Release 模式）
RUN if [ -f /usr/lib/x86_64-linux-gnu/libgflags.so ] && [ ! -e /usr/lib/x86_64-linux-gnu/libgflags_shared.so ]; then \
        ln -s /usr/lib/x86_64-linux-gnu/libgflags.so /usr/lib/x86_64-linux-gnu/libgflags_shared.so; \
    fi && \
    rm -rf build && mkdir -p build && cd build && \
    cmake -G Ninja \
      -DCMAKE_BUILD_TYPE=Release \
      -DENABLE_FOLLY=${PROJECT_ENABLE_FOLLY} \
      -DCMAKE_PREFIX_PATH=/usr/local \
      .. 2>&1 | tee /tmp/cmake.log && \
    if [ "${PROJECT_ENABLE_FOLLY}" = "ON" ]; then \
      grep -Eq "Folly found via CMake package|Folly found via pkg-config" /tmp/cmake.log && \
      ! grep -q "ENABLE_FOLLY=ON but Folly not found" /tmp/cmake.log; \
    fi && \
    cmake --build . -j"$(nproc)"

# ============================================
# 运行时基础镜像（包含 Folly 运行依赖）
# ============================================
FROM ubuntu:22.04 AS runtime-base

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libboost-all-dev \
    libdouble-conversion3 \
    libevent-2.1-7 \
    libfmt8 \
    libgflags2.2 \
    libgoogle-glog0v5 \
    libjemalloc2 \
    liblz4-1 \
    liblzma5 \
    libsodium23 \
    libsnappy1v5 \
    libssh-4 \
    libssl3 \
    libunwind8 \
    libzstd1 \
    netcat-openbsd \
    openssh-client \
    zlib1g \
    libbz2-1.0 \
    && if [ -f /usr/lib/x86_64-linux-gnu/libgflags.so ] && [ ! -e /usr/lib/x86_64-linux-gnu/libgflags_shared.so ]; then \
        ln -s /usr/lib/x86_64-linux-gnu/libgflags.so /usr/lib/x86_64-linux-gnu/libgflags_shared.so; \
    fi \
    && rm -rf /var/lib/apt/lists/*

COPY --from=folly-builder /usr/local/ /usr/local/
RUN ldconfig

# ============================================
# Server 运行阶段
# ============================================
FROM runtime-base AS server

# 创建运行用户和目录
RUN groupadd -r sshjump && \
    useradd -r -g sshjump -s /bin/false sshjump && \
    mkdir -p /etc/ssh_jump /var/log/ssh_jump /opt/ssh_jump

# 复制二进制文件
COPY --from=builder /build/build/ssh_jump_server /opt/ssh_jump/
COPY --from=builder /build/build/ssh_jump_node_tool /opt/ssh_jump/
COPY --from=builder /build/build/ssh_jump_cluster_admin_tool /opt/ssh_jump/
RUN chmod +x /opt/ssh_jump/ssh_jump_server && \
    chmod +x /opt/ssh_jump/ssh_jump_node_tool && \
    chmod +x /opt/ssh_jump/ssh_jump_cluster_admin_tool && \
    ln -sf /opt/ssh_jump/ssh_jump_server /usr/local/bin/ && \
    ln -sf /opt/ssh_jump/ssh_jump_node_tool /usr/local/bin/ && \
    ln -sf /opt/ssh_jump/ssh_jump_cluster_admin_tool /usr/local/bin/

# 复制默认配置
COPY docker/server-config/ /etc/ssh_jump/

# 启动脚本
COPY docker/scripts/start-server.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/start-server.sh

EXPOSE 2222 8888

WORKDIR /var/log/ssh_jump

ENTRYPOINT ["/usr/local/bin/start-server.sh"]

# ============================================
# Agent 运行阶段
# ============================================
FROM runtime-base AS agent

# 安装 SSH 服务（用于模拟目标服务器）
RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-server \
    iputils-ping \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

# 配置 SSH 服务（用于模拟目标服务器）
RUN mkdir -p /var/run/sshd && \
    echo 'root:agent123' | chpasswd && \
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config

# 创建运行目录
RUN mkdir -p /etc/ssh_jump /opt/ssh_jump /var/log/ssh_jump

# 复制二进制文件
COPY --from=builder /build/build/ssh_jump_agent /opt/ssh_jump/
RUN chmod +x /opt/ssh_jump/ssh_jump_agent && \
    ln -sf /opt/ssh_jump/ssh_jump_agent /usr/local/bin/

# 启动脚本
COPY docker/scripts/start-agent.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/start-agent.sh

EXPOSE 22

ENTRYPOINT ["/usr/local/bin/start-agent.sh"]

# ============================================
# Client 运行阶段
# ============================================
FROM ubuntu:22.04 AS client

ENV DEBIAN_FRONTEND=noninteractive

# 安装 SSH 客户端工具
RUN apt-get update && apt-get install -y \
    openssh-client \
    sshpass \
    iputils-ping \
    net-tools \
    netcat-openbsd \
    curl \
    nano \
    vim-tiny \
    && rm -rf /var/lib/apt/lists/*

# 创建客户端目录
RUN mkdir -p /root/.ssh /etc/ssh_jump

# 配置 SSH 客户端（自动接受新主机密钥）
RUN echo "StrictHostKeyChecking no" >> /etc/ssh/ssh_config && \
    echo "UserKnownHostsFile /dev/null" >> /etc/ssh/ssh_config

# 复制测试脚本
COPY docker/scripts/client-test.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/client-test.sh

# 默认保持运行
CMD ["sleep", "infinity"]
