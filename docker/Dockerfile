# SSH Jump Server - Docker 构建文件
# 三个角色：Server、Agent、Client

# ============================================
# 构建阶段
# ============================================
FROM ubuntu:22.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive

# 安装编译依赖
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    pkg-config \
    libssh-dev \
    libssl-dev \
    git \
    && (apt-get install -y libfolly-dev || echo "[WARN] libfolly-dev not available, fallback to std mode") \
    && rm -rf /var/lib/apt/lists/*

# 复制源代码
WORKDIR /build
COPY . .

# 编译项目（Release 模式）
RUN rm -rf build && mkdir -p build && cd build && \
    cmake -DCMAKE_BUILD_TYPE=Release -DENABLE_FOLLY=ON .. && \
    make -j$(nproc)

# ============================================
# Server 运行阶段
# ============================================
FROM ubuntu:22.04 AS server

ENV DEBIAN_FRONTEND=noninteractive

# 安装运行依赖
RUN apt-get update && apt-get install -y \
    libssh-4 \
    libssl3 \
    openssh-client \
    netcat-openbsd \
    && (apt-get install -y libfolly-dev || true) \
    && rm -rf /var/lib/apt/lists/*

# 创建运行用户和目录
RUN groupadd -r sshjump && \
    useradd -r -g sshjump -s /bin/false sshjump && \
    mkdir -p /etc/ssh_jump /var/log/ssh_jump /opt/ssh_jump

# 复制二进制文件
COPY --from=builder /build/build/ssh_jump_server /opt/ssh_jump/
COPY --from=builder /build/build/ssh_jump_node_tool /opt/ssh_jump/
RUN chmod +x /opt/ssh_jump/ssh_jump_server && \
    chmod +x /opt/ssh_jump/ssh_jump_node_tool && \
    ln -sf /opt/ssh_jump/ssh_jump_server /usr/local/bin/
RUN ln -sf /opt/ssh_jump/ssh_jump_node_tool /usr/local/bin/

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
FROM ubuntu:22.04 AS agent

ENV DEBIAN_FRONTEND=noninteractive

# 安装运行依赖和 SSH 服务（用于模拟目标服务器）
RUN apt-get update && apt-get install -y \
    libssh-4 \
    libssl3 \
    openssh-server \
    iputils-ping \
    net-tools \
    netcat-openbsd \
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
