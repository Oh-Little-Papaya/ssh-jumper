# SSH Jump Server

`ssh_jump_server` 和 `ssh_jump_agent` 现在是纯命令行参数驱动，不支持 `-c/--config` 配置文件启动。

## 1) 安装与编译

安装依赖（Folly 必选）：

```bash
sudo apt-get update
sudo apt-get install -y \
  build-essential ca-certificates cmake git ninja-build pkg-config \
  libboost-all-dev libevent-dev libdouble-conversion-dev \
  libgflags-dev libgoogle-glog-dev libgtest-dev libssl-dev \
  libunwind-dev libfmt-dev libsodium-dev libzstd-dev liblz4-dev \
  libsnappy-dev libjemalloc-dev zlib1g-dev libbz2-dev liblzma-dev \
  libssh-dev
```

安装 Folly：

```bash
git clone --depth 1 --branch v2024.08.19.00 https://github.com/facebook/folly.git
cmake -S folly -B folly/build -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX=/usr/local \
  -DBUILD_TESTS=OFF -DBUILD_BENCHMARKS=OFF -DBUILD_EXAMPLES=OFF \
  -DBUILD_SHARED_LIBS=ON
cmake --build folly/build -j"$(nproc)"
sudo cmake --install folly/build
sudo ldconfig
rm -rf folly
```

编译项目：

```bash
git clone <repository-url>
cd ssh-jumper
cmake -S . -B build -G Ninja -DENABLE_FOLLY=ON -DCMAKE_PREFIX_PATH=/usr/local
cmake --build build -j"$(nproc)"
```

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
