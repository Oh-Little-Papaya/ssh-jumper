/**
 * @file main.cpp
 * @brief JumpServer 风格 SSH 跳板机主程序
 * 
 * 支持多种接入方式:
 * 1. 直接指定目标: ssh admin@jump.example.com web-server-01
 * 2. 环境变量: JUMP_TARGET=web-server-01 ssh admin@jump.example.com
 * 3. 交互式菜单: ssh admin@jump.example.com
 * 4. 快捷连接: ssh admin@jump.example.com @1 (连接最近访问的第1个)
 */

#include "common.h"
#include "event_loop.h"
#include "thread_pool.h"
#include "ssh_server.h"
#include "cluster_manager.h"
#include "asset_manager.h"
#include "node_registry.h"
#include "config_manager.h"

#include <getopt.h>

using namespace sshjump;

// 全局运行标志
static volatile sig_atomic_t g_running = 1;

// 信号处理
void signalHandler(int sig) {
    (void)sig;
    g_running = 0;
}

// 打印帮助信息
void printUsage(const char* program) {
    std::cout << "Usage: " << program << " [options]\n"
              << "\nOptions:\n"
              << "  -c, --config <path>     Configuration file path\n"
              << "  -p, --port <port>       SSH server port (default: 2222)\n"
              << "  -a, --agent-port <port> Agent cluster port (default: 8888)\n"
              << "  -d, --daemon            Run as daemon\n"
              << "  -v, --verbose           Verbose output\n"
              << "  -h, --help              Show this help message\n"
              << "  -V, --version           Show version information\n"
              << "\nUser Access Methods:\n"
              << "  1. Direct:    ssh -p 2222 admin@jump.example.com web-server-01\n"
              << "  2. Env var:   JUMP_TARGET=web-server-01 ssh -p 2222 admin@jump.example.com\n"
              << "  3. Interactive: ssh -p 2222 admin@jump.example.com\n"
              << "  4. Quick:     ssh -p 2222 admin@jump.example.com @1\n"
              << "\nExamples:\n"
              << "  " << program << " -p 2222 -a 8888\n"
              << "  " << program << " -c /etc/ssh_jump/config.conf -d\n";
}

// 打印版本信息
void printVersion() {
    std::cout << "SSH Jump Server v" << VERSION << " (JumpServer Style)\n"
              << "Copyright (c) 2024\n"
              << "Features: Interactive menu, Asset management, Direct connect, Quick access\n";
}

// 守护进程化
bool daemonize() {
    pid_t pid = fork();
    if (pid < 0) {
        LOG_ERROR("Failed to fork: " + std::string(strerror(errno)));
        return false;
    }
    
    if (pid > 0) {
        exit(0);
    }
    
    if (setsid() < 0) {
        LOG_ERROR("Failed to create new session: " + std::string(strerror(errno)));
        return false;
    }
    
    signal(SIGHUP, SIG_IGN);
    
    pid = fork();
    if (pid < 0) {
        LOG_ERROR("Failed to fork: " + std::string(strerror(errno)));
        return false;
    }
    
    if (pid > 0) {
        exit(0);
    }
    
    if (chdir("/") < 0) {
        LOG_ERROR("Failed to change working directory to /: " + std::string(strerror(errno)));
        return false;
    }

    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    int fd0 = open("/dev/null", O_RDONLY);
    int fd1 = open("/dev/null", O_WRONLY);
    int fd2 = open("/dev/null", O_WRONLY);

    if (fd0 < 0 || fd1 < 0 || fd2 < 0) {
        LOG_ERROR("Failed to redirect standard streams");
        return false;
    }

    return true;
}

// 创建 PID 文件
bool createPidFile(const std::string& path) {
    std::ofstream file(path);
    if (!file.is_open()) {
        LOG_ERROR("Failed to create PID file: " + path);
        return false;
    }
    file << getpid() << std::endl;
    file.close();
    return true;
}

// 删除 PID 文件
void removePidFile(const std::string& path) {
    unlink(path.c_str());
}

int main(int argc, char* argv[]) {
    // 默认配置
    std::string configPath = "/etc/ssh_jump/config.conf";
    int sshPort = DEFAULT_SSH_PORT;
    int agentPort = DEFAULT_CLUSTER_PORT;
    bool runAsDaemon = false;
    bool verbose = false;
    
    // 命令行参数解析
    static struct option longOptions[] = {
        {"config", required_argument, nullptr, 'c'},
        {"port", required_argument, nullptr, 'p'},
        {"agent-port", required_argument, nullptr, 'a'},
        {"daemon", no_argument, nullptr, 'd'},
        {"verbose", no_argument, nullptr, 'v'},
        {"help", no_argument, nullptr, 'h'},
        {"version", no_argument, nullptr, 'V'},
        {nullptr, 0, nullptr, 0}
    };
    
    int opt;
    while ((opt = getopt_long(argc, argv, "c:p:a:dvhV", longOptions, nullptr)) != -1) {
        switch (opt) {
            case 'c':
                configPath = optarg;
                break;
            case 'p':
                sshPort = safeStringToInt(optarg, DEFAULT_SSH_PORT);
                if (sshPort <= 0 || sshPort > 65535) {
                    std::cerr << "Invalid SSH port: " << optarg << std::endl;
                    return 1;
                }
                break;
            case 'a':
                agentPort = safeStringToInt(optarg, DEFAULT_CLUSTER_PORT);
                if (agentPort <= 0 || agentPort > 65535) {
                    std::cerr << "Invalid agent port: " << optarg << std::endl;
                    return 1;
                }
                break;
            case 'd':
                runAsDaemon = true;
                break;
            case 'v':
                verbose = true;
                break;
            case 'h':
                printUsage(argv[0]);
                return 0;
            case 'V':
                printVersion();
                return 0;
            default:
                printUsage(argv[0]);
                return 1;
        }
    }
    
    // 设置日志级别
    if (verbose) {
        g_logLevel = LogLevel::DEBUG;
    }
    
    // 打印版本信息
    printVersion();
    std::cout << std::endl;

#ifdef SSHJUMP_USE_FOLLY
    LOG_INFO("Performance optimization: Folly enabled");
#else
    LOG_INFO("Performance optimization: Folly disabled (std fallback)");
#endif
    
    // 初始化 libssh
    int ret = ssh_init();
    if (ret != SSH_OK) {
        LOG_FATAL("Failed to initialize libssh");
        return 1;
    }
    
    // 加载配置
    auto& configManager = ConfigManager::getInstance();
    if (!configManager.loadFromFile(configPath)) {
        LOG_WARN("Failed to load config file, using default settings");
        auto& config = configManager.getServerConfig();
        config.ssh.port = sshPort;
        config.cluster.port = agentPort;
    } else {
        // 使用配置文件中的端口
        auto& config = configManager.getServerConfig();
        sshPort = config.ssh.port;
        agentPort = config.cluster.port;
    }
    
    // 守护进程化
    if (runAsDaemon) {
        LOG_INFO("Running as daemon...");
        if (!daemonize()) {
            LOG_FATAL("Failed to daemonize");
            ssh_finalize();
            return 1;
        }
    }
    
    // 创建 PID 文件
    std::string pidFile = "/var/run/ssh_jump.pid";
    if (!createPidFile(pidFile)) {
        LOG_WARN("Failed to create PID file");
    }
    
    // 设置信号处理
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
    signal(SIGPIPE, SIG_IGN);
    
    // 创建事件循环
    auto eventLoop = EventLoopFactory::create(EventLoopFactory::Type::EPOLL);
    auto epollLoop = std::dynamic_pointer_cast<EpollEventLoop>(eventLoop);
    if (epollLoop && !epollLoop->initialize()) {
        LOG_FATAL("Failed to initialize event loop");
        removePidFile(pidFile);
        ssh_finalize();
        return 1;
    }
    
    // 创建并启动集群管理器 (用于内网机器注册)
    auto clusterManager = std::make_shared<ClusterManager>();
    auto& clusterConfig = configManager.getServerConfig().cluster;
    auto& clusterListenAddr = clusterConfig.listenAddress;
    if (!clusterManager->initialize(clusterListenAddr, agentPort, eventLoop)) {
        LOG_FATAL("Failed to initialize cluster manager");
        removePidFile(pidFile);
        ssh_finalize();
        return 1;
    }

    clusterManager->setReverseTunnelOptions(
        clusterConfig.reverseTunnelPortStart,
        clusterConfig.reverseTunnelPortEnd,
        clusterConfig.reverseTunnelRetries,
        clusterConfig.reverseTunnelAcceptTimeoutMs);
    
    // 加载 Agent token 配置
    clusterManager->loadAgentTokens(clusterConfig.agentTokenFile);
    
    if (!clusterManager->start()) {
        LOG_FATAL("Failed to start cluster manager");
        removePidFile(pidFile);
        ssh_finalize();
        return 1;
    }
    
    LOG_INFO("Cluster Manager started on port " + std::to_string(agentPort));
    
    // 创建资产管理器
    auto assetManager = std::make_shared<AssetManager>();
    assetManager->initialize(clusterManager);

    // 创建并加载子节点注册表（公网管理节点配置）
    auto nodeRegistry = std::make_shared<ChildNodeRegistry>();
    const std::string childNodesFile = configManager.getServerConfig().management.childNodesFile;
    nodeRegistry->loadFromFile(childNodesFile);
    LOG_INFO("Child node registry ready, file=" + childNodesFile +
             ", count=" + std::to_string(nodeRegistry->size()));
    
    // 加载用户权限配置
    assetManager->loadUserPermissions(configManager.getServerConfig().assets.permissionsFile);
    
    // 创建并启动 SSH 服务器
    auto sshServer = std::make_unique<SSHServer>();
    auto& sshListenAddr = configManager.getServerConfig().ssh.listenAddress;
    auto& hostKeyPath = configManager.getServerConfig().ssh.hostKeyPath;
    if (!sshServer->initialize(sshListenAddr, sshPort, hostKeyPath, eventLoop)) {
        LOG_FATAL("Failed to initialize SSH server");
        removePidFile(pidFile);
        ssh_finalize();
        return 1;
    }
    
    // 设置集群管理器和资产管理器
    sshServer->setClusterManager(clusterManager);
    sshServer->setAssetManager(assetManager);
    sshServer->setNodeRegistry(nodeRegistry);
    
    if (!sshServer->start()) {
        LOG_FATAL("Failed to start SSH server");
        removePidFile(pidFile);
        ssh_finalize();
        return 1;
    }
    
    LOG_INFO("SSH Server started on port " + std::to_string(sshPort));
    LOG_INFO("JumpServer-style interactive access enabled");
    LOG_INFO("Direct connect: ssh -p " + std::to_string(sshPort) + " username@<server> <asset>");
    LOG_INFO("Interactive: ssh -p " + std::to_string(sshPort) + " username@<server>");
    
    // 启动定时器线程，定期清理超时连接
    TimerThread cleanupTimer;
    cleanupTimer.start();
    cleanupTimer.scheduleRepeat(std::chrono::seconds(60), [&sshServer]() {
        sshServer->getConnectionPool()->cleanupTimeoutConnections(300);
    });
    
    // 主事件循环
    int shutdownTimeout = 0;
    while (g_running != 0) {
        eventLoop->poll(100);  // 100ms 超时
    }
    
    LOG_INFO("Shutting down...");
    
    // 给服务一些时间处理剩余连接，但最多等3秒
    while (shutdownTimeout < 30) {  // 30 * 100ms = 3秒
        eventLoop->poll(100);
        shutdownTimeout++;
    }
    
    // 停止服务
    LOG_INFO("Stopping services...");
    
    cleanupTimer.stop();
    sshServer->stop();
    clusterManager->stop();
    
    removePidFile(pidFile);
    ssh_finalize();
    
    LOG_INFO("SSH Jump Server stopped");
    
    return 0;
}
