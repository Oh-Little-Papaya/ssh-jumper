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
#include <filesystem>
#include <iomanip>
#include <openssl/sha.h>
#include <sstream>
#include <system_error>
#include <sys/stat.h>

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
              << "  -p, --port <port>       SSH server port (default: 2222)\n"
              << "  -a, --agent-port <port> Agent cluster port (default: 8888)\n"
              << "      --listen-address <addr>            SSH listen address (default: 0.0.0.0)\n"
              << "      --cluster-listen-address <addr>    Cluster listen address (default: 0.0.0.0)\n"
              << "      --user <name:password>             Add user from CLI (repeatable)\n"
              << "      --user-hash <name:hash>            Add user hash from CLI (repeatable)\n"
              << "      --token <token>                    Shared cluster token for all agents\n"
              << "                                         (if no --user, defaults to admin/admin123)\n"
              << "      --child-node <id:addr[:ssh[:cluster[:name]]]> Add child node from CLI (repeatable)\n"
              << "      --default-target-user <user>       Default target SSH user (default: root)\n"
              << "      --default-target-password <pass>   Default target SSH password\n"
              << "      --default-target-private-key <path>    Default target private key path\n"
              << "      --default-target-key-password <pass>   Default target key password\n"
              << "      --reverse-tunnel-port-start <port> Reverse tunnel port pool start (default: 38000)\n"
              << "      --reverse-tunnel-port-end <port>   Reverse tunnel port pool end (default: 38199)\n"
              << "      --reverse-tunnel-retries <n>       Reverse tunnel retries (default: 3)\n"
              << "      --reverse-tunnel-accept-timeout-ms <ms> Reverse tunnel accept timeout (default: 7000)\n"
              << "      --max-connections-per-minute <n>   SSH connection rate limit (default: 0, unlimited)\n"
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
              << "  " << program << " -p 2222 -a 8888 --token cluster-secret\n"
              << "  " << program << " -d --token cluster-secret --user admin:admin123\n";
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

bool splitSpec(const std::string& spec, char delimiter, std::string& left, std::string& right) {
    size_t pos = spec.find(delimiter);
    if (pos == std::string::npos || pos == 0 || pos + 1 >= spec.size()) {
        return false;
    }
    left = trimString(spec.substr(0, pos));
    right = trimString(spec.substr(pos + 1));
    return !left.empty() && !right.empty();
}

std::string sha256Hex(const std::string& plainText) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(plainText.data()), plainText.size(), hash);

    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        oss << std::setw(2) << static_cast<int>(hash[i]);
    }
    return oss.str();
}

bool parseChildNodeSpec(const std::string& spec, ChildNodeInfo& node) {
    auto parts = splitString(spec, ':');
    if (parts.size() < 2) {
        return false;
    }

    node = ChildNodeInfo();
    node.nodeId = trimString(parts[0]);
    node.publicAddress = trimString(parts[1]);

    if (parts.size() >= 3 && !trimString(parts[2]).empty()) {
        node.sshPort = safeStringToInt(trimString(parts[2]), DEFAULT_SSH_PORT);
    }
    if (parts.size() >= 4 && !trimString(parts[3]).empty()) {
        node.clusterPort = safeStringToInt(trimString(parts[3]), DEFAULT_CLUSTER_PORT);
    }
    if (parts.size() >= 5) {
        node.name = trimString(parts[4]);
    }
    if (node.name.empty()) {
        node.name = node.nodeId;
    }

    return node.isValid();
}

bool generateAndExportHostKey(enum ssh_keytypes_e keyType, int bits, const std::string& keyPath) {
    ssh_key key = nullptr;
    int rc = ssh_pki_generate(keyType, bits, &key);
    if (rc != SSH_OK || !key) {
        return false;
    }

    rc = ssh_pki_export_privkey_file(key, nullptr, nullptr, nullptr, keyPath.c_str());
    ssh_key_free(key);

    if (rc != SSH_OK) {
        return false;
    }

    chmod(keyPath.c_str(), 0600);
    return true;
}

bool generateEphemeralHostKeys(std::string& hostKeyPath, std::string& hostKeyDir) {
    char dirTemplate[] = "/tmp/ssh_jump_hostkey_XXXXXX";
    char* dir = mkdtemp(dirTemplate);
    if (!dir) {
        return false;
    }

    hostKeyDir = dir;
    hostKeyPath = hostKeyDir + "/host_key";

    if (!generateAndExportHostKey(SSH_KEYTYPE_RSA, 3072, hostKeyPath)) {
        return false;
    }

    // ECDSA 可选，失败仅降级，不影响启动
    const std::string ecdsaKeyPath = hostKeyPath + "_ecdsa";
    if (!generateAndExportHostKey(SSH_KEYTYPE_ECDSA, 521, ecdsaKeyPath)) {
        LOG_WARN("Failed to generate optional ECDSA host key, fallback to RSA only");
    }

    return true;
}

struct TempPathGuard {
    std::string path;
    ~TempPathGuard() {
        if (path.empty()) {
            return;
        }
        std::error_code ec;
        std::filesystem::remove_all(path, ec);
    }
};

int main(int argc, char* argv[]) {
    // 默认配置（纯命令行参数驱动）
    int sshPort = DEFAULT_SSH_PORT;
    int agentPort = DEFAULT_CLUSTER_PORT;
    std::string sshListenAddr = "0.0.0.0";
    std::string clusterListenAddr = "0.0.0.0";
    std::string hostKeyPath;
    TempPathGuard generatedHostKeyGuard;
    std::vector<std::pair<std::string, std::string>> cliUsers;
    std::vector<std::pair<std::string, std::string>> cliUsersHash;
    std::string sharedClusterToken;
    std::vector<ChildNodeInfo> cliChildNodes;
    std::string defaultTargetUser = "root";
    std::string defaultTargetPassword;
    std::string defaultTargetPrivateKey;
    std::string defaultTargetKeyPassword;
    int reverseTunnelPortStart = 38000;
    int reverseTunnelPortEnd = 38199;
    int reverseTunnelRetries = 3;
    int reverseTunnelAcceptTimeoutMs = 7000;
    int maxConnectionsPerMinute = 0;
    bool runAsDaemon = false;
    bool verbose = false;

    enum LongOptionValue {
        OPT_LISTEN_ADDRESS = 1000,
        OPT_CLUSTER_LISTEN_ADDRESS,
        OPT_USER,
        OPT_USER_HASH,
        OPT_SHARED_TOKEN,
        OPT_CHILD_NODE,
        OPT_DEFAULT_TARGET_USER,
        OPT_DEFAULT_TARGET_PASSWORD,
        OPT_DEFAULT_TARGET_PRIVATE_KEY,
        OPT_DEFAULT_TARGET_KEY_PASSWORD,
        OPT_RT_PORT_START,
        OPT_RT_PORT_END,
        OPT_RT_RETRIES,
        OPT_RT_ACCEPT_TIMEOUT_MS,
        OPT_MAX_CONNECTIONS_PER_MINUTE
    };
    
    // 命令行参数解析
    static struct option longOptions[] = {
        {"port", required_argument, nullptr, 'p'},
        {"agent-port", required_argument, nullptr, 'a'},
        {"listen-address", required_argument, nullptr, OPT_LISTEN_ADDRESS},
        {"cluster-listen-address", required_argument, nullptr, OPT_CLUSTER_LISTEN_ADDRESS},
        {"user", required_argument, nullptr, OPT_USER},
        {"user-hash", required_argument, nullptr, OPT_USER_HASH},
        {"token", required_argument, nullptr, OPT_SHARED_TOKEN},
        {"child-node", required_argument, nullptr, OPT_CHILD_NODE},
        {"default-target-user", required_argument, nullptr, OPT_DEFAULT_TARGET_USER},
        {"default-target-password", required_argument, nullptr, OPT_DEFAULT_TARGET_PASSWORD},
        {"default-target-private-key", required_argument, nullptr, OPT_DEFAULT_TARGET_PRIVATE_KEY},
        {"default-target-key-password", required_argument, nullptr, OPT_DEFAULT_TARGET_KEY_PASSWORD},
        {"reverse-tunnel-port-start", required_argument, nullptr, OPT_RT_PORT_START},
        {"reverse-tunnel-port-end", required_argument, nullptr, OPT_RT_PORT_END},
        {"reverse-tunnel-retries", required_argument, nullptr, OPT_RT_RETRIES},
        {"reverse-tunnel-accept-timeout-ms", required_argument, nullptr, OPT_RT_ACCEPT_TIMEOUT_MS},
        {"max-connections-per-minute", required_argument, nullptr, OPT_MAX_CONNECTIONS_PER_MINUTE},
        {"daemon", no_argument, nullptr, 'd'},
        {"verbose", no_argument, nullptr, 'v'},
        {"help", no_argument, nullptr, 'h'},
        {"version", no_argument, nullptr, 'V'},
        {nullptr, 0, nullptr, 0}
    };
    
    int opt;
    while ((opt = getopt_long(argc, argv, "p:a:dvhV", longOptions, nullptr)) != -1) {
        switch (opt) {
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
            case OPT_LISTEN_ADDRESS:
                sshListenAddr = optarg;
                break;
            case OPT_CLUSTER_LISTEN_ADDRESS:
                clusterListenAddr = optarg;
                break;
            case OPT_USER: {
                std::string username;
                std::string password;
                if (!splitSpec(optarg, ':', username, password)) {
                    std::cerr << "Invalid --user format, expected name:password, got: " << optarg << std::endl;
                    return 1;
                }
                cliUsers.emplace_back(username, password);
                break;
            }
            case OPT_USER_HASH: {
                std::string username;
                std::string hashValue;
                if (!splitSpec(optarg, ':', username, hashValue)) {
                    std::cerr << "Invalid --user-hash format, expected name:hash, got: " << optarg << std::endl;
                    return 1;
                }
                cliUsersHash.emplace_back(username, hashValue);
                break;
            }
            case OPT_SHARED_TOKEN:
                sharedClusterToken = trimString(optarg);
                break;
            case OPT_CHILD_NODE: {
                ChildNodeInfo node;
                if (!parseChildNodeSpec(optarg, node)) {
                    std::cerr << "Invalid --child-node format, expected id:addr[:ssh[:cluster[:name]]], got: "
                              << optarg << std::endl;
                    return 1;
                }
                cliChildNodes.push_back(node);
                break;
            }
            case OPT_DEFAULT_TARGET_USER:
                defaultTargetUser = optarg;
                break;
            case OPT_DEFAULT_TARGET_PASSWORD:
                defaultTargetPassword = optarg;
                break;
            case OPT_DEFAULT_TARGET_PRIVATE_KEY:
                defaultTargetPrivateKey = optarg;
                break;
            case OPT_DEFAULT_TARGET_KEY_PASSWORD:
                defaultTargetKeyPassword = optarg;
                break;
            case OPT_RT_PORT_START:
                reverseTunnelPortStart = safeStringToInt(optarg, 38000);
                break;
            case OPT_RT_PORT_END:
                reverseTunnelPortEnd = safeStringToInt(optarg, 38199);
                break;
            case OPT_RT_RETRIES:
                reverseTunnelRetries = safeStringToInt(optarg, 3);
                break;
            case OPT_RT_ACCEPT_TIMEOUT_MS:
                reverseTunnelAcceptTimeoutMs = safeStringToInt(optarg, 7000);
                break;
            case OPT_MAX_CONNECTIONS_PER_MINUTE:
                maxConnectionsPerMinute = safeStringToInt(optarg, 0);
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

    if (reverseTunnelPortStart <= 0 || reverseTunnelPortStart > 65535 ||
        reverseTunnelPortEnd <= 0 || reverseTunnelPortEnd > 65535 ||
        reverseTunnelPortStart > reverseTunnelPortEnd) {
        std::cerr << "Invalid reverse tunnel port range: "
                  << reverseTunnelPortStart << "-" << reverseTunnelPortEnd << std::endl;
        return 1;
    }
    if (reverseTunnelRetries <= 0 || reverseTunnelRetries > 20) {
        std::cerr << "Invalid reverse tunnel retries: " << reverseTunnelRetries << std::endl;
        return 1;
    }
    if (reverseTunnelAcceptTimeoutMs <= 0 || reverseTunnelAcceptTimeoutMs > 120000) {
        std::cerr << "Invalid reverse tunnel accept timeout: " << reverseTunnelAcceptTimeoutMs << std::endl;
        return 1;
    }
    if (maxConnectionsPerMinute < 0 || maxConnectionsPerMinute > 100000) {
        std::cerr << "Invalid max connections per minute: " << maxConnectionsPerMinute << std::endl;
        return 1;
    }

    std::string generatedHostKeyDir;
    if (!generateEphemeralHostKeys(hostKeyPath, generatedHostKeyDir)) {
        std::cerr << "Failed to auto-generate host key" << std::endl;
        return 1;
    }
    generatedHostKeyGuard.path = generatedHostKeyDir;
    
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
    
    // 将命令行参数写入运行配置（不读取配置文件）
    auto& configManager = ConfigManager::getInstance();
    {
        auto& config = configManager.getServerConfig();
        config.ssh.listenAddress = sshListenAddr;
        config.ssh.port = sshPort;
        config.ssh.hostKeyPath = hostKeyPath;

        config.cluster.listenAddress = clusterListenAddr;
        config.cluster.port = agentPort;
        config.cluster.agentTokenFile.clear();
        config.cluster.reverseTunnelPortStart = reverseTunnelPortStart;
        config.cluster.reverseTunnelPortEnd = reverseTunnelPortEnd;
        config.cluster.reverseTunnelRetries = reverseTunnelRetries;
        config.cluster.reverseTunnelAcceptTimeoutMs = reverseTunnelAcceptTimeoutMs;

        config.assets.permissionsFile.clear();

        config.security.usersFile.clear();
        config.security.defaultTargetUser = defaultTargetUser;
        config.security.defaultTargetPassword = defaultTargetPassword;
        config.security.defaultTargetPrivateKey = defaultTargetPrivateKey;
        config.security.defaultTargetPrivateKeyPassword = defaultTargetKeyPassword;
        config.security.maxConnectionsPerMinute = maxConnectionsPerMinute;

        config.management.childNodesFile.clear();
    }

    {
        auto& config = configManager.getServerConfig();

        for (const auto& userSpec : cliUsers) {
            UserAuthInfo user;
            user.username = userSpec.first;
            user.passwordHash = sha256Hex(userSpec.second);
            user.enabled = true;
            config.users[user.username] = user;
            LOG_INFO("Loaded CLI user (plain password): " + user.username);
        }

        for (const auto& userSpec : cliUsersHash) {
            UserAuthInfo user;
            user.username = userSpec.first;
            user.passwordHash = userSpec.second;
            user.enabled = true;
            config.users[user.username] = user;
            LOG_INFO("Loaded CLI user-hash: " + user.username);
        }

        if (config.users.empty()) {
            UserAuthInfo defaultUser;
            defaultUser.username = "admin";
            defaultUser.passwordHash = sha256Hex("admin123");
            defaultUser.enabled = true;
            config.users[defaultUser.username] = defaultUser;
            LOG_WARN("No users configured, auto-created default user admin/admin123");
        }
    }

    if (!configManager.validate()) {
        LOG_FATAL("Invalid runtime configuration from command line arguments");
        ssh_finalize();
        return 1;
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
    if (!clusterManager->initialize(clusterConfig.listenAddress, clusterConfig.port, eventLoop)) {
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

    if (!sharedClusterToken.empty()) {
        clusterManager->setSharedToken(sharedClusterToken);
        LOG_INFO("Loaded shared cluster token from --token");
    }
    
    if (sharedClusterToken.empty()) {
        LOG_FATAL("No cluster token configured. Provide --token.");
        removePidFile(pidFile);
        ssh_finalize();
        return 1;
    }
    
    if (!clusterManager->start()) {
        LOG_FATAL("Failed to start cluster manager");
        removePidFile(pidFile);
        ssh_finalize();
        return 1;
    }
    
    LOG_INFO("Cluster Manager started on port " + std::to_string(clusterConfig.port));
    
    // 创建资产管理器
    auto assetManager = std::make_shared<AssetManager>();
    assetManager->initialize(clusterManager);

    // 创建并加载子节点注册表（公网管理节点配置，纯 CLI）
    auto nodeRegistry = std::make_shared<ChildNodeRegistry>();
    for (const auto& node : cliChildNodes) {
        if (!nodeRegistry->createNode(node, true)) {
            LOG_WARN("Failed to create CLI child node: " + node.nodeId);
        }
    }
    LOG_INFO("Child node registry ready, count=" + std::to_string(nodeRegistry->size()));
    
    // 权限策略简化：所有已配置用户默认允许访问全部资产
    const auto& users = configManager.getServerConfig().users;
    for (const auto& pair : users) {
        if (!pair.second.enabled) {
            continue;
        }
        UserPermission permission;
        permission.username = pair.first;
        permission.allowAll = true;
        assetManager->upsertUserPermission(permission);
    }
    LOG_INFO("Permissions initialized: allow_all=true for all configured users");
    
    // 创建并启动 SSH 服务器
    auto sshServer = std::make_unique<SSHServer>();
    auto& sshConfig = configManager.getServerConfig().ssh;
    if (!sshServer->initialize(sshConfig.listenAddress, sshConfig.port, sshConfig.hostKeyPath, eventLoop)) {
        LOG_FATAL("Failed to initialize SSH server");
        removePidFile(pidFile);
        ssh_finalize();
        return 1;
    }
    
    // 设置集群管理器和资产管理器
    sshServer->setClusterManager(clusterManager);
    sshServer->setAssetManager(assetManager);
    sshServer->setNodeRegistry(nodeRegistry);
    const int rateLimitPerMinute = configManager.getServerConfig().security.maxConnectionsPerMinute;
    sshServer->setConnectionRateLimitPerMinute(rateLimitPerMinute);
    if (rateLimitPerMinute <= 0) {
        LOG_INFO("Connection rate limit disabled");
    } else {
        LOG_INFO("Connection rate limit set to " +
                 std::to_string(rateLimitPerMinute) +
                 " per minute per IP");
    }
    
    if (!sshServer->start()) {
        LOG_FATAL("Failed to start SSH server");
        removePidFile(pidFile);
        ssh_finalize();
        return 1;
    }
    
    LOG_INFO("SSH Server started on port " + std::to_string(sshConfig.port));
    LOG_INFO("JumpServer-style interactive access enabled");
    LOG_INFO("Direct connect: ssh -p " + std::to_string(sshConfig.port) + " username@<server> <asset>");
    LOG_INFO("Interactive: ssh -p " + std::to_string(sshConfig.port) + " username@<server>");
    
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
