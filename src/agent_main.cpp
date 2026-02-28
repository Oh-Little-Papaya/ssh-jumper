/**
 * @file agent_main.cpp
 * @brief 内网机器Agent客户端主程序
 * 
 * 此程序运行在内网机器上，用于向跳板机注册并提供服务
 */

#include "common.h"
#include "cluster_manager.h"
#include "config_manager.h"

#include <getopt.h>

using namespace sshjump;

// 全局运行标志
static std::atomic<bool> g_running{true};

// 信号处理
void signalHandler(int sig) {
    LOG_INFO("Received signal " + std::to_string(sig) + ", shutting down...");
    g_running = false;
}

// 打印帮助信息
void printUsage(const char* program) {
    std::cout << "Usage: " << program << " [options]\n"
              << "\nOptions:\n"
              << "  -s, --server <addr>     Jump server address (required)\n"
              << "  -p, --port <port>       Jump server cluster port (default: 8888)\n"
              << "  -i, --id <id>           Agent ID (default: auto-generated)\n"
              << "  -t, --token <token>     Authentication token (required)\n"
              << "  -n, --hostname <name>   Hostname to register\n"
              << "  -I, --ip <ip>           Local IP address to report (auto-detect if not set)\n"
              << "  -S, --service <spec>    Service to expose (format: name:type:port)\n"
              << "  -c, --config <path>     Configuration file\n"
              << "  -d, --daemon            Run as daemon\n"
              << "  -v, --verbose           Verbose output\n"
              << "  -h, --help              Show this help message\n"
              << "  -V, --version           Show version information\n"
              << "\nExamples:\n"
              << "  " << program << " -s jump.example.com -t mysecrettoken -S ssh:ssh:22\n"
              << "  " << program << " -s 192.168.1.100 -p 8888 -i web-01 -t token -I 192.168.1.10 -S web:http:80\n"
              << "  " << program << " -c /etc/ssh_jump/agent.conf -d\n";
}

// 打印版本信息
void printVersion() {
    std::cout << "SSH Jump Agent v" << VERSION << "\n"
              << "Copyright (c) 2024\n";
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
    
    const int fd0 = open("/dev/null", O_RDONLY);
    const int fd1 = open("/dev/null", O_WRONLY);
    const int fd2 = open("/dev/null", O_WRONLY);
    if (fd0 < 0 || fd1 < 0 || fd2 < 0) {
        LOG_ERROR("Failed to redirect standard streams");
        return false;
    }
    
    return true;
}

// 从配置文件加载
bool loadConfig(const std::string& path, 
                std::string& serverAddr, 
                int& serverPort,
                std::string& agentId,
                std::string& authToken,
                std::string& hostname,
                std::string& localIp,
                std::vector<ServiceInfo>& services) {
    std::ifstream file(path);
    if (!file.is_open()) {
        LOG_ERROR("Failed to open config file: " + path);
        return false;
    }
    
    std::string line;
    std::string currentSection;
    
    while (std::getline(file, line)) {
        line = trimString(line);
        
        if (line.empty() || line[0] == '#' || line[0] == ';') {
            continue;
        }
        
        if (line[0] == '[' && line[line.size() - 1] == ']') {
            currentSection = line.substr(1, line.size() - 2);
            continue;
        }
        
        size_t pos = line.find('=');
        if (pos == std::string::npos) {
            continue;
        }
        
        std::string key = trimString(line.substr(0, pos));
        std::string value = trimString(line.substr(pos + 1));
        
        if (value.size() >= 2 && value[0] == '"' && value[value.size() - 1] == '"') {
            value = value.substr(1, value.size() - 2);
        }
        
        if (currentSection == "server") {
            if (key == "address") serverAddr = value;
            else if (key == "port") serverPort = safeStringToInt(value, DEFAULT_CLUSTER_PORT);
        }
        else if (currentSection == "agent") {
            if (key == "id") agentId = value;
            else if (key == "token") authToken = value;
            else if (key == "hostname") hostname = value;
            else if (key == "ip") localIp = value;
        }
        else if (currentSection == "service" && key == "expose") {
            // 解析服务规格: name:type:port[:description]
            auto parts = splitString(value, ':');
            if (parts.size() >= 3) {
                ServiceInfo service;
                service.name = parts[0];
                service.type = parts[1];
                service.port = safeStringToInt(parts[2], 22);
                if (parts.size() > 3) {
                    service.description = parts[3];
                }
                services.push_back(service);
            }
        }
    }
    
    file.close();
    return true;
}

// 解析服务规格
bool parseServiceSpec(const std::string& spec, ServiceInfo& service) {
    auto parts = splitString(spec, ':');
    if (parts.size() < 3) {
        return false;
    }

    service.name = parts[0];
    service.type = parts[1];
    service.port = safeStringToInt(parts[2], 22);

    // 可选的描述字段
    if (parts.size() > 3) {
        service.description = parts[3];
    }

    return true;
}

int main(int argc, char* argv[]) {
    // 配置参数
    std::string serverAddr;
    int serverPort = DEFAULT_CLUSTER_PORT;
    std::string agentId = generateUUID().substr(0, 8);
    std::string authToken;
    std::string hostname;
    std::string localIp;
    std::vector<ServiceInfo> services;
    std::string configPath;
    bool runAsDaemon = false;
    bool verbose = false;
    
    // 命令行参数解析
    static struct option longOptions[] = {
        {"server", required_argument, nullptr, 's'},
        {"port", required_argument, nullptr, 'p'},
        {"id", required_argument, nullptr, 'i'},
        {"token", required_argument, nullptr, 't'},
        {"hostname", required_argument, nullptr, 'n'},
        {"ip", required_argument, nullptr, 'I'},
        {"service", required_argument, nullptr, 'S'},
        {"config", required_argument, nullptr, 'c'},
        {"daemon", no_argument, nullptr, 'd'},
        {"verbose", no_argument, nullptr, 'v'},
        {"help", no_argument, nullptr, 'h'},
        {"version", no_argument, nullptr, 'V'},
        {nullptr, 0, nullptr, 0}
    };
    
    int opt;
    while ((opt = getopt_long(argc, argv, "s:p:i:t:n:I:S:c:dvhV", longOptions, nullptr)) != -1) {
        switch (opt) {
            case 's':
                serverAddr = optarg;
                break;
            case 'p':
                serverPort = safeStringToInt(optarg, DEFAULT_CLUSTER_PORT);
                if (serverPort <= 0 || serverPort > 65535) {
                    std::cerr << "Invalid port: " << optarg << std::endl;
                    return 1;
                }
                break;
            case 'i':
                agentId = optarg;
                break;
            case 't':
                authToken = optarg;
                break;
            case 'n':
                hostname = optarg;
                break;
            case 'I':
                localIp = optarg;
                break;
            case 'S': {
                ServiceInfo service;
                if (parseServiceSpec(optarg, service)) {
                    services.push_back(service);
                } else {
                    std::cerr << "Invalid service spec: " << optarg << std::endl;
                    return 1;
                }
                break;
            }
            case 'c':
                configPath = optarg;
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
    
    // 加载配置文件
    if (!configPath.empty()) {
        if (!loadConfig(configPath, serverAddr, serverPort, agentId, authToken, hostname, localIp, services)) {
            LOG_WARN("Failed to load config file: " + configPath);
        }
    }
    
    // 验证必需参数
    if (serverAddr.empty()) {
        std::cerr << "Error: Server address is required (-s option)" << std::endl;
        printUsage(argv[0]);
        return 1;
    }
    
    if (authToken.empty()) {
        std::cerr << "Error: Authentication token is required (-t option)" << std::endl;
        printUsage(argv[0]);
        return 1;
    }
    
    // 如果没有指定服务，添加默认SSH服务
    if (services.empty()) {
        ServiceInfo sshService;
        sshService.name = "ssh";
        sshService.type = "ssh";
        sshService.port = 22;
        services.push_back(sshService);
        LOG_INFO("No services specified, using default SSH service on port 22");
    }
    
    // 如果没有指定主机名，使用Agent ID
    if (hostname.empty()) {
        hostname = "agent-" + agentId;
    }
    
    // 打印配置信息
    LOG_INFO("Agent Configuration:");
    LOG_INFO("  Server: " + serverAddr + ":" + std::to_string(serverPort));
    LOG_INFO("  Agent ID: " + agentId);
    LOG_INFO("  Hostname: " + hostname);
    LOG_INFO("  Local IP: " + (localIp.empty() ? std::string("(auto-detect)") : localIp));
    LOG_INFO("  Services:");
    for (const auto& service : services) {
        LOG_INFO("    - " + service.name + " (" + service.type + "):" + std::to_string(service.port));
    }
    
    // 守护进程化
    if (runAsDaemon) {
        LOG_INFO("Running as daemon...");
        if (!daemonize()) {
            LOG_FATAL("Failed to daemonize");
            return 1;
        }
    }
    
    // 设置信号处理
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
    signal(SIGPIPE, SIG_IGN);
    
    // 创建Agent客户端
    ClusterAgentClient agent;
    
    if (!agent.initialize(serverAddr, serverPort, agentId, authToken, hostname, localIp)) {
        LOG_FATAL("Failed to initialize agent");
        return 1;
    }
    
    agent.setServices(services);
    
    // 注册到集群
    LOG_INFO("Registering to cluster...");
    if (!agent.registerToCluster(services)) {
        LOG_FATAL("Failed to register to cluster");
        return 1;
    }
    
    // 启动Agent
    LOG_INFO("Starting agent worker...");
    agent.start();
    
    LOG_INFO("Agent started successfully");
    
    // 主循环 - 使用短 sleep 周期检查 g_running
    int checkInterval = 0;
    while (g_running) {
        // 每 100ms 检查一次，以便快速响应 Ctrl+C
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        checkInterval++;
        
        // 每秒检查一次连接状态
        if (checkInterval >= 10) {
            checkInterval = 0;
            
            // 检查连接状态
            if (!agent.isConnected()) {
                LOG_WARN("Connection lost, attempting to reconnect...");
                
                // 尝试重新注册
                if (!agent.registerToCluster(services)) {
                    LOG_ERROR("Reconnection failed, will retry...");
                }
            }
        }
    }
    
    // 注销并停止
    LOG_INFO("Unregistering from cluster...");
    agent.unregister();
    agent.stop();
    
    LOG_INFO("Agent stopped");
    
    return 0;
}
