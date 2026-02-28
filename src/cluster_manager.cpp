/**
 * @file cluster_manager.cpp
 * @brief 集群管理器实现
 */

#include "cluster_manager.h"
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <cctype>

#ifdef SSHJUMP_USE_FOLLY
#include <folly/executors/CPUThreadPoolExecutor.h>
#endif

namespace sshjump {

namespace {

constexpr int kConnectTimeoutMs = 5000;
constexpr int kDefaultTunnelAcceptTimeoutMs = 7000;
constexpr int kDefaultReverseTunnelPortStart = 38000;
constexpr int kDefaultReverseTunnelPortEnd = 38199;
constexpr int kDefaultReverseTunnelRetries = 3;
constexpr int kSendTimeoutMs = 5000;

std::string extractJsonStringValue(const std::string& payload, const std::string& key) {
    const std::string searchKey = "\"" + key + "\":\"";
    const size_t pos = payload.find(searchKey);
    if (pos == std::string::npos) {
        return "";
    }

    const size_t valueStart = pos + searchKey.length();
    const size_t valueEnd = payload.find('"', valueStart);
    if (valueEnd == std::string::npos) {
        return "";
    }

    return payload.substr(valueStart, valueEnd - valueStart);
}

int extractJsonIntValue(const std::string& payload, const std::string& key, int defaultValue = 0) {
    const std::string searchKey = "\"" + key + "\":";
    const size_t pos = payload.find(searchKey);
    if (pos == std::string::npos) {
        return defaultValue;
    }

    size_t valueStart = pos + searchKey.length();
    while (valueStart < payload.size() && std::isspace(static_cast<unsigned char>(payload[valueStart]))) {
        ++valueStart;
    }

    size_t valueEnd = valueStart;
    if (valueEnd < payload.size() && payload[valueEnd] == '-') {
        ++valueEnd;
    }
    while (valueEnd < payload.size() && std::isdigit(static_cast<unsigned char>(payload[valueEnd]))) {
        ++valueEnd;
    }

    if (valueEnd == valueStart) {
        return defaultValue;
    }

    return safeStringToInt(payload.substr(valueStart, valueEnd - valueStart), defaultValue);
}

bool isWildcardAddress(const std::string& address) {
    return address.empty() || address == "0.0.0.0" || address == "::";
}

std::string sockaddrToIp(const struct sockaddr* addr) {
    if (!addr) {
        return "";
    }

    char ipBuf[INET6_ADDRSTRLEN] = {0};
    if (addr->sa_family == AF_INET) {
        const auto* v4 = reinterpret_cast<const struct sockaddr_in*>(addr);
        if (inet_ntop(AF_INET, &v4->sin_addr, ipBuf, sizeof(ipBuf))) {
            return ipBuf;
        }
        return "";
    }

    if (addr->sa_family == AF_INET6) {
        const auto* v6 = reinterpret_cast<const struct sockaddr_in6*>(addr);
        if (inet_ntop(AF_INET6, &v6->sin6_addr, ipBuf, sizeof(ipBuf))) {
            return ipBuf;
        }
    }

    return "";
}

std::string getSocketLocalIp(int fd) {
    if (fd < 0) {
        return "";
    }

    struct sockaddr_storage localAddr;
    socklen_t localLen = sizeof(localAddr);
    memset(&localAddr, 0, sizeof(localAddr));
    if (getsockname(fd, reinterpret_cast<struct sockaddr*>(&localAddr), &localLen) != 0) {
        return "";
    }

    return sockaddrToIp(reinterpret_cast<struct sockaddr*>(&localAddr));
}

int createTcpListener(const std::string& bindHost, int bindPort, int* actualPort) {
    if (actualPort) {
        *actualPort = 0;
    }

    if (bindPort <= 0 || bindPort > 65535) {
        return -1;
    }

    struct addrinfo hints;
    struct addrinfo* result = nullptr;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    const std::string service = std::to_string(bindPort);
    const char* node = bindHost.empty() ? nullptr : bindHost.c_str();
    const int gaiRet = getaddrinfo(node, service.c_str(), &hints, &result);
    if (gaiRet != 0 || !result) {
        LOG_WARN("Failed to resolve listener address " +
                 (bindHost.empty() ? std::string("*") : bindHost) + ":" + service +
                 " - " + std::string(gai_strerror(gaiRet)));
        return -1;
    }

    int listenFd = -1;
    for (auto* ai = result; ai != nullptr; ai = ai->ai_next) {
        listenFd = socket(ai->ai_family, ai->ai_socktype | SOCK_CLOEXEC, ai->ai_protocol);
        if (listenFd < 0) {
            continue;
        }

        setReuseAddr(listenFd);
#ifdef IPV6_V6ONLY
        if (ai->ai_family == AF_INET6) {
            int v6only = 0;
            setsockopt(listenFd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only));
        }
#endif

        if (bind(listenFd, ai->ai_addr, ai->ai_addrlen) != 0) {
            closeSocket(listenFd);
            continue;
        }

        if (listen(listenFd, 1) != 0) {
            closeSocket(listenFd);
            continue;
        }

        struct sockaddr_storage boundAddr;
        socklen_t boundLen = sizeof(boundAddr);
        if (getsockname(listenFd, reinterpret_cast<struct sockaddr*>(&boundAddr), &boundLen) == 0) {
            if (boundAddr.ss_family == AF_INET) {
                const auto* v4 = reinterpret_cast<const struct sockaddr_in*>(&boundAddr);
                if (actualPort) {
                    *actualPort = ntohs(v4->sin_port);
                }
            } else if (boundAddr.ss_family == AF_INET6) {
                const auto* v6 = reinterpret_cast<const struct sockaddr_in6*>(&boundAddr);
                if (actualPort) {
                    *actualPort = ntohs(v6->sin6_port);
                }
            }
        }

        if (actualPort && *actualPort == 0) {
            *actualPort = bindPort;
        }
        break;
    }

    freeaddrinfo(result);
    return listenFd;
}

bool sendAllWithTimeout(int fd, const uint8_t* data, size_t len, int timeoutMs) {
    if (fd < 0 || !data) {
        return false;
    }

    size_t totalSent = 0;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);

    while (totalSent < len) {
        const ssize_t n = send(fd, data + totalSent, len - totalSent, MSG_NOSIGNAL);
        if (n > 0) {
            totalSent += static_cast<size_t>(n);
            continue;
        }

        if (n < 0 && errno == EINTR) {
            continue;
        }

        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            const auto now = std::chrono::steady_clock::now();
            if (now >= deadline) {
                return false;
            }

            const int waitMs = static_cast<int>(
                std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count());
            struct pollfd pfd{fd, POLLOUT, 0};
            const int ret = poll(&pfd, 1, waitMs);
            if (ret <= 0) {
                return false;
            }
            continue;
        }

        return false;
    }

    return true;
}

int connectTcpWithTimeout(const std::string& host, int port, int timeoutMs) {
    if (host.empty() || port <= 0 || port > 65535) {
        return -1;
    }

    struct addrinfo hints;
    struct addrinfo* result = nullptr;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    const std::string service = std::to_string(port);
    const int gaiRet = getaddrinfo(host.c_str(), service.c_str(), &hints, &result);
    if (gaiRet != 0 || !result) {
        LOG_ERROR("Failed to resolve address " + host + ":" + service + " - " + std::string(gai_strerror(gaiRet)));
        return -1;
    }

    int sockFd = -1;
    for (auto* ai = result; ai != nullptr; ai = ai->ai_next) {
        sockFd = socket(ai->ai_family, ai->ai_socktype | SOCK_CLOEXEC, ai->ai_protocol);
        if (sockFd < 0) {
            continue;
        }

        setTcpNoDelay(sockFd);
        if (setNonBlocking(sockFd) < 0) {
            closeSocket(sockFd);
            continue;
        }

        int ret = ::connect(sockFd, ai->ai_addr, ai->ai_addrlen);
        if (ret < 0 && errno != EINPROGRESS) {
            closeSocket(sockFd);
            continue;
        }

        if (ret < 0) {
            struct pollfd pfd{sockFd, POLLOUT, 0};
            ret = poll(&pfd, 1, timeoutMs);
            if (ret <= 0) {
                closeSocket(sockFd);
                continue;
            }

            int error = 0;
            socklen_t len = sizeof(error);
            if (getsockopt(sockFd, SOL_SOCKET, SO_ERROR, &error, &len) < 0 || error != 0) {
                closeSocket(sockFd);
                continue;
            }
        }

        // 连接成功后恢复阻塞模式，便于后续 libssh 握手
        int flags = fcntl(sockFd, F_GETFL, 0);
        if (flags >= 0) {
            fcntl(sockFd, F_SETFL, flags & ~O_NONBLOCK);
        }

        break;
    }

    freeaddrinfo(result);
    return sockFd;
}

void bridgeSocketPair(int leftFd, int rightFd) {
    if (leftFd < 0 || rightFd < 0) {
        return;
    }

    setNonBlocking(leftFd);
    setNonBlocking(rightFd);

    char buffer[DEFAULT_BUFFER_SIZE];

    while (true) {
        struct pollfd pfds[2];
        pfds[0].fd = leftFd;
        pfds[0].events = POLLIN;
        pfds[0].revents = 0;
        pfds[1].fd = rightFd;
        pfds[1].events = POLLIN;
        pfds[1].revents = 0;

        const int ret = poll(pfds, 2, 60 * 1000);
        if (ret < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }

        if (ret == 0) {
            continue;
        }

        if (pfds[0].revents & (POLLERR | POLLHUP | POLLNVAL)) {
            break;
        }
        if (pfds[1].revents & (POLLERR | POLLHUP | POLLNVAL)) {
            break;
        }

        if (pfds[0].revents & POLLIN) {
            const ssize_t n = recv(leftFd, buffer, sizeof(buffer), 0);
            if (n <= 0 || !sendAllWithTimeout(rightFd, reinterpret_cast<const uint8_t*>(buffer),
                                               static_cast<size_t>(n), kSendTimeoutMs)) {
                break;
            }
        }

        if (pfds[1].revents & POLLIN) {
            const ssize_t n = recv(rightFd, buffer, sizeof(buffer), 0);
            if (n <= 0 || !sendAllWithTimeout(leftFd, reinterpret_cast<const uint8_t*>(buffer),
                                              static_cast<size_t>(n), kSendTimeoutMs)) {
                break;
            }
        }
    }
}

void submitForwardTask(std::function<void()> task) {
#ifdef SSHJUMP_USE_FOLLY
    static std::shared_ptr<folly::CPUThreadPoolExecutor> executor = []() {
        auto ex = std::make_shared<folly::CPUThreadPoolExecutor>(4);
        LOG_INFO("Forward task executor initialized with Folly CPUThreadPoolExecutor");
        return ex;
    }();
    executor->add(std::move(task));
#else
    std::thread(std::move(task)).detach();
#endif
}

} // namespace

// ============================================
// AgentMessage 实现
// ============================================

std::vector<uint8_t> AgentMessage::serialize() const {
    std::vector<uint8_t> data;
    data.reserve(9 + payload.length());
    
    // Magic (4 bytes)
    data.push_back((magic >> 24) & 0xFF);
    data.push_back((magic >> 16) & 0xFF);
    data.push_back((magic >> 8) & 0xFF);
    data.push_back(magic & 0xFF);
    
    // Type (1 byte)
    data.push_back(static_cast<uint8_t>(type));
    
    // Length (4 bytes)
    data.push_back((length >> 24) & 0xFF);
    data.push_back((length >> 16) & 0xFF);
    data.push_back((length >> 8) & 0xFF);
    data.push_back(length & 0xFF);
    
    // Payload
    data.insert(data.end(), payload.begin(), payload.end());
    
    return data;
}

bool AgentMessage::deserialize(const uint8_t* data, size_t len, AgentMessage& msg) {
    if (len < 9) {
        return false;
    }
    
    // Magic
    msg.magic = (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3];
    if (msg.magic != MAGIC_NUMBER) {
        return false;
    }
    
    // Type
    msg.type = static_cast<AgentMessageType>(data[4]);
    
    // Length
    msg.length = (data[5] << 24) | (data[6] << 16) | (data[7] << 8) | data[8];
    
    if (len < 9 + msg.length) {
        return false;
    }
    
    // Payload
    msg.payload.assign(reinterpret_cast<const char*>(data + 9), msg.length);
    
    return true;
}

AgentMessage AgentMessage::create(AgentMessageType type, const std::string& payload) {
    AgentMessage msg;
    msg.magic = MAGIC_NUMBER;
    msg.type = type;
    msg.length = payload.length();
    msg.payload = payload;
    return msg;
}

// ============================================
// AgentConnection 实现
// ============================================

AgentConnection::AgentConnection(int fd, ClusterManager* manager)
    : fd_(fd)
    , manager_(manager) {
}

AgentConnection::~AgentConnection() {
    close();
}

bool AgentConnection::initialize() {
    setNonBlocking(fd_);
    return true;
}

int AgentConnection::onRead() {
    char buffer[DEFAULT_BUFFER_SIZE];
    ssize_t n = recv(fd_, buffer, sizeof(buffer), 0);
    
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0;
        }
        return -1;
    }
    
    if (n == 0) {
        return -1;  // 连接关闭
    }
    
    readBuffer_.append(buffer, n);
    
    // 尝试解析消息
    while (readBuffer_.readableBytes() >= 9) {
        AgentMessage msg;
        if (AgentMessage::deserialize(
                reinterpret_cast<const uint8_t*>(readBuffer_.readableData()),
                readBuffer_.readableBytes(), msg)) {
            
            handleMessage(msg);
            readBuffer_.retrieve(9 + msg.length);
        } else {
            break;
        }
    }
    
    return 0;
}

int AgentConnection::onWrite() {
    std::lock_guard<std::mutex> lock(mutex_);

    if (writeBuffer_.readableBytes() == 0) {
        return 0;
    }
    
    ssize_t n = send(fd_, writeBuffer_.readableData(), writeBuffer_.readableBytes(), MSG_NOSIGNAL);
    
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0;
        }
        return -1;
    }
    
    writeBuffer_.retrieve(n);
    return 0;
}

void AgentConnection::onError() {
    LOG_ERROR("Agent connection error: " + agentId_);
    close();
}

void AgentConnection::onClose() {
    LOG_INFO("Agent connection closed: " + agentId_);
    close();
}

void AgentConnection::handleMessage(const AgentMessage& msg) {
    switch (msg.type) {
        case AgentMessageType::REGISTER:
            handleRegister(msg.payload);
            break;
        case AgentMessageType::HEARTBEAT:
            handleHeartbeat(msg.payload);
            break;
        case AgentMessageType::UNREGISTER:
            handleUnregister(msg.payload);
            break;
        default:
            LOG_WARN("Unknown message type: " + std::to_string(static_cast<int>(msg.type)));
            break;
    }
}

void AgentConnection::handleRegister(const std::string& payload) {
    // 解析 JSON 注册信息
    // 格式: {"agentId":"xxx","hostname":"xxx","ipAddress":"xxx","authToken":"xxx","services":[...]}
    
    auto extractString = [&payload](const std::string& key) -> std::string {
        std::string searchKey = "\"" + key + "\":\"";
        size_t pos = payload.find(searchKey);
        if (pos == std::string::npos) return "";
        pos += searchKey.length();
        size_t endPos = payload.find("\"", pos);
        if (endPos == std::string::npos) return "";
        return payload.substr(pos, endPos - pos);
    };
    
    AgentInfo info;
    info.agentId = extractString("agentId");
    info.hostname = extractString("hostname");
    info.ipAddress = extractString("ipAddress");
    info.authToken = extractString("authToken");
    
    if (info.agentId.empty()) {
        LOG_WARN("Invalid register payload: missing agentId");
        sendResponse(false, "Missing agentId");
        return;
    }
    
    // 解析 services 数组 (简化解析)
    size_t servicesPos = payload.find("\"services\":");
    if (servicesPos != std::string::npos) {
        size_t arrStart = payload.find("[", servicesPos);
        size_t arrEnd = payload.find("]", arrStart);
        if (arrStart != std::string::npos && arrEnd != std::string::npos) {
            std::string servicesStr = payload.substr(arrStart + 1, arrEnd - arrStart - 1);
            // 简化的服务解析，每个服务格式: {"name":"xxx","type":"yyy","port":zzz}
            size_t pos = 0;
            while ((pos = servicesStr.find("{", pos)) != std::string::npos) {
                size_t endPos = servicesStr.find("}", pos);
                if (endPos == std::string::npos) break;
                
                std::string svcStr = servicesStr.substr(pos, endPos - pos + 1);
                ServiceInfo svc;
                
                auto extractSvcString = [&svcStr](const std::string& key) -> std::string {
                    std::string searchKey = "\"" + key + "\":\"";
                    size_t p = svcStr.find(searchKey);
                    if (p == std::string::npos) return "";
                    p += searchKey.length();
                    size_t ep = svcStr.find("\"", p);
                    if (ep == std::string::npos) return "";
                    return svcStr.substr(p, ep - p);
                };
                
                svc.name = extractSvcString("name");
                svc.type = extractSvcString("type");

                // 解析 port 数字（安全处理）
                size_t portPos = svcStr.find("\"port\":");
                if (portPos != std::string::npos) {
                    portPos += 7; // length of "\"port\":"
                    std::string portStr = svcStr.substr(portPos);
                    // 提取数字部分（直到遇到非数字字符）
                    std::string portNum;
                    for (char c : portStr) {
                        if (std::isdigit(c)) {
                            portNum += c;
                        } else {
                            break;
                        }
                    }
                    if (!portNum.empty()) {
                        try {
                            svc.port = std::stoi(portNum);
                        } catch (...) {
                            svc.port = 22;  // 默认 SSH 端口
                        }
                    }
                }
                
                info.services.push_back(svc);
                pos = endPos + 1;
            }
        }
    }
    
    // 设置连接 fd 并注册
    info.controlFd = fd_;
    if (manager_->registerAgent(info, fd_)) {
        agentId_ = info.agentId;
        LOG_INFO("Agent registered: " + agentId_ + " (" + info.hostname + "), services: " + std::to_string(info.services.size()));
        sendResponse(true, "Registered successfully");
    } else {
        LOG_WARN("Agent registration failed: " + info.agentId);
        sendResponse(false, "Registration failed");
    }
}

void AgentConnection::handleHeartbeat(const std::string& /*payload*/) {
    if (!agentId_.empty()) {
        manager_->updateHeartbeat(agentId_);
    }
    sendResponse(true, "Heartbeat received");
}

void AgentConnection::handleUnregister(const std::string& /*payload*/) {
    if (!agentId_.empty()) {
        manager_->unregisterAgent(agentId_);
    }
    sendResponse(true, "Unregistered successfully");
}

void AgentConnection::sendResponse(bool success, const std::string& message) {
    std::string payload = success ? "OK:" + message : "ERR:" + message;
    AgentMessage msg = AgentMessage::create(AgentMessageType::RESPONSE, payload);
    
    auto data = msg.serialize();
    {
        std::lock_guard<std::mutex> lock(mutex_);
        writeBuffer_.append(reinterpret_cast<const char*>(data.data()), data.size());
    }
    
    // 触发写入
    onWrite();
}

void AgentConnection::close() {
    // 防止重复关闭
    if (fd_ < 0) {
        return;
    }

    if (!agentId_.empty() && manager_) {
        manager_->unregisterAgent(agentId_);
        agentId_.clear();  // 清空，防止重复注销
    }
    if (manager_) {
        manager_->removeConnectionByFd(fd_);
    }
    closeSocket(fd_);
}

bool AgentConnection::sendMessage(const AgentMessage& msg) {
    auto data = msg.serialize();
    std::lock_guard<std::mutex> lock(mutex_);
    return sendAllWithTimeout(fd_, data.data(), data.size(), kSendTimeoutMs);
}

// ============================================
// ClusterManager 实现
// ============================================

ClusterManager::ClusterManager()
    : listenFd_(-1)
    , port_(DEFAULT_CLUSTER_PORT)
    , running_(false)
    , reverseTunnelPortStart_(kDefaultReverseTunnelPortStart)
    , reverseTunnelPortEnd_(kDefaultReverseTunnelPortEnd)
    , reverseTunnelRetries_(kDefaultReverseTunnelRetries)
    , reverseTunnelAcceptTimeoutMs_(kDefaultTunnelAcceptTimeoutMs)
    , reverseTunnelPortCursor_(kDefaultReverseTunnelPortStart) {
}

ClusterManager::~ClusterManager() {
    stop();
}

bool ClusterManager::initialize(const std::string& listenAddr, int port,
                                std::shared_ptr<IEventLoop> eventLoop) {
    listenAddr_ = listenAddr;
    port_ = port;
    eventLoop_ = eventLoop;
    
    // 绑定地址
    struct sockaddr_in6 addr6;
    struct sockaddr_in addr4;
    struct sockaddr* addr = nullptr;
    socklen_t addrLen = 0;
    int domain = AF_INET;
    
    // 先初始化内存
    memset(&addr6, 0, sizeof(addr6));
    memset(&addr4, 0, sizeof(addr4));
    
    // 检查地址类型并设置
    if (inet_pton(AF_INET6, listenAddr.c_str(), &addr6.sin6_addr) == 1) {
        addr6.sin6_family = AF_INET6;
        addr6.sin6_port = htons(port);
        addr = (struct sockaddr*)&addr6;
        addrLen = sizeof(addr6);
        domain = AF_INET6;
    } else if (inet_pton(AF_INET, listenAddr.c_str(), &addr4.sin_addr) == 1) {
        addr4.sin_family = AF_INET;
        addr4.sin_port = htons(port);
        addr = (struct sockaddr*)&addr4;
        addrLen = sizeof(addr4);
        domain = AF_INET;
    } else {
        LOG_ERROR("Invalid address: " + listenAddr);
        return false;
    }
    
    // 创建对应地址类型的监听 socket
    listenFd_ = socket(domain, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (listenFd_ < 0) {
        LOG_ERROR("Failed to create socket: " + std::string(strerror(errno)));
        return false;
    }
    
    setReuseAddr(listenFd_);
    
    if (bind(listenFd_, addr, addrLen) < 0) {
        LOG_ERROR("Failed to bind: " + std::string(strerror(errno)));
        closeSocket(listenFd_);
        return false;
    }
    
    if (listen(listenFd_, DEFAULT_BACKLOG) < 0) {
        LOG_ERROR("Failed to listen: " + std::string(strerror(errno)));
        closeSocket(listenFd_);
        return false;
    }
    
    LOG_INFO("ClusterManager initialized on " + listenAddr + ":" + std::to_string(port));
    return true;
}

void ClusterManager::setReverseTunnelOptions(int portStart, int portEnd, int retries, int acceptTimeoutMs) {
    if (portStart <= 0 || portStart > 65535 ||
        portEnd <= 0 || portEnd > 65535 || portStart > portEnd) {
        LOG_WARN("Invalid reverse tunnel port range provided, fallback to defaults");
        portStart = kDefaultReverseTunnelPortStart;
        portEnd = kDefaultReverseTunnelPortEnd;
    }
    if (retries <= 0) {
        LOG_WARN("Invalid reverse tunnel retries provided, fallback to default");
        retries = kDefaultReverseTunnelRetries;
    }
    if (acceptTimeoutMs <= 0) {
        LOG_WARN("Invalid reverse tunnel accept timeout provided, fallback to default");
        acceptTimeoutMs = kDefaultTunnelAcceptTimeoutMs;
    }

    reverseTunnelPortStart_ = portStart;
    reverseTunnelPortEnd_ = portEnd;
    reverseTunnelRetries_ = retries;
    reverseTunnelAcceptTimeoutMs_ = acceptTimeoutMs;
    reverseTunnelPortCursor_.store(portStart);

    LOG_INFO("Reverse tunnel options updated: ports=" +
             std::to_string(reverseTunnelPortStart_) + "-" + std::to_string(reverseTunnelPortEnd_) +
             ", retries=" + std::to_string(reverseTunnelRetries_) +
             ", acceptTimeoutMs=" + std::to_string(reverseTunnelAcceptTimeoutMs_));
}

std::tuple<int, int, int, int> ClusterManager::getReverseTunnelOptions() const {
    return std::make_tuple(reverseTunnelPortStart_, reverseTunnelPortEnd_,
                           reverseTunnelRetries_, reverseTunnelAcceptTimeoutMs_);
}

bool ClusterManager::start() {
    running_ = true;
    
    // 将监听 socket 添加到事件循环
    if (eventLoop_ && listenFd_ >= 0) {
        eventLoop_->addHandler(listenFd_, EventType::READ, shared_from_this());
        LOG_INFO("ClusterManager listening on fd: " + std::to_string(listenFd_));
    }
    
    // 启动定时器检查心跳
    timerThread_ = std::make_unique<TimerThread>();
    timerThread_->start();
    timerThread_->scheduleRepeat(std::chrono::seconds(30), [this]() {
        this->checkAgentHealth();
    });
    
    LOG_INFO("ClusterManager started");
    return true;
}

void ClusterManager::stop() {
    running_ = false;
    
    if (timerThread_) {
        timerThread_->stop();
    }
    
    closeSocket(listenFd_);
    
    // 关闭所有 Agent 连接
    std::lock_guard<std::mutex> lock(mutex_);
    pendingConnections_.clear();
    agentConnections_.clear();
    agents_.clear();
    
    LOG_INFO("ClusterManager stopped");
}

bool ClusterManager::registerAgent(const AgentInfo& info, int controlFd) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // 查找预配置
    auto configIt = agentConfigs_.find(info.agentId);
    auto tokenIt = agentTokens_.find(info.agentId);
    
    // 验证 token
    bool tokenValid = false;
    std::string effectiveIp = info.ipAddress;
    std::string effectiveHostname = info.hostname;
    std::vector<ServiceInfo> effectiveServices = info.services;
    
    if (configIt != agentConfigs_.end()) {
        // 使用预配置的完整配置
        if (configIt->second.token == info.authToken) {
            tokenValid = true;
            // 使用预配置的 IP（关键修改）
            effectiveIp = configIt->second.ipAddress;
            // 如果预配置了主机名，也使用预配置的
            if (!configIt->second.hostname.empty()) {
                effectiveHostname = configIt->second.hostname;
            }
            // 如果预配置了服务，合并或替换
            if (!configIt->second.services.empty()) {
                effectiveServices = configIt->second.services;
            }
            LOG_INFO("Using pre-configured IP for agent " + info.agentId + ": " + effectiveIp);
        }
    } else if (tokenIt != agentTokens_.end()) {
        // 简单格式，只验证 token
        if (tokenIt->second == info.authToken) {
            tokenValid = true;
            LOG_WARN("Agent " + info.agentId + " using simple token config, IP from agent: " + effectiveIp);
        }
    }
    
    if (!tokenValid) {
        LOG_WARN("Invalid token for agent: " + info.agentId);
        return false;
    }
    
    // 检查 IP 是否有效（不能是回环地址）
    if (effectiveIp == "127.0.0.1" || effectiveIp == "127.0.1.1" || effectiveIp.empty()) {
        LOG_ERROR("Invalid IP address for agent " + info.agentId + ": " + effectiveIp);
        LOG_ERROR("Please configure a valid IP in agent_tokens.conf");
        return false;
    }
    
    auto agent = std::make_shared<AgentInfo>(info);
    agent->ipAddress = effectiveIp;  // 使用预配置的 IP
    agent->hostname = effectiveHostname;  // 使用有效的主机名
    agent->services = effectiveServices;  // 使用有效的服务列表
    agent->isOnline = true;
    agent->registerTime = std::chrono::steady_clock::now();
    agent->lastHeartbeat = std::chrono::steady_clock::now();
    agent->controlFd = controlFd;
    
    agents_[info.agentId] = agent;
    hostnameToAgentId_[agent->hostname] = info.agentId;

    if (controlFd >= 0) {
        auto pendingIt = pendingConnections_.find(controlFd);
        if (pendingIt != pendingConnections_.end()) {
            agentConnections_[info.agentId] = pendingIt->second;
            pendingConnections_.erase(pendingIt);
        }
    }
    
    LOG_INFO("Agent registered: " + info.agentId + " (" + agent->hostname + ") at " + agent->ipAddress);
    return true;
}

void ClusterManager::unregisterAgent(const std::string& agentId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = agents_.find(agentId);
    if (it != agents_.end()) {
        if (it->second->controlFd >= 0) {
            pendingConnections_.erase(it->second->controlFd);
        }
        agentConnections_.erase(agentId);
        it->second->isOnline = false;
        hostnameToAgentId_.erase(it->second->hostname);
        agents_.erase(it);
        LOG_INFO("Agent unregistered: " + agentId);
    }
}

void ClusterManager::updateHeartbeat(const std::string& agentId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = agents_.find(agentId);
    if (it != agents_.end()) {
        it->second->lastHeartbeat = std::chrono::steady_clock::now();
        it->second->consecutiveFailures = 0;
    }
}

std::shared_ptr<AgentInfo> ClusterManager::getAgent(const std::string& agentId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = agents_.find(agentId);
    if (it != agents_.end()) {
        return it->second;
    }
    
    return nullptr;
}

std::shared_ptr<AgentInfo> ClusterManager::findAgentByHostname(const std::string& hostname) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = hostnameToAgentId_.find(hostname);
    if (it != hostnameToAgentId_.end()) {
        return agents_[it->second];
    }
    
    return nullptr;
}

std::vector<std::shared_ptr<AgentInfo>> ClusterManager::getAllAgents() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<std::shared_ptr<AgentInfo>> result;
    for (const auto& pair : agents_) {
        result.push_back(pair.second);
    }
    
    return result;
}

size_t ClusterManager::getOnlineAgentCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    size_t count = 0;
    for (const auto& pair : agents_) {
        if (pair.second->isOnline) {
            count++;
        }
    }
    
    return count;
}

bool ClusterManager::verifyAgentToken(const std::string& agentId, const std::string& token) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // 先检查完整配置
    auto configIt = agentConfigs_.find(agentId);
    if (configIt != agentConfigs_.end()) {
        return configIt->second.token == token;
    }
    
    // 再检查简单 token 格式
    auto tokenIt = agentTokens_.find(agentId);
    if (tokenIt != agentTokens_.end()) {
        return tokenIt->second == token;
    }
    
    return false;
}

int ClusterManager::establishForwardConnection(const std::string& agentId, int targetPort) {
    std::shared_ptr<AgentInfo> agent;
    std::shared_ptr<AgentConnection> controlConn;

    {
        std::lock_guard<std::mutex> lock(mutex_);

        auto it = agents_.find(agentId);
        if (it == agents_.end() || !it->second->isOnline) {
            LOG_ERROR("Agent not found or offline: " + agentId);
            return -1;
        }

        agent = it->second;

        auto connIt = agentConnections_.find(agentId);
        if (connIt != agentConnections_.end()) {
            controlConn = connIt->second;
        }
    }

    // 优先使用 Agent 回拨通道（适配 NAT 后主机）
    if (controlConn) {
        std::string connectBackHost = getSocketLocalIp(controlConn->getFd());
        if (isWildcardAddress(connectBackHost) && !isWildcardAddress(listenAddr_)) {
            connectBackHost = listenAddr_;
        }

        const int configuredRange = reverseTunnelPortEnd_ - reverseTunnelPortStart_ + 1;
        const int portRangeSize = configuredRange > 0 ? configuredRange : 1;
        const int maxAttempts = reverseTunnelRetries_ > 0 ? reverseTunnelRetries_ : 1;
        bool reverseTunnelEstablished = false;
        std::string lastReverseFailure = "unknown";

        for (int attempt = 1; attempt <= maxAttempts; ++attempt) {
            const int sequence = reverseTunnelPortCursor_.fetch_add(1);
            int offset = (sequence - reverseTunnelPortStart_) % portRangeSize;
            if (offset < 0) {
                offset += portRangeSize;
            }
            const int preferredPort = reverseTunnelPortStart_ + offset;

            std::string bindHost = connectBackHost;
            if (isWildcardAddress(bindHost)) {
                bindHost.clear();
            }

            int listenFd = -1;
            int connectBackPort = 0;
            listenFd = createTcpListener(bindHost, preferredPort, &connectBackPort);
            if (listenFd < 0) {
                lastReverseFailure = "listener_bind_failed";
                LOG_WARN("Reverse tunnel attempt " + std::to_string(attempt) + "/" +
                         std::to_string(maxAttempts) + " failed to bind callback listener for agent " +
                         agentId + " on port " + std::to_string(preferredPort));
                continue;
            }

            const std::string requestId = generateUUID();
            std::string payload = "{";
            payload += "\"requestId\":\"" + requestId + "\",";
            payload += "\"targetHost\":\"127.0.0.1\",";
            payload += "\"targetPort\":" + std::to_string(targetPort) + ",";
            payload += "\"connectBackPort\":" + std::to_string(connectBackPort);
            if (!connectBackHost.empty() && !isWildcardAddress(connectBackHost)) {
                payload += ",\"connectBackHost\":\"" + connectBackHost + "\"";
            }
            payload += "}";

            const AgentMessage request = AgentMessage::create(AgentMessageType::FORWARD_REQUEST, payload);
            if (!controlConn->sendMessage(request)) {
                lastReverseFailure = "send_forward_request_failed";
                LOG_WARN("Reverse tunnel attempt " + std::to_string(attempt) + "/" +
                         std::to_string(maxAttempts) + " failed to send FORWARD_REQUEST for agent " + agentId +
                         ", requestId=" + requestId + ", callbackPort=" + std::to_string(connectBackPort));
                closeSocket(listenFd);
                continue;
            }

            struct pollfd pfd{listenFd, POLLIN, 0};
            const int pollRet = poll(&pfd, 1, reverseTunnelAcceptTimeoutMs_);
            if (pollRet > 0 && (pfd.revents & POLLIN)) {
                const int tunnelFd = accept4(listenFd, nullptr, nullptr, SOCK_CLOEXEC);
                if (tunnelFd >= 0) {
                    setTcpNoDelay(tunnelFd);
                    closeSocket(listenFd);
                    reverseTunnelEstablished = true;
                    LOG_INFO("Reverse tunnel established for agent " + agentId +
                             ", requestId=" + requestId +
                             ", attempt=" + std::to_string(attempt) +
                             ", callbackPort=" + std::to_string(connectBackPort) +
                             ", targetPort=" + std::to_string(targetPort));
                    return tunnelFd;
                }
                lastReverseFailure = "accept_failed";
                LOG_WARN("Reverse tunnel attempt " + std::to_string(attempt) + "/" +
                         std::to_string(maxAttempts) + " accept failed for agent " + agentId +
                         ", requestId=" + requestId + ", callbackPort=" + std::to_string(connectBackPort) +
                         ", error=" + std::string(strerror(errno)));
            } else if (pollRet == 0) {
                lastReverseFailure = "accept_timeout";
                LOG_WARN("Reverse tunnel attempt " + std::to_string(attempt) + "/" +
                         std::to_string(maxAttempts) + " timed out for agent " + agentId +
                         ", requestId=" + requestId + ", callbackPort=" + std::to_string(connectBackPort) +
                         ", timeoutMs=" + std::to_string(reverseTunnelAcceptTimeoutMs_));
            } else {
                lastReverseFailure = "accept_poll_failed";
                LOG_WARN("Reverse tunnel attempt " + std::to_string(attempt) + "/" +
                         std::to_string(maxAttempts) + " poll failed for agent " + agentId +
                         ", requestId=" + requestId + ", callbackPort=" + std::to_string(connectBackPort) +
                         ", error=" + std::string(strerror(errno)));
            }

            closeSocket(listenFd);
        }

        if (!reverseTunnelEstablished) {
            LOG_WARN("Reverse tunnel exhausted for agent " + agentId +
                     ", retries=" + std::to_string(maxAttempts) +
                     ", lastFailure=" + lastReverseFailure +
                     ", fallback=direct_connect");
        }
    }

    // 回退到直连模式（兼容无 NAT 场景）
    const std::string targetIp = agent->ipAddress;
    if (targetIp.empty()) {
        LOG_ERROR("Agent has no IP address for direct connect: " + agentId);
        return -1;
    }

    int sockFd = connectTcpWithTimeout(targetIp, targetPort, kConnectTimeoutMs);
    if (sockFd < 0) {
        LOG_ERROR("Failed to establish direct forward connection to " + agentId +
                  " (" + targetIp + ":" + std::to_string(targetPort) + ")");
        return -1;
    }

    LOG_INFO("Direct forward connection established to agent " + agentId +
             " at " + targetIp + ":" + std::to_string(targetPort) +
             ", fd=" + std::to_string(sockFd));
    return sockFd;
}

int ClusterManager::onRead() {
    // 有新连接到来
    acceptConnection();
    return 0;
}

void ClusterManager::onError() {
    LOG_ERROR("ClusterManager error on listen socket");
}

void ClusterManager::onClose() {
    LOG_INFO("ClusterManager listen socket closed");
}

void ClusterManager::acceptConnection() {
    struct sockaddr_storage clientAddr;
    socklen_t addrLen = sizeof(clientAddr);
    
    int clientFd = accept4(listenFd_, (struct sockaddr*)&clientAddr, &addrLen,
                          SOCK_NONBLOCK | SOCK_CLOEXEC);
    
    if (clientFd < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            LOG_ERROR("Accept failed: " + std::string(strerror(errno)));
        }
        return;
    }
    
    // 创建 Agent 连接
    auto conn = std::make_shared<AgentConnection>(clientFd, this);
    conn->initialize();

    {
        std::lock_guard<std::mutex> lock(mutex_);
        pendingConnections_[clientFd] = conn;
    }
    
    // 添加到事件循环
    if (eventLoop_) {
        eventLoop_->addHandler(clientFd, EventType::READ | EventType::ERROR | EventType::HUP, conn);
    }
    
    LOG_INFO("New agent connection accepted");
}

void ClusterManager::removeConnectionByFd(int fd) {
    if (fd < 0) {
        return;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    pendingConnections_.erase(fd);
}

bool ClusterManager::loadAgentTokens(const std::string& configPath) {
    std::ifstream file(configPath);
    if (!file.is_open()) {
        LOG_WARN("Failed to open agent tokens file: " + configPath);
        return false;
    }
    
    std::string line;
    std::string currentSection;
    AgentTokenConfig currentConfig;
    bool inAgentSection = false;
    
    while (std::getline(file, line)) {
        line = trimString(line);
        
        // 跳过空行和注释
        if (line.empty() || line[0] == '#') {
            continue;
        }
        
        // 检查是否是节开始 [agent:agent_id]
        if (line[0] == '[' && line[line.size() - 1] == ']') {
            // 保存上一个配置
            if (inAgentSection && currentConfig.isValid()) {
                agentConfigs_[currentConfig.agentId] = currentConfig;
                LOG_DEBUG("Loaded agent config: " + currentConfig.agentId + 
                         " (IP: " + currentConfig.ipAddress + ")");
            }
            
            // 解析新节
            std::string section = line.substr(1, line.size() - 2);
            if (section.substr(0, 6) == "agent:") {
                inAgentSection = true;
                currentConfig = AgentTokenConfig();  // 重置
                currentConfig.agentId = section.substr(6);
            } else {
                inAgentSection = false;
            }
            continue;
        }
        
        // 在 agent 节内解析键值对
        if (inAgentSection) {
            size_t pos = line.find('=');
            if (pos == std::string::npos) continue;
            
            std::string key = trimString(line.substr(0, pos));
            std::string value = trimString(line.substr(pos + 1));
            
            if (key == "token") {
                currentConfig.token = value;
            } else if (key == "ip") {
                currentConfig.ipAddress = value;
            } else if (key == "hostname") {
                currentConfig.hostname = value;
            } else if (key == "service") {
                // 解析服务规格: name:type:port[:description]
                auto parts = splitString(value, ':');
                if (parts.size() >= 3) {
                    ServiceInfo svc;
                    svc.name = parts[0];
                    svc.type = parts[1];
                    svc.port = safeStringToInt(parts[2], 22);  // 默认 SSH 端口
                    if (parts.size() > 3) {
                        svc.description = parts[3];
                    }
                    currentConfig.services.push_back(svc);
                }
            }
        } else {
            // 简单格式: agent_id = token
            size_t pos = line.find('=');
            if (pos != std::string::npos) {
                std::string agentId = trimString(line.substr(0, pos));
                std::string token = trimString(line.substr(pos + 1));
                if (!agentId.empty() && !token.empty()) {
                    agentTokens_[agentId] = token;
                }
            }
        }
    }
    
    // 保存最后一个配置
    if (inAgentSection && currentConfig.isValid()) {
        agentConfigs_[currentConfig.agentId] = currentConfig;
    }
    
    size_t totalConfigs = agentConfigs_.size() + agentTokens_.size();
    LOG_INFO("Loaded " + std::to_string(agentConfigs_.size()) + " agent configs (with IP) and " +
             std::to_string(agentTokens_.size()) + " simple tokens, total: " + std::to_string(totalConfigs));
    
    // 记录加载的预配置
    for (const auto& pair : agentConfigs_) {
        LOG_INFO("  - " + pair.first + " -> " + pair.second.ipAddress);
    }
    
    return true;
}

void ClusterManager::upsertAgentToken(const std::string& agentId, const std::string& token) {
    if (agentId.empty() || token.empty()) {
        return;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    agentTokens_[agentId] = token;
}

void ClusterManager::checkAgentHealth() {
    std::lock_guard<std::mutex> lock(mutex_);

    auto now = std::chrono::steady_clock::now();
    std::vector<std::string> toRemove;

    for (const auto& pair : agents_) {
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            now - pair.second->lastHeartbeat).count();

        if (elapsed > 90) {  // 90秒超时
            LOG_WARN("Agent heartbeat timeout: " + pair.first);
            toRemove.push_back(pair.first);
        }
    }

    for (const auto& agentId : toRemove) {
        // 先清理 hostname 到 agentId 的映射
        auto it = agents_.find(agentId);
        if (it != agents_.end() && it->second) {
            if (it->second->controlFd >= 0) {
                pendingConnections_.erase(it->second->controlFd);
            }
            hostnameToAgentId_.erase(it->second->hostname);
        }
        agentConnections_.erase(agentId);
        agents_.erase(agentId);
        LOG_INFO("Agent removed due to timeout: " + agentId);
    }
}

// ============================================
// ClusterAgentClient 实现
// ============================================

ClusterAgentClient::ClusterAgentClient()
    : serverPort_(DEFAULT_CLUSTER_PORT)
    , sockFd_(-1)
    , heartbeatInterval_(30)
    , connected_(false)
    , running_(false) {
}

ClusterAgentClient::~ClusterAgentClient() {
    stop();
}

bool ClusterAgentClient::initialize(const std::string& serverAddr, int serverPort,
                                    const std::string& agentId, const std::string& authToken,
                                    const std::string& hostname,
                                    const std::string& localIp) {
    serverAddr_ = serverAddr;
    serverPort_ = serverPort;
    agentId_ = agentId;
    authToken_ = authToken;
    hostname_ = hostname.empty() ? agentId : hostname;
    localIp_ = localIp;
    
    return true;
}

bool ClusterAgentClient::registerToCluster(const std::vector<ServiceInfo>& services) {
    services_ = services;
    
    if (!connected_ && !connectToServer()) {
        return false;
    }
    
    // 获取本机 IP 地址
    std::string localIp;
    if (!localIp_.empty()) {
        // 使用手动指定的 IP
        localIp = localIp_;
        LOG_INFO("Using manually specified IP: " + localIp);
    } else {
        // 自动获取本机 IP
        localIp = getLocalIpAddress();
        if (localIp.empty()) {
            localIp = "127.0.0.1";
        }
        LOG_INFO("Using auto-detected IP: " + localIp);
    }
    
    // 构建注册消息 - 发送完整的 JSON 信息
    // 格式: {"agentId":"xxx","hostname":"xxx","ipAddress":"xxx","authToken":"xxx","services":[{"name":"ssh","type":"ssh","port":22}]}
    std::string payload = "{";
    payload += "\"agentId\":\"" + agentId_ + "\",";
    payload += "\"hostname\":\"" + hostname_ + "\",";
    payload += "\"ipAddress\":\"" + localIp + "\",";
    payload += "\"authToken\":\"" + authToken_ + "\",";
    payload += "\"services\":[";
    for (size_t i = 0; i < services.size(); ++i) {
        if (i > 0) payload += ",";
        payload += "{";
        payload += "\"name\":\"" + services[i].name + "\",";
        payload += "\"type\":\"" + services[i].type + "\",";
        payload += "\"port\":" + std::to_string(services[i].port);
        payload += "}";
    }
    payload += "]}";
    
    AgentMessage msg = AgentMessage::create(AgentMessageType::REGISTER, payload);
    
    if (!sendMessage(msg)) {
        return false;
    }
    
    LOG_INFO("Registered to cluster");
    return true;
}

void ClusterAgentClient::start() {
    running_ = true;
    workerThread_ = std::thread(&ClusterAgentClient::workerLoop, this);
}

void ClusterAgentClient::stop() {
    running_ = false;
    
    if (workerThread_.joinable()) {
        workerThread_.join();
    }
    
    disconnect();
}

bool ClusterAgentClient::sendHeartbeat() {
    if (!connected_ || sockFd_ < 0) {
        return false;
    }

    AgentMessage msg = AgentMessage::create(AgentMessageType::HEARTBEAT, "");
    if (!sendMessage(msg)) {
        LOG_ERROR("Failed to send heartbeat");
        return false;
    }
    return true;
}

bool ClusterAgentClient::unregister() {
    if (!connected_) {
        return false;
    }
    
    AgentMessage msg = AgentMessage::create(AgentMessageType::UNREGISTER, "");
    return sendMessage(msg);
}

void ClusterAgentClient::workerLoop() {
    int heartbeatCount = 0;
    auto nextHeartbeat = std::chrono::steady_clock::now();

    while (running_) {
        if (!connected_) {
            if (!registerToCluster(services_)) {
                for (int i = 0; i < 50 && running_; ++i) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                }
                continue;
            }
            nextHeartbeat = std::chrono::steady_clock::now();
        }

        // 到点发送心跳
        const auto now = std::chrono::steady_clock::now();
        if (now >= nextHeartbeat) {
            if (!sendHeartbeat()) {
                LOG_WARN("Heartbeat failed, connection may be lost");
                disconnect();
                continue;
            }

            heartbeatCount++;
            if (heartbeatCount % 10 == 0) {
                LOG_INFO("Agent heartbeat OK (" + std::to_string(heartbeatCount) + ")");
            }

            nextHeartbeat = now + std::chrono::seconds(std::max(1, heartbeatInterval_));
        }

        // 轮询控制连接，接收服务端命令
        const auto nowForWait = std::chrono::steady_clock::now();
        auto waitDuration = std::chrono::duration_cast<std::chrono::milliseconds>(nextHeartbeat - nowForWait);
        if (waitDuration < std::chrono::milliseconds(50)) {
            waitDuration = std::chrono::milliseconds(50);
        } else if (waitDuration > std::chrono::milliseconds(500)) {
            waitDuration = std::chrono::milliseconds(500);
        }
        const int waitMs = static_cast<int>(waitDuration.count());

        struct pollfd pfd;
        pfd.fd = sockFd_;
        pfd.events = POLLIN | POLLERR | POLLHUP;
        pfd.revents = 0;

        const int ret = poll(&pfd, 1, waitMs);
        if (ret < 0) {
            if (errno == EINTR) {
                continue;
            }
            LOG_ERROR("Poll error on control connection: " + std::string(strerror(errno)));
            disconnect();
            continue;
        }

        if (ret == 0) {
            continue;
        }

        if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
            LOG_WARN("Control connection closed by server");
            disconnect();
            continue;
        }

        if (pfd.revents & POLLIN) {
            AgentMessage msg;
            if (!receiveMessage(msg)) {
                LOG_WARN("Failed to receive control message, reconnecting");
                disconnect();
                continue;
            }
            handleServerMessage(msg);
        }
    }
}

void ClusterAgentClient::handleServerMessage(const AgentMessage& msg) {
    switch (msg.type) {
        case AgentMessageType::FORWARD_REQUEST:
            handleForwardRequest(msg.payload);
            break;
        case AgentMessageType::RESPONSE:
            LOG_DEBUG("Received server response: " + msg.payload);
            break;
        default:
            LOG_DEBUG("Ignoring unsupported server message type: " +
                      std::to_string(static_cast<int>(msg.type)));
            break;
    }
}

void ClusterAgentClient::handleForwardRequest(const std::string& payload) {
    const std::string requestId = extractJsonStringValue(payload, "requestId");
    const std::string targetHost = [&payload]() {
        std::string host = extractJsonStringValue(payload, "targetHost");
        return host.empty() ? std::string("127.0.0.1") : host;
    }();
    const std::string connectBackHost = extractJsonStringValue(payload, "connectBackHost");
    const int targetPort = extractJsonIntValue(payload, "targetPort", 22);
    const int connectBackPort = extractJsonIntValue(payload, "connectBackPort", 0);

    if (targetPort <= 0 || targetPort > 65535 || connectBackPort <= 0 || connectBackPort > 65535) {
        LOG_WARN("Invalid forward request payload: " + payload);
        return;
    }

    const std::string requestLabel = requestId.empty() ? generateUUID() : requestId;
    const std::string callbackHost = connectBackHost.empty() ? serverAddr_ : connectBackHost;

    submitForwardTask([requestLabel, callbackHost, connectBackPort, targetHost, targetPort]() {
        int targetFd = connectTcpWithTimeout(targetHost, targetPort, kConnectTimeoutMs);
        if (targetFd < 0) {
            LOG_ERROR("Forward request " + requestLabel + " failed: cannot connect target " +
                      targetHost + ":" + std::to_string(targetPort));
            return;
        }

        int tunnelFd = connectTcpWithTimeout(callbackHost, connectBackPort, kConnectTimeoutMs);
        if (tunnelFd < 0) {
            LOG_ERROR("Forward request " + requestLabel + " failed: cannot connect back to server " +
                      callbackHost + ":" + std::to_string(connectBackPort));
            closeSocket(targetFd);
            return;
        }

        setTcpNoDelay(targetFd);
        setTcpNoDelay(tunnelFd);
        LOG_INFO("Forward request " + requestLabel + " established: server " + callbackHost +
                 ":" + std::to_string(connectBackPort) + " <-> target " +
                 targetHost + ":" + std::to_string(targetPort));

        bridgeSocketPair(tunnelFd, targetFd);

        closeSocket(tunnelFd);
        closeSocket(targetFd);
        LOG_INFO("Forward request " + requestLabel + " closed");
    });
}

bool ClusterAgentClient::connectToServer() {
    if (connected_ && sockFd_ >= 0) {
        return true;
    }

    if (sockFd_ >= 0) {
        closeSocket(sockFd_);
    }

    sockFd_ = connectTcpWithTimeout(serverAddr_, serverPort_, kConnectTimeoutMs);
    if (sockFd_ < 0) {
        LOG_ERROR("Failed to connect to server: " + serverAddr_ + ":" + std::to_string(serverPort_));
        return false;
    }

    setTcpNoDelay(sockFd_);
    connected_ = true;
    LOG_INFO("Connected to server: " + serverAddr_ + ":" + std::to_string(serverPort_));
    return true;
}

void ClusterAgentClient::disconnect() {
    closeSocket(sockFd_);
    connected_ = false;
}

bool ClusterAgentClient::sendMessage(const AgentMessage& msg) {
    auto data = msg.serialize();

    if (!sendAllWithTimeout(sockFd_, data.data(), data.size(), kSendTimeoutMs)) {
        LOG_ERROR("Failed to send message");
        connected_ = false;
        return false;
    }

    return true;
}

bool ClusterAgentClient::receiveMessage(AgentMessage& msg) {
    if (!connected_ || sockFd_ < 0) {
        return false;
    }

    // 读取消息头部（9 字节: magic + type + length）
    uint8_t header[9];
    ssize_t totalRead = 0;

    // 设置读取超时（使用 poll）
    struct pollfd pfd;
    pfd.fd = sockFd_;
    pfd.events = POLLIN;

    // 读取头部
    while (totalRead < 9) {
        int ret = poll(&pfd, 1, 5000);  // 5 秒超时
        if (ret <= 0) {
            if (ret == 0) {
                LOG_WARN("Timeout waiting for message header");
            } else {
                LOG_ERROR("Poll error: " + std::string(strerror(errno)));
            }
            return false;
        }

        ssize_t n = recv(sockFd_, header + totalRead, 9 - totalRead, 0);
        if (n <= 0) {
            if (n == 0) {
                LOG_WARN("Connection closed by server");
            } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
                LOG_ERROR("Recv error: " + std::string(strerror(errno)));
            }
            connected_ = false;
            return false;
        }

        totalRead += n;
    }

    // 解析头部
    msg.magic = (header[0] << 24) | (header[1] << 16) | (header[2] << 8) | header[3];

    // 验证 magic number
    if (msg.magic != MAGIC_NUMBER) {
        LOG_ERROR("Invalid magic number in message: 0x" + std::to_string(msg.magic));
        return false;
    }

    // 解析消息类型和长度
    msg.type = static_cast<AgentMessageType>(header[4]);
    msg.length = (header[5] << 24) | (header[6] << 16) | (header[7] << 8) | header[8];

    // 检查消息长度是否合理（最大 10MB）
    if (msg.length > 10 * 1024 * 1024) {
        LOG_ERROR("Message too large: " + std::to_string(msg.length) + " bytes");
        return false;
    }

    // 读取 payload
    if (msg.length > 0) {
        msg.payload.resize(msg.length);
        totalRead = 0;

        while (totalRead < static_cast<ssize_t>(msg.length)) {
            int ret = poll(&pfd, 1, 5000);  // 5 秒超时
            if (ret <= 0) {
                LOG_WARN("Timeout waiting for message payload");
                return false;
            }

            ssize_t n = recv(sockFd_, &msg.payload[totalRead], msg.length - totalRead, 0);
            if (n <= 0) {
                if (n == 0) {
                    LOG_WARN("Connection closed by server during payload read");
                } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    LOG_ERROR("Recv error during payload: " + std::string(strerror(errno)));
                }
                connected_ = false;
                return false;
            }

            totalRead += n;
        }
    }

    return true;
}

std::string ClusterAgentClient::getLocalIpAddress() {
    // 方法1: 尝试通过主机名获取（使用线程安全的 getaddrinfo）
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) == 0) {
        struct addrinfo hints, *result = nullptr;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;

        if (getaddrinfo(hostname, nullptr, &hints, &result) == 0 && result) {
            struct sockaddr_in* addr = (struct sockaddr_in*)result->ai_addr;
            char ipStr[INET_ADDRSTRLEN];
            if (inet_ntop(AF_INET, &addr->sin_addr, ipStr, sizeof(ipStr))) {
                freeaddrinfo(result);
                if (std::string(ipStr) != "127.0.0.1") {
                    return ipStr;
                }
            } else {
                freeaddrinfo(result);
            }
        }
    }

    // 方法2: 尝试获取与服务器通信的本地 socket 地址
    if (sockFd_ >= 0) {
        struct sockaddr_in localAddr;
        socklen_t addrLen = sizeof(localAddr);
        if (getsockname(sockFd_, (struct sockaddr*)&localAddr, &addrLen) == 0) {
            char ipStr[INET_ADDRSTRLEN];
            if (inet_ntop(AF_INET, &localAddr.sin_addr, ipStr, sizeof(ipStr))) {
                if (std::string(ipStr) != "127.0.0.1") {
                    return ipStr;
                }
            }
        }
    }

    // 方法3: 尝试连接一个外部地址，获取使用的本地地址
    int testSock = socket(AF_INET, SOCK_DGRAM, 0);
    if (testSock >= 0) {
        struct sockaddr_in remoteAddr;
        memset(&remoteAddr, 0, sizeof(remoteAddr));
        remoteAddr.sin_family = AF_INET;
        remoteAddr.sin_port = htons(53); // DNS port
        inet_pton(AF_INET, "8.8.8.8", &remoteAddr.sin_addr);

        if (connect(testSock, (struct sockaddr*)&remoteAddr, sizeof(remoteAddr)) == 0) {
            struct sockaddr_in localAddr;
            socklen_t addrLen = sizeof(localAddr);
            if (getsockname(testSock, (struct sockaddr*)&localAddr, &addrLen) == 0) {
                char ipStr[INET_ADDRSTRLEN];
                if (inet_ntop(AF_INET, &localAddr.sin_addr, ipStr, sizeof(ipStr))) {
                    close(testSock);
                    return ipStr;
                }
            }
        }
        close(testSock);
    }

    // 如果都失败，返回空字符串
    return "";
}

} // namespace sshjump
