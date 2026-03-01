/**
 * @file cluster_manager.h
 * @brief 集群管理 - 内网机器加入集群、心跳管理
 */

#ifndef SSH_JUMP_CLUSTER_MANAGER_H
#define SSH_JUMP_CLUSTER_MANAGER_H

#include "common.h"
#include "event_loop.h"
#include <tuple>

namespace sshjump {

// 前向声明
class ClusterManager;

// ============================================
// 服务信息
// ============================================
struct ServiceInfo {
    std::string name;
    std::string type;       // ssh, http, https, tcp, etc.
    int port;
    std::string description;
    std::map<std::string, std::string> metadata;
};

// ============================================
// Agent 预配置信息 (从配置文件加载)
// ============================================
struct AgentTokenConfig {
    std::string agentId;            // Agent ID
    std::string token;              // 认证令牌
    std::string ipAddress;          // 预配置的 IP 地址
    std::string hostname;           // 预配置的主机名
    std::vector<ServiceInfo> services;  // 预配置的服务列表
    
    // 检查是否有效配置
    bool isValid() const {
        return !agentId.empty() && !token.empty() && !ipAddress.empty();
    }
};

// ============================================
// Agent信息
// ============================================
struct AgentInfo {
    std::string agentId;
    std::string hostname;
    std::string ipAddress;
    int port;
    std::string version;
    std::string authToken;
    std::vector<ServiceInfo> services;
    std::chrono::steady_clock::time_point registerTime;
    std::chrono::steady_clock::time_point lastHeartbeat;
    bool isOnline{false};
    int consecutiveFailures{0};
    int controlFd{-1};  // 控制连接fd
    
    // 默认构造函数
    AgentInfo() = default;
    
    // 从其他 AgentInfo 构造（拷贝构造）
    AgentInfo(const AgentInfo& other)
        : agentId(other.agentId)
        , hostname(other.hostname)
        , ipAddress(other.ipAddress)
        , port(other.port)
        , version(other.version)
        , authToken(other.authToken)
        , services(other.services)
        , registerTime(other.registerTime)
        , lastHeartbeat(other.lastHeartbeat)
        , isOnline(other.isOnline)
        , consecutiveFailures(other.consecutiveFailures)
        , controlFd(other.controlFd) {}
    
    // 赋值操作符
    AgentInfo& operator=(const AgentInfo& other) {
        if (this != &other) {
            agentId = other.agentId;
            hostname = other.hostname;
            ipAddress = other.ipAddress;
            port = other.port;
            version = other.version;
            authToken = other.authToken;
            services = other.services;
            registerTime = other.registerTime;
            lastHeartbeat = other.lastHeartbeat;
            isOnline = other.isOnline;
            consecutiveFailures = other.consecutiveFailures;
            controlFd = other.controlFd;
        }
        return *this;
    }
};

// ============================================
// Agent消息
// ============================================
struct AgentMessage {
    uint32_t magic;                 // 魔数
    AgentMessageType type;          // 消息类型
    uint32_t length;                // 负载长度
    std::string payload;            // JSON负载
    
    // 序列化
    std::vector<uint8_t> serialize() const;
    
    // 反序列化
    static bool deserialize(const uint8_t* data, size_t len, AgentMessage& msg);
    
    // 创建消息
    static AgentMessage create(AgentMessageType type, const std::string& payload);
};

// ============================================
// Agent连接处理器
// ============================================
class AgentConnection : public EventHandler, public std::enable_shared_from_this<AgentConnection> {
public:
    AgentConnection(int fd, ClusterManager* manager);
    ~AgentConnection() override;
    
    // 初始化
    bool initialize();
    
    // EventHandler接口实现
    int onRead() override;
    int onWrite() override;
    void onError() override;
    void onClose() override;
    int getFd() const override { return fd_; }
    
    // 获取Agent ID
    const std::string& getAgentId() const { return agentId_; }
    
    // 发送消息
    bool sendMessage(const AgentMessage& msg);
    
    // 关闭连接
    void close();
    
private:
    // 处理消息
    void handleMessage(const AgentMessage& msg);
    
    // 处理注册请求
    void handleRegister(const std::string& payload);
    
    // 处理心跳
    void handleHeartbeat(const std::string& payload);
    
    // 处理注销
    void handleUnregister(const std::string& payload);

    // 处理管理命令（节点 CRUD）
    void handleCommand(const std::string& payload);
    
    // 发送响应
    void sendResponse(bool success, const std::string& message);
    
    // socket fd
    int fd_;
    
    // 所属管理器
    ClusterManager* manager_;
    
    // Agent ID
    std::string agentId_;
    
    // 读取缓冲区
    Buffer readBuffer_;
    
    // 写入缓冲区
    Buffer writeBuffer_;
    
    // 互斥锁
    mutable std::mutex mutex_;

    // 是否已为该连接启用 EPOLLOUT 订阅
    bool writeEventEnabled_{false};
};

// ============================================
// 集群管理器
// ============================================
class ClusterManager : public EventHandler, 
                       public std::enable_shared_from_this<ClusterManager>,
                       public NonCopyable {
public:
    ClusterManager();
    ~ClusterManager();
    
    // EventHandler 接口实现
    int onRead() override;  // 接受新连接
    int onWrite() override { return 0; }
    void onError() override;
    void onClose() override;
    int getFd() const override { return listenFd_; }
    
    // 初始化
    bool initialize(const std::string& listenAddr, int port,
                    std::shared_ptr<IEventLoop> eventLoop = nullptr);
    
    // 启动
    bool start();
    
    // 停止
    void stop();
    
    // 注册Agent
    bool registerAgent(const AgentInfo& info, int controlFd);
    
    // 注销Agent
    void unregisterAgent(const std::string& agentId);

    // 基于控制连接 fd 的安全注销（避免旧连接误删新注册）
    void unregisterAgentByConnection(const std::string& agentId, int controlFd);
    
    // 更新心跳
    void updateHeartbeat(const std::string& agentId);
    
    // 获取Agent信息
    std::shared_ptr<AgentInfo> getAgent(const std::string& agentId);
    
    // 通过主机名查找Agent
    std::shared_ptr<AgentInfo> findAgentByHostname(const std::string& hostname);
    
    // 获取所有Agent
    std::vector<std::shared_ptr<AgentInfo>> getAllAgents();
    
    // 获取在线Agent数量
    size_t getOnlineAgentCount() const;
    
    // 验证Agent token
    bool verifyAgentToken(const std::string& agentId, const std::string& token);

    // 验证管理命令 token（独立 admin token）
    bool validateAdminToken(const std::string& token) const;

    // 使用 admin token 解密安全管理请求
    bool decryptAdminPayload(const std::string& ivHex,
                             const std::string& ciphertextHex,
                             const std::string& tagHex,
                             std::string& plaintext) const;

    // 使用共享 token/节点 token 解密安全注册请求
    bool decryptAgentPayload(const std::string& agentIdHint,
                             const std::string& ivHex,
                             const std::string& ciphertextHex,
                             const std::string& tagHex,
                             std::string& plaintext,
                             std::string* tokenUsed = nullptr) const;

    // 获取/维护集群节点配置（内存态）
    std::vector<AgentTokenConfig> listConfiguredAgents() const;
    std::optional<AgentTokenConfig> getConfiguredAgent(const std::string& agentId) const;
    bool upsertConfiguredAgent(const AgentTokenConfig& config);
    bool deleteConfiguredAgent(const std::string& agentId);
    
    // 建立到Agent的转发连接
    int establishForwardConnection(const std::string& agentId, int targetPort);

    // 设置 NAT 回拨隧道参数（端口池、重试、超时）
    void setReverseTunnelOptions(int portStart, int portEnd, int retries, int acceptTimeoutMs);

    // 获取 NAT 回拨隧道参数
    std::tuple<int, int, int, int> getReverseTunnelOptions() const;
    
    // 获取监听fd
    int getListenFd() const { return listenFd_; }
    
    // 接受新连接
    void acceptConnection();

    // 移除连接（AgentConnection 关闭时调用）
    void removeConnectionByFd(int fd);

    // 更新连接写事件订阅（AgentConnection 发送缓冲变化时调用）
    void setConnectionWriteInterest(int fd, bool enabled);

    // 加载Agent token配置
    bool loadAgentTokens(const std::string& configPath);

    // 直接设置/覆盖单个 Agent token（CLI 场景）
    void upsertAgentToken(const std::string& agentId, const std::string& token);

    // 设置集群共享 token（任意 agentId 使用同一 token 可注册）
    void setSharedToken(const std::string& token);

    // 设置管理 API token（admin 专用）
    void setAdminToken(const std::string& token);
    
private:
    // 启动心跳检查
    void startHeartbeatCheck();
    
    // 检查Agent健康状态
    void checkAgentHealth();
    
    // 监听socket
    int listenFd_;
    
    // 监听地址和端口
    std::string listenAddr_;
    int port_;
    
    // 事件循环
    std::shared_ptr<IEventLoop> eventLoop_;
    
    // 定时器线程
    std::unique_ptr<TimerThread> timerThread_;
    
    // Agent映射
    std::unordered_map<std::string, std::shared_ptr<AgentInfo>> agents_;
    
    // Agent连接映射
    std::unordered_map<std::string, std::shared_ptr<AgentConnection>> agentConnections_;

    // 尚未完成注册的连接映射 (fd -> connection)
    std::unordered_map<int, std::shared_ptr<AgentConnection>> pendingConnections_;
    
    // Agent token映射 (agentId -> token) - 简单格式
    std::unordered_map<std::string, std::string> agentTokens_;

    // 集群共享 token（所有 Agent 共用）
    std::string sharedToken_;

    // 管理接口独立 token（与 sharedToken_ 分离）
    std::string adminToken_;
    
    // Agent 预配置映射 (agentId -> 完整配置) - 完整格式
    std::unordered_map<std::string, AgentTokenConfig> agentConfigs_;
    
    // 主机名到Agent ID映射
    std::unordered_map<std::string, std::string> hostnameToAgentId_;
    
    // 互斥锁
    mutable std::mutex mutex_;
    
    // 运行标志
    std::atomic<bool> running_;

    // NAT 回拨隧道参数
    int reverseTunnelPortStart_;
    int reverseTunnelPortEnd_;
    int reverseTunnelRetries_;
    int reverseTunnelAcceptTimeoutMs_;
    std::atomic<int> reverseTunnelPortCursor_;
};

// ============================================
// Agent客户端 (运行在内网机器上)
// ============================================
class ClusterAgentClient : public NonCopyable {
public:
    ClusterAgentClient();
    ~ClusterAgentClient();
    
    // 初始化
    bool initialize(const std::string& serverAddr, int serverPort,
                    const std::string& agentId, const std::string& authToken,
                    const std::string& hostname = "",
                    const std::string& localIp = "");
    
    // 注册到集群
    bool registerToCluster(const std::vector<ServiceInfo>& services);
    
    // 启动 (开始心跳和事件处理)
    void start();
    
    // 停止
    void stop();
    
    // 发送心跳
    bool sendHeartbeat();
    
    // 注销
    bool unregister();
    
    // 设置服务列表
    void setServices(const std::vector<ServiceInfo>& services) { services_ = services; }
    
    // 设置心跳间隔
    void setHeartbeatInterval(int seconds) { heartbeatInterval_ = seconds; }
    
    // 检查是否已连接
    bool isConnected() const { return connected_; }
    
private:
    // 工作线程函数
    void workerLoop();

    // 处理服务器消息
    void handleServerMessage(const AgentMessage& msg);

    // 处理转发请求（由服务端下发）
    void handleForwardRequest(const std::string& payload);
    
    // 连接到服务器
    bool connectToServer();
    
    // 断开连接
    void disconnect();
    
    // 发送消息
    bool sendMessage(const AgentMessage& msg);
    
    // 接收消息
    bool receiveMessage(AgentMessage& msg);
    
    // 获取本机 IP 地址
    std::string getLocalIpAddress();
    
    // 服务器地址和端口
    std::string serverAddr_;
    int serverPort_;
    
    // Agent ID、认证token和主机名
    std::string agentId_;
    std::string authToken_;
    std::string hostname_;
    std::string localIp_;  // 手动指定的本机 IP
    
    // 服务列表
    std::vector<ServiceInfo> services_;
    
    // socket fd
    int sockFd_;
    
    // 心跳间隔
    int heartbeatInterval_;
    
    // 连接状态
    std::atomic<bool> connected_;
    
    // 运行标志
    std::atomic<bool> running_;
    
    // 工作线程
    std::thread workerThread_;
    
    // 互斥锁
    mutable std::mutex mutex_;
};

} // namespace sshjump

#endif // SSH_JUMP_CLUSTER_MANAGER_H
