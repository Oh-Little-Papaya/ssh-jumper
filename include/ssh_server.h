/**
 * @file ssh_server.h
 * @brief SSH 服务器 - 支持交互式 JumpServer 风格 - 使用 libssh
 * 
 * 支持多种接入方式:
 * 1. 直接指定目标: ssh admin@jump.example.com web-server-01
 * 2. 环境变量: JUMP_TARGET=web-server-01 ssh admin@jump.example.com
 * 3. 交互式菜单: ssh admin@jump.example.com
 */

#ifndef SSH_JUMP_SSH_SERVER_H
#define SSH_JUMP_SSH_SERVER_H

#include "common.h"
#include "event_loop.h"
#include "thread_pool.h"
#include "cluster_manager.h"
#include "asset_manager.h"
#include "node_registry.h"
#include "ssh_connection.h"

namespace sshjump {

// 前向声明
class InteractiveSession;

// ============================================
// 连接速率限制器
// ============================================
class ConnectionRateLimiter {
public:
    explicit ConnectionRateLimiter(int maxConnectionsPerMinute = 10);
    void setMaxConnectionsPerMinute(int maxConnectionsPerMinute);
    bool checkAndRecord(const std::string& clientIp);
    void cleanup();

private:
    std::unordered_map<std::string, std::vector<std::chrono::steady_clock::time_point>> connections_;
    std::mutex mutex_;
    int maxConnectionsPerMinute_;
};

// ============================================
// 认证失败跟踪器
// ============================================
class AuthFailureTracker {
public:
    void recordFailure(const std::string& clientIp);
    bool isBlocked(const std::string& clientIp);
    void cleanup();

private:
    struct FailureInfo {
        int count = 0;
        std::chrono::steady_clock::time_point blockedUntil;
    };
    std::unordered_map<std::string, FailureInfo> failures_;
    std::mutex mutex_;
    static constexpr int MAX_FAILURES = 5;
    static constexpr int BLOCK_DURATION_SECONDS = 300; // 5分钟
};

// ============================================
// 连接池
// ============================================
class ConnectionPool : public NonCopyable {
public:
    explicit ConnectionPool(size_t maxSize = DEFAULT_MAX_CONNECTIONS);
    ~ConnectionPool();

    // 添加连接（返回是否成功）
    bool addConnection(const std::string& id, std::shared_ptr<SSHConnection> conn);
    
    // 获取连接
    std::shared_ptr<SSHConnection> getConnection(const std::string& id);
    
    // 移除连接
    void removeConnection(const std::string& id);
    
    // 获取连接数
    size_t size() const;
    
    // 清理超时连接
    void cleanupTimeoutConnections(int timeoutSeconds);
    
    // 关闭所有连接
    void closeAll();
    
private:
    // 连接映射
    std::unordered_map<std::string, std::weak_ptr<SSHConnection>> connections_;
    
    // 最大连接数
    size_t maxSize_;
    
    // 互斥锁
    mutable std::mutex mutex_;
};

// ============================================
// SSH 服务器
// ============================================
class SSHServer : public NonCopyable {
public:
    SSHServer();
    ~SSHServer();
    
    // 初始化
    bool initialize(const std::string& listenAddr, int port,
                    const std::string& hostKeyPath,
                    std::shared_ptr<IEventLoop> eventLoop = nullptr);
    
    // 设置集群管理器
    void setClusterManager(std::shared_ptr<ClusterManager> cm) { clusterManager_ = cm; }
    
    // 获取集群管理器
    std::shared_ptr<ClusterManager> getClusterManager() { return clusterManager_; }
    
    // 设置资产管理器
    void setAssetManager(std::shared_ptr<AssetManager> am) { assetManager_ = am; }
    
    // 获取资产管理器
    std::shared_ptr<AssetManager> getAssetManager() { return assetManager_; }

    // 设置/获取子节点注册表
    void setNodeRegistry(std::shared_ptr<ChildNodeRegistry> registry) { nodeRegistry_ = registry; }
    std::shared_ptr<ChildNodeRegistry> getNodeRegistry() { return nodeRegistry_; }
    
    // 启动服务器
    bool start();
    
    // 停止服务器
    void stop();
    
    // 运行事件循环
    void run();
    
    // 获取事件循环
    std::shared_ptr<IEventLoop> getEventLoop() { return eventLoop_; }
    
    // 获取连接池
    std::shared_ptr<ConnectionPool> getConnectionPool() { return connPool_; }
    
    // 获取线程池
    std::shared_ptr<ThreadPool> getThreadPool() { return threadPool_; }
    
    // 验证用户
    bool authenticateUser(const std::string& username, const std::string& password);
    
    // 检查用户公钥
    bool checkUserPublicKey(const std::string& username, const std::string& publicKey);

    // 记录认证失败
    void recordAuthFailure(const std::string& clientIp) {
        authFailureTracker_.recordFailure(clientIp);
    }

    // 配置连接速率限制（每 IP 每分钟）
    void setConnectionRateLimitPerMinute(int maxConnectionsPerMinute) {
        rateLimiter_.setMaxConnectionsPerMinute(maxConnectionsPerMinute);
    }
    
private:
    // 接受连接循环
    void acceptLoop();
    
    // libssh bind
    ssh_bind sshbind_;
    
    // 监听地址和端口
    std::string listenAddr_;
    int port_;
    
    // 主机密钥路径
    std::string hostKeyPath_;
    
    // 事件循环
    std::shared_ptr<IEventLoop> eventLoop_;
    
    // 连接池
    std::shared_ptr<ConnectionPool> connPool_;
    
    // 线程池
    std::shared_ptr<ThreadPool> threadPool_;
    
    // 集群管理器
    std::shared_ptr<ClusterManager> clusterManager_;
    
    // 资产管理器
    std::shared_ptr<AssetManager> assetManager_;

    // 子节点注册表
    std::shared_ptr<ChildNodeRegistry> nodeRegistry_;
    
    // 运行标志
    std::atomic<bool> running_;

    // 接受线程
    std::thread acceptThread_;

    // 连接速率限制器
    ConnectionRateLimiter rateLimiter_;

    // 认证失败跟踪器
    AuthFailureTracker authFailureTracker_;
};

} // namespace sshjump

#endif // SSH_JUMP_SSH_SERVER_H
