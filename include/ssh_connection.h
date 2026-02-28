/**
 * @file ssh_connection.h
 * @brief SSH 连接管理 - 使用 libssh
 */

#ifndef SSH_JUMP_SSH_CONNECTION_H
#define SSH_JUMP_SSH_CONNECTION_H

#include "common.h"

namespace sshjump {

// 前向声明
class SSHServer;
class InteractiveSession;

// ============================================
// SSH 连接 - 表示一个用户 SSH 连接
// ============================================
class SSHConnection : public std::enable_shared_from_this<SSHConnection> {
public:
    SSHConnection(ssh_session session, ssh_bind sshbind, SSHServer* server);
    ~SSHConnection();
    
    // 初始化 SSH 会话
    bool initialize();
    
    // 开始处理
    void start();
    
    // 关闭连接
    void close();
    
    // 获取连接状态
    bool isAuthenticated() const { return authenticated_; }
    
    // 获取用户名
    const std::string& getUsername() const { return username_; }
    
    // 获取 libssh 会话和通道
    ssh_session getSession() { return session_; }
    ssh_channel getChannel() { return channel_; }
    
    // 获取最后活动时间
    std::chrono::steady_clock::time_point getLastActivity() const { return lastActivity_; }
    
    // 更新活动时间
    void updateActivity() { lastActivity_ = std::chrono::steady_clock::now(); }
    
    // 获取连接ID
    const std::string& getId() const { return connId_; }
    
    // 设置原始命令 (SSH 命令行参数)
    void setRawCommand(const std::string& cmd) { rawCommand_ = cmd; }
    
    // 获取原始命令
    const std::string& getRawCommand() const { return rawCommand_; }
    
    // 获取所属服务器
    SSHServer* getServer() { return server_; }

    // 获取客户端 IP
    const std::string& getClientIp() const { return clientIp_; }

    // 设置客户端 IP
    void setClientIp(const std::string& ip) { clientIp_ = ip; }
    
private:
    // 处理会话消息循环
    void handleSession();
    
    // 处理认证请求
    void handlePasswordAuth(ssh_message message);
    void handlePublickeyAuth(ssh_message message);
    
    // 处理通道请求
    void handleChannelOpen(ssh_message message);
    void handleChannelRequest(ssh_message message);
    
    // 启动交互式会话
    void startInteractiveSession();
    
    // libssh 会话
    ssh_session session_;
    
    // libssh bind
    ssh_bind sshbind_;
    
    // 所属服务器
    SSHServer* server_;
    
    // 连接ID
    std::string connId_;

    // 客户端 IP
    std::string clientIp_;
    
    // 当前通道
    ssh_channel channel_;
    
    // 握手完成状态
    std::atomic<bool> handshakeComplete_;
    
    // 认证状态
    std::atomic<bool> authenticated_;
    
    // 用户名
    std::string username_;
    
    // 原始命令 (用于直接指定目标)
    std::string rawCommand_;
    
    // 最后活动时间
    std::chrono::steady_clock::time_point lastActivity_;
    
    // 互斥锁
    mutable std::mutex mutex_;
    
    // 交互式会话
    std::shared_ptr<InteractiveSession> interactiveSession_;
};

} // namespace sshjump

#endif // SSH_JUMP_SSH_CONNECTION_H
