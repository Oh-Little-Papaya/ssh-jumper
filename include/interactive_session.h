/**
 * @file interactive_session.h
 * @brief 交互式会话 - JumpServer风格资产选择和连接
 * 
 * 支持多种接入方式:
 * 1. 直接指定目标: ssh admin@jump.example.com web-server-01
 * 2. 环境变量: JUMP_TARGET=web-server-01 ssh admin@jump.example.com
 * 3. 交互式菜单: ssh admin@jump.example.com (显示资产列表)
 * 4. 快捷连接: ssh admin@jump.example.com @1 (连接最近访问的第1个)
 */

#ifndef SSH_JUMP_INTERACTIVE_SESSION_H
#define SSH_JUMP_INTERACTIVE_SESSION_H

#include "common.h"
#include "ssh_connection.h"
#include "asset_manager.h"

namespace sshjump {

// 前向声明
class SSHServer;
class DataBridge;

// ============================================
// SSH 客户端 - 跳板机作为客户端连接目标
// ============================================
class SSHClient : public EventHandler, public std::enable_shared_from_this<SSHClient> {
public:
    SSHClient();
    ~SSHClient() override;
    
    // 连接到目标主机
    bool connect(const std::string& host, int port, 
                 const std::string& username,
                 const std::string& password = "",
                 const std::string& privateKey = "");

    // 使用已建立的 socket 连接目标（用于 NAT 打洞后的回拨通道）
    bool connectWithSocket(int connectedSockFd,
                           const std::string& host, int port,
                           const std::string& username,
                           const std::string& password = "",
                           const std::string& privateKey = "");
    
    // 断开连接
    void disconnect();
    
    // 执行命令
    bool executeCommand(const std::string& command, std::string& output);
    
    // 请求 PTY
    bool requestPty(const std::string& term = "xterm", 
                    int cols = 80, int rows = 24);
    
    // 打开 Shell 会话
    bool openShell();
    
    // 发送数据
    int write(const char* data, size_t len);
    
    // 读取数据
    int read(char* buffer, size_t len);
    
    // EventHandler 接口实现 (用于异步 I/O)
    int onRead() override;
    int onWrite() override;
    void onError() override;
    void onClose() override;
    int getFd() const override { return sockFd_; }
    
    // 获取会话
    ssh_session getSession() { return session_; }
    ssh_channel getChannel() { return channel_; }
    
    // 检查是否已连接
    bool isConnected() const { return connected_; }
    
    // 设置非阻塞模式
    void setNonBlockingMode();
    
private:
    // socket
    int sockFd_;
    
    // libssh 会话
    ssh_session session_;
    ssh_channel channel_;
    
    // 连接状态
    std::atomic<bool> connected_;
    
    // 目标信息
    std::string host_;
    int port_;
    std::string username_;
    
    // 读取缓冲区
    Buffer readBuffer_;
    
    // 互斥锁
    mutable std::mutex mutex_;
};

// ============================================
// 数据桥接 - 在用户连接和目标连接间转发数据
// ============================================
class DataBridge : public std::enable_shared_from_this<DataBridge> {
public:
    DataBridge(std::shared_ptr<SSHConnection> userConn,
               std::shared_ptr<SSHClient> targetClient);
    ~DataBridge();
    
    // 开始桥接
    void start();
    
    // 停止桥接
    void stop();
    
    // 是否运行中
    bool isRunning() const { return running_; }
    
private:
    // 用户到目标的转发线程
    void userToTargetLoop();
    
    // 目标到用户的转发线程
    void targetToUserLoop();
    
    // 用户连接 (PTY 主端)
    std::shared_ptr<SSHConnection> userConn_;
    
    // 目标客户端 (PTY 从端)
    std::shared_ptr<SSHClient> targetClient_;
    
    // 运行标志
    std::atomic<bool> running_;
    
    // 转发线程
    std::thread userToTargetThread_;
    std::thread targetToUserThread_;
};

// ============================================
// 最近访问记录
// ============================================
struct RecentAsset {
    std::string assetId;
    std::string hostname;
    std::chrono::system_clock::time_point lastAccess;
    int accessCount = 0;
};

// ============================================
// 交互式会话 - 处理菜单显示和资产选择
// ============================================
class InteractiveSession : public std::enable_shared_from_this<InteractiveSession> {
public:
    InteractiveSession(std::shared_ptr<SSHConnection> connection,
                       SSHServer* server);
    ~InteractiveSession();
    
    // 设置直接连接目标 (通过命令行参数)
    void setDirectTarget(const std::string& target) { directTarget_ = target; }
    
    // 启动交互式会话
    void start();
    
    // 停止会话
    void stop();
    
private:
    // 尝试直接连接 (命令行参数/环境变量指定)
    bool tryDirectConnect();
    
    // 显示资产菜单
    void showAssetMenu(const std::vector<AssetInfo>& assets, int page = 0);
    
    // 显示欢迎信息
    void showWelcome();
    
    // 显示帮助信息
    void showHelp();
    
    // 显示最近访问
    void showRecentAssets();
    
    // 清屏
    void clearScreen();
    
    // 读取用户输入
    std::string readUserInput();
    
    // 处理用户选择
    bool handleUserSelection(const std::string& input, const std::vector<AssetInfo>& assets);
    
    // 解析用户输入，返回匹配的资产
    std::vector<AssetInfo> parseUserInput(const std::string& input, 
                                          const std::vector<AssetInfo>& assets);
    
    // 连接到指定资产
    bool connectToAsset(const AssetInfo& asset);
    
    // 发送数据到用户
    void sendToUser(const std::string& data);
    
    // 发送格式化表格
    void sendTable(const std::vector<std::vector<std::string>>& rows,
                   const std::vector<std::string>& headers);
    
    // 记录最近访问
    void recordRecentAccess(const std::string& assetId, const std::string& hostname);
    
    // 获取最近访问列表
    std::vector<RecentAsset> getRecentAssets(int limit = 5);
    
    // 显示空资产菜单 (没有可访问资产时的菜单)
    void showEmptyAssetMenu();
    
    // 处理空资产菜单的用户选择
    bool handleEmptyMenuSelection(const std::string& input);
    
    // 用户连接 (弱引用)
    std::weak_ptr<SSHConnection> connection_;
    
    // 所属服务器
    SSHServer* server_;
    
    // 资产管理器
    std::shared_ptr<AssetManager> assetManager_;
    
    // 当前数据桥接
    std::shared_ptr<DataBridge> currentBridge_;
    
    // 直接连接目标
    std::string directTarget_;
    
    // 会话状态
    enum class SessionState {
        INITIAL,        // 初始状态
        MENU,           // 显示菜单
        CONNECTING,     // 正在连接
        FORWARDING,     // 数据转发中
        EXITING         // 退出
    };
    std::atomic<SessionState> state_;
    
    // 用户名
    std::string username_;
    
    // 运行标志
    std::atomic<bool> running_;
    
    // 最近访问列表 (持久化到文件)
    std::vector<RecentAsset> recentAssets_;
    
    // 互斥锁
    mutable std::mutex mutex_;
    
    // 每页显示数量
    static constexpr int ASSETS_PER_PAGE = 10;
};

} // namespace sshjump

#endif // SSH_JUMP_INTERACTIVE_SESSION_H
