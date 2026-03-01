/**
 * @file interactive_session.cpp
 * @brief 交互式会话实现 - JumpServer风格
 * 
 * 支持多种接入方式:
 * 1. 直接指定目标: ssh admin@jump.example.com web-server-01
 * 2. 环境变量: JUMP_TARGET=web-server-01 ssh admin@jump.example.com
 * 3. 交互式菜单: ssh admin@jump.example.com
 * 4. 快捷连接: ssh admin@jump.example.com @1 (连接最近访问的第1个)
 */

#include "interactive_session.h"
#include "asset_manager.h"
#include "ssh_server.h"
#include "config_manager.h"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cctype>
#include <fstream>

namespace sshjump {

// ============================================
// SSHClient 实现
// ============================================

SSHClient::SSHClient()
    : sockFd_(-1)
    , session_(nullptr)
    , channel_(nullptr)
    , connected_(false) {
}

SSHClient::~SSHClient() {
    disconnect();
}

bool SSHClient::connect(const std::string& host, int port,
                        const std::string& username,
                        const std::string& password,
                        const std::string& privateKey) {
    // 使用 getaddrinfo 进行线程安全的地址解析
    struct addrinfo hints, *result = nullptr;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    int gaiRet = getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &result);
    if (gaiRet != 0 || !result) {
        LOG_ERROR("Failed to resolve host: " + host + " - " + std::string(gai_strerror(gaiRet)));
        return false;
    }

    int connectedFd = -1;
    for (auto* ai = result; ai != nullptr; ai = ai->ai_next) {
        int fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) {
            continue;
        }
        if (::connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) {
            connectedFd = fd;
            break;
        }
        close(fd);
    }

    freeaddrinfo(result);
    if (connectedFd < 0) {
        LOG_ERROR("Failed to connect to " + host + ":" + std::to_string(port));
        return false;
    }

    sockFd_ = connectedFd;
    return connectWithSocket(sockFd_, host, port, username, password, privateKey);
}

bool SSHClient::connectWithSocket(int connectedSockFd,
                                  const std::string& host, int port,
                                  const std::string& username,
                                  const std::string& password,
                                  const std::string& privateKey) {
    if (connectedSockFd < 0) {
        LOG_ERROR("Invalid socket fd for SSH connection");
        return false;
    }

    if (sockFd_ >= 0 && sockFd_ != connectedSockFd) {
        closeSocket(sockFd_);
    }

    sockFd_ = connectedSockFd;
    host_ = host;
    port_ = port;
    username_ = username;

    // libssh 握手阶段默认使用阻塞 socket，避免握手失败
    int flags = fcntl(sockFd_, F_GETFL, 0);
    if (flags >= 0 && (flags & O_NONBLOCK)) {
        fcntl(sockFd_, F_SETFL, flags & ~O_NONBLOCK);
    }

    // 创建 libssh 会话
    session_ = ssh_new();
    if (!session_) {
        LOG_ERROR("Failed to create libssh session");
        closeSocket(sockFd_);
        return false;
    }
    
    // 设置选项
    ssh_options_set(session_, SSH_OPTIONS_HOST, host.c_str());
    ssh_options_set(session_, SSH_OPTIONS_USER, username.c_str());
    ssh_options_set(session_, SSH_OPTIONS_PORT, &port);
    
    // 设置 socket
    ssh_options_set(session_, SSH_OPTIONS_FD, &sockFd_);
    
    // 执行握手
    int ret = ssh_connect(session_);
    if (ret != SSH_OK) {
        LOG_ERROR("SSH handshake failed: " + std::string(ssh_get_error(session_)));
        disconnect();
        return false;
    }
    
    // 认证
    if (!privateKey.empty()) {
        ssh_key privKey = nullptr;
        ret = ssh_pki_import_privkey_file(privateKey.c_str(), 
                                           password.empty() ? nullptr : password.c_str(),
                                           nullptr, nullptr, &privKey);
        if (ret != SSH_OK) {
            LOG_ERROR("Failed to import private key: " + std::string(ssh_get_error(session_)));
            disconnect();
            return false;
        }
        ret = ssh_userauth_publickey(session_, nullptr, privKey);
        ssh_key_free(privKey);
    } else if (!password.empty()) {
        ret = ssh_userauth_password(session_, nullptr, password.c_str());
    } else {
        // 没有提供认证方法，尝试使用 SSH agent 或默认密钥
        ret = ssh_userauth_publickey_auto(session_, nullptr, nullptr);
        if (ret != SSH_OK) {
            LOG_ERROR("No authentication method provided and SSH agent authentication failed");
            disconnect();
            return false;
        }
    }
    
    if (ret != SSH_OK) {
        LOG_ERROR("Authentication failed: " + std::string(ssh_get_error(session_)));
        disconnect();
        return false;
    }
    
    connected_ = true;
    LOG_INFO("SSHClient connected to " + host + ":" + std::to_string(port));
    return true;
}

void SSHClient::disconnect() {
    if (channel_) {
        ssh_channel_close(channel_);
        ssh_channel_free(channel_);
        channel_ = nullptr;
    }
    
    if (session_) {
        ssh_disconnect(session_);
        ssh_free(session_);
        session_ = nullptr;
    }
    
    closeSocket(sockFd_);
    connected_ = false;
    
    LOG_INFO("SSHClient disconnected");
}

bool SSHClient::requestPty(const std::string& term, int cols, int rows) {
    if (!connected_ || !session_) {
        return false;
    }
    
    channel_ = ssh_channel_new(session_);
    if (!channel_) {
        LOG_ERROR("Failed to create channel");
        return false;
    }
    
    int ret = ssh_channel_open_session(channel_);
    if (ret != SSH_OK) {
        LOG_ERROR("Failed to open channel session: " + std::string(ssh_get_error(session_)));
        ssh_channel_free(channel_);
        channel_ = nullptr;
        return false;
    }
    
    ret = ssh_channel_request_pty_size(channel_, term.c_str(), cols, rows);
    if (ret != SSH_OK) {
        LOG_ERROR("Failed to request PTY: " + std::string(ssh_get_error(session_)));
        ssh_channel_close(channel_);
        ssh_channel_free(channel_);
        channel_ = nullptr;
        return false;
    }
    
    return true;
}

bool SSHClient::openShell() {
    if (!channel_) {
        return false;
    }
    
    int ret = ssh_channel_request_shell(channel_);
    if (ret != SSH_OK) {
        LOG_ERROR("Failed to open shell: " + std::string(ssh_get_error(session_)));
        return false;
    }
    
    return true;
}

int SSHClient::write(const char* data, size_t len) {
    if (!channel_) {
        return -1;
    }
    
    int ret = ssh_channel_write(channel_, data, len);
    if (ret < 0 && ret != SSH_AGAIN) {
        LOG_ERROR("Write to channel failed: " + std::to_string(ret));
    }
    return ret;
}

int SSHClient::read(char* buffer, size_t len) {
    if (!channel_) {
        return -1;
    }

    // 使用带超时的读取，在非阻塞模式下更可靠
    int ret = ssh_channel_read_timeout(channel_, buffer, len, 0, 1);
    if (ret < 0 && ret != SSH_AGAIN) {
        LOG_ERROR("Read from channel failed: " + std::to_string(ret));
    }
    return ret;
}

int SSHClient::onRead() {
    char buffer[DEFAULT_BUFFER_SIZE];
    int n = read(buffer, sizeof(buffer));
    if (n > 0) {
        readBuffer_.append(buffer, n);
    }
    return n;
}

int SSHClient::onWrite() {
    return 0;
}

void SSHClient::onError() {
    LOG_ERROR("SSHClient error");
    disconnect();
}

void SSHClient::onClose() {
    LOG_INFO("SSHClient closed");
    disconnect();
}

void SSHClient::setNonBlockingMode() {
    if (sockFd_ >= 0) {
        setNonBlocking(sockFd_);
    }
    if (session_) {
        ssh_set_blocking(session_, 0);
    }
}

// ============================================
// DataBridge 实现
// ============================================

DataBridge::DataBridge(std::shared_ptr<SSHConnection> userConn,
                       std::shared_ptr<SSHClient> targetClient)
    : userConn_(userConn)
    , targetClient_(targetClient)
    , running_(false) {
}

DataBridge::~DataBridge() {
    stop();
}

void DataBridge::start() {
    running_ = true;
    
    userToTargetThread_ = std::thread(&DataBridge::userToTargetLoop, this);
    targetToUserThread_ = std::thread(&DataBridge::targetToUserLoop, this);
    
    LOG_INFO("DataBridge started");
}

void DataBridge::stop() {
    running_ = false;
    
    if (userToTargetThread_.joinable()) {
        userToTargetThread_.join();
    }
    if (targetToUserThread_.joinable()) {
        targetToUserThread_.join();
    }
    
    LOG_INFO("DataBridge stopped");
}

void DataBridge::userToTargetLoop() {
    char buffer[DEFAULT_BUFFER_SIZE];

    while (running_) {
        auto userSession = userConn_->getSession();
        auto userChannel = userConn_->getChannel();

        if (!userSession || !userChannel) {
            break;
        }

        // 检查 channel 是否仍然打开
        if (!ssh_channel_is_open(userChannel)) {
            break;
        }

        int n = ssh_channel_read_timeout(userChannel, buffer, sizeof(buffer), 0, 1);
        if (n > 0) {
            int written = 0;
            while (written < n) {
                int ret = targetClient_->write(buffer + written, n - written);
                if (ret > 0) {
                    written += ret;
                } else if (ret != SSH_AGAIN) {
                    LOG_ERROR("Failed to write to target");
                    running_ = false;
                    break;
                } else {
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                }
            }
        } else if (n < 0 && n != SSH_AGAIN) {
            LOG_ERROR("Read from user failed: " + std::to_string(n));
            break;
        }

        // n == 0 时需要检查是否 EOF
        if (n == 0) {
            if (ssh_channel_is_eof(userChannel)) {
                // 用户连接已关闭
                LOG_INFO("User channel EOF, closing connection");
                break;
            }
            // 否则只是超时，继续循环
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        } else if (n == SSH_AGAIN) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }

    running_ = false;
}

void DataBridge::targetToUserLoop() {
    char buffer[DEFAULT_BUFFER_SIZE];

    while (running_) {
        int n = targetClient_->read(buffer, sizeof(buffer));
        if (n > 0) {
            auto userSession = userConn_->getSession();
            auto userChannel = userConn_->getChannel();

            if (!userSession || !userChannel) {
                break;
            }

            // 检查 channel 是否仍然打开
            if (!ssh_channel_is_open(userChannel)) {
                break;
            }

            int written = 0;
            while (written < n) {
                int ret = ssh_channel_write(userChannel, buffer + written, n - written);
                if (ret > 0) {
                    written += ret;
                } else if (ret != SSH_AGAIN) {
                    LOG_ERROR("Failed to write to user");
                    running_ = false;
                    break;
                } else {
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                }
            }
        } else if (n < 0 && n != SSH_AGAIN) {
            LOG_ERROR("Read from target failed: " + std::to_string(n));
            break;
        }

        // n == 0 时需要检查是否 EOF
        if (n == 0) {
            auto targetChannel = targetClient_->getChannel();
            if (targetChannel && ssh_channel_is_eof(targetChannel)) {
                // 目标连接已关闭（用户执行了 exit）
                LOG_INFO("Target channel EOF, closing connection");
                break;
            }
            // 否则只是超时，继续循环
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        } else if (n == SSH_AGAIN) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }

    running_ = false;
}

// ============================================
// InteractiveSession 实现
// ============================================

InteractiveSession::InteractiveSession(std::shared_ptr<SSHConnection> connection,
                                       SSHServer* server)
    : connection_(connection)
    , server_(server)
    , state_(SessionState::INITIAL)
    , running_(false) {
}

InteractiveSession::~InteractiveSession() {
    stop();
}

void InteractiveSession::start() {
    running_ = true;
    state_ = SessionState::INITIAL;

    // 获取用户名（先检查连接是否有效）
    auto conn = connection_.lock();
    if (!conn) {
        LOG_ERROR("Connection expired, cannot start session");
        return;
    }
    username_ = conn->getUsername();

    // 获取共享的资产管理器
    assetManager_ = server_->getAssetManager();
    if (!assetManager_) {
        LOG_ERROR("AssetManager not available");
        return;
    }
    
    // 加载最近访问记录
    recentAssets_ = getRecentAssets();
    
    // 尝试直接连接 (命令行参数或环境变量指定)
    if (tryDirectConnect()) {
        return;
    }
    
    // 进入交互式菜单模式
    state_ = SessionState::MENU;
    clearScreen();
    showWelcome();
    
    // 主循环
    while (running_ && state_ != SessionState::EXITING) {
        // 获取用户可访问的资产
        auto assets = assetManager_->getUserAssets(username_, true);

        if (assets.empty()) {
            showEmptyAssetMenu();

            // 读取用户输入
            sendToUser("\r\n\033[32m> \033[0m");
            std::string input = readUserInput();

            // 处理空资产菜单的用户输入
            if (!handleEmptyMenuSelection(input)) {
                sendToUser("\r\n\033[31m无效的选项，请重试。\033[0m\r\n");
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
            }

            // 如果还在菜单模式，清屏重新显示
            if (state_ == SessionState::MENU) {
                clearScreen();
            }
            continue;
        }

        // 显示资产菜单
        showAssetMenu(assets);
        
        // 读取用户输入
        sendToUser("\r\n\033[32m> \033[0m");
        std::string input = readUserInput();
        
        if (!handleUserSelection(input, assets)) {
            sendToUser("\r\n\033[90m无效的选项，按回车继续...\033[0m");
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        
        // 如果还在菜单模式，清屏重新显示
        if (state_ == SessionState::MENU) {
            clearScreen();
        }
    }
    
    // 保存最近访问记录
    // TODO: 持久化到文件
    
    // 发送退出消息
    sendToUser("\r\n\033[90m已退出。\033[0m\r\n");
}

void InteractiveSession::stop() {
    running_ = false;
    if (currentBridge_) {
        currentBridge_->stop();
    }
}

bool InteractiveSession::tryDirectConnect() {
    std::string target;
    
    // 1. 检查命令行参数 (通过 SSH 原始命令)
    if (!directTarget_.empty()) {
        target = directTarget_;
    }
    
    // 2. 检查环境变量
    if (target.empty()) {
        const char* envTarget = getenv("JUMP_TARGET");
        if (envTarget) {
            target = envTarget;
        }
    }
    
    if (target.empty()) {
        return false;
    }
    
    // 尝试查找并连接目标
    auto assets = assetManager_->getUserAssets(username_, true);
    auto matches = parseUserInput(target, assets);

    if (matches.size() == 1) {
        sendToUser("\r\n正在直接连接到 \033[1;33m" + matches[0].hostname + "\033[0m ...\r\n");
        if (connectToAsset(matches[0])) {
            // 等待连接结束（添加超时检查，最多等待 24 小时）
            auto startTime = std::chrono::steady_clock::now();
            const auto maxWaitTime = std::chrono::hours(24);
            while (running_ && state_ == SessionState::FORWARDING) {
                if (currentBridge_ && !currentBridge_->isRunning()) {
                    break;
                }
                // 检查超时
                if (std::chrono::steady_clock::now() - startTime > maxWaitTime) {
                    LOG_WARN("Session timeout after 24 hours, force closing");
                    break;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
            return true;
        }
    } else if (matches.size() > 1) {
        sendToUser("\r\n\033[31m找到多个匹配项，请使用更精确的名称:\033[0m\r\n");
        for (const auto& asset : matches) {
            sendToUser("  - " + asset.hostname + "\r\n");
        }
        sendToUser("\r\n按任意键继续...\r\n");
        readUserInput();
    } else {
        sendToUser("\r\n\033[31m未找到目标: " + target + "\033[0m\r\n");
        sendToUser("\r\n按任意键继续...\r\n");
        readUserInput();
    }
    
    return false;
}

void InteractiveSession::showAssetMenu(const std::vector<AssetInfo>& assets, int page) {
    // 计算分页
    int totalPages = (assets.size() + ASSETS_PER_PAGE - 1) / ASSETS_PER_PAGE;
    if (page < 0) page = 0;
    if (page >= totalPages) page = totalPages - 1;

    int startIdx = page * ASSETS_PER_PAGE;
    int endIdx = std::min(startIdx + ASSETS_PER_PAGE, static_cast<int>(assets.size()));

    std::stringstream ss;

    // 清屏后显示简化标题
    ss << "\r\n\033[1;36m资产列表\033[0m (" << username_ << ")\r\n";
    ss << "\033[90m" << std::string(70, '-') << "\033[0m\r\n\r\n";

    if (assets.empty()) {
        ss << "  \033[90m暂无可访问的资产\033[0m\r\n";
        ss << "  \033[90m请确认 Agent 是否正常运行并注册到跳板机\033[0m\r\n";
    } else {
        // 简洁的表头
        ss << "  \033[1m序号  主机名              IP地址           状态    \033[0m\r\n";
        ss << "  " << std::string(62, '-') << "\r\n";

        // 资产列表
        for (int i = startIdx; i < endIdx; i++) {
            const auto& asset = assets[i];
            std::string status = asset.isOnline ? "\033[32m●\033[0m" : "\033[31m●\033[0m";
            std::string ip = asset.ipAddress.empty() ? "N/A" : asset.ipAddress;

            // 格式化主机名（限制显示宽度）
            std::string hostname = asset.hostname;
            if (hostname.length() > 18) hostname = hostname.substr(0, 15) + "...";

            // 格式化IP地址（限制显示宽度）
            if (ip.length() > 16) ip = ip.substr(0, 13) + "...";

            ss << "  \033[33m" << std::setw(2) << (i + 1) << "\033[0m   "
               << std::left << std::setw(18) << hostname << "  "
               << std::setw(16) << ip << "  "
               << status << "\r\n";
        }

        // 分页信息
        if (totalPages > 1) {
            ss << "\r\n  页码: \033[1;36m" << (page + 1) << "/" << totalPages << "\033[0m"
               << "  (使用 \033[33mn\033[0m 下一页 / \033[33mp\033[0m 上一页)\r\n";
        }
    }

    // 最近访问（紧凑显示在右侧）
    if (!recentAssets_.empty()) {
        ss << "\r\n  \033[90m最近: \033[0m";
        for (size_t i = 0; i < std::min(size_t(3), recentAssets_.size()); i++) {
            ss << "\033[33m@" << (i + 1) << "\033[0m " << recentAssets_[i].hostname;
            if (i < std::min(size_t(3), recentAssets_.size()) - 1) {
                ss << "  ";
            }
        }
        ss << "\r\n";
    }

    // 简化的提示行
    ss << "\r\n\033[90m" << std::string(70, '-') << "\033[0m\r\n";
    ss << "  \033[36m>\033[0m ";

    sendToUser(ss.str());
}

void InteractiveSession::showWelcome() {
    std::string welcome = "\r\n\033[1;36mSSH Jump Server\033[0m - 安全访问网关\r\n";
    sendToUser(welcome);
}


void InteractiveSession::showHelp() {
    std::string help = R"(
\033[1;36m快速操作指南\033[0m
\033[90m\033[0m

  连接方式:
    \033[33m[序号]\033[0m       直接连接 (如: \033[36m1\033[0m)
    \033[33m[关键字]\033[0m     模糊搜索 (如: \033[36mweb\033[0m)
    \033[33m^[前缀]\033[0m      前缀匹配 (如: \033[36m^web\033[0m)
    \033[33m$后缀\033[0m       后缀匹配 (如: \033[36m$prod\033[0m)
    \033[33m@[序号]\033[0m      最近访问 (如: \033[36m@1\033[0m)

  快捷命令:
    \033[33mn/p\033[0m         下一页/上一页
    \033[33mr\033[0m            刷新资产列表
    \033[33mh\033[0m            显示帮助
    \033[33mq\033[0m            退出系统

  连接后:
    \033[33mexit\033[0m         返回菜单
    \033[33m~.\033[0m           强制断开

\033[90m按回车键返回...\033[0m
)";
    sendToUser(help);
    readUserInput();
}

void InteractiveSession::clearScreen() {
    sendToUser("\033[2J\033[H");
}

std::string InteractiveSession::readUserInput() {
    auto conn = connection_.lock();
    if (!conn) {
        return "";
    }
    
    char buffer[256];
    std::string input;
    
    while (running_) {
        auto channel = conn->getChannel();
        if (!channel) {
            break;
        }
        
        int n = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
        if (n > 0) {
            for (int i = 0; i < n; i++) {
                char c = buffer[i];
                
                // 处理退格
                if (c == '\b' || c == 127) {
                    if (!input.empty()) {
                        input.pop_back();
                        sendToUser("\b \b");
                    }
                    continue;
                }
                
                // 处理回车
                if (c == '\r' || c == '\n') {
                    sendToUser("\r\n");
                    return input;
                }
                
                // 处理 Ctrl+C
                if (c == 3) {
                    return "^C";
                }
                
                // 普通字符
                if (c >= 32 && c < 127) {
                    input += c;
                    std::string echo(1, c);
                    sendToUser(echo);
                }
            }
        } else if (n < 0 && n != SSH_AGAIN) {
            break;
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    
    return input;
}

bool InteractiveSession::handleUserSelection(const std::string& input, 
                                              const std::vector<AssetInfo>& assets) {
    if (input.empty() || input == "^C") {
        return false;
    }
    
    // 处理特殊命令
    if (input == "q" || input == "quit" || input == "exit") {
        state_ = SessionState::EXITING;
        return true;
    }
    
    if (input == "r" || input == "refresh" || input == "l" || input == "list") {
        assetManager_->refreshAssets();
        return true;
    }
    
    if (input == "h" || input == "help" || input == "?") {
        clearScreen();
        showHelp();
        return true;
    }
    
    // 解析输入，获取匹配的资产
    auto matches = parseUserInput(input, assets);
    
    if (matches.empty()) {
        return false;
    }
    
    if (matches.size() == 1) {
        return connectToAsset(matches[0]);
    } else {
        // 多个匹配，显示列表让用户选择
        sendToUser("\r\n找到多个匹配项:\r\n");
        for (size_t i = 0; i < matches.size() && i < 10; i++) {
            sendToUser("  " + std::to_string(i + 1) + ". " + matches[i].hostname + 
                      " (" + matches[i].ipAddress + ")\r\n");
        }
        sendToUser("\r\n请输入序号选择: ");
        return false;
    }
}

std::vector<AssetInfo> InteractiveSession::parseUserInput(const std::string& input, 
                                                           const std::vector<AssetInfo>& assets) {
    std::vector<AssetInfo> matches;
    
    // 检查是否是最近访问快捷方式 (@1, @2, ...)
    if (!input.empty() && input[0] == '@') {
        try {
            int idx = std::stoi(input.substr(1)) - 1;
            if (idx >= 0 && idx < static_cast<int>(recentAssets_.size())) {
                auto asset = assetManager_->getAssetById(recentAssets_[idx].assetId);
                if (asset) {
                    matches.push_back(*asset);
                }
            }
        } catch (...) {
            // 忽略解析错误
        }
        return matches;
    }
    
    // 尝试解析为数字序号
    try {
        int index = std::stoi(input);
        if (index >= 1 && index <= static_cast<int>(assets.size())) {
            matches.push_back(assets[index - 1]);
            return matches;
        }
    } catch (...) {
        // 不是数字，继续按主机名搜索
    }
    
    // 检查是否是前缀匹配 (^web)
    if (!input.empty() && input[0] == '^') {
        std::string prefix = input.substr(1);
        std::string lowerPrefix = prefix;
        std::transform(lowerPrefix.begin(), lowerPrefix.end(), lowerPrefix.begin(), ::tolower);
        
        for (const auto& asset : assets) {
            std::string lowerHostname = asset.hostname;
            std::transform(lowerHostname.begin(), lowerHostname.end(), lowerHostname.begin(), ::tolower);
            
            if (lowerHostname.find(lowerPrefix) == 0) {
                matches.push_back(asset);
            }
        }
        return matches;
    }
    
    // 检查是否是后缀匹配 ($prod)
    if (!input.empty() && input[0] == '$') {
        std::string suffix = input.substr(1);
        std::string lowerSuffix = suffix;
        std::transform(lowerSuffix.begin(), lowerSuffix.end(), lowerSuffix.begin(), ::tolower);
        
        for (const auto& asset : assets) {
            std::string lowerHostname = asset.hostname;
            std::transform(lowerHostname.begin(), lowerHostname.end(), lowerHostname.begin(), ::tolower);
            
            if (lowerHostname.size() >= lowerSuffix.size() &&
                lowerHostname.compare(lowerHostname.size() - lowerSuffix.size(), 
                                      lowerSuffix.size(), lowerSuffix) == 0) {
                matches.push_back(asset);
            }
        }
        return matches;
    }
    
    // 按主机名模糊搜索 (不区分大小写)
    std::string lowerInput = input;
    std::transform(lowerInput.begin(), lowerInput.end(), lowerInput.begin(), ::tolower);
    
    for (const auto& asset : assets) {
        std::string lowerHostname = asset.hostname;
        std::transform(lowerHostname.begin(), lowerHostname.end(), lowerHostname.begin(), ::tolower);
        
        if (lowerHostname.find(lowerInput) != std::string::npos) {
            matches.push_back(asset);
        }
    }
    
    return matches;
}

bool InteractiveSession::connectToAsset(const AssetInfo& asset) {
    state_ = SessionState::CONNECTING;
    
    sendToUser("\r\n正在连接到 \033[1;33m" + asset.hostname + "\033[0m (" + asset.ipAddress + ")...\r\n");
    
    // 创建 SSH 客户端连接目标
    auto targetClient = std::make_shared<SSHClient>();
    
    std::string targetHost = asset.ipAddress.empty() ? asset.hostname : asset.ipAddress;
    int targetPort = asset.getSshPort();

    // 从配置获取目标连接凭据
    auto& configManager = ConfigManager::getInstance();
    const auto securityConfig = configManager.getServerConfig().security;
    std::string targetUser = securityConfig.defaultTargetUser.empty() ? "root" : securityConfig.defaultTargetUser;
    std::string targetPassword = securityConfig.defaultTargetPassword;
    std::string targetPrivateKey = securityConfig.defaultTargetPrivateKey;
    int forwardFd = -1;

    // 检查凭据配置
    if (targetPassword.empty() && targetPrivateKey.empty()) {
        sendToUser("\r\n\033[31m连接失败: 未配置目标连接凭据，请检查服务器配置\033[0m\r\n");
        state_ = SessionState::MENU;
        return false;
    }

    // 优先尝试通过 Agent 回拨建立 NAT 穿透连接
    if (server_ && server_->getClusterManager()) {
        forwardFd = server_->getClusterManager()->establishForwardConnection(asset.id, targetPort);
        if (forwardFd >= 0) {
            sendToUser("\033[90m已建立 Agent 回拨通道，正在进行 SSH 握手...\033[0m\r\n");
            std::string logicalHost = asset.hostname.empty() ? targetHost : asset.hostname;
            if (!targetClient->connectWithSocket(forwardFd, logicalHost, targetPort,
                                                 targetUser, targetPassword, targetPrivateKey)) {
                forwardFd = -1;
                LOG_WARN("SSH handshake over reverse tunnel failed, fallback to direct connect: " + asset.hostname);
            } else {
                LOG_INFO("Connected via reverse tunnel: " + asset.hostname);
            }
        }
    }

    // NAT 通道失败时回退到直连模式（兼容已有非 NAT 场景）
    if (!targetClient->isConnected() &&
        !targetClient->connect(targetHost, targetPort, targetUser, targetPassword, targetPrivateKey)) {
        sendToUser("\r\n\033[31m连接失败: 无法连接到 " + asset.hostname + "\033[0m\r\n");
        state_ = SessionState::MENU;
        return false;
    }
    
    // 请求 PTY
    if (!targetClient->requestPty("xterm", 80, 24)) {
        sendToUser("\r\n\033[31m连接失败: 无法分配终端\033[0m\r\n");
        targetClient->disconnect();
        state_ = SessionState::MENU;
        return false;
    }
    
    // 打开 Shell
    if (!targetClient->openShell()) {
        sendToUser("\r\n\033[31m连接失败: 无法打开 Shell\033[0m\r\n");
        targetClient->disconnect();
        state_ = SessionState::MENU;
        return false;
    }

    // 设置非阻塞模式（对 DataBridge 很重要！）
    targetClient->setNonBlockingMode();

    sendToUser("\033[32m连接成功！正在建立会话...\033[0m\r\n\r\n");

    // 清屏，准备直接转发
    clearScreen();

    // 记录最近访问
    recordRecentAccess(asset.id, asset.hostname);

    // 创建数据桥接
    currentBridge_ = std::make_shared<DataBridge>(connection_.lock(), targetClient);
    currentBridge_->start();

    state_ = SessionState::FORWARDING;

    LOG_INFO("User " + username_ + " connected to asset " + asset.hostname);

    // 等待桥接结束（添加超时检查，最多等待 24 小时）
    auto startTime = std::chrono::steady_clock::now();
    const auto maxWaitTime = std::chrono::hours(24);
    while (running_ && state_ == SessionState::FORWARDING) {
        if (!currentBridge_->isRunning()) {
            break;
        }
        // 检查超时
        if (std::chrono::steady_clock::now() - startTime > maxWaitTime) {
            LOG_WARN("Session timeout after 24 hours, force closing");
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    // 断开目标连接
    targetClient->disconnect();

    // 连接结束，返回菜单
    state_ = SessionState::MENU;
    currentBridge_.reset();

    // 重新显示菜单
    clearScreen();
    showWelcome();

    return true;
}

void InteractiveSession::sendToUser(const std::string& data) {
    auto conn = connection_.lock();
    if (!conn) {
        return;
    }
    
    auto channel = conn->getChannel();
    if (!channel) {
        return;
    }
    
    size_t written = 0;
    while (written < data.length()) {
        int ret = ssh_channel_write(channel, data.c_str() + written, 
                                        data.length() - written);
        if (ret > 0) {
            written += ret;
        } else if (ret != SSH_AGAIN) {
            break;
        }
    }
}

void InteractiveSession::recordRecentAccess(const std::string& assetId, const std::string& hostname) {
    std::lock_guard<std::mutex> lock(mutex_);

    // 检查是否已存在
    for (auto& recent : recentAssets_) {
        if (recent.assetId == assetId) {
            recent.lastAccess = std::chrono::system_clock::now();
            recent.accessCount++;
            return;
        }
    }
    
    // 添加新记录
    RecentAsset recent;
    recent.assetId = assetId;
    recent.hostname = hostname;
    recent.lastAccess = std::chrono::system_clock::now();
    recent.accessCount = 1;
    recentAssets_.insert(recentAssets_.begin(), recent);
    
    // 只保留最近 10 条
    if (recentAssets_.size() > 10) {
        recentAssets_.resize(10);
    }
}

std::vector<RecentAsset> InteractiveSession::getRecentAssets(int limit) {
    if (limit <= 0) {
        return {};
    }

    std::lock_guard<std::mutex> lock(mutex_);
    const size_t count = std::min(static_cast<size_t>(limit), recentAssets_.size());
    return std::vector<RecentAsset>(recentAssets_.begin(), recentAssets_.begin() + count);
}

void InteractiveSession::showEmptyAssetMenu() {
    std::stringstream ss;

    ss << "\r\n\033[1;36m资产列表\033[0m (" << username_ << ")\r\n";
    ss << "\033[90m" << std::string(70, '-') << "\033[0m\r\n";
    ss << "\r\n  \033[90m暂无可访问的资产\033[0m\r\n";
    ss << "  \033[90m请确认 Agent 是否正常运行并注册到跳板机\033[0m\r\n";

    // 最近访问（紧凑显示）
    if (!recentAssets_.empty()) {
        ss << "\r\n  \033[90m最近: \033[0m";
        for (size_t i = 0; i < std::min(size_t(3), recentAssets_.size()); i++) {
            ss << "\033[33m@" << (i + 1) << "\033[0m " << recentAssets_[i].hostname;
            if (i < std::min(size_t(3), recentAssets_.size()) - 1) {
                ss << "  ";
            }
        }
        ss << "\r\n";
    }

    ss << "\r\n\033[90m" << std::string(70, '-') << "\033[0m\r\n";
    ss << "  \033[36mr\033[0m 刷新  \033[36mh\033[0m 帮助  \033[36mq\033[0m 退出\r\n";
    ss << "\033[90m" << std::string(70, '-') << "\033[0m\r\n";
    ss << "  \033[36m>\033[0m ";

    sendToUser(ss.str());
}

bool InteractiveSession::handleEmptyMenuSelection(const std::string& input) {
    if (input.empty()) {
        return true;  // 空输入，重新显示菜单
    }
    
    char cmd = std::tolower(input[0]);
    
    switch (cmd) {
        case 'r': {
            // 刷新资产列表
            sendToUser("\r\n\033[90m正在刷新资产列表...\033[0m\r\n");
            // AssetManager 会在下次循环自动刷新
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            return true;
        }
        
        case 'h': {
            // 显示帮助
            showHelp();
            return true;
        }
        
        case 'q':
        case 'e': {  // exit 的 e
            // 退出系统
            state_ = SessionState::EXITING;
            return true;
        }
        
        case '@': {
            // 尝试连接最近访问
            if (input.length() > 1 && !recentAssets_.empty()) {
                try {
                    int index = std::stoi(input.substr(1)) - 1;
                    if (index >= 0 && index < static_cast<int>(recentAssets_.size())) {
                        // 重新连接到该资产
                        sendToUser("\r\n\033[90m尝试连接最近访问...\033[0m\r\n");
                        // TODO: 实现重新连接逻辑
                    }
                } catch (...) {
                    // 无效的数字
                }
            }
            return true;
        }
        
        default: {
            // 检查是否是搜索输入（长度大于1，不是命令）
            if (input.length() > 1) {
                sendToUser("\r\n\033[90m正在搜索: " + input + "...\033[0m\r\n");
                // 搜索功能：如果资产列表为空，搜索也不会找到结果
                // 但仍然给用户反馈
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
                sendToUser("\033[31m未找到匹配的资产: " + input + "\033[0m\r\n");
                std::this_thread::sleep_for(std::chrono::milliseconds(1000));
                return true;
            }
            return false;  // 无效的命令
        }
    }
}

} // namespace sshjump
