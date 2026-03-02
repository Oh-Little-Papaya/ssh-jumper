/**
 * @file ssh_server.cpp
 * @brief SSH 服务器实现 - 使用 libssh
 *
 * 支持多种接入方式:
 * 1. 直接指定目标: ssh admin@jump.example.com web-server-01
 * 2. 环境变量: JUMP_TARGET=web-server-01 ssh admin@jump.example.com
 * 3. 交互式菜单: ssh admin@jump.example.com
 */

#include "ssh_server.h"

#include <sys/stat.h>

#include <algorithm>
#include <cctype>
#include <iomanip>

#include "config_manager.h"
#include "interactive_session.h"

namespace sshjump {

namespace {

int resolveAuthMethodsMask(const std::string& rawMethods) {
  int mask = 0;
  for (const auto& tokenRaw : splitString(rawMethods, ',')) {
    std::string token = trimString(tokenRaw);
    std::transform(token.begin(), token.end(), token.begin(), ::tolower);
    if (token == "password") {
      mask |= SSH_AUTH_METHOD_PASSWORD;
    } else if (token == "publickey" || token == "public_key") {
      mask |= SSH_AUTH_METHOD_PUBLICKEY;
    } else if (!token.empty()) {
      LOG_WARN("Unsupported SSH auth method ignored: " + token);
    }
  }

  // 安全兜底：至少保留公钥认证
  if (mask == 0) {
    mask = SSH_AUTH_METHOD_PUBLICKEY;
  }
  return mask;
}

}  // namespace

// ============================================
// ConnectionRateLimiter 实现
// ============================================

ConnectionRateLimiter::ConnectionRateLimiter(int maxConnectionsPerMinute)
    : maxConnectionsPerMinute_(std::max(0, maxConnectionsPerMinute)) {}

void ConnectionRateLimiter::setMaxConnectionsPerMinute(
    int maxConnectionsPerMinute) {
  std::lock_guard<std::mutex> lock(mutex_);
  maxConnectionsPerMinute_ = std::max(0, maxConnectionsPerMinute);
}

bool ConnectionRateLimiter::checkAndRecord(const std::string& clientIp) {
  std::lock_guard<std::mutex> lock(mutex_);

  // <=0 表示关闭限流
  if (maxConnectionsPerMinute_ <= 0) {
    return true;
  }

  auto now = std::chrono::steady_clock::now();
  auto& times = connections_[clientIp];

  // 移除一分钟前的记录
  auto oneMinuteAgo = now - std::chrono::seconds(60);
  times.erase(
      std::remove_if(
          times.begin(), times.end(),
          [&oneMinuteAgo](const std::chrono::steady_clock::time_point& tp) {
            return tp < oneMinuteAgo;
          }),
      times.end());

  // 检查是否超过限制
  if (static_cast<int>(times.size()) >= maxConnectionsPerMinute_) {
    LOG_WARN("Rate limit exceeded for IP: " + clientIp +
             " (limit=" + std::to_string(maxConnectionsPerMinute_) + "/min)");
    return false;
  }

  // 记录本次连接
  times.push_back(now);
  return true;
}

void ConnectionRateLimiter::cleanup() {
  std::lock_guard<std::mutex> lock(mutex_);

  auto oneMinuteAgo =
      std::chrono::steady_clock::now() - std::chrono::seconds(60);
  for (auto it = connections_.begin(); it != connections_.end();) {
    auto& times = it->second;
    times.erase(
        std::remove_if(
            times.begin(), times.end(),
            [&oneMinuteAgo](const std::chrono::steady_clock::time_point& tp) {
              return tp < oneMinuteAgo;
            }),
        times.end());
    if (times.empty()) {
      it = connections_.erase(it);
    } else {
      ++it;
    }
  }
}

// ============================================
// AuthFailureTracker 实现
// ============================================

void AuthFailureTracker::recordFailure(const std::string& clientIp) {
  std::lock_guard<std::mutex> lock(mutex_);

  auto& info = failures_[clientIp];
  info.count++;

  if (info.count >= MAX_FAILURES) {
    info.blockedUntil = std::chrono::steady_clock::now() +
                        std::chrono::seconds(BLOCK_DURATION_SECONDS);
    LOG_WARN("IP " + clientIp + " blocked for " +
             std::to_string(BLOCK_DURATION_SECONDS) + " seconds due to " +
             std::to_string(info.count) + " failed auth attempts");
  }
}

bool AuthFailureTracker::isBlocked(const std::string& clientIp) {
  std::lock_guard<std::mutex> lock(mutex_);

  auto it = failures_.find(clientIp);
  if (it == failures_.end()) {
    return false;
  }

  const auto& info = it->second;
  if (info.count < MAX_FAILURES) {
    return false;
  }

  // 检查是否仍在封禁期内
  if (std::chrono::steady_clock::now() < info.blockedUntil) {
    return true;
  }

  // 封禁期已过，重置计数
  failures_.erase(it);
  return false;
}

void AuthFailureTracker::cleanup() {
  std::lock_guard<std::mutex> lock(mutex_);

  auto now = std::chrono::steady_clock::now();
  for (auto it = failures_.begin(); it != failures_.end();) {
    const auto& info = it->second;
    // 移除封禁期已过且无近期失败的记录
    if (info.count >= MAX_FAILURES && now >= info.blockedUntil) {
      it = failures_.erase(it);
    } else {
      ++it;
    }
  }
}

// ============================================
// ConnectionPool 实现
// ============================================

ConnectionPool::ConnectionPool(size_t maxSize) : maxSize_(maxSize) {}

ConnectionPool::~ConnectionPool() { closeAll(); }

bool ConnectionPool::addConnection(const std::string& id,
                                   std::shared_ptr<SSHConnection> conn) {
  std::unique_lock<std::mutex> lock(mutex_);

  // 清理已失效的连接
  for (auto it = connections_.begin(); it != connections_.end();) {
    if (it->second.expired()) {
      it = connections_.erase(it);
    } else {
      ++it;
    }
  }

  // 检查是否超过最大连接数
  if (connections_.size() >= maxSize_) {
    LOG_WARN("Connection pool full, rejecting new connection");
    return false;
  }

  connections_[id] = conn;
  LOG_INFO("Connection added to pool, id=" + id +
           ", total=" + std::to_string(connections_.size()));
  return true;
}

std::shared_ptr<SSHConnection> ConnectionPool::getConnection(
    const std::string& id) {
  std::unique_lock<std::mutex> lock(mutex_);

  auto it = connections_.find(id);
  if (it != connections_.end()) {
    return it->second.lock();
  }

  return nullptr;
}

void ConnectionPool::removeConnection(const std::string& id) {
  std::unique_lock<std::mutex> lock(mutex_);
  connections_.erase(id);
  LOG_DEBUG("Connection removed from pool, id=" + id);
}

size_t ConnectionPool::size() const {
  std::unique_lock<std::mutex> lock(mutex_);
  return connections_.size();
}

void ConnectionPool::cleanupTimeoutConnections(int timeoutSeconds) {
  auto now = std::chrono::steady_clock::now();
  std::vector<std::string> toRemove;

  {
    std::unique_lock<std::mutex> lock(mutex_);

    for (auto& pair : connections_) {
      auto conn = pair.second.lock();
      if (!conn) {
        toRemove.push_back(pair.first);
      } else {
        auto lastActivity = conn->getLastActivity();
        auto elapsed =
            std::chrono::duration_cast<std::chrono::seconds>(now - lastActivity)
                .count();

        if (elapsed > timeoutSeconds) {
          toRemove.push_back(pair.first);
        }
      }
    }
  }

  // 关闭超时连接
  for (const auto& id : toRemove) {
    auto conn = getConnection(id);
    if (conn) {
      LOG_INFO("Closing timeout connection, id=" + id);
      conn->close();
    }
    removeConnection(id);
  }
}

void ConnectionPool::closeAll() {
  std::vector<std::shared_ptr<SSHConnection>> conns;

  {
    std::unique_lock<std::mutex> lock(mutex_);
    for (auto& pair : connections_) {
      auto conn = pair.second.lock();
      if (conn) {
        conns.push_back(conn);
      }
    }
    connections_.clear();
  }

  for (auto& conn : conns) {
    conn->close();
  }
}

// ============================================
// SSHConnection 实现
// ============================================

SSHConnection::SSHConnection(ssh_session session, ssh_bind sshbind,
                             SSHServer* server)
    : session_(session),
      sshbind_(sshbind),
      server_(server),
      channel_(nullptr),
      handshakeComplete_(false),
      authenticated_(false) {
  memset(&serverCallbacks_, 0, sizeof(serverCallbacks_));
  connId_ = generateUUID();
  lastActivity_ = std::chrono::steady_clock::now();
}

SSHConnection::~SSHConnection() { close(); }

bool SSHConnection::initialize() {
  if (!session_) {
    LOG_ERROR("SSH session is null");
    return false;
  }

  LOG_INFO("SSHConnection initialized, id=" + connId_);
  return true;
}

ssh_session SSHConnection::getSession() {
  std::lock_guard<std::mutex> lock(mutex_);
  return session_;
}

ssh_channel SSHConnection::getChannel() {
  std::lock_guard<std::mutex> lock(mutex_);
  return channel_;
}

std::chrono::steady_clock::time_point SSHConnection::getLastActivity() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return lastActivity_;
}

void SSHConnection::updateActivity() {
  std::lock_guard<std::mutex> lock(mutex_);
  lastActivity_ = std::chrono::steady_clock::now();
}

int SSHConnection::readChannel(char* buffer, size_t len, int timeoutMs) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (!channel_) {
    return -1;
  }
  return ssh_channel_read_timeout(channel_, buffer, len, 0, timeoutMs);
}

int SSHConnection::writeChannel(const char* data, size_t len) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (!channel_) {
    return -1;
  }
  return ssh_channel_write(channel_, data, len);
}

bool SSHConnection::hasSession() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return session_ != nullptr;
}

bool SSHConnection::hasChannel() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return channel_ != nullptr;
}

bool SSHConnection::isChannelOpen() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return channel_ && ssh_channel_is_open(channel_);
}

bool SSHConnection::isChannelEof() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return channel_ && ssh_channel_is_eof(channel_);
}

void SSHConnection::start() {
  const auto config = ConfigManager::getInstance().getServerConfig();
  const int authMethodsMask = resolveAuthMethodsMask(config.ssh.authMethods);

  // 注册服务端认证回调，避免使用已弃用的 ssh_message_auth_* 接口。
  memset(&serverCallbacks_, 0, sizeof(serverCallbacks_));
  serverCallbacks_.userdata = this;
  serverCallbacks_.auth_password_function = &SSHConnection::onAuthPassword;
  serverCallbacks_.auth_pubkey_function = &SSHConnection::onAuthPublickey;
  ssh_callbacks_init(&serverCallbacks_);
  if (ssh_set_server_callbacks(session_, &serverCallbacks_) != SSH_OK) {
    LOG_ERROR("Failed to set server callbacks: " +
              std::string(ssh_get_error(session_)));
    close();
    return;
  }
  ssh_set_message_callback(session_, &SSHConnection::onMessage, this);
  ssh_set_auth_methods(session_, authMethodsMask);

  // 处理密钥交换
  int rc = ssh_handle_key_exchange(session_);
  if (rc != SSH_OK) {
    LOG_ERROR("SSH key exchange failed: " +
              std::string(ssh_get_error(session_)));
    close();
    return;
  }

  handshakeComplete_ = true;
  LOG_INFO("SSH handshake successful, id=" + connId_);

  // 添加到连接池
  server_->getConnectionPool()->addConnection(connId_, shared_from_this());

  // 回调驱动认证阶段
  ssh_set_blocking(session_, 0);
  while (!authenticated_ && session_ && ssh_is_connected(session_)) {
    if (ssh_execute_message_callbacks(session_) != SSH_OK) {
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }

  if (!authenticated_) {
    LOG_WARN("Authentication failed or cancelled, id=" + connId_);
    close();
    return;
  }

  // 继续处理通道请求
  handleSession();
}

void SSHConnection::close() {
  std::shared_ptr<InteractiveSession> interactiveSession;
  ssh_channel channel = nullptr;
  ssh_session session = nullptr;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    interactiveSession = std::move(interactiveSession_);
    channel = channel_;
    channel_ = nullptr;
    session = session_;
    session_ = nullptr;
  }

  // 先停止交互会话，再释放 libssh 资源，避免并发读写造成数据竞争。
  if (interactiveSession) {
    interactiveSession->stop();
  }

  if (channel) {
    ssh_channel_close(channel);
    ssh_channel_free(channel);
  }

  if (session) {
    ssh_disconnect(session);
    ssh_free(session);
  }

  if (server_) {
    server_->getConnectionPool()->removeConnection(connId_);
  }

  LOG_INFO("SSHConnection closed, id=" + connId_);
}

void SSHConnection::handleSession() {
  while (session_ && ssh_is_connected(session_)) {
    if (ssh_execute_message_callbacks(session_) != SSH_OK) {
      if (session_) {
        LOG_ERROR("Failed to process SSH messages: " +
                  std::string(ssh_get_error(session_)));
      }
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
}

int SSHConnection::onAuthPassword(ssh_session session, const char* user,
                                  const char* password, void* userdata) {
  (void)session;
  auto* self = static_cast<SSHConnection*>(userdata);
  if (!self) {
    return SSH_AUTH_DENIED;
  }
  return self->handleAuthPassword(user, password);
}

int SSHConnection::onAuthPublickey(ssh_session session, const char* user,
                                   ssh_key pubkey, char signatureState,
                                   void* userdata) {
  (void)session;
  auto* self = static_cast<SSHConnection*>(userdata);
  if (!self) {
    return SSH_AUTH_DENIED;
  }
  return self->handleAuthPublickey(user, pubkey, signatureState);
}

int SSHConnection::onMessage(ssh_session session, ssh_message message,
                             void* userdata) {
  (void)session;
  auto* self = static_cast<SSHConnection*>(userdata);
  if (!self || !message) {
    return 1;
  }
  return self->handleMessage(message);
}

int SSHConnection::handleAuthPassword(const char* user, const char* password) {
  if (!user || !password) {
    return SSH_AUTH_DENIED;
  }

  auto& configManager = ConfigManager::getInstance();
  if (configManager.verifyUserPassword(user, password)) {
    username_ = user;
    authenticated_ = true;
    LOG_INFO("Password authentication successful, user=" + username_);
    return SSH_AUTH_SUCCESS;
  }

  if (server_ && !clientIp_.empty()) {
    server_->recordAuthFailure(clientIp_);
  }
  LOG_WARN("Password authentication failed for user=" + std::string(user) +
           " from " + clientIp_);
  return SSH_AUTH_DENIED;
}

int SSHConnection::handleAuthPublickey(const char* user, ssh_key clientPubKey,
                                       char signatureState) {
  if (!user || !clientPubKey) {
    if (server_ && !clientIp_.empty()) {
      server_->recordAuthFailure(clientIp_);
    }
    return SSH_AUTH_DENIED;
  }

  auto& configManager = ConfigManager::getInstance();
  if (!configManager.userExists(user)) {
    if (server_ && !clientIp_.empty()) {
      server_->recordAuthFailure(clientIp_);
    }
    LOG_WARN("Public key authentication failed: user not found: " +
             std::string(user));
    return SSH_AUTH_DENIED;
  }

  if (signatureState != SSH_PUBLICKEY_STATE_NONE &&
      signatureState != SSH_PUBLICKEY_STATE_VALID) {
    if (server_ && !clientIp_.empty()) {
      server_->recordAuthFailure(clientIp_);
    }
    LOG_WARN(
        "Public key authentication failed: invalid signature state for user=" +
        std::string(user));
    return SSH_AUTH_DENIED;
  }

  unsigned char* hash = nullptr;
  size_t hashLen = 0;
  int rc = ssh_get_publickey_hash(clientPubKey, SSH_PUBLICKEY_HASH_SHA256,
                                  &hash, &hashLen);
  if (rc != SSH_OK || !hash || hashLen == 0) {
    if (server_ && !clientIp_.empty()) {
      server_->recordAuthFailure(clientIp_);
    }
    LOG_WARN(
        "Public key authentication failed: unable to get public key hash for "
        "user=" +
        std::string(user));
    return SSH_AUTH_DENIED;
  }

  std::stringstream ss;
  for (size_t i = 0; i < hashLen; i++) {
    ss << std::hex << std::setw(2) << std::setfill('0')
       << static_cast<int>(hash[i]);
  }
  std::string keyFingerprint = ss.str();
  ssh_clean_pubkey_hash(&hash);

  if (!configManager.verifyUserPublicKey(user, keyFingerprint)) {
    if (server_ && !clientIp_.empty()) {
      server_->recordAuthFailure(clientIp_);
    }
    LOG_WARN(
        "Public key authentication failed: fingerprint mismatch for user=" +
        std::string(user));
    return SSH_AUTH_DENIED;
  }

  if (signatureState == SSH_PUBLICKEY_STATE_VALID) {
    username_ = user;
    authenticated_ = true;
    LOG_INFO("Public key authentication successful, user=" + username_);
  }
  return SSH_AUTH_SUCCESS;
}

int SSHConnection::handleMessage(ssh_message message) {
  updateActivity();

  const int msgType = ssh_message_type(message);
  const int msgSubtype = ssh_message_subtype(message);
  switch (msgType) {
    case SSH_REQUEST_CHANNEL_OPEN:
      if (msgSubtype == SSH_CHANNEL_SESSION) {
        handleChannelOpen(message);
        return 0;
      }
      return 1;
    case SSH_REQUEST_CHANNEL:
      handleChannelRequest(message);
      return 0;
    default:
      return 1;
  }
}

void SSHConnection::handleChannelOpen(ssh_message message) {
  if (!authenticated_) {
    LOG_WARN("Channel open rejected: not authenticated, id=" + connId_);
    ssh_message_reply_default(message);
    return;
  }

  // 使用 libssh 的正确函数接受通道打开请求
  channel_ = ssh_message_channel_request_open_reply_accept(message);
  if (!channel_) {
    LOG_ERROR("Failed to accept channel: " +
              std::string(ssh_get_error(session_)));
    return;
  }

  // 设置通道为非阻塞模式
  ssh_channel_set_blocking(channel_, 0);
}

void SSHConnection::handleChannelRequest(ssh_message message) {
  if (!channel_) {
    ssh_message_reply_default(message);
    return;
  }

  int subtype = ssh_message_subtype(message);

  switch (subtype) {
    case SSH_CHANNEL_REQUEST_PTY: {
      // PTY 请求
      ssh_message_channel_request_reply_success(message);
      break;
    }

    case SSH_CHANNEL_REQUEST_SHELL: {
      // Shell 请求
      ssh_message_channel_request_reply_success(message);
      // 启动交互式会话
      startInteractiveSession();
      break;
    }

    case SSH_CHANNEL_REQUEST_EXEC: {
      // Exec 请求 - 获取命令
      const char* cmd = ssh_message_channel_request_command(message);
      if (cmd) {
        rawCommand_ = cmd;
        ssh_message_channel_request_reply_success(message);
        // 启动交互式会话，传入命令
        startInteractiveSession();
      } else {
        ssh_message_reply_default(message);
      }
      break;
    }

    default:
      ssh_message_reply_default(message);
      break;
  }
}

void SSHConnection::startInteractiveSession() {
  interactiveSession_ =
      std::make_shared<InteractiveSession>(shared_from_this(), server_);

  // 如果有原始命令，设置为直接目标
  if (!rawCommand_.empty()) {
    interactiveSession_->setDirectTarget(rawCommand_);
  }

  // 在当前线程中运行交互式会话（阻塞模式）
  // 这会处理所有后续的通道通信
  interactiveSession_->start();

  // 会话结束，断开连接
  LOG_INFO("Interactive session ended, closing connection id=" + connId_);
  close();
}

// ============================================
// SSHServer 实现
// ============================================

SSHServer::SSHServer()
    : sshbind_(nullptr), port_(DEFAULT_SSH_PORT), running_(false) {}

SSHServer::~SSHServer() { stop(); }

bool SSHServer::initialize(const std::string& listenAddr, int port,
                           const std::string& hostKeyPath,
                           std::shared_ptr<IEventLoop> eventLoop) {
  listenAddr_ = listenAddr;
  port_ = port;
  hostKeyPath_ = hostKeyPath;
  eventLoop_ = eventLoop;

  // 创建 ssh_bind
  sshbind_ = ssh_bind_new();
  if (!sshbind_) {
    LOG_ERROR("Failed to create ssh_bind");
    return false;
  }

  // 设置监听地址和端口
  ssh_bind_options_set(sshbind_, SSH_BIND_OPTIONS_BINDADDR, listenAddr.c_str());
  ssh_bind_options_set(sshbind_, SSH_BIND_OPTIONS_BINDPORT_STR,
                       std::to_string(port).c_str());

  // 设置主机密钥（RSA）
  if (!hostKeyPath.empty()) {
    std::string rsaKeyPath = hostKeyPath;
    ssh_bind_options_set(sshbind_, SSH_BIND_OPTIONS_RSAKEY, rsaKeyPath.c_str());

    // 也尝试设置 ECDSA 密钥（如果存在）
    std::string ecdsaKeyPath = hostKeyPath + "_ecdsa";
    struct stat st;
    if (stat(ecdsaKeyPath.c_str(), &st) == 0) {
      ssh_bind_options_set(sshbind_, SSH_BIND_OPTIONS_ECDSAKEY,
                           ecdsaKeyPath.c_str());
    }
  }

  // 开始监听
  if (ssh_bind_listen(sshbind_) < 0) {
    LOG_ERROR("Failed to bind/listen: " + std::string(ssh_get_error(sshbind_)));
    ssh_bind_free(sshbind_);
    sshbind_ = nullptr;
    return false;
  }

  // 创建连接池
  connPool_ = std::make_shared<ConnectionPool>();

  // 创建线程池
  threadPool_ = std::make_shared<ThreadPool>();
  threadPool_->start();

  LOG_INFO("SSHServer initialized on " + listenAddr + ":" +
           std::to_string(port));
  return true;
}

bool SSHServer::start() {
  if (!sshbind_) {
    LOG_ERROR("Server not initialized");
    return false;
  }

  running_ = true;

  // 启动接受连接的线程
  acceptThread_ = std::thread(&SSHServer::acceptLoop, this);

  LOG_INFO("SSHServer started");
  return true;
}

void SSHServer::stop() {
  running_ = false;

  // 关闭 sshbind 的 socket 来中断 accept 调用
  if (sshbind_) {
    socket_t fd = ssh_bind_get_fd(sshbind_);
    if (fd != -1) {
      int tmpFd = fd;
      closeSocket(tmpFd);
    }
  }

  // 等待 accept 线程退出，避免对象销毁后后台线程继续访问 this。
  if (acceptThread_.joinable()) {
    acceptThread_.join();
  }

  if (connPool_) {
    connPool_->closeAll();
  }

  if (threadPool_) {
    threadPool_->stop();
  }

  if (sshbind_) {
    ssh_bind_free(sshbind_);
    sshbind_ = nullptr;
  }

  LOG_INFO("SSHServer stopped");
}

void SSHServer::run() {
  // 主循环保持运行
  while (running_) {
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
}

void SSHServer::acceptLoop() {
  while (running_) {
    // 创建新的会话
    ssh_session session = ssh_new();
    if (!session) {
      LOG_ERROR("Failed to create ssh session");
      continue;
    }

    // 接受连接
    int rc = ssh_bind_accept(sshbind_, session);
    if (rc == SSH_ERROR) {
      if (running_) {
        LOG_ERROR("Failed to accept connection: " +
                  std::string(ssh_get_error(sshbind_)));
      }
      ssh_free(session);
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
      continue;
    }

    // 获取客户端地址
    struct sockaddr_storage clientAddr;
    socklen_t addrLen = sizeof(clientAddr);
    socket_t fd = ssh_get_fd(session);
    std::string clientIpStr = "unknown";
    memset(&clientAddr, 0, sizeof(clientAddr));
    if (fd != -1 &&
        getpeername(fd, reinterpret_cast<struct sockaddr*>(&clientAddr),
                    &addrLen) == 0) {
      char clientIp[INET6_ADDRSTRLEN] = {0};
      const void* addrPtr = nullptr;
      int family = AF_UNSPEC;
      if (clientAddr.ss_family == AF_INET) {
        family = AF_INET;
        addrPtr = &reinterpret_cast<struct sockaddr_in*>(&clientAddr)->sin_addr;
      } else if (clientAddr.ss_family == AF_INET6) {
        family = AF_INET6;
        addrPtr =
            &reinterpret_cast<struct sockaddr_in6*>(&clientAddr)->sin6_addr;
      }

      if (addrPtr &&
          inet_ntop(family, addrPtr, clientIp, sizeof(clientIp)) != nullptr) {
        clientIpStr = clientIp;
      }
    }

    // 检查是否被封禁
    if (authFailureTracker_.isBlocked(clientIpStr)) {
      LOG_WARN("Connection rejected from blocked IP: " + clientIpStr);
      ssh_disconnect(session);
      ssh_free(session);
      continue;
    }

    // 检查速率限制
    if (!rateLimiter_.checkAndRecord(clientIpStr)) {
      LOG_WARN("Connection rejected due to rate limiting: " + clientIpStr);
      ssh_disconnect(session);
      ssh_free(session);
      continue;
    }

    LOG_INFO("New connection from " + clientIpStr);

    // 提交到线程池处理
    threadPool_->submit([this, session, clientIpStr]() {
      auto conn = std::make_shared<SSHConnection>(session, sshbind_, this);
      conn->setClientIp(clientIpStr);

      if (!conn->initialize()) {
        LOG_ERROR("Failed to initialize connection");
        ssh_disconnect(session);
        ssh_free(session);
        return;
      }

      conn->start();
    });
  }
}

bool SSHServer::authenticateUser(const std::string& username,
                                 const std::string& password) {
  auto& configManager = ConfigManager::getInstance();
  return configManager.verifyUserPassword(username, password);
}

bool SSHServer::checkUserPublicKey(const std::string& username,
                                   const std::string& publicKey) {
  auto& configManager = ConfigManager::getInstance();
  return configManager.verifyUserPublicKey(username, publicKey);
}

}  // namespace sshjump
