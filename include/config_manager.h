/**
 * @file config_manager.h
 * @brief 配置管理器
 */

#ifndef SSH_JUMP_CONFIG_MANAGER_H
#define SSH_JUMP_CONFIG_MANAGER_H

#include "common.h"

namespace sshjump {

// ============================================
// SSH 配置
// ============================================
struct SSHConfig {
    std::string listenAddress = "0.0.0.0";
    int port = DEFAULT_SSH_PORT;
    std::string hostKeyPath = "/etc/ssh_jump/host_key";
    std::string authMethods = "publickey";
    bool permitRootLogin = false;
    int maxAuthTries = 3;
    int idleTimeout = 300;
};

// ============================================
// 集群配置
// ============================================
struct ClusterConfig {
    std::string listenAddress = "0.0.0.0";
    int port = DEFAULT_CLUSTER_PORT;
    std::string agentTokenFile = "/etc/ssh_jump/agent_tokens.conf";
    int heartbeatInterval = 30;
    int heartbeatTimeout = 90;
};

// ============================================
// 资产配置
// ============================================
struct AssetsConfig {
    int refreshInterval = 30;
    std::string permissionsFile = "/etc/ssh_jump/user_permissions.conf";
};

// ============================================
// 日志配置
// ============================================
struct LoggingConfig {
    std::string level = "info";
    std::string logFile = "/var/log/ssh_jump/server.log";
    std::string auditLog = "/var/log/ssh_jump/audit.log";
    bool sessionRecording = true;
    std::string sessionPath = "/var/log/ssh_jump/sessions/";
};

// ============================================
// 安全配置
// ============================================
struct SecurityConfig {
    bool commandAudit = true;
    std::vector<std::string> allowedCommands;
    std::vector<std::string> forbiddenCommands;
    bool allowPortForwarding = false;
    bool allowSftp = false;
    std::string usersFile = "/etc/ssh_jump/users.conf";  // 用户认证文件路径

    // 目标连接凭据配置（用于连接到 Agent）
    std::string defaultTargetUser = "root";           // 默认目标用户
    std::string defaultTargetPassword;                // 默认目标密码（建议使用私钥）
    std::string defaultTargetPrivateKey;              // 默认目标私钥路径
    std::string defaultTargetPrivateKeyPassword;      // 私钥密码（如果有）
};

// ============================================
// 公网管理节点配置
// ============================================
struct ManagementConfig {
    std::string childNodesFile = "/etc/ssh_jump/child_nodes.conf";
};

// ============================================
// 用户认证信息
// ============================================
struct UserAuthInfo {
    std::string username;
    std::string passwordHash;      // PBKDF2 或旧 SHA256 哈希
    std::string publicKey;         // 可选的公钥
    bool enabled = true;
    bool mustChangePassword = false;  // 首次登录强制修改密码

    // 检查密码哈希格式是否为新版 PBKDF2
    bool isPbkdf2Hash() const {
        return passwordHash.find("PBKDF2$") == 0;
    }
};

// ============================================
// 服务器配置
// ============================================
struct ServerConfig {
    SSHConfig ssh;
    ClusterConfig cluster;
    AssetsConfig assets;
    LoggingConfig logging;
    SecurityConfig security;
    ManagementConfig management;
    std::unordered_map<std::string, UserAuthInfo> users;  // 用户认证信息
};

// ============================================
// 配置管理器
// ============================================
class ConfigManager : public Singleton<ConfigManager> {
public:
    ConfigManager();
    ~ConfigManager();
    
    // 从文件加载配置
    bool loadFromFile(const std::string& path);
    
    // 加载用户认证配置
    bool loadUsers(const std::string& path);
    
    // 验证用户密码
    bool verifyUserPassword(const std::string& username, const std::string& password);
    
    // 验证用户公钥
    bool verifyUserPublicKey(const std::string& username, const std::string& publicKey);
    
    // 检查用户是否存在
    bool userExists(const std::string& username);

    // 获取服务器配置（线程安全）
    ServerConfig& getServerConfig() {
        std::unique_lock<std::shared_mutex> lock(configMutex_);
        return serverConfig_;
    }
    const ServerConfig& getServerConfig() const {
        std::shared_lock<std::shared_mutex> lock(configMutex_);
        return serverConfig_;
    }
    
    // 验证配置
    bool validate();
    
    // 打印配置
    void printConfig();
    
private:
    // 解析配置行
    void parseLine(const std::string& line, std::string& currentSection);
    
    // 计算密码 SHA256 哈希
    std::string hashPassword(const std::string& password);

    // 使用 PBKDF2-HMAC-SHA512 计算密码哈希
    std::string hashPasswordPbkdf2(const std::string& password);

    // 验证 PBKDF2 密码哈希
    bool verifyPbkdf2Password(const std::string& password, const std::string& storedHash);

    // 验证旧版 SHA256 密码哈希（向后兼容）
    bool verifySha256Password(const std::string& password, const std::string& storedHash);

    // 生成随机盐值
    static std::string generateSalt(size_t length = 32);

    // 服务器配置
    ServerConfig serverConfig_;
    mutable std::shared_mutex configMutex_;  // 读写锁保护 serverConfig_
};

} // namespace sshjump

#endif // SSH_JUMP_CONFIG_MANAGER_H
