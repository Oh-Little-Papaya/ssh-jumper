/**
 * @file config_manager.cpp
 * @brief 配置管理器实现
 */

#include "config_manager.h"
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <iomanip>

namespace sshjump {

// PBKDF2 配置常量
constexpr int PBKDF2_ITERATIONS = 100000;
constexpr int PBKDF2_SALT_LENGTH = 32;
constexpr int PBKDF2_HASH_LENGTH = 64;

// 全局日志级别定义
std::atomic<LogLevel> g_logLevel{LogLevel::INFO};

ConfigManager::ConfigManager() {
}

ConfigManager::~ConfigManager() {
}

bool ConfigManager::loadFromFile(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) {
        LOG_WARN("Failed to open config file: " + path);
        return false;
    }

    std::string line;
    std::string currentSection;

    while (std::getline(file, line)) {
        line = trimString(line);

        if (line.empty() || line[0] == '#' || line[0] == ';') {
            continue;
        }

        // 解析节
        if (line[0] == '[' && line[line.size() - 1] == ']') {
            currentSection = line.substr(1, line.size() - 2);
            continue;
        }

        // 解析键值对并直接处理（移除冗余的 parseLine 调用）
        parseLine(line, currentSection);
    }

    file.close();
    LOG_INFO("Config loaded from: " + path);

    // 加载用户认证配置
    loadUsers(serverConfig_.security.usersFile);

    return true;
}

void ConfigManager::parseLine(const std::string& line, std::string& currentSection) {
    size_t pos = line.find('=');
    if (pos == std::string::npos) {
        return;
    }

    std::string key = trimString(line.substr(0, pos));
    std::string value = trimString(line.substr(pos + 1));

    if (value.size() >= 2 && value[0] == '"' && value[value.size() - 1] == '"') {
        value = value.substr(1, value.size() - 2);
    }

    if (currentSection == "ssh") {
        if (key == "listen_address") serverConfig_.ssh.listenAddress = value;
        else if (key == "port") serverConfig_.ssh.port = safeStringToInt(value, DEFAULT_SSH_PORT);
        else if (key == "host_key_path") serverConfig_.ssh.hostKeyPath = value;
        else if (key == "auth_methods") serverConfig_.ssh.authMethods = value;
        else if (key == "permit_root_login") serverConfig_.ssh.permitRootLogin = (value == "true");
        else if (key == "max_auth_tries") serverConfig_.ssh.maxAuthTries = safeStringToInt(value, 3);
        else if (key == "idle_timeout") serverConfig_.ssh.idleTimeout = safeStringToInt(value, 300);
    }
    else if (currentSection == "cluster") {
        if (key == "listen_address") serverConfig_.cluster.listenAddress = value;
        else if (key == "port") serverConfig_.cluster.port = safeStringToInt(value, DEFAULT_CLUSTER_PORT);
        else if (key == "agent_token_file") serverConfig_.cluster.agentTokenFile = value;
        else if (key == "heartbeat_interval") serverConfig_.cluster.heartbeatInterval = safeStringToInt(value, DEFAULT_HEARTBEAT_INTERVAL);
        else if (key == "heartbeat_timeout") serverConfig_.cluster.heartbeatTimeout = safeStringToInt(value, 90);
    }
    else if (currentSection == "assets") {
        if (key == "refresh_interval") serverConfig_.assets.refreshInterval = safeStringToInt(value, 30);
        else if (key == "permissions_file") serverConfig_.assets.permissionsFile = value;
    }
    else if (currentSection == "logging") {
        if (key == "level") serverConfig_.logging.level = value;
        else if (key == "log_file") serverConfig_.logging.logFile = value;
        else if (key == "audit_log") serverConfig_.logging.auditLog = value;
        else if (key == "session_recording") serverConfig_.logging.sessionRecording = (value == "true");
        else if (key == "session_path") serverConfig_.logging.sessionPath = value;
    }
    else if (currentSection == "security") {
        if (key == "command_audit") serverConfig_.security.commandAudit = (value == "true");
        else if (key == "allow_port_forwarding") serverConfig_.security.allowPortForwarding = (value == "true");
        else if (key == "allow_sftp") serverConfig_.security.allowSftp = (value == "true");
        else if (key == "users_file") serverConfig_.security.usersFile = value;
        else if (key == "default_target_user") serverConfig_.security.defaultTargetUser = value;
        else if (key == "default_target_password") serverConfig_.security.defaultTargetPassword = value;
        else if (key == "default_target_private_key") serverConfig_.security.defaultTargetPrivateKey = value;
        else if (key == "default_target_key_password") serverConfig_.security.defaultTargetPrivateKeyPassword = value;
    }
    else if (currentSection == "management") {
        if (key == "child_nodes_file") serverConfig_.management.childNodesFile = value;
    }
}

bool ConfigManager::loadUsers(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) {
        LOG_ERROR("Failed to open users file: " + path);
        LOG_ERROR("Please create users using the user_tool utility");
        LOG_ERROR("Example: ./ssh_jump_user_tool --create-user admin --password 'YourSecurePassword'");
        return false;
    }

    std::string line;
    while (std::getline(file, line)) {
        line = trimString(line);

        if (line.empty() || line[0] == '#' || line[0] == ';') {
            continue;
        }

        // 格式: username = password_hash [:public_key] [:must_change]
        size_t pos = line.find('=');
        if (pos == std::string::npos) {
            continue;
        }

        std::string username = trimString(line.substr(0, pos));
        std::string value = trimString(line.substr(pos + 1));

        if (username.empty() || value.empty()) {
            continue;
        }

        UserAuthInfo user;
        user.username = username;

        // 解析各个部分
        std::vector<std::string> parts = splitString(value, ':');
        if (parts.empty()) {
            continue;
        }

        // 第一部分是密码哈希
        user.passwordHash = trimString(parts[0]);

        // 检查剩余部分
        for (size_t i = 1; i < parts.size(); i++) {
            std::string part = trimString(parts[i]);

            if (part == "must_change") {
                user.mustChangePassword = true;
            } else if (part.substr(0, 7) == "ssh-rsa" ||
                       part.substr(0, 7) == "ssh-ed2" ||
                       part.substr(0, 8) == "ssh-ed25519" ||
                       part.substr(0, 7) == "ecdsa-") {
                // 公钥
                user.publicKey = part;
            } else if (part.find("SHA256:") == 0 || part.length() >= 32) {
                // 可能是公钥指纹
                user.publicKey = part;
            }
        }

        user.enabled = true;
        serverConfig_.users[username] = user;
        LOG_INFO("Loaded user: " + username);
    }

    file.close();
    LOG_INFO("Users loaded from: " + path + ", total: " + std::to_string(serverConfig_.users.size()));
    return true;
}

std::string ConfigManager::hashPassword(const std::string& password) {
    // 默认使用 PBKDF2-HMAC-SHA512
    return hashPasswordPbkdf2(password);
}

std::string ConfigManager::hashPasswordPbkdf2(const std::string& password) {
    // 生成随机盐值
    std::string salt = generateSalt(PBKDF2_SALT_LENGTH);
    if (salt.empty()) {
        LOG_ERROR("Failed to generate salt for password hashing");
        return "";
    }

    // 计算哈希
    unsigned char hash[PBKDF2_HASH_LENGTH];
    int ret = PKCS5_PBKDF2_HMAC(
        password.c_str(), password.length(),
        reinterpret_cast<const unsigned char*>(salt.c_str()), salt.length(),
        PBKDF2_ITERATIONS,
        EVP_sha512(),
        PBKDF2_HASH_LENGTH, hash
    );

    if (ret != 1) {
        LOG_ERROR("PKCS5_PBKDF2_HMAC failed");
        return "";
    }

    // 格式: PBKDF2$iterations$salt_hex$hash_hex
    std::stringstream ss;
    ss << "PBKDF2$" << PBKDF2_ITERATIONS << "$";

    // 盐值转十六进制
    for (int i = 0; i < PBKDF2_SALT_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0')
           << static_cast<int>(static_cast<unsigned char>(salt[i]));
    }
    ss << "$";

    // 哈希转十六进制
    for (int i = 0; i < PBKDF2_HASH_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0')
           << static_cast<int>(hash[i]);
    }

    return ss.str();
}

bool ConfigManager::verifyPbkdf2Password(const std::string& password, const std::string& storedHash) {
    // 解析存储的哈希: PBKDF2$iterations$salt_hex$hash_hex
    auto parts = splitString(storedHash, '$');
    if (parts.size() != 4 || parts[0] != "PBKDF2") {
        LOG_ERROR("Invalid PBKDF2 hash format");
        return false;
    }

    int iterations = std::stoi(parts[1]);
    std::string saltHex = parts[2];
    std::string expectedHashHex = parts[3];

    // 十六进制转字节
    auto hexToBytes = [](const std::string& hex) -> std::vector<unsigned char> {
        std::vector<unsigned char> bytes;
        if (hex.length() % 2 != 0) return bytes;
        for (size_t i = 0; i < hex.length(); i += 2) {
            unsigned int byte;
            std::stringstream ss;
            ss << std::hex << hex.substr(i, 2);
            ss >> byte;
            bytes.push_back(static_cast<unsigned char>(byte));
        }
        return bytes;
    };

    std::vector<unsigned char> salt = hexToBytes(saltHex);
    std::vector<unsigned char> expectedHash = hexToBytes(expectedHashHex);

    if (salt.empty() || expectedHash.empty()) {
        LOG_ERROR("Failed to parse PBKDF2 hash components");
        return false;
    }

    // 使用相同参数计算哈希
    std::vector<unsigned char> computedHash(expectedHash.size());
    int ret = PKCS5_PBKDF2_HMAC(
        password.c_str(), password.length(),
        salt.data(), salt.size(),
        iterations,
        EVP_sha512(),
        computedHash.size(), computedHash.data()
    );

    if (ret != 1) {
        LOG_ERROR("PKCS5_PBKDF2_HMAC verification failed");
        return false;
    }

    // 常量时间比较，防止时序攻击
    if (computedHash.size() != expectedHash.size()) {
        return false;
    }

    unsigned char diff = 0;
    for (size_t i = 0; i < computedHash.size(); i++) {
        diff |= computedHash[i] ^ expectedHash[i];
    }

    return diff == 0;
}

bool ConfigManager::verifySha256Password(const std::string& password, const std::string& storedHash) {
    // 旧版 SHA256 哈希验证（向后兼容）
    unsigned char hash[SHA256_DIGEST_LENGTH];
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        return false;
    }

    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(ctx, password.c_str(), password.length());
    EVP_DigestFinal_ex(ctx, hash, nullptr);
    EVP_MD_CTX_free(ctx);

    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }

    return ss.str() == storedHash;
}

std::string ConfigManager::generateSalt(size_t length) {
    std::string salt(length, '\0');
    if (RAND_bytes(reinterpret_cast<unsigned char*>(&salt[0]), length) != 1) {
        LOG_ERROR("RAND_bytes failed to generate salt");
        return "";
    }
    return salt;
}

bool ConfigManager::verifyUserPassword(const std::string& username, const std::string& password) {
    auto it = serverConfig_.users.find(username);
    if (it == serverConfig_.users.end()) {
        return false;
    }

    if (!it->second.enabled) {
        return false;
    }

    const std::string& storedHash = it->second.passwordHash;

    // 检查哈希格式，选择对应的验证方法
    if (it->second.isPbkdf2Hash()) {
        // 新版 PBKDF2 格式
        return verifyPbkdf2Password(password, storedHash);
    } else {
        // 旧版 SHA256 格式（向后兼容）
        bool valid = verifySha256Password(password, storedHash);

        // 如果验证成功，自动升级为 PBKDF2 格式
        if (valid) {
            std::string newHash = hashPasswordPbkdf2(password);
            if (!newHash.empty()) {
                it->second.passwordHash = newHash;
                LOG_INFO("Upgraded password hash for user " + username + " to PBKDF2");
            }
        }

        return valid;
    }
}

bool ConfigManager::verifyUserPublicKey(const std::string& username, const std::string& publicKey) {
    auto it = serverConfig_.users.find(username);
    if (it == serverConfig_.users.end()) {
        return false;
    }

    if (!it->second.enabled) {
        return false;
    }

    // 必须配置了公钥才能验证
    if (it->second.publicKey.empty()) {
        LOG_WARN("User " + username + " has no public key configured, public key authentication denied");
        return false;
    }

    const std::string& configuredKey = it->second.publicKey;

    // 仅支持完全匹配（移除不安全的后缀匹配）
    if (publicKey == configuredKey) {
        return true;
    }

    // 支持 SHA256:xxx 格式的完整匹配（不是后缀匹配）
    // 如果配置的是 "SHA256:xxx"，则实际指纹也必须是 "SHA256:xxx"
    if (configuredKey.find("SHA256:") == 0) {
        // 配置的是带前缀的完整指纹
        return publicKey == configuredKey;
    }

    return false;
}

bool ConfigManager::userExists(const std::string& username) {
    auto it = serverConfig_.users.find(username);
    return it != serverConfig_.users.end() && it->second.enabled;
}

bool ConfigManager::validate() {
    // 验证必要配置
    if (serverConfig_.ssh.port <= 0 || serverConfig_.ssh.port > 65535) {
        LOG_ERROR("Invalid SSH port");
        return false;
    }

    if (serverConfig_.cluster.port <= 0 || serverConfig_.cluster.port > 65535) {
        LOG_ERROR("Invalid cluster port");
        return false;
    }

    // 检查是否至少有一个用户
    if (serverConfig_.users.empty()) {
        LOG_ERROR("No users configured!");
        LOG_ERROR("Please create users using the user_tool utility:");
        LOG_ERROR("  ./ssh_jump_user_tool --create-user admin --password 'YourPassword'");
        return false;
    }

    return true;
}

void ConfigManager::printConfig() {
    LOG_INFO("=== Server Configuration ===");
    LOG_INFO("SSH:");
    LOG_INFO("  Listen: " + serverConfig_.ssh.listenAddress + ":" + std::to_string(serverConfig_.ssh.port));
    LOG_INFO("  Host Key: " + serverConfig_.ssh.hostKeyPath);
    LOG_INFO("  Auth Methods: " + serverConfig_.ssh.authMethods);
    LOG_INFO("Cluster:");
    LOG_INFO("  Listen: " + serverConfig_.cluster.listenAddress + ":" + std::to_string(serverConfig_.cluster.port));
    LOG_INFO("  Token File: " + serverConfig_.cluster.agentTokenFile);
    LOG_INFO("Management:");
    LOG_INFO("  Child Nodes File: " + serverConfig_.management.childNodesFile);
    LOG_INFO("Users: " + std::to_string(serverConfig_.users.size()));
    for (const auto& pair : serverConfig_.users) {
        LOG_INFO("  - " + pair.first + (pair.second.enabled ? "" : " [disabled]"));
    }
    LOG_INFO("============================");
}

} // namespace sshjump
