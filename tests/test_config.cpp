/**
 * @file test_config.cpp
 * @brief 配置管理模块测试 - 使用真实的 ConfigManager
 */

#include "test_framework.h"
#include "../include/config_manager.h"
#include <fstream>
#include <cstdio>
#include <openssl/sha.h>

using namespace sshjump;

// ============================================
// 配置加载测试
// ============================================
TEST(config_load_valid_file, "配置管理") {
    // 创建测试配置文件
    const char* testFile = "/tmp/test_config_valid.conf";
    std::ofstream file(testFile);
    file << "# Test configuration\n";
    file << "[ssh]\n";
    file << "listen_address = 127.0.0.1\n";
    file << "port = 3333\n";
    file << "host_key_path = /tmp/host_key\n";
    file << "auth_methods = publickey,password\n";
    file << "permit_root_login = true\n";
    file << "max_auth_tries = 5\n";
    file << "idle_timeout = 600\n";
    file << "\n";
    file << "[cluster]\n";
    file << "port = 9999\n";
    file << "heartbeat_interval = 60\n";
    file << "reverse_tunnel_port_start = 42000\n";
    file << "reverse_tunnel_port_end = 42010\n";
    file << "reverse_tunnel_retries = 5\n";
    file << "reverse_tunnel_accept_timeout_ms = 9000\n";
    file << "\n";
    file << "[security]\n";
    file << "users_file = /tmp/test_users.conf\n";
    file.close();
    
    // 创建空的用户文件，避免创建默认用户
    std::ofstream userFile("/tmp/test_users.conf");
    userFile << "admin = 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8\n"; // "password" 的 SHA256
    userFile.close();
    
    ConfigManager config;
    bool result = config.loadFromFile(testFile);
    
    std::remove(testFile);
    std::remove("/tmp/test_users.conf");
    
    ASSERT_TRUE(result);
    ASSERT_EQ("127.0.0.1", config.getServerConfig().ssh.listenAddress);
    ASSERT_EQ(3333, config.getServerConfig().ssh.port);
    ASSERT_EQ("/tmp/host_key", config.getServerConfig().ssh.hostKeyPath);
    ASSERT_EQ("publickey,password", config.getServerConfig().ssh.authMethods);
    ASSERT_TRUE(config.getServerConfig().ssh.permitRootLogin);
    ASSERT_EQ(5, config.getServerConfig().ssh.maxAuthTries);
    ASSERT_EQ(600, config.getServerConfig().ssh.idleTimeout);
    ASSERT_EQ(9999, config.getServerConfig().cluster.port);
    ASSERT_EQ(60, config.getServerConfig().cluster.heartbeatInterval);
    ASSERT_EQ(42000, config.getServerConfig().cluster.reverseTunnelPortStart);
    ASSERT_EQ(42010, config.getServerConfig().cluster.reverseTunnelPortEnd);
    ASSERT_EQ(5, config.getServerConfig().cluster.reverseTunnelRetries);
    ASSERT_EQ(9000, config.getServerConfig().cluster.reverseTunnelAcceptTimeoutMs);
    
    return true;
}

TEST(config_load_invalid_file, "配置管理") {
    ConfigManager config;
    bool result = config.loadFromFile("/nonexistent/path/config.conf");
    // 即使主配置文件不存在，也会创建默认用户
    ASSERT_FALSE(result);
    return true;
}

TEST(config_default_values, "配置管理") {
    // 创建空的配置文件，只设置用户文件路径
    const char* testFile = "/tmp/test_config_default.conf";
    std::ofstream file(testFile);
    file << "[security]\n";
    file << "users_file = /tmp/test_users_default.conf\n";
    file.close();
    
    // 创建用户文件
    std::ofstream userFile("/tmp/test_users_default.conf");
    userFile << "testuser = 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8\n";
    userFile.close();
    
    ConfigManager config;
    config.loadFromFile(testFile);
    
    std::remove(testFile);
    std::remove("/tmp/test_users_default.conf");
    
    // 检查默认值
    ASSERT_EQ("0.0.0.0", config.getServerConfig().ssh.listenAddress);
    ASSERT_EQ(2222, config.getServerConfig().ssh.port);
    ASSERT_EQ("password,publickey", config.getServerConfig().ssh.authMethods);
    ASSERT_FALSE(config.getServerConfig().ssh.permitRootLogin);
    ASSERT_EQ(3, config.getServerConfig().ssh.maxAuthTries);
    ASSERT_EQ(300, config.getServerConfig().ssh.idleTimeout);
    ASSERT_EQ(8888, config.getServerConfig().cluster.port);
    ASSERT_EQ(30, config.getServerConfig().cluster.heartbeatInterval);
    ASSERT_EQ(38000, config.getServerConfig().cluster.reverseTunnelPortStart);
    ASSERT_EQ(38199, config.getServerConfig().cluster.reverseTunnelPortEnd);
    ASSERT_EQ(3, config.getServerConfig().cluster.reverseTunnelRetries);
    ASSERT_EQ(7000, config.getServerConfig().cluster.reverseTunnelAcceptTimeoutMs);
    ASSERT_EQ("info", config.getServerConfig().logging.level);
    ASSERT_TRUE(config.getServerConfig().logging.sessionRecording);
    ASSERT_EQ(0, config.getServerConfig().security.maxConnectionsPerMinute);
    
    return true;
}

TEST(config_parse_quoted_values, "配置管理") {
    const char* testFile = "/tmp/test_config_quoted.conf";
    std::ofstream file(testFile);
    file << "[ssh]\n";
    file << "listen_address = \"192.168.1.1\"\n";
    file << "[logging]\n";
    file << "level = \"debug\"\n";
    file << "[security]\n";
    file << "users_file = /tmp/test_users_quoted.conf\n";
    file.close();
    
    std::ofstream userFile("/tmp/test_users_quoted.conf");
    userFile << "admin = hash123\n";
    userFile.close();
    
    ConfigManager config;
    bool result = config.loadFromFile(testFile);
    
    std::remove(testFile);
    std::remove("/tmp/test_users_quoted.conf");
    
    ASSERT_TRUE(result);
    ASSERT_EQ("192.168.1.1", config.getServerConfig().ssh.listenAddress);
    ASSERT_EQ("debug", config.getServerConfig().logging.level);
    
    return true;
}

TEST(config_parse_comments_and_empty_lines, "配置管理") {
    const char* testFile = "/tmp/test_config_comments.conf";
    std::ofstream file(testFile);
    file << "# This is a comment\n";
    file << "\n";
    file << "; This is also a comment\n";
    file << "[ssh]\n";
    file << "# Port configuration\n";
    file << "port = 4444\n";
    file << "\n";
    file << "[cluster]\n";
    file << "port = 7777\n";
    file << "[security]\n";
    file << "users_file = /tmp/test_users_comments.conf\n";
    file.close();
    
    std::ofstream userFile("/tmp/test_users_comments.conf");
    userFile << "admin = hash123\n";
    userFile.close();
    
    ConfigManager config;
    bool result = config.loadFromFile(testFile);
    
    std::remove(testFile);
    std::remove("/tmp/test_users_comments.conf");
    
    ASSERT_TRUE(result);
    ASSERT_EQ(4444, config.getServerConfig().ssh.port);
    ASSERT_EQ(7777, config.getServerConfig().cluster.port);
    
    return true;
}

TEST(config_validate_port_range, "配置管理") {
    const char* testFile = "/tmp/test_config_port.conf";
    std::ofstream file(testFile);
    file << "[ssh]\n";
    file << "port = 22\n";
    file << "[cluster]\n";
    file << "port = 1\n";
    file << "[security]\n";
    file << "users_file = /tmp/test_users_port.conf\n";
    file.close();
    
    std::ofstream userFile("/tmp/test_users_port.conf");
    userFile << "admin = hash123\n";
    userFile.close();
    
    ConfigManager config;
    bool result = config.loadFromFile(testFile);
    
    std::remove(testFile);
    std::remove("/tmp/test_users_port.conf");
    
    ASSERT_TRUE(result);
    ASSERT_EQ(22, config.getServerConfig().ssh.port);
    ASSERT_EQ(1, config.getServerConfig().cluster.port);
    
    return true;
}

TEST(config_security_settings, "配置管理") {
    const char* testFile = "/tmp/test_config_security.conf";
    std::ofstream file(testFile);
    file << "[security]\n";
    file << "command_audit = true\n";
    file << "allow_port_forwarding = false\n";
    file << "allow_sftp = false\n";
    file << "max_connections_per_minute = 120\n";
    file << "users_file = /tmp/test_users_security.conf\n";
    file.close();
    
    std::ofstream userFile("/tmp/test_users_security.conf");
    userFile << "admin = hash123\n";
    userFile.close();
    
    ConfigManager config;
    bool result = config.loadFromFile(testFile);
    
    std::remove(testFile);
    std::remove("/tmp/test_users_security.conf");
    
    ASSERT_TRUE(result);
    ASSERT_TRUE(config.getServerConfig().security.commandAudit);
    ASSERT_FALSE(config.getServerConfig().security.allowPortForwarding);
    ASSERT_FALSE(config.getServerConfig().security.allowSftp);
    ASSERT_EQ(120, config.getServerConfig().security.maxConnectionsPerMinute);
    
    return true;
}

TEST(config_management_settings, "配置管理") {
    const char* testFile = "/tmp/test_config_mgmt.conf";
    std::ofstream file(testFile);
    file << "[security]\n";
    file << "users_file = /tmp/test_users_mgmt.conf\n";
    file << "[management]\n";
    file << "child_nodes_file = /tmp/test_child_nodes.conf\n";
    file.close();

    std::ofstream userFile("/tmp/test_users_mgmt.conf");
    userFile << "admin = hash123\n";
    userFile.close();

    ConfigManager config;
    bool result = config.loadFromFile(testFile);

    std::remove(testFile);
    std::remove("/tmp/test_users_mgmt.conf");

    ASSERT_TRUE(result);
    ASSERT_EQ("/tmp/test_child_nodes.conf", config.getServerConfig().management.childNodesFile);
    return true;
}

TEST(config_cluster_reverse_tunnel_validate, "配置管理") {
    const char* testFile = "/tmp/test_config_cluster_reverse_tunnel.conf";
    const char* userFile = "/tmp/test_users_cluster_reverse_tunnel.conf";
    std::ofstream file(testFile);
    file << "[cluster]\n";
    file << "reverse_tunnel_port_start = 45000\n";
    file << "reverse_tunnel_port_end = 45020\n";
    file << "reverse_tunnel_retries = 4\n";
    file << "reverse_tunnel_accept_timeout_ms = 12000\n";
    file << "[security]\n";
    file << "users_file = " << userFile << "\n";
    file.close();

    std::ofstream users(userFile);
    users << "admin = hash123\n";
    users.close();

    ConfigManager config;
    bool loaded = config.loadFromFile(testFile);

    std::remove(testFile);
    std::remove(userFile);

    ASSERT_TRUE(loaded);
    ASSERT_EQ(45000, config.getServerConfig().cluster.reverseTunnelPortStart);
    ASSERT_EQ(45020, config.getServerConfig().cluster.reverseTunnelPortEnd);
    ASSERT_EQ(4, config.getServerConfig().cluster.reverseTunnelRetries);
    ASSERT_EQ(12000, config.getServerConfig().cluster.reverseTunnelAcceptTimeoutMs);
    ASSERT_TRUE(config.validate());
    return true;
}

TEST(config_cluster_reverse_tunnel_invalid_range, "配置管理") {
    const char* testFile = "/tmp/test_config_cluster_reverse_tunnel_invalid.conf";
    const char* userFile = "/tmp/test_users_cluster_reverse_tunnel_invalid.conf";
    std::ofstream file(testFile);
    file << "[cluster]\n";
    file << "reverse_tunnel_port_start = 46010\n";
    file << "reverse_tunnel_port_end = 46000\n";
    file << "[security]\n";
    file << "users_file = " << userFile << "\n";
    file.close();

    std::ofstream users(userFile);
    users << "admin = hash123\n";
    users.close();

    ConfigManager config;
    bool loaded = config.loadFromFile(testFile);

    std::remove(testFile);
    std::remove(userFile);

    ASSERT_TRUE(loaded);
    ASSERT_FALSE(config.validate());
    return true;
}

TEST(config_security_rate_limit_invalid, "配置管理") {
    const char* testFile = "/tmp/test_config_security_rate_limit_invalid.conf";
    const char* userFile = "/tmp/test_users_security_rate_limit_invalid.conf";

    std::ofstream file(testFile);
    file << "[security]\n";
    file << "max_connections_per_minute = -1\n";
    file << "users_file = " << userFile << "\n";
    file.close();

    std::ofstream users(userFile);
    users << "admin = hash123\n";
    users.close();

    ConfigManager config;
    bool loaded = config.loadFromFile(testFile);

    std::remove(testFile);
    std::remove(userFile);

    ASSERT_TRUE(loaded);
    ASSERT_FALSE(config.validate());
    return true;
}

// ============================================
// 用户认证功能测试
// ============================================
TEST(config_user_auth_password, "配置管理") {
    const char* testFile = "/tmp/test_config_user_auth.conf";
    const char* userFile = "/tmp/test_users_auth.conf";
    
    std::ofstream configFile(testFile);
    configFile << "[security]\n";
    configFile << "users_file = " << userFile << "\n";
    configFile.close();
    
    // 创建用户文件 - 密码为 "admin123" 的 SHA256 哈希
    // admin123 的 SHA256: 240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9
    std::ofstream ufile(userFile);
    ufile << "admin = 240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9\n";
    ufile << "user1 = 240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9\n";
    ufile.close();
    
    ConfigManager config;
    bool result = config.loadFromFile(testFile);
    
    std::remove(testFile);
    std::remove(userFile);
    
    ASSERT_TRUE(result);
    
    // 测试用户存在检查
    ASSERT_TRUE(config.userExists("admin"));
    ASSERT_TRUE(config.userExists("user1"));
    ASSERT_FALSE(config.userExists("nonexistent"));
    ASSERT_FALSE(config.userExists(""));
    
    // 测试密码验证
    ASSERT_TRUE(config.verifyUserPassword("admin", "admin123"));
    ASSERT_TRUE(config.verifyUserPassword("user1", "admin123"));
    ASSERT_FALSE(config.verifyUserPassword("admin", "wrongpassword"));
    ASSERT_FALSE(config.verifyUserPassword("admin", ""));
    ASSERT_FALSE(config.verifyUserPassword("nonexistent", "admin123"));
    
    return true;
}

TEST(config_user_auth_publickey, "配置管理") {
    const char* testFile = "/tmp/test_config_pubkey.conf";
    const char* userFile = "/tmp/test_users_pubkey.conf";

    std::ofstream configFile(testFile);
    configFile << "[security]\n";
    configFile << "users_file = " << userFile << "\n";
    configFile.close();

    // 创建用户文件，包含公钥指纹
    // 注意：配置文件使用 : 作为分隔符，所以公钥指纹不能包含 :
    // 这里使用纯十六进制格式的指纹（64个字符）
    std::ofstream ufile(userFile);
    ufile << "admin = 240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890\n";
    ufile << "user1 = hash123\n";  // 没有公钥
    ufile.close();

    ConfigManager config;
    config.loadFromFile(testFile);

    std::remove(testFile);
    std::remove(userFile);

    // 测试公钥验证（现在仅使用完全匹配，移除了不安全的后缀匹配）
    ASSERT_TRUE(config.verifyUserPublicKey("admin", "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"));  // 完全匹配
    ASSERT_FALSE(config.verifyUserPublicKey("admin", "prefix-abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"));  // 后缀匹配已禁用
    ASSERT_FALSE(config.verifyUserPublicKey("user1", "any-key"));  // 没有配置公钥，应该返回 false
    ASSERT_FALSE(config.verifyUserPublicKey("admin", "wrongkey1234567890abcdef1234567890abcdef1234567890abcdef1234567890"));  // 公钥不匹配
    ASSERT_FALSE(config.verifyUserPublicKey("nonexistent", "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"));

    return true;
}

TEST(config_user_auth_sha256_fingerprint_format, "配置管理") {
    const char* testFile = "/tmp/test_config_pubkey_sha256.conf";
    const char* userFile = "/tmp/test_users_pubkey_sha256.conf";

    std::ofstream configFile(testFile);
    configFile << "[security]\n";
    configFile << "users_file = " << userFile << "\n";
    configFile.close();

    std::ofstream ufile(userFile);
    ufile << "admin = hash123:SHA256:abcDEF123456\n";
    ufile.close();

    ConfigManager config;
    ASSERT_TRUE(config.loadFromFile(testFile));

    const auto runtimeConfig = config.getServerConfig();
    auto it = runtimeConfig.users.find("admin");
    ASSERT_TRUE(it != runtimeConfig.users.end());
    ASSERT_EQ("SHA256:abcDEF123456", it->second.publicKey);

    ASSERT_TRUE(config.verifyUserPublicKey("admin", "SHA256:abcDEF123456"));
    ASSERT_FALSE(config.verifyUserPublicKey("admin", "SHA256:other"));

    std::remove(testFile);
    std::remove(userFile);
    return true;
}

TEST(config_user_auth_openssh_key_normalization, "配置管理") {
    const char* testFile = "/tmp/test_config_pubkey_openssh.conf";
    const char* userFile = "/tmp/test_users_pubkey_openssh.conf";

    std::ofstream configFile(testFile);
    configFile << "[security]\n";
    configFile << "users_file = " << userFile << "\n";
    configFile.close();

    // "AQID" => bytes {0x01, 0x02, 0x03}
    std::ofstream ufile(userFile);
    ufile << "admin = hash123:ssh-rsa AQID\n";
    ufile.close();

    ConfigManager config;
    ASSERT_TRUE(config.loadFromFile(testFile));

    unsigned char blob[] = {0x01, 0x02, 0x03};
    unsigned char digest[SHA256_DIGEST_LENGTH] = {0};
    SHA256(blob, sizeof(blob), digest);

    std::stringstream ss;
    for (size_t i = 0; i < sizeof(digest); i++) {
        ss << std::hex << std::setw(2) << std::setfill('0')
           << static_cast<int>(digest[i]);
    }
    const std::string expectedFingerprint = ss.str();

    ASSERT_TRUE(config.verifyUserPublicKey("admin", expectedFingerprint));
    ASSERT_FALSE(config.verifyUserPublicKey("admin", "0000"));

    std::remove(testFile);
    std::remove(userFile);
    return true;
}

TEST(config_default_admin_user, "配置管理") {
    const char* testFile = "/tmp/test_config_default_admin.conf";
    const char* userFile = "/tmp/test_users_nonexistent.conf";

    std::ofstream configFile(testFile);
    configFile << "[security]\n";
    configFile << "users_file = " << userFile << "\n";
    configFile.close();

    // 确保用户文件不存在
    std::remove(userFile);

    ConfigManager config;
    bool result = config.loadFromFile(testFile);

    std::remove(testFile);

    // 当用户文件不存在时，不会创建默认用户（安全行为）
    // loadFromFile 会返回 true（配置文件加载成功），但没有用户
    ASSERT_TRUE(result);
    ASSERT_FALSE(config.userExists("admin"));  // 不会自动创建 admin 用户
    ASSERT_FALSE(config.verifyUserPassword("admin", "admin123"));

    return true;
}

TEST(config_load_users_from_file, "配置管理") {
    const char* userFile = "/tmp/test_load_users.conf";
    
    std::ofstream ufile(userFile);
    ufile << "# User configuration file\n";
    ufile << "\n";
    ufile << "admin = 240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9\n";
    ufile << "developer = 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8\n";  // password
    ufile << "operator = hash456:ssh-rsa KEY123\n";
    ufile.close();
    
    ConfigManager config;
    bool result = config.loadUsers(userFile);
    
    std::remove(userFile);
    
    ASSERT_TRUE(result);
    ASSERT_TRUE(config.userExists("admin"));
    ASSERT_TRUE(config.userExists("developer"));
    ASSERT_TRUE(config.userExists("operator"));
    ASSERT_EQ(3, config.getServerConfig().users.size());
    
    return true;
}

TEST(config_validate_config, "配置管理") {
    ConfigManager config;
    
    // 创建有效的配置
    const char* testFile = "/tmp/test_config_validate.conf";
    const char* userFile = "/tmp/test_users_validate.conf";
    
    std::ofstream configFile(testFile);
    configFile << "[ssh]\n";
    configFile << "port = 2222\n";
    configFile << "[cluster]\n";
    configFile << "port = 8888\n";
    configFile << "[security]\n";
    configFile << "users_file = " << userFile << "\n";
    configFile.close();
    
    std::ofstream ufile(userFile);
    ufile << "admin = hash123\n";
    ufile.close();
    
    config.loadFromFile(testFile);
    
    std::remove(testFile);
    std::remove(userFile);
    
    // 验证配置
    ASSERT_TRUE(config.validate());
    
    return true;
}

TEST(config_validate_creates_default_user, "配置管理") {
    ConfigManager config;

    // 不加载任何配置，直接验证
    // validate 会检查是否有用户，没有用户时返回 false（安全行为）
    ASSERT_FALSE(config.validate());  // 没有用户，验证失败

    // 不会创建默认用户
    ASSERT_FALSE(config.userExists("admin"));

    return true;
}

TEST(config_user_disabled, "配置管理") {
    ConfigManager config;
    
    const char* userFile = "/tmp/test_users_disabled.conf";
    std::ofstream ufile(userFile);
    ufile << "active_user = 240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9\n";
    ufile << "disabled_user = 240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9:disabled\n";
    ufile.close();
    
    config.loadUsers(userFile);
    std::remove(userFile);
    
    // 激活用户可以认证
    ASSERT_TRUE(config.verifyUserPassword("active_user", "admin123"));
    ASSERT_TRUE(config.userExists("active_user"));

    // disabled 标记应生效
    ASSERT_FALSE(config.verifyUserPassword("disabled_user", "admin123"));
    ASSERT_FALSE(config.userExists("disabled_user"));
    
    return true;
}

TEST(config_validate_auth_methods_invalid, "配置管理") {
    const char* testFile = "/tmp/test_config_auth_methods_invalid.conf";
    const char* userFile = "/tmp/test_users_auth_methods_invalid.conf";

    std::ofstream file(testFile);
    file << "[ssh]\n";
    file << "auth_methods = keyboard-interactive\n";
    file << "[security]\n";
    file << "users_file = " << userFile << "\n";
    file.close();

    std::ofstream users(userFile);
    users << "admin = hash123\n";
    users.close();

    ConfigManager config;
    bool loaded = config.loadFromFile(testFile);

    std::remove(testFile);
    std::remove(userFile);

    ASSERT_TRUE(loaded);
    ASSERT_FALSE(config.validate());
    return true;
}

TEST(config_verify_pbkdf2_invalid_iterations, "配置管理") {
    ConfigManager config;
    config.updateServerConfig([](ServerConfig& serverConfig) {
        UserAuthInfo user;
        user.username = "badpbkdf2";
        user.enabled = true;
        user.passwordHash = "PBKDF2$not-a-number$0011$2233";
        serverConfig.users[user.username] = user;
    });

    ASSERT_FALSE(config.verifyUserPassword("badpbkdf2", "any-password"));
    return true;
}

TEST(config_crud_persists_users_file, "配置管理") {
    const char* userFile = "/tmp/test_users_persist.conf";
    std::remove(userFile);

    ConfigManager config;
    config.updateServerConfig([&](ServerConfig& serverConfig) {
        serverConfig.security.usersFile = userFile;
        serverConfig.users.clear();
    });

    UserAuthInfo user;
    user.username = "persisted";
    user.passwordHash = "PBKDF2$100000$0011$2233";
    user.publicKey = "SHA256:abc123";
    user.mustChangePassword = true;
    user.enabled = true;

    ASSERT_TRUE(config.createUser(user));

    ConfigManager reloaded;
    ASSERT_TRUE(reloaded.loadUsers(userFile));
    auto created = reloaded.getUser("persisted");
    ASSERT_TRUE(created.has_value());
    ASSERT_TRUE(created->mustChangePassword);
    ASSERT_TRUE(created->enabled);
    ASSERT_EQ(std::string("SHA256:abc123"), created->publicKey);

    ASSERT_TRUE(config.updateUser("persisted", [](UserAuthInfo& current) {
        current.enabled = false;
        current.mustChangePassword = false;
        current.publicKey.clear();
        return true;
    }));

    ConfigManager updated;
    ASSERT_TRUE(updated.loadUsers(userFile));
    auto updatedUser = updated.getUser("persisted");
    ASSERT_TRUE(updatedUser.has_value());
    ASSERT_FALSE(updatedUser->enabled);
    ASSERT_FALSE(updatedUser->mustChangePassword);
    ASSERT_TRUE(updatedUser->publicKey.empty());

    ASSERT_TRUE(config.deleteUser("persisted"));

    ConfigManager deleted;
    ASSERT_TRUE(deleted.loadUsers(userFile));
    ASSERT_FALSE(deleted.getUser("persisted").has_value());

    std::remove(userFile);
    return true;
}
