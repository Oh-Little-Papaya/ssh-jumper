/**
 * @file user_tool.cpp
 * @brief SSH Jump Server 用户管理命令行工具
 *
 * 用法:
 *   ./ssh_jump_user_tool --create-user <username> --password <password> [--users-file <path>]
 *   ./ssh_jump_user_tool --delete-user <username> [--users-file <path>]
 *   ./ssh_jump_user_tool --list-users [--users-file <path>]
 *   ./ssh_jump_user_tool --change-password <username> --password <password> [--users-file <path>]
 *   ./ssh_jump_user_tool --set-public-key <username> --key <public_key> [--users-file <path>]
 *   ./ssh_jump_user_tool --enable-user <username> [--users-file <path>]
 *   ./ssh_jump_user_tool --disable-user <username> [--users-file <path>]
 */

#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <cstring>
#include <cerrno>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <iomanip>
#include <sys/stat.h>

// PBKDF2 配置常量
constexpr int PBKDF2_ITERATIONS = 100000;
constexpr int PBKDF2_SALT_LENGTH = 32;
constexpr int PBKDF2_HASH_LENGTH = 64;
constexpr const char* DEFAULT_USERS_FILE = "/etc/ssh_jump/users.conf";

// 简单的字符串处理函数
std::string trimString(const std::string& str) {
    size_t start = str.find_first_not_of(" \t\n\r");
    if (start == std::string::npos) return "";
    size_t end = str.find_last_not_of(" \t\n\r");
    return str.substr(start, end - start + 1);
}

std::vector<std::string> splitString(const std::string& str, char delimiter) {
    std::vector<std::string> tokens;
    std::stringstream ss(str);
    std::string token;
    while (std::getline(ss, token, delimiter)) {
        if (!token.empty()) {
            tokens.push_back(token);
        }
    }
    return tokens;
}

// 生成随机盐值
std::string generateSalt(size_t length) {
    std::string salt(length, '\0');
    if (RAND_bytes(reinterpret_cast<unsigned char*>(&salt[0]), length) != 1) {
        std::cerr << "Error: RAND_bytes failed to generate salt" << std::endl;
        return "";
    }
    return salt;
}

// 使用 PBKDF2-HMAC-SHA512 计算密码哈希
std::string hashPasswordPbkdf2(const std::string& password) {
    // 生成随机盐值
    std::string salt = generateSalt(PBKDF2_SALT_LENGTH);
    if (salt.empty()) {
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
        std::cerr << "Error: PKCS5_PBKDF2_HMAC failed" << std::endl;
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

// 用户信息结构
struct UserInfo {
    std::string username;
    std::string passwordHash;
    std::string publicKey;
    bool enabled = true;
    bool mustChangePassword = false;
};

// 加载用户文件
std::vector<UserInfo> loadUsers(const std::string& path) {
    std::vector<UserInfo> users;
    std::ifstream file(path);
    if (!file.is_open()) {
        return users;
    }

    std::string line;
    while (std::getline(file, line)) {
        line = trimString(line);
        if (line.empty() || line[0] == '#' || line[0] == ';') {
            continue;
        }

        size_t pos = line.find('=');
        if (pos == std::string::npos) {
            continue;
        }

        UserInfo user;
        user.username = trimString(line.substr(0, pos));
        std::string value = trimString(line.substr(pos + 1));

        std::vector<std::string> parts = splitString(value, ':');
        if (parts.empty()) {
            continue;
        }

        user.passwordHash = trimString(parts[0]);
        for (size_t i = 1; i < parts.size(); i++) {
            std::string part = trimString(parts[i]);
            if (part == "must_change") {
                user.mustChangePassword = true;
            } else if (part == "disabled") {
                user.enabled = false;
            } else if (!part.empty()) {
                user.publicKey = part;
            }
        }

        users.push_back(user);
    }

    return users;
}

// 保存用户文件
bool saveUsers(const std::string& path, const std::vector<UserInfo>& users) {
    // 确保目录存在
    std::string dir = path;
    size_t lastSlash = dir.find_last_of('/');
    if (lastSlash != std::string::npos) {
        dir = dir.substr(0, lastSlash);
        if (!dir.empty()) {
            if (mkdir(dir.c_str(), 0700) != 0 && errno != EEXIST) {
                std::cerr << "Error: Failed to create directory: " << dir << std::endl;
                return false;
            }
            chmod(dir.c_str(), 0700);
        }
    }

    std::ofstream file(path, std::ios::out | std::ios::trunc);
    if (!file.is_open()) {
        std::cerr << "Error: Cannot open file for writing: " << path << std::endl;
        return false;
    }

    file << "# SSH Jump Server Users Configuration\n";
    file << "# Format: username = password_hash [:public_key] [:must_change] [:disabled]\n";
    file << "# Use this tool to manage users - do not edit manually\n\n";

    for (const auto& user : users) {
        file << user.username << " = " << user.passwordHash;
        if (!user.publicKey.empty()) {
            file << " : " << user.publicKey;
        }
        if (user.mustChangePassword) {
            file << " : must_change";
        }
        if (!user.enabled) {
            file << " : disabled";
        }
        file << "\n";
    }

    file.close();
    if (chmod(path.c_str(), 0600) != 0) {
        std::cerr << "Warning: Failed to set secure permissions on " << path << std::endl;
    }
    return true;
}

// 创建用户
bool createUser(const std::string& usersFile, const std::string& username,
                const std::string& password, bool mustChange = false) {
    auto users = loadUsers(usersFile);

    // 检查用户是否已存在
    for (const auto& user : users) {
        if (user.username == username) {
            std::cerr << "Error: User '" << username << "' already exists" << std::endl;
            return false;
        }
    }

    // 创建新用户
    UserInfo newUser;
    newUser.username = username;
    newUser.passwordHash = hashPasswordPbkdf2(password);
    newUser.mustChangePassword = mustChange;
    newUser.enabled = true;

    if (newUser.passwordHash.empty()) {
        std::cerr << "Error: Failed to hash password" << std::endl;
        return false;
    }

    users.push_back(newUser);

    if (saveUsers(usersFile, users)) {
        std::cout << "User '" << username << "' created successfully" << std::endl;
        if (mustChange) {
            std::cout << "User must change password on first login" << std::endl;
        }
        return true;
    }
    return false;
}

// 删除用户
bool deleteUser(const std::string& usersFile, const std::string& username) {
    auto users = loadUsers(usersFile);
    bool found = false;

    std::vector<UserInfo> newUsers;
    for (const auto& user : users) {
        if (user.username != username) {
            newUsers.push_back(user);
        } else {
            found = true;
        }
    }

    if (!found) {
        std::cerr << "Error: User '" << username << "' not found" << std::endl;
        return false;
    }

    if (saveUsers(usersFile, newUsers)) {
        std::cout << "User '" << username << "' deleted successfully" << std::endl;
        return true;
    }
    return false;
}

// 列出用户
void listUsers(const std::string& usersFile) {
    auto users = loadUsers(usersFile);

    if (users.empty()) {
        std::cout << "No users configured" << std::endl;
        return;
    }

    std::cout << "Configured users (" << users.size() << "):" << std::endl;
    std::cout << std::string(60, '-') << std::endl;

    for (const auto& user : users) {
        std::cout << "  " << user.username;
        if (!user.enabled) {
            std::cout << " [disabled]";
        }
        if (user.mustChangePassword) {
            std::cout << " [must_change]";
        }
        if (!user.publicKey.empty()) {
            std::cout << " [has_key]";
        }
        if (user.passwordHash.find("PBKDF2$") == 0) {
            std::cout << " [PBKDF2]";
        } else {
            std::cout << " [SHA256]";
        }
        std::cout << std::endl;
    }
}

// 修改密码
bool changePassword(const std::string& usersFile, const std::string& username,
                    const std::string& newPassword, bool mustChange = false) {
    auto users = loadUsers(usersFile);
    bool found = false;

    for (auto& user : users) {
        if (user.username == username) {
            user.passwordHash = hashPasswordPbkdf2(newPassword);
            user.mustChangePassword = mustChange;
            found = true;
            break;
        }
    }

    if (!found) {
        std::cerr << "Error: User '" << username << "' not found" << std::endl;
        return false;
    }

    if (saveUsers(usersFile, users)) {
        std::cout << "Password changed for user '" << username << "'" << std::endl;
        return true;
    }
    return false;
}

// 设置公钥
bool setPublicKey(const std::string& usersFile, const std::string& username,
                  const std::string& publicKey) {
    auto users = loadUsers(usersFile);
    bool found = false;

    for (auto& user : users) {
        if (user.username == username) {
            user.publicKey = publicKey;
            found = true;
            break;
        }
    }

    if (!found) {
        std::cerr << "Error: User '" << username << "' not found" << std::endl;
        return false;
    }

    if (saveUsers(usersFile, users)) {
        std::cout << "Public key set for user '" << username << "'" << std::endl;
        return true;
    }
    return false;
}

// 启用/禁用用户
bool setUserStatus(const std::string& usersFile, const std::string& username, bool enabled) {
    auto users = loadUsers(usersFile);
    bool found = false;

    for (auto& user : users) {
        if (user.username == username) {
            user.enabled = enabled;
            found = true;
            break;
        }
    }

    if (!found) {
        std::cerr << "Error: User '" << username << "' not found" << std::endl;
        return false;
    }

    if (saveUsers(usersFile, users)) {
        std::cout << "User '" << username << "' " << (enabled ? "enabled" : "disabled") << std::endl;
        return true;
    }
    return false;
}

// 打印帮助信息
void printHelp(const char* programName) {
    std::cout << "SSH Jump Server User Management Tool" << std::endl;
    std::cout << std::endl;
    std::cout << "Usage:" << std::endl;
    std::cout << "  " << programName << " --create-user <username> --password <password> [options]" << std::endl;
    std::cout << "  " << programName << " --delete-user <username> [options]" << std::endl;
    std::cout << "  " << programName << " --list-users [options]" << std::endl;
    std::cout << "  " << programName << " --change-password <username> --password <password> [options]" << std::endl;
    std::cout << "  " << programName << " --set-public-key <username> --key <public_key> [options]" << std::endl;
    std::cout << "  " << programName << " --enable-user <username> [options]" << std::endl;
    std::cout << "  " << programName << " --disable-user <username> [options]" << std::endl;
    std::cout << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  --users-file <path>     Users configuration file (default: " << DEFAULT_USERS_FILE << ")" << std::endl;
    std::cout << "  --must-change           User must change password on first login" << std::endl;
    std::cout << "  --help, -h              Show this help message" << std::endl;
    std::cout << std::endl;
    std::cout << "Examples:" << std::endl;
    std::cout << "  " << programName << " --create-user admin --password 'SecureP@ss123'" << std::endl;
    std::cout << "  " << programName << " --create-user temp --password 'Temp123' --must-change" << std::endl;
    std::cout << "  " << programName << " --set-public-key admin --key 'ssh-rsa AAAA...'" << std::endl;
    std::cout << "  " << programName << " --list-users" << std::endl;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printHelp(argv[0]);
        return 1;
    }

    std::string usersFile = DEFAULT_USERS_FILE;
    std::string username;
    std::string password;
    std::string publicKey;
    std::string command;
    bool mustChange = false;

    // 解析命令行参数
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];

        if (arg == "--help" || arg == "-h") {
            printHelp(argv[0]);
            return 0;
        } else if (arg == "--create-user" && i + 1 < argc) {
            command = "create";
            username = argv[++i];
        } else if (arg == "--delete-user" && i + 1 < argc) {
            command = "delete";
            username = argv[++i];
        } else if (arg == "--list-users") {
            command = "list";
        } else if (arg == "--change-password" && i + 1 < argc) {
            command = "change-password";
            username = argv[++i];
        } else if (arg == "--set-public-key" && i + 1 < argc) {
            command = "set-key";
            username = argv[++i];
        } else if (arg == "--enable-user" && i + 1 < argc) {
            command = "enable";
            username = argv[++i];
        } else if (arg == "--disable-user" && i + 1 < argc) {
            command = "disable";
            username = argv[++i];
        } else if (arg == "--password" && i + 1 < argc) {
            password = argv[++i];
        } else if (arg == "--key" && i + 1 < argc) {
            publicKey = argv[++i];
        } else if (arg == "--users-file" && i + 1 < argc) {
            usersFile = argv[++i];
        } else if (arg == "--must-change") {
            mustChange = true;
        }
    }

    // 执行命令
    if (command == "create") {
        if (username.empty() || password.empty()) {
            std::cerr << "Error: --create-user requires --password" << std::endl;
            return 1;
        }
        return createUser(usersFile, username, password, mustChange) ? 0 : 1;
    } else if (command == "delete") {
        if (username.empty()) {
            std::cerr << "Error: --delete-user requires username" << std::endl;
            return 1;
        }
        return deleteUser(usersFile, username) ? 0 : 1;
    } else if (command == "list") {
        listUsers(usersFile);
        return 0;
    } else if (command == "change-password") {
        if (username.empty() || password.empty()) {
            std::cerr << "Error: --change-password requires --password" << std::endl;
            return 1;
        }
        return changePassword(usersFile, username, password, mustChange) ? 0 : 1;
    } else if (command == "set-key") {
        if (username.empty() || publicKey.empty()) {
            std::cerr << "Error: --set-public-key requires --key" << std::endl;
            return 1;
        }
        return setPublicKey(usersFile, username, publicKey) ? 0 : 1;
    } else if (command == "enable") {
        if (username.empty()) {
            std::cerr << "Error: --enable-user requires username" << std::endl;
            return 1;
        }
        return setUserStatus(usersFile, username, true) ? 0 : 1;
    } else if (command == "disable") {
        if (username.empty()) {
            std::cerr << "Error: --disable-user requires username" << std::endl;
            return 1;
        }
        return setUserStatus(usersFile, username, false) ? 0 : 1;
    } else {
        std::cerr << "Error: No command specified" << std::endl;
        printHelp(argv[0]);
        return 1;
    }
}
