/**
 * @file password_utils.h
 * @brief 密码哈希工具
 */

#ifndef SSH_JUMP_PASSWORD_UTILS_H
#define SSH_JUMP_PASSWORD_UTILS_H

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

namespace sshjump::security {

constexpr int kPbkdf2Iterations = 100000;
constexpr int kPbkdf2SaltLength = 32;
constexpr int kPbkdf2HashLength = 64;

inline std::string bytesToHex(const unsigned char* data, size_t len) {
    if (!data || len == 0) {
        return "";
    }

    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i) {
        oss << std::setw(2) << static_cast<int>(data[i]);
    }
    return oss.str();
}

inline std::string hashPasswordPbkdf2(const std::string& password) {
    std::vector<unsigned char> salt(kPbkdf2SaltLength, 0);
    if (RAND_bytes(salt.data(), static_cast<int>(salt.size())) != 1) {
        return "";
    }

    std::vector<unsigned char> hash(kPbkdf2HashLength, 0);
    if (PKCS5_PBKDF2_HMAC(password.c_str(),
                          static_cast<int>(password.size()),
                          salt.data(),
                          static_cast<int>(salt.size()),
                          kPbkdf2Iterations,
                          EVP_sha512(),
                          static_cast<int>(hash.size()),
                          hash.data()) != 1) {
        return "";
    }

    return "PBKDF2$" + std::to_string(kPbkdf2Iterations) + "$" +
           bytesToHex(salt.data(), salt.size()) + "$" +
           bytesToHex(hash.data(), hash.size());
}

} // namespace sshjump::security

#endif // SSH_JUMP_PASSWORD_UTILS_H
