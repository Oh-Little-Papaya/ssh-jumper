/**
 * @file common.cpp
 * @brief 公共实现
 */

#include "common.h"
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <array>

namespace sshjump {

bool timingSafeEqual(const std::string& a, const std::string& b) {
    // 先对双方各做一次 SHA256，再常量时间比较摘要。
    // 这样无论输入长度是否相等，比较都走同一条 32 字节路径，
    // 不再通过提前返回泄露 token/哈希长度信息。
    if (a.empty() && b.empty()) {
        return true;
    }

    auto sha256Hex = [](const std::string& s) -> std::array<uint8_t, SHA256_DIGEST_LENGTH> {
        std::array<uint8_t, SHA256_DIGEST_LENGTH> digest{0};
        if (s.empty()) {
            // 对空输入也派生一个确定摘要，保证两边都进入同一比较路径
            SHA256(reinterpret_cast<const unsigned char*>(""), 0, digest.data());
        } else {
            SHA256(reinterpret_cast<const unsigned char*>(s.data()), s.size(),
                   digest.data());
        }
        return digest;
    };

    const auto da = sha256Hex(a);
    const auto db = sha256Hex(b);
    return CRYPTO_memcmp(da.data(), db.data(), da.size()) == 0;
}

std::string bytesToHex(const uint8_t* data, size_t len) {
    if (!data || len == 0) {
        return "";
    }

    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.resize(len * 2);

    for (size_t i = 0; i < len; ++i) {
        out[2 * i] = kHex[(data[i] >> 4) & 0x0F];
        out[2 * i + 1] = kHex[data[i] & 0x0F];
    }

    return out;
}

bool hexToBytes(const std::string& hex, std::vector<uint8_t>& out) {
    out.clear();
    if (hex.empty() || (hex.size() % 2) != 0) {
        return false;
    }

    auto hexValue = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
        if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
        return -1;
    };

    out.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        const int hi = hexValue(hex[i]);
        const int lo = hexValue(hex[i + 1]);
        if (hi < 0 || lo < 0) {
            out.clear();
            return false;
        }
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return true;
}

namespace {

// 使用 PBKDF2-HMAC-SHA256 从 token 派生 AES-256 密钥。
// 引入 per-message 随机盐，显著提高离线暴力难度（相对裸 SHA256(token)）。
// 盐随密文一起传输，因此不是秘密，但每条消息不同，阻止预计算。
constexpr int kAesKeyDerivationIterations = 100000;
constexpr int kAesKeySaltLength = 16;

bool deriveAesKeyFromToken(const std::string& token,
                           const uint8_t* salt, size_t saltLen,
                           uint8_t key[32]) {
    if (token.empty() || !salt || saltLen == 0) {
        return false;
    }
    return PKCS5_PBKDF2_HMAC(token.c_str(),
                             static_cast<int>(token.size()),
                             salt, static_cast<int>(saltLen),
                             kAesKeyDerivationIterations,
                             EVP_sha256(),
                             32, key) == 1;
}

void cleanse(std::vector<uint8_t>& buf) {
    if (!buf.empty()) {
        OPENSSL_cleanse(buf.data(), buf.size());
        buf.clear();
    }
}

} // namespace

bool encryptWithTokenAesGcm(const std::string& plaintext,
                            const std::string& token,
                            std::string& saltHex,
                            std::string& ivHex,
                            std::string& ciphertextHex,
                            std::string& tagHex) {
    saltHex.clear();
    ivHex.clear();
    ciphertextHex.clear();
    tagHex.clear();

    uint8_t salt[kAesKeySaltLength] = {0};
    if (RAND_bytes(salt, sizeof(salt)) != 1) {
        return false;
    }

    uint8_t key[32] = {0};
    if (!deriveAesKeyFromToken(token, salt, sizeof(salt), key)) {
        OPENSSL_cleanse(salt, sizeof(salt));
        return false;
    }

    uint8_t iv[12] = {0};
    if (RAND_bytes(iv, sizeof(iv)) != 1) {
        OPENSSL_cleanse(key, sizeof(key));
        OPENSSL_cleanse(salt, sizeof(salt));
        return false;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        OPENSSL_cleanse(key, sizeof(key));
        OPENSSL_cleanse(salt, sizeof(salt));
        return false;
    }

    bool ok = false;
    std::vector<uint8_t> ciphertext(plaintext.size() + EVP_MAX_BLOCK_LENGTH);
    int outLen = 0;
    int finalLen = 0;
    uint8_t tag[16] = {0};

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(iv), nullptr) == 1 &&
        EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, iv) == 1 &&
        EVP_EncryptUpdate(ctx,
                          ciphertext.data(),
                          &outLen,
                          reinterpret_cast<const unsigned char*>(plaintext.data()),
                          static_cast<int>(plaintext.size())) == 1 &&
        EVP_EncryptFinal_ex(ctx, ciphertext.data() + outLen, &finalLen) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag) == 1) {
        ciphertext.resize(static_cast<size_t>(outLen + finalLen));
        saltHex = bytesToHex(salt, sizeof(salt));
        ivHex = bytesToHex(iv, sizeof(iv));
        ciphertextHex = bytesToHex(ciphertext.data(), ciphertext.size());
        tagHex = bytesToHex(tag, sizeof(tag));
        ok = true;
    }

    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(salt, sizeof(salt));
    OPENSSL_cleanse(tag, sizeof(tag));
    if (!ok) {
        cleanse(ciphertext);
    }
    return ok;
}

bool decryptWithTokenAesGcm(const std::string& saltHex,
                            const std::string& ivHex,
                            const std::string& ciphertextHex,
                            const std::string& tagHex,
                            const std::string& token,
                            std::string& plaintext) {
    plaintext.clear();

    std::vector<uint8_t> salt;
    std::vector<uint8_t> iv;
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> tag;
    if (!hexToBytes(saltHex, salt) || salt.size() != kAesKeySaltLength ||
        !hexToBytes(ivHex, iv) || iv.size() != 12 ||
        !hexToBytes(ciphertextHex, ciphertext) ||
        !hexToBytes(tagHex, tag) || tag.size() != 16) {
        return false;
    }

    uint8_t key[32] = {0};
    if (!deriveAesKeyFromToken(token, salt.data(), salt.size(), key)) {
        OPENSSL_cleanse(key, sizeof(key));
        return false;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        OPENSSL_cleanse(key, sizeof(key));
        return false;
    }

    bool ok = false;
    std::vector<uint8_t> out(ciphertext.size() + EVP_MAX_BLOCK_LENGTH, 0);
    int outLen = 0;
    int finalLen = 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(iv.size()), nullptr) == 1 &&
        EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, iv.data()) == 1 &&
        EVP_DecryptUpdate(ctx,
                          out.data(),
                          &outLen,
                          ciphertext.data(),
                          static_cast<int>(ciphertext.size())) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, static_cast<int>(tag.size()), tag.data()) == 1 &&
        EVP_DecryptFinal_ex(ctx, out.data() + outLen, &finalLen) == 1) {
        out.resize(static_cast<size_t>(outLen + finalLen));
        plaintext.assign(reinterpret_cast<const char*>(out.data()), out.size());
        ok = true;
    }

    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_cleanse(key, sizeof(key));
    // 失败路径也要擦除明文缓冲，避免部分明文残留堆上
    if (!ok) {
        cleanse(out);
    } else {
        // 成功路径下 out 可能仍含 EVP_MAX_BLOCK_LENGTH 余量，擦除后再释放
        OPENSSL_cleanse(out.data(), out.size());
    }
    return ok;
}

} // namespace sshjump
