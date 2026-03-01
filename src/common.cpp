/**
 * @file common.cpp
 * @brief 公共实现
 */

#include "common.h"
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

namespace sshjump {

// 全局日志级别已在 config_manager.cpp 中定义
// extern std::atomic<LogLevel> g_logLevel;

bool timingSafeEqual(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) {
        return false;
    }
    if (a.empty()) {
        return true;
    }
    return CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
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

bool deriveAesKeyFromToken(const std::string& token, uint8_t key[32]) {
    if (token.empty()) {
        return false;
    }
    return SHA256(reinterpret_cast<const unsigned char*>(token.data()),
                  token.size(),
                  key) != nullptr;
}

} // namespace

bool encryptWithTokenAesGcm(const std::string& plaintext,
                            const std::string& token,
                            std::string& ivHex,
                            std::string& ciphertextHex,
                            std::string& tagHex) {
    ivHex.clear();
    ciphertextHex.clear();
    tagHex.clear();

    uint8_t key[32] = {0};
    if (!deriveAesKeyFromToken(token, key)) {
        return false;
    }

    uint8_t iv[12] = {0};
    if (RAND_bytes(iv, sizeof(iv)) != 1) {
        OPENSSL_cleanse(key, sizeof(key));
        return false;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        OPENSSL_cleanse(key, sizeof(key));
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
        ivHex = bytesToHex(iv, sizeof(iv));
        ciphertextHex = bytesToHex(ciphertext.data(), ciphertext.size());
        tagHex = bytesToHex(tag, sizeof(tag));
        ok = true;
    }

    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(tag, sizeof(tag));
    return ok;
}

bool decryptWithTokenAesGcm(const std::string& ivHex,
                            const std::string& ciphertextHex,
                            const std::string& tagHex,
                            const std::string& token,
                            std::string& plaintext) {
    plaintext.clear();

    std::vector<uint8_t> iv;
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> tag;
    if (!hexToBytes(ivHex, iv) || !hexToBytes(ciphertextHex, ciphertext) || !hexToBytes(tagHex, tag)) {
        return false;
    }
    if (iv.size() != 12 || tag.size() != 16) {
        return false;
    }

    uint8_t key[32] = {0};
    if (!deriveAesKeyFromToken(token, key)) {
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
    return ok;
}

} // namespace sshjump
