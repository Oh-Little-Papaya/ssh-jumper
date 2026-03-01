/**
 * @file common.h
 * @brief 公共头文件，包含基本类型定义和工具函数
 */

#ifndef SSH_JUMP_COMMON_H
#define SSH_JUMP_COMMON_H

#include <cstdint>
#include <cstddef>
#include <string>
#include <memory>
#include <functional>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <vector>
#include <map>
#include <unordered_map>
#include <set>
#include <chrono>
#include <thread>
#include <iostream>
#include <sstream>
#include <fstream>
#include <algorithm>
#include <cstring>
#include <csignal>
#include <cassert>
#include <shared_mutex>
#include <optional>

// 系统头文件
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>

// libssh
#include <libssh/libssh.h>
#include <libssh/server.h>

namespace sshjump {

// 版本信息
constexpr const char* VERSION = "2.0.0";
constexpr uint32_t MAGIC_NUMBER = 0x4A534853; // "JSHS" (Jump SSH Server)

// 默认配置
constexpr int DEFAULT_SSH_PORT = 2222;
constexpr int DEFAULT_CLUSTER_PORT = 8888;
constexpr int DEFAULT_BACKLOG = 128;
constexpr int DEFAULT_BUFFER_SIZE = 65536;
constexpr int DEFAULT_THREAD_POOL_SIZE = 8;
constexpr int DEFAULT_MAX_CONNECTIONS = 10000;
constexpr int DEFAULT_HEARTBEAT_INTERVAL = 30; // 秒
constexpr int DEFAULT_CONNECTION_TIMEOUT = 300; // 秒

// 事件类型
enum class EventType {
    READ = 0x01,
    WRITE = 0x02,
    ERROR = 0x04,
    HUP = 0x08
};

inline EventType operator|(EventType a, EventType b) {
    return static_cast<EventType>(static_cast<int>(a) | static_cast<int>(b));
}

inline bool operator&(EventType a, EventType b) {
    return (static_cast<int>(a) & static_cast<int>(b)) != 0;
}

// 连接状态
enum class ConnectionState {
    INITIALIZING,
    HANDSHAKING,
    AUTHENTICATING,
    AUTHENTICATED,
    FORWARDING,
    CLOSING,
    CLOSED
};

// Agent消息类型
enum class AgentMessageType : uint8_t {
    REGISTER = 0x01,
    HEARTBEAT = 0x02,
    UNREGISTER = 0x03,
    COMMAND = 0x04,
    RESPONSE = 0x05,
    FORWARD_REQUEST = 0x06,
    FORWARD_DATA = 0x07
};

// 日志级别
enum class LogLevel {
    DEBUG = 0,
    INFO = 1,
    WARN = 2,
    ERROR = 3,
    FATAL = 4
};

// 全局日志级别
extern std::atomic<LogLevel> g_logLevel;

// 日志消息净化函数 - 防止日志注入攻击
inline std::string sanitizeLogMessage(const std::string& msg) {
    std::string result;
    result.reserve(msg.size());
    for (char c : msg) {
        // 过滤控制字符，但保留换行和制表符
        if (c == '\n' || c == '\t' || (c >= 32 && c < 127)) {
            result += c;
        } else if (c == '\r') {
            // 忽略回车
        } else {
            // 其他控制字符替换为 ?
            result += '?';
        }
    }
    return result;
}

// 日志函数 (线程安全)
inline void log(LogLevel level, const std::string& msg) {
    if (level < g_logLevel.load()) return;

    std::string safeMsg = sanitizeLogMessage(msg);
    const char* levelStr[] = {"DEBUG", "INFO", "WARN", "ERROR", "FATAL"};
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);

    char timeStr[32];
    struct tm tm_result;
    localtime_r(&time, &tm_result);  // 线程安全的 localtime
    std::strftime(timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S", &tm_result);

    std::cout << "[" << timeStr << "][" << levelStr[static_cast<int>(level)] << "] " << safeMsg << std::endl;
}

#define LOG_DEBUG(msg) log(LogLevel::DEBUG, msg)
#define LOG_INFO(msg) log(LogLevel::INFO, msg)
#define LOG_WARN(msg) log(LogLevel::WARN, msg)
#define LOG_ERROR(msg) log(LogLevel::ERROR, msg)
#define LOG_FATAL(msg) log(LogLevel::FATAL, msg)

// 错误码
enum class ErrorCode {
    SUCCESS = 0,
    INVALID_PARAM = -1,
    SOCKET_ERROR = -2,
    BIND_ERROR = -3,
    LISTEN_ERROR = -4,
    ACCEPT_ERROR = -5,
    CONNECT_ERROR = -6,
    EPOLL_ERROR = -7,
    AUTH_ERROR = -8,
    TIMEOUT_ERROR = -9,
    MEMORY_ERROR = -10,
    UNKNOWN_ERROR = -99
};

// 设置非阻塞模式
inline int setNonBlocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

// 设置SO_REUSEADDR和SO_REUSEPORT
inline int setReuseAddr(int fd) {
    int opt = 1;
    int ret = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    #ifdef SO_REUSEPORT
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
    #endif
    return ret;
}

// 设置TCP_NODELAY
inline int setTcpNoDelay(int fd) {
    int opt = 1;
    return setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
}

// 设置发送/接收缓冲区
inline int setSocketBuffer(int fd, int sndBuf, int rcvBuf) {
    int ret = 0;
    if (sndBuf > 0) {
        ret = setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndBuf, sizeof(sndBuf));
        if (ret < 0) return ret;
    }
    if (rcvBuf > 0) {
        ret = setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvBuf, sizeof(rcvBuf));
    }
    return ret;
}

// 安全关闭socket
inline void closeSocket(int& fd) {
    if (fd >= 0) {
        close(fd);
        fd = -1;
    }
}

// Buffer类 - 用于数据缓冲
class Buffer {
public:
    explicit Buffer(size_t size = DEFAULT_BUFFER_SIZE) 
        : data_(size), readPos_(0), writePos_(0) {}
    
    // 获取可读数据指针
    char* readableData() { return data_.data() + readPos_; }
    const char* readableData() const { return data_.data() + readPos_; }
    
    // 获取可写空间指针
    char* writableData() { return data_.data() + writePos_; }
    
    // 可读字节数
    size_t readableBytes() const { return writePos_ - readPos_; }
    
    // 可写字节数
    size_t writableBytes() const { return data_.size() - writePos_; }
    
    // 已读取指定字节
    void retrieve(size_t len) {
        if (len <= readableBytes()) {
            readPos_ += len;
            if (readPos_ == writePos_) {
                readPos_ = writePos_ = 0;
            }
        }
    }
    
    // 写入数据
    void append(const char* data, size_t len) {
        if (!data || len == 0) {
            return;
        }
        ensureWritableBytes(len);
        memcpy(writableData(), data, len);
        writePos_ += len;
    }
    
    // 确保有足够可写空间
    void ensureWritableBytes(size_t len) {
        if (writableBytes() < len) {
            if (readPos_ > 0) {
                // 移动数据到开头
                size_t readable = readableBytes();
                memmove(data_.data(), readableData(), readable);
                readPos_ = 0;
                writePos_ = readable;
            }
            if (writableBytes() < len) {
                data_.resize(writePos_ + len);
            }
        }
    }
    
    // 清空
    void clear() {
        readPos_ = writePos_ = 0;
    }
    
    // 调整写入位置
    void advanceWritePos(size_t len) {
        writePos_ += len;
    }
    
private:
    std::vector<char> data_;
    size_t readPos_;
    size_t writePos_;
};

// 非拷贝基类
class NonCopyable {
public:
    NonCopyable() = default;
    ~NonCopyable() = default;
    NonCopyable(const NonCopyable&) = delete;
    NonCopyable& operator=(const NonCopyable&) = delete;
};

// 单例模板
template<typename T>
class Singleton {
public:
    static T& getInstance() {
        static T instance;
        return instance;
    }
    
    Singleton(const Singleton&) = delete;
    Singleton& operator=(const Singleton&) = delete;
    
protected:
    Singleton() = default;
    ~Singleton() = default;
};

// 工具函数：生成唯一ID
inline std::string generateUUID() {
    static std::atomic<uint64_t> counter{0};
    auto now = std::chrono::high_resolution_clock::now().time_since_epoch().count();
    auto tid = std::hash<std::thread::id>{}(std::this_thread::get_id());
    uint64_t count = counter.fetch_add(1);
    
    std::stringstream ss;
    ss << std::hex << now << "-" << tid << "-" << count;
    return ss.str();
}

// 工具函数：字符串分割
inline std::vector<std::string> splitString(const std::string& str, char delimiter) {
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

// 工具函数：去除字符串首尾空白
inline std::string trimString(const std::string& str) {
    size_t start = str.find_first_not_of(" \t\n\r");
    if (start == std::string::npos) return "";
    size_t end = str.find_last_not_of(" \t\n\r");
    return str.substr(start, end - start + 1);
}

// 工具函数：安全的字符串转整数（带异常处理和默认值）
inline int safeStringToInt(const std::string& str, int defaultValue = 0) {
    try {
        std::string trimmed = trimString(str);
        if (trimmed.empty()) return defaultValue;
        size_t pos;
        int result = std::stoi(trimmed, &pos);
        // 检查是否整个字符串都被解析
        if (pos != trimmed.length()) {
            return defaultValue;
        }
        return result;
    } catch (...) {
        return defaultValue;
    }
}

// 常量时间字符串比较（用于 token 等敏感值校验）
bool timingSafeEqual(const std::string& a, const std::string& b);

// 十六进制编码/解码
std::string bytesToHex(const uint8_t* data, size_t len);
bool hexToBytes(const std::string& hex, std::vector<uint8_t>& out);

// 使用 token 派生密钥进行 AES-256-GCM 加解密
bool encryptWithTokenAesGcm(const std::string& plaintext,
                            const std::string& token,
                            std::string& ivHex,
                            std::string& ciphertextHex,
                            std::string& tagHex);
bool decryptWithTokenAesGcm(const std::string& ivHex,
                            const std::string& ciphertextHex,
                            const std::string& tagHex,
                            const std::string& token,
                            std::string& plaintext);

// 定时器线程类
class TimerThread {
public:
    TimerThread() : running_(false) {}
    ~TimerThread() { stop(); }
    
    void start() {
        running_ = true;
        thread_ = std::thread(&TimerThread::run, this);
    }
    
    void stop() {
        running_ = false;
        cv_.notify_all();
        if (thread_.joinable()) {
            thread_.join();
        }
    }
    
    template<typename Rep, typename Period>
    void scheduleRepeat(std::chrono::duration<Rep, Period> interval, std::function<void()> task) {
        std::unique_lock<std::mutex> lock(mutex_);
        // 设置 lastRun 为一个很早的时间，确保任务在 start 后立即执行
        tasks_.push_back({interval, task, std::chrono::steady_clock::time_point()});
    }

private:
    void run() {
        while (running_) {
            std::vector<std::function<void()>> tasksToExecute;
            auto now = std::chrono::steady_clock::now();

            // 在锁保护下收集需要执行的任务
            {
                std::unique_lock<std::mutex> lock(mutex_);
                for (auto& task : tasks_) {
                    // 如果 lastRun 是 time_point()（未初始化）或者已经过了间隔
                    if (task.lastRun == std::chrono::steady_clock::time_point() ||
                        now - task.lastRun >= task.interval) {
                        tasksToExecute.push_back(task.func);
                        task.lastRun = now;
                    }
                }
            }

            // 在锁外执行任务，避免死锁
            for (auto& func : tasksToExecute) {
                if (func) {
                    func();
                }
            }

            // 等待下一次检查
            std::unique_lock<std::mutex> lock(mutex_);
            cv_.wait_for(lock, std::chrono::milliseconds(10), [this] { return !running_; });
        }
    }

    struct Task {
        std::chrono::steady_clock::duration interval;
        std::function<void()> func;
        std::chrono::steady_clock::time_point lastRun;
    };

    std::vector<Task> tasks_;
    std::atomic<bool> running_;
    std::thread thread_;
    std::mutex mutex_;
    std::condition_variable cv_;
};

} // namespace sshjump

#endif // SSH_JUMP_COMMON_H
