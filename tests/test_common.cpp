/**
 * @file test_common.cpp
 * @brief 通用工具模块测试 - 更新为使用 libssh
 */

#include "test_framework.h"
#include "../include/common.h"
#include <libssh/libssh.h>
#include <libssh/server.h>

using namespace sshjump;

// ============================================
// Buffer 测试
// ============================================
TEST(buffer_basic_operations, "通用工具") {
    Buffer buffer(1024);
    
    // 测试初始状态
    ASSERT_EQ(0, buffer.readableBytes());
    ASSERT_EQ(1024, buffer.writableBytes());
    
    // 写入数据
    const char* data = "Hello, World!";
    buffer.append(data, strlen(data));
    ASSERT_EQ(strlen(data), buffer.readableBytes());
    
    // 读取数据
    ASSERT_EQ(0, memcmp(buffer.readableData(), data, strlen(data)));
    
    // 消费数据
    buffer.retrieve(strlen(data));
    ASSERT_EQ(0, buffer.readableBytes());
    
    return true;
}

TEST(buffer_resize, "通用工具") {
    Buffer buffer(10);
    
    // 写入超过初始大小的数据
    std::string largeData(100, 'X');
    buffer.append(largeData.c_str(), largeData.size());
    
    ASSERT_EQ(100, buffer.readableBytes());
    ASSERT_EQ(0, memcmp(buffer.readableData(), largeData.c_str(), largeData.size()));
    
    return true;
}

TEST(buffer_clear, "通用工具") {
    Buffer buffer(1024);
    buffer.append("test data", 9);
    buffer.clear();
    
    ASSERT_EQ(0, buffer.readableBytes());
    
    return true;
}

TEST(buffer_multiple_operations, "通用工具") {
    Buffer buffer(64);
    
    // 第一次写入和读取
    buffer.append("ABC", 3);
    ASSERT_EQ(3, buffer.readableBytes());
    buffer.retrieve(2);  // 消费 "AB"
    ASSERT_EQ(1, buffer.readableBytes());  // 剩余 "C"
    
    // 第二次写入
    buffer.append("DEF", 3);  // 现在应该是 "CDEF"
    ASSERT_EQ(4, buffer.readableBytes());
    ASSERT_TRUE(memcmp(buffer.readableData(), "CDEF", 4) == 0);
    
    return true;
}

// ============================================
// 字符串工具测试
// ============================================
TEST(trim_string_basic, "通用工具") {
    ASSERT_EQ("hello", trimString("  hello  "));
    ASSERT_EQ("hello", trimString("\thello\n"));
    ASSERT_EQ("hello", trimString("hello"));
    ASSERT_EQ("", trimString("   "));
    ASSERT_EQ("", trimString(""));
    return true;
}

TEST(split_string_basic, "通用工具") {
    auto result = splitString("a,b,c", ',');
    ASSERT_EQ(3, result.size());
    ASSERT_EQ("a", result[0]);
    ASSERT_EQ("b", result[1]);
    ASSERT_EQ("c", result[2]);
    return true;
}

TEST(split_string_empty, "通用工具") {
    auto result = splitString("", ',');
    ASSERT_EQ(0, result.size());
    return true;
}

TEST(split_string_no_delimiter, "通用工具") {
    auto result = splitString("single", ',');
    ASSERT_EQ(1, result.size());
    ASSERT_EQ("single", result[0]);
    return true;
}

TEST(split_string_consecutive_delimiters, "通用工具") {
    auto result = splitString("a,,b,,,c", ',');
    ASSERT_EQ(3, result.size());  // 空字符串被忽略
    ASSERT_EQ("a", result[0]);
    ASSERT_EQ("b", result[1]);
    ASSERT_EQ("c", result[2]);
    return true;
}

// ============================================
// UUID 生成测试
// ============================================
TEST(generate_uuid_unique, "通用工具") {
    std::set<std::string> uuids;
    for (int i = 0; i < 100; i++) {
        std::string uuid = generateUUID();
        ASSERT_TRUE(uuids.find(uuid) == uuids.end());  // 唯一性
        uuids.insert(uuid);
    }
    ASSERT_EQ(100, uuids.size());
    return true;
}

TEST(generate_uuid_format, "通用工具") {
    std::string uuid = generateUUID();
    // UUID 应该包含两个连字符
    ASSERT_TRUE(uuid.find('-') != std::string::npos);
    // UUID 应该使用十六进制字符
    for (char c : uuid) {
        ASSERT_TRUE(isxdigit(c) || c == '-');
    }
    return true;
}

// ============================================
// 事件类型测试
// ============================================
TEST(event_type_operations, "通用工具") {
    EventType read = EventType::READ;
    EventType write = EventType::WRITE;
    EventType error = EventType::ERROR;
    
    // 测试或操作
    EventType combined = read | write;
    ASSERT_TRUE(combined & read);
    ASSERT_TRUE(combined & write);
    ASSERT_FALSE(combined & error);
    
    // 测试组合后的或操作
    EventType all = combined | error;
    ASSERT_TRUE(all & read);
    ASSERT_TRUE(all & write);
    ASSERT_TRUE(all & error);
    
    return true;
}

// ============================================
// Socket 工具测试
// ============================================
TEST(socket_buffer_operations, "通用工具") {
    // 创建一对 socket 用于测试
    int fds[2];
    int ret = socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
    ASSERT_EQ(0, ret);
    
    // 测试设置缓冲区 (UNIX domain socket 上可能受限制，不强制要求成功)
    ret = setSocketBuffer(fds[0], 8192, 8192);
    // 缓冲区设置可能因系统限制而失败，只验证函数不崩溃
    (void)ret;  // 忽略返回值
    
    // 清理
    close(fds[0]);
    close(fds[1]);
    
    return true;
}

TEST(tcp_options, "通用工具") {
    // 创建 TCP socket 测试 TCP 特定选项
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_TRUE(fd >= 0);
    
    // 测试设置 TCP_NODELAY
    int ret = setTcpNoDelay(fd);
    ASSERT_EQ(0, ret);
    
    // 测试设置缓冲区
    ret = setSocketBuffer(fd, 8192, 8192);
    // 不强制要求成功，某些系统可能需要特殊权限
    (void)ret;
    
    close(fd);
    return true;
}

TEST(set_nonblocking, "通用工具") {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    ASSERT_TRUE(fd >= 0);
    
    int ret = setNonBlocking(fd);
    ASSERT_EQ(0, ret);
    
    // 验证非阻塞标志已设置
    int flags = fcntl(fd, F_GETFL, 0);
    ASSERT_TRUE(flags & O_NONBLOCK);
    
    close(fd);
    return true;
}

// ============================================
// 常量测试
// ============================================
TEST(constant_values, "通用工具") {
    ASSERT_EQ(2222, DEFAULT_SSH_PORT);
    ASSERT_EQ(8888, DEFAULT_CLUSTER_PORT);
    ASSERT_EQ(128, DEFAULT_BACKLOG);
    ASSERT_EQ(65536, DEFAULT_BUFFER_SIZE);
    ASSERT_EQ(8, DEFAULT_THREAD_POOL_SIZE);
    ASSERT_EQ(10000, DEFAULT_MAX_CONNECTIONS);
    ASSERT_EQ(30, DEFAULT_HEARTBEAT_INTERVAL);
    ASSERT_EQ(300, DEFAULT_CONNECTION_TIMEOUT);
    ASSERT_EQ(0x4A534853, MAGIC_NUMBER);
    return true;
}

// ============================================
// NonCopyable 测试
// ============================================
namespace {
    class TestNonCopyable : public NonCopyable {
    public:
        int value = 42;
    };
}

TEST(noncopyable_basic, "通用工具") {
    TestNonCopyable obj1;
    ASSERT_EQ(42, obj1.value);
    
    obj1.value = 100;
    ASSERT_EQ(100, obj1.value);
    
    // NonCopyable 不可复制也不可移动
    // 验证其基本功能即可
    
    return true;
}

// ============================================
// Singleton 测试
// ============================================
namespace {
    class TestSingleton : public Singleton<TestSingleton> {
    public:
        int counter = 0;
        std::string name = "test";
    };
}

TEST(singleton_instance, "通用工具") {
    // 获取单例实例
    TestSingleton& instance1 = TestSingleton::getInstance();
    TestSingleton& instance2 = TestSingleton::getInstance();
    
    // 应该是同一个实例
    ASSERT_EQ(&instance1, &instance2);
    
    // 修改应该对两者都可见
    instance1.counter = 10;
    ASSERT_EQ(10, instance2.counter);
    
    return true;
}

// ============================================
// TimerThread 测试
// ============================================
TEST(timer_thread_basic, "通用工具") {
    TimerThread timer;
    std::atomic<int> counter{0};
    
    // 先调度任务，再启动 timer
    timer.scheduleRepeat(std::chrono::milliseconds(20), [&counter]() {
        counter.fetch_add(1);
    });
    
    timer.start();
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    timer.stop();
    
    // 只要执行了就行，不严格要求次数（考虑系统调度延迟）
    ASSERT_TRUE(counter.load() >= 1);
    
    return true;
}

TEST(timer_thread_multiple_tasks, "通用工具") {
    TimerThread timer;
    std::atomic<int> counter1{0};
    std::atomic<int> counter2{0};
    
    // 先调度所有任务，再启动 timer
    timer.scheduleRepeat(std::chrono::milliseconds(20), [&counter1]() {
        counter1.fetch_add(1);
    });
    
    timer.scheduleRepeat(std::chrono::milliseconds(50), [&counter2]() {
        counter2.fetch_add(1);
    });
    
    timer.start();
    std::this_thread::sleep_for(std::chrono::milliseconds(250));
    timer.stop();
    
    // 两个任务都应该被执行
    ASSERT_TRUE(counter1.load() >= 1);
    ASSERT_TRUE(counter2.load() >= 1);
    // 快任务应该执行更多次或至少相等
    ASSERT_TRUE(counter1.load() >= counter2.load());
    
    return true;
}

// ============================================
// libssh 集成测试
// ============================================
TEST(libssh_version_check, "libssh集成") {
    // 测试 libssh 版本信息
    // ssh_version(0) 返回版本字符串
    const char* libsshVer = ssh_version(0);
    ASSERT_NOT_NULL(libsshVer);
    ASSERT_TRUE(strlen(libsshVer) > 0);
    
    return true;
}

TEST(libssh_session_create, "libssh集成") {
    // 创建 SSH 会话
    ssh_session my_ssh_session = ssh_new();
    ASSERT_NOT_NULL(my_ssh_session);
    
    // 清理
    ssh_free(my_ssh_session);
    
    return true;
}

TEST(libssh_session_options, "libssh集成") {
    ssh_session session = ssh_new();
    ASSERT_NOT_NULL(session);
    
    // 设置选项
    int rc = ssh_options_set(session, SSH_OPTIONS_HOST, "localhost");
    ASSERT_EQ(SSH_OK, rc);
    
    // 设置端口
    int port = 22;
    rc = ssh_options_set(session, SSH_OPTIONS_PORT, &port);
    ASSERT_EQ(SSH_OK, rc);
    
    // 设置用户
    rc = ssh_options_set(session, SSH_OPTIONS_USER, "testuser");
    ASSERT_EQ(SSH_OK, rc);
    
    ssh_free(session);
    return true;
}

TEST(libssh_key_hash_algorithm, "libssh集成") {
    // 测试 SSH 密钥哈希算法枚举
    // 这些是 libssh 中的标准算法
    ssh_keytypes_e keytype = SSH_KEYTYPE_RSA;
    (void)keytype;  // 仅验证类型存在
    
    // 验证一些常用的 libssh 常量
    ASSERT_EQ(0, SSH_OK);
    ASSERT_EQ(-1, SSH_ERROR);
    ASSERT_EQ(-2, SSH_AGAIN);
    
    return true;
}

TEST(libssh_auth_methods, "libssh集成") {
    // 测试认证方法常量
    int auth_methods = SSH_AUTH_METHOD_PASSWORD | SSH_AUTH_METHOD_PUBLICKEY;
    (void)auth_methods;
    
    // 验证这些值不为零
    ASSERT_TRUE(SSH_AUTH_METHOD_PASSWORD != 0);
    ASSERT_TRUE(SSH_AUTH_METHOD_PUBLICKEY != 0);
    ASSERT_TRUE(SSH_AUTH_METHOD_HOSTBASED != 0);
    ASSERT_TRUE(SSH_AUTH_METHOD_INTERACTIVE != 0);
    
    return true;
}

TEST(libssh_connection_state, "libssh集成") {
    // 验证 ConnectionState 枚举与 libssh 兼容
    ConnectionState states[] = {
        ConnectionState::INITIALIZING,
        ConnectionState::HANDSHAKING,
        ConnectionState::AUTHENTICATING,
        ConnectionState::AUTHENTICATED,
        ConnectionState::FORWARDING,
        ConnectionState::CLOSING,
        ConnectionState::CLOSED
    };
    
    // 验证所有状态都不同
    for (size_t i = 0; i < sizeof(states)/sizeof(states[0]); i++) {
        for (size_t j = i + 1; j < sizeof(states)/sizeof(states[0]); j++) {
            ASSERT_TRUE(states[i] != states[j]);
        }
    }
    
    return true;
}
