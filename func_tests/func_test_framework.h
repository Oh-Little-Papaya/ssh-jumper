/**
 * @file func_test_framework.h
 * @brief 功能测试框架 - 集成测试
 */

#ifndef FUNC_TEST_FRAMEWORK_H
#define FUNC_TEST_FRAMEWORK_H

#include <iostream>
#include <string>
#include <vector>
#include <functional>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <cstdlib>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <filesystem>

namespace fs = std::filesystem;

// 测试结果统计
struct FuncTestStats {
    int total = 0;
    int passed = 0;
    int failed = 0;
    int skipped = 0;
};

// 测试用例
struct FuncTestCase {
    std::string name;
    std::string category;
    std::function<bool()> testFunc;
    bool enabled = true;
    int timeoutSeconds = 30;
};

// 全局统计
inline FuncTestStats g_funcStats;
inline std::vector<FuncTestCase> g_funcTests;
inline std::vector<std::string> g_funcErrors;

// 注册测试
inline void registerFuncTest(const std::string& name, const std::string& category,
                             std::function<bool()> func, bool enabled = true, int timeout = 30) {
    g_funcTests.push_back({name, category, func, enabled, timeout});
}

// 断言宏
#define FUNC_ASSERT_TRUE(expr) \
    do { \
        if (!(expr)) { \
            std::stringstream ss; \
            ss << "ASSERT_TRUE failed at " << __FILE__ << ":" << __LINE__ \
               << " - " << #expr; \
            g_funcErrors.push_back(ss.str()); \
            return false; \
        } \
    } while(0)

#define FUNC_ASSERT_EQ(expected, actual) \
    do { \
        if ((expected) != (actual)) { \
            std::stringstream ss; \
            ss << "ASSERT_EQ failed at " << __FILE__ << ":" << __LINE__ \
               << " - Expected: " << (expected) << ", Actual: " << (actual); \
            g_funcErrors.push_back(ss.str()); \
            return false; \
        } \
    } while(0)

#define FUNC_ASSERT_NE(expected, actual) \
    do { \
        if ((expected) == (actual)) { \
            std::stringstream ss; \
            ss << "ASSERT_NE failed at " << __FILE__ << ":" << __LINE__ \
               << " - Values are equal: " << (expected); \
            g_funcErrors.push_back(ss.str()); \
            return false; \
        } \
    } while(0)

// 测试注册宏
#define FUNC_TEST(name, category) \
    bool func_test_##name(); \
    struct func_test_##name##_registrar { \
        func_test_##name##_registrar() { \
            registerFuncTest(#name, category, func_test_##name); \
        } \
    } func_test_##name##_instance; \
    bool func_test_##name()

#define FUNC_TEST_WITH_TIMEOUT(name, category, timeout_sec) \
    bool func_test_##name(); \
    struct func_test_##name##_registrar { \
        func_test_##name##_registrar() { \
            registerFuncTest(#name, category, func_test_##name, true, timeout_sec); \
        } \
    } func_test_##name##_instance; \
    bool func_test_##name()

// 运行所有测试
inline int runAllFuncTests(const std::string& filter = "") {
    std::cout << "\n========================================\n";
    std::cout << "      SSH Jump Server 功能测试\n";
    std::cout << "========================================\n\n";
    
    std::string currentCategory;
    
    for (const auto& test : g_funcTests) {
        if (!test.enabled) {
            g_funcStats.skipped++;
            continue;
        }
        
        if (!filter.empty() && test.category.find(filter) == std::string::npos 
            && test.name.find(filter) == std::string::npos) {
            continue;
        }
        
        // 打印类别标题
        if (test.category != currentCategory) {
            currentCategory = test.category;
            std::cout << "\n[" << currentCategory << "]\n";
            std::cout << std::string(currentCategory.length() + 2, '-') << "\n";
        }
        
        std::cout << "  Testing " << std::left << std::setw(50) << test.name << " ... ";
        std::cout.flush();
        
        g_funcErrors.clear();
        g_funcStats.total++;
        
        auto start = std::chrono::high_resolution_clock::now();
        bool result = false;
        
        // 使用 alarm 设置超时
        alarm(test.timeoutSeconds);
        
        try {
            result = test.testFunc();
        } catch (const std::exception& e) {
            std::stringstream ss;
            ss << "Exception: " << e.what();
            g_funcErrors.push_back(ss.str());
            result = false;
        } catch (...) {
            g_funcErrors.push_back("Unknown exception");
            result = false;
        }
        
        alarm(0);  // 取消 alarm
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        
        if (result) {
            std::cout << "\033[32mPASS\033[0m (" << duration.count() << "ms)\n";
            g_funcStats.passed++;
        } else {
            std::cout << "\033[31mFAIL\033[0m (" << duration.count() << "ms)\n";
            g_funcStats.failed++;
            for (const auto& err : g_funcErrors) {
                std::cout << "    \033[31mError: " << err << "\033[0m\n";
            }
        }
    }
    
    // 打印统计
    std::cout << "\n========================================\n";
    std::cout << "              测试统计\n";
    std::cout << "========================================\n";
    std::cout << "  总计:   " << g_funcStats.total << "\n";
    std::cout << "  通过:   \033[32m" << g_funcStats.passed << "\033[0m\n";
    std::cout << "  失败:   \033[31m" << g_funcStats.failed << "\033[0m\n";
    std::cout << "  跳过:   " << g_funcStats.skipped << "\n";
    std::cout << "========================================\n";
    
    return g_funcStats.failed == 0 ? 0 : 1;
}

// 信号处理
inline void timeout_handler(int sig) {
    (void)sig;  // 忽略未使用参数警告
    std::cerr << "\n\033[31mTest timed out!\033[0m\n";
    exit(1);
}

// 初始化信号处理
inline void initFuncTest() {
    signal(SIGALRM, timeout_handler);
}

#endif // FUNC_TEST_FRAMEWORK_H
