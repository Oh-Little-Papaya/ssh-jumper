/**
 * @file test_framework.h
 * @brief 轻量级测试框架
 */

#ifndef TEST_FRAMEWORK_H
#define TEST_FRAMEWORK_H

#include <iostream>
#include <string>
#include <vector>
#include <functional>
#include <chrono>
#include <sstream>
#include <iomanip>

// 测试结果统计
struct TestStats {
    int total = 0;
    int passed = 0;
    int failed = 0;
    int skipped = 0;
};

// 测试用例
struct TestCase {
    std::string name;
    std::string category;
    std::function<bool()> testFunc;
    bool enabled = true;
};

// 全局统计
extern TestStats g_stats;
extern std::vector<TestCase> g_tests;
extern std::vector<std::string> g_errors;

// 注册测试
inline void registerTest(const std::string& name, const std::string& category, 
                         std::function<bool()> func, bool enabled = true) {
    g_tests.push_back({name, category, func, enabled});
}

// 断言宏
#define ASSERT_TRUE(expr) \
    do { \
        if (!(expr)) { \
            std::stringstream ss; \
            ss << "ASSERT_TRUE failed at " << __FILE__ << ":" << __LINE__ \
               << " - " << #expr; \
            g_errors.push_back(ss.str()); \
            return false; \
        } \
    } while(0)

#define ASSERT_FALSE(expr) \
    do { \
        if (expr) { \
            std::stringstream ss; \
            ss << "ASSERT_FALSE failed at " << __FILE__ << ":" << __LINE__ \
               << " - " << #expr; \
            g_errors.push_back(ss.str()); \
            return false; \
        } \
    } while(0)

#define ASSERT_EQ(expected, actual) \
    do { \
        if ((expected) != (actual)) { \
            std::stringstream ss; \
            ss << "ASSERT_EQ failed at " << __FILE__ << ":" << __LINE__ \
               << " - Expected: " << (expected) << ", Actual: " << (actual); \
            g_errors.push_back(ss.str()); \
            return false; \
        } \
    } while(0)

#define ASSERT_NE(expected, actual) \
    do { \
        if ((expected) == (actual)) { \
            std::stringstream ss; \
            ss << "ASSERT_NE failed at " << __FILE__ << ":" << __LINE__ \
               << " - Values are equal: " << (expected); \
            g_errors.push_back(ss.str()); \
            return false; \
        } \
    } while(0)

#define ASSERT_NULL(ptr) \
    do { \
        if ((ptr) != nullptr) { \
            std::stringstream ss; \
            ss << "ASSERT_NULL failed at " << __FILE__ << ":" << __LINE__; \
            g_errors.push_back(ss.str()); \
            return false; \
        } \
    } while(0)

#define ASSERT_NOT_NULL(ptr) \
    do { \
        if ((ptr) == nullptr) { \
            std::stringstream ss; \
            ss << "ASSERT_NOT_NULL failed at " << __FILE__ << ":" << __LINE__; \
            g_errors.push_back(ss.str()); \
            return false; \
        } \
    } while(0)

// 测试注册宏
#define TEST(name, category) \
    bool test_##name(); \
    struct test_##name##_registrar { \
        test_##name##_registrar() { \
            registerTest(#name, category, test_##name); \
        } \
    } test_##name##_instance; \
    bool test_##name()

#define TEST_DISABLED(name, category) \
    bool test_##name(); \
    struct test_##name##_registrar { \
        test_##name##_registrar() { \
            registerTest(#name, category, test_##name, false); \
        } \
    } test_##name##_instance; \
    bool test_##name()

// 运行所有测试
inline int runAllTests(const std::string& filter = "") {
    std::cout << "\n========================================\n";
    std::cout << "      SSH Jump Server 功能测试\n";
    std::cout << "========================================\n\n";
    
    std::string currentCategory;
    
    for (const auto& test : g_tests) {
        if (!test.enabled) {
            g_stats.skipped++;
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
        
        std::cout << "  Testing " << std::left << std::setw(40) << test.name << " ... ";
        
        g_errors.clear();
        g_stats.total++;
        
        auto start = std::chrono::high_resolution_clock::now();
        bool result = false;
        
        try {
            result = test.testFunc();
        } catch (const std::exception& e) {
            std::stringstream ss;
            ss << "Exception: " << e.what();
            g_errors.push_back(ss.str());
            result = false;
        } catch (...) {
            g_errors.push_back("Unknown exception");
            result = false;
        }
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        
        if (result) {
            std::cout << "\033[32mPASS\033[0m (" << duration.count() << "ms)\n";
            g_stats.passed++;
        } else {
            std::cout << "\033[31mFAIL\033[0m (" << duration.count() << "ms)\n";
            g_stats.failed++;
            for (const auto& err : g_errors) {
                std::cout << "    \033[31mError: " << err << "\033[0m\n";
            }
        }
    }
    
    // 打印统计
    std::cout << "\n========================================\n";
    std::cout << "              测试统计\n";
    std::cout << "========================================\n";
    std::cout << "  总计:   " << g_stats.total << "\n";
    std::cout << "  通过:   \033[32m" << g_stats.passed << "\033[0m\n";
    std::cout << "  失败:   \033[31m" << g_stats.failed << "\033[0m\n";
    std::cout << "  跳过:   " << g_stats.skipped << "\n";
    std::cout << "========================================\n";
    
    return g_stats.failed == 0 ? 0 : 1;
}

// 使用 C++17 inline 变量，避免重复定义
inline TestStats g_stats;
inline std::vector<TestCase> g_tests;
inline std::vector<std::string> g_errors;

#endif // TEST_FRAMEWORK_H
