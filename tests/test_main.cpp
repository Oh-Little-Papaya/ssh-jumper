/**
 * @file test_main.cpp
 * @brief 测试入口
 */

#include "test_framework.h"

int main(int argc, char* argv[]) {
    std::string filter;
    if (argc > 1) {
        filter = argv[1];
    }
    
    return runAllTests(filter);
}
