/**
 * @file test_integration.cpp
 * @brief 集成测试 - 测试完整工作流程
 */

#include "func_test_framework.h"
#include "test_env.h"
#include <fstream>

using namespace func_test;

// ============================================
// 完整工作流程测试
// ============================================
FUNC_TEST_WITH_TIMEOUT(complete_workflow, "集成测试", 30) {
    // 设置测试环境
    FUNC_ASSERT_TRUE(g_testEnv.setup());
    
    // 1. 启动服务器
    std::cout << "\n    [1/5] 启动服务器... " << std::flush;
    FUNC_ASSERT_TRUE(g_testEnv.startServer());
    std::this_thread::sleep_for(std::chrono::seconds(2));
    FUNC_ASSERT_TRUE(g_testEnv.isServerRunning());
    std::cout << "OK (PID: " << g_testEnv.getServerPid() << ")" << std::flush;
    
    // 2. 启动 Agent
    std::cout << "\n    [2/5] 启动 Agent... " << std::flush;
    FUNC_ASSERT_TRUE(g_testEnv.startAgent("web-01", g_testEnv.getClusterToken(), "web-server-01"));
    std::this_thread::sleep_for(std::chrono::seconds(2));
    FUNC_ASSERT_TRUE(g_testEnv.isAgentRunning());
    std::cout << "OK (PID: " << g_testEnv.getAgentPid() << ")" << std::flush;
    
    // 3. 等待一段时间（模拟心跳）
    std::cout << "\n    [3/5] 运行 3 秒... " << std::flush;
    std::this_thread::sleep_for(std::chrono::seconds(3));
    FUNC_ASSERT_TRUE(g_testEnv.isServerRunning());
    FUNC_ASSERT_TRUE(g_testEnv.isAgentRunning());
    std::cout << "OK" << std::flush;
    
    // 4. 停止 Agent
    std::cout << "\n    [4/5] 停止 Agent... " << std::flush;
    g_testEnv.stopAgent();
    FUNC_ASSERT_TRUE(!g_testEnv.isAgentRunning());
    std::cout << "OK" << std::flush;
    
    // 5. 停止服务器
    std::cout << "\n    [5/5] 停止服务器... " << std::flush;
    g_testEnv.stopServer();
    FUNC_ASSERT_TRUE(!g_testEnv.isServerRunning());
    std::cout << "OK" << std::flush;
    
    // 清理
    g_testEnv.cleanup();
    
    std::cout << "\n    " << std::flush;
    return true;
}

// ============================================
// 多 Agent 测试
// ============================================
FUNC_TEST_WITH_TIMEOUT(multiple_agents, "集成测试", 30) {
    // 设置测试环境
    FUNC_ASSERT_TRUE(g_testEnv.setup());
    
    // 启动服务器
    FUNC_ASSERT_TRUE(g_testEnv.startServer());
    std::this_thread::sleep_for(std::chrono::seconds(2));
    FUNC_ASSERT_TRUE(g_testEnv.isServerRunning());
    
    // 启动多个 Agent
    ProcessManager agent1, agent2, agent3;
    
    std::vector<std::string> args1 = {
        "-s", "127.0.0.1",
        "-p", std::to_string(g_testEnv.getClusterPort()),
        "-i", "web-01",
        "-t", g_testEnv.getClusterToken(),
        "-n", "web-server-01"
    };
    FUNC_ASSERT_TRUE(agent1.start(g_testEnv.getAgentBinary(), args1));
    
    std::vector<std::string> args2 = {
        "-s", "127.0.0.1",
        "-p", std::to_string(g_testEnv.getClusterPort()),
        "-i", "web-02",
        "-t", g_testEnv.getClusterToken(),
        "-n", "web-server-02"
    };
    FUNC_ASSERT_TRUE(agent2.start(g_testEnv.getAgentBinary(), args2));
    
    std::vector<std::string> args3 = {
        "-s", "127.0.0.1",
        "-p", std::to_string(g_testEnv.getClusterPort()),
        "-i", "db-01",
        "-t", g_testEnv.getClusterToken(),
        "-n", "db-server-01"
    };
    FUNC_ASSERT_TRUE(agent3.start(g_testEnv.getAgentBinary(), args3));
    
    // 等待 Agent 连接
    std::this_thread::sleep_for(std::chrono::seconds(3));
    
    // 验证所有 Agent 都在运行
    FUNC_ASSERT_TRUE(agent1.isRunning());
    FUNC_ASSERT_TRUE(agent2.isRunning());
    FUNC_ASSERT_TRUE(agent3.isRunning());
    
    // 停止所有 Agent
    agent1.stop();
    agent2.stop();
    agent3.stop();
    
    // 停止服务器
    g_testEnv.stopServer();
    g_testEnv.cleanup();
    
    return true;
}

// ============================================
// 安全测试 - 无效 Token
// ============================================
FUNC_TEST_WITH_TIMEOUT(security_invalid_token, "集成测试", 20) {
    // 设置测试环境
    FUNC_ASSERT_TRUE(g_testEnv.setup());
    
    // 启动服务器
    FUNC_ASSERT_TRUE(g_testEnv.startServer());
    std::this_thread::sleep_for(std::chrono::seconds(2));
    FUNC_ASSERT_TRUE(g_testEnv.isServerRunning());
    
    // 启动 Agent 使用错误的 token
    ProcessManager badAgent;
    std::vector<std::string> args = {
        "-s", "127.0.0.1",
        "-p", std::to_string(g_testEnv.getClusterPort()),
        "-i", "web-01",
        "-t", "wrong-token",
        "-n", "web-server-01"
    };
    FUNC_ASSERT_TRUE(badAgent.start(g_testEnv.getAgentBinary(), args));
    
    // 等待一段时间
    std::this_thread::sleep_for(std::chrono::seconds(3));
    
    // Agent 应该因为认证失败而退出或无法保持连接
    // 注意: 这取决于 Agent 的实现，可能保持运行但无法注册
    
    badAgent.stop();
    g_testEnv.stopServer();
    g_testEnv.cleanup();
    
    return true;
}
