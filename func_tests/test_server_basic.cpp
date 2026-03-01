/**
 * @file test_server_basic.cpp
 * @brief 服务器基础功能测试
 */

#include "func_test_framework.h"
#include "test_env.h"

using namespace func_test;

// ============================================
// 服务器启动测试
// ============================================
FUNC_TEST_WITH_TIMEOUT(server_start_stop, "服务器基础", 10) {
    // 设置测试环境
    FUNC_ASSERT_TRUE(g_testEnv.setup());
    
    // 启动服务器
    FUNC_ASSERT_TRUE(g_testEnv.startServer());
    FUNC_ASSERT_TRUE(g_testEnv.isServerRunning());
    
    // 等待服务器完全启动
    std::this_thread::sleep_for(std::chrono::seconds(1));
    
    // 检查服务器是否还在运行（间接验证端口监听）
    FUNC_ASSERT_TRUE(g_testEnv.isServerRunning());
    
    // 停止服务器
    g_testEnv.stopServer();
    FUNC_ASSERT_TRUE(!g_testEnv.isServerRunning());
    
    // 清理
    g_testEnv.cleanup();
    
    return true;
}

// ============================================
// Agent 注册测试
// ============================================
FUNC_TEST_WITH_TIMEOUT(agent_registration, "Agent功能", 15) {
    // 设置测试环境
    FUNC_ASSERT_TRUE(g_testEnv.setup());
    
    // 启动服务器
    FUNC_ASSERT_TRUE(g_testEnv.startServer());
    std::this_thread::sleep_for(std::chrono::seconds(1));
    
    // 启动 Agent
    FUNC_ASSERT_TRUE(g_testEnv.startAgent("web-01", "web01-secret-token", "web-server-01"));
    FUNC_ASSERT_TRUE(g_testEnv.isAgentRunning());
    
    // 等待注册完成
    std::this_thread::sleep_for(std::chrono::seconds(2));
    
    // 检查服务器日志中是否有注册成功记录
    std::string logFile = g_testEnv.getWorkDir() + "/log/server.log";
    std::string checkCmd = "grep -q 'Agent registered: web-01' " + logFile;
    int ret = system(checkCmd.c_str());
    FUNC_ASSERT_EQ(0, WEXITSTATUS(ret));
    
    // 停止 Agent
    g_testEnv.stopAgent();
    
    // 等待注销记录
    std::this_thread::sleep_for(std::chrono::seconds(1));
    
    // 停止服务器
    g_testEnv.stopServer();
    
    // 清理
    g_testEnv.cleanup();
    
    return true;
}

// ============================================
// Agent 心跳测试
// ============================================
FUNC_TEST_WITH_TIMEOUT(agent_heartbeat, "Agent功能", 20) {
    // 设置测试环境
    FUNC_ASSERT_TRUE(g_testEnv.setup());
    
    // 启动服务器
    FUNC_ASSERT_TRUE(g_testEnv.startServer());
    std::this_thread::sleep_for(std::chrono::seconds(1));
    
    // 启动 Agent
    FUNC_ASSERT_TRUE(g_testEnv.startAgent("web-01", "web01-secret-token", "web-server-01"));
    
    // 等待多个心跳周期（心跳间隔5秒，等待12秒）
    std::this_thread::sleep_for(std::chrono::seconds(12));
    
    // 检查服务器日志中是否有心跳记录
    std::string logFile = g_testEnv.getWorkDir() + "/log/server.log";
    std::string checkCmd = "grep -c 'Heartbeat from agent: web-01' " + logFile + " 2>/dev/null";
    FILE* pipe = popen(checkCmd.c_str(), "r");
    int heartbeatCount = 0;
    if (pipe) {
        fscanf(pipe, "%d", &heartbeatCount);
        pclose(pipe);
    }
    
    // 应该至少有1个心跳
    FUNC_ASSERT_TRUE(heartbeatCount >= 1);
    
    // 停止
    g_testEnv.stopAgent();
    g_testEnv.stopServer();
    g_testEnv.cleanup();
    
    return true;
}

// ============================================
// 多个 Agent 注册测试
// ============================================
FUNC_TEST_WITH_TIMEOUT(multiple_agents_registration, "Agent功能", 20) {
    // 设置测试环境
    FUNC_ASSERT_TRUE(g_testEnv.setup());
    
    // 启动服务器
    FUNC_ASSERT_TRUE(g_testEnv.startServer());
    std::this_thread::sleep_for(std::chrono::seconds(1));
    
    // 启动多个 Agent
    ProcessManager agent1, agent2, agent3;
    
    std::vector<std::string> args1 = {
        "-s", "127.0.0.1",
        "-p", std::to_string(g_testEnv.getClusterPort()),
        "-i", "web-01",
        "-t", "web01-secret-token",
        "-n", "web-server-01"
    };
    FUNC_ASSERT_TRUE(agent1.start(g_testEnv.getWorkDir() + "/../build/ssh_jump_agent", args1));
    
    std::vector<std::string> args2 = {
        "-s", "127.0.0.1",
        "-p", std::to_string(g_testEnv.getClusterPort()),
        "-i", "web-02",
        "-t", "web02-secret-token",
        "-n", "web-server-02"
    };
    FUNC_ASSERT_TRUE(agent2.start(g_testEnv.getWorkDir() + "/../build/ssh_jump_agent", args2));
    
    std::vector<std::string> args3 = {
        "-s", "127.0.0.1",
        "-p", std::to_string(g_testEnv.getClusterPort()),
        "-i", "db-01",
        "-t", "db01-secret-token",
        "-n", "db-server-01"
    };
    FUNC_ASSERT_TRUE(agent3.start(g_testEnv.getWorkDir() + "/../build/ssh_jump_agent", args3));
    
    // 等待注册
    std::this_thread::sleep_for(std::chrono::seconds(2));
    
    // 检查日志中是否注册了所有 Agent
    std::string logFile = g_testEnv.getWorkDir() + "/log/server.log";
    std::string checkCmd = "grep -c 'Agent registered' " + logFile;
    FILE* pipe = popen(checkCmd.c_str(), "r");
    int registeredCount = 0;
    if (pipe) {
        fscanf(pipe, "%d", &registeredCount);
        pclose(pipe);
    }
    
    FUNC_ASSERT_EQ(3, registeredCount);
    
    // 停止
    agent1.stop();
    agent2.stop();
    agent3.stop();
    g_testEnv.stopServer();
    g_testEnv.cleanup();
    
    return true;
}

// ============================================
// 无效 Token 测试
// ============================================
FUNC_TEST_WITH_TIMEOUT(invalid_token_rejection, "安全功能", 15) {
    // 设置测试环境
    FUNC_ASSERT_TRUE(g_testEnv.setup());
    
    // 启动服务器
    FUNC_ASSERT_TRUE(g_testEnv.startServer());
    std::this_thread::sleep_for(std::chrono::seconds(1));
    
    // 启动 Agent 使用错误的 token
    ProcessManager badAgent;
    std::vector<std::string> args = {
        "-s", "127.0.0.1",
        "-p", std::to_string(g_testEnv.getClusterPort()),
        "-i", "web-01",
        "-t", "wrong-token",
        "-n", "web-server-01"
    };
    FUNC_ASSERT_TRUE(badAgent.start(g_testEnv.getWorkDir() + "/../build/ssh_jump_agent", args));
    
    // 等待尝试连接
    std::this_thread::sleep_for(std::chrono::seconds(3));
    
    // 检查服务器日志中是否有拒绝记录
    std::string logFile = g_testEnv.getWorkDir() + "/log/server.log";
    std::string checkCmd = "grep -q 'Invalid token' " + logFile;
    int ret = system(checkCmd.c_str());
    FUNC_ASSERT_EQ(0, WEXITSTATUS(ret));
    
    // 检查没有成功注册
    checkCmd = "grep -c 'Agent registered: web-01' " + logFile + " 2>/dev/null";
    FILE* pipe = popen(checkCmd.c_str(), "r");
    int registeredCount = 0;
    if (pipe) {
        fscanf(pipe, "%d", &registeredCount);
        pclose(pipe);
    }
    FUNC_ASSERT_EQ(0, registeredCount);
    
    badAgent.stop();
    g_testEnv.stopServer();
    g_testEnv.cleanup();
    
    return true;
}
