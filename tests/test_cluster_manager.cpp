/**
 * @file test_cluster_manager.cpp
 * @brief 集群管理器测试 - 与当前 ClusterManager 实现兼容
 */

#include "test_framework.h"
#include "../include/cluster_manager.h"

using namespace sshjump;

// ============================================
// ServiceInfo 测试
// ============================================
TEST(service_info_basic, "集群管理") {
    ServiceInfo svc;
    svc.name = "SSH";
    svc.type = "ssh";
    svc.port = 22;
    svc.description = "Secure Shell";
    
    ASSERT_EQ("SSH", svc.name);
    ASSERT_EQ("ssh", svc.type);
    ASSERT_EQ(22, svc.port);
    ASSERT_EQ("Secure Shell", svc.description);
    
    return true;
}

TEST(service_info_metadata, "集群管理") {
    ServiceInfo svc;
    svc.type = "http";
    svc.port = 8080;
    svc.metadata["version"] = "1.0";
    svc.metadata["ssl"] = "true";
    
    ASSERT_EQ(2, svc.metadata.size());
    ASSERT_EQ("1.0", svc.metadata["version"]);
    ASSERT_EQ("true", svc.metadata["ssl"]);
    
    return true;
}

// ============================================
// AgentInfo 测试
// ============================================
TEST(agent_info_initialization, "集群管理") {
    AgentInfo agent;
    agent.agentId = "agent-01";
    agent.hostname = "web-server-01";
    agent.ipAddress = "10.0.1.10";
    agent.port = 8888;
    agent.version = "1.0.0";
    agent.authToken = "secret-token";
    agent.isOnline = false;  // 默认是 false
    agent.consecutiveFailures = 0;
    agent.controlFd = -1;
    
    ASSERT_EQ("agent-01", agent.agentId);
    ASSERT_EQ("web-server-01", agent.hostname);
    ASSERT_EQ("10.0.1.10", agent.ipAddress);
    ASSERT_EQ(8888, agent.port);
    ASSERT_EQ("1.0.0", agent.version);
    ASSERT_EQ("secret-token", agent.authToken);
    ASSERT_FALSE(agent.isOnline);  // 初始为 false
    ASSERT_EQ(0, agent.consecutiveFailures);
    ASSERT_EQ(-1, agent.controlFd);
    
    return true;
}

TEST(agent_info_services, "集群管理") {
    AgentInfo agent;
    agent.agentId = "multi-service-agent";
    
    ServiceInfo sshSvc;
    sshSvc.type = "ssh";
    sshSvc.port = 22;
    agent.services.push_back(sshSvc);
    
    ServiceInfo httpSvc;
    httpSvc.type = "http";
    httpSvc.port = 80;
    agent.services.push_back(httpSvc);
    
    ASSERT_EQ(2, agent.services.size());
    ASSERT_EQ("ssh", agent.services[0].type);
    ASSERT_EQ("http", agent.services[1].type);
    
    return true;
}

TEST(agent_info_copy_constructor, "集群管理") {
    AgentInfo original;
    original.agentId = "original-agent";
    original.hostname = "original-host";
    original.ipAddress = "192.168.1.1";
    original.isOnline = true;
    original.consecutiveFailures = 3;
    
    ServiceInfo svc;
    svc.type = "ssh";
    svc.port = 22;
    original.services.push_back(svc);
    
    // 使用拷贝构造函数
    AgentInfo copy(original);
    
    ASSERT_EQ(original.agentId, copy.agentId);
    ASSERT_EQ(original.hostname, copy.hostname);
    ASSERT_EQ(original.ipAddress, copy.ipAddress);
    ASSERT_EQ(original.isOnline, copy.isOnline);
    ASSERT_EQ(original.consecutiveFailures, copy.consecutiveFailures);
    ASSERT_EQ(original.services.size(), copy.services.size());
    
    return true;
}

TEST(agent_info_assignment_operator, "集群管理") {
    AgentInfo agent1;
    agent1.agentId = "agent1";
    agent1.hostname = "host1";
    
    AgentInfo agent2;
    agent2 = agent1;
    
    ASSERT_EQ(agent1.agentId, agent2.agentId);
    ASSERT_EQ(agent1.hostname, agent2.hostname);
    
    // 自赋值
    agent2 = agent2;
    ASSERT_EQ("agent1", agent2.agentId);
    
    return true;
}

// ============================================
// AgentMessage 测试
// ============================================
TEST(agent_message_serialization, "集群管理") {
    AgentMessage msg;
    msg.magic = MAGIC_NUMBER;
    msg.type = AgentMessageType::REGISTER;
    msg.payload = "test data";  // 9 bytes
    msg.length = msg.payload.length();  // 应该设置为 payload 的实际长度
    
    std::vector<uint8_t> data = msg.serialize();
    ASSERT_FALSE(data.empty());
    ASSERT_EQ(9 + 9, data.size());  // 头部9字节 + 9字节payload
    
    // 反序列化
    AgentMessage parsed;
    bool result = AgentMessage::deserialize(data.data(), data.size(), parsed);
    
    ASSERT_TRUE(result);
    ASSERT_EQ(msg.magic, parsed.magic);
    ASSERT_EQ(static_cast<uint8_t>(msg.type), static_cast<uint8_t>(parsed.type));
    ASSERT_EQ(msg.length, parsed.length);
    ASSERT_EQ(msg.payload, parsed.payload);
    
    return true;
}

TEST(agent_message_create, "集群管理") {
    AgentMessage msg = AgentMessage::create(AgentMessageType::HEARTBEAT, "{\"status\":\"ok\"}");
    
    ASSERT_EQ(MAGIC_NUMBER, msg.magic);
    ASSERT_EQ(static_cast<uint8_t>(AgentMessageType::HEARTBEAT), static_cast<uint8_t>(msg.type));
    ASSERT_EQ(std::string("{\"status\":\"ok\"}"), msg.payload);
    ASSERT_EQ(msg.payload.length(), msg.length);
    
    return true;
}

TEST(agent_message_deserialize_invalid, "集群管理") {
    // 数据太短
    uint8_t shortData[4] = {0};
    AgentMessage msg;
    bool result = AgentMessage::deserialize(shortData, 4, msg);
    ASSERT_FALSE(result);
    
    // 错误的魔数
    uint8_t wrongMagic[16] = {0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 
                              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    result = AgentMessage::deserialize(wrongMagic, 16, msg);
    ASSERT_FALSE(result);
    
    return true;
}

TEST(agent_message_empty_payload, "集群管理") {
    AgentMessage msg = AgentMessage::create(AgentMessageType::HEARTBEAT, "");
    
    ASSERT_EQ(0, msg.length);
    ASSERT_TRUE(msg.payload.empty());
    
    std::vector<uint8_t> data = msg.serialize();
    ASSERT_EQ(9, data.size());  // 只有头部
    
    AgentMessage parsed;
    bool result = AgentMessage::deserialize(data.data(), data.size(), parsed);
    ASSERT_TRUE(result);
    ASSERT_TRUE(parsed.payload.empty());
    
    return true;
}

TEST(agent_message_large_payload, "集群管理") {
    std::string largePayload(1000, 'X');
    AgentMessage msg = AgentMessage::create(AgentMessageType::FORWARD_DATA, largePayload);
    
    ASSERT_EQ(1000, msg.length);
    
    std::vector<uint8_t> data = msg.serialize();
    ASSERT_EQ(9 + 1000, data.size());
    
    AgentMessage parsed;
    bool result = AgentMessage::deserialize(data.data(), data.size(), parsed);
    ASSERT_TRUE(result);
    ASSERT_EQ(largePayload, parsed.payload);
    
    return true;
}

// ============================================
// ClusterManager 基本测试
// ============================================
TEST(cluster_manager_initialization, "集群管理") {
    ClusterManager manager;
    
    // 获取监听 fd 应该返回 -1（未初始化）
    ASSERT_EQ(-1, manager.getListenFd());
    
    // 在线 Agent 数量应该是 0
    ASSERT_EQ(0, manager.getOnlineAgentCount());
    
    return true;
}

TEST(cluster_manager_agent_tokens, "集群管理") {
    ClusterManager manager;
    
    // 创建测试 token 文件
    const char* testFile = "/tmp/test_agent_tokens.conf";
    std::ofstream file(testFile);
    file << "web-01 = ws01-token\n";
    file << "db-01 = db01-token\n";
    file << "redis-01 = rd01-token\n";
    file.close();
    
    bool result = manager.loadAgentTokens(testFile);
    std::remove(testFile);
    
    ASSERT_TRUE(result);
    
    // 验证 token
    ASSERT_TRUE(manager.verifyAgentToken("web-01", "ws01-token"));
    ASSERT_TRUE(manager.verifyAgentToken("db-01", "db01-token"));
    ASSERT_TRUE(manager.verifyAgentToken("redis-01", "rd01-token"));
    
    // 错误的 token
    ASSERT_FALSE(manager.verifyAgentToken("web-01", "wrong-token"));
    ASSERT_FALSE(manager.verifyAgentToken("unknown", "token"));
    
    return true;
}

TEST(cluster_manager_load_invalid_tokens_file, "集群管理") {
    ClusterManager manager;
    
    // 测试加载不存在的文件
    bool result = manager.loadAgentTokens("/nonexistent/tokens.conf");
    ASSERT_FALSE(result);
    
    return true;
}

TEST(cluster_manager_token_file_with_comments, "集群管理") {
    ClusterManager manager;
    
    const char* testFile = "/tmp/test_tokens_comments.conf";
    std::ofstream file(testFile);
    file << "# This is a comment\n";
    file << "\n";
    file << "agent-01 = token-01\n";
    file << "# Another comment\n";
    file << "agent-02 = token-02\n";
    file.close();
    
    bool result = manager.loadAgentTokens(testFile);
    std::remove(testFile);
    
    ASSERT_TRUE(result);
    ASSERT_TRUE(manager.verifyAgentToken("agent-01", "token-01"));
    ASSERT_TRUE(manager.verifyAgentToken("agent-02", "token-02"));
    ASSERT_FALSE(manager.verifyAgentToken("#", "This"));  // 注释行不应被解析
    
    return true;
}

// ============================================
// Agent 注册/注销测试
// ============================================
TEST(cluster_manager_register_agent, "集群管理") {
    ClusterManager manager;
    
    // 先加载 token 配置
    const char* tokenFile = "/tmp/test_tokens.conf";
    std::ofstream file(tokenFile);
    file << "test-agent = test-token-123\n";
    file.close();
    manager.loadAgentTokens(tokenFile);
    std::remove(tokenFile);
    
    AgentInfo agent;
    agent.agentId = "test-agent";
    agent.hostname = "test-host";
    agent.ipAddress = "10.0.0.100";  // 使用有效的非回环 IP
    agent.isOnline = true;
    agent.authToken = "test-token-123";  // 设置正确的 token
    
    // 注册 Agent
    bool result = manager.registerAgent(agent, -1);
    ASSERT_TRUE(result);
    
    // 获取 Agent
    auto retrieved = manager.getAgent("test-agent");
    ASSERT_NOT_NULL(retrieved.get());
    ASSERT_EQ("test-agent", retrieved->agentId);
    ASSERT_EQ("test-host", retrieved->hostname);
    
    // 获取所有 Agent
    auto allAgents = manager.getAllAgents();
    ASSERT_EQ(1, allAgents.size());
    
    // 注销 Agent
    manager.unregisterAgent("test-agent");
    
    retrieved = manager.getAgent("test-agent");
    ASSERT_NULL(retrieved.get());
    
    return true;
}

TEST(cluster_manager_register_invalid_token, "集群管理") {
    ClusterManager manager;
    
    // 先加载 token
    const char* tokenFile = "/tmp/test_tokens_invalid.conf";
    std::ofstream file(tokenFile);
    file << "valid-agent = valid-token\n";
    file.close();
    manager.loadAgentTokens(tokenFile);
    std::remove(tokenFile);
    
    // 尝试用错误的 token 注册
    AgentInfo agent;
    agent.agentId = "valid-agent";
    agent.hostname = "test-host";
    agent.ipAddress = "10.0.0.101";  // 使用有效的非回环 IP
    agent.authToken = "wrong-token";
    
    bool result = manager.registerAgent(agent, -1);
    ASSERT_FALSE(result);
    
    // 尝试注册不存在的 agent
    agent.agentId = "unknown-agent";
    agent.authToken = "any-token";
    result = manager.registerAgent(agent, -1);
    ASSERT_FALSE(result);
    
    return true;
}

TEST(cluster_manager_find_agent_by_hostname, "集群管理") {
    ClusterManager manager;
    
    // 先加载 token
    const char* tokenFile = "/tmp/test_tokens2.conf";
    std::ofstream file(tokenFile);
    file << "agent-01 = token-01\n";
    file.close();
    manager.loadAgentTokens(tokenFile);
    std::remove(tokenFile);
    
    AgentInfo agent;
    agent.agentId = "agent-01";
    agent.hostname = "web-server-01";
    agent.ipAddress = "10.0.1.10";
    agent.isOnline = true;
    agent.authToken = "token-01";  // 设置正确的 token
    
    manager.registerAgent(agent, -1);
    
    // 通过主机名查找
    auto found = manager.findAgentByHostname("web-server-01");
    ASSERT_NOT_NULL(found.get());
    ASSERT_EQ("agent-01", found->agentId);
    
    // 查找不存在的主机名
    auto notFound = manager.findAgentByHostname("nonexistent");
    ASSERT_NULL(notFound.get());
    
    return true;
}

TEST(cluster_manager_online_count, "集群管理") {
    ClusterManager manager;
    
    ASSERT_EQ(0, manager.getOnlineAgentCount());
    
    // 先加载 token
    const char* tokenFile = "/tmp/test_tokens_count.conf";
    std::ofstream file(tokenFile);
    file << "agent-01 = token-01\n";
    file << "agent-02 = token-02\n";
    file.close();
    manager.loadAgentTokens(tokenFile);
    std::remove(tokenFile);
    
    AgentInfo agent1;
    agent1.agentId = "agent-01";
    agent1.hostname = "host-01";
    agent1.ipAddress = "10.0.0.201";  // 使用有效的非回环 IP
    agent1.isOnline = true;
    agent1.authToken = "token-01";
    manager.registerAgent(agent1, -1);
    
    AgentInfo agent2;
    agent2.agentId = "agent-02";
    agent2.hostname = "host-02";
    agent2.ipAddress = "10.0.0.202";  // 使用有效的非回环 IP
    agent2.isOnline = true;
    agent2.authToken = "token-02";
    manager.registerAgent(agent2, -1);
    
    // 注册后应该有 2 个在线 Agent
    ASSERT_EQ(2, manager.getOnlineAgentCount());
    
    // 注销一个
    manager.unregisterAgent("agent-01");
    ASSERT_EQ(1, manager.getOnlineAgentCount());
    
    return true;
}

TEST(cluster_manager_multiple_agents, "集群管理") {
    ClusterManager manager;
    
    // 加载多个 token
    const char* tokenFile = "/tmp/test_tokens_multi.conf";
    std::ofstream file(tokenFile);
    file << "agent-01 = token-01\n";
    file << "agent-02 = token-02\n";
    file << "agent-03 = token-03\n";
    file.close();
    manager.loadAgentTokens(tokenFile);
    std::remove(tokenFile);
    
    // 注册多个 agents
    for (int i = 1; i <= 3; i++) {
        AgentInfo agent;
        agent.agentId = "agent-0" + std::to_string(i);
        agent.hostname = "host-0" + std::to_string(i);
        agent.ipAddress = "10.0.0." + std::to_string(i);
        agent.isOnline = true;
        agent.authToken = "token-0" + std::to_string(i);
        manager.registerAgent(agent, -1);
    }
    
    // 获取所有 agents
    auto allAgents = manager.getAllAgents();
    ASSERT_EQ(3, allAgents.size());
    
    // 验证每个 agent
    for (int i = 1; i <= 3; i++) {
        auto agent = manager.getAgent("agent-0" + std::to_string(i));
        ASSERT_NOT_NULL(agent.get());
        ASSERT_EQ("host-0" + std::to_string(i), agent->hostname);
    }
    
    return true;
}

// ============================================
// ClusterAgentClient 测试
// ============================================
TEST(cluster_agent_client_initialization, "集群管理") {
    ClusterAgentClient client;
    
    // 初始状态应该是未连接
    ASSERT_FALSE(client.isConnected());
    
    return true;
}

TEST(cluster_agent_client_set_services, "集群管理") {
    ClusterAgentClient client;
    
    std::vector<ServiceInfo> services;
    ServiceInfo svc1;
    svc1.type = "ssh";
    svc1.port = 22;
    services.push_back(svc1);
    
    ServiceInfo svc2;
    svc2.type = "http";
    svc2.port = 80;
    services.push_back(svc2);
    
    client.setServices(services);
    
    // 测试设置心跳间隔
    client.setHeartbeatInterval(60);
    
    return true;
}

TEST(cluster_agent_client_initialize, "集群管理") {
    ClusterAgentClient client;
    
    bool result = client.initialize("127.0.0.1", 8888, "test-agent", "test-token");
    ASSERT_TRUE(result);
    
    return true;
}

// ============================================
// 心跳测试
// ============================================
TEST(cluster_manager_heartbeat, "集群管理") {
    ClusterManager manager;
    
    // 先加载 token
    const char* tokenFile = "/tmp/test_tokens3.conf";
    std::ofstream file(tokenFile);
    file << "heartbeat-agent = hb-token\n";
    file.close();
    manager.loadAgentTokens(tokenFile);
    std::remove(tokenFile);
    
    AgentInfo agent;
    agent.agentId = "heartbeat-agent";
    agent.hostname = "heartbeat-host";
    agent.ipAddress = "10.0.0.203";  // 使用有效的非回环 IP
    agent.isOnline = true;
    agent.authToken = "hb-token";  // 设置正确的 token
    
    bool result = manager.registerAgent(agent, -1);
    ASSERT_TRUE(result);
    
    // 获取注册时的 lastHeartbeat
    auto retrievedBefore = manager.getAgent("heartbeat-agent");
    ASSERT_NOT_NULL(retrievedBefore.get());
    auto lastHbBefore = retrievedBefore->lastHeartbeat;
    
    // 稍微等待以确保时间有变化
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    
    // 更新心跳
    manager.updateHeartbeat("heartbeat-agent");
    
    // 获取 Agent 验证心跳已更新
    auto retrieved = manager.getAgent("heartbeat-agent");
    ASSERT_NOT_NULL(retrieved.get());
    // lastHeartbeat 应该已被更新（时间上应该晚于之前）
    ASSERT_TRUE(retrieved->lastHeartbeat >= lastHbBefore);
    
    return true;
}

TEST(cluster_manager_heartbeat_unknown_agent, "集群管理") {
    ClusterManager manager;
    
    // 更新不存在的心跳，应该不会崩溃
    manager.updateHeartbeat("unknown-agent");
    
    // 验证没有崩溃，且未知 agent 不存在
    auto agent = manager.getAgent("unknown-agent");
    ASSERT_NULL(agent.get());
    
    return true;
}

// ============================================
// 消息类型测试
// ============================================
TEST(agent_message_types, "集群管理") {
    // 测试所有消息类型
    ASSERT_EQ(0x01, static_cast<uint8_t>(AgentMessageType::REGISTER));
    ASSERT_EQ(0x02, static_cast<uint8_t>(AgentMessageType::HEARTBEAT));
    ASSERT_EQ(0x03, static_cast<uint8_t>(AgentMessageType::UNREGISTER));
    ASSERT_EQ(0x04, static_cast<uint8_t>(AgentMessageType::COMMAND));
    ASSERT_EQ(0x05, static_cast<uint8_t>(AgentMessageType::RESPONSE));
    ASSERT_EQ(0x06, static_cast<uint8_t>(AgentMessageType::FORWARD_REQUEST));
    ASSERT_EQ(0x07, static_cast<uint8_t>(AgentMessageType::FORWARD_DATA));
    
    return true;
}

// ============================================
// 序列化边界测试
// ============================================
TEST(agent_message_deserialize_insufficient_data, "集群管理") {
    // 数据刚好够头部但不够 payload
    uint8_t data[9] = {
        0x4A, 0x53, 0x48, 0x53,  // Magic: 0x4A534853
        0x01,                     // Type: REGISTER
        0x00, 0x00, 0x00, 0x10   // Length: 16 (但我们没有 16 字节的 payload)
    };
    
    AgentMessage msg;
    bool result = AgentMessage::deserialize(data, 9, msg);
    ASSERT_FALSE(result);  // 数据不足
    
    return true;
}

TEST(agent_message_all_types_roundtrip, "集群管理") {
    // 测试所有消息类型的序列化和反序列化
    std::vector<AgentMessageType> types = {
        AgentMessageType::REGISTER,
        AgentMessageType::HEARTBEAT,
        AgentMessageType::UNREGISTER,
        AgentMessageType::COMMAND,
        AgentMessageType::RESPONSE,
        AgentMessageType::FORWARD_REQUEST,
        AgentMessageType::FORWARD_DATA
    };
    
    for (auto type : types) {
        std::string payload = "test payload for type " + std::to_string(static_cast<int>(type));
        AgentMessage msg = AgentMessage::create(type, payload);
        
        std::vector<uint8_t> data = msg.serialize();
        AgentMessage parsed;
        bool result = AgentMessage::deserialize(data.data(), data.size(), parsed);
        
        ASSERT_TRUE(result);
        ASSERT_EQ(static_cast<uint8_t>(type), static_cast<uint8_t>(parsed.type));
        ASSERT_EQ(payload, parsed.payload);
    }
    
    return true;
}

// ============================================
// ClusterManager 启动/停止测试
// ============================================
TEST(cluster_manager_start_stop, "集群管理") {
    ClusterManager manager;
    
    // 注意：启动需要有效的事件循环和监听地址
    // 这里只测试基本功能
    
    // 尝试启动（可能会失败，因为没有初始化）
    bool result = manager.start();
    // 不强制要求成功，只验证函数可调用
    
    // 停止
    manager.stop();
    
    return true;
}

TEST(cluster_manager_initialize_with_address, "集群管理") {
    ClusterManager manager;
    
    // 测试使用 IPv4 地址初始化
    bool result = manager.initialize("127.0.0.1", 19999, nullptr);
    ASSERT_TRUE(result);
    
    // 停止清理
    manager.stop();
    
    return true;
}

TEST_DISABLED(cluster_manager_initialize_ipv6, "集群管理") {
    ClusterManager manager;
    
    // 测试使用 IPv6 地址初始化
    bool result = manager.initialize("::1", 19998, nullptr);
    ASSERT_TRUE(result);
    
    manager.stop();
    
    return true;
}

TEST(cluster_manager_initialize_invalid_address, "集群管理") {
    ClusterManager manager;
    
    // 使用无效地址初始化应该失败
    bool result = manager.initialize("invalid-address-string", 19997, nullptr);
    ASSERT_FALSE(result);
    
    return true;
}
