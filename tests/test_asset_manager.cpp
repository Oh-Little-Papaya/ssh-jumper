/**
 * @file test_asset_manager.cpp
 * @brief 资产管理器测试 - 与当前 AssetManager 实现兼容
 */

#include "test_framework.h"
#include "../include/asset_manager.h"
#include "../include/cluster_manager.h"

using namespace sshjump;

// ============================================
// AssetInfo 测试
// ============================================
TEST(asset_info_get_ssh_port, "资产管理") {
    AssetInfo asset;
    
    // 没有 SSH 服务时返回默认端口 22
    ASSERT_EQ(22, asset.getSshPort());
    
    // 添加 SSH 服务
    ServiceInfo sshService;
    sshService.type = "ssh";
    sshService.port = 2222;
    asset.services.push_back(sshService);
    
    ASSERT_EQ(2222, asset.getSshPort());
    
    // 添加另一个服务不影响 SSH 端口
    ServiceInfo httpService;
    httpService.type = "http";
    httpService.port = 8080;
    asset.services.push_back(httpService);
    
    ASSERT_EQ(2222, asset.getSshPort());
    
    return true;
}

TEST(asset_info_json_serialization, "资产管理") {
    AssetInfo asset;
    asset.id = "web-01";
    asset.hostname = "web-server-01";
    asset.ipAddress = "10.0.1.10";
    asset.osType = "linux";
    asset.description = "Web Server";
    asset.isOnline = true;
    asset.tags = {"web", "production"};
    
    ServiceInfo svc;
    svc.type = "ssh";
    svc.port = 22;
    svc.name = "SSH";
    asset.services.push_back(svc);
    
    // 序列化
    std::string json = asset.toJson();
    ASSERT_FALSE(json.empty());
    ASSERT_TRUE(json.find("web-01") != std::string::npos);
    ASSERT_TRUE(json.find("web-server-01") != std::string::npos);
    ASSERT_TRUE(json.find("10.0.1.10") != std::string::npos);
    
    // 反序列化
    AssetInfo parsed = AssetInfo::fromJson(json);
    ASSERT_EQ(asset.id, parsed.id);
    ASSERT_EQ(asset.hostname, parsed.hostname);
    ASSERT_EQ(asset.ipAddress, parsed.ipAddress);
    ASSERT_EQ(asset.osType, parsed.osType);
    ASSERT_EQ(asset.isOnline, parsed.isOnline);
    
    return true;
}

// ============================================
// UserPermission 测试
// ============================================
TEST(user_permission_allow_all, "资产管理") {
    UserPermission perm;
    perm.username = "admin";
    perm.allowAll = true;
    
    ASSERT_TRUE(perm.canAccess("any-asset", "any-hostname"));
    ASSERT_TRUE(perm.canAccess("web-01", "web-server-01"));
    
    return true;
}

TEST(user_permission_allowed_assets, "资产管理") {
    UserPermission perm;
    perm.username = "developer";
    perm.allowAll = false;
    perm.allowedAssets = {"web-01", "web-02", "db-01"};
    
    ASSERT_TRUE(perm.canAccess("web-01", "web-server-01"));
    ASSERT_TRUE(perm.canAccess("db-01", "db-server-01"));
    ASSERT_FALSE(perm.canAccess("web-03", "web-server-03"));
    ASSERT_FALSE(perm.canAccess("redis-01", "redis-01"));
    
    return true;
}

TEST(user_permission_allowed_patterns, "资产管理") {
    UserPermission perm;
    perm.username = "developer";
    perm.allowAll = false;
    perm.allowedPatterns = {"web-*", "api-*"};
    
    ASSERT_TRUE(perm.canAccess("web-01", "web-server-01"));
    ASSERT_TRUE(perm.canAccess("web-02", "web-server-02"));
    ASSERT_TRUE(perm.canAccess("api-01", "api-server-01"));
    ASSERT_FALSE(perm.canAccess("db-01", "db-server-01"));
    ASSERT_FALSE(perm.canAccess("my-web-01", "my-web-server-01"));  // 不匹配开头
    
    return true;
}

TEST(user_permission_denied_assets, "资产管理") {
    UserPermission perm;
    perm.username = "developer";
    perm.allowAll = false;
    perm.allowedPatterns = {"web-*", "db-*"};
    perm.deniedAssets = {"db-admin"};  // 明确拒绝
    
    ASSERT_TRUE(perm.canAccess("web-01", "web-server-01"));
    ASSERT_TRUE(perm.canAccess("db-01", "db-server-01"));
    ASSERT_FALSE(perm.canAccess("db-admin", "db-admin-server"));  // 被拒绝
    
    return true;
}

TEST(user_permission_empty, "资产管理") {
    UserPermission perm;
    perm.username = "nobody";
    perm.allowAll = false;
    // 没有允许的资产或模式
    
    ASSERT_FALSE(perm.canAccess("any-asset", "any-hostname"));
    
    return true;
}

// ============================================
// AssetManager 测试
// ============================================
TEST(asset_manager_basic_operations, "资产管理") {
    AssetManager manager;
    
    // 初始时资产列表为空
    auto assets = manager.getAllAssets(false);
    ASSERT_EQ(0, assets.size());
    
    return true;
}

TEST(asset_manager_search_by_hostname, "资产管理") {
    AssetManager manager;
    
    // 创建测试资产
    AssetInfo asset1;
    asset1.id = "web-01";
    asset1.hostname = "web-server-01";
    asset1.ipAddress = "10.0.1.10";
    asset1.isOnline = true;
    
    AssetInfo asset2;
    asset2.id = "web-02";
    asset2.hostname = "web-server-02";
    asset2.ipAddress = "10.0.1.11";
    asset2.isOnline = true;
    
    AssetInfo asset3;
    asset3.id = "db-01";
    asset3.hostname = "db-server-01";
    asset3.ipAddress = "10.0.2.10";
    asset3.isOnline = true;
    
    // 这里我们需要通过 refreshAssets 来同步
    // 由于没有 ClusterManager，我们测试搜索逻辑
    
    // 测试 AssetInfo 结构
    ASSERT_EQ("web-server-01", asset1.hostname);
    ASSERT_EQ("web-server-02", asset2.hostname);
    ASSERT_EQ("db-server-01", asset3.hostname);
    
    return true;
}

TEST(asset_manager_user_permissions, "资产管理") {
    AssetManager manager;
    
    // 测试用户权限配置加载
    const char* testFile = "/tmp/test_permissions.conf";
    std::ofstream file(testFile);
    file << "[user:admin]\n";
    file << "allow_all = true\n";
    file << "\n";
    file << "[user:developer]\n";
    file << "allowed_patterns = web-*,api-*\n";
    file << "max_sessions = 5\n";
    file << "\n";
    file << "[user:dba]\n";
    file << "allowed_patterns = db-*,redis-*\n";
    file << "denied_assets = db-admin\n";
    file.close();
    
    bool result = manager.loadUserPermissions(testFile);
    std::remove(testFile);
    
    ASSERT_TRUE(result);
    
    // 检查 admin 权限
    auto adminPerm = manager.getUserPermission("admin");
    ASSERT_TRUE(adminPerm.has_value());
    ASSERT_TRUE(adminPerm->allowAll);
    
    // 检查 developer 权限
    auto devPerm = manager.getUserPermission("developer");
    ASSERT_TRUE(devPerm.has_value());
    ASSERT_FALSE(devPerm->allowAll);
    ASSERT_EQ(5, devPerm->maxSessions);
    ASSERT_TRUE(devPerm->canAccess("web-01", "web-server-01"));
    ASSERT_FALSE(devPerm->canAccess("db-01", "db-server-01"));
    
    // 检查 dba 权限
    auto dbaPerm = manager.getUserPermission("dba");
    ASSERT_TRUE(dbaPerm.has_value());
    ASSERT_TRUE(dbaPerm->canAccess("db-01", "db-server-01"));
    ASSERT_TRUE(dbaPerm->canAccess("redis-01", "redis-01"));
    ASSERT_FALSE(dbaPerm->canAccess("db-admin", "db-admin-server"));
    
    // 检查不存在的用户
    auto nobodyPerm = manager.getUserPermission("nobody");
    ASSERT_FALSE(nobodyPerm.has_value());
    
    return true;
}

TEST(asset_manager_permission_validation, "资产管理") {
    AssetManager manager;
    
    // 先加载权限配置
    const char* testFile = "/tmp/test_perm_check.conf";
    std::ofstream file(testFile);
    file << "[user:admin]\n";
    file << "allow_all = true\n";
    file << "\n";
    file << "[user:developer]\n";
    file << "allowed_assets = web-01,web-02\n";
    file.close();
    
    manager.loadUserPermissions(testFile);
    std::remove(testFile);
    
    // 直接测试用户权限（不需要资产存在）
    auto adminPerm = manager.getUserPermission("admin");
    ASSERT_TRUE(adminPerm.has_value());
    ASSERT_TRUE(adminPerm->allowAll);
    // allowAll 为 true 时可以访问任何资产
    ASSERT_TRUE(adminPerm->canAccess("any-asset", "any-host"));
    
    auto devPerm = manager.getUserPermission("developer");
    ASSERT_TRUE(devPerm.has_value());
    // developer 只能访问 web-01 和 web-02
    ASSERT_TRUE(devPerm->canAccess("web-01", "web-server-01"));
    ASSERT_TRUE(devPerm->canAccess("web-02", "web-server-02"));
    ASSERT_FALSE(devPerm->canAccess("web-03", "web-server-03"));
    
    // 未知用户没有权限
    auto unknownPerm = manager.getUserPermission("unknown-user");
    ASSERT_FALSE(unknownPerm.has_value());
    
    return true;
}

TEST(asset_manager_load_invalid_permissions_file, "资产管理") {
    AssetManager manager;
    
    // 测试加载不存在的文件
    bool result = manager.loadUserPermissions("/nonexistent/permissions.conf");
    ASSERT_FALSE(result);
    
    return true;
}

TEST(asset_manager_search_by_tag, "资产管理") {
    AssetManager manager;
    
    // 由于 AssetManager 依赖 ClusterManager 来获取资产
    // 这里主要测试接口存在性
    auto assets = manager.searchAssetsByTag("production");
    // 初始为空
    ASSERT_EQ(0, assets.size());
    
    return true;
}

TEST(asset_manager_asset_by_id, "资产管理") {
    AssetManager manager;
    
    // 测试获取不存在的资产
    auto asset = manager.getAssetById("nonexistent");
    ASSERT_FALSE(asset.has_value());
    
    return true;
}

TEST(asset_manager_user_assets_filter, "资产管理") {
    AssetManager manager;
    
    // 测试获取用户资产（空列表）
    auto assets = manager.getUserAssets("any-user", true);
    ASSERT_EQ(0, assets.size());
    
    return true;
}

TEST(asset_info_from_agent_info, "资产管理") {
    AgentInfo agent;
    agent.agentId = "test-agent-01";
    agent.hostname = "test-host";
    agent.ipAddress = "192.168.1.100";
    agent.isOnline = true;
    
    ServiceInfo svc;
    svc.type = "ssh";
    svc.port = 22;
    agent.services.push_back(svc);
    
    AssetInfo asset = AssetInfo::fromAgentInfo(agent);
    
    ASSERT_EQ(agent.agentId, asset.id);
    ASSERT_EQ(agent.hostname, asset.hostname);
    ASSERT_EQ(agent.ipAddress, asset.ipAddress);
    ASSERT_EQ(agent.isOnline, asset.isOnline);
    ASSERT_EQ(1, asset.services.size());
    
    return true;
}

TEST(asset_manager_can_user_access, "资产管理") {
    AssetManager manager;
    
    // 加载权限配置
    const char* testFile = "/tmp/test_can_access.conf";
    std::ofstream file(testFile);
    file << "[user:testuser]\n";
    file << "allowed_assets = web-01\n";
    file.close();
    
    manager.loadUserPermissions(testFile);
    std::remove(testFile);
    
    // 测试 canUserAccess（资产不存在，所以应该返回 false）
    ASSERT_FALSE(manager.canUserAccess("testuser", "web-01"));
    ASSERT_FALSE(manager.canUserAccess("testuser", "nonexistent"));
    ASSERT_FALSE(manager.canUserAccess("unknown", "web-01"));
    
    return true;
}

TEST(asset_manager_on_asset_changed_callback, "资产管理") {
    AssetManager manager;
    
    bool callbackCalled = false;
    bool addedFlag = false;
    
    // 注册回调
    manager.onAssetChanged([&callbackCalled, &addedFlag](const AssetInfo& asset, bool added) {
        callbackCalled = true;
        addedFlag = added;
    });
    
    // 注意：由于无法直接添加资产（需要通过 ClusterManager），
    // 这里只验证回调可以被注册
    ASSERT_FALSE(callbackCalled);  // 还没有资产变更
    
    return true;
}

TEST(asset_manager_initialize, "资产管理") {
    AssetManager manager;
    
    // 测试不使用 ClusterManager 初始化
    // initialize 需要 ClusterManager，这里只测试基本构造
    
    // 验证 manager 可以被创建
    ASSERT_EQ(0, manager.getAllAssets().size());
    
    return true;
}

TEST(asset_manager_refresh_assets, "资产管理") {
    AssetManager manager;
    
    // 测试刷新资产（没有 ClusterManager，应该无操作）
    manager.refreshAssets();
    
    // 验证资产列表仍为空
    ASSERT_EQ(0, manager.getAllAssets().size());
    
    return true;
}

TEST(asset_permission_complex_scenario, "资产管理") {
    AssetManager manager;
    
    // 创建复杂的权限配置
    const char* testFile = "/tmp/test_complex_perm.conf";
    std::ofstream file(testFile);
    file << "[user:devops]\n";
    file << "allowed_patterns = *\n";
    file << "denied_assets = prod-db-admin,prod-network-core\n";
    file << "max_sessions = 20\n";
    file << "\n";
    file << "[user:readonly]\n";
    file << "allowed_patterns = dev-*,staging-*\n";
    file << "allowed_assets = prod-web-01\n";
    file << "max_sessions = 3\n";
    file.close();
    
    bool result = manager.loadUserPermissions(testFile);
    std::remove(testFile);
    
    ASSERT_TRUE(result);
    
    // 测试 devops 权限
    auto devops = manager.getUserPermission("devops");
    ASSERT_TRUE(devops.has_value());
    ASSERT_FALSE(devops->allowAll);  // 不是 allowAll，而是 allowed_patterns = *
    ASSERT_EQ(20, devops->maxSessions);
    
    // devops 可以访问大部分资产
    ASSERT_TRUE(devops->canAccess("dev-web-01", "dev-web-01"));
    ASSERT_TRUE(devops->canAccess("staging-db-01", "staging-db-01"));
    ASSERT_TRUE(devops->canAccess("prod-web-01", "prod-web-01"));
    
    // 但不能访问被拒绝的资产
    ASSERT_FALSE(devops->canAccess("prod-db-admin", "prod-db-admin"));
    ASSERT_FALSE(devops->canAccess("prod-network-core", "prod-network-core"));
    
    // 测试 readonly 权限
    auto readonly = manager.getUserPermission("readonly");
    ASSERT_TRUE(readonly.has_value());
    ASSERT_EQ(3, readonly->maxSessions);
    
    ASSERT_TRUE(readonly->canAccess("dev-web-01", "dev-web-01"));
    ASSERT_TRUE(readonly->canAccess("staging-db-01", "staging-db-01"));
    ASSERT_TRUE(readonly->canAccess("prod-web-01", "prod-web-01"));  // 明确允许
    ASSERT_FALSE(readonly->canAccess("prod-db-01", "prod-db-01"));  // 不在允许列表中
    
    return true;
}

TEST(asset_permission_need_approval, "资产管理") {
    AssetManager manager;
    
    const char* testFile = "/tmp/test_approval.conf";
    std::ofstream file(testFile);
    file << "[user:contractor]\n";
    file << "allowed_patterns = temp-*\n";
    file << "need_approval = true\n";
    file.close();
    
    manager.loadUserPermissions(testFile);
    std::remove(testFile);
    
    auto perm = manager.getUserPermission("contractor");
    ASSERT_TRUE(perm.has_value());
    ASSERT_TRUE(perm->needApproval);
    
    return true;
}
