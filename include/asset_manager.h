/**
 * @file asset_manager.h
 * @brief 资产管理器 - 维护可访问的主机资产列表
 */

#ifndef SSH_JUMP_ASSET_MANAGER_H
#define SSH_JUMP_ASSET_MANAGER_H

#include "common.h"
#include "cluster_manager.h"

namespace sshjump {

// ============================================
// 资产信息
// ============================================
struct AssetInfo {
    std::string id;                 // 资产ID (通常是 agentId)
    std::string hostname;           // 主机名
    std::string ipAddress;          // IP地址
    std::string osType;             // 操作系统类型
    std::vector<ServiceInfo> services;  // 提供的服务
    std::string description;        // 描述
    std::vector<std::string> tags;  // 标签
    bool isOnline = false;          // 是否在线
    
    // 获取 SSH 服务端口
    int getSshPort() const {
        for (const auto& svc : services) {
            if (svc.type == "ssh") {
                return svc.port;
            }
        }
        return 22;  // 默认 SSH 端口
    }
    
    // 序列化为 JSON
    std::string toJson() const;
    
    // 从 JSON 解析
    static AssetInfo fromJson(const std::string& json);
    
    // 从 AgentInfo 转换
    static AssetInfo fromAgentInfo(const AgentInfo& agent);
};

// ============================================
// 用户权限
// ============================================
struct UserPermission {
    std::string username;
    std::vector<std::string> allowedAssets;     // 允许访问的资产ID列表
    std::vector<std::string> allowedPatterns;   // 允许的主机名模式 (通配符)
    std::vector<std::string> deniedAssets;      // 明确拒绝的资产
    bool allowAll = false;                      // 是否允许访问所有
    int maxSessions = 10;                       // 最大并发会话数
    bool needApproval = false;                  // 是否需要审批
    
    // 检查是否允许访问指定资产
    bool canAccess(const std::string& assetId, const std::string& hostname) const;
};

// ============================================
// 资产管理器
// ============================================
class AssetManager : public std::enable_shared_from_this<AssetManager> {
public:
    AssetManager();
    ~AssetManager();
    
    // 初始化
    bool initialize(std::shared_ptr<ClusterManager> clusterManager);
    
    // 设置集群管理器
    void setClusterManager(std::shared_ptr<ClusterManager> cm) { clusterManager_ = cm; }
    
    // 获取所有资产 (仅在线)
    std::vector<AssetInfo> getAllAssets(bool onlineOnly = true);
    
    // 根据用户权限获取可访问资产
    std::vector<AssetInfo> getUserAssets(const std::string& username, bool onlineOnly = true);
    
    // 根据ID获取资产
    std::optional<AssetInfo> getAssetById(const std::string& id);
    
    // 根据主机名搜索资产
    std::vector<AssetInfo> searchAssetsByHostname(const std::string& pattern);
    
    // 根据标签搜索资产
    std::vector<AssetInfo> searchAssetsByTag(const std::string& tag);
    
    // 刷新资产列表 (从 ClusterManager 同步)
    void refreshAssets();
    
    // 加载用户权限配置
    bool loadUserPermissions(const std::string& configPath);
    
    // 获取用户权限
    std::optional<UserPermission> getUserPermission(const std::string& username);
    
    // 检查用户是否可以访问资产
    bool canUserAccess(const std::string& username, const std::string& assetId);
    
    // 注册资产变更回调
    void onAssetChanged(std::function<void(const AssetInfo&, bool added)> callback);
    
private:
    // 从 ClusterManager 同步资产
    void syncFromCluster();
    
    // 集群管理器
    std::shared_ptr<ClusterManager> clusterManager_;
    
    // 资产映射
    std::unordered_map<std::string, AssetInfo> assets_;
    
    // 用户权限映射
    std::unordered_map<std::string, UserPermission> userPermissions_;
    
    // 变更回调
    std::vector<std::function<void(const AssetInfo&, bool added)>> changeCallbacks_;
    
    // 互斥锁
    mutable std::shared_mutex mutex_;
    
    // 刷新定时器
    std::unique_ptr<TimerThread> refreshTimer_;
};

} // namespace sshjump

#endif // SSH_JUMP_ASSET_MANAGER_H
