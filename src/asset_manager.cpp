/**
 * @file asset_manager.cpp
 * @brief 资产管理器实现
 */

#include "asset_manager.h"
#include <algorithm>
#include <fnmatch.h>

namespace sshjump {

// ============================================
// AssetInfo 实现
// ============================================

std::string AssetInfo::toJson() const {
    // 简化的 JSON 序列化
    std::string json = "{";
    json += "\"id\":\"" + id + "\",";
    json += "\"hostname\":\"" + hostname + "\",";
    json += "\"ipAddress\":\"" + ipAddress + "\",";
    json += "\"osType\":\"" + osType + "\",";
    json += "\"description\":\"" + description + "\",";
    json += "\"isOnline\":" + std::string(isOnline ? "true" : "false");
    json += "}";
    return json;
}

AssetInfo AssetInfo::fromJson(const std::string& json) {
    AssetInfo info;
    // 简化的 JSON 解析 - 提取字符串值
    auto extractString = [&json](const std::string& key) -> std::string {
        std::string searchKey = "\"" + key + "\":\"";
        size_t pos = json.find(searchKey);
        if (pos == std::string::npos) return "";
        pos += searchKey.length();
        size_t endPos = json.find("\"", pos);
        if (endPos == std::string::npos) return "";
        return json.substr(pos, endPos - pos);
    };
    
    info.id = extractString("id");
    info.hostname = extractString("hostname");
    info.ipAddress = extractString("ipAddress");
    info.osType = extractString("osType");
    info.description = extractString("description");
    
    // 解析 isOnline
    size_t onlinePos = json.find("\"isOnline\":");
    if (onlinePos != std::string::npos) {
        onlinePos += 11;  // length of "isOnline":
        info.isOnline = (json.substr(onlinePos, 4) == "true");
    }
    
    return info;
}

AssetInfo AssetInfo::fromAgentInfo(const AgentInfo& agent) {
    AssetInfo asset;
    asset.id = agent.agentId;
    asset.hostname = agent.hostname;
    asset.ipAddress = agent.ipAddress;
    asset.services = agent.services;
    asset.isOnline = agent.isOnline;
    // 可以从 metadata 中提取更多信息
    return asset;
}

// ============================================
// UserPermission 实现
// ============================================

bool UserPermission::canAccess(const std::string& assetId, const std::string& hostname) const {
    // 检查是否被拒绝
    if (std::find(deniedAssets.begin(), deniedAssets.end(), assetId) != deniedAssets.end()) {
        return false;
    }
    
    // 检查是否允许所有
    if (allowAll) {
        return true;
    }
    
    // 检查是否在允许列表中
    if (std::find(allowedAssets.begin(), allowedAssets.end(), assetId) != allowedAssets.end()) {
        return true;
    }
    
    // 检查模式匹配
    for (const auto& pattern : allowedPatterns) {
        if (fnmatch(pattern.c_str(), hostname.c_str(), 0) == 0) {
            return true;
        }
    }
    
    return false;
}

// ============================================
// AssetManager 实现
// ============================================

AssetManager::AssetManager()
    : refreshTimer_(std::make_unique<TimerThread>()) {
}

AssetManager::~AssetManager() {
    if (refreshTimer_) {
        refreshTimer_->stop();
    }
}

bool AssetManager::initialize(std::shared_ptr<ClusterManager> clusterManager) {
    clusterManager_ = clusterManager;
    
    // 立即同步一次
    syncFromCluster();
    
    // 启动定时刷新 (每 5 秒，便于快速同步 Agent 变化)
    refreshTimer_->start();
    refreshTimer_->scheduleRepeat(std::chrono::seconds(5), [this]() {
        this->refreshAssets();
    });
    
    LOG_INFO("AssetManager initialized with " + std::to_string(assets_.size()) + " assets");
    return true;
}

std::vector<AssetInfo> AssetManager::getAllAssets(bool onlineOnly) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    
    std::vector<AssetInfo> result;
    for (const auto& pair : assets_) {
        if (!onlineOnly || pair.second.isOnline) {
            result.push_back(pair.second);
        }
    }
    
    // 按主机名排序
    std::sort(result.begin(), result.end(), 
              [](const AssetInfo& a, const AssetInfo& b) {
                  return a.hostname < b.hostname;
              });
    
    return result;
}

std::vector<AssetInfo> AssetManager::getUserAssets(const std::string& username, bool onlineOnly) {
    auto allAssets = getAllAssets(onlineOnly);

    // 检查用户权限
    auto perm = getUserPermission(username);
    if (!perm) {
        // 没有配置权限，默认拒绝访问所有资产（安全策略）
        LOG_WARN("User " + username + " has no permission configured, denying access to all assets");
        return {};
    }

    // 过滤有权限访问的资产
    std::vector<AssetInfo> result;
    for (const auto& asset : allAssets) {
        if (perm->canAccess(asset.id, asset.hostname)) {
            result.push_back(asset);
        }
    }

    return result;
}

std::optional<AssetInfo> AssetManager::getAssetById(const std::string& id) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    
    auto it = assets_.find(id);
    if (it != assets_.end()) {
        return it->second;
    }
    
    return std::nullopt;
}

std::vector<AssetInfo> AssetManager::searchAssetsByHostname(const std::string& pattern) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    
    std::vector<AssetInfo> result;
    std::string lowerPattern = pattern;
    std::transform(lowerPattern.begin(), lowerPattern.end(), lowerPattern.begin(), ::tolower);
    
    for (const auto& pair : assets_) {
        std::string lowerHostname = pair.second.hostname;
        std::transform(lowerHostname.begin(), lowerHostname.end(), lowerHostname.begin(), ::tolower);
        
        if (lowerHostname.find(lowerPattern) != std::string::npos) {
            result.push_back(pair.second);
        }
    }
    
    return result;
}

std::vector<AssetInfo> AssetManager::searchAssetsByTag(const std::string& tag) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    
    std::vector<AssetInfo> result;
    
    for (const auto& pair : assets_) {
        for (const auto& assetTag : pair.second.tags) {
            if (assetTag == tag) {
                result.push_back(pair.second);
                break;
            }
        }
    }
    
    return result;
}

void AssetManager::refreshAssets() {
    syncFromCluster();
}

void AssetManager::syncFromCluster() {
    if (!clusterManager_) {
        return;
    }
    
    std::unique_lock<std::shared_mutex> lock(mutex_);
    
    // 获取所有在线 Agent
    auto agents = clusterManager_->getAllAgents();
    
    // 更新资产列表
    std::set<std::string> currentIds;
    for (const auto& agent : agents) {
        if (!agent) continue;
        
        currentIds.insert(agent->agentId);
        
        auto it = assets_.find(agent->agentId);
        if (it == assets_.end()) {
            // 新资产
            AssetInfo asset = AssetInfo::fromAgentInfo(*agent);
            assets_[agent->agentId] = asset;
            
            // 触发新增回调
            for (auto& callback : changeCallbacks_) {
                callback(asset, true);
            }
        } else {
            // 更新现有资产
            it->second.hostname = agent->hostname;
            it->second.ipAddress = agent->ipAddress;
            it->second.services = agent->services;
            it->second.isOnline = agent->isOnline;
        }
    }
    
    // 移除离线的资产
    for (auto it = assets_.begin(); it != assets_.end();) {
        if (currentIds.find(it->first) == currentIds.end()) {
            // 资产离线
            it->second.isOnline = false;
            
            // 触发移除回调
            for (auto& callback : changeCallbacks_) {
                callback(it->second, false);
            }
            ++it;
        } else {
            ++it;
        }
    }
}

bool AssetManager::loadUserPermissions(const std::string& configPath) {
    // 从配置文件加载用户权限
    // 配置文件格式示例:
    // [user:admin]
    // allow_all = true
    // 
    // [user:developer]
    // allowed_assets = web-01,web-02,db-01
    // allowed_patterns = web-*,api-*
    // denied_assets = db-admin
    
    std::ifstream file(configPath);
    if (!file.is_open()) {
        LOG_WARN("Failed to open user permissions file: " + configPath);
        return false;
    }
    
    std::string line;
    std::string currentUser;
    UserPermission currentPerm;
    
    while (std::getline(file, line)) {
        line = trimString(line);
        
        if (line.empty() || line[0] == '#') {
            continue;
        }
        
        // 解析 [user:username] 节
        if (line[0] == '[' && line[line.size() - 1] == ']') {
            // 保存上一个用户的配置
            if (!currentUser.empty()) {
                currentPerm.username = currentUser;
                userPermissions_[currentUser] = currentPerm;
                currentPerm = UserPermission();  // 重置
            }
            
            // 提取用户名
            size_t pos = line.find(':');
            if (pos != std::string::npos && line.substr(1, pos - 1) == "user") {
                currentUser = line.substr(pos + 1, line.size() - pos - 2);
            }
            continue;
        }
        
        // 解析键值对
        size_t pos = line.find('=');
        if (pos == std::string::npos) continue;
        
        std::string key = trimString(line.substr(0, pos));
        std::string value = trimString(line.substr(pos + 1));
        
        if (key == "allow_all") {
            currentPerm.allowAll = (value == "true" || value == "1");
        } else if (key == "allowed_assets") {
            auto assets = splitString(value, ',');
            for (auto& asset : assets) {
                currentPerm.allowedAssets.push_back(trimString(asset));
            }
        } else if (key == "allowed_patterns") {
            auto patterns = splitString(value, ',');
            for (auto& pattern : patterns) {
                currentPerm.allowedPatterns.push_back(trimString(pattern));
            }
        } else if (key == "denied_assets") {
            auto assets = splitString(value, ',');
            for (auto& asset : assets) {
                currentPerm.deniedAssets.push_back(trimString(asset));
            }
        } else if (key == "max_sessions") {
            currentPerm.maxSessions = std::stoi(value);
        } else if (key == "need_approval") {
            currentPerm.needApproval = (value == "true" || value == "1");
        }
    }
    
    // 保存最后一个用户的配置
    if (!currentUser.empty()) {
        currentPerm.username = currentUser;
        userPermissions_[currentUser] = currentPerm;
    }
    
    file.close();
    
    LOG_INFO("Loaded permissions for " + std::to_string(userPermissions_.size()) + " users");
    return true;
}

void AssetManager::upsertUserPermission(const UserPermission& permission) {
    if (permission.username.empty()) {
        return;
    }

    std::unique_lock<std::shared_mutex> lock(mutex_);
    userPermissions_[permission.username] = permission;
}

std::optional<UserPermission> AssetManager::getUserPermission(const std::string& username) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    
    auto it = userPermissions_.find(username);
    if (it != userPermissions_.end()) {
        return it->second;
    }
    
    // 如果没有找到配置，返回默认权限 (拒绝所有)
    return std::nullopt;
}

bool AssetManager::canUserAccess(const std::string& username, const std::string& assetId) {
    auto perm = getUserPermission(username);
    if (!perm) {
        return false;
    }
    
    auto asset = getAssetById(assetId);
    if (!asset) {
        return false;
    }
    
    return perm->canAccess(assetId, asset->hostname);
}

void AssetManager::onAssetChanged(std::function<void(const AssetInfo&, bool added)> callback) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    changeCallbacks_.push_back(callback);
}

} // namespace sshjump
