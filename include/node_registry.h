/**
 * @file node_registry.h
 * @brief 子节点注册表（公网管理节点用于管理下级跳板节点）
 */

#ifndef SSH_JUMP_NODE_REGISTRY_H
#define SSH_JUMP_NODE_REGISTRY_H

#include "common.h"

#ifdef SSHJUMP_USE_FOLLY
#include <folly/container/F14Map.h>
#endif

namespace sshjump {

// ============================================
// 子节点信息
// ============================================
struct ChildNodeInfo {
    std::string nodeId;          // 子节点唯一 ID
    std::string name;            // 展示名称
    std::string publicAddress;   // 公网地址/IP
    int sshPort{DEFAULT_SSH_PORT};
    int clusterPort{DEFAULT_CLUSTER_PORT};
    std::string description;     // 描述
    bool enabled{true};
    std::map<std::string, std::string> metadata;
    std::chrono::system_clock::time_point createdAt;
    std::chrono::system_clock::time_point updatedAt;

    bool isValid() const {
        return !nodeId.empty() && !publicAddress.empty() &&
               sshPort > 0 && sshPort <= 65535 &&
               clusterPort > 0 && clusterPort <= 65535;
    }
};

#ifdef SSHJUMP_USE_FOLLY
template <typename K, typename V>
using NodeMap = folly::F14FastMap<K, V>;
#else
template <typename K, typename V>
using NodeMap = std::unordered_map<K, V>;
#endif

// ============================================
// 子节点注册表
// ============================================
class ChildNodeRegistry : public NonCopyable {
public:
    ChildNodeRegistry() = default;
    ~ChildNodeRegistry() = default;

    // 加载/保存子节点配置文件
    bool loadFromFile(const std::string& path);
    bool saveToFile(const std::string& path) const;

    // CRUD
    bool createNode(const ChildNodeInfo& node, bool overwrite = false);
    bool updateNode(const std::string& nodeId, const ChildNodeInfo& patch);
    bool deleteNode(const std::string& nodeId);
    std::optional<ChildNodeInfo> getNode(const std::string& nodeId) const;
    std::vector<ChildNodeInfo> listNodes(bool enabledOnly = false) const;

    // 清空（测试辅助）
    void clear();
    size_t size() const;

private:
    static std::string formatTimestamp(const std::chrono::system_clock::time_point& tp);
    static std::chrono::system_clock::time_point parseTimestamp(const std::string& value);
    static void trimNode(ChildNodeInfo& node);

    mutable std::shared_mutex mutex_;
    NodeMap<std::string, ChildNodeInfo> nodes_;
};

} // namespace sshjump

#endif // SSH_JUMP_NODE_REGISTRY_H

