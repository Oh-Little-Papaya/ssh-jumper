/**
 * @file test_node_registry.cpp
 * @brief 子节点注册表测试
 */

#include "test_framework.h"
#include "../include/node_registry.h"

using namespace sshjump;

TEST(node_registry_create_and_get, "子节点管理") {
    ChildNodeRegistry registry;

    ChildNodeInfo node;
    node.nodeId = "edge-01";
    node.name = "Edge Node 01";
    node.publicAddress = "203.0.113.10";
    node.sshPort = 2222;
    node.clusterPort = 8888;
    node.description = "primary edge";
    node.enabled = true;
    node.metadata["region"] = "us-west";

    ASSERT_TRUE(registry.createNode(node));
    ASSERT_EQ(1, registry.size());

    auto loaded = registry.getNode("edge-01");
    ASSERT_TRUE(loaded.has_value());
    ASSERT_EQ("Edge Node 01", loaded->name);
    ASSERT_EQ("203.0.113.10", loaded->publicAddress);
    ASSERT_EQ("us-west", loaded->metadata["region"]);
    return true;
}

TEST(node_registry_update, "子节点管理") {
    ChildNodeRegistry registry;

    ChildNodeInfo node;
    node.nodeId = "edge-02";
    node.publicAddress = "198.51.100.10";
    ASSERT_TRUE(registry.createNode(node));

    ChildNodeInfo patch;
    patch.name = "Edge Node 02";
    patch.description = "updated";
    patch.sshPort = 2200;
    patch.enabled = false;
    patch.metadata["owner"] = "ops";

    ASSERT_TRUE(registry.updateNode("edge-02", patch));
    auto updated = registry.getNode("edge-02");
    ASSERT_TRUE(updated.has_value());
    ASSERT_EQ("Edge Node 02", updated->name);
    ASSERT_EQ(2200, updated->sshPort);
    ASSERT_FALSE(updated->enabled);
    ASSERT_EQ("ops", updated->metadata["owner"]);
    return true;
}

TEST(node_registry_delete, "子节点管理") {
    ChildNodeRegistry registry;
    ChildNodeInfo node;
    node.nodeId = "edge-03";
    node.publicAddress = "192.0.2.3";
    ASSERT_TRUE(registry.createNode(node));
    ASSERT_EQ(1, registry.size());

    ASSERT_TRUE(registry.deleteNode("edge-03"));
    ASSERT_EQ(0, registry.size());
    ASSERT_FALSE(registry.getNode("edge-03").has_value());
    return true;
}

TEST(node_registry_list_enabled_only, "子节点管理") {
    ChildNodeRegistry registry;

    ChildNodeInfo a;
    a.nodeId = "a";
    a.publicAddress = "10.0.0.1";
    a.enabled = true;
    ASSERT_TRUE(registry.createNode(a));

    ChildNodeInfo b;
    b.nodeId = "b";
    b.publicAddress = "10.0.0.2";
    b.enabled = false;
    ASSERT_TRUE(registry.createNode(b));

    auto all = registry.listNodes(false);
    auto enabled = registry.listNodes(true);
    ASSERT_EQ(2, all.size());
    ASSERT_EQ(1, enabled.size());
    ASSERT_EQ("a", enabled[0].nodeId);
    return true;
}

TEST(node_registry_persistence, "子节点管理") {
    const std::string path = "/tmp/test_child_nodes.conf";

    {
        ChildNodeRegistry registry;
        ChildNodeInfo node;
        node.nodeId = "edge-04";
        node.name = "Persist Node";
        node.publicAddress = "203.0.113.44";
        node.enabled = true;
        node.metadata["zone"] = "z1";
        ASSERT_TRUE(registry.createNode(node));
        ASSERT_TRUE(registry.saveToFile(path));
    }

    {
        ChildNodeRegistry registry;
        ASSERT_TRUE(registry.loadFromFile(path));
        auto node = registry.getNode("edge-04");
        ASSERT_TRUE(node.has_value());
        ASSERT_EQ("Persist Node", node->name);
        ASSERT_EQ("z1", node->metadata["zone"]);
    }

    std::remove(path.c_str());
    return true;
}

