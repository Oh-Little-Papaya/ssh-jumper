/**
 * @file node_tool.cpp
 * @brief 子节点管理工具（公网管理节点 CRUD）
 */

#include "node_registry.h"

namespace {

constexpr const char* kDefaultNodesFile = "/etc/ssh_jump/child_nodes.conf";

std::string boolLabel(bool v) {
    return v ? "enabled" : "disabled";
}

void printHelp(const char* program) {
    std::cout << "SSH Jump Child Node Management Tool\n\n"
              << "Usage:\n"
              << "  " << program << " --list-nodes [--nodes-file <path>]\n"
              << "  " << program << " --get-node <node_id> [--nodes-file <path>]\n"
              << "  " << program << " --add-node <node_id> --public-address <addr> [options]\n"
              << "  " << program << " --update-node <node_id> [options]\n"
              << "  " << program << " --delete-node <node_id> [--nodes-file <path>]\n\n"
              << "Options:\n"
              << "  --name <name>                 Node display name\n"
              << "  --public-address <addr>       Public endpoint (ip/host)\n"
              << "  --ssh-port <port>             SSH port (default: 2222)\n"
              << "  --cluster-port <port>         Cluster port (default: 8888)\n"
              << "  --description <text>          Description\n"
              << "  --enabled / --disabled        Enable/disable node\n"
              << "  --meta <k=v>                  Metadata key-value (repeatable)\n"
              << "  --remove-meta <k>             Remove metadata key (repeatable)\n"
              << "  --nodes-file <path>           Node config path (default: " << kDefaultNodesFile << ")\n"
              << "  --help                        Show help\n";
}

void printNode(const sshjump::ChildNodeInfo& node) {
    std::cout << "node_id      : " << node.nodeId << "\n"
              << "name         : " << (node.name.empty() ? "-" : node.name) << "\n"
              << "public_addr  : " << node.publicAddress << "\n"
              << "ssh_port     : " << node.sshPort << "\n"
              << "cluster_port : " << node.clusterPort << "\n"
              << "status       : " << boolLabel(node.enabled) << "\n"
              << "description  : " << (node.description.empty() ? "-" : node.description) << "\n";
    if (!node.metadata.empty()) {
        std::cout << "metadata     :\n";
        for (const auto& kv : node.metadata) {
            std::cout << "  - " << kv.first << "=" << kv.second << "\n";
        }
    }
}

void printNodesTable(const std::vector<sshjump::ChildNodeInfo>& nodes) {
    if (nodes.empty()) {
        std::cout << "No child nodes configured\n";
        return;
    }

    std::cout << "Child nodes (" << nodes.size() << "):\n";
    std::cout << "-----------------------------------------------------------------------------\n";
    std::cout << "ID\tNAME\tPUBLIC\tSSH\tCLUSTER\tSTATUS\n";
    std::cout << "-----------------------------------------------------------------------------\n";
    for (const auto& node : nodes) {
        std::cout << node.nodeId << "\t"
                  << (node.name.empty() ? "-" : node.name) << "\t"
                  << node.publicAddress << "\t"
                  << node.sshPort << "\t"
                  << node.clusterPort << "\t"
                  << boolLabel(node.enabled) << "\n";
    }
}

bool parseKeyValue(const std::string& kv, std::string& key, std::string& value) {
    const size_t pos = kv.find('=');
    if (pos == std::string::npos || pos == 0 || pos + 1 >= kv.size()) {
        return false;
    }
    key = sshjump::trimString(kv.substr(0, pos));
    value = sshjump::trimString(kv.substr(pos + 1));
    return !key.empty();
}

} // namespace

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printHelp(argv[0]);
        return 1;
    }

    std::string cmd;
    std::string nodeId;
    std::string nodesFile = kDefaultNodesFile;

    bool nameSet = false;
    std::string name;
    bool publicAddressSet = false;
    std::string publicAddress;
    bool sshPortSet = false;
    int sshPort = sshjump::DEFAULT_SSH_PORT;
    bool clusterPortSet = false;
    int clusterPort = sshjump::DEFAULT_CLUSTER_PORT;
    bool descSet = false;
    std::string description;
    bool enabledSet = false;
    bool enabled = true;
    std::map<std::string, std::string> metadataToSet;
    std::set<std::string> metadataToRemove;

    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--help" || arg == "-h") {
            printHelp(argv[0]);
            return 0;
        }
        if (arg == "--list-nodes") {
            cmd = "list";
            continue;
        }
        if (arg == "--get-node" && i + 1 < argc) {
            cmd = "get";
            nodeId = argv[++i];
            continue;
        }
        if (arg == "--add-node" && i + 1 < argc) {
            cmd = "add";
            nodeId = argv[++i];
            continue;
        }
        if (arg == "--update-node" && i + 1 < argc) {
            cmd = "update";
            nodeId = argv[++i];
            continue;
        }
        if (arg == "--delete-node" && i + 1 < argc) {
            cmd = "delete";
            nodeId = argv[++i];
            continue;
        }
        if (arg == "--nodes-file" && i + 1 < argc) {
            nodesFile = argv[++i];
            continue;
        }
        if (arg == "--name" && i + 1 < argc) {
            nameSet = true;
            name = argv[++i];
            continue;
        }
        if (arg == "--public-address" && i + 1 < argc) {
            publicAddressSet = true;
            publicAddress = argv[++i];
            continue;
        }
        if (arg == "--ssh-port" && i + 1 < argc) {
            sshPortSet = true;
            sshPort = sshjump::safeStringToInt(argv[++i], sshjump::DEFAULT_SSH_PORT);
            continue;
        }
        if (arg == "--cluster-port" && i + 1 < argc) {
            clusterPortSet = true;
            clusterPort = sshjump::safeStringToInt(argv[++i], sshjump::DEFAULT_CLUSTER_PORT);
            continue;
        }
        if (arg == "--description" && i + 1 < argc) {
            descSet = true;
            description = argv[++i];
            continue;
        }
        if (arg == "--enabled") {
            enabledSet = true;
            enabled = true;
            continue;
        }
        if (arg == "--disabled") {
            enabledSet = true;
            enabled = false;
            continue;
        }
        if (arg == "--meta" && i + 1 < argc) {
            std::string key;
            std::string value;
            if (!parseKeyValue(argv[++i], key, value)) {
                std::cerr << "Invalid --meta format, expect key=value\n";
                return 1;
            }
            metadataToSet[key] = value;
            continue;
        }
        if (arg == "--remove-meta" && i + 1 < argc) {
            metadataToRemove.insert(sshjump::trimString(argv[++i]));
            continue;
        }
    }

    if (cmd.empty()) {
        std::cerr << "No command specified\n";
        printHelp(argv[0]);
        return 1;
    }

    sshjump::ChildNodeRegistry registry;
    registry.loadFromFile(nodesFile);

    if (cmd == "list") {
        printNodesTable(registry.listNodes(false));
        return 0;
    }

    if (cmd == "get") {
        if (nodeId.empty()) {
            std::cerr << "--get-node requires node id\n";
            return 1;
        }
        auto node = registry.getNode(nodeId);
        if (!node) {
            std::cerr << "Node not found: " << nodeId << "\n";
            return 1;
        }
        printNode(*node);
        return 0;
    }

    if (cmd == "delete") {
        if (nodeId.empty()) {
            std::cerr << "--delete-node requires node id\n";
            return 1;
        }
        if (!registry.deleteNode(nodeId)) {
            std::cerr << "Node not found: " << nodeId << "\n";
            return 1;
        }
        if (!registry.saveToFile(nodesFile)) {
            return 1;
        }
        std::cout << "Deleted node: " << nodeId << "\n";
        return 0;
    }

    if (cmd == "add") {
        if (nodeId.empty() || !publicAddressSet) {
            std::cerr << "--add-node requires --public-address\n";
            return 1;
        }
        sshjump::ChildNodeInfo node;
        node.nodeId = nodeId;
        node.name = nameSet ? name : nodeId;
        node.publicAddress = publicAddress;
        node.sshPort = sshPortSet ? sshPort : sshjump::DEFAULT_SSH_PORT;
        node.clusterPort = clusterPortSet ? clusterPort : sshjump::DEFAULT_CLUSTER_PORT;
        node.description = descSet ? description : "";
        node.enabled = enabledSet ? enabled : true;
        node.metadata = metadataToSet;

        if (!registry.createNode(node, false)) {
            std::cerr << "Failed to create node (already exists or invalid): " << nodeId << "\n";
            return 1;
        }
        if (!registry.saveToFile(nodesFile)) {
            return 1;
        }
        std::cout << "Created node: " << nodeId << "\n";
        return 0;
    }

    if (cmd == "update") {
        if (nodeId.empty()) {
            std::cerr << "--update-node requires node id\n";
            return 1;
        }
        auto current = registry.getNode(nodeId);
        if (!current) {
            std::cerr << "Node not found: " << nodeId << "\n";
            return 1;
        }

        sshjump::ChildNodeInfo patch;
        patch.enabled = enabledSet ? enabled : current->enabled;
        if (nameSet) {
            patch.name = name;
        }
        if (publicAddressSet) {
            patch.publicAddress = publicAddress;
        }
        if (sshPortSet) {
            patch.sshPort = sshPort;
        }
        if (clusterPortSet) {
            patch.clusterPort = clusterPort;
        }
        if (descSet) {
            patch.description = description;
        }
        patch.metadata = metadataToSet;
        for (const auto& key : metadataToRemove) {
            patch.metadata[key] = "";
        }

        if (!registry.updateNode(nodeId, patch)) {
            std::cerr << "Failed to update node: " << nodeId << "\n";
            return 1;
        }
        if (!registry.saveToFile(nodesFile)) {
            return 1;
        }
        std::cout << "Updated node: " << nodeId << "\n";
        return 0;
    }

    std::cerr << "Unsupported command\n";
    return 1;
}

