#include "cluster_manager.h"

#include <nlohmann/json.hpp>

#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <unistd.h>

namespace {

using json = nlohmann::json;

constexpr int kDefaultPort = sshjump::DEFAULT_CLUSTER_PORT;
constexpr int kIoTimeoutMs = 10000;
constexpr uint32_t kMaxMessageSize = 10 * 1024 * 1024;

void printHelp(const char* program) {
    std::cout << "SSH Jump Cluster Admin Tool\n\n"
              << "Node commands:\n"
              << "  " << program << " --list-nodes --admin-token <token> [--server <addr>] [--port <port>]\n"
              << "  " << program << " --get-node <agent_id> --admin-token <token> [--server <addr>] [--port <port>]\n"
              << "  " << program << " --add-node <agent_id> --ip <ip> --node-token <token> --admin-token <token> [--hostname <name>]\n"
              << "  " << program << " --update-node <agent_id> --admin-token <token> [--ip <ip>] [--node-token <token>] [--hostname <name>]\n"
              << "  " << program << " --delete-node <agent_id> --admin-token <token> [--server <addr>] [--port <port>]\n\n"
              << "User commands:\n"
              << "  " << program << " --list-users --admin-token <token> [--server <addr>] [--port <port>]\n"
              << "  " << program << " --get-user <username> --admin-token <token> [--server <addr>] [--port <port>]\n"
              << "  " << program << " --add-user <username> --admin-token <token> (--password <pwd> | --password-hash <hash>) [--public-key <key>] [--must-change] [--enabled|--disabled]\n"
              << "  " << program << " --update-user <username> --admin-token <token> [--password <pwd>] [--password-hash <hash>] [--public-key <key>|--clear-public-key] [--must-change|--no-must-change] [--enabled|--disabled]\n"
              << "  " << program << " --delete-user <username> --admin-token <token> [--server <addr>] [--port <port>]\n\n"
              << "Options:\n"
              << "  --server <addr>          Cluster server address (default: 127.0.0.1)\n"
              << "  --port <port>            Cluster server port (default: 8888)\n"
              << "  --admin-token <token>    Admin API token\n"
              << "  --token <token>          Alias of --admin-token (backward compatible)\n"
              << "  --ip <ip>                Node IP address\n"
              << "  --hostname <name>        Node hostname\n"
              << "  --node-token <token>     Node token for agent registration\n"
              << "  --password <pwd>         User password (encrypted transport; server hashes)\n"
              << "  --password-hash <hash>   User password hash (PBKDF2$... or SHA256 hex)\n"
              << "  --public-key <key>       User public key\n"
              << "  --clear-public-key       Clear user public key\n"
              << "  --must-change            Force password change on next login\n"
              << "  --no-must-change         Disable force password change\n"
              << "  --enabled                Enable user\n"
              << "  --disabled               Disable user\n"
              << "  --help                   Show help\n";
}

bool sendAll(int fd, const uint8_t* data, size_t len) {
    size_t offset = 0;
    while (offset < len) {
        ssize_t n = send(fd, data + offset, len - offset, MSG_NOSIGNAL);
        if (n > 0) {
            offset += static_cast<size_t>(n);
            continue;
        }
        if (n < 0 && errno == EINTR) {
            continue;
        }
        return false;
    }
    return true;
}

bool recvWithTimeout(int fd, uint8_t* data, size_t len, int timeoutMs) {
    size_t offset = 0;
    while (offset < len) {
        struct pollfd pfd{fd, POLLIN, 0};
        int ret = poll(&pfd, 1, timeoutMs);
        if (ret <= 0) {
            return false;
        }
        ssize_t n = recv(fd, data + offset, len - offset, 0);
        if (n > 0) {
            offset += static_cast<size_t>(n);
            continue;
        }
        if (n < 0 && errno == EINTR) {
            continue;
        }
        return false;
    }
    return true;
}

int connectToServer(const std::string& host, int port) {
    struct addrinfo hints;
    struct addrinfo* result = nullptr;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    const std::string service = std::to_string(port);
    if (getaddrinfo(host.c_str(), service.c_str(), &hints, &result) != 0 || !result) {
        return -1;
    }

    int fd = -1;
    for (auto* ai = result; ai != nullptr; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype | SOCK_CLOEXEC, ai->ai_protocol);
        if (fd < 0) {
            continue;
        }

        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) {
            break;
        }

        close(fd);
        fd = -1;
    }

    freeaddrinfo(result);
    return fd;
}

bool receiveMessage(int fd, sshjump::AgentMessage& msg) {
    uint8_t header[9] = {0};
    if (!recvWithTimeout(fd, header, sizeof(header), kIoTimeoutMs)) {
        return false;
    }

    uint32_t payloadLen = (static_cast<uint32_t>(header[5]) << 24) |
                          (static_cast<uint32_t>(header[6]) << 16) |
                          (static_cast<uint32_t>(header[7]) << 8) |
                          static_cast<uint32_t>(header[8]);

    if (payloadLen > kMaxMessageSize) {
        return false;
    }

    std::vector<uint8_t> raw;
    raw.reserve(sizeof(header) + payloadLen);
    raw.insert(raw.end(), header, header + sizeof(header));

    if (payloadLen > 0) {
        std::vector<uint8_t> payload(payloadLen, 0);
        if (!recvWithTimeout(fd, payload.data(), payload.size(), kIoTimeoutMs)) {
            return false;
        }
        raw.insert(raw.end(), payload.begin(), payload.end());
    }

    return sshjump::AgentMessage::deserialize(raw.data(), raw.size(), msg);
}

void printNode(const json& node) {
    std::cout << "agentId        : " << node.value("agentId", "") << "\n"
              << "hostname       : " << node.value("hostname", "") << "\n"
              << "ipAddress      : " << node.value("ipAddress", "") << "\n"
              << "online         : " << (node.value("online", false) ? "true" : "false") << "\n";

    const std::string runtimeIp = node.value("runtimeIpAddress", "");
    const std::string runtimeHost = node.value("runtimeHostname", "");
    if (!runtimeIp.empty() || !runtimeHost.empty()) {
        std::cout << "runtimeHost/IP : " << runtimeHost << " / " << runtimeIp << "\n";
    }
}

void printUser(const json& user) {
    std::cout << "username         : " << user.value("username", "") << "\n"
              << "enabled          : " << (user.value("enabled", true) ? "true" : "false") << "\n"
              << "mustChangePasswd : " << (user.value("mustChangePassword", false) ? "true" : "false") << "\n"
              << "hasPublicKey     : " << (user.value("hasPublicKey", false) ? "true" : "false") << "\n"
              << "hashType         : " << user.value("passwordHashType", "") << "\n";
}

bool isNodeCommand(const std::string& cmd) {
    return cmd == "list_nodes" || cmd == "get_node" || cmd == "create_node" ||
           cmd == "update_node" || cmd == "delete_node";
}

bool isUserCommand(const std::string& cmd) {
    return cmd == "list_users" || cmd == "get_user" || cmd == "create_user" ||
           cmd == "update_user" || cmd == "delete_user";
}

} // namespace

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printHelp(argv[0]);
        return 1;
    }

    std::string cmd;
    std::string server = "127.0.0.1";
    int port = kDefaultPort;
    std::string adminToken;

    std::string agentId;
    std::string ipAddress;
    std::string hostname;
    std::string nodeToken;
    bool hasIpAddress = false;
    bool hasHostname = false;
    bool hasNodeToken = false;

    std::string username;
    std::string password;
    std::string passwordHash;
    std::string publicKey;
    bool hasPassword = false;
    bool hasPasswordHash = false;
    bool hasPublicKey = false;
    bool clearPublicKey = false;
    bool hasMustChange = false;
    bool mustChange = false;
    bool hasEnabled = false;
    bool enabled = true;

    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];

        if (arg == "--help" || arg == "-h") {
            printHelp(argv[0]);
            return 0;
        }

        if (arg == "--list-nodes") {
            cmd = "list_nodes";
            continue;
        }
        if (arg == "--get-node" && i + 1 < argc) {
            cmd = "get_node";
            agentId = argv[++i];
            continue;
        }
        if (arg == "--add-node" && i + 1 < argc) {
            cmd = "create_node";
            agentId = argv[++i];
            continue;
        }
        if (arg == "--update-node" && i + 1 < argc) {
            cmd = "update_node";
            agentId = argv[++i];
            continue;
        }
        if (arg == "--delete-node" && i + 1 < argc) {
            cmd = "delete_node";
            agentId = argv[++i];
            continue;
        }

        if (arg == "--list-users") {
            cmd = "list_users";
            continue;
        }
        if (arg == "--get-user" && i + 1 < argc) {
            cmd = "get_user";
            username = argv[++i];
            continue;
        }
        if (arg == "--add-user" && i + 1 < argc) {
            cmd = "create_user";
            username = argv[++i];
            continue;
        }
        if (arg == "--update-user" && i + 1 < argc) {
            cmd = "update_user";
            username = argv[++i];
            continue;
        }
        if (arg == "--delete-user" && i + 1 < argc) {
            cmd = "delete_user";
            username = argv[++i];
            continue;
        }

        if (arg == "--server" && i + 1 < argc) {
            server = argv[++i];
            continue;
        }
        if (arg == "--port" && i + 1 < argc) {
            port = sshjump::safeStringToInt(argv[++i], kDefaultPort);
            continue;
        }
        if ((arg == "--admin-token" || arg == "--token") && i + 1 < argc) {
            adminToken = argv[++i];
            continue;
        }

        if (arg == "--ip" && i + 1 < argc) {
            ipAddress = argv[++i];
            hasIpAddress = true;
            continue;
        }
        if (arg == "--hostname" && i + 1 < argc) {
            hostname = argv[++i];
            hasHostname = true;
            continue;
        }
        if (arg == "--node-token" && i + 1 < argc) {
            nodeToken = argv[++i];
            hasNodeToken = true;
            continue;
        }

        if (arg == "--password" && i + 1 < argc) {
            password = argv[++i];
            hasPassword = true;
            continue;
        }
        if (arg == "--password-hash" && i + 1 < argc) {
            passwordHash = argv[++i];
            hasPasswordHash = true;
            continue;
        }
        if (arg == "--public-key" && i + 1 < argc) {
            publicKey = argv[++i];
            hasPublicKey = true;
            continue;
        }
        if (arg == "--clear-public-key") {
            clearPublicKey = true;
            continue;
        }
        if (arg == "--must-change") {
            hasMustChange = true;
            mustChange = true;
            continue;
        }
        if (arg == "--no-must-change") {
            hasMustChange = true;
            mustChange = false;
            continue;
        }
        if (arg == "--enabled") {
            hasEnabled = true;
            enabled = true;
            continue;
        }
        if (arg == "--disabled") {
            hasEnabled = true;
            enabled = false;
            continue;
        }
    }

    if (cmd.empty()) {
        std::cerr << "No command specified\n";
        printHelp(argv[0]);
        return 1;
    }

    if (!isNodeCommand(cmd) && !isUserCommand(cmd)) {
        std::cerr << "Unsupported command\n";
        return 1;
    }

    if (adminToken.empty()) {
        std::cerr << "--admin-token is required\n";
        return 1;
    }

    if ((cmd == "get_node" || cmd == "create_node" || cmd == "update_node" || cmd == "delete_node") &&
        agentId.empty()) {
        std::cerr << "agent_id is required\n";
        return 1;
    }

    if (cmd == "create_node" && (!hasIpAddress || !hasNodeToken)) {
        std::cerr << "--add-node requires --ip and --node-token\n";
        return 1;
    }

    if (cmd == "update_node" && !hasIpAddress && !hasNodeToken && !hasHostname) {
        std::cerr << "--update-node requires at least one of --ip/--node-token/--hostname\n";
        return 1;
    }

    if ((cmd == "get_user" || cmd == "create_user" || cmd == "update_user" || cmd == "delete_user") &&
        username.empty()) {
        std::cerr << "username is required\n";
        return 1;
    }

    if (cmd == "create_user" && !hasPassword && !hasPasswordHash) {
        std::cerr << "--add-user requires --password or --password-hash\n";
        return 1;
    }

    if (cmd == "update_user" && !hasPassword && !hasPasswordHash && !hasPublicKey && !clearPublicKey &&
        !hasMustChange && !hasEnabled) {
        std::cerr << "--update-user requires at least one update option\n";
        return 1;
    }

    json req;
    req["op"] = cmd;
    req["ts"] = std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count();
    req["nonce"] = sshjump::generateUUID();

    if (!agentId.empty()) {
        req["agentId"] = agentId;
    }
    if (hasIpAddress) {
        req["ipAddress"] = ipAddress;
    }
    if (hasHostname) {
        req["hostname"] = hostname;
    }
    if (hasNodeToken) {
        req["nodeToken"] = nodeToken;
    }

    if (!username.empty()) {
        req["username"] = username;
    }
    if (hasPassword) {
        req["password"] = password;
    }
    if (hasPasswordHash) {
        req["passwordHash"] = passwordHash;
    }
    if (hasPublicKey) {
        req["publicKey"] = publicKey;
    }
    if (clearPublicKey) {
        req["clearPublicKey"] = true;
    }
    if (hasMustChange) {
        req["mustChangePassword"] = mustChange;
    }
    if (hasEnabled) {
        req["enabled"] = enabled;
    }

    std::string ivHex;
    std::string ciphertextHex;
    std::string tagHex;
    if (!sshjump::encryptWithTokenAesGcm(req.dump(), adminToken, ivHex, ciphertextHex, tagHex)) {
        std::cerr << "Failed to encrypt command payload\n";
        return 1;
    }

    json wireReq;
    wireReq["secure"] = {
        {"alg", "AES-256-GCM"},
        {"iv", ivHex},
        {"ciphertext", ciphertextHex},
        {"tag", tagHex}
    };

    int fd = connectToServer(server, port);
    if (fd < 0) {
        std::cerr << "Failed to connect to " << server << ":" << port << "\n";
        return 1;
    }

    const sshjump::AgentMessage request =
        sshjump::AgentMessage::create(sshjump::AgentMessageType::COMMAND, wireReq.dump());
    const auto raw = request.serialize();
    if (!sendAll(fd, raw.data(), raw.size())) {
        close(fd);
        std::cerr << "Failed to send command\n";
        return 1;
    }

    sshjump::AgentMessage response;
    if (!receiveMessage(fd, response)) {
        close(fd);
        std::cerr << "Failed to receive response\n";
        return 1;
    }
    close(fd);

    if (response.type != sshjump::AgentMessageType::RESPONSE) {
        std::cerr << "Unexpected response type\n";
        return 1;
    }

    const std::string& payload = response.payload;
    if (payload.rfind("ERR:", 0) == 0) {
        std::cerr << payload.substr(4) << "\n";
        return 1;
    }
    if (payload.rfind("OK:", 0) != 0) {
        std::cerr << "Malformed response: " << payload << "\n";
        return 1;
    }

    const std::string body = payload.substr(3);
    if (cmd == "delete_node") {
        std::cout << "Deleted node: " << agentId << "\n";
        return 0;
    }
    if (cmd == "delete_user") {
        std::cout << "Deleted user: " << username << "\n";
        return 0;
    }

    if (body.empty()) {
        std::cout << "OK\n";
        return 0;
    }

    json resp;
    try {
        resp = json::parse(body);
    } catch (const std::exception&) {
        std::cout << body << "\n";
        return 0;
    }

    if (cmd == "list_nodes") {
        const auto nodes = resp.value("nodes", json::array());
        if (nodes.empty()) {
            std::cout << "No cluster nodes configured\n";
            return 0;
        }
        std::cout << "Cluster nodes (" << nodes.size() << "):\n";
        std::cout << "ID\tHOSTNAME\tIP\tONLINE\n";
        for (const auto& node : nodes) {
            std::cout << node.value("agentId", "") << "\t"
                      << node.value("hostname", "") << "\t"
                      << node.value("ipAddress", "") << "\t"
                      << (node.value("online", false) ? "yes" : "no") << "\n";
        }
        return 0;
    }

    if (cmd == "list_users") {
        const auto users = resp.value("users", json::array());
        if (users.empty()) {
            std::cout << "No users configured\n";
            return 0;
        }
        std::cout << "Users (" << users.size() << "):\n";
        std::cout << "USERNAME\tENABLED\tMUST_CHANGE\tHAS_PUBKEY\tHASH\n";
        for (const auto& user : users) {
            std::cout << user.value("username", "") << "\t"
                      << (user.value("enabled", true) ? "yes" : "no") << "\t"
                      << (user.value("mustChangePassword", false) ? "yes" : "no") << "\t"
                      << (user.value("hasPublicKey", false) ? "yes" : "no") << "\t"
                      << user.value("passwordHashType", "") << "\n";
        }
        return 0;
    }

    if (cmd == "get_node" || cmd == "create_node" || cmd == "update_node") {
        printNode(resp);
        return 0;
    }

    printUser(resp);
    return 0;
}
