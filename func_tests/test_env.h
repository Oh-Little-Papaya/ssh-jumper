/**
 * @file test_env.h
 * @brief 测试环境管理
 */

#ifndef TEST_ENV_H
#define TEST_ENV_H

#include "func_test_framework.h"
#include <fstream>
#include <thread>
#include <atomic>
#include <csignal>
#include <cerrno>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

namespace func_test {

// 测试配置
struct TestConfig {
    std::string workDir;
    int sshPort = 22222;        // 测试用 SSH 端口
    int clusterPort = 28888;    // 测试用集群端口
    std::string serverBinary;
    std::string agentBinary;
    std::string clusterToken = "cluster-test-token";
    std::string adminToken = "admin-test-token";
    std::string adminUser = "admin";
    std::string adminPassword = "Admin123!";
    
    TestConfig() {
        workDir = "/tmp/ssh_jump_func_test";
        serverBinary = "../build/ssh_jump_server";
        agentBinary = "../build/ssh_jump_agent";
        sshPort = 15022;        // 使用高位端口避免冲突
        clusterPort = 15088;
    }
};

// 进程管理
class ProcessManager {
public:
    ProcessManager() : pid_(-1) {}
    
    ~ProcessManager() {
        stop();
    }
    
    bool start(const std::string& cmd, const std::vector<std::string>& args) {
        if (!fs::exists(cmd)) {
            return false;
        }

        pid_ = fork();
        if (pid_ < 0) {
            return false;
        }
        
        if (pid_ == 0) {
            // 子进程
            std::vector<char*> argv;
            argv.push_back(const_cast<char*>(cmd.c_str()));
            for (const auto& arg : args) {
                argv.push_back(const_cast<char*>(arg.c_str()));
            }
            argv.push_back(nullptr);
            
            // 注意: 保留 stdout/stderr 以便查看日志
            // 生产环境可以重定向到文件
            
            execv(cmd.c_str(), argv.data());
            _exit(1);
        }
        
        // 父进程：等待进程启动
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        return isRunning();
    }
    
    bool isRunning() {
        if (pid_ < 0) return false;

        int status = 0;
        pid_t ret = waitpid(pid_, &status, WNOHANG);
        if (ret == 0) {
            return (kill(pid_, 0) == 0);
        }

        if (ret == pid_) {
            pid_ = -1;
            return false;
        }

        if (ret < 0 && errno == ECHILD) {
            pid_ = -1;
            return false;
        }

        return false;
    }
    
    void stop() {
        if (pid_ > 0) {
            kill(pid_, SIGTERM);
            // 等待进程结束，带超时
            int status;
            int ret = waitpid(pid_, &status, WNOHANG);
            int waitCount = 0;
            while (ret == 0 && waitCount < 50) {  // 最多等 5 秒
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                ret = waitpid(pid_, &status, WNOHANG);
                waitCount++;
            }
            if (ret == 0) {
                // 进程仍在运行，强制终止
                kill(pid_, SIGKILL);
                waitpid(pid_, &status, 0);
            }
            pid_ = -1;
        }
    }
    
    pid_t getPid() const { return pid_; }
    
private:
    pid_t pid_;
};

// 测试环境
class TestEnvironment {
public:
    TestEnvironment() {}
    
    ~TestEnvironment() {
        cleanup();
    }
    
    bool setup() {
        // 清理之前的工作目录
        cleanup();
        
        // 创建工作目录
        fs::create_directories(config_.workDir);
        
        // 创建配置目录
        fs::create_directories(config_.workDir + "/etc");
        fs::create_directories(config_.workDir + "/log");
        
        // 创建主机密钥
        generateHostKey();
        
        // 创建配置文件
        createServerConfig();
        createAgentTokens();
        createUserPermissions();
        createUsersConfig();
        
        return true;
    }
    
    void cleanup() {
        // 停止所有进程
        stopServer();
        stopAgent();
        
        // 清理工作目录
        if (fs::exists(config_.workDir)) {
            fs::remove_all(config_.workDir);
        }
    }
    
    bool startServer() {
        std::vector<std::string> args = {
            "-p", std::to_string(config_.sshPort),
            "-a", std::to_string(config_.clusterPort),
            "--listen-address", "127.0.0.1",
            "--cluster-listen-address", "127.0.0.1",
            "--token", config_.clusterToken,
            "--admin-token", config_.adminToken,
            "--user", config_.adminUser + ":" + config_.adminPassword
        };
        return serverProcess_.start(config_.serverBinary, args);
    }
    
    void stopServer() {
        serverProcess_.stop();
    }
    
    bool isServerRunning() {
        return serverProcess_.isRunning();
    }
    
    bool startAgent(const std::string& agentId, const std::string& token,
                    const std::string& hostname) {
        std::vector<std::string> args = {
            "-s", "127.0.0.1",
            "-p", std::to_string(config_.clusterPort),
            "-i", agentId,
            "-t", token,
            "-n", hostname
        };
        return agentProcess_.start(config_.agentBinary, args);
    }
    
    void stopAgent() {
        agentProcess_.stop();
    }
    
    bool isAgentRunning() {
        return agentProcess_.isRunning();
    }

    void setBinaries(const std::string& serverBinary, const std::string& agentBinary) {
        config_.serverBinary = serverBinary;
        config_.agentBinary = agentBinary;
    }
    
    std::string getWorkDir() const { return config_.workDir; }
    int getSshPort() const { return config_.sshPort; }
    int getClusterPort() const { return config_.clusterPort; }
    const std::string& getClusterToken() const { return config_.clusterToken; }
    int getServerPid() const { return serverProcess_.getPid(); }
    int getAgentPid() const { return agentProcess_.getPid(); }
    const std::string& getServerBinary() const { return config_.serverBinary; }
    const std::string& getAgentBinary() const { return config_.agentBinary; }
    
private:
    void generateHostKey() {
        std::string keyPath = config_.workDir + "/etc/host_key";
        std::string cmd = "ssh-keygen -t rsa -b 2048 -f " + keyPath + " -N '' -q";
        system(cmd.c_str());
        
        // 同时生成 ECDSA 密钥
        std::string ecdsaKeyPath = config_.workDir + "/etc/host_key_ecdsa";
        std::string ecdsaCmd = "ssh-keygen -t ecdsa -b 256 -f " + ecdsaKeyPath + " -N '' -q";
        system(ecdsaCmd.c_str());
    }
    
    void createServerConfig() {
        std::ofstream file(config_.workDir + "/etc/server.conf");
        file << "[ssh]\n";
        file << "listen_address = 127.0.0.1\n";
        file << "port = " << config_.sshPort << "\n";
        file << "host_key_path = " << config_.workDir << "/etc/host_key\n";
        file << "auth_methods = publickey,password\n";
        file << "\n";
        file << "[cluster]\n";
        file << "listen_address = 127.0.0.1\n";
        file << "port = " << config_.clusterPort << "\n";
        file << "agent_token_file = " << config_.workDir << "/etc/agent_tokens.conf\n";
        file << "heartbeat_interval = 5\n";
        file << "\n";
        file << "[assets]\n";
        file << "permissions_file = " << config_.workDir << "/etc/user_permissions.conf\n";
        file << "\n";
        file << "[logging]\n";
        file << "level = debug\n";
        file << "log_file = " << config_.workDir << "/log/server.log\n";
        file << "audit_log = " << config_.workDir << "/log/audit.log\n";
        file << "\n";
        file << "[security]\n";
        file << "users_file = " << config_.workDir << "/etc/users.conf\n";
        file.close();
    }
    
    void createAgentTokens() {
        std::ofstream file(config_.workDir + "/etc/agent_tokens.conf");
        file << "# Agent tokens with static IP (avoid loopback auto-detection in tests)\n";
        file << "[agent:web-01]\n";
        file << "token = web01-secret-token\n";
        file << "ip = 10.10.0.11\n";
        file << "hostname = web-server-01\n";
        file << "\n";

        file << "[agent:web-02]\n";
        file << "token = web02-secret-token\n";
        file << "ip = 10.10.0.12\n";
        file << "hostname = web-server-02\n";
        file << "\n";

        file << "[agent:db-01]\n";
        file << "token = db01-secret-token\n";
        file << "ip = 10.10.0.13\n";
        file << "hostname = db-server-01\n";
        file << "\n";
        file.close();
    }
    
    void createUserPermissions() {
        std::ofstream file(config_.workDir + "/etc/user_permissions.conf");
        file << "# User permissions\n";
        file << "[user:admin]\n";
        file << "allow_all = true\n";
        file << "\n";
        file << "[user:developer]\n";
        file << "allowed_patterns = web-*\n";
        file << "max_sessions = 5\n";
        file.close();
    }
    
    void createUsersConfig() {
        // 创建用户认证配置文件
        std::ofstream file(config_.workDir + "/etc/users.conf");
        file << "# User authentication configuration\n";
        file << "# Format: username = password_hash (SHA256)\n";
        file << "\n";
        file << "# admin user, password: admin123\n";
        file << "admin = 240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9\n";
        file << "\n";
        file << "# test user, password: test123\n";
        file << "test = 6ca13d52ca70c883e0f0bb101e425a89e8624de51db2d2392593af6a84118090\n";
        file.close();
    }
    
    TestConfig config_;
    ProcessManager serverProcess_;
    ProcessManager agentProcess_;
};

// 全局测试环境
inline TestEnvironment g_testEnv;

} // namespace func_test

#endif // TEST_ENV_H
