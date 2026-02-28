/**
 * @file func_test_main.cpp
 * @brief 功能测试入口
 */

#include "func_test_framework.h"
#include "test_env.h"

// 包含所有测试文件
#include "test_integration.cpp"

namespace {

std::string resolveBinaryPath(const std::vector<fs::path>& candidates) {
    for (const auto& candidate : candidates) {
        std::error_code ec;
        if (fs::exists(candidate, ec) && fs::is_regular_file(candidate, ec)) {
            return fs::absolute(candidate).string();
        }
    }
    return "";
}

} // namespace

int main(int argc, char* argv[]) {
    initFuncTest();
    
    std::string filter;
    if (argc > 1) {
        filter = argv[1];
    }
    
    std::cout << "========================================\n";
    std::cout << "  SSH Jump Server 功能测试\n";
    std::cout << "========================================\n";
    std::cout << "\n注意: 功能测试会实际启动服务器和Agent进程\n";
    std::cout << "      请确保端口 15022 (SSH) 和 15088 (Cluster) 可用\n\n";
    
    const fs::path exeDir = fs::absolute(fs::path(argv[0])).parent_path();

    const char* envServer = std::getenv("SSHJUMP_TEST_SERVER_BINARY");
    const char* envAgent = std::getenv("SSHJUMP_TEST_AGENT_BINARY");

    std::string serverBinary = resolveBinaryPath({
        envServer ? fs::path(envServer) : fs::path(),
        exeDir / "ssh_jump_server",
        fs::current_path() / "ssh_jump_server",
        "../build/ssh_jump_server"
    });
    std::string agentBinary = resolveBinaryPath({
        envAgent ? fs::path(envAgent) : fs::path(),
        exeDir / "ssh_jump_agent",
        fs::current_path() / "ssh_jump_agent",
        "../build/ssh_jump_agent"
    });

    if (serverBinary.empty()) {
        std::cerr << "错误: 找不到服务器二进制文件 ssh_jump_server\n";
        std::cerr << "请先编译项目: cmake --build <build-dir> -j$(nproc)\n";
        return 1;
    }
    if (agentBinary.empty()) {
        std::cerr << "错误: 找不到 Agent 二进制文件 ssh_jump_agent\n";
        std::cerr << "请先编译项目: cmake --build <build-dir> -j$(nproc)\n";
        return 1;
    }

    func_test::g_testEnv.setBinaries(serverBinary, agentBinary);
    
    int result = runAllFuncTests(filter);
    
    // 确保清理
    func_test::g_testEnv.cleanup();
    
    return result;
}
