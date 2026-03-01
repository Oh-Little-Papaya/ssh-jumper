cmake_minimum_required(VERSION 3.14)
project(ssh_jump_server VERSION 2.0.0 LANGUAGES CXX)

# C++标准
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# 编译选项
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra")
set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -fsanitize=address")
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG")

# 查找依赖包
find_package(PkgConfig REQUIRED)
find_package(Threads REQUIRED)

# 查找 libssh - 优先使用系统版本，如果没有则自动下载
option(USE_SYSTEM_LIBSSH "Use system installed libssh" ON)

if(USE_SYSTEM_LIBSSH)
    pkg_check_modules(LIBSSH libssh)
endif()

if(NOT LIBSSH_FOUND)
    message(STATUS "System libssh not found, will download and build from source")
    include(FetchContent)
    
    FetchContent_Declare(
        libssh
        GIT_REPOSITORY https://gitlab.com/libssh/libssh-mirror.git
        GIT_TAG libssh-0.11.3
        GIT_SHALLOW TRUE
    )
    
    # 设置 libssh 构建选项
    set(WITH_SERVER ON CACHE BOOL "Build with server support" FORCE)
    set(WITH_ZLIB OFF CACHE BOOL "Build with zlib support" FORCE)
    set(WITH_SFTP ON CACHE BOOL "Build with SFTP support" FORCE)
    set(WITH_GSSAPI OFF CACHE BOOL "Build with GSSAPI support" FORCE)
    set(WITH_PCAP OFF CACHE BOOL "Build with pcap support" FORCE)
    set(WITH_EXAMPLES OFF CACHE BOOL "Build examples" FORCE)
    set(WITH_TESTS OFF CACHE BOOL "Build tests" FORCE)
    set(WITH_DOC OFF CACHE BOOL "Build documentation" FORCE)
    
    FetchContent_MakeAvailable(libssh)
    
    # 设置 libssh 变量
    set(LIBSSH_LIBRARIES ssh)
    set(LIBSSH_INCLUDE_DIRS ${libssh_SOURCE_DIR}/include)
    set(LIBSSH_FOUND TRUE)
    
    message(STATUS "libssh will be built from source")
else()
    message(STATUS "Using system libssh: ${LIBSSH_VERSION}")
endif()

# 查找 OpenSSL
find_package(OpenSSL REQUIRED)

# Folly 性能优化组件（默认启用；启用时必须可用）
option(ENABLE_FOLLY "Enable Folly-based performance optimizations" ON)
set(FOLLY_ENABLED FALSE)
set(FOLLY_USING_TARGET FALSE)
set(FOLLY_TARGET_NAME "")
if(ENABLE_FOLLY)
    find_package(folly CONFIG QUIET)
    if(folly_FOUND)
        if(TARGET Folly::folly)
            set(FOLLY_TARGET_NAME Folly::folly)
        elseif(TARGET folly::folly)
            set(FOLLY_TARGET_NAME folly::folly)
        endif()

        if(FOLLY_TARGET_NAME)
            set(FOLLY_ENABLED TRUE)
            set(FOLLY_USING_TARGET TRUE)
            message(STATUS "Folly found via CMake package target: ${FOLLY_TARGET_NAME}")
        else()
            message(STATUS "Folly package found but no imported target exported, try pkg-config")
        endif()
    endif()

    if(NOT FOLLY_ENABLED)
        pkg_check_modules(FOLLY QUIET folly)
        if(FOLLY_FOUND)
            set(FOLLY_ENABLED TRUE)
            message(STATUS "Folly found via pkg-config: ${FOLLY_VERSION}")
        else()
            message(FATAL_ERROR
                "ENABLE_FOLLY=ON but Folly not found. "
                "Install Folly first (for example: ./scripts/install_folly.sh).")
        endif()
    endif()
endif()

# 下载 nlohmann/json 库
include(FetchContent)
FetchContent_Declare(
    json
    URL https://github.com/nlohmann/json/releases/download/v3.11.2/json.tar.xz
)
FetchContent_MakeAvailable(json)

# 检查 io_uring 支持
include(CheckIncludeFileCXX)
check_include_file_cxx("liburing.h" HAS_IO_URING_H)
if(HAS_IO_URING_H)
    find_library(IO_URING_LIB uring)
    if(IO_URING_LIB)
        set(HAS_IO_URING TRUE)
        add_definitions(-DHAS_IO_URING)
        message(STATUS "io_uring support enabled")
    endif()
endif()

# 头文件目录
include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${LIBSSH_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIR}
)

# 链接目录
if(LIBSSH_LIBRARY_DIRS)
    link_directories(${LIBSSH_LIBRARY_DIRS})
endif()

# 公共源文件
set(COMMON_SOURCES
    src/common.cpp
    src/event_loop.cpp
    src/thread_pool.cpp
    src/cluster_manager.cpp
    src/node_registry.cpp
    src/config_manager.cpp
    src/asset_manager.cpp
    src/interactive_session.cpp
    src/ssh_server.cpp
    src/session_recorder.cpp
)

# 创建静态库
add_library(sshjump_static STATIC ${COMMON_SOURCES})
target_link_libraries(sshjump_static
    PUBLIC
        ${LIBSSH_LIBRARIES}
        ${OPENSSL_LIBRARIES}
        Threads::Threads
        nlohmann_json::nlohmann_json
)

if(FOLLY_ENABLED)
    target_compile_definitions(sshjump_static PUBLIC SSHJUMP_USE_FOLLY)
    if(FOLLY_USING_TARGET)
        target_link_libraries(sshjump_static PUBLIC ${FOLLY_TARGET_NAME})
    else()
        if(FOLLY_INCLUDE_DIRS)
            target_include_directories(sshjump_static PUBLIC ${FOLLY_INCLUDE_DIRS})
        endif()
        if(FOLLY_LIBRARY_DIRS)
            target_link_directories(sshjump_static PUBLIC ${FOLLY_LIBRARY_DIRS})
        endif()
        target_link_libraries(sshjump_static PUBLIC ${FOLLY_LIBRARIES})
    endif()
endif()

if(HAS_IO_URING)
    target_link_libraries(sshjump_static PUBLIC ${IO_URING_LIB})
endif()

# SSH 服务器可执行文件
add_executable(ssh_jump_server src/main.cpp)
target_link_libraries(ssh_jump_server
    sshjump_static
    ${LIBSSH_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    Threads::Threads
)

if(HAS_IO_URING)
    target_link_libraries(ssh_jump_server ${IO_URING_LIB})
endif()

# Agent 客户端可执行文件
add_executable(ssh_jump_agent src/agent_main.cpp)
target_link_libraries(ssh_jump_agent
    sshjump_static
    ${LIBSSH_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    Threads::Threads
)

if(HAS_IO_URING)
    target_link_libraries(ssh_jump_agent ${IO_URING_LIB})
endif()

# 用户管理工具
add_executable(ssh_jump_user_tool src/user_tool.cpp)
target_link_libraries(ssh_jump_user_tool
    ${OPENSSL_LIBRARIES}
    Threads::Threads
)

# 子节点管理工具（CRUD）
add_executable(ssh_jump_node_tool src/node_tool.cpp)
target_link_libraries(ssh_jump_node_tool
    sshjump_static
    ${LIBSSH_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    Threads::Threads
)

# 集群管理工具（运行时用户+节点 CRUD）
add_executable(ssh_jump_cluster_admin_tool src/cluster_admin_tool.cpp)
target_link_libraries(ssh_jump_cluster_admin_tool
    sshjump_static
    ${LIBSSH_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    Threads::Threads
)

# 单元测试
enable_testing()

# 性能基准测试（用于 Folly ON/OFF 对比）
add_executable(ssh_jump_perf_bench tests/benchmark_forward_executor.cpp)
target_link_libraries(ssh_jump_perf_bench PRIVATE Threads::Threads)

if(FOLLY_ENABLED)
    target_compile_definitions(ssh_jump_perf_bench PRIVATE SSHJUMP_USE_FOLLY)
    if(FOLLY_USING_TARGET)
        target_link_libraries(ssh_jump_perf_bench PRIVATE ${FOLLY_TARGET_NAME})
    else()
        if(FOLLY_INCLUDE_DIRS)
            target_include_directories(ssh_jump_perf_bench PRIVATE ${FOLLY_INCLUDE_DIRS})
        endif()
        if(FOLLY_LIBRARY_DIRS)
            target_link_directories(ssh_jump_perf_bench PRIVATE ${FOLLY_LIBRARY_DIRS})
        endif()
        target_link_libraries(ssh_jump_perf_bench PRIVATE ${FOLLY_LIBRARIES})
    endif()
endif()

# 单元测试源文件
set(UNIT_TEST_SOURCES
    tests/test_main.cpp
    tests/test_config.cpp
    tests/test_common.cpp
    tests/test_asset_manager.cpp
    tests/test_cluster_manager.cpp
    tests/test_node_registry.cpp
)

# 创建单元测试可执行文件
add_executable(ssh_jump_tests ${UNIT_TEST_SOURCES})
target_link_libraries(ssh_jump_tests
    sshjump_static
    ${LIBSSH_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    Threads::Threads
)

if(HAS_IO_URING)
    target_link_libraries(ssh_jump_tests ${IO_URING_LIB})
endif()

# 添加单元测试
add_test(NAME UnitTests COMMAND ssh_jump_tests)

# 功能测试
set(FUNC_TEST_SOURCES
    func_tests/func_test_main.cpp
)

add_executable(ssh_jump_func_tests ${FUNC_TEST_SOURCES})
target_link_libraries(ssh_jump_func_tests
    ${LIBSSH_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    Threads::Threads
)

if(HAS_IO_URING)
    target_link_libraries(ssh_jump_func_tests ${IO_URING_LIB})
endif()

set_target_properties(ssh_jump_func_tests PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
)

# 安装目标
install(TARGETS ssh_jump_server ssh_jump_agent ssh_jump_user_tool
        ssh_jump_node_tool ssh_jump_cluster_admin_tool
    RUNTIME DESTINATION bin
)

install(DIRECTORY include/
    DESTINATION include/sshjump
    FILES_MATCHING PATTERN "*.h"
)

# 创建默认配置目录
install(DIRECTORY DESTINATION etc/ssh_jump)

# 打印配置摘要
message(STATUS "")
message(STATUS "=== SSH Jump Server Build Configuration ===")
message(STATUS "Version: ${PROJECT_VERSION}")
message(STATUS "C++ Standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "Build Type: ${CMAKE_BUILD_TYPE}")
message(STATUS "io_uring Support: ${HAS_IO_URING}")
message(STATUS "Folly Support: ${FOLLY_ENABLED}")
if(LIBSSH_VERSION)
    message(STATUS "libssh: ${LIBSSH_VERSION}")
else()
    message(STATUS "libssh: will be built from source (0.11.3)")
endif()
message(STATUS "Features: Interactive menu, Asset management, JumpServer-style")
message(STATUS "===============================================")
message(STATUS "")
