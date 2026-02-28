/**
 * @file session_recorder.h
 * @brief 会话录制器 - 记录 SSH 会话的双向数据流
 */

#ifndef SSH_JUMP_SESSION_RECORDER_H
#define SSH_JUMP_SESSION_RECORDER_H

#include "common.h"
#include <fstream>

namespace sshjump {

/**
 * @brief 会话录制器
 *
 * 记录 SSH 会话的双向数据流，用于审计和回放
 * 文件格式:
 *   - 每条记录包含: 时间戳(8字节) + 方向(1字节) + 数据长度(4字节) + 数据
 *   - 方向: 0 = 用户输入, 1 = 服务器输出
 */
class SessionRecorder : public NonCopyable {
public:
    /**
     * @brief 数据方向
     */
    enum class Direction : uint8_t {
        USER_INPUT = 0,     ///< 用户输入的数据
        SERVER_OUTPUT = 1   ///< 服务器输出的数据
    };

    /**
     * @brief 构造函数
     */
    SessionRecorder();

    /**
     * @brief 析构函数
     */
    ~SessionRecorder();

    /**
     * @brief 开始录制
     * @param sessionPath 会话存储路径
     * @param username 用户名
     * @param assetId 资产ID
     * @param hostname 目标主机名
     * @return 是否成功
     */
    bool startRecording(const std::string& sessionPath,
                       const std::string& username,
                       const std::string& assetId,
                       const std::string& hostname);

    /**
     * @brief 停止录制
     */
    void stopRecording();

    /**
     * @brief 记录数据
     * @param direction 数据方向
     * @param data 数据内容
     * @param len 数据长度
     */
    void record(Direction direction, const char* data, size_t len);

    /**
     * @brief 检查是否正在录制
     * @return 是否正在录制
     */
    bool isRecording() const { return recording_; }

    /**
     * @brief 获取录制文件路径
     * @return 录制文件路径
     */
    const std::string& getRecordFilePath() const { return recordFilePath_; }

    /**
     * @brief 获取会话ID
     * @return 会话ID
     */
    const std::string& getSessionId() const { return sessionId_; }

    /**
     * @brief 获取已录制的数据大小
     * @return 数据大小（字节）
     */
    size_t getRecordedSize() const { return recordedSize_; }

private:
    /**
     * @brief 写入会话头部信息
     */
    void writeHeader();

    /**
     * @brief 写入数据记录
     */
    void writeRecord(Direction direction, const char* data, size_t len);

    // 会话ID
    std::string sessionId_;

    // 用户名
    std::string username_;

    // 资产ID
    std::string assetId_;

    // 目标主机名
    std::string hostname_;

    // 录制文件路径
    std::string recordFilePath_;

    // 录制文件流
    std::ofstream recordFile_;

    // 是否正在录制
    std::atomic<bool> recording_;

    // 开始时间
    std::chrono::steady_clock::time_point startTime_;

    // 已录制的数据大小
    std::atomic<size_t> recordedSize_;

    // 互斥锁
    mutable std::mutex mutex_;
};

} // namespace sshjump

#endif // SSH_JUMP_SESSION_RECORDER_H
