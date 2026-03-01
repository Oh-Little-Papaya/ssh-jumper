/**
 * @file session_recorder.cpp
 * @brief 会话录制器实现
 */

#include "session_recorder.h"
#include <sys/stat.h>
#include <iomanip>
#include <cerrno>

namespace sshjump {

SessionRecorder::SessionRecorder()
    : recording_(false)
    , recordedSize_(0) {
}

SessionRecorder::~SessionRecorder() {
    stopRecording();
}

bool SessionRecorder::startRecording(const std::string& sessionPath,
                                     const std::string& username,
                                     const std::string& assetId,
                                     const std::string& hostname) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (recording_) {
        return false;
    }

    username_ = username;
    assetId_ = assetId;
    hostname_ = hostname;
    sessionId_ = generateUUID();
    startTime_ = std::chrono::steady_clock::now();

    // 确保目录存在
    std::string dirPath = sessionPath;
    if (!dirPath.empty() && dirPath.back() != '/') {
        dirPath += '/';
    }

    // 创建目录（如果不存在）
    if (mkdir(dirPath.c_str(), 0700) != 0 && errno != EEXIST) {
        LOG_ERROR("Failed to create directory: " + dirPath + " - " + strerror(errno));
        return false;
    }
    chmod(dirPath.c_str(), 0700);

    // 创建用户子目录
    std::string userDir = dirPath + username_;
    if (mkdir(userDir.c_str(), 0700) != 0 && errno != EEXIST) {
        LOG_ERROR("Failed to create user directory: " + userDir + " - " + strerror(errno));
        return false;
    }
    chmod(userDir.c_str(), 0700);

    // 生成录制文件名: {timestamp}_{assetId}.rec
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    struct tm tm_result;
    localtime_r(&time, &tm_result);

    char timeStr[32];
    strftime(timeStr, sizeof(timeStr), "%Y%m%d_%H%M%S", &tm_result);

    recordFilePath_ = userDir + "/" + timeStr + "_" + assetId_ + ".rec";

    // 打开录制文件
    recordFile_.open(recordFilePath_, std::ios::binary | std::ios::out);
    if (!recordFile_.is_open()) {
        LOG_ERROR("Failed to open recording file: " + recordFilePath_);
        return false;
    }
    chmod(recordFilePath_.c_str(), 0600);

    // 写入文件头
    writeHeader();

    recording_ = true;
    recordedSize_ = 0;

    LOG_INFO("Session recording started: " + sessionId_ + " -> " + recordFilePath_);
    return true;
}

void SessionRecorder::stopRecording() {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!recording_) {
        return;
    }

    recording_ = false;

    if (recordFile_.is_open()) {
        recordFile_.flush();
        recordFile_.close();
    }

    LOG_INFO("Session recording stopped: " + sessionId_ +
             ", recorded: " + std::to_string(recordedSize_) + " bytes");
}

void SessionRecorder::record(Direction direction, const char* data, size_t len) {
    if (!recording_ || !data || len == 0) {
        return;
    }

    std::lock_guard<std::mutex> lock(mutex_);

    if (!recording_ || !recordFile_.is_open()) {
        return;
    }

    writeRecord(direction, data, len);
}

void SessionRecorder::writeHeader() {
    // 文件头格式:
    // Magic (4 bytes): "SREC"
    // Version (2 bytes): 0x0001
    // Session ID length (2 bytes)
    // Session ID (variable)
    // Username length (2 bytes)
    // Username (variable)
    // Asset ID length (2 bytes)
    // Asset ID (variable)
    // Hostname length (2 bytes)
    // Hostname (variable)
    // Start timestamp (8 bytes)

    // Magic
    recordFile_.write("SREC", 4);

    // Version
    uint16_t version = 1;
    recordFile_.write(reinterpret_cast<const char*>(&version), sizeof(version));

    // Session ID
    uint16_t len = static_cast<uint16_t>(sessionId_.length());
    recordFile_.write(reinterpret_cast<const char*>(&len), sizeof(len));
    recordFile_.write(sessionId_.c_str(), len);

    // Username
    len = static_cast<uint16_t>(username_.length());
    recordFile_.write(reinterpret_cast<const char*>(&len), sizeof(len));
    recordFile_.write(username_.c_str(), len);

    // Asset ID
    len = static_cast<uint16_t>(assetId_.length());
    recordFile_.write(reinterpret_cast<const char*>(&len), sizeof(len));
    recordFile_.write(assetId_.c_str(), len);

    // Hostname
    len = static_cast<uint16_t>(hostname_.length());
    recordFile_.write(reinterpret_cast<const char*>(&len), sizeof(len));
    recordFile_.write(hostname_.c_str(), len);

    // Start timestamp (milliseconds since epoch)
    auto epoch = startTime_.time_since_epoch();
    uint64_t timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(epoch).count();
    recordFile_.write(reinterpret_cast<const char*>(&timestamp), sizeof(timestamp));

    recordFile_.flush();
}

void SessionRecorder::writeRecord(Direction direction, const char* data, size_t len) {
    // 记录格式:
    // Timestamp offset (4 bytes): milliseconds since recording start
    // Direction (1 byte): 0 = user input, 1 = server output
    // Data length (4 bytes)
    // Data (variable)

    // 计算时间偏移
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - startTime_).count();
    uint32_t timestampOffset = static_cast<uint32_t>(elapsed);

    // 写入时间偏移
    recordFile_.write(reinterpret_cast<const char*>(&timestampOffset), sizeof(timestampOffset));

    // 写入方向
    uint8_t dir = static_cast<uint8_t>(direction);
    recordFile_.write(reinterpret_cast<const char*>(&dir), sizeof(dir));

    // 写入数据长度
    uint32_t dataLen = static_cast<uint32_t>(len);
    recordFile_.write(reinterpret_cast<const char*>(&dataLen), sizeof(dataLen));

    // 写入数据
    recordFile_.write(data, len);

    recordedSize_ += sizeof(timestampOffset) + sizeof(dir) + sizeof(dataLen) + len;

    // 定期刷新，避免数据丢失
    if (recordedSize_ % 65536 == 0) {
        recordFile_.flush();
    }
}

} // namespace sshjump
