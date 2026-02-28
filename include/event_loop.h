/**
 * @file event_loop.h
 * @brief 事件循环 - 支持 epoll 和 io_uring
 */

#ifndef SSH_JUMP_EVENT_LOOP_H
#define SSH_JUMP_EVENT_LOOP_H

#include "common.h"

namespace sshjump {

// 前向声明
class EventHandler;

// ============================================
// 事件处理器接口
// ============================================
class EventHandler {
public:
    virtual ~EventHandler() = default;
    
    virtual int onRead() = 0;
    virtual int onWrite() = 0;
    virtual void onError() = 0;
    virtual void onClose() = 0;
    virtual int getFd() const = 0;
};

// ============================================
// 事件循环接口
// ============================================
class IEventLoop {
public:
    virtual ~IEventLoop() = default;
    
    virtual bool initialize() = 0;
    virtual void poll(int timeoutMs) = 0;
    virtual void stop() = 0;
    virtual void addHandler(int fd, EventType events, std::shared_ptr<EventHandler> handler) = 0;
    virtual void removeHandler(int fd) = 0;
    virtual void modifyHandler(int fd, EventType events) = 0;
};

// ============================================
// Epoll 事件循环
// ============================================
class EpollEventLoop : public IEventLoop, public std::enable_shared_from_this<EpollEventLoop> {
public:
    EpollEventLoop();
    ~EpollEventLoop() override;
    
    bool initialize() override;
    void poll(int timeoutMs) override;
    void stop() override;
    void addHandler(int fd, EventType events, std::shared_ptr<EventHandler> handler) override;
    void removeHandler(int fd) override;
    void modifyHandler(int fd, EventType events) override;
    
private:
    int epollFd_;
    std::unordered_map<int, std::shared_ptr<EventHandler>> handlers_;
    std::atomic<bool> running_;
    std::mutex mutex_;
};

// ============================================
// 事件循环工厂
// ============================================
class EventLoopFactory {
public:
    enum class Type {
        EPOLL,
        IO_URING
    };
    
    static std::shared_ptr<IEventLoop> create(Type type);
};

} // namespace sshjump

#endif // SSH_JUMP_EVENT_LOOP_H
