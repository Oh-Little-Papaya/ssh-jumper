/**
 * @file event_loop.cpp
 * @brief 事件循环实现
 */

#include "event_loop.h"

namespace sshjump {

// ============================================
// EpollEventLoop 实现
// ============================================

EpollEventLoop::EpollEventLoop()
    : epollFd_(-1)
    , running_(false) {
}

EpollEventLoop::~EpollEventLoop() {
    stop();
    if (epollFd_ >= 0) {
        close(epollFd_);
    }
}

bool EpollEventLoop::initialize() {
    epollFd_ = epoll_create1(EPOLL_CLOEXEC);
    if (epollFd_ < 0) {
        LOG_ERROR("Failed to create epoll: " + std::string(strerror(errno)));
        return false;
    }
    running_ = true;
    return true;
}

void EpollEventLoop::poll(int timeoutMs) {
    const int MAX_EVENTS = 1024;
    struct epoll_event events[MAX_EVENTS];
    
    int nfds = epoll_wait(epollFd_, events, MAX_EVENTS, timeoutMs);
    if (nfds < 0) {
        if (errno != EINTR) {
            LOG_ERROR("epoll_wait failed: " + std::string(strerror(errno)));
        }
        return;
    }
    
    for (int i = 0; i < nfds; i++) {
        int fd = events[i].data.fd;
        uint32_t ev = events[i].events;
        
        std::shared_ptr<EventHandler> handler;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            auto it = handlers_.find(fd);
            if (it == handlers_.end()) {
                continue;
            }
            handler = it->second;
        }
        
        if (ev & EPOLLIN) {
            if (handler->onRead() < 0) {
                handler->onClose();
                removeHandler(fd);
                continue;
            }
        }
        
        if (ev & EPOLLOUT) {
            if (handler->onWrite() < 0) {
                handler->onError();
                removeHandler(fd);
                continue;
            }
        }
        
        if (ev & (EPOLLERR | EPOLLHUP)) {
            handler->onError();
            removeHandler(fd);
        }
    }
}

void EpollEventLoop::stop() {
    running_ = false;
}

void EpollEventLoop::addHandler(int fd, EventType events, std::shared_ptr<EventHandler> handler) {
    struct epoll_event ev;
    ev.data.fd = fd;
    ev.events = 0;
    
    if (events & EventType::READ) ev.events |= EPOLLIN;
    if (events & EventType::WRITE) ev.events |= EPOLLOUT;
    if (events & EventType::ERROR) ev.events |= EPOLLERR;
    if (events & EventType::HUP) ev.events |= EPOLLHUP;
    
    ev.events |= EPOLLET;  // 边缘触发
    
    {
        std::lock_guard<std::mutex> lock(mutex_);
        handlers_[fd] = handler;
    }
    
    if (epoll_ctl(epollFd_, EPOLL_CTL_ADD, fd, &ev) < 0) {
        LOG_ERROR("Failed to add fd to epoll: " + std::string(strerror(errno)));
        std::lock_guard<std::mutex> lock(mutex_);
        handlers_.erase(fd);
    }
}

void EpollEventLoop::removeHandler(int fd) {
    epoll_ctl(epollFd_, EPOLL_CTL_DEL, fd, nullptr);
    
    std::lock_guard<std::mutex> lock(mutex_);
    handlers_.erase(fd);
}

void EpollEventLoop::modifyHandler(int fd, EventType events) {
    struct epoll_event ev;
    ev.data.fd = fd;
    ev.events = 0;
    
    if (events & EventType::READ) ev.events |= EPOLLIN;
    if (events & EventType::WRITE) ev.events |= EPOLLOUT;
    if (events & EventType::ERROR) ev.events |= EPOLLERR;
    if (events & EventType::HUP) ev.events |= EPOLLHUP;
    
    ev.events |= EPOLLET;
    
    epoll_ctl(epollFd_, EPOLL_CTL_MOD, fd, &ev);
}

// ============================================
// EventLoopFactory 实现
// ============================================

std::shared_ptr<IEventLoop> EventLoopFactory::create(Type type) {
    switch (type) {
        case Type::EPOLL:
            return std::make_shared<EpollEventLoop>();
        case Type::IO_URING:
            // TODO: 实现 io_uring 支持
            return std::make_shared<EpollEventLoop>();
        default:
            return std::make_shared<EpollEventLoop>();
    }
}

} // namespace sshjump
