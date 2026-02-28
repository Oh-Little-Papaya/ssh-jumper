/**
 * @file thread_pool.h
 * @brief 线程池实现
 */

#ifndef SSH_JUMP_THREAD_POOL_H
#define SSH_JUMP_THREAD_POOL_H

#include "common.h"

namespace sshjump {

// ============================================
// 线程池
// ============================================
class ThreadPool : public NonCopyable {
public:
    explicit ThreadPool(size_t numThreads = DEFAULT_THREAD_POOL_SIZE);
    ~ThreadPool();
    
    // 启动线程池
    void start();
    
    // 停止线程池
    void stop();
    
    // 提交任务
    void submit(std::function<void()> task);
    
    // 获取任务队列大小
    size_t queueSize() const;
    
private:
    // 工作线程函数
    void workerLoop();
    
    // 线程数量
    size_t numThreads_;
    
    // 工作线程
    std::vector<std::thread> workers_;
    
    // 任务队列
    std::queue<std::function<void()>> tasks_;
    
    // 互斥锁
    mutable std::mutex mutex_;
    
    // 条件变量
    std::condition_variable cv_;
    
    // 运行标志
    std::atomic<bool> running_;
};

} // namespace sshjump

#endif // SSH_JUMP_THREAD_POOL_H
