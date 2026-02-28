/**
 * @file thread_pool.cpp
 * @brief 线程池实现
 */

#include "thread_pool.h"

namespace sshjump {

ThreadPool::ThreadPool(size_t numThreads)
    : numThreads_(numThreads)
    , running_(false) {
}

ThreadPool::~ThreadPool() {
    stop();
}

void ThreadPool::start() {
    running_ = true;
    
    for (size_t i = 0; i < numThreads_; i++) {
        workers_.emplace_back(&ThreadPool::workerLoop, this);
    }
    
    LOG_INFO("Thread pool started with " + std::to_string(numThreads_) + " threads");
}

void ThreadPool::stop() {
    {
        std::unique_lock<std::mutex> lock(mutex_);
        running_ = false;
    }
    
    cv_.notify_all();
    
    for (auto& worker : workers_) {
        if (worker.joinable()) {
            worker.join();
        }
    }
    
    workers_.clear();
    
    LOG_INFO("Thread pool stopped");
}

void ThreadPool::submit(std::function<void()> task) {
    {
        std::unique_lock<std::mutex> lock(mutex_);
        if (!running_) {
            return;
        }
        tasks_.push(std::move(task));
    }
    
    cv_.notify_one();
}

size_t ThreadPool::queueSize() const {
    std::unique_lock<std::mutex> lock(mutex_);
    return tasks_.size();
}

void ThreadPool::workerLoop() {
    while (running_) {
        std::function<void()> task;

        {
            std::unique_lock<std::mutex> lock(mutex_);
            cv_.wait(lock, [this] { return !running_ || !tasks_.empty(); });

            // 如果停止了，立即退出（不处理剩余任务）
            if (!running_) {
                return;
            }

            if (tasks_.empty()) {
                continue;
            }

            task = std::move(tasks_.front());
            tasks_.pop();
        }

        if (task) {
            task();
        }
    }
}

} // namespace sshjump
