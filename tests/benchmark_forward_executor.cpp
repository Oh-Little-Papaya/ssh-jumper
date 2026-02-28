#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdlib>
#include <exception>
#include <functional>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <numeric>
#include <string>
#include <thread>
#include <vector>

#ifdef SSHJUMP_USE_FOLLY
#include <folly/executors/CPUThreadPoolExecutor.h>
#endif

namespace {

struct BenchConfig {
    int tasks = 30000;
    int work = 200;
    int rounds = 5;
};

bool parsePositiveInt(const std::string& value, int& out) {
    char* end = nullptr;
    const long parsed = std::strtol(value.c_str(), &end, 10);
    if (end == value.c_str() || *end != '\0' || parsed <= 0 || parsed > 100000000) {
        return false;
    }
    out = static_cast<int>(parsed);
    return true;
}

bool parseArgs(int argc, char* argv[], BenchConfig& cfg) {
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        auto needValue = [&](int& target) -> bool {
            if (i + 1 >= argc) {
                return false;
            }
            ++i;
            return parsePositiveInt(argv[i], target);
        };

        if (arg == "--tasks") {
            if (!needValue(cfg.tasks)) {
                return false;
            }
        } else if (arg == "--work") {
            if (!needValue(cfg.work)) {
                return false;
            }
        } else if (arg == "--rounds") {
            if (!needValue(cfg.rounds)) {
                return false;
            }
        } else if (arg == "--help" || arg == "-h") {
            std::cout << "Usage: ssh_jump_perf_bench [--tasks N] [--work N] [--rounds N]\n";
            return false;
        } else {
            return false;
        }
    }
    return true;
}

bool submitForwardTask(std::function<void()> task) {
#ifdef SSHJUMP_USE_FOLLY
    static folly::CPUThreadPoolExecutor executor(4);
    executor.add(std::move(task));
    return true;
#else
    try {
        std::thread(std::move(task)).detach();
        return true;
    } catch (const std::exception&) {
        return false;
    }
#endif
}

double runOneRound(const BenchConfig& cfg) {
    std::atomic<int> done{0};
    std::mutex mutex;
    std::condition_variable cv;

    const auto start = std::chrono::steady_clock::now();

    for (int i = 0; i < cfg.tasks; ++i) {
        auto task = [&, i]() {
            volatile uint64_t sink = 0;
            for (int j = 0; j < cfg.work; ++j) {
                sink += static_cast<uint64_t>((i + 1) * (j + 3));
            }
            if (done.fetch_add(1, std::memory_order_release) + 1 == cfg.tasks) {
                std::lock_guard<std::mutex> lock(mutex);
                cv.notify_one();
            }
            (void)sink;
        };
        if (!submitForwardTask(task)) {
            task();
        }
    }

    std::unique_lock<std::mutex> lock(mutex);
    cv.wait(lock, [&]() {
        return done.load(std::memory_order_acquire) == cfg.tasks;
    });

    const auto end = std::chrono::steady_clock::now();
    return std::chrono::duration<double, std::milli>(end - start).count();
}

}  // namespace

int main(int argc, char* argv[]) {
    BenchConfig cfg;
    if (!parseArgs(argc, argv, cfg)) {
        std::cerr << "Invalid arguments.\n";
        std::cerr << "Usage: ssh_jump_perf_bench [--tasks N] [--work N] [--rounds N]\n";
        return 1;
    }

    std::vector<double> roundMs;
    roundMs.reserve(static_cast<size_t>(cfg.rounds));

#ifdef SSHJUMP_USE_FOLLY
    const char* mode = "folly";
#else
    const char* mode = "std";
#endif

    std::cout << "MODE=" << mode << "\n";
    std::cout << "TASKS=" << cfg.tasks << "\n";
    std::cout << "WORK=" << cfg.work << "\n";
    std::cout << "ROUNDS=" << cfg.rounds << "\n";

    for (int r = 1; r <= cfg.rounds; ++r) {
        const double ms = runOneRound(cfg);
        const double tps = (static_cast<double>(cfg.tasks) * 1000.0) / ms;
        roundMs.push_back(ms);
        std::cout << std::fixed << std::setprecision(3)
                  << "ROUND_" << r << "_MS=" << ms << " TPS=" << tps << "\n";
    }

    const double sum = std::accumulate(roundMs.begin(), roundMs.end(), 0.0);
    const double avgMs = sum / static_cast<double>(roundMs.size());
    const double avgTps = (static_cast<double>(cfg.tasks) * 1000.0) / avgMs;

    std::sort(roundMs.begin(), roundMs.end());
    const double p50Ms = roundMs[roundMs.size() / 2];
    const double p50Tps = (static_cast<double>(cfg.tasks) * 1000.0) / p50Ms;

    std::cout << std::fixed << std::setprecision(3)
              << "AVG_MS=" << avgMs << "\n"
              << "AVG_TPS=" << avgTps << "\n"
              << "P50_MS=" << p50Ms << "\n"
              << "P50_TPS=" << p50Tps << "\n";

    return 0;
}
