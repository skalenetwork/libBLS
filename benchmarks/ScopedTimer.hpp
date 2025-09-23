#pragma once
#include <chrono>

// Simple RAII timer. Starts on construction; stops on destruction.
// Accumulates into an external double reference (milliseconds).
struct ScopedTimer {
    using clock = std::chrono::steady_clock;
    std::chrono::time_point< clock > start;
    double& acc_ms;
    bool stopped{ false };

    explicit ScopedTimer( double& acc ) : start( clock::now() ), acc_ms( acc ) {}

    ~ScopedTimer() { stop(); }

    void stop() {
        if ( stopped )
            return;
        auto end = clock::now();
        acc_ms += std::chrono::duration< double, std::milli >( end - start ).count();
        stopped = true;
    }
};