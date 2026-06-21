#undef NDEBUG
#define NDEBUG 1
#include <benchmark/benchmark.h>
#include <string>
#include <vector>
#include "luminawaf.h"
#include "hardware_pmu.h"

// Generate a synthetic payload with a specific percentage of malicious/encoded content
std::string generate_synthetic_payload(size_t length, int malicious_percent) {
    std::string payload;
    payload.reserve(length);
    for (size_t i = 0; i < length; ++i) {
        if ((rand() % 100) < malicious_percent) {
            // Malicious/Encoded part
            const char* bad_chars[] = {"%20", "%27", "<script>", "../"};
            payload += bad_chars[rand() % 4];
        } else {
            // Normal part
            payload += (char)('a' + (rand() % 26));
        }
    }
    // Truncate to exact length if overshot
    if (payload.length() > length) {
        payload.resize(length);
    }
    return payload;
}

static void BM_Synthetic_BranchPenalty(benchmark::State& state) {
    size_t payload_size = 1024;
    int malicious_percent = state.range(0);
    std::string payload = generate_synthetic_payload(payload_size, malicious_percent);

    luminawaf_init_worker(1);

    PmuProfiler pmu;

    for (auto _ : state) {
        pmu.start();
        
        LuminaResult res;
        luminawaf_inspect_request(reinterpret_cast<const unsigned char*>(payload.c_str()), payload.length(), &res);
        
        // Prevent compiler optimization
        benchmark::DoNotOptimize(res);
        
        pmu.stop();
    }

    state.SetBytesProcessed(int64_t(state.iterations()) * int64_t(payload.length()));
    pmu.report_to_benchmark(state);
}

// Test scaled malicious saturation from 0% to 100%
BENCHMARK(BM_Synthetic_BranchPenalty)->Arg(0)->Arg(25)->Arg(50)->Arg(100);

BENCHMARK_MAIN();
