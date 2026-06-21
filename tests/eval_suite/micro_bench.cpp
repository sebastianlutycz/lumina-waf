#undef NDEBUG
#define NDEBUG 1
#include <benchmark/benchmark.h>
#include <modsecurity/modsecurity.h>
#include <modsecurity/rules_set.h>
#include <modsecurity/transaction.h>
#include <string>

extern "C" {
    int lumina_waf_scan(const unsigned char *str, size_t len);
}

// Global ModSecurity state
modsecurity::ModSecurity *modsec = nullptr;
modsecurity::RulesSet *rules = nullptr;

static void SetupModSecurity() {
    if (!modsec) {
        modsec = new modsecurity::ModSecurity();
        rules = new modsecurity::RulesSet();
        
        // Load the 1000 generated rules
        if (rules->loadFromUri("/home/sebastian/workspace/lumina-waf/tests/eval_suite/modsec_1000_rules.conf") < 0) {
            fprintf(stderr, "Failed to load ModSec rules from URI\n");
        }
    }
}

static void BM_LuminaWAF_WarmCache(benchmark::State& state) {
    size_t payload_len = state.range(0);
    std::string payload(payload_len, 'A');
    payload += "<script>alert(1);</script>";
    
    for (auto _ : state) {
        int threat = lumina_waf_scan(reinterpret_cast<const unsigned char*>(payload.data()), payload.size());
        benchmark::DoNotOptimize(threat);
    }
    state.SetBytesProcessed(int64_t(state.iterations()) * int64_t(payload.size()));
}

static void BM_LuminaWAF_ColdCache(benchmark::State& state) {
    size_t payload_len = state.range(0);
    std::string payload(payload_len, 'A');
    payload += "<script>alert(1);</script>";
    
    for (auto _ : state) {
        state.PauseTiming();
        std::string cold_payload = payload;
        // flush cache for the payload
        for (size_t i = 0; i < cold_payload.size(); i += 64) {
            __builtin_ia32_clflush(&cold_payload[i]);
        }
        state.ResumeTiming();
        
        int threat = lumina_waf_scan(reinterpret_cast<const unsigned char*>(cold_payload.data()), cold_payload.size());
        benchmark::DoNotOptimize(threat);
        benchmark::ClobberMemory();
    }
    state.SetBytesProcessed(int64_t(state.iterations()) * int64_t(payload.size()));
}

static void BM_ModSecurity_WarmCache(benchmark::State& state) {
    SetupModSecurity();
    size_t payload_len = state.range(0);
    std::string payload(payload_len, 'A');
    payload += "<script>alert(1);</script>";

    for (auto _ : state) {
        modsecurity::Transaction *trans = new modsecurity::Transaction(modsec, rules, nullptr);
        trans->processConnection("127.0.0.1", 12345, "127.0.0.1", 80);
        std::string uri = "http://localhost/test?args=" + payload;
        trans->processURI(uri.c_str(), "GET", "1.1");
        trans->processRequestHeaders();
        trans->processRequestBody();
        benchmark::DoNotOptimize(trans);
        delete trans;
    }
    state.SetBytesProcessed(int64_t(state.iterations()) * int64_t(payload.size()));
}

BENCHMARK(BM_LuminaWAF_WarmCache)->Arg(1024)->Repetitions(10);
BENCHMARK(BM_LuminaWAF_ColdCache)->Arg(1024)->Repetitions(10);
BENCHMARK(BM_ModSecurity_WarmCache)->Arg(1024)->Repetitions(10);

BENCHMARK_MAIN();
