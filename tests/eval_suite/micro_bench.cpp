#undef NDEBUG
#define NDEBUG 1
#include <benchmark/benchmark.h>
#include <modsecurity/modsecurity.h>
#include <modsecurity/rules_set.h>
#include <modsecurity/transaction.h>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <cstring>
#include <vector>
#if defined(__x86_64__) || defined(__i386__)
#include <immintrin.h>
#endif

#include "../../src/luminawaf.h"

extern "C" {
    int lumina_waf_scan(const unsigned char *str, size_t len);
    int lumina_scan_path(const unsigned char *str, size_t len);
    int lumina_pm_lfi_os_files(const unsigned char *data, size_t len);
    int lumina_pm_restricted_files(const unsigned char *data, size_t len);
}

// Global ModSecurity state
modsecurity::ModSecurity *modsec = nullptr;
modsecurity::RulesSet *rules = nullptr;

static void discard_modsec_log(void *, const void *) {}

static void SetupModSecurity() {
    if (!modsec) {
        modsec = new modsecurity::ModSecurity();
        modsec->setServerLogCb(discard_modsec_log);
        rules = new modsecurity::RulesSet();
        
        const char *config = std::getenv("LUMINA_BENCH_V1_MODSEC_CONFIG");
        if (config == nullptr || config[0] == '\0') {
            std::fprintf(stderr,
                         "LUMINA_BENCH_V1_MODSEC_CONFIG is required; run "
                         "bench/benchmark_harness/prepare_runtime.sh first\n");
            std::abort();
        }
        if (rules->loadFromUri(config) < 0) {
            std::fprintf(stderr, "Failed to load ModSecurity rules from %s\n", config);
            std::abort();
        }
    }
}

static void EvictPayloadFromCache(std::string &payload) {
#if defined(__x86_64__) || defined(__i386__)
    for (size_t i = 0; i < payload.size(); i += 64) {
        _mm_clflush(payload.data() + i);
    }
#else
    static thread_local std::vector<unsigned char> eviction(4U * 1024U * 1024U, 1U);
    unsigned int sum = 0;
    for (size_t i = 0; i < eviction.size(); i += 64) {
        sum += eviction[i];
    }
    benchmark::DoNotOptimize(sum);
#endif
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

static void BM_LuminaWAF_InspectRequestPathClean(benchmark::State& state) {
    size_t payload_len = state.range(0);
    std::string uri = "/products/" + std::string(payload_len, 'a');
    LuminaResult result{};
    luminawaf_init_worker(4096);

    for (auto _ : state) {
        LuminaRuleState state; memset(&state, 0, sizeof(state));
        int rc = luminawaf_inspect_request(
            reinterpret_cast<const unsigned char*>(uri.data()), uri.size(), &state, &result);
        benchmark::DoNotOptimize(rc);
        benchmark::DoNotOptimize(result.threat_level);
        benchmark::ClobberMemory();
    }
    state.SetBytesProcessed(int64_t(state.iterations()) * int64_t(uri.size()));
}

static void BM_LuminaWAF_InspectRequestQueryLikeClean(benchmark::State& state) {
    size_t payload_len = state.range(0);
    std::string uri = "/products/search?q=" + std::string(payload_len, 'A');
    LuminaResult result{};
    luminawaf_init_worker(4096);

    for (auto _ : state) {
        LuminaRuleState state; memset(&state, 0, sizeof(state));
        int rc = luminawaf_inspect_request(
            reinterpret_cast<const unsigned char*>(uri.data()), uri.size(), &state, &result);
        benchmark::DoNotOptimize(rc);
        benchmark::DoNotOptimize(result.threat_level);
        benchmark::ClobberMemory();
    }
    state.SetBytesProcessed(int64_t(state.iterations()) * int64_t(uri.size()));
}

static void BM_LuminaWAF_InspectRequestAttack(benchmark::State& state) {
    size_t payload_len = state.range(0);
    std::string uri = "/products/" + std::string(payload_len, 'a') + "/<script>alert(1)</script>";
    LuminaResult result{};
    luminawaf_init_worker(4096);

    for (auto _ : state) {
        LuminaRuleState state; memset(&state, 0, sizeof(state));
        int rc = luminawaf_inspect_request(
            reinterpret_cast<const unsigned char*>(uri.data()), uri.size(), &state, &result);
        benchmark::DoNotOptimize(rc);
        benchmark::DoNotOptimize(result.threat_level);
        benchmark::ClobberMemory();
    }
    state.SetBytesProcessed(int64_t(state.iterations()) * int64_t(uri.size()));
}

static void BM_LuminaWAF_InspectBufferArgsClean(benchmark::State& state) {
    size_t payload_len = state.range(0);
    std::string args = "q=" + std::string(payload_len, 'A') + "&page=1&sort=asc";
    LuminaResult result{};
    luminawaf_init_worker(4096);

    for (auto _ : state) {
        LuminaRuleState state_obj; memset(&state_obj, 0, sizeof(state_obj));
        int rc = luminawaf_inspect_buffer(
            reinterpret_cast<const unsigned char*>(args.data()), args.size(),
            LUMINA_SCOPE_URI, LUMINA_VAR_ARGS, &state_obj, &result);
        benchmark::DoNotOptimize(rc);
        benchmark::DoNotOptimize(result.threat_level);
        benchmark::ClobberMemory();
    }
    state.SetBytesProcessed(int64_t(state.iterations()) * int64_t(args.size()));
}

static void BM_LuminaWAF_InspectBufferArgsAttack(benchmark::State& state) {
    size_t payload_len = state.range(0);
    std::string args = "q=" + std::string(payload_len, 'A') + "&x=<script>alert(1)</script>";
    LuminaResult result{};
    luminawaf_init_worker(4096);

    for (auto _ : state) {
        LuminaRuleState state_obj; memset(&state_obj, 0, sizeof(state_obj));
        int rc = luminawaf_inspect_buffer(
            reinterpret_cast<const unsigned char*>(args.data()), args.size(),
            LUMINA_SCOPE_URI, LUMINA_VAR_ARGS, &state_obj, &result);
        benchmark::DoNotOptimize(rc);
        benchmark::DoNotOptimize(result.threat_level);
        benchmark::ClobberMemory();
    }
    state.SetBytesProcessed(int64_t(state.iterations()) * int64_t(args.size()));
}

static void BM_LuminaWAF_InspectBundleClean(benchmark::State& state) {
    size_t payload_len = state.range(0);
    std::string uri = "/products/search";
    std::string args = "q=" + std::string(payload_len, 'A') + "&page=1&sort=asc";
    std::string header = "accept: text/html\r\nuser-agent: LuminaBench/1\r\n";
    std::string body = "{\"search\":\"" + std::string(payload_len / 4, 'B') + "\"}";
    const unsigned char method[] = "GET";
    const unsigned char req_line[] = "GET /products/search?q=clean HTTP/1.1";
    const unsigned char ua[] = "LuminaBench/1";
    const unsigned char protocol[] = "HTTP/1.1";
    LuminaResult result{};
    luminawaf_init_worker(4096);

    LuminaBundle bundle{};
    bundle.count = 4;
    bundle.vars[0] = {reinterpret_cast<const unsigned char*>(uri.data()), uri.size(),
                      LUMINA_VAR_URI, LUMINA_SCOPE_URI, 0, 0, nullptr, 0};
    bundle.vars[1] = {reinterpret_cast<const unsigned char*>(args.data()), args.size(),
                      LUMINA_VAR_ARGS, LUMINA_SCOPE_URI, 0, LUMINA_COL_ARGS, nullptr, 0};
    bundle.vars[2] = {reinterpret_cast<const unsigned char*>(header.data()), header.size(),
                      LUMINA_VAR_HDR, LUMINA_SCOPE_HEADERS, 0,
                      LUMINA_COL_REQUEST_HEADERS, nullptr, 0};
    bundle.vars[3] = {reinterpret_cast<const unsigned char*>(body.data()), body.size(),
                      LUMINA_VAR_BODY, LUMINA_SCOPE_BODY | LUMINA_SCOPE_JSON, 0,
                      LUMINA_COL_REQUEST_BODY | LUMINA_COL_JSON, nullptr, 0};
    bundle.req_method = method;
    bundle.req_method_len = sizeof(method) - 1;
    bundle.req_line = req_line;
    bundle.req_line_len = sizeof(req_line) - 1;
    bundle.user_agent = ua;
    bundle.user_agent_len = sizeof(ua) - 1;
    bundle.req_protocol = protocol;
    bundle.req_protocol_len = sizeof(protocol) - 1;
    bundle.req_filename = reinterpret_cast<const unsigned char*>(uri.data());
    bundle.req_filename_len = uri.size();
    size_t basename_offset = uri.rfind('/') + 1;
    bundle.req_basename =
        reinterpret_cast<const unsigned char*>(uri.data() + basename_offset);
    bundle.req_basename_len = uri.size() - basename_offset;
    static const unsigned char processor[] = "JSON";
    bundle.reqbody_processor = processor;
    bundle.reqbody_processor_len = sizeof(processor) - 1;
    bundle.hdr_host_count = 1;
    bundle.hdr_user_agent_count = 1;

    for (auto _ : state) {
        LuminaRuleState state; memset(&state, 0, sizeof(state));
        int rc = luminawaf_inspect_bundle(&bundle, &state, &result);
        benchmark::DoNotOptimize(rc);
        benchmark::DoNotOptimize(result.threat_level);
        benchmark::ClobberMemory();
    }
    state.SetBytesProcessed(int64_t(state.iterations()) *
                            int64_t(uri.size() + args.size() + header.size() + body.size()));
}

static void BM_LuminaWAF_InspectBundleAttack(benchmark::State& state) {
    size_t payload_len = state.range(0);
    std::string uri = "/products/search";
    std::string args = "q=" + std::string(payload_len, 'A') + "&x=<script>alert(1)</script>";
    std::string header = "accept: text/html\r\nuser-agent: LuminaBench/1\r\n";
    std::string body = "{\"search\":\"normal\"}";
    const unsigned char method[] = "GET";
    const unsigned char req_line[] = "GET /products/search?q=attack HTTP/1.1";
    const unsigned char ua[] = "LuminaBench/1";
    const unsigned char protocol[] = "HTTP/1.1";
    LuminaResult result{};
    luminawaf_init_worker(4096);

    LuminaBundle bundle{};
    bundle.count = 4;
    bundle.vars[0] = {reinterpret_cast<const unsigned char*>(uri.data()), uri.size(),
                      LUMINA_VAR_URI, LUMINA_SCOPE_URI, 0, 0, nullptr, 0};
    bundle.vars[1] = {reinterpret_cast<const unsigned char*>(args.data()), args.size(),
                      LUMINA_VAR_ARGS, LUMINA_SCOPE_URI, 0, LUMINA_COL_ARGS, nullptr, 0};
    bundle.vars[2] = {reinterpret_cast<const unsigned char*>(header.data()), header.size(),
                      LUMINA_VAR_HDR, LUMINA_SCOPE_HEADERS, 0,
                      LUMINA_COL_REQUEST_HEADERS, nullptr, 0};
    bundle.vars[3] = {reinterpret_cast<const unsigned char*>(body.data()), body.size(),
                      LUMINA_VAR_BODY, LUMINA_SCOPE_BODY | LUMINA_SCOPE_JSON, 0,
                      LUMINA_COL_REQUEST_BODY | LUMINA_COL_JSON, nullptr, 0};
    bundle.req_method = method;
    bundle.req_method_len = sizeof(method) - 1;
    bundle.req_line = req_line;
    bundle.req_line_len = sizeof(req_line) - 1;
    bundle.user_agent = ua;
    bundle.user_agent_len = sizeof(ua) - 1;
    bundle.req_protocol = protocol;
    bundle.req_protocol_len = sizeof(protocol) - 1;
    bundle.req_filename = reinterpret_cast<const unsigned char*>(uri.data());
    bundle.req_filename_len = uri.size();
    size_t basename_offset = uri.rfind('/') + 1;
    bundle.req_basename =
        reinterpret_cast<const unsigned char*>(uri.data() + basename_offset);
    bundle.req_basename_len = uri.size() - basename_offset;
    static const unsigned char processor[] = "JSON";
    bundle.reqbody_processor = processor;
    bundle.reqbody_processor_len = sizeof(processor) - 1;
    bundle.hdr_host_count = 1;
    bundle.hdr_user_agent_count = 1;

    for (auto _ : state) {
        LuminaRuleState state; memset(&state, 0, sizeof(state));
        int rc = luminawaf_inspect_bundle(&bundle, &state, &result);
        benchmark::DoNotOptimize(rc);
        benchmark::DoNotOptimize(result.threat_level);
        benchmark::ClobberMemory();
    }
    state.SetBytesProcessed(int64_t(state.iterations()) *
                            int64_t(uri.size() + args.size() + header.size() + body.size()));
}

static void BM_LuminaWAF_PathScannerClean(benchmark::State& state) {
    size_t payload_len = state.range(0);
    std::string uri = "/products/" + std::string(payload_len, 'a');

    for (auto _ : state) {
        int threat = lumina_scan_path(
            reinterpret_cast<const unsigned char*>(uri.data()), uri.size());
        benchmark::DoNotOptimize(threat);
    }
    state.SetBytesProcessed(int64_t(state.iterations()) * int64_t(uri.size()));
}

static void BM_LuminaWAF_PMRestrictedClean(benchmark::State& state) {
    size_t payload_len = state.range(0);
    std::string uri = "/products/" + std::string(payload_len, 'a');

    for (auto _ : state) {
        int threat = lumina_pm_restricted_files(
            reinterpret_cast<const unsigned char*>(uri.data()), uri.size());
        benchmark::DoNotOptimize(threat);
    }
    state.SetBytesProcessed(int64_t(state.iterations()) * int64_t(uri.size()));
}

static void BM_LuminaWAF_PMLfiClean(benchmark::State& state) {
    size_t payload_len = state.range(0);
    std::string value = "q=" + std::string(payload_len, 'a') + "&page=1";

    for (auto _ : state) {
        int threat = lumina_pm_lfi_os_files(
            reinterpret_cast<const unsigned char*>(value.data()), value.size());
        benchmark::DoNotOptimize(threat);
    }
    state.SetBytesProcessed(int64_t(state.iterations()) * int64_t(value.size()));
}

static void BM_LuminaWAF_PMRestrictedAttack(benchmark::State& state) {
    std::string uri = "/.git/config";

    for (auto _ : state) {
        int threat = lumina_pm_restricted_files(
            reinterpret_cast<const unsigned char*>(uri.data()), uri.size());
        benchmark::DoNotOptimize(threat);
    }
    state.SetBytesProcessed(int64_t(state.iterations()) * int64_t(uri.size()));
}

static void BM_LuminaWAF_ColdCache(benchmark::State& state) {
    size_t payload_len = state.range(0);
    std::string payload(payload_len, 'A');
    payload += "<script>alert(1);</script>";
    
    for (auto _ : state) {
        state.PauseTiming();
        std::string cold_payload = payload;
        EvictPayloadFromCache(cold_payload);
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

    // Move URI allocation outside the benchmark loop to provide a fair fight
    std::string uri = "/test?args=" + payload;

    for (auto _ : state) {
        modsecurity::Transaction *trans = new modsecurity::Transaction(modsec, rules, nullptr);
        trans->processConnection("127.0.0.1", 12345, "127.0.0.1", 80);
        trans->addRequestHeader("Host", "localhost");
        trans->addRequestHeader("User-Agent", "LuminaIronBenchmark/9");
        trans->processURI(uri.c_str(), "GET", "1.1");
        trans->processRequestHeaders();
        trans->processRequestBody();
        benchmark::DoNotOptimize(trans);
        delete trans;
    }
    state.SetBytesProcessed(int64_t(state.iterations()) * int64_t(payload.size()));
}

BENCHMARK(BM_LuminaWAF_WarmCache)->Arg(1024)->Repetitions(10);
BENCHMARK(BM_LuminaWAF_InspectRequestPathClean)->Arg(64)->Arg(1024)->Repetitions(10);
BENCHMARK(BM_LuminaWAF_InspectRequestQueryLikeClean)->Arg(1024)->Repetitions(10);
BENCHMARK(BM_LuminaWAF_InspectRequestAttack)->Arg(1024)->Repetitions(10);
BENCHMARK(BM_LuminaWAF_InspectBufferArgsClean)->Arg(1024)->Repetitions(10);
BENCHMARK(BM_LuminaWAF_InspectBufferArgsAttack)->Arg(1024)->Repetitions(10);
BENCHMARK(BM_LuminaWAF_InspectBundleClean)->Arg(1024)->Repetitions(10);
BENCHMARK(BM_LuminaWAF_InspectBundleAttack)->Arg(1024)->Repetitions(10);
BENCHMARK(BM_LuminaWAF_PathScannerClean)->Arg(64)->Arg(1024)->Repetitions(10);
BENCHMARK(BM_LuminaWAF_PMRestrictedClean)->Arg(64)->Arg(1024)->Repetitions(10);
BENCHMARK(BM_LuminaWAF_PMLfiClean)->Arg(1024)->Repetitions(10);
BENCHMARK(BM_LuminaWAF_PMRestrictedAttack)->Repetitions(10);
BENCHMARK(BM_LuminaWAF_ColdCache)->Arg(1024)->Repetitions(10);
BENCHMARK(BM_ModSecurity_WarmCache)->Arg(1024)->Repetitions(10);

BENCHMARK_MAIN();
