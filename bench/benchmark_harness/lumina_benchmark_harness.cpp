#include <benchmark/benchmark.h>
#include <dlfcn.h>
#include <modsecurity/intervention.h>
#include <modsecurity/modsecurity.h>
#include <modsecurity/rules_set.h>
#include <modsecurity/transaction.h>

#include <array>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <string>

#include "benchmark_harness_v1_workload.h"
#include "luminawaf.h"

#ifndef LUMINA_BENCH_V1_DEFAULT_MODSEC_CONFIG
#define LUMINA_BENCH_V1_DEFAULT_MODSEC_CONFIG "tests/eval_suite/modsec_crs_pl2.conf"
#endif

namespace {

constexpr char kMethod[] = "GET";
constexpr char kProtocol[] = "HTTP/1.1";
constexpr char kProtocolToken[] = "1.1";
constexpr char kPath[] = "/products/search";
constexpr char kCleanQuery[] = "q=desk-lamp&page=1&sort=asc";
constexpr char kAttackQuery[] = "q=1%27%20OR%201%3D1--&page=1";
constexpr char kHostName[] = "Host";
constexpr char kHostValue[] = "benchmark.local";
constexpr char kUserAgentName[] = "User-Agent";
constexpr char kUserAgentValue[] = "LuminaIronBenchmark/10";
constexpr char kAcceptName[] = "Accept";
constexpr char kAcceptValue[] = "text/html,application/xhtml+xml";

struct Request {
    std::string query;
    std::string uri;
    std::string request_line;
    bool expected_block;
};

Request make_request(bool attack) {
    Request request;
    request.query = attack ? kAttackQuery : kCleanQuery;
    request.uri = std::string(kPath) + "?" + request.query;
    request.request_line = std::string(kMethod) + " " + request.uri + " " + kProtocol;
    request.expected_block = attack;
    return request;
}

void add_var(LuminaBundle *bundle, const unsigned char *value, size_t length,
             LuminaVarType type, uint32_t scope, uint32_t header_mask,
             uint64_t collection_mask, const unsigned char *name = nullptr,
             size_t name_length = 0) {
    BundleVar &var = bundle->vars[bundle->count++];
    var.ptr = value;
    var.len = length;
    var.var_type = static_cast<uint8_t>(type);
    var.scope = scope;
    var.header_mask = header_mask;
    var.collection_mask = collection_mask;
    var.name = name;
    var.name_len = name_length;
}

LuminaBundle make_lumina_bundle(const Request &request) {
    LuminaBundle bundle{};
    add_var(&bundle, reinterpret_cast<const unsigned char *>(request.uri.data()),
            request.uri.size(), LUMINA_VAR_URI, LUMINA_SCOPE_URI, 0, 0);
    add_var(&bundle, reinterpret_cast<const unsigned char *>(request.query.data()),
            request.query.size(), LUMINA_VAR_ARGS, LUMINA_SCOPE_URI, 0,
            LUMINA_COL_ARGS);
    add_var(&bundle, reinterpret_cast<const unsigned char *>(kHostValue),
            sizeof(kHostValue) - 1, LUMINA_VAR_HDR, LUMINA_SCOPE_HEADERS,
            LUMINA_HDR_HOST, LUMINA_COL_REQUEST_HEADERS,
            reinterpret_cast<const unsigned char *>(kHostName), sizeof(kHostName) - 1);
    add_var(&bundle, reinterpret_cast<const unsigned char *>(kUserAgentValue),
            sizeof(kUserAgentValue) - 1, LUMINA_VAR_HDR, LUMINA_SCOPE_HEADERS,
            LUMINA_HDR_USER_AGENT, LUMINA_COL_REQUEST_HEADERS,
            reinterpret_cast<const unsigned char *>(kUserAgentName),
            sizeof(kUserAgentName) - 1);
    add_var(&bundle, reinterpret_cast<const unsigned char *>(kAcceptValue),
            sizeof(kAcceptValue) - 1, LUMINA_VAR_HDR, LUMINA_SCOPE_HEADERS,
            LUMINA_HDR_ACCEPT, LUMINA_COL_REQUEST_HEADERS,
            reinterpret_cast<const unsigned char *>(kAcceptName), sizeof(kAcceptName) - 1);

    bundle.hdr_presence_mask = LUMINA_HDR_HOST | LUMINA_HDR_USER_AGENT | LUMINA_HDR_ACCEPT;
    bundle.req_method = reinterpret_cast<const unsigned char *>(kMethod);
    bundle.req_method_len = sizeof(kMethod) - 1;
    bundle.req_line = reinterpret_cast<const unsigned char *>(request.request_line.data());
    bundle.req_line_len = request.request_line.size();
    bundle.user_agent = reinterpret_cast<const unsigned char *>(kUserAgentValue);
    bundle.user_agent_len = sizeof(kUserAgentValue) - 1;
    bundle.req_protocol = reinterpret_cast<const unsigned char *>(kProtocol);
    bundle.req_protocol_len = sizeof(kProtocol) - 1;
    bundle.req_filename = reinterpret_cast<const unsigned char *>(kPath);
    bundle.req_filename_len = sizeof(kPath) - 1;
    bundle.req_basename = reinterpret_cast<const unsigned char *>("search");
    bundle.req_basename_len = sizeof("search") - 1;
    bundle.hdr_host_count = 1;
    bundle.hdr_user_agent_count = 1;
    return bundle;
}

int run_lumina(const Request &request) {
    LuminaBundle bundle = make_lumina_bundle(request);
    LuminaRuleState rule_state{};
    LuminaResult result{};
    const int rc = luminawaf_inspect_bundle(&bundle, &rule_state, &result);
    return rc == 0 && result.threat_level != 0;
}

struct RotationRequest {
    const iron_v10_workload::Request *descriptor;
    std::string uri;
    std::string request_line;
    std::string basename;
};

uint32_t header_mask(const char *name) {
    if (std::strcmp(name, "Host") == 0) return LUMINA_HDR_HOST;
    if (std::strcmp(name, "User-Agent") == 0) return LUMINA_HDR_USER_AGENT;
    if (std::strcmp(name, "Accept") == 0) return LUMINA_HDR_ACCEPT;
    if (std::strcmp(name, "Content-Type") == 0) return LUMINA_HDR_CONTENT_TYPE;
    if (std::strcmp(name, "Accept-Encoding") == 0) return LUMINA_HDR_ACCEPT_ENCODING;
    if (std::strcmp(name, "Cookie") == 0) return LUMINA_HDR_COOKIE;
    if (std::strcmp(name, "Referer") == 0) return LUMINA_HDR_REFERER;
    if (std::strcmp(name, "Range") == 0) return LUMINA_HDR_RANGE;
    return 0;
}

RotationRequest make_rotation_request(const iron_v10_workload::Request &source) {
    RotationRequest request{&source, source.path, {}, {}};
    if (source.query[0] != '\0') {
        request.uri += "?";
        request.uri += source.query;
    }
    request.request_line = std::string(source.method) + " " + request.uri + " " + source.protocol;
    const char *slash = std::strrchr(source.path, '/');
    request.basename = slash != nullptr ? slash + 1 : source.path;
    return request;
}

using RotationRequests = std::array<RotationRequest, iron_v10_workload::kAllowRequestCount>;

RotationRequests make_rotation_requests() {
    RotationRequests requests{
        make_rotation_request(iron_v10_workload::kAllowRequests[0]),
        make_rotation_request(iron_v10_workload::kAllowRequests[1]),
        make_rotation_request(iron_v10_workload::kAllowRequests[2]),
        make_rotation_request(iron_v10_workload::kAllowRequests[3]),
        make_rotation_request(iron_v10_workload::kAllowRequests[4]),
        make_rotation_request(iron_v10_workload::kAllowRequests[5]),
    };
    static_assert(iron_v10_workload::kAllowRequestCount == 6,
                  "V1.0 Protocol overhead rotation contract requires exactly six allow requests");
    return requests;
}

LuminaBundle make_rotation_bundle(const RotationRequest &request) {
    const auto &source = *request.descriptor;
    LuminaBundle bundle{};
    add_var(&bundle, reinterpret_cast<const unsigned char *>(request.uri.data()),
            request.uri.size(), LUMINA_VAR_URI, LUMINA_SCOPE_URI, 0, 0);
    add_var(&bundle, reinterpret_cast<const unsigned char *>(source.query),
            std::strlen(source.query), LUMINA_VAR_ARGS, LUMINA_SCOPE_URI, 0,
            LUMINA_COL_ARGS);
    for (std::size_t index = 0; index < source.header_count; ++index) {
        const auto &header = source.headers[index];
        const uint32_t mask = header_mask(header.name);
        add_var(&bundle, reinterpret_cast<const unsigned char *>(header.value),
                std::strlen(header.value),
                mask == LUMINA_HDR_COOKIE ? LUMINA_VAR_COOKIE : LUMINA_VAR_HDR,
                LUMINA_SCOPE_HEADERS, mask,
                mask == LUMINA_HDR_COOKIE ? LUMINA_COL_REQUEST_COOKIES
                                          : LUMINA_COL_REQUEST_HEADERS,
                reinterpret_cast<const unsigned char *>(header.name),
                std::strlen(header.name));
        bundle.hdr_presence_mask |= mask;
        if (mask == LUMINA_HDR_HOST) ++bundle.hdr_host_count;
        if (mask == LUMINA_HDR_USER_AGENT) {
            ++bundle.hdr_user_agent_count;
            bundle.user_agent = reinterpret_cast<const unsigned char *>(header.value);
            bundle.user_agent_len = std::strlen(header.value);
        }
        if (mask == LUMINA_HDR_CONTENT_TYPE) ++bundle.hdr_content_type_count;
    }
    bundle.req_method = reinterpret_cast<const unsigned char *>(source.method);
    bundle.req_method_len = std::strlen(source.method);
    bundle.req_line = reinterpret_cast<const unsigned char *>(request.request_line.data());
    bundle.req_line_len = request.request_line.size();
    bundle.req_protocol = reinterpret_cast<const unsigned char *>(source.protocol);
    bundle.req_protocol_len = std::strlen(source.protocol);
    bundle.req_filename = reinterpret_cast<const unsigned char *>(source.path);
    bundle.req_filename_len = std::strlen(source.path);
    bundle.req_basename = reinterpret_cast<const unsigned char *>(request.basename.data());
    bundle.req_basename_len = request.basename.size();
    return bundle;
}

bool inspect_rotation_bundle(const LuminaBundle &source) {
    LuminaBundle bundle = source;
    LuminaRuleState rule_state{};
    LuminaResult result{};
    const int rc = luminawaf_inspect_bundle(&bundle, &rule_state, &result);
    return rc == 0 && result.threat_level == 0;
}

bool rotation_preflight(const RotationRequests &requests) {
    for (const auto &request : requests) {
        if (!inspect_rotation_bundle(make_rotation_bundle(request))) return false;
    }
    return true;
}

void set_rotation_bytes(benchmark::State &state, const RotationRequests &requests) {
    std::size_t bytes = 0;
    for (const auto &request : requests) bytes += request.uri.size();
    state.SetBytesProcessed(static_cast<int64_t>(
        state.iterations() * bytes / requests.size()));
}

void BM_Lumina_BundleBuild_Rotation(benchmark::State &state) {
    const RotationRequests requests = make_rotation_requests();
    std::size_t index = 0;
    for (auto _ : state) {
        LuminaBundle bundle = make_rotation_bundle(requests[index]);
        benchmark::DoNotOptimize(bundle);
        benchmark::ClobberMemory();
        index = (index + 1) % requests.size();
    }
    set_rotation_bytes(state, requests);
}

void BM_Lumina_InspectPrebuilt_Rotation(benchmark::State &state) {
    const RotationRequests requests = make_rotation_requests();
    std::array<LuminaBundle, iron_v10_workload::kAllowRequestCount> bundles{};
    for (std::size_t index = 0; index < bundles.size(); ++index) {
        bundles[index] = make_rotation_bundle(requests[index]);
    }
    if (!rotation_preflight(requests)) {
        state.SkipWithError("LuminaWAF allow-rotation correctness preflight failed");
        return;
    }
    std::size_t index = 0;
    for (auto _ : state) {
        LuminaBundle bundle = bundles[index];
        LuminaRuleState rule_state{};
        LuminaResult result{};
        int rc = luminawaf_inspect_bundle(&bundle, &rule_state, &result);
        benchmark::DoNotOptimize(rc);
        benchmark::DoNotOptimize(result.threat_level);
        benchmark::ClobberMemory();
        index = (index + 1) % bundles.size();
    }
    set_rotation_bytes(state, requests);
}

void BM_Lumina_FullDirect_Rotation(benchmark::State &state) {
    const RotationRequests requests = make_rotation_requests();
    if (!rotation_preflight(requests)) {
        state.SkipWithError("LuminaWAF allow-rotation correctness preflight failed");
        return;
    }
    std::size_t index = 0;
    for (auto _ : state) {
        LuminaBundle bundle = make_rotation_bundle(requests[index]);
        LuminaRuleState rule_state{};
        LuminaResult result{};
        int rc = luminawaf_inspect_bundle(&bundle, &rule_state, &result);
        benchmark::DoNotOptimize(rc);
        benchmark::DoNotOptimize(result.threat_level);
        benchmark::ClobberMemory();
        index = (index + 1) % requests.size();
    }
    set_rotation_bytes(state, requests);
}

class ModSecurityEngine {
  public:
    ModSecurityEngine() {
        engine_.setServerLogCb([](void *, const void *) {});
        const char *configured = std::getenv("LUMINA_BENCH_V1_MODSEC_CONFIG");
        config_ = configured != nullptr ? configured : LUMINA_BENCH_V1_DEFAULT_MODSEC_CONFIG;
        if (rules_.loadFromUri(config_.c_str()) < 0) {
            error_ = "failed to load ModSecurity config: " + config_;
        }
    }

    bool available() const { return error_.empty(); }
    const std::string &error() const { return error_; }

    int run(const Request &request) {
        modsecurity::Transaction transaction(&engine_, &rules_, nullptr);
        transaction.processConnection("127.0.0.1", 12345, "127.0.0.1", 8080);
        if (intervention_blocked(transaction)) return 1;

        transaction.processURI(request.uri.c_str(), kMethod, kProtocolToken);
        if (intervention_blocked(transaction)) return 1;

        transaction.addRequestHeader(kHostName, kHostValue);
        transaction.addRequestHeader(kUserAgentName, kUserAgentValue);
        transaction.addRequestHeader(kAcceptName, kAcceptValue);
        transaction.processRequestHeaders();
        if (intervention_blocked(transaction)) return 1;

        transaction.processRequestBody();
        return intervention_blocked(transaction) ? 1 : 0;
    }

  private:
    static bool intervention_blocked(modsecurity::Transaction &transaction) {
        modsecurity::ModSecurityIntervention intervention;
        modsecurity::intervention::clean(&intervention);
        const bool blocked = transaction.intervention(&intervention)
            && intervention.disruptive != 0;
        modsecurity::intervention::free(&intervention);
        return blocked;
    }

    modsecurity::ModSecurity engine_;
    modsecurity::RulesSet rules_;
    std::string config_;
    std::string error_;
};

using coraza_handle_t = uintptr_t;
struct CorazaIntervention {
    char *action;
    int status;
    int pause;
    int disruptive;
    char *data;
    int rule_id;
};

class CorazaEngine {
  public:
    CorazaEngine() {
        const char *library = std::getenv("LUMINA_BENCH_V1_CORAZA_SO");
        const char *config = std::getenv("LUMINA_BENCH_V1_CORAZA_CONFIG");
        if (library == nullptr || config == nullptr) {
            error_ = "set LUMINA_BENCH_V1_CORAZA_SO and LUMINA_BENCH_V1_CORAZA_CONFIG";
            return;
        }
        library_ = dlopen(library, RTLD_NOW | RTLD_LOCAL);
        if (library_ == nullptr) {
            error_ = dlerror();
            return;
        }
        try {
            bind();
            const coraza_handle_t cfg = new_config_();
            if (cfg == 0 || rules_add_file_(cfg, config) != 0) {
                if (cfg != 0) free_config_(cfg);
                error_ = "failed to load Coraza config";
                return;
            }
            char *message = nullptr;
            waf_ = new_waf_(cfg, &message);
            free_config_(cfg);
            if (waf_ == 0) {
                error_ = message != nullptr ? message : "coraza_new_waf failed";
                if (message != nullptr) free_string_(message);
                return;
            }
            if (message != nullptr) free_string_(message);
        } catch (const std::exception &exception) {
            error_ = exception.what();
        }
    }

    ~CorazaEngine() {
        if (waf_ != 0 && free_waf_ != nullptr) free_waf_(waf_);
        if (library_ != nullptr) dlclose(library_);
    }

    bool available() const { return error_.empty() && waf_ != 0; }
    const std::string &error() const { return error_; }

    int run(const Request &request) {
        const coraza_handle_t transaction = new_transaction_(waf_);
        if (transaction == 0) return -1;
        process_connection_(transaction, "127.0.0.1", 12345, "127.0.0.1", 8080);
        if (intervention_blocked(transaction)) {
            free_transaction_(transaction);
            return 1;
        }

        process_uri_(transaction, request.uri.c_str(), kMethod, kProtocolToken);
        if (intervention_blocked(transaction)) {
            free_transaction_(transaction);
            return 1;
        }

        add_header_(transaction, kHostName, sizeof(kHostName) - 1, kHostValue,
                    sizeof(kHostValue) - 1);
        add_header_(transaction, kUserAgentName, sizeof(kUserAgentName) - 1,
                    kUserAgentValue, sizeof(kUserAgentValue) - 1);
        add_header_(transaction, kAcceptName, sizeof(kAcceptName) - 1, kAcceptValue,
                    sizeof(kAcceptValue) - 1);
        process_headers_(transaction);
        if (intervention_blocked(transaction)) {
            free_transaction_(transaction);
            return 1;
        }

        process_body_(transaction);
        const int blocked = intervention_blocked(transaction) ? 1 : 0;
        free_transaction_(transaction);
        return blocked;
    }

  private:
    bool intervention_blocked(coraza_handle_t transaction) const {
        CorazaIntervention *intervention = intervention_(transaction);
        // libcoraza's connector contract treats any non-200 intervention as
        // disruptive; the exported ABI currently leaves `disruptive` unset.
        const bool blocked = intervention != nullptr && intervention->status != 200;
        if (intervention != nullptr) free_intervention_(intervention);
        return blocked;
    }

    template <typename T> T symbol(const char *name) {
        void *address = dlsym(library_, name);
        if (address == nullptr) throw std::runtime_error(std::string("missing symbol: ") + name);
        return reinterpret_cast<T>(address);
    }

    void bind() {
        new_config_ = symbol<coraza_handle_t (*)()>("coraza_new_waf_config");
        rules_add_file_ = symbol<int (*)(coraza_handle_t, const char *)>("coraza_rules_add_file");
        free_config_ = symbol<int (*)(coraza_handle_t)>("coraza_free_waf_config");
        new_waf_ = symbol<coraza_handle_t (*)(coraza_handle_t, char **)>("coraza_new_waf");
        new_transaction_ = symbol<coraza_handle_t (*)(coraza_handle_t)>("coraza_new_transaction");
        process_connection_ = symbol<int (*)(coraza_handle_t, const char *, int, const char *, int)>("coraza_process_connection");
        process_uri_ = symbol<int (*)(coraza_handle_t, const char *, const char *, const char *)>("coraza_process_uri");
        add_header_ = symbol<int (*)(coraza_handle_t, const char *, int, const char *, int)>("coraza_add_request_header");
        process_headers_ = symbol<int (*)(coraza_handle_t)>("coraza_process_request_headers");
        process_body_ = symbol<int (*)(coraza_handle_t)>("coraza_process_request_body");
        intervention_ = symbol<CorazaIntervention *(*)(coraza_handle_t)>("coraza_intervention");
        free_intervention_ = symbol<int (*)(CorazaIntervention *)>("coraza_free_intervention");
        free_transaction_ = symbol<int (*)(coraza_handle_t)>("coraza_free_transaction");
        free_waf_ = symbol<int (*)(coraza_handle_t)>("coraza_free_waf");
        free_string_ = symbol<void (*)(char *)>("coraza_free_string");
    }

    void *library_ = nullptr;
    coraza_handle_t waf_ = 0;
    std::string error_;
    coraza_handle_t (*new_config_)() = nullptr;
    int (*rules_add_file_)(coraza_handle_t, const char *) = nullptr;
    int (*free_config_)(coraza_handle_t) = nullptr;
    coraza_handle_t (*new_waf_)(coraza_handle_t, char **) = nullptr;
    coraza_handle_t (*new_transaction_)(coraza_handle_t) = nullptr;
    int (*process_connection_)(coraza_handle_t, const char *, int, const char *, int) = nullptr;
    int (*process_uri_)(coraza_handle_t, const char *, const char *, const char *) = nullptr;
    int (*add_header_)(coraza_handle_t, const char *, int, const char *, int) = nullptr;
    int (*process_headers_)(coraza_handle_t) = nullptr;
    int (*process_body_)(coraza_handle_t) = nullptr;
    CorazaIntervention *(*intervention_)(coraza_handle_t) = nullptr;
    int (*free_intervention_)(CorazaIntervention *) = nullptr;
    int (*free_transaction_)(coraza_handle_t) = nullptr;
    int (*free_waf_)(coraza_handle_t) = nullptr;
    void (*free_string_)(char *) = nullptr;
};

void verify_or_skip(benchmark::State &state, const char *engine, int actual,
                    bool expected) {
    if (actual < 0 || static_cast<bool>(actual) != expected) {
        const std::string message = std::string(engine) + " correctness preflight failed";
        state.SkipWithError(message.c_str());
    }
}

void benchmark_lumina(benchmark::State &state, bool attack) {
    const Request request = make_request(attack);
    verify_or_skip(state, "LuminaWAF", run_lumina(request), request.expected_block);
    if (state.skipped()) return;
    for (auto _ : state) {
        int blocked = run_lumina(request);
        benchmark::DoNotOptimize(blocked);
        benchmark::ClobberMemory();
    }
    state.SetBytesProcessed(static_cast<int64_t>(state.iterations() * request.uri.size()));
}

void benchmark_modsecurity(benchmark::State &state, bool attack) {
    static ModSecurityEngine engine;
    if (!engine.available()) {
        state.SkipWithError(engine.error().c_str());
        return;
    }
    const Request request = make_request(attack);
    verify_or_skip(state, "ModSecurity", engine.run(request), request.expected_block);
    if (state.skipped()) return;
    for (auto _ : state) {
        int blocked = engine.run(request);
        benchmark::DoNotOptimize(blocked);
        benchmark::ClobberMemory();
    }
    state.SetBytesProcessed(static_cast<int64_t>(state.iterations() * request.uri.size()));
}

void benchmark_coraza(benchmark::State &state, bool attack) {
    static CorazaEngine engine;
    if (!engine.available()) {
        state.SkipWithError(engine.error().c_str());
        return;
    }
    const Request request = make_request(attack);
    verify_or_skip(state, "Coraza", engine.run(request), request.expected_block);
    if (state.skipped()) return;
    for (auto _ : state) {
        int blocked = engine.run(request);
        benchmark::DoNotOptimize(blocked);
        benchmark::ClobberMemory();
    }
    state.SetBytesProcessed(static_cast<int64_t>(state.iterations() * request.uri.size()));
}

void BM_Lumina_Clean(benchmark::State &state) { benchmark_lumina(state, false); }
void BM_Lumina_Attack(benchmark::State &state) { benchmark_lumina(state, true); }
void BM_ModSecurity_Clean(benchmark::State &state) { benchmark_modsecurity(state, false); }
void BM_ModSecurity_Attack(benchmark::State &state) { benchmark_modsecurity(state, true); }
void BM_Coraza_Clean(benchmark::State &state) { benchmark_coraza(state, false); }
void BM_Coraza_Attack(benchmark::State &state) { benchmark_coraza(state, true); }

BENCHMARK(BM_Lumina_Clean)->Name("FullTransaction/LuminaWAF/Allow")->Repetitions(10);
BENCHMARK(BM_Lumina_Attack)->Name("FullTransaction/LuminaWAF/Attack")->Repetitions(10);
BENCHMARK(BM_ModSecurity_Clean)->Name("FullTransaction/ModSecurity/Allow")->Repetitions(10);
BENCHMARK(BM_ModSecurity_Attack)->Name("FullTransaction/ModSecurity/Attack")->Repetitions(10);
BENCHMARK(BM_Coraza_Clean)->Name("FullTransaction/Coraza/Allow")->Repetitions(10);
BENCHMARK(BM_Coraza_Attack)->Name("FullTransaction/Coraza/Attack")->Repetitions(10);
BENCHMARK(BM_Lumina_BundleBuild_Rotation)
    ->Name("Overhead/LuminaWAF/BundleBuild/AllowRotation")->Repetitions(10);
BENCHMARK(BM_Lumina_InspectPrebuilt_Rotation)
    ->Name("Overhead/LuminaWAF/InspectPrebuilt/AllowRotation")->Repetitions(10);
BENCHMARK(BM_Lumina_FullDirect_Rotation)
    ->Name("Overhead/LuminaWAF/FullDirect/AllowRotation")->Repetitions(10);

}  // namespace

BENCHMARK_MAIN();
