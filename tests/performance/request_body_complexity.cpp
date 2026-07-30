#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>
#include <time.h>
#include <vector>

#include "luminawaf.h"
#include "generated/crs_short_rules.h"

extern "C" {
int lumina_dispatch_rule(
    int idx, const unsigned char *data, size_t len, size_t offset);
void lumina_reset_transform_view_cache(void);
}

namespace {

constexpr std::array<size_t, 6> kSizes = {
    4u << 10, 8u << 10, 16u << 10, 32u << 10, 64u << 10, 128u << 10,
};
constexpr unsigned kSamples = 7;
constexpr unsigned kIterations = 3;
/*
 * The asymptotic gate intentionally includes a small measurement margin over
 * the 2.20 target. It rejects the former 3.8-4.0x quadratic growth while
 * tolerating clock-tick and cache-boundary noise on this explicit CPU-time
 * benchmark. The adjacent limit is only a coarse outlier guard; the
 * two-doubling geometric ratio is the authoritative complexity check.
 */
constexpr double kMaximumDoublingRatio = 2.25;
constexpr double kMaximumAdjacentRatio = 2.60;

struct Fixture {
    const char *name;
    const char *pattern;
    bool varied;
};

constexpr std::array<Fixture, 4> kFixtures = {{
    {"varied", nullptr, true},
    {"dash", "bcdf-ghjklmnpq_vwxyz", false},
    {"comments", "bcdf/*ghj*/klmnpq_vwxyz", false},
    {"encoded", "bcdf%2dghj%5fklmnpq_vwxyz", false},
}};

uint64_t thread_cpu_ns() {
    timespec ts{};
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts);
    return static_cast<uint64_t>(ts.tv_sec) * UINT64_C(1000000000) +
           static_cast<uint64_t>(ts.tv_nsec);
}

std::string make_json(size_t target_size, const Fixture &fixture) {
    static constexpr char kPrefix[] = "{\"payload\":\"";
    static constexpr char kSuffix[] = "\"}";
    std::string body(kPrefix);
    if (fixture.varied) {
        static constexpr char kAlphabet[] = "bcdfghjklmnpqvwxyz";
        uint32_t state = UINT32_C(0x9e3779b9);
        while (body.size() + sizeof(kSuffix) - 1 < target_size) {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            body.push_back(kAlphabet[state % (sizeof(kAlphabet) - 1u)]);
        }
        body.append(kSuffix);
        return body;
    }
    const char *pattern = fixture.pattern;
    const size_t pattern_len = std::strlen(pattern);
    while (body.size() + pattern_len + sizeof(kSuffix) - 1 <= target_size)
        body.append(pattern, pattern_len);
    while (body.size() + sizeof(kSuffix) - 1 < target_size)
        body.push_back('q');
    body.append(kSuffix);
    return body;
}

std::string make_9341xx_transform_stress(size_t target_size) {
    static constexpr char kEncoded[] = "%59%6d%4e%6b";
    std::string value;
    value.reserve(target_size);
    while (value.size() + sizeof(kEncoded) - 1 <= target_size)
        value.append(kEncoded, sizeof(kEncoded) - 1);
    value.append(target_size - value.size(), 'q');
    return value;
}

std::string make_xml(size_t target_size, bool with_doctype) {
    const char *prefix = with_doctype
                             ? "<!DOCTYPE root><root><payload>"
                             : "<root><payload>";
    static constexpr char kSuffix[] = "</payload></root>";
    std::string body(prefix);
    body.reserve(target_size);
    body.append(
        target_size - body.size() - (sizeof(kSuffix) - 1), 'q');
    body.append(kSuffix);
    return body;
}

int find_rule_index(int rule_id) {
    for (int idx = 0; idx < LUMINA_SHORT_RULE_COUNT; ++idx)
        if (g_short_rule_id[idx] == rule_id) return idx;
    return -1;
}

int dispatch_9341xx(const std::string &value) {
    static const std::array<int, 3> indices = {
        find_rule_index(934100),
        find_rule_index(934160),
        find_rule_index(934101),
    };
    if (std::any_of(indices.begin(), indices.end(),
                    [](int idx) { return idx < 0; }))
        return -1;
    lumina_reset_transform_view_cache();
    int result = 0;
    for (int idx : indices)
        result ^= lumina_dispatch_rule(
            idx,
            reinterpret_cast<const unsigned char *>(value.data()),
            value.size(), 0);
    return result;
}

int inspect_structured(
        const std::string &body, const unsigned char *processor,
        size_t processor_len, const unsigned char *content_type,
        size_t content_type_len, uint32_t body_scope,
        uint64_t body_collection) {
    static constexpr unsigned char kMethod[] = "POST";
    static constexpr unsigned char kPath[] = "/api/body";
    static constexpr unsigned char kRequestLine[] =
        "POST /api/body HTTP/1.1";
    static constexpr unsigned char kProtocol[] = "HTTP/1.1";
    static constexpr unsigned char kUserAgent[] = "lumina-complexity-gate";
    static constexpr unsigned char kHostName[] = "Host";
    static constexpr unsigned char kHost[] = "benchmark.local";
    static constexpr unsigned char kUserAgentName[] = "User-Agent";
    static constexpr unsigned char kContentTypeName[] = "Content-Type";
    static constexpr unsigned char kContentLengthName[] = "Content-Length";

    LuminaBundle bundle{};
    LuminaRuleState state{};
    LuminaResult result{};
    const std::string content_length = std::to_string(body.size());

    auto add_var = [&bundle](
            const unsigned char *data, size_t len, LuminaVarType type,
            uint32_t scope, uint32_t header_mask, uint64_t collection_mask,
            const unsigned char *name = nullptr, size_t name_len = 0) {
        BundleVar &var = bundle.vars[bundle.count++];
        var.ptr = data;
        var.len = len;
        var.var_type = static_cast<uint8_t>(type);
        var.scope = scope;
        var.header_mask = header_mask;
        var.collection_mask = collection_mask;
        var.name = name;
        var.name_len = name_len;
    };

    add_var(kPath, sizeof(kPath) - 1, LUMINA_VAR_URI, LUMINA_SCOPE_URI,
            0, 0);
    add_var(kHost, sizeof(kHost) - 1, LUMINA_VAR_HDR, LUMINA_SCOPE_HEADERS,
            LUMINA_HDR_HOST, LUMINA_COL_REQUEST_HEADERS,
            kHostName, sizeof(kHostName) - 1);
    add_var(kUserAgent, sizeof(kUserAgent) - 1, LUMINA_VAR_HDR,
            LUMINA_SCOPE_HEADERS, LUMINA_HDR_USER_AGENT,
            LUMINA_COL_REQUEST_HEADERS,
            kUserAgentName, sizeof(kUserAgentName) - 1);
    add_var(content_type, content_type_len, LUMINA_VAR_HDR,
            LUMINA_SCOPE_HEADERS, LUMINA_HDR_CONTENT_TYPE,
            LUMINA_COL_REQUEST_HEADERS,
            kContentTypeName, sizeof(kContentTypeName) - 1);
    add_var(
        reinterpret_cast<const unsigned char *>(content_length.data()),
        content_length.size(), LUMINA_VAR_HDR, LUMINA_SCOPE_HEADERS,
        LUMINA_HDR_CONTENT_LENGTH, LUMINA_COL_REQUEST_HEADERS,
        kContentLengthName, sizeof(kContentLengthName) - 1);
    add_var(
        reinterpret_cast<const unsigned char *>(body.data()), body.size(),
        LUMINA_VAR_BODY, body_scope, 0, body_collection);

    bundle.hdr_presence_mask =
        LUMINA_HDR_HOST | LUMINA_HDR_USER_AGENT |
        LUMINA_HDR_CONTENT_TYPE | LUMINA_HDR_CONTENT_LENGTH;
    bundle.req_method = kMethod;
    bundle.req_method_len = sizeof(kMethod) - 1;
    bundle.req_line = kRequestLine;
    bundle.req_line_len = sizeof(kRequestLine) - 1;
    bundle.req_protocol = kProtocol;
    bundle.req_protocol_len = sizeof(kProtocol) - 1;
    bundle.user_agent = kUserAgent;
    bundle.user_agent_len = sizeof(kUserAgent) - 1;
    bundle.req_filename = kPath;
    bundle.req_filename_len = sizeof(kPath) - 1;
    bundle.req_basename = kPath + sizeof("/api/") - 1;
    bundle.req_basename_len = sizeof("body") - 1;
    bundle.reqbody_processor = processor;
    bundle.reqbody_processor_len = processor_len;
    bundle.hdr_host_count = 1;
    bundle.hdr_user_agent_count = 1;
    bundle.hdr_content_type_count = 1;

    if (luminawaf_inspect_bundle(&bundle, &state, &result) != 0)
        return -1;
    if (result.error_flag != LUMINA_ERROR_NONE)
        return -100 - result.error_flag;
    return result.threat_level;
}

int inspect(const std::string &body) {
    static constexpr unsigned char kProcessor[] = "JSON";
    static constexpr unsigned char kContentType[] = "application/json";
    return inspect_structured(
        body, kProcessor, sizeof(kProcessor) - 1,
        kContentType, sizeof(kContentType) - 1,
        LUMINA_SCOPE_BODY | LUMINA_SCOPE_JSON,
        LUMINA_COL_REQUEST_BODY | LUMINA_COL_JSON);
}

int inspect_xml(const std::string &body) {
    static constexpr unsigned char kProcessor[] = "XML";
    static constexpr unsigned char kContentType[] = "application/xml";
    return inspect_structured(
        body, kProcessor, sizeof(kProcessor) - 1,
        kContentType, sizeof(kContentType) - 1,
        LUMINA_SCOPE_BODY, LUMINA_COL_REQUEST_BODY);
}

double median_cpu_ns(const std::string &body) {
    std::array<double, kSamples> samples{};
    volatile int sink = inspect(body);
    for (unsigned sample = 0; sample < kSamples; ++sample) {
        const uint64_t start = thread_cpu_ns();
        for (unsigned iteration = 0; iteration < kIterations; ++iteration)
            sink ^= inspect(body);
        const uint64_t end = thread_cpu_ns();
        samples[sample] =
            static_cast<double>(end - start) / kIterations;
    }
    std::sort(samples.begin(), samples.end());
    if (sink == -1)
        return -1.0;
    return samples[kSamples / 2];
}

#if defined(LUMINA_DATAPLANE_DIAGNOSTICS)
void print_counter_summary(const char *fixture, int threat) {
    LuminaDataplaneCounters counters{};
    if (threat < 0 || luminawaf_dataplane_counters_get(&counters) != 0)
        return;
    std::printf(
        "%-8s diagnostics: value_scans=%llu offsets=%llu candidates=%llu "
        "dispatches=%llu\n",
        fixture,
        static_cast<unsigned long long>(counters.value_scans),
        static_cast<unsigned long long>(counters.offset_positions),
        static_cast<unsigned long long>(counters.candidate_rules),
        static_cast<unsigned long long>(counters.exact_dispatches));
}

void print_dispatch_diagnostics(
        const char *fixture, const std::string &body) {
    luminawaf_dataplane_counters_reset();
    const int threat = inspect(body);
    LuminaDataplaneCounters counters{};
    if (threat < 0 || luminawaf_dataplane_counters_get(&counters) != 0)
        return;

    print_counter_summary(fixture, threat);
    std::printf(
        "  json_zero_copy=%llu/%lluB json_materialized=%llu/%lluB\n",
        static_cast<unsigned long long>(counters.json_zero_copy_values),
        static_cast<unsigned long long>(counters.json_zero_copy_bytes),
        static_cast<unsigned long long>(counters.json_materialized_values),
        static_cast<unsigned long long>(counters.json_materialized_bytes));
    std::array<bool, LUMINA_DATAPLANE_RULE_COUNTER_SLOTS> selected{};
    for (unsigned rank = 0; rank < 12; ++rank) {
        unsigned best = LUMINA_DATAPLANE_RULE_COUNTER_SLOTS;
        for (unsigned idx = 0;
             idx < LUMINA_DATAPLANE_RULE_COUNTER_SLOTS; ++idx) {
            if (selected[idx] || counters.rule_dispatches[idx] == 0)
                continue;
            if (best == LUMINA_DATAPLANE_RULE_COUNTER_SLOTS ||
                counters.rule_dispatches[idx] >
                    counters.rule_dispatches[best]) {
                best = idx;
            }
        }
        if (best == LUMINA_DATAPLANE_RULE_COUNTER_SLOTS)
            break;
        selected[best] = true;
        const int rule_id =
            best < LUMINA_SHORT_RULE_COUNT ? g_short_rule_id[best] : 0;
        std::printf(
            "  rule=%d idx=%u dispatches=%llu\n",
            rule_id, best,
            static_cast<unsigned long long>(
                counters.rule_dispatches[best]));
    }
}
#endif

}  // namespace

int main(int argc, char **argv) {
    std::setvbuf(stdout, nullptr, _IOLBF, 0);
    if (luminawaf_init_worker(1) != 0)
        return 2;

#if defined(LUMINA_DATAPLANE_DIAGNOSTICS)
    if (argc == 2 && std::strcmp(argv[1], "--diagnostics-only") == 0) {
        for (const Fixture &fixture : kFixtures) {
            print_dispatch_diagnostics(
                fixture.name, make_json(32u << 10, fixture));
        }
        luminawaf_destroy_worker();
        return 0;
    }
#endif
    if (argc == 5 && std::strcmp(argv[1], "--profile") == 0) {
        const Fixture *selected = nullptr;
        for (const Fixture &fixture : kFixtures)
            if (std::strcmp(fixture.name, argv[2]) == 0)
                selected = &fixture;
        const size_t size_kib =
            static_cast<size_t>(std::strtoull(argv[3], nullptr, 10));
        const unsigned iterations =
            static_cast<unsigned>(std::strtoul(argv[4], nullptr, 10));
        if (!selected || size_kib == 0 || iterations == 0) {
            luminawaf_destroy_worker();
            return 2;
        }
        const std::string body =
            make_json(size_kib << 10, *selected);
        volatile int sink = 0;
        for (unsigned iteration = 0; iteration < iterations; ++iteration)
            sink ^= inspect(body);
        std::printf(
            "profile fixture=%s size=%zu KiB iterations=%u sink=%d\n",
            selected->name, size_kib, iterations, sink);
        luminawaf_destroy_worker();
        return 0;
    }
    if (argc == 4 && std::strcmp(argv[1], "--profile-9341xx") == 0) {
        const size_t size_kib =
            static_cast<size_t>(std::strtoull(argv[2], nullptr, 10));
        const unsigned iterations =
            static_cast<unsigned>(std::strtoul(argv[3], nullptr, 10));
        if (size_kib == 0 || iterations == 0) {
            luminawaf_destroy_worker();
            return 2;
        }
        const std::string value =
            make_9341xx_transform_stress(size_kib << 10);
        volatile int sink = dispatch_9341xx(value);
        for (unsigned iteration = 0; iteration < iterations; ++iteration)
            sink ^= dispatch_9341xx(value);
        std::printf(
            "profile family=9341xx size=%zu KiB iterations=%u sink=%d\n",
            size_kib, iterations, sink);
        luminawaf_destroy_worker();
        return sink < 0 ? 2 : 0;
    }
    if ((argc == 4 || argc == 5) &&
        std::strcmp(argv[1], "--profile-xml") == 0) {
        const size_t size_kib =
            static_cast<size_t>(std::strtoull(argv[2], nullptr, 10));
        const unsigned iterations =
            static_cast<unsigned>(std::strtoul(argv[3], nullptr, 10));
        const bool with_doctype =
            argc == 5 && std::strcmp(argv[4], "doctype") == 0;
        if (size_kib == 0 || iterations == 0 ||
            (argc == 5 && !with_doctype)) {
            luminawaf_destroy_worker();
            return 2;
        }
        const std::string body = make_xml(size_kib << 10, with_doctype);
        volatile int sink = inspect_xml(body);
        for (unsigned iteration = 0; iteration < iterations; ++iteration)
            sink ^= inspect_xml(body);
        std::printf(
            "profile fixture=xml size=%zu KiB iterations=%u "
            "doctype=%s sink=%d\n",
            size_kib, iterations, with_doctype ? "yes" : "no", sink);
#if defined(LUMINA_DATAPLANE_DIAGNOSTICS)
        luminawaf_dataplane_counters_reset();
        const int diagnostic_threat = inspect_xml(body);
        print_counter_summary(
            with_doctype ? "xml-dtd" : "xml", diagnostic_threat);
#endif
        luminawaf_destroy_worker();
        return sink < 0 ? 2 : 0;
    }

    bool passed = true;
    for (const Fixture &fixture : kFixtures) {
        double previous = 0.0;
        std::array<double, kSizes.size()> medians{};
        int expected_threat = -1;
        size_t size_index = 0;
        for (size_t size : kSizes) {
            const std::string body = make_json(size, fixture);
            const int threat = inspect(body);
            if (threat < 0) {
                std::fprintf(
                    stderr,
                    "%s %zu KiB inspection failed: status=%d\n",
                    fixture.name, size >> 10, threat);
                passed = false;
                break;
            }
            if (expected_threat < 0)
                expected_threat = threat;
            if (threat != expected_threat) {
                std::fprintf(
                    stderr,
                    "%s %zu KiB changed verdict: expected=%d observed=%d\n",
                    fixture.name, size >> 10, expected_threat, threat);
                passed = false;
                break;
            }
            const double cpu_ns = median_cpu_ns(body);
            const double ratio = previous > 0.0 ? cpu_ns / previous : 0.0;
            std::printf(
                "%-8s %3zu KiB median_cpu=%9.3f us ratio=%5.3f threat=%d\n",
                fixture.name, size >> 10, cpu_ns / 1000.0, ratio, threat);
            if (previous > 0.0 && ratio > kMaximumAdjacentRatio) {
                std::fprintf(
                    stderr,
                    "%s %zu KiB exceeded %.2fx adjacent safety gate: %.3fx\n",
                    fixture.name, size >> 10,
                    kMaximumAdjacentRatio, ratio);
                passed = false;
            }
            medians[size_index++] = cpu_ns;
            previous = cpu_ns;
        }
        for (size_t i = 2; i < size_index; ++i) {
            const double ratio_per_doubling =
                std::sqrt(medians[i] / medians[i - 2]);
            if (ratio_per_doubling > kMaximumDoublingRatio) {
                std::fprintf(
                    stderr,
                    "%s %zu-%zu KiB exceeded %.2fx geometric complexity "
                    "gate: %.3fx per doubling\n",
                    fixture.name, kSizes[i - 2] >> 10, kSizes[i] >> 10,
                    kMaximumDoublingRatio, ratio_per_doubling);
                passed = false;
            }
        }
#if defined(LUMINA_DATAPLANE_DIAGNOSTICS)
        if (size_index == kSizes.size())
            print_dispatch_diagnostics(
                fixture.name, make_json(kSizes.back(), fixture));
#endif
    }

    luminawaf_destroy_worker();
    return passed ? 0 : 1;
}
