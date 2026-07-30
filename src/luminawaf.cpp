#include "luminawaf.h"
#include "fast_prefilter.h"
#include "trigger_matcher.h"
#include "canonicalize.h"
#include "json_extract.h"
#include <cstdio>
#include <cstring>
#include "lumina_hit_slab.h"
#include "lumina_xml_parser.h"
#include "generated/crs_rule_idx_map.h"

#if defined(LUMINA_DATAPLANE_DIAGNOSTICS)
static thread_local LuminaDataplaneCounters g_dataplane_counters = {};
static thread_local unsigned g_dataplane_raw_body_depth = 0;

#define LUMINA_DIAG_ADD(field, value) \
    do { g_dataplane_counters.field += (uint64_t)(value); } while (0)
#define LUMINA_DIAG_RAW_ADD(field, value) \
    do { \
        if (g_dataplane_raw_body_depth != 0) \
            g_dataplane_counters.field += (uint64_t)(value); \
    } while (0)
#define LUMINA_DIAG_RULE_DISPATCH(idx) \
    do { \
        if ((unsigned)(idx) < LUMINA_DATAPLANE_RULE_COUNTER_SLOTS) \
            g_dataplane_counters.rule_dispatches[(unsigned)(idx)]++; \
    } while (0)

extern "C" void luminawaf_dataplane_counters_reset(void) {
    g_dataplane_counters = {};
}

extern "C" int luminawaf_dataplane_counters_get(
        LuminaDataplaneCounters *out) {
    if (!out) return -1;
    *out = g_dataplane_counters;
    return 0;
}

extern "C" void luminawaf_dataplane_record_exact_verifier(
        unsigned rule_idx, size_t subject_bytes, int transformed) {
    g_dataplane_counters.exact_verifier_calls++;
    g_dataplane_counters.exact_verifier_subject_bytes += subject_bytes;
    if (subject_bytes >= 4u * 1024u) {
        g_dataplane_counters.exact_verifier_subjects_ge_4k++;
        g_dataplane_counters.exact_verifier_bytes_ge_4k += subject_bytes;
    }
    if (subject_bytes >= 64u * 1024u) {
        g_dataplane_counters.exact_verifier_subjects_ge_64k++;
        g_dataplane_counters.exact_verifier_bytes_ge_64k += subject_bytes;
    }
    if (subject_bytes >
            g_dataplane_counters.exact_verifier_max_subject_bytes) {
        g_dataplane_counters.exact_verifier_max_subject_bytes = subject_bytes;
    }
    if (transformed) {
        g_dataplane_counters.transformed_exact_verifier_calls++;
        g_dataplane_counters.transformed_exact_verifier_subject_bytes +=
            subject_bytes;
    } else {
        g_dataplane_counters.raw_exact_verifier_calls++;
        g_dataplane_counters.raw_exact_verifier_subject_bytes += subject_bytes;
    }
    if (rule_idx < LUMINA_DATAPLANE_RULE_COUNTER_SLOTS) {
        g_dataplane_counters.rule_exact_verifier_calls[rule_idx]++;
        g_dataplane_counters.rule_exact_verifier_subject_bytes[rule_idx] +=
            subject_bytes;
    }
}

extern "C" void luminawaf_dataplane_record_transform_step(
        uint32_t transform, size_t input_bytes, size_t output_bytes) {
    g_dataplane_counters.transform_steps++;
    g_dataplane_counters.transform_input_bytes += input_bytes;
    g_dataplane_counters.transform_output_bytes += output_bytes;
    if (transform == 0 || (transform & (transform - 1u)) != 0) return;
    const unsigned slot = static_cast<unsigned>(__builtin_ctz(transform));
    if (slot >= LUMINA_DATAPLANE_TRANSFORM_COUNTER_SLOTS) return;
    g_dataplane_counters.transform_step_calls[slot]++;
    g_dataplane_counters.transform_step_input_bytes[slot] += input_bytes;
    g_dataplane_counters.transform_step_output_bytes[slot] += output_bytes;
}

extern "C" void luminawaf_dataplane_record_transform_copy(size_t bytes) {
    g_dataplane_counters.transform_copies++;
    g_dataplane_counters.transform_copy_bytes += bytes;
}

extern "C" void luminawaf_dataplane_record_transform_view(
        size_t input_bytes, size_t output_bytes) {
    g_dataplane_counters.transform_views++;
    g_dataplane_counters.transform_view_input_bytes += input_bytes;
    g_dataplane_counters.transform_view_output_bytes += output_bytes;
}

extern "C" void luminawaf_dataplane_record_transform_cache_hit(size_t bytes) {
    g_dataplane_counters.transform_cache_hits++;
    g_dataplane_counters.transform_cache_hit_bytes += bytes;
}
#else
#define LUMINA_DIAG_ADD(field, value) do { (void)(value); } while (0)
#define LUMINA_DIAG_RAW_ADD(field, value) do { (void)(value); } while (0)
#define LUMINA_DIAG_RULE_DISPATCH(idx) do { (void)(idx); } while (0)
#endif

// ============================================================================
// Generated AOT scanner interface.
// ============================================================================
extern "C" {
    void ngx_unescape_uri_scalar(unsigned char** dst, unsigned char** src, size_t size, unsigned int type);
    int lumina_scan_xss(const unsigned char* str, size_t len, uint32_t active_scope);
    int lumina_scan_sqli(const unsigned char* str, size_t len, uint32_t active_scope);
    int lumina_scan_path(const unsigned char* str, size_t len);
    int lumina_scan_cmd(const unsigned char* str, size_t len, uint32_t active_scope);
    int lumina_scan_jndi(const unsigned char* str, size_t len);
    int lumina_scan_ldap(const unsigned char* str, size_t len);
    int lumina_scan_resp_split(const unsigned char* str, size_t len);
    int lumina_scan_ssrf(const unsigned char* str, size_t len);
    int lumina_scan_generated(const unsigned char *data, size_t len, size_t offset,
                              uint32_t context_flag, uint8_t var_type,
                              uint32_t header_mask, uint64_t collection_mask);
    void lumina_eval_target_controls(const unsigned char *data, size_t len,
                                     uint64_t collection_mask,
                                     LuminaRuleState *state);
    int lumina_dispatch_rule(int idx, const unsigned char *data, size_t len, size_t offset);
    __attribute__((visibility("hidden"))) int lumina_dispatch_rule_long(
        int idx, const unsigned char *data, size_t len, size_t offset);
    void lumina_reset_transform_view_cache(void);
    /* Phrase matchers used by CRS rules 930120, 930130 and 920440. */
    int lumina_pm_lfi_os_files(const unsigned char *data, size_t len);
    int lumina_pm_restricted_files(const unsigned char *data, size_t len);
    int lumina_scan_restricted_ext(const unsigned char *url, size_t len);
}

extern "C" {
#include "generated/crs_short_rules.h"
#include "generated/crs_chains.h"
#include "lumina_transforms.h"

static_assert(LUMINA_GENERATED_VAR_TYPE_SLOTS == LUMINA_VAR_TYPE_SLOTS,
              "generated variable-type ABI does not match luminawaf.h");

extern "C" bool lumina_eval_chain(LuminaRuleState *state, int rule_id, const unsigned char *dptr, size_t dlen, size_t doff);

__attribute__((weak)) bool lumina_eval_chain(LuminaRuleState *state, int rule_id, const unsigned char *dptr, size_t dlen, size_t doff) {
    (void)state; (void)rule_id; (void)dptr; (void)dlen; (void)doff;
    return false;
}
}

static inline uint64_t lumina_collection_mask_for_var_type(uint8_t var_type) {
    switch (var_type) {
        case LUMINA_VAR_ARGS: return LUMINA_COL_ARGS;
        case LUMINA_VAR_ARGS_NAMES: return LUMINA_COL_ARGS_NAMES;
        case LUMINA_VAR_COOKIE: return LUMINA_COL_REQUEST_COOKIES;
        case LUMINA_VAR_COOKIE_NAMES: return LUMINA_COL_REQUEST_COOKIES_NAMES;
        case LUMINA_VAR_HDR: return LUMINA_COL_REQUEST_HEADERS;
        case LUMINA_VAR_BODY: return LUMINA_COL_REQUEST_BODY;
        case LUMINA_VAR_FILES: return LUMINA_COL_FILES;
        case LUMINA_VAR_FILES_NAMES: return LUMINA_COL_FILES_NAMES;
        case LUMINA_VAR_REQUEST_FILENAME: return LUMINA_COL_REQUEST_FILENAME;
        case LUMINA_VAR_REQUEST_BASENAME: return LUMINA_COL_REQUEST_BASENAME;
        case LUMINA_VAR_XML:
        case LUMINA_VAR_XML_ATTR: return LUMINA_COL_XML;
        default: return 0;
    }
}

static inline void lumina_build_disabled_mask(
    const LuminaRuleState *state, uint64_t collection_mask,
    uint64_t disabled[CRS_SHORT_RULE_MASK_DIMS]) {
    for (int word = 0; word < CRS_SHORT_RULE_MASK_DIMS; word++) {
        disabled[word] = state->disabled_rules.bits[word];
    }
    uint64_t collections = collection_mask;
    while (collections) {
        unsigned slot = (unsigned)__builtin_ctzll(collections);
        collections &= collections - 1;
        if (slot < LUMINA_TARGET_COLLECTION_SLOTS) {
            for (int word = 0; word < CRS_SHORT_RULE_MASK_DIMS; word++) {
                disabled[word] |= state->disabled_rule_targets[slot].bits[word];
            }
        }
    }
}

extern "C" {
    extern const uint32_t g_short_rule_hdr_mask[];
}

extern "C" {
    extern const uint16_t g_short_rule_var_type[];
}

extern "C" {
    extern const uint8_t g_short_rule_category[];
}

extern "C" {
    extern const uint8_t g_short_rule_paranoia[];
}

typedef struct {
    const uint64_t *pos0;
    const uint64_t *posN;
    uint64_t fallback_pos0[CRS_SHORT_RULE_MASK_DIMS];
    uint64_t fallback_posN[CRS_SHORT_RULE_MASK_DIMS];
} LuminaShortRuleActiveMask;

static inline void lumina_build_short_rule_active_mask(LuminaShortRuleActiveMask *m,
                                                       uint32_t scope,
                                                       uint32_t hdr_presence_mask,
                                                       uint8_t var_type) {
    unsigned scope_idx = scope & (LUMINA_SCOPE_URI | LUMINA_SCOPE_HEADERS | LUMINA_SCOPE_BODY);
    unsigned var_idx = (var_type < LUMINA_VAR_TYPE_SLOTS && var_type != LUMINA_VAR_ANY)
                           ? (unsigned)var_type
                           : (unsigned)LUMINA_VAR_ANY;
    if (var_idx != LUMINA_VAR_HDR) {
        m->pos0 = &g_short_rule_active_pos0[scope_idx][var_idx][0];
        m->posN = &g_short_rule_active_posN[scope_idx][var_idx][0];
        return;
    }

    const uint32_t known_header_mask =
        (UINT32_C(1) << (LUMINA_HEADER_SELECTOR_SLOTS - 1)) - 1;
    uint32_t selectors = hdr_presence_mask & known_header_mask;
    if (selectors == 0) {
        m->pos0 = &g_short_rule_header_active_pos0[scope_idx][0][0];
        m->posN = &g_short_rule_header_active_posN[scope_idx][0][0];
        return;
    }
    if ((selectors & (selectors - 1)) == 0) {
        unsigned selector_slot = (unsigned)__builtin_ctz(selectors) + 1;
        m->pos0 = &g_short_rule_header_active_pos0[scope_idx][selector_slot][0];
        m->posN = &g_short_rule_header_active_posN[scope_idx][selector_slot][0];
        return;
    }

    for (int w = 0; w < CRS_SHORT_RULE_MASK_DIMS; w++) {
        uint64_t pos0 = g_short_rule_header_active_pos0[scope_idx][0][w];
        uint64_t posN = g_short_rule_header_active_posN[scope_idx][0][w];
        uint32_t remaining = selectors;
        while (remaining) {
            unsigned selector_slot = (unsigned)__builtin_ctz(remaining) + 1;
            remaining &= remaining - 1;
            pos0 |= g_short_rule_header_active_pos0[scope_idx][selector_slot][w];
            posN |= g_short_rule_header_active_posN[scope_idx][selector_slot][w];
        }
        m->fallback_pos0[w] = pos0;
        m->fallback_posN[w] = posN;
    }
    m->pos0 = m->fallback_pos0;
    m->posN = m->fallback_posN;
}

typedef struct {
    uint64_t pos0[CRS_SHORT_RULE_MASK_DIMS];
    uint64_t posN[CRS_SHORT_RULE_MASK_DIMS];
} LuminaShortRuleEffectiveMask;

static inline void lumina_build_short_rule_effective_mask(
        LuminaShortRuleEffectiveMask *effective,
        const LuminaShortRuleActiveMask *active,
        const uint64_t *eligibility_mask,
        const uint64_t *disabled_mask) {
    for (int word = 0; word < CRS_SHORT_RULE_MASK_DIMS; ++word) {
        const uint64_t eligible = eligibility_mask
                                      ? eligibility_mask[word] : UINT64_MAX;
        const uint64_t enabled = eligible & ~disabled_mask[word];
        effective->pos0[word] = active->pos0[word] & enabled;
        effective->posN[word] = active->posN[word] & enabled;
    }
}

static inline bool lumina_has_short_rule_candidate(
        const unsigned char *data, size_t len) {
#if LUMINA_SHORT_RULE_FIRST_BYTE_MASK_DENSE
    (void)data;
    return len != 0;
#else
    for (size_t offset = 0; offset < len; ++offset) {
        const uint8_t first = data[offset];
        for (int word = 0; word < CRS_SHORT_RULE_MASK_DIMS; ++word) {
            if (g_short_rule_mask[first][word] != 0) return true;
        }
    }
    return false;
#endif
}

#if LUMINA_SHARED_ROUTER_COUNT > 0
static inline void lumina_run_shared_router(
        int router_id, const unsigned char *data, size_t len, size_t offset,
        const uint64_t *effective_mask, uint64_t *matched,
        uint8_t value_flags) {
    uint64_t wanted[CRS_SHORT_RULE_MASK_DIMS];
    for (int word = 0; word < CRS_SHORT_RULE_MASK_DIMS; ++word) {
        wanted[word] = g_shared_router_rule_mask[router_id][word] &
                       effective_mask[word];
    }
    lumina_dispatch_shared_router(
        router_id, data, len, offset, wanted, matched, value_flags);
}
#endif

// ============================================================================
// Worker and request state. Request-local fields use thread-local storage.
// ============================================================================

/* Generated rules use an exact slab index. Runtime-only rule IDs use the
 * bounded hash set. Both paths share one request state, so repeated matches
 * contribute to the anomaly score only once. */
static inline bool lumina_dedup_test_and_set(LuminaRuleState *state, int rule_id) {
    int e = lumina_rule_id_to_engine_idx(rule_id);
    if (e >= 0) {
        if (lumina_slab_test(&state->completed_rules, e)) return true;
        lumina_slab_mark(&state->completed_rules, e);
        return false;
    }
    unsigned int slot = ((unsigned int)rule_id * 2654435761u) & 511u;
    if ((state->hash_dedup[slot >> 6] >> (slot & 63)) & 1ULL) return true;
    state->hash_dedup[slot >> 6] |= (1ULL << (slot & 63));
    return false;
}

static inline bool lumina_rule_is_disabled(const LuminaRuleState *state, int rule_id) {
    int engine_idx = lumina_rule_id_to_engine_idx(rule_id);
    return state && engine_idx >= 0 &&
           lumina_slab_test(&state->disabled_rules, engine_idx);
}

static inline bool lumina_engine_rule_is_disabled(const LuminaRuleState *state,
                                                  int engine_idx) {
    return state && engine_idx >= 0 && engine_idx < LUMINA_SHORT_RULE_COUNT &&
           lumina_slab_test(&state->disabled_rules, engine_idx);
}

static inline void lumina_record_rule_match(LuminaRuleState *state, int rule_id, const char *caller) {
    (void)caller;
    int engine_idx = lumina_rule_id_to_engine_idx(rule_id);
    if (engine_idx >= 0) {
        if (lumina_slab_test(&state->disabled_rules, engine_idx)) return;
        lumina_slab_mark(&state->matched_rules, engine_idx);
        return;
    }
    for (uint16_t i = 0; i < state->external_match_count; i++) {
        if (state->external_matches[i] == rule_id) return;
    }
    if (state->external_match_count < LUMINA_MAX_EXTERNAL_MATCHES) {
        state->external_matches[state->external_match_count++] = rule_id;
    }
}

int luminawaf_rule_state_matched(const LuminaRuleState *state, int rule_id) {
    if (!state) return 0;
    int engine_idx = lumina_rule_id_to_engine_idx(rule_id);
    if (engine_idx >= 0) {
        if (lumina_slab_test(&state->disabled_rules, engine_idx)) return 0;
        return lumina_slab_test(&state->matched_rules, engine_idx) ? 1 : 0;
    }
    for (uint16_t i = 0; i < state->external_match_count; i++) {
        if (state->external_matches[i] == rule_id) return 1;
    }
    return 0;
}

size_t luminawaf_rule_state_size(void) {
    return sizeof(LuminaRuleState);
}

#define LUMINA_ADD_SCORE_AND_CHECK(state_ptr, rule_id, paranoia, category, threshold, dptr, dlen, doff) \
    do { \
        if (!lumina_rule_is_disabled((state_ptr), (rule_id)) && \
            !lumina_dedup_test_and_set((state_ptr), (rule_id))) { \
            bool _fire = true; \
            int _eidx = lumina_rule_id_to_engine_idx(rule_id); \
            if (_eidx >= 0 && g_rule_chain[_eidx].n_members > 0) { \
                _fire = lumina_eval_chain((state_ptr), _eidx, (const unsigned char*)(dptr), (size_t)(dlen), (size_t)(doff)); \
            } \
            if (_fire) { \
                lumina_record_rule_match((state_ptr), (rule_id), "macro"); \
                g_anomaly_score_tls += (paranoia); \
                g_anomaly_category_tls |= (category); \
                if (g_anomaly_score_tls >= (threshold)) { threat = (rule_id); } \
            } \
        } \
    } while (0)

#define LUMINA_ADD_SCORE_SLAB(state_ptr, idx, rid, paranoia, category, threshold, dptr, dlen, doff) \
    do { \
        if (lumina_engine_rule_is_disabled((state_ptr), (idx))) { \
        } else if ((paranoia) == 0) { \
            lumina_slab_mark(&(state_ptr)->predicate_rules, (idx)); \
        } else if (!lumina_slab_test(&(state_ptr)->completed_rules, (idx))) { \
            (void)(dptr); (void)(dlen); (void)(doff); \
            lumina_slab_mark(&(state_ptr)->completed_rules, (idx)); \
            lumina_slab_mark(&(state_ptr)->matched_rules, (idx)); \
            g_anomaly_score_tls += (paranoia); \
            g_anomaly_category_tls |= (category); \
            if (g_anomaly_score_tls >= (threshold)) { threat = (rid); } \
        } \
    } while(0)

__thread int g_anomaly_score_tls = 0;
__thread int g_anomaly_category_tls = 0;

static inline int lumina_commit_native_rule(LuminaRuleState *state,
                                            int rule_id,
                                            int score,
                                            int category) {
    if (lumina_rule_is_disabled(state, rule_id) ||
        lumina_dedup_test_and_set(state, rule_id)) {
        return 0;
    }
    lumina_record_rule_match(state, rule_id, "native");
    g_anomaly_score_tls += score;
    g_anomaly_category_tls |= category;
    return g_anomaly_score_tls >= LUMINA_ANOMALY_THRESHOLD ? rule_id : 0;
}

extern "C" {
int lumina_commit_generated_rule(LuminaRuleState *state, int engine_idx,
                                 int rule_id, int score, int category) {
    if (!state || engine_idx < 0 || engine_idx >= LUMINA_SHORT_RULE_COUNT || score <= 0) {
        return 0;
    }
    if (lumina_slab_test(&state->disabled_rules, engine_idx)) return 0;
    if (lumina_slab_test(&state->completed_rules, engine_idx)) return 0;
    lumina_slab_mark(&state->completed_rules, engine_idx);
    lumina_slab_mark(&state->matched_rules, engine_idx);
    g_anomaly_score_tls += score;
    g_anomaly_category_tls |= category;
    return g_anomaly_score_tls >= LUMINA_ANOMALY_THRESHOLD ? rule_id : 0;
}

int luminawaf_init_worker(size_t expected_concurrent_connections) {
    /* Kept as an idempotent ABI hook for server integrations. Runtime scratch
     * storage is fixed-capacity thread-local data and needs no worker setup. */
    (void)expected_concurrent_connections;
    return 0;
}

} // extern "C"

static int luminawaf_inspect_scratchpad(unsigned char* scratchpad, size_t decoded_len,
                                        uint32_t active_scope, LuminaRuleState* state, LuminaResult* out_result,
                                        uint32_t hdr_presence_mask, uint8_t var_type);

static inline int compute_adaptive_threshold(const unsigned char *data, size_t len, uint8_t category) {
    int threshold = 5;
    if (len > 64) threshold += 1;
    else if (len < 16) threshold -= 1;
    if (category & (LUMINA_CAT_XSS | LUMINA_CAT_SQLI)) threshold -= 1;

    /* Count unique bytes in the first 64 bytes with a local 256-bit set.
       This removes global timestamp state, data-dependent stores, and the
       rare overflow reset while preserving the old threshold semantics. */
    uint64_t seen[4] = {0, 0, 0, 0};
    size_t sample = len < 64 ? len : 64;
    for (size_t i = 0; i < sample; i++) {
        uint8_t b = data[i];
        seen[b >> 6] |= (1ULL << (b & 63));
    }
    int unique = __builtin_popcountll(seen[0]) +
                 __builtin_popcountll(seen[1]) +
                 __builtin_popcountll(seen[2]) +
                 __builtin_popcountll(seen[3]);

    if (unique > 48) threshold += 1;
    if (threshold < 3) threshold = 3;
    if (threshold > 7) threshold = 7;
    return threshold;
}

static inline int lumina_pre_canonicalize_check(const unsigned char* data, size_t len, LuminaResult* out_result) {
    for (size_t i = 0; i + 1 < len; i++) {
        /* canonicalize() removes %00, so rule 920270 must inspect the raw input. */
        if (data[i] == '%' && i + 2 < len && data[i+1] == '0' && data[i+2] == '0') {
            out_result->error_flag = 0;
            out_result->threat_level = 920270;
            out_result->decoded_buffer = (const char*)data;
            out_result->decoded_length = len;
            return 1;
        }
        if (data[i] == '/' && data[i+1] == '*') {
            out_result->error_flag = 0;
            out_result->threat_level = 942000;
            out_result->decoded_buffer = (const char*)data;
            out_result->decoded_length = len;
            return 1;
        }
        if (data[i] == '-' && i + 1 < len && data[i+1] == '-') {
            out_result->error_flag = 0;
            out_result->threat_level = 942000;
            out_result->decoded_buffer = (const char*)data;
            out_result->decoded_length = len;
            return 1;
        }
        if (data[i] == '0' && i + 1 < len && (data[i+1] == 'x' || data[i+1] == 'X')) {
            if (i + 4 <= len && ((data[i+2] >= '0' && data[i+2] <= '9') ||
                (data[i+2] >= 'a' && data[i+2] <= 'f') || (data[i+2] >= 'A' && data[i+2] <= 'F'))
                && ((data[i+3] >= '0' && data[i+3] <= '9') ||
                (data[i+3] >= 'a' && data[i+3] <= 'f') || (data[i+3] >= 'A' && data[i+3] <= 'F'))) {
                out_result->error_flag = 0;
                out_result->threat_level = 942440;
                out_result->decoded_buffer = (const char*)data;
                out_result->decoded_length = len;
                return 1;
            }
        }
    }
    return 0;
}

int luminawaf_inspect_buffer(const unsigned char* data, size_t len, uint32_t active_scope, uint8_t var_type, LuminaRuleState *state, LuminaResult* out_result) {
    (void)var_type;
    if (!data || !out_result) return -1;
    if (len > LUMINA_MAX_INSPECTED_VALUE) return -1;

    if (lumina_pre_canonicalize_check(data, len, out_result)) return 0;
    
    static thread_local unsigned char scratchpad[LUMINA_MAX_INSPECTED_VALUE];
    
    int is_malloc = 0;
    size_t decoded_len = 0;
    uint32_t decode_scope = active_scope |
        ((var_type == LUMINA_VAR_ARGS || var_type == LUMINA_VAR_ARGS_NAMES) ? (uint32_t)LUMINA_SCOPE_FORM_URLENCODED : 0u);
    unsigned char* decoded_ptr = lumina_canonicalize(data, len, decode_scope, &decoded_len, &is_malloc);
    
    /* The scanners expect writable thread-local storage. canonicalize() may
     * return borrowed input, so keep the copy at this API boundary. */
    if (decoded_len > LUMINA_MAX_INSPECTED_VALUE) {
        lumina_canonicalize_free(decoded_ptr, is_malloc);
        return -1; // Canonicalized input exceeds the scratch buffer.
    }
    
    memcpy(scratchpad, decoded_ptr, decoded_len);
    lumina_canonicalize_free(decoded_ptr, is_malloc);

    return luminawaf_inspect_scratchpad(scratchpad, decoded_len, active_scope, state, out_result, 0, var_type);
}

int luminawaf_inspect_buffer_ex(const unsigned char* data, size_t len, uint32_t active_scope,
                                 uint32_t hdr_presence_mask, uint8_t var_type, LuminaRuleState* state, LuminaResult* out_result) {
    if (!data || !out_result) return -1;
    if (len > LUMINA_MAX_INSPECTED_VALUE) return -1;

    static thread_local unsigned char scratchpad[LUMINA_MAX_INSPECTED_VALUE];

    int is_malloc = 0;
    size_t decoded_len = 0;
    uint32_t decode_scope = active_scope |
        ((var_type == LUMINA_VAR_ARGS || var_type == LUMINA_VAR_ARGS_NAMES) ? (uint32_t)LUMINA_SCOPE_FORM_URLENCODED : 0u);
    unsigned char* decoded_ptr = lumina_canonicalize(data, len, decode_scope, &decoded_len, &is_malloc);

    if (decoded_len > LUMINA_MAX_INSPECTED_VALUE) {
        lumina_canonicalize_free(decoded_ptr, is_malloc);
        return -1;
    }

    memcpy(scratchpad, decoded_ptr, decoded_len);
    lumina_canonicalize_free(decoded_ptr, is_malloc);

    return luminawaf_inspect_scratchpad(scratchpad, decoded_len, active_scope, state, out_result, hdr_presence_mask, var_type);
}

extern "C" int luminawaf_inspect_variable(const unsigned char* data, size_t len, LuminaVarType var_type,
                                uint32_t active_scope, uint32_t hdr_presence_mask, LuminaRuleState* state,
                                LuminaResult* out_result) {
    if (!data || !out_result) return -1;
    if (len > LUMINA_MAX_INSPECTED_VALUE) return -1;

    static thread_local unsigned char scratchpad[LUMINA_MAX_INSPECTED_VALUE];

    int is_malloc = 0;
    size_t decoded_len = 0;
    uint32_t decode_scope = active_scope |
        ((var_type == LUMINA_VAR_ARGS || var_type == LUMINA_VAR_ARGS_NAMES) ? (uint32_t)LUMINA_SCOPE_FORM_URLENCODED : 0u);
    unsigned char* decoded_ptr = lumina_canonicalize(data, len, decode_scope, &decoded_len, &is_malloc);

    if (decoded_len > LUMINA_MAX_INSPECTED_VALUE) {
        lumina_canonicalize_free(decoded_ptr, is_malloc);
        return -1;
    }

    memcpy(scratchpad, decoded_ptr, decoded_len);
    lumina_canonicalize_free(decoded_ptr, is_malloc);

    return luminawaf_inspect_scratchpad(scratchpad, decoded_len, active_scope, state, out_result, hdr_presence_mask, (uint8_t)var_type);
}

static int luminawaf_inspect_scratchpad(unsigned char* scratchpad, size_t decoded_len,
                                        uint32_t active_scope, LuminaRuleState* state, LuminaResult* out_result,
                                        uint32_t hdr_presence_mask, uint8_t var_type) {
    LuminaRuleState fallback_state = {};
    lumina_reset_transform_view_cache();
    if (!state) state = &fallback_state;
    uint64_t collection_mask = lumina_collection_mask_for_var_type(var_type);
    lumina_eval_target_controls(
        scratchpad, decoded_len, collection_mask, state);
    uint64_t disabled_mask[CRS_SHORT_RULE_MASK_DIMS];
    lumina_build_disabled_mask(state, collection_mask, disabled_mask);
    g_anomaly_score_tls = 0;
    g_anomaly_category_tls = 0;
    /* Adjust the local threshold for input length and byte diversity. */
    int adaptive_threshold = compute_adaptive_threshold(scratchpad, decoded_len, 0);
    /* Skip the expensive scanners when neither the prefilter nor a generated
     * first-byte mask can match. URI paths still need the path scanner. */
    DangerPositions danger_positions;
    danger_positions.count = 0;
    bool has_danger = false;
    if (active_scope & LUMINA_SCOPE_HEADERS) {
        has_danger = lumina_fast_prefilter_headers(scratchpad, decoded_len, &danger_positions);
    } else {
        has_danger = lumina_fast_prefilter(scratchpad, decoded_len, &danger_positions);
    }
    bool is_uri_path = ((active_scope & LUMINA_SCOPE_URI) && decoded_len > 0 && scratchpad[0] == '/');

    const bool has_short_rule_candidate =
        lumina_has_short_rule_candidate(scratchpad, decoded_len);

    if (!has_danger && !is_uri_path && !has_short_rule_candidate) {
        if (out_result) {
            out_result->error_flag = 0;
            out_result->threat_level = 0;
            out_result->decoded_buffer = (const char*)scratchpad;
            out_result->decoded_length = decoded_len;
        }
        return 0;
    }

    uint32_t triggers = lumina_trigger_match(scratchpad, decoded_len, &danger_positions);

    // Trigger-routed scanners.
    int threat = 0;
    int r;

    // XSS
    if (triggers & (TRIGGER_XSS_SCRIPT_START |
                    TRIGGER_XSS_ON |
                    TRIGGER_XSS_SCRIPT |
                    TRIGGER_XSS_SCRIPT_GENERIC |
                    TRIGGER_XSS_ALERT |
                    TRIGGER_XSS_JAVASCRIPT |
                    TRIGGER_XSS_ENCODED |
                    TRIGGER_XSS_EXTRA)) {
        r = lumina_scan_xss(scratchpad, decoded_len, active_scope);
        if (r) {
            LUMINA_ADD_SCORE_AND_CHECK(state, r, 5, 0x02, adaptive_threshold, scratchpad, decoded_len, 0);
        }
    }

    // Path traversal and reconnaissance. URI paths always take this route.
    if (!threat && (is_uri_path ||
                    (triggers & (TRIGGER_PATH_TRAV |
                                 TRIGGER_PATH_GITCONFIG |
                                 TRIGGER_RECON)))) {
        r = lumina_scan_path(scratchpad, decoded_len);
        if (r) {
            LUMINA_ADD_SCORE_AND_CHECK(state, r, 5, 0x08, adaptive_threshold, scratchpad, decoded_len, 0);
        }
    }

    // CRS 930130: Restricted file access (@pmFromFile restricted-files.data)
    // Applies to REQUEST_FILENAME (URI scope paths)
    if (!threat && is_uri_path) {
        r = lumina_pm_restricted_files(scratchpad, decoded_len);
        if (r) { LUMINA_ADD_SCORE_AND_CHECK(state, r, 5, 0x08, adaptive_threshold, scratchpad, decoded_len, 0); }
    }

    // CRS 920440: Restricted file extension
    // Applies to REQUEST_BASENAME (URI scope only)
    if (!threat && (active_scope & LUMINA_SCOPE_URI)) {
        r = lumina_scan_restricted_ext(scratchpad, decoded_len);
        if (r) { LUMINA_ADD_SCORE_AND_CHECK(state, r, 5, 0x10, adaptive_threshold, scratchpad, decoded_len, 0); }
    }

    // SQLi
    if (!threat && (triggers & (TRIGGER_SQLI_UNION |
                                TRIGGER_SQLI_XP |
                                TRIGGER_SQLI_UNION_FULL |
                                TRIGGER_SQLI_SELECT |
                                TRIGGER_SQLI_1EQUALS1 |
                                TRIGGER_SQLI_COMMENT |
                                TRIGGER_SQLI_EXTRA))) {
        r = lumina_scan_sqli(scratchpad, decoded_len, active_scope);
        if (r) {
            LUMINA_ADD_SCORE_AND_CHECK(state, r, 5, 0x01, adaptive_threshold, scratchpad, decoded_len, 0);
        }
    }

    // Command injection
    if (!threat && (triggers & TRIGGER_CMD_INJECT)) {
        r = lumina_scan_cmd(scratchpad, decoded_len, active_scope);
        if (r) {
            int para = (decoded_len > 32) ? 1 : 3;
            LUMINA_ADD_SCORE_AND_CHECK(state, r, para, 0x04, adaptive_threshold, scratchpad, decoded_len, 0);
        }
    }
    
    // Evaluate generated rules selected by the first-byte mask.
    if (!threat) {
        LuminaShortRuleActiveMask short_active;
        lumina_build_short_rule_active_mask(&short_active, active_scope, hdr_presence_mask, var_type);
        LuminaShortRuleEffectiveMask effective;
        lumina_build_short_rule_effective_mask(
            &effective, &short_active, NULL, disabled_mask);
        uint64_t processed_transform_search[CRS_SHORT_RULE_MASK_DIMS] = {};

        if (decoded_len > 0) {
            uint8_t c = scratchpad[0];
            for (int _w = 0; _w < CRS_SHORT_RULE_MASK_DIMS && !threat; _w++) {
                uint64_t mw = g_short_rule_mask[c][_w] & effective.pos0[_w];
                while (mw) {
                    int idx = __builtin_ctzll(mw) + (_w << 6);
                    mw &= mw - 1;
                    if (g_short_rule_transform_search[idx]) {
                        const uint64_t bit =
                            UINT64_C(1) << (idx & 63);
                        if (processed_transform_search[_w] & bit) continue;
                        processed_transform_search[_w] |= bit;
                    }
                    r = lumina_dispatch_rule(idx, scratchpad, decoded_len, 0);
                    if (r) {
                        /* HPP counter rules match any non-empty value. Parameter
                         * counting handles them at the transaction level. */
                        if (r == 921170) continue;
                        /* The generated score is the CRS anomaly increment, not
                         * the rule's paranoia level. */
                        int s = g_short_rule_score[idx];
                        LUMINA_ADD_SCORE_SLAB(state, idx, r, s, g_short_rule_category[idx], LUMINA_ANOMALY_THRESHOLD, scratchpad, decoded_len, 0);
                        if (threat) break;
                    }
                }
            }
        }

        for (size_t i = 1; i < decoded_len; i += 16) {
            __builtin_prefetch(scratchpad + i + 256, 0, 3);
            
            for (size_t j = i; j < i + 16 && j < decoded_len; j++) {
                uint8_t c = scratchpad[j];
                for (int _w = 0; _w < CRS_SHORT_RULE_MASK_DIMS && !threat; _w++) {
                    uint64_t mw = g_short_rule_mask[c][_w] & effective.posN[_w];
                        while (mw) {
                            int idx = __builtin_ctzll(mw) + (_w << 6);
                            mw &= mw - 1;
                            size_t dispatch_offset = j;
                            if (g_short_rule_transform_search[idx]) {
                                const uint64_t bit =
                                    UINT64_C(1) << (idx & 63);
                                if (processed_transform_search[_w] & bit)
                                    continue;
                                processed_transform_search[_w] |= bit;
                                dispatch_offset = 0;
                            }
                            r = lumina_dispatch_rule(
                                idx, scratchpad, decoded_len,
                                dispatch_offset);
                            if (r) {
                                /* HPP counter rules are handled by transaction-level
                                 * parameter counting. */
                                if (r == 921170) continue;
                                /* Use the generated CRS anomaly increment. */
                                int s = g_short_rule_score[idx];
                                LUMINA_ADD_SCORE_SLAB(state, idx, r, s, g_short_rule_category[idx], LUMINA_ANOMALY_THRESHOLD, scratchpad, decoded_len, j);
                                if (threat) break;
                            }
                    }
                    if (threat) break;
                }
                if (threat) break;
            }
        }
    }

    if (out_result) {
        out_result->error_flag = 0;
        out_result->threat_level = threat;
        out_result->decoded_buffer = (const char*)scratchpad;
        out_result->decoded_length = decoded_len;
    }

    return 0;
}

static inline void bundle_build_length_order(
        const LuminaBundle *bundle,
        uint8_t order[LUMINA_BUNDLE_MAX_VARS]) {
    for (int i = 0; i < bundle->count; ++i) order[i] = (uint8_t)i;

    for (int i = 1; i < bundle->count; ++i) {
        const uint8_t current = order[i];
        const size_t current_len = bundle->vars[current].len;
        int j = i - 1;
        while (j >= 0 && bundle->vars[order[j]].len > current_len) {
            order[j + 1] = order[j];
            --j;
        }
        order[j + 1] = current;
    }
}

// ============================================================================
// Request metadata rules are evaluated outside the per-value content scanners.
// ============================================================================

/* Rule 911100 uses the default allowed method set: GET, HEAD, POST and OPTIONS. */
static bool lumina_method_allowed(const unsigned char *m, size_t n) {
    static const char *kAllowed[] = {"GET", "HEAD", "POST", "OPTIONS"};
    if (n == 0 || n > 11) return false;  /* verbs are short; >11 is an invalid verb */
    char buf[16];
    for (size_t i = 0; i < n; i++) {
        char c = (char)m[i];
        if (c >= 'a' && c <= 'z') c = (char)(c - 32);
        buf[i] = c;
    }
    buf[n] = 0;
    for (int i = 0; i < 4; i++)
        if (strlen(kAllowed[i]) == n && memcmp(buf, kAllowed[i], n) == 0) return true;
    return false;
}

/* Rule 920100 accepts a 3-10 letter method, a target and an HTTP version.
 * Normal targets contain '/', OPTIONS may use '*', and CONNECT may use an address. */
static bool lumina_request_line_valid(const unsigned char *s, size_t n) {
    if (n == 0 || n > 8192) return false;
    size_t i = 0;
    while (i < n && ((s[i] >= 'a' && s[i] <= 'z') || (s[i] >= 'A' && s[i] <= 'Z'))) i++;
    size_t mlen = i;
    if (mlen < 3 || mlen > 10) return false;          /* verb must be 3-10 letters */
    if (i >= n || s[i] != ' ') return false;
    i++;                                              /* skip SP after method */
    /* CONNECT is special: "connect <ipv4[:port]> HTTP/x.y" (no slash required) */
    bool is_connect = (mlen == 7 && (s[0]=='C'||s[0]=='c') && (s[1]=='O'||s[1]=='o') &&
                       (s[2]=='N'||s[2]=='n') && (s[3]=='N'||s[3]=='n') &&
                       (s[4]=='E'||s[4]=='e') && (s[5]=='C'||s[5]=='c') &&
                       (s[6]=='T'||s[6]=='t'));
    bool is_options = (mlen == 7 && (s[0]=='O'||s[0]=='o') && (s[1]=='P'||s[1]=='p') &&
                       (s[2]=='T'||s[2]=='t') && (s[3]=='I'||s[3]=='i') &&
                       (s[4]=='O'||s[4]=='o') && (s[5]=='N'||s[5]=='n') &&
                       (s[6]=='S'||s[6]=='s'));
    /* Locate the version separator while proving that the target contains no
     * second SP or vertical tab. This keeps origin-form on one linear pass. */
    size_t lastsp = (size_t)-1;
    unsigned separators = 0;
    for (size_t k = i; k < n; k++) {
        if (s[k] == ' ') {
            lastsp = k;
            separators++;
        } else if (s[k] == '\x0b') {
            return false;
        }
    }
    if (separators != 1) return false;
    size_t vstart = lastsp + 1;
    if (vstart >= n) return false;
    /* HTTP-version token must be non-empty and restrict to [A-Za-z0-9./-] */
    for (size_t k = vstart; k < n; k++) {
        char c = s[k];
        if (!((c>='A'&&c<='Z')||(c>='a'&&c<='z')||(c>='0'&&c<='9')||c=='.'||c=='/'||c=='-'))
            return false;
    }
    size_t tstart = i, tend = lastsp;
    if (tstart >= tend) return false;
    if (is_connect) return true;                      /* CONNECT target needs no slash */
    if (s[tstart] == '/') return true;
    if (tend - tstart == 1 && s[tstart] == '*') return is_options;

    size_t scheme_end = tstart;
    while (scheme_end < tend &&
           ((s[scheme_end] >= 'A' && s[scheme_end] <= 'Z') ||
            (s[scheme_end] >= 'a' && s[scheme_end] <= 'z') ||
            (s[scheme_end] >= '0' && s[scheme_end] <= '9') ||
            s[scheme_end] == '_')) {
        scheme_end++;
    }
    size_t scheme_len = scheme_end - tstart;
    if (scheme_len < 3 || scheme_len > 7 ||
        scheme_end + 2 >= tend ||
        s[scheme_end] != ':' ||
        s[scheme_end + 1] != '/' ||
        s[scheme_end + 2] != '/') {
        return false;
    }

    size_t path = scheme_end + 3;
    while (path < tend && s[path] != '/' &&
           s[path] != '?' && s[path] != '#') {
        path++;
    }
    return path < tend && s[path] == '/';
}

/* 920430 - REQUEST_PROTOCOL must be one of the CRS default protocol values.
 * The collection is request metadata and must never be evaluated against a
 * generic URI, argument, header, or body buffer. */
static bool lumina_protocol_allowed(const unsigned char *p, size_t n) {
    static const char *kAllowed[] = {
        "HTTP/1.0", "HTTP/1.1", "HTTP/2", "HTTP/2.0", "HTTP/3", "HTTP/3.0"
    };
    if (!p || n < 6 || n > 8) return false;
    for (size_t i = 0; i < sizeof(kAllowed) / sizeof(kAllowed[0]); i++) {
        size_t allowed_len = strlen(kAllowed[i]);
        if (n == allowed_len && memcmp(p, kAllowed[i], n) == 0) return true;
    }
    return false;
}

/* Execute generated rules over one projected collection value. ARGS_NAMES is
 * derived from the caller-owned raw argument buffer, so it does not consume a
 * BundleVar slot and cannot truncate headers or the request body. */
enum LuminaProofCohort : uint8_t {
    LUMINA_PROOF_COHORT_GLOBAL = 0,
    LUMINA_PROOF_COHORT_REQUEST_BODY = 1,
};

template <bool LongValue>
static inline int lumina_dispatch_projected_rule(
        int idx, const unsigned char *data, size_t len, size_t offset) {
    if constexpr (LongValue)
        return lumina_dispatch_rule_long(idx, data, len, offset);
    return lumina_dispatch_rule(idx, data, len, offset);
}

template <bool LongValue>
static int lumina_scan_projected_value_masked_impl(
        const unsigned char *data, size_t len, uint32_t scope,
        uint8_t var_type, LuminaRuleState *state,
        const uint64_t *eligibility_mask, uint32_t header_mask,
        LuminaProofCohort proof_cohort) {
    if (!data || len == 0 || !state) return 0;
    LUMINA_DIAG_ADD(value_scans, 1);
    LUMINA_DIAG_ADD(value_bytes, len);
    lumina_reset_transform_view_cache();

    uint64_t collection_mask = lumina_collection_mask_for_var_type(var_type);
    lumina_eval_target_controls(data, len, collection_mask, state);
    uint64_t disabled_mask[CRS_SHORT_RULE_MASK_DIMS];
    lumina_build_disabled_mask(state, collection_mask, disabled_mask);
    LuminaShortRuleActiveMask active;
    lumina_build_short_rule_active_mask(&active, scope, header_mask, var_type);
    LuminaShortRuleEffectiveMask effective;
    lumina_build_short_rule_effective_mask(
        &effective, &active, eligibility_mask, disabled_mask);
    uint64_t transform_dirty_rules[CRS_SHORT_RULE_MASK_DIMS];
    uint8_t value_flags = 0;
    if (proof_cohort == LUMINA_PROOF_COHORT_REQUEST_BODY
#if defined(LUMINA_DISABLE_REQUEST_BODY_PROOF_COHORT)
        && false
#endif
    ) {
        lumina_filter_request_body_identity_mandatory_candidates(
            data, len, effective.pos0, effective.posN, transform_dirty_rules,
            &value_flags);
    } else {
        lumina_filter_identity_mandatory_candidates(
            data, len, effective.pos0, effective.posN, transform_dirty_rules,
            &value_flags);
    }
    bool skip_posN = false;
    if (__builtin_expect(len >= 64, 0)) {
        uint64_t remaining_pos0 = 0;
        uint64_t remaining_posN = 0;
        for (int word = 0; word < CRS_SHORT_RULE_MASK_DIMS; ++word) {
            remaining_pos0 |= effective.pos0[word];
            remaining_posN |= effective.posN[word];
        }
        if ((remaining_pos0 | remaining_posN) == 0) {
            LUMINA_DIAG_ADD(exhausted_candidate_masks, 1);
            LUMINA_DIAG_RAW_ADD(raw_request_body_exhausted_masks, 1);
            return 0;
        }
        skip_posN = remaining_posN == 0;
    }
    LUMINA_DIAG_ADD(offset_positions, skip_posN ? 1 : len);
    int threat = 0;
    uint64_t processed_transform_search[CRS_SHORT_RULE_MASK_DIMS] = {};

    uint8_t first = data[0];
#if LUMINA_SHARED_ROUTER_COUNT > 0
    uint8_t processed_routers[LUMINA_SHARED_ROUTER_COUNT] = {};
    uint64_t router_matches[LUMINA_SHARED_ROUTER_COUNT]
                           [CRS_SHORT_RULE_MASK_DIMS] = {};
#endif
    for (int word = 0; word < CRS_SHORT_RULE_MASK_DIMS; word++) {
        uint64_t candidates = g_short_rule_mask[first][word] & effective.pos0[word];
#if !defined(LUMINA_DISABLE_PREFIX2_ROUTER)
        if (len >= 64 && len > 1) {
            const unsigned pair = (unsigned(first) << 8) | data[1];
            const unsigned prefix_class = g_short_rule_prefix2_class[pair];
            candidates &= ~(
                g_short_rule_prefix2_reject[prefix_class][word] &
                ~transform_dirty_rules[word]);
        }
#endif
        while (candidates) {
            int idx = __builtin_ctzll(candidates) + (word << 6);
            candidates &= candidates - 1;
            if (idx >= LUMINA_SHORT_RULE_COUNT) continue;
#if !defined(LUMINA_DISABLE_PREFIX4_GATE)
            if (len >= 64 && len >= 4 &&
                (transform_dirty_rules[word] &
                 (UINT64_C(1) << (idx & 63))) == 0) {
                int (*gate)(const unsigned char *, size_t, size_t) =
                    g_short_rule_prefix4_gate[idx];
                if (gate && !gate(data, len, 0)) continue;
            }
#endif
            LUMINA_DIAG_ADD(candidate_rules, 1);
            LUMINA_DIAG_RAW_ADD(raw_request_body_candidate_rules, 1);
#if LUMINA_SHARED_ROUTER_COUNT > 0
            int router_tag = g_short_rule_shared_router[idx];
            if (router_tag != 0) {
                int router_id = router_tag - 1;
                if (processed_routers[router_id] == 0) {
                    processed_routers[router_id] = 1;
                    LUMINA_DIAG_ADD(shared_router_calls, 1);
                    lumina_run_shared_router(
                        router_id, data, len, 0, effective.pos0,
                        router_matches[router_id], value_flags);
                }
                const uint64_t rule_bit = UINT64_C(1) << (idx & 63);
                if ((router_matches[router_id][word] & rule_bit) != 0) {
                    int score = g_short_rule_score[idx];
                    if (score == 0) {
                        lumina_slab_mark(&state->predicate_rules, idx);
                    } else {
                        int committed = lumina_commit_generated_rule(
                            state, idx, g_short_rule_id[idx], score,
                            g_short_rule_category[idx]);
                        if (committed) threat = committed;
                    }
                }
                continue;
            }
#endif
            if (g_short_rule_transform_search[idx]) {
                const uint64_t bit = UINT64_C(1) << (idx & 63);
                if (processed_transform_search[word] & bit) continue;
                processed_transform_search[word] |= bit;
            }
            LUMINA_DIAG_ADD(exact_dispatches, 1);
            LUMINA_DIAG_RAW_ADD(raw_request_body_exact_dispatches, 1);
            LUMINA_DIAG_RULE_DISPATCH(idx);
            int rule_id = lumina_dispatch_projected_rule<LongValue>(
                idx, data, len, 0);
            if (!rule_id) continue;
            int score = g_short_rule_score[idx];
            if (score == 0) {
                lumina_slab_mark(&state->predicate_rules, idx);
            } else {
                int committed = lumina_commit_generated_rule(
                    state, idx, rule_id, score, g_short_rule_category[idx]);
                if (committed) threat = committed;
            }
        }
    }

    if (skip_posN) {
        LUMINA_DIAG_ADD(exhausted_posN_masks, 1);
        LUMINA_DIAG_RAW_ADD(raw_request_body_exhausted_posN_masks, 1);
        return threat;
    }

    for (size_t offset = 1; offset < len; offset++) {
        uint8_t byte = data[offset];
        for (int word = 0; word < CRS_SHORT_RULE_MASK_DIMS; word++) {
            uint64_t candidates = g_short_rule_mask[byte][word] & effective.posN[word];
#if !defined(LUMINA_DISABLE_PREFIX2_ROUTER)
            if (len >= 64 && offset + 1 < len) {
                const unsigned pair =
                    (unsigned(byte) << 8) | data[offset + 1];
                const unsigned prefix_class = g_short_rule_prefix2_class[pair];
                candidates &= ~(
                    g_short_rule_prefix2_reject[prefix_class][word] &
                    ~transform_dirty_rules[word]);
            }
#endif
            while (candidates) {
                int idx = __builtin_ctzll(candidates) + (word << 6);
                candidates &= candidates - 1;
                if (idx >= LUMINA_SHORT_RULE_COUNT) continue;
#if !defined(LUMINA_DISABLE_PREFIX4_GATE)
                if (len >= 64 && len - offset >= 4 &&
                    (transform_dirty_rules[word] &
                     (UINT64_C(1) << (idx & 63))) == 0) {
                    int (*gate)(const unsigned char *, size_t, size_t) =
                        g_short_rule_prefix4_gate[idx];
                    if (gate && !gate(data, len, offset)) continue;
                }
#endif
                size_t dispatch_offset = offset;
                if (g_short_rule_transform_search[idx]) {
                    const uint64_t bit = UINT64_C(1) << (idx & 63);
                    if (processed_transform_search[word] & bit) continue;
                    processed_transform_search[word] |= bit;
                    dispatch_offset = 0;
                }
                LUMINA_DIAG_ADD(candidate_rules, 1);
                LUMINA_DIAG_ADD(exact_dispatches, 1);
                LUMINA_DIAG_RAW_ADD(raw_request_body_candidate_rules, 1);
                LUMINA_DIAG_RAW_ADD(raw_request_body_exact_dispatches, 1);
                LUMINA_DIAG_RULE_DISPATCH(idx);
                int rule_id = lumina_dispatch_projected_rule<LongValue>(
                    idx, data, len, dispatch_offset);
                if (!rule_id) continue;
                int score = g_short_rule_score[idx];
                if (score == 0) {
                    lumina_slab_mark(&state->predicate_rules, idx);
                } else {
                    int committed = lumina_commit_generated_rule(
                        state, idx, rule_id, score, g_short_rule_category[idx]);
                    if (committed) threat = committed;
                }
            }
        }
    }
    return threat;
}

template __attribute__((noinline, section(".lumina_long_text")))
int lumina_scan_projected_value_masked_impl<true>(
        const unsigned char *data, size_t len, uint32_t scope,
        uint8_t var_type, LuminaRuleState *state,
        const uint64_t *eligibility_mask, uint32_t header_mask,
        LuminaProofCohort proof_cohort);

static int lumina_scan_projected_value_masked(
        const unsigned char *data, size_t len, uint32_t scope,
        uint8_t var_type, LuminaRuleState *state,
        const uint64_t *eligibility_mask, uint32_t header_mask,
        LuminaProofCohort proof_cohort) {
    if (__builtin_expect(len >= 4096u, 0))
        return lumina_scan_projected_value_masked_impl<true>(
            data, len, scope, var_type, state, eligibility_mask,
            header_mask, proof_cohort);
    return lumina_scan_projected_value_masked_impl<false>(
        data, len, scope, var_type, state, eligibility_mask,
        header_mask, proof_cohort);
}

static int lumina_scan_projected_value(const unsigned char *data, size_t len,
                                       uint32_t scope, uint8_t var_type,
                                       LuminaRuleState *state) {
    return lumina_scan_projected_value_masked(
        data, len, scope, var_type, state, NULL, 0,
        LUMINA_PROOF_COHORT_GLOBAL);
}

static int lumina_scan_raw_request_body(const BundleVar *var,
                                        LuminaRuleState *state) {
    if (!var || !var->ptr || var->len == 0 || !state) return 0;
    LUMINA_DIAG_ADD(raw_request_body_scans, 1);
    LUMINA_DIAG_ADD(raw_request_body_bytes, var->len);
#if defined(LUMINA_DATAPLANE_DIAGNOSTICS)
    g_dataplane_raw_body_depth++;
#endif
    int threat = lumina_scan_projected_value_masked(
        var->ptr, var->len, LUMINA_SCOPE_BODY, LUMINA_VAR_BODY, state,
        g_short_rule_request_body_mask, 0,
        LUMINA_PROOF_COHORT_REQUEST_BODY);
#if defined(LUMINA_DATAPLANE_DIAGNOSTICS)
    g_dataplane_raw_body_depth--;
#endif
    return threat;
}

/* Present empty collections are semantically different from missing
 * collections in ModSecurity. The generated nullable mask keeps this path
 * proportional to the handful of predicates that can accept zero bytes. */
static int lumina_scan_empty_variable(const BundleVar *var,
                                      LuminaRuleState *state) {
    if (!var || !var->ptr || var->len != 0 || !state) return 0;
    lumina_reset_transform_view_cache();

    LuminaShortRuleActiveMask active;
    uint32_t header_mask = var->var_type == LUMINA_VAR_HDR ? var->header_mask : 0;
    lumina_eval_target_controls(
        var->ptr, 0, var->collection_mask, state);
    uint64_t disabled_mask[CRS_SHORT_RULE_MASK_DIMS];
    lumina_build_disabled_mask(state, var->collection_mask, disabled_mask);
    lumina_build_short_rule_active_mask(
        &active, var->scope, header_mask, (uint8_t)var->var_type);
    int threat = 0;
    for (int word = 0; word < CRS_SHORT_RULE_MASK_DIMS; word++) {
        uint64_t candidates = g_short_rule_empty_mask[word] & active.pos0[word] &
                              ~disabled_mask[word];
        while (candidates) {
            int idx = __builtin_ctzll(candidates) + (word << 6);
            candidates &= candidates - 1;
            if (idx >= LUMINA_SHORT_RULE_COUNT) continue;
            if (g_short_rule_collection_mask[idx] &&
                !(g_short_rule_collection_mask[idx] & var->collection_mask)) continue;
            int rule_id = lumina_dispatch_rule(idx, var->ptr, 0, 0);
            if (!rule_id) continue;
            int score = g_short_rule_score[idx];
            if (score == 0) {
                lumina_slab_mark(&state->predicate_rules, idx);
            } else {
                int committed = lumina_commit_generated_rule(
                    state, idx, rule_id, score, g_short_rule_category[idx]);
                if (committed) threat = committed;
            }
        }
    }
    return threat;
}

extern "C" int lumina_scan_projected_xml_value(const unsigned char *data, size_t len,
                                                LuminaRuleState *state) {
    return lumina_scan_projected_value(
        data, len, LUMINA_SCOPE_BODY, LUMINA_VAR_XML, state);
}

static bool lumina_bundle_has_form_urlencoded_body(const LuminaBundle *bundle) {
    static const unsigned char expected[] = "application/x-www-form-urlencoded";
    bool has_content_type = false;
    for (int i = 0; i < bundle->count; i++) {
        const BundleVar *var = &bundle->vars[i];
        if (var->var_type != LUMINA_VAR_HDR ||
            !(var->header_mask & LUMINA_HDR_CONTENT_TYPE) ||
            !var->ptr) continue;
        has_content_type = true;
        if (var->len < sizeof(expected) - 1) continue;
        bool equal = true;
        for (size_t j = 0; j < sizeof(expected) - 1; j++) {
            unsigned char value = var->ptr[j];
            if (value >= 'A' && value <= 'Z') value |= 0x20u;
            if (value != expected[j]) {
                equal = false;
                break;
            }
        }
        if (equal) return true;
    }
    if (has_content_type || !bundle->req_method || bundle->req_method_len != 4) return false;
    static const unsigned char post[] = "POST";
    for (size_t i = 0; i < sizeof(post) - 1; i++) {
        unsigned char value = bundle->req_method[i];
        if (value >= 'a' && value <= 'z') value &= 0xdfu;
        if (value != post[i]) return false;
    }
    /* ModSecurity treats a conventional POST body as URL-encoded form data
     * when no conflicting request-body processor was selected. The bounded
     * shape check avoids projecting XML, JSON and arbitrary opaque bodies. */
    for (int i = 0; i < bundle->count; i++) {
        const BundleVar *var = &bundle->vars[i];
        if (var->var_type != LUMINA_VAR_BODY || !var->ptr || var->len == 0) continue;
        size_t pos = 0;
        while (pos < var->len && (var->ptr[pos] == ' ' || var->ptr[pos] == '\t' ||
                                 var->ptr[pos] == '\r' || var->ptr[pos] == '\n')) pos++;
        if (pos < var->len && (var->ptr[pos] == '<' || var->ptr[pos] == '{' ||
                              var->ptr[pos] == '[')) return false;
        return memchr(var->ptr + pos, '=', var->len - pos) != NULL;
    }
    return false;
}

static inline int lumina_form_hex(unsigned char value) {
    if (value >= '0' && value <= '9') return value - '0';
    value |= 0x20u;
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    return -1;
}

static size_t lumina_decode_form_component(const unsigned char *src, size_t len,
                                           unsigned char *dst, size_t cap) {
    if (!src || !dst || len > cap) return SIZE_MAX;
    size_t out = 0;
    for (size_t i = 0; i < len; i++) {
        unsigned char value = src[i];
        if (value == '+' ) {
            dst[out++] = ' ';
            continue;
        }
        if (value == '%' && i + 2 < len) {
            int hi = lumina_form_hex(src[i + 1]);
            int lo = lumina_form_hex(src[i + 2]);
            if (hi >= 0 && lo >= 0) {
                dst[out++] = (unsigned char)((hi << 4) | lo);
                i += 2;
                continue;
            }
        }
        dst[out++] = value;
    }
    return out;
}

typedef struct {
    const unsigned char *ptr;
    size_t len;
    bool needs_unescape;
    bool present;
} LuminaMultipartSlice;

static bool lumina_utf8_valid(const unsigned char *data, size_t len);

static bool lumina_ascii_equal_ci(const unsigned char *value, size_t value_len,
                                  const unsigned char *expected, size_t expected_len) {
    if (!value || !expected || value_len != expected_len) return false;
    for (size_t i = 0; i < value_len; i++) {
        unsigned char a = value[i];
        unsigned char b = expected[i];
        if (a >= 'A' && a <= 'Z') a |= 0x20u;
        if (b >= 'A' && b <= 'Z') b |= 0x20u;
        if (a != b) return false;
    }
    return true;
}

static bool lumina_multipart_boundary_char(unsigned char c) {
    return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') ||
           (c >= 'a' && c <= 'z') || c == '\'' || c == '(' || c == ')' ||
           c == '+' || c == '_' || c == ',' || c == '-' || c == '.' ||
           c == '/' || c == ':' || c == '=' || c == '?' || c == ' ';
}

/* Returns 0 for a non-multipart media type, 1 for a valid boundary and -1 for
 * a declared multipart body with malformed or missing boundary metadata. */
static int lumina_multipart_boundary_from_content_type(
    const unsigned char *content_type, size_t content_type_len,
    unsigned char boundary[71], size_t *boundary_len) {
    static const unsigned char multipart[] = "multipart/";
    static const unsigned char boundary_name[] = "boundary";
    if (!content_type || !boundary || !boundary_len ||
        content_type_len < sizeof(multipart) - 1 ||
        !lumina_ascii_equal_ci(content_type, sizeof(multipart) - 1,
                               multipart, sizeof(multipart) - 1)) {
        return 0;
    }
    size_t pos = sizeof(multipart) - 1;
    if (pos == content_type_len || content_type[pos] == ';') return -1;
    while (pos < content_type_len && content_type[pos] != ';') pos++;
    bool found = false;
    while (pos < content_type_len) {
        pos++;
        while (pos < content_type_len &&
               (content_type[pos] == ' ' || content_type[pos] == '\t')) pos++;
        size_t name_start = pos;
        while (pos < content_type_len && content_type[pos] != '=' &&
               content_type[pos] != ';') pos++;
        size_t name_end = pos;
        while (name_end > name_start &&
               (content_type[name_end - 1] == ' ' ||
                content_type[name_end - 1] == '\t')) {
            name_end--;
        }
        if (pos >= content_type_len || content_type[pos] != '=') {
            return -1;
        }
        pos++;
        while (pos < content_type_len &&
               (content_type[pos] == ' ' || content_type[pos] == '\t')) pos++;
        if (pos == content_type_len) return -1;
        bool is_boundary = lumina_ascii_equal_ci(
            content_type + name_start, name_end - name_start,
            boundary_name, sizeof(boundary_name) - 1);
        if (is_boundary && found) return -1;
        bool quoted = pos < content_type_len && content_type[pos] == '"';
        if (quoted) pos++;
        size_t out = 0;
        bool closed = !quoted;
        while (pos < content_type_len) {
            unsigned char c = content_type[pos];
            if (quoted && c == '"') {
                pos++;
                closed = true;
                break;
            }
            if (!quoted && c == ';') break;
            if (quoted && c == '\\') {
                pos++;
                if (pos == content_type_len) return -1;
                c = content_type[pos];
            }
            if (c < 0x20u || c == 0x7fu) return -1;
            if (is_boundary) {
                if (out >= 70 || !lumina_multipart_boundary_char(c)) return -1;
                boundary[out++] = c;
            }
            pos++;
        }
        if (!closed) return -1;
        if (quoted) {
            while (pos < content_type_len &&
                   (content_type[pos] == ' ' || content_type[pos] == '\t')) {
                pos++;
            }
            if (pos < content_type_len && content_type[pos] != ';') return -1;
        }
        if (is_boundary) {
            while (!quoted && out > 0 && boundary[out - 1] == ' ') out--;
            if (!closed || out == 0 || boundary[out - 1] == ' ') return -1;
            *boundary_len = out;
            found = true;
        }
        while (pos < content_type_len && content_type[pos] != ';') pos++;
    }
    return found ? 1 : -1;
}

static int lumina_multipart_boundary(const LuminaBundle *bundle,
                                     unsigned char boundary[71],
                                     size_t *boundary_len) {
    if (!bundle || !boundary || !boundary_len) return 0;
    for (int i = 0; i < bundle->count; i++) {
        const BundleVar *header = &bundle->vars[i];
        if (header->var_type != LUMINA_VAR_HDR || !header->ptr ||
            !(header->header_mask & LUMINA_HDR_CONTENT_TYPE)) continue;
        return lumina_multipart_boundary_from_content_type(
            header->ptr, header->len, boundary, boundary_len);
    }
    return 0;
}

static int lumina_multipart_boundary_line(const unsigned char *line, size_t line_len,
                                          const unsigned char *boundary,
                                          size_t boundary_len) {
    if (!line || !boundary || line_len < boundary_len + 2 ||
        line[0] != '-' || line[1] != '-') return 0;
    if (__builtin_memcmp(line + 2, boundary, boundary_len) != 0) return 0;
    size_t pos = boundary_len + 2;
    int kind = 1;
    if (pos + 2 <= line_len && line[pos] == '-' && line[pos + 1] == '-') {
        kind = 2;
        pos += 2;
    }
    while (pos < line_len && (line[pos] == ' ' || line[pos] == '\t')) pos++;
    return pos == line_len ? kind : 0;
}

/* Returns 1 when found, 0 when absent and -1 for malformed parameter syntax. */
static int lumina_multipart_parameter(const unsigned char *line, size_t line_len,
                                      const unsigned char *parameter,
                                      size_t parameter_len,
                                      LuminaMultipartSlice *out) {
    if (!line || !parameter || !out) return -1;
    size_t pos = 0;
    while (pos < line_len && line[pos] != ':') pos++;
    if (pos == line_len) return -1;
    bool found = false;
    while (pos < line_len) {
        while (pos < line_len && line[pos] != ';') pos++;
        if (pos == line_len) break;
        pos++;
        while (pos < line_len && (line[pos] == ' ' || line[pos] == '\t')) pos++;
        size_t name_start = pos;
        while (pos < line_len && line[pos] != '=' && line[pos] != ';') pos++;
        size_t name_end = pos;
        while (name_end > name_start &&
               (line[name_end - 1] == ' ' || line[name_end - 1] == '\t')) name_end--;
        if (name_end == name_start || pos == line_len || line[pos] != '=') return -1;
        pos++;
        while (pos < line_len && (line[pos] == ' ' || line[pos] == '\t')) pos++;
        if (pos == line_len) return -1;
        bool quoted = pos < line_len && line[pos] == '"';
        if (quoted) pos++;
        size_t value_start = pos;
        bool escaped = false;
        if (quoted) {
            while (pos < line_len) {
                if (line[pos] == '\\' && pos + 1 < line_len) {
                    escaped = true;
                    pos += 2;
                    continue;
                }
                if (line[pos] == '"') break;
                pos++;
            }
            if (pos == line_len || line[pos] != '"') return -1;
        } else {
            while (pos < line_len && line[pos] != ';') {
                if ((line[pos] < 0x20u &&
                     line[pos] != ' ' && line[pos] != '\t') ||
                    line[pos] == 0x7fu) {
                    return -1;
                }
                pos++;
            }
        }
        size_t value_end = pos;
        while (!quoted && value_end > value_start &&
               (line[value_end - 1] == ' ' || line[value_end - 1] == '\t')) value_end--;
        if (quoted && pos < line_len) {
            pos++;
            while (pos < line_len &&
                   (line[pos] == ' ' || line[pos] == '\t')) {
                pos++;
            }
            if (pos < line_len && line[pos] != ';') return -1;
        }
        if (lumina_ascii_equal_ci(line + name_start, name_end - name_start,
                                  parameter, parameter_len)) {
            if (found) return -1;
            out->ptr = line + value_start;
            out->len = value_end - value_start;
            out->needs_unescape = escaped;
            out->present = true;
            found = true;
        }
    }
    return found ? 1 : 0;
}

static size_t lumina_unescape_multipart_value(const LuminaMultipartSlice *slice,
                                              unsigned char *dst, size_t cap) {
    if (!slice || !slice->ptr || !dst || slice->len > cap) return SIZE_MAX;
    size_t out = 0;
    for (size_t i = 0; i < slice->len; i++) {
        if (slice->ptr[i] == '\\' && i + 1 < slice->len &&
            (slice->ptr[i + 1] == '\\' || slice->ptr[i + 1] == '"')) i++;
        dst[out++] = slice->ptr[i];
    }
    return out;
}

typedef struct {
    LuminaMultipartSlice name;
    LuminaMultipartSlice filename;
    LuminaMultipartSlice filename_ext;
    LuminaMultipartSlice content_type;
    LuminaMultipartSlice transfer_encoding;
    bool saw_disposition;
} LuminaMultipartPart;

static int lumina_base64_value(unsigned char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static LuminaError lumina_decode_multipart_base64(
    const unsigned char *src, size_t len, unsigned char *dst, size_t cap,
    size_t *decoded_len) {
    unsigned char quartet[4];
    size_t qlen = 0;
    size_t out = 0;
    bool finished = false;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = src[i];
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') continue;
        if (finished || (c != '=' && lumina_base64_value(c) < 0)) {
            return LUMINA_ERROR_REQBODY_MALFORMED;
        }
        quartet[qlen++] = c;
        if (qlen != 4) continue;
        int a = lumina_base64_value(quartet[0]);
        int b = lumina_base64_value(quartet[1]);
        if (a < 0 || b < 0) return LUMINA_ERROR_REQBODY_MALFORMED;
        if (quartet[2] == '=') {
            if (quartet[3] != '=' || out == cap) {
                return quartet[3] == '=' ? LUMINA_ERROR_REQBODY_LIMIT
                                         : LUMINA_ERROR_REQBODY_MALFORMED;
            }
            dst[out++] = (unsigned char)((a << 2) | (b >> 4));
            finished = true;
        } else {
            int c2 = lumina_base64_value(quartet[2]);
            if (c2 < 0) return LUMINA_ERROR_REQBODY_MALFORMED;
            if (out > cap - 2) return LUMINA_ERROR_REQBODY_LIMIT;
            dst[out++] = (unsigned char)((a << 2) | (b >> 4));
            dst[out++] = (unsigned char)((b << 4) | (c2 >> 2));
            if (quartet[3] == '=') {
                finished = true;
            } else {
                int d = lumina_base64_value(quartet[3]);
                if (d < 0) return LUMINA_ERROR_REQBODY_MALFORMED;
                if (out == cap) return LUMINA_ERROR_REQBODY_LIMIT;
                dst[out++] = (unsigned char)((c2 << 6) | d);
            }
        }
        qlen = 0;
    }
    if (qlen != 0) return LUMINA_ERROR_REQBODY_MALFORMED;
    *decoded_len = out;
    return LUMINA_ERROR_NONE;
}

static LuminaError lumina_decode_multipart_qp(
    const unsigned char *src, size_t len, unsigned char *dst, size_t cap,
    size_t *decoded_len) {
    size_t out = 0;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = src[i];
        if (c == '=') {
            if (i + 1 < len && src[i + 1] == '\n') {
                i++;
                continue;
            }
            if (i + 2 < len && src[i + 1] == '\r' && src[i + 2] == '\n') {
                i += 2;
                continue;
            }
            if (i + 2 >= len) return LUMINA_ERROR_REQBODY_MALFORMED;
            int hi = lumina_form_hex(src[i + 1]);
            int lo = lumina_form_hex(src[i + 2]);
            if (hi < 0 || lo < 0) return LUMINA_ERROR_REQBODY_MALFORMED;
            c = (unsigned char)((hi << 4) | lo);
            i += 2;
        }
        if (out == cap) return LUMINA_ERROR_REQBODY_LIMIT;
        dst[out++] = c;
    }
    *decoded_len = out;
    return LUMINA_ERROR_NONE;
}

static LuminaError lumina_decode_multipart_body(
    const LuminaMultipartSlice *encoding, const unsigned char *src, size_t len,
    unsigned char *scratch, size_t scratch_cap, const unsigned char **decoded,
    size_t *decoded_len, bool *materialized) {
    static const unsigned char base64[] = "base64";
    static const unsigned char quoted_printable[] = "quoted-printable";
    static const unsigned char binary[] = "binary";
    static const unsigned char seven_bit[] = "7bit";
    static const unsigned char eight_bit[] = "8bit";
    *decoded = src;
    *decoded_len = len;
    *materialized = false;
    if (!encoding->present || encoding->len == 0 ||
        lumina_ascii_equal_ci(encoding->ptr, encoding->len,
                              binary, sizeof(binary) - 1) ||
        lumina_ascii_equal_ci(encoding->ptr, encoding->len,
                              seven_bit, sizeof(seven_bit) - 1) ||
        lumina_ascii_equal_ci(encoding->ptr, encoding->len,
                              eight_bit, sizeof(eight_bit) - 1)) {
        return LUMINA_ERROR_NONE;
    }
    LuminaError error;
    if (lumina_ascii_equal_ci(encoding->ptr, encoding->len,
                              base64, sizeof(base64) - 1)) {
        error = lumina_decode_multipart_base64(
            src, len, scratch, scratch_cap, decoded_len);
    } else if (lumina_ascii_equal_ci(
                   encoding->ptr, encoding->len,
                   quoted_printable, sizeof(quoted_printable) - 1)) {
        error = lumina_decode_multipart_qp(
            src, len, scratch, scratch_cap, decoded_len);
    } else {
        return LUMINA_ERROR_REQBODY_UNSUPPORTED;
    }
    if (error == LUMINA_ERROR_NONE) {
        *decoded = scratch;
        *materialized = true;
    }
    return error;
}

static LuminaError lumina_decode_extended_filename(
    const LuminaMultipartSlice *slice, unsigned char *dst, size_t cap,
    size_t *decoded_len) {
    static const unsigned char utf8[] = "UTF-8";
    static const unsigned char latin1[] = "ISO-8859-1";
    size_t first_quote = 0;
    while (first_quote < slice->len && slice->ptr[first_quote] != '\'') {
        first_quote++;
    }
    if (first_quote == 0 || first_quote == slice->len) {
        return LUMINA_ERROR_REQBODY_MALFORMED;
    }
    size_t second_quote = first_quote + 1;
    while (second_quote < slice->len && slice->ptr[second_quote] != '\'') {
        second_quote++;
    }
    if (second_quote == slice->len) return LUMINA_ERROR_REQBODY_MALFORMED;
    bool is_utf8 = lumina_ascii_equal_ci(
        slice->ptr, first_quote, utf8, sizeof(utf8) - 1);
    bool is_latin1 = lumina_ascii_equal_ci(
        slice->ptr, first_quote, latin1, sizeof(latin1) - 1);
    if (!is_utf8 && !is_latin1) return LUMINA_ERROR_REQBODY_UNSUPPORTED;

    size_t out = 0;
    for (size_t i = second_quote + 1; i < slice->len; i++) {
        unsigned char c = slice->ptr[i];
        if (c == '%') {
            if (i + 2 >= slice->len) return LUMINA_ERROR_REQBODY_MALFORMED;
            int hi = lumina_form_hex(slice->ptr[i + 1]);
            int lo = lumina_form_hex(slice->ptr[i + 2]);
            if (hi < 0 || lo < 0) return LUMINA_ERROR_REQBODY_MALFORMED;
            c = (unsigned char)((hi << 4) | lo);
            i += 2;
        }
        if (is_latin1 && c >= 0x80u) {
            if (out > cap - 2) return LUMINA_ERROR_REQBODY_LIMIT;
            dst[out++] = (unsigned char)(0xc0u | (c >> 6));
            dst[out++] = (unsigned char)(0x80u | (c & 0x3fu));
        } else {
            if (out == cap) return LUMINA_ERROR_REQBODY_LIMIT;
            dst[out++] = c;
        }
    }
    if (is_utf8 && !lumina_utf8_valid(dst, out)) {
        return LUMINA_ERROR_REQBODY_MALFORMED;
    }
    *decoded_len = out;
    return LUMINA_ERROR_NONE;
}

static LuminaError lumina_scan_multipart_body(
    const unsigned char *data, size_t len, const unsigned char *boundary,
    size_t boundary_len, LuminaRuleState *state, unsigned char *scratch,
    size_t scratch_cap, unsigned depth, int *threat);

static LuminaError lumina_scan_multipart_slice(
    const LuminaMultipartPart *part, const unsigned char *body, size_t body_len,
    LuminaRuleState *state, unsigned char *scratch, size_t scratch_cap,
    unsigned depth, int *threat) {
    const LuminaMultipartSlice *filename =
        part->filename_ext.present ? &part->filename_ext : &part->filename;
    bool filename_is_xml = false;
    if (part->name.present) {
        const unsigned char *value = part->name.ptr;
        size_t value_len = part->name.len;
        if (part->name.needs_unescape) {
            value_len = lumina_unescape_multipart_value(
                &part->name, scratch, scratch_cap);
            if (value_len == SIZE_MAX) return LUMINA_ERROR_REQBODY_LIMIT;
            value = scratch;
        }
        LuminaVarType type = filename->present ? LUMINA_VAR_FILES_NAMES
                                               : LUMINA_VAR_ARGS_NAMES;
        int match = lumina_scan_projected_value(
            value, value_len, LUMINA_SCOPE_BODY, type, state);
        if (match && !*threat) *threat = match;
    }
    if (filename->present) {
        const unsigned char *value = filename->ptr;
        size_t value_len = filename->len;
        LuminaError filename_error = LUMINA_ERROR_NONE;
        if (filename == &part->filename_ext) {
            filename_error = lumina_decode_extended_filename(
                filename, scratch, scratch_cap, &value_len);
            value = scratch;
        } else if (filename->needs_unescape) {
            value_len = lumina_unescape_multipart_value(
                filename, scratch, scratch_cap);
            if (value_len == SIZE_MAX) return LUMINA_ERROR_REQBODY_LIMIT;
            value = scratch;
        }
        if (filename_error != LUMINA_ERROR_NONE) return filename_error;
        filename_is_xml = lumina_is_xml_part(
            nullptr, 0, value, value_len, nullptr, 0);
        int match = lumina_scan_projected_value(
            value, value_len, LUMINA_SCOPE_BODY, LUMINA_VAR_FILES, state);
        if (match && !*threat) *threat = match;
    }

    const unsigned char *decoded = body;
    size_t decoded_len = body_len;
    bool materialized = false;
    LuminaError decode_error = lumina_decode_multipart_body(
        &part->transfer_encoding, body, body_len, scratch, scratch_cap,
        &decoded, &decoded_len, &materialized);
    if (decode_error != LUMINA_ERROR_NONE) return decode_error;

    unsigned char nested_boundary[71];
    size_t nested_boundary_len = 0;
    int nested = part->content_type.present
                     ? lumina_multipart_boundary_from_content_type(
                           part->content_type.ptr, part->content_type.len,
                           nested_boundary, &nested_boundary_len)
                     : 0;
    if (nested < 0) return LUMINA_ERROR_REQBODY_MALFORMED;
    if (nested > 0) {
        if (materialized) return LUMINA_ERROR_REQBODY_UNSUPPORTED;
        return lumina_scan_multipart_body(
            decoded, decoded_len, nested_boundary, nested_boundary_len,
            state, scratch, scratch_cap, depth + 1, threat);
    }

    if (filename_is_xml ||
        lumina_is_xml_part(part->content_type.ptr, part->content_type.len,
                           nullptr, 0, decoded, decoded_len)) {
        state->transaction_flags |= LUMINA_FLAG_HAS_MULTIPART_XML;
        int container_threat = lumina_scan_projected_value_masked(
            decoded, decoded_len, LUMINA_SCOPE_BODY, LUMINA_VAR_XML,
            state, g_short_rule_xml_container_mask, 0,
            LUMINA_PROOF_COHORT_GLOBAL);
        if (container_threat && !*threat) *threat = container_threat;
        int xml_threat = 0;
        LuminaError xml_error = lumina_parse_and_scan_xml(
            decoded, decoded_len, state, &xml_threat);
        if (xml_error != LUMINA_ERROR_NONE) return xml_error;
        if (xml_threat && !*threat) *threat = xml_threat;
    }
    if (part->name.present && !filename->present) {
        int field_threat = lumina_scan_projected_value(
            decoded, decoded_len, LUMINA_SCOPE_BODY, LUMINA_VAR_ARGS, state);
        if (field_threat && !*threat) *threat = field_threat;
    }
    return LUMINA_ERROR_NONE;
}

static LuminaError lumina_scan_multipart_body(
    const unsigned char *data, size_t len, const unsigned char *boundary,
    size_t boundary_len, LuminaRuleState *state, unsigned char *scratch,
    size_t scratch_cap, unsigned depth, int *threat) {
    static const unsigned char content_disposition[] = "content-disposition";
    static const unsigned char content_type[] = "content-type";
    static const unsigned char transfer_encoding[] = "content-transfer-encoding";
    static const unsigned char name_parameter[] = "name";
    static const unsigned char filename_parameter[] = "filename";
    static const unsigned char filename_ext_parameter[] = "filename*";
    if (!data || !boundary || boundary_len == 0 || depth > 4) {
        return depth > 4 ? LUMINA_ERROR_REQBODY_LIMIT
                         : LUMINA_ERROR_REQBODY_MALFORMED;
    }

    bool saw_boundary = false;
    bool saw_closing = false;
    bool in_headers = false;
    bool have_part = false;
    bool headers_complete = false;
    size_t part_body_start = 0;
    size_t part_count = 0;
    size_t header_count = 0;
    LuminaMultipartPart part = {};

    for (size_t start = 0; start <= len;) {
        size_t end = start;
        while (end < len && data[end] != '\n') end++;
        size_t line_len = end - start;
        if (line_len && data[start + line_len - 1] == '\r') line_len--;
        const unsigned char *line = data + start;
        int boundary_kind = lumina_multipart_boundary_line(
            line, line_len, boundary, boundary_len);

        if (boundary_kind) {
            if (have_part) {
                if (in_headers || !headers_complete || start < part_body_start) {
                    return LUMINA_ERROR_REQBODY_MALFORMED;
                }
                size_t current_len = start - part_body_start;
                if (current_len && data[part_body_start + current_len - 1] == '\n') {
                    current_len--;
                }
                if (current_len && data[part_body_start + current_len - 1] == '\r') {
                    current_len--;
                }
                LuminaError part_error = lumina_scan_multipart_slice(
                    &part, data + part_body_start, current_len, state,
                    scratch, scratch_cap, depth, threat);
                if (part_error != LUMINA_ERROR_NONE) return part_error;
            }
            saw_boundary = true;
            if (boundary_kind == 2) {
                saw_closing = true;
                have_part = false;
                break;
            }
            if (++part_count > 256) return LUMINA_ERROR_REQBODY_LIMIT;
            memset(&part, 0, sizeof(part));
            have_part = true;
            headers_complete = false;
            in_headers = true;
            header_count = 0;
        } else if (have_part && in_headers) {
            if (line_len == 0) {
                in_headers = false;
                headers_complete = true;
                part_body_start = end < len ? end + 1 : end;
            } else {
                if (line[0] == ' ' || line[0] == '\t') {
                    int native_threat = lumina_commit_native_rule(
                        state, 922130, 5, LUMINA_CAT_PROCOL);
                    if (native_threat && !*threat) *threat = native_threat;
                    return LUMINA_ERROR_NONE;
                }
                if (++header_count > 64) {
                    return LUMINA_ERROR_REQBODY_LIMIT;
                }
                size_t colon = 0;
                while (colon < line_len && line[colon] != ':') colon++;
                if (colon == 0 || colon == line_len) {
                    return LUMINA_ERROR_REQBODY_MALFORMED;
                }
                for (size_t i = 0; i < colon; i++) {
                    unsigned char c = line[i];
                    if (c < 0x21u || c > 0x7eu) {
                        int native_threat = lumina_commit_native_rule(
                            state, 922130, 5, LUMINA_CAT_PROCOL);
                        if (native_threat && !*threat) *threat = native_threat;
                        return LUMINA_ERROR_NONE;
                    }
                    if (!((c >= '0' && c <= '9') ||
                          (c >= 'A' && c <= 'Z') ||
                          (c >= 'a' && c <= 'z') || c == '-')) {
                        return LUMINA_ERROR_REQBODY_MALFORMED;
                    }
                }
                size_t value_start = colon + 1;
                while (value_start < line_len &&
                       (line[value_start] == ' ' || line[value_start] == '\t')) {
                    value_start++;
                }
                size_t value_end = line_len;
                while (value_end > value_start &&
                       (line[value_end - 1] == ' ' ||
                        line[value_end - 1] == '\t')) {
                    value_end--;
                }
                if (lumina_ascii_equal_ci(
                        line, colon, content_disposition,
                        sizeof(content_disposition) - 1)) {
                    if (part.saw_disposition) {
                        return LUMINA_ERROR_REQBODY_MALFORMED;
                    }
                    part.saw_disposition = true;
                    if (lumina_multipart_parameter(
                            line, line_len, name_parameter,
                            sizeof(name_parameter) - 1, &part.name) < 0 ||
                        lumina_multipart_parameter(
                            line, line_len, filename_parameter,
                            sizeof(filename_parameter) - 1,
                            &part.filename) < 0 ||
                        lumina_multipart_parameter(
                            line, line_len, filename_ext_parameter,
                            sizeof(filename_ext_parameter) - 1,
                            &part.filename_ext) < 0) {
                        return LUMINA_ERROR_REQBODY_MALFORMED;
                    }
                } else if (lumina_ascii_equal_ci(
                               line, colon, content_type,
                               sizeof(content_type) - 1)) {
                    if (part.content_type.present || value_start == value_end) {
                        return LUMINA_ERROR_REQBODY_MALFORMED;
                    }
                    part.content_type = {
                        line + value_start, value_end - value_start, false, true};
                } else if (lumina_ascii_equal_ci(
                               line, colon, transfer_encoding,
                               sizeof(transfer_encoding) - 1)) {
                    int native_threat = lumina_commit_native_rule(
                        state, 922120, 5, LUMINA_CAT_PROCOL);
                    if (native_threat && !*threat) *threat = native_threat;
                    if (part.transfer_encoding.present ||
                        value_start == value_end) {
                        return LUMINA_ERROR_REQBODY_MALFORMED;
                    }
                    part.transfer_encoding = {
                        line + value_start, value_end - value_start, false, true};
                }
            }
        }
        if (end == len) break;
        start = end + 1;
    }
    if (!saw_boundary || !saw_closing) {
        return LUMINA_ERROR_REQBODY_MALFORMED;
    }
    return LUMINA_ERROR_NONE;
}

static LuminaError lumina_scan_multipart_file_collections(
    const LuminaBundle *bundle, LuminaRuleState *state, unsigned char *scratch,
    size_t scratch_cap, int *threat) {
    unsigned char boundary[71];
    size_t boundary_len = 0;
    int boundary_status =
        lumina_multipart_boundary(bundle, boundary, &boundary_len);
    if (boundary_status == 0) return LUMINA_ERROR_NONE;
    if (boundary_status < 0) return LUMINA_ERROR_REQBODY_MALFORMED;
    for (int vi = 0; vi < bundle->count; vi++) {
        const BundleVar *body = &bundle->vars[vi];
        if (body->var_type != LUMINA_VAR_BODY || !body->ptr) continue;
        LuminaError error = lumina_scan_multipart_body(
            body->ptr, body->len, boundary, boundary_len, state,
            scratch, scratch_cap, 0, threat);
        if (error != LUMINA_ERROR_NONE) return error;
    }
    return LUMINA_ERROR_NONE;
}

static bool lumina_bundle_processor_is(const LuminaBundle *bundle,
                                       const unsigned char *expected,
                                       size_t expected_len) {
    if (!bundle || !expected || expected_len == 0 ||
        !bundle->reqbody_processor || bundle->reqbody_processor_len != expected_len) {
        return false;
    }
    for (size_t i = 0; i < expected_len; i++) {
        unsigned char value = bundle->reqbody_processor[i];
        if (value >= 'a' && value <= 'z') value &= 0xdfu;
        if (value != expected[i]) return false;
    }
    return true;
}

static bool lumina_bundle_has_json_body(const LuminaBundle *bundle) {
    static const unsigned char processor[] = "JSON";
    if (lumina_bundle_processor_is(bundle, processor, sizeof(processor) - 1)) return true;

    /* Compatibility fallback for callers using the pre-REQBODY_PROCESSOR ABI. */
    static const unsigned char expected[] = "application/json";
    for (int i = 0; i < bundle->count; i++) {
        const BundleVar *var = &bundle->vars[i];
        if (var->var_type != LUMINA_VAR_HDR ||
            !(var->header_mask & LUMINA_HDR_CONTENT_TYPE) ||
            !var->ptr) continue;
        if (var->len < sizeof(expected) - 1) continue;
        bool equal = true;
        for (size_t j = 0; j < sizeof(expected) - 1; j++) {
            unsigned char value = var->ptr[j];
            if (value >= 'A' && value <= 'Z') value |= 0x20u;
            if (value != expected[j]) {
                equal = false;
                break;
            }
        }
        if (equal) return true;
    }
    return false;
}

static bool lumina_bundle_has_xml_body(const LuminaBundle *bundle) {
    static const unsigned char processor[] = "XML";
    return lumina_bundle_processor_is(bundle, processor, sizeof(processor) - 1);
}

typedef struct {
    const unsigned char *data;
    size_t len;
    size_t pos;
    unsigned char *scratch;
    size_t scratch_size;
    LuminaRuleState *state;
    int threat;
    LuminaError error;
} LuminaJsonParser;

typedef struct {
    const unsigned char *ptr;
    size_t len;
    bool materialized;
} LuminaJsonString;

static inline void lumina_json_skip_ws(LuminaJsonParser *parser) {
    while (parser->pos < parser->len) {
        unsigned char c = parser->data[parser->pos];
        if (c != ' ' && c != '\t' && c != '\n' && c != '\r') break;
        parser->pos++;
    }
}

static bool lumina_utf8_valid(const unsigned char *data, size_t len) {
    size_t i = 0;
    while (i < len) {
        unsigned char c = data[i++];
        if (c < 0x80) continue;
        unsigned codepoint;
        size_t continuation;
        unsigned minimum;
        if (c >= 0xc2 && c <= 0xdf) {
            codepoint = c & 0x1fu;
            continuation = 1;
            minimum = 0x80u;
        } else if (c >= 0xe0 && c <= 0xef) {
            codepoint = c & 0x0fu;
            continuation = 2;
            minimum = 0x800u;
        } else if (c >= 0xf0 && c <= 0xf4) {
            codepoint = c & 0x07u;
            continuation = 3;
            minimum = 0x10000u;
        } else {
            return false;
        }
        if (continuation > len - i) return false;
        for (size_t j = 0; j < continuation; j++) {
            unsigned char next = data[i++];
            if ((next & 0xc0u) != 0x80u) return false;
            codepoint = (codepoint << 6) | (next & 0x3fu);
        }
        if (codepoint < minimum || codepoint > 0x10ffffu ||
            (codepoint >= 0xd800u && codepoint <= 0xdfffu)) {
            return false;
        }
    }
    return true;
}

static bool lumina_json_hex4(const unsigned char *data, unsigned *value) {
    unsigned result = 0;
    for (size_t i = 0; i < 4; i++) {
        unsigned char c = data[i];
        result <<= 4;
        if (c >= '0' && c <= '9') result |= c - '0';
        else if (c >= 'a' && c <= 'f') result |= c - 'a' + 10u;
        else if (c >= 'A' && c <= 'F') result |= c - 'A' + 10u;
        else return false;
    }
    *value = result;
    return true;
}

static bool lumina_json_emit_utf8(unsigned char *dst, size_t cap,
                                  size_t *out_len, unsigned codepoint) {
    size_t need = codepoint <= 0x7fu ? 1 :
                  codepoint <= 0x7ffu ? 2 :
                  codepoint <= 0xffffu ? 3 : 4;
    if (need > cap - *out_len) return false;
    if (need == 1) {
        dst[(*out_len)++] = (unsigned char)codepoint;
    } else if (need == 2) {
        dst[(*out_len)++] = (unsigned char)(0xc0u | (codepoint >> 6));
        dst[(*out_len)++] = (unsigned char)(0x80u | (codepoint & 0x3fu));
    } else if (need == 3) {
        dst[(*out_len)++] = (unsigned char)(0xe0u | (codepoint >> 12));
        dst[(*out_len)++] = (unsigned char)(0x80u | ((codepoint >> 6) & 0x3fu));
        dst[(*out_len)++] = (unsigned char)(0x80u | (codepoint & 0x3fu));
    } else {
        dst[(*out_len)++] = (unsigned char)(0xf0u | (codepoint >> 18));
        dst[(*out_len)++] = (unsigned char)(0x80u | ((codepoint >> 12) & 0x3fu));
        dst[(*out_len)++] = (unsigned char)(0x80u | ((codepoint >> 6) & 0x3fu));
        dst[(*out_len)++] = (unsigned char)(0x80u | (codepoint & 0x3fu));
    }
    return true;
}

static bool lumina_json_parse_string(LuminaJsonParser *parser,
                                     LuminaJsonString *value) {
    if (parser->pos >= parser->len || parser->data[parser->pos] != '"') {
        return false;
    }
    parser->pos++;
    const size_t raw_start = parser->pos;
    size_t copied_until = raw_start;
    size_t out_len = 0;
    bool materialized =
#if defined(LUMINA_LEGACY_JSON_STRING_MATERIALIZATION)
        true;
#else
        false;
#endif

    while (parser->pos < parser->len) {
        unsigned char c = parser->data[parser->pos];
        if (c == '"') {
            const size_t raw_end = parser->pos++;
            if (materialized) {
                if (raw_end > copied_until) {
                    size_t tail = raw_end - copied_until;
                    if (tail > parser->scratch_size - out_len) return false;
                    memcpy(parser->scratch + out_len,
                           parser->data + copied_until, tail);
                    out_len += tail;
                }
                value->ptr = parser->scratch;
                value->len = out_len;
                value->materialized = true;
            } else {
                value->ptr = parser->data + raw_start;
                value->len = raw_end - raw_start;
                value->materialized = false;
            }
            return lumina_utf8_valid(value->ptr, value->len);
        }
        if (c < 0x20u) return false;
        if (c != '\\') {
            parser->pos++;
            continue;
        }

        if (!materialized) {
            out_len = parser->pos - raw_start;
            if (out_len > parser->scratch_size) return false;
            if (out_len != 0) {
                memcpy(parser->scratch, parser->data + raw_start, out_len);
            }
            materialized = true;
        } else if (parser->pos > copied_until) {
            size_t plain = parser->pos - copied_until;
            if (plain > parser->scratch_size - out_len) return false;
            memcpy(parser->scratch + out_len, parser->data + copied_until, plain);
            out_len += plain;
        }

        parser->pos++;
        if (parser->pos >= parser->len) return false;
        unsigned char escaped = parser->data[parser->pos++];
        copied_until = parser->pos;
        unsigned char decoded = 0;
        bool single = true;
        switch (escaped) {
            case '"': decoded = '"'; break;
            case '\\': decoded = '\\'; break;
            case '/': decoded = '/'; break;
            case 'b': decoded = '\b'; break;
            case 'f': decoded = '\f'; break;
            case 'n': decoded = '\n'; break;
            case 'r': decoded = '\r'; break;
            case 't': decoded = '\t'; break;
            case 'u': {
                single = false;
                if (parser->len - parser->pos < 4) return false;
                unsigned codepoint;
                if (!lumina_json_hex4(parser->data + parser->pos, &codepoint)) {
                    return false;
                }
                parser->pos += 4;
                copied_until = parser->pos;
                if (codepoint >= 0xd800u && codepoint <= 0xdbffu) {
                    if (parser->len - parser->pos < 6 ||
                        parser->data[parser->pos] != '\\' ||
                        parser->data[parser->pos + 1] != 'u') {
                        return false;
                    }
                    unsigned low;
                    if (!lumina_json_hex4(parser->data + parser->pos + 2, &low) ||
                        low < 0xdc00u || low > 0xdfffu) {
                        return false;
                    }
                    parser->pos += 6;
                    copied_until = parser->pos;
                    codepoint = 0x10000u +
                        ((codepoint - 0xd800u) << 10) + (low - 0xdc00u);
                } else if (codepoint >= 0xdc00u && codepoint <= 0xdfffu) {
                    return false;
                }
                if (!lumina_json_emit_utf8(parser->scratch,
                                           parser->scratch_size,
                                           &out_len, codepoint)) {
                    return false;
                }
                break;
            }
            default:
                return false;
        }
        if (single) {
            if (out_len == parser->scratch_size) return false;
            parser->scratch[out_len++] = decoded;
        }
    }
    return false;
}

static void lumina_json_scan_value(LuminaJsonParser *parser,
                                   const unsigned char *value, size_t len,
                                   LuminaVarType var_type,
                                   bool materialized) {
    if (materialized) {
        LUMINA_DIAG_ADD(json_materialized_values, 1);
        LUMINA_DIAG_ADD(json_materialized_bytes, len);
    } else {
        LUMINA_DIAG_ADD(json_zero_copy_values, 1);
        LUMINA_DIAG_ADD(json_zero_copy_bytes, len);
    }
    if (len == 0) return;
    int match = lumina_scan_projected_value(
        value, len, LUMINA_SCOPE_BODY, var_type, parser->state);
    if (match) parser->threat = match;
}

static bool lumina_json_parse_value(LuminaJsonParser *parser, unsigned depth);

static bool lumina_json_parse_object(LuminaJsonParser *parser, unsigned depth) {
    parser->pos++;
    lumina_json_skip_ws(parser);
    if (parser->pos < parser->len && parser->data[parser->pos] == '}') {
        parser->pos++;
        return true;
    }
    while (parser->pos < parser->len) {
        LuminaJsonString key = {};
        if (!lumina_json_parse_string(parser, &key)) return false;
        lumina_json_scan_value(parser, key.ptr, key.len,
                               LUMINA_VAR_ARGS_NAMES, key.materialized);
        lumina_json_skip_ws(parser);
        if (parser->pos >= parser->len || parser->data[parser->pos++] != ':') {
            return false;
        }
        if (!lumina_json_parse_value(parser, depth)) return false;
        lumina_json_skip_ws(parser);
        if (parser->pos >= parser->len) return false;
        unsigned char separator = parser->data[parser->pos++];
        if (separator == '}') return true;
        if (separator != ',') return false;
        lumina_json_skip_ws(parser);
    }
    return false;
}

static bool lumina_json_parse_array(LuminaJsonParser *parser, unsigned depth) {
    parser->pos++;
    lumina_json_skip_ws(parser);
    if (parser->pos < parser->len && parser->data[parser->pos] == ']') {
        parser->pos++;
        return true;
    }
    while (parser->pos < parser->len) {
        if (!lumina_json_parse_value(parser, depth)) return false;
        lumina_json_skip_ws(parser);
        if (parser->pos >= parser->len) return false;
        unsigned char separator = parser->data[parser->pos++];
        if (separator == ']') return true;
        if (separator != ',') return false;
        lumina_json_skip_ws(parser);
    }
    return false;
}

static bool lumina_json_parse_number(LuminaJsonParser *parser) {
    const size_t start = parser->pos;
    if (parser->data[parser->pos] == '-') {
        parser->pos++;
        if (parser->pos == parser->len) return false;
    }
    if (parser->data[parser->pos] == '0') {
        parser->pos++;
        if (parser->pos < parser->len &&
            parser->data[parser->pos] >= '0' &&
            parser->data[parser->pos] <= '9') {
            return false;
        }
    } else {
        if (parser->data[parser->pos] < '1' ||
            parser->data[parser->pos] > '9') return false;
        do {
            parser->pos++;
        } while (parser->pos < parser->len &&
                 parser->data[parser->pos] >= '0' &&
                 parser->data[parser->pos] <= '9');
    }
    if (parser->pos < parser->len && parser->data[parser->pos] == '.') {
        parser->pos++;
        size_t fraction = parser->pos;
        while (parser->pos < parser->len &&
               parser->data[parser->pos] >= '0' &&
               parser->data[parser->pos] <= '9') {
            parser->pos++;
        }
        if (parser->pos == fraction) return false;
    }
    if (parser->pos < parser->len &&
        (parser->data[parser->pos] == 'e' ||
         parser->data[parser->pos] == 'E')) {
        parser->pos++;
        if (parser->pos < parser->len &&
            (parser->data[parser->pos] == '+' ||
             parser->data[parser->pos] == '-')) {
            parser->pos++;
        }
        size_t exponent = parser->pos;
        while (parser->pos < parser->len &&
               parser->data[parser->pos] >= '0' &&
               parser->data[parser->pos] <= '9') {
            parser->pos++;
        }
        if (parser->pos == exponent) return false;
    }
    lumina_json_scan_value(parser, parser->data + start,
                           parser->pos - start, LUMINA_VAR_ARGS, false);
    return true;
}

static bool lumina_json_parse_literal(LuminaJsonParser *parser,
                                      const char *literal, size_t len) {
    if (len > parser->len - parser->pos ||
        memcmp(parser->data + parser->pos, literal, len) != 0) {
        return false;
    }
    lumina_json_scan_value(parser, parser->data + parser->pos,
                           len, LUMINA_VAR_ARGS, false);
    parser->pos += len;
    return true;
}

static bool lumina_json_parse_value(LuminaJsonParser *parser, unsigned depth) {
    lumina_json_skip_ws(parser);
    if (parser->pos >= parser->len) return false;
    if (depth > 64u) {
        parser->error = LUMINA_ERROR_REQBODY_LIMIT;
        return false;
    }
    unsigned char c = parser->data[parser->pos];
    if (c == '{') return lumina_json_parse_object(parser, depth + 1u);
    if (c == '[') return lumina_json_parse_array(parser, depth + 1u);
    if (c == '"') {
        LuminaJsonString value = {};
        if (!lumina_json_parse_string(parser, &value)) return false;
        lumina_json_scan_value(parser, value.ptr, value.len,
                               LUMINA_VAR_ARGS, value.materialized);
        return true;
    }
    if (c == '-' || (c >= '0' && c <= '9')) {
        return lumina_json_parse_number(parser);
    }
    if (c == 't') return lumina_json_parse_literal(parser, "true", 4);
    if (c == 'f') return lumina_json_parse_literal(parser, "false", 5);
    if (c == 'n') return lumina_json_parse_literal(parser, "null", 4);
    return false;
}

static LuminaError lumina_parse_and_project_json(
    const unsigned char *data, size_t len, LuminaRuleState *state,
    unsigned char *scratch, size_t scratch_size, int *threat) {
    if (!data || len == 0 || !state || !scratch || scratch_size < len) {
        return LUMINA_ERROR_REQBODY_LIMIT;
    }
    LuminaJsonParser parser = {
        data, len, 0, scratch, scratch_size, state, 0,
        LUMINA_ERROR_NONE
    };
    if (!lumina_json_parse_value(&parser, 0u)) {
        return parser.error == LUMINA_ERROR_NONE
                   ? LUMINA_ERROR_REQBODY_MALFORMED
                   : parser.error;
    }
    lumina_json_skip_ws(&parser);
    if (parser.pos != parser.len) {
        return LUMINA_ERROR_REQBODY_MALFORMED;
    }
    if (threat) *threat = parser.threat;
    return LUMINA_ERROR_NONE;
}

static int lumina_scan_projected_collections(const LuminaBundle *bundle,
                                             LuminaRuleState *state) {
    int threat = 0;
    if (bundle->req_filename && bundle->req_filename_len > 0) {
        int projected_match = lumina_scan_projected_value(
            bundle->req_filename, bundle->req_filename_len, LUMINA_SCOPE_URI,
            LUMINA_VAR_REQUEST_FILENAME, state);
        if (projected_match) threat = projected_match;
    }
    if (bundle->req_basename && bundle->req_basename_len > 0) {
        int projected_match = lumina_scan_projected_value(
            bundle->req_basename, bundle->req_basename_len, LUMINA_SCOPE_URI,
            LUMINA_VAR_REQUEST_BASENAME, state);
        if (projected_match) threat = projected_match;
    }
    bool scan_form_body = lumina_bundle_has_form_urlencoded_body(bundle);
    bool scan_json_body = lumina_bundle_has_json_body(bundle);
    bool scan_xml_body = lumina_bundle_has_xml_body(bundle);
    static thread_local unsigned char projected[LUMINA_MAX_INSPECTED_VALUE];

    /*
     * ModSecurity keeps JSON REQUEST_BODY available alongside projected ARGS.
     * XML rules consume projected element/attribute values instead; scanning
     * the serialized XML would incorrectly expose tag and attribute names.
     */
    if (scan_json_body) {
        for (int vi = 0; vi < bundle->count; vi++) {
            const BundleVar *var = &bundle->vars[vi];
            if (var->var_type != LUMINA_VAR_BODY || !var->ptr || var->len == 0) {
                continue;
            }
            int raw_threat = lumina_scan_raw_request_body(var, state);
            if (raw_threat) threat = raw_threat;
        }
    }
    if (scan_json_body) {
        for (int vi = 0; vi < bundle->count; vi++) {
            const BundleVar *var = &bundle->vars[vi];
            if (var->var_type == LUMINA_VAR_BODY && var->ptr && var->len > 0) {
                int json_threat = 0;
                LuminaError json_error = lumina_parse_and_project_json(
                    var->ptr, var->len, state, projected, sizeof(projected),
                    &json_threat);
                if (json_error == LUMINA_ERROR_REQBODY_MALFORMED) {
                    state->transaction_flags |= LUMINA_FLAG_REQBODY_MALFORMED;
                } else if (json_error == LUMINA_ERROR_REQBODY_UNSUPPORTED) {
                    state->transaction_flags |= LUMINA_FLAG_REQBODY_UNSUPPORTED;
                } else if (json_error == LUMINA_ERROR_REQBODY_LIMIT) {
                    state->transaction_flags |= LUMINA_FLAG_REQBODY_LIMIT;
                }
                if (json_threat) threat = json_threat;
            }
        }
    }
    if (scan_xml_body) {
        for (int vi = 0; vi < bundle->count; vi++) {
            const BundleVar *var = &bundle->vars[vi];
            if (var->var_type == LUMINA_VAR_BODY && var->ptr && var->len > 0) {
                int container_threat = lumina_scan_projected_value_masked(
                    var->ptr, var->len, LUMINA_SCOPE_BODY, LUMINA_VAR_XML,
                    state, g_short_rule_xml_container_mask, 0,
                    LUMINA_PROOF_COHORT_GLOBAL);
                if (container_threat) threat = container_threat;
                int xml_threat = 0;
                LuminaError xml_error = lumina_parse_and_scan_xml(
                    var->ptr, var->len, state, &xml_threat);
                if (xml_error == LUMINA_ERROR_REQBODY_MALFORMED) {
                    state->transaction_flags |= LUMINA_FLAG_REQBODY_MALFORMED;
                } else if (xml_error == LUMINA_ERROR_REQBODY_UNSUPPORTED) {
                    state->transaction_flags |= LUMINA_FLAG_REQBODY_UNSUPPORTED;
                } else if (xml_error == LUMINA_ERROR_REQBODY_LIMIT) {
                    state->transaction_flags |= LUMINA_FLAG_REQBODY_LIMIT;
                } else if (xml_error == LUMINA_ERROR_REQBODY_FORBIDDEN) {
                    state->transaction_flags |= LUMINA_FLAG_REQBODY_FORBIDDEN;
                }
                if (xml_threat) threat = xml_threat;
            }
        }
    }
    int multipart_threat = 0;
    LuminaError multipart_error = lumina_scan_multipart_file_collections(
        bundle, state, projected, sizeof(projected), &multipart_threat);
    if (multipart_error == LUMINA_ERROR_REQBODY_MALFORMED) {
        state->transaction_flags |= LUMINA_FLAG_REQBODY_MALFORMED;
    } else if (multipart_error == LUMINA_ERROR_REQBODY_UNSUPPORTED) {
        state->transaction_flags |= LUMINA_FLAG_REQBODY_UNSUPPORTED;
    } else if (multipart_error == LUMINA_ERROR_REQBODY_LIMIT) {
        state->transaction_flags |= LUMINA_FLAG_REQBODY_LIMIT;
    } else if (multipart_error == LUMINA_ERROR_REQBODY_FORBIDDEN) {
        state->transaction_flags |= LUMINA_FLAG_REQBODY_FORBIDDEN;
    }
    if (multipart_threat) threat = multipart_threat;
    for (int vi = 0; vi < bundle->count; vi++) {
        const BundleVar *var = &bundle->vars[vi];
        bool is_query_args = var->var_type == LUMINA_VAR_ARGS;
        bool is_form_body = scan_form_body && var->var_type == LUMINA_VAR_BODY;
        bool is_cookie_container = var->var_type == LUMINA_VAR_COOKIE;
        if ((!is_query_args && !is_form_body && !is_cookie_container) ||
            !var->ptr || var->len == 0) continue;

        if (is_cookie_container) {
            /* REQUEST_COOKIES is projected below, but the original Cookie
             * field is also a REQUEST_HEADERS value. Reuse the same bytes and
             * run only the header-typed active mask; no duplicate BundleVar or
             * copy is needed. */
            int header_threat = lumina_scan_projected_value_masked(
                var->ptr, var->len, var->scope, LUMINA_VAR_HDR, state, NULL,
                var->header_mask, LUMINA_PROOF_COHORT_GLOBAL);
            if (header_threat) threat = header_threat;
            size_t start = 0;
            while (start <= var->len) {
                size_t next = start;
                while (next < var->len && var->ptr[next] != ';') next++;
                size_t end = next;
                while (start < end && (var->ptr[start] == ' ' || var->ptr[start] == '\t')) start++;
                while (end > start && (var->ptr[end - 1] == ' ' || var->ptr[end - 1] == '\t')) end--;
                size_t equal = start;
                while (equal < end && var->ptr[equal] != '=') equal++;
                if (equal < end) {
                    size_t name_end = equal;
                    while (name_end > start && (var->ptr[name_end - 1] == ' ' ||
                                                var->ptr[name_end - 1] == '\t')) name_end--;
                    size_t value_start = equal + 1;
                    while (value_start < end && (var->ptr[value_start] == ' ' ||
                                                 var->ptr[value_start] == '\t')) value_start++;
                    static const unsigned char version_name[] = "$Version";
                    bool version_cookie = false;
                    if (name_end - start >= sizeof(version_name) - 1) {
                        for (size_t pos = start;
                             pos + sizeof(version_name) - 1 <= name_end;
                             pos++) {
                            if (memcmp(var->ptr + pos, version_name,
                                       sizeof(version_name) - 1) == 0) {
                                version_cookie = true;
                                break;
                            }
                        }
                    }
                    if (version_cookie && end - value_start == 1 &&
                        var->ptr[value_start] == '1') {
                        int native_threat = lumina_commit_native_rule(
                            state, 921250, 5, LUMINA_CAT_PROCOL);
                        if (native_threat) threat = native_threat;
                    }
                    if (name_end > start) {
                        int projected_match = lumina_scan_projected_value(
                            var->ptr + start, name_end - start, var->scope,
                            LUMINA_VAR_COOKIE_NAMES, state);
                        if (projected_match) threat = projected_match;
                    }
                    if (value_start < end) {
                        int projected_match = lumina_scan_projected_value(
                            var->ptr + value_start, end - value_start, var->scope,
                            LUMINA_VAR_COOKIE, state);
                        if (projected_match) threat = projected_match;
                    }
                } else if (end > start) {
                    int projected_match = lumina_scan_projected_value(
                        var->ptr + start, end - start, var->scope,
                        LUMINA_VAR_COOKIE, state);
                    if (projected_match) threat = projected_match;
                }
                if (next == var->len) break;
                start = next + 1;
            }
            continue;
        }

        if (is_query_args) {
            int projected_threat = lumina_scan_projected_value(
                var->ptr, var->len, var->scope, LUMINA_VAR_QUERY_STRING, state);
            if (projected_threat) threat = projected_threat;
        }

        size_t start = 0;
        while (start <= var->len) {
            size_t end = start;
            while (end < var->len && var->ptr[end] != '&') end++;
            size_t key_end = start;
            while (key_end < end && var->ptr[key_end] != '=') key_end++;
            if (key_end > start) {
                size_t decoded_len = lumina_decode_form_component(
                    var->ptr + start, key_end - start, projected, sizeof(projected));
                if (decoded_len != SIZE_MAX && decoded_len > 0) {
                    int projected_match = lumina_scan_projected_value(
                        projected, decoded_len, var->scope,
                        LUMINA_VAR_ARGS_NAMES, state);
                    if (projected_match) threat = projected_match;
                }
            }
            size_t value_start = key_end < end ? key_end + 1 : end;
            if (value_start < end) {
                size_t decoded_len = lumina_decode_form_component(
                    var->ptr + value_start, end - value_start, projected, sizeof(projected));
                if (decoded_len != SIZE_MAX && decoded_len > 0) {
                    int projected_threat = lumina_scan_projected_value(
                        projected, decoded_len, var->scope, LUMINA_VAR_ARGS, state);
                    if (projected_threat) threat = projected_threat;
                }
            }
            if (end == var->len) break;
            start = end + 1;
        }
    }
    return threat;
}

extern "C" int lumina_eval_tx_rules(const LuminaBundle *bundle, LuminaRuleState *state);

static int lumina_audit_scan_variable(const BundleVar *var, LuminaRuleState *state,
                                      const uint64_t *eligibility_mask) {
    if (!var || !state || (!var->ptr && var->len != 0) || var->len > LUMINA_MAX_INSPECTED_VALUE) return -1;
    lumina_eval_target_controls(
        var->ptr, var->len, var->collection_mask, state);
    uint64_t disabled_mask[CRS_SHORT_RULE_MASK_DIMS];
    lumina_build_disabled_mask(state, var->collection_mask, disabled_mask);
    if (var->len == 0) {
        (void)lumina_scan_empty_variable(var, state);
        return 0;
    }

    int is_malloc = 0;
    size_t decoded_len = 0;
    uint32_t decode_scope = var->scope |
        ((var->var_type == LUMINA_VAR_ARGS || var->var_type == LUMINA_VAR_ARGS_NAMES) ? (uint32_t)LUMINA_SCOPE_FORM_URLENCODED : 0u);
    unsigned char *decoded = lumina_canonicalize(
        var->ptr, var->len, decode_scope, &decoded_len, &is_malloc);
    if (!decoded || decoded_len > LUMINA_MAX_INSPECTED_VALUE) {
        if (decoded) lumina_canonicalize_free(decoded, is_malloc);
        return -1;
    }
    lumina_reset_transform_view_cache();

    LuminaShortRuleActiveMask active;
    uint32_t header_mask = (var->var_type == LUMINA_VAR_HDR) ? var->header_mask : 0;
    lumina_build_short_rule_active_mask(
        &active, var->scope, header_mask, (uint8_t)var->var_type);
    LuminaShortRuleEffectiveMask effective;
    lumina_build_short_rule_effective_mask(
        &effective, &active, eligibility_mask, disabled_mask);
    uint64_t processed_transform_search[CRS_SHORT_RULE_MASK_DIMS] = {};

    uint8_t first = decoded[0];
    for (int word = 0; word < CRS_SHORT_RULE_MASK_DIMS; word++) {
        uint64_t candidates = g_short_rule_mask[first][word] & effective.pos0[word];
        while (candidates) {
            int idx = __builtin_ctzll(candidates) + (word << 6);
            candidates &= candidates - 1;
            if (g_short_rule_collection_mask[idx] && !(g_short_rule_collection_mask[idx] & var->collection_mask)) {
                continue;
            }
            if (g_short_rule_transform_search[idx]) {
                const uint64_t bit = UINT64_C(1) << (idx & 63);
                if (processed_transform_search[word] & bit) continue;
                processed_transform_search[word] |= bit;
            }
            int rule_id = lumina_dispatch_rule(idx, decoded, decoded_len, 0);
            if (rule_id) {
                if (g_short_rule_score[idx] == 0) {
                    lumina_slab_mark(&state->predicate_rules, idx);
                } else {
                    lumina_record_rule_match(state, rule_id, "scan_pos0");
                }
            }
        }
    }

    for (size_t offset = 1; offset < decoded_len; offset++) {
        uint8_t byte = decoded[offset];
        for (int word = 0; word < CRS_SHORT_RULE_MASK_DIMS; word++) {
            uint64_t candidates = g_short_rule_mask[byte][word] & effective.posN[word];
            while (candidates) {
                int idx = __builtin_ctzll(candidates) + (word << 6);
                candidates &= candidates - 1;
                if (g_short_rule_collection_mask[idx] && !(g_short_rule_collection_mask[idx] & var->collection_mask)) {
                    continue;
                }
                size_t dispatch_offset = offset;
                if (g_short_rule_transform_search[idx]) {
                    const uint64_t bit = UINT64_C(1) << (idx & 63);
                    if (processed_transform_search[word] & bit) continue;
                    processed_transform_search[word] |= bit;
                    dispatch_offset = 0;
                }
                int rule_id = lumina_dispatch_rule(
                    idx, decoded, decoded_len, dispatch_offset);
                if (rule_id) {
                    if (g_short_rule_score[idx] == 0) {
                        lumina_slab_mark(&state->predicate_rules, idx);
                    } else {
                        lumina_record_rule_match(state, rule_id, "scan_pos0");
                    }
                }
            }
        }
    }

    lumina_canonicalize_free(decoded, is_malloc);
    return 0;
}

int luminawaf_audit_bundle_matches(const LuminaBundle *bundle, LuminaRuleState *state) {
    if (!bundle || !state || bundle->count < 0 ||
        bundle->count > LUMINA_BUNDLE_MAX_VARS) return -1;
    int status = 0;
    bool scan_form_body = lumina_bundle_has_form_urlencoded_body(bundle);
    bool scan_structured_body = lumina_bundle_has_json_body(bundle) ||
                                lumina_bundle_has_xml_body(bundle);
    /* Phase controls must be applied before any target rule can enter the
     * exact-match set. Re-evaluation below is idempotent and resolves rules
     * whose predicates are produced by collection scans. */
    (void)lumina_eval_tx_rules(bundle, state);
    (void)lumina_scan_projected_collections(bundle, state);
    for (int i = 0; i < bundle->count; i++) {
        const BundleVar *var = &bundle->vars[i];
        if (var->var_type == LUMINA_VAR_ARGS || var->var_type == LUMINA_VAR_COOKIE) continue;
        if (scan_structured_body && var->var_type == LUMINA_VAR_BODY) continue;
        const uint64_t *eligible = scan_form_body && var->var_type == LUMINA_VAR_BODY
                                       ? g_short_rule_request_body_mask : NULL;
        if (lumina_audit_scan_variable(var, state, eligible) != 0) status = -1;
    }
    (void)lumina_eval_tx_rules(bundle, state);
    return status;
}

static int lumina_audit_rule_variable(int idx, const BundleVar *var, LuminaRuleState *state,
                                      bool restrict_to_request_body) {
    if (!var || (!var->ptr && var->len != 0) || var->len > LUMINA_MAX_INSPECTED_VALUE) return 0;
    if (lumina_engine_rule_is_disabled(state, idx)) return 0;
    if ((g_short_rule_scope[idx] & var->scope) == 0) return 0;
    if (var->var_type >= LUMINA_VAR_TYPE_SLOTS || var->var_type == LUMINA_VAR_ANY) return 0;
    if ((g_short_rule_var_type[idx] & (1u << var->var_type)) == 0) return 0;
    if (restrict_to_request_body &&
        (g_short_rule_request_body_mask[idx >> 6] & (1ULL << (idx & 63))) == 0) return 0;
    if (var->var_type == LUMINA_VAR_HDR && g_short_rule_hdr_mask[idx] != 0 &&
        (g_short_rule_hdr_mask[idx] & var->header_mask) == 0) return 0;
    if (var->len == 0) {
        uint64_t bit = 1ULL << (idx & 63);
        if ((g_short_rule_empty_mask[idx >> 6] & bit) != 0 &&
            (!g_short_rule_collection_mask[idx] ||
             (g_short_rule_collection_mask[idx] & var->collection_mask))) {
            int matched_id = lumina_dispatch_rule(idx, var->ptr, 0, 0);
            if (!matched_id) return 0;
            if (g_short_rule_score[idx] == 0)
                lumina_slab_mark(&state->predicate_rules, idx);
            else
                lumina_record_rule_match(state, matched_id, "audit_empty");
        }
        return 0;
    }

    int is_malloc = 0;
    size_t decoded_len = 0;
    uint32_t decode_scope = var->scope |
        ((var->var_type == LUMINA_VAR_ARGS || var->var_type == LUMINA_VAR_ARGS_NAMES) ? (uint32_t)LUMINA_SCOPE_FORM_URLENCODED : 0u);
    unsigned char *decoded = lumina_canonicalize(
        var->ptr, var->len, decode_scope, &decoded_len, &is_malloc);
    if (!decoded || decoded_len > LUMINA_MAX_INSPECTED_VALUE) {
        if (decoded) lumina_canonicalize_free(decoded, is_malloc);
        return -1;
    }
    lumina_reset_transform_view_cache();

    int word = idx >> 6;
    uint64_t bit = 1ULL << (idx & 63);
    bool anywhere = (g_short_rule_anywhere_mask[word] & bit) != 0;
    for (size_t offset = 0; offset < decoded_len; offset++) {
        if ((g_short_rule_mask[decoded[offset]][word] & bit) == 0) continue;
        int matched_id = lumina_dispatch_rule(idx, decoded, decoded_len, offset);
        if (matched_id) {
            if (g_short_rule_score[idx] == 0) {
                lumina_slab_mark(&state->predicate_rules, idx);
            } else {
                lumina_record_rule_match(state, matched_id, "audit_rule");
            }
            break;
        }
        if (anywhere) break;
    }

    lumina_canonicalize_free(decoded, is_malloc);
    return 0;
}

int luminawaf_audit_bundle_rule(const LuminaBundle *bundle, LuminaRuleState *state, int rule_id) {
    if (!bundle || !state || bundle->count < 0 ||
        bundle->count > LUMINA_BUNDLE_MAX_VARS) return -1;
    int idx = lumina_rule_id_to_engine_idx(rule_id);
    if (idx < 0) return luminawaf_rule_state_matched(state, rule_id);
    bool scan_form_body = lumina_bundle_has_form_urlencoded_body(bundle);
    bool scan_structured_body = lumina_bundle_has_json_body(bundle) ||
                                lumina_bundle_has_xml_body(bundle);
    (void)lumina_eval_tx_rules(bundle, state);
    if (lumina_engine_rule_is_disabled(state, idx)) return 0;
    (void)lumina_scan_projected_collections(bundle, state);
    (void)lumina_eval_tx_rules(bundle, state);
    if (lumina_slab_test(&state->matched_rules, idx)) return 1;
    for (int i = 0; i < bundle->count; i++) {
        const BundleVar *var = &bundle->vars[i];
        if (var->var_type == LUMINA_VAR_ARGS || var->var_type == LUMINA_VAR_COOKIE) continue;
        if (scan_structured_body && var->var_type == LUMINA_VAR_BODY) continue;
        int status = lumina_audit_rule_variable(
            idx, var, state, scan_form_body && var->var_type == LUMINA_VAR_BODY);
        if (status != 0) return status;
        if (lumina_slab_test(&state->matched_rules, idx)) return 1;
    }
    (void)lumina_eval_tx_rules(bundle, state);
    if (lumina_slab_test(&state->matched_rules, idx)) return 1;
    return 0;
}

extern "C" __attribute__((weak)) int lumina_eval_tx_rules(const LuminaBundle *bundle,
                                                           LuminaRuleState *state) {
    (void)bundle;
    (void)state;
    return 0;
}

extern "C" __attribute__((weak)) void lumina_eval_target_controls(
    const unsigned char *data, size_t len, uint64_t collection_mask,
    LuminaRuleState *state) {
    (void)data;
    (void)len;
    (void)collection_mask;
    (void)state;
}

int luminawaf_inspect_tx(const LuminaBundle *bundle, LuminaRuleState *state, LuminaResult *out_result) {
    if (!bundle || !out_result) return -1;
    if (!state) return 0;
    
    int threat = lumina_eval_tx_rules(bundle, state);
    if (threat > out_result->threat_level) {
        out_result->threat_level = threat;
    }
    return threat;
}

int luminawaf_inspect_bundle(const LuminaBundle *bundle, LuminaRuleState *state, LuminaResult *out_result) {
    if (!bundle || !out_result || bundle->count < 1 ||
        bundle->count > LUMINA_BUNDLE_MAX_VARS) return -1;
    for (int i = 0; i < bundle->count; i++) {
        const BundleVar *var = &bundle->vars[i];
        if ((!var->ptr && var->len != 0) ||
            var->len > LUMINA_MAX_INSPECTED_VALUE) {
            return -1;
        }
    }

    LuminaRuleState fallback_state = {};
    if (!state) state = &fallback_state;

    g_anomaly_score_tls = 0;
    g_anomaly_category_tls = 0;
    /* Generated phase controls run before metadata and content evaluation. */
    int threat = lumina_eval_tx_rules(bundle, state);
    uint8_t var_order[LUMINA_BUNDLE_MAX_VARS];
    bundle_build_length_order(bundle, var_order);

    /* Evaluate method, request-line, protocol and header-count rules from the
     * transaction metadata that is not available to per-value scanners. */
    if (bundle->req_method && bundle->req_method_len &&
        !lumina_method_allowed(bundle->req_method, bundle->req_method_len)) {
        LUMINA_ADD_SCORE_AND_CHECK(state, 911100, 5, LUMINA_CAT_PROCOL, LUMINA_ANOMALY_THRESHOLD, bundle->req_method, bundle->req_method_len, 0);
    }
    if (bundle->req_line && bundle->req_line_len &&
        !lumina_request_line_valid(bundle->req_line, bundle->req_line_len)) {
        LUMINA_ADD_SCORE_AND_CHECK(state, 920100, 5, LUMINA_CAT_PROCOL, LUMINA_ANOMALY_THRESHOLD, bundle->req_line, bundle->req_line_len, 0);
    }
    if (bundle->req_protocol &&
        !lumina_protocol_allowed(bundle->req_protocol, bundle->req_protocol_len)) {
        LUMINA_ADD_SCORE_AND_CHECK(state, 920430, 5, LUMINA_CAT_PROCOL, LUMINA_ANOMALY_THRESHOLD, bundle->req_protocol, bundle->req_protocol_len, 0);
    }
    if (bundle->hdr_request_range_count > 0) {
        LUMINA_ADD_SCORE_AND_CHECK(state, 920660, 3, LUMINA_CAT_PROCOL, LUMINA_ANOMALY_THRESHOLD, NULL, 0, 0);
    }
    if (bundle->hdr_host_count == 0) {
        LUMINA_ADD_SCORE_AND_CHECK(state, 920280, 5, LUMINA_CAT_PROCOL, LUMINA_ANOMALY_THRESHOLD, NULL, 0, 0);
    }
    if (bundle->hdr_content_type_count > 1) {
        LUMINA_ADD_SCORE_AND_CHECK(state, 920620, 5, LUMINA_CAT_PROCOL, LUMINA_ANOMALY_THRESHOLD, NULL, 0, 0);
    }
    if (bundle->hdr_user_agent_count == 0) {
        LUMINA_ADD_SCORE_AND_CHECK(state, 920320, 2, LUMINA_CAT_PROCOL, LUMINA_ANOMALY_THRESHOLD, NULL, 0, 0);
    }
    if (bundle->user_agent && bundle->user_agent_len &&
        lumina_pm_runtime_913100(bundle->user_agent, bundle->user_agent_len)) {
        LUMINA_ADD_SCORE_AND_CHECK(state, 913100, 5, LUMINA_CAT_OTHER, LUMINA_ANOMALY_THRESHOLD, bundle->user_agent, bundle->user_agent_len, 0);
    }
    bool scan_form_body = lumina_bundle_has_form_urlencoded_body(bundle);
    bool scan_structured_body = lumina_bundle_has_json_body(bundle) ||
                                lumina_bundle_has_xml_body(bundle);
    int projected_threat = lumina_scan_projected_collections(bundle, state);
    if (!threat && projected_threat) threat = projected_threat;

    static thread_local unsigned char scratchpad[LUMINA_MAX_INSPECTED_VALUE];

    for (int vi = 0; vi < bundle->count && threat == 0; vi++) {
        const BundleVar *v = &bundle->vars[var_order[vi]];
        uint64_t collection_mask = v->collection_mask
                                       ? v->collection_mask
                                       : lumina_collection_mask_for_var_type(
                                             (uint8_t)v->var_type);
        lumina_eval_target_controls(v->ptr, v->len, collection_mask, state);
        uint64_t disabled_mask[CRS_SHORT_RULE_MASK_DIMS];
        lumina_build_disabled_mask(state, collection_mask, disabled_mask);
        int var_score_before = g_anomaly_score_tls;
        if (v->len == 0) {
            int empty_threat = lumina_scan_empty_variable(v, state);
            if (empty_threat) threat = empty_threat;
            continue;
        }
        /* The caller's ARGS slot carries the raw query container. Its raw
         * QUERY_STRING view and projected ARGS/ARGS_NAMES values were handled
         * above; scanning the container again would cross parameter bounds. */
        if (v->var_type == LUMINA_VAR_ARGS || v->var_type == LUMINA_VAR_COOKIE) continue;
        if (scan_structured_body && v->var_type == LUMINA_VAR_BODY) continue;

        if (vi + 1 < bundle->count) {
            __builtin_prefetch(bundle->vars[var_order[vi + 1]].ptr, 0, 3);
        }

        const unsigned char *data_ptr = v->ptr;
        size_t data_len = v->len;
        int is_malloc = 0;

        /* Keep plain values in caller-owned storage. Encoded values are
         * canonicalized into the thread-local scratch buffer. */
        bool needs_decode = (v->ptr[0] == '%') ||
                            (data_len > 3 && memchr(v->ptr, '%', data_len < 32 ? data_len : 32)) ||
                            (data_len > 3 && memchr(v->ptr, '&', data_len < 128 ? data_len : 128)) ||
                            (v->var_type == LUMINA_VAR_ARGS && memchr(v->ptr, '+', data_len));
        
        /* Rule 920270 must inspect raw input because canonicalization removes %00. */
        bool null_byte_found = false;
        if (!threat && data_len >= 3) {
            const unsigned char *p = v->ptr;
            const unsigned char *end = v->ptr + data_len - 2;
            while (p < end) {
                if (p[0] == '%' && p[1] == '0' && p[2] == '0') {
                    LUMINA_ADD_SCORE_AND_CHECK(state, 920270, 5, 0x10, compute_adaptive_threshold(v->ptr, v->len, 0) + var_score_before, v->ptr, v->len, 0);
                    null_byte_found = true;
                    break;
                }
                p++;
            }
        }
        
        if (needs_decode) {
            uint32_t decode_scope = v->scope |
                ((v->var_type == LUMINA_VAR_ARGS || v->var_type == LUMINA_VAR_ARGS_NAMES) ? (uint32_t)LUMINA_SCOPE_FORM_URLENCODED : 0u);
            unsigned char *decoded = lumina_canonicalize(v->ptr, data_len, decode_scope, &data_len, &is_malloc);
            if (decoded) {
                memcpy(scratchpad, decoded, data_len);
                lumina_canonicalize_free(decoded, is_malloc);
                data_ptr = scratchpad;
            }
            // On canonicalization failure, continue with the original value.
        }
        // Plain values remain zero-copy.

        if ((v->scope & LUMINA_SCOPE_JSON) && v->var_type == LUMINA_VAR_BODY && data_len > 4) {
            JsonStrings jstrs;
            int n = extract_json_strings(data_ptr, data_len, &jstrs);
            for (int ji = 0; ji < n; ji++) {
                if (jstrs.strings[ji].len < 3) continue;
                const unsigned char *jptr = jstrs.strings[ji].ptr;
                size_t jlen = jstrs.strings[ji].len;
                if (jlen > LUMINA_MAX_INSPECTED_VALUE) jlen = LUMINA_MAX_INSPECTED_VALUE;
                /* Extracted strings are read-only slices of data_ptr. */
                DangerPositions jp;
                bool jdanger = lumina_fast_prefilter(jptr, jlen, &jp);
                if (!jdanger) continue;
                uint32_t jtriggers = lumina_trigger_match(jptr, jlen, &jp);
                int jthreshold = compute_adaptive_threshold(jptr, jlen, 0);
                int jr;
                if (jtriggers & (TRIGGER_XSS_SCRIPT_START | TRIGGER_XSS_ON | TRIGGER_XSS_SCRIPT |
                                  TRIGGER_XSS_SCRIPT_GENERIC | TRIGGER_XSS_ALERT | TRIGGER_XSS_JAVASCRIPT |
                                  TRIGGER_XSS_ENCODED | TRIGGER_XSS_EXTRA)) {
                    jr = lumina_scan_xss(jptr, jlen, v->scope);
                    if (jr) { LUMINA_ADD_SCORE_AND_CHECK(state, jr, LUMINA_PARA_XSS, 0x02, jthreshold + var_score_before, jptr, jlen, 0); }
                }
                if (!threat && (jtriggers & (TRIGGER_PATH_TRAV | TRIGGER_PATH_GITCONFIG | TRIGGER_RECON))) {
                    jr = lumina_scan_path(jptr, jlen);
                    if (jr) { LUMINA_ADD_SCORE_AND_CHECK(state, jr, LUMINA_PARA_PATH, 0x08, jthreshold + var_score_before, jptr, jlen, 0); }
                }
                if (!threat && (jtriggers & (TRIGGER_SQLI_UNION | TRIGGER_SQLI_XP | TRIGGER_SQLI_UNION_FULL |
                                              TRIGGER_SQLI_SELECT | TRIGGER_SQLI_1EQUALS1 | TRIGGER_SQLI_COMMENT | TRIGGER_SQLI_EXTRA))) {
                    jr = lumina_scan_sqli(jptr, jlen, v->scope);
                    if (jr) { LUMINA_ADD_SCORE_AND_CHECK(state, jr, LUMINA_PARA_SQLI, 0x01, jthreshold + var_score_before, jptr, jlen, 0); }
                }
                if (threat) break;
            }
            if (threat) continue;
        }

        DangerPositions danger_positions;
        danger_positions.count = 0;
        bool has_danger = false;
        if (v->scope & LUMINA_SCOPE_HEADERS) {
            has_danger = lumina_fast_prefilter_headers(data_ptr, data_len, &danger_positions);
        } else {
            has_danger = lumina_fast_prefilter(data_ptr, data_len, &danger_positions);
        }
        bool is_uri_path = (v->scope & LUMINA_SCOPE_URI) && data_len > 0 && data_ptr[0] == '/';

        const bool has_short_rule_candidate =
            lumina_has_short_rule_candidate(data_ptr, data_len);

        /* Null-byte fallback: if %00 was detected in raw data but prefilter
         * finds no danger (e.g. pure null-byte payloads like "+%00" after
         * canonicalization decode to harmless single chars), we must NOT skip
         * this variable. Check if accumulated score meets threshold. */
        if (!has_danger && !is_uri_path && !has_short_rule_candidate) {
            if (null_byte_found && g_anomaly_score_tls >= LUMINA_ANOMALY_THRESHOLD) {
                threat = 920270;
            } else {
                continue;
            }
        }

        uint32_t triggers = lumina_trigger_match(data_ptr, data_len, &danger_positions);
        int adaptive_threshold = compute_adaptive_threshold(data_ptr, data_len, 0);
        int r;

        /* Run trigger-routed scanners before generated rule dispatch. */
        if (triggers & (TRIGGER_XSS_SCRIPT_START | TRIGGER_XSS_ON | TRIGGER_XSS_SCRIPT |
                        TRIGGER_XSS_SCRIPT_GENERIC | TRIGGER_XSS_ALERT | TRIGGER_XSS_JAVASCRIPT |
                        TRIGGER_XSS_ENCODED | TRIGGER_XSS_EXTRA)) {
            r = lumina_scan_xss(data_ptr, data_len, v->scope);
            if (r) { LUMINA_ADD_SCORE_AND_CHECK(state, r, LUMINA_PARA_XSS, 0x02, adaptive_threshold + var_score_before, data_ptr, data_len, 0); }
        }

        if (!threat && (is_uri_path || (triggers & (TRIGGER_PATH_TRAV | TRIGGER_PATH_GITCONFIG | TRIGGER_RECON)))) {
            r = lumina_scan_path(data_ptr, data_len);
            if (r) { LUMINA_ADD_SCORE_AND_CHECK(state, r, LUMINA_PARA_PATH, 0x08, adaptive_threshold + var_score_before, data_ptr, data_len, 0); }
        }

        // Rule 930120: OS file access in arguments, cookies and request bodies.
        if (!threat && (v->scope & (LUMINA_SCOPE_BODY | LUMINA_SCOPE_URI))) {
            r = lumina_pm_lfi_os_files(data_ptr, data_len);
            if (r) { LUMINA_ADD_SCORE_AND_CHECK(state, r, LUMINA_PARA_PATH, 0x08, adaptive_threshold + var_score_before, data_ptr, data_len, 0); }
        }

        // Rule 930130: restricted file access in REQUEST_FILENAME.
        if (!threat && is_uri_path) {
            r = lumina_pm_restricted_files(data_ptr, data_len);
            if (r) { LUMINA_ADD_SCORE_AND_CHECK(state, r, LUMINA_PARA_PATH, 0x08, adaptive_threshold + var_score_before, data_ptr, data_len, 0); }
        }

        // Rule 920440: restricted extensions in REQUEST_BASENAME.
        if (!threat && (v->scope & LUMINA_SCOPE_URI)) {
            r = lumina_scan_restricted_ext(data_ptr, data_len);
            if (r) { LUMINA_ADD_SCORE_AND_CHECK(state, r, 5, 0x10, adaptive_threshold + var_score_before, data_ptr, data_len, 0); }
        }

        if (!threat && (triggers & (TRIGGER_SQLI_UNION | TRIGGER_SQLI_XP | TRIGGER_SQLI_UNION_FULL |
                                    TRIGGER_SQLI_SELECT | TRIGGER_SQLI_1EQUALS1 | TRIGGER_SQLI_COMMENT | TRIGGER_SQLI_EXTRA))) {
            r = lumina_scan_sqli(data_ptr, data_len, v->scope);
            if (r) { LUMINA_ADD_SCORE_AND_CHECK(state, r, LUMINA_PARA_SQLI, 0x01, adaptive_threshold + var_score_before, data_ptr, data_len, 0); }
        }

        if (!threat && (triggers & TRIGGER_CMD_INJECT)) {
            r = lumina_scan_cmd(data_ptr, data_len, v->scope);
            if (r) { LUMINA_ADD_SCORE_AND_CHECK(state, r, LUMINA_PARA_RCE, 0x04, adaptive_threshold + var_score_before, data_ptr, data_len, 0); }
        }

        /* Rule 932130: run the scoped JNDI scanner after a trigger match. */
        if (!threat && (triggers & TRIGGER_JNDI_INJECT)) {
            if (v->collection_mask == 0 || (v->collection_mask & (LUMINA_COL_REQUEST_COOKIES | LUMINA_COL_REQUEST_COOKIES_NAMES | LUMINA_COL_ARGS_NAMES | LUMINA_COL_ARGS | LUMINA_COL_XML))) {
                r = lumina_scan_jndi(data_ptr, data_len);
                if (r) { LUMINA_ADD_SCORE_AND_CHECK(state, r, (data_len > 128) ? 2 : 5, 0x04, adaptive_threshold + var_score_before, data_ptr, data_len, 0); }
            }
        }

        /* LDAP injection (CRS 921110). Filter injection via *(|(, )(&, etc. */
        if (!threat && (triggers & TRIGGER_LDAP_INJECT)) {
            r = lumina_scan_ldap(data_ptr, data_len);
            if (r) { LUMINA_ADD_SCORE_AND_CHECK(state, r, (data_len > 128) ? 2 : 5, 0x10, adaptive_threshold + var_score_before, data_ptr, data_len, 0); }
        }

        /* HTTP Response Splitting (CRS 921130). CRLF + header injection. */
        if (!threat && (triggers & TRIGGER_RESP_SPLIT)) {
            r = lumina_scan_resp_split(data_ptr, data_len);
            int para = (data_len > 128) ? 2 : 5;
            g_anomaly_score_tls += r ? para : 0;
            g_anomaly_category_tls |= r ? 0x10 : 0;
            int new_threat = r & ((g_anomaly_score_tls - var_score_before >= adaptive_threshold) ? 1 : 0);
            threat = new_threat ? r : threat;
        }

        /* SSRF (CRS 934100). Internal network / metadata endpoint access. */
        if (!threat && (triggers & TRIGGER_SSRF)) {
            r = lumina_scan_ssrf(data_ptr, data_len);
            int para = (data_len > 128) ? 2 : 5;
            g_anomaly_score_tls += r ? para : 0;
            g_anomaly_category_tls |= r ? 0x10 : 0;
            int new_threat = r & ((g_anomaly_score_tls - var_score_before >= adaptive_threshold) ? 1 : 0);
            threat = new_threat ? r : threat;
        }

        if (!threat) {
            lumina_reset_transform_view_cache();
            LuminaShortRuleActiveMask short_active;
            uint32_t header_mask = (v->var_type == LUMINA_VAR_HDR) ? v->header_mask : 0;
            lumina_build_short_rule_active_mask(&short_active, v->scope, header_mask, (uint8_t)v->var_type);
            const uint64_t *generated_eligibility =
                scan_form_body && v->var_type == LUMINA_VAR_BODY
                    ? g_short_rule_request_body_mask : NULL;
            LuminaShortRuleEffectiveMask effective;
            lumina_build_short_rule_effective_mask(
                &effective, &short_active, generated_eligibility, disabled_mask);
            uint64_t processed_transform_search[
                CRS_SHORT_RULE_MASK_DIMS] = {};

            if (data_len > 0) {
                uint8_t c = data_ptr[0];
#if LUMINA_SHARED_ROUTER_COUNT > 0
                uint8_t processed_routers[LUMINA_SHARED_ROUTER_COUNT] = {};
                uint64_t router_matches[LUMINA_SHARED_ROUTER_COUNT]
                                       [CRS_SHORT_RULE_MASK_DIMS] = {};
#endif
                for (int _w = 0; _w < CRS_SHORT_RULE_MASK_DIMS && !threat; _w++) {
                    uint64_t mw = g_short_rule_mask[c][_w] & effective.pos0[_w];
                    while (mw) {
                        int idx = __builtin_ctzll(mw) + (_w << 6);
                        mw &= mw - 1;
#if LUMINA_SHARED_ROUTER_COUNT > 0
                        int router_tag = g_short_rule_shared_router[idx];
                        if (router_tag != 0) {
                            int router_id = router_tag - 1;
                            if (processed_routers[router_id] == 0) {
                                processed_routers[router_id] = 1;
                                lumina_run_shared_router(
                                    router_id, data_ptr, data_len, 0,
                                    effective.pos0, router_matches[router_id], 0);
                            }
                            const uint64_t rule_bit =
                                UINT64_C(1) << (idx & 63);
                            if ((router_matches[router_id][_w] & rule_bit) != 0) {
                                int score = g_short_rule_score[idx];
                                if (score != 0) {
                                    LUMINA_ADD_SCORE_AND_CHECK(
                                        state, g_short_rule_id[idx], score,
                                        g_short_rule_category[idx],
                                        adaptive_threshold + var_score_before,
                                        data_ptr, data_len, 0);
                                }
                            }
                            continue;
                        }
#endif
                        if (g_short_rule_transform_search[idx]) {
                            const uint64_t bit =
                                UINT64_C(1) << (idx & 63);
                            if (processed_transform_search[_w] & bit)
                                continue;
                            processed_transform_search[_w] |= bit;
                        }
                        r = lumina_dispatch_rule(idx, data_ptr, data_len, 0);
                        if (r) {
                            /* HPP counter rules are handled by transaction-level
                             * parameter counting. */
                            if (r == 921170) continue;
                            /* Use the generated CRS anomaly increment. */
                            int s = g_short_rule_score[idx];
                            if (s == 0) continue;
                            LUMINA_ADD_SCORE_AND_CHECK(state, r, s, g_short_rule_category[idx], adaptive_threshold + var_score_before, data_ptr, data_len, 0);
                            if (threat) break;
                        }
                    }
                }
            }

            for (size_t i = 1; i < data_len; i += 16) {
                __builtin_prefetch(data_ptr + i + 256, 0, 3);
                for (size_t j = i; j < i + 16 && j < data_len; j++) {
                    uint8_t c = data_ptr[j];
                    for (int _w = 0; _w < CRS_SHORT_RULE_MASK_DIMS && !threat; _w++) {
                        uint64_t mw = g_short_rule_mask[c][_w] & effective.posN[_w];
                        while (mw) {
                            int idx = __builtin_ctzll(mw) + (_w << 6);
                            mw &= mw - 1;
                            size_t dispatch_offset = j;
                            if (g_short_rule_transform_search[idx]) {
                                const uint64_t bit =
                                    UINT64_C(1) << (idx & 63);
                                if (processed_transform_search[_w] & bit)
                                    continue;
                                processed_transform_search[_w] |= bit;
                                dispatch_offset = 0;
                            }
                            r = lumina_dispatch_rule(
                                idx, data_ptr, data_len,
                                dispatch_offset);
                            if (r) {
                                /* HPP counter rules are handled by transaction-level
                                 * parameter counting. */
                                if (r == 921170) continue;
                                /* Use the generated CRS anomaly increment. */
                                int s = g_short_rule_score[idx];
                                if (s == 0) continue;
                                LUMINA_ADD_SCORE_AND_CHECK(state, r, s, g_short_rule_category[idx], adaptive_threshold + var_score_before, data_ptr, data_len, j);
                                if (threat) break;
                            }
                        }
                    }
                    if (threat) break;
                }
                if (threat) break;
            }
        }

        /* Null-byte fallback: if %00 was detected in raw data but no scanner
         * set threat (e.g. pure null-byte payloads like "+%00" with no LFI/SQLi),
         * set threat=920270 so the final score check returns non-zero threat_level. */
        if (!threat && null_byte_found && g_anomaly_score_tls >= LUMINA_ANOMALY_THRESHOLD) {
            threat = 920270;
        }

        /* Generated rules are dispatched once above. Bloom is not a second
         * generic rule executor. */
    }

    int tx_threat = lumina_eval_tx_rules(bundle, state);
    if (tx_threat) {
        if (!threat) threat = tx_threat;
    }

    if (out_result) {
        if (state->transaction_flags & LUMINA_FLAG_REQBODY_LIMIT) {
            out_result->error_flag = LUMINA_ERROR_REQBODY_LIMIT;
        } else if (state->transaction_flags & LUMINA_FLAG_REQBODY_FORBIDDEN) {
            out_result->error_flag = LUMINA_ERROR_REQBODY_FORBIDDEN;
        } else if (state->transaction_flags & LUMINA_FLAG_REQBODY_UNSUPPORTED) {
            out_result->error_flag = LUMINA_ERROR_REQBODY_UNSUPPORTED;
        } else if (state->transaction_flags & LUMINA_FLAG_REQBODY_MALFORMED) {
            out_result->error_flag = LUMINA_ERROR_REQBODY_MALFORMED;
        } else {
            out_result->error_flag = LUMINA_ERROR_NONE;
        }
        /* The final verdict uses the transaction-wide anomaly score. */
        out_result->threat_level = (g_anomaly_score_tls >= LUMINA_ANOMALY_THRESHOLD) ? threat : 0;
        out_result->decoded_buffer = NULL;
        out_result->decoded_length = 0;
    }
    return 0;
}

int luminawaf_inspect_request(const unsigned char* uri_data, size_t uri_len, LuminaRuleState *state, LuminaResult* out_result) {
    return luminawaf_inspect_buffer(
        uri_data, uri_len, LUMINA_SCOPE_URI,
        LUMINA_VAR_REQUEST_FILENAME, state, out_result);
}

void luminawaf_destroy_worker(void) {
    /* ABI-compatible counterpart to the idempotent no-allocation init hook. */
}
