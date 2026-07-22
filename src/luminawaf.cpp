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
        const uint64_t *effective_mask, uint64_t *matched) {
    uint64_t wanted[CRS_SHORT_RULE_MASK_DIMS];
    for (int word = 0; word < CRS_SHORT_RULE_MASK_DIMS; ++word) {
        wanted[word] = g_shared_router_rule_mask[router_id][word] &
                       effective_mask[word];
    }
    lumina_dispatch_shared_router(
        router_id, data, len, offset, wanted, matched);
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
    if (len > 131072) return -1;

    if (lumina_pre_canonicalize_check(data, len, out_result)) return 0;
    
    static thread_local unsigned char scratchpad[131072];
    
    int is_malloc = 0;
    size_t decoded_len = 0;
    uint32_t decode_scope = active_scope |
        ((var_type == LUMINA_VAR_ARGS || var_type == LUMINA_VAR_ARGS_NAMES) ? (uint32_t)LUMINA_SCOPE_FORM_URLENCODED : 0u);
    unsigned char* decoded_ptr = lumina_canonicalize(data, len, decode_scope, &decoded_len, &is_malloc);
    
    /* The scanners expect writable thread-local storage. canonicalize() may
     * return borrowed input, so keep the copy at this API boundary. */
    if (decoded_len > 131072) {
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
    if (len > 131072) return -1;

    static thread_local unsigned char scratchpad[131072];

    int is_malloc = 0;
    size_t decoded_len = 0;
    uint32_t decode_scope = active_scope |
        ((var_type == LUMINA_VAR_ARGS || var_type == LUMINA_VAR_ARGS_NAMES) ? (uint32_t)LUMINA_SCOPE_FORM_URLENCODED : 0u);
    unsigned char* decoded_ptr = lumina_canonicalize(data, len, decode_scope, &decoded_len, &is_malloc);

    if (decoded_len > 131072) {
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
    if (len > 131072) return -1;

    static thread_local unsigned char scratchpad[131072];

    int is_malloc = 0;
    size_t decoded_len = 0;
    uint32_t decode_scope = active_scope |
        ((var_type == LUMINA_VAR_ARGS || var_type == LUMINA_VAR_ARGS_NAMES) ? (uint32_t)LUMINA_SCOPE_FORM_URLENCODED : 0u);
    unsigned char* decoded_ptr = lumina_canonicalize(data, len, decode_scope, &decoded_len, &is_malloc);

    if (decoded_len > 131072) {
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

        if (decoded_len > 0) {
            uint8_t c = scratchpad[0];
            for (int _w = 0; _w < CRS_SHORT_RULE_MASK_DIMS && !threat; _w++) {
                uint64_t mw = g_short_rule_mask[c][_w] & effective.pos0[_w];
                while (mw) {
                    int idx = __builtin_ctzll(mw) + (_w << 6);
                    mw &= mw - 1;
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
                            r = lumina_dispatch_rule(idx, scratchpad, decoded_len, j);
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

static inline void bundle_sort_by_length(LuminaBundle *b) {
    for (int i = 1; i < b->count; i++) {
        BundleVar tmp = b->vars[i];
        int j = i - 1;
        while (j >= 0 && b->vars[j].len > tmp.len) {
            b->vars[j + 1] = b->vars[j];
            j--;
        }
        b->vars[j + 1] = tmp;
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
    /* locate last SP (separator before HTTP-version) */
    size_t lastsp = (size_t)-1;
    for (size_t k = i; k < n; k++) if (s[k] == ' ') lastsp = k;
    if (lastsp == (size_t)-1) return false;
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
    bool has_slash = false;
    for (size_t k = tstart; k < tend; k++) if (s[k] == '/') { has_slash = true; break; }
    if (has_slash) return true;
    return (tend - tstart == 1 && s[tstart] == '*'); /* OPTIONS * */
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
static int lumina_scan_projected_value_masked(const unsigned char *data, size_t len,
                                              uint32_t scope, uint8_t var_type,
                                              LuminaRuleState *state,
                                              const uint64_t *eligibility_mask,
                                              uint32_t header_mask) {
    if (!data || len == 0 || !state) return 0;
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
    int threat = 0;

    uint8_t first = data[0];
#if LUMINA_SHARED_ROUTER_COUNT > 0
    uint8_t processed_routers[LUMINA_SHARED_ROUTER_COUNT] = {};
#endif
    for (int word = 0; word < CRS_SHORT_RULE_MASK_DIMS; word++) {
        uint64_t candidates = g_short_rule_mask[first][word] & effective.pos0[word];
        while (candidates) {
            int idx = __builtin_ctzll(candidates) + (word << 6);
            candidates &= candidates - 1;
            if (idx >= LUMINA_SHORT_RULE_COUNT) continue;
#if LUMINA_SHARED_ROUTER_COUNT > 0
            int router_tag = g_short_rule_shared_router[idx];
            if (router_tag != 0) {
                int router_id = router_tag - 1;
                candidates &= ~g_shared_router_rule_mask[router_id][word];
                if (processed_routers[router_id] != 0) continue;
                processed_routers[router_id] = 1;
                uint64_t matched[CRS_SHORT_RULE_MASK_DIMS];
                lumina_run_shared_router(
                    router_id, data, len, 0, effective.pos0, matched);
                for (int hit_word = 0; hit_word < CRS_SHORT_RULE_MASK_DIMS; ++hit_word) {
                    uint64_t hits = matched[hit_word];
                    while (hits) {
                        int hit_idx = __builtin_ctzll(hits) + (hit_word << 6);
                        hits &= hits - 1;
                        int score = g_short_rule_score[hit_idx];
                        if (score == 0) {
                            lumina_slab_mark(&state->predicate_rules, hit_idx);
                        } else {
                            int committed = lumina_commit_generated_rule(
                                state, hit_idx, g_short_rule_id[hit_idx], score,
                                g_short_rule_category[hit_idx]);
                            if (committed) threat = committed;
                        }
                    }
                }
                continue;
            }
#endif
            int rule_id = lumina_dispatch_rule(idx, data, len, 0);
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

    for (size_t offset = 1; offset < len; offset++) {
        uint8_t byte = data[offset];
        for (int word = 0; word < CRS_SHORT_RULE_MASK_DIMS; word++) {
            uint64_t candidates = g_short_rule_mask[byte][word] & effective.posN[word];
            while (candidates) {
                int idx = __builtin_ctzll(candidates) + (word << 6);
                candidates &= candidates - 1;
                if (idx >= LUMINA_SHORT_RULE_COUNT) continue;
                int rule_id = lumina_dispatch_rule(idx, data, len, offset);
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

static int lumina_scan_projected_value(const unsigned char *data, size_t len,
                                       uint32_t scope, uint8_t var_type,
                                       LuminaRuleState *state) {
    return lumina_scan_projected_value_masked(
        data, len, scope, var_type, state, NULL, 0);
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

static bool lumina_multipart_boundary(const LuminaBundle *bundle,
                                      const unsigned char **boundary,
                                      size_t *boundary_len) {
    static const unsigned char multipart[] = "multipart/";
    static const unsigned char boundary_name[] = "boundary";
    if (!bundle || !boundary || !boundary_len) return false;
    for (int i = 0; i < bundle->count; i++) {
        const BundleVar *header = &bundle->vars[i];
        if (header->var_type != LUMINA_VAR_HDR || !header->ptr ||
            !(header->header_mask & LUMINA_HDR_CONTENT_TYPE) ||
            header->len < sizeof(multipart) - 1) continue;
        if (!lumina_ascii_equal_ci(header->ptr, sizeof(multipart) - 1,
                                   multipart, sizeof(multipart) - 1)) continue;
        size_t pos = sizeof(multipart) - 1;
        while (pos < header->len && header->ptr[pos] != ';') pos++;
        while (pos < header->len) {
            pos++;
            while (pos < header->len &&
                   (header->ptr[pos] == ' ' || header->ptr[pos] == '\t')) pos++;
            size_t name_start = pos;
            while (pos < header->len && header->ptr[pos] != '=' &&
                   header->ptr[pos] != ';') pos++;
            size_t name_end = pos;
            while (name_end > name_start &&
                   (header->ptr[name_end - 1] == ' ' || header->ptr[name_end - 1] == '\t'))
                name_end--;
            if (pos >= header->len || header->ptr[pos] != '=') continue;
            pos++;
            while (pos < header->len &&
                   (header->ptr[pos] == ' ' || header->ptr[pos] == '\t')) pos++;
            bool quoted = pos < header->len && header->ptr[pos] == '"';
            if (quoted) pos++;
            size_t value_start = pos;
            if (quoted) {
                while (pos < header->len && header->ptr[pos] != '"') pos++;
            } else {
                while (pos < header->len && header->ptr[pos] != ';') pos++;
            }
            size_t value_end = pos;
            while (!quoted && value_end > value_start &&
                   (header->ptr[value_end - 1] == ' ' || header->ptr[value_end - 1] == '\t'))
                value_end--;
            if (quoted && pos < header->len) pos++;
            if (lumina_ascii_equal_ci(header->ptr + name_start, name_end - name_start,
                                      boundary_name, sizeof(boundary_name) - 1) &&
                value_end > value_start) {
                *boundary = header->ptr + value_start;
                *boundary_len = value_end - value_start;
                return true;
            }
            while (pos < header->len && header->ptr[pos] != ';') pos++;
        }
    }
    return false;
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

static bool lumina_multipart_parameter(const unsigned char *line, size_t line_len,
                                       const unsigned char *parameter,
                                       size_t parameter_len,
                                       LuminaMultipartSlice *out) {
    if (!line || !parameter || !out) return false;
    size_t pos = 0;
    while (pos < line_len && line[pos] != ':') pos++;
    if (pos == line_len) return false;
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
        if (pos == line_len || line[pos] != '=') continue;
        pos++;
        while (pos < line_len && (line[pos] == ' ' || line[pos] == '\t')) pos++;
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
        } else {
            while (pos < line_len && line[pos] != ';') pos++;
        }
        size_t value_end = pos;
        while (!quoted && value_end > value_start &&
               (line[value_end - 1] == ' ' || line[value_end - 1] == '\t')) value_end--;
        if (quoted && pos < line_len) pos++;
        if (lumina_ascii_equal_ci(line + name_start, name_end - name_start,
                                  parameter, parameter_len)) {
            out->ptr = line + value_start;
            out->len = value_end - value_start;
            out->needs_unescape = escaped;
            out->present = true;
            return true;
        }
    }
    return false;
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

static int lumina_scan_multipart_file_collections(const LuminaBundle *bundle,
                                                  LuminaRuleState *state,
                                                  unsigned char *scratch,
                                                  size_t scratch_cap) {
    static const unsigned char content_disposition[] = "content-disposition";
    static const unsigned char content_type_str[] = "content-type";
    static const unsigned char name_parameter[] = "name";
    static const unsigned char filename_parameter[] = "filename";
    const unsigned char *boundary = NULL;
    size_t boundary_len = 0;
    if (!lumina_multipart_boundary(bundle, &boundary, &boundary_len)) return 0;
    int threat = 0;
    for (int vi = 0; vi < bundle->count; vi++) {
        const BundleVar *body = &bundle->vars[vi];
        if (body->var_type != LUMINA_VAR_BODY || !body->ptr) continue;
        bool in_headers = false;
        size_t part_body_start = 0;
        LuminaMultipartSlice current_filename = {};
        LuminaMultipartSlice current_name = {};
        LuminaMultipartSlice current_content_type = {};

        for (size_t start = 0; start <= body->len;) {
            size_t end = start;
            while (end < body->len && body->ptr[end] != '\n') end++;
            size_t line_len = end - start;
            size_t line_len_no_cr = line_len;
            if (line_len_no_cr && body->ptr[start + line_len_no_cr - 1] == '\r') line_len_no_cr--;
            const unsigned char *line = body->ptr + start;
            int boundary_kind = lumina_multipart_boundary_line(
                line, line_len_no_cr, boundary, boundary_len);
            
            if (boundary_kind) {
                // Finish the previous part body.
                if (part_body_start > 0 && start >= part_body_start) {
                    size_t body_len = start - part_body_start;
                    // Exclude the CRLF that precedes the boundary.
                    if (body_len > 0 && body->ptr[part_body_start + body_len - 1] == '\n') body_len--;
                    if (body_len > 0 && body->ptr[part_body_start + body_len - 1] == '\r') body_len--;
                    
                    if (lumina_is_xml_part(current_content_type.ptr, current_content_type.len,
                                           current_filename.ptr, current_filename.len,
                                           body->ptr + part_body_start, body_len)) {
                        state->transaction_flags |= LUMINA_FLAG_HAS_MULTIPART_XML;
                        int container_threat = lumina_scan_projected_value_masked(
                            body->ptr + part_body_start, body_len, LUMINA_SCOPE_BODY,
                            LUMINA_VAR_XML, state, g_short_rule_xml_container_mask, 0);
                        if (container_threat && !threat) threat = container_threat;
                        int xml_threat = lumina_scan_xml_avx2(body->ptr + part_body_start, body_len, state);
                        if (xml_threat && !threat) threat = xml_threat;
                    }
                }
                
                in_headers = boundary_kind == 1;
                part_body_start = 0;
                memset(&current_filename, 0, sizeof(current_filename));
                memset(&current_name, 0, sizeof(current_name));
                memset(&current_content_type, 0, sizeof(current_content_type));
            } else if (in_headers && line_len_no_cr == 0) {
                in_headers = false;
                part_body_start = end + 1;
                
                // Project the collected filename and field name.
                if (current_filename.present) {
                    const unsigned char *value = current_filename.ptr;
                    size_t value_len = current_filename.len;
                    if (current_filename.needs_unescape) {
                        value_len = lumina_unescape_multipart_value(&current_filename, scratch, scratch_cap);
                        value = scratch;
                    }
                    if (value_len != SIZE_MAX && value_len > 0) {
                        int match = lumina_scan_projected_value(value, value_len, LUMINA_SCOPE_BODY, LUMINA_VAR_FILES, state);
                        if (match && !threat) threat = match;
                    }
                }
                if (current_name.present) {
                    const unsigned char *value = current_name.ptr;
                    size_t value_len = current_name.len;
                    if (current_name.needs_unescape) {
                        value_len = lumina_unescape_multipart_value(&current_name, scratch, scratch_cap);
                        value = scratch;
                    }
                    if (value_len != SIZE_MAX && value_len > 0) {
                        int match = lumina_scan_projected_value(value, value_len, LUMINA_SCOPE_BODY, LUMINA_VAR_FILES_NAMES, state);
                        if (match && !threat) threat = match;
                    }
                }
            } else if (in_headers) {
                size_t colon = 0;
                while (colon < line_len_no_cr && line[colon] != ':') colon++;
                size_t header_name_end = colon;
                while (header_name_end > 0 &&
                       (line[header_name_end - 1] == ' ' || line[header_name_end - 1] == '\t'))
                    header_name_end--;
                if (colon < line_len_no_cr) {
                    if (lumina_ascii_equal_ci(line, header_name_end, content_disposition, sizeof(content_disposition) - 1)) {
                        (void)lumina_multipart_parameter(line, line_len_no_cr, name_parameter, sizeof(name_parameter) - 1, &current_name);
                        (void)lumina_multipart_parameter(line, line_len_no_cr, filename_parameter, sizeof(filename_parameter) - 1, &current_filename);
                    } else if (lumina_ascii_equal_ci(line, header_name_end, content_type_str, sizeof(content_type_str) - 1)) {
                        size_t val_start = colon + 1;
                        while (val_start < line_len_no_cr && (line[val_start] == ' ' || line[val_start] == '\t')) val_start++;
                        current_content_type.ptr = line + val_start;
                        current_content_type.len = line_len_no_cr - val_start;
                        current_content_type.present = true;
                    }
                }
            }
            if (end == body->len) break;
            start = end + 1;
        }
    }
    return threat;
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

static int lumina_parse_and_project_json(const unsigned char *data, size_t len,
                                         LuminaRuleState *state,
                                         unsigned char *scratch, size_t scratch_size) {
    if (len == 0 || !data || !scratch || scratch_size == 0) return 0;
    size_t i = 0;
    int depth = 0;
    int threat = 0;

    while (i < len) {
        unsigned char c = data[i];
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == ',' || c == ':') {
            i++;
            continue;
        }
        if (c == '{' || c == '[') {
            depth++;
            if (depth > 64) return threat;
            i++;
            continue;
        }
        if (c == '}' || c == ']') {
            depth--;
            if (depth < 0) return threat;
            i++;
            continue;
        }
        if (c == '"') {
            i++;
            size_t out_len = 0;
            while (i < len) {
                if (data[i] == '"') {
                    i++;
                    break;
                }
                if (data[i] == '\\' && i + 1 < len) {
                    i++;
                    unsigned char e = data[i];
                    if (e == '"' || e == '\\' || e == '/') {
                        if (out_len < scratch_size) scratch[out_len++] = e;
                    } else if (e == 'b') {
                        if (out_len < scratch_size) scratch[out_len++] = '\b';
                    } else if (e == 'f') {
                        if (out_len < scratch_size) scratch[out_len++] = '\f';
                    } else if (e == 'n') {
                        if (out_len < scratch_size) scratch[out_len++] = '\n';
                    } else if (e == 'r') {
                        if (out_len < scratch_size) scratch[out_len++] = '\r';
                    } else if (e == 't') {
                        if (out_len < scratch_size) scratch[out_len++] = '\t';
                    } else if (e == 'u' && i + 4 < len) {
                        int val = 0;
                        bool valid = true;
                        for (int j = 1; j <= 4; j++) {
                            unsigned char h = data[i+j];
                            val <<= 4;
                            if (h >= '0' && h <= '9') val |= (h - '0');
                            else if (h >= 'a' && h <= 'f') val |= (h - 'a' + 10);
                            else if (h >= 'A' && h <= 'F') val |= (h - 'A' + 10);
                            else { valid = false; break; }
                        }
                        if (valid) {
                            i += 4;
                            if (val <= 0x7F) {
                                if (out_len < scratch_size) scratch[out_len++] = (unsigned char)val;
                            } else if (val <= 0x7FF) {
                                if (out_len < scratch_size) scratch[out_len++] = 0xC0 | (val >> 6);
                                if (out_len < scratch_size) scratch[out_len++] = 0x80 | (val & 0x3F);
                            } else {
                                if (out_len < scratch_size) scratch[out_len++] = 0xE0 | (val >> 12);
                                if (out_len < scratch_size) scratch[out_len++] = 0x80 | ((val >> 6) & 0x3F);
                                if (out_len < scratch_size) scratch[out_len++] = 0x80 | (val & 0x3F);
                            }
                        } else {
                            if (out_len < scratch_size) scratch[out_len++] = 'u';
                        }
                    } else {
                        if (out_len < scratch_size) scratch[out_len++] = e;
                    }
                    i++;
                } else {
                    if (out_len < scratch_size) scratch[out_len++] = data[i];
                    i++;
                }
            }
            bool is_key = false;
            size_t peek = i;
            while (peek < len && (data[peek] == ' ' || data[peek] == '\t' || data[peek] == '\n' || data[peek] == '\r')) {
                peek++;
            }
            if (peek < len && data[peek] == ':') {
                is_key = true;
            }
            if (out_len > 0) {
                if (is_key) {
                    int match = lumina_scan_projected_value(
                        scratch, out_len, LUMINA_SCOPE_BODY, LUMINA_VAR_ARGS_NAMES, state);
                    if (match) threat = match;
                } else {
                    int match = lumina_scan_projected_value(
                        scratch, out_len, LUMINA_SCOPE_BODY, LUMINA_VAR_ARGS, state);
                    if (match) threat = match;
                }
            }
            continue;
        }
        if ((c >= '0' && c <= '9') || c == '-' || c == 't' || c == 'f' || c == 'n') {
            size_t start = i;
            while (i < len && data[i] != ' ' && data[i] != '\t' && data[i] != '\n' && data[i] != '\r' &&
                   data[i] != ',' && data[i] != ']' && data[i] != '}') {
                i++;
            }
            if (i > start) {
                int match = lumina_scan_projected_value(
                    data + start, i - start, LUMINA_SCOPE_BODY, LUMINA_VAR_ARGS, state);
                if (match) threat = match;
            }
            continue;
        }
        i++;
    }
    return threat;
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
    static thread_local unsigned char projected[131072];

    if (scan_json_body) {
        for (int vi = 0; vi < bundle->count; vi++) {
            const BundleVar *var = &bundle->vars[vi];
            if (var->var_type == LUMINA_VAR_BODY && var->ptr && var->len > 0) {
                int json_threat = lumina_parse_and_project_json(
                    var->ptr, var->len, state, projected, sizeof(projected));
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
                    state, g_short_rule_xml_container_mask, 0);
                if (container_threat) threat = container_threat;
                int xml_threat = lumina_scan_xml_avx2(var->ptr, var->len, state);
                if (xml_threat) threat = xml_threat;
            }
        }
    }
    int multipart_threat = lumina_scan_multipart_file_collections(
        bundle, state, projected, sizeof(projected));
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
                var->header_mask);
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
                    if (name_end > start) {
                        int projected_match = lumina_scan_projected_value(
                            var->ptr + start, name_end - start, var->scope,
                            LUMINA_VAR_COOKIE_NAMES, state);
                        if (projected_match) threat = projected_match;
                    }
                    size_t value_start = equal + 1;
                    while (value_start < end && (var->ptr[value_start] == ' ' ||
                                                 var->ptr[value_start] == '\t')) value_start++;
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
    if (!var || !state || (!var->ptr && var->len != 0) || var->len > 131072) return -1;
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
    if (!decoded || decoded_len > 131072) {
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

    uint8_t first = decoded[0];
    for (int word = 0; word < CRS_SHORT_RULE_MASK_DIMS; word++) {
        uint64_t candidates = g_short_rule_mask[first][word] & effective.pos0[word];
        while (candidates) {
            int idx = __builtin_ctzll(candidates) + (word << 6);
            candidates &= candidates - 1;
            if (g_short_rule_collection_mask[idx] && !(g_short_rule_collection_mask[idx] & var->collection_mask)) {
                continue;
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
                int rule_id = lumina_dispatch_rule(idx, decoded, decoded_len, offset);
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
    if (!bundle || !state || bundle->count < 0 || bundle->count > 16) return -1;
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
    if (!var || (!var->ptr && var->len != 0) || var->len > 131072) return 0;
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
    if (!decoded || decoded_len > 131072) {
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
    if (!bundle || !state || bundle->count < 0 || bundle->count > 16) return -1;
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
    if (!bundle || !out_result || bundle->count == 0) return -1;

    LuminaRuleState fallback_state = {};
    if (!state) state = &fallback_state;

    g_anomaly_score_tls = 0;
    g_anomaly_category_tls = 0;
    /* Generated phase controls run before metadata and content evaluation. */
    int threat = lumina_eval_tx_rules(bundle, state);
    LuminaBundle sorted = *bundle;
    bundle_sort_by_length(&sorted);

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

    static thread_local unsigned char scratchpad[131072];

    for (int vi = 0; vi < sorted.count && threat == 0; vi++) {
        const BundleVar *v = &sorted.vars[vi];
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
        if (v->len > 131072) continue;
        /* The caller's ARGS slot carries the raw query container. Its raw
         * QUERY_STRING view and projected ARGS/ARGS_NAMES values were handled
         * above; scanning the container again would cross parameter bounds. */
        if (v->var_type == LUMINA_VAR_ARGS || v->var_type == LUMINA_VAR_COOKIE) continue;
        if (scan_structured_body && v->var_type == LUMINA_VAR_BODY) continue;

        if (vi + 1 < sorted.count) {
            __builtin_prefetch(sorted.vars[vi + 1].ptr, 0, 3);
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
                if (jlen > 131072) jlen = 131072;
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

            if (data_len > 0) {
                uint8_t c = data_ptr[0];
#if LUMINA_SHARED_ROUTER_COUNT > 0
                uint8_t processed_routers[LUMINA_SHARED_ROUTER_COUNT] = {};
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
                            mw &= ~g_shared_router_rule_mask[router_id][_w];
                            if (processed_routers[router_id] != 0) continue;
                            processed_routers[router_id] = 1;
                            uint64_t matched[CRS_SHORT_RULE_MASK_DIMS];
                            lumina_run_shared_router(
                                router_id, data_ptr, data_len, 0,
                                effective.pos0, matched);
                            for (int hit_word = 0;
                                 hit_word < CRS_SHORT_RULE_MASK_DIMS && !threat;
                                 ++hit_word) {
                                uint64_t hits = matched[hit_word];
                                while (hits) {
                                    int hit_idx = __builtin_ctzll(hits) + (hit_word << 6);
                                    hits &= hits - 1;
                                    int score = g_short_rule_score[hit_idx];
                                    if (score == 0) continue;
                                    LUMINA_ADD_SCORE_AND_CHECK(
                                        state, g_short_rule_id[hit_idx], score,
                                        g_short_rule_category[hit_idx],
                                        adaptive_threshold + var_score_before,
                                        data_ptr, data_len, 0);
                                    if (threat) break;
                                }
                            }
                            continue;
                        }
#endif
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
                            r = lumina_dispatch_rule(idx, data_ptr, data_len, j);
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
        out_result->error_flag = 0;
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
