#ifndef LUMINAWAF_H
#define LUMINAWAF_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include "lumina_markers.h"

#define LUMINA_ANOMALY_THRESHOLD 5
#define LUMINA_SINGLE_CATEGORY_THRESHOLD 4

#define LUMINA_CAT_SQLI   0x01
#define LUMINA_CAT_XSS    0x02
#define LUMINA_CAT_RCE    0x04
#define LUMINA_CAT_PATH   0x08
#define LUMINA_CAT_OTHER  0x10
#define LUMINA_CAT_PROCOL 0x20

#define LUMINA_PARA_SQLI   5
#define LUMINA_PARA_XSS    5
#define LUMINA_PARA_RCE    5
#define LUMINA_PARA_PATH   5
#define LUMINA_PARA_OTHER  5
#define LUMINA_PARA_PROCOL 5

typedef enum {
    LUMINA_VAR_URI     = 0,
    LUMINA_VAR_ARGS    = 1,
    LUMINA_VAR_COOKIE  = 2,
    LUMINA_VAR_HDR     = 3,
    LUMINA_VAR_BODY    = 4,
    LUMINA_VAR_ANY     = 5,
    LUMINA_VAR_ARGS_NAMES = 6,
    LUMINA_VAR_FILES   = 7,
    /* Raw query container. ARGS rules execute on projected values, while
     * QUERY_STRING rules execute on the original caller-owned slice. */
    LUMINA_VAR_QUERY_STRING = 8,
    LUMINA_VAR_COOKIE_NAMES = 9,
    LUMINA_VAR_FILES_NAMES = 10,
    LUMINA_VAR_REQUEST_FILENAME = 11,
    LUMINA_VAR_REQUEST_BASENAME = 12,
    LUMINA_VAR_XML     = 13,
    LUMINA_VAR_XML_ATTR = 14
} LuminaVarType;

#define LUMINA_VAR_TYPE_SLOTS 15

typedef enum {
    LUMINA_SCOPE_NONE      = 0,
    LUMINA_SCOPE_URI       = (1 << 0),   // 1
    LUMINA_SCOPE_HEADERS   = (1 << 1),   // 2
    LUMINA_SCOPE_BODY      = (1 << 2),   // 4
    LUMINA_SCOPE_JSON      = (1 << 3),   // 8
    LUMINA_SCOPE_MULTIPART = (1 << 4),   // 16
    LUMINA_SCOPE_FORM_URLENCODED = (1 << 5), // internal ARGS decode contract
    LUMINA_SCOPE_ALL       = 0xFF
} LuminaScope;

// Define collection masks for ModSecurity collections.
// These are independent of topological scopes (URI/BODY/HEADER).
#define LUMINA_COL_ARGS             (1ULL << 0)
#define LUMINA_COL_ARGS_NAMES       (1ULL << 1)
#define LUMINA_COL_REQUEST_COOKIES  (1ULL << 2)
#define LUMINA_COL_REQUEST_HEADERS  (1ULL << 3)
#define LUMINA_COL_REQUEST_BODY     (1ULL << 4)
#define LUMINA_COL_XML              (1ULL << 5)
#define LUMINA_COL_JSON             (1ULL << 6)
#define LUMINA_COL_FILES            (1ULL << 7)
#define LUMINA_COL_FILES_NAMES      (1ULL << 8)
#define LUMINA_COL_REQUEST_COOKIES_NAMES (1ULL << 9)
#define LUMINA_COL_REQUEST_FILENAME (1ULL << 10)
#define LUMINA_COL_REQUEST_BASENAME (1ULL << 11)
#define LUMINA_TARGET_COLLECTION_SLOTS 12

typedef enum {
    LUMINA_HDR_CONTENT_LENGTH  = (1u << 0),
    LUMINA_HDR_REQUEST_RANGE   = (1u << 1),
    LUMINA_HDR_CONNECTION      = (1u << 2),
    LUMINA_HDR_HOST            = (1u << 3),
    LUMINA_HDR_USER_AGENT      = (1u << 4),
    LUMINA_HDR_CONTENT_TYPE    = (1u << 5),
    LUMINA_HDR_ACCEPT_ENCODING = (1u << 6),
    LUMINA_HDR_ACCEPT          = (1u << 7),
    LUMINA_HDR_COOKIE          = (1u << 8),
    LUMINA_HDR_REFERER         = (1u << 9),
    LUMINA_HDR_X_FILENAME      = (1u << 10),
    LUMINA_HDR_RANGE           = (1u << 11),
} LuminaHeaderMask;

/* Fixed-layout result returned through the public C ABI. */
typedef struct {
    int error_flag;
    int threat_level;
    const char* decoded_buffer;
    size_t decoded_length;
} LuminaResult;

/* Idempotent server-integration lifecycle hook. The current runtime uses
 * fixed-capacity thread-local scratch storage and performs no worker setup. */
int luminawaf_init_worker(size_t expected_concurrent_connections);

typedef struct {
    const unsigned char *ptr;
    size_t len;
    uint8_t var_type;
    uint32_t scope;
    uint32_t header_mask;
    uint64_t collection_mask;
    /* Optional caller-owned collection key. For header variables this is the
     * exact REQUEST_HEADERS_NAMES byte slice; value-only collections leave it
     * NULL/zero. The engine never owns or mutates this memory. */
    const unsigned char *name;
    size_t name_len;
} BundleVar;

typedef struct {
    BundleVar vars[16];
    int count;
    uint32_t hdr_presence_mask;
    /* C4 STRUCTURAL: discrete CRS collections that are NOT part of the
     * per-variable buffer scan (vars[]) but are required by CRS rules such as
     * 911100 (REQUEST_METHOD), 920100 (REQUEST_LINE), 913100 (User-Agent).
     * These are fed by the caller (NGINX module / harness) directly. */
    const unsigned char *req_method;   size_t req_method_len;
    const unsigned char *req_line;     size_t req_line_len;
    const unsigned char *user_agent;   size_t user_agent_len;
    const unsigned char *req_protocol; size_t req_protocol_len;
    /* Normalized path collections supplied by the server integration. They
     * remain separate because REQUEST_BASENAME is not equivalent to scanning
     * the complete URI at an arbitrary offset. */
    const unsigned char *req_filename; size_t req_filename_len;
    const unsigned char *req_basename; size_t req_basename_len;
    /* Request-body parser selected by the server integration, exposed as the
     * ModSecurity REQBODY_PROCESSOR collection (for example URLENCODED, JSON,
     * or XML). The slice is caller-owned and may be NULL when no processor is
     * active. */
    const unsigned char *reqbody_processor; size_t reqbody_processor_len;
    uint16_t hdr_host_count;
    uint16_t hdr_user_agent_count;
    uint16_t hdr_content_type_count;
    uint16_t hdr_request_range_count;
    uint16_t hdr_transfer_encoding_count;
} LuminaBundle;

#include "lumina_hit_slab.h"

#define LUMINA_MAX_CAPTURES 10
#define LUMINA_MAX_EXTERNAL_MATCHES 32
#define LUMINA_MAX_TX_VARS 8

typedef struct {
    const unsigned char* ptr;
    size_t len;
} LuminaCapture;

#define LUMINA_FLAG_HAS_MULTIPART_XML (1ULL << 0)
#define LUMINA_FLAG_PAYLOAD_TRUNCATED (1ULL << 1)
#define LUMINA_FLAG_BASE64_STRICT_FAILED (1ULL << 2)

typedef struct {
    LuminaHitSlab completed_rules;
    LuminaHitSlab matched_rules;
    LuminaHitSlab predicate_rules;
    /* Transaction-local ModSecurity ctl:ruleRemoveById state. Generated
     * controls mark engine indices before any request collection is scanned. */
    LuminaHitSlab disabled_rules;
    /* Collection-local ctl:ruleRemoveTargetByTag state. Each slot corresponds
     * to one LUMINA_COL_* bit, so target removal never disables a rule for
     * unrelated collections in the same transaction. */
    LuminaHitSlab disabled_rule_targets[LUMINA_TARGET_COLLECTION_SLOTS];
    uint64_t hash_dedup[8];
    LuminaCapture captures[LUMINA_MAX_CAPTURES];
    LuminaCapture tx_vars[LUMINA_MAX_TX_VARS];
    int external_matches[LUMINA_MAX_EXTERNAL_MATCHES];
    uint64_t transaction_flags;
    uint16_t external_match_count;
    uint16_t reserved;
} LuminaRuleState;

int luminawaf_inspect_bundle(const LuminaBundle *bundle, LuminaRuleState *state, LuminaResult *out_result);
int luminawaf_inspect_tx(const LuminaBundle *bundle, LuminaRuleState *state, LuminaResult *out_result);
int luminawaf_audit_bundle_matches(const LuminaBundle *bundle, LuminaRuleState *state);
int luminawaf_audit_bundle_rule(const LuminaBundle *bundle, LuminaRuleState *state, int rule_id);
int luminawaf_rule_state_matched(const LuminaRuleState *state, int rule_id);
size_t luminawaf_rule_state_size(void);

/* Generated transaction evaluators commit only completed chain heads through
 * this ABI. Predicate progress is recorded separately in predicate_rules. */
int lumina_commit_generated_rule(LuminaRuleState *state, int engine_idx,
                                 int rule_id, int score, int category);

/* Inspect one request buffer and write the verdict to out_result. */
int luminawaf_inspect_request(const unsigned char* uri_data, size_t uri_len, LuminaRuleState *state, LuminaResult* out_result);

int luminawaf_inspect_buffer(const unsigned char* data, size_t len, uint32_t active_scope, uint8_t var_type, LuminaRuleState *state, LuminaResult* out_result);

int luminawaf_inspect_buffer_ex(const unsigned char* data, size_t len, uint32_t active_scope, uint32_t hdr_presence_mask, uint8_t var_type, LuminaRuleState *state, LuminaResult* out_result);

/* ABI-compatible lifecycle hook; currently no worker-owned storage exists. */
void luminawaf_destroy_worker(void);

#ifdef __cplusplus
}
#endif

#endif // LUMINAWAF_H
