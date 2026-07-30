#ifndef LUMINA_TRANSFORMS_H
#define LUMINA_TRANSFORMS_H

#include <stddef.h>
#include <stdint.h>
#include "generated/crs_short_rules.h"

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__GNUC__) || defined(__clang__)
#define LUMINA_TRANSFORM_INTERNAL __attribute__((visibility("hidden")))
#else
#define LUMINA_TRANSFORM_INTERNAL
#endif

/* ============================================================================
 * K3 — Transform pipeline (ModSecurity t: chain) — F2.
 *
 * AOT-compiled: per-rule transform SEQUENCE is static C data
 * (g_rule_transform_seq[LUMINA_SHORT_RULE_COUNT][12], see generated/crs_transform_mask.h), NOT
 * parsed from .conf at runtime (see IMPORTANT.md: zero runtime parsing).
 * The sequence preserves CRS application ORDER and t: inheritance semantics.
 *
 * Runtime applies the chain to a scratch copy of the matched slice in place,
 * each operator may change length, and lumina_apply_transforms returns the new
 * length. A rule with an empty sequence gets NO transform (pre-K3 behavior).
 *
 * Faithful ModSecurity transform semantics (libmodsecurity msc_*.c):
 *   lowercase, removeNulls, urlDecode, urlDecodeUni, htmlEntityDecode,
 *   jsDecode, cssDecode, compressWhitespace, removeWhitespace, normalisePath
 *   (normalizePath/normalizePathWin), utf8toUnicode, cmdLine, replaceComments.
 * ==========================================================================*/

typedef enum {
    LUMINA_T_NONE              = 0,
    LUMINA_T_LOWERCASE         = (1u << 0),
    LUMINA_T_URL_DECODE        = (1u << 1),
    LUMINA_T_URL_DECODE_UNI    = (1u << 2),
    LUMINA_T_HTML_ENTITY_DECODE= (1u << 3),
    LUMINA_T_REMOVE_NULLS      = (1u << 4),
    LUMINA_T_JS_DECODE         = (1u << 5),
    LUMINA_T_CSS_DECODE        = (1u << 6),
    LUMINA_T_NORMALIZE_PATH    = (1u << 7),
    LUMINA_T_COMPRESS_WS       = (1u << 8),
    LUMINA_T_REMOVE_WS         = (1u << 9),
    LUMINA_T_UTF8_TO_UNICODE   = (1u << 10),
    LUMINA_T_NORMALIZE_PATH_WIN= (1u << 11),
    LUMINA_T_REPLACE_COMMENTS  = (1u << 12),
    LUMINA_T_CMDLINE           = (1u << 13),
    LUMINA_T_ESCAPE_SEQ_DECODE = (1u << 14),
    LUMINA_T_BASE64_DECODE     = (1u << 15),
    LUMINA_T_LENGTH            = (1u << 16),
    LUMINA_T_REMOVE_COMMENTS_CHAR = (1u << 17)
} LuminaTransformId;

typedef struct {
    /* Exact observed-byte set when known != 0. Unknown is a sound
     * conservative state: no transform may be skipped from this object. */
    uint64_t observed_bytes[4];
    uint8_t known;
} LuminaTransformFeatures;

/* Per-rule ordered transform chain, indexed by engine rule idx.
 * Declared here for the dispatch; defined in generated/crs_transform_mask.c.
 * Row is a null-terminated list of LuminaTransformId in CRS application order. */
extern const LuminaTransformId g_rule_transform_seq[LUMINA_SHORT_RULE_COUNT][12];
extern const uint8_t g_rule_transform_seq_id[LUMINA_SHORT_RULE_COUNT];

/* Apply the rule's transform chain to buf in place. Returns the new length
 * (some operators shrink/grow the buffer). buf must point at a mutable buffer
 * of at least lumina_xform_scratch_cap() bytes. */
size_t lumina_apply_transforms(const LuminaTransformId *seq, uint8_t *buf, size_t len);
size_t lumina_apply_transform_step(
    LuminaTransformId transform, uint8_t *buf, size_t len);
int lumina_transform_step_may_change(
    LuminaTransformId transform, const uint8_t *buf, size_t len);
LUMINA_TRANSFORM_INTERNAL void lumina_transform_features_init(
    LuminaTransformFeatures *features, const uint64_t observed_bytes[4]);
LUMINA_TRANSFORM_INTERNAL int lumina_transform_features_may_change(
    const LuminaTransformFeatures *features, LuminaTransformId transform);
LUMINA_TRANSFORM_INTERNAL size_t lumina_apply_transform_step_features(
    LuminaTransformId transform, uint8_t *buf, size_t len,
    LuminaTransformFeatures *features);

/* ---- operators (each returns new length; operates in place) ---- */
void   lumina_transform_lower(uint8_t *buf, size_t len);
size_t lumina_transform_remove_nulls(uint8_t *buf, size_t len);
size_t lumina_transform_url_decode(uint8_t *buf, size_t len, int decode_plus);
size_t lumina_transform_url_decode_uni(uint8_t *buf, size_t len);
size_t lumina_transform_html_entity_decode(uint8_t *buf, size_t len);
size_t lumina_transform_js_decode(uint8_t *buf, size_t len);
size_t lumina_transform_css_decode(uint8_t *buf, size_t len);
size_t lumina_transform_compress_ws(uint8_t *buf, size_t len);
size_t lumina_transform_remove_ws(uint8_t *buf, size_t len);
size_t lumina_transform_normalise_path(uint8_t *buf, size_t len, int win);
size_t lumina_transform_replace_comments(uint8_t *buf, size_t len);
size_t lumina_transform_utf8_to_unicode(uint8_t *buf, size_t len);
size_t lumina_transform_cmdline(uint8_t *buf, size_t len);

/* Preallocated per-thread scratch arena for transform copies (zero hot-path
 * allocation). Returned buffer is at least lumina_xform_scratch_cap() bytes. */
uint8_t *lumina_xform_scratch(void);
uint8_t *lumina_xform_scratch_slot(size_t slot);
size_t   lumina_xform_scratch_cap(void);

#ifdef __cplusplus
}
#endif

#undef LUMINA_TRANSFORM_INTERNAL

#endif /* LUMINA_TRANSFORMS_H */
