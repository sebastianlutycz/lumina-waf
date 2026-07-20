#include "trigger_matcher.h"
#include <string.h>
#if defined(__SSE2__)
#include <immintrin.h>
#elif defined(__ARM_NEON)
#include <arm_neon.h>
#endif

/* ============================================================================
 * Trigger Definitions — original table (case-preserving source of truth)
 *   g_triggers_simd[] at init time stores pre-lowercased, 16-byte padded copies.
 *   Runtime comparison is case-insensitive but now uses a single SIMD compare
 *   per candidate instead of O(len) scalar byte-by-byte branches.
 * ==========================================================================*/

#define TRIGGER_MAX_DEFS 256

static const LuminaTriggerDef g_triggers[] = {
    /* XSS */
    {"<sc",        3,  TRIGGER_XSS_SCRIPT_START},
    {"on=",        3,  TRIGGER_XSS_ON},
    {"onerror=",   8,  TRIGGER_XSS_ON},
    {"onload=",    7,  TRIGGER_XSS_EXTRA},
    {"onclick=",   8,  TRIGGER_XSS_EXTRA},
    {"onmouseover=", 12, TRIGGER_XSS_EXTRA},
    {"onfocus=",    8,  TRIGGER_XSS_EXTRA},
    {"ondblclick=",11,  TRIGGER_XSS_EXTRA},
    {"oncontextmenu=", 14, TRIGGER_XSS_EXTRA},
    {"onsubmit=",   9,  TRIGGER_XSS_EXTRA},
    {"ontoggle=",   9,  TRIGGER_XSS_EXTRA},
    {"<script",    7,  TRIGGER_XSS_SCRIPT_START},
    {"<svg",       4,  TRIGGER_XSS_EXTRA},
    {"<iframe",    7,  TRIGGER_XSS_EXTRA},
    {"<img",       4,  TRIGGER_XSS_EXTRA},
    {"<details",   8,  TRIGGER_XSS_EXTRA},
    {"<style",     6,  TRIGGER_XSS_EXTRA},
    {"<body",      5,  TRIGGER_XSS_EXTRA},
    {"<html",      5,  TRIGGER_XSS_EXTRA},
    {"<head",      5,  TRIGGER_XSS_EXTRA},
    {"<meta",      5,  TRIGGER_XSS_EXTRA},   /* META HTTP-EQUIV / charset (941160 libinjection parity) */
    {"<embed",     6,  TRIGGER_XSS_EXTRA},
    {"<object",    7,  TRIGGER_XSS_EXTRA},
    {"<layer",     6,  TRIGGER_XSS_EXTRA},
    {"<xml",       4,  TRIGGER_XSS_EXTRA},
    {"<xss",       4,  TRIGGER_XSS_EXTRA},
    {"<;",         2,  TRIGGER_XSS_EXTRA},        /* <; obfuscation: <;IFRAME, <;META, <;IMG */
    {"<;iframe",   8,  TRIGGER_XSS_EXTRA},        /* coverage for <;IFRAME SRC=... */
    {"<;meta",     5,  TRIGGER_XSS_EXTRA},        /* coverage for <;META ... */
    {"<;img",      4,  TRIGGER_XSS_EXTRA},        /* coverage for <;IMG ... */
    {"<;script",   8,  TRIGGER_XSS_SCRIPT_START}, /* coverage for <;SCRIPT ... */
    {"%3C",        3,  TRIGGER_XSS_ENCODED},
    {"+ADw-",      5,  TRIGGER_XSS_ENCODED},   /* UTF-7 encoded '<' */
    {"+AD4-",      5,  TRIGGER_XSS_ENCODED},   /* UTF-7 encoded '>' */
    {"javascript:",11,  TRIGGER_XSS_JAVASCRIPT},
    {"<?import",   8,  TRIGGER_XSS_EXTRA},
    {"vbscript:",  9,  TRIGGER_XSS_EXTRA},
    {"data:text",  9,  TRIGGER_XSS_EXTRA},
    {"expressio",  9,  TRIGGER_XSS_EXTRA},
    {"alert(",     6,  TRIGGER_XSS_ALERT},
    {"eval(",      5,  TRIGGER_XSS_EXTRA},
    {"document.",  9,  TRIGGER_XSS_EXTRA},
    {"expression(",11, TRIGGER_XSS_EXTRA},
    {"@import",    7,  TRIGGER_XSS_EXTRA},
    {"xmlns:",     6,  TRIGGER_XSS_EXTRA},

    /* SQLi */
    {"UN",         2,  TRIGGER_SQLI_UNION},
    {"UNION",      5,  TRIGGER_SQLI_UNION},
    {"SELECT",     6,  TRIGGER_SQLI_SELECT},
    {"xp_",        3,  TRIGGER_SQLI_XP},
    {"1=1",        3,  TRIGGER_SQLI_1EQUALS1},
    {"--",         2,  TRIGGER_SQLI_COMMENT},
    {"/*!",        3,  TRIGGER_SQLI_EXTRA},
    {"' OR",       4,  TRIGGER_SQLI_EXTRA},
    {"\" OR",      4,  TRIGGER_SQLI_EXTRA},
    {"OR+1",       4,  TRIGGER_SQLI_1EQUALS1},
    {"OR '",       4,  TRIGGER_SQLI_EXTRA},
    {"SLEEP(",     6,  TRIGGER_SQLI_EXTRA},
    {"WAITFOR",    7,  TRIGGER_SQLI_EXTRA},
    {"DROP ",      5,  TRIGGER_SQLI_EXTRA},
    {"DROP\n",     5,  TRIGGER_SQLI_EXTRA},
    {"INSERT ",    7,  TRIGGER_SQLI_EXTRA},
    {"INSERT\n",   7,  TRIGGER_SQLI_EXTRA},
    {"DELETE ",    7,  TRIGGER_SQLI_EXTRA},
    {"DELETE\n",   7,  TRIGGER_SQLI_EXTRA},
    {"UPDATE ",    7,  TRIGGER_SQLI_EXTRA},
    {"UPDATE\n",   7,  TRIGGER_SQLI_EXTRA},
    {"; DROP",     6,  TRIGGER_SQLI_EXTRA},
    {"; DELETE",   8,  TRIGGER_SQLI_EXTRA},
    {"; INSERT",   8,  TRIGGER_SQLI_EXTRA},
    {"'; DROP",    6,  TRIGGER_SQLI_EXTRA},
    {"'; DELETE",  8,  TRIGGER_SQLI_EXTRA},
    {"'; INSERT",  8,  TRIGGER_SQLI_EXTRA},
    {"'; SELECT",  9,  TRIGGER_SQLI_SELECT},
    {"; SELECT",   8,  TRIGGER_SQLI_SELECT},
    {"EXTRACTV",   8,  TRIGGER_SQLI_EXTRA},
    {"CHAR(",      5,  TRIGGER_SQLI_EXTRA},
    {"BENCHMARK(",10,  TRIGGER_SQLI_EXTRA},
    {"EXEC(",      5,  TRIGGER_SQLI_EXTRA},
    {"EXECUTE ",   8,  TRIGGER_SQLI_EXTRA},
    {"IF(",        3,  TRIGGER_SQLI_EXTRA},
    {"CASE WHEN",  9,  TRIGGER_SQLI_EXTRA},
    {"PG_SLEEP(",  9,  TRIGGER_SQLI_EXTRA},
    {"LOAD_FILE(",10,  TRIGGER_SQLI_EXTRA},
    {"INTO OUT",   8,  TRIGGER_SQLI_EXTRA},
    {"INTO DUMP",  9,  TRIGGER_SQLI_EXTRA},
    {"INFORMATIO",10,  TRIGGER_SQLI_EXTRA},
    {"0X",         2,  TRIGGER_SQLI_EXTRA},
    {"CONCAT(0X", 10,  TRIGGER_SQLI_EXTRA},
    {"#/",         2,  TRIGGER_SQLI_COMMENT},
    /* SQLi quoted-special heuristic (libinjection parity for 942100) */
    {"'=",         2,  TRIGGER_SQLI_EXTRA},
    {"'-",         2,  TRIGGER_SQLI_COMMENT},
    {"'/*",        3,  TRIGGER_SQLI_COMMENT},
    {"'&",         2,  TRIGGER_SQLI_EXTRA},
    {"'|",         2,  TRIGGER_SQLI_EXTRA},
    {"'*",         2,  TRIGGER_SQLI_EXTRA},
    {"'^",         2,  TRIGGER_SQLI_EXTRA},
    {"')",         2,  TRIGGER_SQLI_EXTRA},
    {"\"=",        2,  TRIGGER_SQLI_EXTRA},
    {"\"-",        2,  TRIGGER_SQLI_COMMENT},
    {"\"/*",       3,  TRIGGER_SQLI_COMMENT},
    {"\"&",        2,  TRIGGER_SQLI_EXTRA},
    {"\"|",        2,  TRIGGER_SQLI_EXTRA},
    {"\"*",        2,  TRIGGER_SQLI_EXTRA},
    {"\"^",        2,  TRIGGER_SQLI_EXTRA},
    {"\")",        2,  TRIGGER_SQLI_EXTRA},

    /* Path traversal */
    {"..",         2,  TRIGGER_PATH_TRAV},
    {"%2e%2e",     6,  TRIGGER_PATH_TRAV},
    {"%2F",        3,  TRIGGER_PATH_TRAV},
    {".git",       4,  TRIGGER_PATH_GITCONFIG},

    /* Recon */
    {"wp-",        3,  TRIGGER_RECON},
    {"wp-admin",   8,  TRIGGER_RECON},
    {".env",       4,  TRIGGER_RECON},
    {"phpmyadmin", 10, TRIGGER_RECON},
    {"backup.",    7,  TRIGGER_RECON},
    {"/admin",     6,  TRIGGER_RECON},
    {"/shell",     6,  TRIGGER_RECON},
    {"/console",   8,  TRIGGER_RECON},
    {"/manager",   8,  TRIGGER_RECON},
    {"/actuator",  9,  TRIGGER_RECON},
    {"xmlrpc",     6,  TRIGGER_RECON},

    /* LFI / OS file access (CRS 930120 — lfi-os-files.data key entries) */
    {"etc/",       4,  TRIGGER_PATH_TRAV},
    {"proc/",      5,  TRIGGER_PATH_TRAV},
    {"system32",   8,  TRIGGER_PATH_TRAV},
    {"syswow64",   8,  TRIGGER_PATH_TRAV},
    {"windows/",   8,  TRIGGER_PATH_TRAV},
    {"winnt/",     6,  TRIGGER_PATH_TRAV},
    {"c:",         2,  TRIGGER_PATH_TRAV},
    {"\\",         1,  TRIGGER_PATH_TRAV},
    {"%00",        3,  TRIGGER_PATH_TRAV},

    /* Command injection */
    {"cmd=",       4,  TRIGGER_CMD_INJECT},
    {"exec=",      5,  TRIGGER_CMD_INJECT},
    {";cat ",      5,  TRIGGER_CMD_INJECT},
    {"|bash",      5,  TRIGGER_CMD_INJECT},
    {"wget ",      5,  TRIGGER_CMD_INJECT},
    {"curl ",      5,  TRIGGER_CMD_INJECT},
    {"`",         1,  TRIGGER_CMD_INJECT},
    {"$(",             2,  TRIGGER_CMD_INJECT},
    {"${",             2,  TRIGGER_CMD_INJECT},
    {"$ne:",           4,  TRIGGER_CMD_INJECT},  /* NoSQL (942290) */
    {"$gt:",           4,  TRIGGER_CMD_INJECT},
    {"$lt:",           4,  TRIGGER_CMD_INJECT},
    {"$where:",        7,  TRIGGER_CMD_INJECT},
    {"jndi:",      5,  TRIGGER_CMD_INJECT},
    {"ldap://",    7,  TRIGGER_CMD_INJECT},
    {"ldaps://",   8,  TRIGGER_CMD_INJECT},
    /* Node.js / NoSQL injection (CRS 934100 — function(), db.<coll>.<method>, mapReduce) */
    {"function(",  9,  TRIGGER_CMD_INJECT},
    {"mapReduce(", 10,  TRIGGER_CMD_INJECT},
    {"emit(",       5,  TRIGGER_CMD_INJECT},
    {"&(uid=",      7,  TRIGGER_LDAP_INJECT},  /* moved from CMD_INJECT to LDAP */
    {"objectClass",11,  TRIGGER_LDAP_INJECT},  /* moved from CMD_INJECT to LDAP */

    /* RCE / Unix Shell (CRS 932160 — unix-shell.data key entries) */
    {"$home",      5,  TRIGGER_CMD_INJECT},
    {"$path",      5,  TRIGGER_CMD_INJECT},
    {"$user",      5,  TRIGGER_CMD_INJECT},
    {"$shell",     6,  TRIGGER_CMD_INJECT},
    {"$lang",      5,  TRIGGER_CMD_INJECT},
    {"/bin/",      5,  TRIGGER_CMD_INJECT},
    {"/usr/bin",   8,  TRIGGER_CMD_INJECT},
    {"/sbin/",     6,  TRIGGER_CMD_INJECT},

    /* JNDI Injection (CRS 932130 — Log4Shell / Log4j RCE) */
    {"${jndi:",    7,  TRIGGER_JNDI_INJECT},
    {"jndi:",      5,  TRIGGER_JNDI_INJECT},   /* after ${} stripping */
    {"${lower:",   8,  TRIGGER_JNDI_INJECT},   /* log4j obfuscation: ${lower:${lower:h${lower:}}${lower:e}...} */
    {"${upper:",   8,  TRIGGER_JNDI_INJECT},
    {"${env:",     6,  TRIGGER_JNDI_INJECT},   /* env variable exfiltration: ${env:HOSTNAME} */
    {"${sys:",     6,  TRIGGER_JNDI_INJECT},   /* Java system property: ${sys:user.name} */
    {"${java:",    7,  TRIGGER_JNDI_INJECT},   /* Java enumeration: ${java:os} */
    {"${date:",    7,  TRIGGER_JNDI_INJECT},   /* log4j date lookup */
    {"${ctx:",     6,  TRIGGER_JNDI_INJECT},   /* log4j context lookup */

    /* LDAP Injection (CRS 921110) */
    {"* (",        3,  TRIGGER_LDAP_INJECT},   /* wildcard filter start */
    {"*(&",        3,  TRIGGER_LDAP_INJECT},   /* AND filter */
    {"*(|",        3,  TRIGGER_LDAP_INJECT},   /* OR filter (already in CMD_INJECT — moved here) */
    {")(&",        3,  TRIGGER_LDAP_INJECT},   /* nested AND */
    {")(|",        3,  TRIGGER_LDAP_INJECT},   /* nested OR */
    {")(uid=",     6,  TRIGGER_LDAP_INJECT},   /* uid attribute injection */
    {")(cn=",      5,  TRIGGER_LDAP_INJECT},   /* common name injection */
    {")(mail=",    7,  TRIGGER_LDAP_INJECT},   /* email injection */
    {")(userpass", 10, TRIGGER_LDAP_INJECT},   /* password attribute */
    {")objectclass",12, TRIGGER_LDAP_INJECT},  /* already in CMD too, but LDAP-specific */

    /* HTTP Response Splitting / Header Injection (CRS 921130) */
    {"http/1",     6,  TRIGGER_RESP_SPLIT},
    {"%0d%0a",     6,  TRIGGER_RESP_SPLIT},   /* CRLF URL-encoded */
    {"%0d",        3,  TRIGGER_RESP_SPLIT},   /* CR URL-encoded */
    {"%0a",        3,  TRIGGER_RESP_SPLIT},   /* LF URL-encoded */
    {"content-type:",13, TRIGGER_RESP_SPLIT},  /* header injection via CRLF */
    {"location:",   9,  TRIGGER_RESP_SPLIT},   /* redirect injection */
    {"set-cookie:",11,  TRIGGER_RESP_SPLIT},   /* cookie injection */

    /* SSRF (CRS 934100) */
    {"127.0.0.1",  9,  TRIGGER_SSRF},
    {"169.254",    8,  TRIGGER_SSRF},          /* AWS/GCP metadata endpoint */
    {"metadata",   8,  TRIGGER_SSRF},           /* metadata.google.internal */
    {"[::1]",      5,  TRIGGER_SSRF},           /* IPv6 loopback */
    {"localhost",  9,  TRIGGER_SSRF},
    {"0.0.0.0",    7,  TRIGGER_SSRF},
    {"169.254.169", 11, TRIGGER_SSRF},         /* cloud metadata IP */
    {"100.100.",   8,  TRIGGER_SSRF},           /* Alibaba Cloud metadata */
    {"http://127", 10,  TRIGGER_SSRF},
    {"http://[",    8,  TRIGGER_SSRF},          /* http://[::1] */
    {"fc00::",     6,  TRIGGER_SSRF},           /* unique-local (private) IPv6 */
    {"fe80::",     6,  TRIGGER_SSRF},           /* link-local IPv6 */
    {"fd",         2,  TRIGGER_SSRF}            /* fd00::/8 private IPv6 prefix (short but aggressive) */
};

/* Computed at compile time — no manual count needed */
#define TRIGGER_ACTIVE_DEFS ((int)(sizeof(g_triggers) / sizeof(g_triggers[0])))

/* ============================================================================
 * Pre-lowercased trigger table for SIMD comparison.
 *
 * One 16-byte SSE/NEON-friendly copy per trigger. Constructed at load time by
 * lowercasing the original prefix and zero-padding. Zero-padding lets us do a
 * full 16-byte SIMD compare regardless of prefix length — only the first
 * `plen` bytes matter (checked via the movemask bit range).
 *
 * Layout: 128 entries × 16 bytes = 2048 bytes = 32 cache lines. All trigger
 * prefixes that a typical request touches land in one or two cache lines.
 * ==========================================================================*/
typedef struct {
    char     prefix16[16]  __attribute__((aligned(16)));
    uint8_t  len;
    uint8_t  _pad[3];
    uint32_t bit;
} LuminaTriggerDefSIMD;

static LuminaTriggerDefSIMD g_triggers_simd[TRIGGER_MAX_DEFS];
static uint64_t g_trigger_lo64[TRIGGER_MAX_DEFS] __attribute__((aligned(64)));
static uint64_t g_trigger_hi64[TRIGGER_MAX_DEFS] __attribute__((aligned(64)));
static uint64_t g_trigger_lo_mask[TRIGGER_MAX_DEFS] __attribute__((aligned(64)));
static uint64_t g_trigger_hi_mask[TRIGGER_MAX_DEFS] __attribute__((aligned(64)));

/* First-byte → candidate bitmask.  4 × 64 = 256 bits supports up to 256
   trigger entries.  Now uses lowercased bytes only, since we lowercase
   data[i] once before the dispatch.  */
static uint64_t g_trigger_first_mask[256][4];
static uint32_t g_trigger1_bits[256] __attribute__((aligned(64)));
static uint16_t g_trigger2_idx[65536] __attribute__((aligned(64)));
static uint64_t g_trigger2_mask[TRIGGER_MAX_DEFS + 1][4] __attribute__((aligned(64)));
static uint16_t g_trigger2_used;

static inline unsigned char lower1(unsigned char c) {
    return (unsigned char)(c | ((((unsigned)(c - 'A') <= ('Z' - 'A'))) << 5));
}

static inline uint64_t mask_for_bytes(unsigned n) {
    return (n >= 8) ? ~0ULL : ((1ULL << (n * 8)) - 1ULL);
}

static inline uint64_t lower8_ascii(uint64_t x) {
    const uint64_t hi = x & 0x8080808080808080ULL;
    uint64_t lo = x & 0x7f7f7f7f7f7f7f7fULL;
    uint64_t ge_a = lo + 0x3f3f3f3f3f3f3f3fULL;
    uint64_t le_z = lo + 0x2525252525252525ULL;
    uint64_t upper = (ge_a & ~le_z & 0x8080808080808080ULL) >> 2;
    return hi | lo | upper;
}

static inline uint64_t loadu64(const void *p) {
    uint64_t v;
    memcpy(&v, p, sizeof(v));
    return v;
}

__attribute__((constructor))
static void trigger_init_first_mask(void) {
    memset(g_trigger_first_mask, 0, sizeof(g_trigger_first_mask));
    memset(g_triggers_simd, 0, sizeof(g_triggers_simd));
    memset(g_trigger_lo64, 0, sizeof(g_trigger_lo64));
    memset(g_trigger_hi64, 0, sizeof(g_trigger_hi64));
    memset(g_trigger_lo_mask, 0, sizeof(g_trigger_lo_mask));
    memset(g_trigger_hi_mask, 0, sizeof(g_trigger_hi_mask));
    memset(g_trigger1_bits, 0, sizeof(g_trigger1_bits));
    memset(g_trigger2_idx, 0, sizeof(g_trigger2_idx));
    memset(g_trigger2_mask, 0, sizeof(g_trigger2_mask));
    g_trigger2_used = 0;

    for (int i = 0; i < TRIGGER_ACTIVE_DEFS; i++) {
        const LuminaTriggerDef *src = &g_triggers[i];

        /* Lowercase + zero-pad into prefix16 */
        for (int k = 0; k < 16; k++) {
            char c = (k < (int)src->len) ? src->prefix[k] : 0;
            if (c >= 'A' && c <= 'Z') c |= 0x20;
            g_triggers_simd[i].prefix16[k] = c;
        }
        g_triggers_simd[i].len = (uint8_t)src->len;
        g_triggers_simd[i].bit = src->bit;
        g_trigger_lo64[i] = loadu64(g_triggers_simd[i].prefix16);
        g_trigger_hi64[i] = loadu64(g_triggers_simd[i].prefix16 + 8);
        g_trigger_lo_mask[i] = mask_for_bytes(src->len < 8 ? src->len : 8);
        g_trigger_hi_mask[i] = (src->len > 8) ? mask_for_bytes(src->len - 8) : 0;

        /* Register in first-byte dispatch (lowercase only — we lowercase
           data[i] once before lookup, so no need for uppercase entries). */
        unsigned char first = (unsigned char)g_triggers_simd[i].prefix16[0];
        g_trigger_first_mask[first][i / 64] |= (1ULL << (i % 64));

        if (src->len == 1) {
            unsigned char a = lower1((unsigned char)src->prefix[0]);
            g_trigger1_bits[a] |= src->bit;
        } else if (src->len >= 2) {
            unsigned char a = lower1((unsigned char)src->prefix[0]);
            unsigned char b = lower1((unsigned char)src->prefix[1]);
            unsigned key = ((unsigned)a << 8) | b;
            uint16_t idx = g_trigger2_idx[key];
            if (idx == 0) {
                idx = ++g_trigger2_used;
                g_trigger2_idx[key] = idx;
            }
            g_trigger2_mask[idx][i / 64] |= (1ULL << (i % 64));
        }
    }
}

/* ---- SIMD helpers -------------------------------------------------------- */

#if defined(__SSE2__) || (defined(__ARM_NEON) && defined(__aarch64__))
#  define LUMINA_TRIGGER_SIMD 1
#else
#  define LUMINA_TRIGGER_SIMD 0
#endif

#if defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
#  define LUMINA_TRIGGER_SWAR_XOR 1
#else
#  define LUMINA_TRIGGER_SWAR_XOR 0
#endif

#if LUMINA_TRIGGER_SIMD
#if defined(__SSE2__)
/* Returns 16-bit mask of positions where lowercased `v` equals `prefix`. */
static inline int simd_lower_eq_mask(const unsigned char *data, const char *prefix16) {
    __m128i v       = _mm_loadu_si128((const __m128i *)data);
    /* SIMD lowercase:  alpha = (v >= 'A') & (v <= 'Z'); v |= (alpha & 0x20) */
    __m128i ge_A     = _mm_cmpgt_epi8(v, _mm_set1_epi8('A' - 1));  /* v >= 'A' (signed cmp ok for ASCII) */
    __m128i le_Z     = _mm_cmpgt_epi8(_mm_set1_epi8('Z' + 1), v);  /* v <= 'Z' */
    __m128i alpha    = _mm_and_si128(ge_A, le_Z);
    __m128i lower    = _mm_or_si128(v, _mm_and_si128(alpha, _mm_set1_epi8(0x20)));
    __m128i prefix   = _mm_loadu_si128((const __m128i *)prefix16);
    __m128i eq       = _mm_cmpeq_epi8(lower, prefix);
    return _mm_movemask_epi8(eq);
}
#elif defined(__ARM_NEON)
/* Returns 16-bit mask of positions where lowercased `v` equals `prefix`. */
static inline int simd_lower_eq_mask(const unsigned char *data, const char *prefix16) {
    uint8x16_t v       = vld1q_u8(data);
    uint8x16_t ge_A    = vcgeq_s8(v, vdupq_n_s8('A'));
    uint8x16_t le_Z    = vcleq_s8(v, vdupq_n_s8('Z'));
    uint8x16_t alpha   = vandq_u8(ge_A, le_Z);
    uint8x16_t lower   = vorrq_u8(v, vandq_u8(alpha, vdupq_n_u8(0x20)));
    uint8x16_t prefix  = vld1q_u8((const uint8_t *)prefix16);
    uint8x16_t eq      = vceqq_u8(lower, prefix);
    /* NEON has no movemask — narrow 16 bytes to 16 bits via pairwise adds. */
    uint8x16_t bits1   = vandq_u8(eq, vdupq_n_u8(1));
    uint16x8_t paired8 = vpaddlq_u8(bits1);
    uint32x4_t paired16= vpaddlq_u16(paired8);
    uint64x2_t paired32= vpaddlq_u32(paired16);
    uint64_t lo        = vgetq_lane_u64(paired32, 0);
    uint64_t hi        = vgetq_lane_u64(paired32, 1);
    return (int)(lo | (hi << 8));
}
#endif

/* SIMD-verify a candidate trigger at `pos`. Returns 1 if matched, 0 otherwise. */
static inline int simd_verify(const unsigned char *data, size_t len, size_t pos,
                               int tidx, uint32_t *hits) {
    const LuminaTriggerDefSIMD *def = &g_triggers_simd[tidx];
    uint8_t plen = def->len;
    if (pos + plen > len) return 0;
    if (*hits & def->bit) return 0;   /* satisfied-trigger skip */

    int matched = 0;
    int scalar_tail = 0;
#if LUMINA_TRIGGER_SWAR_XOR
    if (pos + 8 <= len) {
        uint64_t lo = lower8_ascii(loadu64(data + pos));
        uint64_t diff = (lo ^ g_trigger_lo64[tidx]) & g_trigger_lo_mask[tidx];
        if (diff == 0) {
            uint64_t hi_mask = g_trigger_hi_mask[tidx];
            if (hi_mask == 0) {
                matched = 1;
            } else if (pos + 16 <= len) {
                uint64_t hi = lower8_ascii(loadu64(data + pos + 8));
                matched = (((hi ^ g_trigger_hi64[tidx]) & hi_mask) == 0) ? 1 : 0;
            } else {
                scalar_tail = 1;
            }
        }
    } else
#endif
    if (pos + 16 <= len) {
        /* Hot path: single SIMD compare */
        int eq_mask = simd_lower_eq_mask(data + pos, def->prefix16);
        int want    = (1 << plen) - 1;
        matched = ((eq_mask & want) == want) ? 1 : 0;
    } else {
        scalar_tail = 1;
    }

    if (scalar_tail) {
        /* Tail: scalar fallback (pos+16 > len but pos+plen <= len) */
        size_t k;
        for (k = 0; k < plen; k++) {
            unsigned char a = data[pos + k];
            if (a >= 'A' && a <= 'Z') a |= 0x20;
            if (a != (unsigned char)def->prefix16[k]) break;
        }
        matched = (k == plen) ? 1 : 0;
    }

    if (matched) {
        *hits |= def->bit;
        if (*hits == 0xFFFFFFFFu) return -1;   /* all bits saturated */
    }
    return matched;
}
#endif /* LUMINA_TRIGGER_SIMD */

static inline int verify_word(const unsigned char *data, size_t len, size_t pos,
                              uint64_t word, int base, uint32_t *hits) {
    while (word) {
        int tidx = __builtin_ctzll(word) + base;
        word &= word - 1;
        if (tidx >= TRIGGER_ACTIVE_DEFS) continue;
        if (simd_verify(data, len, pos, tidx, hits) == -1) return -1;
    }
    return 0;
}

static inline int scan_pair_pos(const unsigned char *data, size_t len, size_t pos, uint32_t *hits) {
    unsigned a = lower1(data[pos]);
    unsigned b = lower1(data[pos + 1]);
    *hits |= g_trigger1_bits[a];
    unsigned key = (a << 8) | b;
    uint16_t idx = g_trigger2_idx[key];
    if (__builtin_expect(idx == 0, 1)) return 0;

    uint64_t c0 = g_trigger2_mask[idx][0];
    uint64_t c1 = g_trigger2_mask[idx][1];
    uint64_t c2 = g_trigger2_mask[idx][2];
    uint64_t c3 = g_trigger2_mask[idx][3];

    if (c0 && verify_word(data, len, pos, c0, 0, hits) == -1) return -1;
    if (c1 && verify_word(data, len, pos, c1, 64, hits) == -1) return -1;
    if (c2 && verify_word(data, len, pos, c2, 128, hits) == -1) return -1;
    if (c3 && verify_word(data, len, pos, c3, 192, hits) == -1) return -1;
    return 0;
}

static inline uint32_t trigger_match_pair_span(const unsigned char *data, size_t len, size_t start, size_t end) {
    uint32_t hits = 0;
    if (end <= start) return 0;

    size_t i = start;
    for (; i + 8 <= end; i += 8) {
        __builtin_prefetch(data + i + 64, 0, 0);
        if (scan_pair_pos(data, len, i + 0, &hits) == -1) return hits;
        if (scan_pair_pos(data, len, i + 1, &hits) == -1) return hits;
        if (scan_pair_pos(data, len, i + 2, &hits) == -1) return hits;
        if (scan_pair_pos(data, len, i + 3, &hits) == -1) return hits;
        if (scan_pair_pos(data, len, i + 4, &hits) == -1) return hits;
        if (scan_pair_pos(data, len, i + 5, &hits) == -1) return hits;
        if (scan_pair_pos(data, len, i + 6, &hits) == -1) return hits;
        if (scan_pair_pos(data, len, i + 7, &hits) == -1) return hits;
    }
    for (; i < end; i++) {
        if (scan_pair_pos(data, len, i, &hits) == -1) return hits;
    }
    hits |= g_trigger1_bits[lower1(data[end])];
    return hits;
}

static inline uint32_t trigger_match_pair_full(const unsigned char *data, size_t len) {
    uint32_t hits = g_trigger1_bits[lower1(data[0])];
    if (len == 1) return hits;
    return hits | trigger_match_pair_span(data, len, 0, len - 1);
}

static inline uint32_t trigger_match_pair_windowed(const unsigned char *data, size_t len,
                                                   const DangerPositions *positions) {
    uint32_t hits = 0;
    size_t last_end = 0;
    for (size_t p = 0; p < positions->count; p++) {
        size_t center = positions->offsets[p];
        size_t start = (center > 16) ? center - 16 : 0;
        size_t end = (center + 16 < len) ? center + 16 : len - 1;
        if (start < last_end) start = last_end;
        if (start > end) continue;
        hits |= trigger_match_pair_span(data, len, start, end);
        last_end = end + 1;
    }
    return hits;
}

#define POSITIONS_FULL_SCAN_THRESHOLD 32

uint32_t lumina_trigger_match(const unsigned char *data, size_t len, const DangerPositions *positions) {
    if (!data || len == 0) return 0;

    /* Two-byte dispatch cuts the candidate set before exact SIMD verify. */
    if (positions && positions->count > 0 && positions->count < POSITIONS_FULL_SCAN_THRESHOLD) {
        return trigger_match_pair_windowed(data, len, positions);
    }
    return trigger_match_pair_full(data, len);
}
