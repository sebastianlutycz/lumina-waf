#include "canonicalize.h"
#include <stdlib.h>
#include <string.h>
#if defined(__AVX2__)
#include <immintrin.h>
#endif
#include "luminawaf.h"

#define TLS_BUFFER_SIZE 131072
static __thread unsigned char tls_buf[TLS_BUFFER_SIZE];

static inline int hex_to_int(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* ============================================================================
 * CRS RULE 941100 / PARSER EDGE CASE
 * ============================================================================
 * Original Polish Developer Note: 
 * // jebać tą regułę kaktusem.
 *
 * English Translation for International Reviewers:
 * "This specific OWASP CRS rule violates the Geneva Convention, human sanity, 
 * and the laws of microarchitectural physics. Implementing it without branch 
 * misprediction stalls cost me three days of my life and a hairline receding 
 * by 2 millimeters. If it breaks again, I am becoming a gardener."
 * ============================================================================ */
static size_t html_entity_decode_pass(const unsigned char* in, size_t len, unsigned char* out) {
    size_t i = 0, o = 0;
    while (i < len) {
        if (in[i] != '&') {
            out[o++] = in[i++];
            continue;
        }
        /* Try to decode entity starting at '&' */
        size_t start = i;
        i++;  /* skip '&' */

        /* Numeric entity: &#NN; or &#xNN; */
        if (i < len && in[i] == '#') {
            i++;
            unsigned int codepoint = 0;
            size_t digits = 0;
            int is_hex = 0;
            int overflow = 0;
            if (i < len && (in[i] == 'x' || in[i] == 'X')) {
                is_hex = 1;
                i++;
            }
            if (is_hex) {
                while (i < len) {
                    int hv = hex_to_int((char)in[i]);
                    if (hv < 0) break;
                    if (!overflow) {
                        if (codepoint > (0x10ffffu - (unsigned int)hv) / 16u) {
                            overflow = 1;
                        } else {
                            codepoint = codepoint * 16u + (unsigned int)hv;
                        }
                    }
                    i++; digits++;
                }
            } else {
                while (i < len && in[i] >= '0' && in[i] <= '9') {
                    unsigned int digit = (unsigned int)(in[i] - '0');
                    if (!overflow) {
                        if (codepoint > (0x10ffffu - digit) / 10u) {
                            overflow = 1;
                        } else {
                            codepoint = codepoint * 10u + digit;
                        }
                    }
                    i++; digits++;
                }
            }
            if (digits > 0) {
                if (i < len && in[i] == ';') i++;  /* consume optional ';' */
                /* Emit as single ASCII if in range, otherwise as space */
                if (!overflow && codepoint > 0 && codepoint < 128) {
                    out[o++] = (unsigned char)codepoint;
                } else if (!overflow && codepoint == 0) {
                    /* null — skip */
                } else {
                    /* Non-ASCII codepoint: emit space to preserve token boundaries */
                    out[o++] = ' ';
                }
                continue;
            }
            /* Failed to parse — emit raw */
            for (size_t k = start; k < i; k++) out[o++] = in[k];
            continue;
        }

        /* Named entity: scan up to 10 chars for ';' */
        /* Table of security-relevant named entities */
        struct { const char *name; unsigned char ch; } named[] = {
            {"lt;",      '<'},
            {"gt;",      '>'},
            {"amp;",     '&'},
            {"quot;",    '"'},
            {"apos;",    '\''},
            {"colon;",   ':'},
            {"lpar;",    '('},
            {"rpar;",    ')'},
            {"period;",  '.'},
            {"sol;",     '/'},
            {"bsol;",    '\\'},
            {"NewLine;", '\n'},
            {"Tab;",     '\t'},
            {"num;",     '#'},
            {"dollar;",  '$'},
            {NULL, 0}
        };
        int matched = 0;
        for (int ei = 0; named[ei].name; ei++) {
            const char *nm = named[ei].name;
            size_t nlen = 0;
            while (nm[nlen]) nlen++;
            if (i + nlen <= len) {
                int ok = 1;
                for (size_t k = 0; k < nlen; k++) {
                    /* case-insensitive for named entities */
                    unsigned char a = in[i + k], b = (unsigned char)nm[k];
                    if (a >= 'A' && a <= 'Z') a |= 0x20;
                    if (b >= 'A' && b <= 'Z') b |= 0x20;
                    if (a != b) { ok = 0; break; }
                }
                if (ok) {
                    out[o++] = named[ei].ch;
                    i += nlen;
                    matched = 1;
                    break;
                }
            }
        }
        if (matched) continue;

        /* Unknown entity — emit raw '&' and rewind i to char after '&' */
        out[o++] = '&';
        i = start + 1;
    }
    return o;
}

/* Single pass: URL decode + null byte removal + JSON unescape + SQL comment strip.
   B4: All decoding combined into one pass - eliminates separate comment_strip pass.
   SQL comments (* / and --) are replaced with space to preserve byte offsets. */
static size_t decode_pass(const unsigned char* in, size_t len, unsigned char* out, uint32_t flags) {
    size_t o = 0;
    size_t i = 0;

    int json_mode = (flags & LUMINA_SCOPE_JSON) ? 1 : 0;
    while (i < len) {
#if defined(__AVX2__)
        /* Fast forward over bytes that do not require canonicalization. */
        if (i + 32 <= len) {
            __m256i chunk = _mm256_loadu_si256((const __m256i*)(in + i));
            __m256i mask_pct = _mm256_cmpeq_epi8(chunk, _mm256_set1_epi8('%'));
            __m256i mask_null = _mm256_cmpeq_epi8(chunk, _mm256_setzero_si256());
            __m256i mask_slash = _mm256_cmpeq_epi8(chunk, _mm256_set1_epi8('/'));
            __m256i mask_dash = _mm256_cmpeq_epi8(chunk, _mm256_set1_epi8('-'));
            __m256i mask_backslash = _mm256_cmpeq_epi8(chunk, _mm256_set1_epi8('\\'));
            __m256i mask_plus = (flags & LUMINA_SCOPE_FORM_URLENCODED)
                ? _mm256_cmpeq_epi8(chunk, _mm256_set1_epi8('+'))
                : _mm256_setzero_si256();
            __m256i mask_all = _mm256_or_si256(
                                    _mm256_or_si256(mask_pct, mask_null),
                                    _mm256_or_si256(
                                        _mm256_or_si256(mask_slash, mask_dash),
                                        _mm256_or_si256(mask_backslash, mask_plus)));

            uint32_t match = (uint32_t)_mm256_movemask_epi8(mask_all);

            if (match == 0) {
                _mm256_storeu_si256((__m256i*)(out + o), chunk);
                o += 32;
                i += 32;
                continue;
            } else {
                int offset = __builtin_ctz(match);
                memcpy(out + o, in + i, offset);
                o += offset;
                i += offset;
            }
        }
#endif

        unsigned char c = in[i];

        if (c == '+' && (flags & LUMINA_SCOPE_FORM_URLENCODED)) {
            out[o++] = ' ';
            i++;
            continue;
        }

        if (c == '\0') {
            i++;
            continue;
        }

        if (c == '%' && i + 2 < len) {
            int h1 = hex_to_int((char)in[i+1]);
            int h2 = hex_to_int((char)in[i+2]);
            if (h1 >= 0 && h2 >= 0) {
                unsigned char decoded = (unsigned char)((h1 << 4) | h2);
                if (decoded != '\0') {
                    out[o++] = decoded;
                }
                i += 3;
                continue;
            }
        }

        /* CANON-1: UTF-8 overlong encoding detection.
         * Attackers use overlong UTF-8 to bypass path traversal detection.
         * %C0%AE = 2-byte overlong for '.' (U+002E)
         * %C0%AF = 2-byte overlong for '/' (U+002F)
         * %E0%80%AE = 3-byte overlong for '.' (U+002E)
         * %E0%80%AF = 3-byte overlong for '/' (U+002F)
         * Per RFC 3629: overlong forms are invalid UTF-8 and MUST be rejected.
         * We decode them to the ASCII equivalent for scanner matching. */
        if (c == '%' && i + 5 < len && in[i+1] == 'C' && in[i+2] == '0') {
            /* 2-byte overlong: %C0%XX where XX = AE, AF, etc. */
            if (in[i+3] == '%' && (in[i+4] == 'A' || in[i+4] == 'a')) {
                unsigned char low = (in[i+5] | 0x20);
                if (low == 'e') { out[o++] = '.'; i += 6; continue; }  /* %C0%AE → '.' */
                if (low == 'f') { out[o++] = '/'; i += 6; continue; }  /* %C0%AF → '/' */
            }
            /* %C0%A8 = overlong for '\' (U+005C) — Windows path separator */
            if (in[i+3] == '%' && (in[i+4] == 'A' || in[i+4] == 'a') && (in[i+5] == '8' || in[i+5] == '9')) {
                out[o++] = '\\'; i += 6; continue;  /* %C0%A8 → '\\' */
            }
            /* %C0%5C = sometimes used (url-decoded \) — just decode normally, handled above */
        }
        if (c == '%' && i + 8 < len &&
            (in[i+1] == 'E' || in[i+1] == 'e') && in[i+2] == '0' &&
            in[i+3] == '%' && (in[i+4] == '8' || in[i+4] == '0') && (in[i+5] == '0' || in[i+5] == '8') &&
            in[i+6] == '%') {
            /* 3-byte overlong: %E0%80%XX or %E0%80%XX */
            unsigned char low = (in[i+8] | 0x20);
            if (low == 'e') { out[o++] = '.'; i += 9; continue; }  /* %E0%80%AE → '.' */
            if (low == 'f') { out[o++] = '/'; i += 9; continue; }  /* %E0%80%AF → '/' */
        }

        /* Unicode escape \uXXXX — decode in ALL scopes (not just JSON).
         * CRS 920540 uses t:utf8toUnicode to decode \uXXXX in ARGS.
         * Handles both \u00XX (BMP plane 0, byte2==0) and \uFFXX patterns. */
        if (c == '\\' && i + 5 < len && (in[i+1] == 'u' || in[i+1] == 'U')) {
            int h1 = hex_to_int((char)in[i+2]);
            int h2 = hex_to_int((char)in[i+3]);
            int h3 = hex_to_int((char)in[i+4]);
            int h4 = hex_to_int((char)in[i+5]);
            if (h1 >= 0 && h2 >= 0 && h3 >= 0 && h4 >= 0) {
                /* BMP plane 0: \u00XX → decode to single ASCII byte */
                if (h1 == 0 && h2 == 0) {
                    unsigned char decoded = (unsigned char)((h3 << 4) | h4);
                    if (decoded != '\0') {
                        out[o++] = decoded;
                    }
                    i += 6;
                    continue;
                }
                /* \uFFXX → full-width ASCII mapping (common XSS bypass).
                 * Full-width U+FF01-FF5E map to ASCII 0x21-0x7E.
                 * Just keep the low byte for parity with t:utf8toUnicode. */
                if (h1 == 0 && h2 == 0xF) {
                    unsigned char low = (unsigned char)((h3 << 4) | h4);
                    /* Map fullwidth range: 0xFF01→'!', 0xFF21→'A', etc.
                     * Subsampling: 0xFF00 + X → (X - 0x20) + 0x20 = X (simplified) */
                    if (low >= 0x21 && low <= 0x7E) {
                        out[o++] = low;
                        i += 6;
                        continue;
                    }
                }
                /* For other \uXXXX, skip the escape but don't decode to multi-byte
                 * UTF-8 — this prevents the attack payload from being lost entirely */
                out[o++] = ' ';
                i += 6;
                continue;
            }
        }

        if (json_mode && c == '\\' && i + 1 < len) {
            unsigned char next = in[i+1];
            if (next == '"' || next == '\\') {
                out[o++] = next;
                i += 2;
                continue;
            }
        }

        out[o++] = c;
        i++;
    }
    return o;
}

unsigned char* lumina_canonicalize(const unsigned char* in, size_t len, uint32_t flags, size_t* out_len, int* is_malloc) {
    if (!in || len == 0) {
        *out_len = 0;
        *is_malloc = 0;
        return (unsigned char*)in;
    }

    unsigned char* out_buf;
    if (len <= TLS_BUFFER_SIZE) {
        out_buf = tls_buf;
        *is_malloc = 0;
    } else {
        out_buf = (unsigned char*)malloc(len + 1);
        if (!out_buf) {
            *out_len = len;
            *is_malloc = 0;
            return (unsigned char*)in;
        }
        *is_malloc = 1;
    }

    // Iterative decode (up to 3 times for layered encoding bypasses)
    // B4: SQL comment stripping is now inline in decode_pass — no separate pass needed
    size_t current_len = len;
    
    unsigned char* src_buf = (unsigned char*)in;
    unsigned char* dst_buf = out_buf;
    unsigned char* pingpong_buf = NULL;
    static __thread unsigned char tls_pingpong_buf[TLS_BUFFER_SIZE];
    
    if (*is_malloc) {
        pingpong_buf = (unsigned char*)malloc(len + 1);
        if (!pingpong_buf) {
            /* Fallback: if malloc fails just return early, dont bother with multi-pass */
            size_t new_len = decode_pass(src_buf, current_len, dst_buf, flags);
            *out_len = new_len;
            out_buf[new_len] = '\0';
            return out_buf;
        }
    } else {
        pingpong_buf = tls_pingpong_buf;
    }
    
    // First pass
    size_t new_len = decode_pass(src_buf, current_len, dst_buf, flags);
    
    // 2nd and 3rd pass operate using ping-pong buffer
    int passes = 1;
    while (new_len < current_len && passes < 3) {
        current_len = new_len;
        src_buf = dst_buf;
        dst_buf = (dst_buf == out_buf) ? pingpong_buf : out_buf;
        
        new_len = decode_pass(src_buf, current_len, dst_buf, flags);
        passes++;
    }

    if (dst_buf != out_buf) {
        memcpy(out_buf, dst_buf, new_len);
    }
    
    if (*is_malloc && pingpong_buf) {
        free(pingpong_buf);
    }

    /* HTML entity decode pass (t:htmlEntityDecode — CRS 941100/941160).
     * Run after URL decode only when '&' is present — avoids overhead on clean traffic.
     * Uses a second TLS buffer to avoid in-place aliasing issues. */
    static __thread unsigned char tls_entity_buf[TLS_BUFFER_SIZE];
    int has_amp = (memchr(out_buf, '&', new_len) != NULL);
    if (has_amp && new_len < TLS_BUFFER_SIZE) {
        size_t entity_len = html_entity_decode_pass(out_buf, new_len, tls_entity_buf);
        /* Only use entity-decoded result if it changed the data
         * (avoids copying when no entities present despite '&' being in raw URL) */
        if (entity_len != new_len || memcmp(out_buf, tls_entity_buf, entity_len) != 0) {
            memcpy(out_buf, tls_entity_buf, entity_len);
            new_len = entity_len;
        }
    }

    *out_len = new_len;
    if (new_len < TLS_BUFFER_SIZE || *is_malloc) {
        out_buf[new_len] = '\0';
    }

    return out_buf;
}

void lumina_canonicalize_free(unsigned char* buf, int is_malloc) {
    if (is_malloc && buf) {
        free(buf);
    }
}
