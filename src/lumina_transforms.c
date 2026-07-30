#include "lumina_transforms.h"

#include <string.h>

#if defined(LUMINA_DATAPLANE_DIAGNOSTICS)
#include "luminawaf.h"
#define LUMINA_RECORD_TRANSFORM_STEP(transform, input_len, output_len) \
    luminawaf_dataplane_record_transform_step( \
        (uint32_t)(transform), (input_len), (output_len))
#else
#define LUMINA_RECORD_TRANSFORM_STEP(transform, input_len, output_len) \
    do { \
        (void)(transform); \
        (void)(input_len); \
        (void)(output_len); \
    } while (0)
#endif

#if defined(__AVX2__)
#include <immintrin.h>
#elif defined(__ARM_NEON) && defined(__aarch64__)
#include <arm_neon.h>
#endif

/* ----------------------------------------------------------------------------
 * lowercase — SIMD masked OR (see prior notes). Non-length-changing.
 * --------------------------------------------------------------------------*/
void lumina_transform_lower(uint8_t *buf, size_t len) {
#if defined(__AVX2__)
    const __m256i add  = _mm256_set1_epi8((char)(0x80 - 'A'));
    const __m256i top  = _mm256_set1_epi8((char)0x9A);
    const __m256i bit  = _mm256_set1_epi8(0x20);

    uint8_t *p = buf;
    uint8_t *end = buf + len;
    for (; p + 32 <= end; p += 32) {
        __m256i v = _mm256_loadu_si256((const __m256i *)p);
        __m256i c = _mm256_add_epi8(v, add);
        __m256i m = _mm256_cmpgt_epi8(top, c);
        __m256i lower = _mm256_and_si256(m, bit);
        _mm256_storeu_si256((__m256i *)p, _mm256_or_si256(v, lower));
    }
#elif defined(__ARM_NEON) && defined(__aarch64__)
    const uint8x16_t lower_bound = vdupq_n_u8((uint8_t)'A');
    const uint8x16_t upper_bound = vdupq_n_u8((uint8_t)'Z');
    const uint8x16_t lowercase_bit = vdupq_n_u8(UINT8_C(0x20));

    uint8_t *p = buf;
    uint8_t *end = buf + len;
    for (; p + 16 <= end; p += 16) {
        uint8x16_t value = vld1q_u8(p);
        uint8x16_t is_upper = vandq_u8(vcgeq_u8(value, lower_bound),
                                       vcleq_u8(value, upper_bound));
        vst1q_u8(p, vorrq_u8(value, vandq_u8(is_upper, lowercase_bit)));
    }
#else
    uint8_t *p = buf;
    uint8_t *end = buf + len;
#endif
    for (; p < end; ++p) {
        if (*p >= 'A' && *p <= 'Z') *p |= 0x20;
    }
}

/* ----------------------------------------------------------------------------
 * helpers
 * --------------------------------------------------------------------------*/
static inline int hexval(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* encode a unicode code point as UTF-8 into out[..]; returns bytes written (<=4) */
static inline int utf8_emit(uint8_t *out, unsigned cp) {
    if (cp < 0x80)        { out[0] = (uint8_t)cp;                     return 1; }
    if (cp < 0x800)       { out[0] = 0xC0 | (cp >> 6);
                            out[1] = 0x80 | (cp & 0x3F);              return 2; }
    if (cp < 0x10000)     { out[0] = 0xE0 | (cp >> 12);
                            out[1] = 0x80 | ((cp >> 6) & 0x3F);
                            out[2] = 0x80 | (cp & 0x3F);              return 3; }
    out[0] = 0xF0 | (cp >> 18);
    out[1] = 0x80 | ((cp >> 12) & 0x3F);
    out[2] = 0x80 | ((cp >> 6) & 0x3F);
    out[3] = 0x80 | (cp & 0x3F);
    return 4;
}

static inline unsigned unicode_bestfit_ascii(unsigned cp) {
    /* Unicode full-width ASCII compatibility forms used by CRS evasions. */
    if (cp >= 0xFF01 && cp <= 0xFF5E) return cp - 0xFEE0;
    if (cp == 0x3000) return 0x20;
    return cp;
}

static inline int is_ws(int c) {
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v';
}

/* ----------------------------------------------------------------------------
 * removeNulls — drop NUL bytes (in place compaction).
 * --------------------------------------------------------------------------*/
size_t lumina_transform_remove_nulls(uint8_t *buf, size_t len) {
    uint8_t *first = (uint8_t *)memchr(buf, 0, len);
    if (!first) return len;
    size_t o = (size_t)(first - buf);
    for (size_t i = o + 1; i < len; i++) {
        if (buf[i] != 0) buf[o++] = buf[i];
    }
    return o;
}

/* ----------------------------------------------------------------------------
 * urlDecode — %XX -> byte, optional '+' -> space. Length-reducing.
 * --------------------------------------------------------------------------*/
size_t lumina_transform_url_decode(uint8_t *buf, size_t len, int decode_plus) {
    if (!memchr(buf, '%', len) && (!decode_plus || !memchr(buf, '+', len))) return len;
    size_t o = 0, i = 0;
    while (i < len) {
        uint8_t c = buf[i];
        if (c == '%' && i + 2 < len) {
            int h1 = hexval(buf[i+1]), h2 = hexval(buf[i+2]);
            if (h1 >= 0 && h2 >= 0) { buf[o++] = (uint8_t)((h1 << 4) | h2); i += 3; continue; }
        }
        if (decode_plus && c == '+') { buf[o++] = ' '; i++; continue; }
        buf[o++] = c; i++;
    }
    return o;
}

/* ----------------------------------------------------------------------------
 * urlDecodeUni — like urlDecode + %uXXXX (BMP) -> UTF-8. Length-reducing.
 * --------------------------------------------------------------------------*/
size_t lumina_transform_url_decode_uni(uint8_t *buf, size_t len) {
    if (!memchr(buf, '%', len) && !memchr(buf, '+', len)) return len;
    size_t o = 0, i = 0;
    while (i < len) {
        uint8_t c = buf[i];
        if (c == '%' && i + 2 < len) {
            int h1 = hexval(buf[i+1]), h2 = hexval(buf[i+2]);
            if (h1 >= 0 && h2 >= 0) { buf[o++] = (uint8_t)((h1 << 4) | h2); i += 3; continue; }
            /* %uXXXX unicode escape */
            if ((buf[i+1] == 'u' || buf[i+1] == 'U') && i + 5 < len) {
                int n = 0;
                int ok = 1;
                for (int k = 0; k < 4; k++) {
                    int h = hexval(buf[i+2+k]);
                    if (h < 0) { ok = 0; break; }
                    n = (n << 4) | h;
                }
                if (ok) {
                    o += utf8_emit(buf + o, unicode_bestfit_ascii((unsigned)n));
                    i += 6;
                    continue;
                }
            }
        }
        if (c == '+') { buf[o++] = ' '; i++; continue; }
        buf[o++] = c; i++;
    }
    return o;
}

/* ----------------------------------------------------------------------------
 * htmlEntityDecode — &amp; &lt; &gt; &quot; &apos; &nbsp; and &#NN; &#xHH;
 * --------------------------------------------------------------------------*/
size_t lumina_transform_html_entity_decode(uint8_t *buf, size_t len) {
    if (!memchr(buf, '&', len)) return len;
    static const struct { const char *name; int nlen; uint8_t val; } ents[] = {
        {"amp;",  4, '&'}, {"lt;",  3, '<'}, {"gt;",  3, '>'},
        {"quot;", 5, '"'}, {"apos;", 5, '\''}, {"nbsp;", 5, 0xA0},
    };
    size_t o = 0, i = 0;
    while (i < len) {
        if (buf[i] == '&') {
            int matched = 0;
            for (size_t e = 0; e < sizeof(ents)/sizeof(ents[0]); e++) {
                if (i + 1 + ents[e].nlen <= len &&
                    memcmp(buf + i + 1, ents[e].name, ents[e].nlen) == 0) {
                    buf[o++] = ents[e].val; i += 1 + ents[e].nlen; matched = 1; break;
                }
            }
            if (!matched && i + 1 < len && buf[i+1] == '#') {
                size_t j = i + 2;
                int base = 10;
                if (j < len && (buf[j] == 'x' || buf[j] == 'X')) { base = 16; j++; }
                unsigned num = 0; int dig = 0;
                while (j < len && ((base == 10 && buf[j] >= '0' && buf[j] <= '9') ||
                                   (base == 16 && hexval(buf[j]) >= 0))) {
                    num = (base == 10) ? num * 10 + (unsigned)(buf[j] - '0')
                                       : num * 16 + (unsigned)hexval(buf[j]);
                    j++; dig++;
                }
                if (dig > 0) {
                    if (j < len && buf[j] == ';') j++;   /* optional ';' */
                    o += utf8_emit(buf + o, num);
                    i = j; matched = 1;
                }
            }
            if (!matched) { buf[o++] = '&'; i++; }
            continue;
        }
        buf[o++] = buf[i++];
    }
    return o;
}

/* ----------------------------------------------------------------------------
 * jsDecode — \xHH, \uHHHH, \OOO (octal), and named escapes (\n \t \\ etc.)
 * --------------------------------------------------------------------------*/
size_t lumina_transform_js_decode(uint8_t *buf, size_t len) {
    if (!memchr(buf, '\\', len)) return len;
    static const char map[256] = {
        ['b']='\b',['f']='\f',['n']='\n',['r']='\r',['t']='\t',
        ['v']='\v',['0']='\0',['\'']='\'',['"']='"',['\\']='\\',['/']='/'
    };
    size_t o = 0, i = 0;
    while (i < len) {
        if (buf[i] == '\\' && i + 1 < len) {
            uint8_t n = buf[i+1]; i += 2;
            if (n == 'x' && i + 1 < len) {
                int h1 = hexval(buf[i]), h2 = hexval(buf[i+1]);
                if (h1 >= 0 && h2 >= 0) { buf[o++] = (uint8_t)((h1 << 4) | h2); i += 2; continue; }
            }
            if (n == 'u' && i + 3 < len) {
                int v = 0, ok = 1;
                for (int k = 0; k < 4; k++) { int h = hexval(buf[i+k]); if (h < 0) { ok = 0; break; } v = (v << 4) | h; }
                if (ok) { o += utf8_emit(buf + o, (unsigned)v); i += 4; continue; }
            }
            if (n >= '0' && n <= '7') {
                int v = n - '0'; int c = 1;
                while (c < 3 && i < len && buf[i] >= '0' && buf[i] <= '7') { v = v * 8 + (buf[i] - '0'); i++; c++; }
                buf[o++] = (uint8_t)(v & 0xFF); continue;
            }
            /* named / unknown escape: drop backslash, keep following char */
            buf[o++] = (uint8_t)map[n]; continue;
        }
        buf[o++] = buf[i++];
    }
    return o;
}

/* ----------------------------------------------------------------------------
 * cssDecode — \HHHHHH (1..6 hex), optional trailing space; \X specials.
 * --------------------------------------------------------------------------*/
size_t lumina_transform_css_decode(uint8_t *buf, size_t len) {
    if (!memchr(buf, '\\', len)) return len;
    size_t o = 0, i = 0;
    while (i < len) {
        if (buf[i] == '\\') {
            size_t j = i + 1;
            unsigned v = 0; int cnt = 0;
            while (cnt < 6 && j < len && hexval(buf[j]) >= 0) { v = v * 16 + (unsigned)hexval(buf[j]); j++; cnt++; }
            if (cnt > 0) {
                if (j < len && is_ws(buf[j])) j++;   /* consume one trailing ws */
                o += utf8_emit(buf + o, v);
                i = j; continue;
            }
            /* \ not followed by hex: keep the following char (drop backslash) */
            if (j < len) { buf[o++] = buf[j]; i = j + 1; continue; }
            i++; continue;   /* stray backslash at end: drop */
        }
        buf[o++] = buf[i++];
    }
    return o;
}

/* ----------------------------------------------------------------------------
 * compressWhitespace — runs of whitespace -> single space.
 * --------------------------------------------------------------------------*/
size_t lumina_transform_compress_ws(uint8_t *buf, size_t len) {
    size_t o = 0; int in_ws = 0;
    for (size_t i = 0; i < len; i++) {
        if (is_ws(buf[i])) {
            if (!in_ws) { buf[o++] = ' '; in_ws = 1; }
        } else { buf[o++] = buf[i]; in_ws = 0; }
    }
    return o;
}

/* ----------------------------------------------------------------------------
 * removeWhitespace — delete all whitespace.
 * --------------------------------------------------------------------------*/
size_t lumina_transform_remove_ws(uint8_t *buf, size_t len) {
    size_t o = 0;
    for (size_t i = 0; i < len; i++) {
        const uint8_t byte = buf[i];
        const unsigned control_ws =
            (unsigned)(byte - (uint8_t)'\t') <=
            (unsigned)((uint8_t)'\r' - (uint8_t)'\t');
        const size_t keep = (size_t)!(control_ws | (byte == (uint8_t)' '));
        buf[o] = byte;
        o += keep;
    }
    return o;
}

/* ----------------------------------------------------------------------------
 * normalisePath — win: backslash->slash; then collapse //, remove /./, resolve
 * /seg/../  (keeping leading ../). Operates via a temp copy.
 * --------------------------------------------------------------------------*/
size_t lumina_transform_normalise_path(uint8_t *buf, size_t len, int win) {
    static __thread uint8_t tmp[1 << 18];
    if (len > sizeof(tmp)) return len; /* can't normalise safely -> unchanged */
    size_t n = 0;
    for (size_t i = 0; i < len; i++) {
        uint8_t c = buf[i];
        if (win && c == '\\') c = '/';
        tmp[n++] = c;
    }
    /* 1) collapse duplicate slashes */
    size_t w = 0;
    for (size_t i = 0; i < n; i++) {
        if (tmp[i] == '/' && w > 0 && tmp[w-1] == '/') continue;
        tmp[w++] = tmp[i];
    }
    n = w;
    /* 2) remove /./  and trailing /. */
    w = 0;
    for (size_t i = 0; i < n; i++) {
        if (tmp[i] == '/' && i + 1 < n && tmp[i+1] == '.' &&
            (i + 2 >= n || tmp[i+2] == '/')) {
            if (i + 2 >= n) continue;           /* trailing "/." -> drop '.' */
            tmp[w++] = '/'; i += 2; continue;   /* "/./" -> "/" */
        }
        tmp[w++] = tmp[i];
    }
    n = w;
    /* 3) resolve /seg/../ repeatedly (keep leading ../) */
    int changed = 1;
    while (changed) {
        changed = 0;
        for (size_t i = 0; i + 1 < n; i++) {
            if (tmp[i] != '/') continue;
            size_t s = i + 1;
            if (s >= n) continue;
            size_t segend = s;
            while (segend < n && tmp[segend] != '/') segend++;
            if (segend == s) continue;          /* empty segment (already collapsed) */
            if (segend + 2 < n && tmp[segend] == '/' &&
                tmp[segend+1] == '.' && tmp[segend+2] == '.' &&
                (segend + 3 >= n || tmp[segend+3] == '/')) {
                size_t rem = segend + 3;        /* past the "/" after ".." */
                memmove(tmp + i, tmp + rem, n - rem);
                n -= (rem - i); changed = 1; break;
            }
            if (segend == n && n >= 3 &&
                tmp[n-3] == '/' && tmp[n-2] == '.' && tmp[n-1] == '.') {
                n = i; changed = 1; break;      /* trailing /seg/.. -> drop */
            }
        }
    }
    memcpy(buf, tmp, n);
    return n;
}

/* ----------------------------------------------------------------------------
 * replaceComments — <!-- ... --> -> nothing (single line).
 * --------------------------------------------------------------------------*/
size_t lumina_transform_replace_comments(uint8_t *buf, size_t len) {
    /* Both HTML and C/SQL comment forms are part of CRS semantics. */
    if (!memchr(buf, '<', len) && !memchr(buf, '/', len)) return len;
    size_t o = 0, i = 0;
    while (i < len) {
        /* HTML comment: <!-- ... --> */
        if (buf[i] == '<' && i + 3 < len && buf[i+1] == '!' && buf[i+2] == '-' && buf[i+3] == '-') {
            size_t j = i + 4;
            while (j + 2 < len && !(buf[j] == '-' && buf[j+1] == '-' && buf[j+2] == '>')) j++;
            if (j + 2 < len) { 
                buf[o++] = ' ';
                i = j + 3; 
                continue; 
            }
        }
        /* C/SQL block-comment form. */
        else if (buf[i] == '/' && i + 1 < len && buf[i+1] == '*') {
            size_t j = i + 2;
            while (j + 1 < len && !(buf[j] == '*' && buf[j+1] == '/')) j++;
            if (j + 1 < len) { 
                buf[o++] = ' ';
                i = j + 2; 
                continue; 
            }
        }
        buf[o++] = buf[i++];
    }
    return o;
}

/* ----------------------------------------------------------------------------
 * utf8toUnicode - preserve ASCII and encode multibyte UTF-8 as %uXXXX.
 * --------------------------------------------------------------------------*/
size_t lumina_transform_utf8_to_unicode(uint8_t *buf, size_t len) {
    static __thread uint8_t uni[1 << 18];
    static const char hex[] = "0123456789abcdef";
    int has_multibyte = 0;
    for (size_t q = 0; q < len; q++) {
        if (buf[q] & 0x80) { has_multibyte = 1; break; }
    }
    if (!has_multibyte) return len;
    size_t o = 0, i = 0;
    while (i < len) {
        uint8_t c = buf[i];
        if (c < 0x80) {
            if (o >= sizeof(uni)) return len;
            uni[o++] = c;
            i++;
            continue;
        }
        size_t width = 0;
        unsigned cp = 0;
        if ((c & 0xE0) == 0xC0) { width = 2; cp = c & 0x1F; }
        else if ((c & 0xF0) == 0xE0) { width = 3; cp = c & 0x0F; }
        else if ((c & 0xF8) == 0xF0 && c < 0xF5) { width = 4; cp = c & 0x07; }
        int valid = width != 0 && i + width <= len;
        for (size_t k = 1; valid && k < width; k++) {
            uint8_t tail = buf[i + k];
            if ((tail & 0xC0) != 0x80) valid = 0;
            else cp = (cp << 6) | (tail & 0x3F);
        }
        if (valid) {
            valid = !((width == 2 && cp < 0x80) ||
                      (width == 3 && cp < 0x800) ||
                      (width == 4 && cp < 0x10000) ||
                      (cp >= 0xD800 && cp <= 0xDFFF) || cp > 0x10FFFF);
        }
        if (!valid) {
            if (o >= sizeof(uni)) return len;
            uni[o++] = c;
            i++;
            continue;
        }
        char digits[6];
        size_t ndigits = 0;
        unsigned value = cp;
        do { digits[ndigits++] = hex[value & 0xF]; value >>= 4; } while (value && ndigits < sizeof(digits));
        while (ndigits < 4) digits[ndigits++] = '0';
        if (o + 2 + ndigits > sizeof(uni)) return len;
        uni[o++] = '%';
        uni[o++] = 'u';
        while (ndigits > 0) uni[o++] = (uint8_t)digits[--ndigits];
        i += width;
    }
    memcpy(buf, uni, o);
    return o;
}

/* ----------------------------------------------------------------------------
 * cmdLine - ModSecurity-compatible command-line canonicalization.
 * --------------------------------------------------------------------------*/
size_t lumina_transform_cmdline(uint8_t *buf, size_t len) {
    size_t o = 0;
    for (size_t i = 0; i < len; i++) {
        uint8_t c = buf[i];
        if (c == '\\' || c == '"' || c == '\'' || c == '^') continue;
        bool whitespace = c == ' ' || c == '\t' || c == '\r' || c == '\n' ||
                          c == '\v' || c == '\f' || c == 0xA0 || c == ',' || c == ';';
        if (whitespace) {
            if (o != 0 && buf[o - 1] != ' ') buf[o++] = ' ';
            continue;
        }
        if ((c == '/' || c == '(') && o != 0 && buf[o - 1] == ' ') o--;
        if (c >= 'A' && c <= 'Z') c = (uint8_t)(c | 0x20);
        buf[o++] = c;
    }
    return o;
}

/* ----------------------------------------------------------------------------
 * Apply a rule's ordered transform chain. Returns new length.
 * --------------------------------------------------------------------------*/

#include <stdio.h>

size_t lumina_transform_length(uint8_t *buf, size_t len) {
    char tmp[32];
    int n = snprintf(tmp, sizeof(tmp), "%zu", len);
    if (n > 0 && n < (int)sizeof(tmp)) {
        for (int i = 0; i < n; i++) buf[i] = tmp[i];
        return n;
    }
    return 0;
}

size_t lumina_transform_remove_comments_char(uint8_t *buf, size_t len) {
    size_t i = 0, j = 0;
    while (i < len) {
        if (buf[i] == '/' && i + 1 < len && buf[i + 1] == '*') {
            i += 2;
        } else if (buf[i] == '*' && i + 1 < len && buf[i + 1] == '/') {
            i += 2;
        } else if (buf[i] == '<' && i + 3 < len && buf[i + 1] == '!' && buf[i + 2] == '-' && buf[i + 3] == '-') {
            i += 4;
        } else if (buf[i] == '-' && i + 2 < len && buf[i + 1] == '-' && buf[i + 2] == '>') {
            i += 3;
        } else if (buf[i] == '-' && i + 1 < len && buf[i + 1] == '-') {
            i += 2;
        } else if (buf[i] == '#') {
            i += 1;
        } else {
            buf[j++] = buf[i++];
        }
    }
    return j;
}

static inline void lumina_transform_features_record(
        LuminaTransformFeatures *features, uint8_t byte) {
    if (features)
        features->observed_bytes[byte >> 6] |=
            UINT64_C(1) << (byte & 63);
}

static size_t lumina_transform_base64_decode_impl(
        uint8_t *buf, size_t len, LuminaTransformFeatures *features) {
    static const int8_t b64t[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
    };
    /* Strict ModSecurity validation: if invalid chars present (other than whitespace or '='), abort */
    int valid_chars = 0;
    for (size_t i = 0; i < len; i++) {
        uint8_t c = buf[i];
        if (c == '=') break;
        if (c == '\n' || c == '\r' || c == ' ' || c == '\t') continue;
        if (b64t[c] < 0) return len; /* Abort, return original string */
        valid_chars++;
    }
    if (valid_chars == 0 || valid_chars % 4 == 1) return len;

    if (features) {
        for (size_t word = 0; word < 4; ++word)
            features->observed_bytes[word] = 0;
        features->known = 1;
    }
    size_t out = 0;
    int state = 0;
    uint32_t val = 0;
    for (size_t i = 0; i < len; i++) {
        uint8_t c = buf[i];
        if (c == '=') break;
        int8_t v = b64t[c];
        if (v < 0) continue;
        val = (val << 6) | (uint8_t)v;
        state++;
        if (state == 4) {
            uint8_t byte0 = (uint8_t)((val >> 16) & 0xffu);
            uint8_t byte1 = (uint8_t)((val >> 8) & 0xffu);
            uint8_t byte2 = (uint8_t)(val & 0xffu);
            buf[out++] = byte0;
            buf[out++] = byte1;
            buf[out++] = byte2;
            lumina_transform_features_record(features, byte0);
            lumina_transform_features_record(features, byte1);
            lumina_transform_features_record(features, byte2);
            val = 0;
            state = 0;
        }
    }
    if (state == 3) {
        uint8_t byte0 = (uint8_t)((val >> 10) & 0xffu);
        uint8_t byte1 = (uint8_t)((val >> 2) & 0xffu);
        buf[out++] = byte0;
        buf[out++] = byte1;
        lumina_transform_features_record(features, byte0);
        lumina_transform_features_record(features, byte1);
    } else if (state == 2) {
        uint8_t byte = (uint8_t)((val >> 4) & 0xffu);
        buf[out++] = byte;
        lumina_transform_features_record(features, byte);
    }
    return out;
}

size_t lumina_transform_base64_decode(uint8_t *buf, size_t len) {
    return lumina_transform_base64_decode_impl(buf, len, NULL);
}

static inline int isodigit(int c) { return c >= '0' && c <= '7'; }
static inline int x2c(const uint8_t *what) {
    uint8_t digit;
    digit = (what[0] >= 'A' ? ((what[0] & 0xdf) - 'A')+10 : (what[0] - '0'));
    digit *= 16;
    digit += (what[1] >= 'A' ? ((what[1] & 0xdf) - 'A')+10 : (what[1] - '0'));
    return digit;
}
static inline int ishex(int c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'); }

size_t lumina_transform_escape_seq_decode(uint8_t *buf, size_t len) {
    size_t i = 0, j = 0;
    while (i < len) {
        if (buf[i] == '\\' && i + 1 < len) {
            int c = -1;
            switch (buf[i + 1]) {
                case 'a': c = '\a'; break;
                case 'b': c = '\b'; break;
                case 'f': c = '\f'; break;
                case 'n': c = '\n'; break;
                case 'r': c = '\r'; break;
                case 't': c = '\t'; break;
                case 'v': c = '\v'; break;
                case '\\': c = '\\'; break;
                case '?': c = '?'; break;
                case '\'': c = '\''; break;
                case '"': c = '"'; break;
            }
            if (c != -1) {
                buf[j++] = c;
                i += 2;
                continue;
            }
            if (buf[i + 1] == 'x' || buf[i + 1] == 'X') {
                if (i + 3 < len && ishex(buf[i + 2]) && ishex(buf[i + 3])) {
                    buf[j++] = x2c(&buf[i + 2]);
                    i += 4;
                    continue;
                }
            } else if (isodigit(buf[i + 1])) {
                char obuf[4];
                int k = 0;
                while (i + 1 + k < len && k < 3) {
                    obuf[k] = buf[i + 1 + k];
                    k++;
                    if (!isodigit(buf[i + 1 + k])) break;
                }
                obuf[k] = '\0';
                if (k > 0) {
                    buf[j++] = strtol(obuf, NULL, 8);
                    i += 1 + k;
                    continue;
                }
            }
            buf[j++] = buf[i + 1];
            i += 2;
        } else {
            buf[j++] = buf[i++];
        }
    }
    return j;
}

static int lumina_contains_complete_comment(const uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        if (i + 3 < len && buf[i] == '<' && buf[i + 1] == '!' &&
            buf[i + 2] == '-' && buf[i + 3] == '-') {
            for (size_t j = i + 4; j + 2 < len; ++j)
                if (buf[j] == '-' && buf[j + 1] == '-' &&
                    buf[j + 2] == '>')
                    return 1;
        }
        if (i + 1 < len && buf[i] == '/' && buf[i + 1] == '*') {
            for (size_t j = i + 2; j + 1 < len; ++j)
                if (buf[j] == '*' && buf[j + 1] == '/')
                    return 1;
        }
    }
    return 0;
}

static int lumina_base64_may_decode(const uint8_t *buf, size_t len) {
    size_t valid = 0;
    for (size_t i = 0; i < len; ++i) {
        uint8_t byte = buf[i];
        if (byte == '=') break;
        if (byte == '\n' || byte == '\r' || byte == ' ' || byte == '\t')
            continue;
        if ((byte >= 'A' && byte <= 'Z') ||
            (byte >= 'a' && byte <= 'z') ||
            (byte >= '0' && byte <= '9') || byte == '+' || byte == '/') {
            ++valid;
            continue;
        }
        return 0;
    }
    return valid != 0 && (valid & 3u) != 1u;
}

int lumina_transform_step_may_change(
        LuminaTransformId transform, const uint8_t *buf, size_t len) {
    if (!buf) return 0;
    switch (transform) {
    case LUMINA_T_LOWERCASE:
        for (size_t i = 0; i < len; ++i)
            if (buf[i] >= 'A' && buf[i] <= 'Z') return 1;
        return 0;
    case LUMINA_T_URL_DECODE:
    case LUMINA_T_URL_DECODE_UNI:
        for (size_t i = 0; i < len; ++i) {
            if (buf[i] == '+') return 1;
            if (buf[i] != '%' || i + 2 >= len) continue;
            if (hexval(buf[i + 1]) >= 0 && hexval(buf[i + 2]) >= 0)
                return 1;
            if (transform == LUMINA_T_URL_DECODE_UNI &&
                i + 5 < len && (buf[i + 1] == 'u' || buf[i + 1] == 'U') &&
                hexval(buf[i + 2]) >= 0 && hexval(buf[i + 3]) >= 0 &&
                hexval(buf[i + 4]) >= 0 && hexval(buf[i + 5]) >= 0)
                return 1;
        }
        return 0;
    case LUMINA_T_HTML_ENTITY_DECODE:
        return memchr(buf, '&', len) != NULL;
    case LUMINA_T_REMOVE_NULLS:
        return memchr(buf, 0, len) != NULL;
    case LUMINA_T_JS_DECODE:
    case LUMINA_T_CSS_DECODE:
    case LUMINA_T_ESCAPE_SEQ_DECODE:
        return memchr(buf, '\\', len) != NULL;
    case LUMINA_T_COMPRESS_WS:
    case LUMINA_T_REMOVE_WS:
        for (size_t i = 0; i < len; ++i)
            if (buf[i] == ' ' || buf[i] == '\t' || buf[i] == '\r' ||
                buf[i] == '\n' || buf[i] == '\f' || buf[i] == '\v')
                return 1;
        return 0;
    case LUMINA_T_NORMALIZE_PATH:
        return memchr(buf, '/', len) != NULL || memchr(buf, '.', len) != NULL;
    case LUMINA_T_NORMALIZE_PATH_WIN:
        return memchr(buf, '/', len) != NULL || memchr(buf, '.', len) != NULL ||
               memchr(buf, '\\', len) != NULL;
    case LUMINA_T_REPLACE_COMMENTS:
        return lumina_contains_complete_comment(buf, len);
    case LUMINA_T_UTF8_TO_UNICODE:
        for (size_t i = 0; i < len; ++i)
            if (buf[i] & 0x80u) return 1;
        return 0;
    case LUMINA_T_CMDLINE:
        for (size_t i = 0; i < len; ++i) {
            uint8_t byte = buf[i];
            if ((byte >= 'A' && byte <= 'Z') ||
                byte == '\\' || byte == '"' || byte == '\'' || byte == '^' ||
                byte == ' ' || byte == '\t' || byte == '\r' || byte == '\n' ||
                byte == '\v' || byte == '\f' || byte == ',' || byte == ';' ||
                byte == '/' || byte == '(' || byte == ')' || byte == 0xa0)
                return 1;
        }
        return 0;
    case LUMINA_T_BASE64_DECODE:
        return lumina_base64_may_decode(buf, len);
    case LUMINA_T_LENGTH:
        return 1;
    case LUMINA_T_REMOVE_COMMENTS_CHAR:
        for (size_t i = 0; i < len; ++i) {
            if (buf[i] == '#') return 1;
            if (i + 1 < len &&
                ((buf[i] == '/' && buf[i + 1] == '*') ||
                 (buf[i] == '*' && buf[i + 1] == '/') ||
                 (buf[i] == '-' && buf[i + 1] == '-')))
                return 1;
            if (i + 3 < len && buf[i] == '<' && buf[i + 1] == '!' &&
                buf[i + 2] == '-' && buf[i + 3] == '-')
                return 1;
        }
        return 0;
    default:
        return 0;
    }
}

size_t lumina_apply_transform_step(
        LuminaTransformId transform, uint8_t *buf, size_t len) {
#if defined(LUMINA_DATAPLANE_DIAGNOSTICS)
    size_t output_len = len;
    switch (transform) {
    case LUMINA_T_LOWERCASE:
        lumina_transform_lower(buf, len);
        break;
    case LUMINA_T_REMOVE_NULLS:
        output_len = lumina_transform_remove_nulls(buf, len);
        break;
    case LUMINA_T_URL_DECODE:
        output_len = lumina_transform_url_decode(buf, len, 1);
        break;
    case LUMINA_T_URL_DECODE_UNI:
        output_len = lumina_transform_url_decode_uni(buf, len);
        break;
    case LUMINA_T_HTML_ENTITY_DECODE:
        output_len = lumina_transform_html_entity_decode(buf, len);
        break;
    case LUMINA_T_JS_DECODE:
        output_len = lumina_transform_js_decode(buf, len);
        break;
    case LUMINA_T_CSS_DECODE:
        output_len = lumina_transform_css_decode(buf, len);
        break;
    case LUMINA_T_COMPRESS_WS:
        output_len = lumina_transform_compress_ws(buf, len);
        break;
    case LUMINA_T_REMOVE_WS:
        output_len = lumina_transform_remove_ws(buf, len);
        break;
    case LUMINA_T_NORMALIZE_PATH:
        output_len = lumina_transform_normalise_path(buf, len, 0);
        break;
    case LUMINA_T_NORMALIZE_PATH_WIN:
        output_len = lumina_transform_normalise_path(buf, len, 1);
        break;
    case LUMINA_T_REPLACE_COMMENTS:
        output_len = lumina_transform_replace_comments(buf, len);
        break;
    case LUMINA_T_UTF8_TO_UNICODE:
        output_len = lumina_transform_utf8_to_unicode(buf, len);
        break;
    case LUMINA_T_CMDLINE:
        output_len = lumina_transform_cmdline(buf, len);
        break;
    case LUMINA_T_ESCAPE_SEQ_DECODE:
        output_len = lumina_transform_escape_seq_decode(buf, len);
        break;
    case LUMINA_T_BASE64_DECODE:
        output_len = lumina_transform_base64_decode(buf, len);
        break;
    case LUMINA_T_LENGTH:
        output_len = lumina_transform_length(buf, len);
        break;
    case LUMINA_T_REMOVE_COMMENTS_CHAR:
        output_len = lumina_transform_remove_comments_char(buf, len);
        break;
    default:
        break;
    }
    LUMINA_RECORD_TRANSFORM_STEP(transform, len, output_len);
    return output_len;
#else
    switch (transform) {
    case LUMINA_T_LOWERCASE:          lumina_transform_lower(buf, len); return len;
    case LUMINA_T_REMOVE_NULLS:       return lumina_transform_remove_nulls(buf, len);
    case LUMINA_T_URL_DECODE:         return lumina_transform_url_decode(buf, len, 1);
    case LUMINA_T_URL_DECODE_UNI:     return lumina_transform_url_decode_uni(buf, len);
    case LUMINA_T_HTML_ENTITY_DECODE: return lumina_transform_html_entity_decode(buf, len);
    case LUMINA_T_JS_DECODE:          return lumina_transform_js_decode(buf, len);
    case LUMINA_T_CSS_DECODE:         return lumina_transform_css_decode(buf, len);
    case LUMINA_T_COMPRESS_WS:        return lumina_transform_compress_ws(buf, len);
    case LUMINA_T_REMOVE_WS:          return lumina_transform_remove_ws(buf, len);
    case LUMINA_T_NORMALIZE_PATH:     return lumina_transform_normalise_path(buf, len, 0);
    case LUMINA_T_NORMALIZE_PATH_WIN: return lumina_transform_normalise_path(buf, len, 1);
    case LUMINA_T_REPLACE_COMMENTS:   return lumina_transform_replace_comments(buf, len);
    case LUMINA_T_UTF8_TO_UNICODE:    return lumina_transform_utf8_to_unicode(buf, len);
    case LUMINA_T_CMDLINE:            return lumina_transform_cmdline(buf, len);
    case LUMINA_T_ESCAPE_SEQ_DECODE:  return lumina_transform_escape_seq_decode(buf, len);
    case LUMINA_T_BASE64_DECODE:      return lumina_transform_base64_decode(buf, len);
    case LUMINA_T_LENGTH:             return lumina_transform_length(buf, len);
    case LUMINA_T_REMOVE_COMMENTS_CHAR:
        return lumina_transform_remove_comments_char(buf, len);
    default:
        return len;
    }
#endif
}

void lumina_transform_features_init(
        LuminaTransformFeatures *features,
        const uint64_t observed_bytes[4]) {
    if (!features || !observed_bytes) return;
    for (size_t word = 0; word < 4; ++word)
        features->observed_bytes[word] = observed_bytes[word];
    features->known = 1;
}

static inline int lumina_transform_feature_has_byte(
        const LuminaTransformFeatures *features, unsigned byte) {
    return (features->observed_bytes[byte >> 6] >> (byte & 63)) & 1u;
}

int lumina_transform_features_may_change(
        const LuminaTransformFeatures *features,
        LuminaTransformId transform) {
    if (!features || !features->known)
        return transform != LUMINA_T_NONE;
    const uint64_t *bytes = features->observed_bytes;
    const uint64_t uppercase = UINT64_C(0x0000000007fffffe);
    const uint64_t whitespace = UINT64_C(0x0000000100003e00);
    switch (transform) {
    case LUMINA_T_NONE:
        return 0;
    case LUMINA_T_LOWERCASE:
        return (bytes[1] & uppercase) != 0;
    case LUMINA_T_URL_DECODE:
    case LUMINA_T_URL_DECODE_UNI:
        return lumina_transform_feature_has_byte(features, '%') ||
               lumina_transform_feature_has_byte(features, '+');
    case LUMINA_T_HTML_ENTITY_DECODE:
        return lumina_transform_feature_has_byte(features, '&');
    case LUMINA_T_REMOVE_NULLS:
        return (bytes[0] & UINT64_C(1)) != 0;
    case LUMINA_T_JS_DECODE:
    case LUMINA_T_CSS_DECODE:
    case LUMINA_T_ESCAPE_SEQ_DECODE:
        return lumina_transform_feature_has_byte(features, '\\');
    case LUMINA_T_COMPRESS_WS:
    case LUMINA_T_REMOVE_WS:
        return (bytes[0] & whitespace) != 0;
    case LUMINA_T_NORMALIZE_PATH:
        return lumina_transform_feature_has_byte(features, '/') ||
               lumina_transform_feature_has_byte(features, '.');
    case LUMINA_T_NORMALIZE_PATH_WIN:
        return lumina_transform_feature_has_byte(features, '/') ||
               lumina_transform_feature_has_byte(features, '.') ||
               lumina_transform_feature_has_byte(features, '\\');
    case LUMINA_T_REPLACE_COMMENTS:
        return lumina_transform_feature_has_byte(features, '<') ||
               lumina_transform_feature_has_byte(features, '/');
    case LUMINA_T_UTF8_TO_UNICODE:
        return (bytes[2] | bytes[3]) != 0;
    case LUMINA_T_CMDLINE:
        return (bytes[1] & uppercase) != 0 ||
               lumina_transform_feature_has_byte(features, '\\') ||
               lumina_transform_feature_has_byte(features, '"') ||
               lumina_transform_feature_has_byte(features, '\'') ||
               lumina_transform_feature_has_byte(features, '^') ||
               lumina_transform_feature_has_byte(features, ' ') ||
               lumina_transform_feature_has_byte(features, '\t') ||
               lumina_transform_feature_has_byte(features, '\r') ||
               lumina_transform_feature_has_byte(features, '\n') ||
               lumina_transform_feature_has_byte(features, '\v') ||
               lumina_transform_feature_has_byte(features, '\f') ||
               lumina_transform_feature_has_byte(features, ',') ||
               lumina_transform_feature_has_byte(features, ';') ||
               lumina_transform_feature_has_byte(features, '/') ||
               lumina_transform_feature_has_byte(features, '(') ||
               lumina_transform_feature_has_byte(features, ')') ||
               lumina_transform_feature_has_byte(features, 0xa0u);
    case LUMINA_T_REMOVE_COMMENTS_CHAR:
        return lumina_transform_feature_has_byte(features, '/') ||
               lumina_transform_feature_has_byte(features, '*') ||
               lumina_transform_feature_has_byte(features, '<') ||
               lumina_transform_feature_has_byte(features, '-') ||
               lumina_transform_feature_has_byte(features, '#');
    case LUMINA_T_BASE64_DECODE:
    case LUMINA_T_LENGTH:
        return 1;
    default:
        return 1;
    }
}

static void lumina_transform_features_after_simple(
        LuminaTransformFeatures *features,
        LuminaTransformId transform) {
    const uint64_t uppercase = UINT64_C(0x0000000007fffffe);
    const uint64_t whitespace = UINT64_C(0x0000000100003e00);
    switch (transform) {
    case LUMINA_T_LOWERCASE: {
        uint64_t present = features->observed_bytes[1] & uppercase;
        features->observed_bytes[1] &= ~uppercase;
        features->observed_bytes[1] |= present << 32;
        return;
    }
    case LUMINA_T_REMOVE_NULLS:
        features->observed_bytes[0] &= ~UINT64_C(1);
        return;
    case LUMINA_T_REMOVE_WS:
        features->observed_bytes[0] &= ~whitespace;
        return;
    case LUMINA_T_COMPRESS_WS:
        features->observed_bytes[0] &= ~whitespace;
        features->observed_bytes[0] |= UINT64_C(1) << 32;
        return;
    case LUMINA_T_LENGTH:
        for (size_t word = 0; word < 4; ++word)
            features->observed_bytes[word] = 0;
        features->observed_bytes[0] = UINT64_C(0x03ff) << '0';
        return;
    default:
        return;
    }
}

size_t lumina_apply_transform_step_features(
        LuminaTransformId transform, uint8_t *buf, size_t len,
        LuminaTransformFeatures *features) {
    if (transform == LUMINA_T_BASE64_DECODE) {
#if defined(LUMINA_DATAPLANE_DIAGNOSTICS)
        size_t output_len =
            lumina_transform_base64_decode_impl(buf, len, features);
        LUMINA_RECORD_TRANSFORM_STEP(transform, len, output_len);
        return output_len;
#else
        return lumina_transform_base64_decode_impl(buf, len, features);
#endif
    }

    size_t out = lumina_apply_transform_step(transform, buf, len);
    if (!features) return out;
    switch (transform) {
    case LUMINA_T_LOWERCASE:
    case LUMINA_T_REMOVE_NULLS:
    case LUMINA_T_REMOVE_WS:
    case LUMINA_T_COMPRESS_WS:
    case LUMINA_T_LENGTH:
        lumina_transform_features_after_simple(features, transform);
        break;
    default:
        /* Unknown is a sound upper bound: subsequent feasibility checks
         * execute instead of risking a false-negative transform skip. */
        features->known = 0;
        break;
    }
    return out;
}

size_t lumina_apply_transforms(const LuminaTransformId *seq, uint8_t *buf, size_t len) {
    size_t out = len;
    for (int k = 0; seq[k] != LUMINA_T_NONE; k++)
        out = lumina_apply_transform_step(seq[k], buf, out);
    return out;
}

/* Per-thread scratch arenas for transform copies — zero hot-path allocation. */
#define LUMINA_XFORM_SCRATCH_CAP (1u << 18)
#define LUMINA_XFORM_SCRATCH_SLOTS 8u
static __thread uint8_t
    g_xform_scratch[LUMINA_XFORM_SCRATCH_SLOTS][LUMINA_XFORM_SCRATCH_CAP];

uint8_t *lumina_xform_scratch(void) { return g_xform_scratch[0]; }
uint8_t *lumina_xform_scratch_slot(size_t slot) {
    return g_xform_scratch[slot & (LUMINA_XFORM_SCRATCH_SLOTS - 1u)];
}
size_t   lumina_xform_scratch_cap(void) { return LUMINA_XFORM_SCRATCH_CAP; }

#ifdef LUMINA_TRANSFORMS_SELFTEST
#include <stdio.h>
int main(void) {
    int all = 1;
    /* lowercase */
    { const char *in = "Az_@[]\\]^09{}~ReQuEsT_URI/ADMIN";
      char buf[64]; memcpy(buf, in, strlen(in)+1);
      lumina_transform_lower((uint8_t*)buf, strlen(in));
      const char *exp = "az_@[]\\]^09{}~request_uri/admin";
      int okk = (strcmp(buf, exp)==0); all &= okk;
      printf("lowercase: %s\n", okk?"PASS":"FAIL"); }
    { static const uint8_t input[] = {'A', 'Z', '@', '['};
      static const uint8_t expected[] = {'a', 'z', '@', '['};
      uint8_t buf[64]; int okk = 1;
      for (size_t i = 0; i < sizeof(buf); i++) buf[i] = input[i & 3];
      lumina_transform_lower(buf, sizeof(buf));
      for (size_t i = 0; i < sizeof(buf); i++) okk &= buf[i] == expected[i & 3];
      all &= okk;
      printf("lowercase SIMD boundaries: %s\n", okk?"PASS":"FAIL"); }
    /* urlDecode */
    { char buf[] = "a%20b+c%2F"; size_t n = lumina_transform_url_decode((uint8_t*)buf, strlen(buf), 1);
      buf[n]=0; int okk = (strcmp(buf,"a b c/")==0); all &= okk;
      printf("urlDecode: %s (%s)\n", okk?"PASS":"FAIL", buf); }
    /* urlDecodeUni %uXXXX */
    { char buf[] = "%u0041%u00e9"; size_t n = lumina_transform_url_decode_uni((uint8_t*)buf, strlen(buf));
      buf[n]=0; int okk = (n==3 && buf[0]=='A' && (unsigned char)buf[1]==0xC3 && (unsigned char)buf[2]==0xA9);
      all &= okk; printf("urlDecodeUni: %s (n=%zu)\n", okk?"PASS":"FAIL", n); }
    { char buf[] = "%uff1cscript%uff1e%u3000";
      size_t n = lumina_transform_url_decode_uni((uint8_t*)buf, strlen(buf));
      buf[n]=0; int okk = (strcmp(buf,"<script> ")==0); all &= okk;
      printf("urlDecodeUni best-fit: %s (%s)\n", okk?"PASS":"FAIL", buf); }
    /* removeNulls */
    { char buf[] = "a\0b\0c"; size_t n = lumina_transform_remove_nulls((uint8_t*)buf, 5);
      int okk = (n==3 && buf[0]=='a'&&buf[1]=='b'&&buf[2]=='c'); all &= okk;
      printf("removeNulls: %s\n", okk?"PASS":"FAIL"); }
    /* htmlEntityDecode */
    { char buf[] = "&lt;a&amp;b&gt;"; size_t n = lumina_transform_html_entity_decode((uint8_t*)buf, strlen(buf));
      buf[n]=0; int okk = (strcmp(buf,"<a&b>")==0); all &= okk;
      printf("htmlEntityDecode: %s (%s)\n", okk?"PASS":"FAIL", buf); }
    /* jsDecode */
    { char buf[] = "a\\x41\\n\\t"; size_t n = lumina_transform_js_decode((uint8_t*)buf, strlen(buf));
      buf[n]=0; int okk = (n==4 && buf[0]=='a'&&buf[1]=='A'&&buf[2]=='\n'&&buf[3]=='\t'); all &= okk;
      printf("jsDecode: %s (n=%zu)\n", okk?"PASS":"FAIL", n); }
    /* cssDecode */
    { char buf[] = "a\\41 b"; size_t n = lumina_transform_css_decode((uint8_t*)buf, strlen(buf));
      buf[n]=0; int okk = (n==3 && buf[0]=='a'&&buf[1]=='A'&&buf[2]=='b'); all &= okk;
      printf("cssDecode: %s (n=%zu)\n", okk?"PASS":"FAIL", n); }
    /* compressWhitespace */
    { char buf[] = "a  \t\n b"; size_t n = lumina_transform_compress_ws((uint8_t*)buf, strlen(buf));
      buf[n]=0; int okk = (strcmp(buf,"a b")==0); all &= okk;
      printf("compressWS: %s (%s)\n", okk?"PASS":"FAIL", buf); }
    /* removeWhitespace */
    { char buf[] = "a b\tc"; size_t n = lumina_transform_remove_ws((uint8_t*)buf, strlen(buf));
      buf[n]=0; int okk = (strcmp(buf,"abc")==0); all &= okk;
      printf("removeWS: %s (%s)\n", okk?"PASS":"FAIL", buf); }
    /* normalisePath */
    { char buf[] = "/a//b/./c/../d"; size_t n = lumina_transform_normalise_path((uint8_t*)buf, strlen(buf), 0);
      buf[n]=0; int okk = (strcmp(buf,"/a/b/d")==0); all &= okk;
      printf("normalisePath: %s (%s)\n", okk?"PASS":"FAIL", buf); }
    /* cmdLine */
    { char buf[] = "FOR  /F %V IN (SET),; DO C^M\\\"D";
      size_t n = lumina_transform_cmdline((uint8_t*)buf, strlen(buf));
      buf[n]=0; int okk = (strcmp(buf,"for/f %v in(set) do cmd")==0); all &= okk;
      printf("cmdLine: %s (%s)\n", okk?"PASS":"FAIL", buf); }
    /* utf8toUnicode */
    { char buf[] = "LIKE NULL"; size_t n = lumina_transform_utf8_to_unicode((uint8_t*)buf, strlen(buf));
      buf[n]=0; int okk = (strcmp(buf,"LIKE NULL")==0); all &= okk;
      printf("utf8toUnicode ASCII: %s (%s)\n", okk?"PASS":"FAIL", buf); }
    { char buf[32] = "\xEF\xBC\x9C"; size_t n = lumina_transform_utf8_to_unicode((uint8_t*)buf, 3);
      buf[n]=0; int okk = (strcmp(buf,"%uff1c")==0); all &= okk;
      printf("utf8toUnicode multibyte: %s (%s)\n", okk?"PASS":"FAIL", buf); }
    printf("OVERALL: %s\n", all?"PASS":"FAIL");
    return all ? 0 : 1;
}
#endif
