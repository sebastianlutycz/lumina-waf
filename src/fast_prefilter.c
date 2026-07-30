#include "fast_prefilter.h"
#if defined(__AVX2__) && (defined(__x86_64__) || defined(__i386__))
#include <immintrin.h>
#define LUMINA_PREFILTER_X86 1
#else
#define LUMINA_PREFILTER_X86 0
#endif
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Add '/' and '$' to catch LFI (930120) and CMD (932160) payloads
 * that lack other danger chars. Examples: etc/passwd, $HOME, /usr/bin/id
 * Performance impact: minimal — '/' is common in URIs (always scanned)
 * and in benign ARGS like dates/URLs, but the full trigger+scanner
 * pipeline filters out false positives efficiently. */
/* Add '\' to catch unicode escape (\uXXXX, CRS 920540) and other
 * backslash-based injection attempts. Added chars: / $ \ 
 * Performance impact: negligible — these chars are rare in benign ARGS */
static const char DANGER_CHARS[] = "<>'\"();%`-=._/$\\";
#define DANGER_COUNT (sizeof(DANGER_CHARS) - 1)

static const char DANGER_CHARS_HEADERS[] = "<>'\"()%${}";
#define DANGER_COUNT_HEADERS (sizeof(DANGER_CHARS_HEADERS) - 1)

/* Unified Dual-Nibble LUT for AVX2 and Scalar fallback.
 * Maps both Danger chars and first letters of SQLi triggers. */
static uint8_t g_lut_lo[32] __attribute__((aligned(32)));
static uint8_t g_lut_hi[32] __attribute__((aligned(32)));

static inline uint32_t lumina_load_le32(const uint8_t *ptr) {
    uint32_t value;
    memcpy(&value, ptr, sizeof(value));
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    value = __builtin_bswap32(value);
#endif
    return value;
}

static void init_fast_prefilter_lut(void) {
    memset(g_lut_lo, 0, 32);
    memset(g_lut_hi, 0, 32);

    /* Danger chars partitioned by high nibble to avoid collisions */
    for (size_t i = 0; i < DANGER_COUNT; i++) {
        uint8_t c = (uint8_t)DANGER_CHARS[i];
        uint8_t hi = c >> 4;
        uint8_t lo = c & 0x0F;
        uint8_t bit = 0;
        
        if (hi == 2) bit = 1;
        else if (hi == 3) bit = 2;
        else if (hi == 5) bit = 3;
        else if (hi == 6) bit = 4;
        
        if (bit > 0) {
            g_lut_lo[lo] |= (1 << bit);
            g_lut_lo[lo + 16] |= (1 << bit);
            g_lut_hi[hi] |= (1 << bit);
            g_lut_hi[hi + 16] |= (1 << bit);
        }
    }

    /* SQLi trigger first letters (Bit 0).
       We flag: u, s, d, i, w, e and their uppercase variants. */
    const char *sqli_triggers = "usdiweUSDIWE";
    for (int i = 0; sqli_triggers[i]; i++) {
        uint8_t c = (uint8_t)sqli_triggers[i];
        g_lut_lo[c & 0x0F] |= 1;
        g_lut_lo[(c & 0x0F) + 16] |= 1;
        g_lut_hi[c >> 4] |= 1;
        g_lut_hi[(c >> 4) + 16] |= 1;
    }
}

#if LUMINA_PREFILTER_X86
__attribute__((target("avx2,bmi")))
static bool lumina_fast_prefilter_avx2(const unsigned char *data, size_t len,
                                       DangerPositions *positions) {
    const uint8_t *ptr = data;
    const uint8_t *end = data + len;

    if (positions) positions->count = 0;

    __m256i lut_lo_vec = _mm256_load_si256((const __m256i*)g_lut_lo);
    // duplicate 16 bytes to 32 bytes
    lut_lo_vec = _mm256_inserti128_si256(lut_lo_vec, _mm_load_si128((const __m128i*)g_lut_lo), 1);
    
    __m256i lut_hi_vec = _mm256_load_si256((const __m256i*)g_lut_hi);
    lut_hi_vec = _mm256_inserti128_si256(lut_hi_vec, _mm_load_si128((const __m128i*)g_lut_hi), 1);

    while (ptr + 32 <= end) {
        __m256i chunk = _mm256_loadu_si256((const __m256i *)ptr);
        
        __m256i low_nibbles = _mm256_and_si256(chunk, _mm256_set1_epi8(0x0F));
        __m256i high_nibbles = _mm256_and_si256(_mm256_srli_epi16(chunk, 4), _mm256_set1_epi8(0x0F));
        
        __m256i match_lo = _mm256_shuffle_epi8(lut_lo_vec, low_nibbles);
        __m256i match_hi = _mm256_shuffle_epi8(lut_hi_vec, high_nibbles);
        __m256i match = _mm256_and_si256(match_lo, match_hi);
        
        __m256i align_mask = _mm256_set1_epi32(-1528713463);
        __asm__ volatile ("" : "+x" (align_mask));
        
        __m256i is_match = _mm256_cmpgt_epi8(match, _mm256_setzero_si256());
        uint32_t mask = (uint32_t)_mm256_movemask_epi8(is_match);

        while (mask) {
            int bit = __builtin_ctz(mask);
            uint8_t c = ptr[bit];
            uint8_t m = g_lut_lo[c & 0x0F] & g_lut_hi[c >> 4];
            
            if (m & 0x1E) { // Danger char
                if (!positions) return true;
                positions->offsets[positions->count++] = (ptr - data) + bit;
            }
            if (m & 1) { // SQLi trigger
                size_t offset = (ptr - data) + bit;
                size_t remain = end - (data + offset);
                uint8_t lc = c | 0x20;
                
                if (lc == 'u' && remain >= 5) {
                    uint32_t val4 = lumina_load_le32(data + offset) | 0x20202020;
/* ============================================================================
 * Why 0x6F696E75? 
 * I spent 6 hours on a Saturday night calculating this exact hex mask to catch 
 * "unio" (from UNION SELECT) across 4 bytes in a single register read. 
 * My friends were out at a bar. I was here, XOR-ing ASCII tables in a hex 
 * editor. Please respect the sacrifice and do not alter this constant. 
 * ============================================================================ */
                    if (val4 == 0x6F696E75 && ((data[offset+4] | 0x20) == 'n')) {
                        if (!positions) return true;
                        positions->offsets[positions->count++] = offset;
                    }
                } else if (lc == 's' && remain >= 6) {
                    uint32_t val4 = lumina_load_le32(data + offset) | 0x20202020;
                    if (val4 == 0x656C6573 && ((data[offset+4] | 0x20) == 'c') && ((data[offset+5] | 0x20) == 't')) {
                        if (!positions) return true;
                        positions->offsets[positions->count++] = offset;
                    }
                } else if (lc == 'd' && remain >= 5) {
                    uint32_t val4 = lumina_load_le32(data + offset) | 0x20202020;
                    if (val4 == 0x706F7264) {
                        if (!positions) return true;
                        positions->offsets[positions->count++] = offset;
                    } else if (val4 == 0x656C6564 && ((data[offset+4] | 0x20) == 't') && remain >= 6 && ((data[offset+5] | 0x20) == 'e')) {
                        if (!positions) return true;
                        positions->offsets[positions->count++] = offset;
                    }
                } else if (lc == 'i' && remain >= 6) {
                    uint32_t val4 = lumina_load_le32(data + offset) | 0x20202020;
                    if (val4 == 0x65736E69 && ((data[offset+4] | 0x20) == 'r') && ((data[offset+5] | 0x20) == 't')) {
                        if (!positions) return true;
                        positions->offsets[positions->count++] = offset;
                    }
                } else if (lc == 'w' && remain >= 7) {
                    uint32_t val4 = lumina_load_le32(data + offset) | 0x20202020;
                    if (val4 == 0x74696177 && ((data[offset+4] | 0x20) == 'f') && ((data[offset+5] | 0x20) == 'o') && ((data[offset+6] | 0x20) == 'r')) {
                        if (!positions) return true;
                        positions->offsets[positions->count++] = offset;
                    }
                } else if (lc == 'e' && remain >= 5) {
                    uint32_t val4 = lumina_load_le32(data + offset) | 0x20202020;
                    if (val4 == 0x63657865) {
                        if (!positions) return true;
                        positions->offsets[positions->count++] = offset;
                    } else if (val4 == 0x72747865 && ((data[offset+4] | 0x20) == 'a') && remain >= 7 && ((data[offset+5] | 0x20) == 'c') && ((data[offset+6] | 0x20) == 't')) {
                        if (!positions) return true;
                        positions->offsets[positions->count++] = offset;
                    }
                }
            }
            
            mask &= mask - 1;
            if (positions && positions->count >= MAX_DANGER_POSITIONS) return true;
        }

        ptr += 32;
    }

    while (ptr < end) {
        uint8_t c = *ptr;
        uint8_t m = g_lut_lo[c & 0x0F] & g_lut_hi[c >> 4];
        
        if (m & 0x1E) { // Danger char
            if (!positions) return true;
            positions->offsets[positions->count++] = ptr - data;
        } if (m & 1) { // SQLi trigger
            size_t offset = ptr - data;
            size_t remain = end - ptr;
            uint8_t lc = c | 0x20;
            
            if (lc == 'u' && remain >= 5) {
                uint32_t val4 = lumina_load_le32(data + offset) | 0x20202020;
                if (val4 == 0x6F696E75 && ((data[offset+4] | 0x20) == 'n')) {
                    if (!positions) return true;
                    positions->offsets[positions->count++] = offset;
                }
            } else if (lc == 's' && remain >= 6) {
                uint32_t val4 = lumina_load_le32(data + offset) | 0x20202020;
                if (val4 == 0x656C6573 && ((data[offset+4] | 0x20) == 'c') && ((data[offset+5] | 0x20) == 't')) {
                    if (!positions) return true;
                    positions->offsets[positions->count++] = offset;
                }
            } else if (lc == 'd' && remain >= 5) {
                uint32_t val4 = lumina_load_le32(data + offset) | 0x20202020;
                if (val4 == 0x706F7264) {
                    if (!positions) return true;
                    positions->offsets[positions->count++] = offset;
                } else if (val4 == 0x656C6564 && ((data[offset+4] | 0x20) == 't') && remain >= 6 && ((data[offset+5] | 0x20) == 'e')) {
                    if (!positions) return true;
                    positions->offsets[positions->count++] = offset;
                }
            } else if (lc == 'i' && remain >= 6) {
                uint32_t val4 = lumina_load_le32(data + offset) | 0x20202020;
                if (val4 == 0x65736E69 && ((data[offset+4] | 0x20) == 'r') && ((data[offset+5] | 0x20) == 't')) {
                    if (!positions) return true;
                    positions->offsets[positions->count++] = offset;
                }
            } else if (lc == 'w' && remain >= 7) {
                uint32_t val4 = lumina_load_le32(data + offset) | 0x20202020;
                if (val4 == 0x74696177 && ((data[offset+4] | 0x20) == 'f') && ((data[offset+5] | 0x20) == 'o') && ((data[offset+6] | 0x20) == 'r')) {
                    if (!positions) return true;
                    positions->offsets[positions->count++] = offset;
                }
            } else if (lc == 'e' && remain >= 5) {
                uint32_t val4 = lumina_load_le32(data + offset) | 0x20202020;
                if (val4 == 0x63657865) {
                    if (!positions) return true;
                    positions->offsets[positions->count++] = offset;
                } else if (val4 == 0x72747865 && ((data[offset+4] | 0x20) == 'a') && remain >= 7 && ((data[offset+5] | 0x20) == 'c') && ((data[offset+6] | 0x20) == 't')) {
                    if (!positions) return true;
                    positions->offsets[positions->count++] = offset;
                }
            }
        }
        
        ptr++;
        if (positions && positions->count >= MAX_DANGER_POSITIONS) return true;
    }

    return positions ? positions->count > 0 : false;
}
#endif

static bool lumina_fast_prefilter_scalar(const unsigned char *data, size_t len,
                                         DangerPositions *positions) {
    const uint8_t *ptr = data;
    const uint8_t *end = data + len;

    if (positions) positions->count = 0;

    while (ptr < end) {
        uint8_t c = *ptr;
        uint8_t m = g_lut_lo[c & 0x0F] & g_lut_hi[c >> 4];
        
        if (m & 0x1E) { // Danger char
            if (!positions) return true;
            positions->offsets[positions->count++] = ptr - data;
        } if (m & 1) { // SQLi trigger
            size_t offset = ptr - data;
            size_t remain = end - ptr;
            uint8_t lc = c | 0x20;
            
            if (lc == 'u' && remain >= 5) {
                uint32_t val4 = lumina_load_le32(data + offset) | 0x20202020;
                if (val4 == 0x6F696E75 && ((data[offset+4] | 0x20) == 'n')) {
                    if (!positions) return true;
                    positions->offsets[positions->count++] = offset;
                }
            } else if (lc == 's' && remain >= 6) {
                uint32_t val4 = lumina_load_le32(data + offset) | 0x20202020;
                if (val4 == 0x656C6573 && ((data[offset+4] | 0x20) == 'c') && ((data[offset+5] | 0x20) == 't')) {
                    if (!positions) return true;
                    positions->offsets[positions->count++] = offset;
                }
            } else if (lc == 'd' && remain >= 5) {
                uint32_t val4 = lumina_load_le32(data + offset) | 0x20202020;
                if (val4 == 0x706F7264) {
                    if (!positions) return true;
                    positions->offsets[positions->count++] = offset;
                } else if (val4 == 0x656C6564 && ((data[offset+4] | 0x20) == 't') && remain >= 6 && ((data[offset+5] | 0x20) == 'e')) {
                    if (!positions) return true;
                    positions->offsets[positions->count++] = offset;
                }
            } else if (lc == 'i' && remain >= 6) {
                uint32_t val4 = lumina_load_le32(data + offset) | 0x20202020;
                if (val4 == 0x65736E69 && ((data[offset+4] | 0x20) == 'r') && ((data[offset+5] | 0x20) == 't')) {
                    if (!positions) return true;
                    positions->offsets[positions->count++] = offset;
                }
            } else if (lc == 'w' && remain >= 7) {
                uint32_t val4 = lumina_load_le32(data + offset) | 0x20202020;
                if (val4 == 0x74696177 && ((data[offset+4] | 0x20) == 'f') && ((data[offset+5] | 0x20) == 'o') && ((data[offset+6] | 0x20) == 'r')) {
                    if (!positions) return true;
                    positions->offsets[positions->count++] = offset;
                }
            } else if (lc == 'e' && remain >= 5) {
                uint32_t val4 = lumina_load_le32(data + offset) | 0x20202020;
                if (val4 == 0x63657865) {
                    if (!positions) return true;
                    positions->offsets[positions->count++] = offset;
                } else if (val4 == 0x72747865 && ((data[offset+4] | 0x20) == 'a') && remain >= 7 && ((data[offset+5] | 0x20) == 'c') && ((data[offset+6] | 0x20) == 't')) {
                    if (!positions) return true;
                    positions->offsets[positions->count++] = offset;
                }
            }
        }
        
        ptr++;
        if (positions && positions->count >= MAX_DANGER_POSITIONS) return true;
    }

    return positions ? positions->count > 0 : false;
}

static bool (*fast_prefilter_impl)(const unsigned char *, size_t, DangerPositions *) = NULL;

__attribute__((constructor))
static void init_fast_prefilter(void) {
    init_fast_prefilter_lut();
#if LUMINA_PREFILTER_X86
    if (__builtin_cpu_supports("avx2") && __builtin_cpu_supports("bmi")) {
        fast_prefilter_impl = lumina_fast_prefilter_avx2;
    } else {
        fast_prefilter_impl = lumina_fast_prefilter_scalar;
    }
#else
    fast_prefilter_impl = lumina_fast_prefilter_scalar;
#endif
}

bool lumina_fast_prefilter(const unsigned char *data, size_t len,
                           DangerPositions *positions) {
    if (!fast_prefilter_impl) {
        init_fast_prefilter();
    }
    return fast_prefilter_impl(data, len, positions);
}

#if LUMINA_PREFILTER_X86
__attribute__((target("avx2,bmi")))
static bool lumina_fast_prefilter_headers_avx2(const unsigned char *data, size_t len, DangerPositions *positions) {
    const uint8_t *ptr = data;
    const uint8_t *end = data + len;
    if (positions) positions->count = 0;
    __m256i danger_vecs[DANGER_COUNT_HEADERS];
    for (size_t i = 0; i < (size_t)DANGER_COUNT_HEADERS; i++) {
        danger_vecs[i] = _mm256_set1_epi8(DANGER_CHARS_HEADERS[i]);
    }
    while (ptr + 32 <= end) {
        __m256i chunk = _mm256_loadu_si256((const __m256i *)ptr);
        __m256i acc = _mm256_setzero_si256();
        for (size_t i = 0; i < (size_t)DANGER_COUNT_HEADERS; i++) {
            acc = _mm256_or_si256(acc, _mm256_cmpeq_epi8(chunk, danger_vecs[i]));
        }
        uint32_t danger_mask = (uint32_t)_mm256_movemask_epi8(acc);
        if (danger_mask) {
            if (!positions) return true;
            while (danger_mask && positions->count < MAX_DANGER_POSITIONS) {
                int bit = __builtin_ctz(danger_mask);
                positions->offsets[positions->count++] = (ptr - data) + bit;
                danger_mask &= danger_mask - 1;
            }
            if (positions->count >= MAX_DANGER_POSITIONS) return true;
        }
        ptr += 32;
    }
    while (ptr < end) {
        char c = *ptr;
        for (size_t i = 0; i < (size_t)DANGER_COUNT_HEADERS; i++) {
            if (c == DANGER_CHARS_HEADERS[i]) {
                if (!positions) return true;
                if (positions->count < MAX_DANGER_POSITIONS) positions->offsets[positions->count++] = ptr - data;
                else return true;
                break;
            }
        }
        ptr++;
    }
    return positions ? positions->count > 0 : false;
}
#endif

static bool lumina_fast_prefilter_headers_scalar(const unsigned char *data, size_t len, DangerPositions *positions) {
    const uint8_t *ptr = data;
    const uint8_t *end = data + len;
    if (positions) positions->count = 0;
    while (ptr < end) {
        char c = *ptr;
        for (size_t i = 0; i < (size_t)DANGER_COUNT_HEADERS; i++) {
            if (c == DANGER_CHARS_HEADERS[i]) {
                if (!positions) return true;
                if (positions->count < MAX_DANGER_POSITIONS) positions->offsets[positions->count++] = ptr - data;
                else return true;
                break;
            }
        }
        ptr++;
    }
    return positions ? positions->count > 0 : false;
}

static bool (*fast_prefilter_headers_impl)(const unsigned char *, size_t, DangerPositions *) = NULL;

bool lumina_fast_prefilter_headers(const unsigned char *data, size_t len, DangerPositions *positions) {
    if (!fast_prefilter_headers_impl) {
#if LUMINA_PREFILTER_X86
        if (__builtin_cpu_supports("avx2") && __builtin_cpu_supports("bmi")) {
            fast_prefilter_headers_impl = lumina_fast_prefilter_headers_avx2;
        } else {
            fast_prefilter_headers_impl = lumina_fast_prefilter_headers_scalar;
        }
#else
        fast_prefilter_headers_impl = lumina_fast_prefilter_headers_scalar;
#endif
    }
    return fast_prefilter_headers_impl(data, len, positions);
}
