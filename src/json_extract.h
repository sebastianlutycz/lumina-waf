#ifndef JSON_EXTRACT_H
#define JSON_EXTRACT_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#if defined(__AVX2__)
#include <immintrin.h>
#endif

#define MAX_JSON_STRINGS 32

typedef struct {
    const unsigned char *ptr;
    size_t len;
} JsonString;

typedef struct {
    JsonString strings[MAX_JSON_STRINGS];
    int count;
} JsonStrings;

static inline int extract_json_strings(const unsigned char *data, size_t len, JsonStrings *out) {
    out->count = 0;
    if (len < 2) return 0;

    const unsigned char *end = data + len;
    const unsigned char *p = data;

#if defined(__AVX2__)
    __m256i quote_mask = _mm256_set1_epi8('"');
    while (p + 32 <= end) {
        __m256i chunk = _mm256_loadu_si256((const __m256i*)p);
        __m256i cmp_quote = _mm256_cmpeq_epi8(chunk, quote_mask);
        uint32_t mask = _mm256_movemask_epi8(cmp_quote);

        while (mask) {
            int bit = __builtin_ctz(mask);
            mask &= mask - 1;
            const unsigned char *quote = p + bit;

            const unsigned char *close = quote + 1;
            while (close < end && *close != '"') {
                if (*close == '\\' && close + 1 < end) close++;
                close++;
            }

            if (close < end && close - quote > 1 && out->count < MAX_JSON_STRINGS) {
                size_t slen = close - quote - 1;
                if (slen > 2 && slen < 4096) {
                    out->strings[out->count].ptr = quote + 1;
                    out->strings[out->count].len = slen;
                    out->count++;
                }
            }
            p = close + 1;
        }
        p += 32;
    }
#endif

    while (p < end) {
        if (*p == '"') {
            const unsigned char *close = p + 1;
            while (close < end && *close != '"') {
                if (*close == '\\' && close + 1 < end) close++;
                close++;
            }
            if (close < end && close - p > 1 && out->count < MAX_JSON_STRINGS) {
                size_t slen = close - p - 1;
                if (slen > 2 && slen < 4096) {
                    out->strings[out->count].ptr = p + 1;
                    out->strings[out->count].len = slen;
                    out->count++;
                }
            }
            p = close + 1;
        } else {
            p++;
        }
    }

    return out->count;
}

#endif
