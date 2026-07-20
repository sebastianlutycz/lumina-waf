#include <stddef.h>
#include <stdint.h>
#if defined(__AVX2__)
#include <immintrin.h>

typedef unsigned char u_char;

static const int8_t hex_lut[256] = {
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
     0, 1, 2, 3, 4, 5, 6, 7,  8, 9,-1,-1,-1,-1,-1,-1,
    -1,10,11,12,13,14,15,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,10,11,12,13,14,15,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
};

void lumina_unescape_uri_avx2(u_char **dst, u_char **src, size_t *size) {
    u_char *d = *dst;
    u_char *s = *src;
    size_t remaining = *size;

    while (remaining >= 32) {
        __m256i chunk = _mm256_loadu_si256((const __m256i*)s);
        __m256i pct = _mm256_cmpeq_epi8(chunk, _mm256_set1_epi8('%'));
        int pct_mask = _mm256_movemask_epi8(pct);

        if (pct_mask == 0) {
            _mm256_storeu_si256((__m256i*)d, chunk);
            s += 32;
            d += 32;
            remaining -= 32;
            continue;
        }

        int pos = 0;
        while (pct_mask) {
            int next_pct = __builtin_ctz(pct_mask);
            int safe_len = next_pct - pos;
            if (safe_len > 0) {
                for (int j = 0; j < safe_len; j++) d[j] = s[pos + j];
                d += safe_len;
            }
            pos = next_pct;
            pct_mask &= pct_mask - 1;

            if (pos + 2 < 32 && remaining >= (size_t)(pos + 3)) {
                int8_t v1 = hex_lut[s[pos + 1]];
                int8_t v2 = hex_lut[s[pos + 2]];
                if (v1 >= 0 && v2 >= 0) {
                    *d++ = (u_char)((v1 << 4) | v2);
                    pos += 3;
                    continue;
                }
            }
            d[0] = s[pos];
            d++;
            pos++;
        }

        if (pos < 32) {
            int tail = 32 - pos;
            for (int j = 0; j < tail; j++) d[j] = s[pos + j];
            d += tail;
        }
        s += 32;
        remaining -= 32;
    }

    while (remaining > 0) {
        u_char ch = *s++;
        remaining--;
        if (ch == '%' && remaining >= 2) {
            int8_t v1 = hex_lut[*s];
            int8_t v2 = hex_lut[*(s + 1)];
            if (v1 >= 0 && v2 >= 0) {
                s += 2;
                remaining -= 2;
                *d++ = (u_char)((v1 << 4) | v2);
                continue;
            }
            *d++ = '%';
        } else {
            *d++ = ch;
        }
    }

    *dst = d;
    *src = s;
    *size = remaining;
}
#endif
