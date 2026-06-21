#include <stdio.h>
#include <string.h>
#include <immintrin.h>

static inline __m256i hex_valid_vec(__m256i v) {
    __m256i v_up = _mm256_and_si256(v, _mm256_set1_epi8(0xDF));
    __m256i is_num = _mm256_and_si256(_mm256_cmpgt_epi8(v, _mm256_set1_epi8(0x2F)), _mm256_cmpgt_epi8(_mm256_set1_epi8(0x3A), v));
    __m256i is_let = _mm256_and_si256(_mm256_cmpgt_epi8(v_up, _mm256_set1_epi8(0x40)), _mm256_cmpgt_epi8(_mm256_set1_epi8(0x47), v_up));
    return _mm256_or_si256(is_num, is_let);
}

int main() {
    char test[] = "09aFZ";
    __m256i v = _mm256_setr_epi8(test[0], test[1], test[2], test[3], test[4], 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0);
    __m256i res = hex_valid_vec(v);
    unsigned char out[32];
    _mm256_storeu_si256((__m256i*)out, res);
    for (int i=0; i<5; i++) printf("%c: %02x\n", test[i], out[i]);
    return 0;
}
