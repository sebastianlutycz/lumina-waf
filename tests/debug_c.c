#include <stdio.h>
#include <string.h>

void lumina_unescape_uri_avx2(unsigned char **dst, unsigned char **src, size_t *size);

int main() {
    unsigned char src[] = "F%29HqH%40%20vX%40G-vWWPF%3Cscript%3E93urYmkaof%28%2688q%23O8Ql";
    unsigned char dst[128] = {0};
    unsigned char *s = src;
    unsigned char *d = dst;
    size_t sz = strlen((char*)src);
    
    lumina_unescape_uri_avx2(&d, &s, &sz);
    
    printf("Decoded chunk length: %ld\n", d - dst);
    printf("Decoded chunk: %.*s\n", (int)(d - dst), dst);
    printf("Remaining src sz: %ld, str: %s\n", sz, s);
    return 0;
}
