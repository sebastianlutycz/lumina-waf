#include <stddef.h>

typedef unsigned char u_char;
typedef unsigned int ngx_uint_t;

// NGINX GOLD STANDARD (ngx_unescape_uri) z src/core/ngx_string.c
void ngx_unescape_uri_scalar(u_char **dst, u_char **src, size_t size, ngx_uint_t type) {
    (void)type;
    u_char *d = *dst, *s = *src, ch, c, decoded;
    enum { sw_usual = 0, sw_quoted, sw_quoted_second } state;
    state = sw_usual;
    decoded = 0;

    while (size--) {
        ch = *s++;
        switch (state) {
        case sw_usual:
            if (ch == '?') { *d++ = ch; goto done; }
            if (ch == '%') { state = sw_quoted; break; }
            *d++ = ch;
            break;
        case sw_quoted:
            if (ch >= '0' && ch <= '9') { decoded = ch - '0'; state = sw_quoted_second; break; }
            c = ch | 0x20;
            if (c >= 'a' && c <= 'f') { decoded = c - 'a' + 10; state = sw_quoted_second; break; }
            state = sw_usual; *d++ = '%'; *d++ = ch;
            break;
        case sw_quoted_second:
            state = sw_usual;
            if (ch >= '0' && ch <= '9') { ch = (decoded << 4) + ch - '0'; *d++ = ch; break; }
            c = ch | 0x20;
            if (c >= 'a' && c <= 'f') {
                ch = (decoded << 4) + (c - 'a') + 10;
                *d++ = ch; break;
            }
            break;
        }
    }
done:
    *dst = d; *src = s;
}
