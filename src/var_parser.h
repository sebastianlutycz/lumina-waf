#ifndef VAR_PARSER_H
#define VAR_PARSER_H

#include <stddef.h>
#include <stdint.h>

#define MAX_VAR_TOKENS 64

typedef struct {
    const unsigned char *ptr;
    size_t len;
} VarToken;

typedef struct {
    VarToken tokens[MAX_VAR_TOKENS];
    int count;
} VarTokens;

static inline int tokenize_args(const unsigned char *data, size_t len, VarTokens *out) {
    int count = 0;
    const unsigned char *val_start = NULL;
    const unsigned char *end = data + len;
    for (const unsigned char *p = data; p < end; p++) {
        if (*p == '=') {
            val_start = p + 1;
        } else if (*p == '&' || *p == ';') {
            if (val_start && count < MAX_VAR_TOKENS) {
                out->tokens[count].ptr = val_start;
                out->tokens[count].len = p - val_start;
                count++;
            }
            val_start = NULL;
        }
    }
    if (val_start && val_start < end && count < MAX_VAR_TOKENS) {
        out->tokens[count].ptr = val_start;
        out->tokens[count].len = end - val_start;
        count++;
    }
    out->count = count;
    return count;
}

static inline int tokenize_cookies(const unsigned char *data, size_t len, VarTokens *out) {
    int count = 0;
    const unsigned char *p = data, *end = data + len;
    const unsigned char *val_start = NULL;
    while (p < end && (*p == ' ' || *p == '\t')) p++;
    while (p < end) {
        if (*p == '=') {
            val_start = p + 1;
        } else if (*p == ';') {
            if (val_start && count < MAX_VAR_TOKENS) {
                size_t vlen = p - val_start;
                while (vlen > 0 && (val_start[vlen-1] == ' ' || val_start[vlen-1] == '\t')) vlen--;
                out->tokens[count].ptr = val_start;
                out->tokens[count].len = vlen;
                count++;
            }
            p++;
            while (p < end && (*p == ' ' || *p == '\t')) p++;
            val_start = NULL;
            continue;
        }
        p++;
    }
    if (val_start && val_start < end && count < MAX_VAR_TOKENS) {
        size_t vlen = end - val_start;
        while (vlen > 0 && (val_start[vlen-1] == ' ' || val_start[vlen-1] == '\t')) vlen--;
        out->tokens[count].ptr = val_start;
        out->tokens[count].len = vlen;
        count++;
    }
    out->count = count;
    return count;
}

static inline int tokenize_body_urlencoded(const unsigned char *data, size_t len, VarTokens *out) {
    return tokenize_args(data, len, out);
}

#endif
