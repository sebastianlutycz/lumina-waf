#include "lumina_xml_tokenizer.h"
#include <string.h>

#define XML_SCRATCH_SIZE 65536

typedef enum {
    STATE_TEXT,
    STATE_TAG_START,
    STATE_IN_TAG_NAME,
    STATE_IN_TAG,
    STATE_ATTR_NAME,
    STATE_BEFORE_ATTR_VAL,
    STATE_ATTR_VAL_DQ,
    STATE_ATTR_VAL_SQ,
    STATE_PI,
    STATE_DECL,
    STATE_COMMENT,
    STATE_CDATA
} xml_state_t;

// Helper to decode entities into a scratch buffer if needed.
// Returns the length of the decoded string.
static size_t decode_entities(const unsigned char *in, size_t in_len, unsigned char *out, size_t out_max) {
    size_t in_idx = 0;
    size_t out_idx = 0;
    while (in_idx < in_len && out_idx < out_max) {
        if (in[in_idx] == '&' && in_idx + 1 < in_len) {
            size_t end = in_idx + 1;
            while (end < in_len && in[end] != ';' && (end - in_idx) < 10) {
                end++;
            }
            if (end < in_len && in[end] == ';') {
                size_t ent_len = end - in_idx - 1;
                const unsigned char *ent = in + in_idx + 1;
                if (ent_len == 2 && memcmp(ent, "lt", 2) == 0) {
                    out[out_idx++] = '<';
                } else if (ent_len == 2 && memcmp(ent, "gt", 2) == 0) {
                    out[out_idx++] = '>';
                } else if (ent_len == 3 && memcmp(ent, "amp", 3) == 0) {
                    out[out_idx++] = '&';
                } else if (ent_len == 4 && memcmp(ent, "apos", 4) == 0) {
                    out[out_idx++] = '\'';
                } else if (ent_len == 4 && memcmp(ent, "quot", 4) == 0) {
                    out[out_idx++] = '"';
                } else if (ent_len > 1 && ent[0] == '#') {
                    // Numeric entity
                    unsigned long code = 0;
                    if (ent[1] == 'x' || ent[1] == 'X') {
                        for (size_t k = 2; k < ent_len; k++) {
                            unsigned char c = ent[k];
                            if (c >= '0' && c <= '9') code = (code << 4) | (c - '0');
                            else if (c >= 'a' && c <= 'f') code = (code << 4) | (c - 'a' + 10);
                            else if (c >= 'A' && c <= 'F') code = (code << 4) | (c - 'A' + 10);
                            else break;
                        }
                    } else {
                        for (size_t k = 1; k < ent_len; k++) {
                            unsigned char c = ent[k];
                            if (c >= '0' && c <= '9') code = (code * 10) + (c - '0');
                            else break;
                        }
                    }
                    if (code > 0 && code <= 0xFF) {
                        out[out_idx++] = (unsigned char)code;
                    } else {
                        out[out_idx++] = '?';
                    }
                } else {
                    // Unknown entity, just keep it raw
                    for (size_t k = in_idx; k <= end && out_idx < out_max; k++) {
                        out[out_idx++] = in[k];
                    }
                }
                in_idx = end + 1;
                continue;
            }
        }
        out[out_idx++] = in[in_idx++];
    }
    return out_idx;
}

static void emit_val(const unsigned char *data, size_t start, size_t end, lumina_xml_value_kind_t kind, lumina_xml_emit_fn emit_cb, void *context, unsigned char *scratch, size_t scratch_size) {
    if (start >= end) return;
    size_t len = end - start;
    bool has_entity = false;
    for (size_t k = start; k < end; k++) {
        if (data[k] == '&') {
            has_entity = true;
            break;
        }
    }

    lumina_xml_span_t span;
    span.kind = kind;
    if (has_entity) {
        span.length = decode_entities(data + start, len, scratch, scratch_size);
        span.data = scratch;
    } else {
        span.length = len;
        span.data = data + start;
    }
    if (span.length > 0) {
        emit_cb(&span, context);
    }
}

int lumina_tokenize_xml(const unsigned char *data, size_t length, lumina_xml_emit_fn emit_cb, void *context) {
    xml_state_t state = STATE_TEXT;
    size_t i = 0;
    size_t val_start = 0;

    // Static thread local scratch for entities
    static _Thread_local unsigned char scratch[XML_SCRATCH_SIZE];

    while (i < length) {
        unsigned char c = data[i];
        switch (state) {
            case STATE_TEXT:
                if (c == '<') {
                    emit_val(data, val_start, i, LUMINA_XML_TEXT, emit_cb, context, scratch, sizeof(scratch));
                    state = STATE_TAG_START;
                }
                break;
            case STATE_TAG_START:
                if (c == '?') {
                    state = STATE_PI;
                } else if (c == '!') {
                    if (i + 2 < length && data[i+1] == '-' && data[i+2] == '-') {
                        state = STATE_COMMENT;
                        i += 2;
                    } else if (i + 7 < length && memcmp(data + i + 1, "[CDATA[", 7) == 0) {
                        state = STATE_CDATA;
                        i += 7;
                        val_start = i + 1;
                    } else {
                        state = STATE_DECL;
                    }
                } else if (c == '/') {
                    state = STATE_IN_TAG_NAME;
                } else if (c > ' ') {
                    state = STATE_IN_TAG_NAME;
                }
                break;
            case STATE_IN_TAG_NAME:
                if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                    state = STATE_IN_TAG;
                } else if (c == '>' || c == '/') {
                    state = STATE_TEXT;
                    val_start = i + 1;
                }
                break;
            case STATE_IN_TAG:
                if (c == '>' || c == '/') {
                    state = STATE_TEXT;
                    val_start = i + 1;
                } else if (c > ' ') {
                    state = STATE_ATTR_NAME;
                }
                break;
            case STATE_ATTR_NAME:
                if (c == '=') {
                    state = STATE_BEFORE_ATTR_VAL;
                } else if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                    state = STATE_IN_TAG;
                } else if (c == '>' || c == '/') {
                    state = STATE_TEXT;
                    val_start = i + 1;
                }
                break;
            case STATE_BEFORE_ATTR_VAL:
                if (c == '"') {
                    state = STATE_ATTR_VAL_DQ;
                    val_start = i + 1;
                } else if (c == '\'') {
                    state = STATE_ATTR_VAL_SQ;
                    val_start = i + 1;
                } else if (c != ' ' && c != '\t' && c != '\n' && c != '\r') {
                    // Unquoted attribute value
                    state = STATE_IN_TAG;
                }
                break;
            case STATE_ATTR_VAL_DQ:
                if (c == '"') {
                    emit_val(data, val_start, i, LUMINA_XML_ATTRIBUTE, emit_cb, context, scratch, sizeof(scratch));
                    state = STATE_IN_TAG;
                }
                break;
            case STATE_ATTR_VAL_SQ:
                if (c == '\'') {
                    emit_val(data, val_start, i, LUMINA_XML_ATTRIBUTE, emit_cb, context, scratch, sizeof(scratch));
                    state = STATE_IN_TAG;
                }
                break;
            case STATE_PI:
                if (c == '?' && i + 1 < length && data[i+1] == '>') {
                    state = STATE_TEXT;
                    val_start = i + 2;
                    i++;
                }
                break;
            case STATE_COMMENT:
                if (c == '-' && i + 2 < length && data[i+1] == '-' && data[i+2] == '>') {
                    state = STATE_TEXT;
                    val_start = i + 3;
                    i += 2;
                }
                break;
            case STATE_CDATA:
                if (c == ']' && i + 2 < length && data[i+1] == ']' && data[i+2] == '>') {
                    // CDATA doesn't have entities decoded
                    lumina_xml_span_t span;
                    span.kind = LUMINA_XML_TEXT;
                    span.data = data + val_start;
                    span.length = i - val_start;
                    if (span.length > 0) emit_cb(&span, context);

                    state = STATE_TEXT;
                    val_start = i + 3;
                    i += 2;
                }
                break;
            case STATE_DECL:
                if (c == '>') {
                    state = STATE_TEXT;
                    val_start = i + 1;
                }
                break;
        }
        i++;
    }

    if (state == STATE_TEXT && val_start < length) {
        emit_val(data, val_start, length, LUMINA_XML_TEXT, emit_cb, context, scratch, sizeof(scratch));
    }

    return 0;
}
