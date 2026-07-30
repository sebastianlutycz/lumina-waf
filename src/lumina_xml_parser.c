#include "lumina_xml_parser.h"
#include <stdint.h>
#include <string.h>

/* Limits for Zero-Allocation Extractor */
#define LUMINA_XML_MAX_NESTING 128
#define LUMINA_XML_MAX_ATTRIBUTES 256
#define LUMINA_XML_MAX_DTD_NAME_LEN 64
#define LUMINA_XML_MAX_ENTITY_LEN (LUMINA_XML_MAX_DTD_NAME_LEN + 2)
#define LUMINA_XML_MAX_VALUE_LEN (1024 * 1024) /* 1MB */
#define LUMINA_XML_MAX_DTD_ENTITIES 32
#define LUMINA_XML_MAX_DTD_DECLARATION_CODEPOINTS 8192
#define LUMINA_XML_MAX_DTD_EXPANSION_DEPTH 4
#define LUMINA_XML_MAX_DTD_EXPANDED_BYTES (128 * 1024)

#if defined(__GNUC__) || defined(__clang__)
#define LUMINA_XML_ALWAYS_INLINE __attribute__((always_inline)) inline
#define LUMINA_XML_LIKELY(value) __builtin_expect(!!(value), 1)
#define LUMINA_XML_COLD __attribute__((cold))
#else
#define LUMINA_XML_ALWAYS_INLINE inline
#define LUMINA_XML_LIKELY(value) (value)
#define LUMINA_XML_COLD
#endif

typedef enum {
    XML_STATE_TEXT,
    XML_STATE_TAG_OPEN,
    XML_STATE_START_TAG_NAME,
    XML_STATE_END_TAG_NAME,
    XML_STATE_BETWEEN_ATTRIBUTES,
    XML_STATE_ATTRIBUTE_NAME,
    XML_STATE_AFTER_ATTRIBUTE_NAME,
    XML_STATE_BEFORE_ATTRIBUTE_VALUE,
    XML_STATE_ATTRIBUTE_VALUE_SINGLE,
    XML_STATE_ATTRIBUTE_VALUE_DOUBLE,
    XML_STATE_COMMENT_START_1,
    XML_STATE_COMMENT_START_2,
    XML_STATE_COMMENT,
    XML_STATE_CDATA_START_1,
    XML_STATE_CDATA_START_2,
    XML_STATE_CDATA_START_3,
    XML_STATE_CDATA_START_4,
    XML_STATE_CDATA_START_5,
    XML_STATE_CDATA_START_6,
    XML_STATE_CDATA,
    XML_STATE_PI_OR_XML_DECL,
    XML_STATE_ENTITY_TEXT,
    XML_STATE_ENTITY_ATTR_S,
    XML_STATE_ENTITY_ATTR_D,
    XML_STATE_SELF_CLOSE
} XmlState;

typedef enum {
    XML_ENCODING_UTF8,
    XML_ENCODING_UTF16_LE,
    XML_ENCODING_UTF16_BE
} XmlEncoding;

typedef struct {
    const unsigned char *data;
    size_t len;
    size_t pos;
    XmlEncoding encoding;
    bool bom;
    bool error;
} XmlCodepointCursor;

typedef struct {
    uint32_t value;
    size_t start;
    size_t end;
} XmlCodepoint;

typedef struct {
    size_t start;
    size_t end;
    bool active;
} XmlValueRun;

typedef struct {
    unsigned char name[LUMINA_XML_MAX_DTD_NAME_LEN];
    unsigned char name_len;
    size_t value_start;
    size_t value_end;
} XmlDtdEntity;

typedef struct {
    XmlDtdEntity entities[LUMINA_XML_MAX_DTD_ENTITIES];
    const unsigned char *data;
    size_t root_name_start;
    size_t root_name_end;
    size_t declaration_codepoints;
    size_t expanded_bytes;
    size_t expansion_limit;
    XmlEncoding encoding;
    unsigned entity_count;
    bool present;
} XmlDtdContext;

static bool lumina_ascii_equal_ci(const unsigned char *left,
                                  const char *right, size_t len) {
    for (size_t i = 0; i < len; i++) {
        unsigned char c = left[i];
        if (c >= 'A' && c <= 'Z') c = (unsigned char)(c | 0x20u);
        if (c != (unsigned char)right[i]) return false;
    }
    return true;
}

static bool lumina_ascii_suffix_ci(const unsigned char *data, size_t len,
                                   const char *suffix, size_t suffix_len) {
    return len >= suffix_len &&
           lumina_ascii_equal_ci(data + len - suffix_len, suffix, suffix_len);
}

bool lumina_is_xml_part(const unsigned char *content_type, size_t content_type_len,
                        const unsigned char *filename, size_t filename_len,
                        const unsigned char *body, size_t body_len) {
    if (content_type && content_type_len > 0) {
        size_t media_len = 0;
        while (media_len < content_type_len &&
               content_type[media_len] != ';') {
            media_len++;
        }
        while (media_len > 0 &&
               (content_type[media_len - 1] == ' ' ||
                content_type[media_len - 1] == '\t')) {
            media_len--;
        }
        if ((media_len == 8 &&
             lumina_ascii_equal_ci(content_type, "text/xml", 8)) ||
            (media_len == 15 &&
             lumina_ascii_equal_ci(content_type, "application/xml", 15)) ||
            lumina_ascii_suffix_ci(content_type, media_len, "+xml", 4)) {
            return true;
        }
    }
    if (filename && filename_len > 0) {
        if (lumina_ascii_suffix_ci(filename, filename_len, ".xml", 4) ||
            lumina_ascii_suffix_ci(filename, filename_len, ".xsd", 4) ||
            lumina_ascii_suffix_ci(filename, filename_len, ".xsl", 4) ||
            lumina_ascii_suffix_ci(filename, filename_len, ".svg", 4) ||
            lumina_ascii_suffix_ci(filename, filename_len, ".xslt", 5) ||
            lumina_ascii_suffix_ci(filename, filename_len, ".wsdl", 5)) {
            return true;
        }
    }
    if (!body) return false;

    if (body_len >= 2 &&
        ((body[0] == 0xffu && body[1] == 0xfeu) ||
         (body[0] == 0xfeu && body[1] == 0xffu))) {
        return true;
    }
    if (body_len >= 4 &&
        ((body[0] == 0x00u && body[1] == '<' &&
          body[2] == 0x00u && body[3] == '?') ||
         (body[0] == '<' && body[1] == 0x00u &&
          body[2] == '?' && body[3] == 0x00u))) {
        return true;
    }

    /* Sniff only an XML declaration. A leading '<' alone is valid form data. */
    size_t scan_len = body_len < 256 ? body_len : 256;
    for (size_t i = 0; i < scan_len; i++) {
        if (body[i] == ' ' || body[i] == '\t' || body[i] == '\r' || body[i] == '\n') continue;
        return i + 5 <= body_len && memcmp(body + i, "<?xml", 5) == 0;
    }
    return false;
}

extern int lumina_scan_projected_xml_value(const unsigned char *data, size_t len,
                                           LuminaRuleState *state);

/* Logical Stream Sink */
static _Thread_local unsigned char g_xml_value_buffer[LUMINA_XML_MAX_VALUE_LEN];
static _Thread_local size_t g_xml_value_len = 0;
static _Thread_local LuminaVarType g_xml_current_var_type = LUMINA_VAR_ANY;
static _Thread_local int g_xml_threat = 0;
static _Thread_local bool g_xml_value_overflow = false;

void lumina_xml_value_begin(LuminaRuleState *state, LuminaVarType var_type) {
    (void)state;
    g_xml_value_len = 0;
    g_xml_current_var_type = var_type;
}

void lumina_xml_value_fragment(LuminaRuleState *state, const unsigned char *ptr, size_t len) {
    (void)state;
    if (g_xml_value_len + len <= LUMINA_XML_MAX_VALUE_LEN) {
        memcpy(g_xml_value_buffer + g_xml_value_len, ptr, len);
        g_xml_value_len += len;
    } else {
        g_xml_value_overflow = true;
    }
}

void lumina_xml_value_end(LuminaRuleState *state) {
    if (g_xml_value_len > 0) {
        int match = lumina_scan_projected_xml_value(
            g_xml_value_buffer, g_xml_value_len, state);
        if (match) g_xml_threat = match;
    }
    g_xml_value_len = 0;
}

static bool lumina_xml_codepoint_valid(uint32_t codepoint) {
    return codepoint == 0x09u || codepoint == 0x0au || codepoint == 0x0du ||
           (codepoint >= 0x20u && codepoint <= 0xd7ffu) ||
           (codepoint >= 0xe000u && codepoint <= 0xfffdu) ||
           (codepoint >= 0x10000u && codepoint <= 0x10ffffu);
}

static bool lumina_xml_cursor_init(XmlCodepointCursor *cursor,
                                   const unsigned char *data, size_t len) {
    if (!cursor || !data || len == 0) return false;
    *cursor = (XmlCodepointCursor){
        .data = data,
        .len = len,
        .pos = 0,
        .encoding = XML_ENCODING_UTF8,
        .bom = false,
        .error = false,
    };
    if (len >= 2 && data[0] == 0xffu && data[1] == 0xfeu) {
        cursor->encoding = XML_ENCODING_UTF16_LE;
        cursor->pos = 2;
        cursor->bom = true;
    } else if (len >= 2 && data[0] == 0xfeu && data[1] == 0xffu) {
        cursor->encoding = XML_ENCODING_UTF16_BE;
        cursor->pos = 2;
        cursor->bom = true;
    } else if (len >= 4 && data[0] == 0x00u && data[1] == '<' &&
               data[2] == 0x00u && data[3] == '?') {
        cursor->encoding = XML_ENCODING_UTF16_BE;
    } else if (len >= 4 && data[0] == '<' && data[1] == 0x00u &&
               data[2] == '?' && data[3] == 0x00u) {
        cursor->encoding = XML_ENCODING_UTF16_LE;
    } else if (len >= 3 && data[0] == 0xefu && data[1] == 0xbbu &&
               data[2] == 0xbfu) {
        cursor->pos = 3;
        cursor->bom = true;
    }
    if (cursor->encoding != XML_ENCODING_UTF8 &&
        ((cursor->len - cursor->pos) & 1u) != 0) {
        cursor->error = true;
        return false;
    }
    return true;
}

static uint16_t lumina_xml_read_u16(const unsigned char *data,
                                    XmlEncoding encoding) {
    if (encoding == XML_ENCODING_UTF16_LE) {
        return (uint16_t)data[0] | ((uint16_t)data[1] << 8);
    }
    return ((uint16_t)data[0] << 8) | (uint16_t)data[1];
}

static bool lumina_xml_cursor_next_slow(XmlCodepointCursor *cursor,
                                        XmlCodepoint *codepoint) {
    if (!cursor || !codepoint || cursor->error ||
        cursor->pos >= cursor->len) {
        return false;
    }
    codepoint->start = cursor->pos;
    uint32_t value;
    if (cursor->encoding == XML_ENCODING_UTF8) {
        unsigned char first = cursor->data[cursor->pos++];
        if (first < 0x80u) {
            value = first;
        } else {
            size_t continuation;
            uint32_t minimum;
            if (first >= 0xc2u && first <= 0xdfu) {
                value = first & 0x1fu;
                continuation = 1;
                minimum = 0x80u;
            } else if (first >= 0xe0u && first <= 0xefu) {
                value = first & 0x0fu;
                continuation = 2;
                minimum = 0x800u;
            } else if (first >= 0xf0u && first <= 0xf4u) {
                value = first & 0x07u;
                continuation = 3;
                minimum = 0x10000u;
            } else {
                cursor->error = true;
                return false;
            }
            if (continuation > cursor->len - cursor->pos) {
                cursor->error = true;
                return false;
            }
            for (size_t i = 0; i < continuation; i++) {
                unsigned char next = cursor->data[cursor->pos++];
                if ((next & 0xc0u) != 0x80u) {
                    cursor->error = true;
                    return false;
                }
                value = (value << 6) | (next & 0x3fu);
            }
            if (value < minimum) {
                cursor->error = true;
                return false;
            }
        }
    } else {
        if (cursor->len - cursor->pos < 2) {
            cursor->error = true;
            return false;
        }
        uint16_t first = lumina_xml_read_u16(
            cursor->data + cursor->pos, cursor->encoding);
        cursor->pos += 2;
        if (first >= 0xd800u && first <= 0xdbffu) {
            if (cursor->len - cursor->pos < 2) {
                cursor->error = true;
                return false;
            }
            uint16_t second = lumina_xml_read_u16(
                cursor->data + cursor->pos, cursor->encoding);
            if (second < 0xdc00u || second > 0xdfffu) {
                cursor->error = true;
                return false;
            }
            cursor->pos += 2;
            value = 0x10000u +
                    (((uint32_t)first - 0xd800u) << 10) +
                    ((uint32_t)second - 0xdc00u);
        } else if (first >= 0xdc00u && first <= 0xdfffu) {
            cursor->error = true;
            return false;
        } else {
            value = first;
        }
    }
    if (!lumina_xml_codepoint_valid(value)) {
        cursor->error = true;
        return false;
    }
    codepoint->value = value;
    codepoint->end = cursor->pos;
    return true;
}

static LUMINA_XML_ALWAYS_INLINE bool lumina_xml_cursor_next(
    XmlCodepointCursor *cursor, XmlCodepoint *codepoint) {
    if (LUMINA_XML_LIKELY(cursor && codepoint && !cursor->error &&
                          cursor->pos < cursor->len &&
                          cursor->encoding == XML_ENCODING_UTF8)) {
        unsigned char value = cursor->data[cursor->pos];
        if (LUMINA_XML_LIKELY(value >= 0x20u) ||
            value == '\t' || value == '\n' || value == '\r') {
            codepoint->start = cursor->pos;
            codepoint->end = ++cursor->pos;
            codepoint->value = value;
            return true;
        }
    }
    return lumina_xml_cursor_next_slow(cursor, codepoint);
}

static bool lumina_xml_cursor_peek(const XmlCodepointCursor *cursor,
                                   XmlCodepoint *codepoint) {
    XmlCodepointCursor probe = *cursor;
    return lumina_xml_cursor_next(&probe, codepoint);
}

static bool lumina_xml_cursor_match_ascii(XmlCodepointCursor *cursor,
                                          const char *sequence, size_t len) {
    XmlCodepointCursor probe = *cursor;
    XmlCodepoint codepoint;
    for (size_t i = 0; i < len; i++) {
        if (!lumina_xml_cursor_next(&probe, &codepoint) ||
            codepoint.value != (unsigned char)sequence[i]) {
            return false;
        }
    }
    *cursor = probe;
    return true;
}

static bool lumina_xml_space(uint32_t codepoint);

static LuminaError lumina_xml_validate_encoding_declaration(
    const XmlCodepointCursor *cursor) {
    XmlCodepointCursor probe = *cursor;
    if (!lumina_xml_cursor_match_ascii(&probe, "<?xml", 5)) {
        return cursor->encoding == XML_ENCODING_UTF8 || cursor->bom
                   ? LUMINA_ERROR_NONE
                   : LUMINA_ERROR_REQBODY_MALFORMED;
    }

    unsigned char declaration[192];
    size_t declaration_len = 0;
    bool closed = false;
    XmlCodepoint codepoint;
    while (lumina_xml_cursor_next(&probe, &codepoint)) {
        if (codepoint.value == '?' &&
            lumina_xml_cursor_match_ascii(&probe, ">", 1)) {
            closed = true;
            break;
        }
        if (codepoint.value > 0x7fu ||
            declaration_len == sizeof(declaration)) {
            return LUMINA_ERROR_REQBODY_MALFORMED;
        }
        declaration[declaration_len++] = (unsigned char)codepoint.value;
    }
    if (!closed || declaration_len == 0 ||
        !lumina_xml_space(declaration[0])) {
        return LUMINA_ERROR_REQBODY_MALFORMED;
    }

    size_t pos = 0;
    unsigned attribute_index = 0;
    bool saw_version = false;
    bool saw_encoding = false;
    bool saw_standalone = false;
    const unsigned char *encoding_value = NULL;
    size_t encoding_len = 0;
    while (pos < declaration_len) {
        while (pos < declaration_len &&
               lumina_xml_space(declaration[pos])) {
            pos++;
        }
        if (pos == declaration_len) break;

        size_t name_start = pos;
        while (pos < declaration_len &&
               ((declaration[pos] >= 'A' && declaration[pos] <= 'Z') ||
                (declaration[pos] >= 'a' && declaration[pos] <= 'z'))) {
            pos++;
        }
        size_t name_len = pos - name_start;
        while (pos < declaration_len &&
               lumina_xml_space(declaration[pos])) {
            pos++;
        }
        if (name_len == 0 || pos == declaration_len ||
            declaration[pos++] != '=') {
            return LUMINA_ERROR_REQBODY_MALFORMED;
        }
        while (pos < declaration_len &&
               lumina_xml_space(declaration[pos])) {
            pos++;
        }
        if (pos == declaration_len ||
            (declaration[pos] != '\'' && declaration[pos] != '"')) {
            return LUMINA_ERROR_REQBODY_MALFORMED;
        }
        unsigned char quote = declaration[pos++];
        size_t value_start = pos;
        while (pos < declaration_len && declaration[pos] != quote) pos++;
        if (pos == declaration_len) return LUMINA_ERROR_REQBODY_MALFORMED;
        size_t value_len = pos - value_start;
        pos++;

        const unsigned char *name = declaration + name_start;
        const unsigned char *value = declaration + value_start;
        if (name_len == 7 && memcmp(name, "version", 7) == 0) {
            if (attribute_index != 0 || saw_version ||
                !((value_len == 3 && memcmp(value, "1.0", 3) == 0) ||
                  (value_len == 3 && memcmp(value, "1.1", 3) == 0))) {
                return LUMINA_ERROR_REQBODY_MALFORMED;
            }
            saw_version = true;
        } else if (name_len == 8 &&
                   memcmp(name, "encoding", 8) == 0) {
            if (!saw_version || saw_encoding || saw_standalone ||
                value_len == 0) {
                return LUMINA_ERROR_REQBODY_MALFORMED;
            }
            saw_encoding = true;
            encoding_value = value;
            encoding_len = value_len;
        } else if (name_len == 10 &&
                   memcmp(name, "standalone", 10) == 0) {
            if (!saw_version || saw_standalone ||
                !((value_len == 3 && memcmp(value, "yes", 3) == 0) ||
                  (value_len == 2 && memcmp(value, "no", 2) == 0))) {
                return LUMINA_ERROR_REQBODY_MALFORMED;
            }
            saw_standalone = true;
        } else {
            return LUMINA_ERROR_REQBODY_MALFORMED;
        }
        attribute_index++;
    }
    if (!saw_version ||
        (cursor->encoding != XML_ENCODING_UTF8 &&
         !cursor->bom && !saw_encoding)) {
        return LUMINA_ERROR_REQBODY_MALFORMED;
    }
    if (!saw_encoding) return LUMINA_ERROR_NONE;

    bool declared_utf8 =
        encoding_len == 5 &&
        lumina_ascii_equal_ci(encoding_value, "utf-8", 5);
    bool declared_utf16 =
        encoding_len == 6 &&
        lumina_ascii_equal_ci(encoding_value, "utf-16", 6);
    bool declared_utf16le =
        encoding_len == 8 &&
        lumina_ascii_equal_ci(encoding_value, "utf-16le", 8);
    bool declared_utf16be =
        encoding_len == 8 &&
        lumina_ascii_equal_ci(encoding_value, "utf-16be", 8);
    if (!declared_utf8 && !declared_utf16 &&
        !declared_utf16le && !declared_utf16be) {
        return LUMINA_ERROR_REQBODY_UNSUPPORTED;
    }
    if ((cursor->encoding == XML_ENCODING_UTF8 && !declared_utf8) ||
        (cursor->encoding == XML_ENCODING_UTF16_LE &&
         !(declared_utf16 || declared_utf16le)) ||
        (cursor->encoding == XML_ENCODING_UTF16_BE &&
         !(declared_utf16 || declared_utf16be))) {
        return LUMINA_ERROR_REQBODY_MALFORMED;
    }
    return LUMINA_ERROR_NONE;
}

static bool lumina_xml_cursor_project_utf8_text_run(
    XmlCodepointCursor *cursor, LuminaRuleState *state) {
    const unsigned char *start = cursor->data + cursor->pos;
    size_t remaining = cursor->len - cursor->pos;
    const unsigned char *lt = memchr(start, '<', remaining);
    const unsigned char *amp = memchr(start, '&', remaining);
    const unsigned char *end = cursor->data + cursor->len;
    if (lt && lt < end) end = lt;
    if (amp && amp < end) end = amp;

    size_t run_end = (size_t)(end - cursor->data);
    size_t pos = cursor->pos;
    while (pos < run_end) {
        unsigned char value = cursor->data[pos];
        if (LUMINA_XML_LIKELY(value >= 0x20u && value < 0x80u)) {
            pos++;
            continue;
        }
        if (value == '\t' || value == '\n' || value == '\r') {
            pos++;
            continue;
        }
        XmlCodepointCursor probe = *cursor;
        XmlCodepoint codepoint;
        probe.pos = pos;
        if (!lumina_xml_cursor_next_slow(&probe, &codepoint) ||
            codepoint.end > run_end) {
            cursor->error = true;
            return false;
        }
        pos = codepoint.end;
    }

    if (run_end > cursor->pos) {
        lumina_xml_value_fragment(
            state, cursor->data + cursor->pos, run_end - cursor->pos);
        if (g_xml_value_overflow) return false;
        cursor->pos = run_end;
        return true;
    }
    return false;
}

static bool lumina_xml_name_start(uint32_t codepoint) {
    return (codepoint >= 'A' && codepoint <= 'Z') ||
           (codepoint >= 'a' && codepoint <= 'z') ||
           codepoint == '_' || codepoint == ':' || codepoint >= 0x80u;
}

static bool lumina_xml_name_char(uint32_t codepoint) {
    return lumina_xml_name_start(codepoint) ||
           (codepoint >= '0' && codepoint <= '9') ||
           codepoint == '-' || codepoint == '.';
}

static bool lumina_xml_space(uint32_t codepoint) {
    return codepoint == ' ' || codepoint == '\t' ||
           codepoint == '\n' || codepoint == '\r';
}

static size_t lumina_xml_cursor_skip_space(XmlCodepointCursor *cursor) {
    size_t count = 0;
    XmlCodepoint codepoint;
    while (lumina_xml_cursor_peek(cursor, &codepoint) &&
           lumina_xml_space(codepoint.value)) {
        if (!lumina_xml_cursor_next(cursor, &codepoint)) break;
        count++;
    }
    return count;
}

static LuminaError lumina_xml_cursor_read_ascii_name(
    XmlCodepointCursor *cursor, unsigned char *name, size_t *name_len,
    size_t *raw_start, size_t *raw_end) {
    XmlCodepoint codepoint;
    if (!lumina_xml_cursor_peek(cursor, &codepoint) ||
        !lumina_xml_name_start(codepoint.value)) {
        return LUMINA_ERROR_REQBODY_MALFORMED;
    }
    if (codepoint.value > 0x7fu) return LUMINA_ERROR_REQBODY_UNSUPPORTED;

    size_t len = 0;
    size_t start = codepoint.start;
    size_t end = start;
    while (lumina_xml_cursor_peek(cursor, &codepoint) &&
           lumina_xml_name_char(codepoint.value)) {
        if (codepoint.value > 0x7fu) {
            return LUMINA_ERROR_REQBODY_UNSUPPORTED;
        }
        if (len == LUMINA_XML_MAX_DTD_NAME_LEN) {
            return LUMINA_ERROR_REQBODY_LIMIT;
        }
        if (!lumina_xml_cursor_next(cursor, &codepoint)) {
            return LUMINA_ERROR_REQBODY_MALFORMED;
        }
        name[len++] = (unsigned char)codepoint.value;
        end = codepoint.end;
    }
    *name_len = len;
    if (raw_start) *raw_start = start;
    if (raw_end) *raw_end = end;
    return LUMINA_ERROR_NONE;
}

static bool lumina_xml_dtd_entity_exists(const XmlDtdContext *dtd,
                                         const unsigned char *name,
                                         size_t name_len) {
    static const char *predefined[] = {"lt", "gt", "amp", "quot", "apos"};
    for (size_t i = 0; i < sizeof(predefined) / sizeof(predefined[0]); i++) {
        size_t len = strlen(predefined[i]);
        if (name_len == len && memcmp(name, predefined[i], len) == 0) {
            return true;
        }
    }
    for (unsigned i = 0; i < dtd->entity_count; i++) {
        const XmlDtdEntity *entity = &dtd->entities[i];
        if (entity->name_len == name_len &&
            memcmp(entity->name, name, name_len) == 0) {
            return true;
        }
    }
    return false;
}

static LUMINA_XML_COLD LuminaError lumina_xml_skip_dtd_comment(
    XmlCodepointCursor *cursor) {
    bool previous_dash = false;
    XmlCodepoint codepoint;
    while (lumina_xml_cursor_next(cursor, &codepoint)) {
        if (codepoint.value == '-' && previous_dash) {
            if (!lumina_xml_cursor_match_ascii(cursor, ">", 1)) {
                return LUMINA_ERROR_REQBODY_MALFORMED;
            }
            return LUMINA_ERROR_NONE;
        }
        previous_dash = codepoint.value == '-';
    }
    return LUMINA_ERROR_REQBODY_MALFORMED;
}

static LUMINA_XML_COLD LuminaError lumina_xml_parse_dtd_entity(
    XmlCodepointCursor *cursor, XmlDtdContext *dtd) {
    if (lumina_xml_cursor_skip_space(cursor) == 0) {
        return LUMINA_ERROR_REQBODY_MALFORMED;
    }

    XmlCodepoint codepoint;
    if (!lumina_xml_cursor_peek(cursor, &codepoint)) {
        return LUMINA_ERROR_REQBODY_MALFORMED;
    }
    if (codepoint.value == '%') {
        return LUMINA_ERROR_REQBODY_FORBIDDEN;
    }
    if (dtd->entity_count == LUMINA_XML_MAX_DTD_ENTITIES) {
        return LUMINA_ERROR_REQBODY_LIMIT;
    }

    unsigned char name[LUMINA_XML_MAX_DTD_NAME_LEN];
    size_t name_len = 0;
    LuminaError status = lumina_xml_cursor_read_ascii_name(
        cursor, name, &name_len, NULL, NULL);
    if (status != LUMINA_ERROR_NONE) return status;
    if (lumina_xml_dtd_entity_exists(dtd, name, name_len)) {
        return LUMINA_ERROR_REQBODY_MALFORMED;
    }
    if (lumina_xml_cursor_skip_space(cursor) == 0) {
        return LUMINA_ERROR_REQBODY_MALFORMED;
    }

    if (lumina_xml_cursor_match_ascii(cursor, "SYSTEM", 6) ||
        lumina_xml_cursor_match_ascii(cursor, "PUBLIC", 6)) {
        return LUMINA_ERROR_REQBODY_FORBIDDEN;
    }
    if (!lumina_xml_cursor_next(cursor, &codepoint) ||
        (codepoint.value != '\'' && codepoint.value != '"')) {
        return LUMINA_ERROR_REQBODY_MALFORMED;
    }

    uint32_t quote = codepoint.value;
    size_t value_start = cursor->pos;
    size_t value_end = value_start;
    bool closed = false;
    bool in_reference = false;
    size_t reference_len = 0;
    while (lumina_xml_cursor_next(cursor, &codepoint)) {
        if (!in_reference && codepoint.value == quote) {
            value_end = codepoint.start;
            closed = true;
            break;
        }
        if (++dtd->declaration_codepoints >
            LUMINA_XML_MAX_DTD_DECLARATION_CODEPOINTS) {
            return LUMINA_ERROR_REQBODY_LIMIT;
        }
        if (codepoint.value == '<') {
            return LUMINA_ERROR_REQBODY_MALFORMED;
        }
        if (codepoint.value == '%') {
            return LUMINA_ERROR_REQBODY_FORBIDDEN;
        }
        if (!in_reference && codepoint.value == '&') {
            in_reference = true;
            reference_len = 1;
            continue;
        }
        if (in_reference) {
            if (codepoint.value > 0x7fu ||
                lumina_xml_space(codepoint.value) ||
                codepoint.value == '&' ||
                ++reference_len > LUMINA_XML_MAX_ENTITY_LEN) {
                return LUMINA_ERROR_REQBODY_MALFORMED;
            }
            if (codepoint.value == ';') in_reference = false;
        }
    }
    if (!closed || in_reference) return LUMINA_ERROR_REQBODY_MALFORMED;
    lumina_xml_cursor_skip_space(cursor);
    if (!lumina_xml_cursor_next(cursor, &codepoint) ||
        codepoint.value != '>') {
        return LUMINA_ERROR_REQBODY_MALFORMED;
    }

    XmlDtdEntity *entity = &dtd->entities[dtd->entity_count++];
    memcpy(entity->name, name, name_len);
    entity->name_len = (unsigned char)name_len;
    entity->value_start = value_start;
    entity->value_end = value_end;
    return LUMINA_ERROR_NONE;
}

static LUMINA_XML_COLD LuminaError lumina_xml_parse_doctype(
    XmlCodepointCursor *cursor, XmlDtdContext *dtd) {
    if (dtd->present ||
        !lumina_xml_cursor_match_ascii(cursor, "OCTYPE", 6) ||
        lumina_xml_cursor_skip_space(cursor) == 0) {
        return LUMINA_ERROR_REQBODY_MALFORMED;
    }

    unsigned char root_name[LUMINA_XML_MAX_DTD_NAME_LEN];
    size_t root_name_len = 0;
    LuminaError status = lumina_xml_cursor_read_ascii_name(
        cursor, root_name, &root_name_len,
        &dtd->root_name_start, &dtd->root_name_end);
    if (status != LUMINA_ERROR_NONE) return status;
    (void)root_name;
    (void)root_name_len;

    lumina_xml_cursor_skip_space(cursor);
    XmlCodepoint codepoint;
    if (!lumina_xml_cursor_peek(cursor, &codepoint)) {
        return LUMINA_ERROR_REQBODY_MALFORMED;
    }
    if (codepoint.value == '>') {
        lumina_xml_cursor_next(cursor, &codepoint);
        dtd->present = true;
        return LUMINA_ERROR_NONE;
    }
    if (lumina_xml_cursor_match_ascii(cursor, "SYSTEM", 6) ||
        lumina_xml_cursor_match_ascii(cursor, "PUBLIC", 6)) {
        return LUMINA_ERROR_REQBODY_FORBIDDEN;
    }
    if (codepoint.value != '[') {
        return LUMINA_ERROR_REQBODY_MALFORMED;
    }
    lumina_xml_cursor_next(cursor, &codepoint);

    for (;;) {
        lumina_xml_cursor_skip_space(cursor);
        if (!lumina_xml_cursor_next(cursor, &codepoint)) {
            return LUMINA_ERROR_REQBODY_MALFORMED;
        }
        if (codepoint.value == '%') {
            return LUMINA_ERROR_REQBODY_FORBIDDEN;
        }
        if (codepoint.value == ']') {
            lumina_xml_cursor_skip_space(cursor);
            if (!lumina_xml_cursor_next(cursor, &codepoint) ||
                codepoint.value != '>') {
                return LUMINA_ERROR_REQBODY_MALFORMED;
            }
            dtd->present = true;
            return LUMINA_ERROR_NONE;
        }
        if (codepoint.value != '<' ||
            !lumina_xml_cursor_match_ascii(cursor, "!", 1)) {
            return LUMINA_ERROR_REQBODY_MALFORMED;
        }
        if (lumina_xml_cursor_match_ascii(cursor, "--", 2)) {
            status = lumina_xml_skip_dtd_comment(cursor);
        } else if (lumina_xml_cursor_match_ascii(cursor, "ENTITY", 6)) {
            status = lumina_xml_parse_dtd_entity(cursor, dtd);
        } else if (lumina_xml_cursor_match_ascii(cursor, "ATTLIST", 7) ||
                   lumina_xml_cursor_match_ascii(cursor, "ELEMENT", 7) ||
                   lumina_xml_cursor_match_ascii(cursor, "NOTATION", 8)) {
            status = LUMINA_ERROR_REQBODY_UNSUPPORTED;
        } else {
            status = LUMINA_ERROR_REQBODY_MALFORMED;
        }
        if (status != LUMINA_ERROR_NONE) return status;
    }
}

static bool lumina_xml_emit_codepoint(LuminaRuleState *state,
                                      unsigned codepoint) {
    unsigned char encoded[4];
    size_t len;
    if (!lumina_xml_codepoint_valid(codepoint)) return false;
    if (codepoint <= 0x7fu) {
        encoded[0] = (unsigned char)codepoint;
        len = 1;
    } else if (codepoint <= 0x7ffu) {
        encoded[0] = (unsigned char)(0xc0u | (codepoint >> 6));
        encoded[1] = (unsigned char)(0x80u | (codepoint & 0x3fu));
        len = 2;
    } else if (codepoint <= 0xffffu) {
        encoded[0] = (unsigned char)(0xe0u | (codepoint >> 12));
        encoded[1] = (unsigned char)(0x80u | ((codepoint >> 6) & 0x3fu));
        encoded[2] = (unsigned char)(0x80u | (codepoint & 0x3fu));
        len = 3;
    } else {
        encoded[0] = (unsigned char)(0xf0u | (codepoint >> 18));
        encoded[1] = (unsigned char)(0x80u | ((codepoint >> 12) & 0x3fu));
        encoded[2] = (unsigned char)(0x80u | ((codepoint >> 6) & 0x3fu));
        encoded[3] = (unsigned char)(0x80u | (codepoint & 0x3fu));
        len = 4;
    }
    lumina_xml_value_fragment(state, encoded, len);
    return !g_xml_value_overflow;
}

static bool lumina_xml_flush_value_run(
    LuminaRuleState *state, const XmlCodepointCursor *cursor,
    XmlValueRun *run) {
    if (!run->active) return true;
    lumina_xml_value_fragment(
        state, cursor->data + run->start, run->end - run->start);
    run->active = false;
    return !g_xml_value_overflow;
}

static bool lumina_xml_project_codepoint_slow(
    LuminaRuleState *state, const XmlCodepointCursor *cursor,
    const XmlCodepoint *codepoint, XmlValueRun *run) {
    if (cursor->encoding == XML_ENCODING_UTF8) {
        if (!run->active) {
            run->start = codepoint->start;
            run->end = codepoint->end;
            run->active = true;
        } else if (run->end == codepoint->start) {
            run->end = codepoint->end;
        } else {
            if (!lumina_xml_flush_value_run(state, cursor, run)) return false;
            run->start = codepoint->start;
            run->end = codepoint->end;
            run->active = true;
        }
        return true;
    }
    return lumina_xml_emit_codepoint(state, codepoint->value);
}

static LUMINA_XML_ALWAYS_INLINE bool lumina_xml_project_codepoint(
    LuminaRuleState *state, const XmlCodepointCursor *cursor,
    const XmlCodepoint *codepoint, XmlValueRun *run) {
    if (LUMINA_XML_LIKELY(cursor->encoding == XML_ENCODING_UTF8 &&
                          run->active &&
                          run->end == codepoint->start)) {
        run->end = codepoint->end;
        return true;
    }
    return lumina_xml_project_codepoint_slow(
        state, cursor, codepoint, run);
}

static bool lumina_xml_decode_builtin_entity(
    const unsigned char *entity, size_t len, uint32_t *decoded) {
    if (len == 4 && memcmp(entity, "&lt;", 4) == 0) {
        *decoded = '<';
        return true;
    }
    if (len == 4 && memcmp(entity, "&gt;", 4) == 0) {
        *decoded = '>';
        return true;
    }
    if (len == 5 && memcmp(entity, "&amp;", 5) == 0) {
        *decoded = '&';
        return true;
    }
    if (len == 6 && memcmp(entity, "&quot;", 6) == 0) {
        *decoded = '"';
        return true;
    }
    if (len == 6 && memcmp(entity, "&apos;", 6) == 0) {
        *decoded = '\'';
        return true;
    }
    if (len <= 3 || entity[0] != '&' || entity[1] != '#' ||
        entity[len - 1] != ';') {
        return false;
    }

    size_t i = 2;
    unsigned base = 10;
    if (i < len - 1 && (entity[i] == 'x' || entity[i] == 'X')) {
        base = 16;
        i++;
    }
    if (i == len - 1) return false;
    unsigned codepoint = 0;
    for (; i < len - 1; i++) {
        unsigned digit;
        unsigned char c = entity[i];
        if (c >= '0' && c <= '9') digit = c - '0';
        else if (base == 16 && c >= 'a' && c <= 'f') digit = c - 'a' + 10u;
        else if (base == 16 && c >= 'A' && c <= 'F') digit = c - 'A' + 10u;
        else return false;
        if (codepoint > (0x10ffffu - digit) / base) return false;
        codepoint = codepoint * base + digit;
    }
    if (!lumina_xml_codepoint_valid(codepoint)) return false;
    *decoded = codepoint;
    return true;
}

static int lumina_xml_dtd_find_entity(const XmlDtdContext *dtd,
                                      const unsigned char *name,
                                      size_t name_len) {
    for (unsigned i = 0; i < dtd->entity_count; i++) {
        const XmlDtdEntity *entity = &dtd->entities[i];
        if (entity->name_len == name_len &&
            memcmp(entity->name, name, name_len) == 0) {
            return (int)i;
        }
    }
    return -1;
}

static LuminaError lumina_xml_cursor_read_reference(
    XmlCodepointCursor *cursor, unsigned char *reference,
    size_t *reference_len) {
    size_t len = 1;
    reference[0] = '&';
    XmlCodepoint codepoint;
    while (lumina_xml_cursor_next(cursor, &codepoint)) {
        if (codepoint.value > 0x7fu ||
            lumina_xml_space(codepoint.value) ||
            codepoint.value == '<' || codepoint.value == '&' ||
            len == LUMINA_XML_MAX_ENTITY_LEN) {
            return LUMINA_ERROR_REQBODY_MALFORMED;
        }
        reference[len++] = (unsigned char)codepoint.value;
        if (codepoint.value == ';') {
            *reference_len = len;
            return LUMINA_ERROR_NONE;
        }
    }
    return LUMINA_ERROR_REQBODY_MALFORMED;
}

static LuminaError lumina_xml_validate_dtd_entity(
    const XmlDtdContext *dtd, unsigned index, unsigned depth,
    uint32_t active, uint32_t *validated) {
    uint32_t bit = 1u << index;
    if (*validated & bit) return LUMINA_ERROR_NONE;
    if (active & bit) return LUMINA_ERROR_REQBODY_MALFORMED;
    if (depth >= LUMINA_XML_MAX_DTD_EXPANSION_DEPTH) {
        return LUMINA_ERROR_REQBODY_LIMIT;
    }

    const XmlDtdEntity *entity = &dtd->entities[index];
    XmlCodepointCursor cursor = {
        .data = dtd->data,
        .len = entity->value_end,
        .pos = entity->value_start,
        .encoding = dtd->encoding,
        .bom = false,
        .error = false,
    };
    XmlCodepoint codepoint;
    while (lumina_xml_cursor_next(&cursor, &codepoint)) {
        if (codepoint.value == '<') {
            return LUMINA_ERROR_REQBODY_MALFORMED;
        }
        if (codepoint.value == '%') {
            return LUMINA_ERROR_REQBODY_FORBIDDEN;
        }
        if (codepoint.value != '&') continue;

        unsigned char reference[LUMINA_XML_MAX_ENTITY_LEN];
        size_t reference_len = 0;
        LuminaError status = lumina_xml_cursor_read_reference(
            &cursor, reference, &reference_len);
        if (status != LUMINA_ERROR_NONE) return status;

        uint32_t decoded;
        if (lumina_xml_decode_builtin_entity(
                reference, reference_len, &decoded)) {
            continue;
        }
        if (reference_len < 3 || reference[1] == '#') {
            return LUMINA_ERROR_REQBODY_MALFORMED;
        }
        int child = lumina_xml_dtd_find_entity(
            dtd, reference + 1, reference_len - 2);
        if (child < 0) return LUMINA_ERROR_REQBODY_MALFORMED;
        status = lumina_xml_validate_dtd_entity(
            dtd, (unsigned)child, depth + 1, active | bit, validated);
        if (status != LUMINA_ERROR_NONE) return status;
    }
    if (cursor.error) return LUMINA_ERROR_REQBODY_MALFORMED;
    *validated |= bit;
    return LUMINA_ERROR_NONE;
}

static LuminaError lumina_xml_validate_dtd(XmlDtdContext *dtd) {
    uint32_t validated = 0;
    for (unsigned i = 0; i < dtd->entity_count; i++) {
        LuminaError status = lumina_xml_validate_dtd_entity(
            dtd, i, 0, 0, &validated);
        if (status != LUMINA_ERROR_NONE) return status;
    }
    return LUMINA_ERROR_NONE;
}

static size_t lumina_xml_utf8_codepoint_len(uint32_t codepoint) {
    if (codepoint <= 0x7fu) return 1;
    if (codepoint <= 0x7ffu) return 2;
    if (codepoint <= 0xffffu) return 3;
    return 4;
}

static LuminaError lumina_xml_emit_expanded_codepoint(
    LuminaRuleState *state, XmlDtdContext *dtd, uint32_t codepoint) {
    size_t encoded_len = lumina_xml_utf8_codepoint_len(codepoint);
    if (dtd->expanded_bytes > dtd->expansion_limit ||
        encoded_len > dtd->expansion_limit - dtd->expanded_bytes) {
        return LUMINA_ERROR_REQBODY_LIMIT;
    }
    if (!lumina_xml_emit_codepoint(state, codepoint)) {
        return LUMINA_ERROR_REQBODY_LIMIT;
    }
    dtd->expanded_bytes += encoded_len;
    return LUMINA_ERROR_NONE;
}

static LuminaError lumina_xml_expand_reference(
    LuminaRuleState *state, XmlDtdContext *dtd,
    const unsigned char *reference, size_t reference_len,
    unsigned depth, uint32_t active);

static LuminaError lumina_xml_expand_dtd_entity(
    LuminaRuleState *state, XmlDtdContext *dtd, unsigned index,
    unsigned depth, uint32_t active) {
    uint32_t bit = 1u << index;
    if (active & bit) return LUMINA_ERROR_REQBODY_MALFORMED;
    if (depth >= LUMINA_XML_MAX_DTD_EXPANSION_DEPTH) {
        return LUMINA_ERROR_REQBODY_LIMIT;
    }

    const XmlDtdEntity *entity = &dtd->entities[index];
    XmlCodepointCursor cursor = {
        .data = dtd->data,
        .len = entity->value_end,
        .pos = entity->value_start,
        .encoding = dtd->encoding,
        .bom = false,
        .error = false,
    };
    XmlCodepoint codepoint;
    while (lumina_xml_cursor_next(&cursor, &codepoint)) {
        if (codepoint.value == '&') {
            unsigned char reference[LUMINA_XML_MAX_ENTITY_LEN];
            size_t reference_len = 0;
            LuminaError status = lumina_xml_cursor_read_reference(
                &cursor, reference, &reference_len);
            if (status != LUMINA_ERROR_NONE) return status;
            status = lumina_xml_expand_reference(
                state, dtd, reference, reference_len,
                depth + 1, active | bit);
            if (status != LUMINA_ERROR_NONE) return status;
        } else {
            LuminaError status = lumina_xml_emit_expanded_codepoint(
                state, dtd, codepoint.value);
            if (status != LUMINA_ERROR_NONE) return status;
        }
    }
    return cursor.error ? LUMINA_ERROR_REQBODY_MALFORMED
                        : LUMINA_ERROR_NONE;
}

static LuminaError lumina_xml_expand_reference(
    LuminaRuleState *state, XmlDtdContext *dtd,
    const unsigned char *reference, size_t reference_len,
    unsigned depth, uint32_t active) {
    uint32_t decoded;
    if (lumina_xml_decode_builtin_entity(
            reference, reference_len, &decoded)) {
        return lumina_xml_emit_expanded_codepoint(state, dtd, decoded);
    }
    if (reference_len < 3 || reference[0] != '&' ||
        reference[reference_len - 1] != ';' ||
        reference[1] == '#') {
        return LUMINA_ERROR_REQBODY_MALFORMED;
    }
    int index = lumina_xml_dtd_find_entity(
        dtd, reference + 1, reference_len - 2);
    if (index < 0) return LUMINA_ERROR_REQBODY_MALFORMED;
    return lumina_xml_expand_dtd_entity(
        state, dtd, (unsigned)index, depth, active);
}

static bool lumina_xml_dtd_root_matches(
    const XmlDtdContext *dtd, const unsigned char *data,
    size_t element_start, size_t element_end) {
    if (!dtd->present) return true;
    size_t dtd_len = dtd->root_name_end - dtd->root_name_start;
    size_t element_len = element_end - element_start;
    return dtd_len == element_len &&
           memcmp(data + dtd->root_name_start,
                  data + element_start, element_len) == 0;
}

LuminaError lumina_parse_and_scan_xml(const unsigned char *data, size_t len,
                                      LuminaRuleState *state, int *threat) {
    if (!data || len == 0 || !state) return LUMINA_ERROR_REQBODY_MALFORMED;
    g_xml_threat = 0;
    g_xml_value_overflow = false;

    XmlCodepointCursor cursor;
    if (!lumina_xml_cursor_init(&cursor, data, len)) {
        return LUMINA_ERROR_REQBODY_MALFORMED;
    }
    LuminaError encoding_status =
        lumina_xml_validate_encoding_declaration(&cursor);
    if (encoding_status != LUMINA_ERROR_NONE) return encoding_status;
    size_t expansion_limit =
        len > LUMINA_XML_MAX_DTD_EXPANDED_BYTES / 2
            ? LUMINA_XML_MAX_DTD_EXPANDED_BYTES
            : len * 2;
    XmlDtdContext dtd;
    dtd.data = data;
    dtd.root_name_start = 0;
    dtd.root_name_end = 0;
    dtd.declaration_codepoints = 0;
    dtd.expanded_bytes = 0;
    dtd.expansion_limit = expansion_limit;
    dtd.encoding = cursor.encoding;
    dtd.entity_count = 0;
    dtd.present = false;

    XmlState current_state = XML_STATE_TEXT;
    XmlState pre_entity_state = XML_STATE_TEXT;

    size_t tag_name_start = 0;
    size_t end_tag_name_start = 0;
    size_t tag_starts[LUMINA_XML_MAX_NESTING];
    size_t tag_lens[LUMINA_XML_MAX_NESTING];
    unsigned char entity[LUMINA_XML_MAX_ENTITY_LEN + 1];
    size_t entity_len = 0;
    XmlValueRun value_run = {0, 0, false};
    bool saw_root = false;
    bool root_closed = false;

    int depth = 0;
    int attr_count = 0;

    lumina_xml_value_begin(state, LUMINA_VAR_XML);

    XmlCodepoint token;
    while (cursor.pos < cursor.len) {
        if (current_state == XML_STATE_TEXT && depth > 0 &&
            cursor.encoding == XML_ENCODING_UTF8 &&
            lumina_xml_cursor_project_utf8_text_run(&cursor, state)) {
            continue;
        }
        if (!lumina_xml_cursor_next(&cursor, &token)) break;
        uint32_t c = token.value;
        switch (current_state) {
            case XML_STATE_TEXT:
                if (c == '<') {
                    if (!lumina_xml_flush_value_run(
                            state, &cursor, &value_run)) {
                        return LUMINA_ERROR_REQBODY_LIMIT;
                    }
                    current_state = XML_STATE_TAG_OPEN;
                } else if (c == '&') {
                    if (depth == 0) return LUMINA_ERROR_REQBODY_MALFORMED;
                    if (!lumina_xml_flush_value_run(
                            state, &cursor, &value_run)) {
                        return LUMINA_ERROR_REQBODY_LIMIT;
                    }
                    entity[0] = '&';
                    entity_len = 1;
                    pre_entity_state = XML_STATE_TEXT;
                    current_state = XML_STATE_ENTITY_TEXT;
                } else if (depth == 0 &&
                           !lumina_xml_space(c)) {
                    return LUMINA_ERROR_REQBODY_MALFORMED;
                } else if (!lumina_xml_project_codepoint(
                               state, &cursor, &token, &value_run)) {
                    return LUMINA_ERROR_REQBODY_LIMIT;
                }
                break;
            case XML_STATE_TAG_OPEN:
                if (c == '/') {
                    if (depth <= 0) return LUMINA_ERROR_REQBODY_MALFORMED;
                    end_tag_name_start = token.end;
                    current_state = XML_STATE_END_TAG_NAME;
                } else if (c == '!') {
                    current_state = XML_STATE_COMMENT_START_1;
                } else if (c == '?') {
                    current_state = XML_STATE_PI_OR_XML_DECL;
                } else {
                    if (root_closed || c == '>' || c == '/' ||
                        lumina_xml_space(c) ||
                        !lumina_xml_name_start(c)) {
                        return LUMINA_ERROR_REQBODY_MALFORMED;
                    }
                    if (depth == 0) {
                        if (saw_root) return LUMINA_ERROR_REQBODY_MALFORMED;
                        saw_root = true;
                    }
                    tag_name_start = token.start;
                    current_state = XML_STATE_START_TAG_NAME;
                    attr_count = 0;
                }
                break;
            case XML_STATE_START_TAG_NAME:
                if (lumina_xml_space(c)) {
                    if (token.start == tag_name_start) {
                        return LUMINA_ERROR_REQBODY_MALFORMED;
                    }
                    if (depth == 0 &&
                        !lumina_xml_dtd_root_matches(
                            &dtd, data, tag_name_start, token.start)) {
                        return LUMINA_ERROR_REQBODY_MALFORMED;
                    }
                    if (depth >= LUMINA_XML_MAX_NESTING) {
                        return LUMINA_ERROR_REQBODY_LIMIT;
                    }
                    tag_starts[depth] = tag_name_start;
                    tag_lens[depth] = token.start - tag_name_start;
                    depth++;
                    current_state = XML_STATE_BETWEEN_ATTRIBUTES;
                } else if (c == '>') {
                    if (token.start == tag_name_start) {
                        return LUMINA_ERROR_REQBODY_MALFORMED;
                    }
                    if (depth == 0 &&
                        !lumina_xml_dtd_root_matches(
                            &dtd, data, tag_name_start, token.start)) {
                        return LUMINA_ERROR_REQBODY_MALFORMED;
                    }
                    if (depth >= LUMINA_XML_MAX_NESTING) {
                        return LUMINA_ERROR_REQBODY_LIMIT;
                    }
                    tag_starts[depth] = tag_name_start;
                    tag_lens[depth] = token.start - tag_name_start;
                    depth++;
                    current_state = XML_STATE_TEXT;
                } else if (c == '/') {
                    if (token.start == tag_name_start) {
                        return LUMINA_ERROR_REQBODY_MALFORMED;
                    }
                    if (depth == 0 &&
                        !lumina_xml_dtd_root_matches(
                            &dtd, data, tag_name_start, token.start)) {
                        return LUMINA_ERROR_REQBODY_MALFORMED;
                    }
                    if (depth >= LUMINA_XML_MAX_NESTING) {
                        return LUMINA_ERROR_REQBODY_LIMIT;
                    }
                    tag_starts[depth] = tag_name_start;
                    tag_lens[depth] = token.start - tag_name_start;
                    depth++;
                    current_state = XML_STATE_SELF_CLOSE;
                } else if (!lumina_xml_name_char(c)) {
                    return LUMINA_ERROR_REQBODY_MALFORMED;
                }
                break;
            case XML_STATE_END_TAG_NAME:
                if (c == '>') {
                    size_t name_len = token.start - end_tag_name_start;
                    if (name_len == 0 || depth <= 0 ||
                        tag_lens[depth - 1] != name_len ||
                        memcmp(data + tag_starts[depth - 1],
                               data + end_tag_name_start, name_len) != 0) {
                        return LUMINA_ERROR_REQBODY_MALFORMED;
                    }
                    depth--;
                    if (depth == 0) root_closed = true;
                    current_state = XML_STATE_TEXT;
                    if (!lumina_xml_flush_value_run(
                            state, &cursor, &value_run)) {
                        return LUMINA_ERROR_REQBODY_LIMIT;
                    }
                    lumina_xml_value_end(state);
                    lumina_xml_value_begin(state, LUMINA_VAR_XML);
                } else if (lumina_xml_space(c) || c == '<' || c == '/' ||
                           !lumina_xml_name_char(c) ||
                           (token.start == end_tag_name_start &&
                            !lumina_xml_name_start(c))) {
                    return LUMINA_ERROR_REQBODY_MALFORMED;
                }
                break;
            case XML_STATE_BETWEEN_ATTRIBUTES:
                if (c == '>') {
                    current_state = XML_STATE_TEXT;
                } else if (c == '/') {
                    current_state = XML_STATE_SELF_CLOSE;
                } else if (!lumina_xml_space(c)) {
                    if (!lumina_xml_name_start(c)) {
                        return LUMINA_ERROR_REQBODY_MALFORMED;
                    }
                    current_state = XML_STATE_ATTRIBUTE_NAME;
                }
                break;
            case XML_STATE_ATTRIBUTE_NAME:
                if (c == '=') {
                    current_state = XML_STATE_BEFORE_ATTRIBUTE_VALUE;
                    attr_count++;
                    if (attr_count > LUMINA_XML_MAX_ATTRIBUTES) {
                        return LUMINA_ERROR_REQBODY_LIMIT;
                    }
                } else if (lumina_xml_space(c)) {
                    current_state = XML_STATE_AFTER_ATTRIBUTE_NAME;
                } else if (c == '>' || c == '/' || c == '<' || c == '"' ||
                           c == '\'' || !lumina_xml_name_char(c)) {
                    return LUMINA_ERROR_REQBODY_MALFORMED;
                }
                break;
            case XML_STATE_AFTER_ATTRIBUTE_NAME:
                if (c == '=') {
                    current_state = XML_STATE_BEFORE_ATTRIBUTE_VALUE;
                    attr_count++;
                    if (attr_count > LUMINA_XML_MAX_ATTRIBUTES) {
                        return LUMINA_ERROR_REQBODY_LIMIT;
                    }
                } else if (!lumina_xml_space(c)) {
                    return LUMINA_ERROR_REQBODY_MALFORMED;
                }
                break;
            case XML_STATE_BEFORE_ATTRIBUTE_VALUE:
                if (c == '\'') {
                    if (!lumina_xml_flush_value_run(
                            state, &cursor, &value_run)) {
                        return LUMINA_ERROR_REQBODY_LIMIT;
                    }
                    current_state = XML_STATE_ATTRIBUTE_VALUE_SINGLE;
                    lumina_xml_value_end(state);
                    lumina_xml_value_begin(state, LUMINA_VAR_XML_ATTR);
                } else if (c == '"') {
                    if (!lumina_xml_flush_value_run(
                            state, &cursor, &value_run)) {
                        return LUMINA_ERROR_REQBODY_LIMIT;
                    }
                    current_state = XML_STATE_ATTRIBUTE_VALUE_DOUBLE;
                    lumina_xml_value_end(state);
                    lumina_xml_value_begin(state, LUMINA_VAR_XML_ATTR);
                } else if (!lumina_xml_space(c)) {
                    return LUMINA_ERROR_REQBODY_MALFORMED;
                }
                break;
            case XML_STATE_ATTRIBUTE_VALUE_SINGLE:
                if (c == '\'') {
                    if (!lumina_xml_flush_value_run(
                            state, &cursor, &value_run)) {
                        return LUMINA_ERROR_REQBODY_LIMIT;
                    }
                    lumina_xml_value_end(state);
                    lumina_xml_value_begin(state, LUMINA_VAR_XML);
                    current_state = XML_STATE_BETWEEN_ATTRIBUTES;
                } else if (c == '&') {
                    if (!lumina_xml_flush_value_run(
                            state, &cursor, &value_run)) {
                        return LUMINA_ERROR_REQBODY_LIMIT;
                    }
                    entity[0] = '&';
                    entity_len = 1;
                    pre_entity_state = XML_STATE_ATTRIBUTE_VALUE_SINGLE;
                    current_state = XML_STATE_ENTITY_ATTR_S;
                } else if (!lumina_xml_project_codepoint(
                               state, &cursor, &token, &value_run)) {
                    return LUMINA_ERROR_REQBODY_LIMIT;
                }
                break;
            case XML_STATE_ATTRIBUTE_VALUE_DOUBLE:
                if (c == '"') {
                    if (!lumina_xml_flush_value_run(
                            state, &cursor, &value_run)) {
                        return LUMINA_ERROR_REQBODY_LIMIT;
                    }
                    lumina_xml_value_end(state);
                    lumina_xml_value_begin(state, LUMINA_VAR_XML);
                    current_state = XML_STATE_BETWEEN_ATTRIBUTES;
                } else if (c == '&') {
                    if (!lumina_xml_flush_value_run(
                            state, &cursor, &value_run)) {
                        return LUMINA_ERROR_REQBODY_LIMIT;
                    }
                    entity[0] = '&';
                    entity_len = 1;
                    pre_entity_state = XML_STATE_ATTRIBUTE_VALUE_DOUBLE;
                    current_state = XML_STATE_ENTITY_ATTR_D;
                } else if (!lumina_xml_project_codepoint(
                               state, &cursor, &token, &value_run)) {
                    return LUMINA_ERROR_REQBODY_LIMIT;
                }
                break;
            case XML_STATE_ENTITY_TEXT:
            case XML_STATE_ENTITY_ATTR_S:
            case XML_STATE_ENTITY_ATTR_D:
                if (c > 0x7fu || entity_len == sizeof(entity)) {
                    return LUMINA_ERROR_REQBODY_MALFORMED;
                }
                entity[entity_len++] = (unsigned char)c;
                if (c == ';') {
                    LuminaError entity_status = lumina_xml_expand_reference(
                        state, &dtd, entity, entity_len, 0, 0);
                    if (entity_status != LUMINA_ERROR_NONE) {
                        return entity_status;
                    }
                    current_state = pre_entity_state;
                } else if (c == '<' || lumina_xml_space(c)) {
                    return LUMINA_ERROR_REQBODY_MALFORMED;
                }
                break;
            case XML_STATE_COMMENT_START_1:
                if (c == '-') current_state = XML_STATE_COMMENT_START_2;
                else if (c == '[') current_state = XML_STATE_CDATA_START_1;
                else if (c == 'D') {
                    if (depth != 0 || saw_root || root_closed) {
                        return LUMINA_ERROR_REQBODY_MALFORMED;
                    }
                    LuminaError dtd_status =
                        lumina_xml_parse_doctype(&cursor, &dtd);
                    if (dtd_status != LUMINA_ERROR_NONE) return dtd_status;
                    dtd_status = lumina_xml_validate_dtd(&dtd);
                    if (dtd_status != LUMINA_ERROR_NONE) return dtd_status;
                    current_state = XML_STATE_TEXT;
                }
                else return LUMINA_ERROR_REQBODY_MALFORMED;
                break;
            case XML_STATE_COMMENT_START_2:
                if (c == '-') current_state = XML_STATE_COMMENT;
                else return LUMINA_ERROR_REQBODY_MALFORMED;
                break;
            case XML_STATE_COMMENT:
                if (c == '-' &&
                    lumina_xml_cursor_match_ascii(&cursor, "->", 2)) {
                    current_state = XML_STATE_TEXT;
                } else if (c == '-') {
                    XmlCodepoint next;
                    if (lumina_xml_cursor_peek(&cursor, &next) &&
                        next.value == '-') {
                        return LUMINA_ERROR_REQBODY_MALFORMED;
                    }
                }
                break;
            case XML_STATE_CDATA_START_1: if (c == 'C') current_state = XML_STATE_CDATA_START_2; else return LUMINA_ERROR_REQBODY_MALFORMED; break;
            case XML_STATE_CDATA_START_2: if (c == 'D') current_state = XML_STATE_CDATA_START_3; else return LUMINA_ERROR_REQBODY_MALFORMED; break;
            case XML_STATE_CDATA_START_3: if (c == 'A') current_state = XML_STATE_CDATA_START_4; else return LUMINA_ERROR_REQBODY_MALFORMED; break;
            case XML_STATE_CDATA_START_4: if (c == 'T') current_state = XML_STATE_CDATA_START_5; else return LUMINA_ERROR_REQBODY_MALFORMED; break;
            case XML_STATE_CDATA_START_5: if (c == 'A') current_state = XML_STATE_CDATA_START_6; else return LUMINA_ERROR_REQBODY_MALFORMED; break;
            case XML_STATE_CDATA_START_6: 
                if (c == '[') {
                    if (depth == 0) return LUMINA_ERROR_REQBODY_MALFORMED;
                    current_state = XML_STATE_CDATA;
                } else return LUMINA_ERROR_REQBODY_MALFORMED;
                break;
            case XML_STATE_CDATA:
                if (c == ']' &&
                    lumina_xml_cursor_match_ascii(&cursor, "]>", 2)) {
                    if (!lumina_xml_flush_value_run(
                            state, &cursor, &value_run)) {
                        return LUMINA_ERROR_REQBODY_LIMIT;
                    }
                    current_state = XML_STATE_TEXT;
                } else if (!lumina_xml_project_codepoint(
                               state, &cursor, &token, &value_run)) {
                    return LUMINA_ERROR_REQBODY_LIMIT;
                }
                break;
            case XML_STATE_PI_OR_XML_DECL:
                if (c == '?' &&
                    lumina_xml_cursor_match_ascii(&cursor, ">", 1)) {
                    current_state = XML_STATE_TEXT;
                }
                break;
            case XML_STATE_SELF_CLOSE:
                if (c != '>' || depth <= 0) {
                    return LUMINA_ERROR_REQBODY_MALFORMED;
                }
                depth--;
                if (depth == 0) root_closed = true;
                current_state = XML_STATE_TEXT;
                break;
            default:
                break;
        }
    }

    if (cursor.error) return LUMINA_ERROR_REQBODY_MALFORMED;
    if (current_state != XML_STATE_TEXT || depth != 0 ||
        !saw_root || !root_closed) {
        return LUMINA_ERROR_REQBODY_MALFORMED;
    }
    if (!lumina_xml_flush_value_run(state, &cursor, &value_run)) {
        return LUMINA_ERROR_REQBODY_LIMIT;
    }
    lumina_xml_value_end(state);
    if (g_xml_value_overflow) return LUMINA_ERROR_REQBODY_LIMIT;
    if (threat) *threat = g_xml_threat;
    return LUMINA_ERROR_NONE;
}

int lumina_scan_xml_avx2(const unsigned char *data, size_t len,
                         LuminaRuleState *state) {
    int threat = 0;
    LuminaError status =
        lumina_parse_and_scan_xml(data, len, state, &threat);
    return status == LUMINA_ERROR_NONE ? threat : -1;
}
