#include "lumina_xml_parser.h"
#include <string.h>
#if defined(__AVX2__)
#include <immintrin.h>
#endif

/* Limits for Zero-Allocation Extractor */
#define LUMINA_XML_MAX_NESTING 128
#define LUMINA_XML_MAX_ATTRIBUTES 256
#define LUMINA_XML_MAX_ENTITY_LEN 16
#define LUMINA_XML_MAX_VALUE_LEN (1024 * 1024) /* 1MB */

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
    XML_STATE_DOCTYPE,
    XML_STATE_ENTITY_TEXT,
    XML_STATE_ENTITY_ATTR_S,
    XML_STATE_ENTITY_ATTR_D
} XmlState;

bool lumina_is_xml_part(const unsigned char *content_type, size_t content_type_len,
                        const unsigned char *filename, size_t filename_len,
                        const unsigned char *body, size_t body_len) {
    if (content_type && content_type_len > 0) {
        if (content_type_len >= 8 && memcmp(content_type + content_type_len - 8, "text/xml", 8) == 0) return true;
        if (content_type_len >= 15 && memcmp(content_type + content_type_len - 15, "application/xml", 15) == 0) return true;
        if (content_type_len >= 4 && memcmp(content_type + content_type_len - 4, "+xml", 4) == 0) return true;
    }
    if (filename && filename_len > 0) {
        if (filename_len >= 4 && (memcmp(filename + filename_len - 4, ".xml", 4) == 0 ||
                                  memcmp(filename + filename_len - 4, ".xsd", 4) == 0 ||
                                  memcmp(filename + filename_len - 4, ".xsl", 4) == 0 ||
                                  memcmp(filename + filename_len - 4, ".svg", 4) == 0)) return true;
        if (filename_len >= 5 && (memcmp(filename + filename_len - 5, ".xslt", 5) == 0 ||
                                  memcmp(filename + filename_len - 5, ".wsdl", 5) == 0)) return true;
    }
    // Sniffing (limit to 256 bytes)
    size_t scan_len = body_len < 256 ? body_len : 256;
    for (size_t i = 0; i < scan_len; i++) {
        if (body[i] == ' ' || body[i] == '\t' || body[i] == '\r' || body[i] == '\n') continue;
        if (body[i] == '<') {
            if (i + 4 < body_len && memcmp(body + i, "<?xml", 5) == 0) return true;
            // Optionally, just returning true on `<` might be too aggressive, but since we restrict to part boundaries, it's safer.
        }
        break; // First non-whitespace is not '<'
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

static inline void handle_entity(LuminaRuleState *state, const unsigned char *entity, size_t len) {
    if (len == 4 && memcmp(entity, "&lt;", 4) == 0) lumina_xml_value_fragment(state, (const unsigned char*)"<", 1);
    else if (len == 4 && memcmp(entity, "&gt;", 4) == 0) lumina_xml_value_fragment(state, (const unsigned char*)">", 1);
    else if (len == 5 && memcmp(entity, "&amp;", 5) == 0) lumina_xml_value_fragment(state, (const unsigned char*)"&", 1);
    else if (len == 6 && memcmp(entity, "&quot;", 6) == 0) lumina_xml_value_fragment(state, (const unsigned char*)"\"", 1);
    else if (len == 6 && memcmp(entity, "&apos;", 6) == 0) lumina_xml_value_fragment(state, (const unsigned char*)"'", 1);
    else if (len > 3 && entity[0] == '&' && entity[1] == '#') {
        int val = 0;
        size_t i = 2;
        if (entity[2] == 'x' || entity[2] == 'X') {
            i = 3;
            for (; i < len - 1; i++) {
                char c = entity[i];
                if (c >= '0' && c <= '9') val = val * 16 + (c - '0');
                else if (c >= 'a' && c <= 'f') val = val * 16 + (c - 'a' + 10);
                else if (c >= 'A' && c <= 'F') val = val * 16 + (c - 'A' + 10);
                else break;
            }
        } else {
            for (; i < len - 1; i++) {
                char c = entity[i];
                if (c >= '0' && c <= '9') val = val * 10 + (c - '0');
                else break;
            }
        }
        if (val > 0 && val <= 255) {
            unsigned char c = (unsigned char)val;
            lumina_xml_value_fragment(state, &c, 1);
        } else if (val > 255) {
            // Simplified UTF-8 encoding for numerical entities (just pass the raw entity if we don't fully decode UTF-8 numericals here, or implement a basic UTF-8 encoder)
            // For now, let's just pass the entity verbatim if we don't handle it.
            lumina_xml_value_fragment(state, entity, len);
        }
    } else {
        lumina_xml_value_fragment(state, entity, len); // Fallback: pass as is
    }
}

int lumina_scan_xml_avx2(const unsigned char *data, size_t len, LuminaRuleState *state) {
    if (!data || len == 0) return 0;
    g_xml_threat = 0;
    
    // Check for UTF-16 (BOM)
    if (len >= 2 && ((data[0] == 0xFF && data[1] == 0xFE) || (data[0] == 0xFE && data[1] == 0xFF))) {
        return -1; // LIMIT_EXCEEDED / UNSUPPORTED
    }
    
    XmlState current_state = XML_STATE_TEXT;
    XmlState pre_entity_state = XML_STATE_TEXT;
    
    size_t i = 0;
    size_t text_start = 0;
    size_t entity_start = 0;
    
    int depth = 0;
    int attr_count = 0;
    
    lumina_xml_value_begin(state, LUMINA_VAR_XML);
    
    while (i < len) {
        /* Optional delimiter search acceleration. The state machine below is
         * the architecture-neutral semantic path used on x86_64 and ARM64. */
#if defined(__AVX2__)
        if (current_state == XML_STATE_TEXT || current_state == XML_STATE_ATTRIBUTE_VALUE_SINGLE || current_state == XML_STATE_ATTRIBUTE_VALUE_DOUBLE || current_state == XML_STATE_CDATA) {
            while (i + 31 < len) {
                __m256i chunk = _mm256_loadu_si256((const __m256i*)(data + i));
                __m256i cmp_lt = _mm256_cmpeq_epi8(chunk, _mm256_set1_epi8('<'));
                __m256i cmp_gt = _mm256_cmpeq_epi8(chunk, _mm256_set1_epi8('>'));
                __m256i cmp_amp = _mm256_cmpeq_epi8(chunk, _mm256_set1_epi8('&'));
                __m256i cmp_sq = _mm256_cmpeq_epi8(chunk, _mm256_set1_epi8('\''));
                __m256i cmp_dq = _mm256_cmpeq_epi8(chunk, _mm256_set1_epi8('"'));
                __m256i cmp_rsb = _mm256_cmpeq_epi8(chunk, _mm256_set1_epi8(']'));
                
                __m256i mask_vec = _mm256_or_si256(cmp_lt, cmp_gt);
                mask_vec = _mm256_or_si256(mask_vec, cmp_amp);
                mask_vec = _mm256_or_si256(mask_vec, cmp_sq);
                mask_vec = _mm256_or_si256(mask_vec, cmp_dq);
                mask_vec = _mm256_or_si256(mask_vec, cmp_rsb);
                
                uint32_t mask = _mm256_movemask_epi8(mask_vec);
                if (mask == 0) {
                    i += 32;
                } else {
                    i += __builtin_ctz(mask);
                    break;
                }
            }
        }
#endif
        
        if (i >= len) break;
        
        unsigned char c = data[i];
        
        switch (current_state) {
            case XML_STATE_TEXT:
                if (c == '<') {
                    if (i > text_start) lumina_xml_value_fragment(state, data + text_start, i - text_start);
                    current_state = XML_STATE_TAG_OPEN;
                } else if (c == '&') {
                    if (i > text_start) lumina_xml_value_fragment(state, data + text_start, i - text_start);
                    entity_start = i;
                    pre_entity_state = XML_STATE_TEXT;
                    current_state = XML_STATE_ENTITY_TEXT;
                }
                break;
            case XML_STATE_TAG_OPEN:
                if (c == '/') {
                    current_state = XML_STATE_END_TAG_NAME;
                    depth--;
                } else if (c == '!') {
                    current_state = XML_STATE_COMMENT_START_1;
                } else if (c == '?') {
                    current_state = XML_STATE_PI_OR_XML_DECL;
                } else {
                    current_state = XML_STATE_START_TAG_NAME;
                    depth++;
                    if (depth > LUMINA_XML_MAX_NESTING) return -1;
                    attr_count = 0;
                }
                break;
            case XML_STATE_START_TAG_NAME:
                if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                    current_state = XML_STATE_BETWEEN_ATTRIBUTES;
                } else if (c == '>') {
                    current_state = XML_STATE_TEXT;
                    text_start = i + 1;
                } else if (c == '/') {
                    current_state = XML_STATE_TEXT;
                    depth--; // Self closing
                }
                break;
            case XML_STATE_END_TAG_NAME:
                if (c == '>') {
                    current_state = XML_STATE_TEXT;
                    text_start = i + 1;
                    lumina_xml_value_end(state); // Evaluate the logic stream for the element
                    lumina_xml_value_begin(state, LUMINA_VAR_XML); // Begin new stream
                }
                break;
            case XML_STATE_BETWEEN_ATTRIBUTES:
                if (c == '>') {
                    current_state = XML_STATE_TEXT;
                    text_start = i + 1;
                } else if (c == '/') {
                    current_state = XML_STATE_TEXT;
                    depth--; // Self closing
                } else if (c != ' ' && c != '\t' && c != '\n' && c != '\r') {
                    current_state = XML_STATE_ATTRIBUTE_NAME;
                }
                break;
            case XML_STATE_ATTRIBUTE_NAME:
                if (c == '=') {
                    current_state = XML_STATE_BEFORE_ATTRIBUTE_VALUE;
                    attr_count++;
                    if (attr_count > LUMINA_XML_MAX_ATTRIBUTES) return -1;
                } else if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                    current_state = XML_STATE_AFTER_ATTRIBUTE_NAME;
                } else if (c == '>') {
                    current_state = XML_STATE_TEXT;
                    text_start = i + 1;
                }
                break;
            case XML_STATE_AFTER_ATTRIBUTE_NAME:
                if (c == '=') {
                    current_state = XML_STATE_BEFORE_ATTRIBUTE_VALUE;
                    attr_count++;
                    if (attr_count > LUMINA_XML_MAX_ATTRIBUTES) return -1;
                } else if (c == '>') {
                    current_state = XML_STATE_TEXT;
                    text_start = i + 1;
                } else if (c != ' ' && c != '\t' && c != '\n' && c != '\r') {
                    current_state = XML_STATE_ATTRIBUTE_NAME;
                }
                break;
            case XML_STATE_BEFORE_ATTRIBUTE_VALUE:
                if (c == '\'') {
                    current_state = XML_STATE_ATTRIBUTE_VALUE_SINGLE;
                    // Push previous text fragment if any?
                    lumina_xml_value_end(state); // We end previous text node or attr
                    lumina_xml_value_begin(state, LUMINA_VAR_XML);
                    text_start = i + 1;
                } else if (c == '"') {
                    current_state = XML_STATE_ATTRIBUTE_VALUE_DOUBLE;
                    lumina_xml_value_end(state);
                    lumina_xml_value_begin(state, LUMINA_VAR_XML);
                    text_start = i + 1;
                } else if (c == '>') {
                    current_state = XML_STATE_TEXT;
                    text_start = i + 1;
                }
                break;
            case XML_STATE_ATTRIBUTE_VALUE_SINGLE:
                if (c == '\'') {
                    if (i > text_start) lumina_xml_value_fragment(state, data + text_start, i - text_start);
                    lumina_xml_value_end(state);
                    lumina_xml_value_begin(state, LUMINA_VAR_XML); // Reset for next nodes
                    current_state = XML_STATE_BETWEEN_ATTRIBUTES;
                } else if (c == '&') {
                    if (i > text_start) lumina_xml_value_fragment(state, data + text_start, i - text_start);
                    entity_start = i;
                    pre_entity_state = XML_STATE_ATTRIBUTE_VALUE_SINGLE;
                    current_state = XML_STATE_ENTITY_ATTR_S;
                }
                break;
            case XML_STATE_ATTRIBUTE_VALUE_DOUBLE:
                if (c == '"') {
                    if (i > text_start) lumina_xml_value_fragment(state, data + text_start, i - text_start);
                    lumina_xml_value_end(state);
                    lumina_xml_value_begin(state, LUMINA_VAR_XML); // Reset for next nodes
                    current_state = XML_STATE_BETWEEN_ATTRIBUTES;
                } else if (c == '&') {
                    if (i > text_start) lumina_xml_value_fragment(state, data + text_start, i - text_start);
                    entity_start = i;
                    pre_entity_state = XML_STATE_ATTRIBUTE_VALUE_DOUBLE;
                    current_state = XML_STATE_ENTITY_ATTR_D;
                }
                break;
            case XML_STATE_ENTITY_TEXT:
            case XML_STATE_ENTITY_ATTR_S:
            case XML_STATE_ENTITY_ATTR_D:
                if (c == ';') {
                    handle_entity(state, data + entity_start, i - entity_start + 1);
                    current_state = pre_entity_state;
                    text_start = i + 1;
                } else if (i - entity_start > LUMINA_XML_MAX_ENTITY_LEN || c == '<' || c == ' ' || c == '\n') {
                    // Invalid entity
                    lumina_xml_value_fragment(state, data + entity_start, i - entity_start);
                    current_state = pre_entity_state;
                    text_start = i;
                    i--; // Re-evaluate char
                }
                break;
            case XML_STATE_COMMENT_START_1:
                if (c == '-') current_state = XML_STATE_COMMENT_START_2;
                else if (c == '[') current_state = XML_STATE_CDATA_START_1;
                else if (c == 'D') current_state = XML_STATE_DOCTYPE;
                else current_state = XML_STATE_TEXT; // Malformed
                break;
            case XML_STATE_COMMENT_START_2:
                if (c == '-') current_state = XML_STATE_COMMENT;
                else current_state = XML_STATE_TEXT; // Malformed
                break;
            case XML_STATE_COMMENT:
                if (c == '-' && i + 2 < len && data[i+1] == '-' && data[i+2] == '>') {
                    i += 2;
                    current_state = XML_STATE_TEXT;
                    text_start = i + 1;
                }
                break;
            case XML_STATE_CDATA_START_1: if (c == 'C') current_state = XML_STATE_CDATA_START_2; else current_state = XML_STATE_TEXT; break;
            case XML_STATE_CDATA_START_2: if (c == 'D') current_state = XML_STATE_CDATA_START_3; else current_state = XML_STATE_TEXT; break;
            case XML_STATE_CDATA_START_3: if (c == 'A') current_state = XML_STATE_CDATA_START_4; else current_state = XML_STATE_TEXT; break;
            case XML_STATE_CDATA_START_4: if (c == 'T') current_state = XML_STATE_CDATA_START_5; else current_state = XML_STATE_TEXT; break;
            case XML_STATE_CDATA_START_5: if (c == 'A') current_state = XML_STATE_CDATA_START_6; else current_state = XML_STATE_TEXT; break;
            case XML_STATE_CDATA_START_6: 
                if (c == '[') {
                    current_state = XML_STATE_CDATA;
                    text_start = i + 1;
                } else current_state = XML_STATE_TEXT;
                break;
            case XML_STATE_CDATA:
                if (c == ']' && i + 2 < len && data[i+1] == ']' && data[i+2] == '>') {
                    if (i > text_start) lumina_xml_value_fragment(state, data + text_start, i - text_start);
                    i += 2;
                    current_state = XML_STATE_TEXT;
                    text_start = i + 1;
                }
                break;
            case XML_STATE_PI_OR_XML_DECL:
                if (c == '?' && i + 1 < len && data[i+1] == '>') {
                    i++;
                    current_state = XML_STATE_TEXT;
                    text_start = i + 1;
                }
                break;
            case XML_STATE_DOCTYPE:
                if (c == '>') {
                    current_state = XML_STATE_TEXT;
                    text_start = i + 1;
                }
                // Naive skip over DOCTYPE, ignoring nested [] 
                break;
            default:
                break;
        }
        i++;
    }
    
    if (current_state == XML_STATE_TEXT && i > text_start) {
        lumina_xml_value_fragment(state, data + text_start, i - text_start);
    }
    
    lumina_xml_value_end(state);
    
    return g_xml_threat;
}
