#ifndef LUMINA_XML_TOKENIZER_H
#define LUMINA_XML_TOKENIZER_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    LUMINA_XML_TEXT,
    LUMINA_XML_ATTRIBUTE
} lumina_xml_value_kind_t;

typedef struct {
    const unsigned char *data;
    size_t length;
    lumina_xml_value_kind_t kind;
} lumina_xml_span_t;

// Callback function to emit spans
typedef void (*lumina_xml_emit_fn)(const lumina_xml_span_t *span, void *context);

// Tokenize XML and emit spans for text nodes and attribute values
int lumina_tokenize_xml(const unsigned char *data, size_t length, lumina_xml_emit_fn emit_cb, void *context);

#ifdef __cplusplus
}
#endif

#endif // LUMINA_XML_TOKENIZER_H
