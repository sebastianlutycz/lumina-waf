#ifndef LUMINA_XML_PARSER_H
#define LUMINA_XML_PARSER_H

#include "luminawaf.h"
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

bool lumina_is_xml_part(const unsigned char *content_type, size_t content_type_len,
                        const unsigned char *filename, size_t filename_len,
                        const unsigned char *body, size_t body_len);

void lumina_xml_value_begin(LuminaRuleState *state, LuminaVarType var_type);
void lumina_xml_value_fragment(LuminaRuleState *state, const unsigned char *ptr, size_t len);
void lumina_xml_value_end(LuminaRuleState *state);

int lumina_scan_xml_avx2(const unsigned char *data, size_t len, LuminaRuleState *state);
LuminaError lumina_parse_and_scan_xml(const unsigned char *data, size_t len,
                                      LuminaRuleState *state, int *threat);

#ifdef __cplusplus
}
#endif

#endif
