#ifndef LUMINA_SQLI_H
#define LUMINA_SQLI_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int lumina_sqli_detect(const uint8_t *data, size_t len);

#ifdef __cplusplus
}
#endif

#endif
