#ifndef LUMINA_FAST_PREFILTER_H
#define LUMINA_FAST_PREFILTER_H

#include <stdbool.h>
#include <stddef.h>

#define MAX_DANGER_POSITIONS 64

typedef struct {
    size_t offsets[MAX_DANGER_POSITIONS];
    size_t count;
} DangerPositions;

#ifdef __cplusplus
extern "C" {
#endif

bool lumina_fast_prefilter(const unsigned char *data, size_t len,
                           DangerPositions *positions);

bool lumina_fast_prefilter_headers(const unsigned char *data, size_t len,
                                   DangerPositions *positions);

#ifdef __cplusplus
}
#endif

#endif
