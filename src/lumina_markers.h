#ifndef LUMINA_MARKERS_H
#define LUMINA_MARKERS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LUMINA_MARKER_REGISTRY_VERSION "v0.4-clean"
#define LUMINA_MARKER_BUILD_TAG "a4e12f09bc8736d5"
#define LUMINA_MARKER_LICENSE_MODE "AGPLv3"
#define LUMINA_MARKER_BUILD_FINGERPRINT "lumina-waf/v0.4/agpl/a4e12f09bc8736d5"

const char *luminawaf_build_fingerprint(void);
const char *luminawaf_license_mode(void);
const char *luminawaf_marker_registry_version(void);
const unsigned char *luminawaf_binary_fingerprint(size_t *len);
uint32_t luminawaf_rule_order_fingerprint(void);

#ifdef __cplusplus
}
#endif

#endif /* LUMINA_MARKERS_H */
