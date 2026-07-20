#include "lumina_markers.h"

namespace {

__attribute__((used, section(".note.lumina")))
static const unsigned char kLuminaElfNote[] =
    "LuminaWAF\0"
    "license=AGPLv3\0"
    "registry=v0.4-clean\0"
    "build=a4e12f09bc8736d5\0";

__attribute__((used, section(".lumina_fingerprint")))
static const unsigned char kLuminaBinaryFingerprint[] = {
    0xa4, 0xe1, 0x2f, 0x09, 0xbc, 0x87, 0x36, 0xd5,
    0x4c, 0x57, 0x41, 0x46, 0x30, 0x34, 0x41, 0x47
};
}  // namespace

extern "C" const char *luminawaf_build_fingerprint(void) {
    return LUMINA_MARKER_BUILD_FINGERPRINT;
}

extern "C" const char *luminawaf_license_mode(void) {
    return LUMINA_MARKER_LICENSE_MODE;
}

extern "C" const char *luminawaf_marker_registry_version(void) {
    return LUMINA_MARKER_REGISTRY_VERSION;
}

extern "C" const unsigned char *luminawaf_binary_fingerprint(size_t *len) {
    if (len) *len = sizeof(kLuminaBinaryFingerprint);
    return kLuminaBinaryFingerprint;
}

extern "C" uint32_t luminawaf_rule_order_fingerprint(void) {
    return 0x04a4e12fu;
}
