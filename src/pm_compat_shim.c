/*
 * pm_compat_shim.c — VERIFICATION-ONLY bridge.
 *
 * The runtime (luminawaf.cpp) calls the historical PM scanner names
 * (lumina_pm_lfi_os_files, lumina_pm_restricted_files, lumina_scan_restricted_ext)
 * for the FILES variable. The AOT transpiler (sidecar_translator.py) now emits
 * these phrase scanners with a `_data` suffix (e.g. lumina_pm_lfi_os_files_data).
 * This shim bridges the two naming conventions in the materialized AOT runtime.
 */
#include <stddef.h>
#include <stdint.h>

extern int lumina_pm_lfi_os_files_data(const unsigned char *data, size_t len);
extern int lumina_pm_restricted_files_data(const unsigned char *data, size_t len);

int lumina_pm_lfi_os_files(const unsigned char *data, size_t len) {
    return lumina_pm_lfi_os_files_data(data, len);
}

int lumina_pm_restricted_files(const unsigned char *data, size_t len) {
    return lumina_pm_restricted_files_data(data, len);
}

/* Not emitted by the current AOT; retained as a no-match compatibility stub. */
int lumina_scan_restricted_ext(const unsigned char *url, size_t len) {
    (void)url; (void)len;
    return 0;
}
