#include "luminawaf.h"
#include <string.h>
#include <stdint.h>

/* ============================================================================
 * SSRF Scanner (CRS 934100 — Server-Side Request Forgery)
 *
 * Detects access to internal/metadata endpoints:
 * - Loopback: 127.0.0.1, localhost, 0.0.0.0, [::1], ::1
 * - Link-local: 169.254.x.x, fe80::/10
 * - Private IPv4: 10.x.x.x, 172.16-31.x.x, 192.168.x.x
 * - Private IPv6: fc00::/7, fd00::/8
 * - Cloud metadata: 169.254.169.254, metadata.google.internal, 100.100.100.200
 * - Internal hostnames: .local, .internal, .intranet
 * ==========================================================================*/

#define LUMINA_MAX_STEPS 4096

static inline int ci_match(const unsigned char *str, size_t len, size_t off,
                           const char *pat, size_t plen) {
    if (off + plen > len) return 0;
    for (size_t k = 0; k < plen; k++) {
        unsigned char a = str[off + k];
        unsigned char b = (unsigned char)pat[k];
        if (a >= 'A' && a <= 'Z') a |= 0x20;
        if (b >= 'A' && b <= 'Z') b |= 0x20;
        if (a != b) return 0;
    }
    return 1;
}

int lumina_scan_ssrf(const unsigned char *str, size_t len) {
    for (size_t i = 0; i < len && i < LUMINA_MAX_STEPS; i++) {
        unsigned char c = str[i];

        /* ── Loopback addresses ── */
        if (c == '1' && ci_match(str, len, i, "127.0.0", 7)) return 934100;
        if (c == '1' && ci_match(str, len, i, "127.0.1", 7)) return 934100;
        if (c == '0' && ci_match(str, len, i, "0.0.0.0", 7)) return 934100;
        if (c == '0' && i + 1 < len && str[i+1] == '0' &&
            i + 2 < len && str[i+2] == '0' && i + 3 < len && str[i+3] == '7') {
            /* 007 = octal 7 = 127 → 0177.0.0.1 */
            return 934100;
        }

        /* ── Localhost ── */
        if ((c == 'l' || c == 'L') && ci_match(str, len, i, "localhost", 9)) return 934100;

        /* ── AWS/GCP/Azure cloud metadata ── */
        if (c == '1' && ci_match(str, len, i, "169.254", 7)) return 934100;
        if (c == '1' && i + 10 <= len && ci_match(str, len, i, "169.254.169", 11)) return 934100;
        if ((c == 'm' || c == 'M') && ci_match(str, len, i, "metadata", 8)) return 934100;
        if (c == '1' && ci_match(str, len, i, "100.100.100", 11)) return 934100;

        /* ── Private IPv4 ranges ── */
        if (c == '1' && ci_match(str, len, i, "10.", 3)) {
            /* 10.x.x.x — but only if preceded by http/scheme or . */
            if (i == 0 || str[i-1] == '/' || str[i-1] == '=' ||
                str[i-1] == '.' || str[i-1] == '?' || str[i-1] == '&') {
                return 934100;
            }
        }
        if (c == '1' && ci_match(str, len, i, "172.1", 5)) {
            /* 172.16-31.x.x */
            if (i + 5 < len && str[i+4] >= '6' && str[i+4] <= '3') return 934100;
        }
        if (c == '1' && ci_match(str, len, i, "192.168", 7)) return 934100;

        /* ── IPv6 loopback and link-local ── */
        if (c == '[' && ci_match(str, len, i, "[::1]", 5)) return 934100;
        if (c == ':' && i > 0 && str[i-1] == ':' && ci_match(str, len, i-1, "::1", 3)) return 934100;
        if ((c == 'f' || c == 'F') && ci_match(str, len, i, "fc00:", 5)) return 934100;
        if ((c == 'f' || c == 'F') && ci_match(str, len, i, "fd00:", 5)) return 934100;
        if ((c == 'f' || c == 'F') && ci_match(str, len, i, "fe80:", 5)) return 934100;

        /* ── Internal hostnames ── */
        if (c == '.' && i + 1 < len) {
            if (ci_match(str, len, i, ".local", 6)) return 934100;
            if (ci_match(str, len, i, ".internal", 9)) return 934100;
            if (ci_match(str, len, i, ".intranet", 9)) return 934100;
            if (ci_match(str, len, i, ".localhost", 10)) return 934100;
        }
        /* Standalone hostnames without dot prefix */
        if ((c == 'l' || c == 'L') && ci_match(str, len, i, "localhost", 9)) return 934100;

        /* ── Octal/hex IP obfuscation ── */
        if (c == '0' && i + 1 < len && str[i+1] == 'x') {
            /* 0x7f000001 = 127.0.0.1 in hex */
            if (i + 11 <= len && ci_match(str, len, i, "0x7f0000", 8)) return 934100;
        }
        if (c == '0' && i + 3 < len && str[i+1] == '1' && str[i+2] == '7' && str[i+3] == '7') {
            /* 0177 = octal 127 */
            if (i + 8 <= len && ci_match(str, len, i, "0177.0.0", 8)) return 934100;
        }
        if (c == '2' && ci_match(str, len, i, "2130706433", 10)) return 934100; /* 127.0.0.1 in decimal */

        /* ── URL scheme check for SSRF context ── */
        if (c == 'h' && (ci_match(str, len, i, "http://127", 10) ||
                         ci_match(str, len, i, "http://0", 8) ||
                         ci_match(str, len, i, "http://[", 8) ||
                         ci_match(str, len, i, "http://local", 12) ||
                         ci_match(str, len, i, "https://127", 11) ||
                         ci_match(str, len, i, "https://0", 9) ||
                         ci_match(str, len, i, "https://[", 9) ||
                         ci_match(str, len, i, "https://local", 13))) {
            return 934100;
        }

        /* ── Gopher / Dict / FTP scheme (SSRF protocol smuggling) ── */
        if (c == 'g' && ci_match(str, len, i, "gopher://", 9)) return 934100;
        if (c == 'd' && ci_match(str, len, i, "dict://", 7)) return 934100;
        if (c == 'f' && ci_match(str, len, i, "ftp://", 6) &&
            /* Only flag ftp:// internal, not external FTP */
            (i + 12 <= len && (ci_match(str, len, i, "ftp://127", 10) ||
                              ci_match(str, len, i, "ftp://10.", 9) ||
                              ci_match(str, len, i, "ftp://192", 10) ||
                              ci_match(str, len, i, "ftp://0.0", 9) ||
                              ci_match(str, len, i, "ftp://local", 12)))) {
            return 934100;
        }
    }
    return 0;
}
