#include "luminawaf.h"
#include <string.h>
#include <stdint.h>

/* ============================================================================
 * HTTP Response Splitting / Header Injection scanner (CRS 921130)
 *
 * PRECISE: Only fires when there is evidence of CRLF + header injection.
 * NOT just HTML in ARGS (that's XSS category, not response splitting).
 *
 * Detection criteria:
 * 1. Raw CRLF (0x0d0a) followed by header-like content
 * 2. URL-encoded CRLF (%0d%0a, %0d, %0a) followed by header-like content
 * 3. HTTP response version injection (HTTP/1.x after CRLF or standalone)
 * 4. Explicit header injection: \r\nHeader-Name: (with colon after header name)
 * ==========================================================================*/

#define LUMINA_MAX_STEPS 4096

/* Check if a position looks like a header name start (letter followed by
 * more letters/dashes, ending with a colon) */
static inline int looks_like_header(const unsigned char *str, size_t len, size_t start) {
    if (start >= len) return 0;
    unsigned char c = str[start];
    if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'))) return 0;
    
    /* Scan for colon within 30 chars */
    size_t end = start + 30;
    if (end > len) end = len;
    int has_colon = 0;
    int all_valid = 1;
    for (size_t j = start; j < end; j++) {
        unsigned char h = str[j];
        if (h == ':') { has_colon = 1; break; }
        if (!((h >= 'a' && h <= 'z') || (h >= 'A' && h <= 'Z') ||
              (h >= '0' && h <= '9') || h == '-' || h == '_')) {
            all_valid = 0;
            break;
        }
    }
    return has_colon && all_valid;
}

int lumina_scan_resp_split(const unsigned char *str, size_t len) {
    for (size_t i = 0; i < len && i < LUMINA_MAX_STEPS; i++) {
        unsigned char c = str[i];

        /* ── Raw CRLF detection (0x0d0a) ── */
        if (c == 0x0d && i + 1 < len && str[i+1] == 0x0a) {
            /* Check for header injection after CRLF */
            for (size_t j = i + 2; j < len && j < i + 64; j++) {
                unsigned char h = str[j];
                if (h == ' ' || h == '\t') continue;
                if (looks_like_header(str, len, j)) return 921130;
                break;
            }
            /* CRLF + HTTP response version */
            for (size_t j = i + 2; j < len && j < i + 64; j++) {
                unsigned char h = str[j] | 0x20;
                if (h == 'h') {
                    if (j + 5 <= len && (str[j]|0x20)=='h' && (str[j+1]|0x20)=='t' &&
                        (str[j+2]|0x20)=='t' && (str[j+3]|0x20)=='p' && str[j+4]=='/') {
                        return 921130;
                    }
                }
                break;
            }
        }

        /* ── Lone LF with header injection ── */
        if (c == 0x0a && i + 1 < len) {
            for (size_t j = i + 1; j < len && j < i + 64; j++) {
                unsigned char h = str[j];
                if (h == ' ' || h == '\t') continue;
                if (looks_like_header(str, len, j)) return 921130;
                break;
            }
        }

        /* ── URL-encoded CRLF: %0d%0a, %0d, %0a ── */
        if (c == '%' && i + 2 < len) {
            unsigned char h2_lower = str[i+2] | 0x20;
            if (str[i+1] == '0' && (h2_lower == 'd' || h2_lower == 'a')) {
                /* Found %0d or %0a — check for header injection after */
                size_t next = i + 3;
                /* Skip %0d%0a pair */
                if (next + 2 < len && str[next] == '%' && str[next+1] == '0' &&
                    ((str[next+2]|0x20) == 'd' || (str[next+2]|0x20) == 'a')) {
                    next += 3;
                }
                /* Check what follows the CRLF */
                for (size_t j = next; j < len && j < next + 64; j++) {
                    unsigned char h = str[j];
                    if (h == ' ' || h == '\t') continue;
                    if (looks_like_header(str, len, j)) return 921130;
                    if ((h|0x20) == 'h' && j + 5 <= len &&
                        (str[j]|0x20)=='h' && (str[j+1]|0x20)=='t' &&
                        (str[j+2]|0x20)=='t' && (str[j+3]|0x20)=='p' && str[j+4]=='/') {
                        return 921130;
                    }
                    break;
                }
                return 921130;  /* Standalone CRLF in input is suspicious enough */
            }
        }

        /* ── HTTP response version after CRLF context ──
         * Only match "HTTP/1." when preceded by CRLF or at the start of aHeaderValue.
         * Do NOT fire on "http://127.0.0.1" — that's SSRF, not response splitting. */
        if ((c == 'H' || c == 'h') && i + 5 <= len) {
            if ((str[i]|0x20)=='h' && (str[i+1]|0x20)=='t' && (str[i+2]|0x20)=='t' &&
                (str[i+3]|0x20)=='p' && str[i+4]=='/' && i + 7 <= len &&
                (str[i+5]=='1' || str[i+5]=='0') && str[i+6]=='.') {
                /* Match HTTP/1. or HTTP/0. — only if preceded by CRLF-like context
                 * (not just a URL with http://) */
                if (i == 0 || str[i-1] == 0x0a || str[i-1] == 0x0d ||
                    (i >= 2 && str[i-2] == '%' && str[i-1] == '0')) {
                    return 921130;
                }
            }
        }
    }
    return 0;
}
