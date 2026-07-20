#include "luminawaf.h"
#include <string.h>
#include <stdint.h>

/* ============================================================================
 * JNDI Injection scanner (CRS 932130 — Log4Shell / Log4j RCE)
 *
 * Detects ${jndi:ldap:}, ${jndi:rmi:}, ${jndi:ldaps:}, ${jndi:dns:},
 * ${jndi:nis:}, ${jndi:iiop:}, ${jndi:nds:}, ${jndi:corba:},
 * and log4j obfuscation patterns like ${lower:}, ${upper:}, ${env:},
 * ${sys:}, ${java:}, ${date:}, ${ctx:}.
 *
 * All patterns stored in lowercase — case-insensitive match via |0x20 normalization.
 * First-byte dispatch computed at init time. */

#define LUMINA_MAX_STEPS 4096

static const struct { const char *pat; size_t plen; int id; } g_patterns[] = {
    /* ── Direct JNDI lookups (CRS 932130) ── */
    {"${jndi:",        7,  932130},
    {"jndi:",          5,  932130},   /* after ${} stripping by canonicalize */
    {"jndi:ldap:",    10,  932130},
    {"jndi:rmi:",      9,  932130},
    {"jndi:ldaps:",   11,  932130},
    {"jndi:dns:",      9,  932130},
    {"jndi:nis:",      9,  932130},
    {"jndi:iiop:",    10,  932130},
    {"jndi:nds:",      9,  932130},
    {"jndi:corba:",   11,  932130},
    {"jndi:http:",    10,  932130},

    /* ── Log4j obfuscation via nested lookups ── */
    {"${lower:",       8,  932131},   /* ${lower:${lower:h}${lower:e}...} */
    {"${upper:",       8,  932131},
    {"${env:",         6,  932131},   /* ${env:HOSTNAME} */
    {"${sys:",         6,  932131},   /* ${sys:user.name} */
    {"${java:",        7,  932131},   /* ${java:os} */
    {"${date:",        7,  932131},   /* ${date:YYYY-MM-dd} */
    {"${ctx:",         6,  932131},   /* log4j ThreadContext */
    {"${main:",        7,  932131},   /* log4j main lookup */
    {"${log4j:",       7,  932131},   /* log4j config lookup */

    /* ── Known obfuscation patterns ── */
    {"${::-",          5,  932132},   /* ${::-j} — default value trick */
    {"${hostnam",      9,  932132},   /* ${hostname} info leak */
    {"${docker:",      9,  932132},   /* Docker env lookup */
    {"${k8s:",         5,  932132},   /* Kubernetes env lookup */
};

#define PATTERN_COUNT ((int)(sizeof(g_patterns) / sizeof(g_patterns[0])))

static uint64_t g_first_mask[256][2];

__attribute__((constructor))
static void jndi_init_first_mask(void) {
    memset(g_first_mask, 0, sizeof(g_first_mask));
    for (int i = 0; i < PATTERN_COUNT; i++) {
        unsigned char first = (unsigned char)g_patterns[i].pat[0];
        int w = i / 64;
        int b = i % 64;
        g_first_mask[first][w] |= (1ULL << b);
        if (first >= 'a' && first <= 'z') {
            g_first_mask[first & ~0x20][w] |= (1ULL << b);
        } else if (first >= 'A' && first <= 'Z') {
            g_first_mask[first | 0x20][w] |= (1ULL << b);
        }
    }
}

int lumina_scan_jndi(const unsigned char *str, size_t len) {
    for (size_t i = 0; i < len && i < LUMINA_MAX_STEPS; i++) {
        unsigned char lc = str[i];
        if (lc >= 'A' && lc <= 'Z') lc |= 0x20;

        for (int w = 0; w < 2; w++) {
            uint64_t mask = g_first_mask[lc][w];
            int base = w * 64;
            while (mask) {
                int idx = __builtin_ctzll(mask) + base;
                mask &= mask - 1;
                if (idx >= PATTERN_COUNT) continue;
                const char *pat = g_patterns[idx].pat;
                size_t plen = g_patterns[idx].plen;
                if (i + plen > len) continue;
                size_t k;
                for (k = 0; k < plen; k++) {
                    unsigned char a = str[i + k];
                    unsigned char b = (unsigned char)pat[k];
                    if (a >= 'A' && a <= 'Z') a |= 0x20;
                    if (b >= 'A' && b <= 'Z') b |= 0x20;
                    if (a != b) break;
                }
                if (k == plen) return g_patterns[idx].id;
            }
        }
        /* Also check raw '$' for patterns starting with ${ */
        if (str[i] == '$' && i + 1 < len && str[i+1] == '{') {
            /* Scan forward for any JNDI-related lookup */
            for (int w = 0; w < 2; w++) {
                uint64_t mask = g_first_mask[(unsigned char)'$'][w];
                int base = w * 64;
                while (mask) {
                    int idx = __builtin_ctzll(mask) + base;
                    mask &= mask - 1;
                    if (idx >= PATTERN_COUNT) continue;
                    const char *pat = g_patterns[idx].pat;
                    size_t plen = g_patterns[idx].plen;
                    if (pat[0] != '$') continue;  /* only ${...} patterns */
                    if (i + plen > len) continue;
                    size_t k;
                    for (k = 0; k < plen; k++) {
                        unsigned char a = str[i + k];
                        unsigned char b = (unsigned char)pat[k];
                        if (a >= 'A' && a <= 'Z') a |= 0x20;
                        if (b >= 'A' && b <= 'Z') b |= 0x20;
                        if (a != b) break;
                    }
                    if (k == plen) return g_patterns[idx].id;
                }
            }
        }
    }
    return 0;
}
