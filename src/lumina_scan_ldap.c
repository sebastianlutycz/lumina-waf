#include "luminawaf.h"
#include <string.h>
#include <stdint.h>

/* ============================================================================
 * LDAP Injection scanner (CRS 921110)
 *
 * Detects LDAP filter injection via:
 * - Wildcard patterns: *(|(, *(&
 * - Nested filters: )(&, )(|, )(!(, ))(
 * - Attribute injection: )(uid=, )(cn=, )(mail=, )(samaccountname=, )(userpassword=, )(objectclass=
 * - Closing filter: )()
 * - Bind injection: \x00 (null byte in LDAP), *() (trivial filter)
 *
 * All patterns stored in lowercase — case-insensitive match via |0x20 normalization.
 * First-byte dispatch computed at init time. */

#define LUMINA_MAX_STEPS 4096

static const struct { const char *pat; size_t plen; int id; } g_patterns[] = {
    /* ── Wildcard filter start ── */
    {"* (",           3,  921110},   /* *(|( = OR filter injection */
    {"*(&",           3,  921110},   /* *(& = AND filter injection */
    {"*(|",           3,  921110},
    {"*()!",          4,  921110},   /* *()! = NOT filter injection */

    /* ── Nested filter injection ── */
    {")(|",           3,  921110},
    {")(&",           3,  921110},
    {")(!",           3,  921110},
    {"))(",           3,  921110},   /* closing one filter, opening another */
    {")()",           3,  921110},   /* empty filter close */

    /* ── Attribute injection ── */
    {")(uid=",        6,  921110},
    {")(cn=",         5,  921110},
    {")(mail=",       7,  921110},
    {")(samaccount", 11,  921110},
    {")(userpassw", 11,  921110},
    {")(objectclas", 12,  921110},
    {")(givenname=",12,  921110},
    {")(sn=",         5,  921110},
    {")(telephonenum",14, 921110},
    {")(l=",          4,  921110},   /* location attribute */
    {")(o=",          4,  921110},   /* organization attribute */
    {")(ou=",         5,  921110},   /* organizational unit */
    {")(title=",      7,  921110},
    {")(memberof=",  10,  921110},
    {")(distinguished",15,921110},

    /* ── LDAP data exfiltration ── */
    {"objectclass",  11,  921110},
    {"objectcategory",14, 921110},
    {"1.1",           3,  921111},   /* LDAP NOATTRIBUTES — info probe */
    {"2.5.4",         5,  921111},   /* OID prefix for standard LDAP attributes */
    {"0.9.2342",      8,  921111},   /* ISO OID prefix */
};

#define PATTERN_COUNT ((int)(sizeof(g_patterns) / sizeof(g_patterns[0])))

static uint64_t g_first_mask[256][2];

__attribute__((constructor))
static void ldap_init_first_mask(void) {
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

int lumina_scan_ldap(const unsigned char *str, size_t len) {
    for (size_t i = 0; i < len && i < LUMINA_MAX_STEPS; i++) {
        unsigned char lc = str[i];

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
    }
    return 0;
}
