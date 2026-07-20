#ifndef LUMINA_TRIGGER_MATCHER_H
#define LUMINA_TRIGGER_MATCHER_H

#include <stdint.h>
#include <stddef.h>
#include "fast_prefilter.h"

#define LUMINA_TRIGGER_MAX 32

#define TRIGGER_XSS_SCRIPT_START   (1u << 0)
#define TRIGGER_XSS_ON             (1u << 1)
#define TRIGGER_SQLI_UNION         (1u << 2)
#define TRIGGER_SQLI_XP            (1u << 3)
#define TRIGGER_PATH_TRAV          (1u << 4)
#define TRIGGER_CMD_PIPE           (1u << 5)
#define TRIGGER_XSS_SCRIPT         (1u << 6)
#define TRIGGER_XSS_SCRIPT_GENERIC (1u << 7)
#define TRIGGER_XSS_ALERT          (1u << 8)
#define TRIGGER_XSS_JAVASCRIPT     (1u << 9)
#define TRIGGER_XSS_ENCODED        (1u << 10)
#define TRIGGER_SQLI_UNION_FULL    (1u << 11)
#define TRIGGER_SQLI_SELECT        (1u << 12)
#define TRIGGER_SQLI_1EQUALS1      (1u << 13)
#define TRIGGER_SQLI_COMMENT       (1u << 14)
#define TRIGGER_PATH_GITCONFIG     (1u << 15)
#define TRIGGER_RECON              (1u << 16)  /* wp-admin, .env, phpmyadmin, backup */
#define TRIGGER_CMD_INJECT         (1u << 17)  /* cat, wget, curl, bash, cmd= */
#define TRIGGER_SQLI_EXTRA         (1u << 18)
#define TRIGGER_JNDI_INJECT        (1u << 19)
#define TRIGGER_LDAP_INJECT        (1u << 20)
#define TRIGGER_RESP_SPLIT         (1u << 21)
#define TRIGGER_SSRF               (1u << 22)
#define TRIGGER_XSS_EXTRA          (1u << 23)
#define TRIGGER_XSS_ENCODED_EXTRA  (1u << 24)

typedef struct {
    const char *prefix;
    size_t len;
    uint32_t bit;
} LuminaTriggerDef;

#ifdef __cplusplus
extern "C" {
#endif

/* Zwraca bitmaskę pasujących triggerów */
uint32_t lumina_trigger_match(const unsigned char *data, size_t len, const DangerPositions *positions);

#ifdef __cplusplus
}
#endif

#endif
