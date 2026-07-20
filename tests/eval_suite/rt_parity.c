/*
 * rt_parity.c — full-runtime parity smoke test through the public ABI.
 *
 * Uses luminawaf_inspect_buffer() with CORRECT variable scoping (unlike the
 * raw AOT smoke). A request is blocked iff out_result->threat_level != 0.
 * Validates that PL2 attack classes block while benign traffic does not.
 *
 * Build: clang -O2 rt_parity.c -I ../src -L ../build -lluminawaf -o rt_parity
 *        LD_LIBRARY_PATH=../build ./rt_parity
 */
#include <stdio.h>
#include <string.h>
#include "luminawaf.h"

/* scope constants mirrored from luminawaf.h */
#define SC_URI    1
#define SC_HDR    2
#define SC_BODY   4

typedef struct {
    const char *name;
    const char *payload;
    int var_type;     /* LUMINA_VAR_* */
    int scope;        /* LUMINA_SCOPE_* */
    int attack;       /* 1 = expect block (threat_level != 0) */
} T;

static const T tests[] = {
    { "XSS <script> (URI)",      "<script>alert(1)</script>", 0, SC_URI,  1 },
    { "SQLi union (ARGS)",       "id=1 UNION SELECT password FROM users", 1, SC_URI, 1 },
    { "SQLi boolean (ARGS)",     "q=' OR '1'='1", 1, SC_URI, 1 },
    { "LFI /etc/passwd (URI)",   "/../../../etc/passwd", 0, SC_URI, 1 },
    { "LFI windows (URI)",       "..\\..\\..\\windows\\win.ini", 0, SC_URI, 1 },
    { "PHP injection (BODY)",    "<?php echo system($_GET['c']); ?>", 4, SC_BODY, 1 },
    { "RCE command (ARGS)",      "; cat /etc/passwd", 1, SC_URI, 1 },
    { "Node.js RCE (BODY)",      "require('child_process').exec('id')", 4, SC_BODY, 1 },
    { "RFI http (ARGS)",         "http://evil.example.com/shell.txt", 1, SC_URI, 1 },
    { "Scanner UA (HDR)",        "sqlmap/1.6", 3, SC_HDR, 1 },
    { "SSRF metadata (ARGS)",    "http://169.254.169.254/latest/meta-data/", 1, SC_URI, 1 },

    { "benign path (URI)",       "/index.html", 0, SC_URI, 0 },
    { "benign api (URI)",        "GET /api/v1/users?page=2 HTTP/1.1", 0, SC_URI, 0 },
    { "benign query (ARGS)",     "q=hello+world&lang=en", 1, SC_URI, 0 },
    { "benign long (BODY)",      "The quick brown fox jumps over the lazy dog while the sun sets behind the quiet hills.", 4, SC_BODY, 0 },
    { "benign json (BODY)",      "{\"user\":\"alice\",\"action\":\"view\"}", 4, SC_BODY, 0 },
};

int main(void) {
    luminawaf_init_worker(4096);
    int pass = 0, fail = 0;
    int n = (int)(sizeof(tests) / sizeof(tests[0]));
    for (int i = 0; i < n; i++) {
        const T *t = &tests[i];
        LuminaResult r;
        memset(&r, 0, sizeof(r));
        int rc = luminawaf_inspect_buffer((const unsigned char *)t->payload,
                                          strlen(t->payload), t->scope, t->var_type, &r);
        int blocked = (rc == 0 && r.threat_level != 0);
        int ok = (t->attack == blocked) ? 1 : 0;
        printf("%-24s scope=%d vtype=%d -> threat=%d %s%s\n",
               t->name, t->scope, t->var_type, r.threat_level,
               ok ? "PASS" : "FAIL", t->attack ? " (attack)" : " (benign)");
        if (ok) pass++; else fail++;
    }
    printf("\n%d/%d passed\n", pass, n);
    return fail ? 1 : 0;
}
