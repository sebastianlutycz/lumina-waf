#include "luminawaf.h"
#include <string.h>
#include <stdint.h>

#define LUMINA_MAX_STEPS 4096

/* PREC-2: Comprehensive XSS pattern table for CRS PL2 parity.
   All patterns in lowercase — case-insensitive match via |0x20 normalization.
   scope_mask: bitmap of allowed scopes (0x3F = all scopes).
   First-byte dispatch computed at init time. */

#define XSS_SCOPE_ALL 63  /* URI|ARGS|COOKIE|HDR|BODY|MULTIPART */

static const struct { const char *pat; size_t plen; int id; uint32_t scope_mask; } g_patterns[] = {
    /* ── HTML tag injections ── */
    {"<svg",              4, 1000001, XSS_SCOPE_ALL},
    {"<iframe",           7, 1000002, XSS_SCOPE_ALL},
    {"<img",              4, 1000003, XSS_SCOPE_ALL},
    {"<body",             5, 1000004, XSS_SCOPE_ALL},
    {"<input",            6, 1000005, XSS_SCOPE_ALL},
    {"<embed",            6, 1000006, XSS_SCOPE_ALL},
    {"<object",           7, 1000007, XSS_SCOPE_ALL},
    {"<base",             5, 1000008, XSS_SCOPE_ALL},
    {"<form",             5, 1000009, XSS_SCOPE_ALL},
    {"<math",             5, 1000010, XSS_SCOPE_ALL},
    {"<video",            6, 1000011, XSS_SCOPE_ALL},
    {"<audio",            6, 1000012, XSS_SCOPE_ALL},
    {"<marquee",          8, 1000013, XSS_SCOPE_ALL},
    {"<meta",             5, 1000014, XSS_SCOPE_ALL},
    {"<link",             5, 1000015, XSS_SCOPE_ALL},
    {"<script",           7, 1000050, XSS_SCOPE_ALL},
    {"<noscript",         9, 1000051, XSS_SCOPE_ALL},
    {"<style",            6, 1000052, XSS_SCOPE_ALL},
    {"<details",          8, 1000053, XSS_SCOPE_ALL},
    {"<details/open=",   12, 1000054, XSS_SCOPE_ALL},  /* auto-trigger */
    /* <; obfuscation patterns: semicolon right after '<' bypasses regex-based CRS */
    {"<;script",          8, 1000108, XSS_SCOPE_ALL},
    {"<;iframe",          8, 1000109, XSS_SCOPE_ALL},
    {"<;img",             5, 1000110, XSS_SCOPE_ALL},
    {"<;meta",            6, 1000111, XSS_SCOPE_ALL},
    {"<;link",            6, 1000112, XSS_SCOPE_ALL},
    {"<;",                2, 1000113, XSS_SCOPE_ALL},   /* generic <; prefix — low specificity */
    {"<xss",              4, 1000055, XSS_SCOPE_ALL},   /* arbitrary tag */
    {"<isindex",          8, 1000056, XSS_SCOPE_ALL},  /* legacy HTML */
    {"<applet",           7, 1000057, XSS_SCOPE_ALL},
    {"<frame",            6, 1000058, XSS_SCOPE_ALL},   /* frameset */
    {"<layer",            6, 1000059, XSS_SCOPE_ALL},   /* Netscape layer */
    {"<xml",              4, 1000060, XSS_SCOPE_ALL},   /* XML + SRC injection */
    {"<xml src=",         9, 1000069, XSS_SCOPE_ALL},   /* XML SRC injection */
    {"<html",             5, 1000114, XSS_SCOPE_ALL},
    {"<head",             5, 1000115, XSS_SCOPE_ALL},
    {"<?import",          8, 1000116, XSS_SCOPE_ALL},   /* XML stylesheet import */
    {"xmlns:xss",         9, 1000117, XSS_SCOPE_ALL},   /* XSS namespace */
    {"+ADw-SCRIPT+AD4-", 15, 1000118, XSS_SCOPE_ALL},   /* UTF-7 encoded <SCRIPT> */
    {"+ADw-",             5, 1000119, XSS_SCOPE_ALL},   /* UTF-7 encoded '<' */
    {"ev:event=",         9, 1000120, XSS_SCOPE_ALL},   /* XML Events */
    {"ev:handler=",      11, 1000121, XSS_SCOPE_ALL},   /* XML Events handler */

    /* ── Event handlers ── */
    {"onload=",           7, 1000020, XSS_SCOPE_ALL},
    {"onclick=",          8, 1000021, XSS_SCOPE_ALL},
    {"onmouseover=",    12, 1000022, XSS_SCOPE_ALL},
    {"onfocus=",          8, 1000023, XSS_SCOPE_ALL},
    {"onerror=",          8, 1000024, XSS_SCOPE_ALL},
    {"onmouseout=",      10, 1000025, XSS_SCOPE_ALL},
    {"ondblclick=",      11, 1000026, XSS_SCOPE_ALL},
    {"oncontextmenu=",   14, 1000027, XSS_SCOPE_ALL},
    {"onkeydown=",       10, 1000028, XSS_SCOPE_ALL},
    {"onkeyup=",          8, 1000029, XSS_SCOPE_ALL},
    {"onsubmit=",         9, 1000060, XSS_SCOPE_ALL},
    {"onreset=",          8, 1000061, XSS_SCOPE_ALL},
    {"onchange=",         9, 1000062, XSS_SCOPE_ALL},
    {"oninput=",          8, 1000063, XSS_SCOPE_ALL},
    {"onanimationend=",  15, 1000064, XSS_SCOPE_ALL},
    {"ontoggle=",         9, 1000065, XSS_SCOPE_ALL},
    {"onpointerover=",   14, 1000066, XSS_SCOPE_ALL},
    {"onbeforeinput=",   14, 1000067, XSS_SCOPE_ALL},
    {"ontransitionend=", 17, 1000068, XSS_SCOPE_ALL},

    /* ── Additional event handlers (GoTestWAF coverage) ── */
    {"oncopy=",           8, 1000070, XSS_SCOPE_ALL},
    {"oncut=",            7, 1000071, XSS_SCOPE_ALL},
    {"onpaste=",          9, 1000072, XSS_SCOPE_ALL},
    {"ondrag=",           8, 1000073, XSS_SCOPE_ALL},
    {"ondragend=",       10, 1000074, XSS_SCOPE_ALL},
    {"ondragenter=",     12, 1000075, XSS_SCOPE_ALL},
    {"ondragleave=",     12, 1000076, XSS_SCOPE_ALL},
    {"ondragover=",      12, 1000077, XSS_SCOPE_ALL},
    {"ondragstart=",     12, 1000078, XSS_SCOPE_ALL},
    {"ondrop=",           8, 1000079, XSS_SCOPE_ALL},
    {"onscroll=",         9, 1000080, XSS_SCOPE_ALL},
    {"onwheel=",          9, 1000081, XSS_SCOPE_ALL},
    {"oncanplay=",       10, 1000082, XSS_SCOPE_ALL},
    {"onfullscreenchange=",19,1000083, XSS_SCOPE_ALL},
    {"onbeforeinput=",   14, 1000084, XSS_SCOPE_ALL},
    {"onblur=",           8, 1000085, XSS_SCOPE_ALL},
    {"onbeforedeactivate=",18,1000086, XSS_SCOPE_ALL},
    {"ondeactivate=",    13, 1000087, XSS_SCOPE_ALL},
    {"onmove=",           8, 1000088, XSS_SCOPE_ALL},
    {"onresize=",         9, 1000089, XSS_SCOPE_ALL},
    {"onsearch=",         9, 1000090, XSS_SCOPE_ALL},
    {"onselect=",         9, 1000091, XSS_SCOPE_ALL},
    {"onplay=",           8, 1000092, XSS_SCOPE_ALL},
    {"onpause=",          8, 1000093, XSS_SCOPE_ALL},
    {"onended=",          8, 1000094, XSS_SCOPE_ALL},
    {"onseeked=",         9, 1000095, XSS_SCOPE_ALL},
    {"ontimeupdate=",    13, 1000096, XSS_SCOPE_ALL},
    {"onvolumechange=",  15, 1000097, XSS_SCOPE_ALL},
    {"onmessage=",       10, 1000098, XSS_SCOPE_ALL},
    {"ondevicelight=",   14, 1000100, XSS_SCOPE_ALL},
    {"onloadstart=",     11, 1000101, XSS_SCOPE_ALL},
    {"onloadeddata=",    12, 1000102, XSS_SCOPE_ALL},
    {"onprogress=",      11, 1000103, XSS_SCOPE_ALL},
    {"onstalled=",       10, 1000104, XSS_SCOPE_ALL},
    {"onsuspend=",       10, 1000105, XSS_SCOPE_ALL},
    {"onwaiting=",       10, 1000106, XSS_SCOPE_ALL},
    {"onerror=",          8, 1000107, XSS_SCOPE_ALL}, /* alias for trigger match */

    /* ── Pseudo-protocols ── */
    {"javascript:",      11, 1000030, XSS_SCOPE_ALL},
    {"vbscript:",         9, 1000031, XSS_SCOPE_ALL},
    {"data:text/html",   14, 1000032, XSS_SCOPE_ALL},
    {"data:text/html;base64,", 22, 1000033, XSS_SCOPE_ALL},
    {"data:image/svg",   14, 1000034, XSS_SCOPE_ALL},   /* SVG in data: URI */

    /* ── CSS injection ── */
    {"expression(",      11, 1000040, XSS_SCOPE_ALL},  /* IE CSS expression */
    {"-moz-binding",    12, 1000041, XSS_SCOPE_ALL},   /* Firefox XBL */
    {"url(",             4, 1000070, XSS_SCOPE_ALL},   /* CSS url() injection */
    {"@import",          7, 1000071, XSS_SCOPE_ALL},   /* CSS import */

    /* ── JS string patterns (post-delimiter) ── */
    {"alert(",            6, 1000080, XSS_SCOPE_ALL},
    {"confirm(",          8, 1000081, XSS_SCOPE_ALL},
    {"prompt(",           7, 1000082, XSS_SCOPE_ALL},
    {"document.cookie",  15, 1000083, XSS_SCOPE_ALL},
    {"document.write",   14, 1000084, XSS_SCOPE_ALL},
    {".innerhtml",       10, 1000085, XSS_SCOPE_ALL},
    {".outerhtml",       10, 1000086, XSS_SCOPE_ALL},
    {".srcdoc",           7, 1000087, XSS_SCOPE_ALL},
    {"eval(",             5, 1000088, XSS_SCOPE_ALL},
    {"settimeout(",      12, 1000089, XSS_SCOPE_ALL},
    {"setinterval(",     13, 1000090, XSS_SCOPE_ALL},
    {"window.location",  16, 1000091, XSS_SCOPE_ALL},
    {"location.href",    13, 1000092, XSS_SCOPE_ALL},
};

#define PATTERN_COUNT ((int)(sizeof(g_patterns) / sizeof(g_patterns[0])))

/* First-byte dispatch mask — computed at init.
   Both cases registered for alphabetic bytes. */
static uint64_t g_first_mask[256][2];

__attribute__((constructor))
static void xss_init_first_mask(void) {
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

int lumina_scan_xss(const unsigned char *str, size_t len, uint32_t active_scope) {
    uint32_t scope = active_scope ? active_scope : 0x3F;
    for (size_t i = 0; i < len && i < LUMINA_MAX_STEPS; i++) {
        for (int w = 0; w < 2; w++) {
            uint64_t mask = g_first_mask[str[i]][w];
            int base = w * 64;
            while (mask) {
                int idx = __builtin_ctzll(mask) + base;
                mask &= mask - 1;
                if (idx >= PATTERN_COUNT) continue;
                if (scope && !(g_patterns[idx].scope_mask & scope)) continue;
                size_t plen = g_patterns[idx].plen;
                if (i + plen > len) continue;
                size_t k;
                for (k = 0; k < plen; k++) {
                    unsigned char a = str[i+k];
                    unsigned char b = (unsigned char)g_patterns[idx].pat[k];
                    if (a >= 'A' && a <= 'Z') a |= 0x20;
                    if (a != b) break;
                }
                if (k == plen) return g_patterns[idx].id;
            }
        }
    }
    return 0;
}
