#include "luminawaf.h"

/* ============================================================================
 * Command Injection scanner
 * Wywoływany gdy TRIGGER_CMD_INJECT jest aktywny.
 * CRS 932160: @pmFromFile unix-shell.data — added key strings.
 * ============================================================================ */
int lumina_scan_cmd(const unsigned char *str, size_t len, uint32_t active_scope) {
    static const struct { const char *pat; size_t plen; int id; uint32_t scope_mask; } cmds[] = {
        {"exec=",          5,  1002002, LUMINA_SCOPE_ALL},
        {";cat ",          5,  1002003, LUMINA_SCOPE_ALL},
        {"|cat ",          5,  1002003, LUMINA_SCOPE_ALL},
        {"`cat ",          5,  1002003, LUMINA_SCOPE_ALL},
        {"wget ",          5,  1002004, LUMINA_SCOPE_ALL},
        {"curl ",          5,  1002005, LUMINA_SCOPE_ALL},
        {"|bash",          5,  1002006, LUMINA_SCOPE_ALL},
        {";bash",          5,  1002006, LUMINA_SCOPE_ALL},
        {"/bin/sh",        7,  1002007, LUMINA_SCOPE_ALL},
        {"/bin/bash",      9,  1002007, LUMINA_SCOPE_ALL},
        {"system(",        7,  1002008, LUMINA_SCOPE_ALL},
        {"passthru(",      9,  1002008, LUMINA_SCOPE_ALL},
        {"shell_exec(",   11,  1002008, LUMINA_SCOPE_ALL},
        {"popen(",         6,  1002008, LUMINA_SCOPE_ALL},
        {"proc_open(",    10,  1002008, LUMINA_SCOPE_ALL},
        {"%0a",            3,  1002009, LUMINA_SCOPE_ALL},  /* newline injection */
        {"%0d%0a",         6,  1002009, LUMINA_SCOPE_ALL},  /* CRLF */
        {"$(",             2,  1002010, LUMINA_SCOPE_ALL},  /* bash subshell */
        {"${",             2,  1002010, LUMINA_SCOPE_HEADERS | LUMINA_SCOPE_URI | LUMINA_SCOPE_MULTIPART}, /* FP prone in JSON */

        /* --- CRS 932160: unix-shell.data key strings --- */
        {"$home",          5,  1002012, LUMINA_SCOPE_ALL},
        {"$path",          5,  1002012, LUMINA_SCOPE_ALL},
        {"$user",          5,  1002012, LUMINA_SCOPE_ALL},
        {"$shell",         6,  1002012, LUMINA_SCOPE_ALL},
        {"$lang",          5,  1002012, LUMINA_SCOPE_ALL},
        {"/etc/shadow",   10,  1002013, LUMINA_SCOPE_ALL},
        {"/etc/passwd",   10,  1002013, LUMINA_SCOPE_ALL},
        {"proc/self",      9,  1002014, LUMINA_SCOPE_ALL},
        {"/bin/cat",       8,  1002003, LUMINA_SCOPE_ALL},
        {"/bin/ls",        7,  1002015, LUMINA_SCOPE_ALL},
        {"/bin/id",        7,  1002015, LUMINA_SCOPE_ALL},
        {"/bin/uname",     9,  1002015, LUMINA_SCOPE_ALL},
        {"/usr/bin/",      9,  1002016, LUMINA_SCOPE_ALL},  /* FIX: was 10 */
        {"/usr/sbin/",      10,  1002016, LUMINA_SCOPE_ALL}, /* FIX: was 11 */
        {"/sbin/",         6,  1002016, LUMINA_SCOPE_ALL},

        {"&&",             2,  1002011, LUMINA_SCOPE_HEADERS | LUMINA_SCOPE_URI | LUMINA_SCOPE_MULTIPART}, /* FP prone in JSON */

        /* --- CRS 942290: NoSQL injection patterns (expanded) --- */
        {"$ne:",            4,  1002017, LUMINA_SCOPE_ALL},  /* { $ne: 1 } */
        {"$gt:",            4,  1002017, LUMINA_SCOPE_ALL},  /* { $gt: 0 } */
        {"$lt:",            4,  1002017, LUMINA_SCOPE_ALL},
        {"$gte:",           5,  1002017, LUMINA_SCOPE_ALL},
        {"$lte:",           5,  1002017, LUMINA_SCOPE_ALL},
        {"$in:",            4,  1002017, LUMINA_SCOPE_ALL},
        {"$nin:",           5,  1002017, LUMINA_SCOPE_ALL},
        {"$exists:",        8,  1002017, LUMINA_SCOPE_ALL},
        {"$regex:",         7,  1002017, LUMINA_SCOPE_ALL},
        {"$where:",         7,  1002017, LUMINA_SCOPE_ALL},
        {"$not:",           5,  1002017, LUMINA_SCOPE_ALL},
        {"$all:",           5,  1002017, LUMINA_SCOPE_ALL},
        {"$elemMatch:",    11,  1002017, LUMINA_SCOPE_ALL},
        {"$size:",          6,  1002017, LUMINA_SCOPE_ALL},
        {"$type:",          6,  1002017, LUMINA_SCOPE_ALL},
        {"$mod:",           5,  1002017, LUMINA_SCOPE_ALL},
        {"$jsonSchema:",   13,  1002017, LUMINA_SCOPE_ALL},
        {"$expr:",          6,  1002017, LUMINA_SCOPE_ALL},
        {"$function:",     10,  1002017, LUMINA_SCOPE_ALL},
        {"$accumulator:",  13,  1002017, LUMINA_SCOPE_ALL},
        {"$match:",         7,  1002017, LUMINA_SCOPE_ALL},
        {"$group:",         7,  1002017, LUMINA_SCOPE_ALL},
        {"$project:",       9,  1002017, LUMINA_SCOPE_ALL},
        {"$lookup:",        8,  1002017, LUMINA_SCOPE_ALL},
        {"$merge:",         7,  1002017, LUMINA_SCOPE_ALL},
        {"$addFields:",    10,  1002017, LUMINA_SCOPE_ALL},
        {"$facet:",         7,  1002017, LUMINA_SCOPE_ALL},
        {"$bucket:",        8,  1002017, LUMINA_SCOPE_ALL},
        {"$limit:",         7,  1002017, LUMINA_SCOPE_ALL},
        {"$skip:",          6,  1002017, LUMINA_SCOPE_ALL},
        {"$unwind:",        8,  1002017, LUMINA_SCOPE_ALL},

        /* --- CRS 934100: Node.js / NoSQL JS injection (function(), db.<coll>, mapReduce) --- */
        {"function()",      10, 1002018, LUMINA_SCOPE_ALL},   /* generic JS callback — high signal for RCE */
        {"function() {",    12, 1002018, LUMINA_SCOPE_ALL},   /* normalized after t:removeWhitespace */
        {"function(){",     11, 1002018, LUMINA_SCOPE_ALL},
        {"mapReduce(",      10, 1002018, LUMINA_SCOPE_ALL},   /* MongoDB JS-side mapReduce */
        {"emit(",            5, 1002018, LUMINA_SCOPE_ALL},   /* MongoDB emit() inside mapReduce */
        {"return 1;",        9, 1002018, LUMINA_SCOPE_ALL},   /* common JS-body marker */
        {";return 1;",      11, 1002018, LUMINA_SCOPE_ALL},
        {"db.injection",   13, 1002018, LUMINA_SCOPE_ALL},   /* payload-specific collection probe */
        {"db.stores",      10, 1002018, LUMINA_SCOPE_ALL},
        {".insert(",         9, 1002018, LUMINA_SCOPE_ALL},   /* covers db.<coll>.insert( */
        {".update(",         9, 1002018, LUMINA_SCOPE_ALL},
        {".remove(",         9, 1002018, LUMINA_SCOPE_ALL},
        {".aggregate(",     12, 1002018, LUMINA_SCOPE_ALL},
        {"process.exec",    12, 1002018, LUMINA_SCOPE_ALL},
        {"require(",         8, 1002018, LUMINA_SCOPE_ALL},
        {"module.exports",  15, 1002018, LUMINA_SCOPE_ALL},
        {"child_process",   14, 1002018, LUMINA_SCOPE_ALL},
        {"new Function(",   14, 1002018, LUMINA_SCOPE_ALL},
        {"this.constructor", 17, 1002018, LUMINA_SCOPE_ALL},
        {"String.fromCharCode", 20, 1002018, LUMINA_SCOPE_ALL},

        {NULL, 0, 0, 0}
    };

    for (int t = 0; cmds[t].pat != NULL; t++) {
        if (!(cmds[t].scope_mask & active_scope)) continue;
        
        const char *pat = cmds[t].pat;
        size_t plen = cmds[t].plen;
        if (len < plen) continue;
        
        int steps = 0;
        for (size_t i = 0; i <= len - plen; i++) {
            if (steps++ >= 4096) break; /* MAX_STEPS guard */
            
            size_t k;
            for (k = 0; k < plen; k++) {
                unsigned char a = str[i+k];
                unsigned char b = (unsigned char)pat[k];
                if (a >= 'A' && a <= 'Z') a |= 0x20;
                if (b >= 'A' && b <= 'Z') b |= 0x20;
                if (a != b) break;
            }
            if (k == plen) return cmds[t].id;
        }
    }
    return 0;
}
