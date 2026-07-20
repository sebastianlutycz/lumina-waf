#include <stddef.h>
#include <string.h>

#define LUMINA_MAX_STEPS 4096

/* Pomocnik: case-insensitive porównanie buforu z literałem */
static inline int ci_match(const unsigned char *buf, size_t buf_len,
                            size_t offset, const char *pat, size_t pat_len) {
    if (offset + pat_len > buf_len) return 0;
    for (size_t k = 0; k < pat_len; k++) {
        unsigned char a = buf[offset + k];
        unsigned char b = (unsigned char)pat[k];
        if (a >= 'A' && a <= 'Z') a |= 0x20;
        if (b >= 'A' && b <= 'Z') b |= 0x20;
        if (a != b) return 0;
    }
    return 1;
}

int lumina_scan_path(const unsigned char *str, size_t len) {
    for (size_t i = 0; i < len && i < LUMINA_MAX_STEPS; i++) {
        unsigned char c = str[i];

        /* ----------------------------------------------------------------
         * Path traversal: ../ and URL-encoded variants
         * ---------------------------------------------------------------- */
        if (c == '.') {
            if (i + 1 < len && str[i+1] == '.') {
                /* Classical ../ */
                return 1001001;
            }

            /* .env */
            if (ci_match(str, len, i, ".env", 4)) {
                /* Make sure it's a boundary: start of string, after '/' or '?' */
                if (i == 0 || str[i-1] == '/' || str[i-1] == '?') {
                    return 1001004;
                }
            }

            /* .git/config, .git/HEAD, .git/ anything */
            if (ci_match(str, len, i, ".git/", 5)) {
                return 1001005;
            }

            /* .htaccess */
            if (ci_match(str, len, i, ".htaccess", 9)) {
                return 1001009;
            }

            /* .htpasswd */
            if (ci_match(str, len, i, ".htpasswd", 9)) {
                return 1001010;
            }

            /* .DS_Store */
            if (ci_match(str, len, i, ".ds_store", 9)) {
                return 1001011;
            }

            /* backup.zip, backup.tar, backup.sql, backup.gz */
            if (ci_match(str, len, i, ".zip", 4) ||
                ci_match(str, len, i, ".tar", 4) ||
                ci_match(str, len, i, ".sql", 4) ||
                ci_match(str, len, i, ".bak", 4)) {
                /* Tylko jeśli poprzedza to 'backup' lub 'dump' */
                if (i >= 6 && ci_match(str, len, i-6, "backup", 6)) {
                    return 1001008;
                }
                if (i >= 4 && ci_match(str, len, i-4, "dump", 4)) {
                    return 1001008;
                }
            }
        }

        /* ----------------------------------------------------------------
         * URL-encoded path traversal: %2e%2e, %2f
         * ---------------------------------------------------------------- */
        if (c == '%') {
            if (ci_match(str, len, i, "%2e%2e", 6)) return 1001001;
            if (ci_match(str, len, i, "%2f%2e%2e", 9)) return 1001001;
        }

        /* ----------------------------------------------------------------
         * /etc/passwd, /etc/shadow, /etc/hosts
         * ---------------------------------------------------------------- */
        if (c == 'e' || c == 'E') {
            if (ci_match(str, len, i, "etc/passwd", 10)) return 1001002;
            if (ci_match(str, len, i, "etc/shadow", 10)) return 1001012;
            if (ci_match(str, len, i, "etc/hosts",  9))  return 1001013;
        }

        /* ----------------------------------------------------------------
         * WordPress rekon
         * ---------------------------------------------------------------- */
        if (c == 'w' || c == 'W') {
            if (ci_match(str, len, i, "wp-admin",   8)) return 1001006;
            if (ci_match(str, len, i, "wp-login",   8)) return 1001014;
            if (ci_match(str, len, i, "wp-content", 10)) return 1001015;
            if (ci_match(str, len, i, "wp-includes", 11)) return 1001016;
            if (ci_match(str, len, i, "xmlrpc.php", 10)) return 1001017;
        }

        /* ----------------------------------------------------------------
         * Administracja bazami danych
         * ---------------------------------------------------------------- */
        if (c == 'p' || c == 'P') {
            if (ci_match(str, len, i, "phpmyadmin", 10)) return 1001007;
            if (ci_match(str, len, i, "pma",         3)) {
                /* Tylko jako ścieżka: /pma/ */
                if ((i == 0 || str[i-1] == '/') &&
                    (i+3 >= len || str[i+3] == '/' || str[i+3] == '?')) {
                    return 1001007;
                }
            }
        }

        if (c == 'a' || c == 'A') {
            if (ci_match(str, len, i, "adminer",    7)) return 1001018;
        }

        /* ----------------------------------------------------------------
         * Panele administracyjne / frameworki
         * ---------------------------------------------------------------- */
        if (c == '/') {
            if (ci_match(str, len, i, "/admin",    6))   return 1001019;
            if (ci_match(str, len, i, "/manager",  8))   return 1001020; /* Tomcat */
            if (ci_match(str, len, i, "/console",  8))   return 1001021; /* JBoss */
            if (ci_match(str, len, i, "/actuator", 9))   return 1001022; /* Spring Boot */
            if (ci_match(str, len, i, "/shell",    6))   return 1001023;
            if (ci_match(str, len, i, "/cgi-bin",  8))   return 1001024;
            if (ci_match(str, len, i, "/.svn",     5))   return 1001025;
        }

        /* ----------------------------------------------------------------
         * Backup files
         * ---------------------------------------------------------------- */
        if (c == 'b' || c == 'B') {
            if (ci_match(str, len, i, "backup",    6)) {
                /* Znajdź rozszerzenie po 'backup' */
                size_t j = i + 6;
                while (j < len && str[j] != '.' && str[j] != '/' && str[j] != '?') j++;
                if (j < len && str[j] == '.') return 1001008;
            }
        }
    }

    return 0;
}


