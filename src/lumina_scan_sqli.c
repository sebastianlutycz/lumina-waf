#include <stddef.h>
#include <stdint.h>

#define LUMINA_MAX_STEPS 1024

int lumina_scan_sqli(const unsigned char *str, size_t len, uint32_t active_scope) {
    (void)active_scope;
    for (size_t i = 0; i < len && i < LUMINA_MAX_STEPS; i++) {
        unsigned char c = str[i];

        if (c == '1') {
            if (i + 10 < len &&
                str[i+1] == '\'' &&
                (str[i+2] == ' ' || str[i+2] == '+') &&
                (str[i+3]|32) == 'o' &&
                (str[i+4]|32) == 'r' &&
                (str[i+5] == ' ' || str[i+5] == '+') &&
                str[i+6] == '1' &&
                str[i+7] == '=' &&
                str[i+8] == '1' &&
                (str[i+9] == '-' && str[i+10] == '-')) {
                return 1001000;
            }
        } else if ((c|0x20) == 'u') {
            if (i + 11 < len &&
                (str[i+1]|32) == 'n' &&
                (str[i+2]|32) == 'i' &&
                (str[i+3]|32) == 'o' &&
                (str[i+4]|32) == 'n' &&
                (str[i+5] == ' ' || str[i+5] == '+') &&
                (str[i+6]|32) == 's' &&
                (str[i+7]|32) == 'e' &&
                (str[i+8]|32) == 'l' &&
                (str[i+9]|32) == 'e' &&
                (str[i+10]|32) == 'c' &&
                (str[i+11]|32) == 't') {
                return 1001003;
            }
        }
    }

    return 0;
}
