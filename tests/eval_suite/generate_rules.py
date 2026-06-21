import sys

def generate_lumina_c(num_rules, filepath):
    c_code = """
#include <stddef.h>

int lumina_waf_scan(const unsigned char *str, size_t len) {
    int threat = 0;
"""
    # Generate 1000 rules
    for i in range(1, num_rules + 1):
        # We will look for <scriptX> or unionX
        # To make it simple but impactful on the compiler:
        pattern = f"<script{i}>"
        pat_len = len(pattern)
        
        c_code += f"    if (len >= {pat_len}) {{\n"
        c_code += f"        for (size_t i = 0; i <= len - {pat_len}; i++) {{\n"
        
        conds = []
        for j, char in enumerate(pattern):
            conds.append(f"str[i+{j}] == '{char}'")
        
        c_code += f"            if ({' && '.join(conds)}) {{\n"
        c_code += f"                return {941000 + i};\n"
        c_code +=  "            }\n"
        c_code +=  "        }\n"
        c_code +=  "    }\n"
        
    c_code += """
    return threat;
}
"""
    with open(filepath, "w") as f:
        f.write(c_code)
    print(f"[*] Generated {num_rules} rules for LuminaWAF in {filepath}")

def generate_modsec_rules(num_rules, filepath):
    modsec_code = ""
    for i in range(1, num_rules + 1):
        modsec_code += f'SecRule ARGS "(?i)<script{i}>" "id:{941000 + i},phase:2,deny"\n'
        
    with open(filepath, "w") as f:
        f.write(modsec_code)
    print(f"[*] Generated {num_rules} rules for ModSecurity in {filepath}")

if __name__ == "__main__":
    num = 1000
    generate_lumina_c(num, "/home/sebastian/workspace/lumina-waf/src/parser_input.c")
    generate_modsec_rules(num, "/home/sebastian/workspace/lumina-waf/tests/eval_suite/modsec_1000_rules.conf")

