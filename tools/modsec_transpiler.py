#!/usr/bin/env python3
import re
import sys

def parse_modsec_conf(conf_path):
    rules = []
    with open(conf_path, 'r') as f:
        for line in f:
            line = line.strip()
            # Przykładowy format: SecRule ARGS "@rx <script>" "id:1,deny,status:403,msg:'XSS'"
            if line.startswith('SecRule'):
                match = re.search(r'@rx\s+([^"]+)"\s+"id:(\d+)', line)
                if match:
                    pattern = match.group(1)
                    rule_id = match.group(2)
                    rules.append({'pattern': pattern, 'id': rule_id})
    return rules

def generate_c_code(rules):
    c_code = ""
    for rule in rules:
        pattern = rule['pattern'].lower()  # Normalizacja do lowercase
        rule_id = rule['id']
        length = len(pattern)
        
        c_code += f"    if (len >= {length}) {{\n"
        c_code += f"        for (size_t i = 0; i <= len - {length}; i++) {{\n"
        
        conditions = []
        for i, char in enumerate(pattern):
            if char.isalpha():
                # Case insensitive bitmask (ASCII)
                conditions.append(f"(str[i+{i}]|32) == '{char}'")
            elif char == ' ':
                conditions.append(f"(str[i+{i}] == ' ' || str[i+{i}] == '+')")
            else:
                if char == '\\':
                    char = '\\\\'
                elif char == "'":
                    char = "\\'"
                conditions.append(f"str[i+{i}] == '{char}'")
        
        c_code += f"            if ({' && '.join(conditions)}) {{\n"
        c_code += f"                threat = {rule_id};\n"
        c_code += f"            }}\n"
        c_code += f"        }}\n"
        c_code += f"    }}\n"
    return c_code

def inject_code(target_c_file, c_code):
    with open(target_c_file, 'r') as f:
        content = f.read()
    
    start_marker = "// -- RULES START --"
    end_marker = "// -- RULES END --"
    
    start_idx = content.find(start_marker)
    end_idx = content.find(end_marker)
    
    if start_idx == -1 or end_idx == -1:
        print("Nie znaleziono znaczników RULES START/END w pliku C!")
        sys.exit(1)
        
    start_idx += len(start_marker)
    
    new_content = content[:start_idx] + "\n" + c_code + "    " + content[end_idx:]
    
    with open(target_c_file, 'w') as f:
        f.write(new_content)
    print(f"Pomyślnie wstrzyknięto {c_code.count('threat =')} reguł do {target_c_file}.")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Użycie: python3 modsec_transpiler.py <modsec.conf> <parser_input.c>")
        sys.exit(1)
        
    conf_file = sys.argv[1]
    c_file = sys.argv[2]
    
    rules = parse_modsec_conf(conf_file)
    print(f"Znaleziono reguł ModSecurity: {len(rules)}")
    
    generated_c = generate_c_code(rules)
    inject_code(c_file, generated_c)
