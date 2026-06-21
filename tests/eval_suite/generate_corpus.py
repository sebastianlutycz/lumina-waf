import json
import random
import string
import os

CORPUS_DIR = os.path.dirname(os.path.abspath(__file__)) + "/corpus"
os.makedirs(CORPUS_DIR, exist_ok=True)

def random_string(length):
    return ''.join(random.choices(string.ascii_letters + string.digits + " !@#%^&*()-_=+", k=length))

def unicode_fuzz(s):
    # Proste fullwidth wstawki, etc.
    return s.replace('<', '＜').replace('>', '＞')

def urlencode(s):
    from urllib.parse import quote
    return quote(s)

def obfuscate(s):
    return s.replace(' ', '/**/').replace('e', '%65').replace('E', '%45')

def generate():
    records = []
    _id = 1000

    def add(req, verdict, rule, category):
        nonlocal _id
        records.append({
            "id": f"rec_{_id}",
            "request": req,
            "expected_verdict": verdict,
            "expected_rule": rule,
            "category": category
        })
        _id += 1

    # Zbiór 1: Real Traffic (Benign)
    benign_words = ["products", "login", "api/orders", "home", "dashboard"]
    for _ in range(5000):
        req = f"GET /{random.choice(benign_words)}?q={random_string(random.randint(5, 20))}"
        add(req, "ALLOW", None, "Real Traffic")

    # Zbiór 3: SQLMap (rule 2)
    sqli_base = ["union select", "UNION SELECT", "UnIoN+SeLeCt", "union/**/select"]
    for _ in range(2000):
        frag = random.choice(sqli_base)
        req = f"GET /api/data?id={random_string(10)}{frag}{random_string(10)}"
        add(req, "BLOCK", 2, "SQLMap")

    # Zbiór 4: XSS (rule 1)
    xss_base = ["<script>", "<ScRiPt>", "<sCrIpt>"]
    for _ in range(2000):
        frag = random.choice(xss_base)
        req = f"GET /search?q={random_string(10)}{frag}{random_string(10)}"
        add(req, "BLOCK", 1, "XSS")

    # Zbiór 5 & 6: Obfuscation & Unicode
    for _ in range(500):
        frag = unicode_fuzz("<script>")
        add(f"GET /?q={frag}", "BLOCK", 1, "Unicode")
        
        frag2 = obfuscate("union select")
        add(f"GET /?q={frag2}", "BLOCK", 2, "Obfuscation")

    # Zbiór 7: Fuzz (random garbage)
    for _ in range(5000):
        add(f"GET /?q={random_string(50)}", "ALLOW", None, "Fuzz")

    out_path = os.path.join(CORPUS_DIR, "ground_truth.jsonl")
    with open(out_path, "w") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")
            
    print(f"Generated {len(records)} records at {out_path}")

if __name__ == "__main__":
    generate()
