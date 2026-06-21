import random
import os
import glob

def load_seclists(base_dir):
    payloads = []
    # Load XSS payloads
    for filepath in glob.glob(f"{base_dir}/Fuzzing/XSS/**/*.txt", recursive=True):
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                lines = [line.strip() for line in f if line.strip()]
                payloads.extend(lines)
        except Exception as e:
            pass
    return list(set(payloads))

def generate_1m_dataset(filepath, seclist_payloads):
    benign_words = ["apple", "banana", "hello", "world", "test", "data", "id", "search", "user", "admin", "login", "config", "session"]
    with open(filepath, "w") as f:
        for i in range(1000000):
            if random.random() < 0.10 and seclist_payloads:
                payload = random.choice(seclist_payloads)
                if random.random() < 0.2:
                    rule_idx = random.randint(1, 1000)
                    payload += f"<script{rule_idx}>"
                f.write(f"{payload}\n")
            else:
                num_words = random.randint(1, 8)
                payload = "_".join(random.choices(benign_words, k=num_words))
                f.write(f"{payload}\n")
    print(f"[*] Generated 1,000,000 payloads in {filepath} (Seeded with SecLists)")

if __name__ == "__main__":
    payloads = load_seclists("/tmp/SecLists")
    print(f"Loaded {len(payloads)} unique malicious payloads from SecLists")
    generate_1m_dataset("/home/sebastian/workspace/lumina-waf/tests/eval_suite/dataset_1m_seclists.txt", payloads)
