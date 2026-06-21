import random

def generate_1m_dataset(filepath):
    # Benign variations
    benign_words = ["apple", "banana", "hello", "world", "test", "data", "id", "search", "user"]
    
    with open(filepath, "w") as f:
        for i in range(1000000):
            if random.random() < 0.05:
                # 5% chance of attack (1 of the 1000 rules)
                rule_idx = random.randint(1, 1000)
                # random prefix and suffix
                prefix = "".join(random.choices("abcdef", k=random.randint(0, 10)))
                suffix = "".join(random.choices("abcdef", k=random.randint(0, 10)))
                f.write(f"{prefix}<script{rule_idx}>{suffix}\n")
            else:
                # benign
                num_words = random.randint(1, 5)
                payload = "_".join(random.choices(benign_words, k=num_words))
                f.write(f"{payload}\n")
    print(f"[*] Generated 1,000,000 payloads in {filepath}")

if __name__ == "__main__":
    generate_1m_dataset("/home/sebastian/workspace/lumina-waf/tests/eval_suite/dataset_1m.txt")
