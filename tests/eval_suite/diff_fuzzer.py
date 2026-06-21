import asyncio
import aiohttp
import json
import os
import random
import string
import time

BASE_URL_LUMINA = "http://localhost:8085/index.html"
BASE_URL_MODSEC = "http://localhost:8086/modsec/index.html"
DIVERGENCE_FILE = "/home/sebastian/workspace/lumina-waf/tests/eval_suite/corpus/differential_divergence.jsonl"

def random_string(length):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def generate_mutant_payload():
    base_payloads = [
        "<script>", "union select", "<svg/onload=alert()>", "OR 1=1--", "javascript:alert(1)"
    ]
    payload = random.choice(base_payloads)
    
    # Mutacja 1: Zmiana wielkości liter
    if random.random() < 0.5:
        payload = "".join(random.choice([c.upper(), c.lower()]) for c in payload)
        
    # Mutacja 2: Wstawki przerwane
    if random.random() < 0.3:
        if "union" in payload.lower():
            payload = payload.lower().replace("union", f"un{random.choice(['/**', '%00', '%20'])}ion")
            
    # Mutacja 3: URL Encoding (Pojedynczy lub podwójny)
    if random.random() < 0.5:
        from urllib.parse import quote
        payload = quote(payload)
        if random.random() < 0.2:
            payload = quote(payload) # Podwójny
            
    # Mutacja 4: Unicode Trick (Fullwidth characters)
    if random.random() < 0.2:
        payload = payload.replace('<', '＜').replace('>', '＞')

    # Mutacja 5: Random noise dookoła
    prefix = random_string(random.randint(0, 50))
    suffix = random_string(random.randint(0, 50))
    
    return f"{prefix}{payload}{suffix}"

async def diff_fuzz_worker(session, idx, divergence_log):
    mutant = generate_mutant_payload()
    path = f"/?q={mutant}"
    
    lumina_url = BASE_URL_LUMINA.replace("/index.html", "") + path
    modsec_url = BASE_URL_MODSEC.replace("/modsec/index.html", "/modsec") + path
    
    try:
        async with session.get(lumina_url) as rl: lum = rl.status
    except:
        lum = 500
        
    try:
        async with session.get(modsec_url) as rm: mod = rm.status
    except:
        mod = 500
        
    if lum != mod:
        # Divergence found!
        record = {
            "id": f"fuzz_{idx}",
            "payload": mutant,
            "lumina_status": lum,
            "modsec_status": mod,
            "timestamp": time.time()
        }
        divergence_log.append(record)
        with open(DIVERGENCE_FILE, "a") as f:
            f.write(json.dumps(record) + "\n")

async def run_fuzzer(iterations=10000):
    print(f"Starting Differential Fuzzer for {iterations} iterations...")
    if os.path.exists(DIVERGENCE_FILE):
        os.remove(DIVERGENCE_FILE)
        
    divergence_log = []
    chunk_size = 500
    connector = aiohttp.TCPConnector(limit=500)
    async with aiohttp.ClientSession(connector=connector) as session:
        for i in range(0, iterations, chunk_size):
            tasks = [diff_fuzz_worker(session, i + j, divergence_log) for j in range(chunk_size)]
            await asyncio.gather(*tasks)
            if i % 1000 == 0:
                print(f"[{i}/{iterations}] Divergences found so far: {len(divergence_log)}")
                
    print(f"Fuzzing complete. Total divergences: {len(divergence_log)}")
    print(f"Saved to {DIVERGENCE_FILE}")

if __name__ == "__main__":
    asyncio.run(run_fuzzer())
