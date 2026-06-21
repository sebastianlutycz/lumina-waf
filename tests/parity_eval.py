#!/usr/bin/env python3
import asyncio
import aiohttp
import random
import string
import time

NUM_BENIGN = 100000
NUM_MALICIOUS = 10000

# Mutacje, które mają szansę zmylić prymitywne parsery
MALICIOUS_FRAGMENTS = [
    "<script>",
    "<ScRiPt>",
    "union select",
    "uNiOn sElEcT",
]

def random_string(length):
    return ''.join(random.choices(string.ascii_letters + string.digits + " !@#%^&*()-_=+", k=length))

def generate_corpus():
    print("Generowanie korpusu testowego...")
    corpus = []
    
    # 1. Benign (Łagodne)
    for _ in range(NUM_BENIGN):
        # Unikamy przypadkowego wygenerowania sygnatur
        s = random_string(random.randint(5, 50))
        if "<script" in s.lower() or "union select" in s.lower():
            continue
        corpus.append((s, False))
        
    # 2. Malicious (Złośliwe)
    for _ in range(NUM_MALICIOUS):
        frag = random.choice(MALICIOUS_FRAGMENTS)
        prefix = random_string(random.randint(0, 20))
        suffix = random_string(random.randint(0, 20))
        payload = f"{prefix}{frag}{suffix}"
        corpus.append((payload, True))
        
    random.shuffle(corpus)
    return corpus

async def fetch(session, url):
    try:
        async with session.get(url) as response:
            return response.status
    except Exception:
        return 0

async def run_eval():
    corpus = generate_corpus()
    total = len(corpus)
    print(f"Wygenerowano {total} żądań.")
    
    # URL bases
    base_lumina = "http://localhost:8085/index.html?q="
    base_modsec = "http://localhost:8085/modsec/index.html?q="
    
    results = {'parity_ok': 0, 'lumina_miss': 0, 'modsec_miss': 0, 'lumina_fp': 0, 'modsec_fp': 0}
    
    print("Rozpoczynam zmasowany atak ewaluacyjny (Data Parity)...")
    start_time = time.time()
    
    connector = aiohttp.TCPConnector(limit=1000)
    async with aiohttp.ClientSession(connector=connector) as session:
        # Przetwarzamy w chunkach, by nie zapchać portów
        chunk_size = 5000
        for i in range(0, total, chunk_size):
            chunk = corpus[i:i+chunk_size]
            
            tasks_lumina = [fetch(session, base_lumina + payload[0]) for payload in chunk]
            tasks_modsec = [fetch(session, base_modsec + payload[0]) for payload in chunk]
            
            lumina_statuses = await asyncio.gather(*tasks_lumina)
            modsec_statuses = await asyncio.gather(*tasks_modsec)
            
            for j in range(len(chunk)):
                expected_threat = chunk[j][1]
                lum_status = lumina_statuses[j]
                mod_status = modsec_statuses[j]
                
                lum_blocked = (lum_status == 403)
                mod_blocked = (mod_status == 403)
                
                if lum_blocked == mod_blocked == expected_threat:
                    results['parity_ok'] += 1
                else:
                    if expected_threat:
                        if not lum_blocked and mod_blocked: results['lumina_miss'] += 1
                        elif lum_blocked and not mod_blocked: results['modsec_miss'] += 1
                    else:
                        if lum_blocked and not mod_blocked: results['lumina_fp'] += 1
                        elif not lum_blocked and mod_blocked: results['modsec_fp'] += 1

            progress = min(100, int((i + chunk_size) / total * 100))
            print(f"[{progress}%] Przetworzono {i+len(chunk)}/{total}...")
            
    elapsed = time.time() - start_time
    print(f"\nZakończono w {elapsed:.2f} sekundy.")
    print("\n--- WYNIKI DATA PARITY ---")
    print(f"Łącznie zapytań: {total}")
    print(f"Zgodność 1:1: {results['parity_ok']} ({(results['parity_ok']/total)*100:.2f}%)")
    print(f"LuminaWAF przepuścił atak (FN): {results['lumina_miss']}")
    print(f"ModSecurity przepuścił atak (FN): {results['modsec_miss']}")
    print(f"LuminaWAF fałszywy alarm (FP): {results['lumina_fp']}")
    print(f"ModSecurity fałszywy alarm (FP): {results['modsec_fp']}")

if __name__ == "__main__":
    asyncio.run(run_eval())
