import asyncio
import aiohttp
from parity_eval import MALICIOUS_FRAGMENTS, random_string
import random

async def find_miss():
    base_lumina = "http://localhost:8085/index.html?q="
    base_modsec = "http://localhost:8085/modsec/index.html?q="
    async with aiohttp.ClientSession() as session:
        for _ in range(500):
            frag = random.choice(MALICIOUS_FRAGMENTS)
            prefix = random_string(random.randint(0, 20))
            suffix = random_string(random.randint(0, 20))
            payload = f"{prefix}{frag}{suffix}"
            
            async with session.get(base_lumina + payload) as rl: lum = rl.status
            async with session.get(base_modsec + payload) as rm: mod = rm.status
            
            if lum == 403 and mod != 403:
                print(f"MODSEC MISSED! Payload: {repr(payload)}")
                return
        print("No misses found in 500 tries")
asyncio.run(find_miss())
