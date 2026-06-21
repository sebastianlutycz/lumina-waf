import asyncio
import aiohttp
async def debug():
    payloads = ["union select", "union%20select", "union+select"]
    base_lumina = "http://localhost:8085/index.html?q="
    async with aiohttp.ClientSession() as session:
        for p in payloads:
            async with session.get(base_lumina + p) as r:
                print(f"Lumina '{p}': {r.status}")
asyncio.run(debug())
