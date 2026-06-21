import asyncio
import aiohttp
async def debug():
    payload = "union select"
    base_lumina = "http://localhost:8085/index.html?q="
    base_modsec = "http://localhost:8085/modsec/index.html?q="
    async with aiohttp.ClientSession() as session:
        async with session.get(base_lumina + payload) as r: print("Lumina:", r.status)
        async with session.get(base_modsec + payload) as r: print("Modsec:", r.status)
asyncio.run(debug())
