import asyncio
import aiohttp
import urllib.parse
async def debug():
    payload = 'F)HqH@ vX@G-vWWPF<script>93urYmkaof(&88q#O8Ql'
    print("URL Encoded:", urllib.parse.quote(payload))
    base_lumina = "http://localhost:8085/index.html?q="
    async with aiohttp.ClientSession() as session:
        async with session.get(base_lumina + payload) as r:
            print("Lumina Status:", r.status)
asyncio.run(debug())
