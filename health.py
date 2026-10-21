"""HTTP health server for PaaS platforms that require a bound port (Render)."""
from __future__ import annotations

import logging
import os

from aiohttp import web

logger = logging.getLogger("obfuscator-bot")


async def start_health_server() -> web.AppRunner:
    async def health(_: web.Request) -> web.Response:
        return web.json_response({"status": "ok", "service": "obfuscator-bot"})

    app = web.Application()
    app.router.add_get("/", health)
    app.router.add_get("/health", health)

    port = int(os.getenv("PORT", "8080"))
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", port)
    await site.start()
    logger.info("Health server listening on 0.0.0.0:%s", port)
    return runner
