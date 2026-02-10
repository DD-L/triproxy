from __future__ import annotations

import asyncio
import hashlib
import secrets
import time
from typing import Any, Callable

from aiohttp import web

from common.config import save_yaml


class AgentWebConsole:
    def __init__(
        self,
        config: dict[str, Any],
        config_path: str,
        get_status: Callable[[], dict[str, Any]],
        on_connect: Callable[[], Any],
        on_disconnect: Callable[[], Any],
        on_password_change: Callable[[str], Any] | None = None,
    ):
        self.config = config
        self.config_path = config_path
        self.get_status = get_status
        self.on_connect = on_connect
        self.on_disconnect = on_disconnect
        self.on_password_change = on_password_change
        self.app = web.Application()
        self.runner: web.AppRunner | None = None
        self.site: web.TCPSite | None = None
        self.nonces: dict[str, float] = {}
        self.sessions: dict[str, float] = {}
        self._setup_routes()

    def _setup_routes(self) -> None:
        self.app.router.add_get("/", self.index)
        self.app.router.add_static("/static", "agent/web_console_static")
        self.app.router.add_get("/api/nonce", self.api_nonce)
        self.app.router.add_post("/api/login", self.api_login)
        self.app.router.add_get("/api/status", self.auth(self.api_status))
        self.app.router.add_post("/api/connect", self.auth(self.api_connect))
        self.app.router.add_post("/api/disconnect", self.auth(self.api_disconnect))
        self.app.router.add_post("/api/password", self.api_password)
        self.app.router.add_get("/api/logout", self.auth(self.api_logout))

    def auth(self, handler: Callable[[web.Request], Any]):
        async def _wrapped(request: web.Request):
            token = request.cookies.get("triproxy_session", "")
            exp = self.sessions.get(token, 0)
            if exp < time.time():
                return web.json_response({"ok": False, "error": "unauthorized"}, status=401)
            return await handler(request)

        return _wrapped

    async def index(self, _: web.Request) -> web.Response:
        return web.FileResponse("agent/web_console_static/index.html")

    async def api_nonce(self, _: web.Request) -> web.Response:
        nonce = secrets.token_hex(32)
        self.nonces[nonce] = time.time() + 60
        return web.json_response({"nonce": nonce})

    async def api_login(self, request: web.Request) -> web.Response:
        data = await request.json()
        nonce = str(data.get("nonce", ""))
        response_hash = str(data.get("response", ""))
        nonce_exp = self.nonces.pop(nonce, 0)
        if nonce_exp < time.time():
            return web.json_response({"ok": False, "error": "nonce_expired"}, status=400)
        stored_hash = str(self.config.get("web_console_password_hash", ""))
        expected = hashlib.sha256((stored_hash + nonce).encode("utf-8")).hexdigest()
        if expected != response_hash:
            return web.json_response({"ok": False, "error": "invalid_credentials"}, status=401)
        token = secrets.token_hex(32)
        self.sessions[token] = time.time() + 12 * 3600
        resp = web.json_response({"ok": True})
        resp.set_cookie("triproxy_session", token, httponly=True, max_age=12 * 3600)
        return resp

    async def api_status(self, _: web.Request) -> web.Response:
        return web.json_response(self.get_status())

    async def api_connect(self, _: web.Request) -> web.Response:
        await self.on_connect()
        return web.json_response({"ok": True})

    async def api_disconnect(self, _: web.Request) -> web.Response:
        await self.on_disconnect()
        return web.json_response({"ok": True})

    async def api_password(self, request: web.Request) -> web.Response:
        # First-boot setup is allowed without existing authenticated session when no password is set yet.
        if self.config.get("web_console_password_hash"):
            token = request.cookies.get("triproxy_session", "")
            exp = self.sessions.get(token, 0)
            if exp < time.time():
                return web.json_response({"ok": False, "error": "unauthorized"}, status=401)
        data = await request.json()
        new_hash = str(data.get("new_password_hash", ""))
        if len(new_hash) != 64:
            return web.json_response({"ok": False, "error": "invalid_hash"}, status=400)
        self.config["web_console_password_hash"] = new_hash
        save_yaml(self.config_path, self.config)
        if self.on_password_change:
            await self.on_password_change(new_hash)
        return web.json_response({"ok": True})

    async def api_logout(self, request: web.Request) -> web.Response:
        token = request.cookies.get("triproxy_session", "")
        self.sessions.pop(token, None)
        resp = web.json_response({"ok": True})
        resp.del_cookie("triproxy_session")
        return resp

    async def start(self) -> None:
        bind = self.config.get("web_console_bind", "127.0.0.1")
        port = int(self.config.get("web_console_port", 3002))
        self.runner = web.AppRunner(self.app)
        await self.runner.setup()
        self.site = web.TCPSite(self.runner, bind, port)
        await self.site.start()

    async def stop(self) -> None:
        if self.runner:
            await self.runner.cleanup()

