from __future__ import annotations

from aiohttp import web


def setup_dashboard_routes(app: web.Application) -> None:
    app.router.add_get("/", handle_root)
    app.router.add_get("/dashboard", handle_dashboard)
    app.router.add_get("/terminal", handle_terminal)


async def handle_root(_: web.Request) -> web.Response:
    raise web.HTTPFound("/dashboard")


async def handle_dashboard(_: web.Request) -> web.FileResponse:
    return web.FileResponse("client/web/static/dashboard.html")


async def handle_terminal(_: web.Request) -> web.FileResponse:
    return web.FileResponse("client/web/static/terminal.html")

