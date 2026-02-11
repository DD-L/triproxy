from __future__ import annotations

from typing import Any, Awaitable, Callable

from aiohttp import web

CreateSessionHandler = Callable[[web.Request], Awaitable[dict[str, Any] | str]]
AttachWsHandler = Callable[[str, web.WebSocketResponse, web.Request], Awaitable[None]]
RouteGuard = Callable[[Callable[[web.Request], Awaitable[web.StreamResponse]]], Callable[[web.Request], Awaitable[web.StreamResponse]]]


def setup_terminal_static_routes(app: web.Application) -> None:
    app.router.add_static("/terminal_static", "common/web_terminal_static")
    app.router.add_static("/terminal_vendor", "client/web/static/js/vendor")


def setup_terminal_routes(
    app: web.Application,
    *,
    create_session: CreateSessionHandler,
    attach_terminal_ws: AttachWsHandler,
    guard: RouteGuard | None = None,
    include_terminal_page: bool = True,
) -> None:
    async def handle_terminal(_: web.Request) -> web.FileResponse:
        return web.FileResponse("common/web_terminal_static/terminal.html")

    async def api_terminal_new(request: web.Request) -> web.Response:
        payload = await create_session(request)
        if isinstance(payload, str):
            payload = {"session_id": payload}
        return web.json_response(payload)

    async def ws_terminal(request: web.Request) -> web.StreamResponse:
        session_id = request.match_info["session_id"]
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        await attach_terminal_ws(session_id, ws, request)
        return ws

    terminal_handler = handle_terminal
    new_handler = api_terminal_new
    ws_handler = ws_terminal
    if guard is not None:
        terminal_handler = guard(terminal_handler)
        new_handler = guard(new_handler)
        ws_handler = guard(ws_handler)

    if include_terminal_page:
        app.router.add_get("/terminal", terminal_handler)
    app.router.add_post("/api/terminal/new", new_handler)
    app.router.add_get("/ws/terminal/{session_id}", ws_handler)
