from __future__ import annotations

from aiohttp import web


def setup_terminal_routes(app: web.Application) -> None:
    app.router.add_post("/api/terminal/new", api_terminal_new)
    app.router.add_get("/ws/terminal/{session_id}", ws_terminal)


async def api_terminal_new(request: web.Request) -> web.Response:
    client_app = request.app["client_app"]
    session_id = await client_app.create_shell_session()
    return web.json_response({"session_id": session_id})


async def ws_terminal(request: web.Request) -> web.StreamResponse:
    client_app = request.app["client_app"]
    session_id = request.match_info["session_id"]
    ws = web.WebSocketResponse()
    await ws.prepare(request)
    await client_app.attach_terminal_ws(session_id, ws)
    return ws

