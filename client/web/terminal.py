from __future__ import annotations

from aiohttp import web

from common.web_terminal import setup_terminal_routes as setup_common_terminal_routes


def setup_terminal_routes(app: web.Application) -> None:
    setup_common_terminal_routes(
        app,
        create_session=api_terminal_new,
        attach_terminal_ws=ws_terminal,
        include_terminal_page=True,
    )


async def api_terminal_new(request: web.Request) -> dict[str, str | None]:
    client_app = request.app["client_app"]
    agent_id = request.query.get("agent_id")
    session_id = await client_app.create_shell_session(agent_id=agent_id)
    return {"session_id": session_id, "agent_id": agent_id}


async def ws_terminal(session_id: str, ws: web.WebSocketResponse, request: web.Request) -> None:
    client_app = request.app["client_app"]
    await client_app.attach_terminal_ws(session_id, ws)

