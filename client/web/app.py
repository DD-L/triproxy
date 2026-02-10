from __future__ import annotations

from aiohttp import web

from client.web.dashboard import setup_dashboard_routes
from client.web.terminal import setup_terminal_routes


def create_web_app(client_app) -> web.Application:
    app = web.Application()
    app["client_app"] = client_app
    setup_dashboard_routes(app)
    setup_terminal_routes(app)
    setup_api_routes(app)
    app.router.add_static("/static", "client/web/static")
    return app


def setup_api_routes(app: web.Application) -> None:
    app.router.add_get("/api/status", api_status)
    app.router.add_get("/api/services", api_services)
    app.router.add_post("/api/services/directed", api_add_directed)
    app.router.add_put("/api/services/directed/{rule_id}", api_update_directed)
    app.router.add_delete("/api/services/directed/{rule_id}", api_delete_directed)
    app.router.add_post("/api/services/{stype}/toggle", api_toggle_service)
    app.router.add_get("/api/sessions", api_sessions)
    app.router.add_delete("/api/sessions/{session_id}", api_kill_session)
    app.router.add_post("/api/agent/password", api_agent_password)


async def api_status(request: web.Request) -> web.Response:
    return web.json_response(await request.app["client_app"].get_status())


async def api_services(request: web.Request) -> web.Response:
    return web.json_response(await request.app["client_app"].get_services())


async def api_add_directed(request: web.Request) -> web.Response:
    data = await request.json()
    result = await request.app["client_app"].add_directed_rule(data)
    return web.json_response(result)


async def api_update_directed(request: web.Request) -> web.Response:
    rid = request.match_info["rule_id"]
    data = await request.json()
    result = await request.app["client_app"].update_directed_rule(rid, data)
    return web.json_response(result)


async def api_delete_directed(request: web.Request) -> web.Response:
    rid = request.match_info["rule_id"]
    await request.app["client_app"].delete_directed_rule(rid)
    return web.json_response({"ok": True})


async def api_toggle_service(request: web.Request) -> web.Response:
    stype = request.match_info["stype"]
    data = await request.json()
    enabled = bool(data.get("enabled", True))
    result = await request.app["client_app"].toggle_service(stype, enabled)
    return web.json_response(result)


async def api_sessions(request: web.Request) -> web.Response:
    return web.json_response(await request.app["client_app"].list_sessions())


async def api_kill_session(request: web.Request) -> web.Response:
    sid = request.match_info["session_id"]
    await request.app["client_app"].kill_session(sid)
    return web.json_response({"ok": True})


async def api_agent_password(request: web.Request) -> web.Response:
    data = await request.json()
    new_hash = str(data.get("new_password_hash", ""))
    await request.app["client_app"].change_agent_password(new_hash)
    return web.json_response({"ok": True})

