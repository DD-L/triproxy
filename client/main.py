from __future__ import annotations

import argparse
import asyncio
import contextlib
import signal
import time
from typing import Any

from aiohttp import web

from client.control import ClientControlConnection
from client.directed import DirectedProxyManager
from client.general import GeneralProxyServer
from client.pool import ClientPoolManager
from client.session import ClientSessionManager
from client.shell_client import ShellClient
from client.web.app import create_web_app
from common.config import load_yaml, require_keys, save_yaml
from common.log import setup_logging
from common.protocol import MsgType


class ClientApp:
    def __init__(self, config: dict[str, Any], config_path: str):
        self.config = config
        self.config_path = config_path
        self.started_at = time.time()
        self.pool_manager = ClientPoolManager(
            config["relay_host"],
            int(config["relay_port_client"]),
            heartbeat_interval=int(config.get("heartbeat_interval", 100)),
            dead_timeout=300,
        )
        self.session_manager = ClientSessionManager(self.pool_manager, self._send_control)
        self.directed_manager = DirectedProxyManager(self.session_manager, agent_id=config.get("agent_id", "default"))
        general_cfg = config.get("services", {}).get("general", {})
        self.general_proxy = GeneralProxyServer(
            self.session_manager,
            bind=general_cfg.get("bind", "127.0.0.1"),
            port=int(general_cfg.get("local_port", 3000)),
            agent_id=config.get("agent_id", "default"),
        )
        self.shell_client = ShellClient()

        self.control: ClientControlConnection | None = None
        self._control_task: asyncio.Task[Any] | None = None
        self.web_app = create_web_app(self)
        self.web_runner: web.AppRunner | None = None
        self.web_site: web.TCPSite | None = None
        self.shell_sessions: dict[str, dict[str, Any]] = {}

    async def _send_control(self, msg_type: str, **fields: Any) -> None:
        if self.control:
            await self.control.send(msg_type, **fields)

    async def on_control_message(self, msg: dict[str, Any]) -> None:
        msg_type = msg.get("type")
        if msg_type == MsgType.POOL_ALLOC.value:
            tokens = [str(t) for t in msg.get("tokens", [])]
            if self.control and self.control.ctrl_key:
                await self.pool_manager.put_tokens(tokens, self.control.ctrl_key)
                for token in tokens:
                    await self._send_control(MsgType.POOL_READY.value, pool_token=token)
            return
        if msg_type == MsgType.POOL_SHRINK.value:
            token = str(msg.get("pool_token", ""))
            if token:
                await self.pool_manager.remove(token)
            return
        if msg_type in (
            MsgType.SESSION_ASSIGN.value,
            MsgType.SESSION_FAIL.value,
            MsgType.SESSION_CLOSE.value,
        ):
            await self.session_manager.on_control_message(msg)
            return

    async def on_connected(self, _: bytes) -> None:
        pass

    async def on_disconnected(self) -> None:
        await self.pool_manager.close_all()

    async def start_control_loop(self) -> None:
        self.control = ClientControlConnection(
            self.config,
            on_message=self.on_control_message,
            on_connected=self.on_connected,
            on_disconnected=self.on_disconnected,
        )
        self._control_task = asyncio.create_task(self.control.run(), name="client-control-loop")

    async def start_services(self) -> None:
        directed_rules = self.config.get("services", {}).get("directed", [])
        await self.directed_manager.load_rules(directed_rules)
        if self.config.get("services", {}).get("general", {}).get("enabled", True):
            await self.general_proxy.start()
        if self.config.get("services", {}).get("shell", {}).get("enabled", True):
            await self.start_web()

    async def start_web(self) -> None:
        if self.web_runner is not None:
            return
        port = int(self.config.get("services", {}).get("shell", {}).get("local_port", 3001))
        self.web_runner = web.AppRunner(self.web_app)
        await self.web_runner.setup()
        self.web_site = web.TCPSite(self.web_runner, "127.0.0.1", port)
        await self.web_site.start()

    async def stop_web(self) -> None:
        if self.web_runner:
            await self.web_runner.cleanup()
            self.web_runner = None
            self.web_site = None

    async def _close_shell_sessions(self) -> None:
        for sid, ctx in list(self.shell_sessions.items()):
            with contextlib.suppress(Exception):
                await self.pool_manager.put_back(ctx["pool_token"], ctx["pool_conn"])
            with contextlib.suppress(Exception):
                await self.session_manager.close_session(sid)
            self.shell_sessions.pop(sid, None)

    async def start(self) -> None:
        await self.start_control_loop()
        await self.start_services()
        if self._control_task:
            await self._control_task

    async def shutdown(self) -> None:
        if self.control:
            await self.control.stop()
        if self._control_task:
            self._control_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._control_task
        await self._close_shell_sessions()
        await self.general_proxy.stop()
        await self.stop_web()
        await self.pool_manager.close_all()

    async def get_status(self) -> dict[str, Any]:
        return {
            "connected": self.control is not None and self.control.ctrl_key is not None,
            "pool_size": await self.pool_manager.size(),
            "active_sessions": len(self.session_manager.active),
            "uptime": time.time() - self.started_at,
        }

    async def get_services(self) -> dict[str, Any]:
        return {
            "directed": [
                {
                    "id": r.rule_id,
                    "local_port": r.local_port,
                    "target_url": r.target_url,
                    "enabled": r.enabled,
                }
                for r in self.directed_manager.rules.values()
            ],
            "general": self.config.get("services", {}).get("general", {}),
            "shell": self.config.get("services", {}).get("shell", {}),
        }

    async def add_directed_rule(self, data: dict[str, Any]) -> dict[str, Any]:
        rule = await self.directed_manager.add_rule(data)
        rules = self.config.setdefault("services", {}).setdefault("directed", [])
        rules.append(
            {
                "id": rule.rule_id,
                "local_port": rule.local_port,
                "target_url": rule.target_url,
                "enabled": rule.enabled,
            }
        )
        save_yaml(self.config_path, self.config)
        return {"ok": True, "id": rule.rule_id}

    async def update_directed_rule(self, rule_id: str, data: dict[str, Any]) -> dict[str, Any]:
        rule = await self.directed_manager.update_rule(rule_id, data)
        rules = self.config.setdefault("services", {}).setdefault("directed", [])
        for item in rules:
            if item.get("id") == rule_id:
                item.update(
                    {
                        "local_port": rule.local_port,
                        "target_url": rule.target_url,
                        "enabled": rule.enabled,
                    }
                )
                break
        save_yaml(self.config_path, self.config)
        return {"ok": True, "id": rule.rule_id}

    async def delete_directed_rule(self, rule_id: str) -> None:
        await self.directed_manager.remove_rule(rule_id)
        rules = self.config.setdefault("services", {}).setdefault("directed", [])
        self.config["services"]["directed"] = [r for r in rules if r.get("id") != rule_id]
        save_yaml(self.config_path, self.config)

    async def toggle_service(self, stype: str, enabled: bool) -> dict[str, Any]:
        if stype not in {"directed", "general", "shell"}:
            raise ValueError(f"unsupported service type: {stype}")
        services = self.config.setdefault("services", {})
        if stype == "directed":
            rules = services.setdefault("directed", [])
            await self.directed_manager.set_all_enabled(enabled)
            for item in rules:
                item["enabled"] = enabled
        elif stype == "general":
            general_cfg = services.setdefault("general", {})
            general_cfg["enabled"] = enabled
            if enabled:
                await self.general_proxy.start()
            else:
                await self.general_proxy.stop()
        elif stype == "shell":
            shell_cfg = services.setdefault("shell", {})
            shell_cfg["enabled"] = enabled
            if enabled:
                await self.start_web()
            else:
                await self._close_shell_sessions()
                await self.stop_web()
        save_yaml(self.config_path, self.config)
        return {"ok": True, "service": stype, "enabled": enabled}

    async def list_sessions(self) -> dict[str, Any]:
        return {"sessions": list(self.session_manager.active.keys())}

    async def kill_session(self, session_id: str) -> None:
        await self.session_manager.close_session(session_id)

    async def create_shell_session(self) -> str:
        assign = await self.session_manager.request_session("shell", None, self.config.get("agent_id", "default"))
        sid, data_key, token, pool_conn = await self.session_manager.use_assigned_pool(assign)
        self.shell_sessions[sid] = {"data_key": data_key, "pool_conn": pool_conn, "pool_token": token}
        return sid

    async def attach_terminal_ws(self, session_id: str, ws: web.WebSocketResponse) -> None:
        ctx = self.shell_sessions.get(session_id)
        if not ctx:
            await ws.close(message=b"invalid_session")
            return
        try:
            await self.shell_client.handle_websocket(ws, ctx["data_key"], ctx["pool_conn"])
        finally:
            with contextlib.suppress(Exception):
                await self.pool_manager.put_back(ctx["pool_token"], ctx["pool_conn"])
            self.shell_sessions.pop(session_id, None)
            await self.session_manager.close_session(session_id)

    async def change_agent_password(self, new_password_hash: str) -> None:
        await self._send_control(MsgType.AGENT_PWD_CHANGE.value, new_password_hash=new_password_hash)


def _install_signal_handlers(app: ClientApp) -> None:
    loop = asyncio.get_running_loop()

    async def _shutdown() -> None:
        await app.shutdown()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, lambda: asyncio.create_task(_shutdown()))
        except NotImplementedError:
            signal.signal(sig, lambda *_: asyncio.create_task(_shutdown()))


async def _amain(config_path: str) -> None:
    cfg = load_yaml(config_path)
    require_keys(
        cfg,
        ["relay_host", "relay_port_client", "rsa_private_key", "rsa_public_key", "services"],
        where="client config",
    )
    setup_logging(cfg.get("log_level", "info"))
    app = ClientApp(cfg, config_path=config_path)
    _install_signal_handlers(app)
    await app.start()


def main() -> None:
    parser = argparse.ArgumentParser(description="TriProxy Client")
    parser.add_argument("config", help="path to client yaml config")
    args = parser.parse_args()
    asyncio.run(_amain(args.config))


if __name__ == "__main__":
    main()

