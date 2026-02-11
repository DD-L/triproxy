from __future__ import annotations

import argparse
import asyncio
import signal
import time
from typing import Any

from agent.control import AgentControlConnection
from agent.pool import AgentPoolManager
from agent.session import AgentSessionHandler
from agent.web_console import AgentWebConsole
from common.config import load_yaml, require_keys, save_yaml
from common.log import setup_logging
from common.protocol import MsgType


class AgentApp:
    def __init__(self, config: dict[str, Any], config_path: str):
        self.config = config
        self.config_path = config_path
        self.started_at = time.time()
        self.pool_manager = AgentPoolManager(
            config["relay_host"],
            int(config["relay_port_agent"]),
            heartbeat_interval=int(config.get("heartbeat_interval", 100)),
            dead_timeout=300,
        )
        self.control: AgentControlConnection | None = None
        self.session_handler = AgentSessionHandler(self.pool_manager, self._send_control, config=config)
        self.web_console = AgentWebConsole(
            config,
            config_path=config_path,
            get_status=self.get_status,
            on_connect=self.connect_now,
            on_disconnect=self.disconnect_now,
            on_password_change=self.on_password_change,
        )
        self._control_task: asyncio.Task[Any] | None = None

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
        if msg_type == MsgType.SESSION_ASSIGN.value:
            await self.session_handler.on_session_assign(msg)
            return
        if msg_type == MsgType.SESSION_CLOSE.value:
            sid = str(msg.get("session_id", ""))
            if sid:
                await self.session_handler.close_session(sid)
            return
        if msg_type == MsgType.AGENT_STATUS_REQ.value:
            await self._send_control(
                MsgType.AGENT_STATUS_RESP.value,
                connected=self.control is not None and self.control.ctrl_key is not None,
                pool_size=await self.pool_manager.size(),
                active_sessions=self.session_handler.active_count(),
                uptime=time.time() - self.started_at,
            )
            return
        if msg_type == MsgType.AGENT_PWD_CHANGE.value:
            new_hash = str(msg.get("new_password_hash", ""))
            if len(new_hash) == 64:
                self.config["web_console_password_hash"] = new_hash
                save_yaml(self.config_path, self.config)
                await self._send_control(MsgType.AGENT_PWD_CHANGED.value)

    async def on_connected(self, _: bytes) -> None:
        pass

    async def on_disconnected(self) -> None:
        await self.pool_manager.close_all()
        await self.session_handler.close_all()

    async def on_password_change(self, _new_hash: str) -> None:
        # Hook point for extra side effects (audit/log/notification) when password changes.
        return

    async def start_control_loop(self) -> None:
        self.control = AgentControlConnection(
            self.config,
            on_message=self.on_control_message,
            on_connected=self.on_connected,
            on_disconnected=self.on_disconnected,
        )
        self._control_task = asyncio.create_task(self.control.run(), name="agent-control-loop")

    async def connect_now(self) -> None:
        if self._control_task and not self._control_task.done():
            return
        await self.start_control_loop()

    async def disconnect_now(self) -> None:
        if self.control:
            await self.control.stop()
        if self._control_task:
            self._control_task.cancel()

    def get_status(self) -> dict[str, Any]:
        return {
            "connected": self.control is not None and self.control.ctrl_key is not None,
            "active_sessions": self.session_handler.active_count(),
            "uptime": time.time() - self.started_at,
        }

    async def start(self) -> None:
        await self.web_console.start()
        await self.start_control_loop()
        if self._control_task:
            await self._control_task

    async def shutdown(self) -> None:
        # Keep control channel alive briefly so SESSION_CLOSE can be delivered.
        await self.session_handler.close_all()
        await asyncio.sleep(0.1)
        await self.disconnect_now()
        await self.web_console.stop()


def _install_signal_handlers(app: AgentApp) -> None:
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
        ["relay_host", "relay_port_agent", "rsa_private_key", "rsa_public_key", "web_console_port"],
        where="agent config",
    )
    setup_logging(cfg.get("log_level", "info"))
    app = AgentApp(cfg, config_path=config_path)
    _install_signal_handlers(app)
    await app.start()


def main() -> None:
    parser = argparse.ArgumentParser(description="TriProxy Agent")
    parser.add_argument("config", help="path to agent yaml config")
    args = parser.parse_args()
    asyncio.run(_amain(args.config))


if __name__ == "__main__":
    main()

