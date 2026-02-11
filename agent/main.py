from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import signal
import time
import uuid
from pathlib import Path
from typing import Any

from agent.control import AgentControlConnection
from agent.pool import AgentPoolManager
from agent.session import AgentSessionHandler
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
        self._control_task: asyncio.Task[Any] | None = None
        self._restart_requested = False
        self._client_status_waiters: list[asyncio.Future[dict[str, Any]]] = []
        self._relay_probe_task: asyncio.Task[Any] | None = None
        self._relay_probe_interval = max(5, int(self.config.get("relay_probe_interval", 20)))
        self._relay_probe_status: dict[str, Any] = {
            "ok": False,
            "checked_at": 0.0,
            "client_connected": False,
            "request_id": "",
            "reason": "not_checked_yet",
        }
        self._probe_status_path = str(Path(self.config_path).with_suffix(".relay_probe.json"))

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
            request_id = str(msg.get("request_id", "")).strip()
            await self._send_control(
                MsgType.AGENT_STATUS_RESP.value,
                connected=self.control is not None and self.control.ctrl_key is not None,
                pool_size=await self.pool_manager.size(),
                active_sessions=self.session_handler.active_count(),
                uptime=time.time() - self.started_at,
                request_id=request_id,
            )
            return
        if msg_type == MsgType.CLIENT_STATUS_RESP.value:
            result = {
                "connected": bool(msg.get("connected", False)),
                "request_id": str(msg.get("request_id", "")).strip(),
            }
            waiters = list(self._client_status_waiters)
            self._client_status_waiters.clear()
            for fut in waiters:
                if not fut.done():
                    fut.set_result(result)
            return
        if msg_type == MsgType.AGENT_PWD_CHANGE.value:
            new_hash = str(msg.get("new_password_hash", ""))
            if len(new_hash) == 64:
                self.config["web_console_password_hash"] = new_hash
                self.config["web_console_force_change"] = False
                save_yaml(self.config_path, self.config)
                await self._send_control(MsgType.AGENT_PWD_CHANGED.value, ok=True)
            else:
                await self._send_control(MsgType.AGENT_PWD_CHANGED.value, ok=False, reason="invalid_hash")
            return
        if msg_type == MsgType.AGENT_RESTART_REQ.value:
            await self._send_control(MsgType.AGENT_RESTART_RESP.value, ok=True)
            asyncio.create_task(self.request_restart(), name="agent-restart-requested")

    async def on_connected(self, _: bytes) -> None:
        if self._relay_probe_task is None or self._relay_probe_task.done():
            self._relay_probe_task = asyncio.create_task(self._relay_probe_loop(), name="agent-relay-probe-loop")

    async def on_disconnected(self) -> None:
        await self.pool_manager.close_all()
        await self.session_handler.close_all()
        waiters = list(self._client_status_waiters)
        self._client_status_waiters.clear()
        for fut in waiters:
            if not fut.done():
                fut.set_result({"connected": False, "request_id": ""})
        self._update_relay_probe_status(
            ok=False,
            reason="control_disconnected",
            client_connected=False,
            request_id="",
        )

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
        self._write_relay_probe_status_file()
        await self.start_control_loop()
        if self._control_task:
            await self._control_task

    async def shutdown(self) -> None:
        if self._relay_probe_task:
            self._relay_probe_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._relay_probe_task
            self._relay_probe_task = None
        # Keep control channel alive briefly so SESSION_CLOSE can be delivered.
        await self.session_handler.close_all()
        await asyncio.sleep(0.1)
        await self.disconnect_now()

    async def request_restart(self) -> None:
        if self._restart_requested:
            return
        self._restart_requested = True
        await asyncio.sleep(0.2)
        await self.shutdown()

    async def request_client_status(self, timeout: float = 5.0) -> dict[str, Any]:
        if not self.control or not self.control.ctrl_key:
            raise RuntimeError("control_not_connected")
        request_id = uuid.uuid4().hex
        waiter = asyncio.get_running_loop().create_future()
        self._client_status_waiters.append(waiter)
        await self._send_control(MsgType.CLIENT_STATUS_REQ.value, request_id=request_id)
        try:
            result = await asyncio.wait_for(waiter, timeout=timeout)
        except asyncio.TimeoutError as exc:
            raise RuntimeError("client status relay probe timeout") from exc
        if result.get("request_id", "") != request_id:
            raise RuntimeError("client status relay probe mismatched response")
        return result

    def _update_relay_probe_status(self, *, ok: bool, reason: str, client_connected: bool, request_id: str) -> None:
        self._relay_probe_status = {
            "ok": bool(ok),
            "checked_at": time.time(),
            "client_connected": bool(client_connected),
            "request_id": str(request_id),
            "reason": str(reason),
        }
        self._write_relay_probe_status_file()

    def _write_relay_probe_status_file(self) -> None:
        try:
            Path(self._probe_status_path).write_text(
                json.dumps(self._relay_probe_status, ensure_ascii=False),
                encoding="utf-8",
            )
        except Exception:
            # Best-effort diagnostics channel only.
            pass

    async def _relay_probe_loop(self) -> None:
        while True:
            try:
                result = await self.request_client_status(timeout=5.0)
                ok = bool(result.get("connected", False))
                self._update_relay_probe_status(
                    ok=ok,
                    reason="" if ok else "relay reports client control not connected",
                    client_connected=ok,
                    request_id=str(result.get("request_id", "")),
                )
            except Exception as exc:
                self._update_relay_probe_status(
                    ok=False,
                    reason=str(exc),
                    client_connected=False,
                    request_id="",
                )
            await asyncio.sleep(self._relay_probe_interval)


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
        ["relay_host", "relay_port_agent", "rsa_private_key", "rsa_public_key"],
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

