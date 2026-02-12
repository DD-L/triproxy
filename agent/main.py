from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import re
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
            heartbeat_interval=int(config.get("heartbeat_interval", 25)),
            dead_timeout=int(config.get("pool_dead_timeout", config.get("dead_timeout", 120))),
        )
        self.control: AgentControlConnection | None = None
        self.session_handler = AgentSessionHandler(self.pool_manager, self._send_control, config=config)
        self._control_task: asyncio.Task[Any] | None = None
        self._restart_requested = False
        self._client_status_waiters: dict[str, asyncio.Future[dict[str, Any]]] = {}
        self._relay_probe_task: asyncio.Task[Any] | None = None
        self._active_pool_probe_task: asyncio.Task[Any] | None = None
        self._relay_probe_interval = max(5, int(self.config.get("relay_probe_interval", 20)))
        self._active_pool_probe_interval = max(30, int(self.config.get("active_pool_probe_interval", 120)))
        self._active_pool_probe_timeout = max(1.0, float(self.config.get("active_pool_probe_timeout", 2.5)))
        self._relay_probe_status: dict[str, Any] = {
            "ok": False,
            "checked_at": 0.0,
            "client_connected": False,
            "request_id": "",
            "reason": "not_checked_yet",
        }
        self._pool_probe_status: dict[str, Any] = {
            "ok": False,
            "checked_at": 0.0,
            "reason": "not_checked_yet",
            "skipped": True,
            "latency_ms": None,
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
                relay_probe=self._relay_probe_status,
                pool_probe=self._pool_probe_status,
            )
            return
        if msg_type == MsgType.CLIENT_STATUS_RESP.value:
            result = {
                "connected": bool(msg.get("connected", False)),
                "request_id": str(msg.get("request_id", "")).strip(),
            }
            req_id = result["request_id"]
            fut = self._client_status_waiters.pop(req_id, None) if req_id else None
            if fut and not fut.done():
                fut.set_result(result)
            return
        if msg_type == MsgType.AGENT_PWD_CHANGE.value:
            new_hash = str(msg.get("new_password_hash", "")).strip().lower()
            if re.fullmatch(r"[0-9a-f]{64}", new_hash):
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
        if self._active_pool_probe_task is None or self._active_pool_probe_task.done():
            self._active_pool_probe_task = asyncio.create_task(
                self._active_pool_probe_loop(),
                name="agent-active-pool-probe-loop",
            )

    async def on_disconnected(self) -> None:
        await self.pool_manager.close_all()
        await self.session_handler.close_all()
        waiters = list(self._client_status_waiters.values())
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
        self._update_pool_probe_status(ok=False, reason="control_disconnected", skipped=True, latency_ms=None)

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
        if self._active_pool_probe_task:
            self._active_pool_probe_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._active_pool_probe_task
            self._active_pool_probe_task = None
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
        self._client_status_waiters[request_id] = waiter
        await self._send_control(MsgType.CLIENT_STATUS_REQ.value, request_id=request_id)
        try:
            result = await asyncio.wait_for(waiter, timeout=timeout)
        except asyncio.TimeoutError as exc:
            raise RuntimeError("client status relay probe timeout") from exc
        finally:
            self._client_status_waiters.pop(request_id, None)
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

    def _update_pool_probe_status(self, *, ok: bool, reason: str, skipped: bool, latency_ms: int | None) -> None:
        self._pool_probe_status = {
            "ok": bool(ok),
            "checked_at": time.time(),
            "reason": str(reason),
            "skipped": bool(skipped),
            "latency_ms": latency_ms,
        }
        self._write_relay_probe_status_file()

    def _write_relay_probe_status_file(self) -> None:
        try:
            payload = dict(self._relay_probe_status)
            payload["control_connected"] = bool(self.control is not None and self.control.ctrl_key is not None)
            payload["pool_probe"] = dict(self._pool_probe_status)
            payload["pool_probe_ok"] = bool(self._pool_probe_status.get("ok", False))
            payload["pool_probe_skipped"] = bool(self._pool_probe_status.get("skipped", True))
            Path(self._probe_status_path).write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
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

    async def _active_pool_probe_loop(self) -> None:
        while True:
            try:
                if not self.control or not self.control.ctrl_key:
                    self._update_pool_probe_status(
                        ok=False,
                        reason="control_not_connected",
                        skipped=True,
                        latency_ms=None,
                    )
                elif not bool(self._relay_probe_status.get("client_connected", False)):
                    # Skip active pool probe when client is offline to avoid blind retries.
                    self._update_pool_probe_status(
                        ok=False,
                        reason="client_not_connected",
                        skipped=True,
                        latency_ms=None,
                    )
                else:
                    result = await self.pool_manager.probe_one(timeout=self._active_pool_probe_timeout)
                    self._update_pool_probe_status(
                        ok=bool(result.get("ok", False)),
                        reason=str(result.get("reason", "")),
                        skipped=False,
                        latency_ms=result.get("latency_ms"),
                    )
            except Exception as exc:
                self._update_pool_probe_status(
                    ok=False,
                    reason=str(exc),
                    skipped=False,
                    latency_ms=None,
                )
            await asyncio.sleep(self._active_pool_probe_interval)


def _install_signal_handlers(app: AgentApp) -> None:
    loop = asyncio.get_running_loop()

    async def _shutdown() -> None:
        await app.shutdown()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, lambda: asyncio.create_task(_shutdown()))
        except NotImplementedError:
            signal.signal(sig, lambda *_: asyncio.create_task(_shutdown()))


def _resolve_path_fields_from_runtime_compat(cfg: dict[str, Any], config_path: str, keys: list[str]) -> None:
    base_dir = Path(config_path).expanduser().resolve().parent
    runtime_dir = Path.cwd()
    for key in keys:
        raw = str(cfg.get(key, "")).strip()
        if not raw:
            continue
        path_value = Path(raw).expanduser()
        if path_value.is_absolute():
            cfg[key] = str(path_value)
        else:
            # Backward-compatible resolution:
            # 1) runtime working directory (historical behavior)
            # 2) config file directory (portable behavior)
            runtime_candidate = (runtime_dir / path_value).resolve()
            if runtime_candidate.exists():
                cfg[key] = str(runtime_candidate)
            else:
                cfg[key] = str((base_dir / path_value).resolve())


async def _amain(config_path: str) -> None:
    cfg = load_yaml(config_path)
    _resolve_path_fields_from_runtime_compat(
        cfg,
        config_path,
        ["rsa_private_key", "rsa_public_key", "agent_public_key_path"],
    )
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

