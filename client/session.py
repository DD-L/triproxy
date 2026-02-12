from __future__ import annotations

import asyncio
import contextlib
import time
import uuid
from typing import Any, Callable

from common.connection import FramedConnection
from common.crypto import b64d
from common.protocol import MsgType
from client.pool import ClientPoolManager


class ClientSessionManager:
    def __init__(self, pool_manager: ClientPoolManager, send_control: Callable[..., Any]):
        self.pool_manager = pool_manager
        self.send_control = send_control
        self.pending: dict[str, asyncio.Future[dict[str, Any]]] = {}
        self.active: dict[str, dict[str, Any]] = {}
        self._lock = asyncio.Lock()

    async def request_session(self, mode: str, target: str | None, agent_id: str = "default") -> dict[str, Any]:
        request_id = uuid.uuid4().hex
        loop = asyncio.get_running_loop()
        fut: asyncio.Future[dict[str, Any]] = loop.create_future()
        async with self._lock:
            self.pending[request_id] = fut
        await self.send_control(
            MsgType.SESSION_REQUEST.value,
            mode=mode,
            target=target,
            agent_id=agent_id,
            request_id=request_id,
        )
        try:
            return await asyncio.wait_for(fut, timeout=30)
        finally:
            async with self._lock:
                self.pending.pop(request_id, None)

    async def on_control_message(self, msg: dict[str, Any]) -> None:
        t = msg.get("type")
        if t == MsgType.SESSION_ASSIGN.value:
            request_id = str(msg.get("request_id", ""))
            if request_id:
                async with self._lock:
                    fut = self.pending.pop(request_id, None)
                if fut and not fut.done():
                    fut.set_result(msg)
                    return
            session_id = str(msg.get("session_id", ""))
            if session_id:
                self.active[session_id] = msg
            return
        if t == MsgType.SESSION_FAIL.value:
            request_id = str(msg.get("request_id", ""))
            if request_id:
                async with self._lock:
                    fut = self.pending.pop(request_id, None)
                if fut and not fut.done():
                    fut.set_exception(RuntimeError(str(msg.get("reason", "session_failed"))))
            return
        if t == MsgType.SESSION_CLOSE.value:
            sid = str(msg.get("session_id", ""))
            self.active.pop(sid, None)

    async def use_assigned_pool(self, assign_msg: dict[str, Any]) -> tuple[str, bytes, str, FramedConnection]:
        sid = str(assign_msg["session_id"])
        data_key = b64d(str(assign_msg["data_key"]))
        token = str(assign_msg["pool_token"])
        pool_conn: FramedConnection | None = None
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline:
            pool_conn = await self.pool_manager.take(token)
            if pool_conn is not None:
                break
            await asyncio.sleep(0.05)
        if not pool_conn:
            raise RuntimeError("assigned pool token unavailable")
        self.active[sid] = assign_msg
        await self.send_control(MsgType.SESSION_READY.value, session_id=sid)
        return sid, data_key, token, pool_conn

    async def close_session(self, session_id: str) -> None:
        self.active.pop(session_id, None)
        # Best-effort close notification; local cleanup should not fail when control is transiently down.
        with contextlib.suppress(Exception):
            await self.send_control(MsgType.SESSION_CLOSE.value, session_id=session_id)

