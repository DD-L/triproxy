from __future__ import annotations

import asyncio
import contextlib
import logging
import time
import uuid

from common.connection import FramedConnection
from common.protocol import MsgType


class ClientPoolManager:
    def __init__(self, relay_host: str, relay_port: int, heartbeat_interval: int = 100, dead_timeout: int = 300):
        self.logger = logging.getLogger("client.pool")
        self.relay_host = relay_host
        self.relay_port = relay_port
        self.heartbeat_interval = max(5, min(int(heartbeat_interval), 30))
        self.dead_timeout = max(self.heartbeat_interval * 3, int(dead_timeout))
        self._conns: dict[str, FramedConnection] = {}
        self._ctrl_keys: dict[str, bytes] = {}
        self._hb_tasks: dict[str, asyncio.Task[None]] = {}
        self._lock = asyncio.Lock()

    async def create_pool_connection(self, token: str, ctrl_key: bytes) -> None:
        reader, writer = await asyncio.open_connection(self.relay_host, self.relay_port)
        conn = FramedConnection(reader, writer)
        await conn.send_encrypted(ctrl_key, MsgType.POOL_AUTH.value, pool_token=token, role="client")
        resp = await conn.recv_encrypted(ctrl_key)
        if resp.get("type") != MsgType.POOL_AUTH_OK.value:
            raise RuntimeError("POOL_AUTH failed")
        async with self._lock:
            self._conns[token] = conn
            self._ctrl_keys[token] = ctrl_key
            self._start_hb_locked(token)

    async def put_tokens(self, tokens: list[str], ctrl_key: bytes) -> None:
        for token in tokens:
            try:
                await self.create_pool_connection(token, ctrl_key)
            except Exception as exc:
                self.logger.warning("create pool connection failed token=%s err=%s", token, exc)

    async def take(self, token: str) -> FramedConnection | None:
        async with self._lock:
            conn = self._conns.pop(token, None)
        await self._stop_hb(token)
        return conn

    async def put_back(self, token: str, conn: FramedConnection) -> None:
        async with self._lock:
            self._conns[token] = conn
            self._start_hb_locked(token)

    async def remove(self, token: str) -> None:
        async with self._lock:
            conn = self._conns.pop(token, None)
            self._ctrl_keys.pop(token, None)
            hb = self._hb_tasks.pop(token, None)
        await self._cancel_hb_task(hb)
        if conn:
            conn.close()
            await conn.wait_closed()

    async def close_all(self) -> None:
        async with self._lock:
            items = list(self._conns.items())
            self._conns.clear()
            self._ctrl_keys.clear()
            hbs = list(self._hb_tasks.values())
            self._hb_tasks.clear()
        for hb in hbs:
            hb.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await hb
        for _, conn in items:
            conn.close()
            await conn.wait_closed()

    async def size(self) -> int:
        async with self._lock:
            return len(self._conns)

    async def probe_one(self, timeout: float = 2.0) -> dict[str, object]:
        token = ""
        conn: FramedConnection | None = None
        ctrl_key: bytes | None = None
        hb_task: asyncio.Task[None] | None = None
        async with self._lock:
            for candidate in self._conns.keys():
                token = candidate
                conn = self._conns.pop(candidate, None)
                ctrl_key = self._ctrl_keys.get(candidate)
                hb_task = self._hb_tasks.pop(candidate, None)
                break
        await self._cancel_hb_task(hb_task)
        if not token or conn is None or ctrl_key is None:
            return {
                "ok": False,
                "reason": "no_pool_connection_available",
                "token": "",
                "latency_ms": None,
            }
        probe_id = uuid.uuid4().hex
        started = time.monotonic()
        reusable = False
        try:
            await conn.send_encrypted(ctrl_key, MsgType.PING.value, ts=time.time(), probe_id=probe_id)
            while True:
                msg = await asyncio.wait_for(conn.recv_encrypted(ctrl_key), timeout=timeout)
                mtype = msg.get("type")
                if mtype == MsgType.PING.value:
                    await conn.send_encrypted(ctrl_key, MsgType.PONG.value, ts=msg.get("ts"))
                    continue
                if mtype == MsgType.PONG.value:
                    reusable = True
                    return {
                        "ok": True,
                        "reason": "",
                        "token": token,
                        "latency_ms": int((time.monotonic() - started) * 1000),
                    }
        except Exception as exc:
            reason = str(exc).strip() or type(exc).__name__
            # Probe timeout/read failure means this pooled connection is stale.
            # Do not put it back, otherwise first session tends to pick a poisoned socket.
            with contextlib.suppress(Exception):
                await conn.close_safe()
            return {
                "ok": False,
                "reason": reason,
                "token": token,
                "latency_ms": int((time.monotonic() - started) * 1000),
            }
        finally:
            async with self._lock:
                if reusable and conn and conn.writer and not conn.writer.is_closing():
                    self._conns[token] = conn
                    self._start_hb_locked(token)
                else:
                    self._conns.pop(token, None)
                    self._ctrl_keys.pop(token, None)

    def _start_hb_locked(self, token: str) -> None:
        task = self._hb_tasks.get(token)
        if task and not task.done():
            return
        if task and task.done():
            self._hb_tasks.pop(token, None)
        self._hb_tasks[token] = asyncio.create_task(self._hb_loop(token), name=f"client-pool-hb-{token}")

    async def _cancel_hb_task(self, hb: asyncio.Task[None] | None) -> None:
        if not hb:
            return
        hb.cancel()
        if hb is asyncio.current_task():
            return
        with contextlib.suppress(asyncio.CancelledError):
            await hb

    async def _stop_hb(self, token: str) -> None:
        async with self._lock:
            hb = self._hb_tasks.pop(token, None)
        await self._cancel_hb_task(hb)

    async def _hb_loop(self, token: str) -> None:
        last_pong = time.monotonic()
        last_ping = 0.0
        while True:
            async with self._lock:
                conn = self._conns.get(token)
                ctrl_key = self._ctrl_keys.get(token)
            if not conn or not ctrl_key:
                break

            now = time.monotonic()
            if now - last_ping >= self.heartbeat_interval:
                await conn.send_encrypted(ctrl_key, MsgType.PING.value, ts=time.time())
                last_ping = now

            try:
                msg = await asyncio.wait_for(conn.recv_encrypted(ctrl_key), timeout=1.0)
            except asyncio.TimeoutError:
                pass
            except Exception:
                await self.remove(token)
                break
            else:
                mtype = msg.get("type")
                if mtype == MsgType.PING.value:
                    await conn.send_encrypted(ctrl_key, MsgType.PONG.value, ts=msg.get("ts"))
                elif mtype == MsgType.PONG.value:
                    last_pong = time.monotonic()

            if time.monotonic() - last_pong > self.dead_timeout:
                self.logger.warning("pool heartbeat timeout token=%s", token)
                await self.remove(token)
                break

