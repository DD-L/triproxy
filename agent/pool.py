from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from typing import Any

from common.connection import FramedConnection
from common.protocol import MsgType


class AgentPoolManager:
    def __init__(self, relay_host: str, relay_port: int, heartbeat_interval: int = 100, dead_timeout: int = 300):
        self.logger = logging.getLogger("agent.pool")
        self.relay_host = relay_host
        self.relay_port = relay_port
        self.heartbeat_interval = heartbeat_interval
        self.dead_timeout = dead_timeout
        self._conns: dict[str, FramedConnection] = {}
        self._ctrl_keys: dict[str, bytes] = {}
        self._hb_tasks: dict[str, asyncio.Task[None]] = {}
        self._lock = asyncio.Lock()

    async def create_pool_connection(self, token: str, ctrl_key: bytes) -> None:
        reader, writer = await asyncio.open_connection(self.relay_host, self.relay_port)
        conn = FramedConnection(reader, writer)
        await conn.send_encrypted(ctrl_key, MsgType.POOL_AUTH.value, pool_token=token, role="agent")
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
            self._stop_hb_locked(token)
            return self._conns.pop(token, None)

    async def put_back(self, token: str, conn: FramedConnection) -> None:
        async with self._lock:
            self._conns[token] = conn
            self._start_hb_locked(token)

    async def remove(self, token: str) -> None:
        async with self._lock:
            conn = self._conns.pop(token, None)
            self._ctrl_keys.pop(token, None)
            hb = self._hb_tasks.pop(token, None)
        if hb:
            hb.cancel()
            if hb is not asyncio.current_task():
                with contextlib.suppress(asyncio.CancelledError):
                    await hb
        if conn:
            await conn.close_safe()

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
            await conn.close_safe()

    async def size(self) -> int:
        async with self._lock:
            return len(self._conns)

    def _start_hb_locked(self, token: str) -> None:
        if token in self._hb_tasks:
            return
        self._hb_tasks[token] = asyncio.create_task(self._hb_loop(token), name=f"agent-pool-hb-{token}")

    def _stop_hb_locked(self, token: str) -> None:
        hb = self._hb_tasks.pop(token, None)
        if hb:
            hb.cancel()

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
            except Exception as exc:
                self.logger.debug("pool heartbeat loop token=%s closing err=%s", token, exc)
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

