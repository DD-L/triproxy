from __future__ import annotations

import asyncio
import contextlib
import time
from collections.abc import Awaitable, Callable
from typing import Any

from common.connection import FramedConnection
from common.protocol import MsgType


class HeartbeatTimeout(ConnectionError):
    pass


class HeartbeatManager:
    def __init__(
        self,
        conn: FramedConnection,
        interval: int = 100,
        timeout: int = 300,
        encrypt_key: bytes | None = None,
        on_timeout: Callable[[], Awaitable[None]] | None = None,
    ):
        self.conn = conn
        self.interval = interval
        self.timeout = timeout
        self.encrypt_key = encrypt_key
        self.on_timeout = on_timeout
        self.last_pong = time.monotonic()
        self._running = False
        self._sender_task: asyncio.Task[Any] | None = None
        self._checker_task: asyncio.Task[Any] | None = None

    async def send_ping(self) -> None:
        ts = time.time()
        if self.encrypt_key:
            await self.conn.send_encrypted(self.encrypt_key, MsgType.PING.value, ts=ts)
        else:
            await self.conn.send_message(MsgType.PING.value, ts=ts)

    async def send_pong(self, ts: float) -> None:
        if self.encrypt_key:
            await self.conn.send_encrypted(self.encrypt_key, MsgType.PONG.value, ts=ts)
        else:
            await self.conn.send_message(MsgType.PONG.value, ts=ts)

    async def sender_loop(self) -> None:
        while self._running:
            await asyncio.sleep(self.interval)
            await self.send_ping()

    async def checker_loop(self) -> None:
        while self._running:
            await asyncio.sleep(1.0)
            if time.monotonic() - self.last_pong > self.timeout:
                self._running = False
                if self.on_timeout:
                    await self.on_timeout()
                raise HeartbeatTimeout("heartbeat timeout")

    async def run(self) -> None:
        self._running = True
        self._sender_task = asyncio.create_task(self.sender_loop(), name="heartbeat-sender")
        self._checker_task = asyncio.create_task(self.checker_loop(), name="heartbeat-checker")
        await asyncio.gather(self._sender_task, self._checker_task)

    def mark_pong(self) -> None:
        self.last_pong = time.monotonic()

    async def stop(self) -> None:
        self._running = False
        for task in (self._sender_task, self._checker_task):
            if task:
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task

