from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from dataclasses import dataclass, field
from typing import Any

from common.connection import FramedConnection
from common.crypto import generate_token
from common.protocol import MsgType


@dataclass(slots=True)
class RelayPoolConn:
    token: str
    agent_id: str
    side: str  # "agent" | "client"
    conn: FramedConnection
    ctrl_key: bytes
    in_use: bool = False
    last_idle_at: float = field(default_factory=time.time)


class RelayPoolManager:
    def __init__(
        self,
        pool_initial_size: int = 5,
        pool_min_idle: int = 0,
        pool_scale_batch: int = 5,
        pool_idle_timeout: int = 300,
        heartbeat_interval: int = 100,
        dead_timeout: int = 300,
    ):
        self.logger = logging.getLogger("relay.pool")
        self.pool_initial_size = pool_initial_size
        self.pool_min_idle = pool_min_idle
        self.pool_scale_batch = pool_scale_batch
        self.pool_idle_timeout = pool_idle_timeout
        self.heartbeat_interval = max(5, min(int(heartbeat_interval), 30))
        self.dead_timeout = max(self.heartbeat_interval * 3, int(dead_timeout))
        self._lock = asyncio.Lock()
        self._expected_tokens: dict[str, tuple[str, str, bytes]] = {}
        self._conns: dict[str, RelayPoolConn] = {}
        self._heartbeat_tasks: dict[str, asyncio.Task[None]] = {}

    async def reserve_tokens(self, agent_id: str, side: str, ctrl_key: bytes, count: int) -> list[str]:
        tokens = [generate_token() for _ in range(count)]
        async with self._lock:
            for token in tokens:
                self._expected_tokens[token] = (agent_id, side, ctrl_key)
        return tokens

    async def register_pool_connection(self, token: str, conn: FramedConnection) -> RelayPoolConn | None:
        async with self._lock:
            expected = self._expected_tokens.pop(token, None)
            if not expected:
                return None
            agent_id, side, ctrl_key = expected
            pool_conn = RelayPoolConn(
                token=token,
                agent_id=agent_id,
                side=side,
                conn=conn,
                ctrl_key=ctrl_key,
            )
            self._conns[token] = pool_conn
            self._start_idle_heartbeat_locked(pool_conn)
            return pool_conn

    async def remove_connection(self, token: str) -> None:
        async with self._lock:
            entry = self._conns.pop(token, None)
            hb = self._heartbeat_tasks.pop(token, None)
        await self._cancel_hb_task(hb)
        if entry:
            await entry.conn.close_safe()

    async def get_connection(self, token: str) -> RelayPoolConn | None:
        async with self._lock:
            return self._conns.get(token)

    async def acquire_idle(self, agent_id: str, side: str) -> RelayPoolConn | None:
        hb_task: asyncio.Task[None] | None = None
        selected: RelayPoolConn | None = None
        async with self._lock:
            for conn in self._conns.values():
                if conn.agent_id == agent_id and conn.side == side and not conn.in_use:
                    conn.in_use = True
                    hb_task = self._heartbeat_tasks.pop(conn.token, None)
                    selected = conn
                    break
        await self._cancel_hb_task(hb_task)
        return selected

    async def release(self, token: str) -> None:
        async with self._lock:
            conn = self._conns.get(token)
            if not conn:
                return
            conn.in_use = False
            conn.last_idle_at = time.time()
            self._start_idle_heartbeat_locked(conn)

    async def idle_count(self, agent_id: str, side: str) -> int:
        async with self._lock:
            return sum(
                1
                for c in self._conns.values()
                if c.agent_id == agent_id and c.side == side and not c.in_use
            )

    async def wait_for_idle(self, agent_id: str, side: str, timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if await self.idle_count(agent_id, side) > 0:
                return True
            await asyncio.sleep(0.1)
        return await self.idle_count(agent_id, side) > 0

    async def snapshot(self, agent_id: str) -> dict[str, int]:
        async with self._lock:
            a_total = 0
            c_total = 0
            a_active = 0
            c_active = 0
            for c in self._conns.values():
                if c.agent_id != agent_id:
                    continue
                if c.side == "agent":
                    a_total += 1
                    if c.in_use:
                        a_active += 1
                else:
                    c_total += 1
                    if c.in_use:
                        c_active += 1
            return {
                "agent_total": a_total,
                "agent_idle": a_total - a_active,
                "agent_active": a_active,
                "client_total": c_total,
                "client_idle": c_total - c_active,
                "client_active": c_active,
            }

    async def shrink_once(self) -> list[str]:
        now = time.time()
        to_close: list[str] = []
        async with self._lock:
            by_group: dict[tuple[str, str], list[RelayPoolConn]] = {}
            for conn in self._conns.values():
                if conn.in_use:
                    continue
                by_group.setdefault((conn.agent_id, conn.side), []).append(conn)
            for _, conns in by_group.items():
                conns.sort(key=lambda c: c.last_idle_at)
                removable = max(0, len(conns) - self.pool_min_idle)
                for conn in conns[:removable]:
                    if now - conn.last_idle_at >= self.pool_idle_timeout:
                        to_close.append(conn.token)
            for token in to_close:
                self._conns.pop(token, None)
        return to_close

    async def close_all_for_agent(self, agent_id: str) -> None:
        entries: list[RelayPoolConn] = []
        hbs: list[asyncio.Task[None]] = []
        async with self._lock:
            for token, conn in list(self._conns.items()):
                if conn.agent_id == agent_id:
                    entries.append(conn)
                    self._conns.pop(token, None)
                    hb = self._heartbeat_tasks.pop(token, None)
                    if hb:
                        hbs.append(hb)
            for token, expected in list(self._expected_tokens.items()):
                if expected[0] == agent_id:
                    self._expected_tokens.pop(token, None)
        for hb in hbs:
            hb.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await hb
        for entry in entries:
            self.logger.info("closing pool conn token=%s", entry.token)
            await entry.conn.close_safe()

    async def close_all(self) -> None:
        entries: list[RelayPoolConn] = []
        hbs: list[asyncio.Task[None]] = []
        async with self._lock:
            entries = list(self._conns.values())
            self._conns.clear()
            self._expected_tokens.clear()
            hbs = list(self._heartbeat_tasks.values())
            self._heartbeat_tasks.clear()
        for hb in hbs:
            hb.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await hb
        for entry in entries:
            await entry.conn.close_safe()

    def _start_idle_heartbeat_locked(self, conn: RelayPoolConn) -> None:
        if conn.in_use:
            return
        task = self._heartbeat_tasks.get(conn.token)
        if task and not task.done():
            return
        if task and task.done():
            self._heartbeat_tasks.pop(conn.token, None)
        self._heartbeat_tasks[conn.token] = asyncio.create_task(
            self._idle_heartbeat_loop(conn.token),
            name=f"relay-pool-heartbeat-{conn.token}",
        )

    async def _cancel_hb_task(self, hb: asyncio.Task[None] | None) -> None:
        if not hb:
            return
        hb.cancel()
        if hb is asyncio.current_task():
            return
        # Idle heartbeat may already be faulted; suppress to avoid task-noise propagation.
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await hb

    async def _idle_heartbeat_loop(self, token: str) -> None:
        last_pong = time.monotonic()
        last_ping = 0.0
        while True:
            async with self._lock:
                conn = self._conns.get(token)
                if not conn or conn.in_use:
                    break
                framed = conn.conn
                ctrl_key = conn.ctrl_key

            try:
                now = time.monotonic()
                if now - last_ping >= self.heartbeat_interval:
                    await framed.send_encrypted(ctrl_key, MsgType.PING.value, ts=time.time())
                    last_ping = now

                msg = await asyncio.wait_for(framed.recv_encrypted(ctrl_key), timeout=1.0)
            except asyncio.TimeoutError:
                pass
            except Exception:
                await self.remove_connection(token)
                break
            else:
                mtype = msg.get("type")
                if mtype == MsgType.PING.value:
                    try:
                        await framed.send_encrypted(ctrl_key, MsgType.PONG.value, ts=msg.get("ts"))
                    except Exception:
                        await self.remove_connection(token)
                        break
                elif mtype == MsgType.PONG.value:
                    last_pong = time.monotonic()

            if time.monotonic() - last_pong > self.dead_timeout:
                self.logger.warning("pool idle heartbeat timeout token=%s", token)
                await self.remove_connection(token)
                break

