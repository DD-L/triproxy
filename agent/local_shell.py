from __future__ import annotations

import asyncio
import contextlib
import logging
import secrets
import time
from typing import Any

from aiohttp import web

from agent.shell import ShellHandler
from common.connection import FramedConnection
from common.crypto import random_bytes
from common.shell_ws import ShellWebsocketBridge


class LocalShellService:
    def __init__(self, config: dict[str, Any] | None = None):
        self.logger = logging.getLogger("agent.local_shell")
        base_cfg = dict(config or {})
        # Web daemon local shell runs in a different host process than agent.main.
        # Keep it resilient on Windows: preserve configured backend (usually conpty/auto)
        # so interactive commands (wsl/claude/etc.) have PTY semantics, but ensure
        # fallback is enabled so startup failures still degrade to subprocess.
        backend = str(base_cfg.get("shell_windows_backend", "auto")).strip().lower()
        fallback = bool(base_cfg.get("shell_windows_conpty_fallback", True))
        if backend == "conpty" and not fallback:
            base_cfg["shell_windows_conpty_fallback"] = True
            self.logger.warning(
                "local shell overrides shell_windows_conpty_fallback=false to true for web console stability"
            )
        self.config = base_cfg
        self.shell_handler = ShellHandler(config=self.config)
        self.bridge = ShellWebsocketBridge()
        self.pending_sessions: dict[str, float] = {}
        self.session_ttl_seconds = int(self.config.get("web_terminal_session_ttl", 120))
        self.active_tasks: dict[str, set[asyncio.Task[Any]]] = {}

    def _prune_sessions(self) -> None:
        now = time.time()
        expired = [sid for sid, exp in self.pending_sessions.items() if exp <= now]
        for sid in expired:
            self.pending_sessions.pop(sid, None)

    async def create_session(self) -> str:
        self._prune_sessions()
        sid = secrets.token_hex(16)
        self.pending_sessions[sid] = time.time() + max(10, self.session_ttl_seconds)
        return sid

    def _consume_session(self, session_id: str) -> bool:
        self._prune_sessions()
        exp = self.pending_sessions.pop(session_id, 0.0)
        return exp > time.time()

    async def close(self) -> None:
        self.pending_sessions.clear()
        for session_id, tasks in list(self.active_tasks.items()):
            for task in list(tasks):
                task.cancel()
            for task in list(tasks):
                with contextlib.suppress(asyncio.TimeoutError, asyncio.CancelledError, Exception):
                    await asyncio.wait_for(task, timeout=1.5)
            self.active_tasks.pop(session_id, None)

    class _MemoryChannel:
        def __init__(self):
            self.buf = bytearray()
            self.eof = False
            self.waiters: list[asyncio.Future[None]] = []

        def _wake_waiters(self) -> None:
            for fut in self.waiters:
                if not fut.done():
                    fut.set_result(None)
            self.waiters.clear()

        async def readexactly(self, n: int) -> bytes:
            while len(self.buf) < n and not self.eof:
                fut = asyncio.get_running_loop().create_future()
                self.waiters.append(fut)
                await fut
            if len(self.buf) < n:
                partial = bytes(self.buf)
                self.buf.clear()
                raise asyncio.IncompleteReadError(partial=partial, expected=n)
            out = bytes(self.buf[:n])
            del self.buf[:n]
            return out

        def write_now(self, data: bytes) -> None:
            if self.eof:
                return
            self.buf.extend(data)
            self._wake_waiters()

        def close_now(self) -> None:
            self.eof = True
            self._wake_waiters()

    class _MemoryReader:
        def __init__(self, ch: "LocalShellService._MemoryChannel"):
            self._ch = ch

        async def readexactly(self, n: int) -> bytes:
            return await self._ch.readexactly(n)

    class _MemoryWriter:
        def __init__(self, peer: "LocalShellService._MemoryChannel"):
            self._peer = peer
            self._closed = False

        def write(self, data: bytes) -> None:
            if self._closed:
                return
            self._peer.write_now(data)

        async def drain(self) -> None:
            return

        def close(self) -> None:
            if self._closed:
                return
            self._closed = True
            self._peer.close_now()

        async def wait_closed(self) -> None:
            return

    async def _create_memory_pair(self) -> tuple[FramedConnection, FramedConnection]:
        chan_a = self._MemoryChannel()
        chan_b = self._MemoryChannel()
        a_reader = self._MemoryReader(chan_a)
        a_writer = self._MemoryWriter(chan_b)
        b_reader = self._MemoryReader(chan_b)
        b_writer = self._MemoryWriter(chan_a)
        return FramedConnection(a_reader, a_writer), FramedConnection(b_reader, b_writer)

    async def attach_terminal_ws(self, session_id: str, ws: web.WebSocketResponse) -> None:
        if not self._consume_session(session_id):
            await ws.close(message=b"invalid_session")
            return

        shell_conn: FramedConnection | None = None
        ws_conn: FramedConnection | None = None
        data_key = random_bytes(32)
        session_tasks: set[asyncio.Task[Any]] = set()
        self.active_tasks[session_id] = session_tasks
        try:
            shell_conn, ws_conn = await self._create_memory_pair()
            shell_task = asyncio.create_task(
                self.shell_handler.run(shell_conn, data_key),
                name=f"agent-local-shell-{session_id}",
            )
            bridge_task = asyncio.create_task(
                self.bridge.handle_websocket(ws, data_key, ws_conn),
                name=f"agent-local-shell-ws-{session_id}",
            )
            session_tasks.update({shell_task, bridge_task})
            done, pending = await asyncio.wait([shell_task, bridge_task], return_when=asyncio.FIRST_COMPLETED)
            for task in pending:
                task.cancel()
                with contextlib.suppress(asyncio.TimeoutError, asyncio.CancelledError):
                    await asyncio.wait_for(task, timeout=1.5)
            for task in done:
                try:
                    await task
                except Exception as exc:
                    self.logger.exception("local shell task failed: %s", exc)
                    with contextlib.suppress(Exception):
                        await ws.send_str(f"\r\n[local-shell-error] {type(exc).__name__}: {exc}\r\n")
        finally:
            if ws_conn is not None:
                with contextlib.suppress(Exception):
                    await ws_conn.close_safe()
            if shell_conn is not None:
                with contextlib.suppress(Exception):
                    await shell_conn.close_safe()
            self.active_tasks.pop(session_id, None)
