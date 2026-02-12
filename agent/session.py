from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from typing import Any, Callable

from common.connection import FramedConnection
from common.crypto import b64d
from common.protocol import MsgType
from agent.proxy import ProxyHandler
from agent.shell import ShellHandler
from agent.pool import AgentPoolManager


class AgentSessionHandler:
    def __init__(
        self,
        pool_manager: AgentPoolManager,
        send_control: Callable[..., Any],
        config: dict[str, Any] | None = None,
    ):
        self.logger = logging.getLogger("agent.session")
        self.pool_manager = pool_manager
        self.send_control = send_control
        self.proxy_handler = ProxyHandler()
        self.shell_handler = ShellHandler(config=config)
        self._tasks: dict[str, asyncio.Task[Any]] = {}

    async def on_session_assign(self, msg: dict[str, Any]) -> None:
        session_id = str(msg.get("session_id", ""))
        pool_token = str(msg.get("pool_token", ""))
        mode = str(msg.get("mode", "directed"))
        target = msg.get("target")
        data_key = b64d(str(msg.get("data_key", "")))

        pool_conn: FramedConnection | None = None
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline:
            pool_conn = await self.pool_manager.take(pool_token)
            if pool_conn is not None:
                break
            await asyncio.sleep(0.05)
        if not pool_conn:
            await self.send_control(MsgType.SESSION_FAIL.value, session_id=session_id, reason="pool_token_not_found")
            return

        async def _runner() -> None:
            try:
                await self.send_control(MsgType.SESSION_READY.value, session_id=session_id)
                if mode in ("directed", "general"):
                    if not target:
                        raise ValueError("target required for proxy modes")
                    await self.proxy_handler.run(pool_conn, data_key, str(target))
                elif mode == "shell":
                    await self.shell_handler.run(pool_conn, data_key)
                else:
                    raise ValueError(f"unsupported mode: {mode}")
            except asyncio.CancelledError:
                self.logger.debug("session cancelled sid=%s", session_id)
                raise
            except Exception as exc:
                self.logger.warning("session failed sid=%s err=%s", session_id, exc)
                await self.send_control(MsgType.SESSION_FAIL.value, session_id=session_id, reason=str(exc))
            finally:
                with contextlib.suppress(Exception):
                    await self.send_control(MsgType.SESSION_CLOSE.value, session_id=session_id)
                with contextlib.suppress(Exception):
                    await self.pool_manager.put_back(pool_token, pool_conn)
                self._tasks.pop(session_id, None)

        self._tasks[session_id] = asyncio.create_task(_runner(), name=f"agent-session-{session_id}")

    async def close_session(self, session_id: str) -> None:
        task = self._tasks.get(session_id)
        if task:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task

    async def close_all(self) -> None:
        for sid in list(self._tasks.keys()):
            await self.close_session(sid)

    def active_count(self) -> int:
        return len(self._tasks)

