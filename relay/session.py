from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Any

from common.crypto import b64e, generate_session_key, generate_token
from common.protocol import MsgType
from relay.bridge import DataBridge
from relay.pool import RelayPoolConn, RelayPoolManager


@dataclass(slots=True)
class RelaySession:
    session_id: str
    agent_id: str
    mode: str
    target: str | None
    data_key: bytes
    agent_pool_token: str
    client_pool_token: str
    client_request_id: str | None = None
    ready_agent: bool = False
    ready_client: bool = False
    bridge_task: asyncio.Task[Any] | None = None
    setup_deadline_task: asyncio.Task[Any] | None = None


class SessionManager:
    def __init__(self, pool_manager: RelayPoolManager, setup_timeout: int = 30):
        self.logger = logging.getLogger("relay.session")
        self.pool_manager = pool_manager
        self.setup_timeout = setup_timeout
        self._sessions: dict[str, RelaySession] = {}
        self._lock = asyncio.Lock()

    async def create_session(
        self,
        agent_id: str,
        mode: str,
        target: str | None,
        client_request_id: str | None = None,
    ) -> RelaySession:
        agent_conn = await self.pool_manager.acquire_idle(agent_id, "agent")
        client_conn = await self.pool_manager.acquire_idle(agent_id, "client")
        if not agent_conn or not client_conn:
            if agent_conn:
                await self.pool_manager.release(agent_conn.token)
            if client_conn:
                await self.pool_manager.release(client_conn.token)
            raise RuntimeError("pool_exhausted")

        session = RelaySession(
            session_id=generate_token(),
            agent_id=agent_id,
            mode=mode,
            target=target,
            data_key=generate_session_key(),
            agent_pool_token=agent_conn.token,
            client_pool_token=client_conn.token,
            client_request_id=client_request_id,
        )
        async with self._lock:
            self._sessions[session.session_id] = session
        return session

    async def get(self, session_id: str) -> RelaySession | None:
        async with self._lock:
            return self._sessions.get(session_id)

    async def mark_ready(self, session_id: str, side: str) -> RelaySession | None:
        async with self._lock:
            session = self._sessions.get(session_id)
            if not session:
                return None
            if side == "agent":
                session.ready_agent = True
            else:
                session.ready_client = True
            return session

    async def start_bridge_if_ready(self, session_id: str) -> bool:
        session = await self.get(session_id)
        if not session or not (session.ready_agent and session.ready_client):
            return False
        if session.setup_deadline_task and not session.setup_deadline_task.done():
            session.setup_deadline_task.cancel()

        agent_pool = await self.pool_manager.get_connection(session.agent_pool_token)
        client_pool = await self.pool_manager.get_connection(session.client_pool_token)
        if not agent_pool or not client_pool:
            return False

        async def _runner() -> None:
            bridge = DataBridge(
                reader_a=agent_pool.conn.reader,
                writer_a=agent_pool.conn.writer,
                reader_b=client_pool.conn.reader,
                writer_b=client_pool.conn.writer,
            )
            await bridge.run()
            await self.close_session(session_id, release_only=True)

        session.bridge_task = asyncio.create_task(_runner(), name=f"bridge-{session_id}")
        return True

    async def arm_setup_timeout(
        self,
        session_id: str,
        timeout_seconds: int,
        on_timeout: Any,
    ) -> None:
        session = await self.get(session_id)
        if not session:
            return

        async def _timer() -> None:
            await asyncio.sleep(timeout_seconds)
            current = await self.get(session_id)
            if not current:
                return
            if current.ready_agent and current.ready_client:
                return
            await on_timeout(current)

        session.setup_deadline_task = asyncio.create_task(_timer(), name=f"session-timeout-{session_id}")

    async def close_session(self, session_id: str, release_only: bool = True) -> None:
        async with self._lock:
            session = self._sessions.pop(session_id, None)
        if not session:
            return
        if session.bridge_task and not session.bridge_task.done():
            session.bridge_task.cancel()
        if session.setup_deadline_task and not session.setup_deadline_task.done():
            session.setup_deadline_task.cancel()
        if release_only:
            await self.pool_manager.release(session.agent_pool_token)
            await self.pool_manager.release(session.client_pool_token)
        else:
            await self.pool_manager.remove_connection(session.agent_pool_token)
            await self.pool_manager.remove_connection(session.client_pool_token)

    async def session_assign_payload_for_agent(self, session: RelaySession) -> dict[str, Any]:
        return {
            "session_id": session.session_id,
            "data_key": b64e(session.data_key),
            "pool_token": session.agent_pool_token,
            "mode": session.mode,
            "target": session.target,
        }

    async def session_assign_payload_for_client(self, session: RelaySession) -> dict[str, Any]:
        payload = {
            "session_id": session.session_id,
            "data_key": b64e(session.data_key),
            "pool_token": session.client_pool_token,
            "mode": session.mode,
            "target": session.target,
        }
        if session.client_request_id:
            payload["request_id"] = session.client_request_id
        return payload

