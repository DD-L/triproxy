from __future__ import annotations

import asyncio
import logging
from typing import Any

from common.connection import FramedConnection
from common.crypto import aes_gcm_decrypt
from common.protocol import MsgType, parse_message
from relay.control import RelayControlManager
from relay.pool import RelayPoolManager


class RelayListener:
    def __init__(self, control_manager: RelayControlManager, pool_manager: RelayPoolManager):
        self.logger = logging.getLogger("relay.listener")
        self.control_manager = control_manager
        self.pool_manager = pool_manager

    async def handle_control_conn(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        side: str,
        first_payload: bytes | None = None,
    ) -> None:
        conn = _BufferedFramedConnection(reader, writer, first_payload)
        try:
            ctrl = await self.control_manager.handshake_and_attach(conn, side=side)
            await self.control_manager.run_control_loop(ctrl)
        except Exception as exc:
            self.logger.warning("control connection ended side=%s err=%s", side, exc)
        finally:
            writer.close()
            await writer.wait_closed()

    async def handle_pool_conn(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        side: str,
        first_payload: bytes,
    ) -> None:
        conn = _BufferedFramedConnection(reader, writer, first_payload)

        parsed_token: str | None = None
        parsed_ctrl_key: bytes | None = None

        controls = (
            self.control_manager.agent_controls.values()
            if side == "agent"
            else self.control_manager.client_controls.values()
        )
        for ctrl in controls:
            try:
                msg = parse_message(aes_gcm_decrypt(ctrl.ctrl_key, first_payload))
            except Exception:
                continue
            if msg.get("type") != MsgType.POOL_AUTH.value:
                continue
            token = str(msg.get("pool_token", ""))
            if not token:
                continue
            entry = await self.pool_manager.register_pool_connection(token, conn)
            if entry and entry.side == side:
                parsed_token = token
                parsed_ctrl_key = ctrl.ctrl_key
                break

        if not parsed_token or not parsed_ctrl_key:
            writer.close()
            await writer.wait_closed()
            return

        await conn.send_encrypted(parsed_ctrl_key, MsgType.POOL_AUTH_OK.value)

        # Keep the connection alive for relay session assignment/bridging.
        # Do not consume the stream here, otherwise it races with DataBridge.
        try:
            await writer.wait_closed()
        finally:
            await self.pool_manager.remove_connection(parsed_token)


class _BufferedFramedConnection(FramedConnection):
    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        first_payload: bytes | None = None,
    ):
        super().__init__(reader, writer)
        self._first_payload = first_payload

    async def recv_frame(self) -> bytes:
        if self._first_payload is not None:
            payload = self._first_payload
            self._first_payload = None
            return payload
        return await super().recv_frame()

