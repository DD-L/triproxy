from __future__ import annotations

import asyncio
import contextlib
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from common.connection import FramedConnection
from common.crypto import load_public_key, pubkey_fingerprint
from common.protocol import MsgType
from relay.handshake import RelayHandshakeServer
from relay.pool import RelayPoolManager
from relay.session import SessionManager


@dataclass(slots=True)
class ControlConn:
    role: str
    agent_id: str
    conn: FramedConnection
    ctrl_key: bytes
    fingerprint: str
    side: str


class RelayControlManager:
    def __init__(self, config: dict[str, Any], pool_manager: RelayPoolManager, session_manager: SessionManager):
        self.logger = logging.getLogger("relay.control")
        self.config = config
        self.pool_manager = pool_manager
        self.session_manager = session_manager
        self.handshake = RelayHandshakeServer(config["rsa_private_key"], config.get("auth_key", ""))
        self.agent_controls: dict[str, ControlConn] = {}
        self.client_controls: dict[str, ControlConn] = {}
        self._lock = asyncio.Lock()

        self.allowed_agents = self._load_allowed(config.get("allowed_agents", []))
        self.allowed_clients = self._load_allowed(config.get("allowed_clients", []))

    def _load_allowed(self, raw_items: list[str]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for item in raw_items:
            path = Path(item)
            if path.exists():
                pub = load_public_key(str(path))
                result[pubkey_fingerprint(pub)] = pub
            else:
                # Raw fingerprint string; useful when key file is not present.
                fp = item.replace("SHA256:", "").strip()
                result[fp] = None
        return result

    def _resolve_allowed(self, role: str) -> dict[str, Any]:
        return self.allowed_agents if role == "agent" else self.allowed_clients

    async def register_control(self, side: str, conn: FramedConnection) -> ControlConn:
        # First message contains role. Use it to choose allowed list.
        first = await conn.recv_message()
        role = str(first.get("role", ""))
        agent_id = str(first.get("agent_id", "default"))
        await conn.send_frame((len(b"{}")).to_bytes(4, "big") + b"{}")
        # Recreate stream semantics: the handshake server expects HELLO as first message.
        # To avoid stream rewind complexity, we enforce listener to pass untouched connection to handshake;
        # register_control is not used in current flow.
        raise RuntimeError("register_control should not be called directly")

    async def handshake_and_attach(self, conn: FramedConnection, side: str) -> ControlConn:
        # We don't know role before HELLO, so allow both side-appropriate peers.
        allowed = self.allowed_agents if side == "agent" else self.allowed_clients
        if any(v is None for v in allowed.values()):
            raise ValueError("allowed peer entries must be public key file paths for handshake verification")
        hs = await self.handshake.run(conn, allowed)

        ctrl = ControlConn(
            role=hs.role,
            agent_id=hs.agent_id,
            conn=conn,
            ctrl_key=hs.ctrl_key,
            fingerprint=hs.peer_fingerprint,
            side=side,
        )
        async with self._lock:
            if side == "agent":
                self.agent_controls[hs.agent_id] = ctrl
            else:
                self.client_controls[hs.agent_id] = ctrl
        self.logger.info("control connected side=%s role=%s agent_id=%s", side, hs.role, hs.agent_id)
        await self._warmup_pool(ctrl)
        return ctrl

    async def _warmup_pool(self, ctrl: ControlConn) -> None:
        tokens = await self.pool_manager.reserve_tokens(
            agent_id=ctrl.agent_id,
            side=ctrl.side,
            ctrl_key=ctrl.ctrl_key,
            count=self.pool_manager.pool_initial_size,
        )
        await ctrl.conn.send_encrypted(ctrl.ctrl_key, MsgType.POOL_ALLOC.value, tokens=tokens)

    async def run_control_loop(self, ctrl: ControlConn) -> None:
        try:
            while True:
                msg = await ctrl.conn.recv_encrypted(ctrl.ctrl_key)
                await self._handle_message(ctrl, msg)
        finally:
            await self.on_disconnect(ctrl)

    async def on_disconnect(self, ctrl: ControlConn) -> None:
        self.logger.warning("control disconnected side=%s agent_id=%s", ctrl.side, ctrl.agent_id)
        async with self._lock:
            if ctrl.side == "agent":
                if self.agent_controls.get(ctrl.agent_id) is ctrl:
                    self.agent_controls.pop(ctrl.agent_id, None)
            else:
                if self.client_controls.get(ctrl.agent_id) is ctrl:
                    self.client_controls.pop(ctrl.agent_id, None)
        await self.pool_manager.close_all_for_agent(ctrl.agent_id)

    async def _handle_message(self, ctrl: ControlConn, msg: dict[str, Any]) -> None:
        msg_type = msg.get("type")
        if msg_type == MsgType.PING.value:
            await ctrl.conn.send_encrypted(ctrl.ctrl_key, MsgType.PONG.value, ts=msg.get("ts"))
            return

        if msg_type == MsgType.POOL_READY.value:
            return

        if msg_type == MsgType.SESSION_REQUEST.value and ctrl.side == "client":
            await self._on_session_request(ctrl, msg)
            return

        if msg_type == MsgType.SESSION_READY.value:
            await self._on_session_ready(ctrl, msg)
            return

        if msg_type in (MsgType.SESSION_CLOSE.value, MsgType.SESSION_FAIL.value):
            sid = str(msg.get("session_id", ""))
            if sid:
                await self.session_manager.close_session(sid)
            return

        if msg_type == MsgType.AGENT_STATUS_REQ.value and ctrl.side == "client":
            await self._on_agent_status_req(ctrl, msg)
            return

        if msg_type == MsgType.CLIENT_STATUS_REQ.value and ctrl.side == "agent":
            await self._on_client_status_req(ctrl, msg)
            return

        if msg_type == MsgType.AGENT_PWD_CHANGE.value and ctrl.side == "client":
            ok = await self._forward_to_agent(ctrl.agent_id, msg)
            if not ok:
                await ctrl.conn.send_encrypted(
                    ctrl.ctrl_key,
                    MsgType.AGENT_PWD_CHANGED.value,
                    ok=False,
                    reason="agent_not_connected",
                )
            return

        if msg_type == MsgType.AGENT_PWD_CHANGED.value and ctrl.side == "agent":
            client_ctrl = self.client_controls.get(ctrl.agent_id)
            if client_ctrl:
                fields = {k: v for k, v in msg.items() if k != "type"}
                await client_ctrl.conn.send_encrypted(client_ctrl.ctrl_key, MsgType.AGENT_PWD_CHANGED.value, **fields)
            return

        if msg_type == MsgType.AGENT_RESTART_REQ.value and ctrl.side == "client":
            ok = await self._forward_to_agent(ctrl.agent_id, msg)
            if not ok:
                await ctrl.conn.send_encrypted(
                    ctrl.ctrl_key,
                    MsgType.AGENT_RESTART_RESP.value,
                    ok=False,
                    reason="agent_not_connected",
                )
            return

        if msg_type == MsgType.AGENT_RESTART_RESP.value and ctrl.side == "agent":
            client_ctrl = self.client_controls.get(ctrl.agent_id)
            if client_ctrl:
                fields = {k: v for k, v in msg.items() if k != "type"}
                await client_ctrl.conn.send_encrypted(client_ctrl.ctrl_key, MsgType.AGENT_RESTART_RESP.value, **fields)
            return

        if msg_type == MsgType.AGENT_STATUS_RESP.value and ctrl.side == "agent":
            client_ctrl = self.client_controls.get(ctrl.agent_id)
            if client_ctrl:
                fields = {k: v for k, v in msg.items() if k != "type"}
                await client_ctrl.conn.send_encrypted(client_ctrl.ctrl_key, MsgType.AGENT_STATUS_RESP.value, **fields)
            return

        if msg_type == MsgType.CLIENT_STATUS_RESP.value and ctrl.side == "client":
            agent_ctrl = self.agent_controls.get(ctrl.agent_id)
            if agent_ctrl:
                fields = {k: v for k, v in msg.items() if k != "type"}
                await agent_ctrl.conn.send_encrypted(agent_ctrl.ctrl_key, MsgType.CLIENT_STATUS_RESP.value, **fields)
            return

        if msg_type == MsgType.RELAY_RESTART_REQ.value and ctrl.side == "client":
            # backward compatibility: old restart command now maps to cert reload
            result = self._reload_cert_materials()
            await ctrl.conn.send_encrypted(ctrl.ctrl_key, MsgType.RELAY_RESTART_RESP.value, **result)
            return

        if msg_type == MsgType.RELAY_CERT_RELOAD_REQ.value and ctrl.side == "client":
            result = self._reload_cert_materials()
            await ctrl.conn.send_encrypted(ctrl.ctrl_key, MsgType.RELAY_CERT_RELOAD_RESP.value, **result)
            return

    async def _on_agent_status_req(self, client_ctrl: ControlConn, msg: dict[str, Any]) -> None:
        agent_ctrl = self.agent_controls.get(client_ctrl.agent_id)
        request_id = str(msg.get("request_id", "")).strip()
        if not agent_ctrl:
            await client_ctrl.conn.send_encrypted(
                client_ctrl.ctrl_key,
                MsgType.AGENT_STATUS_RESP.value,
                connected=False,
                pool_size=0,
                active_sessions=0,
                uptime=0.0,
                request_id=request_id,
            )
            return
        await self._forward_to_agent(
            client_ctrl.agent_id,
            {"type": MsgType.AGENT_STATUS_REQ.value, "request_id": request_id},
        )

    async def _on_client_status_req(self, agent_ctrl: ControlConn, msg: dict[str, Any]) -> None:
        client_ctrl = self.client_controls.get(agent_ctrl.agent_id)
        request_id = str(msg.get("request_id", "")).strip()
        if not client_ctrl:
            payload: dict[str, Any] = {"connected": False}
            if request_id:
                payload["request_id"] = request_id
            await agent_ctrl.conn.send_encrypted(agent_ctrl.ctrl_key, MsgType.CLIENT_STATUS_RESP.value, **payload)
            return
        payload = {"type": MsgType.CLIENT_STATUS_REQ.value}
        if request_id:
            payload["request_id"] = request_id
        await self._forward_to_client(agent_ctrl.agent_id, payload)

    async def _forward_to_agent(self, agent_id: str, msg: dict[str, Any]) -> bool:
        agent_ctrl = self.agent_controls.get(agent_id)
        if not agent_ctrl:
            return False
        msg_type = msg["type"]
        fields = {k: v for k, v in msg.items() if k != "type"}
        await agent_ctrl.conn.send_encrypted(agent_ctrl.ctrl_key, msg_type, **fields)
        return True

    async def _forward_to_client(self, agent_id: str, msg: dict[str, Any]) -> bool:
        client_ctrl = self.client_controls.get(agent_id)
        if not client_ctrl:
            return False
        msg_type = msg["type"]
        fields = {k: v for k, v in msg.items() if k != "type"}
        await client_ctrl.conn.send_encrypted(client_ctrl.ctrl_key, msg_type, **fields)
        return True

    def _reload_cert_materials(self) -> dict[str, Any]:
        try:
            self.handshake = RelayHandshakeServer(self.config["rsa_private_key"], self.config.get("auth_key", ""))
            self.allowed_agents = self._load_allowed(self.config.get("allowed_agents", []))
            self.allowed_clients = self._load_allowed(self.config.get("allowed_clients", []))
            return {"ok": True}
        except Exception as exc:
            self.logger.exception("reload cert materials failed")
            return {"ok": False, "reason": str(exc)}

    async def close_all_controls(self) -> None:
        async with self._lock:
            controls = list(self.agent_controls.values()) + list(self.client_controls.values())
            self.agent_controls.clear()
            self.client_controls.clear()
        for ctrl in controls:
            with contextlib.suppress(Exception):
                await ctrl.conn.close_safe()

    async def _on_session_request(self, client_ctrl: ControlConn, msg: dict[str, Any]) -> None:
        agent_id = str(msg.get("agent_id", client_ctrl.agent_id))
        mode = str(msg.get("mode", "directed"))
        target = msg.get("target")
        request_id = str(msg.get("request_id", "")) or None
        agent_ctrl = self.agent_controls.get(agent_id)
        if not agent_ctrl:
            payload: dict[str, Any] = {"session_id": "", "reason": "agent_not_connected"}
            if request_id:
                payload["request_id"] = request_id
            await client_ctrl.conn.send_encrypted(client_ctrl.ctrl_key, MsgType.SESSION_FAIL.value, **payload)
            return

        # Speculative scale up when idle pool is low.
        idle_before = {
            "agent": await self.pool_manager.idle_count(agent_id, "agent"),
            "client": await self.pool_manager.idle_count(agent_id, "client"),
        }
        for side, ctrl in (("agent", agent_ctrl), ("client", client_ctrl)):
            idle = idle_before[side]
            if idle < self.pool_manager.pool_scale_batch:
                tokens = await self.pool_manager.reserve_tokens(
                    agent_id=agent_id,
                    side=side,
                    ctrl_key=ctrl.ctrl_key,
                    count=self.pool_manager.pool_scale_batch,
                )
                await ctrl.conn.send_encrypted(ctrl.ctrl_key, MsgType.POOL_ALLOC.value, tokens=tokens)

        # If pool was empty, wait for at least one ready connection per side before assignment.
        if idle_before["agent"] == 0:
            ok = await self.pool_manager.wait_for_idle(agent_id, "agent", timeout=5.0)
            if not ok:
                payload = {"session_id": "", "reason": "pool_exhausted"}
                if request_id:
                    payload["request_id"] = request_id
                await client_ctrl.conn.send_encrypted(client_ctrl.ctrl_key, MsgType.SESSION_FAIL.value, **payload)
                return
        if idle_before["client"] == 0:
            ok = await self.pool_manager.wait_for_idle(agent_id, "client", timeout=5.0)
            if not ok:
                payload = {"session_id": "", "reason": "pool_exhausted"}
                if request_id:
                    payload["request_id"] = request_id
                await client_ctrl.conn.send_encrypted(client_ctrl.ctrl_key, MsgType.SESSION_FAIL.value, **payload)
                return

        try:
            session = await self.session_manager.create_session(
                agent_id=agent_id,
                mode=mode,
                target=str(target) if target is not None else None,
                client_request_id=request_id,
            )
        except RuntimeError:
            payload = {"session_id": "", "reason": "pool_exhausted"}
            if request_id:
                payload["request_id"] = request_id
            await client_ctrl.conn.send_encrypted(client_ctrl.ctrl_key, MsgType.SESSION_FAIL.value, **payload)
            return

        agent_payload = await self.session_manager.session_assign_payload_for_agent(session)
        client_payload = await self.session_manager.session_assign_payload_for_client(session)
        await agent_ctrl.conn.send_encrypted(agent_ctrl.ctrl_key, MsgType.SESSION_ASSIGN.value, **agent_payload)
        await client_ctrl.conn.send_encrypted(client_ctrl.ctrl_key, MsgType.SESSION_ASSIGN.value, **client_payload)
        await self.session_manager.arm_setup_timeout(
            session.session_id,
            timeout_seconds=self.session_manager.setup_timeout,
            on_timeout=self._on_session_setup_timeout,
        )

    async def _on_session_ready(self, ctrl: ControlConn, msg: dict[str, Any]) -> None:
        session_id = str(msg.get("session_id", ""))
        if not session_id:
            return
        side = "agent" if ctrl.side == "agent" else "client"
        session = await self.session_manager.mark_ready(session_id, side)
        if not session:
            return
        await self.session_manager.start_bridge_if_ready(session_id)

    async def _on_session_setup_timeout(self, session: Any) -> None:
        client_ctrl = self.client_controls.get(session.agent_id)
        agent_ctrl = self.agent_controls.get(session.agent_id)

        if session.ready_agent and not session.ready_client and agent_ctrl:
            await agent_ctrl.conn.send_encrypted(agent_ctrl.ctrl_key, MsgType.SESSION_CLOSE.value, session_id=session.session_id)
        if session.ready_client and not session.ready_agent and client_ctrl:
            await client_ctrl.conn.send_encrypted(client_ctrl.ctrl_key, MsgType.SESSION_CLOSE.value, session_id=session.session_id)

        if client_ctrl:
            payload: dict[str, Any] = {
                "session_id": session.session_id,
                "reason": "setup_timeout",
            }
            if session.client_request_id:
                payload["request_id"] = session.client_request_id
            await client_ctrl.conn.send_encrypted(client_ctrl.ctrl_key, MsgType.SESSION_FAIL.value, **payload)

        await self.session_manager.close_session(session.session_id)

