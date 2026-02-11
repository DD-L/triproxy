from __future__ import annotations

import asyncio
import contextlib
import hashlib
import logging
import time
from typing import Any, Callable

from common.connection import FramedConnection
from common.crypto import (
    auth_key_proof,
    b64d,
    b64e,
    derive_key,
    load_private_key,
    load_public_key,
    pubkey_fingerprint,
    random_bytes,
    rsa_encrypt,
    rsa_sign,
    rsa_verify,
)
from common.protocol import MsgType, PROTOCOL_VERSION


class AgentControlConnection:
    def __init__(
        self,
        config: dict[str, Any],
        on_message: Callable[[dict[str, Any]], Any],
        on_connected: Callable[[bytes], Any] | None = None,
        on_disconnected: Callable[[], Any] | None = None,
    ):
        self.logger = logging.getLogger("agent.control")
        self.config = config
        self.on_message = on_message
        self.on_connected = on_connected
        self.on_disconnected = on_disconnected
        self.conn: FramedConnection | None = None
        self.ctrl_key: bytes | None = None
        self.running = True
        self.heartbeat_interval = int(config.get("heartbeat_interval", 100))
        self.dead_timeout = 300
        self._last_pong = time.monotonic()
        self._heartbeat_task: asyncio.Task[Any] | None = None

        self.private_key = load_private_key(config["rsa_private_key"])
        self.relay_pub = load_public_key(config["rsa_public_key"])
        self.agent_pub_fp = pubkey_fingerprint(self.private_key.public_key())
        self.relay_pub_fp = pubkey_fingerprint(self.relay_pub)

    async def connect_and_handshake(self) -> None:
        reader, writer = await asyncio.open_connection(
            self.config["relay_host"],
            int(self.config["relay_port_agent"]),
        )
        conn = FramedConnection(reader, writer)
        client_random = random_bytes(32)
        await conn.send_message(
            MsgType.HELLO.value,
            version=PROTOCOL_VERSION,
            role="agent",
            agent_id=self.config.get("agent_id", "default"),
            pubkey_fingerprint=self.agent_pub_fp,
            client_random=b64e(client_random),
        )

        server_hello = await conn.recv_message()
        if server_hello.get("type") != MsgType.SERVER_HELLO.value:
            raise RuntimeError("expected SERVER_HELLO")
        server_random = b64d(str(server_hello["server_random"]))
        if str(server_hello.get("pubkey_fingerprint")) != self.relay_pub_fp:
            raise RuntimeError("relay fingerprint mismatch")

        premaster = random_bytes(48)
        encrypted = rsa_encrypt(self.relay_pub, premaster)
        sig_data = hashlib.sha256(client_random + server_random).digest()
        signature = rsa_sign(self.private_key, sig_data)
        await conn.send_message(
            MsgType.KEY_EXCHANGE.value,
            encrypted_premaster=b64e(encrypted),
            signature=b64e(signature),
        )

        key_verify = await conn.recv_message()
        if key_verify.get("type") != MsgType.KEY_VERIFY.value:
            raise RuntimeError("expected KEY_VERIFY")
        relay_sig = b64d(str(key_verify["signature"]))
        rsa_verify(self.relay_pub, hashlib.sha256(server_random + client_random).digest(), relay_sig)

        ctrl_key = derive_key(
            premaster=premaster,
            salt=client_random + server_random,
            info=b"triproxy-ctrl",
            length=32,
        )

        auth_key = str(self.config.get("auth_key", ""))
        if auth_key:
            proof = auth_key_proof(auth_key, server_random)
            await conn.send_encrypted(ctrl_key, MsgType.AUTH_KEY_VERIFY.value, proof=proof)

        hs_result = await conn.recv_encrypted(ctrl_key)
        if hs_result.get("type") != MsgType.HANDSHAKE_OK.value:
            raise RuntimeError(f"handshake failed: {hs_result}")

        self.conn = conn
        self.ctrl_key = ctrl_key
        self._last_pong = time.monotonic()
        if self.on_connected:
            await self.on_connected(ctrl_key)

    async def send(self, msg_type: str, **fields: Any) -> None:
        if not self.conn or not self.ctrl_key:
            raise RuntimeError("control connection not ready")
        await self.conn.send_encrypted(self.ctrl_key, msg_type, **fields)

    async def message_loop(self) -> None:
        if not self.conn or not self.ctrl_key:
            raise RuntimeError("connection not ready")
        self._heartbeat_task = asyncio.create_task(self._heartbeat_loop(), name="agent-control-heartbeat")
        while True:
            msg = await self.conn.recv_encrypted(self.ctrl_key)
            if msg.get("type") == MsgType.PING.value:
                await self.send(MsgType.PONG.value, ts=msg.get("ts"))
                continue
            if msg.get("type") == MsgType.PONG.value:
                self._last_pong = time.monotonic()
                continue
            await self.on_message(msg)

    async def run(self) -> None:
        backoff = 1
        while self.running:
            try:
                await self.connect_and_handshake()
                backoff = 1
                await self.message_loop()
            except Exception as exc:
                self.logger.warning("control disconnected, reconnect in %ss err=%s", backoff, exc)
                await self._on_disconnect()
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 60)

    async def _on_disconnect(self) -> None:
        if self._heartbeat_task:
            self._heartbeat_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._heartbeat_task
            self._heartbeat_task = None
        if self.on_disconnected:
            await self.on_disconnected()
        if self.conn:
            await self.conn.close_safe()
        self.conn = None
        self.ctrl_key = None

    async def stop(self) -> None:
        self.running = False
        await self._on_disconnect()

    async def _heartbeat_loop(self) -> None:
        while self.conn and self.ctrl_key:
            await asyncio.sleep(self.heartbeat_interval)
            await self.send(MsgType.PING.value, ts=time.time())
            if time.monotonic() - self._last_pong > self.dead_timeout:
                self.logger.warning("control heartbeat timeout, forcing reconnect")
                self.conn.close()
                break

