from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from common.connection import FramedConnection
from common.crypto import (
    b64d,
    b64e,
    derive_key,
    load_private_key,
    pubkey_fingerprint,
    random_bytes,
    rsa_decrypt,
    rsa_sign,
    rsa_verify,
    verify_auth_key_proof,
)
from common.protocol import MsgType, PROTOCOL_VERSION


@dataclass(slots=True)
class HandshakeResult:
    role: str
    agent_id: str
    peer_fingerprint: str
    ctrl_key: bytes


class RelayHandshakeServer:
    def __init__(self, rsa_private_key: str, auth_key: str = ""):
        self.private_key = load_private_key(rsa_private_key)
        self.public_key = self.private_key.public_key()
        self.server_fingerprint = pubkey_fingerprint(self.public_key)
        self.auth_key = auth_key or ""

    async def run(
        self,
        conn: FramedConnection,
        allowed_peers: dict[str, Any],
    ) -> HandshakeResult:
        hello = await conn.recv_message()
        if hello.get("type") != MsgType.HELLO.value:
            await conn.send_message(MsgType.HANDSHAKE_FAIL.value, reason="expected HELLO")
            raise ValueError("expected HELLO")

        if hello.get("version") != PROTOCOL_VERSION:
            await conn.send_message(MsgType.HANDSHAKE_FAIL.value, reason="protocol version mismatch")
            raise ValueError("protocol version mismatch")

        role = str(hello.get("role", ""))
        agent_id = str(hello.get("agent_id", "default"))
        peer_fingerprint = str(hello.get("pubkey_fingerprint", ""))
        client_random = b64d(str(hello.get("client_random", "")))

        if peer_fingerprint not in allowed_peers:
            await conn.send_message(MsgType.HANDSHAKE_FAIL.value, reason="peer fingerprint not allowed")
            raise ValueError("peer fingerprint not allowed")

        server_random = random_bytes(32)
        await conn.send_message(
            MsgType.SERVER_HELLO.value,
            version=PROTOCOL_VERSION,
            server_random=b64e(server_random),
            pubkey_fingerprint=self.server_fingerprint,
        )

        key_exchange = await conn.recv_message()
        if key_exchange.get("type") != MsgType.KEY_EXCHANGE.value:
            await conn.send_message(MsgType.HANDSHAKE_FAIL.value, reason="expected KEY_EXCHANGE")
            raise ValueError("expected KEY_EXCHANGE")

        encrypted_premaster = b64d(str(key_exchange.get("encrypted_premaster", "")))
        signature = b64d(str(key_exchange.get("signature", "")))
        premaster = rsa_decrypt(self.private_key, encrypted_premaster)

        # The peer proves identity by signing client_random + server_random.
        transcript = hashlib.sha256(client_random + server_random).digest()
        peer_pub = allowed_peers[peer_fingerprint]
        rsa_verify(peer_pub, transcript, signature)

        verify_sig = rsa_sign(self.private_key, hashlib.sha256(server_random + client_random).digest())
        await conn.send_message(MsgType.KEY_VERIFY.value, signature=b64e(verify_sig))

        ctrl_key = derive_key(
            premaster=premaster,
            salt=client_random + server_random,
            info=b"triproxy-ctrl",
            length=32,
        )

        if self.auth_key:
            auth_msg = await conn.recv_encrypted(ctrl_key)
            if auth_msg.get("type") != MsgType.AUTH_KEY_VERIFY.value:
                await conn.send_encrypted(ctrl_key, MsgType.HANDSHAKE_FAIL.value, reason="expected AUTH_KEY_VERIFY")
                raise ValueError("expected AUTH_KEY_VERIFY")
            proof = str(auth_msg.get("proof", ""))
            if not verify_auth_key_proof(self.auth_key, server_random, proof):
                await conn.send_encrypted(ctrl_key, MsgType.HANDSHAKE_FAIL.value, reason="AUTH_KEY verify failed")
                raise ValueError("AUTH_KEY verify failed")

        await conn.send_encrypted(ctrl_key, MsgType.HANDSHAKE_OK.value)
        return HandshakeResult(
            role=role,
            agent_id=agent_id,
            peer_fingerprint=peer_fingerprint,
            ctrl_key=ctrl_key,
        )

