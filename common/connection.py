from __future__ import annotations

import asyncio
import contextlib
from typing import Any

from common.crypto import aes_gcm_decrypt, aes_gcm_encrypt
from common.protocol import MAX_FRAME_SIZE, build_message, encode_message, parse_message


class FramedConnection:
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.reader = reader
        self.writer = writer

    async def send_frame(self, payload: bytes) -> None:
        if len(payload) > MAX_FRAME_SIZE:
            raise ValueError("payload exceeds MAX_FRAME_SIZE")
        self.writer.write(len(payload).to_bytes(4, "big") + payload)
        await self.writer.drain()

    async def recv_frame(self) -> bytes:
        raw_len = await self.reader.readexactly(4)
        length = int.from_bytes(raw_len, "big")
        if length > MAX_FRAME_SIZE:
            raise ValueError("received frame exceeds MAX_FRAME_SIZE")
        return await self.reader.readexactly(length)

    async def send_message(self, msg_type: str, **fields: Any) -> None:
        payload = encode_message(build_message(msg_type, **fields))
        await self.send_frame(payload)

    async def recv_message(self) -> dict[str, Any]:
        payload = await self.recv_frame()
        return parse_message(payload)

    async def send_encrypted(self, key: bytes, msg_type: str, **fields: Any) -> None:
        plaintext = encode_message(build_message(msg_type, **fields))
        await self.send_frame(aes_gcm_encrypt(key, plaintext))

    async def recv_encrypted(self, key: bytes) -> dict[str, Any]:
        payload = await self.recv_frame()
        plaintext = aes_gcm_decrypt(key, payload)
        return parse_message(plaintext)

    def close(self) -> None:
        self.writer.close()

    async def wait_closed(self) -> None:
        await self.writer.wait_closed()

    async def close_safe(self) -> None:
        self.close()
        with contextlib.suppress(ConnectionError, BrokenPipeError, OSError):
            await self.wait_closed()

