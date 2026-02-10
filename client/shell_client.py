from __future__ import annotations

import asyncio
import contextlib
import json

from aiohttp import web

from common.connection import FramedConnection
from common.crypto import encrypted_recv, encrypted_send


class ShellClient:
    async def handle_websocket(
        self,
        ws: web.WebSocketResponse,
        data_key: bytes,
        pool_conn: FramedConnection,
    ) -> None:
        async def ws_to_remote() -> None:
            async for msg in ws:
                if msg.type == web.WSMsgType.TEXT:
                    try:
                        payload = json.loads(msg.data)
                    except Exception:
                        await encrypted_send(pool_conn.writer, data_key, b"\x00" + msg.data.encode("utf-8"))
                        continue
                    if payload.get("type") == "resize":
                        body = json.dumps(
                            {"cols": int(payload["cols"]), "rows": int(payload["rows"])}
                        ).encode("utf-8")
                        await encrypted_send(pool_conn.writer, data_key, b"\x01" + body)
                    elif payload.get("type") == "data":
                        await encrypted_send(pool_conn.writer, data_key, b"\x00" + payload.get("data", "").encode("utf-8"))
                elif msg.type == web.WSMsgType.BINARY:
                    await encrypted_send(pool_conn.writer, data_key, b"\x00" + bytes(msg.data))
                elif msg.type in (web.WSMsgType.CLOSE, web.WSMsgType.ERROR):
                    break

        async def remote_to_ws() -> None:
            while True:
                payload = await encrypted_recv(pool_conn.reader, data_key)
                if not payload:
                    break
                kind = payload[:1]
                body = payload[1:]
                if kind == b"\x00":
                    await ws.send_bytes(body)

        tasks = [
            asyncio.create_task(ws_to_remote()),
            asyncio.create_task(remote_to_ws()),
        ]
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for t in pending:
            t.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await t
        for t in done:
            with contextlib.suppress(Exception):
                await t

