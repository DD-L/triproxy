from __future__ import annotations

import asyncio
import contextlib
import json

from aiohttp import web

from common.connection import FramedConnection
from common.crypto import encrypted_recv, encrypted_send

_FRAME_DATA = b"\x00"
_FRAME_RESIZE = b"\x01"
_FRAME_KEEPALIVE = b"\x02"
_SHELL_KEEPALIVE_INTERVAL = 20.0


class ShellWebsocketBridge:
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
                        await encrypted_send(pool_conn.writer, data_key, _FRAME_DATA + msg.data.encode("utf-8"))
                        continue
                    if payload.get("type") == "resize":
                        body = json.dumps(
                            {"cols": int(payload["cols"]), "rows": int(payload["rows"])}
                        ).encode("utf-8")
                        await encrypted_send(pool_conn.writer, data_key, _FRAME_RESIZE + body)
                    elif payload.get("type") == "data":
                        await encrypted_send(pool_conn.writer, data_key, _FRAME_DATA + payload.get("data", "").encode("utf-8"))
                elif msg.type == web.WSMsgType.BINARY:
                    await encrypted_send(pool_conn.writer, data_key, _FRAME_DATA + bytes(msg.data))
                elif msg.type in (web.WSMsgType.CLOSE, web.WSMsgType.ERROR):
                    break

        async def keepalive_to_remote() -> None:
            while True:
                await asyncio.sleep(_SHELL_KEEPALIVE_INTERVAL)
                await encrypted_send(pool_conn.writer, data_key, _FRAME_KEEPALIVE)

        async def remote_to_ws() -> None:
            while True:
                payload = await encrypted_recv(pool_conn.reader, data_key)
                if not payload:
                    break
                kind = payload[:1]
                body = payload[1:]
                if kind == _FRAME_DATA:
                    await ws.send_bytes(body)
                elif kind == _FRAME_KEEPALIVE:
                    continue

        tasks = [
            asyncio.create_task(ws_to_remote()),
            asyncio.create_task(keepalive_to_remote()),
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
