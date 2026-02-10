from __future__ import annotations

import asyncio
import contextlib
from urllib.parse import urlparse

from common.connection import FramedConnection
from common.crypto import encrypted_recv, encrypted_send


def _parse_target(target: str) -> tuple[str, int]:
    if "://" in target:
        u = urlparse(target)
        host = u.hostname or ""
        port = u.port or (443 if u.scheme == "https" else 80)
        return host, port
    if ":" not in target:
        raise ValueError("target must be host:port")
    host, port = target.rsplit(":", 1)
    return host, int(port)


class ProxyHandler:
    async def run(self, pool_conn: FramedConnection, data_key: bytes, target: str) -> None:
        host, port = _parse_target(target)
        target_reader, target_writer = await asyncio.open_connection(host, port)

        async def local_to_target() -> None:
            while True:
                data = await encrypted_recv(pool_conn.reader, data_key)
                if not data:
                    break
                target_writer.write(data)
                await target_writer.drain()

        async def target_to_local() -> None:
            while True:
                data = await target_reader.read(65536)
                if not data:
                    break
                await encrypted_send(pool_conn.writer, data_key, data)

        tasks = [
            asyncio.create_task(local_to_target(), name="agent-proxy-l2t"),
            asyncio.create_task(target_to_local(), name="agent-proxy-t2l"),
        ]
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
        for task in done:
            with contextlib.suppress(Exception):
                await task
        target_writer.close()
        await target_writer.wait_closed()

