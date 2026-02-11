from __future__ import annotations

import asyncio
import contextlib
from urllib.parse import urlsplit

from common.crypto import encrypted_recv, encrypted_send
from client.session import ClientSessionManager


class GeneralProxyServer:
    def __init__(self, session_manager: ClientSessionManager, bind: str, port: int, agent_id: str = "default"):
        self.session_manager = session_manager
        self.bind = bind
        self.port = port
        self.agent_id = agent_id
        self.server: asyncio.AbstractServer | None = None
        self.active_sessions: set[str] = set()

    async def start(self) -> None:
        if self.server is not None:
            return
        self.server = await asyncio.start_server(self._handle_client, host=self.bind, port=self.port)

    async def stop(self) -> None:
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            self.server = None
        for sid in list(self.active_sessions):
            await self.session_manager.close_session(sid)

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        sid = ""
        try:
            first = await reader.readexactly(1)
            if first == b"\x05":
                sid = await self._handle_socks5(first, reader, writer)
            else:
                sid = await self._handle_http(first, reader, writer)
        except Exception:
            pass
        finally:
            if sid:
                self.active_sessions.discard(sid)
                await self.session_manager.close_session(sid)
            writer.close()
            await writer.wait_closed()

    async def _handle_socks5(
        self,
        first: bytes,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> str:
        nm = (await reader.readexactly(1))[0]
        await reader.readexactly(nm)
        writer.write(b"\x05\x00")
        await writer.drain()

        head = await reader.readexactly(4)
        atyp = head[3]
        if atyp == 0x01:
            host = ".".join(str(b) for b in await reader.readexactly(4))
        elif atyp == 0x03:
            n = (await reader.readexactly(1))[0]
            host = (await reader.readexactly(n)).decode("utf-8")
        else:
            raise ValueError("unsupported atyp")
        port = int.from_bytes(await reader.readexactly(2), "big")

        sid, data_key, token, pool_conn = await self._open_session(f"{host}:{port}")
        writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        await writer.drain()
        await self._bridge(reader, writer, pool_conn.reader, pool_conn.writer, data_key)
        await self.session_manager.pool_manager.put_back(token, pool_conn)
        return sid

    async def _handle_http(
        self,
        first: bytes,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> str:
        rest = await reader.readuntil(b"\r\n\r\n")
        req = first + rest
        line = req.split(b"\r\n", 1)[0].decode("latin1")
        method, target, _ = line.split(" ", 2)
        target_host = ""
        target_port = 80
        if method.upper() == "CONNECT":
            host, port = target.rsplit(":", 1)
            target_host, target_port = host, int(port)
        else:
            if target.startswith("http://") or target.startswith("https://"):
                u = urlsplit(target)
                target_host = u.hostname or ""
                target_port = u.port or (443 if u.scheme == "https" else 80)
            else:
                host_hdr = ""
                for h in req.split(b"\r\n"):
                    if h.lower().startswith(b"host:"):
                        host_hdr = h.split(b":", 1)[1].strip().decode("latin1")
                        break
                if ":" in host_hdr:
                    target_host, p = host_hdr.rsplit(":", 1)
                    target_port = int(p)
                else:
                    target_host = host_hdr
                    target_port = 80

        sid, data_key, token, pool_conn = await self._open_session(f"{target_host}:{target_port}")
        if method.upper() == "CONNECT":
            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()
        else:
            await encrypted_send(pool_conn.writer, data_key, req)
        await self._bridge(reader, writer, pool_conn.reader, pool_conn.writer, data_key)
        await self.session_manager.pool_manager.put_back(token, pool_conn)
        return sid

    async def _open_session(self, target: str):
        assign = await self.session_manager.request_session("general", target, self.agent_id)
        sid, data_key, _, pool_conn = await self.session_manager.use_assigned_pool(assign)
        token = str(assign["pool_token"])
        self.active_sessions.add(sid)
        return sid, data_key, token, pool_conn

    async def _bridge(
        self,
        local_reader: asyncio.StreamReader,
        local_writer: asyncio.StreamWriter,
        pool_reader: asyncio.StreamReader,
        pool_writer: asyncio.StreamWriter,
        data_key: bytes,
    ) -> None:
        async def local_to_remote() -> None:
            while True:
                data = await local_reader.read(65536)
                if not data:
                    break
                await encrypted_send(pool_writer, data_key, data)

        async def remote_to_local() -> None:
            while True:
                data = await encrypted_recv(pool_reader, data_key)
                if not data:
                    break
                local_writer.write(data)
                await local_writer.drain()

        tasks = [
            asyncio.create_task(local_to_remote()),
            asyncio.create_task(remote_to_local()),
        ]
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for t in pending:
            t.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await t
        for t in done:
            with contextlib.suppress(Exception):
                await t

