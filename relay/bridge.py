from __future__ import annotations

import asyncio
import contextlib


class DataBridge:
    def __init__(
        self,
        reader_a: asyncio.StreamReader,
        writer_a: asyncio.StreamWriter,
        reader_b: asyncio.StreamReader,
        writer_b: asyncio.StreamWriter,
    ):
        self.reader_a = reader_a
        self.writer_a = writer_a
        self.reader_b = reader_b
        self.writer_b = writer_b
        self._tasks: list[asyncio.Task[None]] = []

    async def _pipe(self, src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> None:
        while True:
            chunk = await src.read(65536)
            if not chunk:
                break
            dst.write(chunk)
            await dst.drain()

    async def run(self) -> None:
        self._tasks = [
            asyncio.create_task(self._pipe(self.reader_a, self.writer_b), name="bridge-a2b"),
            asyncio.create_task(self._pipe(self.reader_b, self.writer_a), name="bridge-b2a"),
        ]
        done, pending = await asyncio.wait(self._tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task
        for task in done:
            with contextlib.suppress(Exception):
                await task

