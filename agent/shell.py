from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import subprocess
import sys
from typing import Any

from common.connection import FramedConnection
from common.crypto import encrypted_recv, encrypted_send


class ShellHandler:
    def __init__(self, config: dict[str, Any] | None = None):
        cfg = config or {}
        self.logger = logging.getLogger("agent.shell")
        self.windows_backend = str(
            cfg.get("shell_windows_backend", os.environ.get("TRIPROXY_WINDOWS_SHELL_BACKEND", "auto"))
        ).strip().lower()
        if self.windows_backend not in {"auto", "conpty", "subprocess"}:
            self.logger.warning(
                "invalid shell_windows_backend=%s, fallback to auto",
                self.windows_backend,
            )
            self.windows_backend = "auto"
        self.windows_shell = str(cfg.get("shell_windows_shell", "powershell.exe"))
        self.conpty_fallback = bool(cfg.get("shell_windows_conpty_fallback", True))
        self._conpty_probe: dict[str, Any] | None = None

    async def run(self, pool_conn: FramedConnection, data_key: bytes) -> None:
        if sys.platform == "win32":
            await self._run_windows(pool_conn, data_key)
            return
        await self._run_subprocess_shell(pool_conn, data_key)

    async def _probe_windows_conpty(self) -> dict[str, Any]:
        if self._conpty_probe is not None:
            return self._conpty_probe
        probe: dict[str, Any] = {
            "platform": sys.platform,
            "backend_setting": self.windows_backend,
            "shell": self.windows_shell,
            "capable": False,
        }
        if sys.platform != "win32":
            probe["reason"] = "not_windows"
            self._conpty_probe = probe
            return probe

        try:
            from winpty import PtyProcess  # type: ignore
        except Exception as exc:
            probe["reason"] = "import_failed"
            probe["error"] = repr(exc)
            self._conpty_probe = probe
            return probe

        probe["read"] = True
        probe["write"] = True
        probe["setwinsize"] = True
        pty = None
        try:
            pty = PtyProcess.spawn(self.windows_shell)
            probe["spawn"] = "ok"
            probe["setwinsize"] = hasattr(pty, "setwinsize")
            token = "__TRIPROXY_CONPTY_PROBE__"
            await asyncio.to_thread(pty.write, f"echo {token}\r\n")
            collected = ""
            loop = asyncio.get_running_loop()
            deadline = loop.time() + 2.5
            while loop.time() < deadline:
                try:
                    chunk_raw = await asyncio.wait_for(asyncio.to_thread(pty.read), timeout=0.4)
                except asyncio.TimeoutError:
                    continue
                chunk = chunk_raw if isinstance(chunk_raw, str) else chunk_raw.decode("utf-8", errors="ignore")
                if chunk:
                    collected += chunk
                    if token in collected:
                        probe["capable"] = True
                        probe["probe_echo"] = "ok"
                        break
            if not probe["capable"]:
                probe["reason"] = "probe_echo_timeout"
                probe["probe_tail"] = collected[-200:]
        except Exception as exc:
            probe["reason"] = "spawn_failed"
            probe["error"] = repr(exc)
        finally:
            if pty is not None:
                with contextlib.suppress(Exception):
                    pty.close()
        self._conpty_probe = probe
        return probe

    async def _run_windows(self, pool_conn: FramedConnection, data_key: bytes) -> None:
        probe = await self._probe_windows_conpty()
        self.logger.debug("windows shell capability probe=%s", probe)
        preferred = self.windows_backend
        use_conpty = preferred == "conpty" or (preferred == "auto" and bool(probe.get("capable")))
        if not use_conpty:
            self.logger.debug("windows shell backend=subprocess reason=%s", probe.get("reason", "forced"))
            await self._run_subprocess_shell(pool_conn, data_key, shell_cmd=self.windows_shell)
            return

        try:
            self.logger.debug("windows shell backend=conpty starting")
            await self._run_windows_conpty(pool_conn, data_key)
            self.logger.debug("windows shell backend=conpty finished")
            return
        except Exception as exc:
            self.logger.warning("conpty shell failed err=%s", exc)
            if not self.conpty_fallback:
                raise
            self.logger.debug("fallback to subprocess after conpty failure")
            await self._run_subprocess_shell(pool_conn, data_key, shell_cmd=self.windows_shell)

    async def _run_windows_conpty(self, pool_conn: FramedConnection, data_key: bytes) -> None:
        from winpty import PtyProcess  # type: ignore

        pty = PtyProcess.spawn(self.windows_shell)
        self.logger.debug("conpty spawned shell=%s", self.windows_shell)

        async def pty_to_remote() -> None:
            empty_reads = 0
            forwarded = 0
            while True:
                try:
                    data_raw = await asyncio.to_thread(pty.read)
                except Exception as exc:
                    self.logger.debug("conpty read failed err=%s", exc)
                    raise
                if data_raw in (b"", "", None):
                    empty_reads += 1
                    if empty_reads == 1 or empty_reads % 50 == 0:
                        self.logger.debug("conpty empty read count=%s", empty_reads)
                    if hasattr(pty, "isalive"):
                        with contextlib.suppress(Exception):
                            if not pty.isalive():
                                self.logger.debug("conpty process not alive; stop reader")
                                break
                    await asyncio.sleep(0.02)
                    continue
                empty_reads = 0
                payload = data_raw if isinstance(data_raw, bytes) else str(data_raw).encode("utf-8", errors="ignore")
                forwarded += len(payload)
                await encrypted_send(pool_conn.writer, data_key, b"\x00" + payload)
                self.logger.debug("conpty -> remote bytes=%s total=%s", len(payload), forwarded)

        async def remote_to_pty() -> None:
            inbound = 0
            while True:
                payload = await encrypted_recv(pool_conn.reader, data_key)
                if not payload:
                    self.logger.debug("conpty stdin closed by remote")
                    break
                frame_type = payload[:1]
                body = payload[1:]
                if frame_type == b"\x00":
                    inbound += len(body)
                    self.logger.debug("remote -> conpty bytes=%s total=%s", len(body), inbound)
                    await asyncio.to_thread(pty.write, body.decode("utf-8", errors="ignore"))
                elif frame_type == b"\x01":
                    with contextlib.suppress(Exception):
                        resize = json.loads(body.decode("utf-8"))
                        cols = int(resize.get("cols", 80))
                        rows = int(resize.get("rows", 24))
                        if hasattr(pty, "setwinsize"):
                            await asyncio.to_thread(pty.setwinsize, rows, cols)
                            self.logger.debug("conpty resize cols=%s rows=%s", cols, rows)
                else:
                    self.logger.debug("remote -> conpty unknown frame_type=%s bytes=%s", frame_type, len(body))

        tasks = [
            asyncio.create_task(pty_to_remote(), name="shell-win-conpty-out"),
            asyncio.create_task(remote_to_pty(), name="shell-win-conpty-in"),
        ]
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
        for task in done:
            with contextlib.suppress(asyncio.CancelledError):
                await task
            if task.cancelled():
                self.logger.debug("conpty task cancelled task=%s", task.get_name())
                continue
            exc = task.exception()
            if exc is not None:
                self.logger.debug("conpty task failed task=%s err=%s", task.get_name(), exc)

        with contextlib.suppress(Exception):
            await asyncio.to_thread(pty.close)

    async def _run_subprocess_shell(
        self,
        pool_conn: FramedConnection,
        data_key: bytes,
        shell_cmd: str | None = None,
    ) -> None:
        if shell_cmd is not None:
            shell = shell_cmd
        else:
            shell = os.environ.get("SHELL", "/bin/bash")
        self.logger.debug("subprocess shell start cmd=%s", shell)
        proc = await asyncio.create_subprocess_exec(
            shell,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )

        assert proc.stdin is not None
        assert proc.stdout is not None

        async def shell_to_remote() -> None:
            forwarded = 0
            while True:
                data = await proc.stdout.read(4096)
                if not data:
                    self.logger.debug("subprocess stdout closed")
                    break
                forwarded += len(data)
                self.logger.debug("subprocess -> remote bytes=%s total=%s", len(data), forwarded)
                await encrypted_send(pool_conn.writer, data_key, b"\x00" + data)

        async def remote_to_shell() -> None:
            inbound = 0
            while True:
                payload = await encrypted_recv(pool_conn.reader, data_key)
                if not payload:
                    self.logger.debug("subprocess stdin closed by remote")
                    break
                frame_type = payload[:1]
                body = payload[1:]
                if frame_type == b"\x00":
                    inbound += len(body)
                    self.logger.debug("remote -> subprocess bytes=%s total=%s", len(body), inbound)
                    proc.stdin.write(body)
                    await proc.stdin.drain()
                elif frame_type == b"\x01":
                    # Subprocess path cannot resize pseudo console on Windows.
                    with contextlib.suppress(Exception):
                        resize = json.loads(body.decode("utf-8"))
                        self.logger.debug(
                            "subprocess resize ignored cols=%s rows=%s",
                            resize.get("cols"),
                            resize.get("rows"),
                        )
                else:
                    self.logger.debug("remote -> subprocess unknown frame_type=%s bytes=%s", frame_type, len(body))

        tasks = [
            asyncio.create_task(shell_to_remote(), name="shell-subprocess-out"),
            asyncio.create_task(remote_to_shell(), name="shell-subprocess-in"),
        ]
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
        for task in done:
            with contextlib.suppress(asyncio.CancelledError):
                await task
            if task.cancelled():
                self.logger.debug("subprocess task cancelled task=%s", task.get_name())
                continue
            exc = task.exception()
            if exc is not None:
                self.logger.debug("subprocess task failed task=%s err=%s", task.get_name(), exc)

        with contextlib.suppress(Exception):
            proc.terminate()
        with contextlib.suppress(Exception):
            await proc.wait()
