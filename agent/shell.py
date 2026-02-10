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
        self.conpty_probe_timeout = float(cfg.get("shell_windows_conpty_probe_timeout", 5.0))
        self.conpty_input_delay_ms = int(cfg.get("shell_windows_conpty_input_delay_ms", 250))
        self._conpty_probe: dict[str, Any] | None = None

    @staticmethod
    def _is_benign_close_exception(exc: BaseException) -> bool:
        if type(exc).__name__ == "InvalidTag":
            return True
        if isinstance(exc, RuntimeError) and not getattr(exc, "args", ()):
            return True
        return isinstance(
            exc,
            (
                asyncio.IncompleteReadError,
                asyncio.CancelledError,
                asyncio.TimeoutError,
                ConnectionError,
                BrokenPipeError,
                EOFError,
                OSError,
            ),
        )

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
            t0 = asyncio.get_running_loop().time()
            pty = PtyProcess.spawn(self.windows_shell)
            probe["spawn"] = "ok"
            probe["setwinsize"] = hasattr(pty, "setwinsize")
            token = "__TRIPROXY_CONPTY_PROBE__"
            startup = ""
            # ConPTY + PowerShell startup can emit control sequences before prompt is ready.
            # Warm-up by draining startup bytes first.
            for _ in range(3):
                try:
                    chunk_raw = await asyncio.wait_for(asyncio.to_thread(pty.read), timeout=0.25)
                except asyncio.TimeoutError:
                    break
                chunk = chunk_raw if isinstance(chunk_raw, str) else chunk_raw.decode("utf-8", errors="ignore")
                if chunk:
                    startup += chunk
            probe["startup_len"] = len(startup)
            probe["startup_drain_ms"] = int((asyncio.get_running_loop().time() - t0) * 1000)

            shell_lower = self.windows_shell.lower()
            if "powershell" in shell_lower or "pwsh" in shell_lower:
                probe_cmds = [
                    "\r\n",
                    f"Write-Output \"{token}\"\r\n",
                    f"echo {token}\r\n",
                    f"\"{token}\"\r\n",
                ]
            else:
                probe_cmds = [
                    "\r\n",
                    f"echo {token}\r\n",
                ]

            probe["probe_timeout"] = self.conpty_probe_timeout
            probe["probe_cmd_count"] = len(probe_cmds)
            collected = ""
            loop = asyncio.get_running_loop()
            deadline = loop.time() + self.conpty_probe_timeout
            for idx, cmd in enumerate(probe_cmds, start=1):
                cmd_start = loop.time()
                await asyncio.to_thread(pty.write, cmd)
                probe[f"probe_cmd_{idx}"] = cmd.strip() or "<newline>"
                inner_deadline = min(deadline, loop.time() + 1.2)
                while loop.time() < inner_deadline:
                    try:
                        chunk_raw = await asyncio.wait_for(asyncio.to_thread(pty.read), timeout=0.25)
                    except asyncio.TimeoutError:
                        continue
                    chunk = chunk_raw if isinstance(chunk_raw, str) else chunk_raw.decode("utf-8", errors="ignore")
                    if not chunk:
                        continue
                    collected += chunk
                    if token in collected:
                        probe["capable"] = True
                        probe["probe_echo"] = "ok"
                        probe["probe_cmd_hit"] = idx
                        probe["probe_cmd_hit_ms"] = int((loop.time() - cmd_start) * 1000)
                        probe["probe_total_ms"] = int((loop.time() - t0) * 1000)
                        break
                if probe["capable"]:
                    break
            if not probe["capable"]:
                probe["reason"] = "probe_echo_timeout"
                probe["probe_total_ms"] = int((loop.time() - t0) * 1000)
                probe["probe_startup_tail"] = startup[-120:]
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
        loop = asyncio.get_running_loop()
        started_at = loop.time()
        first_out_logged = False
        first_in_logged = False

        async def pty_to_remote() -> None:
            nonlocal first_out_logged
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
                if not first_out_logged:
                    first_out_logged = True
                    self.logger.debug("conpty first_output_ms=%s", int((loop.time() - started_at) * 1000))
                await encrypted_send(pool_conn.writer, data_key, b"\x00" + payload)
                self.logger.debug("conpty -> remote bytes=%s total=%s", len(payload), forwarded)

        async def remote_to_pty() -> None:
            nonlocal first_in_logged
            inbound = 0
            first_input_applied = False
            while True:
                try:
                    payload = await encrypted_recv(pool_conn.reader, data_key)
                except Exception as exc:
                    if self._is_benign_close_exception(exc):
                        self.logger.debug(
                            "conpty remote input closed err_type=%s err=%s",
                            type(exc).__name__,
                            exc,
                        )
                        break
                    raise
                if not payload:
                    self.logger.debug("conpty stdin closed by remote")
                    break
                frame_type = payload[:1]
                body = payload[1:]
                if frame_type == b"\x00":
                    if not first_input_applied and self.conpty_input_delay_ms > 0:
                        elapsed_ms = int((loop.time() - started_at) * 1000)
                        if elapsed_ms < self.conpty_input_delay_ms:
                            wait_ms = self.conpty_input_delay_ms - elapsed_ms
                            self.logger.debug("conpty delaying first_input_ms=%s wait_ms=%s", elapsed_ms, wait_ms)
                            await asyncio.sleep(wait_ms / 1000.0)
                        first_input_applied = True
                    inbound += len(body)
                    if not first_in_logged:
                        first_in_logged = True
                        self.logger.debug("conpty first_input_ms=%s", int((loop.time() - started_at) * 1000))
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
            if task.cancelled():
                self.logger.debug("conpty task cancelled task=%s", task.get_name())
                continue
            exc = task.exception()
            if exc is not None:
                if self._is_benign_close_exception(exc):
                    self.logger.debug(
                        "conpty task closed task=%s err_type=%s err=%s",
                        task.get_name(),
                        type(exc).__name__,
                        exc,
                    )
                else:
                    self.logger.debug(
                        "conpty task failed task=%s err_type=%s err=%s",
                        task.get_name(),
                        type(exc).__name__,
                        exc,
                    )

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
                try:
                    payload = await encrypted_recv(pool_conn.reader, data_key)
                except Exception as exc:
                    if self._is_benign_close_exception(exc):
                        self.logger.debug(
                            "subprocess remote input closed err_type=%s err=%s",
                            type(exc).__name__,
                            exc,
                        )
                        break
                    raise
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
            if task.cancelled():
                self.logger.debug("subprocess task cancelled task=%s", task.get_name())
                continue
            exc = task.exception()
            if exc is not None:
                if self._is_benign_close_exception(exc):
                    self.logger.debug(
                        "subprocess task closed task=%s err_type=%s err=%s",
                        task.get_name(),
                        type(exc).__name__,
                        exc,
                    )
                else:
                    self.logger.debug(
                        "subprocess task failed task=%s err_type=%s err=%s",
                        task.get_name(),
                        type(exc).__name__,
                        exc,
                    )

        with contextlib.suppress(Exception):
            proc.terminate()
        with contextlib.suppress(Exception):
            await proc.wait()
