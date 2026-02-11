from __future__ import annotations

import argparse
import asyncio
import contextlib
import datetime
import hashlib
import json
import logging
import os
import secrets
import signal
import sys
import time
from pathlib import Path
from typing import Any

from aiohttp import web
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from agent.local_shell import LocalShellService
from common.config import load_yaml, save_yaml
from common.crypto import load_public_key, pubkey_fingerprint
from common.log import setup_logging
from common.web_terminal import setup_terminal_routes, setup_terminal_static_routes


class AgentProcessManager:
    def __init__(self, config: dict[str, Any], config_path: str):
        self.config = config
        self.config_path = config_path
        self.proc: asyncio.subprocess.Process | None = None
        self.proc_started_at: float | None = None
        self.last_exit_code: int | None = None
        self.last_exit_time: float | None = None
        self._lock = asyncio.Lock()
        self._monitor_task: asyncio.Task[None] | None = None
        self._closed = False
        self._desired_running = True

    def _agent_cmd(self) -> list[str]:
        module = str(self.config.get("agent_process_module", "agent.main"))
        return [self.config.get("agent_python", ""), "-m", module, self.config_path]

    async def _spawn_locked(self) -> bool:
        if self.proc and self.proc.returncode is None:
            return False
        cmd = self._agent_cmd()
        if not cmd[0]:
            import sys

            cmd[0] = sys.executable
        self.proc = await asyncio.create_subprocess_exec(*cmd)
        self.proc_started_at = time.time()
        self.last_exit_code = None
        self.last_exit_time = None
        self._monitor_task = asyncio.create_task(self._monitor(self.proc), name="agent-daemon-monitor")
        return True

    async def start(self) -> bool:
        async with self._lock:
            self._desired_running = True
            return await self._spawn_locked()

    async def stop(self) -> bool:
        async with self._lock:
            self._desired_running = False
            proc = self.proc
            if not proc or proc.returncode is not None:
                return False
            proc.terminate()
        try:
            await asyncio.wait_for(proc.wait(), timeout=float(self.config.get("agent_stop_timeout", 8)))
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
        return True

    async def restart(self) -> None:
        await self.stop()
        await self.start()

    async def _monitor(self, proc: asyncio.subprocess.Process) -> None:
        code = await proc.wait()
        async with self._lock:
            if self.proc is proc:
                self.last_exit_code = code
                self.last_exit_time = time.time()
                self.proc = None
                self.proc_started_at = None
                should_restart = (
                    not self._closed
                    and self._desired_running
                    and bool(self.config.get("auto_restart", True))
                )
            else:
                should_restart = False
        if should_restart:
            await asyncio.sleep(float(self.config.get("agent_restart_delay", 2.0)))
            await self.start()

    async def close(self) -> None:
        self._closed = True
        await self.stop()
        task = self._monitor_task
        if task and not task.done():
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task

    def status(self) -> dict[str, Any]:
        running = self.proc is not None and self.proc.returncode is None
        return {
            "running": running,
            "pid": self.proc.pid if running and self.proc else None,
            "started_at": self.proc_started_at,
            "last_exit_code": self.last_exit_code,
            "last_exit_time": self.last_exit_time,
            "desired_running": self._desired_running,
        }


class AgentWebDaemon:
    def __init__(self, config: dict[str, Any], config_path: str):
        self.logger = logging.getLogger("agent.web_daemon")
        self.config = config
        self.config_path = config_path
        self.process = AgentProcessManager(config, config_path)
        self.nonces: dict[str, float] = {}
        self.sessions: dict[str, dict[str, Any]] = {}
        self.schedules: dict[str, dict[str, Any]] = {}
        self.schedule_tasks: dict[str, asyncio.Task[None]] = {}
        self.public_key_tokens: dict[str, dict[str, Any]] = {}
        self.local_shell = LocalShellService(config=config)
        self._stopping = False
        self._shutdown_task: asyncio.Task[None] | None = None
        self.stop_event = asyncio.Event()
        self.runner: web.AppRunner | None = None
        self.site: web.TCPSite | None = None
        self.app = web.Application()
        self._init_password_policy()
        self._restore_schedules_from_config()
        self._setup_routes()

    def _sync_auth_config_from_disk(self) -> None:
        # Remote password resets may be written by the child agent process.
        # Sync auth-related fields so web login takes effect immediately.
        try:
            latest = load_yaml(self.config_path)
        except Exception:
            return
        for key in ("web_console_password_hash", "web_console_force_change"):
            if key in latest and self.config.get(key) != latest.get(key):
                self.config[key] = latest.get(key)

    def _init_password_policy(self) -> None:
        default_hash = hashlib.sha256("admin-test".encode("utf-8")).hexdigest()
        current = str(self.config.get("web_console_password_hash", ""))
        changed = False
        if not current:
            self.config["web_console_password_hash"] = default_hash
            self.config["web_console_force_change"] = True
            changed = True
        elif "web_console_force_change" not in self.config:
            # For existing deployments, only force change when still using default password.
            self.config["web_console_force_change"] = current == default_hash
            changed = True
        if changed:
            save_yaml(self.config_path, self.config)

    def _setup_routes(self) -> None:
        self.app.router.add_get("/", self.index)
        self.app.router.add_static("/static", "agent/web_console_static")
        setup_terminal_static_routes(self.app)
        self.app.router.add_get("/api/nonce", self.api_nonce)
        self.app.router.add_post("/api/login", self.api_login)
        self.app.router.add_get("/api/status", self.auth(self.api_status))
        self.app.router.add_get("/api/self-check", self.auth(self.api_self_check))
        self.app.router.add_get("/api/config", self.auth(self.api_config_get))
        self.app.router.add_post("/api/config", self.auth(self.api_config_set))
        self.app.router.add_post("/api/start", self.auth(self.api_start))
        self.app.router.add_post("/api/stop", self.auth(self.api_stop))
        self.app.router.add_post("/api/restart", self.auth(self.api_restart))
        self.app.router.add_post("/api/connect", self.auth(self.api_start))
        self.app.router.add_post("/api/disconnect", self.auth(self.api_stop))
        self.app.router.add_post("/api/agent_name", self.auth(self.api_agent_name))
        self.app.router.add_post("/api/schedule", self.auth(self.api_schedule))
        self.app.router.add_get("/api/schedule", self.auth(self.api_schedule_list))
        self.app.router.add_delete("/api/schedule/{job_id}", self.auth(self.api_schedule_delete))
        self.app.router.add_post("/api/certs/regenerate", self.auth(self.api_certs_regenerate))
        self.app.router.add_get("/api/certs/public_link", self.auth(self.api_certs_public_link))
        self.app.router.add_get("/api/certs/relay_check", self.auth(self.api_certs_relay_check))
        self.app.router.add_post("/api/relay_config_path", self.auth(self.api_relay_config_path))
        self.app.router.add_get("/download/pub/{token}", self.api_download_public)
        self.app.router.add_post("/api/password", self.api_password)
        self.app.router.add_get("/api/logout", self.auth(self.api_logout))
        setup_terminal_routes(
            self.app,
            create_session=self.api_terminal_new,
            attach_terminal_ws=self.ws_terminal,
            guard=self.auth,
            include_terminal_page=True,
        )

    def _persist_schedules(self) -> None:
        self.config["web_console_schedules"] = list(self.schedules.values())
        save_yaml(self.config_path, self.config)

    def _restore_schedules_from_config(self) -> None:
        raw = self.config.get("web_console_schedules", [])
        if not isinstance(raw, list):
            return
        now = time.time()
        changed = False
        for item in raw:
            if not isinstance(item, dict):
                changed = True
                continue
            try:
                job_id = str(item["job_id"])
                run_at = float(item["run_at"])
                action = str(item["action"])
                mode = str(item.get("mode", "after"))
            except Exception:
                changed = True
                continue
            if action not in {"connect", "disconnect"}:
                changed = True
                continue
            if run_at <= now:
                changed = True
                continue
            normalized = {
                "job_id": job_id,
                "action": action,
                "mode": mode,
                "run_at": run_at,
                "created_at": float(item.get("created_at", now)),
            }
            self.schedules[job_id] = normalized
            self.schedule_tasks[job_id] = asyncio.create_task(
                self._run_schedule(job_id),
                name=f"agent-schedule-{job_id}",
            )
        if changed:
            self._persist_schedules()

    def auth(self, handler):
        async def _wrapped(request: web.Request):
            token = request.cookies.get("triproxy_session", "")
            session = self.sessions.get(token)
            exp = float(session.get("exp", 0)) if session else 0.0
            if exp < time.time():
                return web.json_response({"ok": False, "error": "unauthorized"}, status=401)
            if bool(session.get("force_change_password")) and request.path not in {
                "/api/password",
                "/api/status",
                "/api/logout",
            }:
                return web.json_response(
                    {"ok": False, "error": "force_change_password_required"},
                    status=403,
                )
            return await handler(request)

        return _wrapped

    async def index(self, _: web.Request) -> web.Response:
        return web.FileResponse("agent/web_console_static/index.html")

    async def api_nonce(self, _: web.Request) -> web.Response:
        nonce = secrets.token_hex(32)
        self.nonces[nonce] = time.time() + 60
        return web.json_response({"nonce": nonce})

    async def api_login(self, request: web.Request) -> web.Response:
        self._sync_auth_config_from_disk()
        data = await request.json()
        nonce = str(data.get("nonce", ""))
        response_hash = str(data.get("response", ""))
        nonce_exp = self.nonces.pop(nonce, 0)
        if nonce_exp < time.time():
            return web.json_response({"ok": False, "error": "nonce_expired"}, status=400)
        stored_hash = str(self.config.get("web_console_password_hash", ""))
        expected = hashlib.sha256((stored_hash + nonce).encode("utf-8")).hexdigest()
        if expected != response_hash:
            return web.json_response({"ok": False, "error": "invalid_credentials"}, status=401)
        token = secrets.token_hex(32)
        force_change_password = bool(self.config.get("web_console_force_change", False))
        self.sessions[token] = {
            "exp": time.time() + 12 * 3600,
            "force_change_password": force_change_password,
        }
        resp = web.json_response({"ok": True, "force_change_password": force_change_password})
        resp.set_cookie("triproxy_session", token, httponly=True, max_age=12 * 3600)
        return resp

    async def api_status(self, request: web.Request) -> web.Response:
        self._sync_auth_config_from_disk()
        token = request.cookies.get("triproxy_session", "")
        session = self.sessions.get(token) or {}
        return web.json_response(
            {
                "ok": True,
                "agent_process": self.process.status(),
                "force_change_password": bool(session.get("force_change_password", False)),
                "agent_id": self.config.get("agent_id", "default"),
                "schedules": list(self.schedules.values()),
                "relay_config_path": str(self.config.get("relay_config_path", "")).strip(),
            }
        )

    def _candidate_paths(self, value: str) -> list[Path]:
        raw = self._normalize_config_path(value)
        if not raw:
            return []
        p = Path(raw).expanduser()
        if p.is_absolute():
            return [p]
        # Runtime uses process CWD for relative paths (same as open(raw)).
        # Keep config-dir fallback to reduce false alarms in mixed deployments.
        cwd_path = Path.cwd() / p
        cfg_path = Path(self.config_path).resolve().parent / p
        if cwd_path == cfg_path:
            return [cwd_path]
        return [cwd_path, cfg_path]

    def _normalize_config_path(self, value: str) -> str:
        raw = str(value).strip()
        if not raw:
            return raw
        # Shared configs may contain Windows-style separators (e.g. certs\agent_public.pem).
        # On POSIX/WSL, normalize them to keep path checks cross-platform.
        if os.name != "nt":
            raw = raw.replace("\\", "/")
        return raw

    def _first_existing_path(self, value: str) -> Path | None:
        for p in self._candidate_paths(value):
            if p.exists():
                return p
        return None

    async def _probe_tcp(self, host: str, port: int, timeout: float = 1.5) -> tuple[bool, str]:
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host=host, port=port), timeout=timeout)
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
            del reader
            return True, ""
        except Exception as exc:
            return False, str(exc)

    async def api_self_check(self, _: web.Request) -> web.Response:
        checks: list[dict[str, Any]] = []

        def add_check(
            name: str,
            ok: bool,
            *,
            reason: str = "",
            suggestion: str = "",
            level: str = "error",
        ) -> None:
            checks.append(
                {
                    "name": name,
                    "ok": ok,
                    "level": "info" if ok else level,
                    "reason": reason,
                    "suggestion": suggestion,
                }
            )

        proc_status = self.process.status()
        add_check(
            "agent_process_running",
            bool(proc_status["running"]),
            reason="Agent process is not running.",
            suggestion="Start Agent from this console, then check config/logs if it exits repeatedly.",
        )

        relay_host = str(self.config.get("relay_host", "")).strip()
        relay_port_raw = self.config.get("relay_port_agent", 0)
        relay_port = 0
        try:
            relay_port = int(relay_port_raw)
        except Exception:
            relay_port = 0
        relay_cfg_ok = bool(relay_host) and 1 <= relay_port <= 65535
        add_check(
            "relay_config",
            relay_cfg_ok,
            reason="relay_host or relay_port_agent is invalid.",
            suggestion="Set relay_host and relay_port_agent (1-65535), save config, then restart Agent.",
        )
        if relay_cfg_ok:
            relay_ok, relay_error = await self._probe_tcp(relay_host, relay_port)
            add_check(
                "relay_reachable",
                relay_ok,
                reason=f"Cannot connect to Relay at {relay_host}:{relay_port}: {relay_error}",
                suggestion="Check Relay service status, firewall/network policy, and host:port correctness.",
            )

        relay_probe = self._agent_client_relay_probe_status()
        relay_probe_ok = bool(relay_probe.get("ok", False))
        relay_probe_reason = str(relay_probe.get("reason", ""))
        relay_probe_suggestion = (
            "Ensure Agent and Client are connected to the same Relay and control channel is stable."
            if not relay_probe_ok
            else ""
        )
        add_check(
            "agent_to_client_via_relay",
            relay_probe_ok,
            reason=relay_probe_reason,
            suggestion=relay_probe_suggestion,
        )
        add_check(
            "client_to_agent_via_relay",
            relay_probe_ok,
            reason=relay_probe_reason,
            suggestion=relay_probe_suggestion,
        )

        agent_private_raw = str(self.config.get("rsa_private_key", "")).strip()
        relay_public_raw = str(self.config.get("rsa_public_key", "")).strip()
        agent_public_raw = str(self.config.get("agent_public_key_path", "")).strip()
        agent_private_found = self._first_existing_path(agent_private_raw)
        relay_public_found = self._first_existing_path(relay_public_raw)
        agent_public_found = self._first_existing_path(agent_public_raw)
        agent_private_candidates = [str(p) for p in self._candidate_paths(agent_private_raw)]
        relay_public_candidates = [str(p) for p in self._candidate_paths(relay_public_raw)]
        agent_public_candidates = [str(p) for p in self._candidate_paths(agent_public_raw)]
        add_check(
            "agent_private_key",
            agent_private_found is not None,
            reason=f"Agent private key not found. Tried: {agent_private_candidates or [agent_private_raw]}",
            suggestion="Generate/import agent private key and update rsa_private_key path.",
        )
        add_check(
            "relay_public_key",
            relay_public_found is not None,
            reason=f"Relay public key not found. Tried: {relay_public_candidates or [relay_public_raw]}",
            suggestion="Copy Relay public key to this host and update rsa_public_key path.",
        )
        add_check(
            "agent_public_key",
            agent_public_found is not None,
            reason=f"Agent public key not found. Tried: {agent_public_candidates or [agent_public_raw]}",
            suggestion="Regenerate cert pair or correct agent_public_key_path.",
        )

        relay_trust = self._relay_trust_status()
        trust_ok = bool(relay_trust.get("relay_has_current_agent_key"))
        add_check(
            "relay_allows_agent_key",
            trust_ok,
            reason=str(relay_trust.get("details", "")) or "Relay trust check failed.",
            suggestion=str(relay_trust.get("suggestion", "")) or "Update relay allowed_agents and reload relay config.",
        )

        if bool(self.config.get("web_console_force_change", False)):
            add_check(
                "console_password_policy",
                False,
                level="warning",
                reason="Web console password is marked for mandatory change.",
                suggestion="Change console password to remove this warning.",
            )
        else:
            add_check("console_password_policy", True)

        errors = [c for c in checks if not c["ok"] and c.get("level") == "error"]
        warnings = [c for c in checks if not c["ok"] and c.get("level") == "warning"]
        return web.json_response(
            {
                "ok": len(errors) == 0,
                "agent_id": self.config.get("agent_id", "default"),
                "checked_at": time.time(),
                "issue_count": len(errors),
                "warning_count": len(warnings),
                "checks": checks,
                "agent_process": proc_status,
                "relay_trust": relay_trust,
            }
        )

    async def api_start(self, _: web.Request) -> web.Response:
        changed = await self.process.start()
        return web.json_response({"ok": True, "changed": changed, "agent_process": self.process.status()})

    async def api_stop(self, _: web.Request) -> web.Response:
        changed = await self.process.stop()
        return web.json_response({"ok": True, "changed": changed, "agent_process": self.process.status()})

    async def api_restart(self, _: web.Request) -> web.Response:
        await self.process.restart()
        return web.json_response({"ok": True, "agent_process": self.process.status()})

    async def api_config_get(self, _: web.Request) -> web.Response:
        return web.json_response(
            {
                "ok": True,
                "config": {
                    "agent_id": str(self.config.get("agent_id", "default")),
                    "relay_host": str(self.config.get("relay_host", "")),
                    "relay_port_agent": int(self.config.get("relay_port_agent", 8080)),
                    "heartbeat_interval": int(self.config.get("heartbeat_interval", 100)),
                    "auto_restart": bool(self.config.get("auto_restart", True)),
                    "log_level": str(self.config.get("log_level", "info")),
                },
            }
        )

    async def api_config_set(self, request: web.Request) -> web.Response:
        data = await request.json()
        cfg = data.get("config", {})
        if not isinstance(cfg, dict):
            return web.json_response({"ok": False, "error": "invalid_config_payload"}, status=400)

        relay_host = str(cfg.get("relay_host", "")).strip()
        if not relay_host:
            return web.json_response({"ok": False, "error": "relay_host_required"}, status=400)
        try:
            relay_port_agent = int(cfg.get("relay_port_agent", 0))
        except Exception:
            return web.json_response({"ok": False, "error": "invalid_relay_port_agent"}, status=400)
        if relay_port_agent < 1 or relay_port_agent > 65535:
            return web.json_response({"ok": False, "error": "invalid_relay_port_agent"}, status=400)
        try:
            heartbeat_interval = int(cfg.get("heartbeat_interval", 0))
        except Exception:
            return web.json_response({"ok": False, "error": "invalid_heartbeat_interval"}, status=400)
        if heartbeat_interval < 1:
            return web.json_response({"ok": False, "error": "invalid_heartbeat_interval"}, status=400)

        log_level = str(cfg.get("log_level", "info")).lower().strip()
        if log_level not in {"debug", "info", "warning", "error"}:
            return web.json_response({"ok": False, "error": "invalid_log_level"}, status=400)

        self.config["relay_host"] = relay_host
        self.config["relay_port_agent"] = relay_port_agent
        self.config["heartbeat_interval"] = heartbeat_interval
        self.config["auto_restart"] = bool(cfg.get("auto_restart", True))
        self.config["log_level"] = log_level
        save_yaml(self.config_path, self.config)
        return web.json_response(
            {
                "ok": True,
                "saved": {
                    "relay_host": relay_host,
                    "relay_port_agent": relay_port_agent,
                    "heartbeat_interval": heartbeat_interval,
                    "auto_restart": bool(self.config["auto_restart"]),
                    "log_level": log_level,
                },
                "restart_required": True,
            }
        )

    async def api_agent_name(self, request: web.Request) -> web.Response:
        data = await request.json()
        agent_id = str(data.get("agent_id", "")).strip()
        if not agent_id:
            return web.json_response({"ok": False, "error": "agent_id_required"}, status=400)
        self.config["agent_id"] = agent_id
        save_yaml(self.config_path, self.config)
        return web.json_response({"ok": True, "agent_id": agent_id, "restart_required": True})

    async def api_schedule(self, request: web.Request) -> web.Response:
        data = await request.json()
        action = str(data.get("action", "")).strip()
        mode = str(data.get("mode", "")).strip()
        if action not in {"connect", "disconnect"}:
            return web.json_response({"ok": False, "error": "invalid_action"}, status=400)
        if mode not in {"after", "at"}:
            return web.json_response({"ok": False, "error": "invalid_mode"}, status=400)

        run_at = 0.0
        if mode == "after":
            after_seconds = int(data.get("after_seconds", 0))
            if after_seconds <= 0:
                return web.json_response({"ok": False, "error": "after_seconds_required"}, status=400)
            run_at = time.time() + after_seconds
        else:
            at_time = str(data.get("at_time", "")).strip()
            try:
                hh, mm, ss = [int(x) for x in at_time.split(":", 2)]
            except Exception:
                return web.json_response({"ok": False, "error": "invalid_at_time"}, status=400)
            now = datetime.datetime.now()
            target = now.replace(hour=hh, minute=mm, second=ss, microsecond=0)
            if target <= now:
                target = target + datetime.timedelta(days=1)
            run_at = target.timestamp()

        job_id = secrets.token_hex(8)
        item = {
            "job_id": job_id,
            "action": action,
            "mode": mode,
            "run_at": run_at,
            "created_at": time.time(),
        }
        self.schedules[job_id] = item
        self.schedule_tasks[job_id] = asyncio.create_task(self._run_schedule(job_id), name=f"agent-schedule-{job_id}")
        self._persist_schedules()
        return web.json_response({"ok": True, "schedule": item})

    async def _run_schedule(self, job_id: str) -> None:
        item = self.schedules.get(job_id)
        if not item:
            return
        delay = max(0.0, float(item["run_at"]) - time.time())
        try:
            await asyncio.sleep(delay)
            action = str(item.get("action"))
            if action == "connect":
                await self.process.start()
            elif action == "disconnect":
                await self.process.stop()
        finally:
            if self._stopping:
                return
            self.schedules.pop(job_id, None)
            self.schedule_tasks.pop(job_id, None)
            self._persist_schedules()

    async def api_schedule_list(self, _: web.Request) -> web.Response:
        return web.json_response({"ok": True, "schedules": list(self.schedules.values())})

    async def api_schedule_delete(self, request: web.Request) -> web.Response:
        job_id = request.match_info["job_id"]
        self.schedules.pop(job_id, None)
        task = self.schedule_tasks.pop(job_id, None)
        if task:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
        self._persist_schedules()
        return web.json_response({"ok": True})

    def _relay_trust_status(self) -> dict[str, Any]:
        public_path_raw = self._normalize_config_path(str(self.config.get("agent_public_key_path", "certs/agent_public.pem")))
        public_path = Path(public_path_raw)
        relay_cfg_path_raw = self._normalize_config_path(str(self.config.get("relay_config_path", "")))
        status: dict[str, Any] = {
            "public_key_path": str(public_path),
            "relay_config_path": relay_cfg_path_raw,
            "relay_checked": False,
            "relay_has_current_agent_key": False,
            "details": "",
            "suggestion": "",
        }
        if not public_path.exists():
            status["details"] = "agent public key file not found"
            status["suggestion"] = "regenerate cert pair or set agent_public_key_path correctly"
            return status
        try:
            agent_pub = load_public_key(str(public_path))
            agent_fp = pubkey_fingerprint(agent_pub)
        except Exception as exc:
            status["details"] = f"failed to parse agent public key: {exc}"
            return status
        status["agent_public_fingerprint"] = f"SHA256:{agent_fp}"
        relay_cfg_path: Path | None = None
        if relay_cfg_path_raw:
            relay_cfg_path = Path(relay_cfg_path_raw)
        else:
            cfg_dir = Path(self.config_path).resolve().parent
            for name in ("relay.yaml", "relay.yaml2", "relay.yaml3"):
                cand = cfg_dir / name
                if cand.exists():
                    relay_cfg_path = cand
                    status["relay_config_path"] = str(cand)
                    status["details"] = f"relay_config_path auto-detected: {cand}"
                    break
        if relay_cfg_path is None:
            status["details"] = "relay_config_path is not set in agent config"
            status["suggestion"] = "set relay_config_path then re-check, or update relay allowed_agents manually"
            return status
        if not relay_cfg_path.exists():
            status["details"] = "relay config file not found at relay_config_path"
            status["suggestion"] = "fix relay_config_path or update relay allowed_agents manually"
            return status
        try:
            relay_cfg = load_yaml(str(relay_cfg_path))
            allowed = relay_cfg.get("allowed_agents", [])
            if not isinstance(allowed, list):
                allowed = []
            matched = False
            normalized_allowed: list[str] = []
            for item in allowed:
                val = self._normalize_config_path(str(item))
                normalized_allowed.append(val)
                if not val:
                    continue
                if val.replace("SHA256:", "").strip() == agent_fp:
                    matched = True
                    continue
                p = Path(val)
                if p.exists():
                    try:
                        fp = pubkey_fingerprint(load_public_key(str(p)))
                        if fp == agent_fp:
                            matched = True
                    except Exception:
                        pass
            status["relay_checked"] = True
            status["relay_has_current_agent_key"] = matched
            status["relay_allowed_agents"] = normalized_allowed
            if matched:
                status["details"] = "relay allowed_agents already contains current agent key"
                status["suggestion"] = "restart relay to reload config if it is already running"
            else:
                status["details"] = "relay allowed_agents does not include current agent key"
                status["suggestion"] = (
                    "add current agent public key path or fingerprint to relay allowed_agents, then restart relay"
                )
        except Exception as exc:
            status["details"] = f"failed to read relay config: {exc}"
            status["suggestion"] = "update relay allowed_agents manually"
        return status

    def _agent_client_relay_probe_status(self) -> dict[str, Any]:
        probe_path = Path(self.config_path).with_suffix(".relay_probe.json")
        status: dict[str, Any] = {
            "ok": False,
            "checked_at": 0.0,
            "reason": "relay probe data not found",
            "probe_path": str(probe_path),
        }
        if not probe_path.exists():
            return status
        try:
            raw = json.loads(probe_path.read_text(encoding="utf-8"))
            checked_at = float(raw.get("checked_at", 0.0))
            # Treat stale result as failed to avoid false-green when agent process is stuck.
            max_age = max(10, int(self.config.get("relay_probe_interval", 20)) * 3)
            age = time.time() - checked_at if checked_at > 0 else 10**9
            ok = bool(raw.get("ok", False)) and age <= max_age
            reason = str(raw.get("reason", ""))
            if age > max_age:
                reason = f"relay probe stale ({int(age)}s old)"
            return {
                "ok": ok,
                "checked_at": checked_at,
                "reason": reason,
                "request_id": str(raw.get("request_id", "")),
                "client_connected": bool(raw.get("client_connected", False)),
                "probe_path": str(probe_path),
            }
        except Exception as exc:
            status["reason"] = f"invalid relay probe data: {exc}"
            return status

    async def api_certs_regenerate(self, _: web.Request) -> web.Response:
        private_path = Path(self._normalize_config_path(str(self.config.get("rsa_private_key", "certs/agent_private.pem"))))
        public_path = Path(
            self._normalize_config_path(str(self.config.get("agent_public_key_path", private_path.with_name("agent_public.pem"))))
        )
        private_path.parent.mkdir(parents=True, exist_ok=True)
        public_path.parent.mkdir(parents=True, exist_ok=True)

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        private_path.write_bytes(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        public_path.write_bytes(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        self.config["agent_public_key_path"] = str(public_path)
        save_yaml(self.config_path, self.config)
        relay_trust = self._relay_trust_status()
        return web.json_response(
            {
                "ok": True,
                "public_key_path": str(public_path),
                "restart_required": True,
                "message": "new cert pair generated; restart Agent to apply",
                "relay_trust": relay_trust,
            }
        )

    async def api_certs_public_link(self, request: web.Request) -> web.Response:
        public_path = Path(self._normalize_config_path(str(self.config.get("agent_public_key_path", "certs/agent_public.pem"))))
        if not public_path.exists():
            return web.json_response({"ok": False, "error": "public_key_not_found"}, status=404)
        token = secrets.token_urlsafe(18)
        self.public_key_tokens[token] = {"path": str(public_path.resolve()), "exp": time.time() + 300}
        base = f"{request.scheme}://{request.host}"
        return web.json_response({"ok": True, "url": f"{base}/download/pub/{token}", "expires_in": 300})

    async def api_certs_relay_check(self, _: web.Request) -> web.Response:
        return web.json_response({"ok": True, "relay_trust": self._relay_trust_status()})

    async def api_relay_config_path(self, request: web.Request) -> web.Response:
        data = await request.json()
        relay_cfg = str(data.get("relay_config_path", "")).strip()
        self.config["relay_config_path"] = relay_cfg
        save_yaml(self.config_path, self.config)
        return web.json_response({"ok": True, "relay_config_path": relay_cfg, "relay_trust": self._relay_trust_status()})

    async def api_download_public(self, request: web.Request) -> web.Response:
        token = request.match_info["token"]
        item = self.public_key_tokens.get(token)
        if not item or float(item.get("exp", 0)) < time.time():
            self.public_key_tokens.pop(token, None)
            raise web.HTTPNotFound()
        path = Path(str(item.get("path", "")))
        if not path.exists():
            self.public_key_tokens.pop(token, None)
            raise web.HTTPNotFound()
        return web.FileResponse(
            path,
            headers={"Content-Disposition": f'attachment; filename="{path.name}"'},
        )

    async def api_password(self, request: web.Request) -> web.Response:
        if self.config.get("web_console_password_hash"):
            token = request.cookies.get("triproxy_session", "")
            session = self.sessions.get(token)
            exp = float(session.get("exp", 0)) if session else 0.0
            if exp < time.time():
                return web.json_response({"ok": False, "error": "unauthorized"}, status=401)
        data = await request.json()
        new_hash = str(data.get("new_password_hash", ""))
        if len(new_hash) != 64:
            return web.json_response({"ok": False, "error": "invalid_hash"}, status=400)
        self.config["web_console_password_hash"] = new_hash
        self.config["web_console_force_change"] = False
        save_yaml(self.config_path, self.config)
        token = request.cookies.get("triproxy_session", "")
        if token in self.sessions:
            self.sessions[token]["force_change_password"] = False
        return web.json_response({"ok": True})

    async def api_logout(self, request: web.Request) -> web.Response:
        token = request.cookies.get("triproxy_session", "")
        self.sessions.pop(token, None)
        resp = web.json_response({"ok": True})
        resp.del_cookie("triproxy_session")
        return resp

    async def api_terminal_new(self, _: web.Request) -> dict[str, str]:
        session_id = await self.local_shell.create_session()
        return {"session_id": session_id}

    async def ws_terminal(self, session_id: str, ws: web.WebSocketResponse, _: web.Request) -> None:
        await self.local_shell.attach_terminal_ws(session_id, ws)

    async def start(self) -> None:
        bind = self.config.get("web_console_bind", "127.0.0.1")
        port = int(self.config.get("web_console_port", 3002))
        self.runner = web.AppRunner(self.app)
        await self.runner.setup()
        self.site = web.TCPSite(self.runner, bind, port)
        await self.site.start()
        await self.process.start()

    async def stop(self) -> None:
        if self._stopping:
            return
        self._stopping = True
        for task in list(self.schedule_tasks.values()):
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
        self.schedule_tasks = {}
        # Keep scheduled jobs in config so daemon restart can restore them.
        with contextlib.suppress(asyncio.TimeoutError, Exception):
            await asyncio.wait_for(self.process.close(), timeout=10.0)
        with contextlib.suppress(asyncio.TimeoutError, Exception):
            await asyncio.wait_for(self.local_shell.close(), timeout=3.0)
        if self.runner:
            with contextlib.suppress(asyncio.TimeoutError, Exception):
                await asyncio.wait_for(self.runner.cleanup(), timeout=5.0)
            self.runner = None
            self.site = None


def _install_signal_handlers(app: AgentWebDaemon) -> None:
    loop = asyncio.get_running_loop()
    force_exit_seconds = float(app.config.get("shutdown_force_exit_seconds", 6.0))
    force_exit_handle: asyncio.TimerHandle | None = None

    async def _shutdown() -> None:
        nonlocal force_exit_handle
        try:
            await app.stop()
        finally:
            if force_exit_handle is not None:
                force_exit_handle.cancel()
                force_exit_handle = None
            app.stop_event.set()

    def _force_exit() -> None:
        if app.stop_event.is_set():
            return
        app.logger.error("shutdown did not finish in %.1fs, forcing process exit", force_exit_seconds)
        os._exit(130)

    def _trigger_shutdown() -> None:
        nonlocal force_exit_handle
        if app._shutdown_task and not app._shutdown_task.done():
            return
        if force_exit_seconds > 0:
            force_exit_handle = loop.call_later(force_exit_seconds, _force_exit)
        app._shutdown_task = asyncio.create_task(_shutdown(), name="agent-web-daemon-shutdown")

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _trigger_shutdown)
        except NotImplementedError:
            signal.signal(sig, lambda *_: _trigger_shutdown())


async def _amain(config_path: str) -> None:
    cfg = load_yaml(config_path)
    setup_logging(cfg.get("log_level", "info"))
    app = AgentWebDaemon(cfg, config_path)
    await app.start()
    _install_signal_handlers(app)
    await app.stop_event.wait()


def _run_with_bounded_executor_shutdown(config_path: str) -> None:
    # asyncio.run() waits indefinitely for default executor threads during shutdown.
    # ConPTY read workers may stay blocked on Windows and delay process exit.
    # Use an explicit event loop with bounded executor shutdown timeout.
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(_amain(config_path))
    finally:
        with contextlib.suppress(Exception):
            loop.run_until_complete(loop.shutdown_asyncgens())
        asyncio.set_event_loop(None)
        loop.close()
        if sys.platform == "win32":
            # Python 3.13 may still block on executor/thread cleanup when ConPTY
            # worker threads are in blocking reads. Force a deterministic process
            # exit after loop cleanup to avoid Ctrl+C hang.
            os._exit(0)


def main() -> None:
    parser = argparse.ArgumentParser(description="TriProxy Agent Web Daemon")
    parser.add_argument("config", help="path to agent yaml config")
    args = parser.parse_args()
    _run_with_bounded_executor_shutdown(args.config)


if __name__ == "__main__":
    main()
