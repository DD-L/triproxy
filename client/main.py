from __future__ import annotations

import argparse
import asyncio
import contextlib
import re
import signal
import time
import uuid
from pathlib import Path
from typing import Any

from aiohttp import web

from client.control import ClientControlConnection
from client.directed import DirectedProxyManager
from client.general import GeneralProxyServer
from client.pool import ClientPoolManager
from client.session import ClientSessionManager
from client.shell_client import ShellClient
from client.web.app import create_web_app
from common.config import load_yaml, require_keys, save_yaml
from common.log import setup_logging
from common.protocol import MsgType


class AgentPasswordChangeError(RuntimeError):
    pass


class AgentRuntime:
    def __init__(self, shared_config: dict[str, Any], config_path: str, agent_cfg: dict[str, Any]):
        self.shared_config = shared_config
        self.config_path = config_path
        self.agent_id = str(agent_cfg.get("agent_id", "default"))
        self.services = agent_cfg.setdefault("services", {})
        self.started_at = time.time()

        self.pool_manager = ClientPoolManager(
            shared_config["relay_host"],
            int(shared_config["relay_port_client"]),
            heartbeat_interval=int(shared_config.get("heartbeat_interval", 25)),
            dead_timeout=int(shared_config.get("pool_dead_timeout", shared_config.get("dead_timeout", 120))),
        )
        self.session_manager = ClientSessionManager(self.pool_manager, self._send_control)
        self.directed_manager = DirectedProxyManager(self.session_manager, agent_id=self.agent_id)
        general_cfg = self.services.get("general", {})
        self.general_proxy = GeneralProxyServer(
            self.session_manager,
            bind=general_cfg.get("bind", "127.0.0.1"),
            port=int(general_cfg.get("local_port", 3000)),
            agent_id=self.agent_id,
        )

        self.control: ClientControlConnection | None = None
        self._control_task: asyncio.Task[Any] | None = None
        self._pwd_change_waiters: list[asyncio.Future[dict[str, Any]]] = []
        self._agent_restart_waiters: list[asyncio.Future[dict[str, Any]]] = []
        self._relay_reload_waiters: list[asyncio.Future[dict[str, Any]]] = []
        self._agent_status_waiters: dict[str, asyncio.Future[dict[str, Any]]] = {}

    def _build_control_config(self) -> dict[str, Any]:
        return {
            "relay_host": self.shared_config["relay_host"],
            "relay_port_client": self.shared_config["relay_port_client"],
            "rsa_private_key": self.shared_config["rsa_private_key"],
            "rsa_public_key": self.shared_config["rsa_public_key"],
            "auth_key": self.shared_config.get("auth_key", ""),
            "heartbeat_interval": self.shared_config.get("heartbeat_interval", 25),
            "control_dead_timeout": self.shared_config.get("control_dead_timeout", self.shared_config.get("dead_timeout", 120)),
            "dead_timeout": self.shared_config.get("dead_timeout", 120),
            "agent_id": self.agent_id,
        }

    async def _send_control(self, msg_type: str, **fields: Any) -> None:
        if self.control:
            await self.control.send(msg_type, **fields)

    async def on_control_message(self, msg: dict[str, Any]) -> None:
        msg_type = msg.get("type")
        if msg_type == MsgType.POOL_ALLOC.value:
            tokens = [str(t) for t in msg.get("tokens", [])]
            if self.control and self.control.ctrl_key:
                await self.pool_manager.put_tokens(tokens, self.control.ctrl_key)
                for token in tokens:
                    await self._send_control(MsgType.POOL_READY.value, pool_token=token)
            return
        if msg_type == MsgType.POOL_SHRINK.value:
            token = str(msg.get("pool_token", ""))
            if token:
                await self.pool_manager.remove(token)
            return
        if msg_type in (
            MsgType.SESSION_ASSIGN.value,
            MsgType.SESSION_FAIL.value,
            MsgType.SESSION_CLOSE.value,
        ):
            await self.session_manager.on_control_message(msg)
            return
        if msg_type == MsgType.AGENT_PWD_CHANGED.value:
            result = {"ok": bool(msg.get("ok", True)), "reason": str(msg.get("reason", ""))}
            waiters = list(self._pwd_change_waiters)
            self._pwd_change_waiters.clear()
            for fut in waiters:
                if not fut.done():
                    fut.set_result(result)
            return
        if msg_type == MsgType.AGENT_RESTART_RESP.value:
            result = {"ok": bool(msg.get("ok", True)), "reason": str(msg.get("reason", ""))}
            waiters = list(self._agent_restart_waiters)
            self._agent_restart_waiters.clear()
            for fut in waiters:
                if not fut.done():
                    fut.set_result(result)
            return
        if msg_type == MsgType.AGENT_STATUS_RESP.value:
            result = {
                "connected": bool(msg.get("connected", False)),
                "pool_size": int(msg.get("pool_size", 0)),
                "active_sessions": int(msg.get("active_sessions", 0)),
                "uptime": float(msg.get("uptime", 0.0)),
                "request_id": str(msg.get("request_id", "")).strip(),
                "pool_probe": msg.get("pool_probe", {}),
                "relay_probe": msg.get("relay_probe", {}),
            }
            req_id = result["request_id"]
            fut = self._agent_status_waiters.pop(req_id, None) if req_id else None
            if fut and not fut.done():
                fut.set_result(result)
            return
        if msg_type == MsgType.CLIENT_STATUS_REQ.value:
            payload: dict[str, Any] = {"connected": self.control is not None and self.control.ctrl_key is not None}
            request_id = str(msg.get("request_id", "")).strip()
            if request_id:
                payload["request_id"] = request_id
            await self._send_control(MsgType.CLIENT_STATUS_RESP.value, **payload)
            return
        if msg_type == MsgType.RELAY_RESTART_RESP.value:
            result = {"ok": bool(msg.get("ok", True)), "reason": str(msg.get("reason", ""))}
            waiters = list(self._relay_reload_waiters)
            self._relay_reload_waiters.clear()
            for fut in waiters:
                if not fut.done():
                    fut.set_result(result)
            return
        if msg_type == MsgType.RELAY_CERT_RELOAD_RESP.value:
            result = {"ok": bool(msg.get("ok", True)), "reason": str(msg.get("reason", ""))}
            waiters = list(self._relay_reload_waiters)
            self._relay_reload_waiters.clear()
            for fut in waiters:
                if not fut.done():
                    fut.set_result(result)

    async def on_connected(self, _: bytes) -> None:
        pass

    async def on_disconnected(self) -> None:
        await self.pool_manager.close_all()
        waiters = list(self._pwd_change_waiters)
        self._pwd_change_waiters.clear()
        restart_waiters = list(self._agent_restart_waiters)
        self._agent_restart_waiters.clear()
        status_waiters = list(self._agent_status_waiters.values())
        self._agent_status_waiters.clear()
        relay_waiters = list(self._relay_reload_waiters)
        self._relay_reload_waiters.clear()
        for fut in waiters:
            if not fut.done():
                fut.set_result({"ok": False, "reason": "control_disconnected"})
        for fut in restart_waiters:
            if not fut.done():
                fut.set_result({"ok": False, "reason": "control_disconnected"})
        for fut in status_waiters:
            if not fut.done():
                fut.set_result({"connected": False, "pool_size": 0, "active_sessions": 0, "uptime": 0.0})
        for fut in relay_waiters:
            if not fut.done():
                fut.set_result({"ok": False, "reason": "control_disconnected"})

    async def start_control_loop(self) -> None:
        self.control = ClientControlConnection(
            self._build_control_config(),
            on_message=self.on_control_message,
            on_connected=self.on_connected,
            on_disconnected=self.on_disconnected,
        )
        self._control_task = asyncio.create_task(self.control.run(), name=f"client-control-loop-{self.agent_id}")

    async def start_services(self) -> None:
        directed_rules = self.services.get("directed", [])
        await self.directed_manager.load_rules(directed_rules)
        if self.services.get("general", {}).get("enabled", True):
            await self.general_proxy.start()

    async def start(self) -> None:
        await self.start_control_loop()
        await self.start_services()

    async def shutdown(self) -> None:
        if self.control:
            await self.control.stop()
        if self._control_task:
            self._control_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._control_task
        await self.general_proxy.stop()
        await self.pool_manager.close_all()

    async def status(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "connected": self.control is not None and self.control.ctrl_key is not None,
            "pool_size": await self.pool_manager.size(),
            "active_sessions": len(self.session_manager.active),
            "uptime": time.time() - self.started_at,
        }

    def services_view(self) -> dict[str, Any]:
        general_cfg = dict(self.services.get("general", {}))
        if "bind" not in general_cfg:
            general_cfg["bind"] = "127.0.0.1"
        if "local_port" not in general_cfg:
            general_cfg["local_port"] = 3000
        return {
            "directed": [
                {
                    "id": r.rule_id,
                    "local_port": r.local_port,
                    "target_url": r.target_url,
                    "enabled": r.enabled,
                }
                for r in self.directed_manager.rules.values()
            ],
            "general": general_cfg,
            "shell": self.services.get("shell", {}),
        }

    async def change_agent_password(self, new_password_hash: str) -> None:
        waiter = asyncio.get_running_loop().create_future()
        self._pwd_change_waiters.append(waiter)
        await self._send_control(MsgType.AGENT_PWD_CHANGE.value, new_password_hash=new_password_hash)
        try:
            result = await asyncio.wait_for(waiter, timeout=15.0)
        except asyncio.TimeoutError as exc:
            raise AgentPasswordChangeError("agent password change timeout") from exc
        finally:
            if waiter in self._pwd_change_waiters:
                self._pwd_change_waiters.remove(waiter)
        if not result.get("ok", False):
            reason = str(result.get("reason", "unknown"))
            raise AgentPasswordChangeError(f"agent password change failed: {reason}")

    async def restart_agent(self) -> None:
        waiter = asyncio.get_running_loop().create_future()
        self._agent_restart_waiters.append(waiter)
        await self._send_control(MsgType.AGENT_RESTART_REQ.value)
        try:
            result = await asyncio.wait_for(waiter, timeout=15.0)
        except asyncio.TimeoutError as exc:
            raise RuntimeError("agent restart timeout") from exc
        finally:
            if waiter in self._agent_restart_waiters:
                self._agent_restart_waiters.remove(waiter)
        if not result.get("ok", False):
            reason = str(result.get("reason", "unknown"))
            raise RuntimeError(f"agent restart failed: {reason}")

    async def reload_relay_certs(self) -> None:
        waiter = asyncio.get_running_loop().create_future()
        self._relay_reload_waiters.append(waiter)
        await self._send_control(MsgType.RELAY_CERT_RELOAD_REQ.value)
        try:
            result = await asyncio.wait_for(waiter, timeout=15.0)
        except asyncio.TimeoutError as exc:
            raise RuntimeError("relay cert reload timeout") from exc
        finally:
            if waiter in self._relay_reload_waiters:
                self._relay_reload_waiters.remove(waiter)
        if not result.get("ok", False):
            reason = str(result.get("reason", "unknown"))
            raise RuntimeError(f"relay cert reload failed: {reason}")

    async def request_agent_status(self, timeout: float = 5.0) -> dict[str, Any]:
        request_id = uuid.uuid4().hex
        waiter = asyncio.get_running_loop().create_future()
        self._agent_status_waiters[request_id] = waiter
        await self._send_control(MsgType.AGENT_STATUS_REQ.value, request_id=request_id)
        try:
            result = await asyncio.wait_for(waiter, timeout=timeout)
        except asyncio.TimeoutError as exc:
            raise RuntimeError("agent status relay probe timeout") from exc
        finally:
            self._agent_status_waiters.pop(request_id, None)
        if str(result.get("request_id", "")).strip() != request_id:
            raise RuntimeError("agent status relay probe mismatched response")
        return result


class ClientApp:
    def __init__(self, config: dict[str, Any], config_path: str):
        self.config = config
        self.config_path = config_path
        self.started_at = time.time()
        self.shell_client = ShellClient()

        self.runtimes: dict[str, AgentRuntime] = {}
        self.primary_agent_id = ""
        self.current_agent_id = ""
        self.web_app = create_web_app(self)
        self.web_runner: web.AppRunner | None = None
        self.web_site: web.TCPSite | None = None
        self.shell_sessions: dict[str, dict[str, Any]] = {}

        agent_items = self._build_agent_items()
        for item in agent_items:
            runtime = AgentRuntime(self.config, config_path, item)
            self.runtimes[runtime.agent_id] = runtime
        self.primary_agent_id = agent_items[0]["agent_id"]
        self.current_agent_id = self.primary_agent_id

    def _build_agent_items(self) -> list[dict[str, Any]]:
        raw = self.config.get("agents")
        items: list[dict[str, Any]] = []
        if isinstance(raw, list) and raw:
            for it in raw:
                if not isinstance(it, dict):
                    continue
                aid = str(it.get("agent_id", "")).strip()
                if not aid:
                    continue
                services = it.get("services", {})
                if not isinstance(services, dict):
                    services = {}
                items.append({"agent_id": aid, "services": services})
        if items:
            return items
        # backward compatibility: old single-agent config
        aid = str(self.config.get("agent_id", "default"))
        services = self.config.get("services", {})
        if not isinstance(services, dict):
            services = {}
        self.config["agents"] = [{"agent_id": aid, "services": services}]
        save_yaml(self.config_path, self.config)
        return self.config["agents"]

    def _pick_agent_id(self, preferred: str | None = None) -> str:
        if preferred and preferred in self.runtimes:
            return preferred
        if self.current_agent_id in self.runtimes:
            return self.current_agent_id
        return self.primary_agent_id

    def _config_agent_entry(self, agent_id: str) -> dict[str, Any]:
        agents = self.config.setdefault("agents", [])
        for item in agents:
            if str(item.get("agent_id")) == agent_id:
                return item
        created = {"agent_id": agent_id, "services": {"directed": [], "general": {}, "shell": {}}}
        agents.append(created)
        return created

    async def start_web(self) -> None:
        if self.web_runner is not None:
            return
        primary = self.runtimes[self.primary_agent_id]
        port = int(primary.services.get("shell", {}).get("local_port", 3001))
        self.web_runner = web.AppRunner(self.web_app)
        await self.web_runner.setup()
        self.web_site = web.TCPSite(self.web_runner, "127.0.0.1", port)
        await self.web_site.start()

    async def stop_web(self) -> None:
        if self.web_runner:
            await self.web_runner.cleanup()
            self.web_runner = None
            self.web_site = None

    async def _close_shell_sessions(self) -> None:
        for sid, ctx in list(self.shell_sessions.items()):
            runtime: AgentRuntime = ctx["runtime"]
            with contextlib.suppress(Exception):
                await runtime.pool_manager.put_back(ctx["pool_token"], ctx["pool_conn"])
            with contextlib.suppress(Exception):
                await runtime.session_manager.close_session(sid)
            self.shell_sessions.pop(sid, None)

    async def start(self) -> None:
        for runtime in self.runtimes.values():
            await runtime.start()
        await self.start_web()
        tasks = [rt._control_task for rt in self.runtimes.values() if rt._control_task]
        if tasks:
            await asyncio.gather(*tasks)

    async def shutdown(self) -> None:
        await self._close_shell_sessions()
        await self.stop_web()
        for runtime in self.runtimes.values():
            await runtime.shutdown()

    async def list_agents(self) -> dict[str, Any]:
        statuses = [await rt.status() for rt in self.runtimes.values()]
        return {
            "agents": statuses,
            "current_agent_id": self.current_agent_id,
            "primary_agent_id": self.primary_agent_id,
        }

    async def set_current_agent(self, agent_id: str) -> dict[str, Any]:
        if agent_id not in self.runtimes:
            raise ValueError("unknown agent_id")
        self.current_agent_id = agent_id
        return {"ok": True, "current_agent_id": self.current_agent_id}

    async def get_status(self, agent_id: str | None = None) -> dict[str, Any]:
        aid = self._pick_agent_id(agent_id)
        st = await self.runtimes[aid].status()
        return {
            "agent_id": aid,
            "connected": st["connected"],
            "pool_size": st["pool_size"],
            "active_sessions": st["active_sessions"],
            "uptime": time.time() - self.started_at,
        }

    async def get_services(self, agent_id: str | None = None) -> dict[str, Any]:
        aid = self._pick_agent_id(agent_id)
        return self.runtimes[aid].services_view()

    def _candidate_paths(self, value: str) -> list[Path]:
        raw = value.strip()
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

    async def self_check(self, agent_id: str | None = None) -> dict[str, Any]:
        aid = self._pick_agent_id(agent_id)
        runtime = self.runtimes[aid]
        st = await runtime.status()
        services = runtime.services_view()
        checks: list[dict[str, Any]] = []

        def add_check(
            name: str,
            ok: bool,
            *,
            reason: str = "",
            suggestion: str = "",
            level: str = "error",
            skipped: bool | None = None,
            latency_ms: int | None = None,
        ) -> None:
            item: dict[str, Any] = {
                "name": name,
                "ok": ok,
                "level": "info" if ok else level,
                "reason": reason,
                "suggestion": suggestion,
            }
            if skipped is not None:
                item["skipped"] = bool(skipped)
            if latency_ms is not None:
                item["latency_ms"] = int(latency_ms)
            checks.append(item)

        add_check(
            "control_connection",
            bool(st["connected"]),
            reason="Client has not established control channel to selected Agent.",
            suggestion="Start Agent process and verify relay_host/relay_port settings on both Agent and Relay.",
        )

        relay_host = str(self.config.get("relay_host", "")).strip()
        relay_port_raw = self.config.get("relay_port_client", 0)
        relay_port = 0
        try:
            relay_port = int(relay_port_raw)
        except Exception:
            relay_port = 0
        relay_cfg_ok = bool(relay_host) and 1 <= relay_port <= 65535
        add_check(
            "relay_config",
            relay_cfg_ok,
            reason="relay_host or relay_port_client is invalid.",
            suggestion="Set a valid relay_host and relay_port_client (1-65535), then restart Client.",
        )

        if relay_cfg_ok:
            relay_ok, relay_error = await self._probe_tcp(relay_host, relay_port)
            add_check(
                "relay_reachable",
                relay_ok,
                reason=f"Cannot connect to Relay at {relay_host}:{relay_port}: {relay_error}",
                suggestion="Check Relay process status, firewall rules, and network route; then retry.",
            )

        client_to_agent_ok = False
        agent_to_client_ok = False
        client_to_agent_reason = ""
        agent_to_client_reason = ""
        via_relay_suggestion = ""
        try:
            agent_status = await runtime.request_agent_status(timeout=5.0)
            client_to_agent_ok = True
            agent_to_client_ok = bool(agent_status.get("connected", False))
            if not agent_to_client_ok:
                agent_to_client_reason = "Relay round-trip succeeded, but Agent reports control channel is not connected."
                via_relay_suggestion = "Start Agent and ensure both Agent and Client stay connected to Relay."
        except Exception as exc:
            client_to_agent_ok = False
            agent_to_client_ok = False
            client_to_agent_reason = f"Relay probe failed to reach Agent status endpoint: {exc}"
            agent_to_client_reason = f"Relay probe failed to return Agent status response: {exc}"
            via_relay_suggestion = "Check Relay health, certificates/auth, and control-channel stability."

        add_check(
            "client_to_agent_via_relay",
            client_to_agent_ok,
            reason=client_to_agent_reason,
            suggestion=via_relay_suggestion,
        )
        add_check(
            "agent_to_client_via_relay",
            agent_to_client_ok,
            reason=agent_to_client_reason,
            suggestion=via_relay_suggestion,
        )

        if agent_to_client_ok:
            agent_pool_probe = agent_status.get("pool_probe", {}) if isinstance(agent_status, dict) else {}
            pool_probe_ok = bool(agent_pool_probe.get("ok", False))
            pool_probe_skipped = bool(agent_pool_probe.get("skipped", True))
            pool_probe_reason = str(agent_pool_probe.get("reason", "") or "agent pool probe unavailable")
            if pool_probe_skipped:
                add_check(
                    "agent_pool_side_effect_probe",
                    False,
                    level="warning",
                    reason=f"Agent active pool probe skipped: {pool_probe_reason}",
                    suggestion="Keep Client online and rerun self-check to validate agent pool data path.",
                    skipped=True,
                    latency_ms=agent_pool_probe.get("latency_ms"),
                )
            else:
                add_check(
                    "agent_pool_side_effect_probe",
                    pool_probe_ok,
                    reason="" if pool_probe_ok else f"Agent active pool probe failed: {pool_probe_reason}",
                    suggestion="" if pool_probe_ok else "Check relay pool channel health and agent pool heartbeat behavior.",
                    skipped=False,
                    latency_ms=agent_pool_probe.get("latency_ms"),
                )
        else:
            add_check(
                "agent_pool_side_effect_probe",
                False,
                level="warning",
                reason="Skipped because agent_to_client_via_relay is not healthy.",
                suggestion="Recover control channel first, then rerun self-check.",
                skipped=True,
            )

        if bool(st["connected"]) and agent_to_client_ok:
            client_probe = await runtime.pool_manager.probe_one(
                timeout=float(self.config.get("client_self_check_pool_probe_timeout", 2.5))
            )
            probe_ok = bool(client_probe.get("ok", False))
            probe_reason = str(client_probe.get("reason", ""))
            probe_level = "error"
            probe_suggestion = "Check relay pool port reachability and client pool heartbeat stability."
            if (not probe_ok) and probe_reason == "no_pool_connection_available":
                # Idle pool can be temporarily empty after reconnect/shrink while no active sessions.
                # Treat as warning to avoid false-red self-check in a healthy-but-idle state.
                if int(st.get("active_sessions", 0)) == 0:
                    probe_level = "warning"
                    probe_suggestion = (
                        "Pool is temporarily empty in idle state. Retry self-check after a short wait or open a session."
                    )
            add_check(
                "client_pool_side_effect_probe",
                probe_ok,
                reason="" if probe_ok else f"Client pool probe failed: {probe_reason}",
                suggestion="" if probe_ok else probe_suggestion,
                level=probe_level,
                skipped=False,
                latency_ms=client_probe.get("latency_ms"),
            )
        else:
            add_check(
                "client_pool_side_effect_probe",
                False,
                level="warning",
                reason="Skipped because client control or relay round-trip is not healthy.",
                suggestion="Recover control/relay connectivity first, then rerun self-check.",
                skipped=True,
            )

        private_key_raw = str(self.config.get("rsa_private_key", "")).strip()
        relay_public_raw = str(self.config.get("rsa_public_key", "")).strip()
        private_key_found = self._first_existing_path(private_key_raw)
        relay_public_found = self._first_existing_path(relay_public_raw)
        private_candidates = [str(p) for p in self._candidate_paths(private_key_raw)]
        relay_candidates = [str(p) for p in self._candidate_paths(relay_public_raw)]
        add_check(
            "client_private_key",
            private_key_found is not None,
            reason=f"Client private key not found. Tried: {private_candidates or [private_key_raw]}",
            suggestion="Generate/import the private key and update rsa_private_key in config.",
        )
        add_check(
            "relay_public_key",
            relay_public_found is not None,
            reason=f"Relay public key not found. Tried: {relay_candidates or [relay_public_raw]}",
            suggestion="Put relay public key on this host and set rsa_public_key to the correct path.",
        )

        general_cfg = services.get("general", {}) if isinstance(services.get("general"), dict) else {}
        general_enabled = bool(general_cfg.get("enabled", True))
        general_running = runtime.general_proxy.server is not None
        if general_enabled:
            add_check(
                "general_proxy",
                general_running,
                reason="General proxy is enabled in config but server is not running.",
                suggestion="Toggle General Proxy in dashboard or restart Client process.",
            )
        else:
            add_check(
                "general_proxy",
                False,
                level="warning",
                reason="General proxy is disabled.",
                suggestion="Enable General Proxy if you need SOCKS/HTTP proxy on local port.",
            )

        directed_rules = services.get("directed", []) if isinstance(services.get("directed"), list) else []
        port_owner: dict[int, str] = {}
        conflict_ports: set[int] = set()

        if general_enabled:
            try:
                gport = int(general_cfg.get("local_port", 3000))
            except Exception:
                gport = 0
            if 1 <= gport <= 65535:
                port_owner[gport] = "general"
            else:
                add_check(
                    "general_proxy_port",
                    False,
                    reason=f"General proxy local_port is invalid: {general_cfg.get('local_port')}",
                    suggestion="Set general.local_port to a valid integer in range 1-65535.",
                )

        for item in directed_rules:
            if not isinstance(item, dict) or not bool(item.get("enabled", True)):
                continue
            rid = str(item.get("id", "unnamed"))
            target_url = str(item.get("target_url", "")).strip()
            try:
                local_port = int(item.get("local_port", 0))
            except Exception:
                local_port = 0
            if not target_url:
                add_check(
                    f"directed_rule_{rid}",
                    False,
                    reason=f"Directed rule {rid} target_url is empty.",
                    suggestion="Set a valid target_url for this directed rule.",
                )
                continue
            if local_port < 1 or local_port > 65535:
                add_check(
                    f"directed_rule_{rid}",
                    False,
                    reason=f"Directed rule {rid} local_port is invalid: {item.get('local_port')}",
                    suggestion="Set local_port to a valid integer in range 1-65535.",
                )
                continue
            owner = port_owner.get(local_port)
            if owner and owner != rid:
                conflict_ports.add(local_port)
            else:
                port_owner[local_port] = rid

        if conflict_ports:
            ports_text = ", ".join(str(p) for p in sorted(conflict_ports))
            add_check(
                "local_port_conflicts",
                False,
                reason=f"Duplicate local listening ports found: {ports_text}.",
                suggestion="Ensure each enabled service/rule uses a unique local_port.",
            )
        else:
            add_check("local_port_conflicts", True)

        errors = [c for c in checks if not c["ok"] and c.get("level") == "error"]
        warnings = [c for c in checks if not c["ok"] and c.get("level") == "warning"]
        return {
            "ok": len(errors) == 0,
            "agent_id": aid,
            "checked_at": time.time(),
            "issue_count": len(errors),
            "warning_count": len(warnings),
            "checks": checks,
        }

    async def add_directed_rule(self, data: dict[str, Any], agent_id: str | None = None) -> dict[str, Any]:
        aid = self._pick_agent_id(agent_id)
        runtime = self.runtimes[aid]
        rule = await runtime.directed_manager.add_rule(data)
        agent_entry = self._config_agent_entry(aid)
        rules = agent_entry.setdefault("services", {}).setdefault("directed", [])
        rules.append(
            {
                "id": rule.rule_id,
                "local_port": rule.local_port,
                "target_url": rule.target_url,
                "enabled": rule.enabled,
            }
        )
        save_yaml(self.config_path, self.config)
        return {"ok": True, "id": rule.rule_id, "agent_id": aid}

    async def update_directed_rule(
        self, rule_id: str, data: dict[str, Any], agent_id: str | None = None
    ) -> dict[str, Any]:
        aid = self._pick_agent_id(agent_id)
        runtime = self.runtimes[aid]
        rule = await runtime.directed_manager.update_rule(rule_id, data)
        agent_entry = self._config_agent_entry(aid)
        rules = agent_entry.setdefault("services", {}).setdefault("directed", [])
        for item in rules:
            if item.get("id") == rule_id:
                item.update(
                    {
                        "local_port": rule.local_port,
                        "target_url": rule.target_url,
                        "enabled": rule.enabled,
                    }
                )
                break
        save_yaml(self.config_path, self.config)
        return {"ok": True, "id": rule.rule_id, "agent_id": aid}

    async def delete_directed_rule(self, rule_id: str, agent_id: str | None = None) -> None:
        aid = self._pick_agent_id(agent_id)
        runtime = self.runtimes[aid]
        await runtime.directed_manager.remove_rule(rule_id)
        agent_entry = self._config_agent_entry(aid)
        rules = agent_entry.setdefault("services", {}).setdefault("directed", [])
        agent_entry["services"]["directed"] = [r for r in rules if r.get("id") != rule_id]
        save_yaml(self.config_path, self.config)

    async def toggle_service(self, stype: str, enabled: bool, agent_id: str | None = None) -> dict[str, Any]:
        if stype not in {"directed", "general", "shell"}:
            raise ValueError(f"unsupported service type: {stype}")
        aid = self._pick_agent_id(agent_id)
        runtime = self.runtimes[aid]
        agent_entry = self._config_agent_entry(aid)
        services = agent_entry.setdefault("services", {})
        if stype == "directed":
            rules = services.setdefault("directed", [])
            await runtime.directed_manager.set_all_enabled(enabled)
            for item in rules:
                item["enabled"] = enabled
        elif stype == "general":
            general_cfg = services.setdefault("general", {})
            general_cfg["enabled"] = enabled
            if enabled:
                await runtime.general_proxy.start()
            else:
                await runtime.general_proxy.stop()
        else:
            shell_cfg = services.setdefault("shell", {})
            shell_cfg["enabled"] = enabled
        save_yaml(self.config_path, self.config)
        return {"ok": True, "service": stype, "enabled": enabled, "agent_id": aid}

    async def list_sessions(self, agent_id: str | None = None) -> dict[str, Any]:
        aid = self._pick_agent_id(agent_id)
        return {"sessions": list(self.runtimes[aid].session_manager.active.keys()), "agent_id": aid}

    async def kill_session(self, session_id: str, agent_id: str | None = None) -> None:
        aid = self._pick_agent_id(agent_id)
        await self.runtimes[aid].session_manager.close_session(session_id)

    async def create_shell_session(self, agent_id: str | None = None) -> str:
        aid = self._pick_agent_id(agent_id)
        runtime = self.runtimes[aid]
        assign = await runtime.session_manager.request_session("shell", None, aid)
        sid, data_key, token, pool_conn = await runtime.session_manager.use_assigned_pool(assign)
        self.shell_sessions[sid] = {
            "data_key": data_key,
            "pool_conn": pool_conn,
            "pool_token": token,
            "runtime": runtime,
            "agent_id": aid,
        }
        return sid

    async def attach_terminal_ws(self, session_id: str, ws: web.WebSocketResponse) -> None:
        ctx = self.shell_sessions.get(session_id)
        if not ctx:
            await ws.close(message=b"invalid_session")
            return
        runtime: AgentRuntime = ctx["runtime"]
        try:
            await self.shell_client.handle_websocket(ws, ctx["data_key"], ctx["pool_conn"])
        finally:
            with contextlib.suppress(Exception):
                await runtime.pool_manager.put_back(ctx["pool_token"], ctx["pool_conn"])
            self.shell_sessions.pop(session_id, None)
            await runtime.session_manager.close_session(session_id)

    async def change_agent_password(self, new_password_hash: str, agent_id: str | None = None) -> None:
        normalized_hash = str(new_password_hash).strip().lower()
        if not re.fullmatch(r"[0-9a-f]{64}", normalized_hash):
            raise ValueError("invalid hash")
        aid = self._pick_agent_id(agent_id)
        await self.runtimes[aid].change_agent_password(normalized_hash)

    async def restart_agent(self, agent_id: str | None = None) -> None:
        aid = self._pick_agent_id(agent_id)
        await self.runtimes[aid].restart_agent()

    async def reload_relay_certs(self, agent_id: str | None = None) -> None:
        aid = self._pick_agent_id(agent_id)
        await self.runtimes[aid].reload_relay_certs()


def _install_signal_handlers(app: ClientApp) -> None:
    loop = asyncio.get_running_loop()

    async def _shutdown() -> None:
        await app.shutdown()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, lambda: asyncio.create_task(_shutdown()))
        except NotImplementedError:
            signal.signal(sig, lambda *_: asyncio.create_task(_shutdown()))


async def _amain(config_path: str) -> None:
    cfg = load_yaml(config_path)
    require_keys(
        cfg,
        ["relay_host", "relay_port_client", "rsa_private_key", "rsa_public_key"],
        where="client config",
    )
    if "services" not in cfg and "agents" not in cfg:
        raise ValueError("client config requires 'services' (legacy) or 'agents' (multi-agent)")
    setup_logging(cfg.get("log_level", "info"))
    app = ClientApp(cfg, config_path=config_path)
    _install_signal_handlers(app)
    await app.start()


def main() -> None:
    parser = argparse.ArgumentParser(description="TriProxy Client")
    parser.add_argument("config", help="path to client yaml config")
    args = parser.parse_args()
    asyncio.run(_amain(args.config))


if __name__ == "__main__":
    main()

