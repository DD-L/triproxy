from __future__ import annotations

import asyncio
import contextlib
from dataclasses import dataclass
from typing import Any

from common.connection import FramedConnection
from common.crypto import encrypted_recv, encrypted_send
from client.session import ClientSessionManager


@dataclass
class DirectedRule:
    rule_id: str
    local_port: int
    target_url: str
    enabled: bool
    server: asyncio.AbstractServer | None = None


class DirectedProxyManager:
    def __init__(self, session_manager: ClientSessionManager, agent_id: str = "default"):
        self.session_manager = session_manager
        self.agent_id = agent_id
        self.rules: dict[str, DirectedRule] = {}
        self.rule_sessions: dict[str, set[str]] = {}

    async def load_rules(self, cfg_rules: list[dict[str, Any]]) -> None:
        for rule in cfg_rules:
            rid = str(rule.get("id") or f"rule-{rule.get('local_port')}")
            await self.add_rule(
                {
                    "id": rid,
                    "local_port": int(rule["local_port"]),
                    "target_url": str(rule["target_url"]),
                    "enabled": bool(rule.get("enabled", True)),
                }
            )

    async def add_rule(self, rule_data: dict[str, Any]) -> DirectedRule:
        rule = DirectedRule(
            rule_id=str(rule_data["id"]),
            local_port=int(rule_data["local_port"]),
            target_url=str(rule_data["target_url"]),
            enabled=bool(rule_data.get("enabled", True)),
        )
        self.rules[rule.rule_id] = rule
        self.rule_sessions[rule.rule_id] = set()
        if rule.enabled:
            await self._start_rule(rule)
        return rule

    async def update_rule(self, rule_id: str, patch: dict[str, Any]) -> DirectedRule:
        old = self.rules[rule_id]
        await self.remove_rule(rule_id)
        merged = {
            "id": rule_id,
            "local_port": int(patch.get("local_port", old.local_port)),
            "target_url": str(patch.get("target_url", old.target_url)),
            "enabled": bool(patch.get("enabled", old.enabled)),
        }
        return await self.add_rule(merged)

    async def remove_rule(self, rule_id: str) -> None:
        rule = self.rules.pop(rule_id, None)
        if not rule:
            return
        await self._stop_rule(rule, close_sessions=True)
        self.rule_sessions.pop(rule_id, None)

    async def _start_rule(self, rule: DirectedRule) -> None:
        if rule.server is not None:
            return
        rule.server = await asyncio.start_server(
            lambda r, w: self._handle_local(rule, r, w),
            host="127.0.0.1",
            port=rule.local_port,
        )

    async def _stop_rule(self, rule: DirectedRule, close_sessions: bool) -> None:
        if rule.server:
            rule.server.close()
            await rule.server.wait_closed()
            rule.server = None
        if close_sessions:
            for sid in list(self.rule_sessions.get(rule.rule_id, set())):
                await self.session_manager.close_session(sid)

    async def set_rule_enabled(self, rule_id: str, enabled: bool) -> DirectedRule:
        rule = self.rules[rule_id]
        if enabled:
            await self._start_rule(rule)
        else:
            await self._stop_rule(rule, close_sessions=True)
        rule.enabled = enabled
        return rule

    async def set_all_enabled(self, enabled: bool) -> None:
        for rule_id in list(self.rules.keys()):
            await self.set_rule_enabled(rule_id, enabled)

    async def _handle_local(
        self,
        rule: DirectedRule,
        local_reader: asyncio.StreamReader,
        local_writer: asyncio.StreamWriter,
    ) -> None:
        sid = ""
        try:
            assign = await self.session_manager.request_session(
                mode="directed",
                target=rule.target_url,
                agent_id=self.agent_id,
            )
            sid, data_key, token, pool_conn = await self.session_manager.use_assigned_pool(assign)
            self.rule_sessions[rule.rule_id].add(sid)

            async def local_to_remote() -> None:
                while True:
                    data = await local_reader.read(65536)
                    if not data:
                        break
                    await encrypted_send(pool_conn.writer, data_key, data)

            async def remote_to_local() -> None:
                while True:
                    data = await encrypted_recv(pool_conn.reader, data_key)
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
            await self.session_manager.pool_manager.put_back(token, pool_conn)
        finally:
            if sid:
                self.rule_sessions[rule.rule_id].discard(sid)
                await self.session_manager.close_session(sid)
            local_writer.close()
            await local_writer.wait_closed()

