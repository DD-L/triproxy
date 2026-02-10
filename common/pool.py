from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class PoolConnState:
    pool_token: str
    role: str
    in_use: bool = False
    last_idle_at: float = field(default_factory=time.time)
    metadata: dict[str, Any] = field(default_factory=dict)


class BasePoolManager:
    def __init__(
        self,
        role: str,
        idle_timeout: int = 300,
        min_idle: int = 0,
        scale_batch: int = 5,
    ):
        self.role = role
        self.idle_timeout = idle_timeout
        self.min_idle = min_idle
        self.scale_batch = scale_batch
        self._conns: dict[str, PoolConnState] = {}
        self._lock = asyncio.Lock()

    async def add_token(self, pool_token: str, metadata: dict[str, Any] | None = None) -> None:
        async with self._lock:
            self._conns[pool_token] = PoolConnState(
                pool_token=pool_token,
                role=self.role,
                metadata=metadata or {},
            )

    async def remove_token(self, pool_token: str) -> None:
        async with self._lock:
            self._conns.pop(pool_token, None)

    async def mark_in_use(self, pool_token: str, in_use: bool) -> None:
        async with self._lock:
            conn = self._conns.get(pool_token)
            if not conn:
                return
            conn.in_use = in_use
            if not in_use:
                conn.last_idle_at = time.time()

    async def list_idle_tokens(self) -> list[str]:
        async with self._lock:
            return [t for t, c in self._conns.items() if not c.in_use]

    async def list_active_tokens(self) -> list[str]:
        async with self._lock:
            return [t for t, c in self._conns.items() if c.in_use]

    async def pop_idle_token(self) -> str | None:
        async with self._lock:
            for token, conn in self._conns.items():
                if not conn.in_use:
                    conn.in_use = True
                    return token
        return None

    async def expired_idle_tokens(self) -> list[str]:
        now = time.time()
        async with self._lock:
            idle_tokens = [t for t, c in self._conns.items() if not c.in_use]
            if len(idle_tokens) <= self.min_idle:
                return []
            extra = len(idle_tokens) - self.min_idle
            expired: list[str] = []
            for token in idle_tokens:
                conn = self._conns[token]
                if now - conn.last_idle_at > self.idle_timeout:
                    expired.append(token)
                    if len(expired) >= extra:
                        break
            return expired

    async def snapshot(self) -> dict[str, int]:
        async with self._lock:
            total = len(self._conns)
            active = sum(1 for c in self._conns.values() if c.in_use)
            idle = total - active
            return {"total": total, "active": active, "idle": idle}

    async def clear(self) -> None:
        async with self._lock:
            self._conns.clear()

