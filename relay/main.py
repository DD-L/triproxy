from __future__ import annotations

import argparse
import asyncio
import contextlib
import signal
from typing import Any

from common.config import load_yaml, require_keys
from common.log import setup_logging
from common.protocol import MsgType, parse_message
from relay.control import RelayControlManager
from relay.listener import RelayListener
from relay.pool import RelayPoolManager
from relay.session import SessionManager


class RelayApp:
    def __init__(self, config: dict[str, Any]):
        self.config = config
        pool_cfg = config.get("pool", {})
        self.pool_manager = RelayPoolManager(
            pool_initial_size=int(pool_cfg.get("initial_size", 5)),
            pool_min_idle=int(pool_cfg.get("min_idle", 0)),
            pool_scale_batch=int(pool_cfg.get("scale_batch", 5)),
            pool_idle_timeout=int(pool_cfg.get("idle_timeout", 300)),
            heartbeat_interval=int(config.get("heartbeat_interval", config.get("heartbeat_timeout", 25))),
            dead_timeout=int(config.get("pool_dead_timeout", config.get("dead_timeout", 120))),
        )
        self.session_manager = SessionManager(
            self.pool_manager,
            setup_timeout=int(pool_cfg.get("session_setup_timeout", 30)),
        )
        self.control_manager = RelayControlManager(config, self.pool_manager, self.session_manager)
        self.listener = RelayListener(self.control_manager, self.pool_manager)
        self._servers: list[asyncio.AbstractServer] = []
        self._running = True
        self._server_tasks: list[asyncio.Task[Any]] = []
        self._shrink_task: asyncio.Task[Any] | None = None
        self._stop_event = asyncio.Event()
        self._shutdown_lock = asyncio.Lock()
        self._shutdown_done = False

    async def start(self) -> None:
        bind_host = self.config.get("bind_host", "0.0.0.0")
        agent_port = int(self.config["bind_port_agent"])
        client_port = int(self.config["bind_port_client"])

        agent_server = await asyncio.start_server(
            lambda r, w: self._route_port(r, w, "agent"),
            host=bind_host,
            port=agent_port,
        )
        client_server = await asyncio.start_server(
            lambda r, w: self._route_port(r, w, "client"),
            host=bind_host,
            port=client_port,
        )
        self._servers = [agent_server, client_server]

        shrink_interval = int(self.config.get("pool", {}).get("shrink_check_interval", 60))
        self._shrink_task = asyncio.create_task(self._shrink_loop(shrink_interval), name="pool-shrink-loop")

        self._server_tasks = [
            asyncio.create_task(server.serve_forever(), name=f"relay-serve-{idx}")
            for idx, server in enumerate(self._servers)
        ]
        await self._stop_event.wait()

    async def _route_port(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, side: str) -> None:
        # Control connections arrive first and perform HELLO handshake.
        # Pool connections perform POOL_AUTH as first encrypted frame.
        # Detect control by decoding first frame as protocol JSON HELLO.
        # Do NOT use magic-byte heuristics: encrypted pool frames are random
        # bytes and can occasionally start with "{" by coincidence.
        try:
            header = await reader.readexactly(4)
            length = int.from_bytes(header, "big")
            first = await reader.readexactly(length)
        except Exception:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return

        try:
            is_control = False
            try:
                first_msg = parse_message(first)
                is_control = (
                    str(first_msg.get("type", "")) == MsgType.HELLO.value
                    and str(first_msg.get("role", "")) == side
                )
            except Exception:
                is_control = False
            if is_control:
                await self.listener.handle_control_conn(reader, writer, side=side, first_payload=first)
            else:
                await self.listener.handle_pool_conn(reader, writer, side=side, first_payload=first)
        except Exception:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def _shrink_loop(self, interval: int) -> None:
        while self._running:
            await asyncio.sleep(interval)
            tokens = await self.pool_manager.shrink_once()
            for token in tokens:
                await self.pool_manager.remove_connection(token)

    async def shutdown(self) -> None:
        async with self._shutdown_lock:
            if self._shutdown_done:
                return
            self._shutdown_done = True
            self._running = False
            self._stop_event.set()

            for server in self._servers:
                server.close()
            for server in self._servers:
                with contextlib.suppress(Exception):
                    await server.wait_closed()

            for task in self._server_tasks:
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task
            self._server_tasks.clear()

            if self._shrink_task:
                self._shrink_task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await self._shrink_task
                self._shrink_task = None

            await self.session_manager.close_all()
            await self.control_manager.close_all_controls()
            await self.pool_manager.close_all()


def _install_signal_handlers(app: RelayApp) -> None:
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
        ["bind_port_agent", "bind_port_client", "rsa_private_key", "allowed_agents", "allowed_clients"],
        where="relay config",
    )
    setup_logging(cfg.get("log_level", "info"))
    app = RelayApp(cfg)
    _install_signal_handlers(app)
    await app.start()


def main() -> None:
    parser = argparse.ArgumentParser(description="TriProxy Relay")
    parser.add_argument("config", help="path to relay yaml config")
    args = parser.parse_args()
    asyncio.run(_amain(args.config))


if __name__ == "__main__":
    main()

