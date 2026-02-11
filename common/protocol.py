from __future__ import annotations

import json
from enum import Enum
from typing import Any, Mapping

PROTOCOL_VERSION = "1.0"
MAX_FRAME_SIZE = 16 * 1024 * 1024


class MsgType(str, Enum):
    # Handshake
    HELLO = "HELLO"
    SERVER_HELLO = "SERVER_HELLO"
    KEY_EXCHANGE = "KEY_EXCHANGE"
    KEY_VERIFY = "KEY_VERIFY"
    AUTH_KEY_VERIFY = "AUTH_KEY_VERIFY"
    HANDSHAKE_OK = "HANDSHAKE_OK"
    HANDSHAKE_FAIL = "HANDSHAKE_FAIL"

    # Heartbeat
    PING = "PING"
    PONG = "PONG"

    # Pool management on control channel
    POOL_ALLOC = "POOL_ALLOC"
    POOL_READY = "POOL_READY"
    POOL_SHRINK = "POOL_SHRINK"

    # Pool auth over pool connection (encrypted with control key)
    POOL_AUTH = "POOL_AUTH"
    POOL_AUTH_OK = "POOL_AUTH_OK"
    POOL_AUTH_FAIL = "POOL_AUTH_FAIL"

    # Session management
    SESSION_REQUEST = "SESSION_REQUEST"
    SESSION_ASSIGN = "SESSION_ASSIGN"
    SESSION_READY = "SESSION_READY"
    SESSION_FAIL = "SESSION_FAIL"
    SESSION_CLOSE = "SESSION_CLOSE"

    # Agent console remote management
    AGENT_PWD_CHANGE = "AGENT_PWD_CHANGE"
    AGENT_PWD_CHANGED = "AGENT_PWD_CHANGED"
    AGENT_STATUS_REQ = "AGENT_STATUS_REQ"
    AGENT_STATUS_RESP = "AGENT_STATUS_RESP"
    CLIENT_STATUS_REQ = "CLIENT_STATUS_REQ"
    CLIENT_STATUS_RESP = "CLIENT_STATUS_RESP"
    AGENT_RESTART_REQ = "AGENT_RESTART_REQ"
    AGENT_RESTART_RESP = "AGENT_RESTART_RESP"
    RELAY_RESTART_REQ = "RELAY_RESTART_REQ"
    RELAY_RESTART_RESP = "RELAY_RESTART_RESP"
    RELAY_CERT_RELOAD_REQ = "RELAY_CERT_RELOAD_REQ"
    RELAY_CERT_RELOAD_RESP = "RELAY_CERT_RELOAD_RESP"


class ProtocolError(ValueError):
    pass


def ensure_message_type(value: Any) -> MsgType:
    if isinstance(value, MsgType):
        return value
    try:
        return MsgType(str(value))
    except Exception as exc:
        raise ProtocolError(f"unknown message type: {value!r}") from exc


def build_message(msg_type: MsgType | str, **fields: Any) -> dict[str, Any]:
    mt = ensure_message_type(msg_type)
    return {"type": mt.value, **fields}


def parse_message(data: bytes) -> dict[str, Any]:
    try:
        obj = json.loads(data.decode("utf-8"))
    except Exception as exc:
        raise ProtocolError("invalid JSON payload") from exc
    if not isinstance(obj, dict):
        raise ProtocolError("message payload must be a JSON object")
    if "type" not in obj:
        raise ProtocolError("message missing required field: type")
    ensure_message_type(obj["type"])
    return obj


def encode_message(message: Mapping[str, Any]) -> bytes:
    return json.dumps(message, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

