"""Wire protocol helpers for relay and UDP LAN chat modes."""

from __future__ import annotations

import time
from typing import Any, Dict, Optional, cast

import msgpack

MSG_TYPES = {
    "connect": 1,   # Relay mode
    "msg": 2,       # Relay mode payload
    "ack": 3,       # Relay + UDP ack
    "presence": 4,  # UDP discovery/presence
    "udp_msg": 5,   # UDP encrypted direct message
}

MAX_CLOCK_SKEW_SECONDS = 60.0


def _unpack_dict(data: bytes) -> Optional[Dict[str, Any]]:
    try:
        result = msgpack.unpackb(data, raw=False)
        if not isinstance(result, dict):
            return None
        return cast(Dict[str, Any], result)
    except (ValueError, TypeError, msgpack.exceptions.ExtraData, msgpack.exceptions.UnpackException):
        return None


def _valid_timestamp(value: Any) -> bool:
    try:
        return abs(time.time() - float(value)) <= MAX_CLOCK_SKEW_SECONDS
    except (TypeError, ValueError):
        return False


def pack_connect(pk: bytes) -> bytes:
    return msgpack.packb({"type": MSG_TYPES["connect"], "pk": pk})


def unpack_connect(data: bytes) -> Optional[Dict[str, Any]]:
    msg = _unpack_dict(data)
    if not msg or msg.get("type") != MSG_TYPES["connect"]:
        return None
    return msg


def pack_message(to_pk: bytes, msg_hash: bytes, ciphertext: bytes, ts: float) -> bytes:
    return msgpack.packb(
        {"type": MSG_TYPES["msg"], "to": to_pk, "h": msg_hash, "c": ciphertext, "t": ts}
    )


def unpack_message(data: bytes) -> Optional[Dict[str, Any]]:
    msg = _unpack_dict(data)
    if not msg:
        return None
    if msg.get("type") not in (MSG_TYPES["msg"], MSG_TYPES["udp_msg"]):
        return None
    if not _valid_timestamp(msg.get("t")):
        return None
    return msg


def pack_ack(hash_val: bytes) -> bytes:
    return msgpack.packb({"type": MSG_TYPES["ack"], "h": hash_val, "t": time.time()})


def unpack_ack(data: bytes) -> Optional[bytes]:
    result = _unpack_dict(data)
    if not result or result.get("type") != MSG_TYPES["ack"]:
        return None
    h = result.get("h")
    if isinstance(h, bytes):
        return h
    if isinstance(h, (list, tuple)):
        return bytes(h)
    return None


def pack_presence(username: str, pk: bytes, listen_port: int, mode: str = "udp") -> bytes:
    return msgpack.packb(
        {
            "type": MSG_TYPES["presence"],
            "u": username,
            "pk": pk,
            "p": int(listen_port),
            "m": mode,
            "t": time.time(),
        }
    )


def unpack_presence(data: bytes) -> Optional[Dict[str, Any]]:
    msg = _unpack_dict(data)
    if not msg or msg.get("type") != MSG_TYPES["presence"]:
        return None
    if not _valid_timestamp(msg.get("t")):
        return None
    if not isinstance(msg.get("u"), str):
        return None
    if not isinstance(msg.get("p"), int):
        return None
    return msg


def pack_udp_message(
    msg_id: bytes,
    seq: int,
    sender_pk: bytes,
    to_pk: bytes,
    msg_hash: bytes,
    ciphertext: bytes,
    ts: float,
) -> bytes:
    return msgpack.packb(
        {
            "type": MSG_TYPES["udp_msg"],
            "id": msg_id,
            "s": int(seq),
            "from": sender_pk,
            "to": to_pk,
            "h": msg_hash,
            "c": ciphertext,
            "t": ts,
        }
    )


def unpack_udp_message(data: bytes) -> Optional[Dict[str, Any]]:
    msg = unpack_message(data)
    if not msg or msg.get("type") != MSG_TYPES["udp_msg"]:
        return None
    if not isinstance(msg.get("s"), int):
        return None
    if not isinstance(msg.get("id"), (bytes, bytearray)):
        return None
    return msg


def pack_udp_ack(msg_id: bytes, msg_hash: bytes, sender_pk: bytes) -> bytes:
    return msgpack.packb(
        {
            "type": MSG_TYPES["ack"],
            "id": msg_id,
            "h": msg_hash,
            "from": sender_pk,
            "t": time.time(),
        }
    )


def unpack_udp_ack(data: bytes) -> Optional[Dict[str, Any]]:
    msg = _unpack_dict(data)
    if not msg or msg.get("type") != MSG_TYPES["ack"]:
        return None
    if not _valid_timestamp(msg.get("t")):
        return None
    if not isinstance(msg.get("id"), (bytes, bytearray)):
        return None
    if not isinstance(msg.get("h"), (bytes, bytearray)):
        return None
    if not isinstance(msg.get("from"), (bytes, bytearray)):
        return None
    return msg
