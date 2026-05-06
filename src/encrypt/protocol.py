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
    "file_meta": 6, # File transfer metadata
    "file_chunk": 7, # File transfer chunk
    "stats_ping": 8, # Latency ping
    "stats_pong": 9, # Latency pong
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


# --- File Transfer ---

def pack_file_meta(transfer_id: bytes, filename: str, total_size: int, total_chunks: int, checksum: str, sender_pk: bytes) -> bytes:
    return msgpack.packb({
        "type": MSG_TYPES["file_meta"],
        "id": transfer_id,
        "name": filename,
        "size": total_size,
        "chunks": total_chunks,
        "sha256": checksum,
        "from": sender_pk,
        "t": time.time(),
    })


def unpack_file_meta(data: bytes) -> Optional[Dict[str, Any]]:
    msg = _unpack_dict(data)
    if not msg or msg.get("type") != MSG_TYPES["file_meta"]:
        return None
    return msg


def pack_file_chunk(transfer_id: bytes, seq: int, data: bytes, sender_pk: bytes) -> bytes:
    return msgpack.packb({
        "type": MSG_TYPES["file_chunk"],
        "id": transfer_id,
        "seq": seq,
        "data": data,
        "from": sender_pk,
        "t": time.time(),
    })


def unpack_file_chunk(data: bytes) -> Optional[Dict[str, Any]]:
    msg = _unpack_dict(data)
    if not msg or msg.get("type") != MSG_TYPES["file_chunk"]:
        return None
    return msg


# --- Stats ---

def pack_stats_ping(ping_id: bytes, sender_pk: bytes) -> bytes:
    return msgpack.packb({
        "type": MSG_TYPES["stats_ping"],
        "id": ping_id,
        "from": sender_pk,
        "t": time.time(),
    })


def unpack_stats_ping(data: bytes) -> Optional[Dict[str, Any]]:
    msg = _unpack_dict(data)
    if not msg or msg.get("type") != MSG_TYPES["stats_ping"]:
        return None
    return msg


def pack_stats_pong(ping_id: bytes, sender_pk: bytes, original_ts: float) -> bytes:
    return msgpack.packb({
        "type": MSG_TYPES["stats_pong"],
        "id": ping_id,
        "from": sender_pk,
        "orig_t": original_ts,
        "t": time.time(),
    })


def unpack_stats_pong(data: bytes) -> Optional[Dict[str, Any]]:
    msg = _unpack_dict(data)
    if not msg or msg.get("type") != MSG_TYPES["stats_pong"]:
        return None
    return msg
