"""
Protocol: Msgpack over TLS. Types: connect, msg, ack. Includes hash for leak detection.
"""
import msgpack
import time
from typing import Dict, Any, Optional, cast
from nacl.utils import random as nacl_random

MSG_TYPES = {
    'connect': 1,
    'msg': 2,
    'ack': 3
}

def pack_connect(pk: bytes) -> bytes:
    """Handshake: Send public key."""
    return msgpack.packb({'type': MSG_TYPES['connect'], 'pk': pk})

def unpack_connect(data: bytes) -> Optional[Dict[str, Any]]:
    """Unpack connection handshake."""
    try:
        result = msgpack.unpackb(data, raw=False)
        if not isinstance(result, dict):
            return None
        return cast(Dict[str, Any], result)
    except (ValueError, TypeError, msgpack.exceptions.ExtraData, msgpack.exceptions.UnpackException):
        return None

def pack_message(to_pk: bytes, msg_hash: bytes, ciphertext: bytes, ts: float) -> bytes:
    """Encrypted msg + metadata for relay."""
    return msgpack.packb({
        'type': MSG_TYPES['msg'],
        'to': to_pk,
        'h': msg_hash,
        'c': ciphertext,
        't': ts
    })

def unpack_message(data: bytes) -> Optional[Dict[str, Any]]:
    """Validate ts (anti-replay, <60s)."""
    try:
        msg = msgpack.unpackb(data, raw=False)
        if not isinstance(msg, dict):
            return None
        
        # Validate timestamp - increased window to 60s for network delays
        timestamp = msg.get('t')
        if timestamp is None:
            return None
        try:
            time_diff = abs(time.time() - float(timestamp))
            if time_diff > 60:  # Increased from 30s to handle network delays
                return None  # Stale timestamp
        except (ValueError, TypeError):
            return None
        
        return cast(Dict[str, Any], msg)
    except (KeyError, ValueError, TypeError, msgpack.exceptions.ExtraData, msgpack.exceptions.UnpackException):
        return None

def pack_ack(hash_val: bytes) -> bytes:
    """Echo hash for sender verification."""
    return msgpack.packb({'type': MSG_TYPES['ack'], 'h': hash_val})

def unpack_ack(data: bytes) -> Optional[bytes]:
    """Unpack acknowledgment and extract hash."""
    try:
        result = msgpack.unpackb(data, raw=False)
        if not isinstance(result, dict):
            return None
        
        h = result.get('h')
        if h is None:
            return None
        
        # Ensure we return bytes
        if isinstance(h, bytes):
            return h
        elif isinstance(h, (list, tuple)):
            return bytes(h)
        else:
            return None
    except (KeyError, ValueError, TypeError, msgpack.exceptions.ExtraData, msgpack.exceptions.UnpackException):
        return None

# Note: generate_nonce() is unused - nonces are generated in encrypt() function
# Keeping for potential future use or removing if not needed
