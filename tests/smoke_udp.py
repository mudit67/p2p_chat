"""Smoke tests for LAN UDP protocol/crypto flow."""

from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.encrypt.crypto import Identity, PublicKey, decrypt, encrypt, hash_message, key_exchange, key_exchange_server
from src.encrypt.protocol import (
    pack_presence,
    pack_udp_ack,
    pack_udp_message,
    unpack_presence,
    unpack_udp_ack,
    unpack_udp_message,
)


def test_session_key_symmetry() -> None:
    alice = Identity.generate()
    bob = Identity.generate()
    a_tx, a_rx = key_exchange(alice.sk, alice.pk, PublicKey(bob.pk.encode()))
    b_tx, b_rx = key_exchange_server(bob.sk, bob.pk, PublicKey(alice.pk.encode()))
    assert a_tx == b_rx
    assert a_rx == b_tx


def test_udp_message_roundtrip() -> None:
    alice = Identity.generate()
    bob = Identity.generate()
    a_tx, _ = key_exchange(alice.sk, alice.pk, PublicKey(bob.pk.encode()))
    _, b_rx = key_exchange_server(bob.sk, bob.pk, PublicKey(alice.pk.encode()))

    plain = b"hello lan peer"
    msg_hash = hash_message(plain)
    ciphertext = encrypt(a_tx, plain)
    packet = pack_udp_message(
        msg_id=b"0123456789abcdef",
        seq=1,
        sender_pk=alice.pk.encode(),
        to_pk=bob.pk.encode(),
        msg_hash=msg_hash,
        ciphertext=ciphertext,
        ts=time.time(),
    )
    unpacked = unpack_udp_message(packet)
    assert unpacked is not None
    recovered = decrypt(b_rx, bytes(unpacked["c"]))
    assert recovered == plain
    assert bytes(unpacked["h"]) == msg_hash


def test_presence_and_ack_packets() -> None:
    identity = Identity.generate()
    presence = pack_presence("alice", identity.pk.encode(), 9001)
    unpacked_presence = unpack_presence(presence)
    assert unpacked_presence is not None
    assert unpacked_presence["u"] == "alice"

    ack = pack_udp_ack(b"0123456789abcdef", b"hash-here-32-bytes........", identity.pk.encode())
    unpacked_ack = unpack_udp_ack(ack)
    assert unpacked_ack is not None
    assert bytes(unpacked_ack["id"]) == b"0123456789abcdef"


if __name__ == "__main__":
    test_session_key_symmetry()
    test_udp_message_roundtrip()
    test_presence_and_ack_packets()
    print("UDP smoke tests passed.")
