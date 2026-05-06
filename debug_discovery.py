#!/usr/bin/env python3
"""Debug script to test UDP discovery."""

import asyncio
import socket
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from src.encrypt.protocol import pack_presence, unpack_presence
from src.encrypt.crypto import Identity


async def test_discovery():
    """Test UDP broadcast discovery."""
    print("=== UDP Discovery Debug ===\n")
    
    # Load identities
    alice = Identity.load("keys/alice.json")
    bob = Identity.load("keys/bob.json")
    
    print(f"Alice PK: {alice.pk.encode().hex()[:16]}...")
    print(f"Bob PK: {bob.pk.encode().hex()[:16]}...\n")
    
    # Create two sockets for testing
    sock_tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock_tx.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock_tx.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock_tx.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
    sock_tx.setblocking(False)
    
    sock_rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock_rx.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock_rx.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock_rx.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
    sock_rx.setblocking(False)
    sock_rx.bind(("", 9999))
    
    print("Sockets created and bound to port 9999\n")
    
    # Send a presence beacon
    payload = pack_presence("alice", alice.pk.encode(), 9001)
    print(f"Sending presence beacon ({len(payload)} bytes)...")
    
    loop = asyncio.get_running_loop()
    
    try:
        sent = await loop.sock_sendto(sock_tx, payload, ("255.255.255.255", 9999))
        print(f"Sent {sent} bytes via broadcast\n")
    except Exception as e:
        print(f"Send error: {e}\n")
    
    # Try to receive
    print("Waiting for beacon on rx socket...")
    try:
        for attempt in range(5):
            try:
                data, addr = await asyncio.wait_for(
                    loop.sock_recvfrom(sock_rx, 4096),
                    timeout=1.0
                )
                print(f"[{attempt+1}] Received {len(data)} bytes from {addr}")
                presence = unpack_presence(data)
                if presence:
                    print(f"    Unpacked: username={presence.get('u')}, "
                          f"port={presence.get('p')}, pk={bytes(presence['pk']).hex()[:16]}...\n")
            except asyncio.TimeoutError:
                print(f"[{attempt+1}] Timeout waiting for beacon...")
                await asyncio.sleep(0.2)
    except Exception as e:
        print(f"Receive error: {e}")
    finally:
        sock_tx.close()
        sock_rx.close()
        print("Sockets closed")


if __name__ == "__main__":
    asyncio.run(test_discovery())
