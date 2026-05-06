#!/usr/bin/env python3
"""Test discovery with two clients."""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from src.encrypt.discovery import LanDiscovery, DISCOVERY_MULTICAST_PORT
from src.encrypt.crypto import Identity


async def test_client(name: str, port: int):
    """Test a single client."""
    identity = Identity.load(f"keys/{name}.json")
    discovered_peers = []
    
    def on_presence(presence: dict, addr: tuple[str, int]):
        username = presence.get('u')
        if username != name:  # Skip self
            discovered_peers.append(username)
            print(f"[{name}] Discovered: {username}")
    
    discovery = LanDiscovery(
        username=name,
        public_key=identity.pk.encode(),
        listen_port=port,
        discovery_port=DISCOVERY_MULTICAST_PORT,
        interval_seconds=1.0,
    )
    
    await discovery.start(on_presence)
    print(f"[{name}] Discovery started on port {port}")
    
    # Run for 10 seconds
    for i in range(10):
        await asyncio.sleep(1)
        print(f"[{name}] {i+1}s elapsed, discovered: {discovered_peers}")
    
    await discovery.stop()
    print(f"[{name}] Discovery stopped")
    
    return len(discovered_peers) > 0


async def main():
    print("Starting discovery test with alice and bob\n")
    
    # Start both clients concurrently
    alice_task = test_client("alice", 9001)
    bob_task = test_client("bob", 9002)
    
    alice_ok, bob_ok = await asyncio.gather(alice_task, bob_task)
    
    print(f"\n=== Results ===")
    print(f"Alice discovered peers: {alice_ok}")
    print(f"Bob discovered peers: {bob_ok}")
    
    if alice_ok and bob_ok:
        print("✓ Discovery working!")
        sys.exit(0)
    else:
        print("✗ Discovery failed!")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
