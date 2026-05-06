#!/usr/bin/env python3
"""
Test script to verify broadcast messages are delivered to all peers.

Usage:
    # Start 3 clients in background
    python3 -m src.encrypt.client alice udp 9001 &
    python3 -m src.encrypt.client bob udp 9002 &
    python3 -m src.encrypt.client candy udp 9003 &
    
    # Run this test
    python3 tests/test_broadcast.py
"""

import asyncio
import socket
import struct
from pathlib import Path
import sys

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.encrypt.discovery import LanDiscovery, DISCOVERY_MULTICAST_GROUP, DISCOVERY_MULTICAST_PORT
from src.encrypt.crypto import Identity
from src.encrypt.protocol import pack_presence, unpack_presence


async def test_peer_discovery():
    """Test that multicast discovery works for multiple peers."""
    print("🧪 Testing UDP Multicast Discovery...\n")
    
    # Load identities
    alice_path = Path("keys/alice.json")
    bob_path = Path("keys/bob.json")
    candy_path = Path("keys/candy.json")
    
    if not all([alice_path.exists(), bob_path.exists(), candy_path.exists()]):
        print("❌ Missing key files. Run: python3 -m src.encrypt.keygen alice bob candy")
        return False
    
    alice = Identity.load(str(alice_path))
    bob = Identity.load(str(bob_path))
    candy = Identity.load(str(candy_path))
    
    discovered = {
        "alice": set(),
        "bob": set(),
        "candy": set(),
    }
    
    def on_alice_presence(data, addr):
        try:
            presence = unpack_presence(data)
            username = str(presence.get("u", "unknown"))
            discovered["alice"].add(username)
        except:
            pass
    
    def on_bob_presence(data, addr):
        try:
            presence = unpack_presence(data)
            username = str(presence.get("u", "unknown"))
            discovered["bob"].add(username)
        except:
            pass
    
    def on_candy_presence(data, addr):
        try:
            presence = unpack_presence(data)
            username = str(presence.get("u", "unknown"))
            discovered["candy"].add(username)
        except:
            pass
    
    # Create discovery instances
    alice_disc = LanDiscovery("alice", alice.pk.encode(), 9001, DISCOVERY_MULTICAST_PORT)
    bob_disc = LanDiscovery("bob", bob.pk.encode(), 9002, DISCOVERY_MULTICAST_PORT)
    candy_disc = LanDiscovery("candy", candy.pk.encode(), 9003, DISCOVERY_MULTICAST_PORT)
    
    # Start discovery
    await alice_disc.start(on_alice_presence)
    await bob_disc.start(on_bob_presence)
    await candy_disc.start(on_candy_presence)
    
    # Wait for discovery
    print("⏳ Waiting 3 seconds for multicast discovery...")
    await asyncio.sleep(3)
    
    # Stop discovery
    await alice_disc.stop()
    await bob_disc.stop()
    await candy_disc.stop()
    
    # Check results
    print("\n📊 Discovery Results:")
    print(f"  Alice discovered: {discovered['alice']} (expected: {{'bob', 'candy'}})")
    print(f"  Bob discovered:   {discovered['bob']} (expected: {{'alice', 'candy'}})")
    print(f"  Candy discovered: {discovered['candy']} (expected: {{'alice', 'bob'}})")
    
    # Verify all peers discovered each other
    alice_ok = discovered["alice"] == {"bob", "candy"}
    bob_ok = discovered["bob"] == {"alice", "candy"}
    candy_ok = discovered["candy"] == {"alice", "bob"}
    
    if alice_ok and bob_ok and candy_ok:
        print("\n✅ All peers discovered each other!")
        return True
    else:
        print("\n❌ Discovery incomplete!")
        return False


async def main():
    try:
        result = await test_peer_discovery()
        sys.exit(0 if result else 1)
    except Exception as e:
        print(f"❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
