"""
Debug script to test key exchange between Alice and Bob
"""
from pathlib import Path
import sys
import os

# Add src directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from encrypt.crypto import Identity, key_exchange, key_exchange_server, encrypt, decrypt, PublicKey

def test_key_exchange():
    print("=== Key Exchange Debug ===\n")
    
    # Load identities
    alice_id = Identity.load('keys/alice.json')
    bob_id = Identity.load('keys/bob.json')
    
    alice_pk = alice_id.pk.encode()
    bob_pk = bob_id.pk.encode()
    
    print(f"Alice PK: {alice_pk.hex()[:16]}...")
    print(f"Bob PK:   {bob_pk.hex()[:16]}...")
    print()
    
    # Determine roles based on lexicographic comparison
    alice_is_client = alice_pk < bob_pk
    print(f"Role Assignment: Alice={'CLIENT' if alice_is_client else 'SERVER'}, Bob={'SERVER' if alice_is_client else 'CLIENT'}")
    print()
    
    # Alice's perspective
    if alice_is_client:
        alice_tx, alice_rx = key_exchange(
            alice_id.sk,
            alice_id.pk,
            PublicKey(bob_pk)
        )
        role_a = "CLIENT"
    else:
        alice_tx, alice_rx = key_exchange_server(
            alice_id.sk,
            alice_id.pk,
            PublicKey(bob_pk)
        )
        role_a = "SERVER"
    
    print(f"Alice's keys (as {role_a}):")
    print(f"  TX: {alice_tx.hex()[:32]}...")
    print(f"  RX: {alice_rx.hex()[:32]}...")
    print()
    
    # Bob's perspective
    if not alice_is_client:  # Bob is client if Alice is server
        bob_tx, bob_rx = key_exchange(
            bob_id.sk,
            bob_id.pk,
            PublicKey(alice_pk)
        )
        role_b = "CLIENT"
    else:
        bob_tx, bob_rx = key_exchange_server(
            bob_id.sk,
            bob_id.pk,
            PublicKey(alice_pk)
        )
        role_b = "SERVER"
    
    print(f"Bob's keys (as {role_b}):")
    print(f"  TX: {bob_tx.hex()[:32]}...")
    print(f"  RX: {bob_rx.hex()[:32]}...")
    print()
    
    # Check if keys match correctly
    print("Key Matching Check:")
    print(f"  Alice TX == Bob RX: {alice_tx == bob_rx}")
    print(f"  Alice RX == Bob TX: {alice_rx == bob_tx}")
    print()
    
    # Test encryption/decryption
    print("=== Encryption Test ===\n")
    
    test_message = b"Hello from Alice to Bob!"
    
    # Alice encrypts with her TX key
    print(f"Original message: {test_message.decode()}")
    ciphertext = encrypt(alice_tx, test_message)
    print(f"Ciphertext length: {len(ciphertext)} bytes")
    print()
    
    # Bob decrypts with his RX key
    decrypted = decrypt(bob_rx, ciphertext)
    
    if decrypted:
        print(f"✓ Bob decrypted: {decrypted.decode()}")
        print(f"✓ Match: {decrypted == test_message}")
    else:
        print("✗ Decryption FAILED")
        print("\nDEBUG INFO:")
        print(f"  Alice TX key: {alice_tx.hex()}")
        print(f"  Bob RX key:   {bob_rx.hex()}")
        print(f"  Keys equal: {alice_tx == bob_rx}")
    print()
    
    # Test reverse direction
    print("=== Reverse Direction Test ===\n")
    
    test_message2 = b"Reply from Bob to Alice!"
    print(f"Original message: {test_message2.decode()}")
    
    # Bob encrypts with his TX key
    ciphertext2 = encrypt(bob_tx, test_message2)
    print(f"Ciphertext length: {len(ciphertext2)} bytes")
    print()
    
    # Alice decrypts with her RX key
    decrypted2 = decrypt(alice_rx, ciphertext2)
    
    if decrypted2:
        print(f"✓ Alice decrypted: {decrypted2.decode()}")
        print(f"✓ Match: {decrypted2 == test_message2}")
    else:
        print("✗ Decryption FAILED")
        print("\nDEBUG INFO:")
        print(f"  Bob TX key:   {bob_tx.hex()}")
        print(f"  Alice RX key: {alice_rx.hex()}")
        print(f"  Keys equal: {bob_tx == alice_rx}")

if __name__ == '__main__':
    try:
        test_key_exchange()
    except (FileNotFoundError, ValueError) as e:
        print(f"Error: {e}")
        print("\nRun this first:")
        print("  python -m src.encrypt.keygen alice bob")
