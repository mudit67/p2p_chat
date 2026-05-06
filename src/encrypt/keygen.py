"""
Key generation utility for setting up test users.
Usage: python -m src.encrypt.keygen alice bob
"""
import sys
from pathlib import Path
from .crypto import Identity

def generate_keys(users):
    """Generate X25519 keypairs for each user."""
    keys_dir = Path('keys')
    keys_dir.mkdir(exist_ok=True)
    
    print("Generating keypairs...")
    
    for user in users:
        identity = Identity.generate()
        key_path = keys_dir / f'{user}.json'
        identity.save(str(key_path))
        print(f"✓ {user}: {identity.pk.encode().hex()[:16]}...")
    
    print(f"\nGenerated {len(users)} keypairs in ./keys/")
    print("Ready for encrypted chat!")


def main():
    """Entry point for keygen."""
    if len(sys.argv) < 2:
        print("Usage: python -m src.encrypt.keygen <user1> <user2> ...")
        print("Example: python -m src.encrypt.keygen alice bob")
        sys.exit(1)
    
    users = sys.argv[1:]
    generate_keys(users)


if __name__ == '__main__':
    main()
