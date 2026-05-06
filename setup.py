"""
One-time setup: Generate user keys.
"""
import sys
from pathlib import Path
from encrypt.crypto import Identity

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python setup.py <user>")
        sys.exit(1)
    
    user = sys.argv[1]
    keys_dir = Path('keys')
    keys_dir.mkdir(exist_ok=True)
    
    iden = Identity.generate()
    iden.save(f'keys/{user}.json')
    print(f"Keys generated for {user}")
