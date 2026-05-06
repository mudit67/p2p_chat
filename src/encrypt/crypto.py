import os
import json
import time
import hashlib
import blake3
from typing import Tuple, Optional
from nacl.public import PrivateKey, PublicKey
from nacl.secret import SecretBox
from nacl.utils import random
from nacl.bindings import crypto_kx_client_session_keys, crypto_kx_server_session_keys

"""
Crypto primitives: X25519 key agreement, XSalsa20-Poly1305 AEAD, BLAKE3 hashing, chained E2EE logging.
"""

class Identity:
    """X25519 keypair for identity and key exchange."""
    def __init__(self, sk: PrivateKey, pk: PublicKey):
        self.sk = sk
        self.pk = pk

    @classmethod
    def generate(cls) -> 'Identity':
        sk = PrivateKey.generate()  # X25519
        return cls(sk, sk.public_key)

    @classmethod
    def load(cls, path: str) -> 'Identity':
        try:
            with open(path, 'r') as f:
                data = json.load(f)
            sk = PrivateKey(bytes.fromhex(data['sk_x']))
            pk = PublicKey(bytes.fromhex(data['pk_x']))
            return cls(sk, pk)
        except (FileNotFoundError, json.JSONDecodeError, KeyError, ValueError) as e:
            raise ValueError(f"Failed to load identity from {path}: {e}") from e

    def save(self, path: str):
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, 'w') as f:
                json.dump({
                    'sk_x': self.sk.encode().hex(),
                    'pk_x': self.pk.encode().hex()
                }, f)
        except (OSError, IOError) as e:
            raise IOError(f"Failed to save identity to {path}: {e}") from e

    def derive_log_key(self) -> bytes:
        """BLAKE2b-derived key for log encryption (from private key).
        
        Returns:
            32-byte key derived from private key using BLAKE2b
        """
        # Use standard hashlib for consistent 32-byte output
        return hashlib.blake2b(self.sk.encode(), digest_size=32).digest()


def key_exchange(client_sk: PrivateKey, client_pk: PublicKey, server_pk: PublicKey) -> Tuple[bytes, bytes]:
    """Client-side X25519 key exchange (Noise-like).
    
    Note: NaCl returns (rx_key, tx_key), so we swap to return (tx_key, rx_key).
    
    Returns:
        Tuple of (tx_key, rx_key) for the client
    """
    rx_key, tx_key = crypto_kx_client_session_keys(client_pk.encode(), client_sk.encode(), server_pk.encode())
    return (tx_key, rx_key)

def key_exchange_server(server_sk: PrivateKey, server_pk: PublicKey, client_pk: PublicKey) -> Tuple[bytes, bytes]:
    """Server-side key exchange.
    
    Note: NaCl returns (rx_key, tx_key), so we swap to return (tx_key, rx_key).
    
    Returns:
        Tuple of (tx_key, rx_key) for the server
    """
    rx_key, tx_key = crypto_kx_server_session_keys(server_pk.encode(), server_sk.encode(), client_pk.encode())
    return (tx_key, rx_key)


def encrypt(box_key: bytes, plaintext: bytes) -> bytes:
    """AEAD encrypt with XSalsa20-Poly1305.
    
    Note: SecretBox.encrypt() automatically prepends the nonce to the ciphertext.
    
    Args:
        box_key: 32-byte secret key for SecretBox
        plaintext: Message to encrypt
    
    Returns:
        Encrypted data with nonce prepended (nonce + ciphertext)
    """
    box = SecretBox(box_key)
    # box.encrypt() automatically generates a nonce and prepends it
    return box.encrypt(plaintext)

def decrypt(box_key: bytes, ciphertext: bytes) -> Optional[bytes]:
    """AEAD decrypt; None on failure (tamper/leak).
    
    Args:
        box_key: 32-byte secret key for SecretBox
        ciphertext: Encrypted data (nonce + ciphertext)
    
    Returns:
        Decrypted plaintext bytes, or None if decryption fails
    """
    if len(ciphertext) < SecretBox.NONCE_SIZE:
        return None
    if len(box_key) != 32:
        return None
    try:
        box = SecretBox(box_key)
        nonce = ciphertext[:SecretBox.NONCE_SIZE]
        ct = ciphertext[SecretBox.NONCE_SIZE:]
        return box.decrypt(ct, nonce)
    except (ValueError, TypeError):
        # ValueError: authentication failed (tamper detected) or invalid key
        # TypeError: invalid input types
        return None
    except Exception:
        # Catch-all for other crypto errors
        return None


def hash_message(msg: bytes, prev_hash: Optional[bytes] = None) -> bytes:
    """BLAKE3 hash; chain with prev for tamper-proof logs.
    
    Args:
        msg: Message bytes to hash
        prev_hash: Optional previous hash to chain with (for log integrity)
    
    Returns:
        32-byte hash digest
    """
    hasher = blake3.blake3()
    if prev_hash:
        hasher.update(prev_hash)
    hasher.update(msg)
    return hasher.digest()  # 32 bytes


class SecureLogger:
    """Chained, E2EE audit log."""
    def __init__(self, identity: Identity, path: str):
        self.path = path
        self.box = SecretBox(identity.derive_log_key())
        self.prev_hash = b'\x00' * 32  # Genesis
        os.makedirs(os.path.dirname(path), exist_ok=True)

    def log_entry(self, direction: str, peer_pk: bytes, msg: bytes, sent_hash: bytes):
        """Log: timestamp, dir, peer, msg, hash, prev_hash. Chain via BLAKE3."""
        entry = {
            't': time.time(),
            'dir': direction,  
            'peer': peer_pk.hex(),
            'msg': msg.decode('utf-8', errors='ignore'),
            'h': sent_hash.hex(),
            'prev': self.prev_hash.hex()
        }
        data = json.dumps(entry).encode()
        
        # Compute new hash from prev_hash + data
        new_hash = hash_message(data, self.prev_hash)
        self.prev_hash = new_hash

        encrypted = self.box.encrypt(data)
        try:
            with open(self.path, 'ab') as f:
                f.write(encrypted + b'\n')
        except (OSError, IOError) as e:
            # Log write failures are critical but shouldn't crash the app
            # In production, consider using a logging framework
            raise IOError(f"Failed to write log entry: {e}") from e

    def verify_chain(self) -> bool:
        """Verify log integrity (for demo/export).
        
        Optimized to read file in chunks for better performance on large logs.
        
        Returns:
            True if chain is valid, False otherwise
        """
        prev_hash = b'\x00' * 32
        try:
            with open(self.path, 'rb') as f:
                # Read file in chunks for efficiency
                buffer = b''
                for chunk in iter(lambda: f.read(8192), b''):
                    buffer += chunk
                    # Process complete lines
                    while b'\n' in buffer:
                        line, buffer = buffer.split(b'\n', 1)
                        if not line.strip():
                            continue
                        try:
                            data = self.box.decrypt(line.strip())
                            entry = json.loads(data)
                            
                            # Verify previous hash matches
                            if bytes.fromhex(entry['prev']) != prev_hash:
                                return False
                            
                            # Compute expected hash
                            expected = hash_message(data, prev_hash)
                            prev_hash = expected
                        except (ValueError, TypeError, json.JSONDecodeError, KeyError):
                            # ValueError: decryption failed or hex decode failed
                            # TypeError: invalid types
                            # json.JSONDecodeError: malformed JSON
                            # KeyError: missing required fields
                            return False
                # Process remaining buffer
                if buffer.strip():
                    try:
                        data = self.box.decrypt(buffer.strip())
                        entry = json.loads(data)
                        if bytes.fromhex(entry['prev']) != prev_hash:
                            return False
                    except (ValueError, TypeError, json.JSONDecodeError, KeyError):
                        return False
            return True
        except FileNotFoundError:
            return True  # Empty log is valid
        except (OSError, IOError):
            # File system errors
            return False
