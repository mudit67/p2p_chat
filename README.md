# E2EE Encrypted Chat System

A secure end-to-end encrypted chat application with a TUI (Text User Interface) built using Python, featuring:

- **X25519 Key Exchange**: Secure key agreement protocol
- **XSalsa20-Poly1305 AEAD**: Authenticated encryption for messages
- **BLAKE3 Hashing**: Fast cryptographic hashing for integrity verification
- **Chained Audit Logs**: Tamper-proof encrypted logging
- **TLS Transport**: Secure transport layer for relay server

## Features

- 🔐 End-to-end encryption (E2EE)
- 🛡️ Tamper detection via hash verification
- 📝 Encrypted audit logging with chain verification
- 🎨 Modern TUI interface using Textual
- ⚡ Async/await for high performance
- 🔄 Automatic key exchange and session management

## Prerequisites

- Python 3.13 or higher
- `uv` package manager (recommended) or `pip`
- OpenSSL (for TLS certificate generation)
- Linux/macOS/WSL (Windows Subsystem for Linux)

## Quick Start

### Option 1: Automated Setup (Recommended)

Run the bootstrap script to set up everything automatically:

```bash
chmod +x bootstrap.sh
./bootstrap.sh
```

This will:
1. Check for `uv` package manager
2. Install dependencies (PyNaCl, blake3, msgpack, textual)
3. Generate TLS certificates
4. Create necessary directories
5. Generate user keypairs (alice and bob)
6. Start the relay server

### Option 2: Manual Setup

#### 1. Install Dependencies

**Using uv (recommended):**
```bash
uv pip install PyNaCl blake3 msgpack textual --system
```

**Using pip:**
```bash
pip install PyNaCl blake3 msgpack textual
```

#### 2. Generate TLS Certificates

```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem \
    -days 365 -nodes -subj "/CN=localhost" -batch
```

#### 3. Create Directories

```bash
mkdir -p keys logs
```

#### 4. Generate User Keypairs

```bash
# Using the keygen module (recommended)
python -m src.encrypt.keygen alice bob

# OR using setup.py
python setup.py alice
python setup.py bob
```

#### 5. Start the Relay Server

```bash
python -m src.encrypt.server
```

The server will start on `127.0.0.1:8888` by default.

## Running the Application

### Start the Relay Server

In one terminal, start the relay server:

```bash
python -m src.encrypt.server
```

You should see:
```
Client connected: ('127.0.0.1', ...)
TLS relay listening on 127.0.0.1:8888
```

### Start Client 1 (Alice)

In a second terminal:

```bash
python -m src.encrypt.client alice
```

### Start Client 2 (Bob)

In a third terminal:

```bash
python -m src.encrypt.client bob
```

## Usage

### Client Interface

Once both clients are connected:

1. **Send Messages**: Type your message and press Enter or click the "Send" button
2. **View Messages**: Messages from the peer appear in blue
3. **Verify Logs**: Press `L` to verify the integrity of your encrypted log chain
4. **Exit**: Press `Ctrl+C` to exit

### Keyboard Shortcuts

- `Ctrl+C`: Quit the application
- `L`: Verify log chain integrity

### Status Indicators

- **Connected**: Green status bar - ready to send/receive
- **Disconnected**: Red status bar - connection lost
- **LEAK DETECTED**: Red alert - tampering or decryption failure detected

## Project Structure

```
encrypt/
├── src/
│   └── encrypt/
│       ├── __init__.py
│       ├── crypto.py          # Cryptographic primitives
│       ├── protocol.py         # Message protocol (msgpack)
│       ├── client.py            # TUI client application
│       ├── server.py            # TLS relay server
│       └── keygen.py            # Key generation utility
├── keys/                        # User keypairs (alice.json, bob.json)
├── logs/                        # Encrypted audit logs
├── cert.pem                     # TLS certificate
├── key.pem                      # TLS private key
├── bootstrap.sh                 # Automated setup script
├── cleanup.sh                   # Server cleanup script
├── debug_keys.py                # Key exchange debugging tool
└── requirements.txt             # Python dependencies
```

## Testing Key Exchange

To verify that key exchange is working correctly:

```bash
python debug_keys.py
```

This will:
- Load Alice and Bob's keys
- Perform key exchange
- Test encryption/decryption in both directions
- Verify key matching

## Troubleshooting

### Port Already in Use

If port 8888 is already in use:

```bash
# Find the process
lsof -i:8888

# Kill it
kill -9 <PID>

# Or use the cleanup script
./cleanup.sh
```

### Missing Keys

If you get "Peer key file not found":

```bash
# Generate keys for both users
python -m src.encrypt.keygen alice bob
```

### SSL Certificate Errors

If the server can't load certificates:

```bash
# Regenerate certificates
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem \
    -days 365 -nodes -subj "/CN=localhost" -batch
```

### Connection Refused

1. Ensure the server is running first
2. Check that both clients are using the same host/port
3. Verify firewall settings

### Import Errors

If you see import errors:

```bash
# Make sure you're in the project root directory
cd /path/to/encrypt

# Install dependencies
uv pip install PyNaCl blake3 msgpack textual --system
```

## Security Notes

⚠️ **Important Security Warnings:**

1. **SSL Certificate Verification**: Currently disabled for demo purposes (`ssl.CERT_NONE`). In production, enable proper certificate verification.

2. **Key Storage**: Private keys are stored in plain JSON files. In production, use secure key storage (HSM, keychain, etc.).

3. **Network Security**: The relay server does not inspect message contents (by design), but ensure proper network security in production.

4. **Log Files**: Audit logs are encrypted, but ensure proper access controls on the `logs/` directory.

## Development

### Running Tests

```bash
# Test key exchange
python debug_keys.py

# Test log verification (from within client)
# Press 'L' key in the client interface
```

### Adding New Users

```bash
# Generate keys for a new user
python -m src.encrypt.keygen charlie

# Start client with new user
python -m src.encrypt.client charlie
```

Note: You'll need to update the client code to handle peer discovery for more than 2 users.

## Architecture

### Key Exchange Flow

1. Client connects to relay server via TLS
2. Client sends public key to server
3. Server acknowledges connection
4. Client loads peer's public key from `keys/` directory
5. Both parties derive session keys using X25519:
   - Lexicographically smaller PK → CLIENT role
   - Lexicographically larger PK → SERVER role
6. Session keys (tx_key, rx_key) are derived for bidirectional communication

### Message Flow

1. **Send**: 
   - Hash plaintext → `msg_hash`
   - Encrypt with `tx_key` → `ciphertext`
   - Pack message with metadata
   - Send to relay server
   - Wait for ACK

2. **Receive**:
   - Receive encrypted message
   - Decrypt with `rx_key`
   - Verify hash matches
   - Log to encrypted audit log
   - Display message

3. **Relay**:
   - Server receives message
   - Validates timestamp (anti-replay)
   - Relays to target client
   - Sends ACK to sender

### Audit Logging

- Each log entry is encrypted with a key derived from the user's private key
- Logs are chained using BLAKE3 hashing (prev_hash → current_hash)
- Tampering detection via chain verification
- Logs stored in `logs/<username>.log`

## License

This project is provided as-is for educational and demonstration purposes.

## Contributing

This is a demonstration project. For production use, consider:
- Adding proper certificate validation
- Implementing user authentication
- Adding multi-user support
- Implementing message persistence
- Adding group chat capabilities

