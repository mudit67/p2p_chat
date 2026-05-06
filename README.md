# E2EE LAN UDP Multi-Peer Chat

A peer-to-peer encrypted chat application using X25519 key exchange, XChaCha20-Poly1305 authenticated encryption, and UDP multicast for local network discovery. Built with Textual TUI for interactive multi-peer messaging.

## Current Capabilities

- **UDP Multicast Discovery** - Automatic LAN peer discovery via multicast (239.255.255.250:5353)
- **Direct P2P Messaging** - No central relay required; messages go directly between peers
- **X25519 Session Keys** - Per-peer session keys (`tx`/`rx`) derived from ECDH key exchange
- **Authenticated Encryption** - XChaCha20-Poly1305 with per-message integrity hashing
- **Reliable UDP Delivery** - Retry mechanism with ACK/NACK flow for lossy networks
- **Tamper Detection** - Message hashing and cryptographic verification detect packet modification
- **Encrypted Audit Logs** - Chained audit logs with integrity verification (press `L` to verify)
- **Multi-Client Support** - Run any number of clients simultaneously
- **Relay Fallback** - TLS relay server available for non-UDP scenarios

## Quick Start

### 1. Setup

```bash
chmod +x bootstrap.sh
./bootstrap.sh
```

### 2. Create Client Keys

Pre-generated keys include alice, bob, candy, dave, eve, frank, grace. To add more:

```bash
python3 -m src.encrypt.keygen henry iris jack
```

This creates `keys/henry.json`, `keys/iris.json`, `keys/jack.json`.

### 3. Run Multiple Clients

Open separate terminals and start clients on different UDP ports:

```bash
# Terminal 1
python3 -m src.encrypt.client alice udp 9001

# Terminal 2
python3 -m src.encrypt.client bob udp 9002

# Terminal 3
python3 -m src.encrypt.client candy udp 9003

# Terminal 4
python3 -m src.encrypt.client dave udp 9004
```

All peers auto-discover each other within ~1 second via UDP multicast.

## Message Flow

When you send a message:

1. **Encryption** - Message is encrypted with recipient's session key (X25519 derived)
2. **Hashing** - SHA-256 hash created for integrity verification
3. **Packaging** - UDP packet assembled with msg_id, sequence, and metadata
4. **Transmission** - Packet sent to peer's UDP port
5. **Retry Loop** - If no ACK, retries up to 3 times with 1.5s intervals
6. **Peer Receipt** - Recipient decrypts, verifies hash, and sends ACK
7. **Status** - Message marked as ✓ when ACK received, or ✗ if delivery fails

## Client Usage

### Basic Commands

- **Send to all peers**: Type message and press Enter
- **Send to specific peer**: `/to <peer8> <message>` where `peer8` is first 8 hex chars of peer's public key
- **Verify audit log**: Press `L` to verify encrypted message history

### UI Layout

```
┌─ Peers ─────────────┐                    ┌─ Chat Log ──────────────┐
│ * alice  0665eef4  2s │                    │ bob: hello alice        │
│   bob    43374bce  5s │                    │ [green]ACK[/] bob       │
│   candy  300d1b10  0s │  Type message... │ alice: hi everyone!     │
└──────────────────────┘   [Send]            └─────────────────────────┘
```

- Left panel: List of discovered peers (age in seconds, `*` = selected)
- Right panel: Chat log with messages and ACK status
- Bottom: Input box for composing messages

## Relay Fallback Mode

For scenarios where direct UDP doesn't work:

```bash
# Terminal 1 - Start relay server
python3 -m src.encrypt.server

# Terminal 2 - Client via relay
python3 -m src.encrypt.client alice relay

# Terminal 3
python3 -m src.encrypt.client bob relay
```

Relay mode uses TLS for transport security but requires `/to <peer8>` format for messaging.

## Testing

Run smoke tests to verify crypto and protocol:

```bash
python3 tests/smoke_udp.py
```

Debug utilities:

```bash
python3 debug_keys.py                    # Show key info
python3 debug_discovery.py               # Test UDP multicast
python3 test_discovery.py                # Integration test
```

## Architecture

### Core Components

| Module | Purpose |
|--------|---------|
| `client.py` | TUI application, message handling, display |
| `discovery.py` | UDP multicast peer discovery (239.255.255.250:5353) |
| `udp_transport.py` | UDP socket management, replay deduplication |
| `protocol.py` | Msgpack message format (presence, msg, ack) |
| `crypto.py` | X25519 key exchange, XChaCha20 encryption, SHA-256 hashing |
| `server.py` | TLS relay server (fallback mode) |

### Message Format

All messages use MessagePack binary format:

- **Presence** - Announces peer availability and listening port
- **UDP Message** - Encrypted payload with sender/recipient PKs, hash, sequence number
- **ACK** - Confirms receipt via message ID and hash

### Cryptography

- **Key Exchange** - X25519 ECDH per peer (derives tx_key and rx_key)
- **Encryption** - XChaCha20-Poly1305 (authenticated encryption)
- **Hashing** - SHA-256 (per-message integrity verification)
- **Replay Protection** - msg_id deduplication + timestamp validation (60s window)

## Security Notes

⚠️ **Demo/POC Implementation** - Not production-ready

- Keys stored as plain JSON files (use secure key storage in production)
- LAN-first design; no internet-grade NAT traversal or firewall punching
- Relay mode uses demo-grade TLS settings (verify_mode=CERT_NONE)
- No forward secrecy; compromise of long-term keys compromises all past messages

## Project Structure

```
.
├── src/encrypt/
│   ├── client.py          # TUI & message handling
│   ├── discovery.py       # Multicast discovery
│   ├── udp_transport.py   # UDP socket layer
│   ├── protocol.py        # MessagePack wire format
│   ├── crypto.py          # Encryption & key exchange
│   ├── keygen.py          # Key generation utility
│   └── server.py          # Relay server
├── tests/
│   └── smoke_udp.py       # Crypto & protocol tests
├── keys/
│   ├── alice.json         # Pre-generated identities
│   ├── bob.json
│   └── ...
├── logs/
│   ├── alice.log          # Encrypted audit trails
│   └── bob.log
└── README.md
```

## Troubleshooting

### Peers Not Discovering Each Other

- Check that all clients are on same network
- Verify multicast is not blocked by firewall (UDP port 5353)
- Run `python3 test_discovery.py` to debug

### Messages Not Delivered

- Ensure recipient's client is still running
- Check UDP port is open and not in use
- Delivery will retry 3 times, then fail after ~4.5 seconds
- Relay fallback available if UDP is problematic

### Performance Issues

- Multicast discovery runs every 2 seconds (tunable in LanDiscovery)
- UDP retry interval is 1.5 seconds (tunable in _send_udp_with_retry)
- Audit log verification is on-demand (press `L`)

