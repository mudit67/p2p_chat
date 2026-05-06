"""
TUI Client: Textual app with async network task. Handles connect, send/recv, leak detection, logging.
"""

import ssl
import asyncio
import time
import sys
import msgpack
from pathlib import Path
from typing import Optional
from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, Input, Button, Static, RichLog
from textual.reactive import reactive
from textual.message import Message
from textual import on
from .crypto import Identity, key_exchange, key_exchange_server, encrypt, decrypt, hash_message, SecureLogger, PublicKey
from .protocol import pack_connect, pack_message, unpack_message, pack_ack, unpack_ack, MSG_TYPES


class LeakAlert(Message):
    """Custom alert for hash mismatch/tamper."""
    pass


class StatusBar(Static):
    """Reactive status bar."""
    pass


class ChatApp(App):
    CSS = """
    RichLog {
        height: 1fr;
        background: $panel;
    }
    Input {
        dock: bottom;
        width: 1fr;
    }
    Button {
        dock: bottom;
        margin-left: 1;
        width: auto;
    }
    StatusBar {
        dock: bottom;
        height: 1;
        background: $accent;
        padding: 0 1;
    }
    """

    BINDINGS = [
        ("ctrl+c", "quit", "Quit"),
        ("l", "verify_log", "Verify Log"),
    ]

    connected = reactive(False)
    peer_pk: Optional[bytes] = None
    identity: Identity
    logger: SecureLogger
    reader: Optional[asyncio.StreamReader] = None
    writer: Optional[asyncio.StreamWriter] = None
    tx_key: Optional[bytes] = None  # For sending
    rx_key: Optional[bytes] = None  # For receiving
    pending_acks: dict[bytes, asyncio.Future] = {}  # Hash -> Future for ACK

    def __init__(self, user: str, host: str = '127.0.0.1', port: int = 8888):
        super().__init__()
        self.user = user
        self.host = host
        self.port = port
        self.pending_acks = {}  # Initialize here
        key_path = Path('keys') / f'{user}.json'
        self.identity = Identity.load(str(key_path))
        log_path = Path('logs') / f'{user}.log'
        self.logger = SecureLogger(self.identity, str(log_path))

    def compose(self) -> ComposeResult:
        yield Header()
        yield RichLog(id='chatlog', highlight=True, markup=True)
        yield Input(placeholder="Type message...", id='input')
        yield Button("Send", id='send')
        yield StatusBar("Disconnected", id='status')
        yield Footer()

    def on_mount(self) -> None:
        self.write_log("Connecting...")
        asyncio.create_task(self.connect())

    async def connect(self):
        try:
            # Create SSL context
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE
            
            self.reader, self.writer = await asyncio.open_connection(
                self.host, self.port, ssl=ssl_ctx
            )

            # Handshake: Send PK
            self.writer.write(pack_connect(self.identity.pk.encode()))
            await self.writer.drain()

            # Recv connect ack
            ack_data = await self.reader.read(1024)
            if not ack_data:
                raise Exception("No ACK received from server")
            unpack_ack(ack_data)

            # Load peer identity
            peer_key_path = Path('keys') / ('bob.json' if self.user == 'alice' else 'alice.json')
            peer_id = Identity.load(str(peer_key_path))
            self.peer_pk = peer_id.pk.encode()
            
            # Derive session keys
            # For key exchange to work, both parties must agree on roles:
            # - The party with the lexicographically smaller public key is "client"
            # - The party with the larger public key is "server"
            my_pk = self.identity.pk.encode()
            
            # Determine roles based on public key comparison
            i_am_client = my_pk < self.peer_pk
            
            if i_am_client:
                # I'm client, peer is server
                self.tx_key, self.rx_key = key_exchange(
                    self.identity.sk, 
                    self.identity.pk, 
                    PublicKey(self.peer_pk)
                )
                self.write_log(f"[dim]Role: CLIENT | TX={self.tx_key.hex()[:16]}... RX={self.rx_key.hex()[:16]}...[/]")
            else:
                # I'm server, peer is client
                self.tx_key, self.rx_key = key_exchange_server(
                    self.identity.sk,
                    self.identity.pk,
                    PublicKey(self.peer_pk)
                )
                self.write_log(f"[dim]Role: SERVER | TX={self.tx_key.hex()[:16]}... RX={self.rx_key.hex()[:16]}...[/]")

            self.connected = True
            self.query_one('#status', StatusBar).update("Connected")
            self.write_log(f"Secure session with {self.peer_pk.hex()[:8]}...")

            # Start receive loop
            asyncio.create_task(self.receive_loop())
            
        except FileNotFoundError as e:
            self.write_log(f"[red]Error: Peer key file not found - {e}[/]")
            self.query_one('#status', StatusBar).update("Key Error")
        except (ConnectionError, OSError, ssl.SSLError, ValueError) as e:
            self.write_log(f"[red]Connection failed: {e}[/]")
            self.query_one('#status', StatusBar).update("Connection Failed")
        except Exception as e:
            # Catch-all for unexpected errors
            self.write_log(f"[red]Unexpected error: {e}[/]")
            self.query_one('#status', StatusBar).update("Error")

    async def receive_loop(self):
        if not self.reader:
            return
            
        while self.connected:
            try:
                data = await self.reader.read(4096)
                if not data:
                    break
                
                # First try to unpack and check type
                try:
                    raw_msg = msgpack.unpackb(data, raw=False)
                    msg_type = raw_msg.get('type')
                    
                    # Route based on message type
                    if msg_type == MSG_TYPES['msg']:
                        msg = unpack_message(data)
                        if msg:
                            await self.handle_message(msg)
                    elif msg_type == MSG_TYPES['ack']:
                        ack_hash = unpack_ack(data)
                        if ack_hash:
                            await self.handle_ack(ack_hash)
                    else:
                        self.write_log(f"[yellow]Unknown message type: {msg_type}[/]")
                        
                except (msgpack.exceptions.ExtraData, msgpack.exceptions.UnpackException, ValueError, TypeError) as e:
                    self.write_log(f"[yellow]Failed to parse message: {e}[/]")
                    continue

            except (ConnectionError, OSError, asyncio.IncompleteReadError) as e:
                self.write_log(f"[red]Recv error: {e}[/]")
                break
            except asyncio.CancelledError:
                # Task was cancelled
                break

        self.connected = False
        # Clean up pending ACKs on disconnect
        for future in self.pending_acks.values():
            if not future.done():
                future.cancel()
        self.pending_acks.clear()
        
        # Close writer if still open
        if self.writer:
            try:
                self.writer.close()
                await self.writer.wait_closed()
            except (OSError, asyncio.CancelledError):
                pass
            finally:
                self.writer = None
                self.reader = None
        
        self.query_one('#status', StatusBar).update("Disconnected")

    async def handle_message(self, msg: dict) -> None:
        """Handle incoming encrypted message."""
        ct = bytes(msg['c'])
        
        # Type guard for rx_key
        if not self.rx_key:
            self.write_log("[red]Error: No receive key available[/]")
            return
        
        try:
            plain = decrypt(self.rx_key, ct)
        except Exception as e:
            self.write_log(f"[red]Decryption error: {e}[/]")
            self.post_message(LeakAlert())
            return
        
        if plain is None:
            self.post_message(LeakAlert())
            self.write_log("[red]DECRYPT FAILED: Potential leak/tamper![/]")
            self.write_log(f"[dim]Debug: Ciphertext length: {len(ct)}, RX key length: {len(self.rx_key) if self.rx_key else 0}[/]")
            self.write_log("[yellow]Tip: Run 'python debug_keys.py' to verify key exchange[/]")
            return

        computed_hash = hash_message(plain)
        if computed_hash != bytes(msg['h']):
            self.post_message(LeakAlert())
            self.write_log("[red]HASH MISMATCH: Message altered in transit![/]")
            return

        # Type guard for peer_pk
        if not self.peer_pk:
            self.write_log("[red]Error: No peer public key[/]")
            return

        self.write_log(f"[blue]{self.peer_pk.hex()[:8]}[/]: {plain.decode()}")
        self.logger.log_entry('<<', self.peer_pk, plain, bytes(msg['h']))

    async def handle_ack(self, ack_hash: bytes) -> None:
        """Handle ACK response."""
        if ack_hash in self.pending_acks:
            future = self.pending_acks.pop(ack_hash)
            if not future.done():
                try:
                    future.set_result(ack_hash)
                except asyncio.InvalidStateError:
                    # Future already completed/cancelled
                    pass

    @on(Button.Pressed, "#send")
    @on(Input.Submitted, "#input")
    async def send_message(self, event: Button.Pressed | Input.Submitted) -> None:
        input_widget = self.query_one('#input', Input)
        msg = input_widget.value.strip()
        
        if not msg or not self.connected:
            return

        # Type guards
        if not self.tx_key or not self.peer_pk or not self.writer:
            self.write_log("[red]Error: Connection not properly established[/]")
            return

        input_widget.value = ''
        msg_bytes = msg.encode()

        try:
            # Hash before encrypt
            msg_hash = hash_message(msg_bytes)

            # Encrypt using tx_key
            ct = encrypt(self.tx_key, msg_bytes)

            # Create future for ACK
            ack_future = asyncio.get_event_loop().create_future()
            self.pending_acks[msg_hash] = ack_future

            # Pack & send
            self.writer.write(pack_message(self.peer_pk, msg_hash, ct, time.time()))
            await self.writer.drain()

            self.write_log(f"[green]>>[/] {msg}")
            self.logger.log_entry('>>', self.peer_pk, msg_bytes, msg_hash)

            # Wait for ack with timeout
            try:
                received_hash = await asyncio.wait_for(ack_future, timeout=5.0)
                
                if received_hash != msg_hash:
                    self.post_message(LeakAlert())
                    self.write_log("[red]ACK HASH MISMATCH: Server tamper detected![/]")
            except asyncio.TimeoutError:
                self.write_log("[yellow]Warning: ACK timeout[/]")
                if msg_hash in self.pending_acks:
                    del self.pending_acks[msg_hash]
                
        except (ConnectionError, OSError, ValueError) as e:
            self.write_log(f"[red]Send error: {e}[/]")
            if msg_hash in self.pending_acks:
                del self.pending_acks[msg_hash]

    async def on_leak_alert(self, message: LeakAlert) -> None:
        self.bell()
        self.query_one('#status', StatusBar).update("[red]LEAK DETECTED![/]")

    def action_verify_log(self) -> None:
        """Verify log chain integrity."""
        if self.logger.verify_chain():
            self.write_log("[green]✓ Log chain verified OK[/]")
        else:
            self.write_log("[red]✗ Log chain broken![/]")

    def write_log(self, text: str) -> None:
        """Write to chat log (renamed to avoid conflict with Textual's log)."""
        chat_log = self.query_one('#chatlog', RichLog)
        chat_log.write(text)


def main():
    """Entry point for client."""
    if len(sys.argv) < 2:
        print("Usage: python -m src.encrypt.client <username>")
        print("Example: python -m src.encrypt.client alice")
        sys.exit(1)
        
    user = sys.argv[1]
    app = ChatApp(user)
    app.run()


if __name__ == '__main__':
    main()
