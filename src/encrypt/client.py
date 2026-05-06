"""Textual client for LAN UDP multi-peer encrypted chat."""

from __future__ import annotations

import asyncio
import ssl
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from nacl.utils import random as nacl_random
from textual import on
from textual.app import App, ComposeResult
from textual.containers import Horizontal
from textual.message import Message
from textual.reactive import reactive
from textual.widgets import Button, Footer, Header, Input, RichLog, Static

from .crypto import (
    Identity,
    PublicKey,
    SecureLogger,
    decrypt,
    encrypt,
    hash_message,
    key_exchange,
    key_exchange_server,
)
from .discovery import LanDiscovery, DISCOVERY_MULTICAST_PORT
from .protocol import (
    MSG_TYPES,
    pack_ack,
    pack_connect,
    pack_message,
    pack_udp_ack,
    pack_udp_message,
    unpack_ack,
    unpack_message,
    unpack_udp_ack,
    unpack_udp_message,
)
from .udp_transport import UdpTransport


class LeakAlert(Message):
    """Custom alert for hash mismatch/tamper."""
    pass


class StatusBar(Static):
    pass


@dataclass
class PeerSession:
    username: str
    pk: bytes
    addr: tuple[str, int]
    tx_key: bytes
    rx_key: bytes
    last_seen: float = field(default_factory=time.time)
    next_seq: int = 1


@dataclass
class PendingDelivery:
    msg_id: bytes
    msg_hash: bytes
    packet: bytes
    addr: tuple[str, int]
    peer_name: str
    message_text: str
    attempts_left: int = 3
    acked: bool = False


class ChatApp(App):
    CSS = """
    #main {
        height: 1fr;
    }
    #peers {
        width: 32;
        border: round $accent;
        padding: 0 1;
    }
    RichLog {
        height: 1fr;
        background: $panel;
    }
    #composer {
        dock: bottom;
        height: 3;
        padding: 0 1;
    }
    #composer Input {
        width: 1fr;
    }
    #composer Button {
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

    # Peer discovery timeout (remove peers not seen for 10 seconds)
    PEER_TIMEOUT_SECONDS = 10.0
    # Cleanup check interval (every 2 seconds)
    PEER_CLEANUP_INTERVAL = 2.0

    connected = reactive(False)
    identity: Identity
    logger: SecureLogger
    udp_transport: Optional[UdpTransport] = None
    discovery: Optional[LanDiscovery] = None
    peers: dict[bytes, PeerSession]
    selected_peer_hex: Optional[str]
    pending_deliveries: dict[bytes, PendingDelivery]
    relay_reader: Optional[asyncio.StreamReader]
    relay_writer: Optional[asyncio.StreamWriter]
    relay_peer_pk: Optional[bytes]

    def __init__(
        self,
        user: str,
        mode: str = "udp",
        host: str = "127.0.0.1",
        relay_port: int = 8888,
        udp_port: int = 9000,
        discovery_port: int = DISCOVERY_MULTICAST_PORT,
    ):
        super().__init__()
        self.user = user
        self.mode = mode
        self.host = host
        self.relay_port = relay_port
        self.udp_port = udp_port
        self.discovery_port = discovery_port
        self.peers = {}
        self.selected_peer_hex = None
        self.pending_deliveries = {}
        self.relay_reader = None
        self.relay_writer = None
        self.relay_peer_pk = None
        self._cleanup_task: Optional[asyncio.Task[None]] = None
        key_path = Path("keys") / f"{user}.json"
        self.identity = Identity.load(str(key_path))
        log_path = Path("logs") / f"{user}.log"
        self.logger = SecureLogger(self.identity, str(log_path))

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="main"):
            yield Static("Peers:\n  (discovering...)", id="peers")
            yield RichLog(id="chatlog", highlight=True, markup=True)
        with Horizontal(id="composer"):
            yield Input(placeholder="Type message or /to <peer8> ...", id="input")
            yield Button("Send", id="send")
        yield StatusBar("Disconnected", id="status")
        yield Footer()

    def on_mount(self) -> None:
        self.write_log(f"Starting in [bold]{self.mode.upper()}[/] mode...")
        asyncio.create_task(self.connect())
        self._cleanup_task = asyncio.create_task(self._peer_cleanup_loop())

    async def connect(self) -> None:
        if self.mode == "udp":
            await self._connect_udp()
        else:
            await self._connect_relay()

    async def _connect_udp(self) -> None:
        self.udp_transport = UdpTransport("0.0.0.0", self.udp_port)
        await self.udp_transport.start()
        self.discovery = LanDiscovery(
            username=self.user,
            public_key=self.identity.pk.encode(),
            listen_port=self.udp_port,
            discovery_port=self.discovery_port,
        )
        await self.discovery.start(self._handle_presence)
        self.connected = True
        self.query_one("#status", StatusBar).update(
            f"UDP connected on :{self.udp_port}, discovery :{self.discovery_port}"
        )
        asyncio.create_task(self.receive_loop())

    async def _connect_relay(self) -> None:
        try:
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE
            self.relay_reader, self.relay_writer = await asyncio.open_connection(
                self.host, self.relay_port, ssl=ssl_ctx
            )
            self.relay_writer.write(pack_connect(self.identity.pk.encode()))
            await self.relay_writer.drain()
            ack_data = await self.relay_reader.read(1024)
            if not ack_data or unpack_ack(ack_data) is None:
                raise ConnectionError("No relay ACK")
            self.connected = True
            self.query_one("#status", StatusBar).update("Relay connected")
            self.write_log("[yellow]Relay fallback mode active (single target with /to <peer8>).[/]")
            asyncio.create_task(self.receive_loop())
        except Exception as exc:
            self.write_log(f"[red]Relay connection failed: {exc}[/]")
            self.query_one("#status", StatusBar).update("Connection Failed")

    def _derive_session(self, peer_pk: bytes) -> tuple[bytes, bytes]:
        my_pk = self.identity.pk.encode()
        if my_pk < peer_pk:
            return key_exchange(self.identity.sk, self.identity.pk, PublicKey(peer_pk))
        return key_exchange_server(self.identity.sk, self.identity.pk, PublicKey(peer_pk))

    def _handle_presence(self, presence: dict, addr: tuple[str, int]) -> None:
        peer_pk = bytes(presence["pk"])
        if peer_pk == self.identity.pk.encode():
            return
        username = str(presence["u"])
        peer_addr = (addr[0], int(presence["p"]))
        is_new_peer = peer_pk not in self.peers
        
        if is_new_peer:
            # New peer discovered
            tx_key, rx_key = self._derive_session(peer_pk)
            self.peers[peer_pk] = PeerSession(
                username=username, pk=peer_pk, addr=peer_addr, tx_key=tx_key, rx_key=rx_key
            )
            self.write_log(f"[green]Discovered peer[/] {username} ({peer_pk.hex()[:8]}) @ {peer_addr}")
        else:
            # Peer reconnected or updated
            peer = self.peers[peer_pk]
            if peer.addr != peer_addr:
                self.write_log(f"[yellow]Peer reconnected[/] {username} @ {peer_addr}")
            peer.username = username  # Update username if changed
            peer.addr = peer_addr
        
        self.peers[peer_pk].last_seen = time.time()
        self._refresh_peers_panel()

    def _refresh_peers_panel(self) -> None:
        panel = self.query_one("#peers", Static)
        now = time.time()
        if not self.peers:
            panel.update("Peers:\n  (discovering...)")
            return
        lines = ["Peers:"]
        for peer in sorted(self.peers.values(), key=lambda p: p.username):
            age = int(now - peer.last_seen)
            marker = "*" if peer.pk.hex()[:8] == self.selected_peer_hex else " "
            # Show status indicator
            status = "✓" if age < 5 else "◐" if age < 10 else "✗"
            lines.append(f"{marker} {status} {peer.username:<8} {peer.pk.hex()[:8]}  {age:>3}s")
        panel.update("\n".join(lines))

    async def receive_loop(self) -> None:
        while self.connected:
            try:
                if self.mode == "udp":
                    if not self.udp_transport:
                        break
                    data, addr = await self.udp_transport.recv()
                    await self._handle_udp_packet(data, addr)
                else:
                    if not self.relay_reader:
                        break
                    data = await self.relay_reader.read(4096)
                    if not data:
                        break
                    await self._handle_relay_packet(data)
            except asyncio.CancelledError:
                break
            except Exception as exc:
                self.write_log(f"[red]Receive loop error: {exc}[/]")
        self.connected = False
        self.query_one("#status", StatusBar).update("Disconnected")

    async def _peer_cleanup_loop(self) -> None:
        """Remove stale peers that haven't been seen in PEER_TIMEOUT_SECONDS."""
        while True:
            try:
                await asyncio.sleep(self.PEER_CLEANUP_INTERVAL)
                now = time.time()
                stale_peers = [
                    pk for pk, peer in self.peers.items()
                    if now - peer.last_seen > self.PEER_TIMEOUT_SECONDS
                ]
                for pk in stale_peers:
                    peer = self.peers.pop(pk)
                    self.write_log(f"[dim]Peer offline[/] {peer.username} ({pk.hex()[:8]}) - not seen for {self.PEER_TIMEOUT_SECONDS}s")
                    # Clear selection if selected peer went offline
                    if peer.pk.hex()[:8] == self.selected_peer_hex:
                        self.selected_peer_hex = None
                    self._refresh_peers_panel()
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.write_log(f"[red]Cleanup loop error: {e}[/]")

    def action_quit(self) -> None:
        """Gracefully shutdown - close discovery and cleanup."""
        self.write_log("[yellow]Shutting down...[/]")
        asyncio.create_task(self._shutdown())

    async def _shutdown(self) -> None:
        """Clean shutdown: stop discovery, close UDP transport, cancel tasks."""
        self.connected = False
        
        # Stop discovery
        if self.discovery:
            await self.discovery.stop()
            self.discovery = None
        
        # Close UDP transport
        if self.udp_transport:
            self.udp_transport.close()
            self.udp_transport = None
        
        # Close relay connection
        if self.relay_writer:
            self.relay_writer.close()
            await self.relay_writer.wait_closed()
            self.relay_reader = None
            self.relay_writer = None
        
        # Cancel cleanup task
        if self._cleanup_task:
            self._cleanup_task.cancel()
        
        # Exit app
        self.exit()

    async def _handle_udp_packet(self, data: bytes, addr: tuple[str, int]) -> None:
        msg = unpack_udp_message(data)
        if msg:
            await self._handle_udp_message(msg, addr)
            return
        ack = unpack_udp_ack(data)
        if ack:
            await self._handle_udp_ack(ack)

    async def _handle_udp_message(self, msg: dict, addr: tuple[str, int]) -> None:
        if not self.udp_transport:
            return
        msg_id = bytes(msg["id"])
        if self.udp_transport.is_duplicate(msg_id):
            return
        self.udp_transport.mark_seen(msg_id)

        sender_pk = bytes(msg["from"])
        peer = self.peers.get(sender_pk)
        if peer is None:
            tx_key, rx_key = self._derive_session(sender_pk)
            peer = PeerSession(
                username=sender_pk.hex()[:8], pk=sender_pk, addr=addr, tx_key=tx_key, rx_key=rx_key
            )
            self.peers[sender_pk] = peer
        peer.addr = addr
        peer.last_seen = time.time()
        self._refresh_peers_panel()

        plain = decrypt(peer.rx_key, bytes(msg["c"]))
        if plain is None:
            self.post_message(LeakAlert())
            self.write_log("[red]DECRYPT FAILED: Potential tamper detected[/]")
            return
        received_hash = bytes(msg["h"])
        if hash_message(plain) != received_hash:
            self.post_message(LeakAlert())
            self.write_log("[red]HASH MISMATCH: Message altered in transit[/]")
            return

        ack = pack_udp_ack(msg_id, received_hash, self.identity.pk.encode())
        self.udp_transport.send(ack, peer.addr)
        text = plain.decode("utf-8", errors="replace")
        self.write_log(f"[blue]{peer.username}[/]: {text}")
        self.logger.log_entry("<<", sender_pk, plain, received_hash)

    async def _handle_udp_ack(self, ack: dict) -> None:
        msg_id = bytes(ack["id"])
        pending = self.pending_deliveries.get(msg_id)
        if not pending:
            return
        if bytes(ack["h"]) != pending.msg_hash:
            self.post_message(LeakAlert())
            self.write_log("[red]ACK HASH MISMATCH: Potential tamper[/]")
            return
        pending.acked = True
        self.write_log(f"[green]ACK[/] {pending.peer_name}: {pending.message_text}")
        del self.pending_deliveries[msg_id]

    async def _handle_relay_packet(self, data: bytes) -> None:
        message = unpack_message(data)
        if message and message.get("type") == MSG_TYPES["msg"]:
            await self._handle_relay_message(message)
            return
        ack_hash = unpack_ack(data)
        if ack_hash:
            for msg_id, pending in list(self.pending_deliveries.items()):
                if pending.msg_hash == ack_hash:
                    pending.acked = True
                    self.write_log(f"[green]ACK[/] relay {pending.peer_name}: {pending.message_text}")
                    del self.pending_deliveries[msg_id]
                    break

    async def _handle_relay_message(self, msg: dict) -> None:
        if self.relay_peer_pk is None:
            sender = bytes(msg["to"]) if isinstance(msg.get("to"), (bytes, bytearray)) else b"relay"
            self.relay_peer_pk = sender
        peer_pk = self.relay_peer_pk
        tx_key, rx_key = self._derive_session(peer_pk)
        plain = decrypt(rx_key, bytes(msg["c"]))
        if plain is None:
            self.post_message(LeakAlert())
            return
        if hash_message(plain) != bytes(msg["h"]):
            self.post_message(LeakAlert())
            return
        self.write_log(f"[blue]{peer_pk.hex()[:8]}[/]: {plain.decode('utf-8', errors='replace')}")
        self.logger.log_entry("<<", peer_pk, plain, bytes(msg["h"]))

    async def _send_udp_with_retry(self, pending: PendingDelivery) -> None:
        if not self.udp_transport:
            return
        while pending.attempts_left > 0 and not pending.acked:
            self.udp_transport.send(pending.packet, pending.addr)
            pending.attempts_left -= 1
            self.write_log(
                f"[dim]sent -> {pending.peer_name} ({3 - pending.attempts_left}/3): {pending.message_text}[/]"
            )
            await asyncio.sleep(1.5)
        if not pending.acked and pending.msg_id in self.pending_deliveries:
            self.write_log(f"[yellow]Delivery failed[/] {pending.peer_name}: {pending.message_text}")
            del self.pending_deliveries[pending.msg_id]

    async def _send_relay(self, peer_pk: bytes, text: str) -> None:
        if not self.relay_writer:
            self.write_log("[red]Relay writer unavailable[/]")
            return
        tx_key, _ = self._derive_session(peer_pk)
        msg_bytes = text.encode()
        msg_hash = hash_message(msg_bytes)
        ct = encrypt(tx_key, msg_bytes)
        self.relay_writer.write(pack_message(peer_pk, msg_hash, ct, time.time()))
        await self.relay_writer.drain()
        self.write_log(f"[green]>>[/] {text}")
        self.logger.log_entry(">>", peer_pk, msg_bytes, msg_hash)

    @on(Button.Pressed, "#send")
    @on(Input.Submitted, "#input")
    async def send_message(self, event: Button.Pressed | Input.Submitted) -> None:
        input_widget = self.query_one("#input", Input)
        msg = input_widget.value.strip()
        if not msg or not self.connected:
            return
        input_widget.value = ""

        target_peer_hex = None
        if msg.startswith("/broadcast "):
            parts = msg.split(maxsplit=1)
            msg = parts[1] if len(parts) > 1 else ""
            if not msg:
                self.write_log("[yellow]Usage: /broadcast <message>[/]")
                return
            # Send to all peers
            if self.mode == "udp":
                await self._send_udp(msg, broadcast=True)
            else:
                await self._send_relay_message(msg)
            return
        elif msg.startswith("/to "):
            parts = msg.split(maxsplit=2)
            if len(parts) < 3:
                self.write_log("[yellow]Usage: /to <peer8> <message>[/]")
                return
            target_peer_hex = parts[1].strip()
            msg = parts[2].strip()
            if not msg:
                return

        if self.mode == "udp":
            await self._send_udp(msg, target_peer_hex=target_peer_hex)
        else:
            await self._send_relay_message(msg)

    async def _send_udp(self, text: str, target_peer_hex: Optional[str] = None, broadcast: bool = False) -> None:
        """Send UDP message to peers.
        
        Args:
            text: Message text
            target_peer_hex: Send only to peer with this hex prefix (unicast)
            broadcast: If True, send to all peers
        """
        if not self.peers:
            self.write_log("[yellow]No peers discovered yet[/]")
            return
        
        # Determine target peers
        if broadcast:
            # Broadcast to all peers
            targets = list(self.peers.values())
            if targets:
                self.write_log(f"[cyan]Broadcasting to {len(targets)} peer(s)[/]")
        elif target_peer_hex:
            # Send to specific peer by hex prefix
            targets = [p for p in self.peers.values() if p.pk.hex()[:8].startswith(target_peer_hex)]
            if not targets:
                self.write_log(f"[yellow]Peer {target_peer_hex} not found[/]")
                return
        else:
            # Default: broadcast to all peers (no auto-selection)
            targets = list(self.peers.values())
            if len(targets) > 1:
                self.write_log(f"[cyan]Broadcasting to {len(targets)} peer(s)[/]")
        msg_bytes = text.encode()
        for peer in targets:
            msg_hash = hash_message(msg_bytes)
            ct = encrypt(peer.tx_key, msg_bytes)
            msg_id = nacl_random(16)
            packet = pack_udp_message(
                msg_id=msg_id,
                seq=peer.next_seq,
                sender_pk=self.identity.pk.encode(),
                to_pk=peer.pk,
                msg_hash=msg_hash,
                ciphertext=ct,
                ts=time.time(),
            )
            peer.next_seq += 1
            self.logger.log_entry(">>", peer.pk, msg_bytes, msg_hash)
            pending = PendingDelivery(
                msg_id=msg_id,
                msg_hash=msg_hash,
                packet=packet,
                addr=peer.addr,
                peer_name=peer.username,
                message_text=text,
            )
            self.pending_deliveries[msg_id] = pending
            asyncio.create_task(self._send_udp_with_retry(pending))

    async def _send_relay_message(self, text: str) -> None:
        peer = self._pick_relay_peer()
        if not peer:
            self.write_log("[yellow]No peer key found for relay mode. Use /to <peer8> ...[/]")
            return
        await self._send_relay(peer, text)

    def _pick_relay_peer(self) -> Optional[bytes]:
        key_dir = Path("keys")
        if not key_dir.exists():
            return None
        target_prefix = self.selected_peer_hex or ""
        for file in key_dir.glob("*.json"):
            if file.stem == self.user:
                continue
            identity = Identity.load(str(file))
            pk = identity.pk.encode()
            if pk.hex().startswith(target_prefix):
                return pk
        return None

    async def on_leak_alert(self, message: LeakAlert) -> None:
        self.bell()
        self.query_one("#status", StatusBar).update("[red]LEAK DETECTED![/]")

    def action_verify_log(self) -> None:
        """Verify log chain integrity."""
        if self.logger.verify_chain():
            self.write_log("[green]✓ Log chain verified OK[/]")
        else:
            self.write_log("[red]✗ Log chain broken![/]")

    def write_log(self, text: str) -> None:
        """Write to chat log (renamed to avoid conflict with Textual's log)."""
        chat_log = self.query_one("#chatlog", RichLog)
        chat_log.write(text)


def main() -> None:
    """Entry point for client."""
    if len(sys.argv) < 2:
        print("Usage: python -m src.encrypt.client <username> [udp|relay] [udp_port]")
        print("Example: python -m src.encrypt.client alice udp 9001")
        sys.exit(1)

    user = sys.argv[1]
    mode = sys.argv[2] if len(sys.argv) > 2 else "udp"
    udp_port = int(sys.argv[3]) if len(sys.argv) > 3 else 9000
    app = ChatApp(user=user, mode=mode, udp_port=udp_port)
    app.run()


if __name__ == "__main__":
    main()
