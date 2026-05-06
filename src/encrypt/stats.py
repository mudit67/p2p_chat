"""Network statistics: packet counters and RTT latency via PING/PONG."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, Optional

from nacl.utils import random as nacl_random

from .protocol import (
    pack_stats_ping,
    pack_stats_pong,
    unpack_stats_ping,
    unpack_stats_pong,
)
from .udp_transport import UdpTransport


@dataclass
class PeerStats:
    username: str
    packets_sent: int = 0
    packets_received: int = 0
    last_rtt_ms: Optional[float] = None
    rtt_samples: list[float] = field(default_factory=list)

    @property
    def avg_rtt_ms(self) -> Optional[float]:
        if not self.rtt_samples:
            return None
        return sum(self.rtt_samples) / len(self.rtt_samples)


class StatsTracker:
    """Tracks per-peer packet counts and measures RTT via STATS_PING/STATS_PONG."""

    def __init__(self, transport: UdpTransport, my_pk: bytes):
        self.transport = transport
        self.my_pk = my_pk
        self._peers: Dict[bytes, PeerStats] = {}
        self._pending_pings: Dict[bytes, tuple[float, bytes]] = {}  # ping_id -> (sent_ts, peer_pk)
        self._on_rtt: Optional[Callable[[str, float], None]] = None

    def set_on_rtt(self, callback: Callable[[str, float], None]) -> None:
        """Register callback(username, rtt_ms) called when a PONG is received."""
        self._on_rtt = callback

    def register_peer(self, peer_pk: bytes, username: str) -> None:
        if peer_pk not in self._peers:
            self._peers[peer_pk] = PeerStats(username=username)

    def record_sent(self, peer_pk: bytes) -> None:
        if peer_pk in self._peers:
            self._peers[peer_pk].packets_sent += 1

    def record_received(self, peer_pk: bytes) -> None:
        if peer_pk in self._peers:
            self._peers[peer_pk].packets_received += 1

    def get_stats(self, peer_pk: bytes) -> Optional[PeerStats]:
        return self._peers.get(peer_pk)

    def all_stats(self) -> Dict[bytes, PeerStats]:
        return dict(self._peers)

    def send_ping(self, peer_addr: tuple[str, int], peer_pk: bytes) -> None:
        """Send a STATS_PING to measure RTT."""
        ping_id = nacl_random(8)
        packet = pack_stats_ping(ping_id, self.my_pk)
        self._pending_pings[ping_id] = (time.time(), peer_pk)
        self.transport.send(packet, peer_addr)

    def handle_packet(self, data: bytes, addr: tuple[str, int]) -> bool:
        """
        Try to handle data as STATS_PING or STATS_PONG.
        Returns True if packet was consumed.
        """
        ping = unpack_stats_ping(data)
        if ping:
            self._handle_ping(ping, addr)
            return True

        pong = unpack_stats_pong(data)
        if pong:
            self._handle_pong(pong)
            return True

        return False

    def _handle_ping(self, msg: dict, addr: tuple[str, int]) -> None:
        """Reply with a PONG echoing the original timestamp."""
        pong = pack_stats_pong(
            ping_id=bytes(msg["id"]),
            sender_pk=self.my_pk,
            original_ts=float(msg["t"]),
        )
        self.transport.send(pong, addr)

    def _handle_pong(self, msg: dict) -> None:
        """Compute RTT from the echoed timestamp."""
        ping_id = bytes(msg["id"])
        pending = self._pending_pings.pop(ping_id, None)
        if pending is None:
            return

        sent_ts, peer_pk = pending
        rtt_ms = (time.time() - sent_ts) * 1000.0

        peer = self._peers.get(peer_pk)
        if peer:
            peer.last_rtt_ms = rtt_ms
            peer.rtt_samples.append(rtt_ms)
            if len(peer.rtt_samples) > 20:  # keep last 20 samples
                peer.rtt_samples.pop(0)
            if self._on_rtt:
                self._on_rtt(peer.username, rtt_ms)

    async def ping_loop(self, get_peers: Callable[[], Dict[bytes, tuple[str, tuple[str, int]]]], interval: float = 5.0) -> None:
        """
        Periodically ping all known peers.
        get_peers() must return {peer_pk: (username, addr)}.
        """
        while True:
            try:
                await asyncio.sleep(interval)
                for peer_pk, (username, addr) in get_peers().items():
                    self.register_peer(peer_pk, username)
                    self.send_ping(addr, peer_pk)
            except asyncio.CancelledError:
                break
