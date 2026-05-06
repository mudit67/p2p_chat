"""LAN discovery via UDP multicast presence beacons."""

from __future__ import annotations

import asyncio
import socket
import struct
from collections.abc import Callable
from typing import Optional

from .protocol import pack_presence, unpack_presence

# Use mDNS-like multicast address (not actually mDNS, but similar principle)
DISCOVERY_MULTICAST_GROUP = "239.255.255.250"
DISCOVERY_MULTICAST_PORT = 5353


class LanDiscovery:
    def __init__(
        self,
        username: str,
        public_key: bytes,
        listen_port: int,
        discovery_port: int = DISCOVERY_MULTICAST_PORT,
        interval_seconds: float = 2.0,
        broadcast_addr: str = DISCOVERY_MULTICAST_GROUP,
    ):
        self.username = username
        self.public_key = public_key
        self.listen_port = listen_port
        self.discovery_port = discovery_port
        self.interval_seconds = interval_seconds
        self.broadcast_addr = broadcast_addr
        self.sock: Optional[socket.socket] = None
        self._running = False
        self._tx_task: Optional[asyncio.Task[None]] = None
        self._rx_task: Optional[asyncio.Task[None]] = None

    async def start(self, on_presence: Callable[[dict, tuple[str, int]], None]) -> None:
        if self._running:
            return
        
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        # Allow multicast socket reuse on macOS
        if hasattr(socket, 'SO_REUSEPORT'):
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        
        # Bind to the multicast port (allows multiple processes to bind)
        self.sock.bind(("", self.discovery_port))
        
        # Join multicast group
        mreq = struct.pack("4sl", socket.inet_aton(self.broadcast_addr), socket.INADDR_ANY)
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        
        # Enable multicast loopback for localhost testing
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
        
        # Set multicast TTL
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        
        self.sock.setblocking(False)
        self._running = True
        self._tx_task = asyncio.create_task(self._tx_loop())
        self._rx_task = asyncio.create_task(self._rx_loop(on_presence))

    async def stop(self) -> None:
        self._running = False
        for task in (self._tx_task, self._rx_task):
            if task:
                task.cancel()
        if self.sock:
            self.sock.close()
            self.sock = None

    async def _tx_loop(self) -> None:
        if not self.sock:
            return
        loop = asyncio.get_running_loop()
        payload = pack_presence(self.username, self.public_key, self.listen_port)
        while self._running:
            try:
                await loop.sock_sendto(self.sock, payload, (self.broadcast_addr, self.discovery_port))
            except (OSError, ConnectionError):
                # Transient send errors are non-fatal, continue broadcasting
                pass
            await asyncio.sleep(self.interval_seconds)

    async def _rx_loop(self, on_presence: Callable[[dict, tuple[str, int]], None]) -> None:
        if not self.sock:
            return
        loop = asyncio.get_running_loop()
        while self._running:
            try:
                data, addr = await loop.sock_recvfrom(self.sock, 4096)
                presence = unpack_presence(data)
                if presence:
                    on_presence(presence, addr)
            except (ConnectionError, BrokenPipeError):
                # These indicate the socket is truly broken
                break
            except (OSError, asyncio.CancelledError):
                # OSError can include EAGAIN which is normal for non-blocking sockets
                # CancelledError is expected when stopping
                if not self._running:
                    break
                # Otherwise just continue - asyncio.sock_recvfrom handles non-blocking properly
                await asyncio.sleep(0.01)
