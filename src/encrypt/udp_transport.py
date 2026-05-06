"""UDP transport with packet queueing and replay dedupe."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from typing import Optional


class _DatagramProtocol(asyncio.DatagramProtocol):
    def __init__(self, on_packet: Callable[[bytes, tuple[str, int]], None]):
        self.on_packet = on_packet

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        self.on_packet(data, addr)


class UdpTransport:
    def __init__(self, bind_host: str, bind_port: int, dedupe_ttl_seconds: float = 120.0):
        self.bind_host = bind_host
        self.bind_port = bind_port
        self.dedupe_ttl_seconds = dedupe_ttl_seconds
        self.transport: Optional[asyncio.DatagramTransport] = None
        self.packet_queue: asyncio.Queue[tuple[bytes, tuple[str, int]]] = asyncio.Queue()
        self._seen_ids: dict[bytes, float] = {}

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(
            lambda: _DatagramProtocol(self._on_packet),
            local_addr=(self.bind_host, self.bind_port),
            allow_broadcast=True,
        )
        self.transport = transport

    def close(self) -> None:
        if self.transport is not None:
            self.transport.close()
            self.transport = None

    def _on_packet(self, data: bytes, addr: tuple[str, int]) -> None:
        self.packet_queue.put_nowait((data, addr))

    async def recv(self) -> tuple[bytes, tuple[str, int]]:
        return await self.packet_queue.get()

    def send(self, data: bytes, addr: tuple[str, int]) -> None:
        if self.transport is None:
            raise RuntimeError("UDP transport is not started")
        self.transport.sendto(data, addr)

    def mark_seen(self, msg_id: bytes) -> None:
        self._seen_ids[msg_id] = time.time() + self.dedupe_ttl_seconds
        self._cleanup_seen()

    def is_duplicate(self, msg_id: bytes) -> bool:
        expiry = self._seen_ids.get(msg_id)
        if expiry is None:
            return False
        if expiry < time.time():
            del self._seen_ids[msg_id]
            return False
        return True

    def _cleanup_seen(self) -> None:
        now = time.time()
        expired = [msg_id for msg_id, expiry in self._seen_ids.items() if expiry < now]
        for msg_id in expired:
            del self._seen_ids[msg_id]
