"""Chunked file transfer over UDP transport."""

from __future__ import annotations

import asyncio
import hashlib
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, Optional

from nacl.utils import random as nacl_random

from .protocol import (
    pack_file_chunk,
    pack_file_meta,
    unpack_file_chunk,
    unpack_file_meta,
)
from .udp_transport import UdpTransport

CHUNK_SIZE = 1024  # bytes


@dataclass
class InboundTransfer:
    transfer_id: bytes
    filename: str
    total_size: int
    total_chunks: int
    expected_checksum: str
    chunks: Dict[int, bytes] = field(default_factory=dict)

    def is_complete(self) -> bool:
        return len(self.chunks) == self.total_chunks

    def reconstruct(self) -> bytes:
        return b"".join(self.chunks[i] for i in range(self.total_chunks))


class FileTransfer:
    """Handles sending and receiving chunked files over UDP."""

    def __init__(self, transport: UdpTransport, my_pk: bytes):
        self.transport = transport
        self.my_pk = my_pk
        self._inbound: Dict[bytes, InboundTransfer] = {}
        self._on_complete: Optional[Callable[[str, bytes, str], None]] = None

    def set_on_complete(self, callback: Callable[[str, bytes, str], None]) -> None:
        """Register callback(filename, data, transfer_id_hex) called when a file is fully received."""
        self._on_complete = callback

    async def send_file(self, filepath: str, peer_addr: tuple[str, int]) -> None:
        """Read file, compute checksum, send FILE_META then FILE_CHUNKs."""
        path = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {filepath}")

        data = path.read_bytes()
        checksum = hashlib.sha256(data).hexdigest()
        chunks = [data[i : i + CHUNK_SIZE] for i in range(0, len(data), CHUNK_SIZE)]
        total_chunks = len(chunks)
        transfer_id = nacl_random(16)

        meta = pack_file_meta(
            transfer_id=transfer_id,
            filename=path.name,
            total_size=len(data),
            total_chunks=total_chunks,
            checksum=checksum,
            sender_pk=self.my_pk,
        )
        self.transport.send(meta, peer_addr)
        await asyncio.sleep(0.05)  # brief pause before chunks

        for seq, chunk in enumerate(chunks):
            packet = pack_file_chunk(transfer_id, seq, chunk, self.my_pk)
            self.transport.send(packet, peer_addr)
            await asyncio.sleep(0.01)  # avoid flooding

    def handle_packet(self, data: bytes) -> bool:
        """
        Try to handle data as FILE_META or FILE_CHUNK.
        Returns True if packet was consumed.
        """
        meta = unpack_file_meta(data)
        if meta:
            self._handle_meta(meta)
            return True

        chunk = unpack_file_chunk(data)
        if chunk:
            self._handle_chunk(chunk)
            return True

        return False

    def _handle_meta(self, msg: dict) -> None:
        tid = bytes(msg["id"])
        self._inbound[tid] = InboundTransfer(
            transfer_id=tid,
            filename=str(msg["name"]),
            total_size=int(msg["size"]),
            total_chunks=int(msg["chunks"]),
            expected_checksum=str(msg["sha256"]),
        )

    def _handle_chunk(self, msg: dict) -> None:
        tid = bytes(msg["id"])
        transfer = self._inbound.get(tid)
        if transfer is None:
            return  # META not yet received, discard
        seq = int(msg["seq"])
        transfer.chunks[seq] = bytes(msg["data"])

        if transfer.is_complete():
            self._finalize(transfer)

    def _finalize(self, transfer: InboundTransfer) -> None:
        data = transfer.reconstruct()
        actual = hashlib.sha256(data).hexdigest()
        del self._inbound[transfer.transfer_id]

        if actual != transfer.expected_checksum:
            if self._on_complete:
                # Signal integrity failure with empty data
                self._on_complete(transfer.filename, b"", transfer.transfer_id.hex())
            return

        if self._on_complete:
            self._on_complete(transfer.filename, data, transfer.transfer_id.hex())
