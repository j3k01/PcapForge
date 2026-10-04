"""Capture file writers: classic pcap and pcapng, Ethernet link type, microsecond timestamps."""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Iterable

from pcapforge import __version__

LINKTYPE_ETHERNET = 1
SNAPLEN = 262144


def write_pcap(path: Path, frames: Iterable[tuple[int, bytes]]) -> None:
    """``frames``: (timestamp in microseconds since the epoch, frame bytes)."""
    record = struct.Struct("<IIII")
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, SNAPLEN, LINKTYPE_ETHERNET))
        for micros, data in frames:
            seconds, fraction = divmod(micros, 1_000_000)
            f.write(record.pack(seconds, fraction, len(data), len(data)))
            f.write(data)


def _block(block_type: int, body: bytes) -> bytes:
    length = 12 + len(body)
    return struct.pack("<II", block_type, length) + body + struct.pack("<I", length)


def _option(code: int, value: bytes) -> bytes:
    return struct.pack("<HH", code, len(value)) + value + b"\x00" * (-len(value) % 4)


def write_pcapng(path: Path, frames: Iterable[tuple[int, bytes]]) -> None:
    end = _option(0, b"")
    shb = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1) + _option(4, f"pcapforge {__version__}".encode()) + end
    idb = struct.pack("<HHI", LINKTYPE_ETHERNET, 0, SNAPLEN) + _option(9, b"\x06") + end  # if_tsresol: µs
    epb = struct.Struct("<IIIII")
    with open(path, "wb") as f:
        f.write(_block(0x0A0D0D0A, shb))
        f.write(_block(1, idb))
        for micros, data in frames:
            body = epb.pack(0, micros >> 32, micros & 0xFFFFFFFF, len(data), len(data))
            f.write(_block(6, body + data + b"\x00" * (-len(data) % 4)))


WRITERS = {"pcap": write_pcap, "pcapng": write_pcapng}
