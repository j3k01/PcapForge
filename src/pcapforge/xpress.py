"""Xpress compression as WSUS uses it for SOAP responses ([MS-WUSP] section 2.1.1).

The input is cut into blocks of at most 65535 bytes (the Windows block size). Each block is
LZ77-compressed with the DIRECT2 encoding (CompressOrDecompressWin2k3, the "plain LZ77" of
[MS-XCA]) and prefixed with its original and compressed size as little-endian 32-bit integers.

DIRECT2: a 32-bit little-endian bitmask precedes every 32 elements, its most significant bit
describing the first element (0 = a literal byte, 1 = a match); a 1 after the last element marks
the end. A match is two little-endian bytes, the high 13 bits the offset minus one (an 8 KiB
window), the low 3 bits the length minus three; the value 7 extends the length into a nibble
shared by two long matches (the first takes the low nibble of a new byte, the second the high
one), 15 there into a further byte, and 255 there into a final 16-bit length minus three.
"""

from __future__ import annotations

import struct

BLOCK = 65535
WINDOW = 8192
MIN_MATCH = 3
MAX_MATCH = 65535 + MIN_MATCH
CANDIDATES = 32  # previous positions of the same 3-byte prefix tried per match


def _compress_block(data: bytes) -> bytes:
    out = bytearray(4)
    flag_at, flags, count = 0, 0, 0
    nibble_at: int | None = None
    chains: dict[bytes, list[int]] = {}
    n = len(data)
    i = 0

    def remember(pos: int) -> None:
        if pos + MIN_MATCH <= n:
            chains.setdefault(data[pos:pos + MIN_MATCH], []).append(pos)

    while i < n:
        best_len, best_off = 0, 0
        if i + MIN_MATCH <= n:
            for p in reversed(chains.get(data[i:i + MIN_MATCH], [])[-CANDIDATES:]):
                if i - p > WINDOW:
                    break
                length = MIN_MATCH
                limit = min(n - i, MAX_MATCH)
                while length < limit and data[p + length] == data[i + length]:
                    length += 1
                if length > best_len:
                    best_len, best_off = length, i - p
                    if length == limit:
                        break
        if best_len >= MIN_MATCH:
            extra = best_len - MIN_MATCH
            out += struct.pack("<H", ((best_off - 1) << 3) | min(extra, 7))
            if extra >= 7:
                extra -= 7
                if nibble_at is None:
                    nibble_at = len(out)
                    out.append(min(extra, 15))
                else:
                    out[nibble_at] |= min(extra, 15) << 4
                    nibble_at = None
                if extra >= 15:
                    extra -= 15
                    if extra < 255:
                        out.append(extra)
                    else:
                        out.append(255)
                        out += struct.pack("<H", best_len - MIN_MATCH)
            flags |= 1 << (31 - count)
            for pos in range(i, i + best_len):
                remember(pos)
            i += best_len
        else:
            out.append(data[i])
            remember(i)
            i += 1
        count += 1
        if count == 32:
            out[flag_at:flag_at + 4] = struct.pack("<I", flags)
            flag_at, flags, count = len(out), 0, 0
            out += bytes(4)
    flags |= (1 << (32 - count)) - 1  # the end marker: a 1 after the last element (the rest unused)
    out[flag_at:flag_at + 4] = struct.pack("<I", flags)
    return bytes(out)


def compress(data: bytes) -> bytes:
    """``data`` as a sequence of (original size, compressed size, block) Xpress blocks."""
    out = bytearray()
    for start in range(0, len(data), BLOCK):
        block = _compress_block(data[start:start + BLOCK])
        out += struct.pack("<ii", min(BLOCK, len(data) - start), len(block)) + block
    return bytes(out)


def _decompress_block(data: bytes, size: int) -> bytes:
    out = bytearray()
    i, nibble_at = 0, None
    flags, count = 0, 0
    while len(out) < size:
        if count == 0:
            flags = struct.unpack_from("<I", data, i)[0]
            i += 4
            count = 32
        count -= 1
        if not flags & (1 << count):
            out.append(data[i])
            i += 1
            continue
        value = struct.unpack_from("<H", data, i)[0]
        i += 2
        offset, length = (value >> 3) + 1, value & 7
        if length == 7:
            if nibble_at is None:
                nibble_at = i
                nibble = data[i] & 15
                i += 1
            else:
                nibble = data[nibble_at] >> 4
                nibble_at = None
            if nibble == 15:
                byte = data[i]
                i += 1
                if byte == 255:
                    length = struct.unpack_from("<H", data, i)[0]
                    i += 2
                else:
                    length = 7 + 15 + byte
            else:
                length = 7 + nibble
        for _ in range(length + MIN_MATCH):
            out.append(out[-offset])
    return bytes(out)


def decompress(data: bytes) -> bytes:
    out = bytearray()
    i = 0
    while i < len(data):
        size, packed = struct.unpack_from("<ii", data, i)
        out += _decompress_block(data[i + 8:i + 8 + packed], size)
        i += 8 + packed
    return bytes(out)
