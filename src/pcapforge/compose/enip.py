"""EtherNet/IP payload rewrites: the socket address a ListIdentity reply announces."""

from __future__ import annotations

import struct

_ENCAP = struct.Struct("<HH")    # command, length (of the 24-byte encapsulation header)
_ENCAP_HEADER = 24
_ITEM = struct.Struct("<HH")     # CPF item type id, length
LIST_IDENTITY = 0x0063
CIP_IDENTITY_ITEM = 0x000C
_SIN_ADDR = 2 + 4                # encapsulation version, sin_family, sin_port, then sin_addr


def rewrite_list_identity(payload: bytes, remap) -> bytes:
    """Replace the sin_addr of every CIP Identity item in ListIdentity replies for which
    ``remap(ip4_bytes) -> bytes | None`` has a final address. The sin_port (44818, big-endian)
    and every other byte stay as recorded; anything that is not a ListIdentity reply is returned
    unchanged. A TCP payload may carry several encapsulation messages back to back."""
    out = None
    offset = 0
    try:
        while offset + _ENCAP_HEADER <= len(payload):
            command, length = _ENCAP.unpack_from(payload, offset)
            data, end = offset + _ENCAP_HEADER, offset + _ENCAP_HEADER + length
            if end > len(payload):
                break
            if command == LIST_IDENTITY and length >= 2:
                count = struct.unpack_from("<H", payload, data)[0]
                item = data + 2
                for _ in range(count):
                    kind, size = _ITEM.unpack_from(payload, item)
                    body = item + _ITEM.size
                    if body + size > end:
                        break
                    if kind == CIP_IDENTITY_ITEM and size >= _SIN_ADDR + 4:
                        start = body + _SIN_ADDR
                        new = remap(payload[start:start + 4])
                        if new is not None:
                            out = out if out is not None else bytearray(payload)
                            out[start:start + 4] = new
                    item = body + size
            offset = end
    except struct.error:
        return payload
    return bytes(out) if out is not None else payload
