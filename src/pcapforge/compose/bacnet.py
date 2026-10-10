"""BACnet/IP payload rewrites: the originator's B/IP address a BBMD puts in a Forwarded-NPDU."""

from __future__ import annotations

FORWARDED_NPDU = 0x04
_ADDRESS = slice(4, 8)           # after type, function and length: IPv4 address, then the UDP port


def rewrite_forwarded_npdu(payload: bytes, remap) -> bytes:
    """Replace the originating IPv4 address of a BVLC Forwarded-NPDU for which
    ``remap(ip4_bytes) -> bytes | None`` has a final address. The port (47808 as sent) and the
    NPDU stay as recorded; any other BVLC message is returned unchanged."""
    if len(payload) < 10 or payload[0] != 0x81 or payload[1] != FORWARDED_NPDU:
        return payload
    new = remap(payload[_ADDRESS])
    if new is None:
        return payload
    return payload[:_ADDRESS.start] + new + payload[_ADDRESS.stop:]
