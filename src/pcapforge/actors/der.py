"""Minimal ASN.1 DER encoder and a TLV reader for the Active Directory protocols (Kerberos,
SPNEGO / GSS-API, LDAP): definite lengths, minimal integers, no indefinite forms."""

from __future__ import annotations

import datetime as dt

BOOLEAN, INTEGER, BIT_STRING, OCTET_STRING, NULL, OID, ENUMERATED = 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x0A
GENERAL_STRING, GENERALIZED_TIME, SEQUENCE, SET = 0x1B, 0x18, 0x30, 0x31


def length(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + length(len(content)) + content


def seq(*items: bytes) -> bytes:
    return tlv(SEQUENCE, b"".join(items))


def set_of(*items: bytes) -> bytes:
    return tlv(SET, b"".join(items))


def ctx(number: int, content: bytes) -> bytes:
    """Explicit (constructed) context tag ``[number]``."""
    return tlv(0xA0 | number, content)


def ctx_prim(number: int, content: bytes) -> bytes:
    """Implicit primitive context tag ``[number]``."""
    return tlv(0x80 | number, content)


def app(number: int, content: bytes) -> bytes:
    """Constructed application tag ``[APPLICATION number]``."""
    return tlv(0x60 | number, content)


def app_prim(number: int, content: bytes) -> bytes:
    return tlv(0x40 | number, content)


def integer(value: int, tag: int = INTEGER) -> bytes:
    size = max(1, (value + (value < 0)).bit_length() // 8 + 1)
    return tlv(tag, value.to_bytes(size, "big", signed=True))


def enumerated(value: int) -> bytes:
    return integer(value, ENUMERATED)


def boolean(value: bool) -> bytes:
    return tlv(BOOLEAN, b"\xff" if value else b"\x00")


def octets(data: bytes) -> bytes:
    return tlv(OCTET_STRING, data)


def gstring(text: str) -> bytes:
    return tlv(GENERAL_STRING, text.encode("ascii"))


def gtime(epoch: float) -> bytes:
    """KerberosTime: GeneralizedTime in UTC, whole seconds."""
    stamp = dt.datetime.fromtimestamp(int(epoch), dt.UTC).strftime("%Y%m%d%H%M%SZ")
    return tlv(GENERALIZED_TIME, stamp.encode())


def flags32(value: int) -> bytes:
    """KerberosFlags: a 32-bit BIT STRING, bit 0 the most significant."""
    return tlv(BIT_STRING, b"\x00" + value.to_bytes(4, "big"))


def oid(dotted: str) -> bytes:
    parts = [int(p) for p in dotted.split(".")]
    body = bytearray([40 * parts[0] + parts[1]])
    for part in parts[2:]:
        chunk = [part & 0x7F]
        part >>= 7
        while part:
            chunk.append(0x80 | (part & 0x7F))
            part >>= 7
        body.extend(reversed(chunk))
    return tlv(OID, bytes(body))


def read(data: bytes, offset: int = 0) -> tuple[int, bytes, int]:
    """The TLV at ``offset``: (tag, content, offset after it)."""
    tag = data[offset]
    first = data[offset + 1]
    offset += 2
    if first & 0x80:
        count = first & 0x7F
        size = int.from_bytes(data[offset:offset + count], "big")
        offset += count
    else:
        size = first
    end = offset + size
    if end > len(data):
        raise ValueError("truncated DER element")
    return tag, data[offset:end], end


def children(content: bytes) -> list[tuple[int, bytes]]:
    """(tag, content) of every element inside a constructed value."""
    out, offset = [], 0
    while offset < len(content):
        tag, value, offset = read(content, offset)
        out.append((tag, value))
    return out


def fields(content: bytes) -> dict[int, bytes]:
    """Context-tagged members of a SEQUENCE: tag number -> content of the explicit tag."""
    return {tag & 0x1F: value for tag, value in children(content) if tag & 0xC0 == 0x80}


def to_int(content: bytes) -> int:
    """Value of an INTEGER element given as its full TLV."""
    _, value, _ = read(content)
    return int.from_bytes(value, "big", signed=True)


def to_str(content: bytes) -> str:
    _, value, _ = read(content)
    return value.decode("ascii")
