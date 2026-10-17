"""LDAP v3 (RFC 4511) messages, the CLDAP DC-locator ping and its NETLOGON_SAM_LOGON_RESPONSE_EX
reply (MS-ADTS 6.3.1.9, 7.3.3), as a Windows client and an Active Directory DC exchange them."""

from __future__ import annotations

import struct
import uuid

from pcapforge.actors import der

BIND_REQUEST, BIND_RESPONSE, UNBIND_REQUEST, SEARCH_REQUEST, SEARCH_ENTRY, SEARCH_DONE = 0, 1, 2, 3, 4, 5
SCOPE_BASE, SCOPE_ONE, SCOPE_SUBTREE = 0, 1, 2
SUCCESS = 0
# NtVer of a Windows DC-locator ping: NETLOGON_NT_VERSION_5 | 5EX | WITH_CLOSEST_SITE.
NT_VERSION_PING = 0x00000016
LOGON_SAM_LOGON_RESPONSE_EX = 23
# DS_PDC | GC | LDAP | DS | KDC | TIMESERV | CLOSEST | WRITABLE | GOOD_TIMESERV | FULL_SECRET_DOMAIN_6 |
# WS | DS_8 | DS_9 | DS_10: a Windows Server 2016+ writable DC that holds the PDC emulator role.
DC_FLAGS = 0x0001F3FD
DEFAULT_SITE = "Default-First-Site-Name"


def message(message_id: int, op: bytes) -> bytes:
    return der.seq(der.integer(message_id), op)


def ldap_string(text: str) -> bytes:
    return der.octets(text.encode("utf-8"))


def bind_sasl(message_id: int, mechanism: str, credentials: bytes) -> bytes:
    sasl = der.tlv(0xA3, ldap_string(mechanism) + der.octets(credentials))
    return message(message_id, der.app(BIND_REQUEST, der.integer(3) + ldap_string("") + sasl))


def bind_response(message_id: int, server_creds: bytes | None) -> bytes:
    body = der.enumerated(SUCCESS) + ldap_string("") + ldap_string("")
    if server_creds is not None:
        body += der.ctx_prim(7, server_creds)
    return message(message_id, der.app(BIND_RESPONSE, body))


def unbind(message_id: int) -> bytes:
    return message(message_id, der.app_prim(UNBIND_REQUEST, b""))


def equality(attribute: str, value: bytes) -> bytes:
    return der.tlv(0xA3, ldap_string(attribute) + der.octets(value))


def present(attribute: str) -> bytes:
    return der.ctx_prim(7, attribute.encode())


def and_filter(*filters: bytes) -> bytes:
    return der.tlv(0xA0, b"".join(filters))


def or_filter(*filters: bytes) -> bytes:
    return der.tlv(0xA1, b"".join(filters))


def search(message_id: int, base: str, scope: int, filt: bytes, attributes: list[str]) -> bytes:
    body = (ldap_string(base) + der.enumerated(scope) + der.enumerated(0) + der.integer(0) + der.integer(0)
            + der.boolean(False) + filt + der.seq(*(ldap_string(a) for a in attributes)))
    return message(message_id, der.app(SEARCH_REQUEST, body))


def search_entry(message_id: int, dn: str, attributes: list[tuple[str, list[bytes]]]) -> bytes:
    attrs = der.seq(*(der.seq(ldap_string(name), der.set_of(*(der.octets(v) for v in values)))
                      for name, values in attributes))
    return message(message_id, der.app(SEARCH_ENTRY, ldap_string(dn) + attrs))


def search_done(message_id: int) -> bytes:
    return message(message_id, der.app(SEARCH_DONE, der.enumerated(SUCCESS) + ldap_string("") + ldap_string("")))


def parse(data: bytes) -> tuple[int, int, bytes]:
    """(message id, protocol op number, op content) of one LDAPMessage."""
    _, content, _ = der.read(data)
    _, mid, offset = der.read(content)
    tag, op, _ = der.read(content, offset)
    return int.from_bytes(mid, "big"), tag & 0x1F, op


def message_size(data: bytes, offset: int = 0) -> int | None:
    """Length of the complete LDAPMessage starting at ``offset``, None while incomplete."""
    if len(data) - offset < 2:
        return None
    first = data[offset + 1]
    head = 2 + (first & 0x7F if first & 0x80 else 0)
    if len(data) - offset < head:
        return None
    size = int.from_bytes(data[offset + 2:offset + head], "big") if first & 0x80 else first
    return head + size


# --- DC locator -------------------------------------------------------------------------

def cldap_ping(message_id: int, domain: str, host: str) -> bytes:
    filt = and_filter(equality("DnsDomain", domain.encode()), equality("Host", host.encode()),
                      equality("NtVer", struct.pack("<I", NT_VERSION_PING)))
    return search(message_id, "", SCOPE_BASE, filt, ["Netlogon"])


class _Names:
    """RFC 1035 name compression relative to the start of the NETLOGON blob."""

    def __init__(self, base: int) -> None:
        self.base = base
        self.seen: dict[tuple[str, ...], int] = {}

    def encode(self, name: str, offset: int) -> bytes:
        labels = tuple(name.split(".")) if name else ()
        out = bytearray()
        for i in range(len(labels)):
            suffix = tuple(label.lower() for label in labels[i:])
            if suffix in self.seen:
                return bytes(out) + struct.pack("!H", 0xC000 | self.seen[suffix])
            self.seen[suffix] = offset + len(out)
            label = labels[i].encode("utf-8")
            out += bytes([len(label)]) + label
        return bytes(out) + b"\x00"


def netlogon_response(domain_guid: bytes, forest: str, domain: str, dc_fqdn: str, netbios_domain: str,
                      netbios_dc: str, site: str = DEFAULT_SITE) -> bytes:
    """NETLOGON_SAM_LOGON_RESPONSE_EX for NtVer 0x16 (no DcSockAddr, with NextClosestSiteName)."""
    blob = bytearray(struct.pack("<HHI", LOGON_SAM_LOGON_RESPONSE_EX, 0, DC_FLAGS) + domain_guid)
    names = _Names(0)
    for name in (forest, domain, dc_fqdn, netbios_domain, netbios_dc, "", site, site, ""):
        blob += names.encode(name, len(blob))
    blob += struct.pack("<IHH", 0x00000005, 0xFFFF, 0xFFFF)
    return bytes(blob)


def cldap_reply(message_id: int, blob: bytes) -> bytes:
    return search_entry(message_id, "", [("netlogon", [blob])]) + search_done(message_id)


def domain_dn(domain: str) -> str:
    return ",".join(f"DC={part}" for part in domain.split("."))


def guid_string(value: uuid.UUID) -> str:
    return "{" + str(value).upper() + "}"
