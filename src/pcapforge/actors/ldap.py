"""LDAP v3 (RFC 4511) messages, the CLDAP DC-locator ping and its NETLOGON_SAM_LOGON_RESPONSE_EX
reply (MS-ADTS 6.3.1.9, 7.3.3), as a Windows client and an Active Directory DC exchange them."""

from __future__ import annotations

import struct
import uuid

from pcapforge.actors import der

BIND_REQUEST, BIND_RESPONSE, UNBIND_REQUEST, SEARCH_REQUEST, SEARCH_ENTRY, SEARCH_DONE = 0, 1, 2, 3, 4, 5
SCOPE_BASE, SCOPE_ONE, SCOPE_SUBTREE = 0, 1, 2
DEREF_NEVER = 0
SIMPLE_AUTH = 0x80          # BindRequest authentication CHOICE [0]: a cleartext (simple) password
PAGED_RESULTS_OID = "1.2.840.113556.1.4.319"   # MS-ADTS paged results control
SUCCESS = 0
# NtVer of a Windows DC-locator ping: NETLOGON_NT_VERSION_5 | 5EX | WITH_CLOSEST_SITE.
NT_VERSION_PING = 0x00000016
LOGON_SAM_LOGON_RESPONSE_EX = 23
# DS_PDC | GC | LDAP | DS | KDC | TIMESERV | CLOSEST | WRITABLE | GOOD_TIMESERV | FULL_SECRET_DOMAIN_6 |
# WS | DS_8 | DS_9 | DS_10: a Windows Server 2016+ writable DC that holds the PDC emulator role.
DC_FLAGS = 0x0001F3FD
DEFAULT_SITE = "Default-First-Site-Name"


def message(message_id: int, op: bytes, controls: bytes = b"") -> bytes:
    return der.seq(der.integer(message_id), op, controls)


def ldap_string(text: str) -> bytes:
    return der.octets(text.encode("utf-8"))


def bind_sasl(message_id: int, mechanism: str, credentials: bytes) -> bytes:
    sasl = der.tlv(0xA3, ldap_string(mechanism) + der.octets(credentials))
    return message(message_id, der.app(BIND_REQUEST, der.integer(3) + ldap_string("") + sasl))


def bind_simple(message_id: int, name: str, password: bytes = b"") -> bytes:
    """A LDAP v3 simple bind: the bound DN in cleartext and a [0] password (empty = unauthenticated)."""
    auth = der.ctx_prim(0, password)
    return message(message_id, der.app(BIND_REQUEST, der.integer(3) + ldap_string(name) + auth))


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


def search(message_id: int, base: str, scope: int, filt: bytes, attributes: list[str],
           controls: bytes = b"") -> bytes:
    body = (ldap_string(base) + der.enumerated(scope) + der.enumerated(DEREF_NEVER) + der.integer(0)
            + der.integer(0) + der.boolean(False) + filt + der.seq(*(ldap_string(a) for a in attributes)))
    return message(message_id, der.app(SEARCH_REQUEST, body), controls)


def search_entry(message_id: int, dn: str, attributes: list[tuple[str, list[bytes]]]) -> bytes:
    attrs = der.seq(*(der.seq(ldap_string(name), der.set_of(*(der.octets(v) for v in values)))
                      for name, values in attributes))
    return message(message_id, der.app(SEARCH_ENTRY, ldap_string(dn) + attrs))


def search_done(message_id: int, result: int = SUCCESS, controls: bytes = b"") -> bytes:
    return message(message_id, der.app(SEARCH_DONE, der.enumerated(result) + ldap_string("") + ldap_string("")),
                   controls)


def parse(data: bytes) -> tuple[int, int, bytes]:
    """(message id, protocol op number, op content) of one LDAPMessage."""
    _, content, _ = der.read(data)
    _, mid, offset = der.read(content)
    tag, op, _ = der.read(content, offset)
    return int.from_bytes(mid, "big"), tag & 0x1F, op


def bind_simple_name(op_content: bytes) -> str | None:
    """The bound DN of a BindRequest whose authentication is simple ([0]), else None."""
    items = der.children(op_content)
    if len(items) < 3 or items[2][0] != SIMPLE_AUTH:
        return None
    return items[1][1].decode("utf-8", "replace")


def _tlvs(content: bytes) -> list[bytes]:
    """The raw bytes of every TLV concatenated in ``content``."""
    out, offset = [], 0
    while offset < len(content):
        _, _, end = der.read(content, offset)
        out.append(content[offset:end])
        offset = end
    return out


def search_parts(op_content: bytes) -> tuple[str, int, bytes, list[str]]:
    """(baseObject, scope, raw filter TLV, attribute names) of a SearchRequest."""
    base, b_off = der.read(op_content)[1], der.read(op_content)[2]
    scope, s_off = der.read(op_content, b_off)[1], der.read(op_content, b_off)[2]
    offset = s_off
    for _ in range(4):                       # derefAliases, sizeLimit, timeLimit, typesOnly
        offset = der.read(op_content, offset)[2]
    filt_start = offset
    offset = der.read(op_content, offset)[2]
    filt = op_content[filt_start:offset]
    attrs = [v.decode("utf-8", "replace") for _, v in der.children(der.read(op_content, offset)[1])]
    return base.decode("utf-8", "replace"), int.from_bytes(scope, "big"), filt, attrs


def filter_text(filt: bytes) -> str:
    """An LDAP filter rendered the way Wireshark/Zeek show it, e.g. ``(servicePrincipalName=*)``."""
    tag, content, _ = der.read(filt)
    if tag == 0xA0:
        return "(&" + "".join(filter_text(f) for f in _tlvs(content)) + ")"
    if tag == 0xA1:
        return "(|" + "".join(filter_text(f) for f in _tlvs(content)) + ")"
    if tag == 0xA2:
        return "(!" + filter_text(_tlvs(content)[0]) + ")"
    if tag == 0xA3:
        attr, value = der.children(content)
        return f"({attr[1].decode()}={value[1].decode('utf-8', 'replace')})"
    if tag == 0x87:
        return f"({content.decode()}=*)"
    return "(?)"


def filter_matches(filt: bytes, attrs: dict[str, list[bytes]]) -> bool:
    """Whether an object (lower-cased attribute name -> values) satisfies ``filt``."""
    tag, content, _ = der.read(filt)
    if tag == 0xA0:
        return all(filter_matches(f, attrs) for f in _tlvs(content))
    if tag == 0xA1:
        return any(filter_matches(f, attrs) for f in _tlvs(content))
    if tag == 0xA2:
        return not filter_matches(_tlvs(content)[0], attrs)
    if tag == 0xA3:
        attr, value = der.children(content)
        return value[1] in attrs.get(attr[1].decode().lower(), [])
    if tag == 0x87:
        return content.decode().lower() in attrs
    return False


def paged_control(size: int, cookie: bytes = b"") -> bytes:
    """The MS-ADTS paged-results control carried in a request (``size`` page) or a response (cookie)."""
    value = der.seq(der.integer(size), der.octets(cookie))
    return der.tlv(0xA0, der.seq(ldap_string(PAGED_RESULTS_OID), der.octets(value)))


def paged_cookie(data: bytes) -> tuple[int, bytes] | None:
    """(page size, cookie) of the paged-results control on an LDAPMessage, or None if absent."""
    content = der.read(data)[1]
    offset = der.read(content)[2]            # after messageID
    offset = der.read(content, offset)[2]    # after protocolOp
    if offset >= len(content):
        return None
    tag, ctrls, _ = der.read(content, offset)
    if tag != 0xA0:
        return None
    for ctrl in _tlvs(ctrls):
        fields = der.children(der.read(ctrl)[1])
        if fields[0][1].decode() != PAGED_RESULTS_OID:
            continue
        inner = der.read(fields[-1][1])[1]
        size, cookie = der.children(inner)
        return int.from_bytes(size[1], "big"), cookie[1]
    return None


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
