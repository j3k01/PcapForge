"""Kerberos V5 (RFC 4120, MS-KILE) and the GSS-API / SPNEGO tokens that carry it in LDAP and SMB.

Messages are encoded as Windows 10 clients and a Windows Server KDC send them. The encrypted parts
(tickets, the KDC reply part, authenticators, PA-ENC-TIMESTAMP) have the size of their real
AES256-CTS-HMAC-SHA1-96 encryption: a 16-byte confounder, the DER plaintext (built here so the
length is right) and a 12-byte HMAC. Their bytes are opaque: derived from the behaviour seed, with
the trailing 12 bytes keyed by the synthetic principal key so the KDC can tell a right from a wrong
pre-authentication. No real cipher runs and no key or password is ever derived from real data.
"""

from __future__ import annotations

import hashlib
import hmac
import struct

from pcapforge.actors import der
from pcapforge.rng import label_bytes

PVNO = 5
AS_REQ, AS_REP, TGS_REQ, TGS_REP, AP_REQ, AP_REP, KRB_ERROR = 10, 11, 12, 13, 14, 15, 30
AES256, AES128, RC4_HMAC, RC4_HMAC_EXP, RC4_HMAC_OLD_EXP = 18, 17, 23, 24, -135
WINDOWS_ETYPES = (AES256, AES128, RC4_HMAC, RC4_HMAC_EXP, RC4_HMAC_OLD_EXP)
NT_PRINCIPAL, NT_SRV_INST, NT_SRV_HST = 1, 2, 3
ADDR_NETBIOS = 20
PA_TGS_REQ, PA_ENC_TIMESTAMP, PA_ETYPE_INFO2, PA_PK_AS_REP_OLD, PA_PK_AS_REQ = 1, 2, 19, 15, 16
PA_PAC_REQUEST, PA_SUPPORTED_ENCTYPES, PA_PAC_OPTIONS = 128, 165, 167
KDC_ERR_PREAUTH_FAILED, KDC_ERR_PREAUTH_REQUIRED, KRB_ERR_RESPONSE_TOO_BIG = 24, 25, 52
# KDC options (bit 0 = most significant): forwardable 1, renewable 8, canonicalize 15, renewable-ok 27.
KDC_OPT_AS = 0x40810010
KDC_OPT_TGS = 0x40810000
AP_OPT_MUTUAL = 0x20000000
PAC_OPT_BRANCH_AWARE = 0x40000000
TICKET_FLAGS_TGT = 0x40E10000      # forwardable, renewable, initial, pre-authent
TICKET_FLAGS_SERVICE = 0x40A50000  # forwardable, renewable, pre-authent, ok-as-delegate, name-canonicalize
# Windows "till" / "rtime" of an AS-REQ: the largest 32-bit time it uses (2037-09-13 02:48:05Z).
WINDOWS_TILL = 2136422885
TICKET_LIFETIME = 10 * 3600
RENEW_LIFETIME = 7 * 86400
UDP_LIMIT = 1465                   # MaxPacketSize (client) / MaxDatagramReplySize (KDC)
CONFOUNDER, MAC = 16, 12

OID_SPNEGO = "1.3.6.1.5.5.2"
OID_KRB5 = "1.2.840.113554.1.2.2"
OID_MS_KRB5 = "1.2.840.48018.1.2.2"
OID_KRB5_U2U = "1.2.840.113554.1.2.2.3"
OID_NEGOEX = "1.3.6.1.4.1.311.2.2.30"
OID_NTLMSSP = "1.3.6.1.4.1.311.2.2.10"
TOK_AP_REQ, TOK_AP_REP = b"\x01\x00", b"\x02\x00"


# --- opaque ciphertext ----------------------------------------------------------------

def seal(label: str, plaintext_size: int, key: bytes) -> bytes:
    """Ciphertext of an AES-CTS-HMAC-SHA1-96 encryption of ``plaintext_size`` bytes: opaque body,
    the trailing 12 bytes an HMAC over it keyed by ``key`` (see ``sealed_by``)."""
    body = label_bytes(label, CONFOUNDER + plaintext_size)
    return body + hmac.new(key, body, hashlib.sha1).digest()[:MAC]


def sealed_by(cipher: bytes, key: bytes) -> bool:
    body, mac = cipher[:-MAC], cipher[-MAC:]
    return hmac.compare_digest(hmac.new(key, body, hashlib.sha1).digest()[:MAC], mac)


# --- basic types --------------------------------------------------------------------

def principal(name_type: int, *parts: str) -> bytes:
    return der.seq(der.ctx(0, der.integer(name_type)), der.ctx(1, der.seq(*(der.gstring(p) for p in parts))))


def encrypted(etype: int, cipher: bytes, kvno: int | None = None) -> bytes:
    items = [der.ctx(0, der.integer(etype))]
    if kvno is not None:
        items.append(der.ctx(1, der.integer(kvno)))
    items.append(der.ctx(2, der.octets(cipher)))
    return der.seq(*items)


def padata(pa_type: int, value: bytes) -> bytes:
    return der.seq(der.ctx(1, der.integer(pa_type)), der.ctx(2, der.octets(value)))


def encryption_key(rng_label: str, etype: int = AES256) -> bytes:
    return der.seq(der.ctx(0, der.integer(etype)), der.ctx(1, der.octets(label_bytes(rng_label, 32))))


def etype_info2(entries: list[tuple[int, str | None]]) -> bytes:
    items = []
    for etype, salt in entries:
        fields = [der.ctx(0, der.integer(etype))]
        if salt is not None:
            fields.append(der.ctx(1, der.gstring(salt)))
        items.append(der.seq(*fields))
    return der.seq(*items)


def netbios_address(name: str) -> bytes:
    """HostAddresses with the client's NetBIOS name (15 characters, space padded, plus the 0x20 suffix)."""
    return der.seq(der.seq(der.ctx(0, der.integer(ADDR_NETBIOS)),
                           der.ctx(1, der.octets(name.upper()[:15].ljust(16).encode("ascii")))))


def ticket(realm: str, sname: bytes, kvno: int, cipher: bytes) -> bytes:
    return der.app(1, der.seq(der.ctx(0, der.integer(PVNO)), der.ctx(1, der.gstring(realm)), der.ctx(2, sname),
                              der.ctx(3, encrypted(AES256, cipher, kvno))))


# --- plaintext sizes ----------------------------------------------------------------

def pac_size(user: str, upn: str, domain: str, groups: int) -> int:
    """Length of a Windows Server 2016+ PAC: PACTYPE header and buffer entries, KERB_VALIDATION_INFO
    (names, group RIDs, domain SID), client info, UPN / DNS info with the SAM name and SID, requestor,
    attributes, server / KDC / ticket / full checksums (HMAC-SHA1-96-AES256, 16 bytes of header each)."""
    logon = 480 + 8 * groups + 2 * (2 * len(user) + len(domain.split(".")[0])) + 24
    client = 18 + 2 * len(user)
    upn_dns = 32 + 2 * (len(upn) + len(domain) + len(user)) + 28
    buffers = [logon, client, upn_dns, 28, 8, 16, 16, 16, 16]
    return 8 + 16 * len(buffers) + sum((b + 7) // 8 * 8 for b in buffers)


def enc_ticket_part_size(crealm: str, cname: bytes, pac: int) -> int:
    t = der.gtime(0)
    auth_data = der.seq(der.seq(der.ctx(0, der.integer(1)), der.ctx(1, der.octets(der.seq(der.seq(
        der.ctx(0, der.integer(128)), der.ctx(1, der.octets(bytes(pac)))))))))
    body = der.app(3, der.seq(der.ctx(0, der.flags32(0)), der.ctx(1, encryption_key("k")), der.ctx(2, der.gstring(crealm)),
                              der.ctx(3, cname), der.ctx(4, der.seq(der.ctx(0, der.integer(1)), der.ctx(1, der.octets(b"")))),
                              der.ctx(5, t), der.ctx(6, t), der.ctx(7, t), der.ctx(8, t), der.ctx(10, auth_data)))
    return len(body)


def enc_kdc_rep_part_size(tgs: bool, nonce: int, srealm: str, sname: bytes) -> int:
    t = der.gtime(0)
    items = [der.ctx(0, encryption_key("k")), der.ctx(1, der.seq(der.seq(der.ctx(0, der.integer(0)), der.ctx(1, t)))),
             der.ctx(2, der.integer(nonce)), der.ctx(3, t), der.ctx(4, der.flags32(0)), der.ctx(5, t), der.ctx(6, t),
             der.ctx(7, t), der.ctx(8, t), der.ctx(9, der.gstring(srealm)), der.ctx(10, sname),
             der.ctx(12, der.seq(padata(PA_SUPPORTED_ENCTYPES, b"\x1f\x00\x00\x00")))]
    return len(der.app(26 if tgs else 25, der.seq(*items)))


def authenticator_size(crealm: str, cname: bytes, gss: bool) -> int:
    """Authenticator of a TGS-REQ (checksum over the request body) or of a GSS AP-REQ (0x8003 GSS
    checksum, subkey, sequence number and the Windows restriction / AP-options authorization data)."""
    t = der.gtime(0)
    checksum = der.seq(der.ctx(0, der.integer(0x8003 if gss else 16)), der.ctx(1, der.octets(bytes(24 if gss else 12))))
    items = [der.ctx(0, der.integer(PVNO)), der.ctx(1, der.gstring(crealm)), der.ctx(2, cname), der.ctx(3, checksum),
             der.ctx(4, der.integer(999999)), der.ctx(5, t)]
    if gss:
        items += [der.ctx(6, encryption_key("k")), der.ctx(7, der.integer(0x7FFFFFFF)),
                  der.ctx(8, der.octets(bytes(152)))]
    return len(der.app(2, der.seq(*items)))


def ap_rep_part_size() -> int:
    return len(der.app(27, der.seq(der.ctx(0, der.gtime(0)), der.ctx(1, der.integer(999999)),
                                   der.ctx(2, encryption_key("k")), der.ctx(3, der.integer(0x7FFFFFFF)))))


def enc_timestamp_size() -> int:
    return len(der.seq(der.ctx(0, der.gtime(0)), der.ctx(1, der.integer(999999))))


# --- messages -----------------------------------------------------------------------

def req_body(options: int, realm: str, sname: bytes, nonce: int, cname: bytes | None = None,
             addresses: bytes | None = None, rtime: bool = True) -> bytes:
    items = [der.ctx(0, der.flags32(options))]
    if cname is not None:
        items.append(der.ctx(1, cname))
    items += [der.ctx(2, der.gstring(realm)), der.ctx(3, sname), der.ctx(5, der.gtime(WINDOWS_TILL))]
    if rtime:
        items.append(der.ctx(6, der.gtime(WINDOWS_TILL)))
    items += [der.ctx(7, der.integer(nonce)), der.ctx(8, der.seq(*(der.integer(e) for e in WINDOWS_ETYPES)))]
    if addresses is not None:
        items.append(der.ctx(9, addresses))
    return der.seq(*items)


def kdc_req(msg_type: int, pa: list[bytes], body: bytes) -> bytes:
    return der.app(msg_type, der.seq(der.ctx(1, der.integer(PVNO)), der.ctx(2, der.integer(msg_type)),
                                     der.ctx(3, der.seq(*pa)), der.ctx(4, body)))


def kdc_rep(msg_type: int, pa: list[bytes] | None, crealm: str, cname: bytes, tkt: bytes, enc_part: bytes) -> bytes:
    items = [der.ctx(0, der.integer(PVNO)), der.ctx(1, der.integer(msg_type))]
    if pa:
        items.append(der.ctx(2, der.seq(*pa)))
    items += [der.ctx(3, der.gstring(crealm)), der.ctx(4, cname), der.ctx(5, tkt), der.ctx(6, enc_part)]
    return der.app(msg_type, der.seq(*items))


def krb_error(code: int, stime: float, susec: int, realm: str, sname: bytes, e_data: bytes | None = None) -> bytes:
    items = [der.ctx(0, der.integer(PVNO)), der.ctx(1, der.integer(KRB_ERROR)), der.ctx(4, der.gtime(stime)),
             der.ctx(5, der.integer(susec)), der.ctx(6, der.integer(code)), der.ctx(9, der.gstring(realm)),
             der.ctx(10, sname)]
    if e_data is not None:
        items.append(der.ctx(12, der.octets(e_data)))
    return der.app(KRB_ERROR, der.seq(*items))


def ap_req(options: int, tkt: bytes, authenticator: bytes) -> bytes:
    return der.app(AP_REQ, der.seq(der.ctx(0, der.integer(PVNO)), der.ctx(1, der.integer(AP_REQ)),
                                   der.ctx(2, der.flags32(options)), der.ctx(3, tkt),
                                   der.ctx(4, encrypted(AES256, authenticator))))


def ap_rep(cipher: bytes) -> bytes:
    return der.app(AP_REP, der.seq(der.ctx(0, der.integer(PVNO)), der.ctx(1, der.integer(AP_REP)),
                                   der.ctx(2, encrypted(AES256, cipher))))


def tcp_frame(message: bytes) -> bytes:
    return struct.pack("!I", len(message)) + message


# --- parsing (KDC side) -------------------------------------------------------------

def parse_kdc_req(message: bytes) -> dict:
    """msg_type, padata {type: value}, and the request body's cname / realm / sname / nonce."""
    tag, content, _ = der.read(message)
    _, body, _ = der.read(content)
    top = der.fields(body)
    pa = {}
    for _, item in der.children(der.read(top[3])[1]):
        f = der.fields(item)
        pa[der.to_int(f[1])] = der.read(f[2])[1]
    req = der.fields(der.read(top[4])[1])
    return {"msg_type": tag & 0x1F, "padata": pa, "realm": der.to_str(req[2]),
            "cname": names(req[1]) if 1 in req else None, "sname": names(req[3]), "nonce": der.to_int(req[7])}


def names(principal_tlv: bytes) -> tuple[int, list[str]]:
    f = der.fields(der.read(principal_tlv)[1])
    return der.to_int(f[0]), [v.decode("ascii") for _, v in der.children(der.read(f[1])[1])]


def ticket_cipher(ticket_tlv: bytes) -> bytes:
    """enc-part cipher of a Ticket."""
    tkt = der.fields(der.read(der.read(ticket_tlv)[1])[1])
    enc = der.fields(der.read(tkt[3])[1])
    return der.read(enc[2])[1]


def ap_req_parts(message: bytes) -> tuple[bytes, bytes]:
    """(ticket cipher, authenticator cipher) of an AP-REQ."""
    f = der.fields(der.read(der.read(message)[1])[1])
    enc = der.fields(der.read(f[4])[1])
    return ticket_cipher(f[3]), der.read(enc[2])[1]


def enc_timestamp_cipher(value: bytes) -> bytes:
    f = der.fields(der.read(value)[1])
    return der.read(f[2])[1]


# --- GSS-API / SPNEGO ---------------------------------------------------------------

def krb5_token(tok_id: bytes, message: bytes) -> bytes:
    """RFC 1964 / 4121 InitialContextToken framing of an AP-REQ or AP-REP."""
    return der.app(0, der.oid(OID_KRB5) + tok_id + message)


def neg_token_init(mech_token: bytes) -> bytes:
    mechs = der.seq(*(der.oid(o) for o in (OID_MS_KRB5, OID_KRB5, OID_NEGOEX, OID_NTLMSSP)))
    return der.app(0, der.oid(OID_SPNEGO) + der.ctx(0, der.seq(der.ctx(0, mechs), der.ctx(2, der.octets(mech_token)))))


def neg_token_init2() -> bytes:
    """SPNEGO hint a Windows server puts in its SMB2 NEGOTIATE response (MS-SPNG 2.2.1)."""
    mechs = der.seq(*(der.oid(o) for o in (OID_NEGOEX, OID_MS_KRB5, OID_KRB5, OID_KRB5_U2U, OID_NTLMSSP)))
    hints = der.seq(der.ctx(0, der.gstring("not_defined_in_RFC4178@please_ignore")))
    return der.app(0, der.oid(OID_SPNEGO) + der.ctx(0, der.seq(der.ctx(0, mechs), der.ctx(3, hints))))


def neg_token_resp(response_token: bytes) -> bytes:
    return der.ctx(1, der.seq(der.ctx(0, der.enumerated(0)), der.ctx(1, der.oid(OID_MS_KRB5)),
                              der.ctx(2, der.octets(response_token))))


def spnego_ap_req(message: bytes) -> bytes:
    """AP-REQ inside a NegTokenInit (the client's first SPNEGO token)."""
    _, content, _ = der.read(message)            # [APPLICATION 0]
    _, _, offset = der.read(content)             # OID
    _, init, _ = der.read(content, offset)       # [0] NegotiationToken
    f = der.fields(der.read(init)[1])
    token = der.read(f[2])[1]
    _, inner, _ = der.read(token)                # KRB5 InitialContextToken
    _, _, offset = der.read(inner)
    return inner[offset + 2:]


WRAP_HEADER = 16


def wrap_token(label: str, plaintext_size: int, acceptor: bool, seq_number: int, ec: int = 16, rrc: int = 28) -> bytes:
    """RFC 4121 Wrap token with confidentiality (sealed), the way Windows seals SASL / LDAP traffic:
    header (TOK_ID 05 04, flags, filler, EC, RRC, SND_SEQ), then E(confounder | data | EC filler |
    header) | HMAC rotated right by RRC; the rotated cipher is opaque."""
    flags = 0x02 | 0x04 | (0x01 if acceptor else 0)
    header = struct.pack("!2sBBHHQ", b"\x05\x04", flags, 0xFF, ec, rrc, seq_number)
    return header + label_bytes(label, CONFOUNDER + plaintext_size + ec + WRAP_HEADER + MAC)
