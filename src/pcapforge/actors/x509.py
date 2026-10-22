"""X.509 v3 certificates of a synthetic Active Directory Certificate Services (AD CS) enterprise root CA.

The certificates are well-formed DER that Wireshark, Zeek and OpenSSL parse, with the names,
validity and extensions an AD CS root and its "Web Server" template issue (template name, CDP and
AIA pointing into the directory over LDAP, SAN). The keys and signatures are not real: the RSA
modulus and the signature are seed-derived bytes of the right size, so nothing verifies.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass

from pcapforge.actors import der
from pcapforge.rng import label_bytes

SHA256_RSA, RSA = "1.2.840.113549.1.1.11", "1.2.840.113549.1.1.1"
CN, DC = "2.5.4.3", "0.9.2342.19200300.100.1.25"
UTF8_STRING, IA5_STRING, BMP_STRING, UTC_TIME = 0x0C, 0x16, 0x1E, 0x17
KEY_USAGE, BASIC_CONSTRAINTS, SUBJECT_KEY_ID, AUTHORITY_KEY_ID = "2.5.29.15", "2.5.29.19", "2.5.29.14", "2.5.29.35"
EXT_KEY_USAGE, SUBJECT_ALT_NAME, CRL_POINTS, AIA = "2.5.29.37", "2.5.29.17", "2.5.29.31", "1.3.6.1.5.5.7.1.1"
CA_VERSION, TEMPLATE_NAME, SERVER_AUTH, CA_ISSUERS = ("1.3.6.1.4.1.311.21.1", "1.3.6.1.4.1.311.20.2",
                                                     "1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.48.2")
KEY_BITS = 2048


def _alg(oid: str) -> bytes:
    return der.seq(der.oid(oid), der.tlv(der.NULL, b""))


def name(cn: str, domain: str) -> bytes:
    """``CN=<cn>, DC=<label>, ...`` of a directory object, most significant RDN (the top label) first."""
    rdns = [(DC, IA5_STRING, label) for label in reversed(domain.split("."))] + [(CN, UTF8_STRING, cn)]
    return der.seq(*(der.set_of(der.seq(der.oid(o), der.tlv(tag, value.encode()))) for o, tag, value in rdns))


def cn_only(cn: str) -> bytes:
    return der.seq(der.set_of(der.seq(der.oid(CN), der.tlv(UTF8_STRING, cn.encode()))))


def _time(epoch: float) -> bytes:
    return der.tlv(UTC_TIME, dt.datetime.fromtimestamp(int(epoch), dt.UTC).strftime("%y%m%d%H%M%SZ").encode())


def _extension(oid: str, value: bytes, critical: bool = False) -> bytes:
    return der.seq(der.oid(oid), *([der.boolean(True)] if critical else []), der.octets(value))


def _bits(data: bytes, unused: int = 0) -> bytes:
    return der.tlv(der.BIT_STRING, bytes((unused,)) + data)


@dataclass(frozen=True)
class Certificate:
    der: bytes
    subject: str          # the subject as Wireshark / OpenSSL print it
    issuer: str
    serial: str           # hex
    not_before: float
    not_after: float
    key_id: bytes


def _key(label: str) -> tuple[bytes, bytes]:
    """(SubjectPublicKeyInfo, key identifier) of a seed-derived 2048-bit RSA public key."""
    modulus = bytearray(label_bytes(f"rsa-modulus\x1f{label}", KEY_BITS // 8))
    modulus[0] |= 0xC0
    modulus[-1] |= 0x01
    public = der.seq(der.integer(int.from_bytes(modulus, "big")), der.integer(65537))
    return der.seq(_alg(RSA), _bits(public)), label_bytes(f"rsa-key-id\x1f{label}", 20)


def _certificate(label: str, issuer: bytes, subject: bytes, not_before: float, not_after: float,
                 extensions: list[bytes], spki: bytes) -> tuple[bytes, str]:
    serial = bytearray(label_bytes(f"x509-serial\x1f{label}", 16))
    serial[0] &= 0x7F
    serial[0] |= 0x10
    tbs = der.seq(der.ctx(0, der.integer(2)), der.tlv(der.INTEGER, bytes(serial)), _alg(SHA256_RSA), issuer,
                  der.seq(_time(not_before), _time(not_after)), subject, spki, der.ctx(3, der.seq(*extensions)))
    return der.seq(tbs, _alg(SHA256_RSA), _bits(label_bytes(f"x509-signature\x1f{label}", KEY_BITS // 8))), serial.hex()


def ca_name(netbios: str, host_name: str) -> str:
    """AD CS default CA name: ``<NetBIOS domain>-<server>-CA``."""
    return f"{netbios.lower()}-{host_name.upper()}-CA"


def root_ca(common_name: str, domain: str, not_before: float, years: int = 5) -> Certificate:
    """Self-signed enterprise root CA (AD CS defaults: 2048-bit RSA, SHA-256, 5 years)."""
    spki, key_id = _key(f"ca\x1f{common_name}")
    dn = name(common_name, domain)
    not_after = not_before + years * 365.25 * 86400
    extensions = [
        _extension(KEY_USAGE, _bits(b"\x86", 1)),
        _extension(BASIC_CONSTRAINTS, der.seq(der.boolean(True)), critical=True),
        _extension(SUBJECT_KEY_ID, der.octets(key_id)),
        _extension(CA_VERSION, der.integer(0)),
    ]
    data, serial = _certificate(f"ca\x1f{common_name}", dn, dn, not_before, not_after, extensions, spki)
    text = _text(common_name, domain)
    return Certificate(data, text, text, serial, not_before, not_after, key_id)


def web_server(ca: Certificate, ca_common_name: str, ca_host: str, domain: str, dns_names: list[str],
               not_before: float, years: int = 2) -> Certificate:
    """Server certificate from the AD CS "Web Server" template for ``dns_names`` (the first is the CN)."""
    spki, key_id = _key(f"web\x1f{dns_names[0]}")
    base = ",".join(f"DC={label}" for label in domain.split("."))
    services = f"CN=Public Key Services,CN=Services,CN=Configuration,{base}"
    cdp = f"ldap:///CN={ca_common_name},CN={ca_host},CN=CDP,{services}?certificateRevocationList?base?objectClass=cRLDistributionPoint"
    aia = f"ldap:///CN={ca_common_name},CN=AIA,{services}?cACertificate?base?objectClass=certificationAuthority"
    extensions = [
        _extension(TEMPLATE_NAME, der.tlv(BMP_STRING, "WebServer".encode("utf-16-be"))),
        _extension(KEY_USAGE, _bits(b"\xa0", 5), critical=True),
        _extension(EXT_KEY_USAGE, der.seq(der.oid(SERVER_AUTH))),
        _extension(SUBJECT_KEY_ID, der.octets(key_id)),
        _extension(AUTHORITY_KEY_ID, der.seq(der.ctx_prim(0, ca.key_id))),
        _extension(CRL_POINTS, der.seq(der.seq(der.ctx(0, der.ctx(0, der.ctx_prim(6, cdp.encode())))))),
        _extension(AIA, der.seq(der.seq(der.oid(CA_ISSUERS), der.ctx_prim(6, aia.encode())))),
        _extension(SUBJECT_ALT_NAME, der.seq(*(der.ctx_prim(2, n.encode()) for n in dns_names))),
    ]
    data, serial = _certificate(f"web\x1f{dns_names[0]}", name(ca_common_name, domain), cn_only(dns_names[0]),
                                not_before, not_before + years * 365.25 * 86400, extensions, spki)
    return Certificate(data, f"CN={dns_names[0]}", _text(ca_common_name, domain), serial, not_before,
                       not_before + years * 365.25 * 86400, key_id)


def _text(common_name: str, domain: str) -> str:
    return ",".join([f"CN={common_name}"] + [f"DC={label}" for label in domain.split(".")])
