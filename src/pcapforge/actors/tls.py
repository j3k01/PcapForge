"""TLS 1.2 on the wire between a Chromium browser (Microsoft Edge) and Windows Schannel (IIS on
Windows Server 2019), without real cryptography.

Handshake messages are byte-exact in structure; random values, key shares, the server's
signature and everything encrypted (Finished, application data) are seed-derived bytes of the
right size, as with the Kerberos ciphertext of the domain traffic.

* ClientHello: Chromium 142 (impit's ``chrome_142`` fingerprint): GREASE cipher first, TLS 1.3 and
  1.2 suites, extensions in a random order per connection with a GREASE extension first and last
  (BoringSSL extension permutation), supported groups GREASE, X25519MLKEM768, x25519, P-256,
  P-384 with key shares for GREASE, X25519MLKEM768 (1216 bytes) and x25519, ALPN h2 / http/1.1,
  ALPS (17613), brotli certificate compression and a GREASE ECH extension.
* Server flight (Windows Server 2019 = Windows 10 1809 Schannel, no TLS 1.3): ServerHello with
  TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (the first RSA suite of the default 1809 order) and a
  32-byte session ID, Certificate (the server certificate and the CA, as IIS sends them),
  ServerKeyExchange on x25519 (first in the default curve order) signed with
  rsa_pss_rsae_sha256, ServerHelloDone, all in one record.
* Client: ClientKeyExchange, ChangeCipherSpec, Finished, and with False Start its first
  application data in the same flight; server ChangeCipherSpec and Finished.
* Resumption: Schannel keeps server sessions in its session ID cache (no session tickets by
  default), so a browser that already has a session with the site offers that session ID in its
  ClientHello (``session``); the server answers with the same ID and goes straight to
  ChangeCipherSpec and Finished (RFC 5246 abbreviated handshake, ``server_resume``), and the client
  answers with its ChangeCipherSpec and Finished (``client_resume_finish``).
* Application data: AES-GCM records, 8-byte explicit nonce + ciphertext + 16-byte tag, at most
  16384 bytes of plaintext each.

Not taken from a capture: the order of the ServerHello extensions and the ServerKeyExchange
signature scheme.
"""

from __future__ import annotations

import struct

from pcapforge.rng import label_bytes

HANDSHAKE, CHANGE_CIPHER_SPEC, ALERT, APPLICATION_DATA = 22, 20, 21, 23
TLS10, TLS12, TLS13 = 0x0301, 0x0303, 0x0304
CLIENT_HELLO, SERVER_HELLO, CERTIFICATE, SERVER_KEY_EXCHANGE, SERVER_HELLO_DONE, CLIENT_KEY_EXCHANGE, FINISHED = (
    1, 2, 11, 12, 14, 16, 20)
MAX_PLAINTEXT = 16384
GCM_OVERHEAD = 8 + 16
GREASE = tuple(0x0A0A + 0x1010 * i for i in range(16))
CHROMIUM_SUITES = (0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8, 0xC013, 0xC014,
                   0x009C, 0x009D, 0x002F, 0x0035)
CHROMIUM_SIGNATURES = (0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601)
X25519MLKEM768, X25519, SECP256R1, SECP384R1 = 0x11EC, 0x001D, 0x0017, 0x0018
SCHANNEL_SUITE = 0xC030
SUITE_NAMES = {0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"}
RSA_PSS_RSAE_SHA256 = 0x0804
ECH_PAYLOADS = (144, 176, 208, 240)


def _u16(value: int) -> bytes:
    return struct.pack("!H", value)


def _vec8(data: bytes) -> bytes:
    return bytes((len(data),)) + data


def _vec16(data: bytes) -> bytes:
    return _u16(len(data)) + data


def _vec24(data: bytes) -> bytes:
    return len(data).to_bytes(3, "big") + data


def record(kind: int, body: bytes, version: int = TLS12) -> bytes:
    return bytes((kind,)) + _u16(version) + _vec16(body)


def handshake(kind: int, body: bytes) -> bytes:
    return bytes((kind,)) + _vec24(body)


def _extension(kind: int, body: bytes = b"") -> bytes:
    return _u16(kind) + _vec16(body)


def client_hello(server_name: str, label: str, order, session: bytes | None = None) -> bytes:
    """Chromium's ClientHello record for ``server_name``; ``order(n)`` permutes the n inner extensions,
    ``session`` is the TLS 1.2 session ID to resume (else a random 32-byte legacy session ID)."""
    rnd = label_bytes(f"tls-client\x1f{label}", 64)
    if session is not None:
        rnd = rnd[:32] + session
    # Independent GREASE values (RFC 8701) for the cipher, the group, the version and the two extensions.
    grease = [GREASE[b % 16] for b in label_bytes(f"tls-grease\x1f{label}", 5)]
    if grease[4] == grease[3]:  # BoringSSL: the two GREASE extensions differ
        grease[4] ^= 0x1010
    name = server_name.encode()
    groups = (grease[1], X25519MLKEM768, X25519, SECP256R1, SECP384R1)
    shares = (_u16(grease[1]) + _vec16(b"\x00")
              + _u16(X25519MLKEM768) + _vec16(label_bytes(f"tls-mlkem\x1f{label}", 1216))
              + _u16(X25519) + _vec16(label_bytes(f"tls-x25519\x1f{label}", 32)))
    ech_size = ECH_PAYLOADS[label_bytes(f"tls-ech-size\x1f{label}", 1)[0] % len(ECH_PAYLOADS)]
    ech = (b"\x00" + _u16(0x0001) + _u16(0x0001) + label_bytes(f"tls-ech-id\x1f{label}", 1)
           + _vec16(label_bytes(f"tls-ech-enc\x1f{label}", 32)) + _vec16(label_bytes(f"tls-ech\x1f{label}", ech_size)))
    inner = [
        _extension(0, _vec16(b"\x00" + _vec16(name))),                          # server_name
        _extension(23),                                                          # extended_master_secret
        _extension(0xFF01, b"\x00"),                                             # renegotiation_info
        _extension(10, _vec16(b"".join(_u16(g) for g in groups))),               # supported_groups
        _extension(11, _vec8(b"\x00")),                                          # ec_point_formats
        _extension(35),                                                          # session_ticket
        _extension(16, _vec16(_vec8(b"h2") + _vec8(b"http/1.1"))),               # ALPN
        _extension(5, b"\x01\x00\x00\x00\x00"),                                  # status_request
        _extension(13, _vec16(b"".join(_u16(s) for s in CHROMIUM_SIGNATURES))),  # signature_algorithms
        _extension(18),                                                          # signed_certificate_timestamp
        _extension(51, _vec16(shares)),                                          # key_share
        _extension(45, _vec8(b"\x01")),                                          # psk_key_exchange_modes
        _extension(43, _vec8(_u16(grease[2]) + _u16(TLS13) + _u16(TLS12))),      # supported_versions
        _extension(27, _vec8(_u16(2))),                                          # compress_certificate (brotli)
        _extension(17613, _vec16(_vec8(b"h2"))),                                 # application_settings
        _extension(0xFE0D, ech),                                                 # encrypted_client_hello (GREASE)
    ]
    extensions = ([_extension(grease[3])] + [inner[i] for i in order(len(inner))]
                  + [_extension(grease[4], b"\x00")])
    suites = (grease[0],) + CHROMIUM_SUITES
    body = (_u16(TLS12) + rnd[:32] + _vec8(rnd[32:]) + _vec16(b"".join(_u16(s) for s in suites)) + _vec8(b"\x00")
            + _vec16(b"".join(extensions)))
    return record(HANDSHAKE, handshake(CLIENT_HELLO, body), TLS10)


def _server_hello(label: str, session: bytes, alpn: bytes) -> bytes:
    rnd = label_bytes(f"tls-server\x1f{label}", 32)
    extensions = _extension(0xFF01, b"\x00") + _extension(23) + _extension(16, _vec16(_vec8(alpn)))
    return handshake(SERVER_HELLO, _u16(TLS12) + rnd + _vec8(session) + _u16(SCHANNEL_SUITE) + b"\x00"
                     + _vec16(extensions))


def session_id(label: str) -> bytes:
    """The session ID Schannel gives the full handshake of the connection ``label``."""
    return label_bytes(f"tls-session\x1f{label}", 32)


def server_flight(label: str, chain: list[bytes], alpn: bytes = b"h2") -> bytes:
    """Schannel's ServerHello ... ServerHelloDone of a full handshake."""
    hello = _server_hello(label, session_id(label), alpn)
    certificate = handshake(CERTIFICATE, _vec24(b"".join(_vec24(c) for c in chain)))
    params = b"\x03" + _u16(X25519) + _vec8(label_bytes(f"tls-ske\x1f{label}", 32))
    signature = _u16(RSA_PSS_RSAE_SHA256) + _vec16(label_bytes(f"tls-ske-signature\x1f{label}", 256))
    key_exchange = handshake(SERVER_KEY_EXCHANGE, params + signature)
    messages = hello + certificate + key_exchange + handshake(SERVER_HELLO_DONE, b"")
    return b"".join(record(HANDSHAKE, messages[i:i + MAX_PLAINTEXT])
                    for i in range(0, len(messages), MAX_PLAINTEXT))


def server_resume(label: str, session: bytes, alpn: bytes = b"h2") -> bytes:
    """Abbreviated handshake: ServerHello with the resumed session ID, ChangeCipherSpec, Finished."""
    return record(HANDSHAKE, _server_hello(label, session, alpn)) + server_finish(label)


def client_resume_finish(label: str) -> bytes:
    """The client's ChangeCipherSpec and Finished closing an abbreviated handshake."""
    return record(CHANGE_CIPHER_SPEC, b"\x01") + record(
        HANDSHAKE, label_bytes(f"tls-client-finished\x1f{label}", 16 + GCM_OVERHEAD))


def client_finish(label: str) -> bytes:
    """ClientKeyExchange (x25519), ChangeCipherSpec and the encrypted Finished."""
    key = handshake(CLIENT_KEY_EXCHANGE, _vec8(label_bytes(f"tls-cke\x1f{label}", 32)))
    return (record(HANDSHAKE, key) + record(CHANGE_CIPHER_SPEC, b"\x01")
            + record(HANDSHAKE, label_bytes(f"tls-client-finished\x1f{label}", 16 + GCM_OVERHEAD)))


def server_finish(label: str) -> bytes:
    return record(CHANGE_CIPHER_SPEC, b"\x01") + record(
        HANDSHAKE, label_bytes(f"tls-server-finished\x1f{label}", 16 + GCM_OVERHEAD))


def application_data(label: str, size: int) -> bytes:
    """``size`` bytes of plaintext as AES-GCM application data records."""
    out = []
    for index, start in enumerate(range(0, max(size, 1), MAX_PLAINTEXT)):
        chunk = min(MAX_PLAINTEXT, size - start)
        out.append(record(APPLICATION_DATA, label_bytes(f"tls-data\x1f{label}\x1f{index}", chunk + GCM_OVERHEAD)))
    return b"".join(out)
