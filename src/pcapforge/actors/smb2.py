"""SMB 2/3 messages (MS-SMB2) of a Windows 10 client reading Group Policy from a DC's SYSVOL:
NEGOTIATE (3.1.1 with negotiate contexts), SESSION_SETUP (SPNEGO / Kerberos), TREE_CONNECT, the
DFS referral IOCTL, CREATE / READ / CLOSE, TREE_DISCONNECT and LOGOFF. Signed messages carry an
opaque 16-byte signature (the signing key would come from the Kerberos session key)."""

from __future__ import annotations

import struct

NEGOTIATE, SESSION_SETUP, LOGOFF, TREE_CONNECT, TREE_DISCONNECT, CREATE, CLOSE, READ, IOCTL = 0, 1, 2, 3, 4, 5, 6, 8, 11
FLAGS_RESPONSE, FLAGS_SIGNED = 0x00000001, 0x00000008
STATUS_SUCCESS = 0
HEADER_SIZE = 64
DIALECTS = (0x0202, 0x0210, 0x0300, 0x0302, 0x0311)
DIALECT_311 = 0x0311
# Client: DFS | LEASING | LARGE_MTU | MULTI_CHANNEL | PERSISTENT_HANDLES | DIRECTORY_LEASING | ENCRYPTION.
CLIENT_CAPABILITIES = 0x0000007F
# Server 2016+ DC on 3.1.1: DFS | LEASING | LARGE_MTU | MULTI_CHANNEL | DIRECTORY_LEASING.
SERVER_CAPABILITIES = 0x0000002F
SIGNING_ENABLED, SIGNING_REQUIRED = 0x01, 0x02
MAX_SIZE = 8388608
PREAUTH_INTEGRITY, ENCRYPTION_CAPS, COMPRESSION_CAPS, NETNAME_CONTEXT = 1, 2, 3, 5
SHA512, AES128_CCM, AES128_GCM = 1, 1, 2
LZNT1, LZ77, LZ77_HUFFMAN, PATTERN_V1 = 1, 2, 3, 4
SHARE_DISK, SHARE_PIPE = 1, 2
FSCTL_DFS_GET_REFERRALS = 0x00060194
DFS_STORAGE_SERVERS = 0x2         # ReferralHeaderFlags S: the targets hold the share's data
DFS_TARGET_SET_BOUNDARY = 0x0004  # ReferralEntryFlags of the first target of a set
FILE_READ = 0x00120089            # READ_DATA | READ_EA | READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE
NON_DIRECTORY_SYNC = 0x00000060   # FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT
ATTRIBUTE_ARCHIVE = 0x20
FILETIME_EPOCH = 116444736000000000
NO_FILE = b"\xff" * 16


def filetime(epoch: float) -> int:
    return FILETIME_EPOCH + int(round(epoch * 10_000_000))


def utf16(text: str) -> bytes:
    return text.encode("utf-16-le")


def pad8(data: bytes) -> bytes:
    return data + bytes(-len(data) % 8)


def header(command: int, message_id: int, *, response: bool = False, status: int = STATUS_SUCCESS,
           credits: int = 1, tree_id: int = 0, session_id: int = 0, signature: bytes | None = None,
           credit_charge: int = 1) -> bytes:
    flags = (FLAGS_RESPONSE if response else 0) | (FLAGS_SIGNED if signature else 0)
    return struct.pack("<4sHHIHHIIQIIQ16s", b"\xfeSMB", HEADER_SIZE, credit_charge, status, command, credits, flags,
                       0, message_id, 0x0000FEFF, tree_id, session_id, signature or bytes(16))


def frame(message: bytes) -> bytes:
    """Direct TCP transport: a zero octet and a 24-bit length."""
    return struct.pack("!I", len(message)) + message


def parse_header(message: bytes) -> dict:
    (_, _, _, status, command, credits, flags, _, message_id, _, tree_id, session_id,
     signature) = struct.unpack_from("<4sHHIHHIIQIIQ16s", message)
    return {"status": status, "command": command, "credits": credits, "flags": flags, "message_id": message_id,
            "tree_id": tree_id, "session_id": session_id}


def _context(context_type: int, data: bytes) -> bytes:
    return struct.pack("<HHI", context_type, len(data), 0) + data


def _contexts(items: list[bytes]) -> bytes:
    return b"".join(pad8(item) if i < len(items) - 1 else item for i, item in enumerate(items))


# --- NEGOTIATE ------------------------------------------------------------------------

def negotiate_request(client_guid: bytes, salt: bytes, server_name: str) -> bytes:
    dialects = b"".join(struct.pack("<H", d) for d in DIALECTS)
    fixed = 36 + len(dialects)
    context_offset = HEADER_SIZE + fixed + (-(HEADER_SIZE + fixed) % 8)
    contexts = _contexts([
        _context(PREAUTH_INTEGRITY, struct.pack("<HHH", 1, len(salt), SHA512) + salt),
        _context(ENCRYPTION_CAPS, struct.pack("<HHH", 2, AES128_GCM, AES128_CCM)),
        _context(COMPRESSION_CAPS, struct.pack("<HHI", 3, 0, 0) + struct.pack("<HHH", LZ77, LZ77_HUFFMAN, LZNT1)),
        _context(NETNAME_CONTEXT, utf16(server_name)),
    ])
    body = struct.pack("<HHHHI16sIHH", 36, len(DIALECTS), SIGNING_ENABLED, 0, CLIENT_CAPABILITIES, client_guid,
                       context_offset, 4, 0) + dialects
    return body + bytes(context_offset - HEADER_SIZE - len(body)) + contexts


def negotiate_response(server_guid: bytes, system_time: float, security: bytes, salt: bytes) -> bytes:
    buffer_offset = HEADER_SIZE + 64
    end = buffer_offset + len(security)
    context_offset = end + (-end % 8)
    contexts = _contexts([
        _context(PREAUTH_INTEGRITY, struct.pack("<HHH", 1, len(salt), SHA512) + salt),
        _context(ENCRYPTION_CAPS, struct.pack("<HH", 1, AES128_GCM)),
    ])
    body = struct.pack("<HHHH16sIIIIQQHHI", 65, SIGNING_ENABLED | SIGNING_REQUIRED, DIALECT_311, 2, server_guid,
                       SERVER_CAPABILITIES, MAX_SIZE, MAX_SIZE, MAX_SIZE, filetime(system_time), 0,
                       buffer_offset, len(security), context_offset)
    return body + security + bytes(context_offset - end) + contexts


# --- SESSION_SETUP / LOGOFF -------------------------------------------------------------

def session_setup_request(security: bytes) -> bytes:
    return struct.pack("<HBBIIHHQ", 25, 0, SIGNING_ENABLED, 0x00000001, 0, HEADER_SIZE + 24, len(security), 0) + security


def session_setup_response(security: bytes) -> bytes:
    return struct.pack("<HHHH", 9, 0, HEADER_SIZE + 8, len(security)) + security


def security_buffer(body: bytes) -> bytes:
    """Security blob of a SESSION_SETUP request."""
    offset, size = struct.unpack_from("<HH", body, 12)
    return body[offset - HEADER_SIZE:offset - HEADER_SIZE + size]


def empty(structure_size: int = 4) -> bytes:
    return struct.pack("<HH", structure_size, 0)


# --- TREE_CONNECT / IOCTL -------------------------------------------------------------

def tree_connect_request(path: str) -> bytes:
    name = utf16(path)
    return struct.pack("<HHHH", 9, 0, HEADER_SIZE + 8, len(name)) + name


def tree_connect_path(body: bytes) -> str:
    offset, size = struct.unpack_from("<HH", body, 4)
    return body[offset - HEADER_SIZE:offset - HEADER_SIZE + size].decode("utf-16-le")


def tree_connect_response(share_type: int, share_flags: int, capabilities: int, access: int) -> bytes:
    return struct.pack("<HBBIII", 16, share_type, 0, share_flags, capabilities, access)


def dfs_referral_request(path: str) -> bytes:
    data = struct.pack("<H", 4) + utf16(path) + b"\x00\x00"
    offset = HEADER_SIZE + 56
    return struct.pack("<HHI16sIIIIIIII", 57, 0, FSCTL_DFS_GET_REFERRALS, NO_FILE, offset, len(data), 0, 0, 0,
                       4096, 1, 0) + data


def dfs_referral_response(path: str, targets: list[str], ttl: int = 900) -> bytes:
    """RESP_GET_DFS_REFERRAL with version 4 referral entries (one per SYSVOL target), the first one
    flagged TargetSetBoundary; every entry points at the shared DFS path strings after the entries."""
    entry_size = 34
    strings_at = 8 + entry_size * len(targets)
    path_bytes = utf16(path) + b"\x00\x00"
    blobs = bytearray(path_bytes)
    target_offsets = []
    for target in targets:
        target_offsets.append(strings_at + len(blobs))
        blobs += utf16(target) + b"\x00\x00"
    out = bytearray(struct.pack("<HHI", len(utf16(path)), len(targets), DFS_STORAGE_SERVERS))
    for index, target_offset in enumerate(target_offsets):
        here = 8 + entry_size * index
        out += struct.pack("<HHHHIHHH16s", 4, entry_size, 1, DFS_TARGET_SET_BOUNDARY if index == 0 else 0, ttl,
                           strings_at - here, strings_at - here, target_offset - here, bytes(16))
    data = bytes(out + blobs)
    offset = HEADER_SIZE + 48
    return struct.pack("<HHI16sIIIIII", 49, 0, FSCTL_DFS_GET_REFERRALS, NO_FILE, offset, 0, offset, len(data), 0,
                       0) + data


# --- CREATE / READ / CLOSE --------------------------------------------------------------

def _create_context(name: bytes, data: bytes, last: bool) -> bytes:
    data_offset = 16 + 8 if data else 0
    head = struct.pack("<IHHHHI", 0, 16, len(name), 0, data_offset, len(data)) + name + bytes(8 - len(name))
    item = head + data
    if not last:
        item = pad8(item)
        item = struct.pack("<I", len(item)) + item[4:]
    return item


def create_request(name: str) -> bytes:
    path = utf16(name)
    name_offset = HEADER_SIZE + 56
    contexts_at = name_offset + len(path) + (-(name_offset + len(path)) % 8)
    contexts = (_create_context(b"MxAc", b"", last=False) + _create_context(b"QFid", b"", last=True))
    body = struct.pack("<HBBIQQIIIIIHHII", 57, 0, 0, 2, 0, 0, FILE_READ, 0, 0x00000007, 1, NON_DIRECTORY_SYNC,
                       name_offset, len(path), contexts_at, len(contexts)) + path
    return body + bytes(contexts_at - HEADER_SIZE - len(body)) + contexts


def create_response(file_id: bytes, times: tuple[float, float, float, float], size: int, access: int,
                    disk_id: bytes) -> bytes:
    created, accessed, written, changed = (filetime(t) for t in times)
    contexts = (_create_context(b"MxAc", struct.pack("<II", STATUS_SUCCESS, access), last=False)
                + _create_context(b"QFid", disk_id + bytes(32 - len(disk_id)), last=True))
    contexts_at = HEADER_SIZE + 88
    return struct.pack("<HBBIQQQQQQII16sII", 89, 0, 0, 1, created, accessed, written, changed, 4096, size,
                       ATTRIBUTE_ARCHIVE, 0, file_id, contexts_at, len(contexts)) + contexts


def read_request(file_id: bytes, size: int) -> bytes:
    return struct.pack("<HBBIQ16sIIIHH", 49, 0x50, 0, size, 0, file_id, 0, 0, 0, 0, 0) + b"\x00"


def read_response(data: bytes) -> bytes:
    return struct.pack("<HBBIII", 17, HEADER_SIZE + 16, 0, len(data), 0, 0) + data


def close_request(file_id: bytes) -> bytes:
    return struct.pack("<HHI16s", 24, 0, 0, file_id)


def close_response() -> bytes:
    return struct.pack("<HHIQQQQQQI", 60, 0, 0, 0, 0, 0, 0, 0, 0, 0)


def file_id_of(body: bytes, command: int) -> bytes:
    if command == READ:
        return body[16:32]
    return body[8:24]                      # CLOSE


def create_name(body: bytes) -> str:
    offset, size = struct.unpack_from("<HH", body, 44)
    return body[offset - HEADER_SIZE:offset - HEADER_SIZE + size].decode("utf-16-le")
