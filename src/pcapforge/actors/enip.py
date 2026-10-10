"""EtherNet/IP actors: a Rockwell Logix controller, an HMI driver, and class 1 I/O between the
Logix (scanner) and a PowerFlex 525 drive (adapter).

The controller side is a hand-written encapsulation / CIP target bound to the host's loopback
address on TCP and UDP port 14818 (mapped to 44818). It answers ListIdentity (UDP and TCP),
ListServices, RegisterSession / UnRegisterSession, unconnected SendRRData (Identity
Get_Attribute_All, Connection Manager Forward_Open / Forward_Close, Message Router services) and
connected SendUnitData (Class 3 explicit: Read Tag and Multiple Service Packet). Its
controller-scoped tags mirror the process model at the virtual time of every read.

The client is a FactoryTalk Linx / RSLinx Enterprise style driver: one ListIdentity browse
broadcast at startup, then per controller a session (ListServices, RegisterSession, Identity
Get_Attribute_All, Forward_Open of a Class 3 connection through the backplane to slot 0) and
cyclic Multiple Service Packet tag reads sized to the connection.

Implicit I/O: the scanner (on the Logix host) opens a class 1 connection to the drive's
embedded adapter like a Generic Ethernet Module (RegisterSession, Forward_Open to the Assembly
object: configuration instance 6, O->T point 2, T->O point 1, point-to-point both ways) and
exchanges the first O->T / T->O pair on UDP 12222 (mapped to 2222). The composer continues the
cyclic stream at the API for the rest of the capture (``compose/enip.py``) with the same
``LineProgram`` (Logic Command + speed reference from the controller's process) and ``Drive``
(PowerFlex 525 velocity mode: ramp, Logic Status, feedback, Datalinks) as the recording.
"""

from __future__ import annotations

import asyncio
import math
import re
import socket
import struct
from collections.abc import Callable
from dataclasses import dataclass

from pcapforge import ports
from pcapforge.actors import register
from pcapforge.actors.base import Actor
from pcapforge.actors.modbus import host_process, host_sim
from pcapforge.plan import action_ref, host_ref
from pcapforge.process import BIT_TABLES, Point, ProcessProfile, ProcessSim
from pcapforge.rng import Rng
from pcapforge.scenario import ScenarioError
from pcapforge.topology import SINKS

# --- encapsulation -----------------------------------------------------------------------

ENCAP = struct.Struct("<HHII8sI")    # command, length, session handle, status, sender context, options
ENCAP_PORT = ports.WELL_KNOWN[ports.ENIP]  # the port a ListIdentity reply announces (44818)

CMD_LIST_SERVICES = 0x0004
CMD_LIST_IDENTITY = 0x0063
CMD_REGISTER_SESSION = 0x0065
CMD_UNREGISTER_SESSION = 0x0066
CMD_SEND_RR_DATA = 0x006F
CMD_SEND_UNIT_DATA = 0x0070
UDP_COMMANDS = (CMD_LIST_SERVICES, CMD_LIST_IDENTITY)

STATUS_INVALID_COMMAND = 0x0001
STATUS_INVALID_SESSION = 0x0064
STATUS_INVALID_LENGTH = 0x0065
STATUS_UNSUPPORTED_REVISION = 0x0069

ITEM_NULL = 0x0000
ITEM_IDENTITY = 0x000C
ITEM_CONNECTED_ADDRESS = 0x00A1
ITEM_CONNECTED_DATA = 0x00B1
ITEM_UNCONNECTED_DATA = 0x00B2
ITEM_SERVICES = 0x0100

PROTOCOL_VERSION = 1
# ListServices: "Communications", CIP encapsulation over TCP (bit 5) and Class 0/1 over UDP (bit 8).
SERVICES_ITEM = struct.pack("<HH16s", PROTOCOL_VERSION, 0x0120, b"Communications")
RR_TIMEOUT = 10                       # SendRRData timeout field [s], as Rockwell drivers send it

# --- CIP ---------------------------------------------------------------------------------

SVC_GET_ATTRIBUTE_ALL = 0x01
SVC_MULTIPLE_SERVICE = 0x0A
SVC_READ_TAG = 0x4C
SVC_FORWARD_CLOSE = 0x4E
SVC_FORWARD_OPEN = 0x54
REPLY = 0x80

OK = 0x00
CONNECTION_FAILURE = 0x01
PATH_SEGMENT_ERROR = 0x04
PATH_UNKNOWN = 0x05
SERVICE_NOT_SUPPORTED = 0x08
NOT_ENOUGH_DATA = 0x13
EMBEDDED_ERROR = 0x1E
EXT_CONNECTION_NOT_FOUND = 0x0107
EXT_INVALID_PATH = 0x0315

IDENTITY_PATH = bytes([0x20, 0x01, 0x24, 0x01])          # class 0x01 (Identity), instance 1
ROUTER_PATH = bytes([0x20, 0x02, 0x24, 0x01])            # class 0x02 (Message Router), instance 1
CONNECTION_MANAGER_PATH = bytes([0x20, 0x06, 0x24, 0x01])
BACKPLANE_PORT = 1
CONTROLLER_SLOT = 0                   # CompactLogix 5370: the controller is slot 0 of its backplane
SYMBOLIC = 0x91                       # ANSI extended symbolic segment

REAL, BOOL, DINT = 0xCA, 0xC1, 0xC4
TYPE_NAMES = {REAL: "REAL", BOOL: "BOOL", DINT: "DINT"}
VALUE_SIZE = {REAL: 4, BOOL: 1, DINT: 4}

# Class 3 connection the HMI driver opens: 500-byte variable size point-to-point, low priority,
# server transport with application trigger, 2 s RPI, timeout x32.
CONNECTION_SIZE = 500
NETWORK_PARAMS = 0x4000 | 0x0200 | CONNECTION_SIZE
TRANSPORT_CLASS3 = 0xA3
RPI_US = 2_000_000
TIMEOUT_MULTIPLIER = 3                # x32
PRIORITY_TICK, TIMEOUT_TICKS = 0x0A, 0x05   # 1024 ms ticks x 5 for the unconnected open itself
ORIGINATOR_VENDOR = 1                 # Rockwell Automation (FactoryTalk Linx)

FORWARD_OPEN = struct.Struct("<BBIIHHIB3xIHIHBB")
FORWARD_OPEN_REPLY = struct.Struct("<IIHHIIIBB")
FORWARD_CLOSE = struct.Struct("<BBHHIBB")
FORWARD_CLOSE_REPLY = struct.Struct("<HHIBB")

# Logix status word (owned, I/O connection in run mode, keyswitch remote) and Identity state.
LOGIX_STATUS = 0x3060
LOGIX_STATE = 0x03

# --- implicit (class 1) I/O ----------------------------------------------------------------

ITEM_SEQUENCED_ADDRESS = 0x8002       # CPF item of every class 0/1 packet: connection id, sequence number
IO_PORT = ports.WELL_KNOWN[ports.ENIP_IO]   # 2222
ASSEMBLY_CLASS = 0x04

# A Logix Generic Ethernet Module connection (RSLogix 5000 v18+ "unicast"): point-to-point both
# ways, scheduled priority, fixed size; client transport, cyclic trigger, class 1; timeout x4.
POINT_TO_POINT = 0x4000
SCHEDULED = 0x0800
TRANSPORT_CLASS1 = 0x01
IO_TIMEOUT_MULTIPLIER = 0             # x4
RUN = 0x00000001                      # O->T 32-bit run/idle header, bit 0: run mode
SEQUENCE_COUNT, RUN_IDLE = 2, 4       # bytes before the I/O data of a class 1 packet

EXT_CONNECTION_IN_USE = 0x0100
EXT_TRANSPORT_NOT_SUPPORTED = 0x0103
EXT_OWNERSHIP_CONFLICT = 0x0106
EXT_RPI_NOT_SUPPORTED = 0x0111
EXT_INVALID_OT_SIZE = 0x0127
EXT_INVALID_TO_SIZE = 0x0128

# PowerFlex 525 embedded EtherNet/IP adapter through the Generic profile, Comm Format Data - INT
# (520COM-UM001, chapters 4-5 and appendix D). Output (O->T, assembly 2): Logic Command, Reference
# (0.01 Hz). Input (T->O, assembly 1): two pad words of the Generic profile, Logic Status, Feedback
# (0.01 Hz), Datalink Out 1 = b003 Output Current (0.01 A), Datalink Out 2 = b005 DC Bus Voltage (V).
DRIVE_INPUT_ASSEMBLY, DRIVE_OUTPUT_ASSEMBLY, DRIVE_CONFIG_ASSEMBLY = 1, 2, 6
DRIVE_OUTPUT = struct.Struct("<Hh")
DRIVE_INPUT = struct.Struct("<HHHhHH")
OT_SIZE = SEQUENCE_COUNT + RUN_IDLE + DRIVE_OUTPUT.size      # 10
TO_SIZE = SEQUENCE_COUNT + DRIVE_INPUT.size                  # 14
DRIVE_MIN_RPI_US = 5_000
OUTPUT_IMAGE = ["Logic Command", "Reference (0.01 Hz)"]
INPUT_IMAGE = ["Pad", "Pad", "Logic Status", "Feedback (0.01 Hz)",
               "Datalink Out 1: b003 Output Current (0.01 A)", "Datalink Out 2: b005 DC Bus Voltage (V)"]
# Logic Command (velocity): bit 1 Start, bits 4-5 = 01 Forward. Logic Status: 0 Ready, 1 Active,
# 2 Command Forward, 3 Rotating Forward, 4 Accelerating, 5 Decelerating, 8 At Reference,
# 9 / 10 frequency / run command from the active comm port.
CMD_STOP, CMD_START, CMD_FORWARD = 0x0001, 0x0002, 0x0010
ST_READY, ST_ACTIVE, ST_CMD_FORWARD, ST_FORWARD = 0x0001, 0x0002, 0x0004, 0x0008
ST_ACCEL, ST_DECEL, ST_AT_SPEED, ST_COMM_FREQ, ST_COMM_RUN = 0x0010, 0x0020, 0x0100, 0x0200, 0x0400
MAX_HZ = 60.0                         # P044 [Maximum Freq]
RAMP_HZ_S = MAX_HZ / 10.0             # P041 / P042 [Accel / Decel Time 1] = 10.00 s
RATED_A, MAGNETIZING_A, FULL_LOAD_A, ACCEL_A = 10.5, 3.6, 8.4, 1.2   # 25B-D010N104 on a pump / fan load
DC_BUS_V = 662.0                      # 480 V AC line, rectified


def encap(command: int, data: bytes = b"", session: int = 0, context: bytes = bytes(8), status: int = 0) -> bytes:
    return ENCAP.pack(command, len(data), session, status, context, 0) + data


def cpf(*items: tuple[int, bytes]) -> bytes:
    """Common Packet Format: item count, then (type id, length, data) per item."""
    return struct.pack("<H", len(items)) + b"".join(struct.pack("<HH", kind, len(data)) + data
                                                    for kind, data in items)


def parse_cpf(data: bytes) -> dict[int, bytes]:
    count = struct.unpack_from("<H", data)[0]
    offset, items = 2, {}
    for _ in range(count):
        kind, size = struct.unpack_from("<HH", data, offset)
        items[kind] = data[offset + 4:offset + 4 + size]
        offset += 4 + size
    return items


def rr_data(cip: bytes, timeout: int = RR_TIMEOUT) -> bytes:
    """SendRRData body: interface handle, timeout, Null Address + Unconnected Data items."""
    return struct.pack("<IH", 0, timeout) + cpf((ITEM_NULL, b""), (ITEM_UNCONNECTED_DATA, cip))


def unit_data(connection_id: int, sequence: int, cip: bytes) -> bytes:
    """SendUnitData body: Connected Address + Connected Data (sequence count, CIP message)."""
    return struct.pack("<IH", 0, 0) + cpf((ITEM_CONNECTED_ADDRESS, struct.pack("<I", connection_id)),
                                          (ITEM_CONNECTED_DATA, struct.pack("<H", sequence) + cip))


def cip_request(service: int, path: bytes, data: bytes = b"") -> bytes:
    return bytes([service, len(path) // 2]) + path + data


def parse_request(message: bytes) -> tuple[int, bytes, bytes]:
    """(service, request path, request data) of a CIP request."""
    if len(message) < 2 or len(message) < 2 + 2 * message[1]:
        raise ValueError("truncated CIP request")
    end = 2 + 2 * message[1]
    return message[0], message[2:end], message[end:]


def cip_reply(service: int, status: int = OK, data: bytes = b"", extended: tuple[int, ...] = ()) -> bytes:
    return (bytes([service | REPLY, 0, status, len(extended)]) + struct.pack(f"<{len(extended)}H", *extended)
            + data)


def reply_data(reply: bytes) -> bytes:
    return reply[4 + 2 * reply[3]:]


def symbolic_path(name: str) -> bytes:
    raw = name.encode("ascii")
    return bytes([SYMBOLIC, len(raw)]) + raw + b"\x00" * (len(raw) & 1)


def read_tag_request(name: str, elements: int = 1) -> bytes:
    return cip_request(SVC_READ_TAG, symbolic_path(name), struct.pack("<H", elements))


def pack_services(messages: list[bytes]) -> bytes:
    """Multiple Service Packet body: count, offsets (from the count field), embedded messages."""
    offsets, offset = [], 2 + 2 * len(messages)
    for message in messages:
        offsets.append(offset)
        offset += len(message)
    return struct.pack(f"<H{len(messages)}H", len(messages), *offsets) + b"".join(messages)


def unpack_services(data: bytes) -> list[bytes]:
    count = struct.unpack_from("<H", data)[0]
    offsets = list(struct.unpack_from(f"<{count}H", data, 2))
    if any(not 2 + 2 * count <= a <= b <= len(data) for a, b in zip(offsets, offsets[1:] + [len(data)])):
        raise ValueError("bad Multiple Service Packet offsets")
    return [data[a:b] for a, b in zip(offsets, offsets[1:] + [len(data)])]


def multiple_read_request(names: list[str]) -> bytes:
    return cip_request(SVC_MULTIPLE_SERVICE, ROUTER_PATH, pack_services([read_tag_request(n) for n in names]))


def connection_path(slot: int = CONTROLLER_SLOT) -> bytes:
    """Port segment to the backplane slot, then the controller's Message Router."""
    return bytes([BACKPLANE_PORT, slot]) + ROUTER_PATH


def forward_open_request(ot_id: int, to_id: int, serial: int, originator_serial: int, *,
                         rpi_us: int = RPI_US, ot_params: int = NETWORK_PARAMS, to_params: int = NETWORK_PARAMS,
                         transport: int = TRANSPORT_CLASS3, multiplier: int = TIMEOUT_MULTIPLIER,
                         path: bytes | None = None) -> bytes:
    """Forward_Open; the defaults are the HMI driver's class 3 connection to the controller."""
    path = connection_path() if path is None else path
    data = FORWARD_OPEN.pack(PRIORITY_TICK, TIMEOUT_TICKS, ot_id, to_id, serial, ORIGINATOR_VENDOR,
                             originator_serial, multiplier, rpi_us, ot_params, rpi_us, to_params, transport,
                             len(path) // 2)
    return cip_request(SVC_FORWARD_OPEN, CONNECTION_MANAGER_PATH, data + path)


def forward_close_request(serial: int, originator_serial: int, path: bytes | None = None) -> bytes:
    path = connection_path() if path is None else path
    data = FORWARD_CLOSE.pack(PRIORITY_TICK, TIMEOUT_TICKS, serial, ORIGINATOR_VENDOR, originator_serial,
                              len(path) // 2, 0)
    return cip_request(SVC_FORWARD_CLOSE, CONNECTION_MANAGER_PATH, data + path)


def io_path(config: int = DRIVE_CONFIG_ASSEMBLY, ot_point: int = DRIVE_OUTPUT_ASSEMBLY,
            to_point: int = DRIVE_INPUT_ASSEMBLY) -> bytes:
    """Application path of an I/O connection: Assembly class, configuration instance, then the
    O->T (consumed) and T->O (produced) connection points."""
    return bytes([0x20, ASSEMBLY_CLASS, 0x24, config, 0x2C, ot_point, 0x2C, to_point])


def io_forward_open_request(ot_id: int, to_id: int, serial: int, originator_serial: int, rpi_us: int) -> bytes:
    """The scanner's Forward_Open of the drive's class 1 connection (the target assigns the
    point-to-point O->T id; the originator's T->O id is the one the drive produces with)."""
    return forward_open_request(ot_id, to_id, serial, originator_serial, rpi_us=rpi_us,
                                ot_params=POINT_TO_POINT | SCHEDULED | OT_SIZE,
                                to_params=POINT_TO_POINT | SCHEDULED | TO_SIZE,
                                transport=TRANSPORT_CLASS1, multiplier=IO_TIMEOUT_MULTIPLIER, path=io_path())


def io_packet(connection_id: int, sequence: int, count: int, data: bytes) -> bytes:
    """One class 1 datagram: Sequenced Address item (connection id, encapsulation sequence
    number) and Connected Data item (16-bit CIP sequence count, then the I/O data)."""
    return cpf((ITEM_SEQUENCED_ADDRESS, struct.pack("<II", connection_id, sequence)),
               (ITEM_CONNECTED_DATA, struct.pack("<H", count) + data))


def parse_io_packet(datagram: bytes) -> tuple[int, int, int, bytes]:
    """(connection id, sequence number, sequence count, I/O data) of a class 1 datagram."""
    items = parse_cpf(datagram)
    connection_id, sequence = struct.unpack("<II", items[ITEM_SEQUENCED_ADDRESS])
    data = items[ITEM_CONNECTED_DATA]
    return connection_id, sequence, struct.unpack_from("<H", data)[0], data[SEQUENCE_COUNT:]


# --- identity and tags -------------------------------------------------------------------

@dataclass(frozen=True)
class Identity:
    vendor: int
    device_type: int
    product_code: int
    revision: tuple[int, int]
    serial: int
    name: str
    status: int = LOGIX_STATUS
    state: int = LOGIX_STATE

    def attributes(self) -> bytes:
        """Identity attributes 1-7 (Get_Attribute_All reply; also inside ListIdentity)."""
        name = self.name.encode("ascii")
        return struct.pack("<HHHBBHIB", self.vendor, self.device_type, self.product_code, *self.revision,
                           self.status, self.serial, len(name)) + name

    def list_identity(self, address: str) -> bytes:
        """CPF of a ListIdentity reply: one CIP Identity item with the target's socket address."""
        sockaddr = struct.pack(">HH4s8x", socket.AF_INET, ENCAP_PORT, socket.inet_aton(address))
        body = struct.pack("<H", PROTOCOL_VERSION) + sockaddr + self.attributes() + bytes([self.state])
        return cpf((ITEM_IDENTITY, body))

    def facts(self) -> dict:
        return {"vendor_id": self.vendor, "device_type": self.device_type, "product_code": self.product_code,
                "product_name": self.name, "revision": "{}.{:03d}".format(*self.revision),
                "serial": f"0x{self.serial:08x}"}


@dataclass(frozen=True)
class Tag:
    name: str      # controller-scoped Logix tag
    point: str     # process point it mirrors
    table: str
    type: int      # CIP data type code
    unit: str = ""

    def encode(self, value: float) -> bytes:
        if self.type == REAL:
            return struct.pack("<f", value)
        if self.type == DINT:
            return struct.pack("<i", max(-2 ** 31, min(2 ** 31 - 1, round(value))))
        return b"\x01" if value else b"\x00"


TAG_TABLES = ("input", "holding", "discrete", "coils")      # measurements first, as an HMI lists them
TABLE_SUFFIX = {"input": "AI", "holding": "AO", "discrete": "DI", "coils": "DO"}


def tag_name(point: str) -> str:
    """Logix-style tag name of a point: ``clearwell_level_sp`` -> ``Clearwell_Level_SP``."""
    return "_".join(w.upper() if len(w) <= 2 else w[:1].upper() + w[1:] for w in point.split("_") if w)


def logix_tags(profile: ProcessProfile) -> list[Tag]:
    """Controller tags of a process: REAL for analog points, DINT for counters, BOOL for bits. A
    point name that occurs in several tables gets the table's I/O suffix (``Spare_DI``)."""
    points = [p for table in TAG_TABLES for p in profile.table(table)]
    seen: dict[str, int] = {}
    for p in points:
        seen[tag_name(p.name)] = seen.get(tag_name(p.name), 0) + 1
    tags = []
    for p in points:
        name = tag_name(p.name)
        if seen[name] > 1:
            name = f"{name}_{TABLE_SUFFIX[p.table]}"
        if p.table in BIT_TABLES:
            kind = BOOL
        elif p.model and p.model["type"] == "counter":
            kind = DINT
        else:
            kind = REAL
        tags.append(Tag(name, p.name, p.table, kind, p.unit))
    return tags


def read_groups(tags: list[Tag], size: int = CONNECTION_SIZE) -> list[list[Tag]]:
    """Split ``tags`` into Multiple Service Packet reads whose connected request and response
    (sequence count included) each fit ``size`` bytes, keeping the tag order."""
    groups: list[list[Tag]] = []
    request = response = math.inf
    for tag in tags:
        req = len(read_tag_request(tag.name)) + 2            # embedded request + its offset
        resp = 4 + 2 + VALUE_SIZE[tag.type] + 2              # reply header, type, value, offset
        if request + req > size or response + resp > size:
            groups.append([])
            request = 2 + 2 + len(ROUTER_PATH) + 2           # sequence, service + path size, path, count
            response = 2 + 4 + 2                             # sequence, reply header, count
        groups[-1].append(tag)
        request += req
        response += resp
    return groups


@dataclass
class Controller:
    """Plan-time description of one Logix controller."""
    host_id: str
    profile: ProcessProfile
    identity: Identity
    tags: list[Tag]
    session_base: int
    key: str                              # rng key of the O->T connection ids the controller assigns

    def connection_id(self, serial: int, vendor: int, originator_serial: int) -> int:
        """O->T network connection id the controller assigns to a Forward_Open (deterministic)."""
        return Rng(self.key, serial, vendor, originator_serial).getrandbits(32) or 1


@dataclass
class _Connection:
    to_id: int
    triplet: tuple[int, int, int]         # connection serial, originator vendor, originator serial


class EncapTarget:
    """Encapsulation layer of an EtherNet/IP target, independent of sockets: ``handle`` turns one
    encapsulation message into its reply (None: no reply). Subclasses answer unconnected CIP
    requests (``unconnected``) and, if they accept class 3 connections, ``unit_data``."""

    def __init__(self, identity: Identity, session_base: int, address: str) -> None:
        self.identity = identity
        self.address = address
        self.sessions: set[int] = set()
        self.next_session = session_base
        self.connections: dict[int, _Connection | _IoConnection] = {}   # by O->T connection id

    def handle(self, message: bytes, udp: bool = False) -> bytes | None:
        command, length, session, _, context, _ = ENCAP.unpack_from(message)
        data = message[ENCAP.size:ENCAP.size + length]
        if udp and command not in UDP_COMMANDS:
            return None
        if command == CMD_LIST_IDENTITY:
            return encap(command, self.identity.list_identity(self.address), session, context)
        if command == CMD_LIST_SERVICES:
            return encap(command, cpf((ITEM_SERVICES, SERVICES_ITEM)), session, context)
        if command == CMD_REGISTER_SESSION:
            if len(data) != 4:
                return encap(command, b"", 0, context, STATUS_INVALID_LENGTH)
            if struct.unpack_from("<H", data)[0] != PROTOCOL_VERSION:
                return encap(command, struct.pack("<HH", PROTOCOL_VERSION, 0), 0, context,
                             STATUS_UNSUPPORTED_REVISION)
            handle, self.next_session = self.next_session, (self.next_session + 1) & 0xFFFFFFFF
            self.sessions.add(handle)
            return encap(command, data, handle, context)
        if session not in self.sessions:
            return encap(command, b"", session, context, STATUS_INVALID_SESSION)
        if command == CMD_UNREGISTER_SESSION:
            self.sessions.discard(session)
            return None
        try:
            if command == CMD_SEND_RR_DATA:
                cip = parse_cpf(data[6:])[ITEM_UNCONNECTED_DATA]
                return encap(command, rr_data(self.unconnected(cip), 0), session, context)
            if command == CMD_SEND_UNIT_DATA:
                reply = self.unit_data(parse_cpf(data[6:]))
                return None if reply is None else encap(command, reply, session, context)
        except (KeyError, IndexError, struct.error):
            return encap(command, b"", session, context, STATUS_INVALID_LENGTH)
        return encap(command, b"", session, context, STATUS_INVALID_COMMAND)

    def unconnected(self, message: bytes) -> bytes:
        raise NotImplementedError

    def unit_data(self, items: dict[int, bytes]) -> bytes | None:
        """SendUnitData body answering a connected message (None: drop it, no such connection)."""
        return None

    def forward_close(self, data: bytes) -> bytes:
        if len(data) < FORWARD_CLOSE.size:
            return cip_reply(SVC_FORWARD_CLOSE, NOT_ENOUGH_DATA)
        _, _, serial, vendor, originator_serial, _, _ = FORWARD_CLOSE.unpack_from(data)
        triplet = (serial, vendor, originator_serial)
        for ot_id, connection in self.connections.items():
            if connection.triplet == triplet:
                del self.connections[ot_id]
                return cip_reply(SVC_FORWARD_CLOSE, OK, FORWARD_CLOSE_REPLY.pack(*triplet, 0, 0))
        return cip_reply(SVC_FORWARD_CLOSE, CONNECTION_FAILURE, FORWARD_CLOSE_REPLY.pack(*triplet, 0, 0),
                         (EXT_CONNECTION_NOT_FOUND,))


class LogixTarget(EncapTarget):
    """Encapsulation / CIP target of one controller. ``values(table)`` returns the process
    values ({point: value}) at the current virtual time."""

    def __init__(self, controller: Controller, address: str, values: Callable[[str], dict[str, float]]) -> None:
        super().__init__(controller.identity, controller.session_base, address)
        self.controller = controller
        self.values = values
        self.by_name = {t.name: t for t in controller.tags}
        self._snapshot: dict[str, dict[str, float]] = {}

    def handle(self, message: bytes, udp: bool = False) -> bytes | None:
        self._snapshot = {}
        return super().handle(message, udp)

    def unit_data(self, items: dict[int, bytes]) -> bytes | None:
        connection = self.connections.get(struct.unpack("<I", items[ITEM_CONNECTED_ADDRESS])[0])
        if connection is None:
            return None  # unknown connection: the controller drops the packet
        payload = items[ITEM_CONNECTED_DATA]
        reply = self.route(payload[2:])
        return unit_data(connection.to_id, struct.unpack_from("<H", payload)[0], reply)

    # -- CIP -------------------------------------------------------------------------------
    def unconnected(self, message: bytes) -> bytes:
        try:
            service, path, data = parse_request(message)
        except ValueError:
            return cip_reply(message[0] if message else 0, NOT_ENOUGH_DATA)
        if path == CONNECTION_MANAGER_PATH and service == SVC_FORWARD_OPEN:
            return self.forward_open(data)
        if path == CONNECTION_MANAGER_PATH and service == SVC_FORWARD_CLOSE:
            return self.forward_close(data)
        return self.route(message)

    def route(self, message: bytes) -> bytes:
        """Message Router services: Identity Get_Attribute_All, Multiple Service Packet, Read Tag."""
        try:
            service, path, data = parse_request(message)
        except ValueError:
            return cip_reply(message[0] if message else 0, NOT_ENOUGH_DATA)
        if service == SVC_GET_ATTRIBUTE_ALL and path == IDENTITY_PATH:
            return cip_reply(service, OK, self.controller.identity.attributes())
        if service == SVC_MULTIPLE_SERVICE and path == ROUTER_PATH:
            try:
                requests = unpack_services(data)
            except (ValueError, struct.error):
                return cip_reply(service, NOT_ENOUGH_DATA)
            replies = [self.route(r) for r in requests]
            status = EMBEDDED_ERROR if any(r[2] != OK for r in replies) else OK
            return cip_reply(service, status, pack_services(replies))
        if service == SVC_READ_TAG:
            return self.read_tag(path, data)
        if path in (IDENTITY_PATH, ROUTER_PATH, CONNECTION_MANAGER_PATH):
            return cip_reply(service, SERVICE_NOT_SUPPORTED)
        return cip_reply(service, PATH_UNKNOWN)

    def read_tag(self, path: bytes, data: bytes) -> bytes:
        if len(path) < 2 or path[0] != SYMBOLIC or len(path) != 2 + path[1] + (path[1] & 1):
            return cip_reply(SVC_READ_TAG, PATH_SEGMENT_ERROR)
        if len(data) < 2:
            return cip_reply(SVC_READ_TAG, NOT_ENOUGH_DATA)
        tag = self.by_name.get(path[2:2 + path[1]].decode("ascii", "replace"))
        if tag is None:
            return cip_reply(SVC_READ_TAG, PATH_UNKNOWN)
        table = self._snapshot.get(tag.table)
        if table is None:
            table = self._snapshot[tag.table] = self.values(tag.table)
        return cip_reply(SVC_READ_TAG, OK, struct.pack("<H", tag.type) + tag.encode(table[tag.point]))

    def forward_open(self, data: bytes) -> bytes:
        if len(data) < FORWARD_OPEN.size:
            return cip_reply(SVC_FORWARD_OPEN, NOT_ENOUGH_DATA)
        (_, _, _, to_id, serial, vendor, originator_serial, _, ot_rpi, _, to_rpi, _, transport,
         path_words) = FORWARD_OPEN.unpack_from(data)
        triplet = (serial, vendor, originator_serial)
        path = data[FORWARD_OPEN.size:FORWARD_OPEN.size + 2 * path_words]
        if path != connection_path() or transport & 0x0F != 3:
            return cip_reply(SVC_FORWARD_OPEN, CONNECTION_FAILURE, FORWARD_CLOSE_REPLY.pack(*triplet, 0, 0),
                             (EXT_INVALID_PATH,))
        ot_id = self.controller.connection_id(*triplet)
        self.connections[ot_id] = _Connection(to_id, triplet)
        return cip_reply(SVC_FORWARD_OPEN, OK,
                         FORWARD_OPEN_REPLY.pack(ot_id, to_id, *triplet, ot_rpi, to_rpi, 0, 0))


# --- server ----------------------------------------------------------------------------

class _Datagrams(asyncio.DatagramProtocol):
    def __init__(self, target: EncapTarget) -> None:
        self.target = target
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, addr) -> None:
        if len(data) >= ENCAP.size:
            reply = self.target.handle(data, udp=True)
            if reply is not None:
                self.transport.sendto(reply, addr)

    def error_received(self, exc) -> None:
        pass


class _Endpoint:
    """One target's listeners (TCP and UDP 14818); ``Runtime.servers`` awaits ``shutdown()``."""

    def __init__(self, target: EncapTarget) -> None:
        self.target = target
        self.server: asyncio.Server | None = None
        self.udp: _Datagrams | None = None
        self.writers: set[asyncio.StreamWriter] = set()

    async def start(self, address: str) -> None:
        self.server = await asyncio.start_server(self.connection, address, ports.ENIP)
        _, self.udp = await asyncio.get_running_loop().create_datagram_endpoint(
            lambda: _Datagrams(self.target), local_addr=(address, ports.ENIP))

    async def connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.writers.add(writer)
        try:
            while True:
                header = await reader.readexactly(ENCAP.size)
                body = await reader.readexactly(struct.unpack_from("<H", header, 2)[0])
                reply = self.target.handle(header + body)
                if reply is not None:
                    writer.write(reply)
                    await writer.drain()
                if struct.unpack_from("<H", header)[0] == CMD_UNREGISTER_SESSION:
                    break  # the target closes the TCP connection of an unregistered session
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            self.writers.discard(writer)
            writer.close()

    async def send_identity(self, address: tuple[str, int]) -> None:
        self.udp.transport.sendto(self.target.handle(encap(CMD_LIST_IDENTITY), udp=True), address)

    async def shutdown(self) -> None:
        self.udp.transport.close()
        for writer in list(self.writers):
            writer.close()
        self.server.close()
        await self.server.wait_closed()


def _revision(text: str) -> tuple[int, int]:
    match = re.fullmatch(r"V?(\d+)\.(\d+)", str(text).strip())
    if not match:
        raise ValueError(f"revision '{text}' is not major.minor")
    return int(match[1]), int(match[2])


def device_identity(actor: Actor, host, serial, rng: Rng, status: int = LOGIX_STATUS) -> Identity:
    """CIP Identity of ``host``'s device; ``serial`` (params) or one drawn from ``rng``."""
    ident = host.device.identity or {}
    missing = [k for k in ("VendorId", "DeviceType", "CipProductCode", "ProductCode", "MajorMinorRevision")
               if k not in ident]
    if missing:
        raise ScenarioError(f"{actor.id}: device '{host.device.name}' of host '{host.id}' is not an "
                            f"EtherNet/IP device (identity lacks {', '.join(missing)})")
    drawn = rng.randrange(0x00400000, 0x01000000)
    if serial is None:
        serial = drawn
    elif isinstance(serial, str):
        try:
            serial = int(serial, 0)
        except ValueError:
            raise ScenarioError(f"{actor.id}: params.serial '{serial}' is not a number") from None
    if not isinstance(serial, int) or not 0 < serial <= 0xFFFFFFFF:
        raise ScenarioError(f"{actor.id}: params.serial must be a 32-bit serial number")
    try:
        revision = _revision(ident["MajorMinorRevision"])
    except ValueError as exc:
        raise ScenarioError(f"{actor.id}: device '{host.device.name}': {exc}") from None
    return Identity(int(ident["VendorId"]), int(ident["DeviceType"]), int(ident["CipProductCode"]),
                    revision, serial, str(ident["ProductCode"])[:32], status)


@register
class EnipServer(Actor):
    """Rockwell Logix controller: identity from the device, tags mirror the process model."""

    type = "enip.server"
    is_server = True

    def plan(self) -> None:
        serial = self.param("serial")
        if serial is not None and len(self.hosts) > 1:
            raise ScenarioError(f"{self.id}: params.serial names one controller, but the actor runs on "
                                f"{len(self.hosts)} hosts")
        self.controllers: dict[str, Controller] = {}
        facts = []
        for host in self.hosts:
            profile = host_process(self, host)
            rng = self.rng.child(f"controller:{host.id}")
            identity = device_identity(self, host, serial, rng)
            controller = self.controllers[host.id] = Controller(
                host.id, profile, identity, logix_tags(profile),
                session_base=rng.randrange(0x00010000, 0x7FFF0000),
                key=rng.child("connections").key)
            facts.append({"host": host_ref(host.id), "process": profile.id, "slot": CONTROLLER_SLOT,
                          "identity": identity.facts(),
                          "tags": [{"tag": t.name, "point": t.point, "type": TYPE_NAMES[t.type], "unit": t.unit}
                                   for t in controller.tags]})
        self.plan_.facts[self.id] = {"hosts": [host_ref(h.id) for h in self.hosts], "port": ENCAP_PORT,
                                     "controllers": facts}

    async def serve(self, rt) -> None:
        self.endpoints: dict[str, _Endpoint] = {}
        for host in self.hosts:
            controller = self.controllers[host.id]
            host_sim(rt, self, host, controller.profile)

            def values(table: str, host=host, profile=controller.profile) -> dict[str, float]:
                sim = host_sim(rt, self, host, profile)
                sim.advance(rt.clock.t)
                return sim.values(table)

            endpoint = self.endpoints[host.id] = _Endpoint(LogixTarget(controller, host.loopback, values))
            await endpoint.start(host.loopback)
            rt.servers.append(endpoint)

    def execute(self, action, rt) -> None:
        """Server-side action: the ListIdentity reply to an HMI's browse broadcast, unicast from
        44818 to the socket the broadcast came from."""
        if action.op != "enip.identity":
            raise ValueError(f"unknown op {action.op}")
        endpoint = self.endpoints[action.host]
        address = rt.clients[browse_key(action.args["browser"], action.args["to"])].getsockname()
        asyncio.run_coroutine_threadsafe(endpoint.send_identity(address), rt.loop).result(5)


def browse_key(actor_id: str, host_id: str) -> tuple:
    """``Runtime.clients`` key of an enip.client's ListIdentity browse socket on ``host_id``."""
    return (actor_id, host_id, None)


def serving_controller(plan, host_id: str) -> tuple[EnipServer, Controller]:
    """The enip.server actor running on ``host_id`` and its controller."""
    for actor in plan.actors:
        if isinstance(actor, EnipServer) and host_id in actor.controllers:
            return actor, actor.controllers[host_id]
    raise ScenarioError(f"no enip.server runs on host '{host_id}'")


# --- client ----------------------------------------------------------------------------

class EnipSession:
    """One TCP encapsulation session with a controller, plus its Class 3 connection."""

    def __init__(self, source: str, target: str, context: int) -> None:
        self.session = 0
        self.context = context
        self.connection: tuple[int, int, int, int] | None = None   # O->T id, T->O id, serial, originator serial
        self.sequence = 0
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self.sock.settimeout(3.0)
            self.sock.bind((source, 0))
            self.sock.connect((target, ports.ENIP))
        except BaseException:
            self.sock.close()
            raise

    def _recv(self, size: int) -> bytes:
        data = b""
        while len(data) < size:
            chunk = self.sock.recv(size - len(data))
            if not chunk:
                raise RuntimeError("EtherNet/IP connection closed by the controller")
            data += chunk
        return data

    def request(self, command: int, data: bytes = b"") -> bytes:
        self.context = (self.context + 1) & 0xFFFFFFFFFFFFFFFF
        context = self.context.to_bytes(8, "little")
        self.sock.sendall(encap(command, data, self.session, context))
        reply, length, session, status, echoed, _ = ENCAP.unpack(self._recv(ENCAP.size))
        body = self._recv(length)
        if reply != command or echoed != context:
            raise RuntimeError("EtherNet/IP reply does not answer the request")
        if status:
            raise RuntimeError(f"EtherNet/IP command 0x{command:04x} failed (status 0x{status:08x})")
        if command == CMD_REGISTER_SESSION:
            self.session = session
        return body

    @staticmethod
    def _check(reply: bytes, service: int) -> bytes:
        if len(reply) < 4 or reply[0] != service | REPLY:
            raise RuntimeError(f"CIP reply does not answer service 0x{service:02x}")
        if reply[2] != OK:
            raise RuntimeError(f"CIP service 0x{service:02x} failed (general status 0x{reply[2]:02x})")
        return reply_data(reply)

    def list_services(self) -> None:
        if ITEM_SERVICES not in parse_cpf(self.request(CMD_LIST_SERVICES)):
            raise RuntimeError("ListServices reply carries no Communications item")

    def register(self) -> None:
        self.request(CMD_REGISTER_SESSION, struct.pack("<HH", PROTOCOL_VERSION, 0))

    def unconnected(self, message: bytes) -> bytes:
        body = self.request(CMD_SEND_RR_DATA, rr_data(message))
        return self._check(parse_cpf(body[6:])[ITEM_UNCONNECTED_DATA], message[0])

    def identify(self) -> None:
        self.unconnected(cip_request(SVC_GET_ATTRIBUTE_ALL, IDENTITY_PATH))

    def forward_open(self, ot_id: int, to_id: int, serial: int, originator_serial: int) -> None:
        data = self.unconnected(forward_open_request(ot_id, to_id, serial, originator_serial))
        ot_id, to_id = struct.unpack_from("<II", data)
        self.connection = (ot_id, to_id, serial, originator_serial)

    def connected(self, message: bytes) -> bytes:
        ot_id, to_id, _, _ = self.connection
        self.sequence = (self.sequence + 1) & 0xFFFF
        items = parse_cpf(self.request(CMD_SEND_UNIT_DATA, unit_data(ot_id, self.sequence, message))[6:])
        payload = items[ITEM_CONNECTED_DATA]
        if (struct.unpack("<I", items[ITEM_CONNECTED_ADDRESS])[0] != to_id
                or struct.unpack_from("<H", payload)[0] != self.sequence):
            raise RuntimeError("connected reply does not match the connection or sequence count")
        return self._check(payload[2:], message[0])

    def read(self, names: list[str]) -> None:
        replies = unpack_services(self.connected(multiple_read_request(names)))
        if len(replies) != len(names):
            raise RuntimeError("Multiple Service Packet reply count does not match the request")
        for name, reply in zip(names, replies):
            self._check(reply, SVC_READ_TAG)

    def close(self, graceful: bool) -> None:
        try:
            if graceful:
                if self.connection is not None:
                    _, _, serial, originator_serial = self.connection
                    self.unconnected(forward_close_request(serial, originator_serial))
                    self.connection = None
                self.sock.sendall(encap(CMD_UNREGISTER_SESSION, b"", self.session,
                                        (self.context + 1).to_bytes(8, "little")))
                while self.sock.recv(4096):  # the controller closes the connection
                    pass
        finally:
            self.sock.close()


@register
class EnipClient(Actor):
    """HMI EtherNet/IP driver: browse, one session + Class 3 connection per controller, cyclic tag reads."""

    type = "enip.client"
    sinks = (("broadcast", ports.ENIP),)

    def plan(self) -> None:
        plan = self.plan_
        targets = plan.topology.select(self.param("targets"))
        interval = float(self.param("interval", 1.0))
        jitter = float(self.param("jitter", 0.02))
        list_identity = bool(self.param("list_identity", True))
        list_services = bool(self.param("list_services", True))
        if interval <= 0 or not 0 <= jitter < 1:
            raise ScenarioError(f"{self.id}: interval must be positive and jitter in [0, 1)")
        if not targets:
            raise ScenarioError(f"{self.id}: no targets")
        servers = {t.id: serving_controller(plan, t.id) for t in targets}
        self.groups = {t.id: [[tag.name for tag in group] for group in read_groups(servers[t.id][1].tags)]
                       for t in targets}
        sessions = []
        for host in self.hosts:
            rng = self.rng.child(host.id)
            t = rng.uniform(0, 0.05)
            if list_identity:
                plan.add(t, self.id, host.id, "enip.list_identity", phase="setup")
                for target in targets:
                    plan.add(t + rng.uniform(0.002, 0.2), servers[target.id][0].id, target.id, "enip.identity",
                             phase="setup", to=host.id, browser=self.id)
                t += 0.3
            for target in targets:
                controller = servers[target.id][1]
                t += rng.uniform(0.01, 0.05)
                plan.add(t, self.id, host.id, "enip.connect", phase="setup", target=target.id,
                         context=rng.getrandbits(32), list_services=list_services)
                t += rng.uniform(0.005, 0.02)
                plan.add(t, self.id, host.id, "enip.identify", phase="setup", target=target.id)
                t += rng.uniform(0.005, 0.02)
                conn = {"ot_id": rng.getrandbits(32), "to_id": rng.getrandbits(32),
                        "serial": rng.randrange(1, 0x10000), "originator_serial": rng.getrandbits(32)}
                plan.add(t, self.id, host.id, "enip.forward_open", phase="setup", target=target.id, **conn)
                ot_id = controller.connection_id(conn["serial"], ORIGINATOR_VENDOR, conn["originator_serial"])
                sessions.append({
                    "client": host_ref(host.id), "target": host_ref(target.id),
                    "connection_serial": f"0x{conn['serial']:04x}", "originator_vendor_id": ORIGINATOR_VENDOR,
                    "originator_serial": f"0x{conn['originator_serial']:08x}",
                    "ot_connection_id": f"0x{ot_id:08x}", "to_connection_id": f"0x{conn['to_id']:08x}",
                    "requests_per_cycle": len(self.groups[target.id])})
            t += rng.uniform(0.05, interval)
            while t < plan.duration:
                tt = t
                for target in targets:
                    for index in range(len(self.groups[target.id])):
                        tt += rng.uniform(0.002, 0.012)
                        plan.add(tt, self.id, host.id, "enip.read", target=target.id, group=index)
                    tt += rng.uniform(0.004, 0.03)
                t += rng.jitter(interval, jitter)
            for target in targets:
                plan.add(plan.duration + 1.0, self.id, host.id, "enip.close", phase="teardown", target=target.id)
        plan.facts[self.id] = {
            "hosts": [host_ref(h.id) for h in self.hosts], "targets": [host_ref(t.id) for t in targets],
            "port": ENCAP_PORT, "interval_s": interval, "list_identity": list_identity,
            "connection": {"transport_class": 3, "rpi_ms": RPI_US // 1000, "size_bytes": CONNECTION_SIZE,
                           "timeout_multiplier": 4 << TIMEOUT_MULTIPLIER,
                           "path": f"{BACKPLANE_PORT},{CONTROLLER_SLOT}"},
            "sessions": sessions,
            "tags_per_cycle": {t.id: sum(len(g) for g in self.groups[t.id]) for t in targets},
        }

    def execute(self, action, rt) -> None:
        a = action.args
        if action.op == "enip.list_identity":
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sock.bind((rt.loopback(action.host), 0))  # replies come back to this socket
                sock.sendto(encap(CMD_LIST_IDENTITY), (SINKS["broadcast"].loopback, ports.ENIP))
            except BaseException:
                sock.close()
                raise
            rt.clients[browse_key(self.id, action.host)] = sock
            return
        key = (self.id, action.host, a["target"])
        if action.op == "enip.connect":
            session = EnipSession(rt.loopback(action.host), rt.loopback(a["target"]), a["context"])
            rt.clients[key] = session
            if a["list_services"]:
                session.list_services()
            session.register()
        elif action.op == "enip.identify":
            rt.clients[key].identify()
        elif action.op == "enip.forward_open":
            rt.clients[key].forward_open(a["ot_id"], a["to_id"], a["serial"], a["originator_serial"])
        elif action.op == "enip.read":
            rt.clients[key].read(self.groups[a["target"]][a["group"]])
        elif action.op == "enip.close":
            rt.clients.pop(key).close(graceful=True)
        else:
            raise ValueError(f"unknown op {action.op}")

    def close(self, rt) -> None:
        for key in [k for k in rt.clients if k[0] == self.id]:
            client = rt.clients.pop(key)
            if isinstance(client, EnipSession):
                client.close(graceful=False)
            else:
                client.close()


# --- implicit I/O: the drive's adapter ---------------------------------------------------------

DRIVE_STATUS = 0x0034                 # Identity status: configured, no I/O connection established


@dataclass
class Adapter:
    """Plan-time description of one drive's embedded EtherNet/IP adapter."""
    host_id: str
    identity: Identity
    session_base: int
    key: str                              # rng key of the O->T connection ids the adapter assigns

    def connection_id(self, serial: int, vendor: int, originator_serial: int) -> int:
        """O->T network connection id the adapter assigns to a Forward_Open (deterministic)."""
        return Rng(self.key, serial, vendor, originator_serial).getrandbits(32) or 1


class Drive:
    """A PowerFlex 525 in velocity mode as its T->O image shows it: while Start is latched the
    output frequency ramps to the latest Reference at the accel / decel rate (to 0 Hz after a
    Stop); Logic Status, Feedback and the Datalinks (output current, DC bus voltage) follow.
    ``rng`` adds the measurement noise of the two Datalinks."""

    def __init__(self, rng: Rng) -> None:
        self.rng = rng
        self.t: float | None = None
        self.hz = 0.0
        self.reference = 0.0
        self.running = False

    @property
    def target(self) -> float:
        return self.reference if self.running else 0.0

    def advance(self, t: float) -> None:
        """Ramp the output frequency to virtual time ``t``."""
        if self.t is not None and t > self.t:
            step = RAMP_HZ_S * (t - self.t)
            gap = self.target - self.hz
            self.hz = self.target if abs(gap) <= step else self.hz + math.copysign(step, gap)
        if self.t is None or t > self.t:
            self.t = t

    def consume(self, t: float, data: bytes) -> None:
        """O->T data after the run/idle header: Logic Command and Reference."""
        self.advance(t)
        command, reference = DRIVE_OUTPUT.unpack_from(data)
        if command & CMD_STOP:
            self.running = False
        elif command & CMD_START:
            self.running = True
        self.reference = min(max(reference / 100.0, 0.0), MAX_HZ)

    def produce(self, t: float) -> bytes:
        """T->O data: the Generic profile's two pad words, Logic Status, Feedback, Datalinks."""
        self.advance(t)
        status = ST_READY | ST_CMD_FORWARD | ST_FORWARD | ST_COMM_FREQ | ST_COMM_RUN
        if self.running:
            status |= ST_ACTIVE
        if self.hz < self.target:
            status |= ST_ACCEL
        elif self.hz > self.target:
            status |= ST_DECEL
        elif self.running:
            status |= ST_AT_SPEED
        amps = 0.0
        if self.running or self.hz > 0:
            amps = (MAGNETIZING_A + (FULL_LOAD_A - MAGNETIZING_A) * (self.hz / MAX_HZ) ** 2
                    + (ACCEL_A if status & ST_ACCEL else 0.0) + self.rng.gauss(0.0, 0.04))
        volts = DC_BUS_V - 6.0 * amps / RATED_A + self.rng.gauss(0.0, 0.8)
        return DRIVE_INPUT.pack(0, 0, status, round(self.hz * 100), max(round(amps * 100), 0), round(volts))


@dataclass
class _IoConnection:
    to_id: int
    triplet: tuple[int, int, int]         # connection serial, originator vendor, originator serial
    drive: Drive
    sequence: int = 0                     # encapsulation sequence number of the last T->O packet
    count: int = 0                        # CIP sequence count of the last T->O packet


class AdapterTarget(EncapTarget):
    """The drive's encapsulation / CIP target: Identity, one exclusive-owner class 1 connection
    to its assemblies (Forward_Open / Forward_Close), and the I/O datagrams of that connection."""

    def __init__(self, adapter: Adapter, address: str) -> None:
        super().__init__(adapter.identity, adapter.session_base, address)
        self.adapter = adapter

    def unconnected(self, message: bytes) -> bytes:
        try:
            service, path, data = parse_request(message)
        except ValueError:
            return cip_reply(message[0] if message else 0, NOT_ENOUGH_DATA)
        if path == CONNECTION_MANAGER_PATH and service == SVC_FORWARD_OPEN:
            return self.forward_open(data)
        if path == CONNECTION_MANAGER_PATH and service == SVC_FORWARD_CLOSE:
            return self.forward_close(data)
        if path == IDENTITY_PATH and service == SVC_GET_ATTRIBUTE_ALL:
            return cip_reply(service, OK, self.identity.attributes())
        if path in (IDENTITY_PATH, CONNECTION_MANAGER_PATH):
            return cip_reply(service, SERVICE_NOT_SUPPORTED)
        return cip_reply(service, PATH_UNKNOWN)

    def forward_open(self, data: bytes) -> bytes:
        if len(data) < FORWARD_OPEN.size:
            return cip_reply(SVC_FORWARD_OPEN, NOT_ENOUGH_DATA)
        (_, _, _, to_id, serial, vendor, originator_serial, _, ot_rpi, ot_params, to_rpi, to_params, transport,
         path_words) = FORWARD_OPEN.unpack_from(data)
        triplet = (serial, vendor, originator_serial)
        path = data[FORWARD_OPEN.size:FORWARD_OPEN.size + 2 * path_words]
        error = None
        if any(c.triplet == triplet for c in self.connections.values()):
            error = EXT_CONNECTION_IN_USE
        elif self.connections:
            error = EXT_OWNERSHIP_CONFLICT
        elif transport != TRANSPORT_CLASS1:
            error = EXT_TRANSPORT_NOT_SUPPORTED
        elif path != io_path():
            error = EXT_INVALID_PATH
        elif ot_params & 0x01FF != OT_SIZE:
            error = EXT_INVALID_OT_SIZE
        elif to_params & 0x01FF != TO_SIZE:
            error = EXT_INVALID_TO_SIZE
        elif min(ot_rpi, to_rpi) < DRIVE_MIN_RPI_US:
            error = EXT_RPI_NOT_SUPPORTED
        if error is not None:
            return cip_reply(SVC_FORWARD_OPEN, CONNECTION_FAILURE, FORWARD_CLOSE_REPLY.pack(*triplet, 0, 0), (error,))
        ot_id = self.adapter.connection_id(*triplet)
        self.connections[ot_id] = _IoConnection(to_id, triplet, Drive(Rng(self.adapter.key, "drive", *triplet)))
        return cip_reply(SVC_FORWARD_OPEN, OK,
                         FORWARD_OPEN_REPLY.pack(ot_id, to_id, *triplet, ot_rpi, to_rpi, 0, 0))

    def io(self, datagram: bytes, t: float) -> bytes | None:
        """Consume an O->T datagram at virtual time ``t`` and return the next T->O datagram (the
        recording's first exchange; the composer continues the stream). None: not a datagram
        of an open connection."""
        try:
            connection_id, _, _, data = parse_io_packet(datagram)
        except (KeyError, struct.error):
            return None
        connection = self.connections.get(connection_id)
        if connection is None or len(data) != OT_SIZE - SEQUENCE_COUNT:
            return None
        if struct.unpack_from("<I", data)[0] & RUN:
            connection.drive.consume(t, data[RUN_IDLE:])
        connection.sequence = (connection.sequence + 1) & 0xFFFFFFFF
        connection.count = (connection.count + 1) & 0xFFFF
        return io_packet(connection.to_id, connection.sequence, connection.count, connection.drive.produce(t))


class _IoDatagrams(asyncio.DatagramProtocol):
    """UDP 2222 (recording port 12222) of an adapter: T->O goes to the originator's port 2222."""

    def __init__(self, target: AdapterTarget, clock: Callable[[], float]) -> None:
        self.target = target
        self.clock = clock
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, addr) -> None:
        reply = self.target.io(data, self.clock())
        if reply is not None:
            self.transport.sendto(reply, (addr[0], ports.ENIP_IO))

    def error_received(self, exc) -> None:
        pass


class _AdapterEndpoint(_Endpoint):
    """An adapter's listeners: encapsulation on TCP / UDP 14818 plus class 1 I/O on UDP 12222."""

    def __init__(self, target: AdapterTarget, clock: Callable[[], float]) -> None:
        super().__init__(target)
        self.clock = clock
        self.io: _IoDatagrams | None = None

    async def start(self, address: str) -> None:
        await super().start(address)
        _, self.io = await asyncio.get_running_loop().create_datagram_endpoint(
            lambda: _IoDatagrams(self.target, self.clock), local_addr=(address, ports.ENIP_IO))

    async def shutdown(self) -> None:
        self.io.transport.close()
        await super().shutdown()


@register
class EnipAdapter(Actor):
    """EtherNet/IP adapter of a PowerFlex 525 drive (Generic profile I/O, one exclusive owner)."""

    type = "enip.adapter"
    is_server = True

    def plan(self) -> None:
        serial = self.param("serial")
        if serial is not None and len(self.hosts) > 1:
            raise ScenarioError(f"{self.id}: params.serial names one drive, but the actor runs on "
                                f"{len(self.hosts)} hosts")
        self.adapters: dict[str, Adapter] = {}
        facts = []
        for host in self.hosts:
            rng = self.rng.child(f"adapter:{host.id}")
            identity = device_identity(self, host, serial, rng, DRIVE_STATUS)
            self.adapters[host.id] = Adapter(host.id, identity, rng.randrange(0x00010000, 0x7FFF0000),
                                             rng.child("connections").key)
            facts.append({"host": host_ref(host.id), "identity": identity.facts(),
                          "assemblies": {"input": DRIVE_INPUT_ASSEMBLY, "output": DRIVE_OUTPUT_ASSEMBLY,
                                         "configuration": DRIVE_CONFIG_ASSEMBLY},
                          "output_image": OUTPUT_IMAGE, "input_image": INPUT_IMAGE,
                          "min_rpi_ms": DRIVE_MIN_RPI_US / 1000})
        self.plan_.facts[self.id] = {"hosts": [host_ref(h.id) for h in self.hosts], "port": ENCAP_PORT,
                                     "io_port": IO_PORT, "drives": facts}

    async def serve(self, rt) -> None:
        for host in self.hosts:
            endpoint = _AdapterEndpoint(AdapterTarget(self.adapters[host.id], host.loopback), lambda: rt.clock.t)
            await endpoint.start(host.loopback)
            rt.servers.append(endpoint)


def serving_adapter(plan, host_id: str) -> tuple[EnipAdapter, Adapter]:
    """The enip.adapter actor running on ``host_id`` and its adapter."""
    for actor in plan.actors:
        if isinstance(actor, EnipAdapter) and host_id in actor.adapters:
            return actor, actor.adapters[host_id]
    raise ScenarioError(f"no enip.adapter runs on host '{host_id}'")


# --- implicit I/O: the Logix scanner -------------------------------------------------------------

MIN_REFERENCE_HZ = 20.0               # P043 [Minimum Freq] of a pump / fan drive


def reference_point(profile: ProcessProfile) -> Point:
    """The process input a drive's speed reference follows: a speed in % (pump, blower, fan),
    else the first daily-cycle measurement, else the first measurement with a normal band."""
    inputs = [p for p in profile.table("input") if p.model and p.model["type"] != "counter"]
    rules = (lambda p: p.unit == "%" and p.name.endswith("_speed"),
             lambda p: p.normal is not None and p.model["type"] == "daily",
             lambda p: p.normal is not None)
    for rule in rules:
        for p in inputs:
            if rule(p):
                return p
    raise ScenarioError(f"process '{profile.id}' has no measurement a drive reference can follow")


def reference_hz(point: Point, value: float) -> float:
    """Speed reference for ``value`` of ``point``: a % of maximum frequency, or the normal band
    mapped onto half to full speed."""
    if point.unit == "%":
        hz = MAX_HZ * value / 100.0
    else:
        lo, hi = point.normal
        hz = MAX_HZ / 2 * (1.0 + (value - lo) / (hi - lo))
    return min(max(hz, MIN_REFERENCE_HZ), MAX_HZ)


class LineProgram:
    """The Logix program side of a drive connection: Logic Command Start + Forward and a speed
    Reference (0.1 Hz steps) that follows one process point, sampled once per virtual second."""

    def __init__(self, point: Point, reference: list[int]) -> None:
        self.point = point
        self.reference = reference        # 0.01 Hz, index = virtual second

    @classmethod
    def follow(cls, sim: ProcessSim, seconds: float) -> LineProgram:
        point = reference_point(sim.profile)
        reference = []
        for second in range(int(math.ceil(seconds)) + 2):
            sim.advance(float(second))
            reference.append(10 * round(10 * reference_hz(point, sim.values(point.table)[point.name])))
        return cls(point, reference)

    def output(self, t: float) -> bytes:
        """O->T data at virtual time ``t``: 32-bit run/idle header (run), Logic Command, Reference."""
        second = min(max(int(t), 0), len(self.reference) - 1)
        return struct.pack("<I", RUN) + DRIVE_OUTPUT.pack(CMD_START | CMD_FORWARD, self.reference[second])


class _IoScan:
    """The scanner's side of one class 1 connection: the encapsulation session it was opened
    on (kept open, as Logix does) and the UDP socket its O->T packets leave from."""

    def __init__(self, session: EnipSession, source: str, target: str) -> None:
        self.session = session
        self.source, self.target = source, target
        self.udp: socket.socket | None = None
        self.ids: tuple[int, int] | None = None            # O->T, T->O connection id
        self.triplet: tuple[int, int] | None = None        # connection serial, originator serial
        self.sequence = self.count = 0

    def open(self, ot_id: int, to_id: int, serial: int, originator_serial: int, rpi_us: int) -> None:
        reply = self.session.unconnected(io_forward_open_request(ot_id, to_id, serial, originator_serial, rpi_us))
        ot_id, echoed, *_ = FORWARD_OPEN_REPLY.unpack_from(reply)
        if echoed != to_id:
            raise RuntimeError("Forward_Open reply does not carry the requested T->O connection id")
        self.ids, self.triplet = (ot_id, to_id), (serial, originator_serial)

    def produce(self, data: bytes) -> None:
        """Send one O->T packet; the adapter answers with its T->O packet."""
        if self.udp is None:
            self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.udp.settimeout(3.0)
            self.udp.bind((self.source, ports.ENIP_IO))
        self.sequence = (self.sequence + 1) & 0xFFFFFFFF
        self.count = (self.count + 1) & 0xFFFF
        self.udp.sendto(io_packet(self.ids[0], self.sequence, self.count, data), (self.target, ports.ENIP_IO))
        reply, _ = self.udp.recvfrom(2048)
        if parse_io_packet(reply)[0] != self.ids[1]:
            raise RuntimeError("T->O packet does not carry the connection's T->O id")

    def close(self, graceful: bool) -> None:
        try:
            if graceful and self.triplet is not None:
                self.session.unconnected(forward_close_request(*self.triplet, io_path()))
        finally:
            if self.udp is not None:
                self.udp.close()
            self.session.close(graceful)


@register
class EnipScanner(Actor):
    """Logix I/O scanner: one class 1 connection per drive in ``targets``, opened during the
    capture (``open_at`` seconds in) at ``rpi_ms``; its Reference follows the controller's process."""

    type = "enip.scanner"

    def plan(self) -> None:
        plan = self.plan_
        targets = plan.topology.select(self.param("targets"))
        rpi_ms = float(self.param("rpi_ms", 100))
        lo, hi = self.span(self.param("open_at", [20, 90]))
        if len(self.hosts) != 1:
            raise ScenarioError(f"{self.id}: a scanner runs on one controller (drives accept one owner)")
        if not targets:
            raise ScenarioError(f"{self.id}: no targets")
        if not DRIVE_MIN_RPI_US <= rpi_ms * 1000 <= 3_200_000:
            raise ScenarioError(f"{self.id}: rpi_ms must be between {DRIVE_MIN_RPI_US / 1000:g} and 3200")
        if not 0 <= lo <= hi < plan.duration:
            raise ScenarioError(f"{self.id}: open_at must lie inside the capture")
        rpi_us = round(rpi_ms * 1000)
        adapters = {t.id: serving_adapter(plan, t.id)[1] for t in targets}
        host = self.hosts[0]
        rng = self.rng.child(host.id)
        try:
            # The controller's own tags run on this simulation (same seed), so the Reference
            # follows the values the HMI reads from it.
            server, controller = serving_controller(plan, host.id)
            sim = ProcessSim(controller.profile, server.rng.child(host.id), plan.start_hour)
            originator_serial = controller.identity.serial
        except ScenarioError:
            profile = host_process(self, host)
            sim = ProcessSim(profile, rng.child("process"), plan.start_hour)
            originator_serial = rng.getrandbits(32)
        self.program = LineProgram.follow(sim, plan.duration)
        connections = []
        for target in targets:
            t = rng.uniform(lo, hi)
            conn = {"ot_id": rng.getrandbits(32), "to_id": rng.getrandbits(32), "serial": rng.randrange(1, 0x10000),
                    "originator_serial": originator_serial, "rpi_us": rpi_us}
            opened = plan.add(t, self.id, host.id, "enip.io_open", target=target.id, context=rng.getrandbits(32),
                              **conn)
            plan.add(t + rng.uniform(0.04, 0.08), self.id, host.id, "enip.io_start", target=target.id,
                     rpi_us=rpi_us)
            plan.add(plan.duration + 1.0, self.id, host.id, "enip.io_close", phase="teardown", target=target.id)
            ot_id = adapters[target.id].connection_id(conn["serial"], ORIGINATOR_VENDOR, originator_serial)
            connections.append({
                "originator": host_ref(host.id), "target": host_ref(target.id), "opened": action_ref(opened),
                "transport_class": 1, "trigger": "cyclic", "rpi_ms": rpi_ms, "api_ms": rpi_ms,
                "timeout_multiplier": 4 << IO_TIMEOUT_MULTIPLIER, "udp_port": IO_PORT,
                "connection_serial": f"0x{conn['serial']:04x}", "originator_vendor_id": ORIGINATOR_VENDOR,
                "originator_serial": f"0x{originator_serial:08x}",
                "ot_connection_id": f"0x{ot_id:08x}", "to_connection_id": f"0x{conn['to_id']:08x}",
                "configuration_instance": DRIVE_CONFIG_ASSEMBLY,
                "ot": {"connection_type": "point-to-point", "connection_point": DRIVE_OUTPUT_ASSEMBLY,
                       "size_bytes": OT_SIZE, "run_idle_header": True},
                "to": {"connection_type": "point-to-point", "connection_point": DRIVE_INPUT_ASSEMBLY,
                       "size_bytes": TO_SIZE, "run_idle_header": False}})
        plan.facts[self.id] = {"hosts": [host_ref(host.id)], "targets": [host_ref(t.id) for t in targets],
                               "rpi_ms": rpi_ms, "reference_point": self.program.point.name,
                               "connections": connections}

    def execute(self, action, rt) -> None:
        a = action.args
        key = (self.id, action.host, a["target"])
        if action.op == "enip.io_open":
            source, target = rt.loopback(action.host), rt.loopback(a["target"])
            scan = rt.clients[key] = _IoScan(EnipSession(source, target, a["context"]), source, target)
            scan.session.register()
            scan.open(a["ot_id"], a["to_id"], a["serial"], a["originator_serial"], a["rpi_us"])
        elif action.op == "enip.io_start":
            rt.clients[key].produce(self.program.output(rt.clock.t))
        elif action.op == "enip.io_close":
            rt.clients.pop(key).close(graceful=True)
        else:
            raise ValueError(f"unknown op {action.op}")

    def close(self, rt) -> None:
        for key in [k for k in rt.clients if k[0] == self.id]:
            rt.clients.pop(key).close(graceful=False)
