"""DNP3 (IEEE 1815) over TCP: an outstation and its SCADA master, polled or with unsolicited reporting.

Polled configuration (the default), as most utility SCADA runs DNP3: unsolicited responses are disabled
(the master sends DISABLE_UNSOLICITED for classes 1-3 at startup and the outstation never reports on its
own), so every application exchange is a master request answered by the outstation. The master collects
buffered events with periodic class 1/2/3 polls and reads the whole point database with a slower
class 0 integrity poll.

Unsolicited configuration (``unsolicited: true`` on both actors): after its restart the outstation
opens each master session with a null unsolicited response (function 130, FIR/FIN/CON/UNS, IIN device
restart) and sends no event before that is confirmed. The master confirms every unsolicited response
at once (CONFIRM with the UNS bit and the response's sequence number), runs its startup (disable
unsolicited, integrity poll, clear restart, time sync) and then sends ENABLE_UNSOLICITED for classes
1-3; it keeps slower event and integrity polls. The outstation scans its process every ``scan_s``
(own actions) and reports the events of the enabled classes in unsolicited responses with their own
4-bit sequence number, separate from the solicited one that echoes the request. One unsolicited
response is outstanding at a time; events in it are not reported by polls and leave the buffer on its
confirm. Without a confirm within ``confirm_timeout_s`` the outstation repeats the identical fragment
(same sequence number) at its next scan. In the recording the master's confirm belongs to the
outstation's scan action, as on the wire it answers the unsolicited response within milliseconds.

The outstation is a hand-written asyncio server bound to the host's loopback. Its point database
mirrors the host's process simulation (shared with a ``modbus.server`` on the same host): discrete
inputs are binary inputs (g1v2, events g2v2 in class 1), coils binary output status (g10v2), input
measurements analog inputs (g30v5 float, events g32v7 in class 2), counter-model inputs 32-bit counters
(g20v1) and holding setpoints analog output status (g40v3). Events are detected when a request arrives
or the outstation scans: it samples the process at that virtual time and compares it with the last
reported values (a bit change, or an analog value outside the deadband of its last event); each change
is detected once and queued for every associated master. An analog event is stamped at the linearly
interpolated time its value crossed the deadband since the previous scan.
Responses carrying events request an application confirm; the events leave the buffer when it arrives.
DEVICE_RESTART stays set until the master clears it (WRITE g80v1 index 7) and NEED_TIME until it writes
the time (RECORD_CURRENT_TIME + WRITE g50v3, the LAN procedure). All timestamps come from the scenario
clock.

The link layer carries application data as unconfirmed user data (function 4) in frames of at most 292
bytes (250 user octets in 16-byte blocks, each with its CRC-16/DNP); a request link status (9) is
answered with link status (11). A response fragment is capped at five full link frames (1460 bytes on
the wire, one TCP segment); events that do not fit stay buffered, their class IIN bits stay set and the
master polls again (or, unsolicited, the outstation sends them after the confirm).
"""

from __future__ import annotations

import asyncio
import math
import socket
import struct
import time
from dataclasses import dataclass

from pcapforge import ports
from pcapforge.actors import register
from pcapforge.actors.base import Actor
from pcapforge.actors.modbus import host_process, host_sim
from pcapforge.plan import action_ref, host_ref
from pcapforge.process import Point, ProcessProfile
from pcapforge.scenario import ScenarioError

# --- link layer ------------------------------------------------------------------------

LINK_START = b"\x05\x64"
LINK_HEADER = 10                      # start, length, control, destination, source, CRC
LINK_MAX_DATA = 250                   # user octets in one frame (length octet 255)
BLOCK = 16                            # user octets per CRC-protected block
DIR, PRM = 0x80, 0x40                 # control: from master, primary station
UNCONFIRMED_USER_DATA = 4             # primary function codes
REQUEST_LINK_STATUS = 9
LINK_STATUS = 11                      # secondary function code
MAX_ADDRESS = 0xFFEF                  # 0xFFF0-0xFFFF are reserved / broadcast

# --- transport and application layers --------------------------------------------------

TR_FIN, TR_FIR = 0x80, 0x40
SEGMENT_MAX = LINK_MAX_DATA - 1       # application octets per transport segment
FRAGMENT_MAX = 5 * SEGMENT_MAX        # five full frames = 1460 bytes: one TCP segment

AC_FIR, AC_FIN, AC_CON, AC_UNS = 0x80, 0x40, 0x20, 0x10
FC_CONFIRM, FC_READ, FC_WRITE = 0, 1, 2
FC_SELECT, FC_OPERATE, FC_DIRECT_OPERATE = 3, 4, 5
FC_ENABLE_UNSOLICITED, FC_DISABLE_UNSOLICITED, FC_RECORD_CURRENT_TIME = 20, 21, 24
# Control relay output block (g12v1): qualifier 0x17 (one-octet object count, one-octet index
# prefix) and an 11-octet block per point (control code, count, on time, off time, status).
CROB_GROUP, CROB_VAR, CROB_QUALIFIER, CROB_SIZE = 12, 1, 0x17, 11
OP_LATCH_ON, OP_LATCH_OFF = 3, 4
DNP3_OP_NAMES = {OP_LATCH_ON: "latch_on", OP_LATCH_OFF: "latch_off"}
DNP3_FUNCTION_NAMES = {FC_SELECT: "select", FC_OPERATE: "operate", FC_DIRECT_OPERATE: "direct_operate"}
FC_RESPONSE, FC_UNSOLICITED_RESPONSE = 129, 130
REPLY_TIMEOUT = 3.0                   # seconds of wall time the recording waits for the peer

IIN1_CLASS = {1: 0x02, 2: 0x04, 3: 0x08}
IIN1_NEED_TIME, IIN1_DEVICE_RESTART = 0x10, 0x80
IIN2_NO_FUNC_CODE_SUPPORT, IIN2_OBJECT_UNKNOWN, IIN2_PARAMETER_ERROR = 0x01, 0x02, 0x04
IIN_DEVICE_RESTART_INDEX = 7          # bit of g80v1 the master writes to clear DEVICE_RESTART

ONLINE, STATE = 0x01, 0x80            # point flags

CRC_POLY = 0xA6BC                     # 0x3D65 reflected


def _crc_table() -> tuple[int, ...]:
    table = []
    for byte in range(256):
        crc = byte
        for _ in range(8):
            crc = (crc >> 1) ^ CRC_POLY if crc & 1 else crc >> 1
        table.append(crc)
    return tuple(table)


_CRC_TABLE = _crc_table()


def crc16(data: bytes) -> int:
    """CRC-16/DNP (poly 0x3D65 reflected, init 0, final complement); sent little-endian."""
    crc = 0
    for byte in data:
        crc = (crc >> 8) ^ _CRC_TABLE[(crc ^ byte) & 0xFF]
    return ~crc & 0xFFFF


def link_frame(control: int, dest: int, src: int, data: bytes = b"") -> bytes:
    """One link frame: header with its CRC, then the user data in 16-byte blocks, each with a CRC."""
    if len(data) > LINK_MAX_DATA:
        raise ValueError(f"{len(data)} user octets exceed one link frame")
    header = LINK_START + struct.pack("<BBHH", 5 + len(data), control, dest, src)
    out = bytearray(header + struct.pack("<H", crc16(header)))
    for offset in range(0, len(data), BLOCK):
        block = data[offset:offset + BLOCK]
        out += block + struct.pack("<H", crc16(block))
    return bytes(out)


def frame_size(length: int) -> int:
    """Octets of a link frame whose length field is ``length``."""
    data = length - 5
    return LINK_HEADER + data + 2 * -(-data // BLOCK)


def parse_link(frame: bytes) -> tuple[int, int, int, bytes]:
    """(control, destination, source, user data) of one link frame; every CRC is checked."""
    if frame[:2] != LINK_START:
        raise ValueError("not a DNP3 link frame")
    length, control, dest, src = struct.unpack_from("<BBHH", frame, 2)
    if length < 5 or len(frame) != frame_size(length):
        raise ValueError("DNP3 link frame length mismatch")
    if struct.unpack_from("<H", frame, 8)[0] != crc16(frame[:8]):
        raise ValueError("DNP3 link header CRC error")
    data = bytearray()
    offset, remaining = LINK_HEADER, length - 5
    while remaining:
        size = min(BLOCK, remaining)
        block = frame[offset:offset + size]
        if struct.unpack_from("<H", frame, offset + size)[0] != crc16(block):
            raise ValueError("DNP3 data block CRC error")
        data += block
        offset += size + 2
        remaining -= size
    return control, dest, src, bytes(data)


def segments(fragment: bytes, seq: int) -> tuple[list[bytes], int]:
    """Transport segments (header + up to 249 octets) of an application fragment, and the next
    transport sequence number."""
    chunks = [fragment[i:i + SEGMENT_MAX] for i in range(0, len(fragment), SEGMENT_MAX)] or [b""]
    out = []
    for index, chunk in enumerate(chunks):
        header = (TR_FIR if index == 0 else 0) | (TR_FIN if index == len(chunks) - 1 else 0) | seq
        out.append(bytes([header]) + chunk)
        seq = (seq + 1) & 0x3F
    return out, seq


def time48(epoch_ms: int) -> bytes:
    """DNP3 absolute time: milliseconds since 1970-01-01 UTC, 48-bit little-endian."""
    return struct.pack("<Q", epoch_ms)[:6]


def epoch_ms(epoch: float) -> int:
    return round(epoch * 1000)


# --- application objects ---------------------------------------------------------------

@dataclass(frozen=True)
class PointType:
    group: int
    variation: int
    event_group: int | None = None
    event_variation: int | None = None
    event_class: int | None = None


# Point types in the order an outstation reports static data (binary, analog, counter, BO, AO).
POINT_TYPES = {
    "binary_inputs": PointType(1, 2, 2, 2, 1),
    "analog_inputs": PointType(30, 5, 32, 7, 2),
    "counters": PointType(20, 1),
    "binary_outputs": PointType(10, 2),
    "analog_outputs": PointType(40, 3),
}
BINARY_TYPES = ("binary_inputs", "binary_outputs")
EVENT_TYPES = ("binary_inputs", "analog_inputs")
# Process table each point type reads.
POINT_TABLES = {"binary_inputs": "discrete", "analog_inputs": "input", "counters": "input",
                "binary_outputs": "coils", "analog_outputs": "holding"}


def point_map(profile: ProcessProfile) -> dict[str, list[Point]]:
    """Process points per DNP3 point type; a point's index is its position in the list."""
    inputs = profile.table("input")
    counter = [p for p in inputs if p.model and p.model["type"] == "counter"]
    return {
        "binary_inputs": profile.table("discrete"),
        "analog_inputs": [p for p in inputs if p not in counter],
        "counters": counter,
        "binary_outputs": profile.table("coils"),
        "analog_outputs": profile.table("holding"),
    }


def deadband_span(point: Point) -> float:
    """Value range a relative deadband applies to: the normal band, else the nominal value."""
    if point.normal is not None:
        return point.normal[1] - point.normal[0]
    return abs(point.nominal) or 1.0


def _range_header(group: int, variation: int, start: int, stop: int) -> bytes:
    if stop <= 0xFF:
        return struct.pack("<BBBBB", group, variation, 0x00, start, stop)
    return struct.pack("<BBBHH", group, variation, 0x01, start, stop)


def static_objects(values: dict[str, list[float]]) -> bytes:
    """Class 0 data: every point type as a start-stop range of all its points."""
    out = bytearray()
    for kind, kind_type in POINT_TYPES.items():
        points = values.get(kind) or []
        if not points:
            continue
        out += _range_header(kind_type.group, kind_type.variation, 0, len(points) - 1)
        for value in points:
            if kind in BINARY_TYPES:
                out.append(ONLINE | (STATE if value >= 0.5 else 0))
            elif kind == "counters":
                out += struct.pack("<BI", ONLINE, int(value) & 0xFFFFFFFF)
            else:
                out += struct.pack("<Bf", ONLINE, value)
    return bytes(out)


@dataclass(frozen=True, eq=False)   # identity: two equal readings are still two events
class Event:
    kind: str          # "binary_inputs" or "analog_inputs"
    index: int
    value: float
    ms: int            # absolute time of occurrence, ms since the epoch

    @property
    def size(self) -> int:
        return 2 + (7 if self.kind == "binary_inputs" else 11)


EVENT_HEADER = 5                      # group, variation, qualifier 0x28, 16-bit count


def event_objects(events: list[Event]) -> bytes:
    """Event objects with 16-bit index prefixes (qualifier 0x28), one header per point type."""
    out = bytearray()
    for kind in EVENT_TYPES:
        chosen = [e for e in events if e.kind == kind]
        if not chosen:
            continue
        kind_type = POINT_TYPES[kind]
        out += struct.pack("<BBBH", kind_type.event_group, kind_type.event_variation, 0x28, len(chosen))
        for e in chosen:
            if kind == "binary_inputs":
                out += struct.pack("<HB", e.index, ONLINE | (STATE if e.value >= 0.5 else 0)) + time48(e.ms)
            else:
                out += struct.pack("<HBf", e.index, ONLINE, e.value) + time48(e.ms)
    return bytes(out)


def class_objects(classes: list[int]) -> bytes:
    """Class data object headers (g60v1 = class 0, g60v2-4 = classes 1-3), all objects."""
    return b"".join(struct.pack("<BBB", 60, c + 1, 0x06) for c in classes)


def crob_blocks(controls: list[tuple[int, int]], status: int = 0) -> bytes:
    """A g12v1 control-relay-output-block request / response body: the object header (qualifier
    0x17) and one CROB per ``(index, control code)`` - latch the relay once with no pulse timing
    and the given status octet (0 in a request, 0 = success when the outstation echoes it)."""
    out = bytearray(struct.pack("<BBBB", CROB_GROUP, CROB_VAR, CROB_QUALIFIER, len(controls)))
    for index, control_code in controls:
        out += struct.pack("<BBBIIB", index, control_code, 1, 0, 0, status)
    return bytes(out)


def parse_crob(data: bytes) -> tuple[list[tuple[int, int]], bool]:
    """(index, control code) of the CROB command objects of a control request (g12v1, qualifier
    0x17), and whether the request held only such objects."""
    controls: list[tuple[int, int]] = []
    offset = 0
    while offset < len(data):
        if len(data) - offset < 4:
            return controls, False
        group, variation, qualifier, count = data[offset:offset + 4]
        offset += 4
        if (group, variation) != (CROB_GROUP, CROB_VAR) or qualifier != CROB_QUALIFIER:
            return controls, False
        for _ in range(count):
            if len(data) - offset < 1 + CROB_SIZE:
                return controls, False
            controls.append((data[offset], data[offset + 1]))
            offset += 1 + CROB_SIZE
    return controls, True


def _request_objects(data: bytes):
    """(group, variation, indices, object payloads) of the object headers of a master request.
    Stops (yielding ``None``) at a qualifier or object it cannot size."""
    sizes = {(50, 1): 6, (50, 3): 6}
    offset = 0
    while offset < len(data):
        if len(data) - offset < 3:
            yield None
            return
        group, variation, qualifier = data[offset:offset + 3]
        offset += 3
        if qualifier == 0x06:
            yield group, variation, None, []
            continue
        if qualifier in (0x00, 0x01):
            fmt = "<BB" if qualifier == 0x00 else "<HH"
            start, stop = struct.unpack_from(fmt, data, offset)
            offset += struct.calcsize(fmt)
            indices = list(range(start, stop + 1))
        elif qualifier in (0x07, 0x08):
            fmt = "<B" if qualifier == 0x07 else "<H"
            count = struct.unpack_from(fmt, data, offset)[0]
            offset += struct.calcsize(fmt)
            indices = list(range(count))
        else:
            yield None
            return
        if (group, variation) == (80, 1):
            packed = data[offset:offset + -(-len(indices) // 8)]
            offset += len(packed)
            yield group, variation, indices, [(packed[i // 8] >> (i % 8)) & 1 for i in range(len(indices))]
        elif (group, variation) in sizes:
            size = sizes[(group, variation)]
            items = [data[offset + i * size:offset + (i + 1) * size] for i in range(len(indices))]
            offset += size * len(indices)
            yield group, variation, indices, items
        else:
            yield None
            return


# --- outstation ------------------------------------------------------------------------

@dataclass(frozen=True)
class OutstationConfig:
    profile: ProcessProfile
    address: int
    masters: tuple[int, ...]
    deadband: float
    transport_seq: dict[int, int]     # master address -> first transport sequence number
    unsolicited: bool                 # reports events unsolicited once a master enables it
    confirm_timeout: float            # seconds before an unconfirmed unsolicited response is repeated
    unsolicited_seq: dict[int, int]   # master address -> first unsolicited sequence number


@dataclass
class _Unsolicited:
    """An unsolicited response awaiting its confirm."""
    seq: int
    events: list[Event]
    fragment: bytes
    sent_t: float                     # virtual time of the last transmission


class _Association:
    """State an outstation keeps per master: IIN bits, event buffer, transport sequence, and the
    unsolicited reporting state of a master session."""

    def __init__(self, master: int, transport_seq: int, unsolicited_seq: int) -> None:
        self.master = master
        self.transport_seq = transport_seq
        self.restart = True
        self.need_time = True
        self.events: list[Event] = []
        self.unconfirmed: tuple[int, list[Event]] | None = None   # (app seq, events sent with CON)
        self.unsolicited_seq = unsolicited_seq     # next unsolicited sequence number (own 4-bit space)
        self.unsolicited_classes: set[int] = set()  # event classes the master enabled
        self.null_confirmed = False                 # the startup null unsolicited response was confirmed
        self.pending: _Unsolicited | None = None
        self.writer: asyncio.StreamWriter | None = None   # connection of the master session
        self.session: Dnp3Master | None = None             # its master (recording: same process)
        self.received = 0                                  # fragments processed from the session


def _requested_classes(data: bytes, first: int) -> tuple[list[int], bool]:
    """Classes named by the class object headers of a request (g60v1-4 = class 0-3, all objects),
    accepting classes from ``first``; and whether every header was such a class object."""
    classes = []
    for obj in _request_objects(data):
        if obj is None or obj[0] != 60 or obj[2] is not None or not first <= obj[1] - 1 <= 3:
            return classes, False
        classes.append(obj[1] - 1)
    return classes, True


class Outstation:
    """One outstation (one host): answers its masters' requests from the process simulation and,
    when configured for it, reports their events unsolicited. Changes are detected once and queued
    for every master associated at that time."""

    def __init__(self, rt, actor: Dnp3Server, host, config: OutstationConfig) -> None:
        self.rt, self.actor, self.host, self.config = rt, actor, host, config
        self.points = point_map(config.profile)
        self.deadbands = [config.deadband * deadband_span(p) for p in self.points["analog_inputs"]]
        self.associations: dict[int, _Association] = {}
        self.writers: set[asyncio.StreamWriter] = set()
        self.expected: dict[tuple[str, int], Dnp3Master] = {}   # master socket (ip, port) -> session
        self.reported_bits: list[bool] | None = None   # last reported state / event value per point
        self.reported_analogs: list[float] = []
        self.scanned_analogs: list[float] = []         # previous scan, for the deadband crossing time
        self.scanned_t = 0.0

    def association(self, master: int) -> _Association:
        if master not in self.associations:
            self.associations[master] = _Association(master, self.config.transport_seq[master],
                                                     self.config.unsolicited_seq[master])
        return self.associations[master]

    def expect(self, sockname: tuple[str, int], session: Dnp3Master) -> None:
        """Announce a master session connecting from ``sockname`` (before it connects): the
        outstation sends it unsolicited responses on the association of its master address."""
        self.expected[sockname] = session

    def _epoch_ms(self, t: float) -> int:
        return epoch_ms(self.rt.plan.start_epoch + t)

    def scan(self) -> dict[str, list[float]]:
        """Sample the process at the current virtual time, queue new events, return the values."""
        t = self.rt.clock.t
        sim = host_sim(self.rt, self.actor, self.host, self.config.profile)
        sim.advance(t)
        tables = {table: sim.values(table) for table in ("discrete", "input", "coils", "holding")}
        values = {kind: [tables[POINT_TABLES[kind]][p.name] for p in points]
                  for kind, points in self.points.items()}
        bits = [v >= 0.5 for v in values["binary_inputs"]]
        analogs = values["analog_inputs"]
        events = []
        if self.reported_bits is None:        # first contact after restart: the values are the reference
            self.reported_bits, self.reported_analogs = bits, list(analogs)
        else:
            for index, (old, new) in enumerate(zip(self.reported_bits, bits)):
                if old != new:
                    events.append(Event("binary_inputs", index, float(new), self._epoch_ms(t)))
            self.reported_bits = bits
            for index, value in enumerate(analogs):
                reference, band = self.reported_analogs[index], self.deadbands[index]
                if abs(value - reference) <= band:
                    continue
                previous = self.scanned_analogs[index]
                crossing = reference + math.copysign(band, value - reference)
                fraction = (crossing - previous) / (value - previous) if value != previous else 1.0
                when = self.scanned_t + min(max(fraction, 0.0), 1.0) * (t - self.scanned_t)
                events.append(Event("analog_inputs", index, value, self._epoch_ms(when)))
                self.reported_analogs[index] = value
        self.scanned_analogs, self.scanned_t = list(analogs), t
        for assoc in self.associations.values():
            assoc.events.extend(events)
        return values

    def _select(self, assoc: _Association, classes, room: int) -> list[Event]:
        """Buffered events of ``classes`` that fit in ``room`` octets, oldest first per point type;
        events in an unconfirmed unsolicited response are not reported again."""
        held = set(assoc.pending.events) if assoc.pending else set()
        ordered = sorted((e for e in assoc.events if POINT_TYPES[e.kind].event_class in classes and e not in held),
                         key=lambda e: (EVENT_TYPES.index(e.kind), e.ms))
        chosen = []
        for event in ordered:
            if event.size > room:
                break
            chosen.append(event)
            room -= event.size
        return chosen

    def _iin1(self, assoc: _Association, reported: list[Event]) -> int:
        """IIN1: restart, need time, and the classes of buffered events this response does not carry
        (nor an unconfirmed unsolicited response)."""
        iin1 = (IIN1_DEVICE_RESTART if assoc.restart else 0) | (IIN1_NEED_TIME if assoc.need_time else 0)
        held = set(reported)
        if assoc.pending:
            held.update(assoc.pending.events)
        for event in assoc.events:
            if event not in held:
                iin1 |= IIN1_CLASS[POINT_TYPES[event.kind].event_class]
        return iin1

    def handle(self, assoc: _Association, fragment: bytes) -> bytes | None:
        """Response fragment to one request fragment (``None`` for a confirm)."""
        if len(fragment) < 2:
            return None
        control, function = fragment[0], fragment[1]
        seq = control & 0x0F
        if function == FC_CONFIRM:
            if control & AC_UNS:
                pending = assoc.pending
                if pending is not None and pending.seq == seq:
                    confirmed = set(pending.events)
                    assoc.events = [e for e in assoc.events if e not in confirmed]
                    assoc.pending = None
                    assoc.null_confirmed = True
            elif assoc.unconfirmed is not None and assoc.unconfirmed[0] == seq:
                sent = set(assoc.unconfirmed[1])
                assoc.events = [e for e in assoc.events if e not in sent]
                assoc.unconfirmed = None
            return None
        values = self.scan()
        iin2 = 0
        objects = b""
        reported: list[Event] = []
        if function == FC_READ:
            classes, known = _requested_classes(fragment[2:], 0)
            if not known:
                iin2 |= IIN2_OBJECT_UNKNOWN
            static = static_objects(values) if 0 in classes else b""
            reported = self._select(assoc, classes, FRAGMENT_MAX - 4 - len(static) - EVENT_HEADER * len(EVENT_TYPES))
            objects = event_objects(reported) + static
        elif function == FC_WRITE:
            for obj in _request_objects(fragment[2:]):
                if obj is None:
                    iin2 |= IIN2_OBJECT_UNKNOWN
                    break
                group, variation, indices, items = obj
                if (group, variation) == (80, 1):
                    for index, bit in zip(indices, items):
                        if index != IIN_DEVICE_RESTART_INDEX or bit:
                            iin2 |= IIN2_PARAMETER_ERROR
                        else:
                            assoc.restart = False
                elif (group, variation) == (50, 3) and len(items) == 1:
                    assoc.need_time = False
                else:
                    iin2 |= IIN2_OBJECT_UNKNOWN
        elif function == FC_ENABLE_UNSOLICITED and not self.config.unsolicited:
            iin2 |= IIN2_NO_FUNC_CODE_SUPPORT
        elif function in (FC_ENABLE_UNSOLICITED, FC_DISABLE_UNSOLICITED):
            classes, known = _requested_classes(fragment[2:], 1)
            if not known:
                iin2 |= IIN2_OBJECT_UNKNOWN
            elif function == FC_ENABLE_UNSOLICITED:
                assoc.unsolicited_classes.update(classes)
            else:
                assoc.unsolicited_classes.difference_update(classes)
        elif function in (FC_SELECT, FC_OPERATE, FC_DIRECT_OPERATE):
            controls, known = parse_crob(fragment[2:])
            if not known:
                iin2 |= IIN2_OBJECT_UNKNOWN
            else:
                # SELECT only arms the point; OPERATE / DIRECT_OPERATE drive it. Echo the command
                # objects with a success status, as an outstation acknowledges a control.
                if function in (FC_OPERATE, FC_DIRECT_OPERATE):
                    self._apply_controls(controls)
                objects = crob_blocks(controls)
        elif function != FC_RECORD_CURRENT_TIME:
            iin2 |= IIN2_NO_FUNC_CODE_SUPPORT
        assoc.unconfirmed = (seq, reported) if reported else None
        response_control = AC_FIR | AC_FIN | (AC_CON if reported else 0) | seq
        return struct.pack("<BBBB", response_control, FC_RESPONSE, self._iin1(assoc, reported), iin2) + objects

    def _apply_controls(self, controls: list[tuple[int, int]]) -> None:
        """Drive the commanded binary outputs (latch on / off) into the process simulation, so the
        outstation reports the new output state on its next scan."""
        sim = host_sim(self.rt, self.actor, self.host, self.config.profile)
        sim.advance(self.rt.clock.t)
        outputs = self.points["binary_outputs"]
        for index, control_code in controls:
            op = control_code & 0x0F
            if 0 <= index < len(outputs) and op in (OP_LATCH_ON, OP_LATCH_OFF):
                sim.write("coils", outputs[index].address, [1 if op == OP_LATCH_ON else 0])

    def unsolicited(self, assoc: _Association) -> bytes | None:
        """The unsolicited response due on ``assoc`` now, if any: the null response that opens the
        session after a restart, the identical repeat (same sequence number) of an unconfirmed one
        once the confirm timeout has expired, or the buffered events of the enabled classes. Only one
        is outstanding at a time, and none while a solicited response awaits its confirm."""
        t = self.rt.clock.t
        pending = assoc.pending
        if pending is not None:
            if t - pending.sent_t < self.config.confirm_timeout:
                return None
            pending.sent_t = t
            return pending.fragment
        if not assoc.null_confirmed:
            events: list[Event] = []
        elif assoc.unconfirmed is not None or not assoc.unsolicited_classes:
            return None
        else:
            events = self._select(assoc, assoc.unsolicited_classes,
                                  FRAGMENT_MAX - 4 - EVENT_HEADER * len(EVENT_TYPES))
            if not events:
                return None
        seq = assoc.unsolicited_seq
        assoc.unsolicited_seq = (seq + 1) & 0x0F
        control = AC_FIR | AC_FIN | AC_CON | AC_UNS | seq
        fragment = struct.pack("<BBBB", control, FC_UNSOLICITED_RESPONSE, self._iin1(assoc, events), 0)
        fragment += event_objects(events)
        assoc.pending = _Unsolicited(seq, events, fragment, t)
        return fragment

    def _send(self, assoc: _Association, writer: asyncio.StreamWriter, fragment: bytes) -> None:
        pieces, assoc.transport_seq = segments(fragment, assoc.transport_seq)
        writer.write(b"".join(link_frame(PRM | UNCONFIRMED_USER_DATA, assoc.master, self.config.address, piece)
                              for piece in pieces))

    async def report(self, scan: bool = True) -> list[_Association]:
        """Send every master session the unsolicited response due, after sampling the process when
        ``scan`` (the follow-up reports of one scan only drain its events: sampling again at the same
        virtual time would draw fresh measurement noise and invent events). Returns the associations
        that got one (their master reads and confirms it)."""
        deadline = time.monotonic() + REPLY_TIMEOUT
        # The master's confirms get no reply: wait until every fragment it sent has been processed.
        while any(a.session is not None and a.received < a.session.sent for a in self.associations.values()):
            if time.monotonic() > deadline:
                raise RuntimeError("DNP3 outstation did not receive the master's confirm")
            await asyncio.sleep(0.0005)
        if scan:
            self.scan()
        sent = []
        for assoc in self.associations.values():
            fragment = self.unsolicited(assoc) if assoc.writer is not None else None
            if fragment is not None:
                self._send(assoc, assoc.writer, fragment)
                await assoc.writer.drain()
                sent.append(assoc)
        return sent

    async def connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.writers.add(writer)
        address = self.config.address
        session = self.expected.pop(writer.get_extra_info("peername")[:2], None)
        if session is not None:
            # A master session opens with a null unsolicited response; event reporting waits for its
            # confirm and for the master to enable it.
            assoc = self.association(session.master)
            assoc.writer, assoc.session, assoc.received = writer, session, 0
            assoc.null_confirmed, assoc.pending = False, None
            assoc.unsolicited_classes.clear()
            self._send(assoc, writer, self.unsolicited(assoc))
            await writer.drain()
        fragment = b""
        try:
            while True:
                header = await reader.readexactly(LINK_HEADER)
                if header[:2] != LINK_START or header[2] < 5:
                    break
                frame = header + await reader.readexactly(frame_size(header[2]) - LINK_HEADER)
                control, dest, src, data = parse_link(frame)
                if dest != address or src not in self.config.masters or control & (DIR | PRM) != DIR | PRM:
                    continue
                function = control & 0x0F
                if function == REQUEST_LINK_STATUS:
                    writer.write(link_frame(LINK_STATUS, src, address))
                    await writer.drain()
                    continue
                if function != UNCONFIRMED_USER_DATA or not data:
                    continue
                if data[0] & TR_FIR:
                    fragment = b""
                fragment += data[1:]
                if not data[0] & TR_FIN:
                    continue
                assoc = self.association(src)
                response = self.handle(assoc, fragment)
                assoc.received += 1
                fragment = b""
                if response is None:
                    continue
                self._send(assoc, writer, response)
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError, ValueError):
            pass
        finally:
            self.writers.discard(writer)
            for assoc in self.associations.values():
                if assoc.writer is writer:
                    assoc.writer = assoc.session = None
            writer.close()


class _Listener:
    """Adapter for ``Runtime.servers`` (which awaits ``shutdown()``)."""

    def __init__(self, server: asyncio.Server, outstation: Outstation) -> None:
        self.server, self.outstation = server, outstation

    async def shutdown(self) -> None:
        self.server.close()
        for writer in list(self.outstation.writers):
            writer.close()
        await self.server.wait_closed()


def _address(actor: Actor, name: str, value) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= MAX_ADDRESS:
        raise ScenarioError(f"{actor.id}: {name} must be a DNP3 link address 0..{MAX_ADDRESS}, not {value!r}")
    return value


def _seconds(actor: Actor, name: str, default: float, allow_zero: bool) -> float:
    value = float(actor.param(name, default) or 0)
    if value < 0 or (value == 0 and not allow_zero):
        raise ScenarioError(f"{actor.id}: {name} must be {'>= 0' if allow_zero else '> 0'}, not {value}")
    return value


def _flag(actor: Actor, name: str) -> bool:
    value = actor.param(name, False)
    if not isinstance(value, bool):
        raise ScenarioError(f"{actor.id}: {name} must be true or false, not {value!r}")
    return value


@register
class Dnp3Server(Actor):
    """DNP3 outstation (SEL RTAC style gateway) serving the host's process to its masters, polled or
    reporting events unsolicited."""

    type = "dnp3.server"
    is_server = True

    def plan(self) -> None:
        deadband = float(self.param("deadband", 0.02))
        if not 0 <= deadband < 1:
            raise ScenarioError(f"{self.id}: deadband is a fraction of the point's band, 0 <= deadband < 1")
        raw = self.param("master_address", 1)
        masters = tuple(_address(self, "master_address", m) for m in (raw if isinstance(raw, list) else [raw]))
        if not masters or len(set(masters)) != len(masters):
            raise ScenarioError(f"{self.id}: master_address must list distinct addresses")
        unsolicited = _flag(self, "unsolicited")
        scan_s = _seconds(self, "scan_s", 2.0, allow_zero=False)
        confirm_timeout = _seconds(self, "confirm_timeout_s", 5.0, allow_zero=False)
        fixed = self.param("address")
        self.configs: dict[str, OutstationConfig] = {}
        facts = []
        for host in self.hosts:
            profile = host_process(self, host)
            rng = self.rng.child(f"outstation:{host.id}")
            if fixed is not None:
                address = _address(self, "address", fixed)
            else:
                address = rng.randint(10, 1000)
                while address in masters:
                    address = rng.randint(10, 1000)
            if address in masters:
                raise ScenarioError(f"{self.id}: outstation address {address} is also a master address")
            config = OutstationConfig(profile, address, masters, deadband,
                                      {m: rng.randrange(64) for m in masters}, unsolicited, confirm_timeout,
                                      {m: rng.randrange(16) for m in masters})
            self.configs[host.id] = config
            if unsolicited:
                # The outstation's event scan: each one may send an unsolicited response.
                scans = self.rng.child(f"scan:{host.id}")
                t = scans.uniform(0.1, scan_s)
                while t < self.plan_.duration:
                    self.plan_.add(t, self.id, host.id, "dnp3.scan")
                    t += scans.jitter(scan_s, 0.02)
            identity = host.device.identity or {}
            facts.append({"host": host_ref(host.id), "process": profile.id, "address": address,
                          "master_addresses": list(masters), "product": identity.get("ProductCode"),
                          "points": point_facts(profile, deadband)})
        self.plan_.facts[self.id] = {"hosts": [host_ref(h.id) for h in self.hosts],
                                     "port": ports.WELL_KNOWN[ports.DNP3],
                                     "unsolicited": unsolicited, "deadband": deadband, "outstations": facts}
        if unsolicited:
            self.plan_.facts[self.id].update(scan_s=scan_s, confirm_timeout_s=confirm_timeout)

    async def serve(self, rt) -> None:
        self.outstations: dict[str, Outstation] = {}
        for host in self.hosts:
            outstation = self.outstations[host.id] = Outstation(rt, self, host, self.configs[host.id])
            server = await asyncio.start_server(outstation.connection, host.loopback, ports.DNP3)
            rt.servers.append(_Listener(server, outstation))

    def execute(self, action, rt) -> None:
        if action.op != "dnp3.scan":
            raise ValueError(f"unknown op {action.op}")
        outstation = self.outstations[action.host]
        scan = True
        while True:
            sent = asyncio.run_coroutine_threadsafe(outstation.report(scan), rt.loop).result(REPLY_TIMEOUT)
            scan = False
            if not sent:
                break
            # The master confirms at once; events that did not fit go out in the next response.
            for assoc in sent:
                assoc.session.unsolicited()


def point_facts(profile: ProcessProfile, deadband: float) -> dict[str, list[dict]]:
    """Point list per DNP3 point type: index, process point, object group/variation, events."""
    out = {}
    for kind, points in point_map(profile).items():
        kind_type = POINT_TYPES[kind]
        rows = []
        for index, p in enumerate(points):
            row = {"index": index, "point": p.name, "unit": p.unit, "desc": p.desc,
                   "group": kind_type.group, "variation": kind_type.variation}
            if kind_type.event_group is not None:
                row.update(event_group=kind_type.event_group, event_variation=kind_type.event_variation,
                           event_class=kind_type.event_class)
            if kind == "analog_inputs":
                row["deadband"] = round(deadband * deadband_span(p), 6)
            rows.append(row)
        out[kind] = rows
    return out


def serving_outstation(plan, host_id: str) -> tuple[Dnp3Server, OutstationConfig]:
    """The dnp3.server actor running the outstation on ``host_id`` and its configuration."""
    for actor in plan.actors:
        if isinstance(actor, Dnp3Server) and host_id in getattr(actor, "configs", {}):
            return actor, actor.configs[host_id]
    raise ScenarioError(f"no dnp3.server runs on host '{host_id}'")


# --- master ----------------------------------------------------------------------------

class Dnp3Master:
    """One master-to-outstation TCP channel with blocking request / response exchanges.

    A session that takes unsolicited responses is announced to the ``station`` (same process) before
    it connects; it confirms the null unsolicited response that opens the session."""

    def __init__(self, source: str, target: str, master: int, outstation: int, transport_seq: int,
                 app_seq: int, station: Outstation | None = None) -> None:
        self.master, self.outstation = master, outstation
        self.transport_seq, self.app_seq = transport_seq, app_seq
        self.sent = 0                  # application fragments sent
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self.sock.settimeout(REPLY_TIMEOUT)
            self.sock.bind((source, 0))
            if station is not None:
                station.expect(self.sock.getsockname()[:2], self)
            self.sock.connect((target, ports.DNP3))
            if station is not None:
                self.unsolicited()
        except BaseException:
            self.sock.close()
            raise

    def _recv(self, size: int) -> bytes:
        data = b""
        while len(data) < size:
            chunk = self.sock.recv(size - len(data))
            if not chunk:
                raise RuntimeError("DNP3 connection closed by the outstation")
            data += chunk
        return data

    def _frame(self) -> tuple[int, bytes]:
        header = self._recv(LINK_HEADER)
        if header[:2] != LINK_START or header[2] < 5:
            raise RuntimeError("DNP3 stream lost link frame sync")
        control, dest, src, data = parse_link(header + self._recv(frame_size(header[2]) - LINK_HEADER))
        if dest != self.master or src != self.outstation or control & DIR:
            raise RuntimeError(f"unexpected DNP3 frame {src} -> {dest}")
        return control, data

    def _fragment(self) -> bytes:
        """The next application fragment from the outstation, reassembled from its transport segments."""
        fragment = b""
        while True:
            control, data = self._frame()
            if control & 0x0F != UNCONFIRMED_USER_DATA or not data:
                continue
            if data[0] & TR_FIR:
                fragment = b""
            fragment += data[1:]
            if data[0] & TR_FIN:
                return fragment

    def _send(self, fragment: bytes) -> None:
        pieces, self.transport_seq = segments(fragment, self.transport_seq)
        self.sock.sendall(b"".join(link_frame(DIR | PRM | UNCONFIRMED_USER_DATA, self.outstation, self.master,
                                              piece) for piece in pieces))
        self.sent += 1

    def request(self, function: int, objects: bytes = b"") -> int:
        """Send one request, wait for its response, confirm it when asked; return the IIN."""
        seq = self.app_seq
        self.app_seq = (seq + 1) & 0x0F
        self._send(bytes([AC_FIR | AC_FIN | seq, function]) + objects)
        fragment = self._fragment()
        if len(fragment) < 4 or fragment[1] != FC_RESPONSE or fragment[0] & (AC_UNS | 0x0F) != seq:
            raise RuntimeError("DNP3 response does not answer the request")
        iin = fragment[2] << 8 | fragment[3]
        if fragment[3] & (IIN2_NO_FUNC_CODE_SUPPORT | IIN2_OBJECT_UNKNOWN | IIN2_PARAMETER_ERROR):
            raise RuntimeError(f"outstation rejected function {function} (IIN 0x{iin:04x})")
        if fragment[0] & AC_CON:
            self._send(bytes([AC_FIR | AC_FIN | seq, FC_CONFIRM]))
        return iin

    def unsolicited(self) -> int:
        """Read one unsolicited response and confirm it (CONFIRM with UNS and its sequence number);
        return the IIN."""
        fragment = self._fragment()
        if len(fragment) < 4 or fragment[1] != FC_UNSOLICITED_RESPONSE or not fragment[0] & AC_UNS:
            raise RuntimeError("expected a DNP3 unsolicited response")
        if fragment[0] & AC_CON:
            self._send(bytes([AC_FIR | AC_FIN | AC_UNS | fragment[0] & 0x0F, FC_CONFIRM]))
        return fragment[2] << 8 | fragment[3]

    def poll(self, classes: list[int]) -> None:
        """Class poll; events left behind (class IIN bits still set) are fetched by event polls."""
        iin = self.request(FC_READ, class_objects(classes))
        for _ in range(3):
            if not iin >> 8 & sum(IIN1_CLASS.values()):
                break
            iin = self.request(FC_READ, class_objects([1, 2, 3]))

    def link_status(self) -> None:
        self.sock.sendall(link_frame(DIR | PRM | REQUEST_LINK_STATUS, self.outstation, self.master))
        control, _ = self._frame()
        if control & 0x0F != LINK_STATUS or control & PRM:
            raise RuntimeError(f"expected LINK_STATUS, got control 0x{control:02x}")

    def close(self) -> None:
        self.sock.close()


EVENT_CLASSES = [1, 2, 3]
INTEGRITY_CLASSES = [1, 2, 3, 0]      # READ g60v2, g60v3, g60v4, g60v1


@register
class Dnp3Client(Actor):
    """SCADA DNP3 master: startup sequence, periodic event and integrity polls, link keep-alives, and
    (``unsolicited``) enabling and confirming the outstation's unsolicited responses."""

    type = "dnp3.client"

    def plan(self) -> None:
        plan = self.plan_
        targets = plan.topology.select(self.param("targets"))
        unsolicited = _flag(self, "unsolicited")
        integrity_s = _seconds(self, "integrity_s", 3600, allow_zero=False)
        # With unsolicited reporting the event poll is only a slow backstop.
        event_s = _seconds(self, "event_s", 300 if unsolicited else 5, allow_zero=True)
        link_status_s = _seconds(self, "link_status_s", 60, allow_zero=True)
        wanted = self.param("address")
        configs = {}
        self.servers: dict[str, Dnp3Server] = {}
        for target in targets:
            server, config = serving_outstation(plan, target.id)
            master = config.masters[0] if wanted is None else _address(self, "address", wanted)
            if master not in config.masters:
                raise ScenarioError(f"{self.id}: outstation on '{target.id}' accepts master addresses "
                                    f"{list(config.masters)}, not {master}")
            if unsolicited and not config.unsolicited:
                raise ScenarioError(f"{self.id}: outstation on '{target.id}' is not configured for unsolicited "
                                    "responses (set unsolicited on its dnp3.server)")
            configs[target.id] = (config, master)
            self.servers[target.id] = server
        self.intervals = (integrity_s, event_s, link_status_s)
        self.unsolicited = unsolicited
        sessions = []
        for host in self.hosts:
            for offset, target in enumerate(targets):
                config, master = configs[target.id]
                self._plan_session(host.id, target.id, config.address, master, 0.1 * offset)
                sessions.append({"host": host_ref(host.id), "target": host_ref(target.id),
                                 "master_address": master, "outstation_address": config.address})
        plan.facts[self.id] = {"hosts": [host_ref(h.id) for h in self.hosts],
                               "targets": [host_ref(t.id) for t in targets], "sessions": sessions,
                               "integrity_s": integrity_s, "event_s": event_s, "link_status_s": link_status_s,
                               "unsolicited": unsolicited}
        if unsolicited:
            plan.facts[self.id]["unsolicited_classes"] = list(EVENT_CLASSES)

    def _plan_session(self, host_id: str, target_id: str, outstation: int, master: int, offset: float) -> None:
        plan = self.plan_
        integrity_s, event_s, link_status_s = self.intervals
        rng = self.rng.child(f"{host_id}:{target_id}")

        def add(t: float, op: str, phase: str = "main", **args):
            return plan.add(t, self.id, host_id, op, phase=phase, target=target_id, **args)

        t = offset + rng.uniform(0, 0.05)
        add(t, "dnp3.connect", "setup", master=master, outstation=outstation,
            transport_seq=rng.randrange(64), app_seq=rng.randrange(16))
        # Startup: unsolicited off, integrity poll, clear DEVICE_RESTART, LAN time sync, then
        # (unsolicited) enable unsolicited reporting of the event classes.
        for op, extra in (("dnp3.disable_unsolicited", {}), ("dnp3.read", {"classes": INTEGRITY_CLASSES}),
                          ("dnp3.clear_restart", {}), ("dnp3.record_time", {})):
            t += rng.uniform(0.004, 0.03)
            recorded = add(t, op, "setup", **extra)
        t += rng.uniform(0.004, 0.03)
        add(t, "dnp3.write_time", "setup", time_ms=epoch_ms(plan.start_epoch + recorded.t))
        if self.unsolicited:
            t += rng.uniform(0.004, 0.03)
            add(t, "dnp3.enable_unsolicited", "setup")
        started = t
        integrity: list[float] = []
        tt = started + rng.jitter(integrity_s, 0.002)
        while tt < plan.duration:
            integrity.append(tt)
            tt += rng.jitter(integrity_s, 0.002)
        polls = [(when, INTEGRITY_CLASSES) for when in integrity]
        if event_s > 0:
            tt = started + rng.jitter(event_s, 0.01)
            while tt < plan.duration:
                if all(abs(tt - other) >= 1.0 for other in integrity):
                    polls.append((tt, EVENT_CLASSES))
                tt += rng.jitter(event_s, 0.01)
        polls.sort(key=lambda poll: poll[0])
        for when, classes in polls:
            add(when, "dnp3.read", classes=classes)
        # Keep-alive: REQUEST_LINK_STATUS whenever the channel has been idle for link_status_s.
        last = started
        for when in [poll[0] for poll in polls] + [plan.duration]:
            while link_status_s > 0 and when - last > link_status_s:
                last += link_status_s
                add(last, "dnp3.link_status")
            last = when
        add(plan.duration + 1.0, "dnp3.close", "teardown")

    def execute(self, action, rt) -> None:
        a = action.args
        key = (self.id, action.host, a["target"])
        if action.op == "dnp3.connect":
            server = self.servers[a["target"]]
            station = server.outstations[a["target"]] if server.configs[a["target"]].unsolicited else None
            rt.clients[key] = Dnp3Master(rt.loopback(action.host), rt.loopback(a["target"]), a["master"],
                                         a["outstation"], a["transport_seq"], a["app_seq"], station)
            return
        if action.op == "dnp3.close":
            rt.clients.pop(key).close()
            return
        master: Dnp3Master = rt.clients[key]
        if action.op == "dnp3.read":
            master.poll(a["classes"])
        elif action.op == "dnp3.disable_unsolicited":
            master.request(FC_DISABLE_UNSOLICITED, class_objects(EVENT_CLASSES))
        elif action.op == "dnp3.enable_unsolicited":
            master.request(FC_ENABLE_UNSOLICITED, class_objects(EVENT_CLASSES))
        elif action.op == "dnp3.clear_restart":
            # WRITE g80v1, start-stop 7-7, IIN1.7 DEVICE_RESTART = 0
            master.request(FC_WRITE, _range_header(80, 1, IIN_DEVICE_RESTART_INDEX, IIN_DEVICE_RESTART_INDEX)
                           + b"\x00")
        elif action.op == "dnp3.record_time":
            master.request(FC_RECORD_CURRENT_TIME)
        elif action.op == "dnp3.write_time":
            # WRITE g50v3 (absolute time at last recorded time), 8-bit count 1
            master.request(FC_WRITE, struct.pack("<BBBB", 50, 3, 0x07, 1) + time48(a["time_ms"]))
        elif action.op == "dnp3.link_status":
            master.link_status()
        else:
            raise ValueError(f"unknown op {action.op}")

    def close(self, rt) -> None:
        for key in [k for k in rt.clients if k[0] == self.id]:
            rt.clients.pop(key).close()


# --- incident: unauthorized control ----------------------------------------------------

@register
class Dnp3ControlInjection(Actor):
    """Unauthorized control from a host outside the approved SCADA path: the attacker opens a DNP3
    master channel to an outstation and issues control-relay-output-block commands
    (select-before-operate) that drive running actuators off - a process upset the SCADA master
    never requested. The outstation applies the operate and reports the new output state. MITRE
    ATT&CK for ICS: Unauthorized Command Message (T0855) and Manipulation of Control (T0831)."""

    type = "dnp3.control_injection"

    def plan(self) -> None:
        plan, rng = self.plan_, self.rng
        host = self.hosts[0]
        target = rng.choice(plan.topology.select(self.param("targets")))
        server, config = serving_outstation(plan, target.id)
        self.servers = {target.id: server}
        # The outstation keeps a separate association per master link address; the attacker takes a
        # configured address other than the approved client's (``masters[0]``) so the two sessions
        # do not share association state.
        master = next((m for m in config.masters if m != config.masters[0]), config.masters[0])
        # Running equipment the attacker can stop: writable binary outputs whose normal state is on.
        outputs = point_map(config.profile)["binary_outputs"]
        runnable = [(index, p) for index, p in enumerate(outputs)
                    if p.writable and p.nominal >= 0.5 and p.name.endswith("_run")]
        if not runnable:
            raise ScenarioError(f"{self.type} '{self.id}': outstation '{config.profile.id}' has no running "
                                "binary output to stop")
        count = max(1, min(int(self.param("controls", 1)), len(runnable)))
        chosen = sorted(rng.sample(runnable, count), key=lambda item: item[0])
        start_lo, start_hi = self.span(self.param("start", [0.35, 0.6]))
        spread = min(float(self.param("spread", 120)), plan.duration * 0.4)
        t0 = plan.duration * rng.uniform(start_lo, start_hi)
        t0 = min(t0, max(plan.duration - spread - 30, plan.duration * 0.1))

        plan.add(t0, self.id, host.id, "dnp3ci.connect", phase="setup", target=target.id, master=master,
                 outstation=config.address, transport_seq=rng.randrange(64), app_seq=rng.randrange(16))
        commands, first = [], None
        for order, (index, point) in enumerate(chosen):
            select_t = t0 + rng.uniform(0.1, 0.4) + order * (spread / max(count - 1, 1))
            operate_t = select_t + rng.uniform(1.0, 4.0)
            args = {"target": target.id, "index": index}
            select = plan.add(select_t, self.id, host.id, "dnp3ci.select", **args)
            operate = plan.add(operate_t, self.id, host.id, "dnp3ci.operate", **args)
            first = first or select
            commands.append({"index": index, "point": point.name, "desc": point.desc,
                             "function": DNP3_FUNCTION_NAMES[FC_OPERATE], "op": DNP3_OP_NAMES[OP_LATCH_OFF],
                             "value": 0, "action": "stop", "select": action_ref(select),
                             "request": action_ref(operate)})
            plan.event(operate, self.id, f"Stop {point.name} on {target.id} (DNP3 latch-off)",
                       ["T0855", "T0831"], point=point.name, index=index)
        plan.add(plan.duration + 1.0, self.id, host.id, "dnp3ci.close", phase="teardown", target=target.id)

        plan.facts[self.id] = {
            "source": host_ref(host.id),
            "target": host_ref(target.id),
            "master_address": master,
            "outstation_address": config.address,
            "command_count": len(commands),
            "commands": commands,
            "points_stopped": [c["point"] for c in commands],
            "point_names": sorted({c["point"] for c in commands}),
            "indices": [c["index"] for c in commands],
            "ioas": [c["index"] for c in commands],
            "function": DNP3_FUNCTION_NAMES[FC_OPERATE],
            "op": DNP3_OP_NAMES[OP_LATCH_OFF],
            "first_command": action_ref(first),
        }

    def execute(self, action, rt) -> None:
        a = action.args
        key = (self.id, action.host, a["target"])
        if action.op == "dnp3ci.connect":
            rt.clients[key] = Dnp3Master(rt.loopback(action.host), rt.loopback(a["target"]), a["master"],
                                         a["outstation"], a["transport_seq"], a["app_seq"])
            return
        if action.op == "dnp3ci.close":
            rt.clients.pop(key).close()
            return
        master: Dnp3Master = rt.clients[key]
        objects = crob_blocks([(a["index"], OP_LATCH_OFF)])
        if action.op == "dnp3ci.select":
            master.request(FC_SELECT, objects)
        elif action.op == "dnp3ci.operate":
            master.request(FC_OPERATE, objects)
        else:
            raise ValueError(f"unknown op {action.op}")

    def close(self, rt) -> None:
        for key in [k for k in rt.clients if k[0] == self.id]:
            rt.clients.pop(key).close()
