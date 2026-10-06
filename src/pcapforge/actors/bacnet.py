"""BACnet/IP actors (ASHRAE 135, Annex J): building controllers and a BMS operator workstation.

``bacnet.server`` is a building controller (Siemens PXC): the host's process model as BACnet
objects - analog inputs (input registers), analog values (setpoints), binary inputs (discrete
inputs) and binary values (coils) - plus the device object. It answers ReadProperty,
ReadPropertyMultiple and SubscribeCOV, broadcasts I-Am and sends UnconfirmedCOVNotifications from
its own planned actions (a COV scan reports the subscribed objects whose present value moved by
the COV increment or whose status flags changed). ``bacnet.client`` is the BMS workstation: Who-Is,
the device's identity and object list, its point database, COV subscriptions renewed before they
expire and cyclic ReadPropertyMultiple polls of present-value and status-flags.

Both sides talk 47808 <-> 47808 (recorded on ``ports.BACNET``); BVLC, NPDU and APDUs are encoded
here, so no BACnet stack is needed.
"""

from __future__ import annotations

import asyncio
import socket
import struct
from dataclasses import dataclass, field
from typing import Callable

from pcapforge import ports
from pcapforge.actors import register
from pcapforge.actors.base import Actor
from pcapforge.actors.modbus import host_process, host_sim
from pcapforge.plan import host_ref
from pcapforge.process import Point, ProcessProfile
from pcapforge.scenario import ScenarioError
from pcapforge.topology import SINKS

MAX_APDU = 1476                 # max-apdu-length-accepted of B/IP devices
MESSAGE_BUDGET = 1400           # largest BVLC message we let a request or response grow to
PROTOCOL_REVISION = 14
SEGMENTED_BOTH = 0
TIMEOUT_S = 3.0

# Object types and the process table each one carries.
ANALOG_INPUT, ANALOG_VALUE, BINARY_INPUT, BINARY_VALUE, DEVICE = 0, 2, 3, 5, 8
OBJECT_TYPE_NAMES = {ANALOG_INPUT: "analog-input", ANALOG_VALUE: "analog-value", BINARY_INPUT: "binary-input",
                     BINARY_VALUE: "binary-value", DEVICE: "device"}
TABLE_TYPES = (("input", ANALOG_INPUT), ("holding", ANALOG_VALUE), ("discrete", BINARY_INPUT),
               ("coils", BINARY_VALUE))
ANALOG = (ANALOG_INPUT, ANALOG_VALUE)

# Property identifiers.
ACTIVE_TEXT = 4
APDU_TIMEOUT = 11
APPLICATION_SOFTWARE_VERSION = 12
COV_INCREMENT = 22
DESCRIPTION = 28
EVENT_STATE = 36
FIRMWARE_REVISION = 44
INACTIVE_TEXT = 46
MAX_APDU_LENGTH_ACCEPTED = 62
MODEL_NAME = 70
NUMBER_OF_APDU_RETRIES = 73
OBJECT_IDENTIFIER = 75
OBJECT_LIST = 76
OBJECT_NAME = 77
OBJECT_TYPE = 79
OUT_OF_SERVICE = 81
PRESENT_VALUE = 85
PROTOCOL_VERSION = 98
SEGMENTATION_SUPPORTED = 107
STATUS_FLAGS = 111
SYSTEM_STATUS = 112
UNITS = 117
VENDOR_IDENTIFIER = 120
VENDOR_NAME = 121
PROTOCOL_REVISION_PROP = 139
DATABASE_REVISION = 155
STRUCTURED_OBJECT_LIST = 209

# Services.
SUBSCRIBE_COV, READ_PROPERTY, READ_PROPERTY_MULTIPLE = 5, 12, 14
I_AM, UNCONFIRMED_COV_NOTIFICATION, WHO_IS = 0, 2, 8
# APDU types.
CONFIRMED, UNCONFIRMED, SIMPLE_ACK, COMPLEX_ACK, SEGMENT_ACK, ERROR, REJECT, ABORT = range(8)
# Error classes / codes and reject reasons.
OBJECT_ERROR, PROPERTY_ERROR, SERVICES_ERROR = 1, 2, 5
UNKNOWN_OBJECT, UNKNOWN_PROPERTY, INVALID_ARRAY_INDEX = 31, 32, 42
OPTIONAL_FUNCTIONALITY_NOT_SUPPORTED, PROPERTY_IS_NOT_AN_ARRAY = 45, 50
REJECT_INVALID_TAG, REJECT_MISSING_PARAMETER, REJECT_UNRECOGNIZED_SERVICE = 4, 5, 9
# Event states.
NORMAL, HIGH_LIMIT, LOW_LIMIT = 0, 3, 4
IN_ALARM = 0x8  # status-flags bit (in-alarm, fault, overridden, out-of-service = 8, 4, 2, 1)

# Process profile unit -> BACnetEngineeringUnits (value, standard identifier).
ENGINEERING_UNITS = {
    "degC": (62, "degrees-celsius"), "degF": (64, "degrees-fahrenheit"), "K": (63, "degrees-kelvin"),
    "%": (98, "percent"), "Pa": (53, "pascals"), "kPa": (54, "kilopascals"), "bar": (55, "bars"),
    "ppm": (96, "parts-per-million"), "mA": (2, "milliamperes"), "A": (3, "amperes"), "V": (5, "volts"),
    "kV": (6, "kilovolts"), "kVA": (9, "kilovolt-amperes"), "MVA": (10, "megavolt-amperes"),
    "Mvar": (13, "megavolt-amperes-reactive"), "kWh": (19, "kilowatt-hours"), "MWh": (146, "megawatt-hours"),
    "kW": (48, "kilowatts"), "MW": (49, "megawatts"), "Hz": (27, "hertz"), "m": (31, "meters"),
    "cm": (118, "centimeters"), "m3": (80, "cubic-meters"), "m3/h": (135, "cubic-meters-per-hour"),
    "L/s": (87, "liters-per-second"), "h": (71, "hours"), "s": (73, "seconds"),
    "rpm": (104, "revolutions-per-minute"), "mg/L": (215, "milligrams-per-liter"), "pH": (234, "ph"),
    "NTU": (233, "nephelometric-turbidity-unit"),
}
NO_UNITS = (95, "no-units")

DEVICE_READS = (OBJECT_NAME, VENDOR_NAME, VENDOR_IDENTIFIER, MODEL_NAME, FIRMWARE_REVISION,
                APPLICATION_SOFTWARE_VERSION, PROTOCOL_VERSION, PROTOCOL_REVISION_PROP,
                MAX_APDU_LENGTH_ACCEPTED, SEGMENTATION_SUPPORTED, DATABASE_REVISION)
POINT_DATABASE = {ANALOG_INPUT: (OBJECT_NAME, DESCRIPTION, UNITS, COV_INCREMENT),
                  ANALOG_VALUE: (OBJECT_NAME, DESCRIPTION, UNITS),
                  BINARY_INPUT: (OBJECT_NAME, DESCRIPTION, ACTIVE_TEXT, INACTIVE_TEXT),
                  BINARY_VALUE: (OBJECT_NAME, DESCRIPTION, ACTIVE_TEXT, INACTIVE_TEXT)}
POLLED = (PRESENT_VALUE, STATUS_FLAGS)


class BacnetError(Exception):
    def __init__(self, error_class: int, code: int) -> None:
        super().__init__(f"BACnet error class {error_class} code {code}")
        self.error_class, self.code = error_class, code


class DecodeError(ValueError):
    pass


# --- encoding --------------------------------------------------------------------------

def _uint(value: int) -> bytes:
    return value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")


def tag(number: int, data: bytes, context: bool = False) -> bytes:
    """Tagged value: tag number, class and length/value/type (extended length when needed)."""
    first = (number << 4) | (0x08 if context else 0)
    size = len(data)
    if size < 5:
        return bytes([first | size]) + data
    if size < 254:
        return bytes([first | 5, size]) + data
    return bytes([first | 5, 254]) + struct.pack(">H", size) + data


def object_id(obj_type: int, instance: int) -> bytes:
    return struct.pack(">I", obj_type << 22 | instance)


def app_bool(value: bool) -> bytes:
    return bytes([0x10 | int(value)])


def app_uint(value: int) -> bytes:
    return tag(2, _uint(value))


def app_real(value: float) -> bytes:
    return tag(4, struct.pack(">f", value))


def app_string(value: str) -> bytes:
    return tag(7, b"\x00" + value.encode("utf-8"))  # character set 0: ANSI X3.4 / UTF-8


def app_bits(bits: int, count: int) -> bytes:
    """Bit string of ``count`` (<= 8) bits; bit 0 of the BACnet string is ``bits``' MSB."""
    return tag(8, bytes([8 - count, (bits << (8 - count)) & 0xFF]))


def app_enum(value: int) -> bytes:
    return tag(9, _uint(value))


def app_object(obj_type: int, instance: int) -> bytes:
    return tag(12, object_id(obj_type, instance))


def ctx_uint(number: int, value: int) -> bytes:
    return tag(number, _uint(value), context=True)


def ctx_object(number: int, obj_type: int, instance: int) -> bytes:
    return tag(number, object_id(obj_type, instance), context=True)


def ctx_bool(number: int, value: bool) -> bytes:
    return tag(number, bytes([int(value)]), context=True)


def opening(number: int) -> bytes:
    return bytes([number << 4 | 0x0E])


def closing(number: int) -> bytes:
    return bytes([number << 4 | 0x0F])


def message(apdu: bytes, broadcast: bool = False, expecting_reply: bool = False) -> bytes:
    """BVLC + NPDU around an APDU: Original-Unicast-NPDU, or Original-Broadcast-NPDU addressed
    to the global broadcast network (DNET 0xFFFF, hop count 255)."""
    control = 0x04 if expecting_reply else 0x00
    if broadcast:
        npdu = bytes([0x01, control | 0x20, 0xFF, 0xFF, 0x00, 0xFF])
    else:
        npdu = bytes([0x01, control])
    return struct.pack(">BBH", 0x81, 0x0B if broadcast else 0x0A, 4 + len(npdu) + len(apdu)) + npdu + apdu


def confirmed(invoke: int, service: int, body: bytes) -> bytes:
    """Confirmed-Request header: unsegmented, no segmented response accepted, 1476-byte APDUs."""
    return bytes([CONFIRMED << 4, 0x05, invoke, service]) + body


def complex_ack(invoke: int, service: int, body: bytes) -> bytes:
    return bytes([COMPLEX_ACK << 4, invoke, service]) + body


def error_pdu(invoke: int, service: int, error: BacnetError) -> bytes:
    return bytes([ERROR << 4, invoke, service]) + app_enum(error.error_class) + app_enum(error.code)


def who_is() -> bytes:
    return message(bytes([UNCONFIRMED << 4, WHO_IS]), broadcast=True)


def read_property(invoke: int, obj: tuple[int, int], prop: int, index: int | None = None) -> bytes:
    body = ctx_object(0, *obj) + ctx_uint(1, prop) + (b"" if index is None else ctx_uint(2, index))
    return confirmed(invoke, READ_PROPERTY, body)


def read_property_multiple(invoke: int, specs: list) -> bytes:
    """``specs``: [[object type, instance, [property, ...]], ...]."""
    body = b"".join(ctx_object(0, t, i) + opening(1) + b"".join(ctx_uint(0, p) for p in props) + closing(1)
                    for t, i, props in specs)
    return confirmed(invoke, READ_PROPERTY_MULTIPLE, body)


def subscribe_cov(invoke: int, process_id: int, obj: tuple[int, int], lifetime: int) -> bytes:
    body = ctx_uint(0, process_id) + ctx_object(1, *obj) + ctx_bool(2, False) + ctx_uint(3, lifetime)
    return confirmed(invoke, SUBSCRIBE_COV, body)


# --- decoding --------------------------------------------------------------------------

def apdu_of(data: bytes) -> bytes:
    """APDU of a BVLC Original-Unicast/Broadcast-NPDU message (b"" for network-layer messages)."""
    if len(data) < 6 or data[0] != 0x81 or data[1] not in (0x0A, 0x0B) or data[4] != 0x01:
        raise DecodeError("not a BACnet/IP NPDU")
    control, pos = data[5], 6
    if control & 0x20:                     # destination network / address
        pos += 3 + data[pos + 2]
    if control & 0x08:                     # source network / address
        pos += 3 + data[pos + 2]
    if control & 0x20:                     # hop count
        pos += 1
    return b"" if control & 0x80 else data[pos:]


class Reader:
    """Sequential reader of tagged values."""

    def __init__(self, data: bytes) -> None:
        self.data, self.pos = data, 0

    def done(self) -> bool:
        return self.pos >= len(self.data)

    def _header(self) -> tuple[int, bool, int, int]:
        if self.done():
            raise DecodeError("missing tag")
        first = self.data[self.pos]
        number, context, lvt, pos = first >> 4, bool(first & 0x08), first & 0x07, self.pos + 1
        if number == 15:
            number, pos = self.data[pos], pos + 1
        return number, context, lvt, pos

    def at(self, number: int, kind: str = "data") -> bool:
        """Is the next tag context tag ``number`` of ``kind`` (data / open / close)?"""
        if self.done():
            return False
        tag_number, context, lvt, _ = self._header()
        found = {6: "open", 7: "close"}.get(lvt, "data") if context else None
        return context and tag_number == number and found == kind

    def context(self, number: int) -> bytes:
        if not self.at(number):
            raise DecodeError(f"expected context tag {number}")
        _, _, size, pos = self._header()
        if size == 5:
            size, pos = self.data[pos], pos + 1
            if size == 254:
                size, pos = struct.unpack_from(">H", self.data, pos)[0], pos + 2
            elif size == 255:
                size, pos = struct.unpack_from(">I", self.data, pos)[0], pos + 4
        if pos + size > len(self.data):
            raise DecodeError("truncated value")
        self.pos = pos + size
        return self.data[pos:self.pos]

    def unsigned(self, number: int) -> int:
        return int.from_bytes(self.context(number), "big")

    def object(self, number: int) -> tuple[int, int]:
        value = self.context(number)
        if len(value) != 4:
            raise DecodeError("object identifier is not 4 bytes")
        raw = int.from_bytes(value, "big")
        return raw >> 22, raw & 0x3FFFFF

    def optional_unsigned(self, number: int) -> int | None:
        return self.unsigned(number) if self.at(number) else None

    def enter(self, number: int) -> None:
        if not self.at(number, "open"):
            raise DecodeError(f"expected opening tag {number}")
        self.pos = self._header()[3]

    def leave(self, number: int) -> bool:
        """Consume closing tag ``number`` if it is next."""
        if self.at(number, "close"):
            self.pos = self._header()[3]
            return True
        return False


# --- controller object model -----------------------------------------------------------

@dataclass(frozen=True)
class BacObject:
    type: int
    instance: int
    name: str
    description: str
    point: Point
    units: tuple[int, str] | None = None     # analog objects
    cov_increment: float | None = None       # analog objects

    @property
    def key(self) -> tuple[int, int]:
        return self.type, self.instance


Snapshot = Callable[[str], dict[str, float]]


def engineering_units(unit: str) -> tuple[int, str]:
    return ENGINEERING_UNITS.get(unit, NO_UNITS)


def objects_of(profile: ProcessProfile, cov_increment: float) -> list[BacObject]:
    """BACnet objects of a process, numbered from 1 per object type in register order."""
    out = []
    for table, obj_type in TABLE_TYPES:
        for instance, p in enumerate(profile.table(table), start=1):
            units = increment = None
            if obj_type in ANALOG:
                units = engineering_units(p.unit)
                span = (p.normal[1] - p.normal[0]) if p.normal else max(abs(p.nominal), 1.0)
                increment = float(f"{cov_increment * span:.3g}")
            out.append(BacObject(obj_type, instance, p.name, p.desc or p.name, p, units, increment))
    return out


@dataclass
class Controller:
    """One building controller: its device object and the process objects it serves."""

    host_id: str
    instance: int
    name: str
    description: str
    vendor_name: str
    vendor_id: int
    model: str
    firmware: str
    application: str
    database_revision: int
    objects: list[BacObject]
    by_key: dict[tuple[int, int], BacObject] = field(init=False)

    def __post_init__(self) -> None:
        self.by_key = {o.key: o for o in self.objects}

    @property
    def device(self) -> tuple[int, int]:
        return DEVICE, self.instance

    def object_list(self) -> list[tuple[int, int]]:
        return [self.device] + [o.key for o in self.objects]

    def status(self, obj: BacObject, value: float) -> tuple[int, int]:
        """(status-flags, event-state): analog inputs alarm outside their normal band."""
        p = obj.point
        if obj.type == ANALOG_INPUT and p.normal:
            if value > p.normal[1]:
                return IN_ALARM, HIGH_LIMIT
            if value < p.normal[0]:
                return IN_ALARM, LOW_LIMIT
        return 0, NORMAL

    def present_value(self, obj: BacObject, snapshot: Snapshot) -> float:
        return snapshot(obj.point.table)[obj.point.name]

    def encode_present_value(self, obj: BacObject, value: float) -> bytes:
        return app_real(value) if obj.type in ANALOG else app_enum(int(value >= 0.5))

    def read(self, key: tuple[int, int], prop: int, index: int | None, snapshot: Snapshot) -> bytes:
        """Application-tagged value of a property; raises ``BacnetError``."""
        if key == self.device:
            return self._read_device(prop, index)
        obj = self.by_key.get(key)
        if obj is None:
            raise BacnetError(OBJECT_ERROR, UNKNOWN_OBJECT)
        if index is not None:
            raise BacnetError(PROPERTY_ERROR, PROPERTY_IS_NOT_AN_ARRAY)
        if prop == OBJECT_IDENTIFIER:
            return app_object(*obj.key)
        if prop == OBJECT_NAME:
            return app_string(obj.name)
        if prop == OBJECT_TYPE:
            return app_enum(obj.type)
        if prop == DESCRIPTION:
            return app_string(obj.description)
        if prop == OUT_OF_SERVICE:
            return app_bool(False)
        if prop in (PRESENT_VALUE, STATUS_FLAGS, EVENT_STATE):
            value = self.present_value(obj, snapshot)
            if prop == PRESENT_VALUE:
                return self.encode_present_value(obj, value)
            flags, state = self.status(obj, value)
            return app_bits(flags, 4) if prop == STATUS_FLAGS else app_enum(state)
        if obj.type in ANALOG and prop == UNITS:
            return app_enum(obj.units[0])
        if obj.type in ANALOG and prop == COV_INCREMENT:
            return app_real(obj.cov_increment)
        if obj.type not in ANALOG and prop == ACTIVE_TEXT:
            return app_string("On" if obj.type == BINARY_VALUE else "Active")
        if obj.type not in ANALOG and prop == INACTIVE_TEXT:
            return app_string("Off" if obj.type == BINARY_VALUE else "Inactive")
        raise BacnetError(PROPERTY_ERROR, UNKNOWN_PROPERTY)

    def _read_device(self, prop: int, index: int | None) -> bytes:
        if prop == OBJECT_LIST:
            objects = self.object_list()
            if index is None:
                return b"".join(app_object(*o) for o in objects)
            if index == 0:
                return app_uint(len(objects))
            if index > len(objects):
                raise BacnetError(PROPERTY_ERROR, INVALID_ARRAY_INDEX)
            return app_object(*objects[index - 1])
        values = {
            OBJECT_IDENTIFIER: lambda: app_object(*self.device),
            OBJECT_NAME: lambda: app_string(self.name),
            OBJECT_TYPE: lambda: app_enum(DEVICE),
            SYSTEM_STATUS: lambda: app_enum(0),  # operational
            VENDOR_NAME: lambda: app_string(self.vendor_name),
            VENDOR_IDENTIFIER: lambda: app_uint(self.vendor_id),
            MODEL_NAME: lambda: app_string(self.model),
            FIRMWARE_REVISION: lambda: app_string(self.firmware),
            APPLICATION_SOFTWARE_VERSION: lambda: app_string(self.application),
            DESCRIPTION: lambda: app_string(self.description),
            PROTOCOL_VERSION: lambda: app_uint(1),
            PROTOCOL_REVISION_PROP: lambda: app_uint(PROTOCOL_REVISION),
            MAX_APDU_LENGTH_ACCEPTED: lambda: app_uint(MAX_APDU),
            SEGMENTATION_SUPPORTED: lambda: app_enum(SEGMENTED_BOTH),
            APDU_TIMEOUT: lambda: app_uint(3000),
            NUMBER_OF_APDU_RETRIES: lambda: app_uint(3),
            DATABASE_REVISION: lambda: app_uint(self.database_revision),
        }
        if prop not in values:
            raise BacnetError(PROPERTY_ERROR, UNKNOWN_PROPERTY)
        if index is not None:
            raise BacnetError(PROPERTY_ERROR, PROPERTY_IS_NOT_AN_ARRAY)
        return values[prop]()

    def read_ack(self, key: tuple[int, int], prop: int, index: int | None, snapshot: Snapshot) -> bytes:
        """ReadProperty-ACK service data."""
        value = self.read(key, prop, index, snapshot)
        return (ctx_object(0, *key) + ctx_uint(1, prop) + (b"" if index is None else ctx_uint(2, index))
                + opening(3) + value + closing(3))

    def rpm_ack(self, specs: list, snapshot: Snapshot) -> bytes:
        """ReadPropertyMultiple-ACK service data: a value or an access error per property."""
        out = []
        for obj_type, instance, refs in specs:
            out.append(ctx_object(0, obj_type, instance) + opening(1))
            for prop, index in refs:
                out.append(ctx_uint(2, prop) + (b"" if index is None else ctx_uint(3, index)))
                try:
                    out.append(opening(4) + self.read((obj_type, instance), prop, index, snapshot) + closing(4))
                except BacnetError as exc:
                    out.append(opening(5) + app_enum(exc.error_class) + app_enum(exc.code) + closing(5))
            out.append(closing(1))
        return b"".join(out)

    def i_am(self) -> bytes:
        return message(bytes([UNCONFIRMED << 4, I_AM]) + app_object(*self.device) + app_uint(MAX_APDU)
                       + app_enum(SEGMENTED_BOTH) + app_uint(self.vendor_id), broadcast=True)

    def nominal(self, table: str) -> dict[str, float]:
        """Plan-time stand-in snapshot (encoded sizes do not depend on the values)."""
        return {o.point.name: o.point.nominal for o in self.objects if o.point.table == table}


def rpm_chunks(controller: Controller, objects: list[BacObject], props: Callable[[BacObject], tuple]) -> list:
    """Split ReadPropertyMultiple specs so request and acknowledgement stay inside one message."""
    chunks: list[list] = []
    for obj in objects:
        spec = [obj.type, obj.instance, list(props(obj))]
        candidate = (chunks[-1] if chunks else []) + [spec]
        refs = [[t, i, [(p, None) for p in ps]] for t, i, ps in candidate]
        ack = len(message(complex_ack(0, READ_PROPERTY_MULTIPLE, controller.rpm_ack(refs, controller.nominal))))
        request = len(message(read_property_multiple(0, candidate), expecting_reply=True))
        if chunks and max(ack, request) <= MESSAGE_BUDGET:
            chunks[-1] = candidate
        else:
            chunks.append([spec])
    return chunks


# --- server ----------------------------------------------------------------------------

@dataclass
class _Subscription:
    address: tuple[str, int]
    process_id: int
    obj: BacObject
    start: float
    lifetime: int
    value: float
    flags: int


class _Device(asyncio.DatagramProtocol):
    """One controller's B/IP port. Replies and server-initiated messages go out with a plain
    ``sendto`` on the bound socket, so a datagram is on the wire when the call returns."""

    def __init__(self, rt, controller: Controller, sim, sock: socket.socket) -> None:
        self.rt, self.controller, self.sim, self.sock = rt, controller, sim, sock
        self.transport = None
        self.subscriptions: dict[tuple, _Subscription] = {}

    def connection_made(self, transport) -> None:
        self.transport = transport

    def error_received(self, exc) -> None:  # ICMP unreachable of an earlier datagram
        pass

    async def shutdown(self) -> None:
        if self.transport is not None:
            self.transport.close()

    def snapshot(self) -> Snapshot:
        self.sim.advance(self.rt.clock.t)
        cache: dict[str, dict[str, float]] = {}

        def values(table: str) -> dict[str, float]:
            if table not in cache:
                cache[table] = self.sim.values(table)
            return cache[table]
        return values

    def datagram_received(self, data: bytes, addr) -> None:
        try:
            apdu = apdu_of(data)
        except (DecodeError, IndexError):
            return
        if len(apdu) < 4 or apdu[0] >> 4 != CONFIRMED or apdu[0] & 0x08:
            return  # unconfirmed requests, acknowledgements and segments need no answer here
        invoke, service = apdu[2], apdu[3]
        try:
            replies = self.confirmed(service, invoke, Reader(apdu[4:]), addr)
        except (DecodeError, IndexError, struct.error) as exc:
            reason = REJECT_MISSING_PARAMETER if "missing" in str(exc) else REJECT_INVALID_TAG
            replies = [bytes([REJECT << 4, invoke, reason])]
        except BacnetError as exc:
            replies = [error_pdu(invoke, service, exc)]
        for reply in replies:
            self.sock.sendto(message(reply), addr)

    def confirmed(self, service: int, invoke: int, reader: Reader, addr) -> list[bytes]:
        controller = self.controller
        if service == READ_PROPERTY:
            key, prop = reader.object(0), reader.unsigned(1)
            index = reader.optional_unsigned(2)
            return [complex_ack(invoke, service, controller.read_ack(key, prop, index, self.snapshot()))]
        if service == READ_PROPERTY_MULTIPLE:
            specs = []
            while not reader.done():
                key = reader.object(0)
                reader.enter(1)
                refs = []
                while not reader.leave(1):
                    refs.append((reader.unsigned(0), reader.optional_unsigned(1)))
                specs.append([*key, refs])
            if not specs:
                raise DecodeError("missing read access specification")
            return [complex_ack(invoke, service, controller.rpm_ack(specs, self.snapshot()))]
        if service == SUBSCRIBE_COV:
            return self.subscribe(invoke, reader, addr)
        return [bytes([REJECT << 4, invoke, REJECT_UNRECOGNIZED_SERVICE])]

    def subscribe(self, invoke: int, reader: Reader, addr) -> list[bytes]:
        process_id, key = reader.unsigned(0), reader.object(1)
        confirmed_notifications = reader.context(2)[0] != 0 if reader.at(2) else None
        lifetime = reader.optional_unsigned(3)
        obj = self.controller.by_key.get(key)
        if obj is None:
            raise BacnetError(OBJECT_ERROR, UNKNOWN_OBJECT)
        sub_key = (addr, process_id, key)
        ack = bytes([SIMPLE_ACK << 4, invoke, SUBSCRIBE_COV])
        if confirmed_notifications is None:     # cancellation
            self.subscriptions.pop(sub_key, None)
            return [ack]
        if confirmed_notifications:
            raise BacnetError(SERVICES_ERROR, OPTIONAL_FUNCTIONALITY_NOT_SUPPORTED)
        snapshot = self.snapshot()
        value = self.controller.present_value(obj, snapshot)
        sub = _Subscription(addr, process_id, obj, self.rt.clock.t, lifetime or 0, value,
                            self.controller.status(obj, value)[0])
        self.subscriptions[sub_key] = sub
        # A new or renewed subscription is answered with the current values at once.
        return [ack, self.notification(sub, value, sub.flags)]

    def notification(self, sub: _Subscription, value: float, flags: int) -> bytes:
        remaining = 0 if not sub.lifetime else max(0, round(sub.lifetime - (self.rt.clock.t - sub.start)))
        values = (ctx_uint(0, PRESENT_VALUE) + opening(2) + self.controller.encode_present_value(sub.obj, value)
                  + closing(2) + ctx_uint(0, STATUS_FLAGS) + opening(2) + app_bits(flags, 4) + closing(2))
        return (bytes([UNCONFIRMED << 4, UNCONFIRMED_COV_NOTIFICATION]) + ctx_uint(0, sub.process_id)
                + ctx_object(1, *self.controller.device) + ctx_object(2, *sub.obj.key)
                + ctx_uint(3, remaining) + opening(4) + values + closing(4))

    async def scan_cov(self) -> None:
        """Notify subscribers of objects that changed by their COV increment or status."""
        now = self.rt.clock.t
        snapshot = self.snapshot()
        for sub_key, sub in list(self.subscriptions.items()):
            if sub.lifetime and now - sub.start >= sub.lifetime:
                del self.subscriptions[sub_key]
                continue
            value = self.controller.present_value(sub.obj, snapshot)
            flags = self.controller.status(sub.obj, value)[0]
            if sub.obj.type in ANALOG:
                moved = abs(value - sub.value) >= sub.obj.cov_increment
            else:
                moved = (value >= 0.5) != (sub.value >= 0.5)
            if moved or flags != sub.flags:
                sub.value, sub.flags = value, flags
                self.sock.sendto(message(self.notification(sub, value, flags)), sub.address)

    async def send_i_am(self) -> None:
        self.sock.sendto(self.controller.i_am(), (SINKS["broadcast"].loopback, ports.BACNET))


@register
class BacnetServer(Actor):
    """Building controller (Siemens PXC): the host's process as BACnet/IP objects."""

    type = "bacnet.server"
    is_server = True
    sinks = (("broadcast", ports.BACNET),)

    def plan(self) -> None:
        plan = self.plan_
        increment = float(self.param("cov_increment", 0.02))
        scan = float(self.param("cov_scan_s", 5.0))
        if not 0 < increment < 1:
            raise ScenarioError(f"{self.id}: cov_increment is a fraction of the normal band (0 < x < 1)")
        if scan <= 0:
            raise ScenarioError(f"{self.id}: cov_scan_s must be positive")
        first = self.param("device_instance")
        if first is None:
            first = self.rng.child("device_instance").randrange(100, 4000) * 100 + 1
        first = int(first)
        if first < 0 or first + len(self.hosts) - 1 > 4194302:
            raise ScenarioError(f"{self.id}: device_instance must lie in 0..4194302")
        self.profiles: dict[str, ProcessProfile] = {}
        self.controllers: dict[str, Controller] = {}
        facts = []
        for index, host in enumerate(self.hosts):
            profile = self.profiles[host.id] = host_process(self, host)
            controller = self.controllers[host.id] = self._controller(host, profile, first + index, increment)
            facts.append({
                "host": host_ref(host.id), "process": profile.id, "device_instance": controller.instance,
                "device_name": controller.name, "vendor_id": controller.vendor_id,
                "vendor_name": controller.vendor_name, "model_name": controller.model,
                "firmware_revision": controller.firmware, "application_software_version": controller.application,
                "objects": [{"type": OBJECT_TYPE_NAMES[o.type], "instance": o.instance, "point": o.point.name,
                             "name": o.name, "description": o.description,
                             **({"units": o.units[1], "units_id": o.units[0], "cov_increment": o.cov_increment}
                                if o.units else {})}
                            for o in controller.objects],
            })
            if self._subscribed(host):
                rng = self.rng.child(f"cov:{host.id}")
                t = rng.uniform(0.5, scan)
                while t < plan.duration:
                    plan.add(t, self.id, host.id, "bacnet.cov")
                    t += rng.jitter(scan, 0.02)
        plan.facts[self.id] = {"hosts": [host_ref(h.id) for h in self.hosts], "cov_increment": increment,
                               "cov_scan_s": scan, "controllers": facts}

    def _subscribed(self, host) -> bool:
        """Does any bacnet.client subscribe to COV on ``host``?"""
        return any(isinstance(actor, BacnetClient) and actor.param("cov", 3)
                   and any(t.id == host.id for t in self.plan_.topology.select(actor.param("targets")))
                   for actor in self.plan_.actors)

    def _controller(self, host, profile: ProcessProfile, instance: int, increment: float) -> Controller:
        identity = host.device.identity or {}
        if "VendorId" not in identity:
            raise ScenarioError(f"{self.id}: device '{host.device.name}' of host '{host.id}' has no BACnet "
                                "identity (identity VendorId)")
        rng = self.rng.child(f"identity:{host.id}")
        return Controller(
            host_id=host.id, instance=instance, name=host.name, description=profile.title,
            vendor_name=identity.get("VendorName", host.device.vendor), vendor_id=int(identity["VendorId"]),
            model=identity.get("ProductCode", ""), firmware=identity.get("MajorMinorRevision", ""),
            application=f"V{rng.randint(1, 4)}.{rng.randint(0, 30):02d}",
            database_revision=rng.randint(3, 400), objects=objects_of(profile, increment))

    async def serve(self, rt) -> None:
        loop = asyncio.get_running_loop()
        self.devices: dict[str, _Device] = {}
        for host in self.hosts:
            sim = host_sim(rt, self, host, self.profiles[host.id])
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind((host.loopback, ports.BACNET))
            sock.setblocking(False)
            controller = self.controllers[host.id]
            _, device = await loop.create_datagram_endpoint(lambda: _Device(rt, controller, sim, sock), sock=sock)
            self.devices[host.id] = device
            rt.servers.append(device)

    def execute(self, action, rt) -> None:
        device = self.devices[action.host]
        if action.op == "bacnet.iam":
            coro = device.send_i_am()
        elif action.op == "bacnet.cov":
            coro = device.scan_cov()
        else:
            raise ValueError(f"unknown op {action.op}")
        asyncio.run_coroutine_threadsafe(coro, rt.loop).result(TIMEOUT_S)


def serving_controller(plan, host_id: str) -> tuple[BacnetServer, Controller]:
    """The bacnet.server actor on ``host_id`` and the controller it runs there."""
    for actor in plan.actors:
        if isinstance(actor, BacnetServer) and host_id in getattr(actor, "controllers", {}):
            return actor, actor.controllers[host_id]
    raise ScenarioError(f"no bacnet.server runs on host '{host_id}'")


# --- client ----------------------------------------------------------------------------

def _transact(sock: socket.socket, target: tuple[str, int], apdu: bytes, invoke: int) -> bytes:
    """Send a confirmed request and return the answer with its invoke id (other datagrams,
    e.g. COV notifications that arrived since the last request, are skipped)."""
    sock.sendto(message(apdu, expecting_reply=True), target)
    while True:
        data, addr = sock.recvfrom(2048)
        if addr != target:
            continue
        reply = apdu_of(data)
        if len(reply) >= 2 and reply[0] >> 4 in (SIMPLE_ACK, COMPLEX_ACK, ERROR, REJECT, ABORT) \
                and reply[1] == invoke:
            return reply


def _await_notification(sock: socket.socket, target: tuple[str, int], obj: tuple[int, int]) -> None:
    while True:
        data, addr = sock.recvfrom(2048)
        reply = apdu_of(data)
        if addr != target or reply[:2] != bytes([UNCONFIRMED << 4, UNCONFIRMED_COV_NOTIFICATION]):
            continue
        reader = Reader(reply[2:])
        reader.unsigned(0)
        reader.object(1)
        if reader.object(2) == tuple(obj):
            return


@register
class BacnetClient(Actor):
    """BMS operator workstation: discovery, point database, COV subscriptions and RPM polls."""

    type = "bacnet.client"
    sinks = (("broadcast", ports.BACNET),)

    def plan(self) -> None:
        plan = self.plan_
        targets = plan.topology.select(self.param("targets"))
        if not targets:
            raise ScenarioError(f"{self.id}: params.targets names no controller")
        poll = float(self.param("poll_s", 30))
        lifetime = int(self.param("cov_lifetime_s", 300))
        whois = float(self.param("whois_s", 0) or 0)
        if poll <= 0:
            raise ScenarioError(f"{self.id}: poll_s must be positive")
        if lifetime < 60:
            raise ScenarioError(f"{self.id}: cov_lifetime_s must be at least 60")
        if whois < 0:
            raise ScenarioError(f"{self.id}: whois_s must be 0 (startup only) or positive")
        controllers = {t.id: serving_controller(plan, t.id)[1] for t in targets}
        cov = {t.id: self._cov_objects(controllers[t.id]) for t in targets}
        hosts_facts = []
        for host in self.hosts:
            rng = self.rng.child(host.id)
            process_id = rng.randint(1, 255)
            requests: dict[str, list] = {t.id: [] for t in targets}
            t = first_who_is = rng.uniform(0.3, 2.0)
            self._who_is(host, t, rng, "setup")
            t += rng.uniform(0.3, 0.8)          # collect the I-Am answers
            renewals = []
            for target in targets:
                t = self._startup(host, target.id, controllers[target.id], cov[target.id], process_id, lifetime,
                                  t, rng, requests[target.id])
                renewals.append((target.id, t))
            for target_id, subscribed in renewals:
                self._renew(host, target_id, cov[target_id], process_id, lifetime, subscribed, rng,
                            requests[target_id])
            chunks = {t.id: rpm_chunks(controllers[t.id], controllers[t.id].objects, lambda o: POLLED)
                      for t in targets}
            t += rng.uniform(1.0, poll)
            while t < plan.duration:
                tt = t
                for target in targets:
                    for specs in chunks[target.id]:
                        requests[target.id].append(plan.add(tt, self.id, host.id, "bacnet.rpm", target=target.id,
                                                            specs=specs))
                        tt += rng.uniform(0.01, 0.05)
                t += rng.jitter(poll, 0.02)
            if whois > 0:
                t = first_who_is + rng.jitter(whois, 0.02)
                while t < plan.duration:
                    self._who_is(host, t, rng, "main")
                    t += rng.jitter(whois, 0.02)
            # Invoke ids count up per workstation-controller session in the order of the requests.
            for target in targets:
                invoke = rng.randrange(256)
                for action in sorted(requests[target.id], key=lambda a: (a.t, a.seq)):
                    action.args["invoke"] = invoke
                    invoke = (invoke + 1) % 256
            hosts_facts.append({"host": host_ref(host.id), "subscriber_process_id": process_id})
        plan.facts[self.id] = {
            "hosts": [host_ref(h.id) for h in self.hosts], "workstations": hosts_facts,
            "targets": [{"host": host_ref(t.id), "device_instance": controllers[t.id].instance,
                         "cov": [{"type": OBJECT_TYPE_NAMES[o.type], "instance": o.instance, "point": o.point.name}
                                 for o in cov[t.id]]} for t in targets],
            "poll_s": poll, "cov_lifetime_s": lifetime, "whois_s": whois,
        }

    def _cov_objects(self, controller: Controller) -> list[BacObject]:
        wanted = self.param("cov", 3)
        if isinstance(wanted, int):
            analog = [o for o in controller.objects if o.type == ANALOG_INPUT]
            moving = [o for o in analog if o.point.model] or analog
            if wanted > len(moving):
                raise ScenarioError(f"{self.id}: cov asks for {wanted} objects, '{controller.host_id}' has "
                                    f"{len(moving)} analog inputs")
            picked = self.rng.child(f"cov:{controller.host_id}").sample(moving, wanted)
            return sorted(picked, key=lambda o: o.key)
        by_name = {o.point.name: o for o in controller.objects}
        unknown = [name for name in wanted if name not in by_name]
        if unknown:
            raise ScenarioError(f"{self.id}: cov names unknown points on '{controller.host_id}': "
                                f"{', '.join(unknown)}")
        return [by_name[name] for name in wanted]

    def _who_is(self, host, t: float, rng, phase: str) -> None:
        """Who-Is to the subnet broadcast and the I-Am of every controller on the host's subnets."""
        plan = self.plan_
        plan.add(t, self.id, host.id, "bacnet.whois", phase=phase)
        for actor in plan.actors:
            if isinstance(actor, BacnetServer):
                for device in actor.hosts:
                    if set(device.subnets) & set(host.subnets):
                        plan.add(t + rng.uniform(0.004, 0.15), actor.id, device.id, "bacnet.iam", phase=phase)

    def _startup(self, host, target_id: str, controller: Controller, cov: list[BacObject], process_id: int,
                 lifetime: int, t: float, rng, requests: list) -> float:
        """Device identity, object list, point database and COV subscriptions of one controller."""
        plan = self.plan_

        def add(op: str, gap=(0.008, 0.04), **args):
            nonlocal t
            t += rng.uniform(*gap)
            requests.append(plan.add(t, self.id, host.id, op, phase="setup", target=target_id, **args))

        device = list(controller.device)
        for prop in DEVICE_READS:
            add("bacnet.read", object=device, property=prop, index=None)
        add("bacnet.read", object=device, property=STRUCTURED_OBJECT_LIST, index=None, expect_error=True)
        add("bacnet.read", object=device, property=OBJECT_LIST, index=0)
        whole = len(message(complex_ack(0, READ_PROPERTY, controller.read_ack(
            controller.device, OBJECT_LIST, None, controller.nominal))))
        if whole <= MESSAGE_BUDGET:
            add("bacnet.read", object=device, property=OBJECT_LIST, index=None)
        else:
            for index in range(1, len(controller.object_list()) + 1):
                add("bacnet.read", object=device, property=OBJECT_LIST, index=index, gap=(0.004, 0.015))
        for specs in rpm_chunks(controller, controller.objects, lambda o: POINT_DATABASE[o.type]):
            add("bacnet.rpm", specs=specs, gap=(0.01, 0.05))
        for obj in cov:
            add("bacnet.subscribe", object=list(obj.key), process_id=process_id, lifetime=lifetime,
                gap=(0.01, 0.06))
        return t

    def _renew(self, host, target_id: str, cov: list[BacObject], process_id: int, lifetime: int,
               subscribed: float, rng, requests: list) -> None:
        """Resubscribe every COV object at about 80 % of the lifetime."""
        plan = self.plan_
        t = subscribed + lifetime * rng.uniform(0.78, 0.82)
        while cov and t < plan.duration:
            tt = t
            for obj in cov:
                requests.append(plan.add(tt, self.id, host.id, "bacnet.subscribe", target=target_id,
                                         object=list(obj.key), process_id=process_id, lifetime=lifetime))
                tt += rng.uniform(0.01, 0.06)
            t += lifetime * rng.uniform(0.78, 0.82)

    # -- recording ------------------------------------------------------------------------

    def _socket(self, rt, host_id: str) -> socket.socket:
        key = ("bacnet", host_id)
        sock = rt.clients.get(key)
        if sock is None:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sock.bind((rt.loopback(host_id), ports.BACNET))   # BACnet devices talk 47808 <-> 47808
                sock.settimeout(TIMEOUT_S)
            except BaseException:
                sock.close()
                raise
            rt.clients[key] = sock
        return sock

    def execute(self, action, rt) -> None:
        a = action.args
        sock = self._socket(rt, action.host)
        if action.op == "bacnet.whois":
            sock.sendto(who_is(), (SINKS["broadcast"].loopback, ports.BACNET))
            return
        target = (rt.loopback(a["target"]), ports.BACNET)
        if action.op == "bacnet.read":
            request = read_property(a["invoke"], tuple(a["object"]), a["property"], a["index"])
        elif action.op == "bacnet.rpm":
            request = read_property_multiple(a["invoke"], a["specs"])
        elif action.op == "bacnet.subscribe":
            request = subscribe_cov(a["invoke"], a["process_id"], tuple(a["object"]), a["lifetime"])
        else:
            raise ValueError(f"unknown op {action.op}")
        reply = _transact(sock, target, request, a["invoke"])
        kind = reply[0] >> 4
        if kind in (REJECT, ABORT) or (kind == ERROR and not a.get("expect_error")):
            raise RuntimeError(f"{action.op} answered with APDU type {kind}: {reply.hex()}")
        if action.op == "bacnet.subscribe":
            _await_notification(sock, target, tuple(a["object"]))

    def close(self, rt) -> None:
        for host in self.hosts:
            sock = rt.clients.pop(("bacnet", host.id), None)
            if sock is not None:
                sock.close()
