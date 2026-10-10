"""BACnet/IP actors (ASHRAE 135, Annex J): building controllers and a BMS operator workstation.

``bacnet.server`` is a building controller (Siemens PXC): the host's process model as BACnet
objects - analog inputs (input registers), analog values (setpoints), binary inputs (discrete
inputs) and binary values (coils) - plus the device object. It answers ReadProperty,
ReadPropertyMultiple, SubscribeCOV and WriteProperty (writable analog / binary values are
commandable: a 16-slot priority array over the relinquish-default, whose winner drives the
process), broadcasts I-Am and sends UnconfirmedCOVNotifications from its own planned actions (a
COV scan reports the subscribed objects whose present value moved by the COV increment or whose
status flags changed). A controller that a client names as its ``bbmd`` is a BACnet Broadcast
Management Device: it keeps a foreign-device table (Register-Foreign-Device, BVLC-Result, TTL plus
the 30 s grace period) and distributes broadcasts as Forwarded-NPDUs - a foreign device's
Distribute-Broadcast-To-Network onto its local subnet, local broadcasts (Who-Is, I-Am) to its
foreign devices.

``bacnet.client`` is the BMS workstation: Who-Is, the device's identity and object list, its point
database, COV subscriptions renewed before they expire, cyclic ReadPropertyMultiple polls of
present-value and status-flags and approved setpoint overrides (WriteProperty at a priority, read
back, relinquished later). With ``bbmd`` it sits on another IP subnet and is a foreign device:
it registers with the BBMD, re-registers before the TTL runs out and broadcasts through it.

Both sides talk 47808 <-> 47808 (recorded on ``ports.BACNET``); BVLC, NPDU and APDUs are encoded
here, so no BACnet stack is needed. The composer rewrites the originating address inside
Forwarded-NPDUs (``compose/bacnet.py``).
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
from pcapforge.plan import action_ref, host_ref
from pcapforge.process import Point, ProcessProfile
from pcapforge.scenario import ScenarioError
from pcapforge.topology import SINKS

MAX_APDU = 1476                 # max-apdu-length-accepted of B/IP devices
MESSAGE_BUDGET = 1400           # largest BVLC message we let a request or response grow to
PROTOCOL_REVISION = 14
SEGMENTED_BOTH = 0
TIMEOUT_S = 3.0
BACNET_PORT = ports.WELL_KNOWN[ports.BACNET]   # the UDP port inside B/IP addresses on the wire

# BVLC functions (Annex J.2) and BVLC-Result codes.
BVLC_RESULT, FORWARDED_NPDU, REGISTER_FOREIGN_DEVICE, DISTRIBUTE_BROADCAST = 0x00, 0x04, 0x05, 0x09
ORIGINAL_UNICAST, ORIGINAL_BROADCAST = 0x0A, 0x0B
RESULT_OK, REGISTER_FOREIGN_DEVICE_NAK, DISTRIBUTE_BROADCAST_NAK = 0x0000, 0x0030, 0x0060
FDT_GRACE_S = 30                # a BBMD keeps a foreign device this long past its TTL (J.5.2.1)
PRIORITIES = 16
MINIMUM_ON_OFF = 6              # priority reserved for minimum on/off time

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
PRIORITY_ARRAY = 87
PROTOCOL_VERSION = 98
RELINQUISH_DEFAULT = 104
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
SUBSCRIBE_COV, READ_PROPERTY, READ_PROPERTY_MULTIPLE, WRITE_PROPERTY = 5, 12, 14, 15
I_AM, UNCONFIRMED_COV_NOTIFICATION, WHO_IS = 0, 2, 8
# APDU types.
CONFIRMED, UNCONFIRMED, SIMPLE_ACK, COMPLEX_ACK, SEGMENT_ACK, ERROR, REJECT, ABORT = range(8)
# Application tag numbers.
TAG_NULL, TAG_REAL, TAG_ENUMERATED = 0, 4, 9
# Error classes / codes and reject reasons.
OBJECT_ERROR, PROPERTY_ERROR, SERVICES_ERROR = 1, 2, 5
UNKNOWN_OBJECT, UNKNOWN_PROPERTY, INVALID_ARRAY_INDEX = 31, 32, 42
OPTIONAL_FUNCTIONALITY_NOT_SUPPORTED, PROPERTY_IS_NOT_AN_ARRAY = 45, 50
INVALID_DATA_TYPE, VALUE_OUT_OF_RANGE, WRITE_ACCESS_DENIED, PARAMETER_OUT_OF_RANGE = 9, 37, 40, 80
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


def app_null() -> bytes:
    return bytes([TAG_NULL << 4])


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


def bvlc(function: int, body: bytes) -> bytes:
    """BACnet Virtual Link Control message: type 0x81 (B/IP), function, total length."""
    return struct.pack(">BBH", 0x81, function, 4 + len(body)) + body


def npdu(apdu: bytes, broadcast: bool = False, expecting_reply: bool = False) -> bytes:
    """NPDU around an APDU: local, or to the global broadcast network (DNET 0xFFFF, hop count 255)."""
    control = 0x04 if expecting_reply else 0x00
    if broadcast:
        return bytes([0x01, control | 0x20, 0xFF, 0xFF, 0x00, 0xFF]) + apdu
    return bytes([0x01, control]) + apdu


def message(apdu: bytes, broadcast: bool = False, expecting_reply: bool = False) -> bytes:
    """Original-Unicast-NPDU, or Original-Broadcast-NPDU to the global broadcast network."""
    return bvlc(ORIGINAL_BROADCAST if broadcast else ORIGINAL_UNICAST, npdu(apdu, broadcast, expecting_reply))


def bip_address(ip: str) -> bytes:
    """B/IP address (IPv4 address + UDP port) as Forwarded-NPDU and the BDT/FDT carry it."""
    return socket.inet_aton(ip) + struct.pack(">H", BACNET_PORT)


def forwarded_npdu(origin_ip: str, data: bytes) -> bytes:
    """Forwarded-NPDU: a BBMD passes on a broadcast NPDU with the address of its originator."""
    return bvlc(FORWARDED_NPDU, bip_address(origin_ip) + data)


def register_foreign_device(ttl: int) -> bytes:
    return bvlc(REGISTER_FOREIGN_DEVICE, struct.pack(">H", ttl))


def distribute_broadcast(data: bytes) -> bytes:
    """Distribute-Broadcast-To-Network: a foreign device hands a broadcast NPDU to its BBMD."""
    return bvlc(DISTRIBUTE_BROADCAST, data)


def bvlc_result(code: int) -> bytes:
    return bvlc(BVLC_RESULT, struct.pack(">H", code))


def confirmed(invoke: int, service: int, body: bytes) -> bytes:
    """Confirmed-Request header: unsegmented, no segmented response accepted, 1476-byte APDUs."""
    return bytes([CONFIRMED << 4, 0x05, invoke, service]) + body


def simple_ack(invoke: int, service: int) -> bytes:
    return bytes([SIMPLE_ACK << 4, invoke, service])


def complex_ack(invoke: int, service: int, body: bytes) -> bytes:
    return bytes([COMPLEX_ACK << 4, invoke, service]) + body


def error_pdu(invoke: int, service: int, error: BacnetError) -> bytes:
    return bytes([ERROR << 4, invoke, service]) + app_enum(error.error_class) + app_enum(error.code)


def who_is_npdu() -> bytes:
    return npdu(bytes([UNCONFIRMED << 4, WHO_IS]), broadcast=True)


def who_is() -> bytes:
    return bvlc(ORIGINAL_BROADCAST, who_is_npdu())


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


def command_value(obj_type: int, value: float | None) -> bytes:
    """Application-tagged value commanding an object's present-value; ``None`` relinquishes (NULL)."""
    if value is None:
        return app_null()
    return app_real(value) if obj_type in ANALOG else app_enum(int(value >= 0.5))


def write_property(invoke: int, obj: tuple[int, int], prop: int, value: bytes, priority: int | None) -> bytes:
    """WriteProperty-Request: object [0], property [1], value [3] and the command priority [4]."""
    body = (ctx_object(0, *obj) + ctx_uint(1, prop) + opening(3) + value + closing(3)
            + (b"" if priority is None else ctx_uint(4, priority)))
    return confirmed(invoke, WRITE_PROPERTY, body)


# --- decoding --------------------------------------------------------------------------

def npdu_of(data: bytes) -> bytes:
    """NPDU a BVLC message carries (Original-Unicast/Broadcast, Distribute-Broadcast-To-Network,
    Forwarded-NPDU after the originator's B/IP address)."""
    if len(data) < 4 or data[0] != 0x81 or struct.unpack_from(">H", data, 2)[0] != len(data):
        raise DecodeError("not a BVLC message")
    if data[1] in (ORIGINAL_UNICAST, ORIGINAL_BROADCAST, DISTRIBUTE_BROADCAST):
        return data[4:]
    if data[1] == FORWARDED_NPDU and len(data) >= 10:
        return data[10:]
    raise DecodeError(f"BVLC function {data[1]:#04x} carries no NPDU")


def apdu_of(data: bytes) -> bytes:
    """APDU of a BVLC message that carries an NPDU (b"" for network-layer messages)."""
    data = npdu_of(data)
    if len(data) < 2 or data[0] != 0x01:
        raise DecodeError("not a BACnet/IP NPDU")
    control, pos = data[1], 2
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
        return self._content(size, pos)

    def application(self) -> tuple[int, bytes]:
        """Next application-tagged value: (tag number, content). A boolean's value is its length field."""
        number, context, size, pos = self._header()
        if context:
            raise DecodeError("expected an application tag")
        if number == 1:
            self.pos = pos
            return number, bytes([size])
        return number, self._content(size, pos)

    def _content(self, size: int, pos: int) -> bytes:
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


@dataclass
class Command:
    """Command state of a commandable object: the priority array (slot 0 = priority 1) over the
    relinquish-default, the setpoint the site ran with before the first command."""

    default: float
    slots: list[float | None] = field(default_factory=lambda: [None] * PRIORITIES)

    def effective(self) -> float:
        return next((v for v in self.slots if v is not None), self.default)


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
        return command_value(obj.type, value)

    @staticmethod
    def commandable(obj: BacObject) -> bool:
        """Writable analog / binary values: present-value is commanded through a priority array."""
        return obj.type in (ANALOG_VALUE, BINARY_VALUE) and obj.point.writable

    def read(self, key: tuple[int, int], prop: int, index: int | None, snapshot: Snapshot,
             commands: dict[tuple[int, int], Command] | None = None) -> bytes:
        """Application-tagged value of a property; raises ``BacnetError``."""
        if key == self.device:
            return self._read_device(prop, index)
        obj = self.by_key.get(key)
        if obj is None:
            raise BacnetError(OBJECT_ERROR, UNKNOWN_OBJECT)
        command = (commands or {}).get(key)
        if prop == PRIORITY_ARRAY and self.commandable(obj):
            slots = command.slots if command else [None] * PRIORITIES
            if index is None:
                return b"".join(command_value(obj.type, v) for v in slots)
            if index == 0:
                return app_uint(PRIORITIES)
            if index > PRIORITIES:
                raise BacnetError(PROPERTY_ERROR, INVALID_ARRAY_INDEX)
            return command_value(obj.type, slots[index - 1])
        if index is not None:
            raise BacnetError(PROPERTY_ERROR, PROPERTY_IS_NOT_AN_ARRAY)
        if prop == RELINQUISH_DEFAULT and self.commandable(obj):
            return command_value(obj.type, command.default if command else self.present_value(obj, snapshot))
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

    def read_ack(self, key: tuple[int, int], prop: int, index: int | None, snapshot: Snapshot,
                 commands: dict[tuple[int, int], Command] | None = None) -> bytes:
        """ReadProperty-ACK service data."""
        value = self.read(key, prop, index, snapshot, commands)
        return (ctx_object(0, *key) + ctx_uint(1, prop) + (b"" if index is None else ctx_uint(2, index))
                + opening(3) + value + closing(3))

    def rpm_ack(self, specs: list, snapshot: Snapshot,
                commands: dict[tuple[int, int], Command] | None = None) -> bytes:
        """ReadPropertyMultiple-ACK service data: a value or an access error per property."""
        out = []
        for obj_type, instance, refs in specs:
            out.append(ctx_object(0, obj_type, instance) + opening(1))
            for prop, index in refs:
                out.append(ctx_uint(2, prop) + (b"" if index is None else ctx_uint(3, index)))
                try:
                    value = self.read((obj_type, instance), prop, index, snapshot, commands)
                    out.append(opening(4) + value + closing(4))
                except BacnetError as exc:
                    out.append(opening(5) + app_enum(exc.error_class) + app_enum(exc.code) + closing(5))
            out.append(closing(1))
        return b"".join(out)

    def command(self, key: tuple[int, int], prop: int, index: int | None, value: tuple[int, bytes],
                priority: int | None, commands: dict[tuple[int, int], Command],
                snapshot: Snapshot) -> tuple[BacObject, float]:
        """Apply a WriteProperty (application-tagged ``value``) to the object's priority array in
        ``commands``: the object and its new present value. Raises ``BacnetError``."""
        obj = self.by_key.get(key)
        if obj is None and key != self.device:
            raise BacnetError(OBJECT_ERROR, UNKNOWN_OBJECT)
        if obj is None or prop != PRESENT_VALUE or not self.commandable(obj):
            raise BacnetError(PROPERTY_ERROR, WRITE_ACCESS_DENIED)
        if index is not None:
            raise BacnetError(PROPERTY_ERROR, PROPERTY_IS_NOT_AN_ARRAY)
        priority = PRIORITIES if priority is None else priority
        if not 1 <= priority <= PRIORITIES:
            raise BacnetError(SERVICES_ERROR, PARAMETER_OUT_OF_RANGE)
        if priority == MINIMUM_ON_OFF:
            raise BacnetError(PROPERTY_ERROR, WRITE_ACCESS_DENIED)
        tag_number, content = value
        if tag_number == TAG_NULL:
            new = None
        elif tag_number == TAG_REAL and obj.type == ANALOG_VALUE and len(content) == 4:
            new = float(f"{struct.unpack('>f', content)[0]:.7g}")   # what float32 resolves
        elif tag_number == TAG_ENUMERATED and obj.type == BINARY_VALUE:
            new = float(int.from_bytes(content, "big"))
            if new > 1:
                raise BacnetError(PROPERTY_ERROR, VALUE_OUT_OF_RANGE)
        else:
            raise BacnetError(PROPERTY_ERROR, INVALID_DATA_TYPE)
        command = commands.get(key)
        if command is None:
            command = commands[key] = Command(self.present_value(obj, snapshot))
        command.slots[priority - 1] = new
        return obj, command.effective()

    def i_am_npdu(self) -> bytes:
        return npdu(bytes([UNCONFIRMED << 4, I_AM]) + app_object(*self.device) + app_uint(MAX_APDU)
                    + app_enum(SEGMENTED_BOTH) + app_uint(self.vendor_id), broadcast=True)

    def i_am(self) -> bytes:
        return bvlc(ORIGINAL_BROADCAST, self.i_am_npdu())

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

    def __init__(self, rt, controller: Controller, sim, sock: socket.socket, bbmd: bool = False) -> None:
        self.rt, self.controller, self.sim, self.sock = rt, controller, sim, sock
        self.transport = None
        self.subscriptions: dict[tuple, _Subscription] = {}
        self.commands: dict[tuple[int, int], Command] = {}
        self.bbmd = bbmd
        # Foreign-device table of a BBMD: B/IP address -> time the entry expires (TTL + grace).
        self.fdt: dict[tuple[str, int], float] = {}

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
        if len(data) < 4 or data[0] != 0x81:
            return
        if data[1] == REGISTER_FOREIGN_DEVICE:
            self.sock.sendto(bvlc_result(self.register(data, addr)), addr)
            return
        if data[1] == DISTRIBUTE_BROADCAST:
            # A registered foreign device's broadcast is distributed by the BBMD's planned
            # ``bacnet.forward`` action; anyone else is refused.
            if not self.bbmd or self.fdt.get(addr, -1.0) <= self.rt.clock.t:
                self.sock.sendto(bvlc_result(DISTRIBUTE_BROADCAST_NAK), addr)
            return
        if data[1] != ORIGINAL_UNICAST:
            return  # broadcasts are answered by planned actions (I-Am), results need no answer
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

    def register(self, data: bytes, addr) -> int:
        """Register-Foreign-Device: (re)new the FDT entry; the BVLC-Result code."""
        if not self.bbmd or len(data) != 6:
            return REGISTER_FOREIGN_DEVICE_NAK
        ttl = struct.unpack_from(">H", data, 4)[0]
        self.fdt[addr] = self.rt.clock.t + ttl + FDT_GRACE_S
        return RESULT_OK

    def confirmed(self, service: int, invoke: int, reader: Reader, addr) -> list[bytes]:
        controller = self.controller
        if service == READ_PROPERTY:
            key, prop = reader.object(0), reader.unsigned(1)
            index = reader.optional_unsigned(2)
            return [complex_ack(invoke, service, controller.read_ack(key, prop, index, self.snapshot(),
                                                                     self.commands))]
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
            return [complex_ack(invoke, service, controller.rpm_ack(specs, self.snapshot(), self.commands))]
        if service == SUBSCRIBE_COV:
            return self.subscribe(invoke, reader, addr)
        if service == WRITE_PROPERTY:
            return [self.write(invoke, reader)]
        return [bytes([REJECT << 4, invoke, REJECT_UNRECOGNIZED_SERVICE])]

    def write(self, invoke: int, reader: Reader) -> bytes:
        """WriteProperty: the priority array's winner becomes the process setpoint / command."""
        key, prop = reader.object(0), reader.unsigned(1)
        index = reader.optional_unsigned(2)
        reader.enter(3)
        value = reader.application()
        if not reader.leave(3):
            raise DecodeError("expected closing tag 3")
        priority = reader.optional_unsigned(4)
        if not reader.done():
            raise DecodeError("unexpected trailing tag")
        snapshot = self.snapshot()
        obj, effective = self.controller.command(key, prop, index, value, priority, self.commands, snapshot)
        point = obj.point
        self.sim.write(point.table, point.address, point.encode(effective))
        return simple_ack(invoke, WRITE_PROPERTY)

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

    async def forward(self, origin: str, data: bytes, broadcast: bool) -> None:
        """BBMD: distribute the broadcast NPDU ``origin`` sent as a Forwarded-NPDU - onto the local
        subnet (``broadcast``: a foreign device's Distribute-Broadcast-To-Network) and to every
        registered foreign device except the originator. Expired FDT entries are purged first."""
        now = self.rt.clock.t
        for addr in [a for a, expires in self.fdt.items() if expires <= now]:
            del self.fdt[addr]
        forwarded = forwarded_npdu(origin, data)
        if broadcast:
            self.sock.sendto(forwarded, (SINKS["broadcast"].loopback, ports.BACNET))
        for addr in self.fdt:
            if addr != (origin, ports.BACNET):
                self.sock.sendto(forwarded, addr)


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
                "bbmd": host.id in foreign_devices(plan),
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
        bbmds = foreign_devices(rt.plan)
        self.devices: dict[str, _Device] = {}
        for host in self.hosts:
            sim = host_sim(rt, self, host, self.profiles[host.id])
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind((host.loopback, ports.BACNET))
            sock.setblocking(False)
            controller = self.controllers[host.id]
            bbmd = host.id in bbmds
            _, device = await loop.create_datagram_endpoint(lambda: _Device(rt, controller, sim, sock, bbmd),
                                                            sock=sock)
            self.devices[host.id] = device
            rt.servers.append(device)

    def execute(self, action, rt) -> None:
        device = self.devices[action.host]
        if action.op == "bacnet.iam":
            coro = device.send_i_am()
        elif action.op == "bacnet.cov":
            coro = device.scan_cov()
        elif action.op == "bacnet.forward":
            origin = action.args["origin"]
            if action.args["kind"] == "who-is":
                data = who_is_npdu()
            else:
                data = serving_controller(rt.plan, origin)[1].i_am_npdu()
            coro = device.forward(rt.loopback(origin), data, action.args["broadcast"])
        else:
            raise ValueError(f"unknown op {action.op}")
        asyncio.run_coroutine_threadsafe(coro, rt.loop).result(TIMEOUT_S)


def serving_controller(plan, host_id: str) -> tuple[BacnetServer, Controller]:
    """The bacnet.server actor on ``host_id`` and the controller it runs there."""
    for actor in plan.actors:
        if isinstance(actor, BacnetServer) and host_id in getattr(actor, "controllers", {}):
            return actor, actor.controllers[host_id]
    raise ScenarioError(f"no bacnet.server runs on host '{host_id}'")


def foreign_devices(plan) -> dict[str, list[tuple[BacnetClient, object]]]:
    """BBMD host id -> the (bacnet.client, host) foreign devices that register with it."""
    out: dict[str, list] = {}
    for actor in plan.actors:
        if isinstance(actor, BacnetClient):
            bbmd = actor.bbmd()
            if bbmd is not None:
                out.setdefault(bbmd.id, []).extend((actor, host) for host in actor.hosts)
    return out


def distribute(plan, origin, t: float, kind: str, rng, phase: str) -> None:
    """A local broadcast (``kind`` who-is / i-am) of ``origin`` at ``t``: every BBMD on its subnet
    with foreign devices registered by then forwards it to them (``bacnet.forward``)."""
    for bbmd_id, devices in foreign_devices(plan).items():
        bbmd = plan.topology.by_id[bbmd_id]
        if not set(bbmd.subnets) & set(origin.subnets):
            continue
        if any(host.id != origin.id and client.registered(host, t) for client, host in devices):
            plan.add(t + rng.uniform(0.0003, 0.002), serving_controller(plan, bbmd_id)[0].id, bbmd_id,
                     "bacnet.forward", phase=phase, origin=origin.id, kind=kind, broadcast=False)


# --- client ----------------------------------------------------------------------------

def _receive(sock: socket.socket, target: tuple[str, int]) -> bytes:
    """Next APDU ``target`` sends (messages without one, e.g. BVLC-Results, are skipped)."""
    while True:
        data, addr = sock.recvfrom(2048)
        if addr != target:
            continue
        try:
            return apdu_of(data)
        except (DecodeError, IndexError):
            continue


def _transact(sock: socket.socket, target: tuple[str, int], apdu: bytes, invoke: int) -> bytes:
    """Send a confirmed request and return the answer with its invoke id (other datagrams,
    e.g. COV notifications or forwarded broadcasts that arrived since the last request, are skipped)."""
    sock.sendto(message(apdu, expecting_reply=True), target)
    while True:
        reply = _receive(sock, target)
        if len(reply) >= 2 and reply[0] >> 4 in (SIMPLE_ACK, COMPLEX_ACK, ERROR, REJECT, ABORT) \
                and reply[1] == invoke:
            return reply


def _await_notification(sock: socket.socket, target: tuple[str, int], obj: tuple[int, int]) -> None:
    while True:
        reply = _receive(sock, target)
        if reply[:2] != bytes([UNCONFIRMED << 4, UNCONFIRMED_COV_NOTIFICATION]):
            continue
        reader = Reader(reply[2:])
        reader.unsigned(0)
        reader.object(1)
        if reader.object(2) == tuple(obj):
            return


def _register(sock: socket.socket, bbmd: tuple[str, int], ttl: int) -> None:
    """Register-Foreign-Device with ``bbmd`` and wait for its BVLC-Result."""
    sock.sendto(register_foreign_device(ttl), bbmd)
    while True:
        data, addr = sock.recvfrom(2048)
        if addr == bbmd and len(data) == 6 and data[:2] == bytes([0x81, BVLC_RESULT]):
            code = struct.unpack_from(">H", data, 4)[0]
            if code != RESULT_OK:
                raise RuntimeError(f"BBMD refused the foreign-device registration (BVLC-Result {code:#06x})")
            return


@register
class BacnetClient(Actor):
    """BMS operator workstation: discovery, point database, COV subscriptions, RPM polls and
    approved setpoint overrides; with ``bbmd`` a foreign device on another IP subnet."""

    type = "bacnet.client"
    sinks = (("broadcast", ports.BACNET),)

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._registrations: dict[str, list[float]] = {}

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
        writes = int(self.param("writes", 0))
        priority = int(self.param("write_priority", 8))
        relinquish = self.span(self.param("relinquish_s", [600, 1800]))
        if writes < 0:
            raise ScenarioError(f"{self.id}: writes must be 0 or positive")
        if not 1 <= priority <= PRIORITIES or priority == MINIMUM_ON_OFF:
            raise ScenarioError(f"{self.id}: write_priority must lie in 1..16 and not be 6 (minimum on/off)")
        if relinquish != (0.0, 0.0) and not 30 <= relinquish[0] <= relinquish[1]:
            raise ScenarioError(f"{self.id}: relinquish_s must be 0 (never) or at least 30 s")
        controllers = {t.id: serving_controller(plan, t.id)[1] for t in targets}
        cov = {t.id: self._cov_objects(controllers[t.id]) for t in targets}
        bbmd = self.bbmd()
        if bbmd is not None:
            serving_controller(plan, bbmd.id)
        hosts_facts, write_facts = [], []
        for host in self.hosts:
            if bbmd is not None and set(bbmd.subnets) & set(host.subnets):
                raise ScenarioError(f"{self.id}: '{host.id}' shares a subnet with its BBMD '{bbmd.id}'; "
                                    "only a host on another subnet registers as a foreign device")
            rng = self.rng.child(host.id)
            process_id = rng.randint(1, 255)
            requests: dict[str, list] = {t.id: [] for t in targets}
            registrations = []
            if bbmd is None:
                t = first_who_is = rng.uniform(0.3, 2.0)
            else:
                for index, at in enumerate(self.registrations(host)):
                    registrations.append(plan.add(at, self.id, host.id, "bacnet.register",
                                                  phase="setup" if index == 0 else "main", bbmd=bbmd.id,
                                                  ttl=self.ttl()))
                t = first_who_is = registrations[0].t + rng.uniform(0.05, 0.3)
            self._who_is(host, t, rng, "setup")
            t += rng.uniform(0.3, 0.8)          # collect the I-Am answers
            renewals = []
            for target in targets:
                t = self._startup(host, target.id, controllers[target.id], cov[target.id], process_id, lifetime,
                                  t, rng, requests[target.id])
                renewals.append((target.id, t))
            started = t
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
            write_facts += self._writes(host, targets, writes, priority, relinquish, started, requests)
            # Invoke ids count up per workstation-controller session in the order of the requests.
            for target in targets:
                invoke = rng.randrange(256)
                for action in sorted(requests[target.id], key=lambda a: (a.t, a.seq)):
                    action.args["invoke"] = invoke
                    invoke = (invoke + 1) % 256
            hosts_facts.append({
                "host": host_ref(host.id), "subscriber_process_id": process_id,
                "foreign_device": None if bbmd is None else {
                    "bbmd": host_ref(bbmd.id), "ttl_s": self.ttl(), "registrations": len(registrations),
                    "first_registration": action_ref(registrations[0])},
            })
        plan.facts[self.id] = {
            "hosts": [host_ref(h.id) for h in self.hosts], "workstations": hosts_facts,
            "targets": [{"host": host_ref(t.id), "device_instance": controllers[t.id].instance,
                         "cov": [{"type": OBJECT_TYPE_NAMES[o.type], "instance": o.instance, "point": o.point.name}
                                 for o in cov[t.id]]} for t in targets],
            "poll_s": poll, "cov_lifetime_s": lifetime, "whois_s": whois,
            "write_priority": priority, "writes": write_facts,
            "write_count": sum(1 + (w["relinquish"] is not None) for w in write_facts),
        }

    # -- foreign device -------------------------------------------------------------------

    def bbmd(self):
        """The BBMD host this client registers with as a foreign device (``params.bbmd``), or None."""
        ref = self.param("bbmd")
        if ref is None:
            return None
        hosts = self.plan_.topology.select(ref)
        if len(hosts) != 1:
            raise ScenarioError(f"{self.id}: bbmd must name exactly one controller")
        return hosts[0]

    def ttl(self) -> int:
        ttl = int(self.param("fd_ttl_s", 300))
        if not 60 <= ttl <= 65535:
            raise ScenarioError(f"{self.id}: fd_ttl_s must lie in 60..65535")
        return ttl

    def registrations(self, host) -> list[float]:
        """When foreign device ``host`` registers with its BBMD: at startup, then again at about
        80 % of the TTL, well before the BBMD drops it (TTL + 30 s). Other actors ask for these
        times while planning, so they come from their own stream."""
        times = self._registrations.get(host.id)
        if times is None:
            rng = self.rng.child(f"fdr:{host.id}")
            ttl = self.ttl()
            times, t = [], rng.uniform(0.3, 2.0)
            while t < self.plan_.duration:
                times.append(t)
                t += ttl * rng.uniform(0.78, 0.82)
            self._registrations[host.id] = times
        return times

    def registered(self, host, t: float) -> bool:
        """Is foreign device ``host`` in its BBMD's table at ``t``? (It re-registers until the end.)"""
        times = self.registrations(host)
        return bool(times) and times[0] < t

    # -- planning helpers -----------------------------------------------------------------

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
        """Who-Is and the I-Am of every controller that receives it: a local broadcast reaches the
        host's subnets; a foreign device's goes to its BBMD (Distribute-Broadcast-To-Network),
        which forwards it onto the BBMD's subnets. BBMDs pass every local broadcast on to their
        registered foreign devices."""
        plan = self.plan_
        bbmd = self.bbmd()
        if bbmd is None:
            plan.add(t, self.id, host.id, "bacnet.whois", phase=phase)
            distribute(plan, host, t, "who-is", rng, phase)
            subnets = set(host.subnets)
        else:
            plan.add(t, self.id, host.id, "bacnet.whois", phase=phase, bbmd=bbmd.id)
            t += rng.uniform(0.0005, 0.003)
            plan.add(t, serving_controller(plan, bbmd.id)[0].id, bbmd.id, "bacnet.forward", phase=phase,
                     origin=host.id, kind="who-is", broadcast=True)
            subnets = set(bbmd.subnets)
        for actor in plan.actors:
            if isinstance(actor, BacnetServer):
                for device in actor.hosts:
                    if set(device.subnets) & subnets:
                        at = t + rng.uniform(0.004, 0.15)
                        plan.add(at, actor.id, device.id, "bacnet.iam", phase=phase)
                        distribute(plan, device, at, "i-am", rng, phase)

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

    def _writes(self, host, targets, count: int, priority: int, relinquish: tuple[float, float],
                started: float, requests: dict[str, list]) -> list[dict]:
        """Approved setpoint overrides: ``count`` analog values the process lists as operator
        adjustable, each written once at ``priority`` (after the command dialog's read of
        present-value, priority-array and relinquish-default, then read back) and relinquished
        (NULL at the same priority) ``relinquish`` seconds later."""
        if count == 0:
            return []
        plan = self.plan_
        rng = self.rng.child(f"writes:{host.id}")
        candidates = []
        for target in targets:
            server, controller = serving_controller(plan, target.id)
            steps = {c["name"]: c["step"] for c in server.profiles[target.id].operator_adjustable}
            candidates += [(target, obj, steps[obj.point.name]) for obj in controller.objects
                           if obj.type == ANALOG_VALUE and controller.commandable(obj)
                           and obj.point.name in steps and obj.point.normal]
        if count > len(candidates):
            raise ScenarioError(f"{self.id}: writes asks for {count} setpoints, the targets have "
                                f"{len(candidates)} operator-adjustable analog values")
        picked = rng.sample(candidates, count)
        lo = started + 60.0
        times = sorted(rng.uniform(lo, max(lo, plan.duration * 0.6)) for _ in picked)
        facts = []
        for (target, obj, step), at in zip(picked, times):
            if at >= plan.duration:
                continue
            point = obj.point
            value = point.nominal + rng.uniform(*step) * rng.choice((-1, 1))
            value = point.typed(round(min(max(value, point.normal[0]), point.normal[1]), 1))
            write = self._command(host, target.id, obj, value, priority, at, rng, requests[target.id])
            released = None
            if relinquish[1] > 0:
                at += rng.uniform(*relinquish)
                if at < plan.duration:
                    released = self._command(host, target.id, obj, None, priority, at, rng, requests[target.id])
            facts.append({"source": host_ref(host.id), "target": host_ref(target.id),
                          "object": {"type": OBJECT_TYPE_NAMES[obj.type], "instance": obj.instance},
                          "point": point.name, "unit": point.unit, "value": value, "priority": priority,
                          "request": action_ref(write),
                          "relinquish": action_ref(released) if released else None})
        return facts

    def _command(self, host, target_id: str, obj: BacObject, value: float | None, priority: int, t: float,
                 rng, requests: list):
        """The operator opens the object's command dialog, writes (``None`` relinquishes) and the
        workstation reads the present value back. Returns the WriteProperty action."""
        plan = self.plan_
        key = list(obj.key)
        requests.append(plan.add(t - rng.uniform(4.0, 20.0), self.id, host.id, "bacnet.rpm", target=target_id,
                                 specs=[[*key, [PRESENT_VALUE, PRIORITY_ARRAY, RELINQUISH_DEFAULT]]]))
        write = plan.add(t, self.id, host.id, "bacnet.write", target=target_id, object=key, value=value,
                         priority=priority)
        requests.append(write)
        requests.append(plan.add(t + rng.uniform(0.3, 1.5), self.id, host.id, "bacnet.read", target=target_id,
                                 object=key, property=PRESENT_VALUE, index=None))
        return write

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
        if action.op == "bacnet.register":
            _register(sock, (rt.loopback(a["bbmd"]), ports.BACNET), a["ttl"])
            return
        if action.op == "bacnet.whois":
            if a.get("bbmd"):
                sock.sendto(distribute_broadcast(who_is_npdu()), (rt.loopback(a["bbmd"]), ports.BACNET))
            else:
                sock.sendto(who_is(), (SINKS["broadcast"].loopback, ports.BACNET))
            return
        target = (rt.loopback(a["target"]), ports.BACNET)
        if action.op == "bacnet.read":
            request = read_property(a["invoke"], tuple(a["object"]), a["property"], a["index"])
        elif action.op == "bacnet.rpm":
            request = read_property_multiple(a["invoke"], a["specs"])
        elif action.op == "bacnet.subscribe":
            request = subscribe_cov(a["invoke"], a["process_id"], tuple(a["object"]), a["lifetime"])
        elif action.op == "bacnet.write":
            request = write_property(a["invoke"], tuple(a["object"]), PRESENT_VALUE,
                                     command_value(a["object"][0], a["value"]), a["priority"])
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
