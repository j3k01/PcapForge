"""IEC 60870-5-104 telecontrol actors: a substation RTU (controlled station) and a SCADA master.

The RTU reports the host's process as information objects - status bits as single points,
measurements and setpoint feedback as short floats - by general interrogation, periodic
transmission and spontaneous (deadband) events. Both sides frame APCI / ASDU themselves and keep
the I-frame send / receive sequence numbers and the k / w acknowledgement windows of the standard.

Server-initiated data (periodic and spontaneous reports) is sent by the RTU's own actions on the
services loop; the master's blocking session reads it at its next action, so it learns from the
RTU's link how many I-frames were sent instead of racing the socket.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import functools
import socket
import struct
import time
from collections import deque
from dataclasses import dataclass

from pcapforge import ports
from pcapforge.actors import register
from pcapforge.actors.base import Actor
from pcapforge.actors.modbus import host_process, host_sim
from pcapforge.plan import host_ref
from pcapforge.process import Point, ProcessProfile
from pcapforge.scenario import ScenarioError

# --- APCI ------------------------------------------------------------------------------

START = 0x68
MAX_APDU = 253                     # APDU length octet: 4 control octets + ASDU
ASDU_HEADER = 6                    # type id, VSQ, COT (2 octets: cause, originator), common address (2)
MAX_ASDU = MAX_APDU - 4
SEQ_MOD = 1 << 15                  # N(S) / N(R) are 15-bit counters
K = 12                             # most unacknowledged I-frames a sender may have outstanding
W = 8                              # latest acknowledgement after w received I-frames
STARTDT_ACT, STARTDT_CON = 0x07, 0x0B
STOPDT_ACT, STOPDT_CON = 0x13, 0x23
TESTFR_ACT, TESTFR_CON = 0x43, 0x83

# --- ASDU ------------------------------------------------------------------------------

M_SP_NA_1, M_ME_NC_1, M_SP_TB_1, M_ME_TF_1 = 1, 13, 30, 36
C_IC_NA_1, C_CS_NA_1 = 100, 103
TYPE_NAMES = {M_SP_NA_1: "M_SP_NA_1", M_ME_NC_1: "M_ME_NC_1", M_SP_TB_1: "M_SP_TB_1", M_ME_TF_1: "M_ME_TF_1",
              C_IC_NA_1: "C_IC_NA_1", C_CS_NA_1: "C_CS_NA_1"}
PERIODIC, SPONTANEOUS, ACTIVATION, ACTCON, ACTTERM, INROGEN = 1, 3, 6, 7, 10, 20
UNKNOWN_TYPE, UNKNOWN_CA = 44, 46
NEGATIVE = 0x40                    # P/N bit of the cause of transmission
QOI_STATION = 20                   # station (general) interrogation
BROADCAST_CA = 0xFFFF
ORIGINATOR = 0                     # originator address of the master's commands
REPLY_TIMEOUT = 5.0

# Information object address blocks per process table (single points, measurands, setpoint
# feedback), the way RTU560 engineering numbers the signal list.
BLOCKS = (("discrete", 1001), ("input", 2001), ("holding", 3001))


def i_frame(ns: int, nr: int, asdu: bytes) -> bytes:
    """Numbered information transfer: N(S) and N(R) shifted left by one in two LE octets each."""
    return struct.pack("<BBHH", START, 4 + len(asdu), ns << 1, nr << 1) + asdu


def s_frame(nr: int) -> bytes:
    """Numbered supervisory function: acknowledges I-frames up to N(R) - 1."""
    return struct.pack("<BBHH", START, 4, 0x0001, nr << 1)


def u_frame(function: int) -> bytes:
    """Unnumbered control function (STARTDT / STOPDT / TESTFR act or con)."""
    return struct.pack("<BBBBH", START, 4, function, 0, 0)


def control_numbers(body: bytes) -> tuple[int, int]:
    """(N(S), N(R)) of an I-frame body (control field first); N(S) is 0 for an S-frame."""
    send, receive = struct.unpack_from("<HH", body)
    return send >> 1, receive >> 1


def asdu_header(type_id: int, count: int, cot: int, ca: int, sq: bool = False, oa: int = ORIGINATOR) -> bytes:
    return struct.pack("<BBBBH", type_id, (0x80 if sq else 0) | count, cot, oa, ca)


def ioa(address: int) -> bytes:
    return address.to_bytes(3, "little")


def cp56time2a(epoch: float) -> bytes:
    """Seven-octet binary time (UTC, standard time): milliseconds of the minute, minute, hour,
    day of month with day of week (1 = Monday), month, year of the century."""
    total_ms = round(epoch * 1000)
    t = dt.datetime.fromtimestamp(total_ms // 1000, dt.UTC)
    return struct.pack("<HBBBBB", t.second * 1000 + total_ms % 1000, t.minute, t.hour,
                       t.isoweekday() << 5 | t.day, t.month, t.year % 100)


def parse_cp56time2a(data: bytes) -> float:
    ms, minute, hour, day, month, year = struct.unpack_from("<HBBBBB", data)
    t = dt.datetime(2000 + (year & 0x7F), month & 0x0F, day & 0x1F, hour & 0x1F, minute & 0x3F, tzinfo=dt.UTC)
    return t.timestamp() + ms / 1000


def asdus(type_id: int, cot: int, ca: int, objects: list[bytes]) -> list[bytes]:
    """Information objects packed into as few SQ=0 ASDUs as fit one APDU."""
    out: list[bytes] = []
    batch: list[bytes] = []
    size = ASDU_HEADER
    for obj in objects:
        if batch and (size + len(obj) > MAX_ASDU or len(batch) == 0x7F):
            out.append(asdu_header(type_id, len(batch), cot, ca) + b"".join(batch))
            batch, size = [], ASDU_HEADER
        batch.append(obj)
        size += len(obj)
    if batch:
        out.append(asdu_header(type_id, len(batch), cot, ca) + b"".join(batch))
    return out


# --- information objects ---------------------------------------------------------------

@dataclass(frozen=True)
class InfoObject:
    ioa: int
    point: Point

    @property
    def single(self) -> bool:
        return self.point.table == "discrete"

    @property
    def type_id(self) -> int:
        """Type without time tag (interrogation, periodic)."""
        return M_SP_NA_1 if self.single else M_ME_NC_1

    @property
    def event_type_id(self) -> int:
        """Type with CP56Time2a time tag (spontaneous)."""
        return M_SP_TB_1 if self.single else M_ME_TF_1

    def encode(self, value: float, time_tag: bytes = b"") -> bytes:
        """IOA + SIQ (single point) or IEEE 754 short float + QDS (good quality) [+ time tag]."""
        element = bytes([1 if value >= 0.5 else 0]) if self.single else struct.pack("<fB", value, 0)
        return ioa(self.ioa) + element + time_tag


def info_objects(profile: ProcessProfile) -> list[InfoObject]:
    return [InfoObject(base + index, p) for table, base in BLOCKS for index, p in enumerate(profile.table(table))]


def deadband_step(point: Point, deadband: float) -> float:
    """Absolute change that triggers a spontaneous report: ``deadband`` of the normal band width
    (of the nominal value for points without a band)."""
    if point.normal:
        return deadband * (point.normal[1] - point.normal[0])
    return deadband * max(abs(point.nominal), 1.0)


@dataclass(frozen=True)
class Station:
    host_id: str
    profile: ProcessProfile
    common_address: int
    objects: tuple[InfoObject, ...]


def _values(sim) -> dict[str, float]:
    values: dict[str, float] = {}
    for table, _ in BLOCKS:
        values.update(sim.values(table))
    return values


# --- server ----------------------------------------------------------------------------

class _Link:
    """Controlled-station side of one connection: sequence numbers and the k window."""

    def __init__(self, rt, station: Station, writer: asyncio.StreamWriter) -> None:
        self.rt, self.station, self.writer = rt, station, writer
        self.active = False            # STARTDT received
        self.vs = self.vr = 0
        self.sent = 0                  # I-frames written since connect
        self.acked = 0                 # of those, acknowledged by the master
        self.settled = 0               # ``acked`` once the frames it released are written
        self.held: deque[bytes] = deque()
        self.last_tx_t = rt.clock.t    # virtual time of the last frame written

    def send(self, asdu: bytes) -> None:
        self.held.append(asdu)
        self._release()

    def _release(self) -> None:
        while self.held and self.sent - self.acked < K:
            self.writer.write(i_frame(self.vs, self.vr, self.held.popleft()))
            self.vs = (self.vs + 1) % SEQ_MOD
            self.sent += 1
            self.last_tx_t = self.rt.clock.t

    def ack(self, nr: int) -> None:
        outstanding = (self.vs - nr) % SEQ_MOD
        if outstanding > self.sent - self.acked:
            raise ConnectionError(f"N(R) {nr} acknowledges I-frames that were never sent")
        self.acked = self.sent - outstanding
        self._release()

    def control(self, function: int) -> None:
        self.writer.write(u_frame(function))
        self.last_tx_t = self.rt.clock.t


class _Running:
    """Adapter for ``Runtime.servers`` (which awaits ``shutdown()``)."""

    def __init__(self, server: asyncio.Server, links: dict) -> None:
        self.server, self.links = server, links

    async def shutdown(self) -> None:
        self.server.close()
        for link in list(self.links.values()):
            link.writer.close()
        await asyncio.wait_for(self.server.wait_closed(), 5)


def _common_address(value, host_id: str, rng, actor_id: str) -> int:
    if isinstance(value, dict):
        value = value.get(host_id)
    if value is None:
        return rng.randrange(1, 1000)
    if not isinstance(value, int) or not 1 <= value <= 0xFFFE:
        raise ScenarioError(f"{actor_id}: common_address must be an integer 1..65534 (or a map host -> address)")
    return value


@register
class Iec104Server(Actor):
    """Substation RTU (ABB RTU560 style): IEC 104 controlled station reporting the host's process."""

    type = "iec104.server"
    is_server = True

    def plan(self) -> None:
        plan = self.plan_
        cyclic = float(self.param("cyclic_s", 10) or 0)
        scan = float(self.param("scan_s", 2.0) or 0)
        deadband = float(self.param("deadband", 0.02))
        if cyclic < 0 or scan < 0:
            raise ScenarioError(f"{self.id}: cyclic_s and scan_s must be >= 0 (0 disables)")
        if not 0 < deadband < 1:
            raise ScenarioError(f"{self.id}: deadband is a fraction of the normal band, 0 < deadband < 1")
        self.stations: dict[str, Station] = {}
        rtus = []
        for host in self.hosts:
            profile = host_process(self, host)
            objects = tuple(info_objects(profile))
            if not objects:
                raise ScenarioError(f"{self.id}: process '{profile.id}' has no points to report")
            ca = _common_address(self.param("common_address"), host.id, self.rng.child(f"address:{host.id}"),
                                 self.id)
            self.stations[host.id] = Station(host.id, profile, ca, objects)
            rng = self.rng.child(f"reports:{host.id}")
            if cyclic:
                t = rng.uniform(0.5, cyclic)
                while t < plan.duration:
                    plan.add(t, self.id, host.id, "iec104.cyclic")
                    t += rng.jitter(cyclic, 0.0005)
            if scan:
                t = rng.uniform(0.1, scan)
                while t < plan.duration:
                    # Events carry the time the RTU detected them, a few ms before transmission.
                    plan.add(t, self.id, host.id, "iec104.spontaneous", lag_ms=round(rng.uniform(1.0, 20.0), 1))
                    t += rng.jitter(scan, 0.02)
            rtus.append({"host": host_ref(host.id), "process": profile.id, "common_address": ca,
                         "objects": [{"ioa": o.ioa, "name": o.point.name, "unit": o.point.unit,
                                      "desc": o.point.desc, "table": o.point.table,
                                      "type_id": o.type_id, "type": TYPE_NAMES[o.type_id],
                                      "event_type_id": o.event_type_id, "event_type": TYPE_NAMES[o.event_type_id],
                                      "deadband": round(deadband_step(o.point, deadband), 6) if not o.single else None}
                                     for o in objects]})
        self.deadband = deadband
        plan.facts[self.id] = {"hosts": [host_ref(h.id) for h in self.hosts],
                               "port": ports.WELL_KNOWN[ports.IEC104], "cyclic_s": cyclic, "scan_s": scan,
                               "deadband": deadband, "k": K, "w": W, "rtus": rtus}

    async def serve(self, rt) -> None:
        self.links: dict[tuple[str, int], _Link] = {}       # master (address, port) -> link
        self.reported: dict[str, dict[str, float]] = {}     # host -> last reported values
        for host in self.hosts:
            station = self.stations[host.id]
            host_sim(rt, self, host, station.profile)
            server = await asyncio.start_server(functools.partial(self._session, rt, station),
                                                host.loopback, ports.IEC104)
            rt.servers.append(_Running(server, self.links))

    async def _session(self, rt, station: Station, reader: asyncio.StreamReader,
                       writer: asyncio.StreamWriter) -> None:
        link = _Link(rt, station, writer)
        key = writer.get_extra_info("peername")[:2]
        self.links[key] = link
        try:
            while True:
                head = await reader.readexactly(2)
                if head[0] != START or head[1] < 4:
                    break
                self._on_frame(rt, link, await reader.readexactly(head[1]))
                await writer.drain()
                link.settled = link.acked
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            self.links.pop(key, None)
            writer.close()

    def _on_frame(self, rt, link: _Link, body: bytes) -> None:
        if body[0] & 0x01 == 0:                                    # I-frame
            ns, nr = control_numbers(body)
            if ns != link.vr:
                raise ConnectionError(f"I-frame N(S) {ns}, expected {link.vr}")
            link.vr = (link.vr + 1) % SEQ_MOD
            link.ack(nr)
            if link.active:
                self._command(rt, link, body[4:])
        elif body[0] & 0x03 == 0x01:                               # S-frame
            link.ack(control_numbers(body)[1])
        elif body[0] == STARTDT_ACT:
            link.active = True
            link.control(STARTDT_CON)
        elif body[0] == STOPDT_ACT:
            link.active = False
            link.control(STOPDT_CON)
        elif body[0] == TESTFR_ACT:
            link.control(TESTFR_CON)

    def _command(self, rt, link: _Link, asdu: bytes) -> None:
        type_id, _, cot, _, ca = struct.unpack_from("<BBBBH", asdu)
        station = link.station

        def mirror(reply_cot: int) -> bytes:
            return asdu[:2] + bytes([reply_cot]) + asdu[3:]

        if ca not in (station.common_address, BROADCAST_CA):
            link.send(mirror(UNKNOWN_CA | NEGATIVE))
        elif type_id == C_IC_NA_1 and cot & 0x3F == ACTIVATION:
            link.send(mirror(ACTCON))
            values = _values(self._sim(rt, station))
            for type_id_ in (M_SP_NA_1, M_ME_NC_1):
                for data in asdus(type_id_, INROGEN, station.common_address,
                                  [o.encode(values[o.point.name]) for o in station.objects if o.type_id == type_id_]):
                    link.send(data)
            link.send(mirror(ACTTERM))
        elif type_id == C_CS_NA_1 and cot & 0x3F == ACTIVATION:
            link.send(mirror(ACTCON))
        else:
            link.send(mirror(UNKNOWN_TYPE | NEGATIVE))

    def execute(self, action, rt) -> None:
        station = self.stations[action.host]
        if action.op == "iec104.cyclic":
            coro = self._cyclic(rt, station)
        elif action.op == "iec104.spontaneous":
            coro = self._spontaneous(rt, station, action.args["lag_ms"])
        else:
            raise ValueError(f"unknown op {action.op}")
        asyncio.run_coroutine_threadsafe(coro, rt.loop).result(REPLY_TIMEOUT)

    def _sim(self, rt, station: Station):
        sim = host_sim(rt, self, rt.plan.topology.by_id[station.host_id], station.profile)
        sim.advance(rt.clock.t)
        return sim

    async def _broadcast(self, station: Station, data: list[bytes]) -> None:
        links = [link for link in self.links.values() if link.station is station and link.active]
        for link in links:
            for asdu in data:
                link.send(asdu)
        for link in links:
            await link.writer.drain()

    async def _cyclic(self, rt, station: Station) -> None:
        values = self._sim(rt, station).values("input")
        await self._broadcast(station, asdus(M_ME_NC_1, PERIODIC, station.common_address,
                                             [o.encode(values[o.point.name]) for o in station.objects
                                              if o.point.table == "input"]))

    async def _spontaneous(self, rt, station: Station, lag_ms: float) -> None:
        values = _values(self._sim(rt, station))
        reported = self.reported.get(station.host_id)
        if reported is None:                  # first scan: the RTU's initial process image
            self.reported[station.host_id] = values
            return
        deadband = self.deadband
        tag = cp56time2a(rt.plan.start_epoch + rt.clock.t - lag_ms / 1000)
        events: dict[int, list[bytes]] = {M_SP_TB_1: [], M_ME_TF_1: []}
        for o in station.objects:
            value, last = values[o.point.name], reported[o.point.name]
            moved = value != last if o.single else abs(value - last) >= deadband_step(o.point, deadband)
            if moved:
                reported[o.point.name] = value
                events[o.event_type_id].append(o.encode(value, tag))
        await self._broadcast(station, [data for type_id, objects in events.items()
                                        for data in asdus(type_id, SPONTANEOUS, station.common_address, objects)])


def serving_rtu(plan, host_id: str) -> tuple[Iec104Server, Station]:
    """The iec104.server actor running on ``host_id`` and its station."""
    for actor in plan.actors:
        if isinstance(actor, Iec104Server) and host_id in actor.stations:
            return actor, actor.stations[host_id]
    raise ScenarioError(f"no iec104.server runs on host '{host_id}'")


# --- client ----------------------------------------------------------------------------

class Iec104Session:
    """Controlling-station side of one connection over a blocking socket."""

    def __init__(self, source: str, target: str) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self.sock.settimeout(REPLY_TIMEOUT)
            self.sock.bind((source, 0))
            self.sock.connect((target, ports.IEC104))
        except BaseException:
            self.sock.close()
            raise
        self.link: _Link | None = None
        self.vs = self.vr = 0
        self.received = 0              # I-frames received since connect
        self.acked = 0                 # of those, acknowledged (S-frame or own I-frame's N(R))
        self.last = 0.0                # virtual time of the last frame exchanged

    def _send(self, frame: bytes, now: float) -> None:
        self.sock.sendall(frame)
        self.last = now

    def _recv(self, size: int) -> bytes:
        data = b""
        while len(data) < size:
            chunk = self.sock.recv(size - len(data))
            if not chunk:
                raise RuntimeError("IEC 104 connection closed by the RTU")
            data += chunk
        return data

    def _next(self, now: float) -> tuple[str, int | bytes]:
        start, length = self._recv(2)
        if start != START or length < 4:
            raise RuntimeError(f"bad APCI start 0x{start:02x} / length {length}")
        body = self._recv(length)
        if body[0] & 0x01 == 0:
            ns = control_numbers(body)[0]
            if ns != self.vr:
                raise RuntimeError(f"I-frame N(S) {ns}, expected {self.vr}")
            self.vr = (self.vr + 1) % SEQ_MOD
            self.received += 1
            if self.received - self.acked >= W:
                self.ack(now)
            return "I", body[4:]
        if body[0] & 0x03 == 0x01:
            return "S", control_numbers(body)[1]
        return "U", body[0]

    def start(self, now: float, links: dict) -> None:
        self.control(STARTDT_ACT, STARTDT_CON, now)
        self.link = links[self.sock.getsockname()[:2]]

    def control(self, act: int, con: int, now: float) -> None:
        self._send(u_frame(act), now)
        while self._next(now) != ("U", con):
            pass

    def ack(self, now: float) -> None:
        """S-frame for every I-frame received; returns once the RTU has processed it (and sent
        what the k window held back)."""
        self._send(s_frame(self.vr), now)
        self.acked = self.received
        deadline = time.monotonic() + REPLY_TIMEOUT
        while self.link.settled < self.received:
            if time.monotonic() > deadline:
                raise RuntimeError("the RTU did not process the S-frame")
            time.sleep(0.0005)

    def sync(self, now: float) -> None:
        """Read every I-frame the RTU has sent so far."""
        while self.received < self.link.sent:
            self._next(now)
        self.last = max(self.last, self.link.last_tx_t)

    def command(self, asdu: bytes, final_cot: int, now: float) -> None:
        """Send a command ASDU and read up to its confirmation with ``final_cot``."""
        self.sync(now)
        self._send(i_frame(self.vs, self.vr, asdu), now)
        self.vs = (self.vs + 1) % SEQ_MOD
        self.acked = self.received
        while True:
            kind, value = self._next(now)
            if kind == "I" and value[0] == asdu[0]:
                if value[2] & NEGATIVE:
                    raise RuntimeError(f"{TYPE_NAMES[asdu[0]]} rejected (cause {value[2] & 0x3F})")
                if value[2] & 0x3F == final_cot:
                    break
        self.last = max(self.last, self.link.last_tx_t)

    def interrogate(self, ca: int, now: float) -> None:
        self.command(asdu_header(C_IC_NA_1, 1, ACTIVATION, ca) + ioa(0) + bytes([QOI_STATION]), ACTTERM, now)

    def clock_sync(self, ca: int, epoch: float, now: float) -> None:
        self.command(asdu_header(C_CS_NA_1, 1, ACTIVATION, ca) + ioa(0) + cp56time2a(epoch), ACTCON, now)

    def idle(self, t3: float, now: float) -> None:
        """t2 expiry: acknowledge what arrived; t3 expiry: test the idle link."""
        self.sync(now)
        if self.received > self.acked:
            self.ack(now)
            self.sync(now)
        elif now - self.last >= t3:
            self.control(TESTFR_ACT, TESTFR_CON, now)

    def stop(self, now: float) -> None:
        self.sync(now)
        if self.received > self.acked:
            self.ack(now)
        self.control(STOPDT_ACT, STOPDT_CON, now)

    def close(self) -> None:
        self.sock.close()


@register
class Iec104Client(Actor):
    """SCADA master: persistent session per RTU with clock sync, general interrogation, t2
    acknowledgements and t3 link tests."""

    type = "iec104.client"

    def plan(self) -> None:
        plan = self.plan_
        targets = plan.topology.select(self.param("targets"))
        gi_interval = float(self.param("gi_interval_s", 900) or 0)
        t2 = float(self.param("t2_s", 10))
        t3 = float(self.param("t3_s", 20))
        clock_sync = bool(self.param("clock_sync", True))
        if gi_interval < 0 or t2 <= 0 or t3 <= 0:
            raise ScenarioError(f"{self.id}: t2_s and t3_s must be > 0, gi_interval_s >= 0 (0 disables)")
        self.servers = {}
        for target in targets:
            server, station = serving_rtu(plan, target.id)
            self.servers[target.id] = server
        sessions = []
        for host in self.hosts:
            for target in targets:
                ca = self.servers[target.id].stations[target.id].common_address
                rng = self.rng.child(f"{host.id}>{target.id}")
                t = rng.uniform(0.05, 0.8)
                plan.add(t, self.id, host.id, "iec104.connect", phase="setup", target=target.id)
                if clock_sync:
                    t += rng.uniform(0.01, 0.05)
                    plan.add(t, self.id, host.id, "iec104.clock_sync", phase="setup", target=target.id, ca=ca)
                t += rng.uniform(0.01, 0.05)
                plan.add(t, self.id, host.id, "iec104.gi", phase="setup", target=target.id, ca=ca)
                if gi_interval:
                    tg = t + rng.jitter(gi_interval, 0.002)
                    while tg < plan.duration:
                        plan.add(tg, self.id, host.id, "iec104.gi", target=target.id, ca=ca)
                        tg += rng.jitter(gi_interval, 0.002)
                ti = t + rng.jitter(t2, 0.1)
                while ti < plan.duration:
                    plan.add(ti, self.id, host.id, "iec104.idle", target=target.id, t3=t3)
                    ti += rng.jitter(t2, 0.1)
                plan.add(plan.duration + 1.0, self.id, host.id, "iec104.close", phase="teardown", target=target.id)
                sessions.append({"master": host_ref(host.id), "rtu": host_ref(target.id), "common_address": ca})
        plan.facts[self.id] = {"hosts": [host_ref(h.id) for h in self.hosts],
                               "targets": [host_ref(t.id) for t in targets], "sessions": sessions,
                               "gi_interval_s": gi_interval, "t2_s": t2, "t3_s": t3, "k": K, "w": W,
                               "clock_sync": clock_sync, "qoi": QOI_STATION}

    def execute(self, action, rt) -> None:
        a = action.args
        key = (self.id, action.host, a["target"])
        now = rt.clock.t
        if action.op == "iec104.connect":
            session = Iec104Session(rt.loopback(action.host), rt.loopback(a["target"]))
            try:
                session.start(now, self.servers[a["target"]].links)
            except BaseException:
                session.close()
                raise
            rt.clients[key] = session
        elif action.op == "iec104.clock_sync":
            rt.clients[key].clock_sync(a["ca"], rt.plan.start_epoch + now, now)
        elif action.op == "iec104.gi":
            rt.clients[key].interrogate(a["ca"], now)
        elif action.op == "iec104.idle":
            rt.clients[key].idle(a["t3"], now)
        elif action.op == "iec104.close":
            session = rt.clients.pop(key)
            try:
                session.stop(now)
            finally:
                session.close()
        else:
            raise ValueError(f"unknown op {action.op}")

    def close(self, rt) -> None:
        for key in [k for k in rt.clients if k[0] == self.id]:
            rt.clients.pop(key).close()
