"""Siemens S7comm (ISO-on-TCP, RFC 1006) actors.

The PLC side is a python-snap7 server (optional extra ``s7``) bound to the host's loopback
address; its data blocks are refreshed from the process simulation at the virtual time of every
read. The client frames COTP / S7 PDUs itself: snap7's client cannot bind a source address.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import logging
import math
import re
import socket
import struct
from dataclasses import dataclass
from functools import cache

from pcapforge import ports
from pcapforge.actors import register
from pcapforge.actors.base import Actor, optional_import
from pcapforge.actors.modbus import serving_profile
from pcapforge.plan import host_ref
from pcapforge.process import BIT_TABLES, ProcessProfile, ProcessSim
from pcapforge.scenario import ScenarioError


@dataclass(frozen=True)
class Cpu:
    module: str        # SZL module type name
    station: str       # TIA Portal default station (automation system) name
    max_pdu: int       # largest S7 PDU the CPU negotiates


# Order code (device identity ProductCode) -> CPU description.
CPUS = {
    "6ES7 214-1AG40-0XB0": Cpu("CPU 1214C DC/DC/DC", "S71200/ET200MP station_1", 240),
    "6ES7 215-1AG40-0XB0": Cpu("CPU 1215C DC/DC/DC", "S71200/ET200MP station_1", 240),
    "6ES7 513-1AL02-0AB0": Cpu("CPU 1513-1 PN", "S71500/ET200MP station_1", 960),
    "6ES7 516-3AN02-0AB0": Cpu("CPU 1516-3 PN/DP", "S71500/ET200MP station_1", 960),
}
CLIENT_PDU = 480                      # PDU size the client proposes (Setup Communication)
TSAP_TYPES = {"pg": 1, "op": 2, "basic": 3}
CPU_STATE_SZL = (0x0424, 0x0000)      # current mode
IDENTITY_SZL = ((0x0011, 0x0000), (0x001C, 0x0000))  # module identification, component identification


# --- data blocks ---------------------------------------------------------------------

@dataclass(frozen=True)
class Block:
    db: int
    name: str
    tables: tuple[str, ...]   # one REAL table, or bit tables packed one after another
    size: int                 # bytes

    @property
    def bits(self) -> bool:
        return self.tables[0] in BIT_TABLES


def blocks(profile: ProcessProfile) -> list[Block]:
    """DB layout of a process: measurements and setpoints as REAL, status bits packed."""
    out = []
    for db, name, table in ((1, "ProcessValues", "input"), (2, "Setpoints", "holding")):
        if profile.size(table):
            out.append(Block(db, name, (table,), 4 * profile.size(table)))
    bit_tables = tuple(t for t in BIT_TABLES if profile.size(t))
    if bit_tables:
        size = sum(-(-profile.size(t) // 8) for t in bit_tables)
        out.append(Block(3, "Status", bit_tables, size + size % 2))
    return out


def block_points(profile: ProcessProfile, block: Block) -> list[dict]:
    """Symbol table of a block (absolute S7 addresses)."""
    points, base = [], 0
    for table in block.tables:
        for p in profile.table(table):
            if block.bits:
                offset = base + p.address // 8
                points.append({"name": p.name, "address": f"DB{block.db}.DBX{offset}.{p.address % 8}",
                               "type": "BOOL"})
            else:
                points.append({"name": p.name, "address": f"DB{block.db}.DBD{4 * p.address}",
                               "type": "REAL", "unit": p.unit})
        base += -(-profile.size(table) // 8)
    return points


def fill(block: Block, profile: ProcessProfile, sim: ProcessSim, data: bytearray) -> None:
    """Write the current process values of ``block`` into its DB image."""
    if block.bits:
        data[:] = bytes(len(data))
        base = 0
        for table in block.tables:
            for address, bit in sim.read(table).items():
                if bit:
                    data[base + address // 8] |= 1 << (address % 8)
            base += -(-profile.size(table) // 8)
        return
    table = block.tables[0]
    for address, raw in sim.read(table).items():
        struct.pack_into(">f", data, 4 * address, profile.by_address[(table, address)].decode(raw))


# --- SZL records -----------------------------------------------------------------------

def _text(value: str, size: int) -> bytes:
    return value.encode("ascii")[:size].ljust(size, b"\x00")


def _szl_list(record_len: int, records: list[bytes]) -> bytes:
    assert all(len(r) == record_len for r in records)
    return struct.pack(">HH", record_len, len(records)) + b"".join(records)


def _bcd(value: int) -> int:
    return (value // 10) << 4 | value % 10


def s7_timestamp(epoch: float) -> bytes:
    """S7 DATE_AND_TIME: BCD year..second, milliseconds and day of week (1 = Sunday)."""
    t = dt.datetime.fromtimestamp(epoch, dt.UTC)
    ms = t.microsecond // 1000
    weekday = t.isoweekday() % 7 + 1
    return bytes([_bcd(t.year % 100), _bcd(t.month), _bcd(t.day), _bcd(t.hour), _bcd(t.minute),
                  _bcd(t.second), _bcd(ms // 10), (ms % 10) << 4 | weekday])


def firmware(revision: str) -> tuple[int, int, int]:
    match = re.fullmatch(r"V?(\d+)\.(\d+)(?:\.(\d+))?", revision.strip())
    if match is None:
        raise ScenarioError(f"cannot read an S7 firmware version from '{revision}' (use e.g. V4.5)")
    major, minor, patch = match.groups()
    return int(major), int(minor), int(patch or 0)


def szl_answers(identity: dict) -> dict[tuple[int, int], bytes]:
    """SZL list contents (LENTHDR, N_DR, records) the CPU answers, keyed by (SZL-ID, index)."""
    order = identity["order_code"].ljust(20).encode("ascii")
    major, minor, patch = identity["firmware"]
    module = struct.pack(">H20sHHH", 0x0001, order, 0x00C0, 0x0001, 0x0001)
    hardware = struct.pack(">H20sHHH", 0x0006, order, 0x00C0, 0x0001, 0x0001)
    fw = struct.pack(">H20sHHH", 0x0007, b" " * 20, 0x00C0, ord("V") << 8 | major, minor << 8 | patch)
    components = [
        struct.pack(">H", 1) + _text(identity["station"], 24) + bytes(8),
        struct.pack(">H", 2) + _text(identity["name"], 24) + bytes(8),
        struct.pack(">H", 3) + bytes(32),
        struct.pack(">H", 4) + _text("Original Siemens Equipment", 26) + bytes(6),
        struct.pack(">H", 5) + _text(identity["serial"], 24) + bytes(8),
        struct.pack(">H", 7) + _text(identity["module"], 32),
    ]
    # Last mode transition: STARTUP (complete restart) -> RUN after a battery-backed power on.
    state = struct.pack(">HBB4sBBBB", 0x4302, 0xFF, 0x58, bytes(4), 0x00, 0x10, 0x00, 0x10) \
        + s7_timestamp(identity["run_since_epoch"])
    return {
        (0x0011, 0x0000): _szl_list(28, [module, hardware, fw]),
        (0x001C, 0x0000): _szl_list(34, components),
        (0x0424, 0x0000): _szl_list(20, [state]),
    }


# --- server ----------------------------------------------------------------------------

@cache
def _server_class():
    optional_import(S7Server.type, *S7Server.requires)
    from snap7.datatypes import S7Area
    from snap7.server import Server
    from snap7.type import SrvArea

    class PlcServer(Server):
        """snap7 server whose DBs, SZL answers and PDU size follow one simulated CPU."""

        def __init__(self, rt, host_id: str, profile: ProcessProfile, layout: list[Block],
                     identity: dict) -> None:
            super().__init__(log=False)
            self.rt, self.host_id, self.profile = rt, host_id, profile
            self.blocks = {b.db: b for b in layout}
            self.szl = szl_answers(identity)
            self.max_pdu = identity["max_pdu"]
            for block in layout:
                self.register_area(SrvArea.DB, block.db, bytearray(block.size))

        def _read_from_memory_area(self, area, db_number, start, count):
            block = self.blocks.get(db_number) if area == S7Area.DB else None
            if block is not None:
                sim = self.rt.sims[self.host_id]
                sim.advance(self.rt.clock.t)
                with self.area_locks[(S7Area.DB, block.db)]:
                    fill(block, self.profile, sim, self.memory_areas[(S7Area.DB, block.db)])
            return super()._read_from_memory_area(area, db_number, start, count)

        def _handle_setup_communication(self, request):
            response = bytearray(super()._handle_setup_communication(request))
            requested = request["parameters"].get("pdu_length", CLIENT_PDU)
            response[-2:] = min(requested, self.max_pdu).to_bytes(2, "big")
            return bytes(response)

        def _get_szl_data(self, szl_id, szl_index):
            return self.szl.get((szl_id, szl_index))

    return PlcServer


class _Running:
    """Adapter for ``Runtime.servers`` (which awaits ``shutdown()``)."""

    def __init__(self, server) -> None:
        self.server = server

    async def shutdown(self) -> None:
        await asyncio.to_thread(self.server.stop)


@register
class S7Server(Actor):
    """Siemens S7-1200/1500 CPU: DBs mirror the process model, identity follows the device."""

    type = "s7.server"
    is_server = True
    requires = ("snap7", "python-snap7", "s7")

    def plan(self) -> None:
        plan = self.plan_
        self.profiles: dict[str, ProcessProfile] = {}
        self.shared: set[str] = set()   # hosts whose process sim belongs to a modbus.server
        self.identities: dict[str, dict] = {}
        facts = []
        for host in self.hosts:
            profile = self._profile(host)
            self.profiles[host.id] = profile
            self.identities[host.id] = identity = self._identity(host)
            facts.append({"host": host_ref(host.id), "process": profile.id,
                          **{k: identity[k] for k in ("module", "order_code", "station", "name", "serial")},
                          "firmware": "V{}.{}.{}".format(*identity["firmware"]),
                          "blocks": [{"db": b.db, "name": b.name, "size": b.size,
                                      "points": block_points(profile, b)} for b in blocks(profile)]})
        plan.facts[self.id] = {"hosts": [host_ref(h.id) for h in self.hosts], "plcs": facts}

    def _profile(self, host) -> ProcessProfile:
        name = self.param("process")
        try:
            modbus = serving_profile(self.plan_, host.id)
        except ValueError:
            modbus = None
        if modbus is not None:
            if name is not None and name != modbus.id:
                raise ScenarioError(f"{self.id}: host '{host.id}' runs process '{modbus.id}' for "
                                    f"modbus.server, not '{name}'")
            self.shared.add(host.id)
            return modbus
        if name is None:
            raise ScenarioError(f"{self.id}: host '{host.id}' needs params.process (no modbus.server runs there)")
        return ProcessProfile(name)

    def _identity(self, host) -> dict:
        ident = host.device.identity or {}
        code = ident.get("ProductCode", "")
        cpu = CPUS.get(code)
        if cpu is None:
            raise ScenarioError(f"{self.id}: device '{host.device.name}' of host '{host.id}' is not a known "
                                f"S7 CPU (identity ProductCode one of: {', '.join(sorted(CPUS))})")
        rng = self.rng.child(f"identity:{host.id}")
        letters = "ABCDEFGHJKLMNPRSTUVWXYZ"
        serial = ("S C-" + rng.choice(letters) + rng.choice(letters + "0123456789")
                  + "".join(rng.choice(letters) for _ in range(2))
                  + "".join(rng.choice("0123456789") for _ in range(8)))
        run_since = self.plan_.start_epoch - rng.uniform(2, 120) * 86400
        return {"module": cpu.module, "order_code": code, "station": cpu.station, "name": host.name,
                "serial": serial, "firmware": firmware(ident.get("MajorMinorRevision", "V1.0")),
                "max_pdu": cpu.max_pdu, "run_since_epoch": round(run_since, 3)}

    async def serve(self, rt) -> None:
        server_class = _server_class()
        logging.getLogger("snap7").setLevel(logging.CRITICAL)
        for host in self.hosts:
            profile = self.profiles[host.id]
            if host.id not in self.shared:
                rt.sims[host.id] = ProcessSim(profile, self.rng.child(host.id), self.plan_.start_hour)
            server = server_class(rt, host.id, profile, blocks(profile), self.identities[host.id])
            server.start_to(host.loopback, ports.S7)
            rt.servers.append(_Running(server))


def serving_cpu(plan, host_id: str) -> tuple[S7Server, ProcessProfile]:
    """The s7.server actor running on ``host_id`` and the process it serves."""
    for actor in plan.actors:
        if isinstance(actor, S7Server) and host_id in actor.profiles:
            return actor, actor.profiles[host_id]
    raise ScenarioError(f"no s7.server runs on host '{host_id}'")


# --- client ----------------------------------------------------------------------------

def read_jobs(items: list[tuple[int, int, int]], pdu: int) -> list[list[list[int]]]:
    """Group (db, start, size) DB reads into Read Var jobs whose request and response fit ``pdu``."""
    largest = (pdu - 18) & ~1          # one item: 12-byte ack header + 2 parameter + 4 item header
    pieces = [(db, start + offset, min(largest, size - offset))
              for db, start, size in items for offset in range(0, size, largest)]
    jobs: list[list[list[int]]] = []
    request = response = math.inf
    for db, start, size in pieces:
        cost = 4 + size + size % 2
        if request + 12 > pdu or response + cost > pdu:
            jobs.append([])
            request, response = 12, 14
        jobs[-1].append([db, start, size])
        request += 12
        response += cost
    return jobs


class S7Session:
    """One ISO-on-TCP connection to a CPU: COTP connect, Setup Communication, then jobs."""

    def __init__(self, source: str, target: str, local_tsap: int, remote_tsap: int, cotp_ref: int,
                 pdu_ref: int) -> None:
        self.pdu_ref = pdu_ref
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self.sock.settimeout(3.0)
            self.sock.bind((source, 0))
            self.sock.connect((target, ports.S7))
            params = (struct.pack(">BBB", 0xC0, 1, 0x0A) + struct.pack(">BBH", 0xC1, 2, local_tsap)
                      + struct.pack(">BBH", 0xC2, 2, remote_tsap))
            self._send(struct.pack(">BBHHB", 6 + len(params), 0xE0, 0x0000, cotp_ref, 0x00) + params)
            if self._frame()[1] != 0xD0:
                raise RuntimeError("COTP connection refused")
            self.job(struct.pack(">BBHHH", 0xF0, 0x00, 1, 1, CLIENT_PDU))
        except BaseException:
            self.sock.close()
            raise

    def _send(self, cotp: bytes) -> None:
        self.sock.sendall(struct.pack(">BBH", 3, 0, 4 + len(cotp)) + cotp)

    def _recv(self, size: int) -> bytes:
        data = b""
        while len(data) < size:
            chunk = self.sock.recv(size - len(data))
            if not chunk:
                raise RuntimeError("S7 connection closed by the PLC")
            data += chunk
        return data

    def _frame(self) -> bytes:
        version, _, length = struct.unpack(">BBH", self._recv(4))
        if version != 3:
            raise RuntimeError(f"bad TPKT version {version}")
        return self._recv(length - 4)

    def _pdu(self, rosctr: int, param: bytes, data: bytes) -> bytes:
        self.pdu_ref = (self.pdu_ref + 1) & 0xFFFF
        header = struct.pack(">BBHHHH", 0x32, rosctr, 0, self.pdu_ref, len(param), len(data))
        self._send(b"\x02\xf0\x80" + header + param + data)
        payload = b""
        while True:  # reassemble COTP DT fragments up to the EOT flag
            frame = self._frame()
            if frame[1] != 0xF0:
                raise RuntimeError(f"unexpected COTP PDU 0x{frame[1]:02x}")
            payload += frame[3:]
            if frame[2] & 0x80:
                break
        if payload[:1] != b"\x32" or struct.unpack_from(">H", payload, 4)[0] != self.pdu_ref:
            raise RuntimeError("S7 response does not answer the request")
        return payload

    def job(self, param: bytes) -> bytes:
        response = self._pdu(0x01, param, b"")
        if response[1] != 0x03 or response[10:12] != b"\x00\x00":
            raise RuntimeError(f"S7 job failed (error 0x{response[10:12].hex()})")
        return response

    def read(self, items: list[list[int]]) -> None:
        param = struct.pack(">BB", 0x04, len(items)) + b"".join(
            struct.pack(">BBBBHHB", 0x12, 0x0A, 0x10, 0x02, size, db, 0x84) + (start * 8).to_bytes(3, "big")
            for db, start, size in items)
        data = self.job(param)[14:]
        offset = 0
        for index, (db, _, size) in enumerate(items):
            if data[offset] != 0xFF:
                raise RuntimeError(f"Read Var DB{db} failed (return code 0x{data[offset]:02x})")
            offset += 4 + size + (size % 2 if index < len(items) - 1 else 0)

    def read_szl(self, szl_id: int, index: int) -> None:
        param = bytes([0x00, 0x01, 0x12, 0x04, 0x11, 0x44, 0x01, 0x00])
        response = self._pdu(0x07, param, struct.pack(">BBHHH", 0xFF, 0x09, 4, szl_id, index))
        param_len = struct.unpack_from(">H", response, 6)[0]
        if response[10 + param_len] != 0xFF:
            raise RuntimeError(f"SZL 0x{szl_id:04x} read failed")

    def close(self) -> None:
        self.sock.close()


@register
class S7Client(Actor):
    """HMI / SCADA S7 driver: persistent session per CPU, cyclic DB reads, CPU-state polling."""

    type = "s7.client"

    def plan(self) -> None:
        plan = self.plan_
        targets = plan.topology.select(self.param("targets"))
        interval = float(self.param("interval", 1.0))
        jitter = float(self.param("jitter", 0.02))
        szl_interval = float(self.param("szl_interval", 60) or 0)
        identify = bool(self.param("identify", True))
        wanted = self.param("dbs")
        rack, slot = int(self.param("rack", 0)), int(self.param("slot", 1))
        connection = self.param("connection", "op")
        if connection not in TSAP_TYPES:
            raise ScenarioError(f"{self.id}: connection must be one of {', '.join(TSAP_TYPES)}")
        remote_tsap = TSAP_TYPES[connection] << 8 | rack << 5 | slot
        jobs = {}
        for target in targets:
            server, profile = serving_cpu(plan, target.id)
            layout = [b for b in blocks(profile) if wanted is None or b.db in wanted]
            if not layout:
                raise ScenarioError(f"{self.id}: no data blocks to read on '{target.id}'")
            pdu = min(CLIENT_PDU, server.identities[target.id]["max_pdu"])
            jobs[target.id] = read_jobs([(b.db, 0, b.size) for b in layout], pdu)
        for host in self.hosts:
            rng = self.rng.child(host.id)
            for target in targets:
                t = rng.uniform(0, 0.05)
                plan.add(t, self.id, host.id, "s7.connect", phase="setup", target=target.id,
                         local_tsap=0x0100, remote_tsap=remote_tsap, cotp_ref=rng.randrange(1, 0x10000),
                         pdu_ref=rng.randrange(0, 0x10000))
                if identify:
                    for szl_id, index in IDENTITY_SZL:
                        t += rng.uniform(0.005, 0.03)
                        plan.add(t, self.id, host.id, "s7.szl", phase="setup", target=target.id,
                                 szl_id=szl_id, index=index)
                if szl_interval > 0:
                    t = rng.uniform(0.2, szl_interval)
                    while t < plan.duration:
                        plan.add(t, self.id, host.id, "s7.szl", target=target.id,
                                 szl_id=CPU_STATE_SZL[0], index=CPU_STATE_SZL[1])
                        t += rng.jitter(szl_interval, 0.05)
            t = rng.uniform(0.1, interval) + 0.1
            while t < plan.duration:
                tt = t
                for target in targets:
                    for items in jobs[target.id]:
                        tt += rng.uniform(0.002, 0.012)
                        plan.add(tt, self.id, host.id, "s7.read", target=target.id, items=items)
                    tt += rng.uniform(0.004, 0.03)
                t += rng.jitter(interval, jitter)
            for target in targets:
                plan.add(plan.duration + 1.0, self.id, host.id, "s7.close", phase="teardown", target=target.id)
        plan.facts[self.id] = {"hosts": [host_ref(h.id) for h in self.hosts],
                               "targets": [host_ref(t.id) for t in targets],
                               "interval_s": interval, "szl_interval_s": szl_interval,
                               "dbs": sorted({item[0] for js in jobs.values() for job in js for item in job})}

    def execute(self, action, rt) -> None:
        a = action.args
        key = (self.id, action.host, a["target"])
        if action.op == "s7.connect":
            rt.clients[key] = S7Session(rt.loopback(action.host), rt.loopback(a["target"]), a["local_tsap"],
                                        a["remote_tsap"], a["cotp_ref"], a["pdu_ref"])
        elif action.op == "s7.read":
            rt.clients[key].read(a["items"])
        elif action.op == "s7.szl":
            rt.clients[key].read_szl(a["szl_id"], a["index"])
        elif action.op == "s7.close":
            rt.clients.pop(key).close()
        else:
            raise ValueError(f"unknown op {action.op}")

    def close(self, rt) -> None:
        for key in [k for k in rt.clients if k[0] == self.id]:
            rt.clients.pop(key).close()
