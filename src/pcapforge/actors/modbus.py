"""Modbus/TCP actors backed by pymodbus."""

from __future__ import annotations

import socket

from pymodbus.client import ModbusTcpClient
from pymodbus.pdu.device import ModbusControlBlock, ModbusDeviceIdentification
from pymodbus.server import ModbusTcpServer
from pymodbus.simulator import DataType, SimData, SimDevice

from pcapforge import ports
from pcapforge.actors import register
from pcapforge.actors.base import Actor
from pcapforge.plan import action_ref, host_ref
from pcapforge.process import BIT_TABLES, FUNCTION_TABLE, ProcessProfile, ProcessSim


@register
class ModbusServer(Actor):
    """Simulated PLC: register tables driven by a physical-process model."""

    type = "modbus.server"
    is_server = True

    def plan(self) -> None:
        self.profile = ProcessProfile(self.param("process"))
        self.plan_.facts[self.id] = {
            "process": self.profile.id,
            "title": self.profile.title,
            "unit_id": self.profile.unit_id,
            "hosts": [host_ref(h.id) for h in self.hosts],
        }

    async def serve(self, rt) -> None:
        for host in self.hosts:
            sim = ProcessSim(self.profile, self.rng.child(host.id), self.plan_.start_hour)
            rt.sims[host.id] = sim
            device = self._device(host, sim, rt)
            server = ModbusTcpServer(device, address=(host.loopback, ports.MODBUS))
            await server.serve_forever(background=True)
            rt.servers.append(server)

    def _device(self, host, sim: ProcessSim, rt) -> SimDevice:
        profile = self.profile

        def block(table: str) -> list[SimData]:
            size = profile.size(table)
            values = sim.read(table)
            if table in BIT_TABLES:
                padded = -(-size // 16) * 16
                bits = [bool(values.get(a, 0)) for a in range(padded)]
                return [SimData(0, values=bits, datatype=DataType.BITS)]
            return [SimData(0, values=[values.get(a, 0) for a in range(size)], datatype=DataType.REGISTERS)]

        async def on_access(function_code, start, address, count, regs, set_values):
            sim.advance(rt.clock.t)
            table = FUNCTION_TABLE.get(function_code)
            if table is None:
                return None
            if set_values is not None:
                sim.write(table, address, [int(v) for v in set_values])
                return None
            values = sim.read(table)
            if table in BIT_TABLES:
                for addr, bit in values.items():
                    word = addr // 16 - start
                    if 0 <= word < len(regs):
                        mask = 1 << (addr % 16)
                        regs[word] = (regs[word] | mask) if bit else (regs[word] & ~mask)
            else:
                for addr, value in values.items():
                    if 0 <= addr - start < len(regs):
                        regs[addr - start] = value
            return None

        identity = None
        if host.device.identity:
            identity = ModbusDeviceIdentification(info_name=dict(host.device.identity))
        return SimDevice(
            id=profile.unit_id,
            identity=identity,
            action=on_access,
            simdata=(block("coils"), block("discrete"), block("holding"), block("input")),
        )


def serving_profile(plan, host_id: str) -> ProcessProfile:
    """Process profile of the modbus.server actor running on ``host_id``."""
    for actor in plan.actors:
        if isinstance(actor, ModbusServer) and any(h.id == host_id for h in actor.hosts):
            return ProcessProfile(actor.param("process"))
    raise ValueError(f"no modbus.server runs on host '{host_id}'")


READERS = {1: "read_coils", 2: "read_discrete_inputs", 3: "read_holding_registers",
           4: "read_input_registers"}


class ModbusClientActor(Actor):
    """Shared client plumbing: one pymodbus client per (host, target) session."""

    def _client(self, rt, host_id: str, target_id: str):
        key = (self.id, host_id, target_id)
        client = rt.clients.get(key)
        if client is None:
            client = ModbusTcpClient(
                rt.loopback(target_id), port=ports.MODBUS,
                source_address=(rt.loopback(host_id), 0), retries=0, timeout=2)
            if not client.connect():
                raise RuntimeError(f"{host_id} cannot reach Modbus service on {target_id}")
            rt.clients[key] = client
        return client

    def _drop(self, rt, host_id: str, target_id: str) -> None:
        client = rt.clients.pop((self.id, host_id, target_id), None)
        if client is not None:
            client.close()

    def execute(self, action, rt) -> None:
        a = action.args
        if action.op == "modbus.connect":
            self._client(rt, action.host, a["target"])
        elif action.op == "modbus.close":
            self._drop(rt, action.host, a["target"])
        elif action.op == "modbus.read":
            client = self._client(rt, action.host, a["target"])
            getattr(client, READERS[a["function"]])(a["start"], count=a["count"], device_id=a["unit"])
        elif action.op == "modbus.identify":
            # pymodbus answers Read Device Identification (function 43) from a process-global
            # control block, not per server, so with several PLCs the last one created would win.
            # Device identification is only ever requested here, one exchange at a time, so set the
            # global to the target PLC's identity for the duration of this blocking read.
            identity = rt.plan.topology.by_id[a["target"]].device.identity
            ModbusControlBlock().Identity.update(ModbusDeviceIdentification(info_name=dict(identity or {})))
            client = self._client(rt, action.host, a["target"])
            client.read_device_information(read_code=1, object_id=0, device_id=a["unit"])
        elif action.op == "modbus.probe":
            # A bare TCP connect to port 502 on a host that may not run Modbus: the SYN and the
            # peer's answer (RST on a closed port) are captured; a refusal is expected and ignored.
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            try:
                sock.bind((rt.loopback(action.host), 0))
                sock.connect((rt.loopback(a["target"]), ports.MODBUS))
            except OSError:
                pass
            finally:
                sock.close()
        elif action.op == "modbus.write":
            client = self._client(rt, action.host, a["target"])
            fn, addr, values = a["function"], a["address"], a["values"]
            if fn == 6:
                client.write_register(addr, values[0], device_id=a["unit"])
            elif fn == 16:
                client.write_registers(addr, values, device_id=a["unit"])
            elif fn == 5:
                client.write_coil(addr, bool(values[0]), device_id=a["unit"])
            elif fn == 15:
                client.write_coils(addr, [bool(v) for v in values], device_id=a["unit"])
        else:
            raise ValueError(f"unknown op {action.op}")

    def close(self, rt) -> None:
        for key in [k for k in rt.clients if k[0] == self.id]:
            rt.clients.pop(key).close()


@register
class ModbusPoller(ModbusClientActor):
    """SCADA/HMI or historian: persistent sessions, cyclic reads of the poll groups."""

    type = "modbus.poller"

    def plan(self) -> None:
        plan = self.plan_
        targets = plan.topology.select(self.param("targets"))
        interval = float(self.param("interval", 1.0))
        jitter = float(self.param("jitter", 0.02))
        wanted = self.param("groups")
        for host in self.hosts:
            rng = self.rng.child(host.id)
            groups = {t.id: serving_profile(plan, t.id).poll_groups for t in targets}
            for target in targets:
                plan.add(rng.uniform(0, 0.05), self.id, host.id, "modbus.connect", phase="setup",
                         target=target.id)
            t = rng.uniform(0.1, interval)
            while t < plan.duration:
                tt = t
                for target in targets:
                    unit = serving_profile(plan, target.id).unit_id
                    for index, group in enumerate(groups[target.id]):
                        if wanted is not None and index not in wanted:
                            continue
                        tt += rng.uniform(0.002, 0.012)
                        plan.add(tt, self.id, host.id, "modbus.read", target=target.id, unit=unit,
                                 function=group["function"], start=group["start"], count=group["count"])
                    tt += rng.uniform(0.004, 0.03)
                t += rng.jitter(interval, jitter)
            for target in targets:
                plan.add(plan.duration + 1.0, self.id, host.id, "modbus.close", phase="teardown",
                         target=target.id)
        plan.facts[self.id] = {"hosts": [host_ref(h.id) for h in self.hosts],
                               "targets": [host_ref(t.id) for t in targets],
                               "interval_s": interval}


def _holding_group(profile: ProcessProfile) -> dict:
    return next((g for g in profile.poll_groups if g["function"] == 3),
                {"function": 3, "start": 0, "count": profile.size("holding")})


class _SessionPlanner:
    """Adds connect / ops / close actions for one short client session."""

    def __init__(self, actor: Actor, host_id: str, target_id: str, unit: int, t: float, rng) -> None:
        self.actor, self.host_id, self.target_id, self.unit, self.t, self.rng = actor, host_id, target_id, unit, t, rng
        self.add("modbus.connect", gap=(0.0, 0.0))

    def add(self, op: str, gap=(0.05, 0.4), **args):
        self.t += self.rng.uniform(*gap)
        extra = {} if op in ("modbus.connect", "modbus.close") else {"unit": self.unit}
        return self.actor.plan_.add(self.t, self.actor.id, self.host_id, op, target=self.target_id,
                                    **extra, **args)

    def read(self, function: int, start: int, count: int, gap=(0.05, 0.4)):
        return self.add("modbus.read", gap=gap, function=function, start=start, count=count)

    def write(self, function: int, address: int, values: list[int], gap=(0.2, 2.0)):
        return self.add("modbus.write", gap=gap, function=function, address=address, values=values)

    def close(self):
        return self.add("modbus.close", gap=(0.01, 0.3))


@register
class ModbusOperator(ModbusClientActor):
    """Engineering workstation: occasional legitimate setpoint adjustments inside the normal band."""

    type = "modbus.operator"

    def plan(self) -> None:
        plan = self.plan_
        targets = plan.topology.select(self.param("targets"))
        count = int(self.param("count", 0))
        host = self.hosts[0]
        slots = sorted(self.rng.uniform(0.05, 0.95) * plan.duration for _ in range(count))
        writes = []
        for t in slots:
            target = self.rng.choice(targets)
            profile = serving_profile(plan, target.id)
            choice = self.rng.choice(profile.operator_adjustable)
            point = profile.by_name[choice["name"]]
            lo, hi = point.normal
            step = self.rng.uniform(*choice["step"]) * self.rng.choice((-1, 1))
            value = min(max(point.nominal + step, lo), hi)
            raw = point.encode(value)
            session = _SessionPlanner(self, host.id, target.id, profile.unit_id, t, self.rng)
            group = _holding_group(profile)
            session.read(3, group["start"], group["count"])
            action = session.write(16, point.address, [raw])
            session.read(3, group["start"], group["count"])
            session.close()
            writes.append({"target": host_ref(target.id), "point": point.name, "address": point.address,
                           "raw": raw, "value": point.decode(raw), "unit": point.unit,
                           "function": 16, "request": {"$action": action}})
            plan.event(action, self.id, f"Operator adjusts {point.name} on {target.id}", [],
                       point=point.name, value=point.decode(raw), legitimate=True)
        plan.facts[self.id] = {"source": host_ref(host.id), "write_count": len(writes), "writes": writes}


DEVIATION = {"extreme": (2.5, 5.0), "moderate": (0.5, 1.2), "subtle": (0.08, 0.25)}


def _push_down(name: str, rng) -> bool:
    """Low-alarm thresholds are pushed further down (alarm never fires), high-alarm
    thresholds up; other setpoints go either way."""
    words = set(name.split("_"))
    if "low" in words:
        return True
    if "high" in words:
        return False
    return rng.random() < 0.4


@register
class ModbusWriter(ModbusClientActor):
    """Host outside the approved change path writing setpoints outside their normal band."""

    type = "modbus.writer"

    def plan(self) -> None:
        plan, rng = self.plan_, self.rng
        host = self.hosts[0]
        target = rng.choice(plan.topology.select(self.param("targets")))
        profile = serving_profile(plan, target.id)
        unit = profile.unit_id
        lo_n, hi_n = (int(v) for v in self.span(self.param("writes", [2, 3])))
        candidates = [p for p in profile.table("holding") if p.writable and p.normal and p.name != "mode"]
        points = sorted(rng.sample(candidates, min(rng.randint(lo_n, hi_n), len(candidates))),
                        key=lambda p: p.address)
        rng.shuffle(points)
        factor_lo, factor_hi = DEVIATION[self.param("deviation", "moderate")]
        function_mode = self.param("function", "single")
        start_lo, start_hi = self.span(self.param("start", [0.3, 0.6]))
        # Short captures (--duration) must still contain every write: cap the spread at half
        # the capture. The shipped difficulty levels are unaffected (spread <= duration / 2).
        spread = min(float(self.param("spread", 120)), plan.duration * 0.5)
        t0 = plan.duration * rng.uniform(start_lo, start_hi)
        t0 = min(t0, max(plan.duration - spread - 60, plan.duration * 0.1))
        one_session = spread <= 180

        identity = target.device.identity
        discovery_action = None
        session = _SessionPlanner(self, host.id, target.id, unit, t0, rng)
        if self.param("discovery", False):
            discovery_action = session.add("modbus.identify", gap=(0.0, 0.05))
            # Tag enumeration: oversized reads are rejected before the real map size is found.
            session.read(3, 0, 64)
            session.read(3, 0, 32)
            session.read(3, 0, 16)
            session.read(3, 0, profile.size("holding"))
            session.read(4, 0, profile.size("input"))
            session.read(1, 0, profile.size("coils"))
            plan.event(discovery_action, self.id, "Device identification and register enumeration",
                       ["T0888", "T0861"], vendor=identity.get("VendorName"), product=identity.get("ProductCode"))
        if not one_session:
            session.close()

        write_times = sorted(rng.uniform(0, spread) for _ in points)
        direction_rng = rng.child("direction")  # separate stream: other draws stay unchanged
        writes = []
        for point, offset in zip(points, write_times):
            lo, hi = point.normal
            distance = (hi - lo) * rng.uniform(factor_lo, factor_hi)
            down = _push_down(point.name, direction_rng)
            if down and lo > 0:
                value = max(lo - distance, 0.0)  # 0 disables a low-alarm threshold entirely
            else:
                down = False
                value = hi + distance
            raw = point.encode(value)
            function = {"single": 6, "multiple": 16}.get(function_mode) or rng.choice((6, 16))
            if not one_session:
                session = _SessionPlanner(self, host.id, target.id, unit, t0 + 20 + offset, rng)
            action = session.write(function, point.address, [raw])
            session.read(3, point.address, 1)
            if not one_session:
                session.close()
            writes.append({"point": point.name, "table": "holding", "address": point.address,
                           "function": function, "raw": raw, "value": point.decode(raw), "unit": point.unit,
                           "normal": list(point.normal), "nominal": point.nominal,
                           "direction": "below" if down else "above",
                           "request": {"$action": action}})
            plan.event(action, self.id, f"Write {point.name} = {point.decode(raw)} {point.unit}".rstrip(),
                       ["T0855", "T0836"], function=function, address=point.address, raw=raw,
                       normal=list(point.normal))
        if one_session:
            session.close()

        affected = sorted({p.name for p in profile.points
                           if p.model and p.name not in {w["point"] for w in writes}
                           and {p.model.get("source"), p.model.get("b")} & {w["point"] for w in writes}})
        plan.facts[self.id] = {
            "source": host_ref(host.id),
            "target": host_ref(target.id),
            "unit_id": unit,
            "write_count": len(writes),
            "writes": writes,
            "register_writes": [w for w in writes if w["table"] == "holding"],
            "point_names": [w["point"] for w in writes],
            "values": {w["point"]: w["value"] for w in writes},
            "function_codes": sorted({w["function"] for w in writes}),
            "first_write": min((w["request"] for w in writes), key=lambda r: r["$action"].t),
            "last_write": max((w["request"] for w in writes), key=lambda r: r["$action"].t),
            "discovery": discovery_action is not None,
            "reported_identity": f"{identity.get('VendorName', '')} {identity.get('ProductCode', '')}".strip(),
            "affected_measurements": affected,
        }


@register
class ModbusScanner(ModbusClientActor):
    """Reconnaissance from a host outside the approved client path: a TCP sweep of the control
    subnet for port 502, then per PLC a device-identification read (function 43) and register
    enumeration (oversized reads rejected with illegal_data_address until the real map is found).
    No writes - this is discovery only (MITRE ATT&CK for ICS T0846, T0888, T0861)."""

    type = "modbus.scanner"

    def plan(self) -> None:
        plan, rng = self.plan_, self.rng
        host = self.hosts[0]
        targets = sorted(plan.topology.select(self.param("targets")), key=lambda h: h.id)
        sweep = plan.topology.select(self.param("sweep")) if self.param("sweep") else []
        start_lo, start_hi = self.span(self.param("start", [0.2, 0.5]))
        t = plan.duration * rng.uniform(start_lo, start_hi)
        scan_start = None

        # Port sweep: a SYN to port 502 on each swept host, ordered by address (the attacker walks
        # the subnet). Hosts that do not serve Modbus answer with a RST; the PLCs are probed below.
        for swept in sorted(sweep, key=lambda h: h.id):
            action = plan.add(t, self.id, host.id, "modbus.probe", target=swept.id)
            scan_start = scan_start or action
            t += rng.uniform(0.05, 0.4)

        identities, enumerated = [], []
        for target in targets:
            profile = serving_profile(plan, target.id)
            unit = profile.unit_id
            session = _SessionPlanner(self, host.id, target.id, unit, t, rng)
            ident = session.add("modbus.identify", gap=(0.01, 0.1))
            scan_start = scan_start or ident
            # Enumerate the map: the oversized read (125 registers) is rejected with
            # illegal_data_address before the real table sizes are read.
            session.read(3, 0, 125)
            for function, table in ((3, "holding"), (4, "input"), (1, "coils"), (2, "discrete")):
                size = profile.size(table)
                if size:
                    session.read(function, 0, size)
            session.close()
            identity = target.device.identity
            reported = f"{identity.get('VendorName', '')} {identity.get('ProductCode', '')}".strip()
            identities.append({"target": host_ref(target.id), "unit_id": unit,
                               "identity": reported, "identify": action_ref(ident)})
            enumerated.append(host_ref(target.id))
            t = session.t + rng.uniform(0.2, 1.0)
            plan.event(ident, self.id, f"Device identification and register enumeration of {target.id}",
                       ["T0846", "T0888", "T0861"], vendor=identity.get("VendorName"),
                       product=identity.get("ProductCode"))

        plan.facts[self.id] = {
            "source": host_ref(host.id),
            "targets": enumerated,
            "plc_count": len(enumerated),
            "swept": [host_ref(s.id) for s in sorted(sweep, key=lambda h: h.id)],
            "identities": identities,
            "reported_identities": sorted({i["identity"] for i in identities if i["identity"]}),
            "function_codes": [1, 2, 3, 4, 43],
            "scan_start": action_ref(scan_start) if scan_start else None,
        }
