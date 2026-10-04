"""Modbus/TCP actors backed by pymodbus."""

from __future__ import annotations

import asyncio

from pymodbus.client import ModbusTcpClient
from pymodbus.pdu.device import ModbusDeviceIdentification
from pymodbus.server import StartAsyncTcpServer
from pymodbus.simulator import DataType, SimData, SimDevice

from pcapforge import ports
from pcapforge.actors import register
from pcapforge.actors.base import Actor
from pcapforge.plan import host_ref
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
            rt.tasks.append(asyncio.create_task(
                StartAsyncTcpServer(device, address=(host.loopback, ports.MODBUS))))

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
            client = self._client(rt, action.host, a["target"])
            client.read_device_information(read_code=1, object_id=0, device_id=a["unit"])
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
