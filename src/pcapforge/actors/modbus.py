"""Modbus/TCP actors backed by pymodbus."""

from __future__ import annotations

import asyncio

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
