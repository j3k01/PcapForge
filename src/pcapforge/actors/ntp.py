"""NTP (RFC 5905) client and server over real UDP sockets.

Timestamps are taken from the scenario's virtual clock, so they match the final capture.
"""

from __future__ import annotations

import asyncio
import socket
import struct

from pcapforge import ports
from pcapforge.actors import register
from pcapforge.actors.base import Actor
from pcapforge.plan import host_ref

NTP_EPOCH_OFFSET = 2208988800  # 1900-01-01 -> 1970-01-01
_PACKET = struct.Struct("!BBbbII4sQQQQ")


def ntp_timestamp(epoch: float) -> int:
    seconds = int(epoch)
    fraction = int((epoch - seconds) * 2**32) & 0xFFFFFFFF
    return ((seconds + NTP_EPOCH_OFFSET) << 32) | fraction


# Per-stack client behaviour: (version, poll exponent, precision, interval seconds).
CLIENT_STYLE = {
    "windows": (3, 10, -23, 1024.0),
    "linux": (4, 6, -24, 64.0),
    "vxworks": (4, 6, -18, 60.0),
}


class _NtpServerProtocol(asyncio.DatagramProtocol):
    def __init__(self, rt, start_epoch: float) -> None:
        self.rt = rt
        self.start_epoch = start_epoch

    def connection_made(self, transport) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, addr) -> None:
        if len(data) < _PACKET.size:
            return
        first, _stratum, poll, _prec, *_rest = _PACKET.unpack_from(data)
        version = (first >> 3) & 0x7
        client_transmit = _PACKET.unpack_from(data)[-1]
        now = self.start_epoch + self.rt.clock.t
        receive = ntp_timestamp(now + 0.000021)
        transmit = ntp_timestamp(now + 0.000048)
        reference = ntp_timestamp(now - 37.5)
        reply = _PACKET.pack(
            (0 << 6) | (version << 3) | 4, 1, poll, -23,
            0, 0x0A30,  # root delay, root dispersion (16.16)
            b"LOCL", reference, client_transmit, receive, transmit)
        self.transport.sendto(reply, addr)


@register
class NtpServer(Actor):
    """Domain controller acting as the site's stratum-1 time source (local clock)."""

    type = "ntp.server"
    is_server = True

    def plan(self) -> None:
        self.plan_.facts[self.id] = {"hosts": [host_ref(h.id) for h in self.hosts]}

    async def serve(self, rt) -> None:
        loop = asyncio.get_running_loop()
        for host in self.hosts:
            transport, _ = await loop.create_datagram_endpoint(
                lambda: _NtpServerProtocol(rt, self.plan_.start_epoch),
                local_addr=(host.loopback, ports.NTP))
            rt.transports.append(transport)


@register
class NtpClient(Actor):
    """Periodic time synchronisation; Windows hosts use port 123 as source like w32time."""

    type = "ntp.client"

    def plan(self) -> None:
        plan = self.plan_
        server = plan.topology.select(self.param("server"))[0]
        for host in self.hosts:
            rng = self.rng.child(host.id)
            version, poll, precision, interval = CLIENT_STYLE[host.device.stack.name]
            offset = rng.uniform(-0.08, 0.08)  # host clock error in seconds
            t = rng.uniform(0, min(interval, plan.duration))
            while t < plan.duration:
                plan.add(t, self.id, host.id, "ntp.query", server=server.id, version=version, poll=poll,
                         precision=precision, clock_offset=round(offset, 6),
                         fixed_port=host.device.stack.name == "windows")
                t += rng.jitter(interval, 0.05)
                offset += rng.uniform(-0.004, 0.004)

    def execute(self, action, rt) -> None:
        a = action.args
        now = self.plan_.start_epoch + rt.clock.t + a["clock_offset"]
        request = _PACKET.pack(
            (0 << 6) | (a["version"] << 3) | 3, 0, a["poll"], a["precision"],
            0, 0x00010000, b"\x00\x00\x00\x00", 0, 0, 0, ntp_timestamp(now))
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.bind((rt.loopback(action.host), ports.NTP if a["fixed_port"] else 0))
            sock.settimeout(2)
            sock.sendto(request, (rt.loopback(a["server"]), ports.NTP))
            sock.recvfrom(512)
        finally:
            sock.close()
