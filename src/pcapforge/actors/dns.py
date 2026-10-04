"""DNS client and an authoritative site DNS server over real UDP sockets.

Address records carry the *recording* (loopback) address of the host; the composer maps
them to the final topology like every IP header.
"""

from __future__ import annotations

import asyncio
import socket

from scapy.layers.dns import DNS, DNSQR, DNSRR, DNSRRSRV

from pcapforge import ports
from pcapforge.actors import register
from pcapforge.actors.base import Actor
from pcapforge.plan import host_ref

EXTERNAL_NAMES = [
    "time.windows.com", "www.msftconnecttest.com", "ctldl.windowsupdate.com",
    "settings-win.data.microsoft.com", "v10.events.data.microsoft.com", "login.live.com",
]
QTYPES = {"A": 1, "SRV": 33, "AAAA": 28}


def zone_records(topology) -> dict[str, str]:
    """FQDN -> host id for every named host of the site."""
    return {f"{h.name.lower()}.{topology.domain}": h.id for h in topology.hosts}


def query_server(rt, host_id: str, server_id: str, name: str, qtype: str, txid: int) -> None:
    """Recursive query from ``host_id`` to the DNS server on ``server_id``; waits for the reply."""
    query = DNS(id=txid, rd=1, qd=DNSQR(qname=name, qtype=qtype))
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind((rt.loopback(host_id), 0))
        sock.settimeout(2)
        sock.sendto(bytes(query), (rt.loopback(server_id), ports.DNS))
        sock.recvfrom(1500)
    finally:
        sock.close()


class _DnsServerProtocol(asyncio.DatagramProtocol):
    def __init__(self, rt, topology, dc_id: str) -> None:
        self.rt = rt
        self.topology = topology
        self.domain = topology.domain
        self.zone = zone_records(topology)
        self.dc_fqdn = next(f for f, hid in self.zone.items() if hid == dc_id)

    def connection_made(self, transport) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, addr) -> None:
        try:
            query = DNS(data)
        except Exception:
            return
        if not query.qd:
            return
        question = query.qd[0]
        qname = question.qname.decode().rstrip(".").lower()
        reply = DNS(id=query.id, qr=1, opcode=0, rd=query.rd, ra=1, qd=question)
        if qname.endswith(self.domain):
            reply.aa = 1
            if question.qtype == QTYPES["A"] and qname in self.zone:
                host = self.topology.by_id[self.zone[qname]]
                reply.an = DNSRR(rrname=question.qname, type="A", ttl=1200, rdata=host.loopback)
            elif question.qtype == QTYPES["SRV"] and qname.startswith("_ldap._tcp.dc._msdcs."):
                reply.an = DNSRRSRV(rrname=question.qname, ttl=600, priority=0, weight=100, port=389,
                                    target=self.dc_fqdn + ".")
            elif qname in self.zone:
                pass  # NOERROR, no data (e.g. AAAA for an IPv4-only host)
            else:
                reply.rcode = 3  # NXDOMAIN
        else:
            reply.rcode = 2  # SERVFAIL: isolated network, no forwarders
        self.transport.sendto(bytes(reply), addr)


@register
class DnsServer(Actor):
    type = "dns.server"
    is_server = True

    def plan(self) -> None:
        self.plan_.facts[self.id] = {"hosts": [host_ref(h.id) for h in self.hosts],
                                     "domain": self.plan_.topology.domain}

    async def serve(self, rt) -> None:
        loop = asyncio.get_running_loop()
        for host in self.hosts:
            transport, _ = await loop.create_datagram_endpoint(
                lambda: _DnsServerProtocol(rt, self.plan_.topology, host.id),
                local_addr=(host.loopback, ports.DNS))
            rt.transports.append(transport)


@register
class DnsClient(Actor):
    """Background name resolution typical of Windows hosts in an AD-joined OT network."""

    type = "dns.client"

    def plan(self) -> None:
        plan = self.plan_
        topo = plan.topology
        server = topo.select(self.param("server"))[0]
        lo, hi = self.span(self.param("per_hour", [10, 30]))
        internal = sorted(zone_records(topo))
        for host in self.hosts:
            rng = self.rng.child(host.id)
            rate = rng.uniform(lo, hi) / 3600.0
            names = [(n, "A") for n in internal if not n.startswith(host.name.lower() + ".")]
            names += [(f"_ldap._tcp.dc._msdcs.{topo.domain}", "SRV"), (f"wpad.{topo.domain}", "A")]
            names += [(n, "A") for n in EXTERNAL_NAMES]
            t = rng.expovariate(rate)
            while t < plan.duration:
                name, qtype = rng.choice(names)
                plan.add(t, self.id, host.id, "dns.query", server=server.id, name=name, qtype=qtype,
                         txid=rng.randrange(1, 65536))
                if qtype == "A" and rng.random() < 0.5:
                    plan.add(t + rng.uniform(0.0002, 0.002), self.id, host.id, "dns.query", server=server.id,
                             name=name, qtype="AAAA", txid=rng.randrange(1, 65536))
                t += rng.expovariate(rate)

    def execute(self, action, rt) -> None:
        a = action.args
        query_server(rt, action.host, a["server"], a["name"], a["qtype"], a["txid"])
