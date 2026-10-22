"""DNS client and an authoritative site DNS server over real UDP sockets.

Address records carry the *recording* (loopback) address of the host; the composer maps
them to the final topology like every IP header. On a dual-stack site (``dualstack``) the
server also answers AAAA for the dual-stack hosts, with the IPv4-mapped form of the loopback
address (``::ffff:127.77.x.y``); the composer writes the host's global address there.
"""

from __future__ import annotations

import asyncio
import base64
import socket

from scapy.layers.dns import DNS, DNSQR, DNSRR, DNSRRSRV

from pcapforge import dualstack, ports
from pcapforge.actors import register
from pcapforge.actors.base import Actor
from pcapforge.plan import action_ref, host_ref
from pcapforge.rng import label_bytes

EXTERNAL_NAMES = [
    "time.windows.com", "www.msftconnecttest.com", "ctldl.windowsupdate.com",
    "settings-win.data.microsoft.com", "v10.events.data.microsoft.com", "login.live.com",
]
QTYPES = {"A": 1, "SRV": 33, "AAAA": 28}


def zone_records(topology) -> dict[str, str]:
    """FQDN -> host id for every named host of the site and its aliases. An alias that already
    contains a dot is a full FQDN (e.g. a fictional external domain this host answers for); a bare
    label becomes ``<label>.<site domain>``."""
    zone = {f"{h.name.lower()}.{topology.domain}": h.id for h in topology.hosts}
    for h in topology.hosts:
        for a in h.aliases:
            alias = a.lower()
            zone[alias if "." in alias else f"{alias}.{topology.domain}"] = h.id
    return zone


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
        self.dual = dualstack.hosts(rt.plan)

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
        in_zone = qname in self.zone
        authoritative = qname.endswith(self.domain)
        if authoritative:
            reply.aa = 1  # the site zone; a fictional external FQDN this host answers for is non-authoritative
        if authoritative or in_zone:
            if question.qtype == QTYPES["A"] and in_zone:
                host = self.topology.by_id[self.zone[qname]]
                reply.an = DNSRR(rrname=question.qname, type="A", ttl=1200, rdata=host.loopback)
            elif question.qtype == QTYPES["SRV"] and qname.startswith("_ldap._tcp.dc._msdcs."):
                reply.an = DNSRRSRV(rrname=question.qname, ttl=600, priority=0, weight=100, port=389,
                                    target=self.dc_fqdn + ".")
            elif question.qtype == QTYPES["AAAA"] and self.zone.get(qname) in self.dual:
                host = self.topology.by_id[self.zone[qname]]
                reply.an = DNSRR(rrname=question.qname, type="AAAA", ttl=1200, rdata=f"::ffff:{host.loopback}")
            elif in_zone:
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
        internal = sorted(n for n in zone_records(topo) if n.endswith(topo.domain))
        for host in self.hosts:
            rng = self.rng.child(host.id)
            rate = rng.uniform(lo, hi) / 3600.0
            names = [(n, "A") for n in internal if not n.startswith(host.name.lower() + ".")]
            names += [(f"_ldap._tcp.dc._msdcs.{topo.domain}", "SRV"), (f"wpad.{topo.domain}", "A")]
            names += [(n, "A") for n in EXTERNAL_NAMES]
            begin, end = self.connected(host)
            t = begin + rng.expovariate(rate)
            while t < end:
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


QTYPE_CODES = {"A": 1, "NS": 2, "CNAME": 5, "NULL": 10, "TXT": 16, "AAAA": 28, "SRV": 33}


def _b32_label(data: bytes) -> str:
    """Lower-case base32 of ``data`` with the padding stripped (a DNS-safe opaque label)."""
    return base64.b32encode(data).decode("ascii").rstrip("=").lower()


@register
class DnsTunnelClient(Actor):
    """Benign equivalent of DNS-based data transfer / tunnelling (MITRE ATT&CK T1048.003, T1071.004).

    One office PC sends a run of queries whose leading label carries base32-encoded chunks of an
    opaque fake payload (``rng.label_bytes``) under a single fictional parent domain, all through the
    site resolver (the DC). The resolver forwards them to the outside like every other external name
    on this isolated network and answers SERVFAIL - no bytes ever leave the loopback range. Only the
    *observable pattern* is produced: long, high-entropy labels sent at volume to one parent, the way
    a real exfiltration tool would look on the wire. The difficulty knobs tune the rate (``interval``),
    the label length (``chunk`` bytes per query), the record type (``qtypes``) and whether the run is
    interleaved with ordinary lookups (``interleave``, the low-and-slow variant).
    """

    type = "dns.tunnel"

    def plan(self) -> None:
        plan, rng = self.plan_, self.rng
        host = self.hosts[0]
        server = plan.topology.select(self.param("server"))[0]
        parent = str(self.param("domain", "telemetry-sync.net")).lower()
        chunk = int(self.param("chunk", 30))
        total_bytes = int(self.param("bytes", 1500))
        qtypes = [str(q).upper() for q in self.param("qtypes", ["TXT"])]
        interleave = bool(self.param("interleave", False))
        lo_gap, hi_gap = self.span(self.param("interval", [1.0, 3.0]))
        start_lo, start_hi = self.span(self.param("start", [0.3, 0.5]))

        begin, end = self.connected(host)
        payload = label_bytes(f"{plan.seed}/{self.id}/{host.id}/{parent}", total_bytes)
        internal = sorted(zone_records(plan.topology))
        label_len = len(_b32_label(bytes(chunk)))
        count = total_bytes // chunk

        t = begin + (end - begin) * rng.uniform(start_lo, start_hi)
        first = None
        queries: list[dict] = []
        bytes_total = 0
        qtypes_used: set[str] = set()
        for i in range(count):
            if t >= end:
                break
            piece = payload[i * chunk:(i + 1) * chunk]
            name = f"{_b32_label(piece)}.{parent}"
            qtype = qtypes[i % len(qtypes)]
            action = plan.add(t, self.id, host.id, "dns.query", server=server.id, name=name,
                              qtype=qtype, txid=rng.randrange(1, 65536))
            first = first or action
            qtypes_used.add(qtype)
            bytes_total += len(piece)
            queries.append({"request": action_ref(action), "bytes": len(piece), "qtype": qtype})
            # Low-and-slow runs hide the encoded queries among the host's ordinary name lookups.
            if interleave and internal and rng.random() < 0.5:
                plan.add(t + rng.uniform(0.01, 0.1), self.id, host.id, "dns.query", server=server.id,
                         name=rng.choice(internal), qtype="A", txid=rng.randrange(1, 65536))
            t += rng.uniform(lo_gap, hi_gap)

        if first is not None:
            plan.event(first, self.id, f"DNS tunnelling: {len(queries)} encoded labels under {parent}",
                       ["T1048.003", "T1071.004"], host=host.id, domain=parent, bytes_sent=bytes_total)
        codes = sorted({QTYPE_CODES[q] for q in qtypes_used})
        plan.facts[self.id] = {
            "source": host_ref(host.id),
            "server": host_ref(server.id),
            "domain": parent,
            "qtypes": sorted(qtypes_used),
            "qtype_codes": codes,
            "qtype_filter": ", ".join(str(c) for c in codes),
            "query_count": len(queries),
            "bytes_total": bytes_total,
            "label_len": label_len,
            "first_query": action_ref(first) if first is not None else None,
            "queries": queries,
        }

    def execute(self, action, rt) -> None:
        a = action.args
        query_server(rt, action.host, a["server"], a["name"], a["qtype"], a["txid"])
