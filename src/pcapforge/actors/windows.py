"""Background chatter of Windows hosts on their segment: link-local name resolution (LLMNR,
NBNS, mDNS), SSDP discovery and Computer Browser host announcements.

All of it is one-way: datagrams go to recording sinks that the composer turns into the
multicast group or the subnet broadcast address (see ``topology.SINKS``). Timing, ports and
payloads follow a Windows 10 capture:

* a name DNS cannot resolve is looked up in parallel over NBNS (three broadcasts from port
  137, 750 ms apart, same transaction ID), LLMNR (A and AAAA, each from its own ephemeral
  port and repeated once ~420 ms later with the same ID) and mDNS (``name.local`` from 5353);
* SSDPSRV searches for an Internet gateway device in three rounds 3 s apart;
* the Computer Browser announces the host to its domain every 12 minutes.

IP TTL / DF of these datagrams come from the stack profile (``link_local`` in devices.yaml).
"""

from __future__ import annotations

import socket

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.llmnr import LLMNRQuery
from scapy.layers.netbios import NBNSHeader, NBNSQueryRequest, NBTDatagram
from scapy.layers.smb import BRWS_HostAnnouncement, SMB_Header, SMBMailslot_Write

from pcapforge import ports
from pcapforge.actors import register
from pcapforge.actors.base import Actor
from pcapforge.scenario import ScenarioError
from pcapforge.topology import SINKS

SSDP_SEARCH = (b"M-SEARCH * HTTP/1.1\r\nHost: 239.255.255.250:1900\r\n"
               b"ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n"
               b'Man: "ssdp:discover"\r\nMX: 3\r\n\r\n')
SSDP_COPIES = (3, 3, 2)       # M-SEARCH copies in each round of one search, rounds 3 s apart
NBNS_TRIES = 3                # NetBT BcastNameQueryCount
NBNS_INTERVAL = 0.75          # NetBT BcastQueryTimeout (s)
LLMNR_RESEND = (0.41, 0.44)   # delay of the single LLMNR retransmission (s)
ANNOUNCE_PERIOD = 720.0       # browser announcement interval of a host that has been up a while
NB_WORKSTATION, NB_SERVER, NB_MASTER_BROWSER = 0x00, 0x20, 0x1D

# Default printer names: Brother "BRN" + MAC, HP JetDirect "NPI" + last three MAC bytes.
BROTHER_OUIS = ("001BA9", "008077", "30055C")


def nb_suffix(suffix: int) -> int:
    """Scapy's form of a NetBIOS name suffix byte (first-level encoding: two letters)."""
    return ((0x41 + (suffix >> 4)) << 8) | (0x41 + (suffix & 0x0F))


def nb_name(name: str) -> str:
    return name.upper()[:15]


@register
class WindowsChatter(Actor):
    """Link-local discovery and name-resolution noise of Windows hosts."""

    type = "windows.chatter"
    sinks = (("broadcast", ports.NBNS), ("broadcast", ports.NBDGM), ("llmnr", ports.LLMNR),
             ("mdns", ports.MDNS), ("ssdp", ports.SSDP))

    def plan(self) -> None:
        rate = float(self.param("rate", 1.0))
        lookups = self.span(self.param("lookups_per_hour", [4, 10]))
        searches = self.span(self.param("ssdp_per_hour", [1, 3]))
        unknown = self._unknown_names(self.rng.child("names"))
        self._exchanges = 0
        for host in self.hosts:
            if host.device.stack.name != "windows":
                raise ScenarioError(f"{self.type} needs Windows hosts; '{host.id}' runs "
                                    f"{host.device.stack.name}")
            rng = self.rng.child(host.id)
            names = [("wpad", NB_WORKSTATION)] + self._silent_site_names(host) + unknown
            self._plan_lookups(host, rng.child("lookups"), rng.uniform(*lookups) * rate / 3600.0, names)
            self._plan_searches(host, rng.child("ssdp"), rng.uniform(*searches) * rate / 3600.0)
            if host.device.browser is not None:
                self._plan_announcements(host, rng.child("browser"))

    # -- names ----------------------------------------------------------------------
    def _unknown_names(self, rng) -> list[tuple[str, int]]:
        """(name, NetBIOS suffix) nobody on the site answers for: typos, retired servers,
        printers that left the network."""
        topo = self.plan_.topology
        code = topo.site_code.upper()
        names: dict[str, int] = {}
        windows = [h for h in topo.hosts if h.device.stack.name == "windows"]
        for host in rng.sample(windows, min(2, len(windows))):
            stem = host.name.rpartition("-")[0] or host.name
            names[f"{stem}-{rng.choice(['00', '02', '03'])}"] = NB_SERVER  # retired twin
            names[host.name.replace("-", "")] = NB_SERVER                 # typed without dashes
        names[f"{rng.choice(['FS', 'NAS', 'FILESRV'])}-{code}-01"] = NB_SERVER
        names[f"{rng.choice(['SCADA', 'OPC', 'WSUS'])}-{code}-OLD"] = NB_SERVER
        names[f"PRN-{code}-{rng.randint(1, 4):02d}"] = NB_WORKSTATION
        names[f"NPI{rng.getrandbits(24):06X}"] = NB_WORKSTATION
        names[f"BRN{rng.choice(BROTHER_OUIS)}{rng.getrandbits(24):06X}"] = NB_WORKSTATION
        taken = {h.name.upper() for h in topo.hosts}
        return [(name, suffix) for name, suffix in names.items() if name.upper() not in taken]

    def _silent_site_names(self, querier) -> list[tuple[str, int]]:
        """Site hosts the querier may look up by short name that do not answer it: field
        devices and routers (no LLMNR/NetBIOS) and Windows hosts off its segment. Hosts that
        only take part in the incident are not part of anybody's routine."""
        topo = self.plan_.topology
        routine = {h.id for actor in self.plan_.actors if not actor.incident for h in actor.hosts}
        out = []
        for host in topo.hosts:
            if host is querier or not (host.router or host.id in routine):
                continue
            if host.device.stack.name == "windows" and topo.common_subnet(host, querier):
                continue  # it would answer
            out.append((host.name, NB_SERVER))
        return out

    # -- planning -------------------------------------------------------------------
    def _exchange(self) -> int:
        """New client socket for a query and its retransmissions."""
        self._exchanges += 1
        return self._exchanges

    def _plan_lookups(self, host, rng, rate: float, names: list[tuple[str, int]]) -> None:
        if rate <= 0:
            return
        plan = self.plan_
        habitual = rng.sample(names[1:], min(3, len(names) - 1))  # stale shortcuts, mapped drives
        txid = rng.randrange(65536)  # NetBT counts its transaction IDs up
        t = rng.expovariate(rate)
        while t < plan.duration - 2.0:
            roll = rng.random()
            pool = habitual if roll < 0.85 and habitual else names
            name, suffix = names[0] if roll < 0.4 else rng.choice(pool)
            if len(name) <= 15:
                txid = (txid + (1 if rng.random() < 0.7 else 2)) & 0xFFFF
                at = t
                for attempt in range(NBNS_TRIES):
                    plan.add(at, self.id, host.id, "nbns.query", name=nb_name(name), suffix=suffix,
                             txid=txid, resend=attempt > 0)
                    at += rng.uniform(NBNS_INTERVAL - 0.01, NBNS_INTERVAL + 0.02)
            sent = t + rng.uniform(0.0002, 0.0008)
            resent = sent + rng.uniform(*LLMNR_RESEND)
            queries = []
            for qtype in ("A", "AAAA"):
                query = {"name": name, "qtype": qtype, "txid": rng.randrange(65536), "exchange": self._exchange()}
                plan.add(sent, self.id, host.id, "llmnr.query", **query, resend=False, last=False)
                queries.append(query)
                sent += rng.uniform(0.0001, 0.0005)
            for query in reversed(queries):  # the AAAA query goes out first again
                plan.add(resent, self.id, host.id, "llmnr.query", **query, resend=True, last=True)
                resent += rng.uniform(0.0002, 0.0012)
            at = t + rng.uniform(0.0005, 0.002)
            for qtype in ("A", "AAAA"):
                plan.add(at, self.id, host.id, "mdns.query", name=f"{name}.local", qtype=qtype)
                at += rng.uniform(0.0001, 0.0004)
            t += max(3.0, rng.expovariate(rate))

    def _plan_searches(self, host, rng, rate: float) -> None:
        if rate <= 0:
            return
        plan = self.plan_
        t = rng.expovariate(rate)
        while t < plan.duration - 8.0:
            exchange = self._exchange()
            sends = []
            for round_index, copies in enumerate(SSDP_COPIES):
                start = t + round_index * 3.0 + rng.uniform(0.0, 0.02)
                offsets = (0.0, rng.uniform(0.0002, 0.006), rng.uniform(0.2, 0.21))
                sends += [start + offset for offset in offsets[:copies]]
            for index, at in enumerate(sends):
                plan.add(at, self.id, host.id, "ssdp.search", exchange=exchange, resend=index > 0,
                         last=index == len(sends) - 1)
            t += max(10.0, rng.expovariate(rate))

    def _plan_announcements(self, host, rng) -> None:
        plan = self.plan_
        browser = host.device.browser
        domain = nb_name(plan.topology.domain.split(".")[0])
        datagram_id = rng.randrange(65536)
        t = rng.uniform(0.0, ANNOUNCE_PERIOD)
        while t < plan.duration:
            datagram_id = (datagram_id + rng.randint(1, 4)) & 0xFFFF
            plan.add(t, self.id, host.id, "browser.announce", name=nb_name(host.name), domain=domain,
                     os_version=list(browser.os_version), server_type=browser.server_type,
                     period_ms=int(ANNOUNCE_PERIOD * 1000), datagram_id=datagram_id)
            t += ANNOUNCE_PERIOD + rng.uniform(0.0, 2.5)

    # -- recording ------------------------------------------------------------------
    def execute(self, action, rt) -> None:
        a = action.args
        source = rt.loopback(action.host)
        if action.op == "nbns.query":
            query = (NBNSHeader(NAME_TRN_ID=a["txid"], NM_FLAGS="RD+B", QDCOUNT=1)
                     / NBNSQueryRequest(QUESTION_NAME=a["name"], SUFFIX=nb_suffix(a["suffix"])))
            self._send(source, ports.NBNS, "broadcast", ports.NBNS, bytes(query))
        elif action.op == "llmnr.query":
            query = LLMNRQuery(id=a["txid"], qd=DNSQR(qname=a["name"], qtype=a["qtype"]))
            self._send_on_exchange(rt, source, a, "llmnr", ports.LLMNR, bytes(query))
        elif action.op == "mdns.query":
            query = DNS(id=0, rd=0, qd=DNSQR(qname=a["name"], qtype=a["qtype"]))
            self._send(source, ports.MDNS, "mdns", ports.MDNS, bytes(query))
        elif action.op == "ssdp.search":
            self._send_on_exchange(rt, source, a, "ssdp", ports.SSDP, SSDP_SEARCH)
        elif action.op == "browser.announce":
            major, minor = a["os_version"]
            announcement = BRWS_HostAnnouncement(
                UpdateCount=0, Periodicity=a["period_ms"], ServerName=a["name"].encode(),
                OSVersionMajor=major, OSVersionMinor=minor, ServerType=a["server_type"],
                BrowserConfigVersionMajor=15, BrowserConfigVersionMinor=1)
            # The datagram header carries the sender's (recording) address; the composer
            # rewrites it like every other address.
            datagram = (NBTDatagram(Type=0x11, Flags=2, ID=a["datagram_id"], SourceIP=source, SourcePort=138,
                                    SourceName=a["name"], SUFFIX1=nb_suffix(NB_SERVER),
                                    DestinationName=a["domain"], SUFFIX2=nb_suffix(NB_MASTER_BROWSER))
                        / SMB_Header(Command=0x25, Flags=0, Flags2=0)
                        / SMBMailslot_Write(Setup=[1, 0, 2], Name=b"\\MAILSLOT\\BROWSE",
                                            Buffer=[("Data", announcement)]))
            self._send(source, ports.NBDGM, "broadcast", ports.NBDGM, bytes(datagram))
        else:
            raise ValueError(f"unknown operation {action.op}")

    @staticmethod
    def _send(source: str, source_port: int, sink: str, port: int, payload: bytes) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.bind((source, source_port))
            sock.sendto(payload, (SINKS[sink].loopback, port))
        finally:
            sock.close()

    def _send_on_exchange(self, rt, source: str, a: dict, sink: str, port: int, payload: bytes) -> None:
        """Send from the exchange's socket so retransmissions keep the query's source port."""
        key = (self.id, a["exchange"])
        sock = rt.clients.get(key)
        if sock is None:
            sock = rt.clients[key] = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind((source, 0))
        sock.sendto(payload, (SINKS[sink].loopback, port))
        if a["last"]:
            rt.clients.pop(key).close()

    def close(self, rt) -> None:
        for key in [k for k in rt.clients if k[0] == self.id]:
            rt.clients.pop(key).close()
