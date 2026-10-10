"""IPv6 of hosts whose stack has it on (``ipv6`` in devices.yaml) and of the sensor segment's
router, with the scenario var ``ipv6``: what the sensor sees of it on its segment.

Hosts (Windows):

* every such host on the sensor subnet gets a link-local address with a randomized
  interface identifier (Windows default) drawn from the presentation seed;
* when the host first shows up (or when its IPv6 interface comes up, ``up`` of its DHCPv6
  actions), the interface start is synthesized like ARP: an MLDv2 report joining the
  solicited-node group from ``::``, the DAD Neighbor Solicitation, and once the address is
  usable MLDv2 reports for the joined groups and up to three Router Solicitations, the
  later ones only while no Router Advertisement has arrived (RFC 4861 section 6.3.7);
* datagrams to a sink with an IPv6 group (LLMNR, mDNS, DHCPv6) are sent over IPv6 as well
  (or only, for DHCPv6): same payload, IPv6 + UDP header with the IPv6 pseudo-header checksum,
  Ethernet 33:33 group address. LLMNR uses its own socket (port) per query and family.
  Windows keeps soliciting DHCPv6 whatever the M / O flags of the RAs say.

Router: the sensor subnet's router, when its device has ``ipv6_router`` (FortiGate: FortiOS
defaults), advertises a ULA prefix ``fdXX:XXXX:XXXX:<subnet>::/64`` (RFC 4193: random 40-bit
global id from the presentation seed; the subnet id is the IPv4 subnet's third octet read as
hex digits, 10.20.37.0/24 -> ``:37::``) from its modified EUI-64 link-local address:

* Router Advertisements to ff02::1 with the Prefix Information (L, A), MTU and Source
  Link-Layer Address options. Unsolicited ones every uniform [MinRtrAdvInterval,
  MaxRtrAdvInterval] s; the router is up before the capture, so the first one falls at a
  random phase. Solicited ones go out 0-MAX_RA_DELAY_TIME (0.5 s) after a Router
  Solicitation, no sooner than MIN_DELAY_BETWEEN_RAS (3 s) after the previous multicast RA,
  and an RS is answered by the next unsolicited RA when that one comes first; the interval
  timer restarts after every multicast RA (RFC 4861 sections 6.2.4 and 6.2.6);
* a router that comes up inside the capture (``router_up``) first joins its solicited-node
  group from ``::``, runs DAD on its link-local address, joins all-routers (ff02::2) and
  spaces its first RAs at most MAX_INITIAL_RTR_ADVERT_INTERVAL (16 s) apart. In the shipped
  scenarios the firewall is always up before the capture starts.

SLAAC (RFC 4862, RFC 8981): a host whose link-local address is usable forms, from the first RA
it receives, a stable address with a randomized interface identifier (Windows default, fixed
per host and seed) and a temporary address in the advertised prefix. For each it joins the
solicited-node group (MLDv2 report from its link-local address, sent twice) and runs DAD (NS
from ``::``); the address is usable one RetransTimer (1 s) later.

Hosts never send from these addresses, as on a real IPv4 site whose router advertises only a
ULA prefix: the site DNS has no AAAA records, and Windows' default prefix policy (RFC 6724)
ranks IPv4 (``::ffff:0:0/96``, precedence 35) above ULA (``fc00::/7``, precedence 3), so
nothing goes out over the ULA addresses and the host does not use its default router either.

Unicast Neighbor Discovery (RFC 4861 section 7):

* right after RA handling the host resolves its new default router: NS from its link-local
  address to the router's solicited-node group with a Source Link-Layer Address option,
  answered by a unicast NA (Router, Solicited, Override, Target Link-Layer Address);
* the router knows the host from that NS (STALE), and answering it is a use: 5 s later
  (DELAY_FIRST_PROBE_TIME) it probes the host with a unicast NS (with its Source Link-Layer
  Address); the host answers with an NA (Solicited, Override, Target Link-Layer Address).
  With no traffic after that, neither side probes again.
"""

from __future__ import annotations

import ipaddress
import math
import struct
from typing import TYPE_CHECKING

from pcapforge import ports
from pcapforge.compose.headers import checksum
from pcapforge.compose.link import mac_bytes, pad
from pcapforge.topology import Sink, group6_mac

if TYPE_CHECKING:
    from pcapforge.compose.headers import Headers
    from pcapforge.compose.packets import Packet
    from pcapforge.plan import Plan
    from pcapforge.profiles import Ipv6Router
    from pcapforge.rng import Rng
    from pcapforge.topology import Host

ETHERTYPE_IPV6 = b"\x86\xdd"
UNSPECIFIED = bytes(16)
LINK_LOCAL = bytes.fromhex("fe80000000000000")
ALL_NODES = ipaddress.IPv6Address("ff02::1").packed
ALL_ROUTERS = ipaddress.IPv6Address("ff02::2").packed
MLDV2_ROUTERS = "ff02::16"
UDP, ICMPV6, HOP_BY_HOP = 17, 58, 0
ND_HOP_LIMIT = 255   # RFC 4861: receivers drop ND messages with another hop limit
MLD_HOP_LIMIT = 1    # RFC 3810
# Hop-by-hop header of MLD messages: next header ICMPv6, Router Alert (MLD), PadN.
ROUTER_ALERT = bytes((ICMPV6, 0, 5, 2, 0, 0, 1, 0))
CHANGE_TO_EXCLUDE = 4  # MLDv2 record type of a join
DAD_S = 1.0            # RetransTimer x DupAddrDetectTransmits (1)
DAD_DELAY = (0.0002, 0.05)
RS_DELAY = (0.001, 1.0)   # MAX_RTR_SOLICITATION_DELAY
REPORT_REPEAT = (0.2, 1.0)  # Unsolicited Report Interval: the report is sent twice
COPY_DELAY = (30e-6, 300e-6)  # IPv6 copy of a datagram after the IPv4 one
# RFC 4861 section 10 constants (router and node).
MAX_RA_DELAY_S = 0.5
MIN_DELAY_BETWEEN_RAS_S = 3.0
MAX_INITIAL_RTR_ADVERT_INTERVAL_S = 16.0
MAX_INITIAL_RTR_ADVERTISEMENTS = 3
DELAY_FIRST_PROBE_S = 5.0
TIMER_SLACK = (0.0, 0.004)     # kernel timer granularity
ND_REPLY = (60e-6, 400e-6)     # NS -> NA at the sensor (wire both ways + kernel)
RA_HANDLING = (0.0005, 0.005)  # RA -> the host's first SLAAC frame
TEMPORARY_AFTER = (0.0005, 0.03)  # stable address DAD -> temporary address
ROUTER_NEED = (0.002, 0.08)    # RA -> the host resolves its new default router
REPORT_DELAY = (0.0005, 0.003)  # DAD done -> MLDv2 report of the joined groups
# ICMPv6 Neighbor Discovery types, NA flags and option types.
RS, RA, NS, NA = 133, 134, 135, 136
NA_ROUTER, NA_SOLICITED, NA_OVERRIDE = 0x80, 0x40, 0x20
SLLA, TLLA, PREFIX_INFO, MTU_OPTION = 1, 2, 3, 5


def _ip6(src: bytes, dst: bytes, hop: int, next_header: int, payload: bytes) -> bytes:
    return struct.pack("!IHBB", 0x60000000, len(payload), next_header, hop) + src + dst + payload


def _with_checksum(src: bytes, dst: bytes, proto: int, l4: bytes, offset: int) -> bytes:
    pseudo = src + dst + struct.pack("!IxxxB", len(l4), proto)
    value = checksum(pseudo + l4)
    if proto == UDP and value == 0:
        value = 0xFFFF
    return l4[:offset] + value.to_bytes(2, "big") + l4[offset + 2:]


def solicited_node(address: bytes) -> bytes:
    return bytes.fromhex("ff0200000000000000000001ff") + address[13:]


def eui64(mac: bytes) -> bytes:
    """Modified EUI-64 interface identifier of a MAC address (RFC 4291 appendix A)."""
    return bytes((mac[0] ^ 0x02,)) + mac[1:3] + b"\xff\xfe" + mac[3:]


def ula_prefix(global_id: int, subnet_id: int) -> bytes:
    """First 64 bits of a RFC 4193 local IPv6 unicast prefix (fd00::/8, L = 1)."""
    return b"\xfd" + global_id.to_bytes(5, "big") + subnet_id.to_bytes(2, "big")


def router_advertisement(config: Ipv6Router, mac: bytes, prefix: bytes) -> bytes:
    """RA message (checksum 0) with Prefix Information, MTU and Source Link-Layer Address."""
    flags = (0x80 if config.managed else 0) | (0x40 if config.other_config else 0)
    message = struct.pack("!BBHBBHII", RA, 0, 0, config.cur_hop_limit, flags, config.router_lifetime,
                          config.reachable_time_ms, config.retrans_timer_ms)
    prefix_flags = (0x80 if config.on_link else 0) | (0x40 if config.autonomous else 0)
    message += struct.pack("!BBBBIII16s", PREFIX_INFO, 4, 64, prefix_flags, config.valid_lifetime,
                           config.preferred_lifetime, 0, prefix + bytes(8))
    if config.mtu:
        message += struct.pack("!BBHI", MTU_OPTION, 1, 0, config.mtu)
    return message + struct.pack("!BB6s", SLLA, 1, mac)


def neighbor_solicitation(target: bytes, mac: bytes | None = None) -> bytes:
    """NS message (checksum 0); ``mac``: Source Link-Layer Address option (not from ``::``)."""
    return struct.pack("!BBHI16s", NS, 0, 0, 0, target) + (struct.pack("!BB6s", SLLA, 1, mac) if mac else b"")


def neighbor_advertisement(target: bytes, flags: int, mac: bytes | None = None) -> bytes:
    """NA message (checksum 0); ``mac``: Target Link-Layer Address option."""
    return struct.pack("!BBHB3x16s", NA, 0, 0, flags, target) + (struct.pack("!BB6s", TLLA, 1, mac) if mac else b"")


def rewrite_duid_mac(payload: bytes, mac: bytes) -> bytes:
    """Write ``mac`` into the DUID-LLT / DUID-LL of a DHCPv6 client message's Client Identifier."""
    offset = 4  # msg-type + transaction id
    while offset + 4 <= len(payload):
        code, length = struct.unpack_from("!HH", payload, offset)
        if code == 1 and length >= 10:
            duid_type, hw_type = struct.unpack_from("!HH", payload, offset + 4)
            at = offset + 4 + {1: 8, 3: 4}.get(duid_type, length)
            if hw_type == 1 and at + 6 <= offset + 4 + length:
                return payload[:at] + mac + payload[at + 6:]
            return payload
        offset += 4 + length
    return payload


class Ipv6:
    def __init__(self, plan: Plan, headers: Headers, rng: Rng, router_up: float | None = None) -> None:
        """``router_up``: epoch at which the router's interface comes up inside the capture
        (None: it is up before the capture starts)."""
        topology = plan.topology
        self.start = plan.start_epoch
        self.headers = headers
        self.rng = rng
        self.address: dict[str, bytes] = {}
        if plan.vars.get("ipv6"):
            for host in topology.hosts:
                if host.device.stack.ipv6 is not None and topology.sensor in host.subnets and not host.router:
                    iid = rng.getrandbits(64) or 1
                    self.address[host.id] = LINK_LOCAL + iid.to_bytes(8, "big")
        self.hosts = {h.id: h for h in topology.hosts if h.id in self.address}
        self.mac = {hid: mac_bytes(h.interface_on(topology.sensor).mac) for hid, h in self.hosts.items()}
        self.up: dict[str, float] = {}
        for action in plan.actions:
            if action.op == "dhcpv6.solicit" and action.host not in self.up:
                self.up[action.host] = self.start + action.args["up"]
        self.valid: dict[str, float] = {}  # host -> when its link-local address is usable
        self.solicits: dict[str, list[float]] = {}  # host -> its Router Solicitations if no RA comes first
        self.router: Host | None = None
        router = topology.subnets[topology.sensor].router if self.address else None
        if router is not None and router.device.ipv6_router is not None:
            self.router = router
            self.router_mac = mac_bytes(router.interface_on(topology.sensor).mac)
            self.router_ll = LINK_LOCAL + eui64(self.router_mac)
            third_octet = topology.subnets[topology.sensor].network.network_address.packed[2]
            self.prefix = ula_prefix(rng.child("ula").getrandbits(40), int(str(third_octet), 16))
        self.router_up = router_up

    def _frame(self, src_mac: bytes, dst_mac: bytes, packet: bytes) -> bytes:
        return pad(dst_mac + src_mac + ETHERTYPE_IPV6 + packet)

    # -- interface start ----------------------------------------------------------------
    def start_before(self, t: float, host: Host) -> list[tuple[float, bytes]]:
        """Interface start of ``host`` if this frame at ``t`` is its first appearance."""
        if host.id not in self.address:
            return []
        if host.id in self.valid:
            return []
        rng = self.rng
        stack = host.device.stack.ipv6
        own, mac = self.address[host.id], self.mac[host.id]
        node_group = solicited_node(own)
        at = min(t, self.up.get(host.id, t))
        frames = [(at, self._mld(mac, UNSPECIFIED, [node_group]))]
        dad = at + rng.uniform(*DAD_DELAY)
        frames.append((dad, self._icmp(mac, UNSPECIFIED, node_group, neighbor_solicitation(own))))
        valid = self.valid[host.id] = dad + DAD_S
        groups = [node_group] + [ipaddress.IPv6Address(g).packed for g in stack.groups]
        report = valid + rng.uniform(*REPORT_DELAY)
        frames.append((report, self._mld(mac, own, groups)))
        frames.append((report + rng.uniform(*REPORT_REPEAT), self._mld(mac, own, groups)))
        when = valid + rng.uniform(*RS_DELAY)
        solicits = self.solicits[host.id] = []
        for _ in range(stack.router_solicitations):
            solicits.append(when)
            when += stack.rs_interval_s * rng.uniform(0.98, 1.02)
        return frames

    def _icmp(self, src_mac: bytes, src: bytes, dst: bytes, message: bytes, dst_mac: bytes | None = None) -> bytes:
        """ND message (hop limit 255) to a multicast group, or unicast to ``dst_mac``."""
        body = _with_checksum(src, dst, ICMPV6, message, 2)
        if dst_mac is None:
            dst_mac = mac_bytes(group6_mac(str(ipaddress.IPv6Address(dst))))
        return self._frame(src_mac, dst_mac, _ip6(src, dst, ND_HOP_LIMIT, ICMPV6, body))

    def _mld(self, src_mac: bytes, src: bytes, groups: list[bytes]) -> bytes:
        dst = ipaddress.IPv6Address(MLDV2_ROUTERS).packed
        records = b"".join(struct.pack("!BBH16s", CHANGE_TO_EXCLUDE, 0, 0, g) for g in groups)
        report = _with_checksum(src, dst, ICMPV6, struct.pack("!BBHHH", 143, 0, 0, 0, len(groups)) + records, 2)
        return self._frame(src_mac, mac_bytes(group6_mac(MLDV2_ROUTERS)),
                           _ip6(src, dst, MLD_HOP_LIMIT, HOP_BY_HOP, ROUTER_ALERT + report))

    def _rs(self, host_id: str) -> bytes:
        mac = self.mac[host_id]
        rs = struct.pack("!BBHI", RS, 0, 0, 0) + struct.pack("!BB6s", SLLA, 1, mac)
        return self._icmp(mac, self.address[host_id], ALL_ROUTERS, rs)

    # -- router, SLAAC and unicast ND -----------------------------------------------------
    def finish(self, first: float, last: float) -> list[tuple[float, bytes]]:
        """Frames that depend on the whole capture (``first`` .. ``last``): the hosts' Router
        Solicitations until an RA answers them, the router's RAs, SLAAC and unicast ND."""
        frames: list[tuple[float, bytes]] = []
        queue = sorted((t, hid) for hid, times in self.solicits.items() for t in times)
        if self.router is None:
            return [(t, self._rs(hid)) for t, hid in queue]
        config = self.router.device.ipv6_router
        rng = self.rng.child("router")
        lo, hi = config.min_rtr_adv_interval, config.max_rtr_adv_interval
        ra = self._icmp(self.router_mac, self.router_ll, ALL_NODES,
                        router_advertisement(config, self.router_mac, self.prefix))
        if self.router_up is None:
            router_valid, initial = -math.inf, 0
            next_ra = first + rng.uniform(0.0, rng.uniform(lo, hi))
        else:
            router_valid = self._router_start(self.router_up, rng, frames)
            initial = MAX_INITIAL_RTR_ADVERTISEMENTS
            next_ra = router_valid + rng.uniform(0.0, MAX_RA_DELAY_S)
        pending: float | None = None  # solicited RA
        last_ra = -math.inf
        configured: set[str] = set()
        index = 0
        while True:
            rs_t = queue[index][0] if index < len(queue) else math.inf
            ra_t = min(math.inf if pending is None else pending, next_ra if next_ra <= last else math.inf)
            if rs_t == ra_t == math.inf:
                break
            if rs_t < ra_t:
                index += 1
                host_id = queue[index - 1][1]
                if host_id in configured:
                    continue  # an RA arrived: no more solicitations
                frames.append((rs_t, self._rs(host_id)))
                if rs_t < router_valid or pending is not None:
                    continue  # router not up yet / the pending RA answers this RS too
                delay = rng.uniform(0.0, MAX_RA_DELAY_S)
                at = rs_t + delay if rs_t - last_ra >= MIN_DELAY_BETWEEN_RAS_S else \
                    last_ra + MIN_DELAY_BETWEEN_RAS_S + delay
                if at < next_ra:
                    pending = at
                continue
            frames.append((ra_t, ra))
            pending, last_ra = None, ra_t
            interval = rng.uniform(lo, hi)
            if initial:
                initial -= 1
                interval = min(interval, MAX_INITIAL_RTR_ADVERT_INTERVAL_S)
            next_ra = ra_t + interval
            for host_id in self.address:
                if host_id not in configured and self.valid.get(host_id, math.inf) <= ra_t:
                    configured.add(host_id)
                    self._configure(host_id, ra_t, frames)
        return frames

    def _router_start(self, at: float, rng: Rng, frames: list[tuple[float, bytes]]) -> float:
        """Interface start of the router at ``at``; returns when its link-local address is usable."""
        mac, own = self.router_mac, self.router_ll
        node_group = solicited_node(own)
        frames.append((at, self._mld(mac, UNSPECIFIED, [node_group])))
        dad = at + rng.uniform(*DAD_DELAY)
        frames.append((dad, self._icmp(mac, UNSPECIFIED, node_group, neighbor_solicitation(own))))
        valid = dad + DAD_S
        report = valid + rng.uniform(*REPORT_DELAY)
        frames.append((report, self._mld(mac, own, [ALL_ROUTERS, node_group])))
        frames.append((report + rng.uniform(*REPORT_REPEAT), self._mld(mac, own, [ALL_ROUTERS, node_group])))
        return valid

    def _configure(self, host_id: str, ra_t: float, frames: list[tuple[float, bytes]]) -> None:
        """What the host does with its first RA (at ``ra_t``): SLAAC, then ND with the router."""
        rng = self.rng.child("slaac").child(host_id)
        mac, own = self.mac[host_id], self.address[host_id]
        rmac, router = self.router_mac, self.router_ll
        joined = {solicited_node(own)}
        t = ra_t + rng.uniform(*RA_HANDLING)
        for _ in ("stable", "temporary"):
            address = self.prefix + (rng.getrandbits(64) or 1).to_bytes(8, "big")
            group = solicited_node(address)
            if group not in joined:
                joined.add(group)
                frames.append((t, self._mld(mac, own, [group])))
                frames.append((t + rng.uniform(*REPORT_REPEAT), self._mld(mac, own, [group])))
                t += rng.uniform(*DAD_DELAY)
            frames.append((t, self._icmp(mac, UNSPECIFIED, group, neighbor_solicitation(address))))
            t += rng.uniform(*TEMPORARY_AFTER)

        # Address resolution of the new default router.
        need = ra_t + rng.uniform(*ROUTER_NEED)
        frames.append((need, self._icmp(mac, own, solicited_node(router), neighbor_solicitation(router, mac))))
        confirmed = need + rng.uniform(*ND_REPLY)
        frames.append((confirmed, self._icmp(rmac, router, own, neighbor_advertisement(
            router, NA_ROUTER | NA_SOLICITED | NA_OVERRIDE, rmac), mac)))
        # The router's entry for the host was STALE (from the NS) when it answered: DELAY, then PROBE.
        probe = confirmed + DELAY_FIRST_PROBE_S + rng.uniform(*TIMER_SLACK)
        frames.append((probe, self._icmp(rmac, router, own, neighbor_solicitation(own, rmac), mac)))
        answered = probe + rng.uniform(*ND_REPLY)
        frames.append((answered, self._icmp(mac, own, router, neighbor_advertisement(
            own, NA_SOLICITED | NA_OVERRIDE, mac), rmac)))

    # -- datagrams ----------------------------------------------------------------------
    def datagram(self, p: Packet) -> tuple[float, bytes] | None:
        """The IPv6 datagram ``p`` (to a sink with an IPv6 group) also goes out as, if any."""
        sink, host = p.dst, p.src
        if not isinstance(sink, Sink) or sink.group6 is None or host.id not in self.address:
            return None
        t = p.time if not sink.ipv4 else p.time + self.rng.uniform(*COPY_DELAY)
        if t < self.valid.get(host.id, float("inf")):
            return None  # the address is not usable yet
        flow = p.flow
        sport = ports.WELL_KNOWN.get(flow.client_port)
        if sport is None:
            sport = flow.v6port
            if sport is None:
                sport = flow.v6port = self.headers.ephemeral(host, self.rng)
        dport = ports.WELL_KNOWN.get(flow.server_port, flow.server_port)
        payload = p.payload
        if flow.server_port == ports.DHCPV6_SERVER:
            payload = rewrite_duid_mac(payload, self.mac[host.id])
        src, dst = self.address[host.id], ipaddress.IPv6Address(sink.group6).packed
        udp = _with_checksum(src, dst, UDP, struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload, 6)
        hop = host.device.stack.ipv6.multicast_hop_limit.get(sink.group6, 1)
        return t, self._frame(self.mac[host.id], mac_bytes(group6_mac(sink.group6)), _ip6(src, dst, hop, UDP, udp))
