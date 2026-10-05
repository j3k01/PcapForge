"""Link-local IPv6 of hosts whose stack has it on (``ipv6`` in devices.yaml), with the
scenario var ``ipv6``: what the sensor sees of it on its segment.

* every such host on the sensor subnet gets a link-local address with a randomized
  interface identifier (Windows default) drawn from the presentation seed;
* when the host first shows up (or when its IPv6 interface comes up, ``up`` of its DHCPv6
  actions), the interface start is synthesized like ARP: an MLDv2 report joining the
  solicited-node group from ``::``, the DAD Neighbor Solicitation, and once the address is
  usable MLDv2 reports for the joined groups and the Router Solicitations;
* datagrams to a sink with an IPv6 group (LLMNR, mDNS, DHCPv6) are sent over IPv6 as well
  (or only, for DHCPv6): same payload, IPv6 + UDP header with the IPv6 pseudo-header checksum,
  Ethernet 33:33 group address. LLMNR uses its own socket (port) per query and family.

There are no IPv6 routers or unicast IPv6 conversations on the modelled segments, so there are
no Router Advertisements and no address-resolution Neighbor Solicitations.
"""

from __future__ import annotations

import ipaddress
import struct
from typing import TYPE_CHECKING

from pcapforge import ports
from pcapforge.compose.headers import checksum
from pcapforge.compose.link import mac_bytes, pad
from pcapforge.topology import Sink, group6_mac

if TYPE_CHECKING:
    from pcapforge.compose.headers import Headers
    from pcapforge.compose.packets import Flow, Packet
    from pcapforge.plan import Plan
    from pcapforge.rng import Rng
    from pcapforge.topology import Host

ETHERTYPE_IPV6 = b"\x86\xdd"
UNSPECIFIED = bytes(16)
LINK_LOCAL = bytes.fromhex("fe80000000000000")
ALL_ROUTERS = "ff02::2"
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
    def __init__(self, plan: Plan, headers: Headers, rng: Rng) -> None:
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
        self.mac = {h.id: mac_bytes(h.interface_on(topology.sensor).mac) for h in topology.hosts
                    if h.id in self.address}
        self.up: dict[str, float] = {}
        for action in plan.actions:
            if action.op == "dhcpv6.solicit" and action.host not in self.up:
                self.up[action.host] = self.start + action.args["up"]
        self.valid: dict[str, float] = {}  # host -> when its link-local address is usable
        self.sockets: dict[Flow, int] = {}  # IPv4 query socket -> source port of its IPv6 twin

    def _frame(self, host: Host, group: str, packet: bytes) -> bytes:
        return pad(mac_bytes(group6_mac(group)) + self.mac[host.id] + ETHERTYPE_IPV6 + packet)

    # -- interface start ----------------------------------------------------------------
    def start_before(self, t: float, host: Host) -> list[tuple[float, bytes]]:
        """Interface start of ``host`` if this frame at ``t`` is its first appearance."""
        if host.id not in self.address or host.id in self.valid:
            return []
        rng = self.rng
        stack = host.device.stack.ipv6
        own = self.address[host.id]
        node_group = solicited_node(own)
        at = min(t, self.up.get(host.id, t))
        frames = [(at, self._mld(host, UNSPECIFIED, [node_group]))]
        dad = at + rng.uniform(*DAD_DELAY)
        ns = struct.pack("!BBHI16s", 135, 0, 0, 0, own)
        frames.append((dad, self._icmp(host, UNSPECIFIED, node_group, ND_HOP_LIMIT, ns)))
        valid = self.valid[host.id] = dad + DAD_S
        groups = [node_group] + [ipaddress.IPv6Address(g).packed for g in stack.groups]
        report = valid + rng.uniform(0.0005, 0.003)
        frames.append((report, self._mld(host, own, groups)))
        frames.append((report + rng.uniform(*REPORT_REPEAT), self._mld(host, own, groups)))
        rs = struct.pack("!BBHI", 133, 0, 0, 0) + b"\x01\x01" + self.mac[host.id]
        when = valid + rng.uniform(*RS_DELAY)
        for _ in range(stack.router_solicitations):
            frames.append((when, self._icmp(host, own, ipaddress.IPv6Address(ALL_ROUTERS).packed, ND_HOP_LIMIT, rs)))
            when += stack.rs_interval_s * rng.uniform(0.98, 1.02)
        return frames

    def _icmp(self, host: Host, src: bytes, dst: bytes, hop: int, message: bytes) -> bytes:
        body = _with_checksum(src, dst, ICMPV6, message, 2)
        group = str(ipaddress.IPv6Address(dst))
        return self._frame(host, group, _ip6(src, dst, hop, ICMPV6, body))

    def _mld(self, host: Host, src: bytes, groups: list[bytes]) -> bytes:
        dst = ipaddress.IPv6Address(MLDV2_ROUTERS).packed
        records = b"".join(struct.pack("!BBH16s", CHANGE_TO_EXCLUDE, 0, 0, g) for g in groups)
        report = _with_checksum(src, dst, ICMPV6, struct.pack("!BBHHH", 143, 0, 0, 0, len(groups)) + records, 2)
        return self._frame(host, MLDV2_ROUTERS, _ip6(src, dst, MLD_HOP_LIMIT, HOP_BY_HOP, ROUTER_ALERT + report))

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
            sport = self.sockets.get(flow)
            if sport is None:
                sport = self.sockets[flow] = self.headers.ephemeral(host, self.rng)
        dport = ports.WELL_KNOWN.get(flow.server_port, flow.server_port)
        payload = p.payload
        if flow.server_port == ports.DHCPV6_SERVER:
            payload = rewrite_duid_mac(payload, self.mac[host.id])
        src, dst = self.address[host.id], ipaddress.IPv6Address(sink.group6).packed
        udp = _with_checksum(src, dst, UDP, struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload, 6)
        hop = host.device.stack.ipv6.multicast_hop_limit.get(sink.group6, 1)
        return t, self._frame(host, sink.group6, _ip6(src, dst, hop, UDP, udp))
