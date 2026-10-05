"""DHCPv4 on the wire: how recorded exchanges are delivered and what a client does with a new lease.

The recording carries every DHCP exchange as unicast between the client's and the server's
loopback addresses (see ``actors/dhcp.py``). The composer

* writes the final topology into the payload: recording addresses in ciaddr / yiaddr / siaddr /
  giaddr and in the address options (router, DNS, NTP, requested address, server identifier,
  ...) become the final addresses, ``chaddr`` and an Ethernet client identifier the client's MAC;
* delivers each message as RFC 2131 (4.1, 4.4.4) prescribes: a client without an address
  (ciaddr 0) sends from 0.0.0.0 to 255.255.255.255, a DHCPINFORM goes to 255.255.255.255 from
  the client's address; the server answers a client without an address on 255.255.255.255
  when the client set the broadcast flag and otherwise unicast to yiaddr / chaddr without ARP;
  renewals, releases and answers to a client that has an address are ordinary unicast. Limited
  broadcasts carry ff:ff:ff:ff:ff:ff, are never routed and use the stack's link-local TTL / DF;
* adds the address conflict detection of a client that just got its lease (ACK to a client
  without an address): ARP probes from 0.0.0.0 for the address, then ARP announcements
  (RFC 5227 timing for dhcpcd; Windows probes DadTransmits = 3 times DadRetransmitTime = 1 s
  apart and announces once when detection ends).
"""

from __future__ import annotations

import socket
from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable

from pcapforge import ports
from pcapforge.actors.dhcp import ACK, BROADCAST_FLAG, CLIENT_ID, INFORM, option_spans, parse
from pcapforge.compose.link import arp_request, mac_bytes
from pcapforge.compose.packets import UDP
from pcapforge.topology import LIMITED_BROADCAST, UNSPECIFIED, Sink

if TYPE_CHECKING:
    from pcapforge.compose.packets import Packet
    from pcapforge.plan import Plan
    from pcapforge.rng import Rng

UNSPECIFIED_BYTES = socket.inet_aton(UNSPECIFIED)
BROADCAST_BYTES = socket.inet_aton(LIMITED_BROADCAST)
JOIN_OP = "dhcp.discover"                  # a host that sends a DISCOVER joins during the capture
ADDRESS_FIELDS = (12, 16, 20, 24)          # ciaddr, yiaddr, siaddr, giaddr
# Options whose value is a list of IPv4 addresses (RFC 2132): router, time, name, DNS, log, LPR,
# NTP, NetBIOS name / datagram servers, requested address, server identifier.
ADDRESS_OPTIONS = frozenset({3, 4, 5, 6, 7, 9, 42, 44, 45, 50, 54})


@dataclass(frozen=True, slots=True)
class Delivery:
    """How a DHCP message deviates from ordinary unicast; the sender does no ARP for it."""

    source: bytes | None  # IPv4 source instead of the sender's address (0.0.0.0)
    broadcast: bool       # to 255.255.255.255 / ff:ff:ff:ff:ff:ff instead of the peer


@dataclass(frozen=True)
class Acd:
    """Address conflict detection of one DHCP client style after it got a lease."""

    wait: tuple[float, float]       # ACK -> first probe (s)
    probes: int
    interval: tuple[float, float]   # between probes (s)
    announce_wait: float            # last probe -> first announcement (s)
    announcements: int
    announce_interval: float


ACD = {
    "windows": Acd(wait=(0.0005, 0.004), probes=3, interval=(1.0, 1.0), announce_wait=1.0, announcements=1,
                   announce_interval=0.0),
    # RFC 5227: PROBE_WAIT 1 s, PROBE_NUM 3, PROBE_MIN 1 s, PROBE_MAX 2 s, ANNOUNCE_WAIT 2 s,
    # ANNOUNCE_NUM 2, ANNOUNCE_INTERVAL 2 s.
    "dhcpcd": Acd(wait=(0.0, 1.0), probes=3, interval=(1.0, 2.0), announce_wait=2.0, announcements=2,
                  announce_interval=2.0),
}
TIMER_JITTER = (0.995, 1.015)  # OS timer granularity on the fixed intervals


def is_dhcp(p: Packet) -> bool:
    flow = p.flow
    return flow.proto == UDP and flow.server_port == ports.DHCP_SERVER and not isinstance(flow.hosts[1], Sink)


def delivery(p: Packet) -> Delivery | None:
    """None for ordinary unicast (and every packet that is not DHCP)."""
    if not is_dhcp(p):
        return None
    message = parse(p.payload)
    if message is None:
        return None
    unaddressed = message.ciaddr == bytes(4)
    if p.side == 0:
        if unaddressed:
            return Delivery(UNSPECIFIED_BYTES, True)
        return Delivery(None, True) if message.type == INFORM else None
    if not unaddressed:
        return None  # RFC 2131 4.1: unicast to ciaddr
    return Delivery(None, bool(message.flags & BROADCAST_FLAG))


def rewrite(payload: bytes, remap: Callable[[bytes], bytes | None], mac: bytes) -> bytes:
    """Final addresses (``remap(recorded) -> final | None``) and the client's ``mac`` in a DHCP message."""
    if parse(payload) is None:
        return payload
    out = bytearray(payload)
    for offset in ADDRESS_FIELDS:
        new = remap(payload[offset:offset + 4])
        if new is not None:
            out[offset:offset + 4] = new
    if payload[1] == 1 and payload[2] == 6:  # Ethernet chaddr
        out[28:34] = mac
    for code, start, end in option_spans(payload):
        if code in ADDRESS_OPTIONS and (end - start) % 4 == 0:
            for at in range(start, end, 4):
                new = remap(payload[at:at + 4])
                if new is not None:
                    out[at:at + 4] = new
        elif code == CLIENT_ID and end - start == 7 and payload[start] == 1:
            out[start + 1:end] = mac
    return bytes(out)


class Dhcp:
    def __init__(self, plan: Plan, rng: Rng) -> None:
        self.topology = plan.topology
        self.rng = rng
        self.joining = frozenset(a.host for a in plan.actions if a.op == JOIN_OP)

    def after(self, p: Packet) -> list[tuple[float, bytes]]:
        """ARP probes and announcements of the client whose new lease ``p`` acknowledges."""
        if p.side != 1 or not is_dhcp(p):
            return []
        message = parse(p.payload)
        acd = ACD.get(p.action.args.get("style"))
        if message is None or message.type != ACK or message.ciaddr != bytes(4) or acd is None:
            return []
        host, server = p.flow.hosts
        iface = self.topology.address_towards(host, server)
        if iface.subnet != self.topology.sensor:
            return []
        rng = self.rng
        mac, address = mac_bytes(iface.mac), socket.inet_aton(iface.ip)
        frames = []
        t = p.time + rng.uniform(*acd.wait)
        for index in range(acd.probes):
            if index:
                t += rng.uniform(*acd.interval) * rng.uniform(*TIMER_JITTER)
            frames.append((t, arp_request(mac, UNSPECIFIED_BYTES, address)))
        t += acd.announce_wait * rng.uniform(*TIMER_JITTER)
        for index in range(acd.announcements):
            if index:
                t += acd.announce_interval * rng.uniform(*TIMER_JITTER)
            frames.append((t, arp_request(mac, address, address)))
        return frames
