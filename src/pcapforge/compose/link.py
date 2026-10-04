"""Layer 2 as seen on the sensor's SPAN port: Ethernet framing and ARP."""

from __future__ import annotations

import socket
import struct
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pcapforge.compose.retime import Network
    from pcapforge.plan import Plan
    from pcapforge.rng import Rng
    from pcapforge.topology import Host

BROADCAST = b"\xff" * 6
ETHERTYPE_IPV4 = b"\x08\x00"
ETHERTYPE_ARP = b"\x08\x06"
MIN_FRAME = 60  # Ethernet minimum without FCS: SPAN copies arrive padded
_ARP = struct.Struct("!HHBBH6s4s6s4s")


def mac_bytes(mac: str) -> bytes:
    return bytes.fromhex(mac.replace(":", ""))


def pad(frame: bytes) -> bytes:
    return frame + b"\x00" * (MIN_FRAME - len(frame)) if len(frame) < MIN_FRAME else frame


class Link:
    def __init__(self, plan: Plan, network: Network, rng: Rng) -> None:
        topology = plan.topology
        self.topology = topology
        self.sensor = topology.sensor
        self.router = topology.subnets[self.sensor].router
        self.network = network
        self.rng = rng
        self.start = plan.start_epoch
        self.mid_session = bool(plan.impairments.get("mid_session"))
        # ARP cache lifetime of each host (Windows / Linux reachable-time style aging).
        self.cache_s = {h.id: rng.uniform(30.0, 120.0) for h in topology.hosts}
        self.last_contact: dict[tuple[str, str], float] = {}
        self._views: dict[tuple[str, str], tuple[bytes, int] | None] = {}

    def view(self, src: Host, dst: Host) -> tuple[bytes, int] | None:
        """(Ethernet header, routed hops) of src -> dst at the sensor, or None if not seen."""
        key = (src.id, dst.id)
        if key not in self._views:
            if self.topology.visible(src, dst):
                src_mac, dst_mac, hops = self.topology.l2_view(src, dst)
                self._views[key] = (mac_bytes(dst_mac) + mac_bytes(src_mac) + ETHERTYPE_IPV4, hops)
            else:
                self._views[key] = None
        return self._views[key]

    def _neighbour(self, host: Host) -> Host:
        """The station on the sensor segment that sends / receives on behalf of ``host``."""
        return host if self.sensor in host.subnets else self.router

    def arp_before(self, t: float, src: Host, dst: Host) -> list[tuple[float, bytes]]:
        """ARP exchange the L2 sender needs before a frame at ``t`` (empty if cached)."""
        sender, target = self._neighbour(src), self._neighbour(dst)
        key = (sender.id, target.id) if sender.id < target.id else (target.id, sender.id)
        last = self.last_contact.get(key)
        if last is None and self.mid_session:
            last = self.start  # capture starts mid-session: caches are warm
        self.last_contact[key] = t
        if last is not None and t - last <= self.cache_s[sender.id]:
            return []
        rng = self.rng
        s_if = sender.interface_on(self.sensor)
        t_if = target.interface_on(self.sensor)
        s_mac, t_mac = mac_bytes(s_if.mac), mac_bytes(t_if.mac)
        s_ip, t_ip = socket.inet_aton(s_if.ip), socket.inet_aton(t_if.ip)
        reply_t = t - rng.uniform(20e-6, 80e-6)
        request_t = reply_t - self.network.round_trip(target, rng) - rng.uniform(40e-6, 250e-6)
        request = BROADCAST + s_mac + ETHERTYPE_ARP + _ARP.pack(
            1, 0x0800, 6, 4, 1, s_mac, s_ip, b"\x00" * 6, t_ip)
        reply = s_mac + t_mac + ETHERTYPE_ARP + _ARP.pack(
            1, 0x0800, 6, 4, 2, t_mac, t_ip, s_mac, s_ip)
        return [(request_t, pad(request)), (reply_t, pad(reply))]
