"""Hosts, subnets and addressing.

Built in two layers:
* the *world* (which hosts exist, their device profile, loopback recording address) comes
  from the behaviour seed, because it influences what is recorded;
* *addressing* (IPs, MACs, hostnames' site code, domain) comes from the presentation seed
  and is only applied when composing the final capture.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

from pcapforge.profiles import Device, device
from pcapforge.rng import Rng
from pcapforge.scenario import ScenarioError, evaluate_when, resolve

LOOPBACK_NET = "127.77"
MARKER_SINK = f"{LOOPBACK_NET}.0.1"
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"


@dataclass(frozen=True)
class Sink:
    """Recording stand-in for a link-local multicast group or the subnet broadcast address.

    Hosts send one-way datagrams to the sink's loopback address; the composer delivers them
    to ``group`` (or, when ``group`` is None, to the directed broadcast of the sender's
    subnet) with the matching Ethernet group address. Routers do not forward them.
    """

    name: str
    loopback: str
    group: str | None

    @property
    def id(self) -> str:
        return f"sink:{self.name}"


SINKS = {s.name: s for s in (
    Sink("llmnr", f"{LOOPBACK_NET}.0.2", "224.0.0.252"),
    Sink("mdns", f"{LOOPBACK_NET}.0.3", "224.0.0.251"),
    Sink("ssdp", f"{LOOPBACK_NET}.0.4", "239.255.255.250"),
    Sink("broadcast", f"{LOOPBACK_NET}.0.5", None),
)}


def group_mac(ip: str) -> str:
    """Ethernet destination of an IPv4 multicast group (RFC 1112: 01:00:5e + low 23 bits)."""
    low = int(ipaddress.IPv4Address(ip)) & 0x7FFFFF
    return "01:00:5e:" + ":".join(f"{b:02x}" for b in low.to_bytes(3, "big"))


@dataclass
class Interface:
    subnet: str
    ip: str
    mac: str


@dataclass
class Host:
    id: str                 # instance id, e.g. "plc2"
    group: str              # scenario host id, e.g. "plc"
    index: int              # 1-based index inside the group
    device: Device
    loopback: str
    router: bool
    name_template: str
    subnets: list[str]
    name: str = ""
    interfaces: list[Interface] = field(default_factory=list)

    @property
    def ip(self) -> str:
        return self.interfaces[0].ip

    @property
    def mac(self) -> str:
        return self.interfaces[0].mac

    def interface_on(self, subnet: str) -> Interface | None:
        return next((i for i in self.interfaces if i.subnet == subnet), None)


@dataclass
class Subnet:
    id: str
    network: ipaddress.IPv4Network
    router: Host | None = None


class Topology:
    def __init__(self, scenario_doc: dict, vars_: dict, world_rng: Rng) -> None:
        topo = scenario_doc["topology"]
        ctx = {"vars": vars_}
        self.sensor: str = topo["sensor"]
        self.subnet_specs = {s["id"]: s for s in topo["subnets"]}
        self.subnets: dict[str, Subnet] = {}
        self.hosts: list[Host] = []
        self.groups: dict[str, list[Host]] = {}
        site = scenario_doc.get("site", {})
        # Names travel inside DNS payloads, so they belong to the recorded world.
        self.site_name: str = world_rng.choice(site.get("names", ["Plant"]))
        self.site_code: str = world_rng.choice(site.get("codes", ["site"]))
        slug = re.sub(r"[^a-z0-9]+", "", self.site_name.lower())
        self.domain: str = site.get("domain") or f"{slug}.local"
        loop_index = 10
        for spec in topo["hosts"]:
            if not evaluate_when(spec.get("when"), ctx):
                continue
            count = int(resolve(spec.get("count", 1), ctx))
            choices = spec["device"] if isinstance(spec["device"], list) else [spec["device"]]
            members = []
            for index in range(1, count + 1):
                host_id = spec["id"] if count == 1 else f"{spec['id']}{index}"
                host = Host(
                    id=host_id,
                    group=spec["id"],
                    index=index,
                    device=device(world_rng.choice(choices)),
                    loopback=f"{LOOPBACK_NET}.{loop_index // 250}.{loop_index % 250 + 2}",
                    router=spec.get("router", False),
                    name_template=spec.get("name", f"{spec['id']}-{{index:02d}}"),
                    subnets=list(spec.get("subnets", [spec.get("subnet")])),
                )
                loop_index += 1
                members.append(host)
                self.hosts.append(host)
            self.groups[spec["id"]] = members
        for host in self.hosts:
            host.name = host.name_template.format(
                code=self.site_code, CODE=self.site_code.upper(), index=host.index)
        self.by_id = {h.id: h for h in self.hosts}
        self.by_loopback = {h.loopback: h for h in self.hosts}
        self.addressed = False

    # -- references -----------------------------------------------------------------
    def select(self, ref: str | list[str]) -> list[Host]:
        refs = ref if isinstance(ref, list) else [ref]
        hosts: list[Host] = []
        for r in refs:
            if r in self.groups:
                hosts.extend(self.groups[r])
            elif r in self.by_id:
                hosts.append(self.by_id[r])
            else:
                raise ScenarioError(f"unknown host reference '{r}'")
        return hosts

    # -- addressing -----------------------------------------------------------------
    def assign_addresses(self, rng: Rng) -> None:
        used_networks: set[ipaddress.IPv4Network] = set()
        for sid, spec in self.subnet_specs.items():
            if "cidr" in spec:
                net = ipaddress.ip_network(spec["cidr"])
            else:
                net = self._pick_network(rng, ipaddress.ip_network(spec["pool"]), spec["prefix"], used_networks)
            used_networks.add(net)
            self.subnets[sid] = Subnet(sid, net)

        used_ips: dict[str, set[int]] = {sid: set() for sid in self.subnets}
        used_macs: set[str] = set()
        # Routers take the conventional first or last usable address.
        router_last = rng.random() < 0.3
        for host in self.hosts:
            if host.router:
                for sid in host.subnets:
                    net = self.subnets[sid].network
                    offset = net.num_addresses - 2 if router_last else 1
                    used_ips[sid].add(offset)
                    host.interfaces.append(Interface(sid, str(net[offset]), self._mac(rng, host, used_macs)))
                    self.subnets[sid].router = host
        for group, members in self.groups.items():
            if members[0].router:
                continue
            sid = members[0].subnets[0]
            net = self.subnets[sid].network
            size = net.num_addresses
            # Engineers allocate device groups as contiguous blocks.
            for _ in range(200):
                base = rng.randint(10, min(size - 2 - len(members), 240))
                block = set(range(base, base + len(members)))
                if not block & used_ips[sid]:
                    break
            else:
                raise ScenarioError(f"cannot place {len(members)} hosts of '{group}' in {net}")
            for host, offset in zip(members, sorted(block)):
                used_ips[sid].add(offset)
                host.interfaces.append(Interface(sid, str(net[offset]), self._mac(rng, host, used_macs)))
        self.addressed = True

    @staticmethod
    def _pick_network(rng: Rng, pool, prefix: int, used: set) -> ipaddress.IPv4Network:
        subnets_available = 2 ** (prefix - pool.prefixlen)
        for _ in range(500):
            idx = rng.randrange(1, subnets_available - 1)
            net = ipaddress.ip_network((int(pool.network_address) + idx * 2 ** (32 - prefix), prefix))
            # Avoid networks that look synthetic (x.0.0.0, x.255.y.0).
            octets = str(net.network_address).split(".")
            if "255" in octets[1:3] or (octets[1] == "0" and octets[2] == "0"):
                continue
            if net not in used:
                return net
        raise ScenarioError(f"cannot pick a /{prefix} from {pool}")

    @staticmethod
    def _mac(rng: Rng, host: Host, used: set[str]) -> str:
        while True:
            oui = rng.choice(host.device.ouis)
            mac = f"{oui}:{rng.randrange(256):02X}:{rng.randrange(256):02X}:{rng.randrange(256):02X}".lower()
            if mac not in used:
                used.add(mac)
                return mac

    # -- paths ----------------------------------------------------------------------
    def common_subnet(self, a: Host, b: Host) -> str | None:
        for sid in a.subnets:
            if sid in b.subnets:
                return sid
        return None

    def address_towards(self, host: Host, peer: Host | Sink) -> Interface:
        if isinstance(peer, Sink):
            # Link-local datagrams leave on the segment we look at, if the host is on it.
            return host.interface_on(self.sensor) or host.interfaces[0]
        shared = self.common_subnet(host, peer)
        return host.interface_on(shared) if shared else host.interfaces[0]

    def sink_address(self, sink: Sink, sender: Host) -> str:
        """Final destination IP of a datagram ``sender`` sends to ``sink``."""
        if sink.group is not None:
            return sink.group
        subnet = self.address_towards(sender, sink).subnet
        return str(self.subnets[subnet].network.broadcast_address)

    def visible(self, src: Host, dst: Host | Sink) -> bool:
        """Is a packet src->dst seen on the sensor subnet's SPAN port?"""
        if isinstance(dst, Sink):
            return self.sensor in src.subnets  # link-local: never routed
        if self.sensor in src.subnets and not src.router:
            return True
        if self.sensor in dst.subnets and not dst.router:
            return True
        if src.router or dst.router:
            # Traffic to/from the router itself is seen only on the sensor-side interface.
            return self.sensor in self.common_subnet_ids(src, dst)
        return False

    def common_subnet_ids(self, a: Host, b: Host) -> list[str]:
        return [s for s in a.subnets if s in b.subnets]

    def l2_view(self, src: Host, dst: Host | Sink) -> tuple[str, str, int]:
        """(src MAC, dst MAC, routed hops before the sensor) as observed at the sensor."""
        if isinstance(dst, Sink):
            dst_mac = BROADCAST_MAC if dst.group is None else group_mac(dst.group)
            return src.interface_on(self.sensor).mac, dst_mac, 0
        router = self.subnets[self.sensor].router
        sensor_side_src = self.sensor in src.subnets
        sensor_side_dst = self.sensor in dst.subnets
        if sensor_side_src:
            src_mac = src.interface_on(self.sensor).mac
        else:
            src_mac = router.interface_on(self.sensor).mac
        if sensor_side_dst:
            dst_mac = dst.interface_on(self.sensor).mac
        else:
            dst_mac = router.interface_on(self.sensor).mac
        hops = 0 if sensor_side_src else 1
        return src_mac, dst_mac, hops

    def describe(self) -> list[dict]:
        return [{
            "id": h.id,
            "role": h.group,
            "name": h.name,
            "fqdn": f"{h.name.lower()}.{self.domain}",
            "device": h.device.name,
            "vendor": h.device.vendor,
            "interfaces": [{"subnet": i.subnet, "ip": i.ip, "mac": i.mac} for i in h.interfaces],
        } for h in self.hosts]

    def describe_subnets(self) -> list[dict]:
        return [{
            "id": s.id,
            "cidr": str(s.network),
            "gateway": s.router.interface_on(s.id).ip if s.router else None,
            "sensor": s.id == self.sensor,
        } for s in self.subnets.values()]
