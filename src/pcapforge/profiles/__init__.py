"""Device, network-stack and physical-process profiles shipped with pcapforge."""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import cache
from pathlib import Path

import yaml

PROFILE_DIR = Path(__file__).parent


@dataclass(frozen=True)
class DelayedAck:
    probability: float
    min_ms: float
    max_ms: float


@dataclass(frozen=True)
class Rto:
    min_ms: float
    plus_rtt: bool  # Linux style: smoothed RTT + rto_min; otherwise max(rto_min, ...) ~ rto_min


@dataclass(frozen=True)
class LinkLocal:
    """IP header of datagrams to link-local multicast groups and the subnet broadcast."""

    df: bool
    ttl: dict[str, int]  # per multicast group; other destinations use the stack's ttl



@dataclass(frozen=True)
class Ipv6:
    """IPv6 of a stack that has it enabled (SLAAC)."""

    multicast_hop_limit: dict[str, int]  # per link-local group the host sends to
    groups: tuple[str, ...]              # groups joined besides the solicited-node group (MLDv2)
    router_solicitations: int            # Router Solicitations when the interface comes up
    rs_interval_s: float
    random_iid: bool = True              # randomized interface identifiers; False: modified EUI-64
    temporary: bool = True               # an RFC 8981 temporary address next to the stable one


@dataclass(frozen=True)
class Ipv6Router:
    """Router Advertisement configuration of a device that routes IPv6 (RFC 4861 section 6.2.1)."""

    min_rtr_adv_interval: float
    max_rtr_adv_interval: float
    router_lifetime: int
    cur_hop_limit: int        # 0: unspecified
    reachable_time_ms: int    # 0: unspecified
    retrans_timer_ms: int     # 0: unspecified
    mtu: int | None           # MTU option; None: not advertised
    managed: bool             # M flag
    other_config: bool        # O flag
    valid_lifetime: int       # Prefix Information option
    preferred_lifetime: int
    on_link: bool             # L flag
    autonomous: bool          # A flag
    rdnss_lifetime: int       # RDNSS option (RFC 8106) when the site advertises IPv6 DNS servers


@dataclass(frozen=True)
class Stack:
    name: str
    ttl: int
    df: bool
    ip_id: str  # "global" | "per_flow"
    mss: int
    syn_window: int
    window_scale: int | None
    window: int
    syn_options: tuple[str, ...]
    timestamps: bool
    ephemeral_ports: tuple[int, int]
    port_allocation: str  # "sequential" | "random"
    delayed_ack: DelayedAck
    rto: Rto
    link_local: LinkLocal
    initial_window: int  # congestion window after idle, in segments (RFC 6928 IW10 / RFC 3390)
    ipv6: Ipv6 | None = None  # None: IPv6 off (not modelled for this stack)
    syn_rto_s: float = 1.0           # first retransmission timeout of an unanswered SYN
    drops_unsolicited: bool = False  # host firewall drops SYNs to closed ports (no RST)


@dataclass(frozen=True)
class Browser:
    """Fields of the host's Computer Browser announcements (NetBIOS datagram service)."""

    os_version: tuple[int, int]  # (major, minor) as announced
    server_type: int             # SV_TYPE_* bit mask


@dataclass(frozen=True)
class Latency:
    median: float
    sigma: float


@dataclass(frozen=True)
class Device:
    name: str
    vendor: str
    ouis: tuple[str, ...]
    stack: Stack
    processing_ms: Latency
    forwarding_ms: Latency | None = None
    identity: dict[str, str] = field(default_factory=dict)
    browser: Browser | None = None  # None: the device sends no browser announcements
    link_mbps: int = 100            # NIC speed: spacing of back-to-back segments on the wire
    ipv6_router: Ipv6Router | None = None  # None: the device does not advertise itself as IPv6 router
    ipv6_enabled: bool = True       # devices.yaml `ipv6: false`: IPv6 off although the stack has it

    @property
    def ipv6(self) -> Ipv6 | None:
        """The device's IPv6 behaviour (None: no IPv6)."""
        return self.stack.ipv6 if self.ipv6_enabled else None


@cache
def _devices_doc() -> dict:
    return yaml.safe_load((PROFILE_DIR / "devices.yaml").read_text(encoding="utf-8"))


@cache
def stack(name: str) -> Stack:
    raw = _devices_doc()["stacks"][name]
    return Stack(
        name=name,
        ttl=raw["ttl"],
        df=raw["df"],
        ip_id=raw["ip_id"],
        mss=raw["mss"],
        syn_window=raw["syn_window"],
        window_scale=raw["window_scale"],
        window=raw["window"],
        syn_options=tuple(raw["syn_options"]),
        timestamps=raw["timestamps"],
        ephemeral_ports=tuple(raw["ephemeral_ports"]),
        port_allocation=raw["port_allocation"],
        delayed_ack=DelayedAck(**raw["delayed_ack"]),
        rto=Rto(**raw["rto"]),
        link_local=LinkLocal(df=raw.get("link_local", {}).get("df", raw["df"]),
                             ttl=dict(raw.get("link_local", {}).get("ttl", {}))),
        initial_window=raw["initial_window"],
        ipv6=Ipv6(multicast_hop_limit=dict(raw["ipv6"]["multicast_hop_limit"]), groups=tuple(raw["ipv6"]["groups"]),
                  router_solicitations=raw["ipv6"]["router_solicitations"],
                  rs_interval_s=raw["ipv6"]["rs_interval_s"],
                  random_iid=raw["ipv6"].get("random_iid", True),
                  temporary=raw["ipv6"].get("temporary", True)) if "ipv6" in raw else None,
        syn_rto_s=float(raw.get("syn_rto_s", 1.0)),
        drops_unsolicited=bool(raw.get("drops_unsolicited", False)),
    )


@cache
def device(name: str) -> Device:
    devices = _devices_doc()["devices"]
    if name not in devices:
        raise KeyError(f"unknown device profile '{name}' (known: {', '.join(sorted(devices))})")
    raw = devices[name]
    return Device(
        name=name,
        vendor=raw["vendor"],
        ouis=tuple(raw["ouis"]),
        stack=stack(raw["stack"]),
        processing_ms=Latency(**raw["processing_ms"]),
        forwarding_ms=Latency(**raw["forwarding_ms"]) if "forwarding_ms" in raw else None,
        identity=dict(raw.get("identity", {})),
        browser=Browser(tuple(raw["browser"]["os_version"]), raw["browser"]["server_type"])
        if "browser" in raw else None,
        link_mbps=raw["link_mbps"],
        ipv6_router=_ipv6_router(raw["ipv6_router"]) if "ipv6_router" in raw else None,
        ipv6_enabled=bool(raw.get("ipv6", True)),
    )


def _ipv6_router(raw: dict) -> Ipv6Router:
    prefix = raw["prefix"]
    return Ipv6Router(
        min_rtr_adv_interval=float(raw["min_rtr_adv_interval"]),
        max_rtr_adv_interval=float(raw["max_rtr_adv_interval"]),
        router_lifetime=raw["router_lifetime"],
        cur_hop_limit=raw["cur_hop_limit"],
        reachable_time_ms=raw["reachable_time_ms"],
        retrans_timer_ms=raw["retrans_timer_ms"],
        mtu=raw.get("mtu"),
        managed=bool(raw["managed"]),
        other_config=bool(raw["other_config"]),
        valid_lifetime=prefix["valid_lifetime"],
        preferred_lifetime=prefix["preferred_lifetime"],
        on_link=bool(prefix["on_link"]),
        autonomous=bool(prefix["autonomous"]),
        rdnss_lifetime=raw["rdnss_lifetime"],
    )


def device_names() -> list[str]:
    return sorted(_devices_doc()["devices"])


@cache
def process_doc(name: str) -> dict:
    path = PROFILE_DIR / "processes" / f"{name}.yaml"
    if not path.is_file():
        raise KeyError(f"unknown process profile '{name}'")
    return yaml.safe_load(path.read_text(encoding="utf-8"))
