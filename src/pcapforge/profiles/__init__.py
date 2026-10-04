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
    )


def device_names() -> list[str]:
    return sorted(_devices_doc()["devices"])


@cache
def process_doc(name: str) -> dict:
    path = PROFILE_DIR / "processes" / f"{name}.yaml"
    if not path.is_file():
        raise KeyError(f"unknown process profile '{name}'")
    return yaml.safe_load(path.read_text(encoding="utf-8"))
