"""Compose a recording into the final capture: realistic timing, addressing, stacks and L2.

Pipeline (see docs/DESIGN.md, "Composer spec"): flow/action assignment from the recording's
markers -> causal retime (TCP segmentation) -> visibility -> header rebuild -> Ethernet + ARP,
link-local IPv6 (ND, MLD, IPv6 copies of group datagrams) -> time-ordered merge -> SPAN
artefacts (duplicates, drops, VLAN tag) -> pcap/pcapng. All randomness comes from the
presentation seed, so the same plan, recording and seed always give a byte-identical file.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from pcapforge.compose.flows import assign_flows
from pcapforge.compose.headers import Headers
from pcapforge.compose.ipv6 import Ipv6
from pcapforge.compose.link import Link, pad
from pcapforge.compose.packets import FIN, SYN, ComposeError, Packet, read_ipv4
from pcapforge.compose.retime import Network, Retimer
from pcapforge.compose.span import Span
from pcapforge.compose.writer import WRITERS
from pcapforge.rng import Rng
from pcapforge.topology import Sink

if TYPE_CHECKING:
    from pcapforge.plan import Plan

__all__ = ["ComposeError", "ComposeResult", "compose"]


@dataclass
class ComposeResult:
    path: Path
    packets: int
    first_epoch: float
    last_epoch: float
    action_frames: dict[int, int]   # action id -> 1-based frame number of the action's request
    action_times: dict[int, float]  # action id -> epoch timestamp of that frame
    # Sensor clock error applied to every frame timestamp: offset (s) and drift (ppm).
    sensor_clock: dict[str, float] = field(default_factory=lambda: {"offset_s": 0.0, "drift_ppm": 0.0})


def compose(plan: Plan, recording: Path, out: Path, seed: str, fmt: str = "pcap") -> ComposeResult:
    writer = WRITERS.get(fmt)
    if writer is None:
        raise ValueError(f"unknown capture format '{fmt}' (known: {', '.join(WRITERS)})")
    root = Rng("pcapforge", plan.scenario.id, plan.difficulty, seed)
    topology = plan.topology
    if not topology.addressed:
        topology.assign_addresses(root.child("addressing"))
    present = root.child("present")

    packets = assign_flows(plan, read_ipv4(Path(recording)))
    network = Network(topology, present.child("latency"))
    timeline = Retimer(plan, network, present).run(packets)
    headers = Headers(plan, present.child("headers"))
    link = Link(plan, network, present.child("arp"))
    ipv6 = Ipv6(plan, headers, present.child("ipv6"))

    # (time, emission index, frame, packet or None for synthesized ARP / ND / MLD / IPv6 copies)
    frames: list[tuple[float, int, bytes, Packet | None]] = []
    for p in timeline:
        ipv4 = not isinstance(p.dst, Sink) or p.dst.ipv4
        view = link.view(p.src, p.dst)
        if view is None:
            if ipv4:
                headers.skip(p)
            continue
        eth, hops = view
        for t, frame in ipv6.start_before(p.time, p.src):
            frames.append((t, len(frames), frame, None))
        if ipv4:
            for t, arp in link.arp_before(p.time, p.src, p.dst):
                frames.append((t, len(frames), arp, None))
            frames.append((p.time, len(frames), pad(eth + headers.build(p, hops)), p))
        copy = ipv6.datagram(p)
        if copy is not None:
            frames.append((copy[0], len(frames), copy[1], None))
    if not frames:
        raise ComposeError("no packet of the recording is visible at the sensor")
    frames.sort(key=lambda f: (f[0], f[1]))
    span = Span(plan, present.child("span"))
    frames = span.apply(frames)

    micros = [round(f[0] * 1_000_000) for f in frames]
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    writer(out, zip(micros, (f[2] for f in frames)))

    requests: dict[int, int] = {}
    controls: dict[int, int] = {}  # SYN / FIN of actions without application data
    for number, (_t, _i, _data, p) in enumerate(frames, 1):
        # A segmented request is decoded (reassembled) in the frame of its last segment.
        if p is None or p.side != 0 or p.retransmission or p.more:
            continue
        if p.is_request:
            requests.setdefault(p.action.id, number)
        elif p.flags & (SYN | FIN):
            controls.setdefault(p.action.id, number)
    action_frames = dict(sorted({**controls, **requests}.items()))
    return ComposeResult(
        path=out,
        packets=len(frames),
        first_epoch=micros[0] / 1_000_000,
        last_epoch=micros[-1] / 1_000_000,
        action_frames=action_frames,
        action_times={aid: micros[n - 1] / 1_000_000 for aid, n in action_frames.items()},
        sensor_clock={"offset_s": span.clock_offset, "drift_ppm": round(span.clock_drift * 1e6, 3)},
    )
