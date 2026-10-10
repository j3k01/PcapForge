"""Compose a recording into the final capture: realistic timing, addressing, stacks and L2.

Pipeline (see docs/DESIGN.md, "Composer spec"): flow/action assignment from the recording's
markers -> causal retime (TCP segmentation) -> host firewall (filtered vs closed ports) ->
EtherNet/IP class 1 cyclic I/O after each recorded first exchange -> visibility -> header rebuild ->
Ethernet + ARP, DHCPv4 delivery (broadcasts, address conflict detection), IPv6 (ND, MLD, IPv6
copies of group datagrams; Router Advertisements, SLAAC and unicast ND once the whole capture is
known) -> time-ordered merge -> SPAN artefacts (duplicates, drops, VLAN tag, sensor clock) ->
pcap/pcapng. All randomness comes from the presentation seed, so the same plan, recording and
seed always give a byte-identical file.

Every stage streams: packets pass through in capture-time order with a bounded look-behind
window, the frames are spooled to a temporary file in time order, and the file is written in one
final pass that merges in the frames depending on the whole capture (IPv6 router / SLAAC / ND).
Memory holds a few minutes of the capture, not all of it.
"""

from __future__ import annotations

import heapq
import itertools
import math
import struct
import tempfile
from array import array
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, TYPE_CHECKING, Iterator

from pcapforge.compose import dhcp, enip
from pcapforge.compose.firewall import host_firewall
from pcapforge.compose.flows import assign_flows
from pcapforge.compose.headers import Headers
from pcapforge.compose.ipv6 import Ipv6
from pcapforge.compose.link import BROADCAST, Link, pad
from pcapforge.compose.packets import FIN, SYN, ComposeError, Packet, read_ipv4
from pcapforge.compose.retime import Network, Retimer
from pcapforge.compose.span import Frame, FrameInfo, Span
from pcapforge.compose.writer import WRITERS
from pcapforge.rng import Rng
from pcapforge.topology import Sink

if TYPE_CHECKING:
    from pcapforge.plan import Plan

__all__ = ["ComposeError", "ComposeResult", "compose"]

# Frames synthesized for a packet (ARP before it, an interface start) may lie this far before it.
FRAME_HORIZON_S = 300.0
_SPOOL = struct.Struct("<dqiBI")   # time, emission index, action id, info bits, frame length
_HAS_INFO, _REQUEST, _CONTROL, _TRAIN = 1, 2, 4, 8


@dataclass
class ComposeResult:
    path: Path
    packets: int
    first_epoch: float
    last_epoch: float
    action_frames: Mapping[int, int]    # action id -> 1-based frame number of the action's request
    action_times: Mapping[int, float]   # action id -> epoch timestamp of that frame
    # Sensor clock error applied to every frame timestamp: offset (s) and drift (ppm).
    sensor_clock: dict[str, float] = field(default_factory=lambda: {"offset_s": 0.0, "drift_ppm": 0.0})


def _info(p: Packet) -> FrameInfo:
    first = p.side == 0 and not p.retransmission and not p.more
    request = first and p.is_request
    return FrameInfo(p.action.id, request, first and not request and bool(p.flags & (SYN | FIN)), p.train)


class _Spool:
    """Frames in (time, index) order on a temporary file, read back once."""

    def __init__(self, file: IO[bytes]) -> None:
        self.file = file
        self.count = 0
        self.first = math.inf
        self.last = -math.inf

    def write(self, frame: Frame) -> None:
        t, index, data, info = frame
        if info is None:
            head = _SPOOL.pack(t, index, -1, 0, len(data))
        else:
            bits = _HAS_INFO | (_REQUEST if info.request else 0) | (_CONTROL if info.control else 0) \
                | (_TRAIN if info.train else 0)
            head = _SPOOL.pack(t, index, info.action, bits, len(data))
        self.file.write(head)
        self.file.write(data)
        self.count += 1
        self.first = min(self.first, t)
        self.last = max(self.last, t)

    def read(self) -> Iterator[Frame]:
        self.file.seek(0)
        read = self.file.read
        size = _SPOOL.size
        while head := read(size):
            t, index, action, bits, length = _SPOOL.unpack(head)
            info = None if not bits & _HAS_INFO else FrameInfo(
                action, bool(bits & _REQUEST), bool(bits & _CONTROL), bool(bits & _TRAIN))
            yield t, index, read(length), info


class _Sorter:
    """Frames pushed roughly in time order (synthesized ones up to ``FRAME_HORIZON_S`` early),
    handed to ``spool`` in exact (time, index) order."""

    def __init__(self, spool: _Spool) -> None:
        self.spool = spool
        self.heap: list[Frame] = []
        self.released: tuple[float, int] = (-math.inf, -1)
        self.index = itertools.count()

    def push(self, t: float, data: bytes, info: FrameInfo | None) -> None:
        index = next(self.index)
        if (t, index) < self.released:
            raise ComposeError(f"frame at {t:.6f} lands behind already written capture time "
                               f"{self.released[0]:.6f} (more than {FRAME_HORIZON_S:.0f} s early)")
        heapq.heappush(self.heap, (t, index, data, info))

    def release(self, until: float) -> None:
        heap = self.heap
        while heap and heap[0][0] < until:
            frame = heapq.heappop(heap)
            self.released = (frame[0], frame[1])
            self.spool.write(frame)


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
    timeline = enip.cyclic_io(plan, host_firewall(Retimer(plan, network, present).stream(packets)),
                              present.child("enip_io"))
    headers = Headers(plan, present.child("headers"))
    leases = dhcp.Dhcp(plan, present.child("dhcp"))
    link = Link(plan, network, present.child("arp"), leases.joining)
    ipv6 = Ipv6(plan, headers, present.child("ipv6"))

    with tempfile.TemporaryFile() as file:
        spool = _Spool(file)
        frames = _Sorter(spool)
        for p in timeline:
            ipv4 = not isinstance(p.dst, Sink) or p.dst.ipv4
            view = link.view(p.src, p.dst)
            if view is None:
                if ipv4:
                    headers.skip(p)
                continue
            eth, hops = view
            for t, frame in ipv6.start_before(p.time, p.src):
                frames.push(t, frame, None)
            if ipv4:
                delivery = dhcp.delivery(p)
                if delivery is None:
                    for t, arp in link.arp_before(p.time, p.src, p.dst):
                        frames.push(t, arp, None)
                elif delivery.broadcast:
                    eth = BROADCAST + eth[6:]
                frames.push(p.time, pad(eth + headers.build(p, hops, delivery)), _info(p))
                for t, arp in leases.after(p):
                    frames.push(t, arp, None)
            copy = ipv6.datagram(p)
            if copy is not None:
                frames.push(copy[0], copy[1], None)
            frames.release(p.time - FRAME_HORIZON_S)
        frames.release(math.inf)
        if not spool.count:
            raise ComposeError("no packet of the recording is visible at the sensor")
        # Router Solicitations, Router Advertisements, SLAAC and unicast ND over the whole capture.
        late = sorted((t, next(frames.index), frame, None) for t, frame in ipv6.finish(spool.first, spool.last))
        span = Span(plan, present.child("span"))
        merged = heapq.merge(spool.read(), late, key=lambda f: (f[0], f[1]))
        written = _Written(span.stream(merged), len(plan.actions))
        out = Path(out)
        out.parent.mkdir(parents=True, exist_ok=True)
        writer(out, written)
    action_frames, action_times = written.index()
    return ComposeResult(
        path=out,
        packets=written.count,
        first_epoch=written.first / 1_000_000,
        last_epoch=written.last / 1_000_000,
        action_frames=action_frames,
        action_times=action_times,
        sensor_clock={"offset_s": span.clock_offset, "drift_ppm": round(span.clock_drift * 1e6, 3)},
    )


class ActionIndex(Mapping):
    """Action id -> value for the actions that have one, over a compact array (a day-long plan has
    millions of actions); ``missing`` marks the others."""

    def __init__(self, values: array, missing) -> None:
        self._values = values
        self._missing = missing

    def __getitem__(self, action_id: int):
        if 0 <= action_id < len(self._values):
            value = self._values[action_id]
            if value != self._missing:
                return value
        raise KeyError(action_id)

    def __iter__(self) -> Iterator[int]:
        missing = self._missing
        return (i for i, value in enumerate(self._values) if value != missing)

    def __len__(self) -> int:
        return sum(1 for _ in self)


class _Written:
    """(microseconds, bytes) of the frames as the writer stores them, numbering them on the way:
    per action the first request frame, or its first SYN / FIN if it sends no application data."""

    def __init__(self, frames: Iterator[Frame], actions: int) -> None:
        self.frames = frames
        self.count = 0
        self.first = self.last = 0
        self.request = array("q", [0]) * actions   # frame number (0: none yet)
        self.control = array("q", [0]) * actions
        self.micros = array("q", [0]) * (2 * actions)   # request / control frame time per action

    def __iter__(self) -> Iterator[tuple[int, bytes]]:
        request, control, times = self.request, self.control, self.micros
        for t, _index, data, info in self.frames:
            micros = round(t * 1_000_000)
            self.count += 1
            if self.count == 1:
                self.first = micros
            self.last = micros
            # A segmented request is decoded (reassembled) in the frame of its last segment.
            if info is not None:
                action = info.action
                if info.request:
                    if not request[action]:
                        request[action] = self.count
                        times[2 * action] = micros
                elif info.control and not control[action]:
                    control[action] = self.count
                    times[2 * action + 1] = micros
            yield micros, data

    def index(self) -> tuple[ActionIndex, ActionIndex]:
        """(action -> frame, action -> epoch): the request frame, else the SYN / FIN one."""
        frames, epochs = array("q"), array("d")
        for action, (req, ctl) in enumerate(zip(self.request, self.control)):
            if req:
                frames.append(req)
                epochs.append(self.micros[2 * action] / 1_000_000)
            elif ctl:
                frames.append(ctl)
                epochs.append(self.micros[2 * action + 1] / 1_000_000)
            else:
                frames.append(0)
                epochs.append(-1.0)
        return ActionIndex(frames, 0), ActionIndex(epochs, -1.0)
