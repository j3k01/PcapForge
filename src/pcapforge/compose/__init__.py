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
window (the host firewall and the cyclic I/O are release stages of the retimer), and frames are
written as they come. When the capture has IPv6 hosts, frames are spooled to a temporary file
first and a final pass merges in the frames that depend on the whole capture (IPv6 router /
SLAAC / ND). Memory holds a few minutes of the capture, not all of it.
"""

from __future__ import annotations

import heapq
import itertools
import math
import struct
import tempfile
from array import array
from collections import deque
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, TYPE_CHECKING, Iterator

from pcapforge.compose import dhcp
from pcapforge.compose.enip import CyclicIo
from pcapforge.compose.firewall import HostFirewall
from pcapforge.compose.flows import assign_flows
from pcapforge.compose.headers import Headers
from pcapforge.compose.ipv6 import ETHERTYPE_IPV6, GlobalAddresses, Ipv6
from pcapforge.compose.link import BROADCAST, Link, pad
from pcapforge.compose.packets import FIN, SYN, ComposeError, Packet, read_ipv4
from pcapforge.compose.retime import Network, Retimer
from pcapforge.compose.span import CONTROL, INFO_SHIFT, REQUEST, TRAIN, Frame, Span
from pcapforge.compose.writer import WRITERS
from pcapforge.rng import Rng
from pcapforge.topology import Sink

if TYPE_CHECKING:
    from pcapforge.plan import Plan

__all__ = ["ComposeError", "ComposeResult", "compose"]

# Frames synthesized for a packet (ARP before it, an interface start) may lie this far before it.
FRAME_HORIZON_S = 300.0
_SPOOL = struct.Struct("<dqqI")   # time, emission index, frame info (-1: synthesized), frame length


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
    # Dual-stack site: host id -> its global IPv6 addresses (stable, temporary).
    ipv6_addresses: dict[str, dict] = field(default_factory=dict)


def _info(p: Packet) -> int:
    info = p.action.id << INFO_SHIFT | (TRAIN if p.train else 0)
    if p.side == 0 and not p.retransmission and not p.more:
        if p.is_request:
            info |= REQUEST
        elif p.flags & (SYN | FIN):
            info |= CONTROL
    return info


class _Spool:
    """Frames in (time, index) order on a temporary file, read back once."""

    CHUNK = 1 << 22

    def __init__(self, file: IO[bytes]) -> None:
        self.file = file
        self.buffer = bytearray()
        self.count = 0
        self.first = self.last = 0.0

    def write(self, frame: Frame) -> None:
        t, index, data, info = frame
        self.buffer += _SPOOL.pack(t, index, -1 if info is None else info, len(data))
        self.buffer += data
        if len(self.buffer) >= self.CHUNK:
            self.file.write(self.buffer)
            self.buffer.clear()
        if not self.count:
            self.first = t
        self.last = t   # frames come in time order
        self.count += 1

    def read(self, late: list[Frame]) -> Iterator[Frame]:
        """The spooled frames merged with ``late`` ones (sorted, few) in (time, index) order."""
        self.file.write(self.buffer)
        self.buffer.clear()
        self.file.seek(0)
        size, unpack = _SPOOL.size, _SPOOL.unpack_from
        pending = deque(late)
        data, pos = b"", 0
        while True:
            if len(data) - pos < size:
                data, pos = data[pos:] + self.file.read(self.CHUNK), 0
                if len(data) < size:
                    break
            t, index, info, length = unpack(data, pos)
            end = pos + size + length
            if end > len(data):
                more = self.file.read(max(self.CHUNK, end - pos))
                if not more:
                    raise ComposeError("frame spool ends inside a frame")
                data, pos = data[pos:] + more, 0
                continue
            while pending and (pending[0][0], pending[0][1]) < (t, index):
                yield pending.popleft()
            yield t, index, data[pos + size:end], None if info < 0 else info
            pos = end
        yield from pending


class _Sorter:
    """Frames in exact (time, index) order: those of timeline packets arrive in that order (a
    queue), synthesized ones (ARP, interface starts, ACD probes, IPv6 copies) up to
    ``FRAME_HORIZON_S`` early or a little late (a heap)."""

    def __init__(self) -> None:
        self.queue: deque[Frame] = deque()
        self.heap: list[Frame] = []
        self.released: tuple[float, int] = (-math.inf, -1)
        self.index = itertools.count()

    def packet(self, t: float, data: bytes, info: int) -> None:
        self.queue.append((t, next(self.index), data, info))

    def synthesized(self, t: float, data: bytes) -> None:
        index = next(self.index)
        if (t, index) < self.released:
            raise ComposeError(f"frame at {t:.6f} lands behind already written capture time "
                               f"{self.released[0]:.6f} (more than {FRAME_HORIZON_S:.0f} s early)")
        heapq.heappush(self.heap, (t, index, data, None))

    def release(self, until: float) -> Iterator[Frame]:
        queue, heap = self.queue, self.heap
        while True:
            if heap and (not queue or (heap[0][0], heap[0][1]) < (queue[0][0], queue[0][1])):
                if heap[0][0] >= until:
                    return
                frame = heapq.heappop(heap)
            elif queue and queue[0][0] < until:
                frame = queue.popleft()
            else:
                return
            self.released = (frame[0], frame[1])
            yield frame


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
    stages = [HostFirewall()]
    if any(a.type == "enip.scanner" for a in plan.actors):
        stages.append(CyclicIo(plan, present.child("enip_io")))
    timeline = Retimer(plan, network, present, stages).stream(packets)
    global6 = GlobalAddresses(plan, present.child("ipv6").child("global"))
    headers = Headers(plan, present.child("headers"), global6)
    leases = dhcp.Dhcp(plan, present.child("dhcp"))
    link = Link(plan, network, present.child("arp"), leases.joining)
    ipv6 = Ipv6(plan, headers, present.child("ipv6"), global6=global6, bound=leases.bound)
    sorter = _Sorter()

    def frames() -> Iterator[Frame]:
        synthesized = sorter.synthesized
        for p in timeline:
            ipv4 = not isinstance(p.dst, Sink) or p.dst.ipv4
            view = link.view(p.src, p.dst)
            if view is None:
                if ipv4:
                    headers.skip(p)
                continue
            eth, hops = view
            for t, frame in ipv6.start_before(p.time, p.src):
                synthesized(t, frame)
            if p.flow.v6:
                src6, dst6 = global6.endpoints(p)
                for t, frame in ipv6.neighbor(p, dst6):
                    synthesized(t, frame)
                frame6 = eth[:12] + ETHERTYPE_IPV6 + headers.build6(p, hops, src6, dst6)
                sorter.packet(p.time, pad(frame6), _info(p))
            elif ipv4:
                delivery = dhcp.delivery(p)
                if delivery is None:
                    for t, arp in link.arp_before(p.time, p.src, p.dst):
                        synthesized(t, arp)
                elif delivery.broadcast:
                    eth = BROADCAST + eth[6:]
                sorter.packet(p.time, pad(eth + headers.build(p, hops, delivery)), _info(p))
                for t, arp in leases.after(p):
                    synthesized(t, arp)
            copy = ipv6.datagram(p)
            if copy is not None:
                synthesized(*copy)
            yield from sorter.release(p.time - FRAME_HORIZON_S)
        yield from sorter.release(math.inf)

    span = Span(plan, present.child("span"))
    out = Path(out)
    with tempfile.TemporaryFile() as file:
        if ipv6.address:
            spool = _Spool(file)
            for frame in frames():
                spool.write(frame)
            if not spool.count:
                raise ComposeError("no packet of the recording is visible at the sensor")
            # Router Solicitations, Router Advertisements, SLAAC and unicast ND over the whole capture.
            late = sorted((t, next(sorter.index), frame, None) for t, frame in ipv6.finish(spool.first, spool.last))
            ordered = spool.read(late)
        else:
            ordered = frames()
            first = next(ordered, None)
            if first is None:
                raise ComposeError("no packet of the recording is visible at the sensor")
            ordered = itertools.chain([first], ordered)
        written = _Written(span.stream(ordered), len(plan.actions))
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
        ipv6_addresses={hid: global6.describe(hid) for hid in sorted(global6.stable)},
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
        count = 0
        for t, _index, data, info in self.frames:
            micros = round(t * 1_000_000)
            count += 1
            if count == 1:
                self.first = micros
            # A segmented request is decoded (reassembled) in the frame of its last segment.
            if info is not None and info & (REQUEST | CONTROL):
                action = info >> INFO_SHIFT
                if info & REQUEST:
                    if not request[action]:
                        request[action] = count
                        times[2 * action] = micros
                elif not control[action]:
                    control[action] = count
                    times[2 * action + 1] = micros
            self.count, self.last = count, micros
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
