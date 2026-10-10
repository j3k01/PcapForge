"""EtherNet/IP at compose time: the socket address a ListIdentity reply announces, and the cyclic
class 1 I/O stream that continues each recorded first O->T / T->O exchange."""

from __future__ import annotations

import heapq
import struct
from array import array
from typing import TYPE_CHECKING, Callable, Iterator

from pcapforge import ports
from pcapforge.actors.enip import RUN, RUN_IDLE, Drive, io_packet, parse_io_packet
from pcapforge.compose.packets import K_DATA, UDP, ComposeError, Packet

if TYPE_CHECKING:
    from pcapforge.plan import Plan
    from pcapforge.rng import Rng

_ENCAP = struct.Struct("<HH")    # command, length (of the 24-byte encapsulation header)
_ENCAP_HEADER = 24
_ITEM = struct.Struct("<HH")     # CPF item type id, length
LIST_IDENTITY = 0x0063
CIP_IDENTITY_ITEM = 0x000C
_SIN_ADDR = 2 + 4                # encapsulation version, sin_family, sin_port, then sin_addr

# Each producer runs its RPI timer off its own crystal and puts every packet on the wire with a
# little scheduling jitter: O->T from the Logix scanner (side 0), T->O from the drive (side 1).
CLOCK_PPM = 30.0
JITTER_S = (40e-6, 150e-6)
# Recorded packets come first among equal times, then the connections in the order they appear,
# each with its packets in sequence (the order key of a sort that is stable on equal times).
ORDER_BASE = 1 << 48
ORDER_FLOW = 1 << 32


def rewrite_list_identity(payload: bytes, remap) -> bytes:
    """Replace the sin_addr of every CIP Identity item in ListIdentity replies for which
    ``remap(ip4_bytes) -> bytes | None`` has a final address. The sin_port (44818, big-endian)
    and every other byte stay as recorded; anything that is not a ListIdentity reply is returned
    unchanged. A TCP payload may carry several encapsulation messages back to back."""
    out = None
    offset = 0
    try:
        while offset + _ENCAP_HEADER <= len(payload):
            command, length = _ENCAP.unpack_from(payload, offset)
            data, end = offset + _ENCAP_HEADER, offset + _ENCAP_HEADER + length
            if end > len(payload):
                break
            if command == LIST_IDENTITY and length >= 2:
                count = struct.unpack_from("<H", payload, data)[0]
                item = data + 2
                for _ in range(count):
                    kind, size = _ITEM.unpack_from(payload, item)
                    body = item + _ITEM.size
                    if body + size > end:
                        break
                    if kind == CIP_IDENTITY_ITEM and size >= _SIN_ADDR + 4:
                        start = body + _SIN_ADDR
                        new = remap(payload[start:start + 4])
                        if new is not None:
                            out = out if out is not None else bytearray(payload)
                            out[start:start + 4] = new
                    item = body + size
            offset = end
    except struct.error:
        return payload
    return bytes(out) if out is not None else payload


class CyclicIo:
    """The class 1 packets after each recorded first exchange on UDP 2222: both directions at the
    connection's API until the end of the capture, sequence numbers and counts continuing from the
    recorded ones, O->T data from the scanner's ``LineProgram`` and T->O data from a ``Drive`` that
    consumes it.

    A release stage of the ``Retimer``: it collects the recorded packets of each I/O connection
    (``observe``) and, when the first of them leaves in capture order (``admit``; the exchange is
    complete by then), starts the connection's stream, handing over one packet at a time."""

    def __init__(self, plan: Plan, rng: Rng) -> None:
        self.actors = {a.id: a for a in plan.actors}
        self.rng = rng
        self.start, self.end = plan.start_epoch, plan.start_epoch + plan.duration
        self.flows: dict[int, list[Packet]] = {}       # recorded packets of each I/O connection
        self.started: set[int] = set()
        self.heads: dict[int, Iterator[Packet]] = {}   # id of a stream packet in flight -> its stream

    def observe(self, p: Packet) -> None:
        flow = p.flow
        if flow.proto == UDP and flow.server_port == ports.ENIP_IO:
            key = id(flow)
            if key in self.started:
                raise ComposeError(f"EtherNet/IP I/O packet of action {p.action.id} after its cyclic stream "
                                   "started: the recorded exchange outlasts the streaming horizon")
            self.flows.setdefault(key, []).append(p)

    def admit(self, p: Packet, insert: Callable[[Packet], None]) -> bool:
        head = self.heads.pop(id(p), None)
        if head is not None:
            self._next(head, insert)
            return True
        key = id(p.flow)
        if key in self.flows and key not in self.started:
            self.started.add(key)
            order = ORDER_BASE + (len(self.started) - 1) * ORDER_FLOW
            self._next(_stream(self.actors, self.flows[key], self.rng, self.start, self.end, order), insert)
        return True

    def _next(self, head: Iterator[Packet], insert: Callable[[Packet], None]) -> None:
        q = next(head, None)
        if q is not None:
            self.heads[id(q)] = head
            insert(q)


def _stream(actors: dict, packets: list[Packet], rng: Rng, start: float, end: float, order: int) -> Iterator[Packet]:
    """The cyclic continuation of one connection whose recorded packets are ``packets``."""
    action = packets[0].action
    program = actors[action.actor].program
    period = action.args["rpi_us"] / 1e6
    clock = rng.child(f"clock:{action.id}")
    drive = Drive(rng.child(f"drive:{action.id}"))
    for p in packets:  # the drive's state after the recorded exchange
        if p.side == 0:
            data = parse_io_packet(p.payload)[3]
            if struct.unpack_from("<I", data)[0] & RUN:
                drive.consume(p.time - start, data[RUN_IDLE:])
        else:
            drive.advance(p.time - start)
    # Both producers' timers are drawn up front (O->T first), as compact arrays of times.
    times: list[array] = []
    state = {}
    for side in (0, 1):
        last = [p for p in packets if p.side == side][-1]
        connection_id, sequence, count, _ = parse_io_packet(last.payload)
        state[side] = [connection_id, sequence, count]
        api = period * (1.0 + clock.uniform(-CLOCK_PPM, CLOCK_PPM) * 1e-6)
        sigma = JITTER_S[side]
        side_times, n = array("d"), 1
        while True:
            t = last.time + n * api + max(-4 * sigma, min(4 * sigma, clock.gauss(0.0, sigma)))
            if t >= end:
                break
            side_times.append(t)
            n += 1
        times.append(side_times)
    flow = packets[0].flow
    merged = heapq.merge(((t, 0) for t in times[0]), ((t, 1) for t in times[1]))
    for t, side in merged:
        connection = state[side]
        connection[1] = (connection[1] + 1) & 0xFFFFFFFF
        connection[2] = (connection[2] + 1) & 0xFFFF
        if side == 0:
            data = program.output(t - start)
            drive.consume(t - start, data[RUN_IDLE:])
        else:
            data = drive.produce(t - start)
        yield Packet(order, flow, side, K_DATA, 0, 0, 0, io_packet(*connection, data), action, t)
        order += 1
