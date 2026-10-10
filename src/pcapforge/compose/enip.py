"""EtherNet/IP at compose time: the socket address a ListIdentity reply announces, and the cyclic
class 1 I/O stream that continues each recorded first O->T / T->O exchange."""

from __future__ import annotations

import heapq
import struct
from typing import TYPE_CHECKING

from pcapforge import ports
from pcapforge.actors.enip import RUN, RUN_IDLE, Drive, io_packet, parse_io_packet
from pcapforge.compose.packets import K_DATA, UDP, Packet

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


def cyclic_io(plan: Plan, timeline: list[Packet], rng: Rng) -> list[Packet]:
    """``timeline`` plus the class 1 packets after each recorded first exchange on UDP 2222:
    both directions at the connection's API until the end of the capture, sequence numbers and
    counts continuing from the recorded ones, O->T data from the scanner's ``LineProgram`` and
    T->O data from a ``Drive`` that consumes it."""
    flows: dict[int, list[Packet]] = {}
    for p in timeline:
        if p.flow.proto == UDP and p.flow.server_port == ports.ENIP_IO:
            flows.setdefault(id(p.flow), []).append(p)
    if not flows:
        return timeline
    actors = {a.id: a for a in plan.actors}
    start, end = plan.start_epoch, plan.start_epoch + plan.duration
    order = 1 + max(p.order for p in timeline)
    added: list[Packet] = []
    for packets in flows.values():
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
        streams = []
        state = {}
        for side in (0, 1):
            last = [p for p in packets if p.side == side][-1]
            connection_id, sequence, count, _ = parse_io_packet(last.payload)
            state[side] = [connection_id, sequence, count]
            api = period * (1.0 + clock.uniform(-CLOCK_PPM, CLOCK_PPM) * 1e-6)
            sigma = JITTER_S[side]
            times, n = [], 1
            while True:
                t = last.time + n * api + max(-4 * sigma, min(4 * sigma, clock.gauss(0.0, sigma)))
                if t >= end:
                    break
                times.append((t, side))
                n += 1
            streams.append(times)
        flow = packets[0].flow
        for t, side in heapq.merge(*streams):
            connection = state[side]
            connection[1] = (connection[1] + 1) & 0xFFFFFFFF
            connection[2] = (connection[2] + 1) & 0xFFFF
            if side == 0:
                data = program.output(t - start)
                drive.consume(t - start, data[RUN_IDLE:])
            else:
                data = drive.produce(t - start)
            added.append(Packet(order, flow, side, K_DATA, 0, 0, 0, io_packet(*connection, data), action, t))
            order += 1
    if not added:
        return timeline
    out = timeline + added
    out.sort(key=lambda p: (p.time, p.order))
    return out
