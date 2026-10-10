"""Host firewall model: a host that drops unsolicited SYNs instead of refusing them."""

from __future__ import annotations

import heapq
import itertools
import math
from collections import deque
from dataclasses import replace
from typing import Iterable, Iterator

from pcapforge.compose.packets import K_DATA, K_RST, K_SYN, K_SYNACK, TCP, Packet
from pcapforge.topology import Sink

# A packet leaves this stage once the timeline has moved this far past it: by then its connection
# has shown whether it was refused (the RST follows the SYN within milliseconds).
DELAY_S = 60.0
_ANSWERED = {K_SYNACK, K_DATA}
_RETRANSMITTED = "syn_retransmitted"   # marker in ``Flow.kinds``: the filtered SYN went out again


def _refused_by_firewall(packet: Packet) -> bool:
    flow = packet.flow
    kinds = flow.kinds
    if flow.proto != TCP or K_SYN not in kinds or K_RST not in kinds or kinds & _ANSWERED:
        return False
    target = flow.hosts[1]
    return not isinstance(target, Sink) and target.device.stack.drops_unsolicited


def host_firewall(timeline: Iterable[Packet]) -> Iterator[Packet]:
    """``timeline`` (sorted by (time, recorded order)) as a host firewall changes it.

    A probe of a closed TCP port is refused with a RST on the loopback recording. If the target
    host's stack drops unsolicited connections (``drops_unsolicited``, e.g. the Windows Defender
    Firewall default), the port looks *filtered* instead: the RST never comes, and the client
    retransmits its SYN once (at its stack's ``syn_rto_s``) before giving up. Ports on hosts that
    refuse (Linux, the PLC stacks) keep their RST and read as *closed*. This is how a port sweep
    tells firewalled machines from listening-but-closed ones.
    """
    waiting: deque[Packet] = deque()
    added: list[tuple[float, int, int, Packet]] = []   # retransmitted SYNs, by (time, order)
    emission = itertools.count()

    def release(until: float) -> Iterator[Packet]:
        while waiting and waiting[0].time < until:
            p = waiting.popleft()
            while added and (added[0][0], added[0][1]) < (p.time, p.order):
                yield heapq.heappop(added)[3]
            if _refused_by_firewall(p):
                if p.kind == K_RST:
                    continue
                if p.kind == K_SYN and p.side == 0 and _RETRANSMITTED not in p.flow.kinds:
                    p.flow.kinds.add(_RETRANSMITTED)
                    rto = p.flow.hosts[0].device.stack.syn_rto_s
                    again = replace(p, time=p.time + rto, retransmission=True)
                    heapq.heappush(added, (again.time, again.order, next(emission), again))
            yield p

    for p in timeline:
        if p.flow.proto == TCP:
            if p.flow.kinds is None:
                p.flow.kinds = set()
            p.flow.kinds.add(p.kind)
        waiting.append(p)
        yield from release(p.time - DELAY_S)
    yield from release(math.inf)
    while added:
        yield heapq.heappop(added)[3]
