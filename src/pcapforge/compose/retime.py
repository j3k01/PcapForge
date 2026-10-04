"""Causal retiming: place recorded packets on the scenario clock as a sensor would see them.

Recorded order is kept. The first packet of an action happens at ``start_epoch + action.t``;
every later packet of the flow follows from the packet it reacts to: path latency between
the sensor and the sender plus the sender's reaction (application processing, delayed ACK,
handshake turnaround). Delayed pure ACKs that a stack would piggyback on the next segment
are not sent. Loss after the sensor is modelled as a retransmission after the stack's RTO.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING

from pcapforge.compose.packets import K_ACK, K_DATA, K_FIN, K_RST, K_SYNACK, TCP, Flow, Packet

if TYPE_CHECKING:
    from pcapforge.plan import Plan
    from pcapforge.rng import Rng
    from pcapforge.topology import Host, Topology

SAME_SENDER = (10e-6, 60e-6)   # back-to-back segments of one sender
QUICK = (20e-6, 60e-6)         # kernel-only reaction (immediate ACK, RST)
SYN_ACK = (30e-6, 80e-6)       # listening socket answers a SYN


class Network:
    """Latency between the sensor and every host, drawn once per host."""

    def __init__(self, topology: Topology, rng: Rng) -> None:
        sensor = topology.sensor
        router = topology.subnets[sensor].router
        self.forwarding = router.device.forwarding_ms if router else None
        self.base: dict[str, float] = {}
        self.routed: dict[str, bool] = {}
        for host in topology.hosts:
            latency = rng.uniform(0.1, 0.4) / 1000.0
            routed = sensor not in host.subnets
            if routed:
                latency += rng.uniform(0.3, 0.8) / 1000.0
            self.base[host.id] = latency
            self.routed[host.id] = routed

    def round_trip(self, host: Host, rng: Rng) -> float:
        """Sensor -> host -> sensor path delay for one packet exchange."""
        delay = self.base[host.id] * rng.uniform(0.9, 1.15)
        if self.routed[host.id] and self.forwarding:
            delay += 2 * rng.lognormal_ms(self.forwarding.median, self.forwarding.sigma)
        return delay


@dataclass(slots=True)
class _Clock:
    """Retiming state of one flow."""

    action: object = None
    last_t: float | None = None
    last: Packet | None = None
    # Per side: does it owe a reaction to the peer's last non-ACK packet, and to which one.
    owed: list[bool] = field(default_factory=lambda: [False, False])
    trigger: list[Packet | None] = field(default_factory=lambda: [None, None])
    pending: Packet | None = None   # delayed pure ACK not yet sent
    due: float = 0.0
    emitted: int = 0


class Retimer:
    def __init__(self, plan: Plan, network: Network, rng: Rng) -> None:
        self.start = plan.start_epoch
        self.net = network
        self.rng = rng.child("timing")
        self.loss = rng.child("retransmit")
        self.rate = float(plan.impairments.get("retransmit_rate") or 0.0)
        self.clocks: dict[Flow, _Clock] = {}
        self.out: list[Packet] = []

    def run(self, packets: list[Packet]) -> list[Packet]:
        """Timed packets (plus retransmissions, minus piggybacked ACKs) sorted by time."""
        for packet in packets:
            self._place(packet)
        for clock in self.clocks.values():
            if clock.pending is not None:
                self._commit(clock, clock.pending, clock.due)
        self.out.sort(key=lambda p: (p.time, p.order))
        return self.out

    # -- placement ----------------------------------------------------------------------
    def _place(self, p: Packet) -> None:
        clock = self.clocks.get(p.flow)
        if clock is None:
            clock = self.clocks[p.flow] = _Clock()
        if clock.pending is not None:
            ack, due = clock.pending, clock.due
            clock.pending = None
            if ack.side == p.side and p.kind != K_ACK:
                t, _ = self._time(clock, p)
                if t < due:
                    # The stack sends this segment before its delayed-ACK timer fires: the
                    # acknowledgement rides on it and the pure ACK never hits the wire.
                    self._commit(clock, p, t)
                    return
                self._commit(clock, ack, due)
                self._commit(clock, p, max(t, due + self.rng.uniform(*SAME_SENDER)))
                return
            self._commit(clock, ack, due)
        t, delayed = self._time(clock, p)
        if delayed:
            clock.pending, clock.due = p, t
            return
        self._commit(clock, p, t)

    def _time(self, clock: _Clock, p: Packet) -> tuple[float, bool]:
        """Sensor time of ``p`` and whether it is a delayed ACK (may be piggybacked)."""
        if clock.last_t is None:
            clock.action = p.action
            return self.start + p.action.t, False
        rng = self.rng
        sender = p.src
        delayed = False
        if clock.last.side != p.side:
            reaction, delayed = self._reaction(p, clock.last)
            t = clock.last_t + self.net.round_trip(sender, rng) + reaction
        else:
            t = clock.last_t + rng.uniform(*SAME_SENDER)
            trigger = clock.trigger[p.side]
            if p.kind != K_ACK and clock.owed[p.side] and trigger is not None:
                reaction, _ = self._reaction(p, trigger)
                t = max(t, trigger.time + self.net.round_trip(sender, rng) + reaction)
        if p.action is not clock.action:
            # First packet of the next action on this flow: on schedule, unless the flow is
            # still busy with the previous exchange.
            clock.action = p.action
            t = max(t, self.start + p.action.t)
        return t, delayed

    def _reaction(self, p: Packet, trigger: Packet) -> tuple[float, bool]:
        rng = self.rng
        if p.kind == K_SYNACK:
            return rng.uniform(*SYN_ACK), False
        if p.kind == K_ACK:
            if trigger.kind == K_DATA:
                delayed_ack = p.src.device.stack.delayed_ack
                if rng.random() < delayed_ack.probability:
                    return rng.uniform(delayed_ack.min_ms, delayed_ack.max_ms) / 1000.0, True
            return rng.uniform(*QUICK), False
        if p.kind == K_RST:
            return rng.uniform(*QUICK), False
        delay = self._processing(p.src)
        if p.kind == K_FIN:
            delay *= 0.5  # closing a socket is cheaper than building a reply
        return delay, False

    def _processing(self, host: Host) -> float:
        latency = host.device.processing_ms
        return self.rng.lognormal_ms(latency.median, latency.sigma)

    def _commit(self, clock: _Clock, p: Packet, t: float) -> None:
        first = clock.emitted == 0
        self._emit(clock, p, t)
        if (self.rate and not first and p.flow.proto == TCP and p.payload
                and self.loss.random() < self.rate):
            # Lost after the sensor: the sender retransmits after its RTO and the rest of
            # the flow reacts to the retransmission.
            stack = p.src.device.stack
            rto = stack.rto.min_ms / 1000.0
            if stack.rto.plus_rtt:
                rto += self.net.round_trip(p.dst, self.loss) + self.net.round_trip(p.src, self.loss)
            rto *= self.loss.uniform(1.0, 1.03)
            self._emit(clock, replace(p, retransmission=True), t + rto)

    def _emit(self, clock: _Clock, p: Packet, t: float) -> None:
        p.time = t
        self.out.append(p)
        clock.last_t = t
        clock.last = p
        clock.emitted += 1
        if p.kind != K_ACK:
            peer = 1 - p.side
            clock.owed[peer] = True
            clock.trigger[peer] = p
            clock.owed[p.side] = False
