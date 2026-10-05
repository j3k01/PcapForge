"""What the sensor adds to and loses from the wire: SPAN duplicates, capture drops, 802.1Q tags.

``impairments`` knobs (all off by default):

* ``span_duplicates``: share of frames the SPAN session delivers twice. A session that mirrors
  ingress and egress of two ports copies a frame once when it enters the switch and again when
  it leaves: identical bytes, the second copy a store-and-forward delay later;
* ``sensor_drop``: share of frames the sensor misses (SPAN oversubscription, capture buffer).
  tshark then reports "previous segment not captured" / "ACKed unseen segment";
* ``vlan``: 802.1Q VLAN id the mirrored frames carry (a SPAN destination that keeps the tag);
* ``clock_offset`` / ``clock_drift_ppm``: the sensor's clock error, a number or a ``[lo, hi]``
  range drawn per seed. Every frame timestamp (and therefore every time in the answer key) is
  shifted by the offset plus the drift accumulated since the first frame; payload clocks (NTP
  timestamps, OPC UA times) keep the site's true time, so the analyst can measure the skew.

Frames of actions the answer key refers to, and segments of a message that tshark has to
reassemble, are never dropped or duplicated: question checks count them, and a missing segment
would leave the message undecodable.
"""

from __future__ import annotations

import struct
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pcapforge.compose.packets import Packet
    from pcapforge.plan import Plan
    from pcapforge.rng import Rng

TPID = b"\x81\x00"
SPAN_RATE = 1e9                   # SPAN destination port: copies leave at 1 Gbit/s
SWITCH_LATENCY = (1.5e-6, 6e-6)   # forwarding decision until the egress copy

Frame = tuple[float, int, bytes, "Packet | None"]


def _draw(value, rng: Rng) -> float:
    """A knob given as a number, or as ``[lo, hi]`` drawn per seed (rounded to the microsecond)."""
    if value is None:
        return 0.0
    if isinstance(value, (list, tuple)):
        return round(rng.uniform(float(value[0]), float(value[1])), 6)
    return float(value)


def answer_actions(plan: Plan) -> set[int]:
    """Ids of the actions the answer key points at (facts and timeline events)."""
    from pcapforge.plan import Action

    found: set[int] = {event.action.id for event in plan.events}
    stack: list = [plan.facts]
    while stack:
        value = stack.pop()
        if isinstance(value, Action):
            found.add(value.id)
        elif isinstance(value, dict):
            stack.extend(value.values())
        elif isinstance(value, (list, tuple)):
            stack.extend(value)
    return found


class Span:
    def __init__(self, plan: Plan, rng: Rng) -> None:
        impairments = plan.impairments
        self.duplicates = float(impairments.get("span_duplicates") or 0.0)
        self.drop = float(impairments.get("sensor_drop") or 0.0)
        vlan = impairments.get("vlan")
        self.tag = TPID + struct.pack("!H", int(vlan)) if vlan else None
        self.rng = rng
        clock = rng.child("clock")
        self.clock_offset = _draw(impairments.get("clock_offset"), clock)
        self.clock_drift = _draw(impairments.get("clock_drift_ppm"), clock) * 1e-6
        self.protected = answer_actions(plan) if self.duplicates or self.drop else set()

    @property
    def active(self) -> bool:
        return bool(self.duplicates or self.drop or self.tag or self.clock_offset or self.clock_drift)

    def _eligible(self, p: Packet | None) -> bool:
        return p is None or not (p.train or p.action.id in self.protected)

    def apply(self, frames: list[Frame]) -> list[Frame]:
        """``frames`` sorted by (time, index) -> what the capture file holds, in the same order.

        Duplicates carry no packet: the answer key always points at the first copy."""
        if not self.active:
            return frames
        drop = self.rng.child("drop") if self.drop else None
        copy = self.rng.child("duplicates") if self.duplicates else None
        out: list[Frame] = []
        late: list[Frame] = []
        t0 = frames[0][0] if frames else 0.0
        for t, index, data, p in frames:
            if self.clock_offset or self.clock_drift:
                t = t + self.clock_offset + (t - t0) * self.clock_drift
            if self.tag is not None:
                data = data[:12] + self.tag + data[12:]
            eligible = self._eligible(p)
            if drop is not None and eligible and drop.random() < self.drop:
                continue
            out.append((t, index, data, p))
            if copy is not None and eligible and copy.random() < self.duplicates:
                delay = (len(data) + 24) * 8 / SPAN_RATE + copy.uniform(*SWITCH_LATENCY)
                late.append((t + delay, index, data, None))
        if late:
            out.extend(late)
            out.sort(key=lambda f: (f[0], f[1], f[3] is None))
        return out
