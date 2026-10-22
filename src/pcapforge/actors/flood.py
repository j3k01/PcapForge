"""Volumetric flood against a local sink service (benign equivalent of a UDP flood).

The sink is an ordinary Discard service (RFC 863, UDP port 9): it binds the port and drops
every datagram, so the OS never answers with an ICMP port-unreachable and the capture holds
only the one-way flood. ``sink.flood`` is the benign stand-in for a network denial-of-service
(MITRE ATT&CK T1498): one or more office hosts send a bounded burst of datagrams to the sink
at a high packet rate. No reflection, no amplification, no spoofing - a plain high-rate client
writing opaque bytes to a local sink, which is the observable pattern an analyst has to spot.

Each datagram is planned as its own action at its own virtual time, so the measured rate in the
capture follows the plan (the composer places the first - and only - packet of an action at its
scheduled time). Every datagram also becomes its own one-packet flow in the SIEM export, which is
what the per-destination, per-minute flow hunts count. Packets per level are capped to keep the
capture small.
"""

from __future__ import annotations

import asyncio
import socket

from pcapforge import ports
from pcapforge.actors import register
from pcapforge.actors.base import Actor
from pcapforge.plan import action_ref, host_ref
from pcapforge.rng import label_bytes


class _SinkProtocol(asyncio.DatagramProtocol):
    """A discard sink: it receives datagrams and drops them (no reply)."""

    def datagram_received(self, data: bytes, addr) -> None:
        pass

    def error_received(self, exc) -> None:
        pass


@register
class SinkServer(Actor):
    """A benign Discard (RFC 863) sink on UDP port 9: binds the port and drops everything it
    receives, so a flood aimed at it draws no ICMP replies."""

    type = "sink.server"
    is_server = True

    def plan(self) -> None:
        self.plan_.facts[self.id] = {"hosts": [host_ref(h.id) for h in self.hosts],
                                     "port": ports.WELL_KNOWN[ports.DISCARD]}

    async def serve(self, rt) -> None:
        loop = asyncio.get_running_loop()
        for host in self.hosts:
            transport, _ = await loop.create_datagram_endpoint(
                _SinkProtocol, local_addr=(host.loopback, ports.DISCARD))
            rt.transports.append(transport)


@register
class VolumetricFlood(Actor):
    """A bounded, high-rate burst of UDP datagrams from one or more office hosts to a local sink
    (benign equivalent of a volumetric network flood, MITRE ATT&CK T1498 / T1498.001).

    Params:
        target: host id of the sink (runs ``sink.server``).
        rate:   per-host datagrams per second (scalar or ``[lo, hi]`` drawn per host).
        window: length of the burst in seconds (scalar or ``[lo, hi]``).
        start:  when the burst begins, as a fraction of the capture (scalar or ``[lo, hi]``).
        ramp:   if true, each host ramps its rate from 25 % to 100 % over the window.
        size:   UDP payload bytes per datagram.
    """

    type = "sink.flood"

    def plan(self) -> None:
        plan, rng = self.plan_, self.rng
        target = plan.topology.select(self.param("target"))[0]
        sources = sorted(self.hosts, key=lambda h: h.id)
        rate_lo, rate_hi = self.span(self.param("rate", 60))
        window = float(self.param("window", 25))
        window = min(window, max(1.0, plan.duration - 2.0))
        ramp = bool(self.param("ramp", False))
        size = int(self.param("size", 64))
        start_lo, start_hi = self.span(self.param("start", [0.3, 0.6]))
        start_t = plan.duration * rng.uniform(start_lo, start_hi)
        start_t = max(0.0, min(start_t, plan.duration - window - 1.0))

        timed: list[tuple[float, object]] = []
        per_source = []
        for host in sources:
            hrng = rng.child(host.id)
            rate = hrng.uniform(rate_lo, rate_hi)
            skew = hrng.uniform(0.0, 0.5)
            actions = []
            t = 0.0
            while t < window:
                at = start_t + skew + t
                if at >= plan.duration - 0.5:
                    break
                action = plan.add(at, self.id, host.id, "sink.udp", target=target.id, size=size)
                actions.append(action)
                timed.append((at, action))
                inst = rate * (0.25 + 0.75 * (t / window)) if ramp else rate
                t += hrng.uniform(0.85, 1.15) / inst
            per_source.append((host, actions))

        if not timed:
            raise ValueError(f"{self.type} '{self.id}' planned no datagrams")
        timed.sort(key=lambda item: item[0])
        first_t, first_action = timed[0]
        last_action = timed[-1][1]
        peak_pps = _peak_per_second(t for t, _ in timed)

        plan.facts[self.id] = {
            "target": host_ref(target.id),
            "port": ports.WELL_KNOWN[ports.DISCARD],
            "protocol": "udp",
            "sources": [host_ref(h.id) for h in sources],
            "source_ips": {"$host_ips": [h.id for h in sources]},
            "source_count": len(sources),
            "total_packets": len(timed),
            "peak_pps": peak_pps,
            "first_packet": action_ref(first_action),
            "last_packet": action_ref(last_action),
            "per_source": [{"source": host_ref(h.id), "packets": len(acts),
                            "first": action_ref(acts[0])} for h, acts in per_source if acts],
        }
        plan.event(first_action, self.id,
                   f"Volumetric UDP flood of {target.id} begins ({len(sources)} source(s), "
                   f"peak ~{peak_pps} pps)", ["T1498", "T1498.001"],
                   target=target.id, sources=[h.id for h in sources],
                   total_packets=len(timed), peak_pps=peak_pps)
        plan.event(last_action, self.id, f"Volumetric UDP flood of {target.id} ends",
                   ["T1498"], target=target.id)

    def execute(self, action, rt) -> None:
        a = action.args
        key = (self.id, action.host)
        sock = rt.clients.get(key)
        if sock is None:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind((rt.loopback(action.host), 0))
            rt.clients[key] = sock
        sock.sendto(label_bytes("sink.flood", a["size"]), (rt.loopback(a["target"]), ports.DISCARD))

    def close(self, rt) -> None:
        for key in [k for k in rt.clients if k[0] == self.id]:
            rt.clients.pop(key).close()


def _peak_per_second(times) -> int:
    """Largest number of datagrams in any one-second window aligned to the first one."""
    times = sorted(times)
    if not times:
        return 0
    base = times[0]
    counts: dict[int, int] = {}
    for t in times:
        bucket = int(t - base)
        counts[bucket] = counts.get(bucket, 0) + 1
    return max(counts.values())
