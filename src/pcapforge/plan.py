"""Seeded scenario plan: the ordered list of actions to record plus answer-key facts."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
from dataclasses import dataclass, field
from operator import attrgetter
from typing import Any

from pcapforge import __version__
from pcapforge.rng import Rng
from pcapforge.scenario import Scenario, evaluate_when, parse_duration, resolve
from pcapforge.topology import Topology

# Recording format version: bump whenever the recorder/actors change what goes on the wire.
RECORDING_VERSION = 1
_SCALARS = (str, int, float, bool, type(None))


@dataclass(slots=True)
class Action:
    t: float          # virtual seconds since capture start
    actor: str
    host: str         # host instance id issuing the action
    op: str
    args: dict
    phase: str = "main"  # "setup" | "main" | "teardown"
    id: int = -1         # insertion order while planning, then the index in capture order


@dataclass(slots=True)
class Event:
    action: Action
    actor: str
    title: str
    techniques: list[str]
    details: dict


def host_ref(host_id: str) -> dict:
    return {"$host": host_id}


def action_ref(action: Action) -> dict:
    return {"$action": action}


@dataclass
class Plan:
    scenario: Scenario
    difficulty: str
    seed: str
    base_seed: str
    vars: dict
    duration: float
    impairments: dict
    start_epoch: float  # UTC epoch of the first packet
    topology: Topology
    rng: Rng
    actions: list[Action] = field(default_factory=list)
    facts: dict[str, Any] = field(default_factory=dict)
    events: list[Event] = field(default_factory=list)
    actors: list = field(default_factory=list)
    _shared_args: dict = field(default_factory=dict, repr=False)   # argument dicts shared while planning

    def add(self, t: float, actor: str, host: str, op: str, phase: str = "main", **args) -> Action:
        """Append an action. Arguments are plain JSON values; equal argument dicts of scalars are one
        shared dict (a day-long plan repeats the same poll arguments millions of times), so an actor
        that changes an action's arguments later assigns a new dict instead of editing it."""
        if all(type(v) in _SCALARS for v in args.values()):
            key = tuple((k, type(v), repr(v) if type(v) is float else v) for k, v in args.items())
            args = self._shared_args.setdefault(key, args)
        action = Action(t=round(t, 6), actor=actor, host=host, op=op, args=args, phase=phase,
                        id=len(self.actions))
        self.actions.append(action)
        return action

    def event(self, action: Action, actor: str, title: str, techniques: list[str], **details) -> None:
        self.events.append(Event(action, actor, title, techniques, details))

    @property
    def start_hour(self) -> float:
        """UTC hour of day at capture start (drives daily process curves)."""
        return (self.start_epoch % 86400) / 3600.0

    def context(self) -> dict:
        return {"vars": self.vars, "facts": self.facts}

    def finalize(self) -> None:
        """Order the actions (time, then insertion: the sort is stable) and number them."""
        self.actions.sort(key=attrgetter("t"))
        for index, action in enumerate(self.actions):
            action.id = index
        self._shared_args.clear()

    def digest(self) -> str:
        """Key of everything that influences the recording (not the presentation).

        The sha256 of ``json.dumps(payload, sort_keys=True, default=str)``, fed action by action
        so a day-long plan is never one string in memory."""
        rest = {
            "recording_version": RECORDING_VERSION,
            "pcapforge": __version__,
            "scenario": self.scenario.id,
            "scenario_version": self.scenario.doc.get("version", 1),
            "start_epoch": self.start_epoch,
            "behaviour": self.rng.key,
            # Names travel inside payloads (DNS, S7 SZL, OPC UA), so they must key the recording.
            "site": (self.topology.site_name, self.topology.site_code, self.topology.domain),
            "hosts": [(h.id, h.name, h.device.name, h.loopback) for h in self.topology.hosts],
        }
        digest = hashlib.sha256(b'{"actions": [')  # "actions" sorts before every other key
        for index, a in enumerate(self.actions):
            item = json.dumps((a.t, a.host, a.op, a.args, a.phase), sort_keys=True, default=str)
            digest.update(((", " if index else "") + item).encode())
        digest.update(("], " + json.dumps(rest, sort_keys=True, default=str)[1:]).encode())
        return digest.hexdigest()[:24]


def _start_epoch(site: dict, rng: Rng) -> float:
    years = site.get("year_range", [2025, 2026])
    weekdays = site.get("weekdays", [0, 1, 2, 3, 4])
    lo, hi = site.get("start_hours", [7, 18])
    while True:
        day = dt.date(rng.randint(*years), 1, 1) + dt.timedelta(days=rng.randrange(365))
        if day.weekday() in weekdays:
            break
    start = dt.datetime(day.year, day.month, day.day, tzinfo=dt.UTC) + dt.timedelta(
        hours=rng.uniform(lo, hi))
    return round(start.timestamp(), 6)


def _draw_vars(raw: dict, rng: Rng) -> dict:
    """Resolve per-seed variation: `{choose: [...]}` picks one item, `{range: [lo, hi]}`
    an integer in the inclusive range. Plain values pass through unchanged."""
    drawn = {}
    for name, value in raw.items():
        if isinstance(value, dict) and set(value) == {"choose"}:
            drawn[name] = rng.child(name).choice(value["choose"])
        elif isinstance(value, dict) and set(value) == {"range"}:
            drawn[name] = rng.child(name).randint(*value["range"])
        else:
            drawn[name] = value
    return drawn


def build_plan(scenario: Scenario, difficulty: str, seed: str, base_seed: str | None = None,
               duration_override: float | None = None) -> Plan:
    from pcapforge.actors import create_actor

    level = scenario.level(difficulty)
    base = base_seed if base_seed is not None else seed
    rng = Rng("pcapforge", scenario.id, difficulty, base)
    vars_ = _draw_vars(level.get("vars", {}), rng.child("vars"))
    topology = Topology(scenario.doc, vars_, rng.child("world"))
    plan = Plan(
        scenario=scenario,
        difficulty=difficulty,
        seed=str(seed),
        base_seed=str(base),
        vars=vars_,
        duration=duration_override or parse_duration(level["duration"]),
        impairments=dict(level.get("impairments", {})),
        start_epoch=_start_epoch(scenario.doc.get("site", {}), rng.child("clock")),
        topology=topology,
        rng=rng,
    )
    ctx = {"vars": vars_}
    for spec in scenario.doc["actors"]:
        if not evaluate_when(spec.get("when"), ctx):
            continue
        hosts_ref = resolve(spec["hosts"], ctx)
        hosts = topology.select(hosts_ref)
        params = resolve(spec.get("params", {}), ctx)
        actor = create_actor(spec["type"], spec["id"], hosts, params, bool(spec.get("incident")),
                             plan, rng.child(f"actor:{spec['id']}"))
        plan.actors.append(actor)
    # A DHCP client that joins and / or leaves during the capture is connected only for that window, and
    # one that joins arrives (its IPv6 start is in the capture); set before planning, so every actor sees it.
    for actor in plan.actors:
        if actor.type == "dhcp.client":
            for host in actor.hosts:
                joined, gone = actor.window(host)
                if joined is not None or gone < plan.duration:
                    host.present = (joined or 0.0, gone)
                host.arrives = host.arrives or joined is not None
    # Servers first so clients can look them up; incident actors last so they can see
    # the background they hide in.
    for actor in sorted(plan.actors, key=lambda a: (a.incident, not a.is_server)):
        actor.plan()
    plan.finalize()
    return plan
