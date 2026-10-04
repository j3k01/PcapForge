"""Deterministic physical-process simulation backing simulated PLC registers.

The simulator runs on *virtual* scenario time (seconds since capture start), so a
recording made at high speed still reports values consistent with the final timeline.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from pcapforge.profiles import process_doc
from pcapforge.rng import Rng

TABLES = ("coils", "discrete", "holding", "input")
BIT_TABLES = ("coils", "discrete")
# Function code -> table it reads or writes.
FUNCTION_TABLE = {1: "coils", 2: "discrete", 3: "holding", 4: "input", 5: "coils", 6: "holding",
                  15: "coils", 16: "holding", 23: "holding"}


@dataclass(frozen=True)
class Point:
    table: str
    address: int
    name: str
    unit: str
    scale: float
    nominal: float
    normal: tuple[float, float] | None
    writable: bool
    model: dict | None

    def encode(self, value: float) -> int:
        if self.table in BIT_TABLES:
            return 1 if value >= 0.5 else 0
        raw = round(value * self.scale)
        if self.model and self.model.get("type") == "counter":
            return raw % 65536
        return min(max(raw, 0), 65535)

    def decode(self, raw: int) -> float:
        if self.table in BIT_TABLES:
            return float(bool(raw))
        return raw / self.scale

    def in_normal(self, value: float) -> bool:
        return self.normal is None or self.normal[0] <= value <= self.normal[1]


class ProcessProfile:
    def __init__(self, name: str) -> None:
        doc = process_doc(name)
        self.id: str = doc["id"]
        self.title: str = doc["title"]
        self.titles: dict[str, str] = {lang: t["title"] for lang, t in doc.get("translations", {}).items()}
        self.unit_id: int = doc.get("unit_id", 1)
        self.points: list[Point] = []
        for table in TABLES:
            for raw in doc.get(table, []):
                self.points.append(Point(
                    table=table,
                    address=raw["address"],
                    name=raw["name"],
                    unit=raw.get("unit", ""),
                    scale=raw.get("scale", 1),
                    nominal=float(raw["nominal"]),
                    normal=tuple(raw["normal"]) if "normal" in raw else None,
                    writable=raw.get("writable", False),
                    model=raw.get("model"),
                ))
        self.by_name = {p.name: p for p in self.points}
        self.by_address = {(p.table, p.address): p for p in self.points}
        self.poll_groups: list[dict] = doc.get("poll_groups", [])
        self.operator_adjustable: list[dict] = doc.get("operator_adjustable", [])

    def table(self, table: str) -> list[Point]:
        return sorted((p for p in self.points if p.table == table), key=lambda p: p.address)

    def size(self, table: str) -> int:
        points = self.table(table)
        return points[-1].address + 1 if points else 0


class ProcessSim:
    """State of one PLC's process. ``advance`` must be called with non-decreasing time."""

    def __init__(self, profile: ProcessProfile, rng: Rng, start_hour: float) -> None:
        self.profile = profile
        self.rng = rng
        self.start_hour = start_hour
        self.t = 0.0
        self.state: dict[str, float] = {}
        for p in profile.points:
            value = p.nominal
            if p.model is None and p.normal and p.writable and p.table == "holding":
                # Each site runs slightly different setpoints, still inside the normal band.
                lo, hi = p.normal
                value = round(rng.uniform(max(lo, p.nominal - (hi - lo) * 0.15),
                                          min(hi, p.nominal + (hi - lo) * 0.15)) * p.scale) / p.scale
            self.state[p.name] = value
        # Lagging measurements start settled on their target.
        for p in profile.points:
            if p.model and p.model["type"] == "follow":
                self.state[p.name] = self._target(p.model)
        self._update_bits()

    def advance(self, t: float) -> None:
        dt = t - self.t
        if dt <= 0:
            return
        self.t = t
        for p in self.profile.points:
            m = p.model
            if not m:
                continue
            kind = m["type"]
            if kind == "follow":
                target = self._target(m)
                self.state[p.name] = target + (self.state[p.name] - target) * math.exp(-dt / m["tau"])
            elif kind == "walk":
                lo, hi = p.normal
                value = self.state[p.name] + self.rng.gauss(0.0, m["step"] * math.sqrt(dt))
                if value < lo:
                    value = 2 * lo - value
                if value > hi:
                    value = 2 * hi - value
                self.state[p.name] = min(max(value, lo), hi)
            elif kind == "counter":
                self.state[p.name] += m["rate"] * dt
        self._update_bits()

    def _target(self, m: dict) -> float:
        """Settling value of a ``follow`` model: weighted sum of its sources, optionally clamped."""
        by_name = self.profile.by_name
        target = self._sample(by_name[m["source"]], noise=False) * m.get("gain", 1.0) + m.get("offset", 0.0)
        for extra in m.get("inputs", ()):
            target += self._sample(by_name[extra["source"]], noise=False) * extra.get("gain", 1.0)
        if "limits" in m:
            lo, hi = m["limits"]
            target = min(max(target, lo), hi)
        return target

    def _update_bits(self) -> None:
        for p in self.profile.points:
            m = p.model
            if m and m["type"] in ("above", "below"):
                a = self._sample(self.profile.by_name[m["a"]], noise=False)
                b = m["b"]
                b = self.state[b] if isinstance(b, str) else float(b)
                self.state[p.name] = float(a > b if m["type"] == "above" else a < b)

    def _sample(self, p: Point, noise: bool = True) -> float:
        m = p.model
        if m and m["type"] == "daily":
            hour = self.start_hour + self.t / 3600.0
            value = p.nominal + m["amplitude"] * math.sin(2 * math.pi * (hour - m["phase_h"]) / 24.0)
        else:
            value = self.state[p.name]
        if noise and m and m.get("noise"):
            value += self.rng.gauss(0.0, m["noise"])
        return value

    def read(self, table: str) -> dict[int, int]:
        """Raw register/bit values of a table, keyed by address."""
        return {p.address: p.encode(self._sample(p)) for p in self.profile.table(table)}

    def write(self, table: str, address: int, raw_values: list[int]) -> None:
        for offset, raw in enumerate(raw_values):
            p = self.profile.by_address.get((table, address + offset))
            if p is not None and p.writable:
                self.state[p.name] = p.decode(int(raw))
        self._update_bits()

    def value(self, name: str) -> float:
        return self.state[name]
