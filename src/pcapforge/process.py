"""Deterministic physical-process simulation backing simulated PLC registers.

The simulator runs on *virtual* scenario time (seconds since capture start), so a
recording made at high speed still reports values consistent with the final timeline.
"""

from __future__ import annotations

import math
import struct
from collections.abc import Sequence
from dataclasses import dataclass

from pcapforge.profiles import process_doc
from pcapforge.rng import Rng

TABLES = ("coils", "discrete", "holding", "input")
BIT_TABLES = ("coils", "discrete")
# Function code -> table it reads or writes.
FUNCTION_TABLE = {1: "coils", 2: "discrete", 3: "holding", 4: "input", 5: "coils", 6: "holding",
                  15: "coils", 16: "holding", 23: "holding"}
# Register encodings of a point in the holding / input tables and how many registers each takes.
# `uint16`: engineering value * scale in one unsigned register. `float32`: IEEE 754 single
# precision across two consecutive registers, in the profile's `word_order` - `big` (ABCD, high
# word first) or `little` (CDAB, low word first, the "Modicon float" of many PLCs and meters).
REGISTER_TYPES = {"uint16": 1, "float32": 2}
WORD_ORDERS = ("big", "little")


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
    desc: str = ""
    type: str = "uint16"
    word_order: str = "big"

    @property
    def words(self) -> int:
        """Registers (or bits) the point occupies, starting at ``address``."""
        return 1 if self.table in BIT_TABLES else REGISTER_TYPES[self.type]

    @property
    def addresses(self) -> range:
        return range(self.address, self.address + self.words)

    def encode(self, value: float) -> list[int]:
        """Wire values (bits or 16-bit registers, in address order) that carry ``value``."""
        if self.table in BIT_TABLES:
            return [1 if value >= 0.5 else 0]
        if self.type == "float32":
            high, low = struct.unpack(">HH", struct.pack(">f", value))
            return [high, low] if self.word_order == "big" else [low, high]
        raw = round(value * self.scale)
        if self.model and self.model.get("type") == "counter":
            return [raw % 65536]
        return [min(max(raw, 0), 65535)]

    def decode(self, raw: Sequence[int]) -> float:
        """Engineering value of the point's wire values (as returned by ``encode``)."""
        if self.table in BIT_TABLES:
            return float(bool(raw[0]))
        if self.type == "float32":
            high, low = (raw[0], raw[1]) if self.word_order == "big" else (raw[1], raw[0])
            # 7 significant digits: what float32 resolves, so 11.6 reads back as 11.6, not 11.600000381.
            return float(f"{struct.unpack('>f', struct.pack('>HH', high, low))[0]:.7g}")
        return raw[0] / self.scale

    def quantize(self, value: float) -> float:
        """``value`` as the PLC stores it (rounded to the register's resolution)."""
        return self.decode(self.encode(value))

    def typed(self, value: float) -> float:
        """A setpoint as an engineer types it into the HMI or engineering tool: at the register's
        resolution, or with two decimals for a float32."""
        return round(value, 2) if self.type == "float32" else round(value * self.scale) / self.scale

    def in_normal(self, value: float) -> bool:
        return self.normal is None or self.normal[0] <= value <= self.normal[1]


class ProcessProfile:
    def __init__(self, name: str) -> None:
        doc = process_doc(name)
        self.id: str = doc["id"]
        self.title: str = doc["title"]
        self.titles: dict[str, str] = {lang: t["title"] for lang, t in doc.get("translations", {}).items()}
        self.unit_id: int = doc.get("unit_id", 1)
        self.word_order: str = doc.get("word_order", "big")
        if self.word_order not in WORD_ORDERS:
            raise ValueError(f"process '{self.id}': word_order must be one of {WORD_ORDERS}")
        self.points: list[Point] = []
        for table in TABLES:
            for raw in doc.get(table, []):
                kind = raw.get("type", "uint16")
                if kind not in REGISTER_TYPES or (table in BIT_TABLES and kind != "uint16"):
                    raise ValueError(f"process '{self.id}': {raw['name']} has an invalid type '{kind}'")
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
                    desc=raw.get("desc", ""),
                    type=kind,
                    word_order=self.word_order,
                ))
        self.by_name = {p.name: p for p in self.points}
        # Every register (or bit) a point occupies -> the point; a float32 owns two registers.
        self.by_register: dict[tuple[str, int], Point] = {}
        for p in self.points:
            for address in p.addresses:
                if (p.table, address) in self.by_register:
                    raise ValueError(f"process '{self.id}': {p.name} overlaps "
                                     f"{self.by_register[(p.table, address)].name} at {p.table} {address}")
                self.by_register[(p.table, address)] = p
        self.poll_groups: list[dict] = doc.get("poll_groups", [])
        self.operator_adjustable: list[dict] = doc.get("operator_adjustable", [])
        # Optional vendor register-numbering convention for the handout, e.g. the Modicon
        # data model {coils: 1, discrete: 10001, input: 30001, holding: 40001}. The wire stays
        # 0-based; this only changes how the register map is labelled for the student.
        self.register_style: dict[str, int] = doc.get("register_style", {})

    def register_label(self, point: Point) -> str:
        """The register's address as the student sees it: the vendor number when the profile
        defines a ``register_style``, otherwise the 0-based wire address. A float32 shows the
        pair it occupies (``40003-40004``)."""
        base = self.register_style.get(point.table, 0)
        first, last = base + point.address, base + point.address + point.words - 1
        return str(first) if first == last else f"{first}-{last}"

    def table(self, table: str) -> list[Point]:
        return sorted((p for p in self.points if p.table == table), key=lambda p: p.address)

    def size(self, table: str) -> int:
        """Registers (or bits) the table spans from address 0."""
        points = self.table(table)
        return points[-1].address + points[-1].words if points else 0

    def decode_block(self, table: str, start: int, values: Sequence[int]) -> list[tuple[Point, float]]:
        """Points whose every register lies inside ``values`` (the wire values read or written
        from ``start`` on), with their engineering values, in address order. A point cut off by
        the block's edges (half a float32) is left out."""
        out = []
        for p in self.table(table):
            offset = p.address - start
            if offset >= 0 and offset + p.words <= len(values):
                out.append((p, p.decode(values[offset:offset + p.words])))
        return out


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
                value = rng.uniform(max(lo, p.nominal - (hi - lo) * 0.15), min(hi, p.nominal + (hi - lo) * 0.15))
                value = p.typed(value)
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

    def values(self, table: str) -> dict[str, float]:
        """Current engineering value of every point of a table (by name), as the PLC stores it."""
        return {p.name: p.quantize(self._sample(p)) for p in self.profile.table(table)}

    def read(self, table: str) -> dict[int, int]:
        """Wire values (16-bit registers or bits) of a table, keyed by address."""
        out: dict[int, int] = {}
        for p in self.profile.table(table):
            for offset, word in enumerate(p.encode(self._sample(p))):
                out[p.address + offset] = word
        return out

    def write(self, table: str, address: int, raw_values: list[int]) -> None:
        """Apply written registers / bits. A write covering only part of a float32 replaces those
        words of the stored value, as a PLC would."""
        end = address + len(raw_values)
        for p in self.profile.table(table):
            if not p.writable or p.address >= end or p.address + p.words <= address:
                continue
            words = p.encode(self.state[p.name])
            for offset in range(p.words):
                if address <= p.address + offset < end:
                    words[offset] = int(raw_values[p.address + offset - address])
            self.state[p.name] = p.decode(words)
        self._update_bits()

    def value(self, name: str) -> float:
        return self.state[name]
