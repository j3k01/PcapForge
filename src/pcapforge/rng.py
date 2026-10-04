"""Deterministic, named random streams.

Every consumer draws from its own child stream (``rng.child("topology")``), so adding
draws in one subsystem never shifts the values produced by another one.
"""

from __future__ import annotations

import hashlib
import random


def derive_seed(*parts: object) -> int:
    digest = hashlib.sha256("\x1f".join(str(p) for p in parts).encode()).digest()
    return int.from_bytes(digest[:8], "big")


class Rng(random.Random):
    def __init__(self, *parts: object) -> None:
        self.key = "/".join(str(p) for p in parts)
        super().__init__(derive_seed(self.key))

    def child(self, name: str) -> "Rng":
        return Rng(self.key, name)

    def jitter(self, value: float, fraction: float) -> float:
        """``value`` scaled by a uniform factor in ``[1 - fraction, 1 + fraction]``."""
        return value * self.uniform(1.0 - fraction, 1.0 + fraction)

    def lognormal_ms(self, median_ms: float, sigma: float) -> float:
        """Latency sample in seconds with the given median (ms) and log-sigma."""
        return self.lognormvariate(0.0, sigma) * median_ms / 1000.0
