"""Actor registry. Scenario `type:` values map to classes registered here."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pcapforge.scenario import ScenarioError

if TYPE_CHECKING:
    from pcapforge.actors.base import Actor

REGISTRY: dict[str, type[Actor]] = {}


def register(cls: type[Actor]) -> type[Actor]:
    REGISTRY[cls.type] = cls
    return cls


def _load_builtin() -> None:
    from pcapforge.actors import dns, modbus, ntp, opcua, s7, windows  # noqa: F401  (registration side effect)


def create_actor(type_: str, id_: str, hosts, params, incident, plan, rng) -> Actor:
    _load_builtin()
    if type_ not in REGISTRY:
        raise ScenarioError(f"unknown actor type '{type_}' (known: {', '.join(sorted(REGISTRY))})")
    return REGISTRY[type_](id_, hosts, params, incident, plan, rng)


def actor_types() -> list[str]:
    _load_builtin()
    return sorted(REGISTRY)
