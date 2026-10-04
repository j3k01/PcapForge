"""Actor interface.

An actor *plans* deterministic actions at virtual times and later *executes* them against
real local services while the recorder captures the loopback traffic.
"""

from __future__ import annotations

import importlib
from types import ModuleType
from typing import TYPE_CHECKING, Any, ClassVar

from pcapforge.scenario import ScenarioError

if TYPE_CHECKING:
    from pcapforge.plan import Action, Plan
    from pcapforge.record import Runtime
    from pcapforge.rng import Rng
    from pcapforge.topology import Host


def optional_import(actor_type: str, module: str, distribution: str, extra: str) -> ModuleType:
    """Import an optional dependency or name the pcapforge extra that installs it."""
    try:
        return importlib.import_module(module)
    except ImportError as exc:
        raise ScenarioError(
            f"{actor_type} needs {distribution}: install the optional extra with "
            f"pip install 'pcapforge[{extra}]' (pip install -e .[{extra}] in a checkout)") from exc


class Actor:
    type: ClassVar[str] = ""
    is_server: ClassVar[bool] = False
    # (sink name, recording port) pairs the actor sends one-way datagrams to; the recorder
    # binds discard sockets on them so the OS answers with no ICMP port unreachable.
    sinks: ClassVar[tuple[tuple[str, int], ...]] = ()
    # Optional package the actor records with: (import name, distribution, extra). The recorder
    # checks it before capturing, so a missing extra fails fast with the install command.
    requires: ClassVar[tuple[str, str, str] | None] = None

    def __init__(self, id: str, hosts: list[Host], params: dict[str, Any], incident: bool,
                 plan: Plan, rng: Rng) -> None:
        self.id = id
        self.hosts = hosts
        self.params = params
        self.incident = incident
        self.plan_ = plan
        self.rng = rng

    def plan(self) -> None:
        """Append actions / facts / events to ``self.plan_``."""

    async def serve(self, rt: Runtime) -> None:
        """Start listening services (server actors only)."""

    def execute(self, action: Action, rt: Runtime) -> None:
        raise NotImplementedError(f"{self.type} has no client actions")

    def close(self, rt: Runtime) -> None:
        """Release client resources at the end of the recording."""

    def check(self) -> None:
        """Raise ``ScenarioError`` when the recording needs a package that is not installed."""
        if self.requires is not None:
            optional_import(self.type, *self.requires)

    # helpers -------------------------------------------------------------------
    def param(self, name: str, default: Any = None) -> Any:
        return self.params.get(name, default)

    def span(self, value: Any) -> tuple[float, float]:
        """Accept a scalar or a [lo, hi] pair."""
        if isinstance(value, (list, tuple)):
            return float(value[0]), float(value[1])
        return float(value), float(value)
