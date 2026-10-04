"""Actor interface.

An actor *plans* deterministic actions at virtual times and later *executes* them against
real local services while the recorder captures the loopback traffic.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar

if TYPE_CHECKING:
    from pcapforge.plan import Action, Plan
    from pcapforge.record import Runtime
    from pcapforge.rng import Rng
    from pcapforge.topology import Host


class Actor:
    type: ClassVar[str] = ""
    is_server: ClassVar[bool] = False

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

    # helpers -------------------------------------------------------------------
    def param(self, name: str, default: Any = None) -> Any:
        return self.params.get(name, default)

    def span(self, value: Any) -> tuple[float, float]:
        """Accept a scalar or a [lo, hi] pair."""
        if isinstance(value, (list, tuple)):
            return float(value[0]), float(value[1])
        return float(value), float(value)
