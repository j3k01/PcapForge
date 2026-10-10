"""Host firewall model: a host that drops unsolicited SYNs instead of refusing them."""

from __future__ import annotations

from dataclasses import replace
from typing import Callable

from pcapforge.compose.packets import K_DATA, K_RST, K_SYN, K_SYNACK, TCP, Packet
from pcapforge.topology import Sink

_ANSWERED = {K_SYNACK, K_DATA}
_RETRANSMITTED = "syn_retransmitted"   # marker in ``Flow.kinds``: the filtered SYN went out again


class HostFirewall:
    """A probe of a closed TCP port is refused with a RST on the loopback recording. If the target
    host's stack drops unsolicited connections (``drops_unsolicited``, e.g. the Windows Defender
    Firewall default), the port looks *filtered* instead: the RST never comes, and the client
    retransmits its SYN once (at its stack's ``syn_rto_s``) before giving up. Ports on hosts that
    refuse (Linux, the PLC stacks) keep their RST and read as *closed*. This is how a port sweep
    tells firewalled machines from listening-but-closed ones.

    A release stage of the ``Retimer``: it sees every timed packet (``observe``) and decides on
    each one as it leaves in capture order (``admit``), by which time a refused connection has
    shown its RST."""

    def observe(self, p: Packet) -> None:
        flow = p.flow
        if flow.proto == TCP:
            if flow.kinds is None:
                flow.kinds = set()
            flow.kinds.add(p.kind)

    def admit(self, p: Packet, insert: Callable[[Packet], None]) -> bool:
        """False for a packet the firewall removes; ``insert`` adds the SYN retransmission."""
        flow = p.flow
        if flow.proto != TCP:
            return True
        kinds = flow.kinds
        if K_RST not in kinds or K_SYN not in kinds or kinds & _ANSWERED:
            return True
        target = flow.hosts[1]
        if isinstance(target, Sink) or not target.device.stack.drops_unsolicited:
            return True  # closed port: the RST stands
        if p.kind == K_RST:
            return False
        if p.kind == K_SYN and p.side == 0 and _RETRANSMITTED not in kinds:
            kinds.add(_RETRANSMITTED)
            insert(replace(p, time=p.time + flow.hosts[0].device.stack.syn_rto_s, retransmission=True))
        return True
