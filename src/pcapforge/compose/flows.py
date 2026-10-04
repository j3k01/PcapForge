"""Flow and action assignment: map every recorded packet to its conversation and action."""

from __future__ import annotations

import socket
import struct
from typing import TYPE_CHECKING, Iterable

from pcapforge import ports
from pcapforge.compose.packets import (
    ACK, FIN, K_ACK, K_DATA, K_FIN, K_RST, K_SYN, K_SYNACK, RST, SYN, TCP, UDP, ComposeError, Flow,
    Packet,
)
from pcapforge.record import parse_marker
from pcapforge.topology import MARKER_SINK

if TYPE_CHECKING:
    from pcapforge.plan import Plan

_TCP_HEADER = struct.Struct("!HHIIBB")
_UDP_HEADER = struct.Struct("!HHH")
SEQ_MASK = 0xFFFFFFFF


def _kind(proto: int, flags: int, payload: bytes) -> str:
    if proto == UDP:
        return K_DATA
    if flags & RST:
        return K_RST
    if flags & SYN:
        return K_SYNACK if flags & ACK else K_SYN
    if payload:
        return K_DATA
    if flags & FIN:
        return K_FIN
    return K_ACK


def assign_flows(plan: Plan, records: Iterable[bytes]) -> list[Packet]:
    """Packets that belong in the output, in recorded order, each bound to flow and action.

    Markers set the current action; a client packet with payload/SYN/FIN binds its flow to
    it and every other packet inherits the flow's action. Packets before the first marker,
    of ``teardown`` actions and (with ``impairments.mid_session``) of ``setup`` actions are
    dropped.
    """
    hosts = {socket.inet_aton(h.loopback): h for h in plan.topology.hosts}
    sink = socket.inet_aton(MARKER_SINK)
    actions = {a.id: a for a in plan.actions}
    mid_session = bool(plan.impairments.get("mid_session"))
    current = None
    live: dict[tuple, Flow] = {}
    packets: list[Packet] = []

    for order, ip in enumerate(records):
        ihl = (ip[0] & 0x0F) * 4
        total = int.from_bytes(ip[2:4], "big")
        if int.from_bytes(ip[6:8], "big") & 0x3FFF:  # fragment
            continue
        proto = ip[9]
        src, dst = ip[12:16], ip[16:20]
        l4 = ip[ihl:total]
        if proto == TCP and len(l4) >= 20:
            sport, dport, seq, ack, offset, flags = _TCP_HEADER.unpack_from(l4)
            payload = l4[(offset >> 4) * 4:]
        elif proto == UDP and len(l4) >= 8:
            sport, dport, length = _UDP_HEADER.unpack_from(l4)
            seq = ack = flags = 0
            payload = l4[8:length]
        else:
            continue

        if proto == UDP and dst == sink and dport == ports.MARKER:
            action_id = parse_marker(payload)
            if action_id is not None:
                if action_id not in actions:
                    raise ComposeError(f"recording marker for unknown action {action_id}; "
                                       "the recording does not belong to this plan")
                current = actions[action_id]
            continue
        src_host, dst_host = hosts.get(src), hosts.get(dst)
        if src_host is None or dst_host is None or current is None:
            continue

        here, there = (src, sport), (dst, dport)
        key = (proto, here, there) if here < there else (proto, there, here)
        flow = live.get(key)
        if proto == TCP:
            if flags & SYN and not flags & ACK:
                if flow is None or flow.endpoints[0] != here or flow.isn[0] != seq:
                    flow = live[key] = Flow(TCP, (src_host, dst_host), (here, there))
            elif flow is None:
                flow = live[key] = _guess_flow(TCP, src_host, dst_host, here, there)
        elif flow is None or (flow.endpoints[0] == here and flow.action is not current):
            # Every client datagram of a new action is a new exchange (new client socket).
            flow = live[key] = _guess_flow(UDP, src_host, dst_host, here, there)

        side = 0 if flow.endpoints[0] == here else 1
        kind = _kind(proto, flags, payload)
        if proto == TCP:
            if flow.isn[side] is None or flags & SYN:
                flow.isn[side] = seq if flags & SYN else (seq - 1) & SEQ_MASK
            if flags & ACK and flow.isn[1 - side] is None:
                flow.isn[1 - side] = (ack - 1) & SEQ_MASK
            sent, flow.sent[side] = flow.sent[side], (seq, ack)
            if sent == (seq, ack) and kind == K_ACK:
                # Window update of the loopback stack: the composed windows are constant,
                # so it would only show up as a duplicate ACK.
                continue
        if side == 0 and (payload or proto == UDP or flags & (SYN | FIN)):
            flow.action = current
        action = flow.action
        if action is None or action.phase == "teardown" or (action.phase == "setup" and mid_session):
            continue
        packets.append(Packet(order, flow, side, kind, flags, seq, ack, bytes(payload), action))
    return packets


def _guess_flow(proto: int, src_host, dst_host, here: tuple, there: tuple) -> Flow:
    """Flow whose opening was not seen: the side on a service port is the server."""
    if proto == TCP and here[1] in ports.WELL_KNOWN and there[1] not in ports.WELL_KNOWN:
        return Flow(proto, (dst_host, src_host), (there, here))
    return Flow(proto, (src_host, dst_host), (here, there))
