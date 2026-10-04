"""IPv4 / TCP / UDP header rebuild with the final addressing and per-OS stack behaviour."""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass
from typing import TYPE_CHECKING

from pcapforge import ports
from pcapforge.compose.packets import ACK, SYN, TCP, UDP, Flow, Packet
from pcapforge.topology import Sink

if TYPE_CHECKING:
    from pcapforge.plan import Plan
    from pcapforge.profiles import Stack
    from pcapforge.rng import Rng
    from pcapforge.topology import Host

M32 = 0xFFFFFFFF
_IP = struct.Struct("!BBHHHBBH4s4s")
_TCP = struct.Struct("!HHIIBBHHH")
_UDP = struct.Struct("!HHHH")
_DNS_RR = struct.Struct("!HHIH")


def checksum(data: bytes) -> int:
    """RFC 1071 Internet checksum (sum of 16-bit words mod 0xFFFF == value mod 0xFFFF)."""
    if len(data) & 1:
        data += b"\x00"
    rest = int.from_bytes(data, "big") % 0xFFFF
    return 0xFFFF - rest if rest else 0


# -- TCP options ------------------------------------------------------------------------

def _option_list(stack: Stack, offered: set[str] | None, ts_ok: bool) -> list[str]:
    """Options of a SYN (``offered`` is None) or SYN-ACK (only what the client offered)."""
    names: list[str] = []
    for name in stack.syn_options:
        dropped = (
            (name == "ws" and stack.window_scale is None)
            or (name == "ts" and not (stack.timestamps if offered is None else ts_ok))
            or (offered is not None and name in ("ws", "sack_perm") and name not in offered)
        )
        if dropped:
            while names and names[-1] == "nop":  # alignment padding of the dropped option
                names.pop()
        else:
            names.append(name)
    while names and names[-1] == "nop":
        names.pop()
    length = sum(_OPTION_SIZE[n] for n in names)
    if length % 4 == 2 and "sack_perm" in names and names[names.index("sack_perm") - 1] != "nop":
        index = names.index("sack_perm")
        names[index:index] = ["nop", "nop"]  # Linux pads SACK-permitted when there is no TS
    return names


_OPTION_SIZE = {"mss": 4, "nop": 1, "ws": 3, "sack_perm": 2, "ts": 10}


def _encode_options(names: list[str], stack: Stack, tsval: int, tsecr: int) -> bytes:
    out = bytearray()
    for name in names:
        if name == "mss":
            out += struct.pack("!BBH", 2, 4, stack.mss)
        elif name == "nop":
            out.append(1)
        elif name == "ws":
            out += bytes((3, 3, stack.window_scale))
        elif name == "sack_perm":
            out += b"\x04\x02"
        elif name == "ts":
            out += struct.pack("!BBII", 8, 10, tsval, tsecr)
    out += b"\x00" * (-len(out) % 4)
    return bytes(out)


# -- DNS --------------------------------------------------------------------------------

def _skip_name(data: bytes, offset: int) -> int:
    while True:
        length = data[offset]
        if length == 0:
            return offset + 1
        if length & 0xC0 == 0xC0:
            return offset + 2
        offset += length + 1


def rewrite_a_records(payload: bytes, remap) -> bytes:
    """Replace A-record addresses for which ``remap(rdata) -> bytes | None`` has a mapping."""
    try:
        qdcount, ancount, nscount, arcount = struct.unpack_from("!HHHH", payload, 4)
        offset = 12
        for _ in range(qdcount):
            offset = _skip_name(payload, offset) + 4
        out = None
        for _ in range(ancount + nscount + arcount):
            offset = _skip_name(payload, offset)
            rtype, rclass, _ttl, rdlength = _DNS_RR.unpack_from(payload, offset)
            offset += _DNS_RR.size
            if rtype == 1 and rclass == 1 and rdlength == 4:
                new = remap(payload[offset:offset + 4])
                if new is not None:
                    out = out if out is not None else bytearray(payload)
                    out[offset:offset + 4] = new
            offset += rdlength
    except (IndexError, struct.error):
        return payload
    return bytes(out) if out is not None else payload


# -- NetBIOS datagram service --------------------------------------------------------------

def rewrite_nbdgm_source(payload: bytes, remap) -> bytes:
    """Replace the header's source IP when ``remap(ip) -> bytes | None`` has a mapping."""
    if len(payload) < 14:
        return payload
    new = remap(payload[4:8])
    return payload if new is None else payload[:4] + new + payload[8:]


# -- per-flow state ---------------------------------------------------------------------

@dataclass(slots=True)
class _FlowHeaders:
    addrs: tuple[bytes, bytes]       # final IP of client, server (as seen by each other)
    ports: tuple[int, int]           # final client, server port
    stacks: tuple[Stack, Stack]
    ttl: tuple[int, int]             # IP TTL per side before routed hops
    df: tuple[bool, bool]
    isn: tuple[int, int]             # final ISN client, server
    ipid: list[int]                  # per-flow IP-ID counters (per_flow stacks)
    ts_base: tuple[int, int]         # TSval clock offset per side
    ts_last: list[int]               # last TSval sent per side
    offered: set[str]                # options in the client's SYN
    ws: bool
    ts: bool


class Headers:
    """Builds final IPv4 packets in capture-time order (IP-ID / TS clocks advance with time)."""

    def __init__(self, plan: Plan, rng: Rng) -> None:
        self.topology = plan.topology
        self.start = plan.start_epoch
        self.rng = rng
        self.flows: dict[Flow, _FlowHeaders] = {}
        self.host_ipid: dict[str, int] = {}
        self.port_cursor: dict[str, int] = {}
        self.ports_used: dict[str, set[int]] = {}
        self.loopback = {socket.inet_aton(h.loopback): h for h in self.topology.hosts}
        self._addr: dict[tuple[str, str], bytes] = {}

    def address(self, host: Host | Sink, peer: Host | Sink) -> bytes:
        key = (host.id, peer.id)
        addr = self._addr.get(key)
        if addr is None:
            if isinstance(host, Sink):
                ip = self.topology.sink_address(host, peer)
            else:
                ip = self.topology.address_towards(host, peer).ip
            addr = self._addr[key] = socket.inet_aton(ip)
        return addr

    # -- flow setup -------------------------------------------------------------------
    def _flow(self, flow: Flow) -> _FlowHeaders:
        state = self.flows.get(flow)
        if state is not None:
            return state
        rng = self.rng
        client, server = flow.hosts
        cstack = client.device.stack
        if isinstance(server, Sink):
            # One-way datagram to a group / the broadcast address: the sink never answers.
            sstack = cstack
            ttl = cstack.link_local.ttl.get(server.group, cstack.ttl)
            ttls, dfs = (ttl, ttl), (cstack.link_local.df, cstack.link_local.df)
        else:
            sstack = server.device.stack
            ttls, dfs = (cstack.ttl, sstack.ttl), (cstack.df, sstack.df)
        offered = set(_option_list(cstack, None, False)) if flow.proto == TCP else set()
        state = self.flows[flow] = _FlowHeaders(
            addrs=(self.address(client, server), self.address(server, client)),
            ports=(self._client_port(flow), ports.WELL_KNOWN.get(flow.server_port, flow.server_port)),
            stacks=(cstack, sstack),
            ttl=ttls,
            df=dfs,
            isn=(rng.getrandbits(32), rng.getrandbits(32)),
            ipid=[rng.randrange(65536), rng.randrange(65536)],
            ts_base=(rng.getrandbits(32), rng.getrandbits(32)),
            ts_last=[0, 0],
            offered=offered,
            ws="ws" in offered and "ws" in sstack.syn_options and sstack.window_scale is not None,
            ts=cstack.timestamps and sstack.timestamps and "ts" in offered and "ts" in sstack.syn_options,
        )
        return state

    def _client_port(self, flow: Flow) -> int:
        recorded = flow.client_port
        if recorded in ports.WELL_KNOWN:  # e.g. w32time sends from 123
            return ports.WELL_KNOWN[recorded]
        host = flow.hosts[0]
        stack = host.device.stack
        lo, hi = stack.ephemeral_ports
        used = self.ports_used.setdefault(host.id, set())
        if len(used) > (hi - lo) // 2:
            used.clear()  # long captures: old connections have left TIME_WAIT
        rng = self.rng
        if stack.port_allocation == "sequential":
            cursor = self.port_cursor.get(host.id)
            if cursor is None:
                cursor = rng.randint(lo, hi)
            # Other processes on the host take ports in between now and then.
            port = cursor + (1 if rng.random() < 0.7 else rng.randint(2, 6))
            while True:
                if port > hi:
                    port = lo + (port - hi - 1)
                if port not in used:
                    break
                port += 1
            self.port_cursor[host.id] = port
        else:
            port = rng.randint(lo, hi)
            while port in used:
                port = rng.randint(lo, hi)
        used.add(port)
        return port

    def _ipid(self, state: _FlowHeaders, side: int, host: Host) -> int:
        if state.stacks[side].ip_id == "per_flow":
            value = state.ipid[side]
            state.ipid[side] = (value + 1) & 0xFFFF
            return value
        value = self.host_ipid.get(host.id)
        if value is None:
            value = self.rng.randrange(65536)
        self.host_ipid[host.id] = (value + 1) & 0xFFFF
        return value

    # -- packets ----------------------------------------------------------------------
    def skip(self, p: Packet) -> None:
        """Account for a packet the sensor does not see (it still uses ports and IP-IDs)."""
        state = self._flow(p.flow)
        self._ipid(state, p.side, p.src)

    def build(self, p: Packet, hops: int) -> bytes:
        flow = p.flow
        state = self._flow(flow)
        side = p.side
        src, dst = state.addrs[side], state.addrs[1 - side]
        sport, dport = state.ports[side], state.ports[1 - side]
        if flow.proto == TCP:
            l4 = self._tcp(p, state, sport, dport)
        else:
            payload = p.payload
            if side == 1 and flow.server_port == ports.DNS:
                payload = rewrite_a_records(payload, lambda rdata: self._dns_address(rdata, flow))
            elif side == 0 and flow.server_port == ports.NBDGM:
                payload = rewrite_nbdgm_source(payload, lambda ip: self._own_address(ip, flow))
            l4 = _UDP.pack(sport, dport, 8 + len(payload), 0) + payload
        pseudo = src + dst + bytes((0, flow.proto)) + len(l4).to_bytes(2, "big")
        csum = checksum(pseudo + l4)
        if flow.proto == UDP and csum == 0:
            csum = 0xFFFF
        offset = 16 if flow.proto == TCP else 6
        l4 = l4[:offset] + csum.to_bytes(2, "big") + l4[offset + 2:]
        header = _IP.pack(0x45, 0, 20 + len(l4), self._ipid(state, side, p.src),
                          0x4000 if state.df[side] else 0, max(state.ttl[side] - hops, 1), flow.proto, 0,
                          src, dst)
        header = header[:10] + checksum(header).to_bytes(2, "big") + header[12:]
        return header + l4

    def _tcp(self, p: Packet, state: _FlowHeaders, sport: int, dport: int) -> bytes:
        flow = p.flow
        side = p.side
        stack = state.stacks[side]
        seq = (p.seq - flow.isn[side] + state.isn[side]) & M32
        ack = (p.ack - flow.isn[1 - side] + state.isn[1 - side]) & M32 if p.flags & ACK else 0
        tsval = tsecr = 0
        if state.ts or (p.flags & SYN and "ts" in state.offered and side == 0):
            tsval = (state.ts_base[side] + int((p.time - self.start) * 1000.0)) & M32
            tsecr = state.ts_last[1 - side] if p.flags & ACK else 0
            state.ts_last[side] = tsval
        if p.flags & SYN:
            window = stack.syn_window
            names = _option_list(stack, state.offered if side == 1 else None, state.ts)
            options = _encode_options(names, stack, tsval, tsecr)
        else:
            window = stack.window if state.ws else stack.syn_window
            options = struct.pack("!BBBBII", 1, 1, 8, 10, tsval, tsecr) if state.ts else b""
        header = _TCP.pack(sport, dport, seq, ack, (20 + len(options)) << 2, p.flags & 0x3F,
                           min(window, 0xFFFF), 0, 0)
        return header + options + p.payload

    def _dns_address(self, rdata: bytes, flow: Flow) -> bytes | None:
        host = self.loopback.get(rdata)
        return None if host is None else self.address(host, flow.hosts[0])

    def _own_address(self, ip: bytes, flow: Flow) -> bytes | None:
        """Final address of the host whose loopback ``ip`` is, as the flow's server sees it."""
        host = self.loopback.get(ip)
        return None if host is None else self.address(host, flow.hosts[1])
