"""Reading the loopback recording and the packet / flow records the composer works on."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Iterator

from scapy.utils import RawPcapReader

if TYPE_CHECKING:
    from pcapforge.plan import Action
    from pcapforge.topology import Host, Sink

TCP = 6
UDP = 17

FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10

# Packet kinds driving the causal timing model.
K_SYN, K_SYNACK, K_DATA, K_FIN, K_RST, K_ACK = "syn", "synack", "data", "fin", "rst", "ack"


class ComposeError(RuntimeError):
    pass


def _strip_null(frame: bytes) -> bytes:  # DLT_NULL / DLT_LOOP: 4-byte address family
    return frame[4:]


def _strip_ethernet(frame: bytes) -> bytes | None:
    offset = 12
    ethertype = frame[12:14]
    while ethertype in (b"\x81\x00", b"\x88\xa8"):  # 802.1Q / 802.1ad tags
        offset += 4
        ethertype = frame[offset:offset + 2]
    return frame[offset + 2:] if ethertype == b"\x08\x00" else None


def _strip_sll(frame: bytes) -> bytes | None:  # Linux cooked capture v1
    return frame[16:] if frame[14:16] == b"\x08\x00" else None


def _strip_sll2(frame: bytes) -> bytes | None:  # Linux cooked capture v2
    return frame[20:] if frame[0:2] == b"\x08\x00" else None


def _strip_raw(frame: bytes) -> bytes:
    return frame


LINK_TYPES: dict[int, Callable[[bytes], bytes | None]] = {
    0: _strip_null, 108: _strip_null, 1: _strip_ethernet, 113: _strip_sll, 276: _strip_sll2,
    101: _strip_raw, 228: _strip_raw,
}


def read_ipv4(path: Path) -> Iterator[bytes]:
    """IPv4 packets of a pcap/pcapng recording, link layer removed, in capture order."""
    with RawPcapReader(str(path)) as reader:
        default = getattr(reader, "linktype", None)
        for data, meta in reader:
            linktype = getattr(meta, "linktype", None)
            if linktype is None:
                linktype = default
            strip = LINK_TYPES.get(linktype)
            if strip is None:
                raise ComposeError(f"{path}: unsupported link type {linktype}")
            packet = strip(data)
            if packet and len(packet) >= 20 and packet[0] >> 4 == 4:
                yield packet


@dataclass(eq=False, slots=True)
class Flow:
    """One transport conversation of the recording (a TCP connection or a UDP exchange)."""

    proto: int
    hosts: tuple[Host, Host | Sink]                 # (client, server); a sink only receives
    endpoints: tuple[tuple[bytes, int], tuple[bytes, int]]  # recorded (ip, port) of client, server
    isn: list[int | None] = field(default_factory=lambda: [None, None])  # recorded ISNs (TCP)
    sent: list[tuple[int, int] | None] = field(default_factory=lambda: [None, None])  # last (seq, ack)
    action: Action | None = None                    # action the flow is currently bound to

    @property
    def client_port(self) -> int:
        return self.endpoints[0][1]

    @property
    def server_port(self) -> int:
        return self.endpoints[1][1]


@dataclass(eq=False, slots=True)
class Packet:
    order: int          # position in the recording (stable tie-break)
    flow: Flow
    side: int           # 0: client -> server, 1: server -> client
    kind: str
    flags: int          # TCP flags (0 for UDP)
    seq: int
    ack: int
    payload: bytes
    action: Action
    time: float = 0.0
    retransmission: bool = False

    @property
    def src(self) -> Host:
        return self.flow.hosts[self.side]

    @property
    def dst(self) -> Host | Sink:
        return self.flow.hosts[1 - self.side]

    @property
    def is_request(self) -> bool:
        """Client-sent packet carrying application data (the action's request)."""
        return self.side == 0 and (bool(self.payload) or self.flow.proto == UDP)
