"""DHCPv4 (RFC 2131 / 2132): the site's DHCP server and DHCP-managed hosts, over real UDP sockets.

While recording, clients talk to the server's loopback address from their own (the BOOTP
client port), so every exchange is one ordinary request/response conversation. Addresses in
the payload (yiaddr, ciaddr, server identifier, router, DNS, NTP, requested address) are
recording addresses and ``chaddr`` / client identifier carry a placeholder MAC derived from
the client's loopback address; the composer writes the final topology into them and puts the
messages on the wire the way RFC 2131 delivers them (``compose/dhcp.py``): a client without
an address sends from 0.0.0.0 to 255.255.255.255, the server answers to the broadcast address
when the client set the broadcast flag (Windows) and otherwise unicast to ``yiaddr`` / ``chaddr``
without ARP (Linux), and a client that has its address (renewal, release) talks unicast.

Client message formats follow the OS DHCP client (``style``):

* ``windows`` (Windows 10 DHCP client service): broadcast flag in DISCOVER / REQUEST, client
  identifier 01+MAC (61), host name (12), client FQDN (81, REQUEST only), vendor class
  ``MSFT 5.0`` (60), its parameter request list (55); a DHCPINFORM (WinHTTP proxy
  auto-detection asks for option 252) once the address is usable after joining;
* ``dhcpcd`` (dhcpcd 8 as configured by Raspberry Pi OS: ``clientid``, ``option rapid_commit``,
  ``option ntp_servers``, ``require dhcp_server_identifier``): no broadcast flag, client
  identifier 01+MAC, rapid commit (80, the server ignores it), maximum message size (57),
  vendor class ``dhcpcd-<version>:<kernel>:<machine>:<hardware>`` (60), host name (12).

The same transaction ID spans DISCOVER / OFFER / REQUEST / ACK; renewals, informs and
releases start new transactions. Messages are padded to the 300-byte BOOTP minimum.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import struct
from dataclasses import dataclass

from pcapforge import ports
from pcapforge.actors import register
from pcapforge.actors.base import Actor
from pcapforge.plan import action_ref, host_ref
from pcapforge.scenario import ScenarioError, parse_duration

BOOTREQUEST, BOOTREPLY = 1, 2
DISCOVER, OFFER, REQUEST, DECLINE, ACK, NAK, RELEASE, INFORM = range(1, 9)
MESSAGE_TYPES = {DISCOVER: "discover", OFFER: "offer", REQUEST: "request", DECLINE: "decline", ACK: "ack",
                 NAK: "nak", RELEASE: "release", INFORM: "inform"}
BROADCAST_FLAG = 0x8000
MAGIC_COOKIE = b"\x63\x82\x53\x63"
HEADER = struct.Struct("!BBBBIHH4s4s4s4s16s64s128s4s")  # fixed BOOTP part incl. the magic cookie (240 bytes)
MIN_SIZE = 300  # RFC 1542: BOOTP messages are padded to at least 300 bytes
PAD, END = 0, 255
# Option codes
SUBNET_MASK, ROUTER, DNS_SERVERS, HOST_NAME, DOMAIN_NAME, NTP_SERVERS = 1, 3, 6, 12, 15, 42
REQUESTED_IP, LEASE_TIME, MESSAGE_TYPE, SERVER_ID, PARAMETERS = 50, 51, 53, 54, 55
MAX_SIZE, RENEWAL_TIME, REBINDING_TIME, VENDOR_CLASS, CLIENT_ID = 57, 58, 59, 60, 61
RAPID_COMMIT, CLIENT_FQDN = 80, 81
T1, T2 = 0.5, 0.875  # RFC 2131 4.4.5: renewal / rebinding time as fractions of the lease

# Address conflict detection after the ACK (composed as ARP, see compose/dhcp.py): Windows
# probes DadTransmits (3) times DadRetransmitTime (1 s) apart, so the address is usable ~3 s
# after the ACK; informs and other first use of the address come after that.
WINDOWS_DAD_S = 3.0
DORA_GAP = (0.004, 0.030)    # OFFER received -> REQUEST sent (s)
INFORM_DELAY = (0.5, 8.0)    # address usable -> DHCPINFORM of WinHTTP proxy auto-detection (s)


@dataclass(frozen=True)
class Style:
    """Wire format of one OS DHCP client."""

    broadcast: bool                  # sets the broadcast flag while it has no address
    parameters: tuple[int, ...]      # option 55 of DISCOVER / REQUEST
    vendor_class: bytes
    inform: tuple[int, ...] | None   # option 55 of the DHCPINFORM after joining (None: no inform)
    max_size: int | None = None      # option 57
    rapid_commit: bool = False       # option 80 in DISCOVER
    fqdn: bool = False               # option 81 in REQUEST


STYLES = {
    # Windows 10 DHCP client service (Fingerbank: Windows 10 / Server 2016+).
    "windows": Style(broadcast=True, parameters=(1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252),
                     vendor_class=b"MSFT 5.0", inform=(1, 15, 3, 6, 44, 46, 47, 31, 33, 121, 249, 43, 252),
                     fqdn=True),
    # dhcpcd 8.1 on Raspberry Pi OS: options in dhcpcd-definitions.conf order.
    "dhcpcd": Style(broadcast=False, parameters=(1, 121, 33, 3, 6, 12, 15, 26, 28, 42, 51, 54, 58, 59, 119),
                    vendor_class=b"dhcpcd-8.1.2:Linux-5.15.84-v7l+:armv7l:BCM2835", inform=None,
                    max_size=1472, rapid_commit=True),
}
DEFAULT_STYLE = {"windows": "windows", "linux": "dhcpcd"}


# -- wire format -------------------------------------------------------------------------

def placeholder_mac(loopback: str) -> bytes:
    """Recording stand-in for a client's MAC (locally administered 02:00 + loopback address)."""
    return b"\x02\x00" + socket.inet_aton(loopback)


def option_spans(payload: bytes) -> list[tuple[int, int, int]]:
    """(code, value start, value end) of every option after the magic cookie."""
    spans = []
    offset = HEADER.size
    if len(payload) < offset or payload[offset - 4:offset] != MAGIC_COOKIE:
        return spans
    while offset < len(payload):
        code = payload[offset]
        if code == END:
            break
        if code == PAD:
            offset += 1
            continue
        if offset + 2 > len(payload):
            break
        end = offset + 2 + payload[offset + 1]
        if end > len(payload):
            break
        spans.append((code, offset + 2, end))
        offset = end
    return spans


@dataclass
class Message:
    op: int
    xid: int
    flags: int
    ciaddr: bytes
    yiaddr: bytes
    chaddr: bytes            # the 6-byte hardware address
    options: dict[int, bytes]

    @property
    def type(self) -> int | None:
        value = self.options.get(MESSAGE_TYPE)
        return value[0] if value else None


def parse(payload: bytes) -> Message | None:
    if len(payload) < HEADER.size:
        return None
    op, _htype, hlen, _hops, xid, _secs, flags, ciaddr, yiaddr, _siaddr, _giaddr, chaddr, _sname, _file, cookie \
        = HEADER.unpack_from(payload)
    if cookie != MAGIC_COOKIE:
        return None
    options = {code: payload[start:end] for code, start, end in option_spans(payload)}
    return Message(op, xid, flags, ciaddr, yiaddr, chaddr[:hlen], options)


def encode(op: int, xid: int, chaddr: bytes, options: list[tuple[int, bytes]], *, flags: int = 0,
           ciaddr: bytes = bytes(4), yiaddr: bytes = bytes(4)) -> bytes:
    head = HEADER.pack(op, 1, 6, 0, xid, 0, flags, ciaddr, yiaddr, bytes(4), bytes(4), chaddr, b"", b"",
                       MAGIC_COOKIE)
    body = b"".join(bytes((code, len(value))) + value for code, value in options) + bytes((END,))
    message = head + body
    return message + bytes(max(0, MIN_SIZE - len(message)))


def _u32(value: int) -> bytes:
    return struct.pack("!I", value)


def _ips(*addresses: str) -> bytes:
    return b"".join(socket.inet_aton(a) for a in addresses)


# -- server --------------------------------------------------------------------------------

class _DhcpServerProtocol(asyncio.DatagramProtocol):
    def __init__(self, actor: DhcpServer, server_loopback: str) -> None:
        self.actor = actor
        self.server_id = socket.inet_aton(server_loopback)
        topology = actor.plan_.topology
        self.clients = {placeholder_mac(h.loopback): h for h in topology.hosts}

    def connection_made(self, transport) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, addr) -> None:
        request = parse(data)
        if request is None or request.op != BOOTREQUEST:
            return
        kind = request.type
        if kind in (DISCOVER, REQUEST):
            client = self.clients.get(request.chaddr)
            if client is None:
                return
            # The lease is the address the topology gives the host; renewals keep it.
            yiaddr = request.ciaddr if request.ciaddr != bytes(4) else socket.inet_aton(client.loopback)
            reply_type = OFFER if kind == DISCOVER else ACK
            reply = encode(BOOTREPLY, request.xid, request.chaddr,
                           self._options(reply_type, request, lease=True), flags=request.flags,
                           ciaddr=request.ciaddr, yiaddr=yiaddr)
        elif kind == INFORM:
            # RFC 2131 4.3.5: configuration only, no lease time, no yiaddr.
            reply = encode(BOOTREPLY, request.xid, request.chaddr, self._options(ACK, request, lease=False),
                           flags=request.flags, ciaddr=request.ciaddr)
        else:
            return  # RELEASE / DECLINE: no answer
        self.transport.sendto(reply, addr)

    def _options(self, reply_type: int, request: Message, lease: bool) -> list[tuple[int, bytes]]:
        actor = self.actor
        options = [(MESSAGE_TYPE, bytes((reply_type,))), (SERVER_ID, self.server_id)]
        if lease:
            options += [(LEASE_TIME, _u32(actor.lease_s)), (RENEWAL_TIME, _u32(int(actor.lease_s * T1))),
                        (REBINDING_TIME, _u32(int(actor.lease_s * T2)))]
        options.append((SUBNET_MASK, actor.mask))
        configured = actor.configured()
        for code in request.options.get(PARAMETERS, b""):  # in the client's order, like ISC dhcpd
            if code in configured and code != SUBNET_MASK:
                options.append((code, configured[code]))
        return options


@register
class DhcpServer(Actor):
    """Site DHCP server, e.g. the firewall's DHCP service on one of its interfaces.

    Params: ``subnet`` (served subnet id, default the host's first), ``pool`` ([first, last]
    host offsets the leases come from, default [100, 199]; static hosts stay out of it),
    ``lease`` (default 8h; T1/T2 = 50/87.5 %), ``dns`` and ``ntp`` (host references handed out
    as options 6 and 42; ``dns`` also hands out the site domain, option 15). The router option
    (3) is the server host when it routes for the subnet.
    """

    type = "dhcp.server"
    is_server = True

    def plan(self) -> None:
        topology = self.plan_.topology
        if len(self.hosts) != 1:
            raise ScenarioError(f"{self.type} '{self.id}' runs on exactly one host")
        host = self.hosts[0]
        self.subnet = self.param("subnet", host.subnets[0])
        if self.subnet not in host.subnets:
            raise ScenarioError(f"{self.type} '{self.id}': '{host.id}' has no interface on '{self.subnet}'")
        spec = topology.subnet_specs[self.subnet]
        prefix = ipaddress.ip_network(spec["cidr"]).prefixlen if "cidr" in spec else int(spec["prefix"])
        self.mask = ipaddress.IPv4Network(f"0.0.0.0/{prefix}").netmask.packed
        first, last = (int(v) for v in self.param("pool", [100, 199]))
        if not 2 <= first <= last <= 2 ** (32 - prefix) - 3:
            raise ScenarioError(f"{self.type} '{self.id}': pool {first}-{last} does not fit a /{prefix}")
        if self.subnet in topology.pools:
            raise ScenarioError(f"{self.type} '{self.id}': '{self.subnet}' already has a DHCP server")
        topology.pools[self.subnet] = (first, last)
        self.lease_s = int(parse_duration(self.param("lease", "8h")))
        self.dns = topology.select(self.param("dns"))[0] if self.param("dns") else None
        self.ntp = topology.select(self.param("ntp"))[0] if self.param("ntp") else None
        self.router = host if host.router else None
        self.plan_.facts[self.id] = {
            "hosts": [host_ref(host.id)],
            "subnet": self.subnet,
            "lease_s": self.lease_s,
            "renewal_s": int(self.lease_s * T1),
            "rebinding_s": int(self.lease_s * T2),
            "router": host_ref(self.router.id) if self.router else None,
            "dns": host_ref(self.dns.id) if self.dns else None,
            "ntp": host_ref(self.ntp.id) if self.ntp else None,
            "domain": topology.domain if self.dns else None,
        }

    def configured(self) -> dict[int, bytes]:
        """Option code -> value (recording addresses) of the options the server hands out."""
        options = {SUBNET_MASK: self.mask}
        if self.router is not None:
            options[ROUTER] = _ips(self.router.loopback)
        if self.dns is not None:
            options[DNS_SERVERS] = _ips(self.dns.loopback)
            options[DOMAIN_NAME] = self.plan_.topology.domain.encode()
        if self.ntp is not None:
            options[NTP_SERVERS] = _ips(self.ntp.loopback)
        return options

    async def serve(self, rt) -> None:
        loop = asyncio.get_running_loop()
        host = self.hosts[0]
        transport, _ = await loop.create_datagram_endpoint(
            lambda: _DhcpServerProtocol(self, host.loopback), local_addr=(host.loopback, ports.DHCP_SERVER))
        rt.transports.append(transport)


# -- clients -------------------------------------------------------------------------------

@register
class DhcpClient(Actor):
    """Hosts that lease their address from the site DHCP server.

    Params: ``server`` (host running the ``dhcp.server``), ``join`` ([lo, hi] fraction of the
    capture at which the host connects: full DORA, address conflict detection and, Windows,
    a DHCPINFORM; omitted: the host holds a lease from before the capture), ``leave`` ([lo, hi]
    fraction at which it disconnects), ``release`` (send DHCPRELEASE when leaving), ``style``
    (``windows`` / ``dhcpcd``; default from the host's OS stack). Leases are renewed with a
    unicast REQUEST at T1 while the host is connected.
    """

    type = "dhcp.client"

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        # Recording state per host: (offered address, server id) between DISCOVER and REQUEST,
        # and the lease it holds.
        self._offers: dict[str, tuple[bytes, bytes]] = {}
        self._leases: dict[str, tuple[bytes, bytes]] = {}

    def plan(self) -> None:
        plan = self.plan_
        topology = plan.topology
        server_host = topology.select(self.param("server"))[0]
        server = next((a for a in plan.actors if isinstance(a, DhcpServer) and a.hosts[0].id == server_host.id), None)
        if server is None:
            raise ScenarioError(f"{self.type} '{self.id}': '{server_host.id}' runs no dhcp.server")
        join, leave = self.param("join"), self.param("leave")
        release = bool(self.param("release", False))
        renewal = server.lease_s * T1
        facts = []
        for host in self.hosts:
            if server.subnet not in host.subnets or host.router:
                raise ScenarioError(f"{self.type} '{self.id}': '{host.id}' is not a host on the "
                                    f"'{server.subnet}' subnet served by '{server_host.id}'")
            style = self.param("style") or DEFAULT_STYLE.get(host.device.stack.name)
            if style not in STYLES:
                raise ScenarioError(f"{self.type} '{self.id}': no DHCP client style for '{host.id}' "
                                    f"({host.device.stack.name}); set params.style ({', '.join(STYLES)})")
            topology.leased.add(host.id)
            rng = self.rng.child(host.id)
            common = {"server": server_host.id, "style": style, "hostname": host.name,
                      "fqdn": f"{host.name}.{topology.domain}"}
            joined = inform = released = None
            joined_at = rng.uniform(*self.span(join)) * plan.duration if join is not None else None
            gone = rng.uniform(*self.span(leave)) * plan.duration if leave is not None else plan.duration
            if joined_at is not None and joined_at >= gone:
                raise ScenarioError(f"{self.type} '{self.id}': '{host.id}' leaves before it joins")
            if joined_at is not None:
                xid = rng.getrandbits(32)
                joined = plan.add(joined_at, self.id, host.id, "dhcp.discover", xid=xid, **common)
                bound = joined_at + rng.uniform(*DORA_GAP)
                # The REQUEST answers the OFFER on the same socket: one exchange with the DISCOVER.
                plan.add(bound, self.id, host.id, "dhcp.request", xid=xid, state="selecting", resend=True, **common)
                informed = bound + WINDOWS_DAD_S + rng.uniform(*INFORM_DELAY)
                if STYLES[style].inform is not None and informed < gone:
                    inform = plan.add(informed, self.id, host.id, "dhcp.inform", xid=rng.getrandbits(32), **common)
            else:
                bound = -rng.uniform(0.0, renewal)  # last renewal before the capture started
            renewals = []
            at = bound + renewal
            while at < gone:
                renewals.append(plan.add(at, self.id, host.id, "dhcp.request", xid=rng.getrandbits(32),
                                         state="renewing", **common))
                at += renewal
            if leave is not None and release:
                released = plan.add(gone, self.id, host.id, "dhcp.release", xid=rng.getrandbits(32), **common)
            facts.append({
                "host": host_ref(host.id),
                "style": style,
                "joined": action_ref(joined) if joined else None,
                "inform": action_ref(inform) if inform else None,
                "renewals": [action_ref(a) for a in renewals],
                "released": action_ref(released) if released else None,
            })
        plan.facts[self.id] = {"server": host_ref(server_host.id), "clients": facts}

    # -- recording ----------------------------------------------------------------------
    def execute(self, action, rt) -> None:
        a = action.args
        style = STYLES[a["style"]]
        loopback = rt.loopback(action.host)
        server = rt.loopback(a["server"])
        chaddr = placeholder_mac(loopback)
        client_id = b"\x01" + chaddr
        # What the host has: the lease it got when joining, else the address it already holds.
        address, server_id = self._leases.get(action.host, (socket.inet_aton(loopback), socket.inet_aton(server)))
        flags, ciaddr = 0, address
        if action.op == "dhcp.discover":
            kind, ciaddr = DISCOVER, bytes(4)
            options = [(MESSAGE_TYPE, bytes((DISCOVER,))), (CLIENT_ID, client_id)]
            if style.rapid_commit:
                options.append((RAPID_COMMIT, b""))
            options += self._identity(style, a, fqdn=False)
        elif action.op == "dhcp.request" and a["state"] == "selecting":
            kind, ciaddr = REQUEST, bytes(4)
            offered, offered_by = self._offers.pop(action.host)
            options = [(MESSAGE_TYPE, bytes((REQUEST,))), (CLIENT_ID, client_id), (REQUESTED_IP, offered),
                       (SERVER_ID, offered_by)]
            options += self._identity(style, a, fqdn=style.fqdn)
        elif action.op == "dhcp.request":  # renewing: unicast to the server that granted the lease
            kind = REQUEST
            options = [(MESSAGE_TYPE, bytes((REQUEST,))), (CLIENT_ID, client_id)]
            options += self._identity(style, a, fqdn=style.fqdn)
        elif action.op == "dhcp.inform":
            kind = INFORM
            options = [(MESSAGE_TYPE, bytes((INFORM,))), (CLIENT_ID, client_id), (HOST_NAME, a["hostname"].encode()),
                       (VENDOR_CLASS, style.vendor_class), (PARAMETERS, bytes(style.inform))]
        elif action.op == "dhcp.release":
            kind = RELEASE
            options = [(MESSAGE_TYPE, bytes((RELEASE,))), (CLIENT_ID, client_id), (SERVER_ID, server_id)]
        else:
            raise ValueError(f"unknown operation {action.op}")
        if style.broadcast and ciaddr == bytes(4):
            flags = BROADCAST_FLAG
        message = encode(BOOTREQUEST, a["xid"], chaddr, options, flags=flags, ciaddr=ciaddr)
        reply = self._send(loopback, server, message, expect=kind != RELEASE)
        if kind == RELEASE:
            self._leases.pop(action.host, None)
            return
        answer = parse(reply)
        expected = OFFER if kind == DISCOVER else ACK
        if answer is None or answer.xid != a["xid"] or answer.type != expected:
            raise RuntimeError(f"DHCP server answered {action.op} with {answer.type if answer else 'garbage'}")
        if kind == DISCOVER:
            self._offers[action.host] = (answer.yiaddr, answer.options[SERVER_ID])
        elif kind == REQUEST:
            self._leases[action.host] = (answer.yiaddr, answer.options[SERVER_ID])

    @staticmethod
    def _identity(style: Style, a: dict, fqdn: bool) -> list[tuple[int, bytes]]:
        """Options after the addresses, in the order the client sends them."""
        hostname = (HOST_NAME, a["hostname"].encode())
        vendor = (VENDOR_CLASS, style.vendor_class)
        parameters = (PARAMETERS, bytes(style.parameters))
        if style.max_size is not None:  # dhcpcd
            return [(MAX_SIZE, struct.pack("!H", style.max_size)), vendor, hostname, parameters]
        options = [hostname]
        if fqdn:  # flags 0, RCODE1/2 0, ASCII name (E bit clear)
            options.append((CLIENT_FQDN, b"\x00\x00\x00" + a["fqdn"].encode()))
        return options + [vendor, parameters]

    @staticmethod
    def _send(source: str, server: str, message: bytes, expect: bool) -> bytes:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.bind((source, ports.DHCP_CLIENT))
            sock.settimeout(2)
            sock.sendto(message, (server, ports.DHCP_SERVER))
            return sock.recvfrom(1500)[0] if expect else b""
        finally:
            sock.close()
