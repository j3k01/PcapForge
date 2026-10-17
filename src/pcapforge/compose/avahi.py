"""avahi-daemon (devices with ``mdns: avahi``) on the sensor segment: the mDNS probes, announcements
and goodbyes it multicasts when the host's addresses appear, from avahi 0.8 (``avahi-core``
announce.c, probe-sched.c, response-sched.c, iface.c, entry.c) with Debian / Ubuntu's
avahi-daemon.conf defaults (publish-addresses yes, publish-hinfo and publish-workstation no,
publish-aaaa-on-ipv4 yes, publish-a-on-ipv6 no):

* every address gets an entry group of two unique records with TTL 120: ``<host>.local`` A / AAAA
  and its reverse PTR (``in-addr.arpa`` / ``ip6.arpa``). An IPv4 address is published on the IPv4
  mDNS interface only, an IPv6 address on both (224.0.0.251 and ff02::fb);
* an address is published once it is usable (avahi skips tentative addresses). An IPv6 link-local
  address counts only while the interface has no global one (a ULA is global too): when the
  first SLAAC address passes DAD, the link-local group is withdrawn;
* per record and interface an announcer probes three times 250 ms apart (first after 0-250 ms),
  waits one more 250 ms, and when the last record of its group has probed, every record of the
  group is announced three times: at once, 1 s (+0-250 ms) and 2 s (+0-250 ms) later. A unique
  record is announced with the rest of its RRset (all AAAA of the host on that interface);
* the interface's probe scheduler sends a probe 50 ms after it is posted and puts every pending
  probe in the packet (one ANY question per name, the records in the authority section, no
  cache-flush); the response scheduler sends 20-120 ms after posting, a goodbye (TTL 0) at once,
  every pending response in the same packet (answers with cache-flush), and drops a record it sent
  less than 500 ms ago. Probes are queries (flags 0), responses ``QR AA``, both with id 0, names
  compressed;
* datagrams leave from port 5353 with TTL / hop limit 255. Over IPv4 Linux sets DF and, the socket
  being unconnected, IP ID 0; over IPv6 the source is the link-local address and the flow label
  the kernel's automatic one (a hash of the flow, constant per host).

Nobody on the segment queries for the host's names, so nothing else follows. Not modelled: the
host leaving (goodbyes on shutdown), name conflicts and temporary-address regeneration.
"""

from __future__ import annotations

import heapq
import ipaddress
import itertools
import struct
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Callable

from pcapforge.compose.headers import checksum
from pcapforge.compose.link import ETHERTYPE_IPV4, mac_bytes, pad
from pcapforge.topology import group6_mac, group_mac

if TYPE_CHECKING:
    from pcapforge.rng import Rng

MDNS_PORT = 5353
GROUP4, GROUP6 = "224.0.0.251", "ff02::fb"
MAC4, MAC6 = mac_bytes(group_mac(GROUP4)), mac_bytes(group6_mac(GROUP6))
ETHERTYPE_IPV6 = b"\x86\xdd"
HOP_LIMIT = 255
TTL_HOST_NAME = 120                 # AVAHI_DEFAULT_TTL_HOST_NAME
TYPE_A, TYPE_PTR, TYPE_AAAA, TYPE_ANY = 1, 12, 28, 255
CLASS_IN, CACHE_FLUSH = 1, 0x8000
FLAGS_RESPONSE = 0x8400             # QR, AA
PROBE_JITTER = 0.25                 # AVAHI_PROBE_JITTER_MSEC
PROBE_INTERVAL = 0.25               # AVAHI_PROBE_INTERVAL_MSEC
PROBE_DEFER = 0.05                  # AVAHI_PROBE_DEFER_MSEC
PROBE_HISTORY = 0.15                # AVAHI_PROBE_HISTORY_MSEC
PROBES = 3
ANNOUNCE_JITTER = 0.25              # AVAHI_ANNOUNCEMENT_JITTER_MSEC
ANNOUNCEMENTS = 3
RESPONSE_DEFER = 0.02               # AVAHI_RESPONSE_DEFER_MSEC
RESPONSE_JITTER = 0.1               # AVAHI_RESPONSE_JITTER_MSEC
RESPONSE_HISTORY = 0.5              # AVAHI_RESPONSE_HISTORY_MSEC
V4, V6 = "v4", "v6"

PROBING, WAITING, ANNOUNCING, ESTABLISHED = "probing", "waiting", "announcing", "established"


@dataclass(frozen=True)
class Record:
    name: str
    rtype: int
    rdata: bytes | str  # address bytes, or the PTR target name
    ttl: int = TTL_HOST_NAME

    def same(self, other: Record) -> bool:
        """avahi_record_equal_no_ttl."""
        return (self.name, self.rtype, self.rdata) == (other.name, other.rtype, other.rdata)

    def goodbye(self) -> Record:
        return Record(self.name, self.rtype, self.rdata, 0)


def reverse_name(address: bytes) -> str:
    if len(address) == 4:
        return ".".join(str(b) for b in reversed(address)) + ".in-addr.arpa"
    return ".".join(reversed(address.hex())) + ".ip6.arpa"


class _Message:
    """A DNS message with avahi's name compression (every suffix already written is a pointer)."""

    def __init__(self, flags: int) -> None:
        self.flags = flags
        self.body = bytearray()
        self.names: dict[tuple[str, ...], int] = {}
        self.counts = [0, 0, 0, 0]

    def name(self, name: str) -> None:
        labels = tuple(label.lower() for label in name.split("."))
        for index in range(len(labels)):
            offset = self.names.get(labels[index:])
            if offset is not None:
                self.body += struct.pack("!H", 0xC000 | offset)
                return
            at = 12 + len(self.body)
            if at < 0x4000:
                self.names[labels[index:]] = at
            raw = name.split(".")[index].encode()
            self.body += bytes((len(raw),)) + raw
        self.body.append(0)

    def question(self, name: str) -> None:
        self.name(name)
        self.body += struct.pack("!HH", TYPE_ANY, CLASS_IN)
        self.counts[0] += 1

    def record(self, record: Record, section: int, flush: bool) -> None:
        self.name(record.name)
        self.body += struct.pack("!HHI", record.rtype, CLASS_IN | (CACHE_FLUSH if flush else 0), record.ttl)
        length_at = len(self.body)
        self.body += b"\x00\x00"
        if record.rtype == TYPE_PTR:
            self.name(record.rdata)
        else:
            self.body += record.rdata
        struct.pack_into("!H", self.body, length_at, len(self.body) - length_at - 2)
        self.counts[section] += 1

    def packet(self) -> bytes:
        return struct.pack("!HHHHHH", 0, self.flags, *self.counts) + bytes(self.body)


@dataclass(eq=False)
class _Job:
    record: Record
    delivery: float
    flush: bool = False
    done: bool = False


@dataclass(eq=False)
class _Group:
    entries: list[_Entry] = field(default_factory=list)
    established: bool = False
    probing: int = 0


@dataclass(eq=False)
class _Entry:
    record: Record
    group: _Group
    interfaces: tuple[str, ...]
    announcers: dict[str, _Announcer] = field(default_factory=dict)
    dead: bool = False


@dataclass(eq=False)
class _Announcer:
    entry: _Entry
    interface: str
    state: str = PROBING
    n: int = 1
    delay: float = 1.0
    timer: int = 0  # version of the pending timer; older ones are stale


class Avahi:
    """The frames avahi-daemon of one host multicasts on the sensor segment."""

    def __init__(self, rng: Rng, host_name: str, mac: str, ipv4: bytes, link_local: bytes) -> None:
        self.rng = rng
        self.fqdn = f"{host_name}.local"
        self.mac = mac_bytes(mac)
        self.ipv4 = ipv4
        self.link_local = link_local
        self.flow_label = rng.getrandbits(20) or 1
        self.events: list[tuple[float, int, Callable[[], None]]] = []
        self.order = itertools.count()
        self.now = 0.0
        self.relevant: set[str] = set()
        self.entries: list[_Entry] = []  # newest first, like avahi's entry lists
        self.probes: dict[str, list[_Job]] = {V4: [], V6: []}
        self.probe_history: dict[str, list[_Job]] = {V4: [], V6: []}
        self.responses: dict[str, list[_Job]] = {V4: [], V6: []}
        self.response_history: dict[str, list[_Job]] = {V4: [], V6: []}
        self.frames: list[tuple[float, bytes]] = []

    # -- inputs --------------------------------------------------------------------------
    def run(self, ipv4_at: float, link_local_at: float, slaac: list[tuple[float, bytes]]) -> list[tuple[float, bytes]]:
        """Frames from the IPv4 address (usable at ``ipv4_at``), the link-local address (usable
        at ``link_local_at``) and the SLAAC addresses ``(usable at, address)``."""
        self._at(ipv4_at, lambda: self._interface_up(V4))
        self._at(ipv4_at, lambda: self._publish(self.ipv4))
        self._at(link_local_at, lambda: self._interface_up(V6))
        link_local = self._at(link_local_at, lambda: self._publish(self.link_local))
        if slaac:
            first = min(t for t, _ in slaac)
            self._at(first, lambda: self._withdraw(link_local))
        for t, address in sorted(slaac):
            self._at(t, lambda address=address: self._publish(address))
        while self.events:
            self.now, _, action = heapq.heappop(self.events)
            action()
        return self.frames

    def _at(self, t: float, action: Callable[[], object]) -> list:
        """Run ``action`` at ``t``; the returned list receives its result."""
        out: list = []
        heapq.heappush(self.events, (t, next(self.order), lambda: out.append(action())))
        return out

    def _interface_up(self, interface: str) -> None:
        """avahi_announce_interface: announcers for the entries already published there."""
        self.relevant.add(interface)
        for entry in self.entries:
            if not entry.dead and interface in entry.interfaces:
                self._announcer(entry, interface)

    def _publish(self, address: bytes) -> _Group:
        """avahi_server_add_address + commit: the address record and its reverse PTR."""
        interfaces = (V4,) if len(address) == 4 else (V4, V6)
        group = _Group()
        records = [Record(self.fqdn, TYPE_A if len(address) == 4 else TYPE_AAAA, address),
                   Record(reverse_name(address), TYPE_PTR, self.fqdn)]
        for record in records:
            entry = _Entry(record, group, interfaces)
            group.entries.append(entry)
            self.entries.insert(0, entry)
        for entry in group.entries:
            for interface in interfaces:
                if interface in self.relevant:
                    self._announcer(entry, interface)
        return group

    def _withdraw(self, holder: list) -> None:
        """The address stopped being relevant: goodbyes for its registered records, no more probes."""
        group: _Group = holder[0]
        for entry in group.entries:
            for interface, announcer in entry.announcers.items():
                if announcer.state in (ANNOUNCING, ESTABLISHED):
                    self._respond(interface, entry.record.goodbye(), True, immediately=True)
                announcer.timer += 1
            entry.dead = True
            entry.announcers.clear()

    # -- announcers (announce.c) ---------------------------------------------------------------
    def _announcer(self, entry: _Entry, interface: str) -> None:
        announcer = entry.announcers[interface] = _Announcer(entry, interface)
        entry.group.probing += 1
        self._schedule(announcer, self.rng.uniform(0.0, PROBE_JITTER))

    def _schedule(self, announcer: _Announcer, delay: float) -> None:
        announcer.timer += 1
        version = announcer.timer
        heapq.heappush(self.events, (self.now + delay, next(self.order),
                                     lambda: self._tick(announcer) if announcer.timer == version else None))

    def _tick(self, announcer: _Announcer) -> None:
        if announcer.state == PROBING:
            if announcer.n > PROBES:
                group = announcer.entry.group
                group.probing -= 1
                if group.established:
                    announcer.state, announcer.n = ANNOUNCING, 1
                    self._tick(announcer)
                else:
                    announcer.state = WAITING
                    self._check_probed(group)
            else:
                self._probe(announcer.interface, announcer.entry.record)
                announcer.n += 1
                self._schedule(announcer, PROBE_INTERVAL)
        elif announcer.state == ANNOUNCING:
            record = announcer.entry.record
            for entry in self.entries:  # the whole RRset of a unique record
                registered = entry.announcers.get(announcer.interface)
                if (not entry.dead and registered is not None and registered.state in (ANNOUNCING, ESTABLISHED)
                        and (entry.record.name, entry.record.rtype) == (record.name, record.rtype)):
                    self._respond(announcer.interface, entry.record, True)
            announcer.n += 1
            if announcer.n > ANNOUNCEMENTS:
                announcer.state = ESTABLISHED
            else:
                self._schedule(announcer, announcer.delay + self.rng.uniform(0.0, ANNOUNCE_JITTER))
                announcer.delay *= 2

    def _check_probed(self, group: _Group) -> None:
        """avahi_s_entry_group_check_probed(g, immediately=1)."""
        if group.probing or group.established:
            return
        group.established = True
        for entry in group.entries:
            for announcer in entry.announcers.values():
                if announcer.state == WAITING:
                    announcer.state, announcer.n = ANNOUNCING, 1
                    self._tick(announcer)

    # -- schedulers (probe-sched.c, response-sched.c) ----------------------------------------
    def _probe(self, interface: str, record: Record) -> None:
        if any(job.record.same(record) for job in self.probes[interface]):
            return
        if any(job.record.same(record) and self.now - job.delivery < PROBE_HISTORY
               for job in self.probe_history[interface]):
            return
        job = _Job(record, self.now + PROBE_DEFER)
        self.probes[interface].insert(0, job)
        heapq.heappush(self.events, (job.delivery, next(self.order), lambda: self._send_probe(interface, job)))

    def _send_probe(self, interface: str, job: _Job) -> None:
        if job.done:
            return
        jobs = self.probes[interface]
        message = _Message(0)
        chosen: list[_Job] = []
        for first in [job] + [j for j in jobs if j is not job]:
            if first in chosen:
                continue
            message.question(first.record.name)
            chosen += [j for j in [first] + jobs if j not in chosen and j.record.name == first.record.name]
        for pending in list(jobs):
            if pending in chosen:
                message.record(pending.record, 2, False)
                self._done(jobs, self.probe_history[interface], pending)
        self._send(interface, message.packet())

    def _respond(self, interface: str, record: Record, flush: bool, immediately: bool = False) -> None:
        for sent in self.response_history[interface]:
            if (sent.record.same(record) and self.now - sent.delivery < RESPONSE_HISTORY
                    and (sent.record.ttl == 0) == (record.ttl == 0) and sent.record.ttl >= record.ttl / 2
                    and (sent.flush or not flush)):
                return
        delivery = self.now if immediately else self.now + RESPONSE_DEFER + self.rng.uniform(0.0, RESPONSE_JITTER)
        jobs = self.responses[interface]
        for job in jobs:
            if job.record.same(record):
                job.record, job.flush = record, job.flush or flush
                if delivery < job.delivery:
                    job.delivery = delivery
                    heapq.heappush(self.events, (delivery, next(self.order),
                                                 lambda job=job: self._send_response(interface, job)))
                return
        job = _Job(record, delivery, flush)
        jobs.insert(0, job)
        heapq.heappush(self.events, (delivery, next(self.order), lambda: self._send_response(interface, job)))

    def _send_response(self, interface: str, job: _Job) -> None:
        if job.done or job.delivery > self.now:
            return  # sent with another job, or moved
        jobs = self.responses[interface]
        message = _Message(FLAGS_RESPONSE)
        for pending in [job] + [j for j in jobs if j is not job]:
            message.record(pending.record, 1, pending.flush)
            pending.delivery = self.now
            self._done(jobs, self.response_history[interface], pending)
        self._send(interface, message.packet())

    def _done(self, jobs: list[_Job], history: list[_Job], job: _Job) -> None:
        job.done = True
        jobs.remove(job)
        history.insert(0, job)

    # -- frames --------------------------------------------------------------------------
    def _send(self, interface: str, dns: bytes) -> None:
        length = 8 + len(dns)
        if interface == V4:
            dst = ipaddress.IPv4Address(GROUP4).packed
            pseudo = self.ipv4 + dst + struct.pack("!xBH", 17, length)
            udp = struct.pack("!HHHH", MDNS_PORT, MDNS_PORT, length, 0) + dns
            udp = udp[:6] + struct.pack("!H", checksum(pseudo + udp) or 0xFFFF) + udp[8:]
            header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + length, 0, 0x4000, HOP_LIMIT, 17, 0, self.ipv4, dst)
            header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
            frame = MAC4 + self.mac + ETHERTYPE_IPV4 + header + udp
        else:
            dst = ipaddress.IPv6Address(GROUP6).packed
            pseudo = self.link_local + dst + struct.pack("!IxxxB", length, 17)
            udp = struct.pack("!HHHH", MDNS_PORT, MDNS_PORT, length, 0) + dns
            udp = udp[:6] + struct.pack("!H", checksum(pseudo + udp) or 0xFFFF) + udp[8:]
            header = struct.pack("!IHBB", 0x60000000 | self.flow_label, length, 17, HOP_LIMIT) + self.link_local + dst
            frame = MAC6 + self.mac + ETHERTYPE_IPV6 + header + udp
        self.frames.append((self.now, pad(frame)))
