"""IPv6 and avahi-daemon of the Raspberry Pi and the desktop Linux laptop on the sensor segment
(devices.yaml profiles, compose/ipv6.py, compose/avahi.py), checked frame by frame."""

import copy
import ipaddress
import subprocess
from collections import defaultdict

import pytest
from scapy.layers.dns import DNS
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import ICMPv6ND_NS, IPv6
from scapy.layers.l2 import Ether

from pcapforge.compose.ipv6 import Ipv6, eui64
from pcapforge.compose.link import mac_bytes
from pcapforge.compose.writer import write_pcap
from pcapforge.plan import build_plan
from pcapforge.rng import Rng
from pcapforge.scenario import Scenario, find
from pcapforge.tools import find_tool

SCENARIO = "ot-modbus-write-manipulation"
DURATION = 1800.0
ATTACKER_UP = 300.0
A, PTR, AAAA = 1, 12, 28


def compose(variant, seed="avahi", bound_after=None):
    """(plan, Ipv6, attacker host, frames) of a medium capture with the attacker on the sensor
    segment: the Raspberry Pi (``pi``) or the Linux laptop moved to the control LAN (``laptop``).
    The attacker's interface starts ``ATTACKER_UP`` s in; ``bound_after``: its IPv4 address comes
    that much later (a DHCP join)."""
    base = find(SCENARIO)
    doc = copy.deepcopy(base.doc)
    attacker = "rogue" if variant == "pi" else "itpc"
    doc["difficulty"]["medium"]["vars"]["writer_host"] = attacker
    for host in doc["topology"]["hosts"]:
        if host["id"] == "itpc":
            host["subnet"] = "control"
    plan = build_plan(Scenario(base.path, doc), "medium", seed, duration_override=DURATION)
    root = Rng("pcapforge", plan.scenario.id, plan.difficulty, seed)
    plan.topology.assign_addresses(root.child("addressing"))
    t0 = plan.start_epoch
    bound = {} if bound_after is None else {attacker: t0 + ATTACKER_UP + bound_after}
    ipv6 = Ipv6(plan, None, root.child("present").child("ipv6"), bound=bound)
    raw = []
    for host_id in ipv6.address:
        host = plan.topology.by_id[host_id]
        raw += ipv6.start_before(t0 + (ATTACKER_UP if host_id == attacker else 0.0), host)
    raw += ipv6.finish(t0, t0 + DURATION)
    raw.sort(key=lambda f: f[0])
    return plan, ipv6, plan.topology.by_id[attacker], [(t, Ether(data), data) for t, data in raw]


@pytest.fixture(scope="module")
def pi():
    return compose("pi")


@pytest.fixture(scope="module")
def laptop():
    return compose("laptop")


def mdns(frames, host):
    """(time, family, packet, DNS) of the host's mDNS datagrams."""
    mac = host.interface_on("control").mac
    out = []
    for t, pkt, _ in frames:
        if UDP in pkt and pkt[UDP].dport == 5353 and pkt.src == mac:
            out.append((t, 4 if IP in pkt else 6, pkt, DNS(bytes(pkt[UDP].payload))))
    return out


def records(dns, section):
    return list(getattr(dns, section) or [])


def key(rr):
    rdata = rr.rdata if not isinstance(rr.rdata, bytes) else rr.rdata.decode()
    return rr.rrname.decode().lower().rstrip("."), rr.type, str(rdata).lower().rstrip(".")


def slaac_addresses(frames, ipv6, host_id):
    """Targets of the host's DAD probes inside the advertised prefix."""
    prefix = ipaddress.IPv6Network((ipv6.prefix + bytes(8), 64))
    mac = ":".join(f"{b:02x}" for b in ipv6.mac[host_id])
    return [ipaddress.IPv6Address(p[ICMPv6ND_NS].tgt) for _, p, _ in frames
            if ICMPv6ND_NS in p and p.src == mac and p[IPv6].src == "::"
            and ipaddress.IPv6Address(p[ICMPv6ND_NS].tgt) in prefix]


def link_local_keys(ipv6, host):
    """Keys of the link-local AAAA record and its reverse PTR."""
    name = f"{host.name}.local".lower()
    link_local = ipaddress.IPv6Address(ipv6.address[host.id])
    return {(name, AAAA, str(link_local)), (link_local.reverse_pointer, PTR, name)}


def test_raspberry_pi_uses_modified_eui64_identifiers_and_no_temporary_address(pi):
    plan, ipv6, host, frames = pi
    iid = eui64(mac_bytes(host.interface_on("control").mac))
    assert ipv6.address[host.id] == bytes.fromhex("fe80000000000000") + iid
    assert [a.packed[8:] for a in slaac_addresses(frames, ipv6, host.id)] == [iid]


def test_linux_laptop_uses_stable_privacy_identifiers_and_a_temporary_address(laptop):
    plan, ipv6, host, frames = laptop
    iid = eui64(mac_bytes(host.interface_on("control").mac))
    link_local = ipv6.address[host.id][8:]
    stable, temporary = slaac_addresses(frames, ipv6, host.id)
    assert iid not in {link_local, stable.packed[8:], temporary.packed[8:]}
    assert len({link_local, stable.packed[8:], temporary.packed[8:]}) == 3


@pytest.mark.parametrize("variant", ["pi", "laptop"])
def test_every_address_is_probed_three_times_then_announced_three_times(variant, request):
    plan, ipv6, host, frames = request.getfixturevalue(variant)
    sent = mdns(frames, host)
    probes, announced = defaultdict(list), defaultdict(list)
    for t, family, pkt, dns in sent:
        if dns.qr:
            assert dns.aa and not dns.qd and dns.id == 0
            for rr in records(dns, "an"):
                assert rr.cacheflush and rr.ttl in (0, 120)
                if rr.ttl:
                    announced[family, key(rr)].append(t)
        else:
            assert dns.id == 0 and dns.qd and all(q.qtype == 255 and not q.unicastresponse for q in dns.qd)
            assert {q.qname for q in dns.qd} == {rr.rrname for rr in records(dns, "ns")}
            for rr in records(dns, "ns"):
                assert not rr.cacheflush and rr.ttl == 120
                probes[family, key(rr)].append(t)
    name = f"{host.name}.local".lower()
    ipv4 = host.interface_on("control").ip
    link_local = str(ipaddress.IPv6Address(ipv6.address[host.id]))
    slaac = [str(a) for a in slaac_addresses(frames, ipv6, host.id)]
    expected = {(4, (name, A, ipv4))}
    expected |= {(family, (name, AAAA, address)) for family in (4, 6) for address in [link_local] + slaac}
    expected |= {(family, (ipaddress.ip_address(address).reverse_pointer, PTR, name))
                 for family, (_, _, address) in set(expected)}
    assert set(probes) == expected
    for record, times in probes.items():
        assert len(times) == 3
        assert all(0.2 <= b - a <= 0.3 for a, b in zip(times, times[1:]))
    withdrawn = link_local_keys(ipv6, host)
    for (family, record), times in announced.items():
        assert (family, record) in probes and min(times) > max(probes[family, record])
        if record not in withdrawn:  # the link-local records are withdrawn before they finish
            # three rounds 1 s and 2 s (+ 0-250 ms) apart; a record also goes out with the rest of
            # its RRset when another address of the host announces
            assert len(times) >= 3 and 3.0 <= times[-1] - times[0] <= 3.8
    # A / AAAA only on IPv4 for the IPv4 address; every IPv6 address on both.
    assert not [r for family, r in announced if family == 6 and r[1] == A]


def test_the_link_local_record_says_goodbye_when_a_slaac_address_becomes_usable(pi):
    plan, ipv6, host, frames = pi
    usable = min(t for t, _ in ipv6.slaac[host.id])
    withdrawn = link_local_keys(ipv6, host)
    goodbyes = [(t, family, key(rr)) for t, family, _, dns in mdns(frames, host) if dns.qr
                for rr in records(dns, "an") if rr.ttl == 0]
    assert {(family, record[1]) for _, family, record in goodbyes} == {(4, AAAA), (4, PTR), (6, AAAA), (6, PTR)}
    assert all(t == usable and record in withdrawn for t, _, record in goodbyes)
    later = [rr for t, _, _, dns in mdns(frames, host) if t > usable for rr in records(dns, "an") + records(dns, "ns")
             if key(rr) in withdrawn and rr.ttl]
    assert not later


def test_ipv4_and_ipv6_headers_follow_linux_and_avahi(pi):
    plan, ipv6, host, frames = pi
    labels = set()
    for _, family, pkt, _ in mdns(frames, host):
        assert pkt[UDP].sport == 5353
        if family == 4:
            ip = pkt[IP]
            assert (ip.dst, ip.ttl, ip.id, ip.flags.DF, ip.src) == ("224.0.0.251", 255, 0, True,
                                                                    host.interface_on("control").ip)
            assert pkt.dst == "01:00:5e:00:00:fb"
        else:
            ip = pkt[IPv6]
            assert (ip.dst, ip.hlim, ip.src) == ("ff02::fb", 255, str(ipaddress.IPv6Address(ipv6.address[host.id])))
            assert pkt.dst == "33:33:00:00:00:fb"
            labels.add(ip.fl)
    assert len(labels) == 1 and labels != {0}, "Linux's automatic flow label: one per flow, not 0"


def test_a_dhcp_client_announces_its_ipv4_address_once_it_is_bound():
    plan, ipv6, host, frames = compose("pi", seed="joined", bound_after=6.0)
    bound = ipv6.bound[host.id]
    ipv4_sent = [t for t, family, _, _ in mdns(frames, host) if family == 4]
    assert ipv4_sent and min(ipv4_sent) > bound
    assert min(t for t, family, _, _ in mdns(frames, host) if family == 6) < bound


@pytest.mark.skipif(not find_tool("tshark"), reason="requires tshark")
def test_tshark_decodes_the_announcements_without_errors(laptop, tmp_path):
    plan, ipv6, host, frames = laptop
    pcap = tmp_path / "avahi.pcap"
    write_pcap(pcap, ((round(t * 1_000_000), data) for t, _, data in frames))
    fields = ["_ws.malformed", "_ws.expert.severity", "udp.checksum.status", "ip.checksum.status", "mdns"]
    out = subprocess.run([find_tool("tshark"), "-n", "-r", str(pcap), "-Y", "udp.port == 5353",
                          "-o", "udp.check_checksum:TRUE", "-o", "ip.check_checksum:TRUE", "-T", "fields",
                          "-E", "separator=|", "-E", "occurrence=a", "-E", "aggregator=,"]
                         + [a for f in fields for a in ("-e", f)], capture_output=True, text=True, check=True).stdout
    rows = [line.split("|") for line in out.splitlines()]
    assert len(rows) == len(mdns(frames, host))
    for malformed, severity, udp_status, ip_status, _ in rows:
        assert not malformed
        assert all(not s or (int(s) & 0x00F00000) < 0x00800000 for s in severity.split(","))
        assert udp_status == "1" and ip_status in ("", "1")
