"""IPv6 on the sensor segment: the firewall's Router Advertisements, SLAAC of the Windows hosts
and unicast Neighbor Discovery (compose/ipv6.py), checked frame by frame with Scapy and tshark."""

import ipaddress
import subprocess

import pytest
from scapy.layers.inet6 import (
    ICMPv6MLReport2, ICMPv6ND_NA, ICMPv6ND_NS, ICMPv6ND_RA, ICMPv6ND_RS, ICMPv6NDOptDstLLAddr, ICMPv6NDOptMTU,
    ICMPv6NDOptPrefixInfo, ICMPv6NDOptSrcLLAddr, IPv6, in6_chksum,
)
from scapy.layers.l2 import Ether

from pcapforge.compose.ipv6 import Ipv6
from pcapforge.compose.writer import write_pcap
from pcapforge.plan import build_plan
from pcapforge.rng import Rng
from pcapforge.scenario import find
from pcapforge.tools import find_tool

SCENARIO = "ot-modbus-write-manipulation"
DURATION = 7200.0


def compose_ipv6(seed="ipv6", starts=None, router_up=None):
    """(plan, Ipv6, decoded frames) of the IPv6 a medium capture of ``DURATION`` s shows.

    ``starts``: host id -> interface start (s into the capture) instead of the DHCPv6 ``up``."""
    plan = build_plan(find(SCENARIO), "medium", seed, duration_override=DURATION)
    root = Rng("pcapforge", plan.scenario.id, plan.difficulty, seed)
    plan.topology.assign_addresses(root.child("addressing"))
    t0 = plan.start_epoch
    ipv6 = Ipv6(plan, None, root.child("present").child("ipv6"),
                router_up=None if router_up is None else t0 + router_up)
    if starts is not None:
        ipv6.up = {}
    raw = []
    for index, host_id in enumerate(ipv6.address):
        host = plan.topology.by_id[host_id]
        offset = starts.get(host_id, 300.0 + index) if starts is not None else 0.0
        raw += ipv6.start_before(t0 + offset, host)
        ipv6.start_before(t0 + DURATION, host)  # the host stays until the end
    raw += ipv6.finish(t0, t0 + DURATION)
    raw.sort(key=lambda f: f[0])
    return plan, ipv6, [(t, Ether(data), data) for t, data in raw]


@pytest.fixture(scope="module")
def default():
    return compose_ipv6()


def addr(packed: bytes) -> str:
    return str(ipaddress.IPv6Address(packed))


def mac(packed: bytes) -> str:
    return ":".join(f"{b:02x}" for b in packed)


def icmp_checksum_ok(pkt) -> bool:
    ip = pkt[IPv6]
    icmp = bytes(ip.payload)[:ip.plen] if ip.nh == 58 else bytes(ip.payload.payload)
    zeroed = icmp[:2] + b"\x00\x00" + icmp[4:]
    return in6_chksum(58, ip, zeroed) == int.from_bytes(icmp[2:4], "big")


def ras(frames):
    return [(t, p) for t, p, _ in frames if ICMPv6ND_RA in p]


def router_of(plan):
    topology = plan.topology
    return topology.subnets[topology.sensor].router.interface_on(topology.sensor)


def test_router_advertisements_carry_the_ula_prefix_mtu_and_source_link_layer_address(default):
    plan, ipv6, frames = default
    router = router_of(plan)
    advertised = ras(frames)
    assert advertised
    prefix = ipaddress.IPv6Network((ipv6.prefix + bytes(8), 64))
    third_octet = ipaddress.IPv4Address(router.ip).packed[2]
    assert prefix.subnet_of(ipaddress.IPv6Network("fd00::/8"))
    assert int.from_bytes(ipv6.prefix[6:8], "big") == int(str(third_octet), 16)
    router_mac = bytes.fromhex(router.mac.replace(":", ""))
    eui64 = bytes((router_mac[0] ^ 2,)) + router_mac[1:3] + b"\xff\xfe" + router_mac[3:]
    for _, pkt in advertised:
        assert (pkt.src, pkt.dst) == (router.mac, "33:33:00:00:00:01")
        assert (pkt[IPv6].src, pkt[IPv6].dst, pkt[IPv6].hlim) == (addr(b"\xfe\x80" + bytes(6) + eui64), "ff02::1", 255)
        ra = pkt[ICMPv6ND_RA]
        assert (ra.chlim, ra.M, ra.O, ra.routerlifetime, ra.reachabletime, ra.retranstimer) == (0, 0, 0, 1800, 0, 0)
        assert icmp_checksum_ok(pkt)
        options = [type(layer) for layer in ra.payload.iterpayloads()]
        assert options == [ICMPv6NDOptPrefixInfo, ICMPv6NDOptMTU, ICMPv6NDOptSrcLLAddr]
        info = ra[ICMPv6NDOptPrefixInfo]
        assert (info.len, info.prefixlen, info.L, info.A, info.validlifetime, info.preferredlifetime) == (
            4, 64, 1, 1, 2592000, 604800)
        assert ipaddress.IPv6Network(f"{info.prefix}/64") == prefix
        assert ra[ICMPv6NDOptMTU].mtu == 1500 and ra[ICMPv6NDOptSrcLLAddr].lladdr == router.mac
        assert pkt[IPv6].plen == 64


def test_solicited_advertisements_follow_router_solicitations_rate_limited(default):
    # Default: hosts come up together at the capture start; "spread": one per second, 5 min in.
    for plan, ipv6, frames in (default, compose_ipv6("spread", starts={})):
        advertised = [t for t, _ in ras(frames)]
        solicits = [(t, p.src) for t, p, _ in frames if ICMPv6ND_RS in p]
        assert solicits and len(advertised) >= 2
        # MIN_DELAY_BETWEEN_RAS between any two multicast RAs.
        assert all(b - a >= 3.0 for a, b in zip(advertised, advertised[1:]))
        for a, b in zip(advertised, advertised[1:]):
            between = [t for t, _ in solicits if a < t < b]
            if between:  # the first RS is answered 0-0.5 s later, or 3 s after the previous RA
                assert b <= max(between[0], a + 3.0) + 0.5 + 1e-9
            else:  # unsolicited: the interval timer restarts after every multicast RA
                assert 198.0 <= b - a <= 600.0
        # A host solicits only after DAD of its link-local address and stops once it has an RA.
        for host_id, host_mac in ipv6.mac.items():
            mine = [t for t, src in solicits if src == mac(host_mac)]
            first_ra = min(t for t in advertised if t >= ipv6.valid[host_id])
            assert len(mine) <= 3 and all(ipv6.valid[host_id] < t < first_ra for t in mine)


def test_a_solicitation_soon_after_an_advertisement_waits_for_min_delay_between_ras():
    first, second = "hmi", "historian"
    # The first host comes up at 0 s, the second 1.6 s later: its link-local address is usable
    # only after the RA that answered the first host, and its RS comes less than 3 s after it.
    plan, ipv6, frames = compose_ipv6("ratelimit", starts={first: 0.0, second: 1.6})
    advertised = [t for t, _ in ras(frames)]
    solicits = [(t, p.src) for t, p, _ in frames if ICMPv6ND_RS in p]
    rs_first = min(t for t, src in solicits if src == mac(ipv6.mac[first]))
    rs_second = min(t for t, src in solicits if src == mac(ipv6.mac[second]))
    ra_first = min(t for t in advertised if t > rs_first)
    ra_second = min(t for t in advertised if t > rs_second)
    assert 0.0 <= ra_first - rs_first <= 0.5
    assert rs_second - ra_first < 3.0 and ra_second > ra_first
    assert 3.0 <= ra_second - ra_first <= 3.5


def test_slaac_addresses_use_the_advertised_prefix_and_pass_dad_before_use(default):
    plan, ipv6, frames = default
    prefix = ipaddress.IPv6Network((ipv6.prefix + bytes(8), 64))
    advertised = [t for t, _ in ras(frames)]
    formed: dict[str, list] = {}
    for t, pkt, _ in frames:
        if ICMPv6ND_NS in pkt and pkt[IPv6].src == "::":
            target = ipaddress.IPv6Address(pkt[ICMPv6ND_NS].tgt)
            if target in prefix:
                formed.setdefault(pkt.src, []).append((t, target))
                assert ICMPv6NDOptSrcLLAddr not in pkt and pkt[IPv6].dst == addr(
                    bytes.fromhex("ff0200000000000000000001ff") + target.packed[13:])
    assert set(formed) == {mac(m) for m in ipv6.mac.values()}
    for host_id, link_local in ipv6.address.items():
        host_mac = mac(ipv6.mac[host_id])
        dads = formed[host_mac]
        if plan.topology.by_id[host_id].device.ipv6.temporary:
            assert len(dads) == 2 and dads[0][1] != dads[1][1], "a stable and a temporary address"
        else:  # embedded Linux: one address, modified EUI-64 like the link-local one
            assert [target.packed[8:] for _, target in dads] == [link_local[8:]]
        first_ra = min(t for t in advertised if t >= ipv6.valid[host_id])
        for t, target in dads:
            assert first_ra < t < first_ra + 0.2
            group = addr(bytes.fromhex("ff0200000000000000000001ff") + target.packed[13:])
            joins = [u for u, p, _ in frames if ICMPv6MLReport2 in p and p.src == host_mac and u <= t
                     and p[IPv6].src == addr(link_local) and group in {r.dst for r in p[ICMPv6MLReport2].records}]
            assert joins, "the solicited-node group is joined (from the link-local address) before DAD"
    # Nothing is ever sent from a SLAAC address: IPv4 outranks the ULA prefix (RFC 6724).
    assert not [p for _, p, _ in frames if IPv6 in p and ipaddress.IPv6Address(p[IPv6].src) in prefix]
    # Nobody defends the tentative addresses.
    assert not [p for _, p, _ in frames if ICMPv6ND_NA in p and ipaddress.IPv6Address(p[ICMPv6ND_NA].tgt) in prefix]


def test_neighbor_solicitations_and_advertisements_carry_rfc_4861_flags_and_targets(default):
    plan, ipv6, frames = default
    router = router_of(plan)
    router_ll = ras(frames)[0][1][IPv6].src
    hosts = {mac(m): addr(ipv6.address[h]) for h, m in ipv6.mac.items()}
    unicast = [(t, p) for t, p, _ in frames if (ICMPv6ND_NS in p or ICMPv6ND_NA in p) and p[IPv6].src != "::"]
    resolutions = probes_by_router = 0
    for index, (t, pkt) in enumerate(unicast):
        assert pkt[IPv6].hlim == 255 and icmp_checksum_ok(pkt)
        if ICMPv6ND_NS not in pkt:
            continue
        ns = pkt[ICMPv6ND_NS]
        reply_t, reply = next((u, p) for u, p in unicast[index + 1:] if ICMPv6ND_NA in p and p.dst == pkt.src)
        na = reply[ICMPv6ND_NA]
        assert 0 < reply_t - t < 0.001 and na.tgt == ns.tgt and reply[IPv6].dst == pkt[IPv6].src
        assert ns[ICMPv6NDOptSrcLLAddr].lladdr == pkt.src
        if pkt.src in hosts:
            assert (pkt[IPv6].src, ns.tgt, reply.src) == (hosts[pkt.src], router_ll, router.mac)
            # address resolution: solicited-node group; NA with Override and TLLA
            group = bytes.fromhex("ff0200000000000000000001ff") + ipaddress.IPv6Address(router_ll).packed[13:]
            assert (pkt[IPv6].dst, pkt.dst) == (addr(group), "33:33:" + mac(group[12:]))
            assert (na.R, na.S, na.O) == (1, 1, 1) and reply[ICMPv6NDOptDstLLAddr].lladdr == router.mac
            resolutions += 1
        else:  # the router probes a host it has just answered (STALE -> DELAY -> PROBE)
            assert pkt.src == router.mac and pkt[IPv6].src == router_ll and ns.tgt == hosts[pkt.dst]
            assert pkt[IPv6].dst == ns.tgt
            assert (na.R, na.S, na.O) == (0, 1, 1) and reply[ICMPv6NDOptDstLLAddr].lladdr == pkt.dst
            answered = [u for u, p in unicast[:index] if ICMPv6ND_NA in p and p.src == router.mac and p.dst == pkt.dst]
            assert 5.0 <= t - answered[-1] <= 5.005
            probes_by_router += 1
    # Each host resolves its router once, the router probes it once 5 s later, and with no IPv6
    # traffic over the router nobody probes again (no NUD from hosts).
    assert resolutions == probes_by_router == len(hosts)


def test_router_starting_inside_the_capture_runs_dad_joins_all_routers_and_sends_initial_ras():
    plan, ipv6, frames = compose_ipv6("routerup", router_up=100.0)
    router = router_of(plan)
    t0 = plan.start_epoch
    mine = [(t, p) for t, p, _ in frames if p.src == router.mac]
    (t_join, join), (t_dad, dad) = mine[:2]
    assert ICMPv6MLReport2 in join and join[IPv6].src == "::" and t_join == t0 + 100.0
    assert ICMPv6ND_NS in dad and dad[IPv6].src == "::" and dad[ICMPv6ND_NS].tgt.startswith("fe80::")
    reports = [p for _, p in mine if ICMPv6MLReport2 in p and p[IPv6].src == dad[ICMPv6ND_NS].tgt]
    assert reports and "ff02::2" in {r.dst for r in reports[0][ICMPv6MLReport2].records}
    advertised = [t for t, _ in ras(frames)]
    assert advertised[0] >= t_dad + 1.0
    initial = advertised[:4]
    assert all(b - a <= 16.0 for a, b in zip(initial, initial[1:]))
    # Hosts that came up before the router sent all their solicitations, then SLAAC on the first RA.
    solicits = [t for t, p, _ in frames if ICMPv6ND_RS in p]
    assert len(solicits) == 3 * len(ipv6.address) and max(solicits) < t0 + 100.0
    dads = [t for t, p, _ in frames if ICMPv6ND_NS in p and p[IPv6].src == "::" and p.src != router.mac
            and not p[ICMPv6ND_NS].tgt.startswith("fe80::")]
    expected = sum(2 if plan.topology.by_id[h].device.ipv6.temporary else 1 for h in ipv6.address)
    assert len(dads) == expected and min(dads) > advertised[0]


def test_same_seed_gives_identical_frames_and_another_seed_another_prefix(default):
    _, ipv6, frames = default
    _, again, frames_again = compose_ipv6()
    assert [(t, data) for t, _, data in frames] == [(t, data) for t, _, data in frames_again]
    _, other, _ = compose_ipv6("another")
    assert other.prefix[:6] != ipv6.prefix[:6]


@pytest.mark.skipif(not find_tool("tshark"), reason="requires tshark")
def test_tshark_decodes_every_frame_without_errors(default, tmp_path):
    plan, ipv6, frames = default
    pcap = tmp_path / "ipv6.pcap"
    write_pcap(pcap, ((round(t * 1_000_000), data) for t, _, data in frames))
    fields = ["frame.number", "_ws.malformed", "_ws.expert.severity", "icmpv6.checksum.status", "icmpv6.type",
              "icmpv6.opt.prefix"]
    out = subprocess.run([find_tool("tshark"), "-n", "-r", str(pcap), "-T", "fields", "-E", "separator=|",
                          "-E", "occurrence=a", "-E", "aggregator=,"] + [a for f in fields for a in ("-e", f)],
                         capture_output=True, text=True, check=True).stdout
    rows = [line.split("|") for line in out.splitlines()]
    assert len(rows) == len(frames)
    prefix = str(ipaddress.IPv6Address(ipv6.prefix + bytes(8)))
    for _, malformed, severity, status, kind, advertised in rows:
        assert not malformed
        assert all(not s or (int(s) & 0x00F00000) < 0x00800000 for s in severity.split(","))
        assert status == "1"
        if kind == "134":
            assert advertised == prefix
    assert {r[4] for r in rows} == {"133", "134", "135", "136", "143"}
