"""End-to-end: record real loopback traffic, compose, and check the result with tshark/Scapy
(and Suricata, when installed, for the generated detection rules).

Needs Wireshark (tshark + dumpcap) and loopback capture rights; skipped otherwise.
"""

import datetime as dt
import hashlib
import ipaddress
import json
import re
import shutil
import subprocess
from collections import Counter

import pytest
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.utils import PcapReader, RawPcapReader

from pcapforge.compose import compose
from pcapforge.detections import SID_BASE
from pcapforge.pipeline import generate
from pcapforge.plan import build_plan
from pcapforge.profiles import device
from pcapforge.record import recording_for
from pcapforge.scenario import find
from pcapforge.tools import MIN_TSHARK, find_tool, tshark_version
from pcapforge.zeek import find_zeek, write_zeek_logs
from sigma_eval import hits, load_rules

SCENARIO = "ot-modbus-write-manipulation"
DURATION = 600.0

pytestmark = pytest.mark.skipif(
    not find_tool("tshark") or not (find_tool("dumpcap") or find_tool("tcpdump"))
    or tshark_version() < MIN_TSHARK,
    reason="requires tshark >= 4.4 and dumpcap/tcpdump with loopback capture rights",
)


@pytest.fixture(scope="module", params=["easy", "medium", "hard"])
def generated(request, tmp_path_factory):
    out = tmp_path_factory.mktemp(request.param)
    result = generate(find(SCENARIO), request.param, "pytest", out, duration=DURATION, siem=True)
    answers = json.loads(result.answers.read_text(encoding="utf-8"))
    return result, answers


def jsonl(path):
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh]


def tshark_fields(pcap, display_filter, fields):
    cmd = [find_tool("tshark"), "-n", "-r", str(pcap), "-Y", display_filter, "-T", "fields",
           "-E", "separator=|"] + [arg for f in fields for arg in ("-e", f)]
    out = subprocess.run(cmd, capture_output=True, text=True, check=True).stdout
    return [line.split("|") for line in out.splitlines() if line]


def test_capture_passes_integrity_and_answer_key_checks(generated):
    result, _ = generated
    failed = [c for c in result.report.checks if not c["ok"]]
    assert result.report.ok, failed


def test_every_recorded_write_in_the_key_matches_the_frame_it_points_to(generated):
    result, answers = generated
    change = answers["facts"]["change"]
    for write in change["writes"]:
        frame = write["request"]["frame"]
        rows = tshark_fields(result.pcap, f"frame.number == {frame}",
                             ["ip.src", "ip.dst", "tcp.dstport", "modbus.func_code",
                              "modbus.reference_num", "modbus.regval_uint16", "frame.time_epoch"])
        assert len(rows) == 1, f"frame {frame} not found"
        src, dst, port, func, ref, value, epoch = rows[0]
        assert (src, dst, port) == (change["source"]["ip"], change["target"]["ip"], "502")
        assert int(func) == write["function"]
        assert int(ref) == write["address"]
        assert [int(v) for v in value.split(",")] == write["registers"]
        assert abs(float(epoch) - write["request"]["epoch"]) < 1e-5


def test_timeline_is_ordered_and_inside_the_capture(generated):
    _, answers = generated
    epochs = [e["epoch"] for e in answers["timeline"]]
    assert epochs == sorted(epochs)
    first, last = answers["capture"]["start"], answers["capture"]["end"]
    assert all(first <= e["time"] <= last for e in answers["timeline"])


def test_checksums_hold_when_recomputed_by_scapy(generated):
    result, _ = generated
    checked = 0
    with PcapReader(str(result.pcap)) as reader:
        for index, pkt in enumerate(reader):
            if index >= 3000:
                break
            if IP not in pkt:
                continue
            ip = pkt[IP]
            fresh = IP(bytes(ip))
            del fresh.chksum
            layers = [layer for layer in (TCP, UDP) if layer in fresh]
            for layer in layers:
                del fresh[layer].chksum
            rebuilt = IP(bytes(fresh))
            assert rebuilt.chksum == ip.chksum
            for layer in layers:
                assert rebuilt[layer].chksum == ip[layer].chksum
            checked += 1
    assert checked > 1000


def test_handout_does_not_reveal_an_unknown_source(generated):
    result, answers = generated
    source = answers["facts"]["change"]["source"]
    briefing = result.handout.read_text(encoding="utf-8")
    if source["role"] in ("rogue", "itpc"):
        assert source["ip"] not in briefing
        assert source["name"] not in briefing


def test_group_and_broadcast_frames_carry_matching_l2_addresses_and_stay_on_the_sensor_segment(generated):
    result, answers = generated
    sensor = ipaddress.ip_network(answers["capture"]["sensor_subnet"])
    broadcasts = ", ".join(str(ipaddress.ip_network(s["cidr"]).broadcast_address)
                           for s in answers["topology"]["subnets"])
    display_filter = f"ip && (ip.dst == 224.0.0.0/4 || eth.dst.ig == 1 || ip.dst in {{{broadcasts}}})"
    rows = tshark_fields(result.pcap, display_filter, ["eth.dst", "ip.src", "ip.dst"])
    for eth_dst, src, dst in rows:
        if dst == "255.255.255.255":  # DHCP: limited broadcast, also from a client without an address
            assert eth_dst == "ff:ff:ff:ff:ff:ff" and (src == "0.0.0.0" or ipaddress.ip_address(src) in sensor)
            continue
        assert ipaddress.ip_address(src) in sensor, f"{src} -> {dst} is not link-local to the sensor"
        group = ipaddress.ip_address(dst)
        if group.is_multicast:
            low = (int(group) & 0x7FFFFF).to_bytes(3, "big")
            assert eth_dst == "01:00:5e:" + ":".join(f"{b:02x}" for b in low), f"{dst} sent to {eth_dst}"
        else:
            assert (dst, eth_dst) == (str(sensor.broadcast_address), "ff:ff:ff:ff:ff:ff")
    if answers["scenario"]["difficulty"] != "easy":
        assert rows, "Windows hosts on the sensor segment send link-local chatter"


def test_dhcp_clients_lease_their_address_the_way_rfc_2131_delivers_it(generated):
    result, answers = generated
    facts = answers["facts"]
    clients = [c for actor in ("rogue_join", "service_visit") if actor in facts for c in facts[actor]["clients"]]
    server = facts["dhcp_service"]["hosts"][0]
    rows = tshark_fields(result.pcap, "dhcp", ["frame.time_epoch", "eth.src", "eth.dst", "ip.src", "ip.dst",
                                               "udp.srcport", "udp.dstport", "dhcp.option.dhcp", "dhcp.flags.bc",
                                               "dhcp.hw.mac_addr", "dhcp.ip.your", "dhcp.option.hostname",
                                               "dhcp.option.dhcp_server_id", "dhcp.option.router"])
    for row in rows:  # chaddr, and again in the client identifier (option 61)
        row[9] = row[9].split(",")[0]
    assert {c["host"]["mac"] for c in clients} == {r[9] for r in rows}
    for client in clients:
        host = client["host"]
        mine = [r for r in rows if r[9] == host["mac"]]
        types = [int(r[7]) for r in mine]
        assert types[:4] == [1, 2, 3, 5], "DISCOVER / OFFER / REQUEST / ACK"
        windows = client["style"] == "windows"
        for epoch, eth_src, eth_dst, src, dst, sport, dport, kind, bc, _, yiaddr, name, server_id, router in mine:
            kind = int(kind)
            if kind in (1, 3):  # the client has no address yet
                assert (src, dst, eth_dst, sport, dport) == ("0.0.0.0", "255.255.255.255", "ff:ff:ff:ff:ff:ff",
                                                             "68", "67")
                assert eth_src == host["mac"] and name == host["name"] and (bc == "True") == windows
            elif kind in (2, 5) and yiaddr != "0.0.0.0":  # lease: broadcast flag -> broadcast, else unicast
                assert (src, eth_src, yiaddr, server_id, router) == (server["ip"], server["mac"], host["ip"],
                                                                      server["ip"], server["ip"])
                assert (dst, eth_dst) == (("255.255.255.255", "ff:ff:ff:ff:ff:ff") if windows
                                          else (host["ip"], host["mac"]))
            elif kind == 8:  # DHCPINFORM from the leased address
                assert (src, dst) == (host["ip"], "255.255.255.255")
            elif kind == 7:  # DHCPRELEASE: unicast to the server
                assert (src, dst, eth_dst) == (host["ip"], server["ip"], server["mac"])
        assert (8 in types) == (client["inform"] is not None) and (7 in types) == (client["released"] is not None)
        # Address conflict detection: ARP probes from 0.0.0.0 for the lease, then announcements, and the
        # address is not used before that.
        ack = next(float(r[0]) for r in mine if r[7] == "5")
        probes = tshark_fields(result.pcap, f"arp.src.hw_mac == {host['mac']} && arp.dst.proto_ipv4 == {host['ip']}",
                               ["frame.time_epoch", "arp.src.proto_ipv4"])
        senders = [s for _, s in probes]
        assert senders[:3] == ["0.0.0.0"] * 3 and host["ip"] in senders[3:]
        assert all(float(t) > ack for t, _ in probes)
        ready = max(float(t) for t, s in probes if s == "0.0.0.0")
        used = tshark_fields(result.pcap, f"ip.src == {host['ip']} && !dhcp", ["frame.time_epoch"])
        assert all(float(t) > ready for (t,) in used)
    records = jsonl(result.exports["siem/dhcp.jsonl"])
    assert len(records) == len(rows)
    assert {r["host_name"] for r in records if r["message"] == "discover"} == {c["host"]["name"] for c in clients}


def test_same_seed_is_byte_identical_and_new_seed_changes_presentation(tmp_path):
    scenario = find(SCENARIO)
    plan = build_plan(scenario, "easy", "repro", duration_override=300)
    recording, _ = recording_for(plan)
    digests, sources = [], []
    for seed, name in (("repro", "a"), ("repro", "b"), ("other", "c")):
        plan = build_plan(scenario, "easy", seed, base_seed="repro", duration_override=300)
        out = compose(plan, recording, tmp_path / f"{name}.pcap", seed)
        digests.append(hashlib.sha256(out.path.read_bytes()).hexdigest())
        sources.append(plan.topology.by_id["rogue"].ip)
    assert digests[0] == digests[1]
    assert digests[0] != digests[2]
    assert sources[0] != sources[2]


def test_modbus_log_flags_exactly_the_incident_writes_as_out_of_band(generated):
    result, answers = generated
    records = jsonl(result.exports["siem/modbus.jsonl"])
    change, operator = answers["facts"]["change"], answers["facts"]["operator_changes"]
    writes = [r for r in records if r["write"]]
    assert len(writes) == change["write_count"] + operator["write_count"]

    flagged = {(r["src"], r["dest"], r["address"], tuple(r["values"]), r["request_frame"], r["point"], r["value"])
               for r in writes if r["in_normal_band"] is False}
    assert flagged == {(change["source"]["ip"], change["target"]["ip"], w["address"], tuple(w["registers"]),
                        w["request"]["frame"], w["point"], w["value"]) for w in change["writes"]}

    by_frame = {r["request_frame"]: r for r in writes}
    for w in operator["writes"]:
        record = by_frame[w["request"]["frame"]]
        assert (record["src"], record["dest"], record["address"], record["values"], record["point"]) == (
            operator["source"]["ip"], w["target"]["ip"], w["address"], w["registers"], w["point"])
        assert record["in_normal_band"] is True

    # Each annotated write carries the register-map metadata: a non-empty description and the
    # vendor (Modicon 4xxxx) register number matching the 0-based holding address.
    single = [r for r in writes if isinstance(r.get("point"), str)]
    assert single and all(r["desc"] and r["register"].split("-")[0] == str(40001 + r["address"]) for r in single)


def test_flow_totals_account_for_every_ip_packet_and_byte(generated):
    result, _ = generated
    packets = octets = 0
    with PcapReader(str(result.pcap)) as reader:
        for pkt in reader:
            if IP in pkt:
                packets += 1
                octets += pkt[IP].len
            elif IPv6 in pkt:
                packets += 1
                octets += 40 + pkt[IPv6].plen
    flows = jsonl(result.exports["siem/flows.jsonl"])
    assert sum(f["packets_out"] + f["packets_in"] for f in flows) == packets
    assert sum(f["bytes_out"] + f["bytes_in"] for f in flows) == octets


def test_windows_hosts_and_the_router_show_an_ipv6_baseline_on_the_sensor_segment(generated):
    result, answers = generated
    # Neighbor Discovery, MLD and the multicast datagrams (the dual-stack conversations have their own test).
    rows = tshark_fields(result.pcap, "ipv6 && (icmpv6 || ipv6.dst == ff00::/8)",
                         ["frame.time_epoch", "eth.src", "eth.dst", "ipv6.src", "ipv6.dst",
                          "ipv6.hlim", "icmpv6.type", "udp.dstport",
                          "dhcpv6.duidllt.link_layer_addr", "dns.qry.name",
                          "icmpv6.nd.ns.target_address", "icmpv6.opt.prefix"])
    mode = find(SCENARIO).level(answers["scenario"]["difficulty"])["vars"].get("ipv6")
    if not mode:
        assert not rows
        return
    dual = mode == "dual"
    sensor = next(s for s in answers["topology"]["subnets"] if s["sensor"])
    ipv6_hosts = [h for h in answers["topology"]["hosts"] if device(h["device"]).ipv6]
    windows = {i["mac"] for h in ipv6_hosts for i in h["interfaces"] if i["subnet"] == sensor["id"]}
    # Embedded Linux controllers (PLCnext, WAGO, RTAC): modified EUI-64 identifiers, no temporary address.
    eui64 = {i["mac"] for h in ipv6_hosts if not device(h["device"]).ipv6.random_iid
             for i in h["interfaces"] if i["subnet"] == sensor["id"]}
    router = next(i["mac"] for h in answers["topology"]["hosts"] for i in h["interfaces"]
                  if i["subnet"] == sensor["id"] and i["ip"] == sensor["gateway"])
    hop_limits = {"133": 255, "134": 255, "135": 255, "136": 255, "143": 1, "5355": 1, "5353": 255, "547": 1}
    prefixes = {r[11] for r in rows if r[6] == "134"}
    assert len(prefixes) == 1, "the firewall advertises one prefix"
    prefix = ipaddress.IPv6Network(f"{prefixes.pop()}/64")
    # A ULA prefix, or on a dual-stack site a global one from the documentation range.
    assert prefix.subnet_of(ipaddress.IPv6Network("2001:db8::/32" if dual else "fd00::/8"))
    link_local = ipaddress.IPv6Network("fe80::/64")
    address_of: dict[str, str] = {}
    dad: dict[str, float] = {}  # tentative address -> DAD Neighbor Solicitation
    slaac: dict[str, set[str]] = {}
    for epoch, mac, eth_dst, src, dst, hops, icmp_type, port, duid_mac, _name, target, _prefix in rows:
        assert mac in windows | {router}, f"IPv6 from {mac}, not a Windows host or the router on the sensor segment"
        assert int(hops) == hop_limits[icmp_type or port]
        group = ipaddress.IPv6Address(dst)
        if group.is_multicast:
            assert eth_dst == "33:33:" + ":".join(f"{b:02x}" for b in group.packed[-4:])
        else:  # unicast Neighbor Discovery between a host and the router (NUD of a global address when dual)
            assert icmp_type in ("135", "136") and {mac, eth_dst} <= windows | {router} and router in {mac, eth_dst}
            assert group in link_local or (dual and group in prefix)
        if icmp_type == "134":
            assert (mac, dst) == (router, "ff02::1")
        if src == "::":  # interface start / SLAAC: MLD join of the solicited-node group, then DAD
            if icmp_type == "135":
                dad[target] = float(epoch)
                if ipaddress.IPv6Address(target) in prefix:
                    slaac.setdefault(mac, set()).add(target)
            continue
        assert float(epoch) >= dad.get(src, 0.0) + 0.999, "an address is used before DAD completes"
        if ipaddress.IPv6Address(src) in link_local:
            assert address_of.setdefault(mac, src) == src, "one link-local address per host"
        else:  # a dual-stack host answering the router's probe of its global address
            assert dual and icmp_type == "136" and ipaddress.IPv6Address(src) in prefix
        if duid_mac:
            assert duid_mac == mac
    assert {r[6] for r in rows} >= {"134", "143"} and {r[7] for r in rows} >= {"5355", "5353", "547"}
    # Every host that solicited a router formed a stable and a temporary address in the prefix
    # (the sensor may miss one of the DAD solicitations). Dual-stack hosts were configured before.
    solicited = {r[1] for r in rows if r[6] == "133"}
    assert dual or solicited
    assert all(1 <= len(slaac.get(mac, ())) <= (1 if mac in eui64 else 2) for mac in solicited)
    assert sum(len(addresses) for addresses in slaac.values()) >= sum(
        1 if mac in eui64 else 2 for mac in solicited) - 1
    for mac in eui64:
        b = bytes.fromhex(mac.replace(":", ""))
        iid = bytes((b[0] ^ 2,)) + b[1:3] + b"\xff\xfe" + b[3:]
        assert address_of.get(mac, str(ipaddress.IPv6Address(b"\xfe\x80" + bytes(6) + iid))) == str(
            ipaddress.IPv6Address(b"\xfe\x80" + bytes(6) + iid))
        assert all(ipaddress.IPv6Address(a).packed[8:] == iid for a in slaac.get(mac, ()))
    # Process traffic stays IPv4: the HMIs and SCADA address the controllers by their IPv4 address.
    assert not tshark_fields(result.pcap, "ipv6 && (mbtcp || s7comm || enip || dnp3 || iec60870_104)",
                             ["frame.number"])
    # LLMNR asks the same names over IPv6 as over IPv4.
    v4 = {r[0] for r in tshark_fields(result.pcap, "ip && llmnr", ["dns.qry.name"])}
    assert {r[9] for r in rows if r[7] == "5355"} == v4


def test_opcua_background_runs_only_between_the_historian_and_the_scada_server(generated):
    result, answers = generated
    rows = tshark_fields(result.pcap, "tcp.port == 4840 || opcua",
                         ["ip.src", "ip.dst", "ipv6.src", "ipv6.dst", "opcua.servicenodeid.numeric"])
    if answers["scenario"]["difficulty"] == "easy":
        assert not rows
        return
    collector = answers["facts"]["historian_opcua"]
    client, server = collector["hosts"][0], collector["server"]
    hosts = {h["id"]: h for h in answers["topology"]["hosts"]}
    # Over IPv4, or on a dual-stack site from the historian's temporary to the server's stable address.
    v6 = hosts[client["id"]]["ipv6"]
    pair = frozenset((v6["temporary"], server["ipv6"])) if v6 else frozenset((client["ip"], server["ip"]))
    assert {frozenset(r[2:4] if v6 else r[:2]) for r in rows} == {pair}
    services = Counter(int(r[4]) for r in rows if r[4])
    # Messages the sensor missed show up as a gap before the sender's next segment.
    missed = len(tshark_fields(result.pcap, "tcp.port == 4840 && tcp.analysis.lost_segment", ["frame.number"]))
    # The session predates the capture: watchdog Reads (631/634) and Publish (826/829) only.
    assert services[631] > 0 and abs(services[631] - services[634]) <= missed
    assert services[826] > services[631] and abs(services[826] - services[829]) <= missed
    assert set(services) <= {631, 634, 826, 829, 446, 449}  # + OpenSecureChannel renewals


def test_sensor_artefacts_follow_the_level_impairments(generated):
    result, answers = generated
    impairments = find(SCENARIO).level(answers["scenario"]["difficulty"]).get("impairments", {})
    vlan = impairments.get("vlan")
    with RawPcapReader(str(result.pcap)) as reader:
        frames = [(meta.sec * 1_000_000 + meta.usec, data) for data, meta in reader]
    tags = Counter(data[12:16] for _, data in frames)
    if vlan:
        assert tags == {b"\x81\x00" + vlan.to_bytes(2, "big"): len(frames)}, "every frame carries the 802.1Q tag"
    else:
        assert b"\x81\x00" not in {tag[:2] for tag in tags}
    # SPAN duplicates: the same bytes again a few microseconds later.
    copies = 0
    for index, (micros, data) in enumerate(frames):
        for later, other in frames[index + 1:index + 6]:
            # (MLD reports repeat byte for byte, but 0.2-1 s later)
            if other == data and later - micros <= 50:
                copies += 1
    assert (copies > 0) == bool(impairments.get("span_duplicates"))
    # Sensor drops: tshark reports the gaps.
    gaps = tshark_fields(result.pcap, "tcp.analysis.lost_segment || tcp.analysis.ack_lost_segment", ["frame.number"])
    assert bool(gaps) == bool(impairments.get("sensor_drop"))


def _eve_epoch(timestamp: str) -> float:
    return dt.datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S.%f%z").timestamp()


def test_sigma_rules_ship_and_match_the_incident_in_the_modbus_export(generated):
    result, answers = generated
    change = answers["facts"]["change"]
    rules = load_rules(result.directory / "detections" / "sigma")
    siem = result.directory / "siem"
    incident = {w["request"]["frame"] for w in change["writes"]}
    # On easy/medium the writer is an unapproved host; on hard it is the legitimate workstation
    # (there the band rule, not the source rule, catches the out-of-band writes).
    unapproved = {r["request_frame"] for r in hits(rules["Modbus write from an unapproved host"], siem)}
    assert unapproved == (set() if answers["scenario"]["difficulty"] == "hard" else incident)
    # Every incident write is out of band, and nothing else is.
    oob = {r["request_frame"] for r in hits(rules["Modbus setpoint written outside its normal band"], siem)}
    assert oob == incident
    # A DHCP client actor runs at every level (the rogue on easy, a service laptop on medium/hard).
    assert "New host leased an address on the control LAN" in rules


@pytest.mark.skipif(not shutil.which("suricata"), reason="requires suricata on PATH")
def test_suricata_rules_alert_on_out_of_band_writes_and_unapproved_writers(generated, tmp_path):
    result, answers = generated
    rules = result.exports["detections/suricata.rules"]
    # --init-errors-fatal: a rule Suricata cannot load fails the run instead of being skipped.
    # Offline reading needs no command socket; Debian/Ubuntu's config enables one under /var/run.
    run = subprocess.run([shutil.which("suricata"), "-r", str(result.pcap), "-S", str(rules),
                          "--set", "app-layer.protocols.modbus.enabled=true", "--set", "unix-command.enabled=no",
                          "--set", "app-layer.protocols.dnp3.enabled=yes",
                          "--set", "app-layer.protocols.enip.enabled=yes",
                          "-l", str(tmp_path), "-k", "none", "--init-errors-fatal"], capture_output=True, text=True)
    assert run.returncode == 0, run.stderr + run.stdout
    alerts = [e for e in jsonl(tmp_path / "eve.json") if e.get("event_type") == "alert"]

    # A FLOAT32 point stored low word first (CDAB) has two rules per side; exactly one fires per write.
    band_sids: dict[tuple[str, str], set[int]] = {}
    for m in re.finditer(r'msg:"PCAPFORGE OT (?P<point>\w+) written (?P<side>above|below) normal band.*?sid:(?P<sid>\d+);',
                         rules.read_text(encoding="utf-8")):
        band_sids.setdefault((m["point"], m["side"]), set()).add(int(m["sid"]))
    all_band = set().union(*band_sids.values())
    band_alerts = [a for a in alerts if a["alert"]["signature_id"] in all_band]
    change = answers["facts"]["change"]
    pair = {change["source"]["ip"], change["target"]["ip"]}
    expected = []
    for w in change["writes"]:
        sids = band_sids[(w["point"], "above" if w["value"] > w["normal"][1] else "below")]
        hits = [a for a in band_alerts if a["alert"]["signature_id"] in sids and {a["src_ip"], a["dest_ip"]} == pair
                and 0 <= _eve_epoch(a["timestamp"]) - w["request"]["epoch"] < 5]
        assert hits, f"no out-of-band alert for {w['point']} written in frame {w['request']['frame']}"
        expected.append(hits[0]["alert"]["signature_id"])
    # One band alert per incident write and none for the in-band operator writes.
    assert sorted(a["alert"]["signature_id"] for a in band_alerts) == sorted(expected)

    unapproved = [a for a in alerts if a["alert"]["signature_id"] == SID_BASE + 1]
    approved_writer = change["source"]["id"] == answers["facts"]["operator_changes"]["source"]["id"]
    assert approved_writer == (answers["scenario"]["difficulty"] == "hard")
    if approved_writer:
        assert not unapproved
    else:
        assert len(unapproved) >= change["write_count"]
        assert all({a["src_ip"], a["dest_ip"]} == pair for a in unapproved)


@pytest.mark.skipif(not find_zeek() and not shutil.which("docker"), reason="requires zeek (or docker)")
def test_zeek_sees_the_modbus_traffic_of_the_export_and_every_incident_write(generated, tmp_path):
    result, answers = generated
    logs = write_zeek_logs(result.pcap, answers, tmp_path / "zeek")
    requests = [r for r in jsonl(logs["modbus"]) if r["pdu_type"] == "REQ"]

    # Every incident write is one Zeek request record from the writer to the PLC at its frame's time.
    change = answers["facts"]["change"]
    writes = {"WRITE_SINGLE_REGISTER", "WRITE_MULTIPLE_REGISTERS", "WRITE_SINGLE_COIL", "WRITE_MULTIPLE_COILS"}
    for w in change["writes"]:
        found = [r for r in requests if r["func"] in writes and r["id.orig_h"] == change["source"]["ip"]
                 and r["id.resp_h"] == change["target"]["ip"] and abs(r["ts"] - w["request"]["epoch"]) < 1e-5]
        assert len(found) == 1, f"write in frame {w['request']['frame']}: {found}"

    conns = jsonl(logs["conn"])
    modbus_conns = [c for c in conns if c["id.resp_p"] == 502]
    # Zeek names the service once it has parsed payload (a connect / close without a request has none).
    unparsed = [(c["id.orig_h"], c["id.orig_p"], c["id.resp_h"], c.get("history"), c.get("service"))
                for c in modbus_conns if c.get("orig_bytes") and "modbus" not in c.get("service", "")]
    assert modbus_conns and not unparsed, unparsed
    # Site::local_nets is the scenario's subnets: every Modbus client and PLC is local.
    assert all(c["local_orig"] and c["local_resp"] for c in modbus_conns)

    if answers["scenario"]["difficulty"] == "easy":
        # Easy has no sensor drops, duplicates or retransmissions: Zeek parses exactly the Modbus
        # requests the pcapforge export has, and finds nothing odd in the TCP/IP layers.
        export = Counter((r["src"], r["src_port"], r["dest"], r["trans_id"])
                         for r in jsonl(result.directory / "siem" / "modbus.jsonl"))
        zeek = Counter((r["id.orig_h"], r["id.orig_p"], r["id.resp_h"], r["tid"]) for r in requests)
        assert zeek == export
        assert "weird" not in logs, (tmp_path / "zeek" / "weird.log").read_text(encoding="utf-8")[:2000]

    # Deterministic mode: a second run gives byte-identical logs.
    again = write_zeek_logs(result.pcap, answers, tmp_path / "zeek2")
    assert {name: path.read_bytes() for name, path in again.items()} == {
        name: path.read_bytes() for name, path in logs.items()}


def test_dual_stack_site_carries_only_windows_to_windows_services_over_ipv6(generated):
    result, answers = generated
    hosts = {h["id"]: h for h in answers["topology"]["hosts"]}
    dual = {h["id"] for h in hosts.values() if h["ipv6"]}
    if answers["scenario"]["difficulty"] != "hard":
        assert not dual  # ULA-only or no IPv6: no global addresses, nothing but ND / MLD / multicast
        assert not tshark_fields(result.pcap, "(tcp || udp) && ipv6 && !(ipv6.dst == ff00::/8)", ["frame.number"])
        return
    # Only Windows PCs and servers are dual-stack; PLCs (also on embedded Windows) stay IPv4.
    assert dual and all(hosts[h]["device"] in ("windows-workstation", "windows-server-vm", "hp-workstation",
                                               "scada-server-vm") for h in dual)
    by_address = {a: h for h in dual for a in hosts[h]["ipv6"].values()}
    rows = tshark_fields(result.pcap, "(tcp || udp) && ipv6 && !(ipv6.dst == ff00::/8)",
                         ["ipv6.src", "ipv6.dst", "tcp.dstport", "tcp.srcport", "udp.dstport", "udp.srcport",
                          "ipv6.hlim", "tcp.options.mss_val"])
    assert rows, "the historian's OPC UA session runs over IPv6"
    for src, dst, tdport, tsport, udport, usport, hlim, mss in rows:
        # Between two dual-stack hosts, from a client's temporary to a server's stable address.
        assert src in by_address and dst in by_address
        ports = {int(p) for p in (tdport, tsport, udport, usport) if p}
        assert ports & {53, 123, 4840}, ports
        assert not ports & {502, 102, 44818, 2404, 20000}
        assert int(hlim) in (127, 128)   # Windows hop limit 128, one less across the router
        if mss:
            assert int(mss) == 1440      # MSS of an IPv6 SYN on Ethernet
    # No Modbus or other PLC traffic over IPv6.
    assert not tshark_fields(result.pcap, "ipv6 && (mbtcp || s7comm || enip || cip)", ["frame.number"])
    # AAAA answers name the hosts' stable addresses; the IPv4-mapped recording form never leaks.
    stable = {hosts[h]["ipv6"]["stable"] for h in dual}
    answered = {a for (row,) in tshark_fields(result.pcap, "dns.aaaa", ["dns.aaaa"]) for a in row.split(",")}
    assert answered <= stable
    # Every RA advertises the dual-stack DNS server (RDNSS), and the dual-stack hosts query it over
    # IPv6 only: no IPv4 DNS from them.
    resolver = answers["facts"]["dns_service"]["hosts"][0]["ipv6"]
    assert resolver in stable
    advertised = tshark_fields(result.pcap, "icmpv6.type == 134", ["icmpv6.opt.rdnss", "icmpv6.opt.rdnss.lifetime"])
    assert advertised and {tuple(r) for r in advertised} == {(resolver, "1800")}
    queries6 = tshark_fields(result.pcap, "dns && udp.dstport == 53 && ipv6 && dns.flags.response == 0", ["ipv6.dst"])
    assert queries6 and {d for (d,) in queries6} == {resolver}
    v4 = {i["ip"] for h in dual for i in hosts[h]["interfaces"]}
    v4_dns = {s for (s,) in tshark_fields(result.pcap, "dns && udp.port == 53 && ip", ["ip.src"])}
    assert not v4_dns & v4 - {answers["facts"]["dns_service"]["hosts"][0]["ip"]}
