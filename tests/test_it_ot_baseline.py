"""The combined IT/OT baseline with an industrial DMZ (it-ot-baseline-operations): office LAN, DMZ and
plant control network on one firewall, no incident. The only cross-zone traffic is the plant historian
replicating to the DMZ replica over HTTPS on a fixed cadence, an office engineer's RDP session to the
DMZ jump host with the jump host's onward RDP session to the engineering workstation inside it, and
the control network's time sync from the DMZ. The answer key points at the right packets, the zones
stay apart on the wire, and no detection fires."""

import copy
import functools
import ipaddress
import json
import shutil
import subprocess

import pytest

from pcapforge.detections import SID_IT_BASE
from pcapforge.pipeline import generate
from pcapforge.plan import build_plan
from pcapforge.scenario import Scenario, ScenarioError, find
from pcapforge.tools import MIN_TSHARK, find_tool, tshark_version

try:
    from sigma_eval import correlation_groups, hits, load_rules
except ImportError:  # pragma: no cover
    correlation_groups = hits = load_rules = None

SCENARIO = "it-ot-baseline-operations"
# level -> (sensor subnet, capture duration of the e2e runs)
LEVELS = {"easy": ("dmz", 360.0), "medium": ("dmz", 360.0), "hard": ("control", 480.0)}
SEEDS = ("42", "7", "plant", "dmz")
ZONE_SIGMA = ("Connection into the OT control network from outside the control zone and DMZ",
              "RDP into the OT control network from a host other than the DMZ jump host")
SID_ZONE = (SID_IT_BASE + 1000, SID_IT_BASE + 1001)
BROADCAST = ipaddress.ip_address("255.255.255.255")

capture_tools = (find_tool("tshark") and (find_tool("dumpcap") or find_tool("tcpdump"))
                 and tshark_version() >= MIN_TSHARK)
needs_capture = pytest.mark.skipif(not capture_tools,
                                   reason="requires tshark >= 4.4 and dumpcap/tcpdump with loopback capture rights")


def tshark(pcap, display_filter, *fields):
    out = subprocess.run([find_tool("tshark"), "-n", "-r", str(pcap), "-Y", display_filter, "-T", "fields",
                          "-E", "occurrence=a", *[arg for f in fields for arg in ("-e", f)]],
                         capture_output=True, text=True, check=True).stdout
    return [line.split("\t") for line in out.splitlines() if line]


@functools.cache
def plans(level):
    return [build_plan(find(SCENARIO), level, seed) for seed in SEEDS]


def zone(topo, host_id):
    (subnet,) = topo.by_id[host_id].subnets
    return subnet


def session_window(plan, session):
    """(open, close) plan time of one rdp.client session from the facts."""
    connect = session["connect"]["$action"]
    close = next(a for a in plan.actions if a.op == "rdp.close" and a.actor == connect.actor
                 and a.host == connect.host and a.args["conn"] == connect.args["conn"])
    return connect.t, close.t


def named_hosts(topo, value):
    """Hosts an action argument names: a host id, a host group, or lists / dicts of them."""
    if isinstance(value, str):
        if value in topo.by_id:
            return [topo.by_id[value]]
        return list(topo.groups.get(value, []))
    if isinstance(value, (list, tuple)):
        return [h for v in value for h in named_hosts(topo, v)]
    if isinstance(value, dict):
        return [h for v in value.values() for h in named_hosts(topo, v)]
    return []


# -- plan ------------------------------------------------------------------------------


@pytest.mark.parametrize("level", LEVELS)
def test_three_zones_on_one_firewall_and_the_sensor_placement(level):
    plan = build_plan(find(SCENARIO), level, "42")
    topo = plan.topology
    assert topo.sensor == LEVELS[level][0]
    assert set(topo.by_id["fw"].subnets) == {"office", "servers", "dmz", "control"}
    assert zone(topo, "eng") == "office"
    assert zone(topo, "jump") == zone(topo, "dmz_hist") == "dmz"
    assert {zone(topo, h) for h in ("ews", "ot_hist", "hmi")} == {"control"}
    assert {zone(topo, p.id) for p in topo.groups["plc"]} == {"control"}


@pytest.mark.parametrize("level", LEVELS)
def test_rdp_chain_is_office_engineer_to_jump_host_to_ews_only(level):
    for plan in plans(level):
        topo, facts = plan.topology, plan.facts
        hops = set()
        for actor in (a for a in plan.actors if a.type == "rdp.client"):
            for session in facts[actor.id]["sessions"]:
                hops.add((zone(topo, session["source"]["$host"]), zone(topo, session["target"]["$host"])))
        assert hops == {("office", "dmz"), ("dmz", "control")}, plan.seed

        office, onward = facts["office_remote_access"], facts["jump_remote_access"]
        assert office["source"] == {"$host": "eng"} and office["target"] == {"$host": "jump"}
        assert onward["source"] == {"$host": "jump"} and onward["target"] == {"$host": "ews"}
        assert office["account"] == plan.vars["engineer_account"]
        assert onward["account"] == plan.vars["ot_admin_account"]
        assert office["port"] == onward["port"] == 3389
        for session in office["sessions"] + onward["sessions"]:
            assert session["requested_protocols"] == ["SSL", "CredSSP (HYBRID)"]
            assert session["selected_protocol"] == "CredSSP (HYBRID)"
            assert session["bursts"] > 0

        # The onward hop runs inside the engineer's session on the jump host: it opens after the
        # engineer has logged on and closes before the engineer leaves.
        (outer,), (inner,) = office["sessions"], onward["sessions"]
        o_open, o_close = session_window(plan, outer)
        i_open, i_close = session_window(plan, inner)
        assert o_open < i_open < i_close < o_close, (plan.seed, (o_open, o_close), (i_open, i_close))


@pytest.mark.parametrize("level", LEVELS)
def test_no_office_host_addresses_the_control_network(level):
    plan = build_plan(find(SCENARIO), level, "42")
    topo = plan.topology
    reached = {"office": set(), "control": set()}
    for action in plan.actions:
        side = zone(topo, action.host) if len(topo.by_id[action.host].subnets) == 1 else None
        if side in reached:
            reached[side].update(s for h in named_hosts(topo, action.args) if len(h.subnets) == 1
                                 for s in h.subnets)
    assert "control" not in reached["office"]
    assert reached["office"] >= {"servers", "dmz"}
    # The control network only ever names its own hosts and the DMZ (replica, time service, jump host).
    assert reached["control"] == {"control", "dmz"}


@pytest.mark.parametrize("level", LEVELS)
def test_replication_pushes_at_the_configured_interval(level):
    plan = build_plan(find(SCENARIO), level, "42")
    topo = plan.topology
    facts = plan.facts["ot_historian_replication"]
    interval = float(plan.vars["replication_interval"])
    assert facts["interval_s"] == interval
    assert zone(topo, facts["source"]["$host"]) == "control"
    assert zone(topo, facts["target"]["$host"]) == "dmz"
    assert facts["port"] == 443

    (channel,) = facts["channels"]
    pushes = [a for a in plan.actions if a.actor == "ot_historian_replication" and a.op == "hist.push"]
    assert len(pushes) == channel["pushes"]
    assert {(a.host, a.args["server"]) for a in pushes} == {("ot_hist", "dmz_hist")}
    # The session opens early in the capture and pushes until its end.
    connect = channel["connect"]["$action"]
    assert connect.t < pushes[0].t <= connect.t + interval
    assert plan.duration - pushes[-1].t <= 1.02 * interval
    gaps = [b.t - a.t for a, b in zip(pushes, pushes[1:])]
    assert all(0.98 * interval <= g <= 1.02 * interval for g in gaps), (min(gaps), max(gaps))
    lo, hi = plan.vars["replication_tags"]
    assert all(lo <= a.args["samples"] <= hi for a in pushes)


@pytest.mark.parametrize("level", LEVELS)
def test_self_signed_certificates_name_their_host_and_are_valid_during_the_capture(level):
    for plan in plans(level):
        topo = plan.topology
        for service in ("jump_rdp_service", "ews_rdp_service", "replica_service"):
            facts = plan.facts[service]
            host = topo.by_id[facts["hosts"][0]["$host"]]
            fqdn = f"{host.name.lower()}.{topo.domain}"
            cert = facts["certificate"]
            assert facts["fqdn"] == fqdn
            assert cert["subject"] == cert["issuer"] == f"CN={fqdn}" and cert["self_signed"]
            assert cert["not_before"] < plan.start_epoch
            assert plan.start_epoch + plan.duration < cert["not_after"], (plan.seed, service)
        # Each client asks for the server by the name on its certificate.
        assert plan.facts["office_remote_access"]["server_fqdn"] == plan.facts["jump_rdp_service"]["fqdn"]
        assert plan.facts["jump_remote_access"]["server_fqdn"] == plan.facts["ews_rdp_service"]["fqdn"]
        assert plan.facts["ot_historian_replication"]["server_fqdn"] == plan.facts["replica_service"]["fqdn"]


@pytest.mark.parametrize("via", ["replica_service", "jump_remote_access", "no_such_actor"])
def test_via_must_name_an_earlier_rdp_client_into_this_host(via):
    scenario = find(SCENARIO)
    doc = copy.deepcopy(scenario.doc)
    actor = next(a for a in doc["actors"] if a["id"] == "jump_remote_access")
    actor["params"]["via"] = via
    with pytest.raises(ScenarioError, match="via"):
        build_plan(Scenario(scenario.path, doc), "easy", "42")


# -- capture ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def runs(tmp_path_factory):
    """level -> (GenerateResult, answers); each level is generated once for the module."""
    cache = {}

    def run(level):
        if level not in cache:
            result = generate(find(SCENARIO), level, "pytest", tmp_path_factory.mktemp(level),
                              duration=LEVELS[level][1], siem=True)
            assert result.report.ok, [c for c in result.report.checks if not c["ok"]]
            cache[level] = result, json.loads(result.answers.read_text(encoding="utf-8"))
        return cache[level]

    return run


def site(answers):
    """(subnet id -> cidr, host id -> {subnet: (ip, mac)})."""
    cidrs = {s["id"]: s["cidr"] for s in answers["topology"]["subnets"]}
    hosts = {h["id"]: {i["subnet"]: (i["ip"], i["mac"]) for i in h["interfaces"]} for h in answers["topology"]["hosts"]}
    return cidrs, hosts


def siem(result, dataset):
    path = result.directory / "siem" / f"{dataset}.jsonl"
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def visible_sessions(answers, level):
    """The RDP sessions that cross the sensor's switch: both on the DMZ switch, only the jump host's
    onward session on the control switch (the engineer's session never reaches the control network)."""
    facts = answers["facts"]
    office, onward = facts["office_remote_access"]["sessions"], facts["jump_remote_access"]["sessions"]
    return office + onward if LEVELS[level][0] == "dmz" else onward


@needs_capture
@pytest.mark.parametrize("level", LEVELS)
def test_rdp_cookies_and_key_frames_match_the_capture(runs, level):
    result, answers = runs(level)
    cidrs, hosts = site(answers)
    facts = answers["facts"]
    sessions = visible_sessions(answers, level)
    assert len(sessions) == (2 if LEVELS[level][0] == "dmz" else 1)

    requests = tshark(result.pcap, "rdp.rt_cookie && !tcp.analysis.retransmission", "frame.number", "ip.src",
                      "ip.dst", "tcp.dstport", "eth.src", "rdp.rt_cookie", "rdp.negReq.requestedProtocols")
    seen = {(src, dst, port, mac, cookie, protocols) for _, src, dst, port, mac, cookie, protocols in requests}
    expected = {(s["source"]["ip"], s["target"]["ip"], "3389", s["source"]["observed_mac"],
                 f"Cookie: mstshash={s['account']}", "0x00000003") for s in sessions}
    assert seen == expected
    frames = {int(row[0]): row for row in requests}
    for session in sessions:
        assert session["connect"]["frame"] in frames, session["connect"]
        assert frames[session["connect"]["frame"]][1:3] == [session["source"]["ip"], session["target"]["ip"]]

    # The cleartext cookies name the engineer (office -> jump host) and ot-admin (jump host -> EWS).
    users = {(s["source"]["id"], s["account"]) for s in sessions}
    onward = {("jump", "ot-admin")}
    assert users == (onward | {("eng", "r.lewandowski")} if LEVELS[level][0] == "dmz" else onward)

    # The MAC the sensor sees: on the DMZ switch the engineer's request arrives routed (the firewall's
    # DMZ MAC) and the jump host's own MAC on its request; on the control switch the jump host's
    # request arrives routed, from the firewall's control-side MAC.
    macs = {(src, mac) for _, src, _, _, mac, _, _ in requests}
    jump_ip = hosts["jump"]["dmz"][0]
    if LEVELS[level][0] == "dmz":
        assert macs == {(hosts["eng"]["office"][0], hosts["fw"]["dmz"][1]), (jump_ip, hosts["jump"]["dmz"][1])}
    else:
        assert macs == {(jump_ip, hosts["fw"]["control"][1])}
        # The engineer's session never crosses the control switch: no frame in the key for it.
        assert all(s["connect"]["frame"] is None for s in facts["office_remote_access"]["sessions"])

    # RDP into the control network comes only from the jump host.
    into_control = tshark(result.pcap, f"tcp.dstport == 3389 && ip.dst == {cidrs['control']}", "ip.src")
    assert into_control and {src for (src,) in into_control} == {jump_ip}


@needs_capture
@pytest.mark.parametrize("level", LEVELS)
def test_rdp_negotiates_in_x224_then_runs_inside_tls(runs, level):
    result, answers = runs(level)
    facts = answers["facts"]
    servers = {facts[s]["hosts"][0]["id"]: facts[s] for s in ("jump_rdp_service", "ews_rdp_service")}
    for session in visible_sessions(answers, level):
        client, server = session["source"]["ip"], session["target"]["ip"]
        fqdn = servers[session["target"]["id"]]["fqdn"]
        ((stream,),) = tshark(result.pcap, f"frame.number == {session['connect']['frame']}", "tcp.stream")
        rows = tshark(result.pcap, f"tcp.stream == {stream} && tcp.len > 0 && !tcp.analysis.retransmission",
                      "ip.src", "cotp.type", "rdp.negReq.selectedProtocol", "tls.handshake.type",
                      "tls.handshake.extensions_server_name", "x509sat.uTF8String", "tls.record.content_type")
        # 1. X.224 Connection Request (client) -> Connection Confirm selecting CredSSP (server).
        assert rows[0][:2] == [client, "0x0e"]
        assert rows[1][:3] == [server, "0x0d", "0x00000002"]
        assert not any(r[1] for r in rows[2:]), "X.224 after the negotiation"
        # 2. TLS: the ClientHello asks for the server's name; the server presents the self-signed
        #    certificate for that name (subject and issuer).
        hello = next(r for r in rows if "1" in r[3].split(","))
        assert hello[0] == client and hello[4] == fqdn
        certificate = next(r for r in rows if "11" in r[3].split(","))
        assert certificate[0] == server and set(certificate[5].split(",")) == {fqdn}
        # 3. Everything after the negotiation is TLS records; the session is opaque application data
        #    in both directions.
        types = {t for r in rows[2:] for t in r[6].split(",") if t}
        assert types <= {"20", "21", "22", "23"}
        assert {r[0] for r in rows if "23" in r[6].split(",")} == {client, server}


@needs_capture
@pytest.mark.parametrize("level", LEVELS)
def test_replication_matches_the_key_and_the_cadence(runs, level):
    result, answers = runs(level)
    cidrs, hosts = site(answers)
    facts = answers["facts"]
    rep, replica = facts["ot_historian_replication"], facts["replica_service"]
    src, dst = rep["source"]["ip"], rep["target"]["ip"]
    assert src == hosts["ot_hist"]["control"][0] and dst == hosts["dmz_hist"]["dmz"][0]

    # The key frame is the plant historian's ClientHello to the replica's name.
    (channel,) = rep["channels"]
    hello = tshark(result.pcap, f"frame.number == {channel['connect']['frame']} && tls.handshake.type == 1",
                   "ip.src", "ip.dst", "tcp.dstport", "tls.handshake.extensions_server_name")
    assert hello == [[src, dst, "443", replica["fqdn"]]]
    certs = tshark(result.pcap, f"tls.handshake.type == 11 && ip.src == {dst}", "x509sat.uTF8String")
    assert certs and all(set(names.split(",")) == {replica["fqdn"]} for (names,) in certs)

    # One burst of client application data per push, at the configured interval.
    times = [float(t) for (t,) in tshark(
        result.pcap, f"ip.src == {src} && ip.dst == {dst} && tcp.dstport == 443 && tls.record.content_type == 23"
                     " && !tcp.analysis.retransmission", "frame.time_epoch")]
    interval = rep["interval_s"]
    starts = [t for i, t in enumerate(times) if i == 0 or t - times[i - 1] > interval / 2]
    assert len(starts) == channel["pushes"] >= 4
    gaps = [b - a for a, b in zip(starts, starts[1:])]
    assert all(0.97 * interval <= g <= 1.03 * interval for g in gaps), gaps

    # Always pushed from the plant side: the replica never opens a connection into the control network.
    assert not tshark(result.pcap, f"tcp.flags.syn == 1 && tcp.flags.ack == 0 && ip.src == {dst}"
                                   f" && ip.dst == {cidrs['control']}", "frame.number")


@needs_capture
@pytest.mark.parametrize("level", LEVELS)
def test_office_and_control_never_talk_directly(runs, level):
    result, answers = runs(level)
    cidrs, hosts = site(answers)
    office, control, dmz = cidrs["office"], cidrs["control"], cidrs["dmz"]
    if LEVELS[level][0] == "control":
        # On the control switch no office address appears at all.
        assert not tshark(result.pcap, f"ip.addr == {office}", "frame.number")
    else:
        # On the DMZ switch the office appears only in the engineer's RDP session to the jump host.
        eng, jump = hosts["eng"]["office"][0], hosts["jump"]["dmz"][0]
        assert not tshark(result.pcap, f"ip.addr == {office} && !(ip.addr == {eng} && ip.addr == {jump}"
                                       " && tcp.port == 3389)", "frame.number")
        assert tshark(result.pcap, f"ip.src == {eng} && ip.dst == {jump} && tcp.dstport == 3389", "frame.number")
    assert not tshark(result.pcap, f"ip.addr == {office} && ip.addr == {control}", "frame.number")
    # Every unicast packet entering or leaving the control network has its other end in the DMZ.
    control_net, dmz_net = ipaddress.ip_network(control), ipaddress.ip_network(dmz)
    peers = set()
    for row in tshark(result.pcap, f"ip.addr == {control}", "ip.src", "ip.dst"):
        src, dst = (field.split(",")[0] for field in row)   # outer header (not an ICMP-quoted one)
        for a, b in ((src, dst), (dst, src)):
            a, b = ipaddress.ip_address(a), ipaddress.ip_address(b)
            if a in control_net and b not in control_net and not b.is_multicast and b != BROADCAST:
                peers.add(b)
    assert peers and all(p in dmz_net for p in peers), sorted(map(str, peers))


@needs_capture
@pytest.mark.parametrize("level", LEVELS)
def test_rdp_siem_records_match_the_requests(runs, level):
    result, answers = runs(level)
    records = siem(result, "rdp")
    sessions = visible_sessions(answers, level)
    assert len(records) == len(sessions)
    got = {(r["src"], r["dest"], r["dest_port"], r["src_mac"], r["cookie"], r["cookie_user"],
            tuple(r["requested_protocols"]), r["requested_protocols_raw"], r["frame"]) for r in records}
    want = {(s["source"]["ip"], s["target"]["ip"], 3389, s["source"]["observed_mac"],
             f"Cookie: mstshash={s['account']}", s["account"], ("SSL", "CredSSP"), 3, s["connect"]["frame"])
            for s in sessions}
    assert got == want
    assert all(r["app"] == "rdp" and r["transport"] == "tcp" for r in records)
    # The record time is the connection request's: the key's time for the session.
    times = {r["frame"]: r["epoch"] for r in records}
    assert all(times[s["connect"]["frame"]] == s["connect"]["epoch"] for s in sessions)


@pytest.mark.skipif(load_rules is None or not capture_tools, reason="requires tshark and the sigma evaluator")
@pytest.mark.parametrize("level", LEVELS)
def test_no_sigma_rule_fires_on_the_baseline(runs, level):
    result, _ = runs(level)
    rules = load_rules(result.directory / "detections" / "sigma")
    assert set(ZONE_SIGMA) <= set(rules), "the zone-policy rules are generated for this site"
    siem_dir = result.directory / "siem"
    bases = {n for r in rules.values() if "correlation" in r for n in r["correlation"]["rules"]}
    fired = {}
    for title, rule in rules.items():
        if rule.get("name") in bases:
            continue  # correlation building blocks, not converted on their own
        found = correlation_groups(rule, rules, siem_dir) if "correlation" in rule else hits(rule, siem_dir)
        if found:
            fired[title] = found
    assert not fired


@pytest.mark.skipif(not capture_tools or not shutil.which("suricata"), reason="requires suricata and tshark on PATH")
@pytest.mark.parametrize("level", LEVELS)
def test_suricata_raises_no_alert_on_the_baseline(runs, level, tmp_path):
    result, _ = runs(level)
    rules_file = result.exports["detections/suricata.rules"]
    text = rules_file.read_text(encoding="utf-8")
    assert all(f"sid:{sid};" in text for sid in SID_ZONE), "the zone-policy rules are generated for this site"
    run = subprocess.run([shutil.which("suricata"), "-r", str(result.pcap), "-S", str(rules_file),
                          "--set", "app-layer.protocols.modbus.enabled=true",
                          "--set", "unix-command.enabled=no", "-l", str(tmp_path), "-k", "none",
                          "--init-errors-fatal"], capture_output=True, text=True)
    assert run.returncode == 0, run.stderr + run.stdout
    path = tmp_path / "eve.json"
    events = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()] if path.exists() else []
    assert not [e["alert"]["signature"] for e in events if e.get("event_type") == "alert"]
