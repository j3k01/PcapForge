"""The HTTPS beaconing incident (it-https-beaconing): the planned check-in cadence matches the
answer key, the recorded TLS check-ins point at the beacon domain from the one beaconing host, and
none of that traffic is present in the office baseline."""

import json
import subprocess

import pytest

from pcapforge.pipeline import generate
from pcapforge.plan import build_plan
from pcapforge.scenario import find
from pcapforge.tools import MIN_TSHARK, find_tool, tshark_version

capture_tools = (find_tool("tshark") and (find_tool("dumpcap") or find_tool("tcpdump"))
                 and tshark_version() >= MIN_TSHARK)


def tshark(pcap, display_filter, *fields):
    out = subprocess.run([find_tool("tshark"), "-n", "-r", str(pcap), "-Y", display_filter, "-T", "fields",
                          "-E", "occurrence=a", *[arg for f in fields for arg in ("-e", f)]],
                         capture_output=True, text=True, check=True).stdout
    return [line.split("\t") for line in out.splitlines()]


@pytest.mark.parametrize("difficulty", ["easy", "medium", "hard"])
def test_planned_cadence_matches_the_answer_key(difficulty):
    """No capture needed: the inter-arrival statistics of the planned check-ins match the interval the
    answer key reports, within the jitter the level configures."""
    scenario = find("it-https-beaconing")
    for seed in ("alpha", "beta", "gamma"):
        plan = build_plan(scenario, difficulty, seed)
        facts = plan.facts["beacon"]
        times = sorted(c["request"]["$action"].t for c in facts["checkins"])
        assert len(times) == facts["checkin_count"] >= 5
        assert times[0] < plan.duration and times[-1] < plan.duration
        # first_checkin is the earliest check-in.
        assert facts["first_checkin"]["$action"].t == times[0]
        interval, jitter = facts["interval_s"], facts["jitter"]
        gaps = [b - a for a, b in zip(times, times[1:])]
        mean = sum(gaps) / len(gaps)
        # The mean spacing is the beacon interval; jitter averages out, so the mean stays within one
        # jitter amplitude of the nominal interval (and essentially exact when there is no jitter).
        assert abs(mean - interval) <= max(1.0, jitter * interval), (difficulty, seed, mean, interval)
        # Each gap is the interval plus the difference of two independent jitters (so up to twice the
        # jitter amplitude either way); a small slack covers the DNS-resolve bump and the monotonic floor.
        low, high = interval * (1 - 2 * jitter) - 2.2, interval * (1 + 2 * jitter) + 0.1
        assert all(low <= g <= high for g in gaps), (difficulty, seed, min(gaps), max(gaps))


@pytest.fixture(scope="module")
def run(tmp_path_factory):
    result = generate(find("it-https-beaconing"), "easy", "pytest-beacon", tmp_path_factory.mktemp("beacon"),
                      duration=900.0)
    assert result.report.ok, [c for c in result.report.checks if not c["ok"]]
    return result, json.loads(result.answers.read_text(encoding="utf-8"))


@pytest.mark.skipif(not capture_tools, reason="requires tshark >= 4.4 and dumpcap/tcpdump with loopback capture rights")
def test_check_ins_point_at_the_beacon_domain_from_the_one_host(run):
    result, answers = run
    beacon = answers["facts"]["beacon"]
    domain, src, dst, mac = (beacon["domain"], beacon["source"]["ip"], beacon["destination"]["ip"],
                             beacon["source"]["mac"])
    # Every ClientHello to the beacon domain comes from the beaconing host (its own MAC, since it is on
    # the sensor segment) and goes to the external destination: one per check-in.
    hellos = tshark(result.pcap, f'tls.handshake.type == 1 && tls.handshake.extensions_server_name == "{domain}"',
                    "ip.src", "ip.dst", "eth.src")
    assert len(hellos) == beacon["checkin_count"]
    assert {(s, d, e) for s, d, e in hellos} == {(src, dst, mac)}
    # No other host beacons to that name, and the destination is outside the office and server subnets.
    others = tshark(result.pcap,
                    f'tls.handshake.type == 1 && tls.handshake.extensions_server_name == "{domain}" && ip.src != {src}',
                    "frame.number")
    assert not others
    # The answer-key frame for the first check-in belongs to the first TLS connection to the beacon
    # destination, and is the earliest beacon frame in the capture.
    first = tshark(result.pcap, f'frame.number == {beacon["first_checkin"]["frame"]}', "ip.dst")
    assert first == [[dst]]
    hello_frames = [int(n) for (n,) in tshark(
        result.pcap, f'tls.handshake.type == 1 && tls.handshake.extensions_server_name == "{domain}"',
        "frame.number")]
    assert min(hello_frames) >= beacon["first_checkin"]["frame"]


@pytest.mark.skipif(not capture_tools, reason="requires tshark >= 4.4 and dumpcap/tcpdump with loopback capture rights")
def test_the_beacon_server_certificate_is_not_the_domain_ca(run):
    result, answers = run
    service = answers["facts"]["beacon_service"]
    # TLS 1.2 sends the chain in clear; the beacon server's issuer is a public CA, not the domain's
    # AD CS root that signs the intranet sites.
    chains = tshark(result.pcap, "tls.handshake.type == 11 && x509ce.dNSName", "x509sat.uTF8String", "x509ce.dNSName")
    beacon_chains = [names for names, sans in chains if service["domain"] in sans.split(",")]
    assert beacon_chains and all(service["issuer"] in names.split(",") for names in beacon_chains)
    web_ca = answers["facts"]["web_service"]["ca"]["name"]
    assert all(web_ca not in names.split(",") for names in beacon_chains)


@pytest.mark.skipif(not capture_tools, reason="requires tshark >= 4.4 and dumpcap/tcpdump with loopback capture rights")
def test_the_beacon_domain_is_absent_from_the_office_baseline(tmp_path_factory):
    result = generate(find("it-baseline-operations"), "easy", "pytest-beacon-base",
                      tmp_path_factory.mktemp("base"), duration=300.0)
    assert result.report.ok, [c for c in result.report.checks if not c["ok"]]
    snis = {row[0] for row in tshark(result.pcap, "tls.handshake.type == 1",
                                     "tls.handshake.extensions_server_name") if row[0]}
    assert snis  # the baseline does open intranet HTTPS
    # The office baseline only talks to the intranet names under the site domain; no external beacon.
    assert all(name.endswith(".local") for name in snis), snis
