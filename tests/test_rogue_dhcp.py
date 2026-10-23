"""The rogue-DHCP scenario (it-rogue-dhcp): a rogue DHCP server (dnsmasq on a Raspberry Pi) answers
clients on the office segment with its own router and DNS, and hosts that join during the capture take
its lease. The answer key points at the right frames and the incident traffic is absent from the
office baseline."""

import json
import shutil
import subprocess

import pytest

from pcapforge.detections import SID_IT_BASE, sigma_rules, suricata_rules
from pcapforge.pipeline import generate
from pcapforge.plan import build_plan
from pcapforge.scenario import find
from pcapforge.tools import MIN_TSHARK, find_tool, tshark_version

SCENARIO = "it-rogue-dhcp"
ROGUE_SID = SID_IT_BASE + 800


capture_tools = (find_tool("tshark") and (find_tool("dumpcap") or find_tool("tcpdump"))
                 and tshark_version() >= MIN_TSHARK)


def tshark(pcap, display_filter, *fields):
    out = subprocess.run([find_tool("tshark"), "-n", "-r", str(pcap), "-Y", display_filter, "-T", "fields",
                          "-E", "occurrence=a", *[arg for f in fields for arg in ("-e", f)]],
                         capture_output=True, text=True, check=True).stdout
    return [line.split("\t") for line in out.splitlines() if line]


def test_plan_has_the_rogue_facts_each_level():
    for level, victims, mask in (("easy", 2, "255.255.254.0"), ("medium", 2, "255.255.255.0"),
                                 ("hard", 1, "255.255.255.0")):
        plan = build_plan(find(SCENARIO), level, "42")
        rd = plan.facts["rogue_dhcp"]
        assert rd["rogue"] is True and rd["style"] == "dnsmasq" and rd["mask"] == mask
        # The rogue hands out itself as both the default gateway and the DNS resolver.
        assert rd["router"] == {"$host": "rogue"} and rd["dns"] == {"$host": "rogue"}
        rl = plan.facts["rogue_lease"]
        assert len(rl["names"]) == victims
        assert rl["first_join"] is not None
        # The rogue leaves the subnet's DHCP pool to the legitimate server (no conflict).
        assert plan.topology.pools.get("office") == (100, 199)


        rl = plan.facts["rogue_lease"]
        assert len(rl["names"]) == victims
        assert rl["first_join"] is not None
        # The rogue's own resolver and the affected hosts' lookups against it are opt-in (medium/hard).
        rogue_dns = {a.id for a in plan.actors} >= {"rogue_resolver", "rogue_lookups"}
        assert rogue_dns == (level != "easy")


def test_baseline_has_no_rogue_dhcp():
    plan = build_plan(find("it-baseline-operations"), "medium", "42")
    assert "rogue_dhcp" not in plan.facts and "rogue_lease" not in plan.facts
    assert not any(a.type == "dhcp.server" and a.incident for a in plan.actors)


@pytest.mark.skipif(not capture_tools, reason="requires tshark >= 4.4 and dumpcap/tcpdump with loopback capture rights")
@pytest.mark.parametrize("level,duration", [("easy", 300.0), ("medium", 420.0), ("hard", 480.0)])
def test_capture_matches_the_key(tmp_path, level, duration):
    result = generate(find(SCENARIO), level, "pytest", tmp_path, duration=duration, siem=True)
    assert result.report.ok, [c for c in result.report.checks if not c["ok"]]
    f = json.loads(result.answers.read_text(encoding="utf-8"))["facts"]
    rogue = f["rogue_dhcp"]
    rogue_ip = rogue["hosts"][0]["ip"]
    rogue_mac = rogue["hosts"][0]["observed_mac"].lower()
    router_ip, dns_ip = rogue["router"]["ip"], rogue["dns"]["ip"]
    legit_ip = f["dhcp_service"]["hosts"][0]["ip"]
    relay_ip = f["dhcp_service"]["relay"]["ip"]
    names = f["rogue_lease"]["names"]
    assert rogue_ip != legit_ip and router_ip == rogue_ip and dns_ip == rogue_ip

    # The rogue's Offers come from its own address and MAC (on-segment, no relay, no gateway MAC),
    # and name itself in the server identifier.
    offers = tshark(result.pcap, f"dhcp.option.dhcp==2 && dhcp.option.dhcp_server_id=={rogue_ip}",
                    "ip.src", "eth.src")
    assert offers, "the rogue sent at least one Offer"
    assert {o[0] for o in offers} == {rogue_ip}
    assert {o[1].lower() for o in offers} == {rogue_mac}

    # Every rogue reply hands out the rogue as router and DNS; on easy also a wrong subnet mask.
    replies = tshark(result.pcap, f"dhcp.option.dhcp in {{2,5}} && dhcp.option.dhcp_server_id=={rogue_ip}",
                     "dhcp.option.router", "dhcp.option.domain_name_server", "dhcp.option.subnet_mask")
    assert replies and all(r[0] == router_ip and r[1] == dns_ip for r in replies)
    if level == "easy":
        assert all(r[2] == rogue["mask"] for r in replies)

    # The legitimate replies come through the relay and name the real server; the two never coincide.
    legit = tshark(result.pcap, f"dhcp.option.dhcp in {{2,5}} && dhcp.option.dhcp_server_id=={legit_ip}", "ip.src")
    assert legit and {l[0] for l in legit} == {relay_ip}
    assert not tshark(result.pcap, f"dhcp.option.dhcp in {{2,5}} && dhcp.option.dhcp_server_id=={legit_ip} && ip.src=={rogue_ip}", "frame.number")

    # Each affected client selected the rogue: a broadcast Request naming the rogue (option 54) and the host.
    assert names
    for name in names:
        rows = tshark(result.pcap,
                      f'dhcp.option.dhcp==3 && dhcp.option.dhcp_server_id=={rogue_ip} && dhcp.option.hostname=="{name}"',
                      "frame.number")
        assert rows, f"{name} did not select the rogue"

    # On medium the affected hosts resolve a few names against the rogue's own resolver (on hard the
    # single host joins late with a short window; its lookups land at the full 2h duration).
    if level == "medium":
        assert tshark(result.pcap, f"dns.flags.response==0 && ip.dst=={rogue_ip}", "frame.number"), \
            "affected hosts query the rogue resolver"


@pytest.mark.skipif(not capture_tools, reason="requires tshark >= 4.4 and dumpcap/tcpdump with loopback capture rights")
def test_baseline_capture_has_no_rogue_offer(tmp_path):
    result = generate(find("it-baseline-operations"), "easy", "pytest", tmp_path, duration=300.0, siem=True)
    f = json.loads(result.answers.read_text(encoding="utf-8"))["facts"]
    legit_ip = f["dhcp_service"]["hosts"][0]["ip"]
    relay_ip = f["dhcp_service"]["relay"]["ip"]
    offers = tshark(result.pcap, "dhcp.option.dhcp in {2,5}", "ip.src", "dhcp.option.dhcp_server_id")
    assert offers, "the baseline still has legitimate DHCP replies"
    # Every DHCP reply names the single legitimate server and arrives from its relay - no second server.
    assert {o[1] for o in offers} == {legit_ip}
    assert {o[0] for o in offers} == {relay_ip}


def test_rogue_rules_only_generate_for_this_scenario():
    # No incident dhcp.server (baseline, OT scenarios) -> no rogue Suricata or Sigma rule.
    for sid in ("it-baseline-operations", "ot-modbus-write-manipulation"):
        answers = {"scenario": {"id": sid, "line": sid.split("-")[0]}, "actors": [],
                   "topology": {"hosts": [], "subnets": []}, "facts": {}}
        assert not any(r.sid == ROGUE_SID for r in suricata_rules(answers))
        assert not any(r["title"] == "Rogue DHCP server on the LAN" for r in sigma_rules(answers))


@pytest.mark.skipif(not capture_tools or not shutil.which("suricata"), reason="requires suricata and tshark on PATH")
def test_suricata_alerts_on_the_rogue_and_never_on_the_office_baseline(tmp_path):
    incident = generate(find(SCENARIO), "easy", "suri", tmp_path / "easy", duration=360.0, siem=True)
    rules_file = incident.exports["detections/suricata.rules"]
    rogue_ip = json.loads(incident.answers.read_text(encoding="utf-8"))["facts"]["rogue_dhcp"]["hosts"][0]["ip"]

    def alerts(pcap, out):
        out.mkdir(parents=True, exist_ok=True)
        run = subprocess.run([shutil.which("suricata"), "-r", str(pcap), "-S", str(rules_file),
                              "--set", "unix-command.enabled=no", "-l", str(out), "-k", "none",
                              "--init-errors-fatal"], capture_output=True, text=True)
        assert run.returncode == 0, run.stderr + run.stdout
        return [json.loads(line) for line in (out / "eve.json").read_text().splitlines()
                if json.loads(line).get("event_type") == "alert"]

    incident_alerts = alerts(incident.pcap, tmp_path / "s1")
    rogue = [a for a in incident_alerts if a["alert"]["signature_id"] == ROGUE_SID]
    assert rogue, "the rogue-DHCP rule did not fire on the rogue's replies"
    # It fires only on the rogue's own replies, not on the legitimate relay's.
    assert {a["src_ip"] for a in rogue} == {rogue_ip}

    base = generate(find("it-baseline-operations"), "medium", "suri-base", tmp_path / "base", duration=360.0, siem=True)
    assert not [a for a in alerts(base.pcap, tmp_path / "s2") if a["alert"]["signature_id"] == ROGUE_SID], \
        "the rogue-DHCP rule fired on the office baseline"
