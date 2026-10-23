"""The Kerberoasting scenario (it-kerberoasting): a domain user on a workstation requests Kerberos
service tickets (TGS-REQ) for many service accounts' SPNs in a burst, asking for RC4-HMAC (etype 23)
where Windows clients offer AES. The answer key points at the right frames and the RC4-only requests
are absent from the office baseline."""

import json
import shutil
import subprocess

import pytest

from pcapforge.detections import (SID_IT_BASE, _it_kerberoasting_rules, _it_kerberoasting_sigma)
from pcapforge.pipeline import generate
from pcapforge.plan import build_plan
from pcapforge.scenario import find
from pcapforge.tools import MIN_TSHARK, find_tool, tshark_version

SCENARIO = "it-kerberoasting"
ROAST = "kerberos.msg_type == 12 && kerberos.ENCTYPE == 23 && !(kerberos.ENCTYPE == 18)"
SID_ROAST = SID_IT_BASE + 500

capture_tools = (find_tool("tshark") and (find_tool("dumpcap") or find_tool("tcpdump"))
                 and tshark_version() >= MIN_TSHARK)


def tshark(pcap, display_filter, *fields):
    out = subprocess.run([find_tool("tshark"), "-n", "-r", str(pcap), "-Y", display_filter, "-T", "fields",
                          "-E", "occurrence=a", *[arg for f in fields for arg in ("-e", f)]],
                         capture_output=True, text=True, check=True).stdout
    return [line.split("\t") for line in out.splitlines() if line]


def test_plan_has_the_roast_facts():
    for level, spns, normal in (("easy", 10, 0), ("medium", 6, 4), ("hard", 8, 6)):
        plan = build_plan(find(SCENARIO), level, "42")
        roast = plan.facts["roast"]
        assert roast["spn_count"] == spns
        assert roast["etype"] == 23 and roast["etype_name"] == "rc4-hmac"
        assert len(roast["services"]) == spns and len(set(roast["services"])) == spns
        assert roast["target_spn"] in roast["services"]
        ops = {}
        for action in plan.actions:
            if action.actor == "roast":
                ops[action.op] = ops.get(action.op, 0) + 1
        assert ops == {"krb.logon": 1, "krb.roast": spns, **({"krb.normal_tgs": normal} if normal else {})}
        # Every service account carries an SPN and the directory stays opt-in.
        accounts = plan.facts["domain_service"]["service_accounts"]
        assert accounts and all(a["spn"] for a in accounts)


def test_baseline_has_no_service_accounts_or_roast():
    plan = build_plan(find("it-baseline-operations"), "medium", "42")
    assert "roast" not in plan.facts
    assert plan.facts["domain_service"]["service_accounts"] == []


def test_rules_only_exist_for_the_incident():
    scenario = {"id": "x", "difficulty": "easy", "seed": "1"}
    without = {"actors": [{"type": "ad.dc", "incident": False}], "scenario": scenario}
    assert _it_kerberoasting_rules(without) == [] and _it_kerberoasting_sigma(without) == []
    with_roast = {"actors": [{"type": "kerberos.roast", "incident": True}], "scenario": scenario}
    assert [r for r in _it_kerberoasting_rules(with_roast) if r.sid == SID_ROAST]
    assert _it_kerberoasting_sigma(with_roast)


@pytest.mark.skipif(not capture_tools, reason="requires tshark >= 4.4 and dumpcap/tcpdump with loopback capture rights")
@pytest.mark.parametrize("level,duration", [("easy", 300.0), ("hard", 600.0)])
def test_capture_matches_the_key(tmp_path, level, duration):
    result = generate(find(SCENARIO), level, "pytest", tmp_path, duration=duration, siem=True)
    assert result.report.ok, [c for c in result.report.checks if not c["ok"]]
    answers = json.loads(result.answers.read_text(encoding="utf-8"))
    roast = answers["facts"]["roast"]
    source = roast["source"]["ip"]

    # Every RC4-only TGS-REQ (etype 23, no AES) comes from the one host; there is one per SPN and the
    # SPNs are distinct.
    rows = tshark(result.pcap, f"{ROAST} && ip.src == {source}", "kerberos.SNameString")
    assert {" ".join(r) for r in rows}, "the incident produced RC4-only TGS-REQs"
    assert len(rows) >= roast["spn_count"]
    any_src = tshark(result.pcap, ROAST, "ip.src")
    assert {r[0] for r in any_src} == {source}, "only the roasting host asks for RC4-only service tickets"

    # The signed-in user's logon: an AS-REQ (msg_type 10) with a pre-auth timestamp (padata 2) from the
    # host, naming the account.
    logon = tshark(result.pcap,
                   f"kerberos.msg_type == 10 && kerberos.padata_type == 2 && ip.src == {source}",
                   "kerberos.CNameString")
    assert any(roast["user"] in (r[0] if r else "") for r in logon), "the roasting user logs on from the host"

    # Each request in the key is an RC4-only TGS-REQ for its SPN.
    for request in roast["requests"]:
        frame = request["request"]["frame"]
        klass, host = request["spn"].split("/", 1)
        got = tshark(result.pcap,
                     f"frame.number == {frame} && kerberos.msg_type == 12 && kerberos.ENCTYPE == 23 "
                     f"&& kerberos.SNameString == \"{klass}\" && kerberos.SNameString == \"{host}\"",
                     "frame.number")
        assert got, f"request frame {frame} is not an RC4 TGS-REQ for {request['spn']}"

    # The KDC answers with RC4-encrypted service tickets (etype 23 in the TGS-REP) to that host.
    reps = tshark(result.pcap, f"kerberos.msg_type == 13 && kerberos.etype == 23 && ip.dst == {source}",
                  "frame.number")
    assert len(reps) >= roast["spn_count"]

    # The first-request frame is the earliest RC4 TGS-REQ.
    first = tshark(result.pcap,
                   f"frame.number == {roast['first_request']['frame']} && {ROAST} && ip.src == {source}",
                   "frame.number")
    assert len(first) == 1


def test_baseline_has_no_rc4_service_tickets(tmp_path):
    if not capture_tools:
        pytest.skip("requires tshark >= 4.4 and dumpcap/tcpdump with loopback capture rights")
    result = generate(find("it-baseline-operations"), "medium", "pytest", tmp_path, duration=300.0)
    assert not tshark(result.pcap, ROAST, "frame.number"), "the baseline never requests RC4-only service tickets"


@pytest.mark.skipif(not capture_tools, reason="requires tshark >= 4.4 and dumpcap/tcpdump with loopback capture rights")
@pytest.mark.skipif(not shutil.which("suricata"), reason="requires suricata on PATH")
def test_suricata_alerts_on_the_roast_and_never_on_the_office_baseline(tmp_path):
    incident = generate(find(SCENARIO), "easy", "suri", tmp_path / "inc", duration=300.0, siem=True)
    rules = incident.exports["detections/suricata.rules"]

    def alerts(pcap, out):
        out.mkdir(parents=True, exist_ok=True)
        run = subprocess.run([shutil.which("suricata"), "-r", str(pcap), "-S", str(rules),
                              "--set", "unix-command.enabled=no", "-l", str(out), "-k", "none",
                              "--init-errors-fatal"], capture_output=True, text=True)
        assert run.returncode == 0, run.stderr + run.stdout
        return [json.loads(line) for line in (out / "eve.json").read_text().splitlines()
                if json.loads(line).get("event_type") == "alert"]

    sids = [a["alert"]["signature_id"] for a in alerts(incident.pcap, tmp_path / "s-inc")]
    assert sids.count(SID_ROAST) >= 1

    base = generate(find("it-baseline-operations"), "medium", "suri-base", tmp_path / "base", duration=300.0, siem=True)
    base_sids = [a["alert"]["signature_id"] for a in alerts(base.pcap, tmp_path / "s-base")]
    assert SID_ROAST not in base_sids
