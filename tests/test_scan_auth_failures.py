"""The scan-and-authentication-failures scenario (it-scan-auth-failures): a TCP port sweep of the
server subnet and Kerberos AS pre-authentication failures (KDC_ERR_PREAUTH_FAILED) against the KDC,
with one successful guess on hard. The answer key points at the right frames and the incident
traffic is absent from the office baseline."""

import json
import subprocess

import pytest

from pcapforge.pipeline import generate
from pcapforge.plan import build_plan
from pcapforge.scenario import find
from pcapforge.tools import MIN_TSHARK, find_tool, tshark_version

SCENARIO = "it-scan-auth-failures"
OPEN_PORTS = {88, 389, 445}

capture_tools = (find_tool("tshark") and (find_tool("dumpcap") or find_tool("tcpdump"))
                 and tshark_version() >= MIN_TSHARK)


def tshark(pcap, display_filter, *fields):
    out = subprocess.run([find_tool("tshark"), "-n", "-r", str(pcap), "-Y", display_filter, "-T", "fields",
                          "-E", "occurrence=a", *[arg for f in fields for arg in ("-e", f)]],
                         capture_output=True, text=True, check=True).stdout
    return [line.split("\t") for line in out.splitlines() if line]


def test_plan_has_the_scan_and_brute_force_facts():
    for level, mode, success in (("easy", "brute-force", False), ("medium", "spray", False), ("hard", "spray", True)):
        plan = build_plan(find(SCENARIO), level, "42")
        scan = plan.facts["scan"]
        assert scan["host_count"] == 3
        assert scan["port_count"] == 7          # 3 DC service ports + 4 closed-only probe ports
        bf = plan.facts["bruteforce"]
        assert bf["mode"] == mode
        assert bf["succeeded"] is success
        assert bf["error_name"] == "KDC_ERR_PREAUTH_FAILED"
        # Every failure in the key is an AS-REQ action this actor planned.
        assert len(bf["failures"]) == bf["failure_count"]
        if success:
            assert bf["compromised"] in bf["accounts"]
            assert bf["success_request"] is not None
        else:
            assert bf["compromised"] is None and bf["success_request"] is None


def test_easy_brute_force_targets_one_account():
    plan = build_plan(find(SCENARIO), "easy", "42")
    bf = plan.facts["bruteforce"]
    assert bf["account_count"] == 1
    assert bf["failure_count"] == 12


def test_baseline_has_no_scan_or_auth_failures():
    plan = build_plan(find("it-baseline-operations"), "medium", "42")
    types = {a.type for a in plan.actors}
    assert "tcp.scanner" not in types and "kerberos.bruteforce" not in types
    assert "scan" not in plan.facts and "bruteforce" not in plan.facts


@pytest.mark.skipif(not capture_tools, reason="requires tshark >= 4.4 and dumpcap/tcpdump with loopback capture rights")
@pytest.mark.parametrize("level,duration", [("easy", 360.0), ("hard", 480.0)])
def test_capture_matches_the_key(tmp_path, level, duration):
    result = generate(find(SCENARIO), level, "pytest", tmp_path, duration=duration, siem=True)
    assert result.report.ok, [c for c in result.report.checks if not c["ok"]]
    answers = json.loads(result.answers.read_text(encoding="utf-8"))
    scan = answers["facts"]["scan"]
    bf = answers["facts"]["bruteforce"]
    source = scan["source"]["ip"]
    assert bf["source"]["ip"] == source     # scan and brute force come from the same host

    # The sweep: a SYN to RDP (3389) on every scanned host. Those hosts are Windows servers that drop
    # unsolicited SYNs, so the probe is filtered (no RST back) and the SYN is retransmitted.
    rdp = tshark(result.pcap, f"tcp.flags.syn==1 && tcp.flags.ack==0 && tcp.dstport==3389 && ip.src=={source}",
                 "ip.dst")
    assert len({r[0] for r in rdp}) == scan["host_count"]
    assert not tshark(result.pcap, f"tcp.flags.reset==1 && ip.dst=={source}", "frame.number"), \
        "a firewalled host drops the probe instead of refusing it with a RST"

    # The open service ports answer the scanner's SYN with a SYN/ACK.
    synack_ports = {int(r[0]) for r in tshark(
        result.pcap, f"tcp.flags.syn==1 && tcp.flags.ack==1 && ip.dst=={source}", "tcp.srcport")}
    assert OPEN_PORTS <= synack_ports
    assert set(scan["open_ports"]) == OPEN_PORTS

    # Every Kerberos pre-authentication failure (KRB-ERROR code 24) goes to the scanning host, and
    # there are exactly as many as the key says. Legitimate domain logons never fail pre-auth.
    errors = tshark(result.pcap, "kerberos.msg_type==30 && kerberos.error_code==24", "ip.dst")
    assert errors, "the incident produced KDC_ERR_PREAUTH_FAILED errors"
    assert {r[0] for r in errors} == {source}, "only the scanner's attempts fail pre-authentication"
    to_scanner = tshark(result.pcap,
                        f"kerberos.msg_type==30 && kerberos.error_code==24 && ip.dst=={source}", "frame.number")
    assert len(to_scanner) == bf["failure_count"]

    # Each failure in the answer key is an AS-REQ (msg_type 10) from the scanner carrying an encrypted
    # pre-authentication timestamp (padata type 2).
    for failure in bf["failures"]:
        frame = failure["request"]["frame"]
        rows = tshark(result.pcap,
                      f"frame.number=={frame} && kerberos.msg_type==10 && kerberos.padata_type==2 && ip.src=={source}",
                      "kerberos.CNameString")
        assert rows, f"failure frame {frame} is not an AS-REQ from the scanner"
        assert failure["account"] in rows[0][0]

    # The targeted accounts all appear as client names of the scanner's failed AS exchanges.
    seen = {r[0] for r in tshark(
        result.pcap, f"kerberos.msg_type==10 && kerberos.padata_type==2 && ip.src=={source}", "kerberos.CNameString")}
    assert set(bf["accounts"]) <= seen

    # Success is only on hard: exactly the compromised account gets an AS-REP (msg_type 11).
    reps = tshark(result.pcap, f"kerberos.msg_type==11 && ip.dst=={source}", "kerberos.CNameString")
    if bf["succeeded"]:
        assert any(bf["compromised"] in (r[0] if r else "") for r in reps), "the guessed account gets a TGT"
    else:
        assert not reps, "no guess should land when success is off"
