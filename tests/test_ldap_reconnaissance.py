"""The LDAP reconnaissance scenario (it-ldap-reconnaissance): a host enumerates the Active Directory
over LDAP - all users, the accounts with a service principal name, the protected (adminCount=1)
accounts, the Domain Admins membership and the domain trusts. On easy/medium the binds are unsealed
so the filters and returned entries are readable; on hard they are Kerberos-sealed and the tell is
volume. The answer key points at the right packets and the enumeration is absent from the office
baseline."""

import json
import shutil
import subprocess

import pytest

from pcapforge.detections import SID_IT_BASE, _it_ldap_recon_sigma, sigma_rules, suricata_rules
from pcapforge.pipeline import generate
from pcapforge.plan import build_plan
from pcapforge.scenario import find
from pcapforge.tools import MIN_TSHARK, find_tool, tshark_version

SCENARIO = "it-ldap-reconnaissance"
SID_SPN = SID_IT_BASE + 700
SID_ADMIN = SID_IT_BASE + 701
SPN_FILTER = "(servicePrincipalName=*)"

capture_tools = (find_tool("tshark") and (find_tool("dumpcap") or find_tool("tcpdump"))
                 and tshark_version() >= MIN_TSHARK)


def tshark(pcap, display_filter, *fields):
    out = subprocess.run([find_tool("tshark"), "-n", "-r", str(pcap), "-Y", display_filter, "-T", "fields",
                          "-E", "occurrence=a", *[arg for f in fields for arg in ("-e", f)]],
                         capture_output=True, text=True, check=True).stdout
    return [line.split("\t") for line in out.splitlines() if line]


def test_plan_has_the_reconnaissance_facts():
    for level, sealed, sessions in (("easy", False, 1), ("medium", False, 1), ("hard", True, 6)):
        plan = build_plan(find(SCENARIO), level, "42")
        recon = plan.facts["recon"]
        assert recon["sealed"] is sealed
        assert recon["session_count"] == sessions
        assert recon["spn_filter"] == SPN_FILTER
        assert recon["entry_count"] > 0
        assert recon["domain_admins"] and "Administrator" in recon["domain_admins"]
        assert recon["domain_admins_dn"].startswith("CN=Domain Admins,")
        assert recon["service_accounts"] and recon["trusts"]


def test_baseline_has_no_reconnaissance():
    plan = build_plan(find("it-baseline-operations"), "medium", "42")
    assert "recon" not in plan.facts


def _answers(with_recon):
    actors = [{"id": "recon", "type": "ldap.recon", "incident": True, "hosts": ["scanner"]}] if with_recon else []
    return {"scenario": {"id": "x", "line": "it", "difficulty": "easy", "seed": "1"},
            "actors": actors, "topology": {"hosts": [], "subnets": []}, "facts": {}}


def test_rules_only_exist_for_the_incident():
    rules = suricata_rules(_answers(True))
    assert {SID_SPN, SID_ADMIN} <= {r.sid for r in rules}
    assert _it_ldap_recon_sigma(_answers(True))
    assert not any(r.sid in (SID_SPN, SID_ADMIN) for r in suricata_rules(_answers(False)))
    assert not _it_ldap_recon_sigma(_answers(False))


@pytest.mark.skipif(not capture_tools, reason="requires tshark >= 4.4 and dumpcap/tcpdump with loopback capture rights")
@pytest.mark.parametrize("level,duration", [("easy", 240.0), ("hard", 360.0)])
def test_capture_matches_the_key(tmp_path, level, duration):
    result = generate(find(SCENARIO), level, "pytest", tmp_path, duration=duration, siem=True)
    assert result.report.ok, [c for c in result.report.checks if not c["ok"]]
    recon = json.loads(result.answers.read_text(encoding="utf-8"))["facts"]["recon"]
    src = recon["source"]["ip"]

    if not recon["sealed"]:
        # Unsealed: the bind name, the tell-tale filters and every returned entry are readable.
        assert tshark(result.pcap, f'ldap.name == "{recon["bind_name"]}" && ip.src == {src}', "frame.number")
        assert tshark(result.pcap, f'ldap.present == "servicePrincipalName" && ip.src == {src}', "frame.number")
        assert tshark(result.pcap, f'ldap.filter && frame.number == {recon["first_search"]["frame"]} '
                      f'&& ip.src == {src}', "frame.number")
        entries = tshark(result.pcap, f"ldap.objectName && ip.dst == {src}", "ldap.objectName")
        assert len(entries) >= recon["entry_count"]
        assert tshark(result.pcap, f'ldap.objectName == "{recon["domain_admins_dn"]}" && ip.dst == {src}',
                      "frame.number")
        # Only the enumerating host sends these reconnaissance filters.
        any_spn = tshark(result.pcap, 'ldap.present == "servicePrincipalName"', "ip.src")
        assert {r[0] for r in any_spn} == {src}
    else:
        # Sealed: the account is visible in the preceding Kerberos, the filters are not, and the tell
        # is the number of LDAP sessions the host opens to the DC.
        logon = tshark(result.pcap, f"kerberos.msg_type == 10 && ip.src == {src}", "kerberos.CNameString")
        assert any(recon["account"] in (r[0] if r else "") for r in logon)
        assert not tshark(result.pcap, f'ldap.present == "servicePrincipalName" && ip.src == {src}', "frame.number")
        syns = tshark(result.pcap, f"tcp.flags.syn == 1 && tcp.flags.ack == 0 && ip.src == {src} "
                      "&& tcp.dstport == 389", "frame.number")
        assert len(syns) >= recon["session_count"]


def test_baseline_has_no_cleartext_directory_filters(tmp_path):
    if not capture_tools:
        pytest.skip("requires tshark >= 4.4 and dumpcap/tcpdump with loopback capture rights")
    result = generate(find("it-baseline-operations"), "medium", "pytest", tmp_path, duration=300.0)
    assert not tshark(result.pcap, 'ldap.present == "servicePrincipalName"', "frame.number"), \
        "the office baseline reads the directory only over sealed LDAP"
    assert not tshark(result.pcap, 'ldap.filter contains "adminCount"', "frame.number")


@pytest.mark.skipif(not capture_tools, reason="requires tshark >= 4.4 and dumpcap/tcpdump with loopback capture rights")
@pytest.mark.skipif(not shutil.which("suricata"), reason="requires suricata on PATH")
def test_suricata_alerts_on_the_recon_and_never_on_the_office_baseline(tmp_path):
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
    assert sids.count(SID_SPN) >= 1 and sids.count(SID_ADMIN) >= 1

    base = generate(find("it-baseline-operations"), "medium", "suri-base", tmp_path / "base", duration=300.0, siem=True)
    base_sids = [a["alert"]["signature_id"] for a in alerts(base.pcap, tmp_path / "s-base")]
    assert SID_SPN not in base_sids and SID_ADMIN not in base_sids
