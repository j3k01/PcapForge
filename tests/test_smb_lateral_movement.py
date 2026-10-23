"""The SMB lateral-movement scenario (it-smb-lateral-movement): one host authenticates with one
domain account and opens the administrative shares (ADMIN$, IPC$, C$) of many office workstations
over SMB 3.1.1, after asking the KDC for a cifs/<workstation> service ticket for each. The answer key
points at the right packets, one target refuses access on hard, and none of the incident traffic is
present in the office baseline."""

import json
import subprocess

import pytest

from pcapforge.pipeline import generate
from pcapforge.plan import build_plan
from pcapforge.scenario import find
from pcapforge.tools import MIN_TSHARK, find_tool, tshark_version

SCENARIO = "it-smb-lateral-movement"

capture_tools = (find_tool("tshark") and (find_tool("dumpcap") or find_tool("tcpdump"))
                 and tshark_version() >= MIN_TSHARK)


def tshark(pcap, display_filter, *fields):
    out = subprocess.run([find_tool("tshark"), "-n", "-r", str(pcap), "-Y", display_filter, "-T", "fields",
                          "-E", "occurrence=a", *[arg for f in fields for arg in ("-e", f)]],
                         capture_output=True, text=True, check=True).stdout
    return [line.split("\t") for line in out.splitlines() if line]


def test_plan_has_the_lateral_movement_facts():
    for level, legit, denied in (("easy", False, False), ("medium", False, False), ("hard", True, True)):
        plan = build_plan(find(SCENARIO), level, "42")
        lat = plan.facts["lateral"]
        assert lat["account"]
        assert lat["share"] == "ADMIN$"
        assert lat["target_count"] >= 3
        assert len(lat["targets"]) == lat["target_count"]
        assert len(lat["per_target"]) == lat["target_count"]
        # One smb.tgs + smb.setup + smb.enum action per target, plus three AS steps.
        ops = [a.op for a in plan.actions if a.actor == "lateral"]
        assert ops.count("smb.as") == 3
        assert ops.count("smb.tgs") == lat["target_count"]
        assert ops.count("smb.enum") == lat["target_count"]
        # The source is a legitimate admin workstation on hard, an uninventoried host otherwise. In the
        # unresolved plan facts a host reference is {"$host": <id>}.
        source = plan.topology.by_id[lat["source"]["$host"]]
        assert source.listed is legit
        if denied:
            assert lat["denied_target"] is not None
            assert lat["denied_target"]["$host"] in {t["$host"] for t in lat["targets"]}
            assert sum(1 for t in lat["per_target"] if t["denied"]) == 1
        else:
            assert lat["denied_target"] is None
            assert not any(t["denied"] for t in lat["per_target"])


def test_easy_reaches_every_workstation():
    plan = build_plan(find(SCENARIO), "easy", "42")
    lat = plan.facts["lateral"]
    workstations = len(plan.topology.groups["pc"]) + len(plan.topology.groups["ws"])
    assert lat["target_count"] == workstations      # count: all


def test_baseline_has_no_lateral_movement():
    plan = build_plan(find("it-baseline-operations"), "medium", "42")
    types = {a.type for a in plan.actors}
    assert "smb.lateral" not in types and "smb.server" not in types
    assert "lateral" not in plan.facts


@pytest.mark.skipif(not capture_tools, reason="requires tshark >= 4.4 and dumpcap/tcpdump with loopback capture rights")
@pytest.mark.parametrize("level,duration", [("easy", 360.0), ("hard", 600.0)])
def test_capture_matches_the_key(tmp_path, level, duration):
    result = generate(find(SCENARIO), level, "pytest", tmp_path, duration=duration, siem=True)
    assert result.report.ok, [c for c in result.report.checks if not c["ok"]]
    answers = json.loads(result.answers.read_text(encoding="utf-8"))
    lat = answers["facts"]["lateral"]
    source = lat["source"]["ip"]
    account = lat["account"]

    # One ADMIN$ tree connect per target from the source, to as many distinct workstations as the key says.
    admin = tshark(result.pcap, f'smb2.cmd==3 && smb2.tree contains "ADMIN$" && ip.src=={source}',
                   "frame.number", "ip.dst")
    assert len(admin) == lat["target_count"]
    assert len({r[1] for r in admin}) == lat["target_count"]

    # The source also mounts IPC$ and C$ on the targets (admin-share access, not just one share).
    assert tshark(result.pcap, f'smb2.cmd==3 && smb2.tree contains "IPC$" && ip.src=={source}', "frame.number")
    assert tshark(result.pcap, f'smb2.cmd==3 && smb2.tree contains "C$" && ip.src=={source}', "frame.number")

    # The account is on the wire as the client name of the source's Kerberos AS exchange.
    as_reqs = tshark(result.pcap,
                     f'kerberos.msg_type==10 && kerberos.CNameString=="{account}" && ip.src=={source}',
                     "frame.number")
    assert as_reqs, "the source authenticates with the account over Kerberos AS"

    # The first_tree_connect frame is the ADMIN$ tree connect to the first target.
    first_frame = lat["first_tree_connect"]["frame"]
    first = tshark(result.pcap, f"frame.number=={first_frame} && smb2.cmd==3 && ip.dst=={lat['first_target']['ip']}",
                   "smb2.tree")
    assert len(first) == 1 and "ADMIN$" in first[0][0]

    # Every per-target tree connect frame in the key points at an ADMIN$ tree connect to that target.
    for entry in lat["per_target"]:
        frame = entry["tree_connect"]["frame"]
        rows = tshark(result.pcap, f"frame.number=={frame} && smb2.cmd==3 && ip.dst=={entry['host']['ip']}", "smb2.tree")
        assert rows and "ADMIN$" in rows[0][0], f"tree-connect frame {frame} is not an ADMIN$ connect to {entry['host']['id']}"

    # The denied target (hard only) answers the ADMIN$ tree connect with STATUS_ACCESS_DENIED.
    if lat["denied_target"]:
        denied_ip = lat["denied_target"]["ip"]
        refused = tshark(result.pcap,
                         f"smb2.cmd==3 && smb2.nt_status==0xc0000022 && ip.src=={denied_ip} && ip.dst=={source}",
                         "frame.number")
        assert refused, "the denied target refuses the ADMIN$ connection with access denied"
        # No other target refuses access.
        all_denied = {r[0] for r in tshark(result.pcap, "smb2.cmd==3 && smb2.nt_status==0xc0000022", "ip.src")}
        assert all_denied == {denied_ip}


@pytest.mark.skipif(not capture_tools, reason="requires tshark >= 4.4 and dumpcap/tcpdump with loopback capture rights")
def test_office_baseline_has_no_admin_share_access(tmp_path):
    result = generate(find("it-baseline-operations"), "medium", "pytest", tmp_path, duration=400.0)
    assert not tshark(result.pcap, 'smb2.cmd==3 && smb2.tree contains "ADMIN$"', "frame.number"), \
        "the office baseline never opens an ADMIN$ administrative share"
