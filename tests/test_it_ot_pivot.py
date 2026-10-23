"""The IT-to-OT pivot scenario (it-ot-pivot): an office workstation routes through the firewall into
the control network, sweeps it for Modbus/TCP, identifies the PLCs and writes a setpoint out of band.
The answer key points at the right packets, the incident is absent from both baselines, and the
detections fire only on the pivot."""

import json
import shutil
import subprocess

import pytest

from pcapforge.detections import SID_BASE, SID_IT_BASE, sigma_rules, suricata_rules
from pcapforge.pipeline import generate
from pcapforge.plan import build_plan
from pcapforge.scenario import find
from pcapforge.tools import MIN_TSHARK, find_tool, tshark_version

try:
    from sigma_eval import hits, load_rules
except ImportError:  # pragma: no cover
    hits = load_rules = None

SCENARIO = "it-ot-pivot"
SID_PIVOT = SID_IT_BASE + 900
SID_WRITE = SID_BASE + 1

capture_tools = (find_tool("tshark") and (find_tool("dumpcap") or find_tool("tcpdump"))
                 and tshark_version() >= MIN_TSHARK)


def tshark(pcap, display_filter, *fields):
    out = subprocess.run([find_tool("tshark"), "-n", "-r", str(pcap), "-Y", display_filter, "-T", "fields",
                          "-E", "occurrence=a", *[arg for f in fields for arg in ("-e", f)]],
                         capture_output=True, text=True, check=True).stdout
    return [line.split("\t") for line in out.splitlines() if line]


@pytest.mark.parametrize("level,sensor", [("easy", "office"), ("medium", "office"), ("hard", "control")])
def test_plan_has_the_pivot_facts(level, sensor):
    plan = build_plan(find(SCENARIO), level, "42")
    assert plan.topology.sensor == sensor
    scan, change = plan.facts["scan"], plan.facts["change"]
    assert scan["source"] == {"$host": "pivot"} and change["source"] == {"$host": "pivot"}
    assert scan["plc_count"] >= 2 and change["write_count"] >= 1
    # Every written setpoint leaves its normal band.
    for w in change["writes"]:
        lo, hi = w["normal"]
        assert not (lo <= w["value"] <= hi), w
    # The pivot is an office host; its target PLCs are on the control subnet.
    topo = plan.topology
    assert "office" in topo.by_id["pivot"].subnets
    assert all("control" in topo.by_id[p.id].subnets for p in topo.groups["plc"])


def test_sweep_is_loud_on_easy_and_targeted_on_medium():
    easy = build_plan(find(SCENARIO), "easy", "42").facts["scan"]
    medium = build_plan(find(SCENARIO), "medium", "42").facts["scan"]
    assert len(easy["swept"]) >= 4   # the whole control subnet
    assert medium["swept"] == []     # a targeted connect to the PLCs only


def test_neither_baseline_pivots_into_the_control_network():
    for sid in ("it-baseline-operations", "ot-baseline-operations"):
        plan = build_plan(find(sid), "medium", "42")
        assert "scan" not in plan.facts and "change" not in plan.facts


def test_suricata_and_sigma_only_generate_for_this_scenario():
    # The office baseline (no modbus.server) gets no pivot rules; an OT scenario (line ot) neither.
    for sid in ("it-baseline-operations", "ot-modbus-write-manipulation"):
        answers = {"scenario": {"id": sid, "line": sid.split("-")[0]}, "actors": [], "topology": {"hosts": [], "subnets": []}}
        assert not any(r.sid == SID_PIVOT for r in suricata_rules(answers))


@pytest.mark.skipif(not capture_tools, reason="requires tshark >= 4.4 and dumpcap/tcpdump with loopback capture rights")
@pytest.mark.parametrize("level,duration", [("easy", 360.0), ("hard", 480.0)])
def test_capture_matches_the_key(tmp_path, level, duration):
    result = generate(find(SCENARIO), level, "pytest", tmp_path / level, duration=duration, siem=True)
    assert result.report.ok, [c for c in result.report.checks if not c["ok"]]
    answers = json.loads(result.answers.read_text(encoding="utf-8"))
    change = answers["facts"]["change"]
    src = change["source"]["ip"]

    # The out-of-band writes come from the office host, to the control-subnet PLC.
    writes = tshark(result.pcap, f"mbtcp && modbus.func_code in {{5,6,15,16}} && ip.src == {src} && !modbus.request_frame",
                    "ip.dst")
    assert len(writes) >= change["write_count"]
    assert all(row[0] == change["target"]["ip"] for row in writes)

    # The sensor placement decides the MAC on those frames: the pivot's own on the office switch,
    # the firewall's control-side MAC when the sensor is on the OT side.
    macs = {row[0] for row in tshark(result.pcap, f"mbtcp && modbus.func_code in {{5,6,15,16}} && ip.src == {src}", "eth.src")}
    assert macs == {change["source"]["observed_mac"]}


@pytest.mark.skipif(not capture_tools, reason="requires tshark >= 4.4 and dumpcap/tcpdump with loopback capture rights")
def test_the_pivot_is_absent_from_the_office_baseline(tmp_path):
    base = generate(find("it-baseline-operations"), "medium", "pytest", tmp_path / "base", duration=360.0)
    assert base.report.ok, [c for c in base.report.checks if not c["ok"]]
    # The office baseline never speaks Modbus.
    assert not tshark(base.pcap, "mbtcp", "frame.number")
    assert not tshark(base.pcap, "tcp.dstport == 502", "frame.number")


@pytest.mark.skipif(hits is None or not capture_tools, reason="requires tshark and the sigma evaluator")
def test_sigma_flags_the_crosszone_connection_and_the_write(tmp_path):
    result = generate(find(SCENARIO), "easy", "pytest-sigma", tmp_path / "run", duration=360.0, siem=True)
    answers = json.loads(result.answers.read_text(encoding="utf-8"))
    src = answers["facts"]["change"]["source"]["ip"]
    rules = load_rules(result.directory / "detections" / "sigma")
    pivot = hits(rules["Connection from the office LAN into the OT control network"], result.directory / "siem")
    assert pivot and all(h["src"] == src for h in pivot)
    write = hits(rules["Modbus write from an unapproved host"], result.directory / "siem")
    assert write and all(h["src"] == src for h in write)


@pytest.mark.skipif(not capture_tools or not shutil.which("suricata"), reason="requires suricata and tshark on PATH")
def test_suricata_alerts_on_the_pivot_and_never_on_the_office_baseline(tmp_path):
    incident = generate(find(SCENARIO), "easy", "suri", tmp_path / "easy", duration=360.0, siem=True)
    rules_file = incident.exports["detections/suricata.rules"]

    def alerts(pcap, out):
        out.mkdir(parents=True, exist_ok=True)
        run = subprocess.run([shutil.which("suricata"), "-r", str(pcap), "-S", str(rules_file),
                              "--set", "app-layer.protocols.modbus.enabled=true",
                              "--set", "unix-command.enabled=no", "-l", str(out), "-k", "none",
                              "--init-errors-fatal"], capture_output=True, text=True)
        assert run.returncode == 0, run.stderr + run.stdout
        path = out / "eve.json"
        events = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()] if path.exists() else []
        return [e["alert"]["signature_id"] for e in events if e.get("event_type") == "alert"]

    sids = alerts(incident.pcap, tmp_path / "s-easy")
    assert SID_PIVOT in sids, "the IT-to-OT pivot rule did not fire"
    assert SID_WRITE in sids, "the unapproved Modbus write rule did not fire"

    base = generate(find("it-baseline-operations"), "medium", "suri-base", tmp_path / "base", duration=360.0, siem=True)
    assert not alerts(base.pcap, tmp_path / "s-base"), "a rule fired on the office baseline"
