"""The volumetric-flood scenario: a bounded, high-rate burst of UDP datagrams to a local sink
(Discard, port 9). The measured rate and volume in the capture match the answer key, the flood is
absent from the office baseline, and Suricata's threshold rule alerts only on the flood."""

import json
import shutil
import subprocess
from collections import Counter

import pytest

from pcapforge.detections import SID_IT_BASE
from pcapforge.pipeline import generate
from pcapforge.plan import build_plan
from pcapforge.scenario import find
from pcapforge.tools import MIN_TSHARK, find_tool, tshark_version

SCENARIO = "it-volumetric-flood"
FLOOD_SID = SID_IT_BASE + 300
capture_tools = (find_tool("tshark") and (find_tool("dumpcap") or find_tool("tcpdump"))
                 and tshark_version() >= MIN_TSHARK)
# A bounded burst: every level stays well under this many flood datagrams (capture-size budget).
MAX_FLOOD_PACKETS = 7000


def tshark(pcap, display_filter, *fields):
    out = subprocess.run([find_tool("tshark"), "-n", "-r", str(pcap), "-Y", display_filter, "-T", "fields",
                          "-E", "occurrence=a", *[arg for f in fields for arg in ("-e", f)]],
                         capture_output=True, text=True, check=True).stdout
    return [line.split("\t") for line in out.splitlines() if line.strip()]


def peak_per_second(epochs):
    base = min(epochs)
    return max(Counter(int(t - base) for t in epochs).values())


# --- plan-level: deterministic, no capture ------------------------------------------------

def test_plan_floods_the_sink_with_a_bounded_burst():
    for level in ("easy", "medium", "hard"):
        plan = build_plan(find(SCENARIO), level, "42")
        flood = [a for a in plan.actions if a.actor == "flood"]
        assert flood and all(a.op == "sink.udp" for a in flood), level
        assert all(a.args["target"] == "sink" for a in flood), level
        f = plan.facts["flood"]
        assert f["total_packets"] == len(flood), level
        assert len(flood) <= MAX_FLOOD_PACKETS, (level, len(flood))
        assert f["peak_pps"] >= 1 and f["port"] == 9 and f["protocol"] == "udp"
        # easy is a single source; medium / hard use several.
        assert f["source_count"] == (1 if level == "easy" else 3), level
        assert len(f["sources"]) == f["source_count"]


def test_baseline_plan_has_no_flood():
    plan = build_plan(find("it-baseline-operations"), "easy", "42")
    assert not any(a.op == "sink.udp" for a in plan.actions)
    assert "flood" not in plan.facts


# --- capture-level ------------------------------------------------------------------------

@pytest.fixture(scope="module")
def easy_run(tmp_path_factory):
    result = generate(find(SCENARIO), "easy", "pytest", tmp_path_factory.mktemp("flood"),
                      duration=240.0, siem=True)
    assert result.report.ok, [c for c in result.report.checks if not c["ok"]]
    return result, json.loads(result.answers.read_text(encoding="utf-8"))


@pytest.mark.skipif(not capture_tools, reason="requires tshark >= 4.4 and dumpcap/tcpdump with loopback capture rights")
def test_measured_rate_and_volume_match_the_answer_key(easy_run):
    result, answers = easy_run
    f = answers["facts"]["flood"]
    sink = f["target"]["ip"]
    rows = tshark(result.pcap, f"udp.dstport == 9 && ip.dst == {sink}",
                  "frame.number", "frame.time_epoch", "ip.src")
    assert rows, "no flood datagrams in the capture"
    numbers = [int(r[0]) for r in rows]
    epochs = [float(r[1]) for r in rows]
    sources = {r[2] for r in rows}

    # Total volume is exact (no SPAN duplicates / drops on this scenario).
    assert abs(len(rows) - f["total_packets"]) <= 1
    # Every source that sent the flood, and only those.
    assert sources == set(f["source_ips"])
    # The measured peak packets-per-second matches the key within the question's tolerance.
    assert abs(peak_per_second(epochs) - f["peak_pps"]) <= 25
    # Start / end answer frames are the first / last flood datagram by time.
    by_time = sorted(zip(epochs, numbers))
    assert by_time[0][1] == f["first_packet"]["frame"]
    assert by_time[-1][1] == f["last_packet"]["frame"]
    assert f["first_packet"]["frame"] in numbers and f["last_packet"]["frame"] in numbers


@pytest.mark.skipif(not capture_tools, reason="requires tshark >= 4.4 and dumpcap/tcpdump with loopback capture rights")
def test_the_flood_is_absent_from_the_office_baseline(tmp_path):
    base = generate(find("it-baseline-operations"), "easy", "pytest", tmp_path / "baseline", duration=240.0)
    assert base.report.ok
    assert not tshark(base.pcap, "udp.dstport == 9", "frame.number")


@pytest.mark.skipif(not capture_tools, reason="requires tshark >= 4.4 and dumpcap/tcpdump with loopback capture rights")
def test_medium_blends_several_sources_into_the_flood(tmp_path):
    result = generate(find(SCENARIO), "medium", "pytest", tmp_path / "medium", duration=300.0, siem=True)
    assert result.report.ok, [c for c in result.report.checks if not c["ok"]]
    answers = json.loads(result.answers.read_text(encoding="utf-8"))
    f = answers["facts"]["flood"]
    sink = f["target"]["ip"]
    sources = {r[0] for r in tshark(result.pcap, f"udp.dstport == 9 && ip.dst == {sink}", "ip.src")}
    assert sources == set(f["source_ips"]) and len(sources) >= 2


@pytest.mark.skipif(not capture_tools, reason="requires tshark >= 4.4 and dumpcap/tcpdump with loopback capture rights")
@pytest.mark.skipif(not shutil.which("suricata"), reason="requires suricata on PATH")
def test_suricata_threshold_alerts_only_on_the_flood(easy_run, tmp_path):
    result, _ = easy_run
    rules = result.exports["detections/suricata.rules"]
    baseline = generate(find("it-baseline-operations"), "easy", "pytest", tmp_path / "baseline", duration=240.0)

    def flood_alerts(pcap, out):
        out.mkdir(parents=True, exist_ok=True)
        run = subprocess.run([shutil.which("suricata"), "-r", str(pcap), "-S", str(rules),
                              "--set", "unix-command.enabled=no", "-l", str(out), "-k", "none",
                              "--init-errors-fatal"], capture_output=True, text=True)
        assert run.returncode == 0, run.stderr + run.stdout
        return [json.loads(line) for line in (out / "eve.json").read_text().splitlines()
                if json.loads(line).get("event_type") == "alert"
                and json.loads(line)["alert"]["signature_id"] == FLOOD_SID]

    assert flood_alerts(result.pcap, tmp_path / "s1"), "the flood rule did not fire on the flood"
    assert not flood_alerts(baseline.pcap, tmp_path / "s2"), "the flood rule fired on the baseline"
