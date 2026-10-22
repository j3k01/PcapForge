"""The DNS-based data-transfer scenario: one workstation sends a run of queries whose leading label
carries base32-encoded chunks of a fake payload under one fictional parent domain, through the site
resolver (the DC). Benign equivalent of DNS tunnelling - the resolver forwards and SERVFAILs, nothing
leaves the loopback range. The answer-key frames decode back to exactly the planned byte count, and
the incident traffic is absent from the baseline."""

import base64
import json
import re
import shutil
import subprocess

import pytest

from pcapforge.detections import SID_IT_BASE
from pcapforge.pipeline import generate
from pcapforge.plan import build_plan
from pcapforge.scenario import find
from pcapforge.tools import MIN_TSHARK, find_tool, tshark_version

SCENARIO = "it-dns-tunneling"


def b32_decode(label: str) -> bytes:
    pad = "=" * ((8 - len(label) % 8) % 8)
    return base64.b32decode(label.upper() + pad)


def test_plan_encodes_a_fixed_payload_into_equal_length_labels():
    plan = build_plan(find(SCENARIO), "easy", "42")
    tunnel = plan.facts["tunnel"]
    assert tunnel["source"] == {"$host": "ws1"}
    assert tunnel["qtypes"] == ["TXT"] and tunnel["qtype_codes"] == [16]
    # easy: 1500 bytes in 30-byte chunks -> 50 queries, each a 48-character base32 label.
    assert tunnel["query_count"] == 50
    assert tunnel["bytes_total"] == 1500
    assert tunnel["label_len"] == 48
    assert sum(q["bytes"] for q in tunnel["queries"]) == tunnel["bytes_total"]
    assert tunnel["domain"] in find(SCENARIO).doc["difficulty"]["easy"]["vars"]["tunnel_domain"]["choose"]
    # The queries all go to the DC resolver, and the first-query reference is the earliest of them.
    assert tunnel["server"] == {"$host": "dc"}
    first = tunnel["first_query"]["$action"]
    assert first.t == min(q["request"]["$action"].t for q in tunnel["queries"])


@pytest.mark.parametrize("difficulty,qtypes", [("medium", ["A", "AAAA"]), ("hard", ["A"])])
def test_label_length_and_record_type_track_difficulty(difficulty, qtypes):
    plan = build_plan(find(SCENARIO), difficulty, "seed-x")
    tunnel = plan.facts["tunnel"]
    assert tunnel["qtypes"] == qtypes
    assert tunnel["label_len"] == {"medium": 32, "hard": 16}[difficulty]
    assert tunnel["bytes_total"] == tunnel["query_count"] * {"medium": 20, "hard": 10}[difficulty]


capture_tools = (find_tool("tshark") and (find_tool("dumpcap") or find_tool("tcpdump"))
                 and tshark_version() >= MIN_TSHARK)


def tshark_rows(pcap, display_filter, *fields):
    out = subprocess.run([find_tool("tshark"), "-n", "-r", str(pcap), "-Y", display_filter,
                          "-T", "fields", *[arg for f in fields for arg in ("-e", f)]],
                         capture_output=True, text=True, check=True).stdout
    return [line.split("\t") for line in out.splitlines() if line]


@pytest.mark.skipif(not capture_tools, reason="requires tshark >= 4.4 and dumpcap/tcpdump with loopback capture rights")
def test_capture_decodes_to_the_planned_byte_count_and_is_absent_from_the_baseline(tmp_path):
    result = generate(find(SCENARIO), "easy", "pytest", tmp_path / "run", duration=400.0, siem=True)
    assert result.report.ok, [c for c in result.report.checks if not c["ok"]]
    answers = json.loads(result.answers.read_text(encoding="utf-8"))
    tunnel = answers["facts"]["tunnel"]
    parent, src = tunnel["domain"], tunnel["source"]["ip"]

    # Every encoded query in the answer key is a query frame from the tunnelling host to the parent.
    key_frames = {q["request"]["frame"] for q in tunnel["queries"]}
    rows = tshark_rows(result.pcap, f'dns.flags.response == 0 && dns.qry.name contains "{parent}"',
                       "frame.number", "ip.src", "dns.qry.name", "dns.qry.type")
    seen = {int(n): (ip, name, qtype) for n, ip, name, qtype in rows}
    assert key_frames <= set(seen), key_frames - set(seen)
    assert all(ip == src for ip, _, _ in seen.values())
    assert all(qtype == "16" for _, _, qtype in seen.values())  # TXT on easy

    # Decoding the leading label of each answer-key frame reconstructs exactly the planned byte count.
    decoded = sum(len(b32_decode(seen[frame][1].split(".", 1)[0])) for frame in key_frames)
    assert decoded == tunnel["bytes_total"] == 1500

    # The first-query answer frame is the earliest encoded query in the capture.
    first_frame = tunnel["first_query"]["frame"]
    assert first_frame == min(key_frames)

    # The dns SIEM dataset carries the same encoded queries (the hunts run over it).
    dns = [json.loads(line) for line in (result.directory / "siem" / "dns.jsonl").read_text().splitlines() if line]
    encoded = [r for r in dns if r.get("query", "").endswith(parent) and r.get("src") == src]
    assert len(encoded) == tunnel["query_count"]

    # Incident traffic is absent from the baseline: the baseline never queries this parent.
    baseline = generate(find("it-baseline-operations"), "easy", "pytest", tmp_path / "base",
                        duration=400.0, siem=False)
    assert not tshark_rows(baseline.pcap, f'dns.qry.name contains "{parent}"', "frame.number")


@pytest.mark.skipif(not capture_tools, reason="requires tshark >= 4.4 and dumpcap/tcpdump with loopback capture rights")
@pytest.mark.skipif(not shutil.which("suricata"), reason="requires suricata on PATH")
def test_suricata_alerts_only_on_the_encoded_queries_and_not_on_the_baseline(tmp_path):
    result = generate(find(SCENARIO), "easy", "pytest", tmp_path / "run", duration=400.0, siem=True)
    answers = json.loads(result.answers.read_text(encoding="utf-8"))
    tunnel = answers["facts"]["tunnel"]
    rules = result.exports["detections/suricata.rules"]
    pair = {tunnel["source"]["ip"], tunnel["server"]["ip"]}

    def alerts(pcap, out):
        out.mkdir(parents=True, exist_ok=True)
        run = subprocess.run([shutil.which("suricata"), "-r", str(pcap), "-S", str(rules),
                              "--set", "unix-command.enabled=no", "-l", str(out), "-k", "none",
                              "--init-errors-fatal"], capture_output=True, text=True)
        assert run.returncode == 0, run.stderr + run.stdout
        return [json.loads(line) for line in (out / "eve.json").read_text().splitlines()
                if json.loads(line).get("event_type") == "alert"]

    hits = [a for a in alerts(result.pcap, tmp_path / "s1") if a["alert"]["signature_id"] == SID_IT_BASE]
    assert len(hits) >= tunnel["query_count"]
    assert all({a["src_ip"], a["dest_ip"]} == pair for a in hits)

    baseline = generate(find("it-baseline-operations"), "easy", "pytest", tmp_path / "base",
                        duration=400.0, siem=False)
    base_hits = [a for a in alerts(baseline.pcap, tmp_path / "s2") if a["alert"]["signature_id"] == SID_IT_BASE]
    assert not base_hits
