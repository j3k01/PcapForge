"""The bulk-upload scenario (it-bulk-upload): one office PC uploads opaque random bytes to an
external file host - the benign equivalent of data exfiltration. Easy is a single plain-HTTP POST,
medium/hard are HTTPS uploads whose only trace is the TLS record sizes and the upload/download ratio."""

import json
import shutil
import subprocess

import pytest

from pcapforge.detections import SID_IT_BASE, sigma_rules, suricata_rules
from pcapforge.pipeline import generate
from pcapforge.plan import build_plan
from pcapforge.scenario import find
from pcapforge.tools import MIN_TSHARK, find_tool, tshark_version

SCENARIO = "it-bulk-upload"
TOLERANCE = 2_000_000  # the total-bytes question tolerance, also the wire-vs-plan allowance
SID_POST, SID_TLS = SID_IT_BASE + 400, SID_IT_BASE + 401

capture_tools = (find_tool("tshark") and (find_tool("dumpcap") or find_tool("tcpdump"))
                 and tshark_version() >= MIN_TSHARK)


def tshark(pcap, display_filter, *fields):
    out = subprocess.run([find_tool("tshark"), "-n", "-r", str(pcap), "-Y", display_filter, "-T", "fields",
                          "-E", "occurrence=a", *[arg for f in fields for arg in ("-e", f)]],
                         capture_output=True, text=True, check=True).stdout
    return [line.split("\t") for line in out.splitlines()]


def jsonl(path):
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh]


# --- plan-level (no capture) ---------------------------------------------------------

@pytest.mark.parametrize("difficulty", ["easy", "medium", "hard"])
def test_plan_uploads_from_one_office_pc_to_the_external_sink(difficulty):
    plan = build_plan(find(SCENARIO), difficulty, "42", duration_override=1800)
    up = plan.facts["bulk_upload"]
    sink = plan.facts["upload_service"]
    assert up["mode"] == ("plain" if difficulty == "easy" else "tls")
    assert up["upload_count"] == len(up["uploads"]) >= 1
    assert up["total_bytes"] == sum(u["size"] for u in up["uploads"]) > 0
    # The destination is the external file host, and its domain is one of the host's dotted aliases.
    assert up["dest"]["$host"] == sink["hosts"][0]["$host"]
    assert up["domain"] in sink["domains"] and "." in up["domain"]
    # The uploader is not the sink, and every upload happens inside the capture.
    assert up["source"]["$host"] != up["dest"]["$host"]
    assert all(u["request"]["$action"].t < plan.duration for u in up["uploads"])
    assert (up["filename"] is not None) == (difficulty == "easy")


# --- end to end (capture) ------------------------------------------------------------

@pytest.mark.skipif(not capture_tools, reason="requires tshark >= 4.4 and dumpcap/tcpdump with loopback capture rights")
def test_easy_is_a_single_plain_http_post_with_the_file_name_and_the_right_volume(tmp_path):
    result = generate(find(SCENARIO), "easy", "pytest", tmp_path, duration=600.0, siem=True)
    assert result.report.ok, [c for c in result.report.checks if not c["ok"]]
    answers = json.loads(result.answers.read_text(encoding="utf-8"))
    up = answers["facts"]["bulk_upload"]
    src, dst, domain = up["source"]["ip"], up["dest"]["ip"], up["domain"]

    posts = tshark(result.pcap, f'http.request.method == "POST" && ip.dst == {dst}',
                   "http.request.uri", "http.host", "http.content_type", "http.content_length_header")
    assert len(posts) == up["upload_count"] == 1
    uri, host, ctype, clen = posts[0]
    assert up["filename"] in uri and host == domain
    assert ctype == "application/octet-stream" and int(clen) == up["total_bytes"]

    # The answer-key "first upload" frame is the first client->server frame to the sink.
    first = tshark(result.pcap, f"frame.number == {up['first']['frame']}", "ip.src", "ip.dst")
    assert first and first[0] == [src, dst]

    # Bytes on the wire from the answer-key flows equal the planned upload volume within tolerance.
    flows = [f for f in jsonl(result.exports["siem/flows.jsonl"])
             if f["dest"] == dst and f["transport"] == "tcp"]
    wire = sum(f["bytes_out"] for f in flows)
    assert wire >= up["total_bytes"] and wire - up["total_bytes"] <= TOLERANCE


@pytest.mark.skipif(not capture_tools, reason="requires tshark >= 4.4 and dumpcap/tcpdump with loopback capture rights")
def test_medium_uploads_over_https_show_only_as_tls_sessions_and_an_outbound_ratio(tmp_path):
    result = generate(find(SCENARIO), "medium", "pytest", tmp_path, duration=900.0, siem=True)
    assert result.report.ok, [c for c in result.report.checks if not c["ok"]]
    answers = json.loads(result.answers.read_text(encoding="utf-8"))
    up = answers["facts"]["bulk_upload"]
    src, dst, domain = up["source"]["ip"], up["dest"]["ip"], up["domain"]

    # Each upload is one HTTPS connection: a ClientHello to the sink with the external SNI; no plain HTTP.
    hellos = tshark(result.pcap, f"tls.handshake.type == 1 && ip.dst == {dst}",
                    "tls.handshake.extensions_server_name")
    assert len(hellos) == up["upload_count"] >= 3 and {sni for (sni,) in hellos} == {domain}
    assert not tshark(result.pcap, f'http.request.method == "POST" && ip.dst == {dst}', "ip.src")

    # The tell: to the sink the host sends far more than it receives; browsing/WSUS are the opposite.
    flows = [f for f in jsonl(result.exports["siem/flows.jsonl"]) if f["transport"] == "tcp"]
    exfil = [f for f in flows if f["dest"] == dst and f["src"] == src]
    wire = sum(f["bytes_out"] for f in exfil)
    assert exfil and sum(f["bytes_out"] for f in exfil) > 8 * sum(f["bytes_in"] for f in exfil)
    assert wire >= up["total_bytes"] and wire - up["total_bytes"] <= TOLERANCE
    # No other destination has this outbound-heavy ratio at this volume.
    by_dest = {}
    for f in flows:
        out, inn = by_dest.get(f["dest"], (0, 0))
        by_dest[f["dest"]] = (out + f["bytes_out"], inn + f["bytes_in"])
    heavy = [d for d, (out, inn) in by_dest.items() if out > 1_000_000 and out > 5 * (inn + 1)]
    assert heavy == [dst]


@pytest.mark.skipif(not capture_tools, reason="requires tshark >= 4.4 and dumpcap/tcpdump with loopback capture rights")
def test_sigma_flows_rule_matches_the_uploads_and_nothing_else(tmp_path):
    from sigma_eval import hits, load_rules
    result = generate(find(SCENARIO), "medium", "sigma", tmp_path, duration=900.0, siem=True)
    answers = json.loads(result.answers.read_text(encoding="utf-8"))
    up = answers["facts"]["bulk_upload"]
    rules = load_rules(result.directory / "detections" / "sigma")
    fired = hits(rules["Large data upload to an external file host"], result.directory / "siem")
    assert fired and {f["dest"] for f in fired} == {up["dest"]["ip"]}
    assert len(fired) == up["upload_count"]


# --- Suricata ------------------------------------------------------------------------

def _suricata_alerts(pcap, rules_file, tmp_path):
    tmp_path.mkdir(parents=True, exist_ok=True)
    run = subprocess.run([shutil.which("suricata"), "-r", str(pcap), "-S", str(rules_file),
                          "--set", "unix-command.enabled=no", "-l", str(tmp_path), "-k", "none",
                          "--init-errors-fatal"], capture_output=True, text=True)
    assert run.returncode == 0, run.stderr + run.stdout
    return [e for e in jsonl(tmp_path / "eve.json") if e.get("event_type") == "alert"]

@pytest.mark.skipif(not shutil.which("suricata") or not capture_tools, reason="requires suricata and tshark on PATH")
def test_suricata_alerts_on_the_upload_and_never_on_the_office_baseline(tmp_path):
    incident = generate(find(SCENARIO), "easy", "suri", tmp_path / "easy", duration=600.0, siem=True)
    rules_file = incident.exports["detections/suricata.rules"]
    alerts = _suricata_alerts(incident.pcap, rules_file, tmp_path / "s-easy")
    sids = [a["alert"]["signature_id"] for a in alerts]
    # The plain-HTTP upload fires the POST rule, from the office PC to the external sink.
    assert sids.count(SID_POST) >= 1 and SID_TLS not in sids
    answers = json.loads(incident.answers.read_text(encoding="utf-8"))
    up = answers["facts"]["bulk_upload"]
    post = next(a for a in alerts if a["alert"]["signature_id"] == SID_POST)
    assert {post["src_ip"], post["dest_ip"]} == {up["source"]["ip"], up["dest"]["ip"]}

    base = generate(find("it-baseline-operations"), "medium", "suri-base", tmp_path / "base", duration=600.0, siem=True)
    base_alerts = _suricata_alerts(base.pcap, rules_file, tmp_path / "s-base")
    assert not [a for a in base_alerts if a["alert"]["signature_id"] in (SID_POST, SID_TLS)]
