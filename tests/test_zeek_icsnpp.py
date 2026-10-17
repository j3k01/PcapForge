"""Zeek with CISA's ICSNPP packages (zeek.py): the OT protocols Zeek's own analyzers do not parse are
logged, and on easy (no drops, duplicates or retransmissions) the ICSNPP records of every incident
match the pcapforge export and the answer key. Each test runs only when its package is installed."""

import json
import subprocess
from collections import Counter

import pytest

from pcapforge.pipeline import generate
from pcapforge.scenario import find
from pcapforge.tools import MIN_TSHARK, find_tool, tshark_version
from pcapforge.zeek import ICSNPP, find_zeek, write_zeek_logs

capture_tools = (find_tool("tshark") and (find_tool("dumpcap") or find_tool("tcpdump"))
                 and tshark_version() >= MIN_TSHARK)


def installed() -> set[str]:
    """The ICSNPP packages the local Zeek can load."""
    zeek = find_zeek()
    if not zeek:
        return set()
    probe = "event zeek_init() { " + " ".join(
        f'if ( find_in_zeekpath("packages/{p}") != "" ) print "{p}";' for p in ICSNPP) + " }"
    proc = subprocess.run([*zeek, "-b", "-e", probe], capture_output=True, text=True, timeout=120, check=False)
    return set(proc.stdout.split()) if proc.returncode == 0 else set()


INSTALLED = installed()


def needs(package):
    return pytest.mark.skipif(not capture_tools or package not in INSTALLED,
                              reason=f"requires tshark >= 4.4, loopback capture and Zeek with {package}")


def jsonl(path):
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh]


def run(tmp_path, scenario, difficulty="easy", duration=360.0):
    result = generate(find(scenario), difficulty, "pytest", tmp_path, duration=duration, siem=True)
    assert result.report.ok, [c for c in result.report.checks if not c["ok"]]
    answers = json.loads(result.answers.read_text(encoding="utf-8"))
    return result, answers, write_zeek_logs(result.pcap, answers, tmp_path / "zeek")


@needs("icsnpp-dnp3")
def test_dnp3_control_log_has_the_attackers_select_and_operate_per_point(tmp_path):
    result, answers, logs = run(tmp_path, "ot-dnp3-control-injection")
    inject = answers["facts"]["inject"]
    controls = [r for r in jsonl(logs["dnp3_control"]) if r["is_orig"] and r["id.orig_h"] == inject["source"]["ip"]]
    export = [r for r in jsonl(result.exports["siem/dnp3.jsonl"])
              if r.get("function_code") in (3, 4) and r["src"] == inject["source"]["ip"]]
    assert Counter((r["function_code"], r["index_number"]) for r in controls) == Counter(
        ({3: "SELECT", 4: "OPERATE"}[r["function_code"]], c["index"]) for r in export for c in r["controls"])
    assert {r["index_number"] for r in controls} == set(inject["indices"])
    assert all(r["id.resp_h"] == inject["target"]["ip"] and r["operation_type"] == "Latch Off" for r in controls)
    assert "weird" not in logs


@needs("icsnpp-bacnet")
def test_bacnet_property_log_has_every_write_of_the_attacker(tmp_path):
    result, answers, logs = run(tmp_path, "ot-bacnet-unauthorized-write")
    inject = answers["facts"]["inject"]
    writes = [r for r in jsonl(logs["bacnet_property"]) if r["pdu_service"] == "write-property"
              and r["is_orig"] and r["id.orig_h"] == inject["source"]["ip"]]
    export = [r for r in jsonl(result.exports["siem/bacnet.jsonl"])
              if r.get("service") == "write_property" and r.get("apdu_type") == "confirmed_request"
              and r["src"] == inject["source"]["ip"]]
    assert Counter(r["instance_number"] for r in writes) == Counter(r["instance"] for r in export)
    assert {r["instance_number"] for r in writes} >= set(inject["instances"])
    assert all(r["id.resp_h"] == inject["target"]["ip"] and r["object_type"] == "analog-value"
               and r["property"] == "present-value" for r in writes)
    assert "weird" not in logs


@needs("icsnpp-enip")
def test_cip_logs_have_the_attackers_forward_open_and_io_stream(tmp_path):
    result, answers, logs = run(tmp_path, "ot-enip-drive-manipulation", duration=300.0)
    inject = answers["facts"]["inject"]
    source, target = inject["source"]["ip"], inject["target"]["ip"]
    export = jsonl(result.exports["siem/enip.jsonl"])
    opens = [r for r in jsonl(logs["cip"]) if r["direction"] == "request" and r["cip_service"] == "Forward Open"
             and r["id.orig_h"] == source]
    assert len(opens) == len([r for r in export if r.get("service") == "forward_open"
                              and r.get("response") is False and r["src"] == source])
    assert opens and all(r["id.resp_h"] == target for r in opens)
    # Class 1 I/O: one cip_io record per packet, as many as the export's per-minute summaries count.
    io = [r for r in jsonl(logs["cip_io"]) if r["source_h"] == source]
    assert len(io) == sum(r["packets"] for r in export if r.get("message") == "io_summary" and r["src"] == source)
    assert all(r["destination_h"] == target for r in io)
    assert "weird" not in logs


@pytest.mark.skipif(not {"icsnpp-s7comm", "icsnpp-opcua-binary"} <= INSTALLED or not capture_tools,
                    reason="requires tshark >= 4.4, loopback capture and Zeek with icsnpp-s7comm and icsnpp-opcua-binary")
def test_s7comm_and_opcua_sessions_are_logged_and_deterministic(tmp_path):
    result, answers, logs = run(tmp_path, "ot-baseline-operations", "medium", duration=600.0)
    hosts = {h["id"]: h for h in answers["topology"]["hosts"]}
    s7plc, scada, historian = (hosts[h]["interfaces"][0]["ip"] for h in ("s7plc", "scada", "historian"))

    # Every S7comm job request is logged: as many as tshark decodes, all to the S7-1500.
    jobs = [r for r in jsonl(logs["s7comm"]) if r["is_orig"] and r["rosctr_name"] == "Job-Request"]
    tshark = subprocess.run([find_tool("tshark"), "-n", "-r", str(result.pcap), "-Y",
                             "s7comm.header.rosctr == 1 && !tcp.analysis.retransmission", "-T", "fields",
                             "-e", "frame.number"], capture_output=True, text=True, check=True).stdout
    assert jobs and all(r["id.resp_h"] == s7plc for r in jobs)
    assert abs(len(jobs) - len(tshark.split())) <= len(tshark.split()) // 100  # mid-session start, sensor drops
    assert {r["function_name"] for r in jobs} >= {"Read Variable"}

    # The historian's OPC UA subscription to the SCADA server: Publish requests.
    opcua = jsonl(logs["opcua_binary"])
    requests = {r.get("req_identifier_str") for r in opcua if r.get("id.resp_h") == scada}
    assert "PublishRequest" in requests
    assert all(r["id.orig_h"] == historian and r["id.resp_h"] == scada for r in opcua)

    # Deterministic mode covers the packages' correlation ids too.
    again = write_zeek_logs(result.pcap, answers, tmp_path / "zeek2")
    assert {n: p.read_bytes() for n, p in again.items()} == {n: p.read_bytes() for n, p in logs.items()}
