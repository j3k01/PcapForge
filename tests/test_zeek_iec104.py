"""pcapforge's IEC 60870-5-104 Spicy analyzer for Zeek (zeek_analyzers/iec104): on easy (no drops,
duplicates or retransmissions) iec104.log has exactly the APDUs of the pcapforge export, field by
field, and iec104_command.log every command object, the attacker's breaker commands included."""

import json
import subprocess

import pytest

from pcapforge.pipeline import generate
from pcapforge.scenario import find
from pcapforge.tools import MIN_TSHARK, find_tool, tshark_version
from pcapforge.zeek import IEC104_SCRIPTS, find_zeek, write_zeek_logs

capture_tools = (find_tool("tshark") and (find_tool("dumpcap") or find_tool("tcpdump"))
                 and tshark_version() >= MIN_TSHARK)


def analyzer_installed() -> bool:
    zeek = find_zeek()
    if not zeek or not capture_tools:
        return False
    probe = f'event zeek_init() {{ print find_in_zeekpath("{IEC104_SCRIPTS}") != ""; }}'
    proc = subprocess.run([*zeek, "-b", "-e", probe], capture_output=True, text=True, timeout=120, check=False)
    return proc.stdout.strip() == "T"


pytestmark = pytest.mark.skipif(not analyzer_installed(), reason="requires tshark >= 4.4, loopback capture and "
                                "Zeek with pcapforge's IEC 104 analyzer (zeek.ANALYZERS_INSTALL)")


def jsonl(path):
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh]


@pytest.fixture(scope="module")
def run(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("iec104")
    result = generate(find("ot-iec104-command-injection"), "easy", "pytest", tmp, duration=360.0, siem=True)
    assert result.report.ok, [c for c in result.report.checks if not c["ok"]]
    answers = json.loads(result.answers.read_text(encoding="utf-8"))
    return result, answers, write_zeek_logs(result.pcap, answers, tmp / "zeek")


def test_every_apdu_of_the_export_is_one_iec104_log_record(run):
    result, _, logs = run
    export = jsonl(result.exports["siem/iec104.jsonl"])
    zeek = jsonl(logs["iec104"])

    def from_export(r):
        return (r["src"], r["dest"], r["apci"], r.get("u_function"), r.get("send_seq"), r.get("recv_seq"),
                r.get("type"), r.get("cause"), r.get("negative"), r.get("common_address"), tuple(r.get("ioa") or ()))

    def from_zeek(r):
        src, dest = (r["id.orig_h"], r["id.resp_h"]) if r["is_orig"] else (r["id.resp_h"], r["id.orig_h"])
        return (src, dest, r["apci"], r.get("u_function"), r.get("send_seq"), r.get("recv_seq"),
                r.get("type_name"), r.get("cause"), r.get("negative"), r.get("common_address"), tuple(r.get("ioa") or ()))

    assert [from_zeek(r) for r in zeek] == [from_export(r) for r in export]
    assert "weird" not in logs


def test_command_log_has_the_attackers_breaker_select_and_execute(run):
    result, answers, logs = run
    inject = answers["facts"]["inject"]
    commands = [r for r in jsonl(logs["iec104_command"])
                if r["is_orig"] and r["id.orig_h"] == inject["source"]["ip"] and r["cause"] == "activation"]
    export = [(o["ioa"], o["value"], o["select"]) for r in jsonl(result.exports["siem/iec104.jsonl"])
              if r["src"] == inject["source"]["ip"] and r.get("cause") == "activation" and r.get("type") == "C_SC_NA_1"
              for o in r["objects"]]
    assert [(r["ioa"], r["value"], r["select"]) for r in commands] == export
    executed = {r["ioa"] for r in commands if not r["select"]}
    assert executed == set(inject["ioas"])
    # Select before execute, both "off" (open the breaker), at the RTU the answer key names.
    for ioa in executed:
        selects = [r["ts"] for r in commands if r["ioa"] == ioa and r["select"]]
        executes = [r["ts"] for r in commands if r["ioa"] == ioa and not r["select"]]
        assert selects and executes and min(selects) < min(executes)
    assert all(r["value"] == 0 and r["id.resp_h"] == inject["target"]["ip"] and r["type_name"] == "C_SC_NA_1"
               for r in commands)



def test_the_analyzer_finds_iec104_on_another_port_by_its_startdt(run, tmp_path):
    """Content-based detection (dpd.sig): the same capture with the RTUs moved from 2404 to 12404."""
    from scapy.layers.inet import IP, TCP
    from scapy.utils import rdpcap, wrpcap

    result, answers, logs = run
    packets = rdpcap(str(result.pcap))
    for pkt in packets:
        if TCP in pkt and 2404 in (pkt[TCP].sport, pkt[TCP].dport):
            tcp = pkt[TCP]
            tcp.sport, tcp.dport = (12404 if p == 2404 else p for p in (tcp.sport, tcp.dport))
            del pkt[IP].chksum, tcp.chksum
    moved = tmp_path / "moved.pcap"
    wrpcap(str(moved), packets)
    moved_logs = write_zeek_logs(moved, answers, tmp_path / "zeek")
    original = [{k: v for k, v in r.items() if k not in ("id.orig_p", "id.resp_p")} for r in jsonl(logs["iec104"])]
    found = [{k: v for k, v in r.items() if k not in ("id.orig_p", "id.resp_p")} for r in jsonl(moved_logs["iec104"])]
    # The STARTDT act that only the con confirms reaches the analyzer replayed, stamped with the con's time.
    assert [{**r, "ts": None} for r in found] == [{**r, "ts": None} for r in original]
    assert all(a["ts"] == b["ts"] or b.get("u_function") == "startdt_act" for a, b in zip(found, original))
    assert all(r["id.resp_p"] == 12404 for r in jsonl(moved_logs["iec104"]))