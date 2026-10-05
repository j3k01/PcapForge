"""The Modbus device-discovery scenario: recon only (sweep + identity + register enumeration),
no writes, and per-PLC device identities that match the answer key on the wire."""

import json
import subprocess

import pytest

from pcapforge.pipeline import generate
from pcapforge.plan import build_plan
from pcapforge.scenario import find
from pcapforge.tools import MIN_TSHARK, find_tool, tshark_version

SCENARIO = "ot-modbus-discovery"


def test_the_scan_plans_recon_actions_and_no_writes():
    plan = build_plan(find(SCENARIO), "easy", "42")
    scan = [a for a in plan.actions if a.actor == "scan"]
    ops = {a.op for a in scan}
    assert "modbus.probe" in ops and "modbus.identify" in ops and "modbus.read" in ops
    assert "modbus.write" not in ops, "discovery must never write"
    facts = plan.facts["scan"]
    assert facts["plc_count"] == len(facts["targets"]) >= 1
    assert facts["function_codes"] == [1, 2, 3, 4, 43]
    assert facts["scan_start"] is not None
    # One probe per swept host, and the swept hosts are the non-Modbus control-LAN hosts.
    assert {h["$host"] for h in facts["swept"]} == {"hmi", "historian", "ews"}


capture_tools = (find_tool("tshark") and (find_tool("dumpcap") or find_tool("tcpdump"))
                 and tshark_version() >= MIN_TSHARK)


def tshark_fields(pcap, display_filter, fields):
    cmd = [find_tool("tshark"), "-n", "-r", str(pcap), "-Y", display_filter, "-T", "fields",
           "-E", "separator=|", "-E", "occurrence=a", "-E", "aggregator=,"] + [a for f in fields for a in ("-e", f)]
    out = subprocess.run(cmd, capture_output=True, text=True, check=True).stdout
    return [line.split("|") for line in out.splitlines() if line]


@pytest.mark.skipif(not capture_tools, reason="requires tshark >= 4.4 and dumpcap/tcpdump with loopback capture rights")
def test_discovery_capture_matches_the_key_with_distinct_per_plc_identities(tmp_path):
    result = generate(find(SCENARIO), "easy", "pytest", tmp_path, duration=360.0, siem=True)
    assert result.report.ok, [c for c in result.report.checks if not c["ok"]]
    answers = json.loads(result.answers.read_text(encoding="utf-8"))
    scan = answers["facts"]["scan"]
    source = scan["source"]["ip"]

    # The subnet sweep: the scanner opens TCP 502 to each swept host and to each PLC.
    ips = {h["id"]: next(i["ip"] for i in h["interfaces"] if i["subnet"] == "control")
           for h in answers["topology"]["hosts"] if any(i["subnet"] == "control" for i in h["interfaces"])}
    swept_ips = {ips[s["id"]] for s in scan["swept"]}
    syn_targets = {r[0] for r in tshark_fields(
        result.pcap, f"tcp.flags.syn==1 && tcp.flags.ack==0 && tcp.dstport==502 && ip.src=={source}", ["ip.dst"])}
    assert swept_ips <= syn_targets, "the scanner probes every swept host on port 502"
    # The swept hosts are not PLCs, so none of them answers a Modbus device identification.
    assert not tshark_fields(
        result.pcap,
        f"mbtcp && modbus.func_code==43 && tcp.srcport==502 && ip.src in {{{','.join(sorted(swept_ips))}}}",
        ["frame.number"])

    # No write ever leaves the scanner.
    assert not tshark_fields(result.pcap, f"mbtcp && modbus.func_code in {{5,6,15,16,22,23}} && ip.src=={source}",
                             ["frame.number"])

    # Register enumeration: the oversized read is rejected with illegal_data_address (exception 2).
    assert tshark_fields(result.pcap, f"mbtcp && modbus.exception_code==2 && ip.dst=={source}", ["frame.number"])

    # Each PLC answers the identity read with its own vendor/product, matching the key.
    for entry in scan["identities"]:
        ip = entry["target"]["ip"]
        rows = tshark_fields(result.pcap, f"mbtcp && modbus.func_code==43 && ip.src=={ip} && modbus.object_str_value",
                             ["modbus.object_str_value"])
        assert rows, f"no identity response from {ip}"
        reported = rows[0][0].replace(",", " ")
        assert entry["identity"].split()[0] in reported  # vendor name on the wire matches the key
    # The two PLCs in the easy run are different vendors, so the wire shows two distinct identities.
    seen = set()
    for entry in scan["identities"]:
        ip = entry["target"]["ip"]
        rows = tshark_fields(result.pcap, f"mbtcp && modbus.func_code==43 && ip.src=={ip} && modbus.object_str_value",
                             ["modbus.object_str_value"])
        seen.add(rows[0][0])
    assert len(seen) == len({e["identity"] for e in scan["identities"]})
