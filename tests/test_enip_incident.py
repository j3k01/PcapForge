"""The EtherNet/IP drive-manipulation scenario: an unapproved host seizes a PowerFlex 525 class 1
connection (Forward_Open) and overspeeds the drive over O->T class 1 I/O. Plan invariants, the
recorded Forward_Open on the wire, and the generic 'CIP Forward_Open from an unexpected host'
detection."""

import json

import pytest

from pcapforge.pipeline import generate
from pcapforge.plan import build_plan
from pcapforge.scenario import find
from pcapforge.tools import MIN_TSHARK, find_tool, tshark_version
from sigma_eval import hits, load_rules

SCENARIO = "ot-enip-drive-manipulation"


@pytest.mark.parametrize("difficulty", ["easy", "medium", "hard"])
def test_the_attacker_seizes_the_drive_from_an_unapproved_host(difficulty):
    plan = build_plan(find(SCENARIO), difficulty, "42")
    inject = plan.facts["inject"]
    originators = {h["$host"] for actor in ("hmi_enip", "logix_io")
                   for h in plan.facts[actor]["hosts"]}
    assert inject["source"]["$host"] not in originators, "the attacker is not an approved originator"
    assert inject["target"]["$host"] == "vfd", "the attacker targets the PowerFlex drive adapter"
    assert inject["command_count"] >= 1 and inject["commanded_reference_hz"]
    # The drive is driven to full speed (the normal process band tops out below the maximum).
    assert inject["max_reference_hz"] == inject["normal_max_reference_hz"]
    assert inject["service"] == "forward_open" and inject["service_code"] == 0x54
    # The Forward_Open seizes the connection before the O->T drive packets.
    assert inject["forward_open"]["$action"].t < inject["first_drive"]["$action"].t


capture_tools = (find_tool("tshark") and (find_tool("dumpcap") or find_tool("tcpdump"))
                 and tshark_version() >= MIN_TSHARK)


def jsonl(path):
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh]


@pytest.mark.skipif(not capture_tools, reason="requires tshark >= 4.4 and dumpcap/tcpdump with loopback capture rights")
def test_the_forward_open_is_on_the_wire_and_the_rule_flags_only_the_attacker(tmp_path):
    result = generate(find(SCENARIO), "easy", "pytest", tmp_path, duration=300.0, siem=True)
    assert result.report.ok, [c for c in result.report.checks if not c["ok"]]
    inject = json.loads(result.answers.read_text(encoding="utf-8"))["facts"]["inject"]

    enip = jsonl(result.exports["siem/enip.jsonl"])
    opens = [r for r in enip if r.get("service") == "forward_open" and r.get("response") is False
             and r["src"] == inject["source"]["ip"]]
    assert opens, "the attacker's Forward_Open is not on the wire"
    assert all(r["dest"] == inject["target"]["ip"] for r in opens)
    assert all(r["transport_class"] == inject["transport_class"] for r in opens)

    # The malicious O->T class 1 I/O stream is summarised per connection and minute.
    io = [r for r in enip if r.get("message") == "io_summary" and r["src"] == inject["source"]["ip"]]
    assert io and sum(r["packets"] for r in io) >= 1, "the attacker's O->T I/O stream is missing"
    assert all(r["dest"] == inject["target"]["ip"] for r in io)

    # The generic CIP Forward_Open rule fires on the attacker and only the attacker.
    rules = load_rules(result.directory / "detections" / "sigma")
    flagged = hits(rules["CIP Forward_Open from an unexpected host"], result.directory / "siem")
    assert flagged, "the Forward_Open from the unexpected host is not flagged"
    assert {r["src"] for r in flagged} == {inject["source"]["ip"]}
