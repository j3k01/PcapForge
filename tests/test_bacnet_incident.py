"""The BACnet unauthorized-write scenario: an unapproved host overrides commandable setpoints out
of their normal band over BACnet/IP (WriteProperty). Plan invariants, the recorded writes on the
wire, and the generic 'write or device control from an unapproved host' detection."""

import json

import pytest

from pcapforge.pipeline import generate
from pcapforge.plan import build_plan
from pcapforge.scenario import find
from pcapforge.tools import MIN_TSHARK, find_tool, tshark_version
from sigma_eval import hits, load_rules

SCENARIO = "ot-bacnet-unauthorized-write"


@pytest.mark.parametrize("difficulty", ["easy", "medium", "hard"])
def test_the_attacker_overrides_setpoints_from_an_unapproved_host(difficulty):
    plan = build_plan(find(SCENARIO), difficulty, "42")
    inject = plan.facts["inject"]
    approved = {h["$host"] for h in plan.facts["bms_bacnet"]["hosts"]}
    assert inject["source"]["$host"] not in approved, "the attacker is not the approved BMS workstation"
    assert inject["command_count"] >= 1
    assert len(inject["overridden_points"]) == inject["command_count"]
    assert len(inject["instances"]) == inject["command_count"]
    assert all(name.endswith("_sp") for name in inject["overridden_points"])
    # Every command is at the high priority and drives the setpoint above its normal band.
    assert 1 <= inject["priority"] <= 16 and inject["priority"] != 6
    for c in inject["commands"]:
        assert c["priority"] == inject["priority"]
        assert c["object"]["type"] == "analog-value"
        assert c["value"] > c["normal"][1], "the written value lies outside the normal band"


capture_tools = (find_tool("tshark") and (find_tool("dumpcap") or find_tool("tcpdump"))
                 and tshark_version() >= MIN_TSHARK)


def jsonl(path):
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh]


@pytest.mark.skipif(not capture_tools, reason="requires tshark >= 4.4 and dumpcap/tcpdump with loopback capture rights")
def test_the_writes_are_on_the_wire_and_the_rule_flags_only_the_attacker(tmp_path):
    result = generate(find(SCENARIO), "easy", "pytest", tmp_path, duration=360.0, siem=True)
    assert result.report.ok, [c for c in result.report.checks if not c["ok"]]
    inject = json.loads(result.answers.read_text(encoding="utf-8"))["facts"]["inject"]

    writes = [r for r in jsonl(result.exports["siem/bacnet.jsonl"])
              if r.get("apdu_type") == "confirmed_request" and r.get("service") == "write_property"
              and r["src"] == inject["source"]["ip"]]
    assert len(writes) >= inject["command_count"]
    assert {r["instance"] for r in writes} >= set(inject["instances"])
    assert all(r["dest"] == inject["target"]["ip"] for r in writes)
    assert all(r.get("object_type") == "analog-value" for r in writes)

    # The generic BACnet write / device-control rule fires on the attacker and only the attacker.
    rules = load_rules(result.directory / "detections" / "sigma")
    flagged = hits(rules["BACnet write or device control from an unapproved host"],
                   result.directory / "siem")
    assert flagged, "the write from the unapproved host is not flagged"
    assert {r["src"] for r in flagged} == {inject["source"]["ip"]}
