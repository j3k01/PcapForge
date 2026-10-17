"""The IEC 104 command-injection scenario: an unapproved host opens feeder breakers over
IEC 60870-5-104 (select-before-operate). Plan invariants, the recorded commands on the wire, and
the generic 'control command from a host other than the SCADA master' detection."""

import json

import pytest

from pcapforge.pipeline import generate
from pcapforge.plan import build_plan
from pcapforge.scenario import find
from pcapforge.tools import MIN_TSHARK, find_tool, tshark_version
from sigma_eval import hits, load_rules

SCENARIO = "ot-iec104-command-injection"


@pytest.mark.parametrize("difficulty", ["easy", "medium", "hard"])
def test_the_attacker_opens_closed_breakers_from_an_unapproved_host(difficulty):
    plan = build_plan(find(SCENARIO), difficulty, "42")
    inject = plan.facts["inject"]
    master = {h["$host"] for h in plan.facts["scada_104"]["hosts"]}
    assert inject["source"]["$host"] not in master, "the attacker is not the approved SCADA master"
    assert inject["command_count"] >= 1 and len(inject["breakers_opened"]) == inject["command_count"]
    assert all(name.endswith("_cb_close") for name in inject["breakers_opened"])
    # Every commanded breaker was closed before and is driven to 0 (open).
    assert all(c["value"] == 0 and c["action"] == "open" for c in inject["commands"])
    # Select precedes execute for each breaker (select-before-operate).
    for c in inject["commands"]:
        assert c["select"]["$action"].t < c["request"]["$action"].t


capture_tools = (find_tool("tshark") and (find_tool("dumpcap") or find_tool("tcpdump"))
                 and tshark_version() >= MIN_TSHARK)


def jsonl(path):
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh]


@pytest.mark.skipif(not capture_tools, reason="requires tshark >= 4.4 and dumpcap/tcpdump with loopback capture rights")
def test_the_breaker_commands_are_on_the_wire_and_the_rule_flags_only_the_attacker(tmp_path):
    result = generate(find(SCENARIO), "easy", "pytest", tmp_path, duration=360.0, siem=True)
    assert result.report.ok, [c for c in result.report.checks if not c["ok"]]
    inject = json.loads(result.answers.read_text(encoding="utf-8"))["facts"]["inject"]

    control = [r for r in jsonl(result.exports["siem/iec104.jsonl"])
               if r.get("category") == "control" and r["src"] == inject["source"]["ip"]]
    executes = [r for r in control if r.get("select") is False]
    assert len(executes) >= inject["command_count"]
    assert {ioa for r in executes for ioa in r["ioa"]} >= set(inject["ioas"])
    assert all(r["dest"] == inject["target"]["ip"] for r in control)

    # The generic telecontrol control-command rule fires on the attacker and only the attacker.
    rules = load_rules(result.directory / "detections" / "sigma")
    flagged = hits(rules["IEC 104 control command from a host other than the SCADA master"],
                   result.directory / "siem")
    assert flagged, "the control command from the unexpected host is not flagged"
    assert {r["src"] for r in flagged} == {inject["source"]["ip"]}
