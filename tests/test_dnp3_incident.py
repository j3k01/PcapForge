"""The DNP3 control-injection scenario: an unapproved host latches running actuators off over
DNP3 (IEEE 1815, select-before-operate). Plan invariants, the recorded commands on the wire, and
the generic 'control / write / restart from a host other than the master' detection."""

import json

import pytest

from pcapforge.pipeline import generate
from pcapforge.plan import build_plan
from pcapforge.scenario import find
from pcapforge.tools import MIN_TSHARK, find_tool, tshark_version
from sigma_eval import hits, load_rules

SCENARIO = "ot-dnp3-control-injection"


@pytest.mark.parametrize("difficulty", ["easy", "medium", "hard"])
def test_the_attacker_stops_running_actuators_from_an_unapproved_host(difficulty):
    plan = build_plan(find(SCENARIO), difficulty, "42")
    inject = plan.facts["inject"]
    master = {h["$host"] for h in plan.facts["scada_dnp3"]["hosts"]}
    assert inject["source"]["$host"] not in master, "the attacker is not the approved DNP3 master"
    # The attacker uses its own master link address, not the control room's.
    assert inject["master_address"] != plan.facts["scada_dnp3"]["sessions"][0]["master_address"]
    assert inject["command_count"] >= 1 and len(inject["point_names"]) == inject["command_count"]
    assert all(c["op"] == "latch_off" and c["value"] == 0 and c["action"] == "stop"
               for c in inject["commands"])
    # Select precedes operate for each point (select-before-operate).
    for c in inject["commands"]:
        assert c["select"]["$action"].t < c["request"]["$action"].t


capture_tools = (find_tool("tshark") and (find_tool("dumpcap") or find_tool("tcpdump"))
                 and tshark_version() >= MIN_TSHARK)


def jsonl(path):
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh]


@pytest.mark.skipif(not capture_tools, reason="requires tshark >= 4.4 and dumpcap/tcpdump with loopback capture rights")
def test_the_control_commands_are_on_the_wire_and_the_rule_flags_only_the_attacker(tmp_path):
    result = generate(find(SCENARIO), "easy", "pytest", tmp_path, duration=360.0, siem=True)
    assert result.report.ok, [c for c in result.report.checks if not c["ok"]]
    inject = json.loads(result.answers.read_text(encoding="utf-8"))["facts"]["inject"]

    control = [r for r in jsonl(result.exports["siem/dnp3.jsonl"])
               if r.get("function_code") in (3, 4, 5) and r["src"] == inject["source"]["ip"]]
    operates = [r for r in control if r["function_code"] == 4]
    assert len(operates) >= inject["command_count"]
    assert {c["index"] for r in operates for c in r["controls"]} >= set(inject["indices"])
    assert all(r["dest"] == inject["target"]["ip"] for r in control)

    # The generic DNP3 control-command rule fires on the attacker and only the attacker.
    rules = load_rules(result.directory / "detections" / "sigma")
    flagged = hits(rules["DNP3 control, write or restart from a host other than the master"],
                   result.directory / "siem")
    assert flagged, "the control command from the unexpected host is not flagged"
    assert {r["src"] for r in flagged} == {inject["source"]["ip"]}
