"""The coil-manipulation scenario: unauthorized Modbus coil commands force actuator state
(function 5 / 15), and on medium/hard an alarm is acknowledged to suppress it."""

import json

import pytest

from pcapforge.pipeline import generate
from pcapforge.plan import build_plan
from pcapforge.scenario import find
from pcapforge.tools import MIN_TSHARK, find_tool, tshark_version

SCENARIO = "ot-modbus-coil-manipulation"


@pytest.mark.parametrize("difficulty", ["easy", "medium", "hard"])
def test_the_force_writes_only_coils_and_flips_them_from_nominal(difficulty):
    plan = build_plan(find(SCENARIO), difficulty, "42")
    force = plan.facts["force"]
    assert force["write_count"] >= 1
    assert all(w["table"] == "coils" and w["function"] in (5, 15) for w in force["writes"])
    for w in force["writes"]:
        assert w["to"] != w["from"], "a forced coil moves away from its normal state"
    assert set(force["function_codes"]) <= {5, 15}
    level = find(SCENARIO).level(difficulty)["vars"]
    assert force["alarm_acknowledged"] == bool(level["ack"])


capture_tools = (find_tool("tshark") and (find_tool("dumpcap") or find_tool("tcpdump"))
                 and tshark_version() >= MIN_TSHARK)


def jsonl(path):
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh]


@pytest.mark.skipif(not capture_tools, reason="requires tshark >= 4.4 and dumpcap/tcpdump with loopback capture rights")
def test_coil_commands_are_on_the_wire_and_acknowledge_the_alarm_on_medium(tmp_path):
    result = generate(find(SCENARIO), "medium", "pytest", tmp_path, duration=480.0, siem=True)
    assert result.report.ok, [c for c in result.report.checks if not c["ok"]]
    answers = json.loads(result.answers.read_text(encoding="utf-8"))
    force = answers["facts"]["force"]
    source, target = force["source"]["ip"], force["target"]["ip"]

    coil_writes = [r for r in jsonl(result.exports["siem/modbus.jsonl"])
                   if r["src"] == source and r["function_code"] in (5, 15) and r.get("write")]
    # Every forced actuator coil shows up (the alarm ack is an extra coil write on top).
    assert len({r["point"] for r in coil_writes} - {"alarm_ack", "alarm_reset"}) >= len(force["writes"])
    assert all(r["dest"] == target for r in coil_writes)

    # The source never touches holding registers here - it commands coils only.
    assert not [r for r in jsonl(result.exports["siem/modbus.jsonl"])
                if r["src"] == source and r["function_code"] in (6, 16)]

    # medium acknowledges the alarm: a write to alarm_ack / alarm_reset from the same source.
    assert force["alarm_acknowledged"]
    assert any(r["point"] in ("alarm_ack", "alarm_reset") for r in coil_writes)
