"""The alarm-masking scenario: an unapproved host moves an alarm threshold out of band first,
then pushes the setpoint it guarded out of band - so the harmful change raises no alarm."""

import json

import pytest

from pcapforge.pipeline import generate
from pcapforge.plan import build_plan
from pcapforge.scenario import find
from pcapforge.tools import MIN_TSHARK, find_tool, tshark_version
from sigma_eval import hits, load_rules

SCENARIO = "ot-modbus-alarm-masking"


@pytest.mark.parametrize("difficulty", ["easy", "medium", "hard"])
def test_the_mask_precedes_the_setpoint_change_and_targets_an_alarm_threshold(difficulty):
    plan = build_plan(find(SCENARIO), difficulty, "42")
    mask = plan.facts["mask"]
    assert mask["masked_alarms"] and all(a.endswith("_alarm") for a in mask["masked_alarms"])
    assert mask["changed_setpoint"] not in mask["masked_alarms"]
    assert not mask["changed_setpoint"].endswith("_alarm")
    mask_times = [w["request"]["$action"].t for w in mask["writes"] if w["stage"] == "mask"]
    change_time = mask["change_write"]["$action"].t
    assert max(mask_times) < change_time, "the threshold is blinded before the harmful change"
    # Each masked threshold actually guards an alarm discrete.
    assert any(w.get("guards_alarm") for w in mask["writes"] if w["stage"] == "mask")


capture_tools = (find_tool("tshark") and (find_tool("dumpcap") or find_tool("tcpdump"))
                 and tshark_version() >= MIN_TSHARK)


def jsonl(path):
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh]


@pytest.mark.skipif(not capture_tools, reason="requires tshark >= 4.4 and dumpcap/tcpdump with loopback capture rights")
def test_the_source_writes_the_threshold_before_the_setpoint_on_the_wire(tmp_path):
    result = generate(find(SCENARIO), "easy", "pytest", tmp_path, duration=360.0, siem=True)
    assert result.report.ok, [c for c in result.report.checks if not c["ok"]]
    answers = json.loads(result.answers.read_text(encoding="utf-8"))
    mask = answers["facts"]["mask"]

    writes = sorted((r for r in jsonl(result.exports["siem/modbus.jsonl"])
                     if r["src"] == mask["source"]["ip"] and r.get("write")), key=lambda r: r["epoch"])
    assert len(writes) >= 2
    # The first write from the source is an alarm threshold; a later one is the governed setpoint.
    assert writes[0]["point"] in mask["masked_alarms"]
    assert writes[0]["point"].endswith("_alarm")
    assert any(w["point"] == mask["changed_setpoint"] and w["epoch"] > writes[0]["epoch"] for w in writes)
    assert mask["changed_setpoint"] not in {a for a in mask["masked_alarms"]}

    # The Sigma alarm-threshold rule flags exactly the masking writes (the setpoint change is caught
    # by the general out-of-band rule).
    rules = load_rules(result.directory / "detections" / "sigma")
    flagged = hits(rules["Alarm threshold written outside its normal band"], result.directory / "siem")
    assert sorted(r["point"] for r in flagged) == sorted(mask["masked_alarms"])
    assert {r["src"] for r in flagged} == {mask["source"]["ip"]}
