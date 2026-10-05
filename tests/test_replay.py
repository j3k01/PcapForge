"""The command-replay scenario: an unapproved host re-sends the operator's writes verbatim,
so the written values stay inside the normal band and only the source and timing betray them."""

import json

import pytest

from pcapforge.pipeline import generate
from pcapforge.plan import build_plan
from pcapforge.scenario import find
from pcapforge.tools import MIN_TSHARK, find_tool, tshark_version

SCENARIO = "ot-modbus-command-replay"


@pytest.mark.parametrize("difficulty", ["easy", "medium", "hard"])
def test_every_replayed_write_is_an_exact_copy_of_an_operator_write(difficulty):
    plan = build_plan(find(SCENARIO), difficulty, "42")
    operator = {(w["point"], w["address"], w["raw"], w["function"], w["target"]["$host"])
                for w in plan.facts["operator_changes"]["writes"]}
    replay = plan.facts["replay"]
    assert replay["write_count"] >= 1
    assert replay["source"]["$host"] != plan.facts["operator_changes"]["source"]["$host"]
    for w in replay["writes"]:
        key = (w["point"], w["address"], w["raw"], w["function"], w["target"]["$host"])
        assert key in operator, f"replayed write {key} is not a copy of any operator write"


capture_tools = (find_tool("tshark") and (find_tool("dumpcap") or find_tool("tcpdump"))
                 and tshark_version() >= MIN_TSHARK)


def jsonl(path):
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh]


@pytest.mark.skipif(not capture_tools, reason="requires tshark >= 4.4 and dumpcap/tcpdump with loopback capture rights")
def test_replayed_writes_are_in_band_and_echo_an_earlier_operator_write(tmp_path):
    result = generate(find(SCENARIO), "easy", "pytest", tmp_path, duration=360.0, siem=True)
    assert result.report.ok, [c for c in result.report.checks if not c["ok"]]
    answers = json.loads(result.answers.read_text(encoding="utf-8"))
    replay = answers["facts"]["replay"]
    operator = answers["facts"]["operator_changes"]

    rows = [r for r in jsonl(result.exports["siem/modbus.jsonl"]) if r.get("write")]
    replayed = [r for r in rows if r["src"] == replay["source"]["ip"]]
    assert len(replayed) == replay["write_count"]
    # The point of the scenario: every replayed value is inside the normal band.
    assert all(r["in_normal_band"] is True for r in replayed)

    # Each replayed (point, value) was written earlier by the legitimate operator.
    operator_writes = {(r["src"], r["point"], tuple(r["values"])) for r in rows if r["src"] == operator["source"]["ip"]}
    for r in replayed:
        assert (operator["source"]["ip"], r["point"], tuple(r["values"])) in operator_writes
        first_operator = min(x["epoch"] for x in rows
                             if x["src"] == operator["source"]["ip"] and x["point"] == r["point"]
                             and tuple(x["values"]) == tuple(r["values"]))
        assert r["epoch"] > first_operator, "the replay comes after the genuine change it copies"
