import copy

import pytest

from pcapforge.process import ProcessProfile
from pcapforge.plan import build_plan
from pcapforge.scenario import ScenarioError, evaluate_when, find, parse_duration, resolve, validate

SCENARIO = "ot-modbus-write-manipulation"


@pytest.fixture(scope="module")
def scenario():
    return find(SCENARIO)


def test_references_keep_type_when_whole_string_and_interpolate_otherwise():
    ctx = {"vars": {"n": 3, "flag": True}, "facts": {"w": [{"a": 7}]}}
    assert resolve("${vars.n}", ctx) == 3
    assert resolve("${facts.w[0].a}", ctx) == 7
    assert resolve("n=${vars.n} f=${vars.flag}", ctx) == "n=3 f=true"
    with pytest.raises(ScenarioError, match="unresolved reference"):
        resolve("${vars.missing}", ctx)


@pytest.mark.parametrize("expr, expected", [
    ("vars.flag", True), ("not vars.flag", False), ("vars.host == 'ews'", True),
    ("vars.host != 'ews'", False), ("vars.absent", False), (None, True),
])
def test_conditions(expr, expected):
    assert evaluate_when(expr, {"vars": {"flag": 1, "host": "ews"}}) is expected


@pytest.mark.parametrize("text, seconds", [(90, 90), ("90s", 90), ("15m", 900), ("2h", 7200), ("1.5h", 5400)])
def test_durations(text, seconds):
    assert parse_duration(text) == seconds


def test_schema_rejects_unknown_keys_and_dangling_hosts(scenario):
    doc = copy.deepcopy(scenario.doc)
    doc["actors"][0]["on"] = "plc"
    with pytest.raises(ScenarioError, match="Additional properties"):
        validate(doc)
    doc = copy.deepcopy(scenario.doc)
    doc["actors"][0]["hosts"] = "nonexistent"
    with pytest.raises(ScenarioError, match="unknown host"):
        validate(doc)


def test_same_seed_same_plan_different_seed_different_variant(scenario):
    a = build_plan(scenario, "medium", "student-1", duration_override=900)
    b = build_plan(scenario, "medium", "student-1", duration_override=900)
    c = build_plan(scenario, "medium", "student-2", duration_override=900)
    assert a.digest() == b.digest()
    assert a.digest() != c.digest()
    assert a.facts["change"]["values"] == b.facts["change"]["values"]


def test_base_seed_shares_recording_between_students(scenario):
    a = build_plan(scenario, "easy", "alice", base_seed="class-a", duration_override=600)
    b = build_plan(scenario, "easy", "bob", base_seed="class-a", duration_override=600)
    assert a.digest() == b.digest()


@pytest.mark.parametrize("difficulty", ["easy", "medium", "hard"])
def test_incident_writes_leave_normal_band_and_operator_writes_stay_inside(scenario, difficulty):
    plan = build_plan(scenario, difficulty, "band-check", duration_override=1800)
    profile = ProcessProfile(plan.vars["process"])
    for write in plan.facts["change"]["writes"]:
        lo, hi = write["normal"]
        assert not lo <= write["value"] <= hi, write
    for write in plan.facts.get("operator_changes", {}).get("writes", []):
        lo, hi = profile.by_name[write["point"]].normal
        assert lo <= write["value"] <= hi, write


def test_per_seed_structure_varies_on_medium_but_easy_stays_fixed(scenario):
    medium = [build_plan(scenario, "medium", str(seed), duration_override=300) for seed in range(30)]
    processes = {plan.vars["process"] for plan in medium}
    assert processes == {"water_treatment", "wastewater_treatment", "hvac_building", "power_substation"}
    assert {plan.vars["plc_count"] for plan in medium} <= {2, 3, 4}
    assert all(len(plan.topology.groups["plc"]) == plan.vars["plc_count"] for plan in medium)
    again = build_plan(scenario, "medium", "7", duration_override=300)
    assert again.vars == medium[7].vars and again.digest() == medium[7].digest()
    easy = {build_plan(scenario, "easy", str(seed), duration_override=300).vars["process"] for seed in range(5)}
    assert easy == {"water_treatment"}


def test_threshold_direction_matches_the_alarm_it_defeats(scenario):
    seen = set()
    for seed in range(40):
        plan = build_plan(scenario, "medium", str(seed), duration_override=300)
        for write in plan.facts["change"]["writes"]:
            lo, hi = write["normal"]
            words = set(write["point"].split("_"))
            if "low" in words:
                assert write["direction"] == "below" and write["value"] < lo, write
            if "high" in words:
                assert write["direction"] == "above" and write["value"] > hi, write
            seen.add(write["direction"])
    assert seen == {"above", "below"}


def test_polish_translation_covers_every_question_and_keeps_answers(scenario):
    from pcapforge.grade import submission_template
    from pcapforge.i18n import localize_answers

    pl = scenario.doc["translations"]["pl"]["questions"]
    ids = [q["id"] for q in scenario.doc["questions"]]
    assert set(pl) == set(ids)
    answers = {"scenario": {"title": scenario.title, "id": scenario.id},
               "questions": [{"id": q, "text": "x", "answer": f"a-{q}", "points": 1, "type": "ip"} for q in ids]}
    localized = localize_answers(answers, scenario.doc, "pl", {"vars": {}, "facts": {}})
    assert [q["answer"] for q in localized["questions"]] == [q["answer"] for q in answers["questions"]]
    assert localized["questions"][0]["text"] == pl[ids[0]]["text"]
    template = submission_template(localized)
    assert "adres IP" in template and "jan-kowalski.yaml" in template


def test_recording_key_changes_when_only_the_site_naming_changes(scenario):
    plan = build_plan(scenario, "easy", "names", duration_override=120)
    before = plan.digest()
    plan.topology.site_code = "zz"
    for host in plan.topology.hosts:
        host.name = host.name + "x"
    assert plan.digest() != before


@pytest.mark.parametrize("difficulty", ["easy", "medium", "hard"])
@pytest.mark.parametrize("duration", [120, 600, None])
def test_every_incident_write_happens_inside_the_capture(scenario, difficulty, duration):
    plan = build_plan(scenario, difficulty, "inside", duration_override=duration)
    times = [w["request"]["$action"].t for w in plan.facts["change"]["writes"]]
    assert times and max(times) < plan.duration
