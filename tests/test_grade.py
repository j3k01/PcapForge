"""Grading submissions against an answer key, and the student/instructor packages of a run."""

import json
import zipfile

import pytest
import yaml

from pcapforge.cli import main
from pcapforge.grade import Submission, grade_submission, load_submissions, score_fraction
from pcapforge.package import package_run

ANSWERS = {
    "scenario": {"id": "demo", "title": "Demo", "difficulty": "easy", "seed": "42"},
    "capture": {"file": "capture.pcap"},
    "questions": [
        {"id": "source_ip", "text": "Writer IP?", "type": "ip", "answer": "10.241.35.164", "points": 10},
        {"id": "source_mac", "text": "Writer MAC?", "type": "mac", "answer": "b8:27:eb:23:26:6d", "points": 5},
        {"id": "first_write", "text": "First write (UTC)?", "type": "timestamp",
         "answer": "2025-03-22T11:45:36.016219Z", "tolerance_s": 1, "points": 10},
        {"id": "points_changed", "text": "Changed points?", "type": "set",
         "answer": ["pid_level_ti", "level_high_alarm", "level_low_alarm", "chlorine_dose_sp"], "points": 15},
        {"id": "values_written", "text": "Written values?", "type": "map",
         "answer": {"pid_level_ti": 1587.0, "level_high_alarm": 635.0, "level_low_alarm": 356.0,
                    "chlorine_dose_sp": 8.36}, "points": 16},
        {"id": "functions_used", "text": "Function codes?", "type": "set", "answer": [6], "points": 5},
        {"id": "writes", "text": "Legitimate writes?", "type": "number", "answer": 6, "points": 10},
        {"id": "duration", "text": "Burst length (s)?", "type": "number", "answer": 12.5, "tolerance": 0.5,
         "points": 5},
        {"id": "technique", "text": "Technique?", "type": "text", "answer": "T0836",
         "accept": ["T0836", "Modify Parameter"], "points": 5},
    ],
}
Q = {q["id"]: q for q in ANSWERS["questions"]}
CORRECT = {
    "source_ip": "10.241.35.164", "source_mac": "b8:27:eb:23:26:6d", "first_write": "2025-03-22T11:45:36.016219Z",
    "points_changed": ["pid_level_ti", "level_high_alarm", "level_low_alarm", "chlorine_dose_sp"],
    "values_written": {"pid_level_ti": 1587, "level_high_alarm": 635, "level_low_alarm": 356, "chlorine_dose_sp": 8.36},
    "functions_used": [6], "writes": 6, "duration": 12.5, "technique": "T0836",
}


def score(qid, given):
    return score_fraction(Q[qid], given)


@pytest.mark.parametrize("given", ["10.241.35.164", " 10.241.35.164 ", "10.241.035.164"])
def test_ip_answers_are_normalised(given):
    assert score("source_ip", given) == 1


@pytest.mark.parametrize("given", ["B8-27-EB-23-26-6D", "b827.eb23.266d", "b8 27 eb 23 26 6d", "B827EB23266D"])
def test_mac_answers_ignore_case_and_separators(given):
    assert score("source_mac", given) == 1


@pytest.mark.parametrize("qid,given", [
    ("source_ip", "10.241.35.159"), ("source_ip", "10.241.35"), ("source_mac", "b8:27:eb:23:26:6e"),
    ("source_mac", "b8:27:eb:23:26"), ("writes", 7), ("writes", "six"), ("technique", "T0855"),
    ("first_write", "yesterday"),
])
def test_wrong_answers_score_zero(qid, given):
    assert score(qid, given) == 0


@pytest.mark.parametrize("given,expected", [
    ("2025-03-22T11:45:37.016219Z", 1),          # exactly at tolerance_s
    ("2025-03-22T11:45:35.016219Z", 1),
    ("2025-03-22T11:45:37.016220Z", 0),          # 1 µs beyond
    ("2025-03-22 11:45:36", 1),                  # space separator, naive = UTC
    ("2025-03-22T11:45:36.016219000Z", 1),       # tshark's nanosecond digits
    ("2025-03-22T12:45:36.0162+01:00", 1),       # offset honoured
    ("2025-03-22T11:45:36.0162+01:00", 0),       # same wall clock, one hour off
])
def test_timestamp_tolerance_and_formats(given, expected):
    assert score("first_write", given) == expected


@pytest.mark.parametrize("qid,given,expected", [
    ("writes", 6, 1), ("writes", "6.0", 1), ("writes", 5, 0),
    ("duration", 12.0, 1), ("duration", "13", 1), ("duration", 13.01, 0), ("duration", 11.99, 0),
])
def test_numbers_exact_or_within_tolerance(qid, given, expected):
    assert score(qid, given) == expected


def test_sets_are_order_and_case_free_with_jaccard_partial_credit():
    assert score("points_changed", ["Chlorine_Dose_SP", "level_low_alarm", "LEVEL_HIGH_ALARM", "pid_level_ti"]) == 1
    assert score("points_changed", "pid_level_ti, level_high_alarm") == pytest.approx(2 / 4)
    # 3 right, 1 missing, 1 extra: |∩| / |∪| = 3 / 5
    assert score("points_changed", ["pid_level_ti", "level_high_alarm", "level_low_alarm", "level_high"]) == \
        pytest.approx(3 / 5)
    assert score("functions_used", ["6", "16"]) == pytest.approx(1 / 2)


def test_maps_score_per_key_with_relative_tolerance():
    exact = dict(CORRECT["values_written"])
    assert score("values_written", exact) == 1
    within = {**exact, "pid_level_ti": 1587 * 1.0049}        # inside the 0.5 % band
    assert score("values_written", within) == 1
    beyond = {**exact, "chlorine_dose_sp": 8.36 * 1.0051}
    assert score("values_written", beyond) == pytest.approx(3 / 4)
    assert score("values_written", "pid_level_ti=1587; Level_High_Alarm: 635") == pytest.approx(2 / 4)
    assert score("values_written", {**exact, "level_high": 1.0}) == pytest.approx(4 / 5)  # extra key


def test_text_accepts_alternatives_ignoring_case_and_whitespace():
    assert score("technique", "  modify   PARAMETER ") == 1
    assert score("technique", "t0836") == 1


def test_full_and_partial_submission_totals_and_unknown_ids():
    full = grade_submission(ANSWERS, Submission("ann", None, dict(CORRECT)))
    assert full["score"] == full["max"] == 81
    assert {q["result"] for q in full["questions"]} == {"correct"}

    partial = dict(CORRECT, source_mac="00:00:00:00:00:00", points_changed=["pid_level_ti", "level_high_alarm"],
                   bogus=1, writes=None)
    report = grade_submission(ANSWERS, Submission("ben", None, partial))
    results = {q["id"]: q for q in report["questions"]}
    assert results["source_mac"]["score"] == 0 and results["source_mac"]["result"] == "wrong"
    assert results["writes"]["result"] == "blank"
    assert results["points_changed"]["score"] == 7.5 and results["points_changed"]["result"] == "partial"
    assert report["score"] == 81 - 5 - 7.5 - 10
    assert report["unknown_questions"] == ["bogus"]


def test_yaml_submission_keeps_unquoted_macs_times_and_words_as_text(tmp_path):
    path = tmp_path / "jane.yaml"
    # YAML 1.1 would read 10:20:30:40:50:59 as a base-60 integer, "no" as False and the time as datetime.
    path.write_text("source_mac: 10:20:30:40:50:59\ntechnique: no\nfirst_write: 2025-03-22 11:45:36\n"
                    "points_changed: [pid_level_ti]\nwrites:\n", encoding="utf-8")
    [sub] = load_submissions([path])
    assert sub.student == "jane"
    assert sub.answers == {"source_mac": "10:20:30:40:50:59", "technique": "no",
                           "first_write": "2025-03-22 11:45:36", "points_changed": ["pid_level_ti"], "writes": None}


def test_class_csv_with_repeated_rows_and_cli_json_report(tmp_path, capsys):
    answers = tmp_path / "answers.json"
    answers.write_text(json.dumps(ANSWERS), encoding="utf-8")
    csv_path = tmp_path / "class.csv"
    csv_path.write_text(
        "\ufeffStudent,Question,Answer\n"
        "amy,source_ip,10.241.35.164\n"
        "amy,points_changed,pid_level_ti\namy,points_changed,level_high_alarm\n"
        "amy,points_changed,level_low_alarm\namy,points_changed,chlorine_dose_sp\n"
        "bo,source_ip,10.241.35.1\nbo,nonsense,x\n"
        'cy,values_written,"pid_level_ti=1587, level_high_alarm=635"\n', encoding="utf-8")
    assert main(["grade", str(answers), str(csv_path), "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    scores = {s["student"]: s["score"] for s in report["students"]}
    assert scores == {"amy": 25, "bo": 0, "cy": 8}
    assert {s["student"]: s["unknown_questions"] for s in report["students"]}["bo"] == ["nonsense"]


@pytest.fixture
def run_dir(tmp_path):
    run = tmp_path / "demo_easy_42"
    (run / "siem").mkdir(parents=True)
    (run / "detections").mkdir()
    (run / "answers.json").write_text(json.dumps(ANSWERS), encoding="utf-8")
    (run / "capture.pcap").write_bytes(b"\xd4\xc3\xb2\xa1fake")
    (run / "briefing.md").write_text("# Demo\n\n1. **[source_ip]** Writer IP?\n", encoding="utf-8")
    (run / "siem" / "modbus.jsonl").write_text('{"src": "10.241.35.164"}\n', encoding="utf-8")
    (run / "detections" / "hunting.md").write_text("answer: 10.241.35.164\n", encoding="utf-8")
    return run


def test_student_package_holds_no_answer_material(run_dir, tmp_path):
    student, instructor = package_run(run_dir, tmp_path / "dist")
    assert student.name == "demo_easy_42-student.zip" and instructor.name == "demo_easy_42-instructor.zip"
    with zipfile.ZipFile(student) as zf:
        names = set(zf.namelist())
        assert names == {"demo_easy_42/capture.pcap", "demo_easy_42/briefing.md",
                         "demo_easy_42/submission_template.yaml"}
        content = b"".join(zf.read(n) for n in names)
        template = yaml.safe_load(zf.read("demo_easy_42/submission_template.yaml"))
    for secret in (b"10.241.35.164", b"b8:27:eb:23:26:6d", b"11:45:36", b"pid_level_ti", b"T0836", b"1587"):
        assert secret not in content
    assert template == {q["id"]: None for q in ANSWERS["questions"]}
    with zipfile.ZipFile(instructor) as zf:
        assert {"demo_easy_42/answers.json", "demo_easy_42/siem/modbus.jsonl",
                "demo_easy_42/detections/hunting.md", "demo_easy_42/submission_template.yaml"} <= set(zf.namelist())
