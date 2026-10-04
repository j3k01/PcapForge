import json
import re

import yaml

from pcapforge.ctfd import export_ctfd, flags_for


def matches(flags, given):
    for flag in flags:
        if flag["type"] == "static" and flag["content"].lower() == given.strip().lower():
            return True
        if flag["type"] == "regex" and re.match(flag["content"], given, re.IGNORECASE):
            return True
    return False


def test_mac_flag_accepts_any_case_and_separator_but_not_another_mac():
    flags = flags_for({"type": "mac", "answer": "00:09:0f:6a:37:6b"})
    for given in ("00:09:0f:6a:37:6b", "00-09-0F-6A-37-6B", "00090f6a376b"):
        assert matches(flags, given), given
    assert not matches(flags, "00:09:0f:6a:37:6c")


def test_timestamp_flag_matches_the_same_second_only():
    flags = flags_for({"type": "timestamp", "answer": "2025-02-04T11:16:12.358811Z"})
    assert matches(flags, "2025-02-04T11:16:12Z")
    assert matches(flags, "2025-02-04 11:16:12.3")
    assert not matches(flags, "2025-02-04T11:16:13Z")


def test_set_and_map_flags_use_a_canonical_sorted_form():
    assert matches(flags_for({"type": "set", "answer": ["ph_sp", "chlorine_dose_sp"]}), "chlorine_dose_sp,ph_sp")
    flags = flags_for({"type": "map", "answer": {"b": 3.0, "a": 3.72}})
    assert matches(flags, "a=3.72,b=3")


def test_export_writes_one_challenge_per_question_without_leaking_answers(tmp_path):
    run = tmp_path / "run"
    run.mkdir()
    (run / "capture.pcap").write_bytes(b"\xd4\xc3\xb2\xa1")
    (run / "briefing.md").write_text("# brief", encoding="utf-8")
    answers = {
        "scenario": {"id": "demo", "seed": "1", "title": "Demo", "difficulty": "easy", "line": "ot"},
        "questions": [
            {"id": "src", "text": "Which IP?", "type": "ip", "answer": "10.0.0.5", "points": 10, "hint": "look"},
            {"id": "n", "text": "How many?", "type": "number", "answer": 3, "points": 5},
        ],
    }
    (run / "answers.json").write_text(json.dumps(answers), encoding="utf-8")
    paths = export_ctfd(run)
    assert len(paths) == 2
    first, second = (yaml.safe_load(p.read_text(encoding="utf-8")) for p in paths)
    assert first["files"] == ["files/capture.pcap", "files/briefing.md"]
    assert (paths[0].parent / "files" / "capture.pcap").is_file()
    assert second["requirements"] == [first["name"]] and "files" not in second
    assert "10.0.0.5" not in first["description"] and first["flags"][0]["content"] == "10.0.0.5"
    assert first["hints"][0]["cost"] == 2
