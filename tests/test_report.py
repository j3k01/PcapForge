"""The HTML debrief (`pcapforge report`) built from a real run, and the Modbus read values in
the SIEM export it charts.

Needs Wireshark (tshark + dumpcap) and loopback capture rights; skipped otherwise.
"""

import html
import json
import re
import shutil
import xml.etree.ElementTree as ET

import pytest
import yaml

from pcapforge.cli import main
from pcapforge.grade import grade, load_submissions
from pcapforge.pipeline import generate
from pcapforge.process import FUNCTION_TABLE
from pcapforge.report import downsample
from pcapforge.scenario import find
from pcapforge.tools import MIN_TSHARK, find_tool, tshark_version

SCENARIO = "ot-modbus-write-manipulation"
SVG = re.compile(r"<svg\b.*?</svg>", re.S)

capture_tools = pytest.mark.skipif(
    not find_tool("tshark") or not (find_tool("dumpcap") or find_tool("tcpdump"))
    or tshark_version() < MIN_TSHARK,
    reason="requires tshark >= 4.4 and dumpcap/tcpdump with loopback capture rights",
)


@pytest.fixture(scope="module")
def run(tmp_path_factory):
    out = tmp_path_factory.mktemp("report")
    result = generate(find(SCENARIO), "easy", "pytest-report", out, duration=300.0, siem=True)
    answers = json.loads(result.answers.read_text(encoding="utf-8"))
    return result.directory, answers


def report(run_dir, tmp_path, *extra):
    out = tmp_path / "report.html"
    assert main(["report", str(run_dir), "--out", str(out), *extra]) == 0
    return out.read_text(encoding="utf-8")


def rows(text, table_class):
    table = re.search(rf'<table class="{table_class}">(.*?)</table>', text, re.S).group(1)
    return re.findall(r"<tr[^>]*>(.*?)</tr>", table, re.S)


@capture_tools
def test_timeline_lists_every_event_with_its_frame_and_kind(run, tmp_path):
    run_dir, answers = run
    text = report(run_dir, tmp_path)
    timeline = [r for r in rows(text, "timeline") if "<td" in r]
    assert any(e["incident"] for e in answers["timeline"])
    assert len(timeline) == len(answers["timeline"])
    for event, row in zip(answers["timeline"], timeline):
        assert html.escape(event["title"]) in row
        assert f'<td class="num">{event["frame"]}</td>' in row
        assert ("incident" if event["incident"] else "legitimate") in row
        for technique in event["techniques"]:
            assert technique in row


@capture_tools
def test_every_written_point_is_charted_as_well_formed_svg_without_external_resources(run, tmp_path):
    run_dir, answers = run
    text = report(run_dir, tmp_path)
    svgs = SVG.findall(text)
    titles = []
    for svg in svgs:
        root = ET.fromstring(svg)  # raises on malformed XML
        assert root.tag == "{http://www.w3.org/2000/svg}svg"
        titles.append(root.findtext("{http://www.w3.org/2000/svg}title"))
    written = {w["point"] for fact in answers["facts"].values() if isinstance(fact, dict)
               for w in fact.get("writes", [])}
    assert written
    for point in written:
        setpoint = [t for t in titles if t.startswith(f"{point} ") and t.endswith("written setpoint")]
        assert len(setpoint) >= 1, f"no chart for {point}"
    # Self-contained: the only URL is the SVG namespace; nothing is loaded from elsewhere.
    assert set(re.findall(r"[a-z]+://[^\s\"'<>)]+", text)) == {"http://www.w3.org/2000/svg"}
    tags = re.findall(r"<[a-zA-Z][^>]*>", text)
    assert not [t for t in tags if re.search(r"\s(src|href|srcset|data)\s*=", t)]
    style = re.search(r"<style>(.*?)</style>", text, re.S).group(1)
    assert "@import" not in style and "url(" not in style


@capture_tools
def test_change_headings_name_the_register_description(run, tmp_path):
    from pcapforge.process import ProcessProfile

    run_dir, answers = run
    text = report(run_dir, tmp_path)
    process = answers["facts"]["plc_service"]["process"]
    profile = ProcessProfile(process)
    changed = {w["point"] for fact in answers["facts"].values() if isinstance(fact, dict)
               for w in fact.get("writes", [])}
    assert changed
    for name in changed:
        desc = profile.by_name[name].desc
        assert desc and html.escape(desc) in text, f"heading for {name} lacks its description"


@capture_tools
def test_report_without_siem_explains_how_to_create_it(run, tmp_path):
    run_dir, answers = run
    bare = tmp_path / "bare"
    shutil.copytree(run_dir, bare, ignore=shutil.ignore_patterns("siem", "detections"))
    text = report(bare, tmp_path)
    assert "pcapforge export" in text
    assert not SVG.findall(text)
    assert all(html.escape(e["title"]) in text for e in answers["timeline"])


@capture_tools
def test_class_results_average_each_question_over_the_submissions(run, tmp_path):
    run_dir, answers = run
    perfect = {q["id"]: q["answer"] for q in answers["questions"]}
    (tmp_path / "alice.yaml").write_text(yaml.safe_dump(perfect), encoding="utf-8")
    (tmp_path / "bob.yaml").write_text(yaml.safe_dump({}), encoding="utf-8")
    grades = tmp_path / "grades.json"  # what `pcapforge grade --json` prints
    graded = grade(answers, load_submissions([tmp_path / "alice.yaml", tmp_path / "bob.yaml"]))
    grades.write_text(json.dumps(graded), encoding="utf-8")
    text = report(run_dir, tmp_path, "--grades", str(grades))
    section = text[text.index("<h2>Class results</h2>"):]
    total = sum(q["points"] for q in answers["questions"])
    assert f"class average {total / 2:g} / {total} points" in section
    for index, question in enumerate(answers["questions"], 1):
        assert re.search(rf"<td>Q{index}</td><td>{re.escape(question['id'])}</td>"
                         rf'<td class="num">{question["points"]}</td>.*?<td class="num">50 %</td>', section)
    assert re.search(r'<td>alice</td><td class="num">' + f"{total:g}", section)
    assert re.search(r'<td>bob</td><td class="num">0</td>', section)


@capture_tools
def test_text_from_the_answer_key_is_escaped(run, tmp_path):
    run_dir, _ = run
    hostile = tmp_path / "hostile"
    shutil.copytree(run_dir, hostile)
    answers = json.loads((hostile / "answers.json").read_text(encoding="utf-8"))
    answers["timeline"][0]["title"] = '<script>alert("x")</script>'
    answers["questions"][0]["text"] = "a < b & c"
    (hostile / "answers.json").write_text(json.dumps(answers), encoding="utf-8")
    text = report(hostile, tmp_path)
    assert "<script" not in text
    assert "&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;" in text
    assert "a &lt; b &amp; c" in text


@capture_tools
def test_modbus_read_records_carry_the_values_the_plc_returned(run):
    run_dir, answers = run
    with open(run_dir / "siem" / "modbus.jsonl", encoding="utf-8") as fh:
        records = [json.loads(line) for line in fh]
    reads = [r for r in records if r["function_code"] in (1, 2, 3, 4) and r["response_frame"] is not None]
    assert reads
    for r in reads:
        if r["exception"] is None:
            assert len(r["values"]) == r["quantity"], r
        else:
            assert r["values"] is None
    # The writer reads each setpoint back right after writing it: the PLC returns the written value.
    change = answers["facts"]["change"]
    for write in change["writes"]:
        frame = write["request"]["frame"]
        readback = next(r for r in reads
                        if r["request_frame"] > frame and r["dest"] == change["target"]["ip"]
                        and FUNCTION_TABLE[r["function_code"]] == write["table"] and r["values"]
                        and r["address"] <= write["address"] < r["address"] + r["quantity"])
        assert readback["values"][write["address"] - readback["address"]] == write["raw"]


def test_downsampling_is_bounded_ordered_and_keeps_extremes():
    series = [(float(t), 10.0 + (t % 7) * 0.1) for t in range(5000)]
    series[3217] = (3217.0, 99.0)
    series[4001] = (4001.0, -5.0)
    shown = downsample(series, 0.0, 5000.0, limit=200)
    assert len(shown) <= 200
    assert [t for t, _ in shown] == sorted(t for t, _ in shown)
    assert (3217.0, 99.0) in shown and (4001.0, -5.0) in shown
    assert set(shown) <= set(series)
    assert downsample(series, 0.0, 5000.0, limit=200) == shown
    assert downsample(series[:150], 0.0, 5000.0, limit=200) == series[:150]
