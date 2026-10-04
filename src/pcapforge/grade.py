"""Grade student submissions against ``answers.json`` and write the blank ``submission_template.yaml``.

A submission is a YAML/JSON map ``{question_id: answer}`` (one student per file, named after the file)
or a CSV with ``student,question,answer`` rows (a whole class; repeated rows for the same question form
a list). Each question is scored by its ``type`` from the answer key:

- ``ip``: IPv4/IPv6 address equality (leading zeros in IPv4 octets ignored);
- ``mac``: hex digits only, case and separators (``:``, ``-``, ``.``, space) ignored;
- ``number``: numeric equality, or ``|given - answer| <= tolerance`` when the key has ``tolerance``;
- ``timestamp``: ISO 8601 (``T`` or space, with or without ``Z``/offset, any fractional digits;
  naive times are UTC), correct when within ``tolerance_s`` of the answer;
- ``set``: order-free and case-insensitive; partial credit |correct ∩ given| / |correct ∪ given|;
- ``map``: per key, numeric values within 0.5 % (relative) or equal text; partial credit
  matched keys / |answer keys ∪ given keys|;
- ``text``: case- and whitespace-insensitive match of the answer or any ``accept`` alternative.
"""

from __future__ import annotations

import csv
import datetime as dt
import ipaddress
import json
import math
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

TEMPLATE_NAME = "submission_template.yaml"
MAP_RELATIVE_TOLERANCE = 0.005
_LIST_SPLIT = re.compile(r"[,;\n]")
_PAIR = re.compile(r"^\s*([^=:]+?)\s*[=:]\s*(.*?)\s*$")


class GradeError(ValueError):
    """A submission or answer key that cannot be read."""


# --- loading -----------------------------------------------------------------------

class _StringLoader(yaml.SafeLoader):
    """YAML without implicit typing except null: ``no`` stays text, ``10:20:30:40:50:59`` stays a MAC
    (YAML 1.1 would read sexagesimal ints), unquoted times stay ISO strings."""


_StringLoader.yaml_implicit_resolvers = {
    first: [(tag, regexp) for tag, regexp in resolvers if tag == "tag:yaml.org,2002:null"]
    for first, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}


@dataclass
class Submission:
    student: str
    source: Path
    answers: dict[str, Any] = field(default_factory=dict)


def _load_map(path: Path) -> dict:
    text = path.read_text(encoding="utf-8-sig")
    try:
        data = json.loads(text) if path.suffix.lower() == ".json" else yaml.load(text, Loader=_StringLoader)
    except (json.JSONDecodeError, yaml.YAMLError) as exc:
        raise GradeError(f"{path}: {exc}") from None
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise GradeError(f"{path}: expected a map of question id -> answer")
    return {str(k): v for k, v in data.items()}


def _load_csv(path: Path) -> list[Submission]:
    with open(path, encoding="utf-8-sig", newline="") as fh:
        reader = csv.DictReader(fh)
        columns = {(name or "").strip().lower(): name for name in reader.fieldnames or []}
        missing = {"student", "question", "answer"} - columns.keys()
        if missing:
            raise GradeError(f"{path}: CSV needs the columns student,question,answer (missing {', '.join(sorted(missing))})")
        students: dict[str, Submission] = {}
        for row in reader:
            student = (row[columns["student"]] or "").strip()
            question = (row[columns["question"]] or "").strip()
            if not student or not question:
                continue
            answer = row[columns["answer"]] or ""
            sub = students.setdefault(student, Submission(student, path))
            if question in sub.answers:  # repeated rows: one element per row (sets, map entries)
                previous = sub.answers[question]
                sub.answers[question] = (previous if isinstance(previous, list) else [previous]) + [answer]
            else:
                sub.answers[question] = answer
    return list(students.values())


def load_submissions(paths: list[Path]) -> list[Submission]:
    subs: list[Submission] = []
    for path in paths:
        if not path.is_file():
            raise GradeError(f"{path}: no such file")
        if path.suffix.lower() == ".csv":
            subs.extend(_load_csv(path))
        else:
            subs.append(Submission(path.stem, path, _load_map(path)))
    seen: dict[str, Path] = {}
    for sub in subs:
        if sub.student in seen:
            raise GradeError(f"student '{sub.student}' appears in {seen[sub.student]} and {sub.source}")
        seen[sub.student] = sub.source
    return subs


# --- normalisation -----------------------------------------------------------------

def _blank(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, str):
        return not value.strip()
    if isinstance(value, (list, dict)):
        return not value
    return False


def _scalar(value: Any) -> Any:
    """A single answer: a one-element list (one CSV row) counts as its element."""
    if isinstance(value, list) and len(value) == 1:
        return value[0]
    return value


def norm_text(value: Any) -> str:
    return " ".join(str(value).split()).casefold()


def norm_ip(value: Any) -> str | None:
    text = str(value).strip()
    parts = text.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        text = ".".join(str(int(p)) for p in parts)
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


def norm_mac(value: Any) -> str | None:
    digits = re.sub(r"[\s:.\-]", "", str(value)).lower()
    return digits if re.fullmatch(r"[0-9a-f]{12}", digits) else None


def to_number(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    try:
        number = float(str(value).strip().replace("_", ""))
    except ValueError:
        return None
    return number if math.isfinite(number) else None


def to_datetime(value: Any) -> dt.datetime | None:
    if isinstance(value, dt.datetime):
        moment = value
    else:
        text = str(value).strip().upper()
        if text.endswith(" UTC"):
            text = text[:-4]
        try:
            moment = dt.datetime.fromisoformat(text)
        except ValueError:
            return None
    return moment.replace(tzinfo=dt.UTC) if moment.tzinfo is None else moment


def _element(value: Any) -> str:
    """Set elements and map keys: numbers by value (``6`` == ``6.0``), everything else as text."""
    number = to_number(value)
    if number is not None and number.is_integer():
        return str(int(number))
    return norm_text(value)


def _as_list(value: Any) -> list:
    if isinstance(value, list):
        items = []
        for item in value:
            items.extend(_as_list(item) if isinstance(item, str) else [item])
        return items
    if isinstance(value, str):
        return [part for part in (p.strip() for p in _LIST_SPLIT.split(value)) if part]
    return [value]


def _as_map(value: Any) -> dict[str, Any] | None:
    if isinstance(value, dict):
        return {_element(k): v for k, v in value.items()}
    pairs = {}
    for item in _as_list(value):
        if isinstance(item, dict):
            pairs.update({_element(k): v for k, v in item.items()})
            continue
        match = _PAIR.match(str(item))
        if not match:
            return None
        pairs[_element(match.group(1))] = match.group(2)
    return pairs


# --- scoring -----------------------------------------------------------------------

def _value_matches(expected: Any, given: Any) -> bool:
    want, got = to_number(expected), to_number(given)
    if want is not None:
        if got is None:
            return False
        return abs(got - want) <= MAP_RELATIVE_TOLERANCE * abs(want) if want else got == 0
    return norm_text(expected) == norm_text(given)


def score_fraction(question: dict, given: Any) -> float:
    """Fraction (0..1) of the question's points the answer earns."""
    if _blank(given):
        return 0.0
    kind = question.get("type", "text")
    expected = question["answer"]
    if kind == "set":
        want = {_element(v) for v in _as_list(expected)}
        got = {_element(v) for v in _as_list(given)}
        union = want | got
        return len(want & got) / len(union) if union else 0.0
    if kind == "map":
        want = {_element(k): v for k, v in expected.items()}
        got = _as_map(given)
        if got is None:
            return 0.0
        keys = want.keys() | got.keys()
        hits = sum(1 for key in want if key in got and _value_matches(want[key], got[key]))
        return hits / len(keys) if keys else 0.0
    given = _scalar(given)
    if kind == "ip":
        got = norm_ip(given)
        return float(got is not None and got == norm_ip(expected))
    if kind == "mac":
        got = norm_mac(given)
        return float(got is not None and got == norm_mac(expected))
    if kind == "number":
        want, got = to_number(expected), to_number(given)
        if got is None or want is None:
            return 0.0
        return float(abs(got - want) <= float(question.get("tolerance", 0)))
    if kind == "timestamp":
        want, got = to_datetime(expected), to_datetime(given)
        if got is None or want is None:
            return 0.0
        return float(abs(got - want) <= dt.timedelta(seconds=float(question.get("tolerance_s", 0))))
    accepted = {norm_text(a) for a in [expected, *question.get("accept", [])]}
    return float(norm_text(given) in accepted)


def _verdict(fraction: float, given: Any) -> str:
    if _blank(given):
        return "blank"
    if fraction >= 1:
        return "correct"
    return "partial" if fraction > 0 else "wrong"


def grade_submission(answers: dict, sub: Submission) -> dict:
    known = {q["id"] for q in answers["questions"]}
    results = []
    for question in answers["questions"]:
        given = sub.answers.get(question["id"])
        fraction = score_fraction(question, given)
        results.append({
            "id": question["id"],
            "type": question.get("type", "text"),
            "points": question["points"],
            "score": round(fraction * question["points"], 2),
            "result": _verdict(fraction, given),
            "given": given,
            "expected": question["answer"],
        })
    score = round(sum(r["score"] for r in results), 2)
    total = sum(q["points"] for q in answers["questions"])
    return {
        "student": sub.student,
        "source": str(sub.source),
        "score": score,
        "max": total,
        "percent": round(100 * score / total, 1) if total else 0.0,
        "questions": results,
        "unknown_questions": sorted(set(sub.answers) - known),
    }


def grade(answers: dict, subs: list[Submission]) -> dict:
    scenario = answers.get("scenario", {})
    return {
        "scenario": scenario.get("id"),
        "difficulty": scenario.get("difficulty"),
        "seed": scenario.get("seed"),
        "max": sum(q["points"] for q in answers["questions"]),
        "students": [grade_submission(answers, sub) for sub in subs],
    }


# --- output ------------------------------------------------------------------------

def _points(value: float) -> str:
    return f"{value:g}"


def _short(value: Any, width: int = 40) -> str:
    text = "" if value is None else (json.dumps(value, ensure_ascii=False, default=str)
                                     if isinstance(value, (list, dict)) else str(value))
    text = " ".join(text.split())
    return text if len(text) <= width else text[:width - 1] + "…"


def _rows(header: list[str], rows: list[list[str]]) -> list[str]:
    widths = [max(len(str(c)) for c in col) for col in zip(header, *rows)]
    fmt = lambda row: "  ".join(str(c).ljust(w) for c, w in zip(row, widths)).rstrip()  # noqa: E731
    return [fmt(header), fmt(["-" * w for w in widths])] + [fmt(r) for r in rows]


def format_report(report: dict) -> str:
    """One detail table per student, then a class summary when there is more than one."""
    lines: list[str] = []
    for student in report["students"]:
        lines.append(f"{student['student']}: {_points(student['score'])}/{student['max']} "
                     f"({student['percent']:g} %)   [{student['source']}]")
        lines += _rows(["question", "type", "score", "result", "given"],
                       [[q["id"], q["type"], f"{_points(q['score'])}/{q['points']}", q["result"], _short(q["given"])]
                        for q in student["questions"]])
        if student["unknown_questions"]:
            lines.append("unknown question ids (not scored): " + ", ".join(student["unknown_questions"]))
        lines.append("")
    if len(report["students"]) > 1:
        ids = [q["id"] for q in report["students"][0]["questions"]]
        lines.append(f"class summary ({len(report['students'])} students, max {report['max']} points; "
                     "Q numbers as in briefing.md)")
        lines += _rows(["student", *[f"Q{i}" for i in range(1, len(ids) + 1)], "total", "%"],
                       [[s["student"], *[_points(q["score"]) for q in s["questions"]],
                         _points(s["score"]), f"{s['percent']:g}"] for s in report["students"]])
        lines += [f"  Q{i} = {qid}" for i, qid in enumerate(ids, 1)]
    return "\n".join(lines).rstrip() + "\n"


# --- template ----------------------------------------------------------------------

_FORMAT_HINTS = {
    "ip": "an IP address",
    "mac": "a MAC address",
    "number": "a number",
    "timestamp": "a UTC time, ISO 8601: YYYY-MM-DDTHH:MM:SS.ffffffZ",
    "set": "a list: [a, b, c]",
    "map": "a map: {name: value, name: value}",
}


def submission_template(answers: dict) -> str:
    """Blank submission: every question id with an empty answer, the question text as comments."""
    scenario = answers.get("scenario", {})
    lines = [
        f"# pcapforge submission: {scenario.get('title', '')}".rstrip(),
        f"# {scenario.get('id', '')} ({scenario.get('difficulty', '')}, seed {scenario.get('seed', '')})",
        "# Write each answer after its colon; quote answers that contain ': ' or start with '[' or '{'.",
        "# Save under your name (e.g. jane-doe.yaml); your instructor grades it with",
        "#   pcapforge grade answers.json jane-doe.yaml",
        "",
    ]
    for index, question in enumerate(answers["questions"], 1):
        text_lines = str(question["text"]).strip().splitlines() or [""]
        lines.append(f"# {index}. {text_lines[0]}")
        lines += [f"#    {line}" for line in text_lines[1:]]
        hint = _FORMAT_HINTS.get(question.get("type", "text"))
        lines.append(f"#    ({question['points']} points" + (f"; answer: {hint})" if hint else ")"))
        lines += [f"{question['id']}:", ""]
    return "\n".join(lines)


def write_submission_template(answers: dict, out_dir: Path) -> Path:
    path = out_dir / TEMPLATE_NAME
    path.write_text(submission_template(answers), encoding="utf-8")
    return path
