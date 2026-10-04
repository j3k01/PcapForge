"""Export a generated run as CTFd challenges in the `ctfcli` format (one `challenge.yml` per question).

Install into CTFd with `ctf challenge install <dir>` for each challenge directory. The first
challenge carries the capture and the briefing as files; the others point to it. Answers
that CTFd cannot compare natively (sets, maps, timestamps with tolerance) get a canonical
flag format, which the challenge description spells out.
"""

from __future__ import annotations

import json
import math
import re
import shutil
from pathlib import Path

import yaml


class _Dumper(yaml.SafeDumper):
    """Multi-line strings as `|` blocks so challenge.yml stays readable."""


_Dumper.add_representer(str, lambda d, v: d.represent_scalar(
    "tag:yaml.org,2002:str", v, style="|" if "\n" in v else None))


FORMAT_NOTES = {
    "ip": "Flag format: the IP address, e.g. 10.1.2.3",
    "mac": "Flag format: the MAC address (case and separators do not matter)",
    "number": "Flag format: a number",
    "timestamp": "Flag format: UTC time to the second, YYYY-MM-DDTHH:MM:SSZ (fractions optional)",
    "set": "Flag format: the items sorted alphabetically, comma-separated, no spaces",
    "map": "Flag format: name=value pairs sorted by name, comma-separated, no spaces; values as plain numbers",
    "text": "Flag format: free text (case-insensitive)",
}


def _num(value) -> str:
    number = float(value)
    return str(int(number)) if number.is_integer() else f"{number:g}"


def _static(content: str) -> dict:
    return {"type": "static", "content": content, "data": "case_insensitive"}


def _regex(pattern: str) -> dict:
    return {"type": "regex", "content": pattern, "data": "case_insensitive"}


def flags_for(question: dict) -> list[dict]:
    kind = question.get("type", "text")
    answer = question["answer"]
    if kind == "mac":
        pairs = re.findall(r"[0-9a-fA-F]{2}", str(answer))
        return [_regex(r"^\s*" + r"[:\-. ]?".join(pairs) + r"\s*$")]
    if kind == "number":
        values = {_num(answer)}
        tolerance = float(question.get("tolerance", 0))
        if tolerance and float(answer).is_integer():
            values.add(f"{float(answer):.1f}")
        return [_static(v) for v in sorted(values)]
    if kind == "timestamp":
        second = str(answer)[:19]  # YYYY-MM-DDTHH:MM:SS
        date, time = second.split("T")
        return [_regex(rf"^\s*{re.escape(date)}[T ]{re.escape(time)}(\.\d+)?Z?\s*$")]
    if kind == "set":
        items = sorted(str(v).strip() for v in answer)
        return [_static(",".join(items))]
    if kind == "map":
        return [_static(",".join(f"{k}={_num(v)}" for k, v in sorted(answer.items())))]
    contents = [str(answer)] + [str(a) for a in question.get("accept", [])]
    return [_static(c) for c in dict.fromkeys(contents)]


def export_ctfd(run_dir: Path, out_dir: Path | None = None) -> list[Path]:
    answers = json.loads((run_dir / "answers.json").read_text(encoding="utf-8"))
    scenario = answers["scenario"]
    out_dir = out_dir or run_dir / "ctfd"
    category = f"{scenario['title']} ({scenario['difficulty']})"
    capture = next(p for p in sorted(run_dir.iterdir()) if p.name.startswith("capture."))
    first_name = None
    written = []
    for index, question in enumerate(answers["questions"], 1):
        name = f"{scenario['id']}-{scenario['seed']} Q{index:02d} {question['id']}"
        directory = out_dir / f"q{index:02d}-{question['id']}"
        directory.mkdir(parents=True, exist_ok=True)
        kind = question.get("type", "text")
        description = [question["text"], "", FORMAT_NOTES.get(kind, FORMAT_NOTES["text"])]
        if kind == "timestamp":
            description.append("Exact to the second.")
        challenge = {
            "name": name,
            "author": "pcapforge",
            "category": category,
            "value": int(question.get("points", 10)),
            "type": "standard",
            "flags": flags_for(question),
            "tags": [scenario["line"], scenario["difficulty"], kind],
            "state": "visible",
            "version": "0.1",
        }
        if first_name is None:
            files = directory / "files"
            files.mkdir(exist_ok=True)
            for source in (capture, run_dir / "briefing.md"):
                shutil.copy2(source, files / source.name)
            challenge["files"] = [f"files/{capture.name}", "files/briefing.md"]
            first_name = name
        else:
            description += ["", f"Use the capture attached to \"{first_name}\"."]
            challenge["requirements"] = [first_name]
        challenge["description"] = "\n".join(description)
        if question.get("hint"):
            challenge["hints"] = [{"content": question["hint"],
                                   "cost": math.ceil(challenge["value"] * 0.2)}]
        path = directory / "challenge.yml"
        path.write_text(yaml.dump(challenge, Dumper=_Dumper, sort_keys=False, allow_unicode=True), encoding="utf-8")
        written.append(path)
    return written
