"""Downloads of the run page: each section's table as CSV and any directory of a run as a zip.

CSV files are UTF-8 with a byte order mark, so spreadsheet programs read non-ASCII text correctly.
Zips are written straight into the response, so a run with a large capture starts downloading at once.
"""

from __future__ import annotations

import csv
import datetime as dt
import io
import json
import zipfile
from collections.abc import Callable
from pathlib import Path
from typing import BinaryIO

from pcapforge.ui import traffic


def _csv(header: list[str], rows) -> bytes:
    buf = io.StringIO(newline="")
    writer = csv.writer(buf)
    writer.writerow(header)
    writer.writerows(rows)
    return buf.getvalue().encode("utf-8-sig")


def _iso(epoch: float) -> str:
    return dt.datetime.fromtimestamp(epoch, dt.UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _start(answers: dict) -> float:
    return dt.datetime.fromisoformat(answers["capture"]["start"].replace("Z", "+00:00")).timestamp()


def hosts(directory: Path, answers: dict) -> bytes:
    rows = []
    for h in answers["topology"]["hosts"]:
        rows.append([h["name"], h.get("fqdn", ""), h["role"], h.get("vendor", ""), h["device"],
                     " ".join(i["ip"] for i in h["interfaces"]),
                     " ".join(i["subnet"] for i in h["interfaces"]),
                     " ".join((h.get("ipv6") or {}).values()),
                     " ".join(i["mac"] for i in h["interfaces"])])
    return _csv(["name", "fqdn", "role", "vendor", "device", "ipv4", "subnets", "ipv6", "mac"], rows)


def timeline(directory: Path, answers: dict) -> bytes | None:
    items = answers.get("timeline", [])
    if not items:
        return None
    start = _start(answers)
    rows = [[t["time"], f"{float(t['epoch']) - start:.6f}", t.get("frame", ""),
             "incident" if t.get("incident") else "normal", t["title"], t["actor"], " ".join(t.get("techniques", [])),
             json.dumps(t["details"], ensure_ascii=False) if t.get("details") else ""] for t in items]
    return _csv(["time", "offset_s", "frame", "kind", "event", "actor", "techniques", "details"], rows)


def flows(directory: Path, answers: dict) -> bytes | None:
    """Every flow of ``siem/flows.jsonl``; the columns are the record keys in order of appearance."""
    path = directory / "siem" / "flows.jsonl"
    if not path.is_file():
        return None
    records, columns = [], {}
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            try:
                record = json.loads(line)
            except ValueError:
                continue
            if isinstance(record, dict):
                records.append(record)
                columns.update(dict.fromkeys(record))
    return _csv(list(columns), ([r.get(c, "") for c in columns] for r in records))


def traffic_buckets(directory: Path, answers: dict) -> bytes | None:
    """The traffic chart's numbers: packets per protocol in each time bucket."""
    data = traffic.load(directory, answers)
    if data is None:
        return None
    names = [c for c in traffic.CATEGORIES if c in data["rows"]]
    rows = [[_iso(data["start"] + i * data["width"]), f"{i * data['width']:.3f}"]
            + [data["rows"][c][i] for c in names] for i in range(data["buckets"])]
    return _csv(["bucket_start", "offset_s"] + names, rows)


def answer_key(directory: Path, answers: dict) -> bytes:
    rows = []
    for q in answers.get("questions", []):
        answer = q["answer"] if isinstance(q["answer"], str) else json.dumps(q["answer"], ensure_ascii=False)
        rows.append([q["id"], " ".join(str(q["text"]).split()), q["type"], q["points"], answer, q.get("hint", ""),
                     "\n".join(c["filter"] for c in q.get("checks", []))])
    return _csv(["id", "question", "type", "points", "answer", "hint", "tshark_filters"], rows)


def grades(directory: Path, answers: dict) -> bytes | None:
    path = directory / "grades.json"
    if not path.is_file():
        return None
    students = json.loads(path.read_text(encoding="utf-8"))["students"]
    ids = [q["id"] for q in students[0]["questions"]] if students else []
    rows = [[s["student"], s["score"], s["max"], s["percent"]] + [q["score"] for q in s["questions"]]
            for s in students]
    return _csv(["student", "score", "max", "percent"] + ids, rows)


CSV: dict[str, Callable[[Path, dict], bytes | None]] = {
    "hosts": hosts, "timeline": timeline, "flows": flows, "traffic": traffic_buckets,
    "answer-key": answer_key, "grades": grades,
}


def write_zip(directory: Path, root: Path, fh: BinaryIO) -> None:
    """Every file under ``directory`` (inside the run ``root``) into a zip on ``fh``, which need not be
    seekable; member names start with the run's name."""
    with zipfile.ZipFile(fh, "w", zipfile.ZIP_DEFLATED, compresslevel=1) as zf:
        for path in sorted(directory.rglob("*")):
            if path.is_file() and path.resolve().is_relative_to(root):
                zf.write(path, (Path(root.name) / path.relative_to(root)).as_posix())
