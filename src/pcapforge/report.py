"""Instructor debrief: one self-contained static HTML file per run (``pcapforge report``).

The report is built from the run directory only: ``answers.json`` for the header, the
incident timeline and the questions, ``siem/modbus.jsonl`` read responses (decoded with
the process register map) for the before/after charts of every changed PLC point, and
optionally the JSON output of ``pcapforge grade --json`` for the class results.
Everything is inline (CSS + SVG) so the file can be mailed or opened offline; all text is
HTML-escaped. Output is a pure function of the inputs (no generation timestamp).
"""

from __future__ import annotations

import datetime as dt
import json
import math
from collections import defaultdict
from dataclasses import dataclass, field
from html import escape
from pathlib import Path

from pcapforge import __version__
from pcapforge.export import host_ips, register_maps
from pcapforge.process import BIT_TABLES, FUNCTION_TABLE, Point, ProcessProfile

MAX_SAMPLES = 600                 # per chart series after downsampling (min/max per bucket)
CHART_W, CHART_H = 760, 150
PAD_L, PAD_R, PAD_T, PAD_B = 70, 16, 20, 30
TICK_STEPS = (1, 2, 5, 10, 15, 30, 60, 120, 300, 600, 900, 1800, 3600, 7200, 10800, 21600, 43200, 86400)
MAX_TICKS = 7


class ReportError(Exception):
    pass


# --- inputs -----------------------------------------------------------------------------

@dataclass
class Change:
    """All writes of one actor to one point of one PLC."""
    actor: str
    incident: bool
    target_id: str | None
    target_label: str
    target_ip: str | None
    point: str
    unit: str
    writes: list[dict] = field(default_factory=list)

    @property
    def first(self) -> float:
        return min(_epoch_of(w) for w in self.writes)


def _epoch_of(write: dict) -> float:
    return float(write["request"]["epoch"])


def _parse_utc(text: str) -> float:
    return dt.datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()


def changes(answers: dict) -> list[Change]:
    """Every point written by any actor (``facts.<actor>.writes``), ordered by first write."""
    incident = {a["id"]: bool(a.get("incident")) for a in answers.get("actors", [])}
    ips = host_ips(answers)
    groups: dict[tuple, Change] = {}
    for actor, fact in answers.get("facts", {}).items():
        writes = fact.get("writes") if isinstance(fact, dict) else None
        if not isinstance(writes, list):
            continue
        for write in writes:
            if not isinstance(write, dict) or "point" not in write or "request" not in write:
                continue
            target = write.get("target") or fact.get("target") or {}
            key = (actor, target.get("id"), write["point"])
            if key not in groups:
                groups[key] = Change(
                    actor=actor, incident=incident.get(actor, False), target_id=target.get("id"),
                    target_label=target.get("name") or target.get("id") or "?",
                    target_ip=ips.get(target.get("id"), target.get("ip")),
                    point=write["point"], unit=write.get("unit", ""))
            groups[key].writes.append(write)
    for change in groups.values():
        change.writes.sort(key=_epoch_of)
    return sorted(groups.values(), key=lambda c: (c.first, c.actor, c.point))


def load_samples(path: Path, maps: dict[str, ProcessProfile]) -> dict[tuple[str, str], list[tuple[float, float]]]:
    """(PLC address, point name) -> [(epoch, engineering value)] from successful read responses."""
    samples: dict[tuple[str, str], list[tuple[float, float]]] = defaultdict(list)
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            record = json.loads(line)
            table = FUNCTION_TABLE.get(record.get("function_code"))
            if record.get("write") or table is None or record.get("address") is None \
                    or not record.get("values") or record.get("exception") is not None:
                continue
            profile = maps.get(record["dest"])
            if profile is None:
                continue
            for offset, raw in enumerate(record["values"]):
                point = profile.by_address.get((table, record["address"] + offset))
                if point is not None:
                    samples[(record["dest"], point.name)].append((float(record["epoch"]), point.decode(raw)))
    for series in samples.values():
        series.sort(key=lambda s: s[0])
    return samples


def dependents(profile: ProcessProfile, name: str) -> list[Point]:
    """Points whose model follows or compares against ``name``, transitively, in map order."""
    found: list[Point] = []
    seen, frontier = {name}, {name}
    while frontier:
        reached = set()
        for point in profile.points:
            if point.name in seen or not point.model:
                continue
            if {point.model.get("source"), point.model.get("a"), point.model.get("b")} & frontier:
                found.append(point)
                reached.add(point.name)
        seen |= reached
        frontier = reached
    return found


# --- formatting -------------------------------------------------------------------------

def _e(value) -> str:
    return escape(str(value), quote=True)


def _num(value: float) -> str:
    if abs(value) >= 100:
        text = f"{value:.1f}"
    else:
        text = f"{value:.3f}"
    text = text.rstrip("0").rstrip(".")
    return "0" if text in ("-0", "") else text


def _value(value: float, unit: str) -> str:
    return f"{_num(value)} {unit}".rstrip()


def _clock(epoch: float, seconds: bool = True) -> str:
    stamp = dt.datetime.fromtimestamp(epoch, dt.UTC)
    return stamp.strftime("%H:%M:%S" if seconds else "%H:%M")


def _utc(epoch: float) -> str:
    return dt.datetime.fromtimestamp(epoch, dt.UTC).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + " UTC"


def _answer_text(value) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return ", ".join(_answer_text(v) for v in value)
    if isinstance(value, dict):
        return "; ".join(f"{k} = {_answer_text(v)}" for k, v in value.items())
    return json.dumps(value, ensure_ascii=False)


def _expect_text(expect: dict) -> str:
    parts = []
    if "count" in expect:
        parts.append(f"exactly {expect['count']} frame(s)")
    if "min" in expect:
        parts.append(f"at least {expect['min']} frame(s)")
    if "max" in expect:
        parts.append(f"at most {expect['max']} frame(s)")
    rest = {k: v for k, v in expect.items() if k not in ("count", "min", "max")}
    if rest:
        parts.append(json.dumps(rest, ensure_ascii=False))
    return ", ".join(parts) or "any"


# --- charts -----------------------------------------------------------------------------

def downsample(series: list[tuple[float, float]], t0: float, t1: float,
               limit: int = MAX_SAMPLES) -> list[tuple[float, float]]:
    """Keep the first minimum and first maximum of each of ``limit // 2`` equal time buckets,
    in time order, so spikes survive. Deterministic; series at or below ``limit`` are kept."""
    if len(series) <= limit:
        return series
    buckets = max(limit // 2, 1)
    width = (t1 - t0) / buckets if t1 > t0 else 1.0
    chosen: dict[int, tuple[int, int]] = {}
    for index, (t, v) in enumerate(series):
        b = min(max(int((t - t0) / width), 0), buckets - 1)
        if b not in chosen:
            chosen[b] = (index, index)
            continue
        lo, hi = chosen[b]
        chosen[b] = (index if v < series[lo][1] else lo, index if v > series[hi][1] else hi)
    keep = sorted({i for pair in chosen.values() for i in pair})
    return [series[i] for i in keep]


def _value_axis(lo: float, hi: float) -> tuple[float, float, list[float]]:
    """Axis bounds on round numbers enclosing [lo, hi] and the ticks between them (at most 6)."""
    if hi - lo < 1e-9:
        pad = abs(lo) * 0.01 or 1.0
        lo, hi = lo - pad, hi + pad
    margin = (hi - lo) * 0.03
    lo, hi = lo - margin, hi + margin
    magnitude = 10 ** math.floor(math.log10((hi - lo) / 5))
    for step in (m * magnitude for m in (1, 2, 2.5, 5, 10, 20)):
        first, last = math.floor(lo / step), math.ceil(hi / step)
        if last - first <= 5:
            break
    ticks = [round(i * step, 9) for i in range(first, last + 1)]
    return ticks[0], ticks[-1], ticks


def _ticks(t0: float, t1: float) -> tuple[list[float], bool]:
    span = max(t1 - t0, 1.0)
    step = next((s for s in TICK_STEPS if span / s <= MAX_TICKS), TICK_STEPS[-1])
    first = (int(t0 // step) + 1) * step if t0 % step else t0
    ticks = []
    t = first
    while t <= t1:
        ticks.append(t)
        t += step
    return ticks, step % 60 != 0


def chart(title: str, series: list[tuple[float, float]], t0: float, t1: float,
          marks: list[tuple[float, str, bool]], *, step: bool, bits: bool = False,
          band: tuple[float, float] | None = None, extra_values: tuple[float, ...] = ()) -> str:
    """Inline SVG line chart of ``series`` over [t0, t1] with write ``marks`` (epoch, tooltip,
    incident) drawn as vertical lines. Y axis spans the data (plus ``band``/``extra_values``)."""
    w, h = CHART_W, CHART_H
    x0, x1, y_top, y_bot = PAD_L, w - PAD_R, PAD_T, h - PAD_B
    values = [v for _, v in series] + list(extra_values)
    if bits:
        y_lo, y_hi = -0.15, 1.15
        y_labels = [(0.0, "off"), (1.0, "on")]
    else:
        lo, hi = (min(values), max(values)) if values else (0.0, 1.0)
        if band:
            lo, hi = min(lo, band[0]), max(hi, band[1])
        y_lo, y_hi, y_ticks = _value_axis(lo, hi)
        y_labels = [(v, _num(v)) for v in y_ticks]
    tspan = (t1 - t0) or 1.0

    def px(t: float) -> float:
        return round(x0 + (t - t0) / tspan * (x1 - x0), 1)

    def py(v: float) -> float:
        return round(y_bot - (v - y_lo) / (y_hi - y_lo) * (y_bot - y_top), 1)

    out = [f'<svg xmlns="http://www.w3.org/2000/svg" class="chart" viewBox="0 0 {w} {h}" '
           f'width="{w}" height="{h}" role="img" aria-label="{_e(title)}">',
           f'<title>{_e(title)}</title>',
           f'<rect x="{x0}" y="{y_top}" width="{x1 - x0}" height="{y_bot - y_top}" class="plot"/>']
    if band and not bits:
        b_top, b_bot = py(min(band[1], y_hi)), py(max(band[0], y_lo))
        out.append(f'<rect x="{x0}" y="{b_top}" width="{x1 - x0}" height="{round(b_bot - b_top, 1)}" '
                   f'class="band"><title>normal band {_e(_num(band[0]))} – {_e(_num(band[1]))}</title></rect>')
    # Y axis: round ticks from the axis minimum to its maximum (off/on for bits).
    for value, label in y_labels:
        y = py(value)
        out.append(f'<line x1="{x0}" y1="{y}" x2="{x1}" y2="{y}" class="grid"/>')
        out.append(f'<text x="{x0 - 6}" y="{y + 4}" class="ylab">{_e(label)}</text>')
    # X axis: aligned UTC time ticks.
    ticks, with_seconds = _ticks(t0, t1)
    for t in ticks:
        x = px(t)
        out.append(f'<line x1="{x}" y1="{y_bot}" x2="{x}" y2="{y_bot + 4}" class="axis"/>')
        out.append(f'<text x="{x}" y="{y_bot + 16}" class="xlab">{_clock(t, with_seconds)}</text>')
    out.append(f'<line x1="{x0}" y1="{y_bot}" x2="{x1}" y2="{y_bot}" class="axis"/>')
    out.append(f'<line x1="{x0}" y1="{y_top}" x2="{x0}" y2="{y_bot}" class="axis"/>')
    # Series, broken at capture gaps (no read responses for a while); isolated samples
    # (e.g. a writer reading its value back long after polling stopped) are drawn as dots.
    if series:
        intervals = sorted(b[0] - a[0] for a, b in zip(series, series[1:]))
        gap = max(60.0, 10 * intervals[len(intervals) // 2]) if intervals else 0.0
        segments: list[list[tuple[float, float]]] = []
        for sample in series:
            if not segments or sample[0] - segments[-1][-1][0] > gap:
                segments.append([])
            segments[-1].append(sample)
        parts: list[str] = []
        for segment in segments:
            if len(segment) == 1:
                t, v = segment[0]
                out.append(f'<circle cx="{px(t)}" cy="{py(v)}" r="2.5" class="dot">'
                           f'<title>{_e(_num(v))} at {_e(_utc(t))}</title></circle>')
                continue
            parts.append(f"M{px(segment[0][0])} {py(segment[0][1])}")
            for t, v in segment[1:]:
                parts.append(f"H{px(t)}V{py(v)}" if step else f"L{px(t)} {py(v)}")
        if parts:
            out.append(f'<path d="{"".join(parts)}" class="series"/>')
    else:
        out.append(f'<text x="{(x0 + x1) / 2}" y="{(y_top + y_bot) / 2}" class="empty">'
                   'no read responses for this point</text>')
    # Write marks; label only those not crowding the previous label.
    last_label = -1e9
    for epoch, tooltip, incident in marks:
        x = px(epoch)
        cls = "mark incident" if incident else "mark approved"
        out.append(f'<line x1="{x}" y1="{y_top}" x2="{x}" y2="{y_bot}" class="{cls}">'
                   f'<title>{_e(tooltip)}</title></line>')
        if x - last_label > 48:
            out.append(f'<text x="{x + 3}" y="{y_top + 11}" class="marklab">write</text>')
            last_label = x
    out.append(f'<text x="{x0}" y="{y_top - 6}" class="ctitle">{_e(title)}</text>')
    out.append("</svg>")
    return "".join(out)


def _bar_chart(rows: list[tuple[str, float]]) -> str:
    """Horizontal bars of percentages (0-100) labelled with ``rows[i][0]``."""
    bar_h, gap, label_w, w = 16, 6, 190, CHART_W
    h = len(rows) * (bar_h + gap) + 26
    x0, x1 = label_w, w - 50
    out = [f'<svg xmlns="http://www.w3.org/2000/svg" class="chart" viewBox="0 0 {w} {h}" '
           f'width="{w}" height="{h}" role="img" aria-label="average score per question">',
           "<title>average score per question (% of points)</title>"]
    for pct in (0, 50, 100):
        x = round(x0 + pct / 100 * (x1 - x0), 1)
        out.append(f'<line x1="{x}" y1="4" x2="{x}" y2="{h - 18}" class="grid"/>')
        out.append(f'<text x="{x}" y="{h - 4}" class="xlab">{pct} %</text>')
    for index, (label, pct) in enumerate(rows):
        y = 6 + index * (bar_h + gap)
        width = round(max(0.0, min(pct, 100.0)) / 100 * (x1 - x0), 1)
        out.append(f'<text x="{x0 - 6}" y="{y + bar_h - 4}" class="ylab">{_e(label)}</text>')
        out.append(f'<rect x="{x0}" y="{y}" width="{width}" height="{bar_h}" class="bar"/>')
        out.append(f'<text x="{x0 + width + 4}" y="{y + bar_h - 4}" class="vlab">{_num(pct)} %</text>')
    out.append("</svg>")
    return "".join(out)


# --- sections ---------------------------------------------------------------------------

def _header(answers: dict) -> str:
    sc, cap, topo = answers["scenario"], answers["capture"], answers.get("topology", {})
    process = next((f.get("title") for f in answers.get("facts", {}).values()
                    if isinstance(f, dict) and f.get("process")), None)
    site = topo.get("site_name", "")
    if topo.get("domain"):
        site = f"{site} ({topo['domain']})"
    rows = [
        ("Scenario", f"{sc.get('id', '')}"),
        ("Difficulty", sc.get("difficulty", "")),
        ("Seed", sc.get("seed", "") + (f" (behaviour from base seed {sc['base_seed']})"
                                        if sc.get("base_seed") not in (None, sc.get("seed")) else "")),
        ("Site", site),
        ("Process", process or "—"),
        ("Capture file", cap.get("file", "")),
        ("Packets", cap.get("packets", "")),
        ("SHA-256", cap.get("sha256", "")),
        ("Start", cap.get("start", "")),
        ("End", cap.get("end", "")),
        ("Sensor subnet", cap.get("sensor_subnet", "")),
    ]
    items = "".join(f"<dt>{_e(k)}</dt><dd>{_e(v)}</dd>" for k, v in rows)
    summary = f'<p class="summary">{_e(sc["summary"])}</p>' if sc.get("summary") else ""
    return (f'<header><p class="kicker">pcapforge debrief — instructor material, contains the answers</p>'
            f'<h1>{_e(sc.get("title", sc.get("id", "")))}</h1>{summary}<dl class="meta">{items}</dl></header>')


def _timeline(answers: dict) -> str:
    events = answers.get("timeline", [])
    names = {m["id"]: m.get("name", "") for m in answers.get("mitre", [])}
    if not events:
        return "<section><h2>Timeline</h2><p>The answer key lists no events.</p></section>"
    note = ""
    if not any(e.get("incident") for e in events):
        note = ('<p class="note">No incident in this capture: the timeline lists only the approved '
                'changes made through the normal change path.</p>')
    rows = []
    for event in events:
        cls = "incident" if event.get("incident") else "legit"
        techniques = "".join(
            f'<span class="tech" title="{_e(names.get(t, ""))}">{_e(t)}'
            f'{" " + _e(names[t]) if names.get(t) else ""}</span>' for t in event.get("techniques", []))
        rows.append(f'<tr class="{cls}"><td class="mono">{_e(_utc(float(event["epoch"])))}</td>'
                    f'<td class="num">{_e(event.get("frame", ""))}</td><td>{_e(event.get("actor", ""))}</td>'
                    f'<td>{_e(event.get("title", ""))}</td><td>{techniques or "—"}</td>'
                    f'<td>{"incident" if event.get("incident") else "legitimate"}</td></tr>')
    return ('<section><h2>Timeline</h2>' + note +
            '<table class="timeline"><thead><tr><th>Time (UTC)</th><th>Frame</th><th>Actor</th>'
            '<th>Event</th><th>ATT&amp;CK</th><th>Kind</th></tr></thead><tbody>'
            + "".join(rows) + "</tbody></table></section>")


def _series_stats(series: list[tuple[float, float]], first: float, last: float, bits: bool) -> list[str]:
    before = [v for t, v in series if t < first]
    after = [v for t, v in series if t > last]

    def summary(values: list[float]) -> str:
        if not values:
            return "—"
        mean = sum(values) / len(values)
        return f"on {_num(100 * mean)} %" if bits else _num(mean)

    values = [v for _, v in series]
    span = [_num(min(values)), _num(max(values))] if values else ["—", "—"]
    return [summary(before), summary(after), *span, _num(series[-1][1]) if series else "—"]


def _changes_section(answers: dict, run_dir: Path) -> str:
    found = changes(answers)
    title = "<h2>Process changes</h2>"
    if not found:
        return f"<section>{title}<p>No PLC point was written in this capture.</p></section>"
    writes_table = ['<table><thead><tr><th>Time (UTC)</th><th>Frame</th><th>Actor</th><th>PLC</th>'
                    '<th>Point</th><th>Value</th><th>Kind</th></tr></thead><tbody>']
    for change in found:
        for write in change.writes:
            cls = "incident" if change.incident else "legit"
            writes_table.append(
                f'<tr class="{cls}"><td class="mono">{_e(_utc(_epoch_of(write)))}</td>'
                f'<td class="num">{_e(write["request"].get("frame", ""))}</td><td>{_e(change.actor)}</td>'
                f'<td>{_e(change.target_label)}</td><td>{_e(change.point)}</td>'
                f'<td class="num">{_e(_value(float(write["value"]), change.unit))}</td>'
                f'<td>{"unauthorized" if change.incident else "approved"}</td></tr>')
    writes_table.append("</tbody></table>")
    parts = [f"<section>{title}", "".join(writes_table)]

    modbus = run_dir / "siem" / "modbus.jsonl"
    if not modbus.is_file():
        parts.append('<p class="note">Charts need the SIEM export, which this run directory does not '
                     f'have. Create it with <code>pcapforge export {_e(run_dir)}</code> (or generate with '
                     '<code>--siem</code>) and run <code>pcapforge report</code> again.</p></section>')
        return "".join(parts)
    maps = register_maps(answers)
    samples = load_samples(modbus, maps)
    if not samples:
        parts.append('<p class="note"><code>siem/modbus.jsonl</code> carries no read values (exported by an '
                     f'older pcapforge). Re-create it with <code>pcapforge export {_e(run_dir)}</code>.</p>'
                     "</section>")
        return "".join(parts)

    t0, t1 = _parse_utc(answers["capture"]["start"]), _parse_utc(answers["capture"]["end"])
    for change in found:
        profile = maps.get(change.target_ip or "")
        point = profile.by_name.get(change.point) if profile else None
        kind = "unauthorized" if change.incident else "approved"
        named = f"{_e(change.point)} ({_e(point.desc)})" if point and point.desc else _e(change.point)
        heading = (f'<h3 class="{"incident" if change.incident else "legit"}">{named} on '
                   f'{_e(change.target_label)} ({_e(change.target_ip or "?")}) — {kind} change by '
                   f'{_e(change.actor)}</h3>')
        if point is None:
            parts.append(f'<div class="change">{heading}<p class="note">No register map for this '
                         'point; nothing to chart.</p></div>')
            continue
        marks = [(_epoch_of(w), f"{change.actor}: {change.point} = {_value(float(w['value']), change.unit)} "
                  f"(frame {w['request'].get('frame', '?')}, {_utc(_epoch_of(w))})", change.incident)
                 for w in change.writes]
        first, last = _epoch_of(change.writes[0]), _epoch_of(change.writes[-1])
        written = tuple(float(w["value"]) for w in change.writes)
        rows, charts = [], []
        for series_point in [point, *dependents(profile, point.name)]:
            series = samples.get((change.target_ip, series_point.name), [])
            bits = series_point.table in BIT_TABLES
            shown = downsample(series, t0, t1)
            label = f"{series_point.name}" + (f" [{series_point.unit}]" if series_point.unit else "")
            role = "written setpoint" if series_point is point else "affected measurement"
            charts.append(chart(f"{label} — {role}", shown, t0, t1, marks,
                                step=bits or series_point.table in ("holding", "coils"), bits=bits,
                                band=series_point.normal,
                                extra_values=written if series_point is point and not bits else ()))
            sampled = f"{len(series)}" + (f" (shown {len(shown)})" if len(shown) != len(series) else "")
            rows.append(f"<tr><td>{_e(series_point.name)}</td><td>{_e(series_point.unit)}</td>"
                        f"<td>{_e(role)}</td><td class=\"num\">{_e(sampled)}</td>"
                        + "".join(f'<td class="num">{_e(v)}</td>'
                                  for v in _series_stats(series, first, last, bits)) + "</tr>")
        normal = f"; normal band {_num(point.normal[0])} – {_value(point.normal[1], point.unit)}" \
            if point.normal else ""
        parts.append(
            f'<div class="change">{heading}<p>Written: '
            + ", ".join(_e(_value(v, change.unit)) for v in written)
            + f"{_e(normal)}; nominal {_e(_value(point.nominal, point.unit))}.</p>"
            + "".join(f'<figure>{svg}</figure>' for svg in charts)
            + '<table class="stats"><thead><tr><th>Point</th><th>Unit</th><th>Role</th><th>Samples</th>'
              '<th>Before first write (mean)</th><th>After last write (mean)</th><th>Min</th><th>Max</th>'
              '<th>Last value</th>'
              '</tr></thead><tbody>' + "".join(rows) + "</tbody></table></div>")
    parts.append('<p class="legend"><span class="sw band"></span> normal band '
                 '<span class="sw incident"></span> unauthorized write '
                 '<span class="sw approved"></span> approved write — values decoded from the read '
                 'responses in <code>siem/modbus.jsonl</code>.</p></section>')
    return "".join(parts)


def _questions(answers: dict) -> str:
    items = []
    for index, q in enumerate(answers.get("questions", []), 1):
        checks = "".join(f'<li><code>{_e(c.get("filter", ""))}</code> — {_e(_expect_text(c.get("expect", {})))}</li>'
                         for c in q.get("checks", []))
        extra = []
        if q.get("accept"):
            extra.append(f"<dt>Also accepted</dt><dd>{_e(_answer_text(q['accept']))}</dd>")
        if q.get("tolerance_s") is not None:
            extra.append(f"<dt>Tolerance</dt><dd>± {_e(q['tolerance_s'])} s</dd>")
        if q.get("hint"):
            extra.append(f"<dt>Hint</dt><dd>{_e(q['hint'])}</dd>")
        items.append(
            f'<li class="question"><p class="qtext"><b>Q{index}</b> <span class="qid">{_e(q["id"])}</span> '
            f'({_e(q.get("points", 0))} pts, {_e(q.get("type", ""))}) — {_e(q.get("text", ""))}</p>'
            f'<dl><dt>Answer</dt><dd class="answer">{_e(_answer_text(q.get("answer")))}</dd>'
            + "".join(extra)
            + (f"<dt>tshark checks</dt><dd><ul>{checks}</ul></dd>" if checks else "")
            + "</dl></li>")
    return '<section><h2>Questions and answers</h2><ol class="questions">' + "".join(items) + "</ol></section>"


def _grades(answers: dict, grades: dict) -> str:
    students = grades.get("students")
    if not isinstance(students, list) or not all(isinstance(s, dict) and "questions" in s for s in students):
        raise ReportError("grades file is not `pcapforge grade --json` output (missing students/questions)")
    note = ""
    sc = answers.get("scenario", {})
    if (grades.get("scenario"), grades.get("seed")) != (sc.get("id"), sc.get("seed")):
        note = (f'<p class="note">The grades were computed for {_e(grades.get("scenario"))} seed '
                f'{_e(grades.get("seed"))}, this run is {_e(sc.get("id"))} seed {_e(sc.get("seed"))}.</p>')
    if not students:
        return f"<section><h2>Class results</h2>{note}<p>No submissions.</p></section>"
    per_q: dict[str, list[dict]] = defaultdict(list)
    for student in students:
        for result in student["questions"]:
            per_q[result["id"]].append(result)
    order = [q["id"] for q in answers.get("questions", []) if q["id"] in per_q]
    order += [qid for qid in per_q if qid not in order]
    q_rows, bars = [], []
    for index, qid in enumerate(order, 1):
        results = per_q[qid]
        points = results[0].get("points", 0)
        mean = sum(r.get("score", 0) for r in results) / len(results)
        pct = 100 * mean / points if points else 0.0
        verdicts = {v: sum(1 for r in results if r.get("result") == v)
                    for v in ("correct", "partial", "wrong", "blank")}
        bars.append((f"Q{index} {qid}", pct))
        q_rows.append(f'<tr><td>Q{index}</td><td>{_e(qid)}</td><td class="num">{_e(points)}</td>'
                      f'<td class="num">{_e(_num(mean))}</td><td class="num">{_e(_num(pct))} %</td>'
                      + "".join(f'<td class="num">{verdicts[v]}</td>' for v in verdicts) + "</tr>")
    s_rows = [f'<tr><td>{_e(s.get("student", ""))}</td><td class="num">{_e(_num(float(s.get("score", 0))))}</td>'
              f'<td class="num">{_e(s.get("max", ""))}</td><td class="num">{_e(s.get("percent", ""))} %</td></tr>'
              for s in students]
    total = sum(float(s.get("score", 0)) for s in students) / len(students)
    return (f'<section><h2>Class results</h2>{note}<p>{len(students)} submission(s); class average '
            f'{_e(_num(total))} / {_e(grades.get("max", ""))} points.</p>'
            f"<figure>{_bar_chart(bars)}</figure>"
            '<table><thead><tr><th>#</th><th>Question</th><th>Points</th><th>Average</th><th>Average %</th>'
            '<th>Correct</th><th>Partial</th><th>Wrong</th><th>Blank</th></tr></thead><tbody>'
            + "".join(q_rows) + "</tbody></table>"
            '<table><thead><tr><th>Student</th><th>Score</th><th>Max</th><th>%</th></tr></thead><tbody>'
            + "".join(s_rows) + "</tbody></table></section>")


CSS = """
:root{color-scheme:light}html{background:#fff}
body{font:14px/1.45 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;color:#1d232a;margin:0 auto;
max-width:1000px;padding:24px}
h1{font-size:24px;margin:4px 0 8px}h2{border-bottom:2px solid #d6dbe1;padding-bottom:4px;margin-top:32px}
h3{font-size:15px;margin:22px 0 4px}h3.incident{color:#a4161a}h3.legit{color:#1b6b3a}
.kicker{color:#5c6773;text-transform:uppercase;font-size:11px;letter-spacing:.06em;margin:0}
.summary{color:#3b4651}
dl.meta{display:grid;grid-template-columns:max-content 1fr;gap:2px 16px;margin:12px 0}
dl.meta dt{color:#5c6773}dl.meta dd{margin:0;word-break:break-all}
table{border-collapse:collapse;width:100%;margin:10px 0;font-size:13px}
th,td{border-bottom:1px solid #e3e7eb;padding:4px 6px;text-align:left;vertical-align:top}
th{background:#f3f5f7}td.num{text-align:right;font-variant-numeric:tabular-nums}
td.mono{white-space:nowrap}
td.mono,code{font-family:ui-monospace,Consolas,monospace;font-size:12px}
tr.incident td{background:#fdecec}tr.incident td:first-child{border-left:4px solid #c62828}
tr.legit td{color:#3b4651}tr.legit td:first-child{border-left:4px solid #2e7d32}
.tech{display:inline-block;background:#eef1f4;border-radius:3px;padding:0 4px;margin:1px 2px;font-size:12px}
.note{background:#fff8e1;border-left:4px solid #f0b400;padding:6px 10px}
figure{margin:6px 0}
svg.chart{max-width:100%;height:auto;font:11px system-ui,sans-serif;background:#fff}
svg .plot{fill:#fbfcfd;stroke:none}svg .band{fill:#2e7d32;fill-opacity:.12}
svg .grid{stroke:#d6dbe1;stroke-dasharray:3 3}svg .axis{stroke:#5c6773}
svg .ylab{text-anchor:end;fill:#3b4651}svg .xlab{text-anchor:middle;fill:#3b4651}
svg .vlab{fill:#3b4651}svg .ctitle{fill:#1d232a;font-weight:600}
svg .series{fill:none;stroke:#1f5fa8;stroke-width:1.4}svg .dot{fill:#1f5fa8}
svg .empty{text-anchor:middle;fill:#8a949e}
svg .mark{stroke-width:1.5;stroke-dasharray:5 3}svg .incident{stroke:#c62828}svg .approved{stroke:#2e7d32}
svg .marklab{fill:#5c6773;font-size:10px}svg .bar{fill:#1f5fa8}
.legend .sw{display:inline-block;width:14px;height:10px;margin:0 4px 0 12px;vertical-align:middle}
.sw.band{background:rgba(46,125,50,.15)}.sw.incident{border-top:2px dashed #c62828}
.sw.approved{border-top:2px dashed #2e7d32}
ol.questions{padding-left:0;list-style:none}li.question{border:1px solid #e3e7eb;border-radius:6px;
padding:8px 12px;margin:10px 0}.qid{font-family:ui-monospace,Consolas,monospace;color:#5c6773}
li.question dl{display:grid;grid-template-columns:max-content 1fr;gap:2px 12px;margin:4px 0}
li.question dt{color:#5c6773}li.question dd{margin:0}li.question ul{margin:0;padding-left:16px}
dd.answer{font-weight:600}
footer{margin-top:40px;color:#8a949e;font-size:12px}
@media print{body{max-width:none}h2{break-after:avoid}.change,li.question{break-inside:avoid}}
"""


def build_report(run_dir: Path, grades: dict | None = None) -> str:
    """The complete HTML document for ``run_dir`` (and optional ``grade --json`` output)."""
    answers_path = run_dir / "answers.json"
    if not answers_path.is_file():
        raise ReportError(f"{run_dir} has no answers.json (not a pcapforge run directory)")
    answers = json.loads(answers_path.read_text(encoding="utf-8"))
    sc = answers["scenario"]
    title = f"{sc.get('title', sc.get('id', ''))} — {sc.get('difficulty', '')} / seed {sc.get('seed', '')}"
    body = [_header(answers), _timeline(answers), _changes_section(answers, run_dir), _questions(answers)]
    if grades is not None:
        body.append(_grades(answers, grades))
    generator = answers.get("generator", {})
    body.append(f"<footer>Debrief generated by pcapforge {_e(__version__)} from answers.json written by "
                f"{_e(generator.get('name', 'pcapforge'))} {_e(generator.get('version', ''))}.</footer>")
    lang = answers.get("lang", "en")
    return (f'<!DOCTYPE html>\n<html lang="{_e(lang)}"><head><meta charset="utf-8">'
            f'<meta name="viewport" content="width=device-width, initial-scale=1">'
            f"<title>{_e(title)}</title><style>{CSS}</style></head><body>"
            + "\n".join(body) + "</body></html>\n")


def write_report(run_dir: Path, out: Path | None = None, grades_path: Path | None = None) -> Path:
    grades = None
    if grades_path is not None:
        try:
            grades = json.loads(grades_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ReportError(f"{grades_path}: not JSON ({exc}); use `pcapforge grade --json` output") from exc
        if not isinstance(grades, dict):
            raise ReportError(f"{grades_path}: not `pcapforge grade --json` output")
    html = build_report(run_dir, grades)
    out = out or run_dir / "report.html"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(html, encoding="utf-8", newline="\n")
    return out
