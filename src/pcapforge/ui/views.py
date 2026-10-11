"""HTML of the web UI pages. Plain server-side markup; every value from scenarios, run
directories or form input is escaped with ``e``."""

from __future__ import annotations

import datetime as dt
import json
from html import escape
from pathlib import Path
from urllib.parse import quote

from pcapforge import __version__
from pcapforge.i18n import LANGS
from pcapforge.scenario import Scenario, parse_duration
from pcapforge.ui.jobs import Job


def e(value) -> str:
    return escape(str(value), quote=True)


def page(title: str, body: str, out_root: Path, active: str = "") -> str:
    nav = "".join(f'<a href="{href}"{" class=on" if name == active else ""}>{name}</a>'
                  for name, href in (("scenarios", "/"), ("runs", "/runs"), ("jobs", "/jobs")))
    return (
        '<!DOCTYPE html>\n<html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f'<title>{e(title)} · pcapforge</title>'
        '<link rel="stylesheet" href="/static/style.css"><script src="/static/app.js" defer></script></head>'
        '<body><header><canvas id="rain" aria-hidden="true"></canvas><div class="bar">'
        f'<a class="brand" href="/">pcapforge</a><nav>{nav}</nav>'
        f'<span class="meta">v{e(__version__)} &middot; out: {e(out_root)}</span></div></header>'
        f'<main>{body}</main></body></html>\n')


def _kv(rows: list[tuple[str, str]]) -> str:
    """Key/value table; values are HTML already."""
    return '<table class="kv">' + "".join(f"<tr><th>{e(k)}</th><td>{v}</td></tr>" for k, v in rows) + "</table>"


def _compact(value) -> str:
    if isinstance(value, dict):
        if set(value) == {"choose"}:
            return "one of " + ", ".join(_compact(v) for v in value["choose"])
        if set(value) == {"range"}:
            lo, hi = value["range"]
            return f"{lo}..{hi}"
        return ", ".join(f"{k}={_compact(v)}" for k, v in value.items())
    if isinstance(value, list):
        return "[" + ", ".join(_compact(v) for v in value) + "]"
    if isinstance(value, bool):
        return "on" if value else "off"
    return str(value)


def _size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return str(n)


def _duration(seconds: float) -> str:
    seconds = int(round(seconds))
    h, rest = divmod(seconds, 3600)
    m, s = divmod(rest, 60)
    return f"{h}h{m:02d}m" if h else (f"{m}m{s:02d}s" if m else f"{s}s")


# -- scenarios -------------------------------------------------------------------------

def catalog(scenarios: dict[str, Scenario]) -> str:
    rows = []
    for sid, sc in sorted(scenarios.items()):
        techniques = " ".join(m["id"] for m in sc.doc.get("mitre", []) if "when" not in m)
        rows.append(f'<tr><td class="nw"><a href="/scenarios/{quote(sid)}">{e(sid)}</a></td><td>{e(sc.line.upper())}</td>'
                    f'<td>{e(sc.title)}</td><td class="nw">{e(" / ".join(sc.difficulties))}</td>'
                    f'<td class="dim">{e(techniques) or "&ndash;"}</td></tr>')
    if not rows:
        return "<h1>scenarios</h1><p>No scenarios found.</p>"
    return ("<h1>scenarios</h1>"
            '<table class="grid"><thead><tr><th>id</th><th>line</th><th>title</th><th>levels</th>'
            "<th>att&amp;ck</th></tr></thead><tbody>" + "".join(rows) + "</tbody></table>")


def scenario(sc: Scenario, runs: list[dict]) -> str:
    doc = sc.doc
    mitre = "".join(f'<tr><td>{e(m["framework"])}</td><td>{e(m["id"])}</td><td>{e(m["name"])}</td>'
                    f'<td class="dim">{e("when " + m["when"]) if "when" in m else ""}</td></tr>'
                    for m in doc.get("mitre", []))
    levels = _levels_matrix(sc)
    questions = "".join(f"<li>{e(' '.join(str(q['text']).split()))}"
                        f'{" <span class=dim>[when " + e(q["when"]) + "]</span>" if "when" in q else ""}</li>'
                        for q in doc["questions"])
    existing = [r for r in runs if r["scenario"] == sc.id]
    body = [
        f'<h1>{e(sc.id)}</h1><p class="lead">{e(sc.title)}</p>',
        f'<p>{e(" ".join(doc["summary"].split()))}</p>',
        _kv([("line", e(sc.line.upper())), ("version", e(doc.get("version", 1))),
             ("license", e(doc.get("license", ""))), ("source", f"<code>{e(sc.path)}</code>")]),
        "<h2>generate</h2>", _generate_form(sc),
        "<h2>levels</h2>", levels,
    ]
    if mitre:
        body.append('<h2>att&amp;ck</h2><table class="grid"><tbody>' + mitre + "</tbody></table>")
    body.append(f"<h2>questions ({len(doc['questions'])})</h2><ol class=\"questions\">{questions}</ol>")
    if existing:
        body.append("<h2>runs of this scenario</h2>" + _runs_table(existing))
    return "".join(body)


def _levels_matrix(sc: Scenario) -> str:
    """One row per knob (duration, each impairment, each var), one column per level; a value that
    differs from the level before is lit, one that repeats it is dimmed."""
    names = sc.difficulties
    levels = [sc.level(n) for n in names]
    rows: list[tuple[str, list]] = [("duration", [lv["duration"] for lv in levels])]
    keys: list[tuple[str, str]] = []
    for section in ("impairments", "vars"):
        for lv in levels:
            keys += [(section, k) for k in lv.get(section, {}) if (section, k) not in keys]
    rows += [(k if section == "vars" else f"sensor.{k}", [lv.get(section, {}).get(k) for lv in levels])
             for section, k in keys]
    out = []
    for label, values in rows:
        cells = []
        for i, v in enumerate(values):
            text = "&ndash;" if v is None else e(_compact(v))
            kind = "" if i == 0 else (" class=lit" if v != values[i - 1] else " class=dim")
            cells.append(f"<td{kind}>{text}</td>")
        out.append(f'<tr><th>{e(label)}</th>{"".join(cells)}</tr>')
    head = "".join(f"<th>{e(n)}</th>" for n in names)
    return (f'<table class="grid levels"><thead><tr><th></th>{head}</tr></thead><tbody>'
            + "".join(out) + "</tbody></table>")


def _generate_form(sc: Scenario) -> str:
    levels = "".join(f'<option{" selected" if d == "medium" else ""}>{e(d)}</option>' for d in sc.difficulties)
    langs = "".join(f"<option>{e(lang)}</option>" for lang in LANGS)
    return (
        f'<form class="gen" method="post" action="/scenarios/{quote(sc.id)}/generate">'
        f'<label>level <select name="difficulty">{levels}</select></label>'
        '<label>seed <input name="seed" value="1" maxlength="64" required></label>'
        '<label>duration <input name="duration" placeholder="level default" size="11" '
        'title="e.g. 20m, 2h; empty = the level\'s duration"></label>'
        f'<label>language <select name="lang">{langs}</select></label>'
        '<label>format <select name="format"><option>pcap</option><option>pcapng</option></select></label>'
        '<label class="check"><input type="checkbox" name="siem" checked> siem + detections</label>'
        '<label class="check"><input type="checkbox" name="zeek"> zeek logs</label>'
        '<button type="submit">generate</button></form>')


# -- runs ------------------------------------------------------------------------------

def run_summary(name: str, answers: dict, mtime: float) -> dict:
    sc, capture = answers.get("scenario", {}), answers.get("capture", {})
    return {"name": name, "scenario": sc.get("id", "?"), "difficulty": sc.get("difficulty", "?"),
            "seed": sc.get("seed", "?"), "packets": capture.get("packets"),
            "duration": capture.get("duration_s"), "lang": answers.get("lang", "en"), "mtime": mtime}


def _runs_table(runs: list[dict]) -> str:
    rows = "".join(
        f'<tr><td><a href="/runs/{quote(r["name"])}">{e(r["name"])}</a></td><td>{e(r["difficulty"])}</td>'
        f'<td>{e(r["seed"])}</td><td class="num">{e(r["packets"] if r["packets"] is not None else "?")}</td>'
        f'<td class="num">{e(_duration(r["duration"])) if r["duration"] else "?"}</td><td>{e(r["lang"])}</td>'
        f'<td class="dim">{dt.datetime.fromtimestamp(r["mtime"]).strftime("%Y-%m-%d %H:%M")}</td></tr>'
        for r in runs)
    return ('<table class="grid"><thead><tr><th>run</th><th>level</th><th>seed</th><th>packets</th>'
            "<th>length</th><th>lang</th><th>written</th></tr></thead><tbody>" + rows + "</tbody></table>")


def runs(items: list[dict]) -> str:
    if not items:
        return '<h1>runs</h1><p>No runs yet. Pick a scenario and <a href="/">generate</a> one.</p>'
    return "<h1>runs</h1>" + _runs_table(items)


def run(name: str, directory: Path, answers: dict, packages: dict[str, Path], active: list[Job]) -> str:
    sc, capture, topo = answers["scenario"], answers["capture"], answers["topology"]
    clock = capture.get("sensor_clock") or {}
    meta = [
        ("scenario", f'<a href="/scenarios/{quote(sc["id"])}">{e(sc["id"])}</a> &middot; {e(sc.get("title", ""))}'),
        ("level / seed", f'{e(sc["difficulty"])} / <code>{e(sc["seed"])}</code>'
                         + (f' (behaviour of <code>{e(sc["base_seed"])}</code>)'
                            if sc.get("base_seed") not in (None, sc["seed"]) else "")),
        ("capture", f'<code>{e(capture["file"])}</code> &middot; {e(capture["packets"])} packets &middot; '
                    f'{e(_duration(capture["duration_s"]))}'),
        ("window", f'{e(capture["start"])} &rarr; {e(capture["end"])}'),
        ("sha-256", f'<code class="small">{e(capture["sha256"])}</code>'),
        ("sensor", f'{e(capture["sensor_subnet"])}'
                   + (f' &middot; clock offset {clock["offset_s"]:+.3f} s, drift {clock["drift_ppm"]:+.1f} ppm'
                      if clock else "")),
        ("site", f'{e(topo.get("site_name", ""))} &middot; <code>{e(topo.get("domain", ""))}</code>'),
    ]
    body = [f"<h1>{e(name)}</h1>", _kv(meta)]
    if active:
        body.append("<p class=\"busy\">" + " ".join(
            f'<a href="/jobs/{j.id}">{e(j.kind)} {e(j.state)}</a>' for j in active) + "</p>")
    body += ["<h2>actions</h2>", _actions(name, directory, packages),
             "<h2>network</h2>", topology_svg(topo), _hosts_table(topo)]
    timeline = answers.get("timeline", [])
    if timeline:
        body += [f"<h2>timeline ({len(timeline)})</h2>", _timeline(timeline, capture)]
    body += [f"<h2>answer key ({len(answers.get('questions', []))} questions)</h2>", _questions(answers)]
    body += ["<h2>files</h2>", _files(name, directory)]
    return "".join(body)


def _post(action: str, name: str, label: str, extra: str = "") -> str:
    return (f'<form method="post" action="/runs/{quote(name)}/{action}">{extra}'
            f'<button type="submit">{e(label)}</button></form>')


def _actions(name: str, directory: Path, packages: dict[str, Path]) -> str:
    link = lambda path, label: f'<a href="/runs/{quote(name)}/files/{quote(path)}">{e(label)}</a>'  # noqa: E731
    rows = [
        ("verify", _post("verify", name, "verify"), "integrity and answer-key checks with tshark"),
        ("siem", _post("export", name, "export", '<label class="check"><input type="checkbox" name="zeek"> zeek'
                       "</label>"),
         " &middot; ".join(link(f"{d}/", f"{d}/") for d in ("siem", "detections", "zeek") if (directory / d).is_dir())
         or "SIEM JSONL, detections"),
        ("debrief", _post("report", name, "build"),
         link("report.html", "open report.html") if (directory / "report.html").is_file() else "instructor HTML report"),
        ("package", _post("package", name, "zip"),
         " &middot; ".join(f'<a href="/runs/{quote(name)}/package/{kind}">{e(path.name)}</a>'
                           for kind, path in packages.items()) or "student / instructor zips"),
        ("ctfd", _post("ctfd", name, "export"),
         link("ctfd/", "ctfd/") if (directory / "ctfd").is_dir() else "ctfcli challenge.yml per question"),
    ]
    return ('<table class="actions">' + "".join(f"<tr><th>{e(k)}</th><td>{form}</td><td>{note}</td></tr>"
                                                for k, form, note in rows) + "</table>")


def _hosts_table(topo: dict) -> str:
    rows = []
    for h in topo["hosts"]:
        ips = "<br>".join(f'{e(i["ip"])} <span class="dim">{e(i["subnet"])}</span>' for i in h["interfaces"])
        v6 = "<br>".join(f'{e(a)} <span class="dim">{e(k)}</span>' for k, a in (h.get("ipv6") or {}).items())
        macs = "<br>".join(e(i["mac"]) for i in h["interfaces"])
        rows.append(f'<tr><td>{e(h["name"])}</td><td>{e(h["role"])}</td><td>{e(h.get("vendor", ""))} '
                    f'<span class="dim">{e(h["device"])}</span></td><td>{ips}</td><td class="small">{v6}</td>'
                    f'<td class="small dim">{macs}</td></tr>')
    return ('<details><summary>hosts ({})</summary><table class="grid"><thead><tr><th>name</th><th>role</th>'
            "<th>device</th><th>ipv4</th><th>ipv6</th><th>mac</th></tr></thead><tbody>").format(len(rows)) \
        + "".join(rows) + "</tbody></table></details>"


def _timeline(items: list[dict], capture: dict) -> str:
    start = dt.datetime.fromisoformat(capture["start"].replace("Z", "+00:00")).timestamp()
    rows = []
    for t in items:
        offset = float(t["epoch"]) - start
        mark = '<span class="alert">incident</span>' if t.get("incident") else '<span class="dim">normal</span>'
        techniques = " ".join(t.get("techniques", []))
        rows.append(f'<tr{" class=hot" if t.get("incident") else ""}><td class="num">+{e(_duration(offset))}</td>'
                    f'<td class="num">{e(t.get("frame", ""))}</td><td>{mark}</td><td>{e(t["title"])}</td>'
                    f'<td class="dim">{e(t["actor"])} {e(techniques)}</td></tr>')
    return ('<table class="grid"><thead><tr><th>t</th><th>frame</th><th></th><th>event</th><th>actor</th>'
            "</tr></thead><tbody>" + "".join(rows) + "</tbody></table>")


def _questions(answers: dict) -> str:
    items = []
    for q in answers.get("questions", []):
        answer = q["answer"] if isinstance(q["answer"], str) else json.dumps(q["answer"], ensure_ascii=False)
        checks = "".join(f'<code class="small">{e(c["filter"])}</code>' for c in q.get("checks", []))
        hint = f'<p class="dim">hint: {e(q["hint"])}</p>' if q.get("hint") else ""
        items.append(f'<li><p>{e(" ".join(str(q["text"]).split()))} <span class="dim">[{e(q["type"])}, '
                     f'{e(q["points"])} pts]</span></p>{hint}<p class="answer">&gt; <code>{e(answer)}</code></p>'
                     f"{checks}</li>")
    return ('<details class="spoiler"><summary>reveal answers</summary><ol class="questions">'
            + "".join(items) + "</ol></details>")


def _files(name: str, directory: Path) -> str:
    return _entries(name, directory, "")


def _entries(name: str, directory: Path, rel: str) -> str:
    """Entries of ``directory`` (``rel`` inside the run); a sub-directory shows its file count and size."""
    rows = []
    for path in sorted(directory.iterdir(), key=lambda p: (not p.is_dir(), p.name)):
        sub = f"{rel}{path.name}" + ("/" if path.is_dir() else "")
        if path.is_dir():
            inner = [p for p in path.rglob("*") if p.is_file()]
            size = f"{len(inner)} files, {_size(sum(p.stat().st_size for p in inner))}"
        else:
            size = _size(path.stat().st_size)
        rows.append(f'<tr><td><a href="/runs/{quote(name)}/files/{quote(sub)}">{e(path.name)}'
                    f'{"/" if path.is_dir() else ""}</a></td><td class="num">{e(size)}</td></tr>')
    return '<table class="grid files"><tbody>' + "".join(rows) + "</tbody></table>"


def listing(name: str, directory: Path, rel: str) -> str:
    """Index of a sub-directory of a run (``rel`` ends with a slash)."""
    return (f'<h1><a href="/runs/{quote(name)}">{e(name)}</a> / {e(rel)}</h1>' + _entries(name, directory, rel))


# -- topology --------------------------------------------------------------------------

BOX_W, BOX_H, GAP, COLS = 186, 46, 10, 4
LEFT = 210           # bands start here; routers sit left of them
BAND_HEAD = 26


def topology_svg(topo: dict) -> str:
    """Subnets as bands of host boxes; multi-homed hosts (routers, firewalls) to the left, wired to
    every band they sit in. The sensor's band is marked SPAN."""
    subnets = topo["subnets"]
    routers = [h for h in topo["hosts"] if len(h["interfaces"]) > 1]
    members = {s["id"]: [h for h in topo["hosts"] if len(h["interfaces"]) == 1 and h["interfaces"][0]["subnet"] == s["id"]]
               for s in subnets}
    width = LEFT + COLS * (BOX_W + GAP) + GAP
    parts, bands, y = [], {}, 8
    for s in subnets:
        rows = max(1, -(-len(members[s["id"]]) // COLS))
        height = BAND_HEAD + rows * (BOX_H + GAP) + GAP
        bands[s["id"]] = (y, height)
        parts.append(f'<g class="band{" sensor" if s.get("sensor") else ""}">'
                     f'<rect x="{LEFT}" y="{y}" width="{width - LEFT - 2}" height="{height}"/>'
                     f'<text class="head" x="{LEFT + 10}" y="{y + 17}">{e(s["id"])}  {e(s["cidr"])}  gw {e(s["gateway"])}'
                     f'{"  [SPAN]" if s.get("sensor") else ""}</text></g>')
        for n, h in enumerate(members[s["id"]]):
            col, row = n % COLS, n // COLS
            parts.append(_host_box(h, LEFT + GAP + col * (BOX_W + GAP), y + BAND_HEAD + row * (BOX_H + GAP)))
        y += height + 14
    total = y
    taken: list[tuple[float, float]] = []
    for h in routers:
        centers = [bands[i["subnet"]][0] + bands[i["subnet"]][1] / 2 for i in h["interfaces"] if i["subnet"] in bands]
        if not centers:
            continue
        top = sum(centers) / len(centers) - BOX_H / 2
        while any(abs(top - t) < BOX_H + GAP for t, _ in taken):
            top += BOX_H + GAP
        taken.append((top, 0))
        x = 12
        for i in h["interfaces"]:
            if i["subnet"] in bands:
                by, bh = bands[i["subnet"]]
                cy = by + bh / 2
                parts.append(f'<path class="wire" d="M{x + BOX_W} {top + BOX_H / 2} H{LEFT - 14} V{cy} H{LEFT}"/>'
                             f'<text class="tiny" x="{LEFT - 8}" y="{cy - 4}" text-anchor="end">{e(i["ip"])}</text>')
        parts.append(_host_box(h, x, top, router=True, show_ip=False))
        total = max(total, top + BOX_H + 8)
    return (f'<svg class="topo" viewBox="0 0 {width} {total:.0f}" role="img" aria-label="network topology">'
            + "".join(parts) + "</svg>")


def _host_box(h: dict, x: float, y: float, router: bool = False, show_ip: bool = True) -> str:
    v6 = ' <tspan class="v6">v6</tspan>' if h.get("ipv6") else ""
    second = h["interfaces"][0]["ip"] if show_ip else h["role"]
    return (f'<g class="host{" router" if router else ""}"><title>{e(h["name"])} &#10;{e(h["device"])}'
            f'{"".join(" &#10;" + e(i["ip"]) for i in h["interfaces"])}</title>'
            f'<rect x="{x}" y="{y}" width="{BOX_W}" height="{BOX_H}"/>'
            f'<text x="{x + 8}" y="{y + 17}">{e(h["name"])}{v6}</text>'
            f'<text class="sub" x="{x + 8}" y="{y + 34}">{e(second)} &middot; {e(h["role"] if show_ip else h["device"])}'
            "</text></g>")


# -- jobs ------------------------------------------------------------------------------

def jobs(items: list[Job]) -> str:
    if not items:
        return "<h1>jobs</h1><p>Nothing ran yet in this session.</p>"
    rows = "".join(
        f'<tr><td class="num"><a href="/jobs/{j.id}">#{j.id}</a></td><td>{e(j.kind)}</td><td>{e(j.title)}</td>'
        f'<td class="state-{e(j.state)}">{e(j.state)}</td><td class="dim">{e(j.result or j.error or "")}</td></tr>'
        for j in items)
    return ('<h1>jobs</h1><table class="grid"><thead><tr><th></th><th>kind</th><th>what</th><th>state</th>'
            "<th>outcome</th></tr></thead><tbody>" + rows + "</tbody></table>")


def job(j: Job) -> str:
    target = f'<a href="/runs/{quote(j.run)}">{e(j.run)}</a>' if j.run else "&ndash;"
    return (f'<h1>job #{j.id} &middot; {e(j.kind)}</h1><p class="lead">{e(j.title)}</p>'
            f'<div id="job" data-id="{j.id}" data-state="{e(j.state)}">'
            + _kv([("state", f'<span id="job-state" class="state-{e(j.state)}">{e(j.state)}</span>'),
                   ("progress", f'<span id="job-bar">{e(progress_bar(j.progress))}</span>'),
                   ("run", f'<span id="job-run">{target}</span>'),
                   ("outcome", f'<span id="job-result">{e(j.result or j.error or "")}</span>')])
            + f'<pre id="job-log">{e(chr(10).join(j.log))}</pre></div>')


def progress_bar(fraction: float | None, width: int = 32) -> str:
    if fraction is None:
        return ""
    filled = int(round(fraction * width))
    return f"[{'#' * filled}{'.' * (width - filled)}] {fraction * 100:3.0f}%"


def error(message: str) -> str:
    return f'<h1>error</h1><pre class="err">{e(message)}</pre>'


def duration_or_none(text: str) -> float | None:
    return parse_duration(text) if text.strip() else None
