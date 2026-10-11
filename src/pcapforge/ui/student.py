"""Student mode of the web UI (``pcapforge ui --student``) and the grading job of the instructor UI.

The student handler serves only the exercise list, the exercise pages with their answer form, the
three hand-out files of the student zip (capture, ``briefing.md``, ``submission_template.yaml``)
and the stylesheet. The answer key never leaves the server: questions are copied field by field
from an allow-list before they reach a page. Submissions are written to
``<run>/submissions/<slug(student)>.yaml`` in the format ``grade.load_submissions`` reads.

With a class roster (``<out>/roster.json``, see ``roster.py``) a student signs in with login +
access code and the session cookie is signed by the server; the submission file is the login's.
Without one the student's name is honour-system (a plain cookie, no password), like ``hints_used``.
The pages speak the exercise's language (``answers['lang']``); the list and login pages that of
the listed runs when they share one, else English.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import re
import tempfile
import threading
import time
from http import HTTPStatus
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler
from importlib.resources import files
from pathlib import Path
from urllib.parse import quote, unquote, urlsplit

import yaml

from pcapforge.grade import (HINTS_KEY, TEMPLATE_NAME, GradeError, Submission, grade, grade_submission, hint_cost,
                             load_submissions, submission_template)
from pcapforge.i18n import LANGS, ui
from pcapforge.pipeline import slug
from pcapforge.ui import roster, views
from pcapforge.ui.roster import RESERVED, RosterError
from pcapforge.ui.server import STATIC, App, Handler
from pcapforge.ui.views import e

COOKIE = "pcapforge_student"
SUBMISSIONS = "submissions"
GRADES = "grades.json"
MAX_NAME = 64
FAILED_LOGIN_DELAY_S = 0.5
QUESTION_FIELDS = ("id", "text", "type", "points", "hint")  # everything else of a question is answer key
SINGLE_LINE = ("ip", "mac", "number", "timestamp", "text")


# -- data ------------------------------------------------------------------------------

def clean_name(raw: str) -> str | None:
    """The student's name as typed (whitespace collapsed), or None when it cannot name a file."""
    name = " ".join(raw.split())
    if not name or len(name) > MAX_NAME or not name.isprintable():
        return None
    stem = slug(name)
    if not re.search(r"[A-Za-z0-9]", name) or stem.startswith(".") or stem.split(".")[0].lower() in RESERVED:
        return None
    return name


def student_questions(answers: dict) -> list[dict]:
    """The questions as students may see them: only ``QUESTION_FIELDS`` plus the hint cost."""
    questions = []
    for q in answers.get("questions", []):
        view = {k: q[k] for k in QUESTION_FIELDS if k in q}
        view["hint_cost"] = hint_cost(view)
        questions.append(view)
    return questions


def submission_path(directory: Path, student: str) -> Path:
    return directory / SUBMISSIONS / f"{slug(student)}.yaml"


def _lines(text: str) -> list[str]:
    return [line.strip() for line in text.splitlines() if line.strip()]


def _parse_map(text: str) -> dict | list | None:
    """``key = value`` (or ``key: value``) per line; with a line that has neither, the raw lines
    (graded as an unreadable map)."""
    pairs: dict[str, str] = {}
    for line in _lines(text):
        sep = "=" if "=" in line else ":" if ":" in line else None
        if sep is None:
            return _lines(text)
        key, value = (part.strip() for part in line.split(sep, 1))
        pairs[key] = value
    return pairs or None


def submission_from_form(questions: list[dict], form: dict[str, str]) -> dict:
    """``{question id: answer, ..., hints_used: [...]}`` from the fields ``a:<id>`` / ``h:<id>``."""
    data: dict = {}
    for q in questions:
        raw = form.get(f"a:{q['id']}", "")
        kind = q.get("type", "text")
        if kind == "set":
            data[q["id"]] = _lines(raw) or None
        elif kind == "map":
            data[q["id"]] = _parse_map(raw)
        else:
            data[q["id"]] = raw.strip() or None
    data[HINTS_KEY] = [q["id"] for q in questions if q.get("hint") and form.get(f"h:{q['id']}")]
    return data


def save_submission(directory: Path, student: str, data: dict) -> Path:
    """Write the submission atomically (temp file + replace); a resubmission overwrites."""
    path = submission_path(directory, student)
    path.parent.mkdir(exist_ok=True)
    stamp = dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    text = (f"# pcapforge submission of {student}, {stamp}\n"
            + yaml.safe_dump(data, allow_unicode=True, sort_keys=False, default_flow_style=False, width=4096))
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    return path


def load_own(directory: Path, student: str) -> Submission | None:
    path = submission_path(directory, student)
    if not path.is_file():
        return None
    try:
        return load_submissions([path])[0]
    except (OSError, GradeError):
        return None


def grade_run(directory: Path) -> dict:
    """Grade ``<run>/submissions/*.yaml`` and write ``<run>/grades.json`` (as ``pcapforge grade --json``)."""
    answers = json.loads((directory / "answers.json").read_text(encoding="utf-8"))
    paths = sorted((directory / SUBMISSIONS).glob("*.yaml"))
    if not paths:
        raise ValueError(f"no submissions in {directory / SUBMISSIONS}")
    report = grade(answers, load_submissions(paths))
    (directory / GRADES).write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    return report


def lang_of(answers: dict) -> str:
    lang = answers.get("lang", "en")
    return lang if lang in LANGS else "en"


def list_lang(items: list[dict]) -> str:
    """The language all ``items`` share, else English."""
    langs = {x["lang"] for x in items}
    return langs.pop() if len(langs) == 1 else "en"


class StudentApp:
    def __init__(self, out: Path, show_score: bool = False) -> None:
        self.out = out
        self.show_score = show_score
        self._secret: bytes | None = None
        self._secret_lock = threading.Lock()

    run_dir = App.run_dir

    def answers(self, directory: Path) -> dict:
        return json.loads((directory / "answers.json").read_text(encoding="utf-8"))

    def roster(self) -> dict[str, dict] | None:
        """The class roster (None: honour system); re-read per request, so instructor changes apply at once."""
        return roster.load(self.out)

    def secret(self) -> bytes:
        with self._secret_lock:
            if self._secret is None:
                self._secret = roster.server_secret(self.out)
            return self._secret

    def exercises(self, student: str | None) -> tuple[list[dict], bool]:
        """Runs whose seed is the student's login (case-insensitive slug), else all runs; the flag
        tells whether the list is personal."""
        found = []
        for path in sorted(self.out.glob("*/answers.json")) if self.out.is_dir() else []:
            if self.run_dir(path.parent.name) is None:
                continue
            try:
                answers = json.loads(path.read_text(encoding="utf-8"))
                sc, capture = answers["scenario"], answers["capture"]
            except (OSError, ValueError, KeyError, TypeError):
                continue
            found.append({"name": path.parent.name, "title": sc.get("title", sc.get("id", "")),
                          "difficulty": sc.get("difficulty", ""), "seed": str(sc.get("seed", "")),
                          "packets": capture.get("packets"), "duration": capture.get("duration_s"),
                          "lang": lang_of(answers),
                          "submitted": student is not None and submission_path(path.parent, student).is_file()})
        if student is None:
            return found, False
        mine = [x for x in found if slug(x["seed"]).casefold() == slug(student).casefold()]
        return (mine, True) if mine else (found, False)

    def handout(self, directory: Path, answers: dict) -> dict[str, Path | None]:
        """The student-zip files by name; None = generated on the fly (template missing on disk)."""
        files_ = {}
        capture = str(answers.get("capture", {}).get("file", ""))
        if Path(capture).name == capture and Path(capture).suffix.lower() in (".pcap", ".pcapng"):
            if (directory / capture).is_file():
                files_[capture] = directory / capture
        if (directory / "briefing.md").is_file():
            files_["briefing.md"] = directory / "briefing.md"
        files_[TEMPLATE_NAME] = directory / TEMPLATE_NAME if (directory / TEMPLATE_NAME).is_file() else None
        return files_


# -- views -----------------------------------------------------------------------------

def login_page(t: dict, roster_mode: bool, message: str = "", login: str = "") -> str:
    error = f'<p class="alert">{e(message)}</p>' if message else ""
    if roster_mode:
        form = (f'<form class="gen" method="post" action="/login"><label>{e(t["st_login"])} '
                f'<input name="login" value="{e(login)}" maxlength="{roster.MAX_NAME}" required autofocus '
                'autocomplete="username" spellcheck="false"></label>'
                f'<label>{e(t["st_code"])} <input name="code" type="password" maxlength="32" required '
                'autocomplete="current-password" spellcheck="false"></label>'
                f'<button type="submit">{e(t["st_sign_in"])}</button></form>')
    else:
        form = (f'<form class="gen" method="post" action="/login"><label>{e(t["st_name"])} '
                f'<input name="name" maxlength="{MAX_NAME}" required autofocus autocomplete="username"></label>'
                f'<button type="submit">{e(t["st_continue"])}</button></form>')
    note = t["st_roster"] if roster_mode else t["st_honour"]
    return (f'<h1>{e(t["st_exercises"])}</h1><p class="lead">{e(t["st_who"])}</p>{error}{form}'
            f'<p class="dim">{e(note)}</p>')


def exercises_page(t: dict, student: str, display: str, items: list[dict], personal: bool) -> str:
    shown = e(display) + (f' <span class="dim">({e(student)})</span>' if display != student else "")
    who = (f'<form class="inline" method="post" action="/logout"><span class="dim">{e(t["st_signed_in"])}</span> '
           f'{shown} <button type="submit">{e(t["st_sign_out"])}</button></form>')
    if not items:
        return f'<h1>{e(t["st_exercises"])}</h1>{who}<p>{e(t["st_none"])}</p>'
    rows = "".join(
        f'<tr><td><a href="/x/{quote(x["name"])}">{e(x["title"])}</a><br><span class="dim small">{e(x["name"])}'
        f'</span></td><td>{e(x["difficulty"])}</td><td>{e(x["seed"])}</td>'
        f'<td class="num">{e(x["packets"] if x["packets"] is not None else "?")}</td>'
        f'<td class="num">{e(views._duration(x["duration"])) if x["duration"] else "?"}</td>'
        f'<td>{e(t["st_done"]) if x["submitted"] else f"<span class=dim>{e(t["st_open"])}</span>"}</td></tr>'
        for x in items)
    head = "".join(f'<th{" class=num" if i in (3, 4) else ""}>{e(c)}</th>' for i, c in enumerate(t["st_list_cols"]))
    return (f'<h1>{e(t["st_exercises"])}</h1>{who}<p class="dim">{e(t["st_mine"] if personal else t["st_all"])}</p>'
            f'<table class="grid"><thead><tr>{head}</tr></thead><tbody>{rows}</tbody></table>')


def _field(q: dict, value, t: dict) -> str:
    name = f"a:{q['id']}"
    kind = q.get("type", "text")
    if kind in SINGLE_LINE:
        text = "" if value is None else str(value[0] if isinstance(value, list) and len(value) == 1 else value)
        return (f'<input type="text" name="{e(name)}" value="{e(text)}" '
                f'placeholder="{e(t["formats"].get(kind, ""))}" autocomplete="off" spellcheck="false">')
    if isinstance(value, dict):
        text = "\n".join(f"{k} = {v if v is not None else ''}" for k, v in value.items())
    elif isinstance(value, list):
        text = "\n".join(str(v) for v in value)
    else:
        text = "" if value is None else str(value)
    placeholder = t["st_set_placeholder"] if kind == "set" else t["st_map_placeholder"]
    return (f'<textarea name="{e(name)}" rows="{max(4, text.count(chr(10)) + 2)}" placeholder="{e(placeholder)}" '
            f'spellcheck="false">{e(text)}</textarea>')


def exercise_page(name: str, answers: dict, handout: dict, briefing: str, previous: Submission | None,
                  saved: str | None) -> str:
    sc, capture = answers.get("scenario", {}), answers.get("capture", {})
    t = ui(lang_of(answers))
    labels = t["st_meta"]
    meta = [
        (labels[0], f'{e(sc.get("id", ""))}'),
        (labels[1], f'{e(sc.get("difficulty", ""))} / <code>{e(sc.get("seed", ""))}</code>'),
        (labels[2], f'<code>{e(capture.get("file", ""))}</code> &middot; {e(capture.get("packets", "?"))} '
                    f'{e(t["st_packets"])}'
                    + (f' &middot; {e(views._duration(capture["duration_s"]))}' if capture.get("duration_s") else "")),
        (labels[3], f'{e(capture.get("start", ""))} &rarr; {e(capture.get("end", ""))}'),
        (labels[4], f'<code class="small">{e(capture.get("sha256", ""))}</code>'),
    ]
    downloads = " &middot; ".join(f'<a href="/x/{quote(name)}/files/{quote(f)}" download>{e(f)}</a>' for f in handout)
    body = [f'<h1>{e(sc.get("title", name))}</h1>', f'<p class="dim">{e(name)}</p>']
    if sc.get("summary"):
        body.append(f'<p>{e(" ".join(str(sc["summary"]).split()))}</p>')
    body += [views._kv(meta), f'<h2>{e(t["st_downloads"])}</h2>', f"<p>{downloads}</p>"]
    if briefing:
        body += [f'<h2>{e(t["st_briefing"])}</h2>', f'<pre class="briefing">{e(briefing)}</pre>']
    questions = student_questions(answers)
    given = previous.answers if previous else {}
    used = given.get(HINTS_KEY) or []
    used = {str(u).strip() for u in (used if isinstance(used, list) else [used])}
    items = []
    for q in questions:
        hint = ""
        if q.get("hint"):
            checked = " checked" if q["id"] in used else ""
            label = t["st_used_hint"].format(cost=q["hint_cost"], points=t["points"])
            hint = (f'<details><summary>{e(t["st_hint"])}</summary>'
                    f'<p class="dim">{e(" ".join(str(q["hint"]).split()))}</p>'
                    f'<label class="check"><input type="checkbox" name="{e("h:" + q["id"])}" value="1"{checked}> '
                    f'{e(label)}</label></details>')
        text = "<br>".join(e(line) for line in str(q.get("text", "")).strip().splitlines())
        items.append(f'<li><p>{text} <span class="dim">[{e(q.get("type", "text"))}, {e(q.get("points", ""))} '
                     f'{e(t["points"])}]</span></p>{_field(q, given.get(q["id"]), t)}{hint}</li>')
    body.append(f'<h2>{e(t["st_questions"].format(n=len(questions)))}</h2>')
    if saved:
        body.append(f'<p class="dim">{e(t["st_prefilled"].format(saved=saved))}</p>')
    body.append(f'<form class="answers" method="post" action="/x/{quote(name)}"><ol class="questions">'
                + "".join(items) + f'</ol><p class="dim">{e(t["st_hint_note"])}</p>'
                f'<button type="submit">{e(t["st_submit"])}</button></form>')
    return "".join(body)


def submitted_page(t: dict, name: str, title: str, saved: str, graded: dict | None) -> str:
    link = f'<a href="/x/{quote(name)}">{e(title)}</a>'
    body = [f'<h1>{e(t["st_submitted"])}</h1><p>{e(t["st_saved"]).format(title=link, saved=e(saved))}</p>']
    if graded is None:
        return "".join(body) + f'<p class="dim">{e(t["st_graded_later"])}</p>'
    css = {"correct": "", "partial": "alert", "wrong": "dim", "blank": "dim"}
    rows = "".join(
        f'<tr><td class="num">{i}</td><td>{e(q["id"])}</td><td class="{css.get(q["result"], "")}">'
        f'{e(t["st_results"].get(q["result"], q["result"]))}</td><td class="num">{q["score"]:g}/{e(q["points"])}</td>'
        f'<td class="num dim">{f"-{q["hint_penalty"]}" if q["hint_penalty"] else ""}</td></tr>'
        for i, q in enumerate(graded["questions"], 1))
    head = "".join(f'<th{"" if i in (1, 2) else " class=num"}>{e(c)}</th>' for i, c in enumerate(t["st_result_cols"]))
    body += [f'<h2>{e(t["st_score"])} {graded["score"]:g}/{e(graded["max"])} ({graded["percent"]:g} %)</h2>',
             f'<table class="grid"><thead><tr>{head}</tr></thead><tbody>{rows}</tbody></table>']
    return "".join(body)


# -- handler ---------------------------------------------------------------------------

class StudentHandler(BaseHTTPRequestHandler):
    """Student routes only; Host/Origin checks and response helpers are the instructor handler's."""

    app: StudentApp
    allowed_hosts: set[str] | None
    server_version = Handler.server_version
    log_message = Handler.log_message
    _host_ok = Handler._host_ok
    _origin_ok = Handler._origin_ok
    _form = Handler._form
    _redirect = Handler._redirect
    _headers = Handler._headers
    _send = Handler._send
    _send_file = Handler._send_file

    def do_GET(self) -> None:  # noqa: N802
        if not self._host_ok():
            return
        try:
            self._get(unquote(urlsplit(self.path).path))
        except RosterError:
            self._broken(roster_broken=True)
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            self._broken()

    def do_POST(self) -> None:  # noqa: N802
        form = self._form()  # read the body first: refusing before it resets the client's connection
        if not self._host_ok() or not self._origin_ok():
            return
        try:
            self._post(unquote(urlsplit(self.path).path), form)
        except RosterError:
            self._broken(roster_broken=True)
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            self._broken()

    def _get(self, path: str) -> None:
        if path == "/":
            student = self._student()
            items, personal = self.app.exercises(student)
            lang = list_lang(items)
            t = ui(lang)
            if student is None:
                return self._page(lang, t["st_exercises"], login_page(t, self.app.roster() is not None))
            return self._page(lang, t["st_exercises"],
                              exercises_page(t, student, self._display(student), items, personal))
        if m := re.fullmatch(r"/x/([^/]+)", path):
            return self._exercise(m.group(1))
        if m := re.fullmatch(r"/x/([^/]+)/submitted", path):
            return self._submitted(m.group(1))
        if m := re.fullmatch(r"/x/([^/]+)/files/([^/]+)", path):
            return self._file(m.group(1), m.group(2))
        if (m := re.fullmatch(r"/static/([^/]+)", path)) and m.group(1) in STATIC:
            return self._send(HTTPStatus.OK, files("pcapforge.ui").joinpath("static", m.group(1)).read_bytes(),
                              STATIC[m.group(1)])
        return self._not_found()

    def _post(self, path: str, form: dict[str, str]) -> None:
        if path == "/login":
            return self._login(form)
        if path == "/logout":
            return self._redirect_cookie("/", "", 0)
        if m := re.fullmatch(r"/x/([^/]+)", path):
            directory = self.app.run_dir(m.group(1))
            if directory is None:
                return self._not_found()
            student = self._student()
            if student is None:
                return self._redirect("/")
            data = submission_from_form(student_questions(self.app.answers(directory)), form)
            save_submission(directory, student, data)
            return self._redirect(f"/x/{quote(m.group(1))}/submitted")
        return self._not_found()

    def _login(self, form: dict[str, str]) -> None:
        lang = list_lang(self.app.exercises(None)[0])
        t = ui(lang)
        current = self.app.roster()
        if current is not None:
            login = roster.check(current, form.get("login", ""), form.get("code", ""))
            if login is None:
                time.sleep(FAILED_LOGIN_DELAY_S)
                typed = form.get("login", "").strip()[:roster.MAX_NAME]
                return self._page(lang, t["st_exercises"], login_page(t, True, t["st_bad_login"], typed),
                                  status=HTTPStatus.FORBIDDEN)
            return self._redirect_cookie("/", roster.sign(self.app.secret(), current, login), roster.SESSION_S)
        name = clean_name(form.get("name", ""))
        if name is None:
            return self._page(lang, t["st_exercises"], login_page(t, False, t["st_bad_name"].format(max=MAX_NAME)),
                              status=HTTPStatus.BAD_REQUEST)
        return self._redirect_cookie("/", quote(name, safe=""), 30 * 24 * 3600)

    # -- pages --------------------------------------------------------------------------
    def _exercise(self, name: str) -> None:
        directory = self.app.run_dir(name)
        if directory is None:
            return self._not_found()
        student = self._student()
        if student is None:
            return self._redirect("/")
        answers = self.app.answers(directory)
        briefing = directory / "briefing.md"
        text = briefing.read_text(encoding="utf-8") if briefing.is_file() else ""
        previous = load_own(directory, student)
        saved = self._saved(directory, student) if previous else None
        title = answers.get("scenario", {}).get("title", name)
        self._page(lang_of(answers), title,
                   exercise_page(name, answers, self.app.handout(directory, answers), text, previous, saved))

    def _submitted(self, name: str) -> None:
        directory = self.app.run_dir(name)
        if directory is None:
            return self._not_found()
        student = self._student()
        own = load_own(directory, student) if student else None
        if own is None:
            return self._redirect(f"/x/{quote(name)}")
        answers = self.app.answers(directory)
        graded = grade_submission(answers, own) if self.app.show_score else None
        title = answers.get("scenario", {}).get("title", name)
        t = ui(lang_of(answers))
        self._page(lang_of(answers), t["st_submitted"],
                   submitted_page(t, name, title, self._saved(directory, student), graded))

    def _file(self, name: str, filename: str) -> None:
        directory = self.app.run_dir(name)
        if directory is None:
            return self._not_found()
        if self._student() is None:
            return self._redirect("/")
        answers = self.app.answers(directory)
        handout = self.app.handout(directory, answers)
        if filename not in handout:
            return self._not_found()
        source = handout[filename]
        if source is None:  # no template on disk: the same one package.py puts into the student zip
            body = submission_template(answers).encode("utf-8")
            self._headers(HTTPStatus.OK, "text/plain; charset=utf-8", len(body))
            self.send_header("Content-Disposition", f'attachment; filename="{TEMPLATE_NAME}"')
            self.end_headers()
            self.wfile.write(body)
            return
        kind = ("application/vnd.tcpdump.pcap" if source.suffix.lower() in (".pcap", ".pcapng")
                else "text/plain; charset=utf-8")
        self._send_file(source, kind, attachment=True)

    # -- helpers ------------------------------------------------------------------------
    def _student(self) -> str | None:
        """The signed-in student: with a roster the login of a valid signed session, else the honour name."""
        try:
            morsel = SimpleCookie(self.headers.get("Cookie") or "").get(COOKIE)
        except CookieError:
            return None
        if not morsel or not morsel.value:
            return None
        current = self.app.roster()
        if current is None:  # a signed session has a raw "|"; honour names are percent-encoded
            return None if "|" in morsel.value else clean_name(unquote(morsel.value))
        return roster.session_login(self.app.secret(), current, morsel.value)

    def _display(self, student: str) -> str:
        current = self.app.roster()
        return str(current[student]["name"]) if current and student in current else student

    @staticmethod
    def _saved(directory: Path, student: str) -> str:
        stamp = submission_path(directory, student).stat().st_mtime
        return dt.datetime.fromtimestamp(stamp, dt.UTC).strftime("%Y-%m-%d %H:%M:%S UTC")

    def _redirect_cookie(self, location: str, value: str, max_age: int) -> None:
        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header("Location", location)
        self.send_header("Set-Cookie", f"{COOKIE}={value}; Path=/; Max-Age={max_age}; HttpOnly; SameSite=Strict")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _page(self, lang: str, title: str, body: str, status: HTTPStatus = HTTPStatus.OK) -> None:
        t = ui(lang)
        try:
            student = self._student()
        except RosterError:
            student = None
        html = views.page(title, body, self.app.out, t["st_exercises"], nav=((t["st_exercises"], "/"),),
                          meta=t["st_mode"] + (f" · {student}" if student else ""), lang=lang)
        self._send(status, html.encode("utf-8"), "text/html; charset=utf-8")

    def _list_lang(self) -> str:
        return list_lang(self.app.exercises(None)[0])

    def _not_found(self) -> None:
        lang = self._list_lang()
        self._page(lang, "404", f'<h1>404</h1><p>{e(ui(lang)["st_not_found"])}</p>', status=HTTPStatus.NOT_FOUND)

    def _broken(self, roster_broken: bool = False) -> None:
        """A run (or the roster) that cannot be read; no details (they could quote the answer key)."""
        lang = self._list_lang()
        message = ui(lang)["st_roster_broken" if roster_broken else "st_broken"]
        self._page(lang, "error", views.error(message), status=HTTPStatus.INTERNAL_SERVER_ERROR)
