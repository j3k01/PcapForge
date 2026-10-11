"""Local web UI (``pcapforge ui``): scenario catalog, generation with progress, run directories
with their answer key, network map and files, and the run actions of the CLI (verify, export,
report, package, CTFd).

Standard library only: ``http.server`` with one thread per request and the job worker of
``jobs.py``. It binds to 127.0.0.1 by default and checks the ``Host`` header (no DNS rebinding)
and the ``Origin`` of every POST (no cross-site form posts), because it writes into the output
directory and runs tshark / Zeek.
"""

from __future__ import annotations

import json
import mimetypes
import re
import shutil
import sys
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

from pcapforge.i18n import LANGS
from pcapforge.scenario import ScenarioError, discover
from pcapforge.ui import batch, views
from pcapforge.ui.jobs import Job, Jobs

_NAME = re.compile(r"[A-Za-z0-9._-]+")
STATIC = {"style.css": "text/css; charset=utf-8", "app.js": "text/javascript; charset=utf-8"}
TEXT_SUFFIXES = {".md", ".yaml", ".yml", ".jsonl", ".log", ".rules", ".txt", ".csv", ".kql", ".spl"}
INLINE_TYPES = {".html": "text/html; charset=utf-8", ".json": "application/json; charset=utf-8"}
RUN_ACTIONS = ("verify", "export", "report", "package", "ctfd", "grade", "traffic")
LOOPBACK = {"127.0.0.1", "localhost", "::1"}


class App:
    def __init__(self, out: Path, scenarios_dir: Path | None = None) -> None:
        self.out = out
        self.scenarios_dir = scenarios_dir
        self.jobs = Jobs()

    def scenarios(self):
        return discover(self.scenarios_dir)

    def run_dir(self, name: str) -> Path | None:
        """The run directory ``name`` under the output root, if it is one."""
        if not _NAME.fullmatch(name) or name in (".", ".."):
            return None
        directory = self.out / name
        return directory if (directory / "answers.json").is_file() else None

    def runs(self) -> list[dict]:
        if not self.out.is_dir():
            return []
        found = []
        for answers_path in self.out.glob("*/answers.json"):
            try:
                answers = json.loads(answers_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            found.append(views.run_summary(answers_path.parent.name, answers, answers_path.stat().st_mtime))
        return sorted(found, key=lambda r: -r["mtime"])

    def packages(self, name: str) -> dict[str, Path]:
        return {kind: path for kind in ("student", "instructor")
                if (path := self.out / f"{name}-{kind}.zip").is_file()}

    # -- jobs ---------------------------------------------------------------------------
    def submit_generate(self, scenario, form: dict[str, str]) -> list[Job]:
        """One generate job per seed: the ``seeds`` list (one per line) if given, else ``seed``.
        Everything is validated before the first job is queued."""
        from pcapforge.pipeline import generate

        difficulty = form.get("difficulty", "medium")
        if difficulty not in scenario.difficulties:
            raise ValueError(f"scenario {scenario.id} has no level {difficulty!r}")
        if form.get("seeds", "").strip():
            seeds = batch.parse_seeds(form["seeds"])
            if not seeds:
                raise ValueError("seeds: only comments and blank lines")
        else:
            seeds = [batch.parse_seed(form.get("seed", ""), "seed") or "1"]
        base_seed = batch.parse_seed(form.get("base_seed", ""), "base seed") or None
        lang = form.get("lang", "en")
        if lang not in LANGS:
            raise ValueError(f"language {lang!r}: one of {', '.join(LANGS)}")
        fmt = form.get("format", "pcap")
        if fmt not in ("pcap", "pcapng"):
            raise ValueError(f"format {fmt!r}: pcap or pcapng")
        duration = views.duration_or_none(form.get("duration", ""))
        siem, zeek = "siem" in form, "zeek" in form

        def work(seed: str):
            def run(job: Job) -> str:
                out = generate(scenario, difficulty, seed, self.out, base_seed=base_seed, fmt=fmt, duration=duration,
                               lang=lang, siem=siem, zeek=zeek, progress=job.note)
                job.run = out.directory.name
                failed = [c for c in out.report.checks if not c["ok"]] if out.report else []
                for check in failed:
                    job.note(f"FAIL {check['name']}: {check['detail']}")
                verdict = "VERIFY FAILED" if failed else "verified"
                return f"{out.packets} packets, {verdict}"
            return run

        suffix = (f" base {base_seed}" if base_seed else "") + (f" ({form['duration']})" if duration else "")
        return [self.jobs.submit("generate", f"{scenario.id} {difficulty} seed {seed}{suffix}", work(seed))
                for seed in seeds]

    def submit_package_all(self, scenario: str, level: str) -> list[Job]:
        """A package job for every run of ``scenario`` at ``level``."""
        if not scenario or not level:
            raise ValueError("package all: scenario and level are required")
        names = [r["name"] for r in batch.matching(self.runs(), scenario, level)]
        dirs = [(name, directory) for name in names if (directory := self.run_dir(name)) is not None]
        if not dirs:
            raise ValueError(f"package all: no runs of {scenario} at level {level}")
        return [self.submit_action("package", name, directory, {}) for name, directory in dirs]

    def submit_action(self, action: str, name: str, directory: Path, form: dict[str, str]) -> Job:
        def verify(job: Job) -> str:
            from pcapforge.verify import verify_capture

            answers = json.loads((directory / "answers.json").read_text(encoding="utf-8"))
            report = verify_capture(directory / answers["capture"]["file"], answers)
            for check in report.checks:
                job.note(f"{'ok  ' if check['ok'] else 'FAIL'} {check['name']}: {check['detail']}")
            failed = sum(not c["ok"] for c in report.checks)
            return f"{len(report.checks)} checks, " + (f"{failed} FAILED" if failed else "all ok")

        def export(job: Job) -> str:
            from pcapforge.pipeline import export_run

            paths = export_run(directory, zeek="zeek" in form)
            for rel in sorted(paths):
                job.note(rel)
            return f"{len(paths)} files"

        def report(job: Job) -> str:
            from pcapforge.report import write_report

            grades = directory / "grades.json"
            path = write_report(directory, grades_path=grades if grades.is_file() else None)
            return f"wrote {path.name}" + (" with class results" if grades.is_file() else "")

        def package(job: Job) -> str:
            from pcapforge.package import package_run

            return "wrote " + ", ".join(p.name for p in package_run(directory, self.out))

        def ctfd(job: Job) -> str:
            from pcapforge.ctfd import export_ctfd

            return f"{len(export_ctfd(directory))} challenges in ctfd/"

        def grade(job: Job) -> str:
            from pcapforge.ui.student import grade_run

            report = grade_run(directory)
            for s in report["students"]:
                job.note(f"{s['student']}: {s['score']:g}/{s['max']} ({s['percent']:g} %)")
            return f"{len(report['students'])} submissions graded, wrote grades.json"

        def traffic(job: Job) -> str:
            from pcapforge.ui.traffic import build

            return build(directory, progress=lambda fraction: setattr(job, "progress", fraction))

        work = {"verify": verify, "export": export, "report": report, "package": package, "ctfd": ctfd,
                "grade": grade, "traffic": traffic}[action]
        return self.jobs.submit(action, name, work, run=name)


class Handler(BaseHTTPRequestHandler):
    app: App
    allowed_hosts: set[str] | None  # None: any Host header (bound to a non-loopback address)
    server_version = "pcapforge-ui"

    def log_message(self, format: str, *args) -> None:  # noqa: A002 - quiet console
        pass

    # -- dispatch -----------------------------------------------------------------------
    def do_GET(self) -> None:  # noqa: N802
        if not self._host_ok():
            return
        path = unquote(urlsplit(self.path).path)
        app = self.app
        try:
            if path == "/":
                return self._page("scenarios", views.catalog(app.scenarios()), "scenarios")
            if m := re.fullmatch(r"/scenarios/([^/]+)", path):
                sc = app.scenarios().get(m.group(1))
                if sc is None:
                    return self._not_found()
                return self._page(sc.id, views.scenario(sc, app.runs()), "scenarios")
            if path == "/runs":
                query = {k: v[-1].strip() for k, v in parse_qs(urlsplit(self.path).query).items()}
                body = batch.runs_page(app.runs(), query.get("scenario", ""), query.get("level", ""))
                return self._page("runs", body, "runs")
            if m := re.fullmatch(r"/runs/([^/]+)", path):
                return self._run_page(m.group(1))
            if m := re.fullmatch(r"/runs/([^/]+)/files/(.*)", path):
                return self._run_file(m.group(1), m.group(2))
            if m := re.fullmatch(r"/runs/([^/]+)/package/(student|instructor)", path):
                zips = app.packages(m.group(1)) if app.run_dir(m.group(1)) else {}
                if m.group(2) not in zips:
                    return self._not_found()
                return self._send_file(zips[m.group(2)], "application/zip", attachment=True)
            if path == "/jobs":
                return self._page("jobs", views.jobs(app.jobs.all()), "jobs")
            if m := re.fullmatch(r"/jobs/(\d+)", path):
                job = app.jobs.get(int(m.group(1)))
                return self._page(f"job {job.id}", views.job(job), "jobs") if job else self._not_found()
            if path == "/api/jobs":
                data = [views.job_row(j) for j in app.jobs.all()]
                return self._send(HTTPStatus.OK, json.dumps(data).encode(), "application/json")
            if m := re.fullmatch(r"/api/jobs/(\d+)", path):
                job = app.jobs.get(int(m.group(1)))
                if job is None:
                    return self._not_found()
                data = job.as_dict() | {"bar": views.progress_bar(job.progress)}
                return self._send(HTTPStatus.OK, json.dumps(data).encode(), "application/json")
            if m := re.fullmatch(r"/static/([^/]+)", path):
                if m.group(1) not in STATIC:
                    return self._not_found()
                body = files("pcapforge.ui").joinpath("static", m.group(1)).read_bytes()
                return self._send(HTTPStatus.OK, body, STATIC[m.group(1)])
            return self._not_found()
        except ScenarioError as exc:
            return self._page("error", views.error(str(exc)), status=HTTPStatus.INTERNAL_SERVER_ERROR)

    def do_POST(self) -> None:  # noqa: N802
        form = self._form()  # read the body first: refusing before it resets the client's connection
        if not self._host_ok() or not self._origin_ok():
            return
        path = unquote(urlsplit(self.path).path)
        app = self.app
        try:
            if m := re.fullmatch(r"/scenarios/([^/]+)/generate", path):
                sc = app.scenarios().get(m.group(1))
                if sc is None:
                    return self._not_found()
                jobs = app.submit_generate(sc, form)
                return self._redirect(f"/jobs/{jobs[0].id}" if len(jobs) == 1 else "/jobs")
            if path == "/package-all":
                app.submit_package_all(form.get("scenario", ""), form.get("level", ""))
                return self._redirect("/jobs")
            if m := re.fullmatch(r"/runs/([^/]+)/([a-z]+)", path):
                directory = app.run_dir(m.group(1))
                if directory is None or m.group(2) not in RUN_ACTIONS:
                    return self._not_found()
                return self._redirect(f"/jobs/{app.submit_action(m.group(2), m.group(1), directory, form).id}")
            return self._not_found()
        except (ValueError, ScenarioError) as exc:
            return self._page("error", views.error(str(exc)), status=HTTPStatus.BAD_REQUEST)

    # -- pages --------------------------------------------------------------------------
    def _run_page(self, name: str) -> None:
        directory = self.app.run_dir(name)
        if directory is None:
            return self._not_found()
        try:
            answers = json.loads((directory / "answers.json").read_text(encoding="utf-8"))
            body = views.run(name, directory, answers, self.app.packages(name), self.app.jobs.active_for(name))
        except (OSError, json.JSONDecodeError, KeyError, TypeError) as exc:
            return self._page(name, views.error(f"{directory}/answers.json: {type(exc).__name__}: {exc}"),
                              status=HTTPStatus.INTERNAL_SERVER_ERROR)
        self._page(name, body, "runs")

    def _run_file(self, name: str, rel: str) -> None:
        directory = self.app.run_dir(name)
        if directory is None:
            return self._not_found()
        root = directory.resolve()
        target = (root / rel).resolve()
        if not target.is_relative_to(root) or not target.exists():
            return self._not_found()
        if target.is_dir():
            if target == root:
                return self._redirect(f"/runs/{name}")
            sub = target.relative_to(root).as_posix() + "/"
            return self._page(f"{name}/{sub}", views.listing(name, target, sub), "runs")
        suffix = target.suffix.lower()
        if suffix in INLINE_TYPES:
            return self._send_file(target, INLINE_TYPES[suffix])
        if suffix in TEXT_SUFFIXES:
            return self._send_file(target, "text/plain; charset=utf-8")
        kind = "application/vnd.tcpdump.pcap" if suffix in (".pcap", ".pcapng") else (
            mimetypes.guess_type(target.name)[0] or "application/octet-stream")
        self._send_file(target, kind, attachment=True)

    # -- helpers ------------------------------------------------------------------------
    def _host_ok(self) -> bool:
        if self.allowed_hosts is None or (self.headers.get("Host") or "").lower() in self.allowed_hosts:
            return True
        self._send(HTTPStatus.MISDIRECTED_REQUEST, b"unexpected Host header\n", "text/plain")
        return False

    def _origin_ok(self) -> bool:
        origin = self.headers.get("Origin")
        if origin is None or urlsplit(origin).netloc.lower() == (self.headers.get("Host") or "").lower():
            return True
        self._send(HTTPStatus.FORBIDDEN, b"cross-origin form post refused\n", "text/plain")
        return False

    def _form(self) -> dict[str, str]:
        length = min(int(self.headers.get("Content-Length") or 0), 64 * 1024)
        raw = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        return {k: v[-1] for k, v in parse_qs(raw, keep_blank_values=True).items()}

    def _page(self, title: str, body: str, active: str = "", status: HTTPStatus = HTTPStatus.OK) -> None:
        html = views.page(title, body, self.app.out, active)
        self._send(status, html.encode("utf-8"), "text/html; charset=utf-8")

    def _not_found(self) -> None:
        self._page("not found", "<h1>404</h1><p>No such page.</p>", status=HTTPStatus.NOT_FOUND)

    def _redirect(self, location: str) -> None:
        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _headers(self, status: HTTPStatus, content_type: str, length: int) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(length))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
                         "form-action 'self'; frame-ancestors 'none'")

    def _send(self, status: HTTPStatus, body: bytes, content_type: str) -> None:
        self._headers(status, content_type, len(body))
        self.end_headers()
        self.wfile.write(body)

    def _send_file(self, path: Path, content_type: str, attachment: bool = False) -> None:
        self._headers(HTTPStatus.OK, content_type, path.stat().st_size)
        if attachment:
            self.send_header("Content-Disposition", f'attachment; filename="{path.name}"')
        self.end_headers()
        with open(path, "rb") as fh:
            shutil.copyfileobj(fh, self.wfile, 1 << 20)


def make_server(app, host: str = "127.0.0.1", port: int = 8765,
                handler: type[BaseHTTPRequestHandler] | None = None) -> ThreadingHTTPServer:
    """``handler``: the request handler class (default ``Handler``; ``student.StudentHandler`` in student mode)."""
    base = handler or Handler
    server = ThreadingHTTPServer((host, port), base)
    bound = server.server_address[1]
    allowed = None
    if host in LOOPBACK:
        allowed = {f"{name}:{bound}" for name in ("127.0.0.1", "localhost", "[::1]")}
    handler = type("BoundHandler", (base,), {"app": app, "allowed_hosts": allowed})
    server.RequestHandlerClass = handler
    server.daemon_threads = True
    return server


def serve(out: Path, scenarios_dir: Path | None, host: str, port: int, open_browser: bool,
          student: bool = False, show_score: bool = False) -> int:
    if student:
        from pcapforge.ui.student import StudentApp, StudentHandler

        server = make_server(StudentApp(out, show_score), host, port, StudentHandler)
    else:
        server = make_server(App(out, scenarios_dir), host, port)
    url = f"http://{'127.0.0.1' if host in ('0.0.0.0', '::') else host}:{server.server_address[1]}/"
    mode = "student mode " if student else ""
    print(f"pcapforge ui {mode}on {url}  (output directory {out.resolve()}; Ctrl+C to stop)", file=sys.stderr)
    if host not in LOOPBACK:
        print("warning: listening beyond this machine; " + (
              "anyone who reaches it can download the captures and submit under any name" if student
              else "anyone who reaches it can run jobs and read answer keys"), file=sys.stderr)
    if open_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0
