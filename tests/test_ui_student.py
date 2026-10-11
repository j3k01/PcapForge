"""Student mode of the web UI never serves the answer key, stores submissions that grade like
hand-written ones, and refuses cross-origin posts; the instructor's grade action writes grades.json.
With a class roster a student needs login + access code, the session cookie is signed and expires,
codes are stored only as salted hashes, a student only ever sees or replaces their own submission,
and student pages speak the language of the exercise."""

from __future__ import annotations

import http.client
import json
import threading
import time
from urllib.parse import urlencode

import pytest

from pcapforge.grade import grade_submission, load_submissions
from pcapforge.i18n import LANGS, UI
from pcapforge.ui import roster, views
from pcapforge.ui.server import App, make_server
from pcapforge.ui.student import COOKIE, StudentApp, StudentHandler

RUN = "ot-test_easy_jdoe"
SECRETS = ["10.9.8.77", "zz_alpha_pt", "zz_beta_pt", "zz_gamma_key", "zz_delta_key", "4242", "T0836X", "SecretAlt",
           "secret.filter", "hunt_marker"]


def _answers() -> dict:
    return {
        "scenario": {"id": "ot-test", "title": "Test <exercise>", "difficulty": "easy", "seed": "JDoe",
                     "summary": "A summary."},
        "capture": {"file": "capture.pcap", "packets": 3, "duration_s": 60.0, "start": "2025-01-01T00:00:00Z",
                    "end": "2025-01-01T00:01:00Z", "sha256": "ab" * 32, "sensor_subnet": "10.0.0.0/24"},
        "topology": {"hosts": [], "subnets": []},
        "timeline": [{"title": "hunt_marker", "epoch": 0}],
        "questions": [
            {"id": "src", "text": "Which host?", "type": "ip", "answer": "10.9.8.77", "points": 10,
             "hint": "Look at writes.", "checks": [{"filter": "secret.filter == 1"}], "hunt": {"kql": "hunt_marker"}},
            {"id": "points", "text": "Which points?", "type": "set", "answer": ["zz_alpha_pt", "zz_beta_pt"],
             "points": 9},
            {"id": "values", "text": "Which values?", "type": "map",
             "answer": {"zz_gamma_key": 123.4, "zz_delta_key": 0.5}, "points": 6},
            {"id": "count", "text": "How many?", "type": "number", "answer": 4242, "tolerance": 3, "points": 4},
            {"id": "technique", "text": "Which technique?", "type": "text", "answer": "T0836X",
             "accept": ["SecretAlt"], "points": 5},
        ],
        "lang": "en",
    }


@pytest.fixture
def student(tmp_path):
    run = tmp_path / RUN
    run.mkdir()
    (run / "answers.json").write_text(json.dumps(_answers()), encoding="utf-8")
    (run / "capture.pcap").write_bytes(b"\xd4\xc3\xb2\xa1")
    (run / "briefing.md").write_text("# Briefing\n\nFind the <writer>.\n", encoding="utf-8")
    (run / "report.html").write_text("10.9.8.77", encoding="utf-8")
    (run / "siem").mkdir()
    (run / "siem" / "modbus.jsonl").write_text('{"src": "10.9.8.77"}\n', encoding="utf-8")
    (run / "submissions").mkdir()
    (run / "submissions" / "other.yaml").write_text("src: 10.9.8.77\n", encoding="utf-8")
    (tmp_path / f"{RUN}-instructor.zip").write_bytes(b"PK")
    server = make_server(StudentApp(tmp_path, show_score=True), "127.0.0.1", 0, StudentHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield run, server.server_address[1]
    server.shutdown()
    server.server_close()


def _request(port: int, method: str, path: str, headers: dict | None = None, form: dict | None = None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    headers = {"Host": f"127.0.0.1:{port}", **(headers or {})}
    body = None
    if form is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        body = urlencode(form)
    conn.request(method, path, body=body, headers=headers)
    response = conn.getresponse()
    data = response.read()
    conn.close()
    return response.status, data, response


def _login(port: int, name: str = "J Doe") -> dict:
    status, _, response = _request(port, "POST", "/login", form={"name": name})
    assert status == 303
    cookie = response.getheader("Set-Cookie")
    assert "HttpOnly" in cookie and "SameSite=Strict" in cookie
    return {"Cookie": cookie.split(";", 1)[0]}


def test_student_pages_never_contain_the_answer_key(student):
    run, port = student
    cookie = _login(port)
    pages = ["/", f"/x/{RUN}", f"/x/{RUN}/files/capture.pcap", f"/x/{RUN}/files/briefing.md",
             f"/x/{RUN}/files/submission_template.yaml"]
    status, _, _ = _request(port, "POST", f"/x/{RUN}", cookie, {"a:src": "1.2.3.4", "a:count": "7"})
    assert status == 303
    pages.append(f"/x/{RUN}/submitted")
    for path in pages:
        status, body, _ = _request(port, "GET", path, cookie)
        assert status == 200, path
        text = body.decode("utf-8", "replace")
        assert not [s for s in SECRETS if s in text], path
    exercise = _request(port, "GET", f"/x/{RUN}", cookie)[1].decode()
    assert "Test &lt;exercise&gt;" in exercise and "Find the &lt;writer&gt;." in exercise
    assert "I used this hint (-2 points)" in exercise


@pytest.mark.parametrize("path", [
    f"/x/{RUN}/files/answers.json", f"/x/{RUN}/files/report.html", f"/x/{RUN}/files/%2e%2e%2fsecret",
    f"/x/{RUN}/files/siem%2fmodbus.jsonl", f"/x/{RUN}/files/siem/modbus.jsonl", f"/x/{RUN}/files/siem",
    f"/x/{RUN}/files/submissions/other.yaml", f"/x/{RUN}/files/other.yaml", f"/runs/{RUN}",
    f"/runs/{RUN}/files/answers.json", f"/runs/{RUN}/package/instructor", "/runs", "/jobs", "/scenarios/ot-test",
    f"/x/{RUN}-instructor.zip", "/x/..%2fsecret",
])
def test_answer_material_and_instructor_routes_are_not_served(student, path):
    _run, port = student
    status, body, _ = _request(port, "GET", path, _login(port))
    assert status == 404 and b"10.9.8.77" not in body


def test_submitted_form_grades_like_a_submission_file(student):
    run, port = student
    cookie = _login(port, "J Doe")
    form = {"a:src": " 10.9.8.77 ", "h:src": "1", "a:points": "zz_alpha_pt\n\nwrong_pt\n",
            "a:values": "zz_gamma_key = 123.4\nzz_delta_key: 0.50", "a:count": "", "a:technique": ""}
    assert _request(port, "POST", f"/x/{RUN}", cookie, form)[0] == 303
    path = run / "submissions" / "J_Doe.yaml"
    assert path.read_text(encoding="utf-8").startswith("# pcapforge submission of J Doe, ")
    [sub] = load_submissions([path])
    assert sub.answers["points"] == ["zz_alpha_pt", "wrong_pt"] and sub.answers["hints_used"] == ["src"]
    graded = grade_submission(_answers(), sub)
    assert {q["id"]: q["score"] for q in graded["questions"]} == {
        "src": 8, "points": 3, "values": 6, "count": 0, "technique": 0}
    assert graded["score"] == 17

    page = _request(port, "GET", f"/x/{RUN}/submitted", cookie)[1].decode()
    assert "score 17/34" in page
    prefilled = _request(port, "GET", f"/x/{RUN}", cookie)[1].decode()
    assert 'value="10.9.8.77"' in prefilled and "zz_gamma_key = 123.4" in prefilled
    assert 'name="h:src" value="1" checked' in prefilled

    assert _request(port, "POST", f"/x/{RUN}", cookie, {"a:count": "4240"})[0] == 303
    [sub] = load_submissions([path])
    assert sub.answers["src"] is None and sub.answers["count"] == "4240" and sub.answers["hints_used"] == []
    assert sorted(p.name for p in (run / "submissions").iterdir()) == ["J_Doe.yaml", "other.yaml"]


def test_exercise_list_prefers_runs_seeded_with_the_login(student):
    run, port = student
    other = run.parent / "ot-test_easy_someone"
    other.mkdir()
    answers = _answers()
    answers["scenario"]["seed"] = "someone"
    (other / "answers.json").write_text(json.dumps(answers), encoding="utf-8")
    mine = _request(port, "GET", "/", _login(port, "jdoe"))[1].decode()
    assert RUN in mine and "ot-test_easy_someone" not in mine
    everyone = _request(port, "GET", "/", _login(port, "nobody"))[1].decode()
    assert RUN in everyone and "ot-test_easy_someone" in everyone


def test_cross_origin_and_foreign_host_requests_are_refused(student):
    run, port = student
    cookie = _login(port)
    evil = {"Origin": "http://evil.example", **cookie}
    assert _request(port, "POST", f"/x/{RUN}", evil, {"a:src": "1.2.3.4"})[0] == 403
    assert _request(port, "POST", "/login", {"Origin": "http://evil.example"}, {"name": "x"})[0] == 403
    assert sorted(p.name for p in (run / "submissions").iterdir()) == ["other.yaml"]
    assert _request(port, "GET", "/", {"Host": f"evil.example:{port}"})[0] == 421


def test_instructor_grade_action_writes_grades_json(tmp_path):
    run = tmp_path / RUN
    (run / "submissions").mkdir(parents=True)
    (run / "answers.json").write_text(json.dumps(_answers()), encoding="utf-8")
    (run / "submissions" / "ann.yaml").write_text("src: 10.9.8.77\npoints: [zz_alpha_pt, zz_beta_pt]\n",
                                                  encoding="utf-8")
    (run / "submissions" / "bob.yaml").write_text("hints_used: [src]\nsrc: 10.9.8.77\n", encoding="utf-8")
    app = App(tmp_path)
    job = app.submit_action("grade", RUN, run, {})
    deadline = time.time() + 20
    while job.state not in ("done", "failed") and time.time() < deadline:
        time.sleep(0.05)
    assert job.state == "done", job.error
    grades = json.loads((run / "grades.json").read_text(encoding="utf-8"))
    assert [(s["student"], s["score"]) for s in grades["students"]] == [("ann", 19), ("bob", 8)]
    assert grades["max"] == 34


# -- class roster ----------------------------------------------------------------------

PL_RUN = "ot-test_easy_ann"


@pytest.fixture
def fast_hash(monkeypatch):
    monkeypatch.setattr(roster, "ITERATIONS", 1000)
    monkeypatch.setattr("pcapforge.ui.student.FAILED_LOGIN_DELAY_S", 0)


def _serve(app, handler=None):
    server = make_server(app, "127.0.0.1", 0, handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


@pytest.fixture
def classroom(tmp_path, fast_hash):
    for name, seed, lang in ((RUN, "JDoe", "en"), (PL_RUN, "ann", "pl")):
        run = tmp_path / name
        run.mkdir()
        answers = _answers()
        answers["scenario"]["seed"], answers["lang"] = seed, lang
        (run / "answers.json").write_text(json.dumps(answers), encoding="utf-8")
        (run / "capture.pcap").write_bytes(b"\xd4\xc3\xb2\xa1")
    issued, kept = roster.add(tmp_path, "# class 3b\nann, Ann Adams\n\nbob\n")
    assert kept == [] and [x["login"] for x in issued] == ["ann", "bob"]
    app = StudentApp(tmp_path)
    server = _serve(app, StudentHandler)
    yield tmp_path, app, server.server_address[1], {x["login"]: x["code"] for x in issued}
    server.shutdown()
    server.server_close()


def _sign_in(port: int, login: str, code: str) -> dict:
    status, _, response = _request(port, "POST", "/login", form={"login": login, "code": code})
    assert status == 303, (login, status)
    cookie = response.getheader("Set-Cookie")
    assert "HttpOnly" in cookie and "SameSite=Strict" in cookie and f"Max-Age={roster.SESSION_S}" in cookie
    return {"Cookie": cookie.split(";", 1)[0]}


def _signed_in(port: int, headers: dict) -> bool:
    return 'name="code"' not in _request(port, "GET", "/", headers)[1].decode()


def test_roster_codes_are_stored_only_as_salted_hashes(classroom):
    out, _app, _port, codes = classroom
    text = (out / roster.ROSTER).read_text(encoding="utf-8")
    data = json.loads(text)
    assert set(data) == {"ann", "bob"} and data["ann"]["name"] == "Ann Adams" and data["bob"]["name"] == "bob"
    assert data["ann"]["salt"] != data["bob"]["salt"]
    for code in codes.values():
        assert code not in text and code.replace("-", "") not in text
        assert len(code) == 14 and set(code.replace("-", "")) <= set(roster.ALPHABET)


def test_roster_login_requires_the_right_code(classroom):
    _out, _app, port, codes = classroom
    page = _request(port, "GET", "/")[1].decode()
    assert 'name="code"' in page and "class roster" in page
    for form in ({"login": "ann"}, {"login": "ann", "code": codes["bob"]}, {"login": "nobody", "code": codes["ann"]},
                 {"name": "ann"}):
        status, body, response = _request(port, "POST", "/login", form=form)
        assert status == 403 and response.getheader("Set-Cookie") is None, form
        assert "Unknown login or wrong access code." in body.decode()
    cookie = _sign_in(port, "ANN", codes["ann"].lower().replace("-", " "))  # case and separators do not matter
    assert _signed_in(port, cookie) and "Ann Adams" in _request(port, "GET", "/", cookie)[1].decode()


def test_forged_tampered_and_expired_sessions_are_refused(classroom):
    out, app, port, codes = classroom
    cookie = _sign_in(port, "ann", codes["ann"])
    _login_, expiry, mac = cookie["Cookie"].split("=", 1)[1].split("|")
    forged = [
        "ann",  # an honour-system cookie
        f"bob|{expiry}|{mac}",  # ann's mac on bob's login
        f"ann|{int(expiry) + 3600}|{mac}",  # extended expiry
        f"ann|{expiry}|{mac[:-1]}{'0' if mac[-1] != '0' else '1'}",
        roster.sign(app.secret(), roster.load(out), "ann", now=time.time() - roster.SESSION_S - 1),  # expired
        roster.sign(b"x" * 32, roster.load(out), "ann"),  # another server's secret
    ]
    for value in forged:
        headers = {"Cookie": f"{COOKIE}={value}"}
        assert not _signed_in(port, headers), value
        assert _request(port, "POST", f"/x/{PL_RUN}", headers, {"a:src": "1.1.1.1"})[0] == 303
        assert _request(port, "GET", f"/x/{PL_RUN}/files/capture.pcap", headers)[0] == 303
    assert not (out / PL_RUN / "submissions").exists()
    assert _signed_in(port, cookie)
    roster.reset(out, "ann")  # a new code ends the sessions of the old one
    assert not _signed_in(port, cookie)
    assert (out / roster.SECRET).is_file()


def test_a_student_only_sees_and_replaces_their_own_submission(classroom):
    out, _app, port, codes = classroom
    ann, bob = _sign_in(port, "ann", codes["ann"]), _sign_in(port, "bob", codes["bob"])
    assert _request(port, "POST", f"/x/{PL_RUN}", ann, {"a:src": "10.1.2.3", "a:technique": "ann_answer"})[0] == 303
    path = out / PL_RUN / "submissions" / "ann.yaml"
    before = path.read_text(encoding="utf-8")
    assert "ann_answer" in before
    page = _request(port, "GET", f"/x/{PL_RUN}", bob)[1].decode()
    assert "ann_answer" not in page and "10.1.2.3" not in page
    status, _, response = _request(port, "GET", f"/x/{PL_RUN}/submitted", bob)
    assert status == 303 and response.getheader("Location") == f"/x/{PL_RUN}"
    assert _request(port, "POST", f"/x/{PL_RUN}", bob, {"a:technique": "bob_answer", "login": "ann"})[0] == 303
    assert path.read_text(encoding="utf-8") == before
    assert sorted(p.name for p in path.parent.iterdir()) == ["ann.yaml", "bob.yaml"]
    assert "ann_answer" in _request(port, "GET", f"/x/{PL_RUN}", ann)[1].decode()


def test_student_pages_follow_the_language_of_the_exercise(classroom):
    _out, _app, port, codes = classroom
    assert '<html lang="en">' in _request(port, "GET", "/")[1].decode()  # runs in en and pl: English
    ann = _sign_in(port, "ann", codes["ann"])
    listing = _request(port, "GET", "/", ann)[1].decode()  # only ann's (pl) run
    assert '<html lang="pl">' in listing and UI["pl"]["st_mine"] in listing
    polish = _request(port, "GET", f"/x/{PL_RUN}", ann)[1].decode()
    assert '<html lang="pl">' in polish and f'>{UI["pl"]["st_submit"]}</button>' in polish
    assert UI["pl"]["st_used_hint"].format(cost=2, points=UI["pl"]["points"]) in polish
    english = _request(port, "GET", f"/x/{RUN}", ann)[1].decode()
    assert '<html lang="en">' in english and ">submit</button>" in english
    _request(port, "POST", f"/x/{PL_RUN}", ann, {"a:src": "10.9.8.77"})
    assert UI["pl"]["st_submitted"] in _request(port, "GET", f"/x/{PL_RUN}/submitted", ann)[1].decode()
    for lang in LANGS:
        assert set(UI[lang]["st_results"]) == set(UI["en"]["st_results"])
        assert len(UI[lang]["st_list_cols"]) == len(UI["en"]["st_list_cols"])
        assert len(UI[lang]["st_meta"]) == len(UI["en"]["st_meta"])


def test_instructor_roster_page_shows_codes_once(tmp_path, fast_hash):
    run = tmp_path / RUN
    (run / "submissions").mkdir(parents=True)
    (run / "answers.json").write_text(json.dumps(_answers()), encoding="utf-8")
    (run / "submissions" / "cy.yaml").write_text("src: 10.9.8.77\n", encoding="utf-8")
    server = _serve(App(tmp_path))
    port = server.server_address[1]
    try:
        assert "No roster yet" in _request(port, "GET", "/students")[1].decode()
        status, body, _ = _request(port, "POST", "/students/add", form={"logins": "cy, Cy <Cole>\ndee"})
        page = body.decode()
        assert status == 200 and "Cy &lt;Cole&gt;" in page
        stored = roster.load(tmp_path)
        shown = [chunk.split("</code>")[0] for chunk in page.split("<code>")[1:]]
        [code] = [c for c in shown if roster.check(stored, "cy", c)]
        assert code not in _request(port, "GET", "/students")[1].decode()
        assert "Cy &lt;Cole&gt;" in views._submissions(RUN, run)  # the instructor's run page

        status, body, _ = _request(port, "POST", "/students/add", form={"logins": "bad login\ncy\n../x"})
        assert status == 400 and "line 1" in body.decode() and "line 3" in body.decode()
        assert set(roster.load(tmp_path)) == {"cy", "dee"}

        assert _request(port, "POST", "/students/reset", form={"login": "cy"})[0] == 200
        assert roster.check(roster.load(tmp_path), "cy", code) is None
        assert _request(port, "POST", "/students/remove", form={"login": "dee"})[0] == 303
        assert set(roster.load(tmp_path)) == {"cy"}
        assert _request(port, "POST", "/students/add", {"Origin": "http://evil.example"}, {"logins": "eve"})[0] == 403
    finally:
        server.shutdown()
        server.server_close()
