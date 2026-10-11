"""Student mode of the web UI never serves the answer key, stores submissions that grade like
hand-written ones, and refuses cross-origin posts; the instructor's grade action writes grades.json."""

from __future__ import annotations

import http.client
import json
import threading
import time
from urllib.parse import urlencode

import pytest

from pcapforge.grade import grade_submission, load_submissions
from pcapforge.ui.server import App, make_server
from pcapforge.ui.student import StudentApp, StudentHandler

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
