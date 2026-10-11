"""Class batches in the web UI: the seed list is validated as a whole before anything is queued,
every seed gets its own generate job with the shared base seed, and the runs page filters by
scenario / level and packages every run of a group."""

from __future__ import annotations

import http.client
import json
import threading
from types import SimpleNamespace
from urllib.parse import urlencode

import pytest

import pcapforge.pipeline
from pcapforge.ui.batch import MAX_SEEDS, parse_seeds
from pcapforge.ui.jobs import Job
from pcapforge.ui.server import App, make_server

SCENARIO = SimpleNamespace(id="ot-test", difficulties=["easy", "medium"])


class FakeJobs:
    """Records submissions instead of running them."""

    def __init__(self) -> None:
        self.submitted: list[tuple[Job, object]] = []

    def submit(self, kind, title, work, run=None) -> Job:
        job = Job(len(self.submitted) + 1, kind, title, run)
        self.submitted.append((job, work))
        return job

    def all(self) -> list[Job]:
        return [job for job, _ in reversed(self.submitted)]

    def get(self, job_id: int) -> Job | None:
        return next((job for job in self.all() if job.id == job_id), None)

    def active_for(self, run: str) -> list[Job]:
        return []


class FakeApp(App):
    def __init__(self, out) -> None:
        super().__init__(out)
        self.jobs = FakeJobs()

    def scenarios(self):
        return {SCENARIO.id: SCENARIO}


def _write_run(root, name: str, scenario: str, level: str) -> None:
    run = root / name
    run.mkdir()
    answers = {"scenario": {"id": scenario, "difficulty": level, "seed": name.rsplit("_", 1)[-1]},
               "capture": {"file": "capture.pcap", "packets": 3, "duration_s": 60.0}, "lang": "en"}
    (run / "answers.json").write_text(json.dumps(answers), encoding="utf-8")


@pytest.fixture
def ui(tmp_path):
    app = FakeApp(tmp_path)
    server = make_server(app, "127.0.0.1", 0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield app, server.server_address[1]
    server.shutdown()
    server.server_close()


def _request(port: int, method: str, path: str, form: dict | None = None, headers: dict | None = None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    headers = {"Host": f"127.0.0.1:{port}", **(headers or {})}
    body = None
    if form is not None:
        body = urlencode(form)
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    conn.request(method, path, body=body, headers=headers)
    response = conn.getresponse()
    data = response.read()
    location = response.getheader("Location")
    conn.close()
    return response.status, data, location


@pytest.fixture
def generate_calls(monkeypatch, tmp_path) -> list[dict]:
    """Replace ``pipeline.generate`` (bound when the form is submitted); the calls it sees."""
    calls = []

    def fake_generate(scenario, difficulty, seed, out_root, **kwargs):
        calls.append({"scenario": scenario.id, "difficulty": difficulty, "seed": seed, **kwargs})
        return SimpleNamespace(directory=tmp_path / f"run-{seed}", packets=1, report=None)

    monkeypatch.setattr(pcapforge.pipeline, "generate", fake_generate)
    return calls


def _run_works(app: FakeApp) -> None:
    for job, work in app.jobs.submitted:
        work(job)


# -- seed list ---------------------------------------------------------------------------

def test_seed_list_skips_blanks_and_comments():
    text = "# class 3A\nalice\n\n   bob  \n  # absent: dave\ncarol\r\n"
    assert parse_seeds(text) == ["alice", "bob", "carol"]
    assert parse_seeds("") == [] and parse_seeds("# only\n\n") == []


@pytest.mark.parametrize("text, message", [
    ("alice\nbob\nalice", "line 3: 'alice' duplicates line 1"),
    ("jan kowalski\njan_kowalski", "both write the run directory"),
    ("x" * 65, "at most 64 characters"),
    ("\n".join(f"s{i}" for i in range(MAX_SEEDS + 1)), f"at most {MAX_SEEDS}"),
])
def test_seed_list_refuses_duplicates_and_limits(text, message):
    with pytest.raises(ValueError, match=message):
        parse_seeds(text)


def test_seed_list_accepts_the_limits():
    seeds = [f"s{i}" for i in range(MAX_SEEDS)]
    assert parse_seeds("\n".join(seeds)) == seeds
    assert parse_seeds("x" * 64) == ["x" * 64]


# -- generate form -----------------------------------------------------------------------

def test_seed_list_queues_one_job_per_seed_with_the_base_seed(ui, generate_calls):
    app, port = ui
    form = {"difficulty": "easy", "seed": "ignored", "seeds": "# class\nalice\n\nbob\ncarol\n",
            "base_seed": " 7 ", "lang": "en", "format": "pcap", "duration": "2m", "siem": "on"}
    status, _, location = _request(port, "POST", "/scenarios/ot-test/generate", form)
    assert (status, location) == (303, "/jobs")
    jobs = [job for job, _ in app.jobs.submitted]
    assert [j.kind for j in jobs] == ["generate"] * 3
    assert [j.title for j in jobs] == [f"ot-test easy seed {s} base 7 (2m)" for s in ("alice", "bob", "carol")]
    _run_works(app)
    calls = generate_calls
    assert [(c["seed"], c["base_seed"]) for c in calls] == [("alice", "7"), ("bob", "7"), ("carol", "7")]
    assert all(c["difficulty"] == "easy" and c["duration"] == 120 and c["siem"] and not c["zeek"] for c in calls)
    assert [j.run for j in jobs] == ["run-alice", "run-bob", "run-carol"]


def test_single_seed_without_base_seed_goes_to_its_job_page(ui, generate_calls):
    app, port = ui
    form = {"difficulty": "medium", "seed": "42", "seeds": "  \n", "base_seed": "", "lang": "en", "format": "pcap"}
    status, _, location = _request(port, "POST", "/scenarios/ot-test/generate", form)
    assert (status, location) == (303, "/jobs/1")
    _run_works(app)
    assert [(c["seed"], c["base_seed"]) for c in generate_calls] == [("42", None)]


@pytest.mark.parametrize("change, message", [
    ({"seeds": "alice\nbob\nalice"}, b"duplicates line 1"),
    ({"seeds": "alice\n" + "y" * 65}, b"line 2: at most 64 characters"),
    ({"seeds": "\n".join(f"s{i}" for i in range(MAX_SEEDS + 1))}, b"at most 200"),
    ({"seeds": "# nobody yet\n"}, b"only comments"),
    ({"base_seed": "b" * 65}, b"base seed: at most 64"),
    ({"seed": "z" * 65, "seeds": ""}, b"seed: at most 64"),
    ({"lang": "xx"}, b"language"),
    ({"duration": "soon"}, b"invalid duration"),
    ({"difficulty": "hard"}, b"no level"),
])
def test_invalid_batch_is_refused_before_anything_is_queued(ui, change, message):
    app, port = ui
    form = {"difficulty": "easy", "seeds": "alice\nbob", "base_seed": "7", "lang": "en", "format": "pcap"} | change
    status, body, _ = _request(port, "POST", "/scenarios/ot-test/generate", form)
    assert status == 400 and message in body
    assert app.jobs.submitted == []


# -- runs page ---------------------------------------------------------------------------

@pytest.fixture
def runs(ui, tmp_path):
    for name, scenario, level in [("ot-a_easy_alice", "ot-a", "easy"), ("ot-a_easy_bob", "ot-a", "easy"),
                                  ("ot-a_hard_alice", "ot-a", "hard"), ("ot-b_easy_alice", "ot-b", "easy")]:
        _write_run(tmp_path, name, scenario, level)
    return ui


def test_runs_page_filters_by_scenario_and_level(runs):
    _app, port = runs
    status, page, _ = _request(port, "GET", "/runs?scenario=ot-a&level=easy")
    assert status == 200
    assert b"ot-a_easy_alice" in page and b"ot-a_easy_bob" in page
    assert b"ot-a_hard_alice" not in page and b"ot-b_easy_alice" not in page
    status, page, _ = _request(port, "GET", "/runs?level=easy")
    assert b"ot-b_easy_alice" in page and b"ot-a_hard_alice" not in page
    status, page, _ = _request(port, "GET", "/runs?scenario=%3Cscript%3Ealert(1)%3C/script%3E")
    assert status == 200 and b"<script>alert" not in page and b"&lt;script&gt;" in page
    assert b"No runs match" in page


def test_package_all_queues_every_run_of_the_group(runs):
    app, port = runs
    status, _, location = _request(port, "POST", "/package-all", {"scenario": "ot-a", "level": "easy"},
                                   {"Origin": f"http://127.0.0.1:{port}"})
    assert (status, location) == (303, "/jobs")
    jobs = [job for job, _ in app.jobs.submitted]
    assert [j.kind for j in jobs] == ["package", "package"]
    assert sorted(j.run for j in jobs) == ["ot-a_easy_alice", "ot-a_easy_bob"]


@pytest.mark.parametrize("form, headers, expected", [
    ({"scenario": "ot-a", "level": "easy"}, {"Origin": "http://evil.example"}, 403),
    ({"scenario": "ot-a", "level": ""}, {}, 400),
    ({"scenario": "ot-c", "level": "easy"}, {}, 400),
])
def test_package_all_refuses_foreign_origins_and_empty_groups(runs, form, headers, expected):
    app, port = runs
    assert _request(port, "POST", "/package-all", form, headers)[0] == expected
    assert app.jobs.submitted == []


def test_jobs_api_lists_the_live_rows(ui):
    app, port = ui
    job = app.jobs.submit("generate", "ot-test easy seed a", lambda j: None)
    job.state = "running"
    job.note("recording 1/4")
    status, body, _ = _request(port, "GET", "/api/jobs")
    assert status == 200
    [row] = json.loads(body)
    assert row["state"] == "running" and row["outcome"].startswith("[########") and "25%" in row["outcome"]
