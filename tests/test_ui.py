"""The web UI only serves run files from inside a run directory, refuses foreign Host / Origin
headers, and escapes run content."""

from __future__ import annotations

import http.client
import json
import threading

import pytest

from pcapforge.ui.server import App, make_server

RUN = "ot-test_easy_1"


def _answers() -> dict:
    host = {"id": "hmi", "role": "hmi", "name": "<script>alert(1)</script>", "device": "windows-workstation",
            "vendor": "Dell", "interfaces": [{"subnet": "control", "ip": "10.0.0.5", "mac": "00:11:22:33:44:55"}],
            "ipv6": None}
    return {
        "scenario": {"id": "ot-test", "title": "Test", "difficulty": "easy", "seed": "1", "base_seed": "1"},
        "capture": {"file": "capture.pcap", "packets": 3, "duration_s": 60.0, "start": "2025-01-01T00:00:00Z",
                    "end": "2025-01-01T00:01:00Z", "sha256": "00" * 32, "sensor_subnet": "10.0.0.0/24",
                    "sensor_clock": None},
        "topology": {"site_name": "Site", "domain": "site.local", "hosts": [host],
                     "subnets": [{"id": "control", "cidr": "10.0.0.0/24", "gateway": "10.0.0.1", "sensor": True}]},
        "timeline": [], "questions": [{"id": "q", "text": "Which?", "type": "ip", "answer": "10.0.0.5", "points": 5}],
        "lang": "en",
    }


@pytest.fixture
def ui(tmp_path):
    run = tmp_path / RUN
    run.mkdir()
    (run / "answers.json").write_text(json.dumps(_answers()), encoding="utf-8")
    (run / "capture.pcap").write_bytes(b"\xd4\xc3\xb2\xa1")
    (tmp_path / "secret.txt").write_text("outside the run", encoding="utf-8")
    app = App(tmp_path)
    server = make_server(app, "127.0.0.1", 0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield app, server.server_address[1]
    server.shutdown()
    server.server_close()


def _request(port: int, method: str, path: str, headers: dict | None = None, body: str | None = None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    headers = {"Host": f"127.0.0.1:{port}", **(headers or {})}
    if body is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    conn.request(method, path, body=body, headers=headers)
    response = conn.getresponse()
    data = response.read()
    conn.close()
    return response.status, data


def test_run_page_escapes_run_content_and_serves_its_files(ui):
    _app, port = ui
    status, page = _request(port, "GET", f"/runs/{RUN}")
    assert status == 200
    assert b"&lt;script&gt;alert(1)&lt;/script&gt;" in page and b"<script>alert" not in page
    assert _request(port, "GET", f"/runs/{RUN}/files/capture.pcap") == (200, b"\xd4\xc3\xb2\xa1")


@pytest.mark.parametrize("path", [
    f"/runs/{RUN}/files/../secret.txt",
    f"/runs/{RUN}/files/%2e%2e/secret.txt",
    f"/runs/{RUN}/files/..%2fsecret.txt",
    "/runs/../files/secret.txt",
    "/runs/..%2f/files/secret.txt",
])
def test_files_outside_the_run_directory_are_not_served(ui, path):
    _app, port = ui
    status, body = _request(port, "GET", path)
    assert status == 404 and b"outside the run" not in body


def test_foreign_host_and_cross_origin_posts_are_refused(ui):
    app, port = ui
    assert _request(port, "GET", "/", {"Host": f"evil.example:{port}"})[0] == 421
    status, _ = _request(port, "POST", f"/runs/{RUN}/report", {"Origin": "http://evil.example"}, "")
    assert status == 403 and not app.jobs.all()
    status, _ = _request(port, "POST", f"/runs/{RUN}/report", {"Origin": f"http://127.0.0.1:{port}"}, "")
    assert status == 303 and [j.kind for j in app.jobs.all()] == ["report"]
