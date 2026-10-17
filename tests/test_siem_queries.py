"""The hunting guide's Splunk SPL and Kibana KQL queries, run against a real Splunk and a real
Elasticsearch loaded with the SIEM export the way detections/hunting.md describes.

For every scenario and level, every question's queries must run without errors and match events,
and an answer that is a field value of the dataset (an IP, a point name, a function) must show up
in what the query returns. Skipped unless a backend is configured:

- ``PCAPFORGE_SPLUNK_URL`` (management port, e.g. ``https://localhost:8089``) with
  ``PCAPFORGE_SPLUNK_AUTH`` (``user:password``, default ``admin:changeme``) and, when Splunk runs
  elsewhere (a container), ``PCAPFORGE_SPLUNK_SPOOL``: a directory Splunk sees at the same path.
- ``PCAPFORGE_ELASTIC_URL`` (e.g. ``http://localhost:9200``, security off). KQL runs through the
  Elasticsearch ``kql`` query (9.1+), the mapping comes from the find-structure API that Kibana's
  file upload uses.
"""

import base64
import json
import os
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import pytest

from pcapforge.pipeline import generate
from pcapforge.scenario import discover
from recordings import ensure_recorded

SPLUNK_URL = os.environ.get("PCAPFORGE_SPLUNK_URL", "").rstrip("/")
ELASTIC_URL = os.environ.get("PCAPFORGE_ELASTIC_URL", "").rstrip("/")
SEED = "siem-queries"
DURATION = 600.0  # 10 minutes hold every incident on every level

RUNS = [(sid, level) for sid, sc in sorted(discover().items())
        if any(q.get("hunt", {}).get("spl") or q.get("hunt", {}).get("kql") for q in sc.doc.get("questions", []))
        for level in ("easy", "medium", "hard")]


@pytest.fixture(scope="session")
def runs(tmp_path_factory):
    """Generated runs with their SIEM export, one per scenario and level, created on first use."""
    root = tmp_path_factory.mktemp("siem-runs")
    cache = {}

    def get(scenario_id, level):
        if (scenario_id, level) not in cache:
            ensure_recorded(discover()[scenario_id], level, SEED, DURATION, root / "recording")
            result = generate(discover()[scenario_id], level, SEED, root, duration=DURATION, siem=True)
            assert result.report.ok, [c for c in result.report.checks if not c["ok"]]
            answers = json.loads(result.answers.read_text(encoding="utf-8"))
            cache[scenario_id, level] = (result.directory, answers)
        return cache[scenario_id, level]
    return get


def hunted(answers):
    return [q for q in answers["questions"] if q.get("hunt", {}).get("spl") or q.get("hunt", {}).get("kql")]


def text(value):
    """A JSON / search-result value as the string both backends show for it (1.0 -> '1')."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value)


def flatten(value):
    if isinstance(value, dict):
        return {s for k, v in value.items() for s in flatten(k) | flatten(v)}
    if isinstance(value, list):
        return {s for v in value for s in flatten(v)}
    return set() if value is None else {text(value)}


def read_jsonl(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def grounded(answer, events):
    """The text parts of an answer that are field values in the dataset (an IP, a point, a function):
    those a query must return. Numbers and yes/no answers would match unrelated fields by chance."""
    present = set().union(*(flatten(e) for e in events)) if events else set()
    words = {s for s in flatten(answer) if s not in ("true", "false") and not s.lstrip("-").replace(".", "").isdigit()}
    return words & present


def request(url, body=None, *, method=None, headers=None, auth=None, context=None, timeout=120):
    data = body.encode("utf-8") if isinstance(body, str) else body
    req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    if auth:
        req.add_header("Authorization", "Basic " + base64.b64encode(auth.encode()).decode())
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=context) as resp:
            return resp.status, resp.read().decode("utf-8")
    except urllib.error.HTTPError as err:
        return err.code, err.read().decode("utf-8")


class Splunk:
    PROPS = {"INDEXED_EXTRACTIONS": "json", "KV_MODE": "none", "TIMESTAMP_FIELDS": "ts",
             "TIME_FORMAT": "%Y-%m-%dT%H:%M:%S.%6NZ", "TZ": "UTC", "MAX_DAYS_HENCE": "3650", "MAX_DAYS_AGO": "10951"}

    def __init__(self, url, auth, spool):
        self.url, self.auth, self.spool = url, auth, spool
        self.context = ssl._create_unverified_context()  # the management port's self-signed certificate
        self.sourcetypes = set()

    def call(self, path, params=None, method="POST"):
        body = urllib.parse.urlencode({**(params or {}), "output_mode": "json"}, doseq=True)
        url = f"{self.url}{path}"
        if method == "GET":
            url, body = f"{url}?{body}", None
        status, payload = request(url, body, method=method, auth=self.auth, context=self.context,
                                  headers={"Content-Type": "application/x-www-form-urlencoded"})
        return status, json.loads(payload) if payload.strip() else {}

    def sourcetype(self, name):
        """The props.conf stanza from hunting.md, created once per dataset."""
        if name in self.sourcetypes:
            return
        status, _ = self.call("/servicesNS/nobody/search/configs/conf-props", {"name": name, **self.PROPS})
        if status == 409:  # left from an earlier session: make sure it holds the documented settings
            status, _ = self.call(f"/servicesNS/nobody/search/configs/conf-props/{urllib.parse.quote(name, safe='')}",
                                  self.PROPS)
        assert status in (200, 201), f"props.conf [{name}]: HTTP {status}"
        self.sourcetypes.add(name)

    def load(self, index, siem):
        """Index every siem/*.jsonl file into a fresh ``index`` with oneshot inputs (Add Data > Upload)."""
        self.call(f"/services/data/indexes/{index}", method="DELETE")
        status, body = self.call("/services/data/indexes", {"name": index})
        assert status == 201, f"create index {index}: HTTP {status} {body}"
        expected = 0
        for path in sorted(siem.glob("*.jsonl")):
            lines = sum(1 for line in path.read_text(encoding="utf-8").splitlines() if line.strip())
            if not lines:
                continue
            spooled = Path(self.spool) / index / path.name
            spooled.parent.mkdir(parents=True, exist_ok=True)
            spooled.write_bytes(path.read_bytes())
            spooled.parent.chmod(0o755)
            spooled.chmod(0o644)
            sourcetype = f"pcapforge:{path.stem}"
            self.sourcetype(sourcetype)
            status, body = self.call("/services/data/inputs/oneshot",
                                     {"name": str(spooled), "sourcetype": sourcetype, "index": index})
            assert status == 201, f"oneshot {spooled}: HTTP {status} {body}"
            expected += lines
        deadline = time.monotonic() + 600
        while True:
            rows, _ = self.search(f"| tstats count WHERE index={index}")
            count = int(rows[0]["count"]) if rows else 0
            if count >= expected:
                assert count == expected, f"index {index}: {count} events, export has {expected}"
                break
            assert time.monotonic() < deadline, f"index {index}: {count} of {expected} events after 10 min"
            time.sleep(2)
        rows, _ = self.search(f"index={index} | where abs(_time - epoch) > 0.001 | stats count")
        assert rows and rows[0]["count"] == "0", f"index {index}: {rows[0]['count']} events off their ts"

    def search(self, spl):
        """Rows of an all-time search (capture dates can lie ahead) and its error messages."""
        query = spl if spl.lstrip().startswith("|") else f"search {spl}"
        status, body = self.call("/services/search/jobs", {"search": query, "exec_mode": "oneshot", "count": 0})
        messages = [m.get("text", "") for m in body.get("messages", []) if m.get("type") in ("ERROR", "FATAL")]
        if status != 200:
            messages.append(f"HTTP {status}")
        return body.get("results", []), messages


class Elastic:
    def __init__(self, url):
        self.url = url

    def call(self, path, body=None, method="POST", content_type="application/json"):
        if body is not None and not isinstance(body, str):
            body = json.dumps(body)
        status, payload = request(f"{self.url}{path}", body, method=method,
                                  headers={"Content-Type": content_type})
        return status, json.loads(payload) if payload.strip() else {}

    def load(self, siem):
        """One index ``pcapforge-<dataset>`` per file, mapped and timestamped as Kibana's file upload does."""
        status, found = self.call("/_resolve/index/pcapforge-*", method="GET")  # wildcard deletes are refused
        for stale in found.get("indices", []) if status == 200 else []:
            self.call(f"/{stale['name']}", method="DELETE")
        for path in sorted(siem.glob("*.jsonl")):
            raw = path.read_text(encoding="utf-8")
            if not raw.strip():
                continue
            index = f"pcapforge-{path.stem}"
            status, structure = self.call("/_text_structure/find_structure?format=ndjson&timestamp_field=ts",
                                          raw, content_type="application/x-ndjson")
            assert status == 200, f"find_structure {path.name}: HTTP {status} {structure}"
            mappings = structure["mappings"]
            # Hunt queries never search the nested detail arrays (objects, controls, ...). Store them
            # unindexed so find_structure's per-field type guesses (e.g. a float objects.value seen as a
            # date) cannot reject a document; keep ts as the only date via timestamp_field.
            mappings["date_detection"] = False
            for nested in ("objects", "controls", "analog_outputs", "services", "tags", "iin_flags"):
                if nested in mappings.get("properties", {}):
                    mappings["properties"][nested] = {"type": "object", "enabled": False}
            status, body = self.call(f"/_ingest/pipeline/{index}", structure["ingest_pipeline"], method="PUT")
            assert status == 200, f"pipeline {index}: HTTP {status} {body}"
            status, body = self.call(f"/{index}", {"settings": {"index.default_pipeline": index,
                                                                "index.number_of_replicas": 0},
                                                   "mappings": mappings}, method="PUT")
            assert status == 200, f"index {index}: HTTP {status} {body}"
            lines = [line for line in raw.splitlines() if line.strip()]
            bulk = "".join('{"index":{}}\n' + line + "\n" for line in lines)
            status, body = self.call(f"/{index}/_bulk?refresh=true", bulk, content_type="application/x-ndjson")
            assert status == 200 and not body.get("errors"), f"bulk {index}: HTTP {status} " + json.dumps(
                next((i for i in body.get("items", []) if i["index"].get("error")), body))[:500]
            assert self.call(f"/{index}/_count", method="GET")[1]["count"] == len(lines)

    def kql(self, dataset, query):
        """Matching documents (up to 10 000) and the total, or the error the query raised."""
        status, body = self.call(f"/pcapforge-{dataset}/_search", {
            "size": 10000, "track_total_hits": True, "query": {"kql": {"query": query}}})
        if status != 200:
            return [], 0, [json.dumps(body.get("error", body))[:500]]
        return [h["_source"] for h in body["hits"]["hits"]], body["hits"]["total"]["value"], []


@pytest.fixture(scope="session")
def splunk(tmp_path_factory):
    spool = os.environ.get("PCAPFORGE_SPLUNK_SPOOL") or tmp_path_factory.mktemp("splunk-spool")
    client = Splunk(SPLUNK_URL, os.environ.get("PCAPFORGE_SPLUNK_AUTH", "admin:changeme"), spool)
    rows, errors = client.search("| makeresults")
    assert rows and not errors, f"Splunk at {SPLUNK_URL} not usable: {errors}"
    return client


@pytest.fixture(scope="session")
def elastic():
    client = Elastic(ELASTIC_URL)
    status, info = client.call("/", method="GET")
    assert status == 200, f"Elasticsearch at {ELASTIC_URL} not usable: HTTP {status} {info}"
    return client


def run_label(scenario_id, level):
    return f"{scenario_id}-{level}"


@pytest.mark.skipif(not SPLUNK_URL, reason="set PCAPFORGE_SPLUNK_URL to run the SPL queries against Splunk")
@pytest.mark.parametrize("scenario_id,level", RUNS, ids=[run_label(*r) for r in RUNS])
def test_spl_queries_run_and_return_the_answer(runs, splunk, scenario_id, level):
    directory, answers = runs(scenario_id, level)
    index = f"pcapforge_{RUNS.index((scenario_id, level))}"
    splunk.load(index, directory / "siem")
    failures = []
    for question in hunted(answers):
        hunt = question["hunt"]
        if not hunt.get("spl"):
            continue
        spl = hunt["spl"]
        assert spl.startswith("index=* "), f"{question['id']}: SPL must start with 'index=* '"
        spl = f"index={index} " + spl[len("index=* "):]  # this run's events only, nothing else changes
        base = spl.split("|", 1)[0]
        rows, errors = splunk.search(f"{base} | stats count")
        matched = int(rows[0]["count"]) if rows and not errors else 0
        rows, errors = splunk.search(spl)
        events = read_jsonl(directory / "siem" / f"{hunt.get('dataset', 'modbus')}.jsonl")
        missing = grounded(question["answer"], events) - set().union(*(flatten(r) for r in rows))
        if errors or not matched or not rows or missing:
            failures.append(f"{question['id']}: {hunt['spl']}\n  errors={errors} matched={matched} "
                            f"rows={len(rows)} missing={sorted(missing)}")
    assert not failures, "\n".join(failures)


@pytest.mark.skipif(not ELASTIC_URL, reason="set PCAPFORGE_ELASTIC_URL to run the KQL queries against Elasticsearch")
@pytest.mark.parametrize("scenario_id,level", RUNS, ids=[run_label(*r) for r in RUNS])
def test_kql_queries_run_and_match_the_answer(runs, elastic, scenario_id, level):
    directory, answers = runs(scenario_id, level)
    elastic.load(directory / "siem")
    failures = []
    for question in hunted(answers):
        hunt = question["hunt"]
        if not hunt.get("kql"):
            continue
        dataset = hunt.get("dataset", "modbus")
        hits, total, errors = elastic.kql(dataset, hunt["kql"])
        missing = set()
        if total <= len(hits):  # every match fetched: the answer must be among them
            events = read_jsonl(directory / "siem" / f"{dataset}.jsonl")
            missing = grounded(question["answer"], events) - set().union(set(), *(flatten(h) for h in hits))
        if errors or not total or missing:
            failures.append(f"{question['id']}: {hunt['kql']}\n  errors={errors} hits={total} "
                            f"missing={sorted(missing)}")
    assert not failures, "\n".join(failures)
