"""The hunting guide's Zeek queries (``hunt.zeek``), run over real Zeek logs of every scenario and level.

Every query must match records, ``hunt_rows`` must agree with the jq command the guide prints (when jq
is installed), and a text answer that is a field value of the queried log (an IP, a MAC, a function or
service name) must be among what the query prints; numbers and yes/no answers would match unrelated
fields by chance. A query over an ICSNPP log is skipped when that package is not installed."""

import json
import shutil
import subprocess

import pytest

from pcapforge.pipeline import generate
from pcapforge.scenario import discover
from pcapforge.tools import MIN_TSHARK, find_tool, tshark_version
from pcapforge.zeek import ICSNPP, IEC104_SCRIPTS, find_zeek, hunt_command, hunt_rows
from recordings import ensure_recorded

SEED = "siem-queries"   # the recordings tests/test_siem_queries.py caches
DURATION = 600.0
# Log name prefix -> the package (ICSNPP, or pcapforge's IEC 104 analyzer) that writes it.
PACKAGE_LOGS = {"s7comm": "icsnpp-s7comm", "cotp": "icsnpp-s7comm", "opcua_binary": "icsnpp-opcua-binary",
                "bacnet": "icsnpp-bacnet", "enip": "icsnpp-enip", "cip": "icsnpp-enip",
                "dnp3_control": "icsnpp-dnp3", "dnp3_objects": "icsnpp-dnp3", "iec104": IEC104_SCRIPTS}

capture_tools = (find_tool("tshark") and (find_tool("dumpcap") or find_tool("tcpdump"))
                 and tshark_version() >= MIN_TSHARK)


def installed() -> set[str]:
    zeek = find_zeek()
    if not zeek:
        return set()
    scripts = {name: f"packages/{name}" for name in ICSNPP} | {IEC104_SCRIPTS: IEC104_SCRIPTS}
    probe = "event zeek_init() { " + " ".join(
        f'if ( find_in_zeekpath("{path}") != "" ) print "{name}";' for name, path in scripts.items()) + " }"
    proc = subprocess.run([*zeek, "-b", "-e", probe], capture_output=True, text=True, timeout=120, check=False)
    return set(proc.stdout.split()) if proc.returncode == 0 else set()


INSTALLED = installed() if capture_tools else set()
RUNS = [(sid, level) for sid, sc in sorted(discover().items())
        if any(q.get("hunt", {}).get("zeek") for q in sc.doc.get("questions", []))
        for level in ("easy", "medium", "hard")]


@pytest.fixture(scope="session")
def runs(tmp_path_factory):
    root = tmp_path_factory.mktemp("zeek-runs")
    cache = {}

    def get(scenario_id, level):
        if (scenario_id, level) not in cache:
            ensure_recorded(discover()[scenario_id], level, SEED, DURATION, root / "recording")
            result = generate(discover()[scenario_id], level, SEED, root, duration=DURATION, zeek=True)
            assert result.report.ok, [c for c in result.report.checks if not c["ok"]]
            answers = json.loads(result.answers.read_text(encoding="utf-8"))
            cache[scenario_id, level] = (result.directory, answers)
        return cache[scenario_id, level]
    return get


def text(value):
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value)


def flatten(value):
    if isinstance(value, dict):
        return set().union(set(), *(flatten(v) for v in value.values()))
    if isinstance(value, list):
        return set().union(set(), *(flatten(v) for v in value))
    return set() if value is None else {text(value)}


def package_of(log):
    return next((p for prefix, p in PACKAGE_LOGS.items() if log.startswith(prefix)), None)


@pytest.mark.skipif(not capture_tools or not find_zeek(), reason="requires tshark >= 4.4, loopback capture and zeek")
@pytest.mark.parametrize("scenario_id,level", RUNS, ids=[f"{s}-{lv}" for s, lv in RUNS])
def test_zeek_queries_match_the_logs_and_return_the_answer(runs, scenario_id, level):
    directory, answers = runs(scenario_id, level)
    failures, skipped = [], []
    for question in answers["questions"]:
        query = question.get("hunt", {}).get("zeek")
        if not query:
            continue
        package = package_of(query["log"])
        if package and package not in INSTALLED:
            skipped.append(question["id"])
            continue
        path = directory / "zeek" / f"{query['log']}.log"
        records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()] if path.exists() else []
        rows = hunt_rows(query, records)
        command = hunt_command(query)
        if shutil.which("jq") and path.exists():
            out = subprocess.run(command, shell=True, cwd=directory, capture_output=True, text=True, check=True).stdout
            printed = [json.loads(line) for line in out.splitlines()]
            key = lambda row: json.dumps(row, sort_keys=True)  # noqa: E731
            if sorted(map(key, printed)) != sorted(map(key, rows)):
                failures.append(f"{question['id']}: jq and hunt_rows differ: {command}")
        present = set().union(set(), *(flatten(r) for r in records))
        answer = {s for s in flatten(question["answer"]) & present
                  if s not in ("true", "false") and not s.lstrip("-").replace(".", "").isdigit()}
        missing = answer - set().union(set(), *(flatten(r) for r in rows))
        if not rows or missing:
            failures.append(f"{question['id']}: {command}\n  rows={len(rows)} missing={sorted(missing)}")
    assert not failures, "\n".join(failures)
    if skipped:
        pytest.skip(f"ICSNPP package missing for {skipped}")
