"""S7comm actors: planning, the optional-extra error, and a recorded session decoded by tshark."""

import importlib.util
import struct
import subprocess
import sys
from pathlib import Path

import pytest

from pcapforge.actors import s7
from pcapforge.compose import compose
from pcapforge.plan import build_plan
from pcapforge.record import record, recording_for
from pcapforge.scenario import Scenario, ScenarioError
from pcapforge.tools import MIN_TSHARK, find_tool, tshark_version
from pcapforge.verify import verify_capture


def scenario(actors, plc_device="siemens-s7-1200"):
    doc = {
        "id": "test-s7", "title": "S7 background", "line": "ot", "version": 1,
        "site": {"names": ["Testfield"], "codes": ["tst"]},
        "topology": {
            "sensor": "control",
            "subnets": [{"id": "control", "pool": "10.0.0.0/8", "prefix": 24}],
            "hosts": [
                {"id": "plc", "device": plc_device, "subnet": "control", "name": "plc-{code}-01"},
                {"id": "hmi", "device": "windows-workstation", "subnet": "control", "name": "HMI-01"},
                {"id": "historian", "device": "windows-server-vm", "subnet": "control", "name": "HIST-01"},
            ],
        },
        "actors": actors,
        "difficulty": {"easy": {"duration": "3m", "vars": {}}},
    }
    return Scenario(Path("test-s7.yaml"), doc)


S7_ACTORS = [
    {"id": "plc_s7", "type": "s7.server", "hosts": "plc", "params": {"process": "water_treatment"}},
    {"id": "hmi_s7", "type": "s7.client", "hosts": "hmi", "params": {"targets": "plc", "interval": 1.0,
                                                                    "szl_interval": 30}},
    {"id": "historian_s7", "type": "s7.client", "hosts": "historian",
     "params": {"targets": "plc", "interval": 10, "dbs": [1], "identify": False, "szl_interval": 0}},
]


def test_planning_needs_no_snap7_and_recording_names_the_extra_before_capturing(monkeypatch, tmp_path):
    for name in ("snap7", "snap7.server", "snap7.datatypes", "snap7.type"):
        monkeypatch.setitem(sys.modules, name, None)
    plan = build_plan(scenario(S7_ACTORS), "easy", "no-extra")
    out = tmp_path / "recordings" / "s7.pcap"
    with pytest.raises(ScenarioError, match=r"s7\.server needs python-snap7: .*pcapforge\[s7\]"):
        record(plan, out)
    assert not out.parent.exists()


def test_server_on_a_modbus_plc_serves_its_process_and_rejects_another():
    modbus = {"id": "plc_mb", "type": "modbus.server", "hosts": "plc", "params": {"process": "water_treatment"}}
    plan = build_plan(scenario([modbus, {**S7_ACTORS[0], "params": {}}, S7_ACTORS[1]]), "easy", "shared")
    server = next(a for a in plan.actors if a.type == "s7.server")
    assert server.profiles["plc"].id == "water_treatment"
    conflicting = {**S7_ACTORS[0], "params": {"process": "wastewater_treatment"}}
    with pytest.raises(ScenarioError, match="water_treatment"):
        build_plan(scenario([modbus, conflicting, S7_ACTORS[1]]), "easy", "shared")


def test_server_rejects_a_device_that_is_not_an_s7_cpu():
    with pytest.raises(ScenarioError, match="not a known S7 CPU"):
        build_plan(scenario(S7_ACTORS, plc_device="schneider-m340"), "easy", "wrong-cpu")


@pytest.mark.parametrize("pdu", [240, 480])
def test_read_jobs_cover_every_byte_and_fit_the_negotiated_pdu(pdu):
    items = [(1, 0, 40), (2, 0, 700), (3, 0, 3), (4, 10, 225)]
    jobs = s7.read_jobs(items, pdu)
    covered = {}
    for job in jobs:
        request = 10 + 2 + 12 * len(job)
        response = 12 + 2 + sum(4 + size + size % 2 for _, _, size in job)
        assert request <= pdu and response <= pdu
        for db, start, size in job:
            covered.setdefault(db, []).append((start, size))
    for db, start, size in items:
        spans = sorted(covered[db])
        assert spans[0][0] == start and sum(s for _, s in spans) == size
        assert all(a + n == b for (a, n), (b, _) in zip(spans, spans[1:]))


capture_tools = (find_tool("tshark") and (find_tool("dumpcap") or find_tool("tcpdump"))
                 and tshark_version() >= MIN_TSHARK)


@pytest.mark.skipif(not capture_tools or importlib.util.find_spec("snap7") is None,
                    reason="requires python-snap7 (extra 's7'), tshark >= 4.4 and loopback capture rights")
def test_recorded_s7_sessions_decode_and_mirror_the_process(tmp_path, monkeypatch):
    monkeypatch.setenv("PCAPFORGE_CACHE", str(tmp_path / "cache"))
    plan = build_plan(scenario(S7_ACTORS), "easy", "e2e")
    recording, _ = recording_for(plan, use_cache=False)
    pcap = compose(plan, recording, tmp_path / "s7.pcap", "e2e").path
    report = verify_capture(pcap)
    assert report.ok, [c for c in report.checks if not c["ok"]]

    def fields(display_filter, *names):
        names = names or ("frame.number",)
        cmd = [find_tool("tshark"), "-n", "-r", str(pcap), "-Y", display_filter, "-T", "fields",
               "-E", "separator=|", *[arg for n in names for arg in ("-e", n)]]
        return [line.split("|") for line in
                subprocess.run(cmd, capture_output=True, text=True, check=True).stdout.splitlines()]

    planned_reads = sum(1 for a in plan.actions if a.op == "s7.read")
    assert len(fields("s7comm.header.rosctr == 1 && s7comm.param.func == 0x04")) == planned_reads
    assert len(fields("s7comm.header.rosctr == 3 && s7comm.param.func == 0x04")) == planned_reads
    # One persistent session per client, each negotiating the S7-1200's 240-byte PDU.
    assert len(fields("cotp.type == 0x0e")) == 2
    assert {row[0] for row in fields("s7comm.header.rosctr == 3 && s7comm.param.func == 0xf0",
                                     "s7comm.param.pdu_length")} == {"240"}
    szl = fields("s7comm.param.userdata.type == 2", "s7comm.data.userdata.szl_id")
    assert sorted({row[0] for row in szl}) == ["0x0011", "0x001c", "0x0424"]
    order_codes = {code.strip() for row in fields("s7comm.szl.xy11.0001.index == 0x0001",
                                                  "s7comm.szl.xy11.0001.anz")
                   for code in row[0].split(",") if code.strip()}
    assert order_codes == {"6ES7 214-1AG40-0XB0"}
    # DB1.DBD0 is the clearwell level: inside the process' plausible range in every response.
    levels = [struct.unpack(">f", bytes.fromhex(row[0].split(",")[0][:8]))[0]
              for row in fields("s7comm.header.rosctr == 3 && s7comm.param.func == 0x04", "s7comm.resp.data")]
    assert levels and all(300 <= level <= 400 for level in levels)
