"""DNP3 actors: planning, link/transport encoding, outstation logic and a recorded polled session."""

import struct
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

import pcapforge.actors.dnp3 as dnp3
from pcapforge.compose import compose
from pcapforge.plan import build_plan
from pcapforge.record import recording_for
from pcapforge.scenario import Scenario, ScenarioError
from pcapforge.tools import MIN_TSHARK, find_tool, tshark_version
from pcapforge.verify import verify_capture


def scenario(actors, duration="3m"):
    doc = {
        "id": "test-dnp3", "title": "DNP3 background", "line": "ot", "version": 1,
        "site": {"names": ["Testfield"], "codes": ["tst"]},
        "topology": {
            "sensor": "control",
            "subnets": [{"id": "control", "pool": "10.0.0.0/8", "prefix": 24}],
            "hosts": [
                {"id": "rtu", "device": "sel-rtac", "subnet": "control", "name": "rtac-{code}-01"},
                {"id": "scada", "device": "scada-server-vm", "subnet": "control", "name": "SCADA-01"},
            ],
        },
        "actors": actors,
        "difficulty": {"easy": {"duration": duration, "vars": {}}},
    }
    return Scenario(Path("test-dnp3.yaml"), doc)


SERVER = {"id": "rtu_dnp3", "type": "dnp3.server", "hosts": "rtu", "params": {"process": "wastewater_treatment"}}
CLIENT = {"id": "scada_dnp3", "type": "dnp3.client", "hosts": "scada",
          "params": {"targets": "rtu", "integrity_s": 60, "event_s": 30, "link_status_s": 20}}


def ops(plan, op):
    return [a for a in plan.actions if a.op == op]


# --- encoding ---------------------------------------------------------------------------

def test_crc16_dnp_matches_the_catalogue_check_value_and_a_known_link_header():
    assert dnp3.crc16(b"123456789") == 0xEA82
    # Reset Link States from master 1024 to outstation 1: the textbook header and its CRC.
    assert dnp3.link_frame(0xC0, 1, 1024) == bytes.fromhex("056405c001000004e921")


def test_link_frame_splits_user_data_into_crc_protected_16_byte_blocks():
    # Integrity poll (transport FIR|FIN seq 0, application FIR|FIN seq 1, READ g60v2/3/4/1).
    poll = bytes.fromhex("c0c1013c02063c03063c04063c0106")
    assert dnp3.link_frame(0xC4, 1, 0, poll) == bytes.fromhex(
        "056414c401000000afb9" "c0c1013c02063c03063c04063c0106" "7a6f")
    data = bytes(range(250))
    frame = dnp3.link_frame(0x44, 3, 77, data)
    assert len(frame) == dnp3.frame_size(255) == 292
    offset = 10
    for start in range(0, 250, 16):
        block = data[start:start + 16]
        assert frame[offset:offset + len(block)] == block
        assert struct.unpack_from("<H", frame, offset + len(block))[0] == dnp3.crc16(block)
        offset += len(block) + 2
    assert dnp3.parse_link(frame) == (0x44, 3, 77, data)
    with pytest.raises(ValueError, match="data block CRC"):
        dnp3.parse_link(frame[:20] + bytes([frame[20] ^ 1]) + frame[21:])
    with pytest.raises(ValueError, match="header CRC"):
        dnp3.parse_link(frame[:3] + b"\x45" + frame[4:])
    with pytest.raises(ValueError):
        dnp3.link_frame(0x44, 3, 77, bytes(251))


def test_transport_segments_carry_fir_fin_and_a_wrapping_sequence():
    fragment = bytes(range(249)) * 2 + bytes(100)
    pieces, after = dnp3.segments(fragment, 62)
    assert [p[0] for p in pieces] == [0x40 | 62, 63, 0x80 | 0]
    assert b"".join(p[1:] for p in pieces) == fragment
    assert all(len(p) <= dnp3.LINK_MAX_DATA for p in pieces) and after == 1
    single, after = dnp3.segments(b"\xc0\x81\x00\x00", 5)
    assert single == [bytes([0xC0 | 5]) + b"\xc0\x81\x00\x00"] and after == 6


def test_time48_is_little_endian_milliseconds():
    assert dnp3.time48(0x0123456789AB) == bytes.fromhex("ab8967452301")


# --- outstation logic ---------------------------------------------------------------------

class _Sim:
    def __init__(self, tables):
        self.tables = tables

    def advance(self, t):
        pass

    def values(self, table):
        return dict(self.tables[table])


def _outstation(monkeypatch, plan):
    server = next(a for a in plan.actors if a.type == "dnp3.server")
    host = plan.topology.by_id["rtu"]
    profile = server.configs["rtu"].profile
    tables = {t: {p.name: p.nominal for p in profile.table(t)} for t in ("discrete", "input", "coils", "holding")}
    sim = _Sim(tables)
    monkeypatch.setattr(dnp3, "host_sim", lambda rt, actor, h, prof: sim)
    rt = SimpleNamespace(plan=plan, clock=SimpleNamespace(t=10.0))
    return dnp3.Outstation(rt, server, host, server.configs["rtu"]), tables, rt


def test_outstation_reports_iin_restart_time_and_buffered_events(monkeypatch):
    plan = build_plan(scenario([SERVER, CLIENT]), "easy", "outstation")
    station, tables, rt = _outstation(monkeypatch, plan)
    assoc = station.association(1)

    def request(seq, function, objects=b""):
        return station.handle(assoc, bytes([0xC0 | seq, function]) + objects)

    response = request(0, dnp3.FC_DISABLE_UNSOLICITED, dnp3.class_objects([1, 2, 3]))
    assert response == bytes([0xC0, 0x81, 0x90, 0x00])          # DEVICE_RESTART | NEED_TIME
    integrity = request(1, dnp3.FC_READ, dnp3.class_objects([1, 2, 3, 0]))
    assert integrity[:4] == bytes([0xC1, 0x81, 0x90, 0x00])     # no events after restart, no CON
    analogs = station.points["analog_inputs"]
    assert integrity[4:9] == bytes([1, 2, 0, 0, len(station.points["binary_inputs"]) - 1])
    start = integrity.index(bytes([30, 5, 0, 0, len(analogs) - 1])) + 5
    assert struct.unpack_from("<Bf", integrity, start) == (1, pytest.approx(analogs[0].nominal))

    assert request(2, dnp3.FC_WRITE, bytes([80, 1, 0, 7, 7, 0]))[2] == 0x10
    assert request(3, dnp3.FC_RECORD_CURRENT_TIME)[2] == 0x10
    assert request(4, dnp3.FC_WRITE, bytes([50, 3, 7, 1]) + dnp3.time48(1_700_000_000_000))[2:4] == b"\x00\x00"

    # An analog moving beyond its deadband and a binary input flipping become buffered events:
    # a write response flags both classes; the event poll returns them and asks for a confirm.
    rt.clock.t = 15.0
    first = analogs[0]
    tables["input"][first.name] = first.nominal + 2 * station.deadbands[0]
    flipped = station.points["binary_inputs"][0]
    tables["discrete"][flipped.name] = 1.0 - flipped.nominal
    assert request(5, dnp3.FC_RECORD_CURRENT_TIME)[2] == 0x02 | 0x04
    poll = request(6, dnp3.FC_READ, dnp3.class_objects([1, 2, 3]))
    assert poll[0] == 0xC0 | 0x20 | 6 and poll[2:4] == b"\x00\x00"
    assert poll[4:9] == bytes([2, 2, 0x28, 1, 0]) and poll[9:11] == b"\x00\x00"
    analog_event = poll.index(bytes([32, 7, 0x28, 1, 0])) + 5
    index, flag, value = struct.unpack_from("<HBf", poll, analog_event)
    assert (index, flag, value) == (0, 1, pytest.approx(tables["input"][first.name]))
    # The crossing is interpolated between the previous scan (t=10) and this one (t=15).
    event_ms = int.from_bytes(poll[analog_event + 7:analog_event + 13], "little")
    assert dnp3.epoch_ms(plan.start_epoch + 10) < event_ms < dnp3.epoch_ms(plan.start_epoch + 15)
    # Unconfirmed events are still flagged; the confirm removes them.
    assert request(7, dnp3.FC_RECORD_CURRENT_TIME)[2] == 0x02 | 0x04
    assert station.handle(assoc, bytes([0xC7, dnp3.FC_CONFIRM])) is None
    assert assoc.events and request(8, dnp3.FC_RECORD_CURRENT_TIME)[2] == 0x06
    assert request(9, dnp3.FC_READ, dnp3.class_objects([1, 2, 3]))[0] & 0x20
    assert station.handle(assoc, bytes([0xC9, dnp3.FC_CONFIRM])) is None
    assert not assoc.events
    assert request(10, dnp3.FC_READ, dnp3.class_objects([1, 2, 3])) == bytes([0xCA, 0x81, 0, 0])


def test_unknown_requests_are_flagged_in_iin2(monkeypatch):
    plan = build_plan(scenario([SERVER, CLIENT]), "easy", "iin2")
    station, _, _ = _outstation(monkeypatch, plan)
    assoc = station.association(1)
    assert station.handle(assoc, bytes([0xC0, 13]))[3] == dnp3.IIN2_NO_FUNC_CODE_SUPPORT
    assert station.handle(assoc, bytes([0xC1, 1, 1, 2, 6]))[3] == dnp3.IIN2_OBJECT_UNKNOWN


# --- planning -----------------------------------------------------------------------------

def test_plan_is_deterministic_and_follows_the_startup_sequence():
    plan = build_plan(scenario([SERVER, CLIENT], duration="10m"), "easy", "seed-1")
    again = build_plan(scenario([SERVER, CLIENT], duration="10m"), "easy", "seed-1")
    assert [(a.t, a.op, a.args) for a in plan.actions] == [(a.t, a.op, a.args) for a in again.actions]
    session = [a for a in plan.actions if a.actor == "scada_dnp3"]
    startup = [a.op for a in session if a.phase == "setup"]
    assert startup == ["dnp3.connect", "dnp3.disable_unsolicited", "dnp3.read", "dnp3.clear_restart",
                       "dnp3.record_time", "dnp3.write_time"]
    record = ops(plan, "dnp3.record_time")[0]
    assert ops(plan, "dnp3.write_time")[0].args["time_ms"] == dnp3.epoch_ms(plan.start_epoch + record.t)
    reads = [a for a in ops(plan, "dnp3.read") if a.phase == "main"]
    integrity = [a for a in reads if 0 in a.args["classes"]]
    assert len(integrity) == 9 and all(a.args["classes"] == [1, 2, 3, 0] for a in integrity)
    assert all(a.args["classes"] == [1, 2, 3] for a in reads if a not in integrity)
    # Polls every 30 s or 60 s never leave the channel idle for the 20 s keep-alive.
    times = sorted(a.t for a in session if a.phase != "teardown")
    keepalives = {a.t for a in ops(plan, "dnp3.link_status")}
    assert keepalives
    for before, after in zip(times, times[1:]):
        assert after - before <= 20.0 + 1e-6 or after in keepalives
    assert ops(plan, "dnp3.close")[0].phase == "teardown"
    connect = ops(plan, "dnp3.connect")[0].args
    outstation = plan.facts["rtu_dnp3"]["outstations"][0]
    assert connect["master"] == 1 and connect["outstation"] == outstation["address"]
    assert 10 <= outstation["address"] <= 1000


def test_frequent_event_polls_need_no_keepalive():
    client = {**CLIENT, "params": {"targets": "rtu"}}
    plan = build_plan(scenario([SERVER, client], duration="10m"), "easy", "defaults")
    assert not ops(plan, "dnp3.link_status")
    reads = [a for a in ops(plan, "dnp3.read") if a.phase == "main"]
    assert 110 <= len(reads) <= 125 and all(a.args["classes"] == [1, 2, 3] for a in reads)


def test_facts_map_every_process_point_to_its_dnp3_object():
    plan = build_plan(scenario([SERVER, CLIENT]), "easy", "facts")
    facts = plan.facts["rtu_dnp3"]
    assert facts["unsolicited"] is False and facts["port"] == 20000
    station = facts["outstations"][0]
    assert station["host"] == {"$host": "rtu"} and station["process"] == "wastewater_treatment"
    assert station["product"] == "SEL-3530 RTAC" and station["master_addresses"] == [1]
    points = station["points"]
    assert [p["point"] for p in points["counters"]] == ["blower1_runtime_h", "influent_total_m3"]
    assert {(p["group"], p["variation"]) for p in points["counters"]} == {(20, 1)}
    analog = {p["point"]: p for p in points["analog_inputs"]}
    assert analog["influent_flow"] == {"index": 0, "point": "influent_flow", "unit": "m3/h",
                                       "desc": "Influent flow", "group": 30, "variation": 5, "event_group": 32,
                                       "event_variation": 7, "event_class": 2,
                                       "deadband": pytest.approx(0.02 * 600)}
    assert {(p["group"], p["variation"], p["event_class"]) for p in points["binary_inputs"]} == {(1, 2, 1)}
    assert {(p["group"], p["variation"]) for p in points["binary_outputs"]} == {(10, 2)}
    assert [p["point"] for p in points["analog_outputs"]][:2] == ["do_sp", "ras_flow_sp"]
    client = plan.facts["scada_dnp3"]
    assert client["sessions"] == [{"host": {"$host": "scada"}, "target": {"$host": "rtu"}, "master_address": 1,
                                   "outstation_address": station["address"]}]
    assert (client["integrity_s"], client["event_s"], client["link_status_s"]) == (60, 30, 20)


@pytest.mark.parametrize("params, message", [
    ({"process": "wastewater_treatment", "deadband": 1.5}, "deadband"),
    ({"process": "wastewater_treatment", "address": 70000}, "link address"),
    ({"process": "wastewater_treatment", "address": 1}, "also a master address"),
    ({"process": "wastewater_treatment", "master_address": [3, 3]}, "distinct"),
    ({}, "needs params.process"),
])
def test_server_params_are_validated(params, message):
    with pytest.raises(ScenarioError, match=message):
        build_plan(scenario([{**SERVER, "params": params}, CLIENT]), "easy", "bad")


@pytest.mark.parametrize("params, message", [
    ({"targets": "rtu", "integrity_s": 0}, "integrity_s"),
    ({"targets": "rtu", "event_s": -1}, "event_s"),
    ({"targets": "rtu", "address": 7}, "accepts master addresses"),
])
def test_client_params_are_validated(params, message):
    with pytest.raises(ScenarioError, match=message):
        build_plan(scenario([SERVER, {**CLIENT, "params": params}]), "easy", "bad")


def test_client_needs_an_outstation_on_its_target():
    with pytest.raises(ScenarioError, match="no dnp3.server"):
        build_plan(scenario([{**CLIENT, "params": {"targets": "scada"}}, SERVER]), "easy", "none")


# --- recorded session -----------------------------------------------------------------------

capture_tools = (find_tool("tshark") and (find_tool("dumpcap") or find_tool("tcpdump"))
                 and tshark_version() >= MIN_TSHARK)


@pytest.mark.skipif(not capture_tools, reason="requires tshark >= 4.4 and loopback capture rights")
def test_recorded_dnp3_session_decodes_and_mirrors_the_process(tmp_path, monkeypatch):
    monkeypatch.setenv("PCAPFORGE_CACHE", str(tmp_path / "cache"))
    plan = build_plan(scenario([SERVER, CLIENT]), "easy", "e2e")
    recording, _ = recording_for(plan, use_cache=False)
    pcap = compose(plan, recording, tmp_path / "dnp3.pcap", "e2e").path
    report = verify_capture(pcap)
    assert report.ok, [c for c in report.checks if not c["ok"]]

    def fields(display_filter, *names):
        names = names or ("frame.number",)
        cmd = [find_tool("tshark"), "-n", "-r", str(pcap), "-Y", display_filter, "-T", "fields",
               "-E", "separator=|", *[arg for n in names for arg in ("-e", n)]]
        return [line.split("|") for line in
                subprocess.run(cmd, capture_output=True, text=True, check=True).stdout.splitlines()]

    assert not fields("dnp3.hdr.CRC.incorrect || dnp3.data_chunk.CRC.incorrect || _ws.malformed")
    reads = ops(plan, "dnp3.read")
    requests = fields("dnp3.al.func == 1 && dnp3.ctl.dir == 1")
    assert len(requests) >= len(reads)
    # Every request is answered: the READs plus DISABLE_UNSOLICITED, two WRITEs and RECORD_CURRENT_TIME.
    assert len(fields("dnp3.al.func == 129 && dnp3.ctl.dir == 0")) == len(requests) + 4
    assert len(fields("dnp3.al.func == 21")) == 1 and len(fields("dnp3.al.func == 24")) == 1
    # IIN: DEVICE_RESTART until the WRITE g80v1, NEED_TIME until the WRITE g50v3, then neither.
    iins = [int(row[0], 16) for row in fields("dnp3.al.func == 129", "dnp3.al.iin")]
    assert [iin & 0x9000 for iin in iins[:5]] == [0x9000, 0x9000, 0x1000, 0x1000, 0]
    assert all(iin & 0x9000 == 0 for iin in iins[5:])
    keepalives = len(ops(plan, "dnp3.link_status"))
    assert keepalives and len(fields("dnp3.ctl.prifunc == 9 && dnp3.ctl.dir == 1")) == keepalives
    assert len(fields("dnp3.ctl.secfunc == 11 && dnp3.ctl.dir == 0")) == keepalives
    # Integrity responses: dissolved oxygen (analog input 2) is plausible, and every analog event
    # reports the value of the same process snapshot as the static g30v5 objects.
    integrity = fields("dnp3.al.func == 129 && dnp3.al.obj == 0x1e05", "dnp3.al.ai.static.index",
                       "dnp3.al.ai.event.index", "dnp3.al.ana.float")
    assert len(integrity) == sum(1 for a in reads if 0 in a.args["classes"])
    for static_index, event_index, floats in integrity:
        values = [float(v) for v in floats.split(",")]
        events = event_index.split(",") if event_index else []
        static = dict(zip(static_index.split(","), values[len(events):]))
        assert 0.5 <= static["2"] <= 4.0
        assert all(static[index] == value for index, value in dict(zip(events, values)).items())
