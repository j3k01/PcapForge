"""IEC 60870-5-104 actors: planning, APCI / ASDU encoding, and a recorded session decoded by tshark."""

import datetime as dt
import struct
import subprocess
from pathlib import Path

import pytest

from pcapforge.actors import iec104
from pcapforge.compose import compose
from pcapforge.plan import build_plan
from pcapforge.process import ProcessSim
from pcapforge.record import recording_for
from pcapforge.scenario import Scenario, ScenarioError
from pcapforge.tools import MIN_TSHARK, find_tool, tshark_version
from pcapforge.verify import verify_capture


def scenario(actors, duration="3m"):
    doc = {
        "id": "test-iec104", "title": "IEC 104 background", "line": "ot", "version": 1,
        "site": {"names": ["Testfield"], "codes": ["tst"]},
        "topology": {
            "sensor": "control",
            "subnets": [{"id": "control", "pool": "10.0.0.0/8", "prefix": 24}],
            "hosts": [
                {"id": "rtu", "device": "abb-rtu560", "subnet": "control", "name": "rtu-{code}-01"},
                {"id": "scada", "device": "scada-server-vm", "subnet": "control", "name": "SCADA-01"},
                {"id": "hmi", "device": "windows-workstation", "subnet": "control", "name": "HMI-01"},
            ],
        },
        "actors": actors,
        "difficulty": {"easy": {"duration": duration, "vars": {}}},
    }
    return Scenario(Path("test-iec104.yaml"), doc)


RTU = {"id": "rtu_104", "type": "iec104.server", "hosts": "rtu", "params": {"process": "power_substation"}}
MASTER = {"id": "scada_104", "type": "iec104.client", "hosts": "scada", "params": {"targets": "rtu",
                                                                                 "gi_interval_s": 60}}


def _actions(plan):
    return [(a.t, a.actor, a.host, a.op, a.phase, a.args) for a in plan.actions]


def test_planning_is_deterministic_and_the_signal_list_follows_the_process():
    plan = build_plan(scenario([RTU, MASTER]), "easy", "plan")
    again = build_plan(scenario([RTU, MASTER]), "easy", "plan")
    assert _actions(plan) == _actions(again) and plan.facts == again.facts

    rtu = plan.facts["rtu_104"]["rtus"][0]
    assert 1 <= rtu["common_address"] <= 0xFFFE
    objects = {o["name"]: o for o in rtu["objects"]}
    assert len(objects) == len(rtu["objects"])                    # one IOA per point
    assert (objects["feeder1_cb_closed"]["ioa"], objects["feeder1_cb_closed"]["type_id"],
            objects["feeder1_cb_closed"]["event_type_id"]) == (1001, 1, 30)
    assert (objects["tap_position"]["ioa"], objects["tap_position"]["type_id"],
            objects["tap_position"]["event_type_id"]) == (2001, 13, 36)
    assert (objects["tap_position_sp"]["ioa"], objects["tap_position_sp"]["type_id"]) == (3001, 13)
    assert objects["frequency"]["deadband"] == pytest.approx(0.02 * 0.1)

    sessions = plan.facts["scada_104"]["sessions"]
    assert sessions == [{"master": {"$host": "scada"}, "rtu": {"$host": "rtu"},
                         "common_address": rtu["common_address"]}]
    master = [a for a in plan.actions if a.actor == "scada_104"]
    assert [a.op for a in master[:3]] == ["iec104.connect", "iec104.clock_sync", "iec104.gi"]
    assert all(a.phase == "setup" for a in master[:3])
    assert master[-1].op == "iec104.close" and master[-1].phase == "teardown"
    assert all(a.args["ca"] == rtu["common_address"] for a in master if a.op in ("iec104.gi", "iec104.clock_sync"))
    gis = [a.t for a in master if a.op == "iec104.gi"]
    assert len(gis) == 3 and all(59 < b - a < 61 for a, b in zip(gis, gis[1:]))
    idle = [a.t for a in master if a.op == "iec104.idle"]
    assert idle and all(8.9 < b - a < 11.1 for a, b in zip(idle, idle[1:]))
    reports = [a for a in plan.actions if a.actor == "rtu_104"]
    assert {a.host for a in reports} == {"rtu"}
    cyclic = [a.t for a in reports if a.op == "iec104.cyclic"]
    assert all(9.9 < b - a < 10.1 for a, b in zip(cyclic, cyclic[1:]))


def test_common_address_parameter_and_validation():
    rtu = {**RTU, "params": {**RTU["params"], "common_address": {"rtu": 4711}}}
    plan = build_plan(scenario([rtu, MASTER]), "easy", "ca")
    assert plan.facts["rtu_104"]["rtus"][0]["common_address"] == 4711
    for bad in ({"common_address": 0}, {"common_address": 65535}, {"deadband": 0}, {"cyclic_s": -1}):
        with pytest.raises(ScenarioError, match="rtu_104"):
            build_plan(scenario([{**RTU, "params": {**RTU["params"], **bad}}, MASTER]), "easy", "bad")
    with pytest.raises(ScenarioError, match="scada_104"):
        build_plan(scenario([RTU, {**MASTER, "params": {"targets": "rtu", "t2_s": 0}}]), "easy", "bad")


def test_master_needs_an_rtu_on_its_targets():
    with pytest.raises(ScenarioError, match="no iec104.server runs on host 'hmi'"):
        build_plan(scenario([RTU, {**MASTER, "params": {"targets": "hmi"}}]), "easy", "no-rtu")


def test_server_without_modbus_needs_a_process():
    with pytest.raises(ScenarioError, match="needs params.process"):
        build_plan(scenario([{**RTU, "params": {}}, MASTER]), "easy", "no-process")


@pytest.mark.parametrize("ns, nr", [(0, 0), (1, 5), (127, 128), (32767, 32766)])
def test_i_frame_carries_15_bit_sequence_numbers_and_the_apdu_length(ns, nr):
    asdu = iec104.asdu_header(iec104.C_IC_NA_1, 1, iec104.ACTIVATION, 700) + iec104.ioa(0) + bytes([20])
    frame = iec104.i_frame(ns, nr, asdu)
    assert frame[0] == 0x68 and frame[1] == len(frame) - 2 == 4 + len(asdu)
    assert frame[2] & 0x01 == 0 and frame[4] & 0x01 == 0
    assert iec104.control_numbers(frame[2:]) == (ns, nr)
    assert frame[6:] == asdu


def test_s_and_u_frames():
    assert iec104.s_frame(5) == bytes.fromhex("68040100" "0a00")
    assert iec104.control_numbers(iec104.s_frame(32767)[2:])[1] == 32767
    assert iec104.u_frame(iec104.STARTDT_ACT) == bytes.fromhex("680407000000")
    assert iec104.u_frame(iec104.TESTFR_CON) == bytes.fromhex("680483000000")


def test_cp56time2a_encodes_utc_with_milliseconds_and_weekday():
    epoch = dt.datetime(2026, 2, 16, 17, 2, 5, 254000, tzinfo=dt.UTC).timestamp()   # a Monday
    raw = iec104.cp56time2a(epoch)
    assert raw == struct.pack("<HBBBBB", 5254, 2, 17, 1 << 5 | 16, 2, 26)
    assert iec104.parse_cp56time2a(raw) == pytest.approx(epoch, abs=1e-6)
    sunday = dt.datetime(2026, 12, 27, 23, 59, 59, 999600, tzinfo=dt.UTC).timestamp()
    raw = iec104.cp56time2a(sunday)                                  # rounds into the next minute
    assert raw == struct.pack("<HBBBBB", 0, 0, 0, 1 << 5 | 28, 12, 26)


@pytest.mark.parametrize("type_id, size", [(iec104.M_SP_NA_1, 4), (iec104.M_ME_NC_1, 8), (iec104.M_ME_TF_1, 15)])
def test_asdus_stay_inside_one_apdu_and_carry_every_object(type_id, size):
    objects = [iec104.ioa(2001 + i) + bytes(range(size - 3)) for i in range(300)]
    out = iec104.asdus(type_id, iec104.INROGEN, 700, objects)
    assert len(out) > 1
    recovered = []
    for asdu in out:
        assert len(asdu) + 4 <= iec104.MAX_APDU
        assert asdu[0] == type_id and asdu[2] == iec104.INROGEN and struct.unpack_from("<H", asdu, 4)[0] == 700
        count = asdu[1] & 0x7F
        assert asdu[1] & 0x80 == 0 and len(asdu) == 6 + count * size
        recovered += [asdu[6 + i * size: 6 + (i + 1) * size] for i in range(count)]
    assert recovered == objects


capture_tools = (find_tool("tshark") and (find_tool("dumpcap") or find_tool("tcpdump"))
                 and tshark_version() >= MIN_TSHARK)


@pytest.mark.skipif(not capture_tools, reason="requires tshark >= 4.4 and loopback capture rights")
def test_recorded_iec104_sessions_decode_and_mirror_the_process(tmp_path, monkeypatch):
    monkeypatch.setenv("PCAPFORGE_CACHE", str(tmp_path / "cache"))
    hmi = {"id": "hmi_104", "type": "iec104.client", "hosts": "hmi",
           "params": {"targets": "rtu", "t2_s": 40, "clock_sync": False}}
    plan = build_plan(scenario([RTU, MASTER, hmi]), "easy", "e2e")
    recording, _ = recording_for(plan, use_cache=False)
    pcap = compose(plan, recording, tmp_path / "iec104.pcap", "e2e").path
    report = verify_capture(pcap)
    assert report.ok, [c for c in report.checks if not c["ok"]]

    def fields(display_filter, *names, occurrence="a"):
        names = names or ("frame.number",)
        cmd = [find_tool("tshark"), "-n", "-r", str(pcap), "-Y", display_filter, "-T", "fields",
               "-E", "separator=|", "-E", f"occurrence={occurrence}", *[arg for n in names for arg in ("-e", n)]]
        return [line.split("|") for line in
                subprocess.run(cmd, capture_output=True, text=True, check=True).stdout.splitlines()]

    rtu = plan.facts["rtu_104"]["rtus"][0]
    # Every planned GI is confirmed, answered with COT 20 data and terminated.
    planned = sum(1 for a in plan.actions if a.op == "iec104.gi")
    gi = "iec60870_asdu.typeid == 100 && iec60870_asdu.causetx == {}"
    assert len(fields(gi.format(6))) == len(fields(gi.format(7))) == len(fields(gi.format(10))) == planned
    assert len(fields("iec60870_asdu.causetx == 20 && iec60870_asdu.typeid in {1, 13}")) >= planned
    assert len(fields("iec60870_asdu.typeid == 103 && iec60870_asdu.causetx == 7")) == 1
    assert {ca for row in fields("iec60870_asdu", "iec60870_asdu.addr")
            for ca in row[0].split(",")} == {str(rtu["common_address"])}

    # Float values mirror the process: setpoint feedback (IOA 3001+) equals the RTU's setpoints,
    # the system frequency stays inside its band. Only measurands (IOA >= 2001) carry floats.
    server = next(a for a in plan.actors if a.id == "rtu_104")
    station = server.stations["rtu"]
    state = ProcessSim(station.profile, server.rng.child("rtu"), plan.start_hour).state
    expected = {o.ioa: struct.unpack("<f", struct.pack("<f", state[o.point.name]))[0]
                for o in station.objects if o.point.table == "holding"}
    frequency_ioa = next(o["ioa"] for o in rtu["objects"] if o["name"] == "frequency")
    floats: dict[int, list[float]] = {}
    for ioas, values in fields("iec60870_asdu.float", "iec60870_asdu.ioa", "iec60870_asdu.float"):
        measurands = [int(i) for i in ioas.split(",") if int(i) >= 2001]
        assert len(measurands) == len(values.split(","))
        for ioa_, value in zip(measurands, values.split(",")):
            floats.setdefault(ioa_, []).append(float(value))
    for ioa_, value in expected.items():
        assert floats[ioa_] and all(v == pytest.approx(value, rel=1e-5) for v in floats[ioa_])
    assert floats[frequency_ioa] and all(49.95 - 1e-3 <= f <= 50.05 + 1e-3 for f in floats[frequency_ioa])

    # Periodic and spontaneous reports; event time tags lie before the frame that carries them.
    assert fields("iec60870_asdu.typeid == 13 && iec60870_asdu.causetx == 1")
    events = fields("iec60870_asdu.typeid == 36 && iec60870_asdu.causetx == 3", "frame.time_epoch",
                    "iec60870_asdu.cp56time.ms", "iec60870_asdu.cp56time.min", "iec60870_asdu.cp56time.hour",
                    "iec60870_asdu.cp56time.day", "iec60870_asdu.cp56time.month", "iec60870_asdu.cp56time.year",
                    occurrence="f")
    delays = []
    for when, ms, minute, hour, day, month, year in events:
        tag = dt.datetime(2000 + int(year), int(month), int(day), int(hour), int(minute), tzinfo=dt.UTC)
        delays.append(float(when) - (tag.timestamp() + int(ms) / 1000))
    assert delays and min(delays) >= 0 and sorted(delays)[len(delays) // 2] < 0.1

    # N(S) counts up from 0 without gaps in both directions; N(R) never acknowledges more than
    # was sent, and no side has more than k unacknowledged I-frames outstanding.
    sent: dict[tuple[str, str], int] = {}
    acked: dict[tuple[str, str], int] = {}          # (stream, sender) -> I-frames the peer acknowledged
    for stream, src, dst, kinds, txs, rxs in fields("iec60870_104", "tcp.stream", "ip.src", "ip.dst",
                                                     "iec60870_104.type", "iec60870_104.tx", "iec60870_104.rx"):
        tx, rx = iter(txs.split(",")), iter(rxs.split(","))
        for kind in (int(k, 16) for k in kinds.split(",")):
            if kind == 3:
                continue
            if kind == 0:
                assert int(next(tx)) == sent.get((stream, src), 0)
                sent[(stream, src)] = sent.get((stream, src), 0) + 1
                assert sent[(stream, src)] - acked.get((stream, src), 0) <= iec104.K
            nr = int(next(rx))
            assert acked.get((stream, dst), 0) <= nr <= sent.get((stream, dst), 0)
            acked[(stream, dst)] = nr
    assert len(sent) == 4
