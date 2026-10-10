"""IEC 60870-5-104 actors: planning, APCI / ASDU encoding, and a recorded session decoded by tshark."""

import datetime as dt
import json
import struct
import subprocess
from pathlib import Path

import pytest

from pcapforge.actors import iec104
from pcapforge.compose import compose
from pcapforge.plan import build_plan
from pcapforge.process import ProcessProfile, ProcessSim
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
# The dispatcher's control operations and counter interrogation compressed into a few minutes.
CONTROL = {**MASTER, "params": {"targets": "rtu", "gi_interval_s": 60, "setpoint_interval_s": 50,
                                "switching_interval_s": 90, "counter_interval_s": 60}}


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
    for bad in ({"t2_s": 0}, {"counter_interval_s": -1}, {"switching_interval_s": -5}):
        with pytest.raises(ScenarioError, match="scada_104"):
            build_plan(scenario([RTU, {**MASTER, "params": {"targets": "rtu", **bad}}]), "easy", "bad")


def test_master_needs_an_rtu_on_its_targets():
    with pytest.raises(ScenarioError, match="no iec104.server runs on host 'hmi'"):
        build_plan(scenario([RTU, {**MASTER, "params": {"targets": "hmi"}}]), "easy", "no-rtu")


def test_server_without_modbus_needs_a_process():
    with pytest.raises(ScenarioError, match="needs params.process"):
        build_plan(scenario([{**RTU, "params": {}}, MASTER]), "easy", "no-process")


def test_signal_list_has_integrated_totals_and_commands_returning_their_state():
    rtu = build_plan(scenario([RTU, MASTER]), "easy", "plan").facts["rtu_104"]["rtus"][0]
    assert [(c["ioa"], c["name"], c["type_id"]) for c in rtu["counters"]] == [(4001, "energy_import_mwh", 15)]
    commands = {c["name"]: c for c in rtu["commands"]}
    assert (commands["tap_position_sp"]["ioa"], commands["tap_position_sp"]["type_id"],
            commands["tap_position_sp"]["select_before_operate"], commands["tap_position_sp"]["feedback_ioa"]) \
        == (5001, 50, False, 3001)
    assert (commands["feeder2_cb_close"]["ioa"], commands["feeder2_cb_close"]["type_id"],
            commands["feeder2_cb_close"]["select_before_operate"], commands["feeder2_cb_close"]["feedback"]) \
        == (6002, 45, True, "feeder2_cb_closed")
    assert commands["avr_auto"]["feedback_ioa"] is None             # no status point mirrors it
    addresses = [o["ioa"] for kind in ("objects", "counters", "commands") for o in rtu[kind]]
    assert len(set(addresses)) == len(addresses)


def test_command_and_integrated_total_elements():
    profile = ProcessProfile("power_substation")
    commands = {c.point.name: c for c in iec104.command_objects(profile, iec104.info_objects(profile))}
    breaker, tap = commands["feeder1_cb_close"], commands["tap_position_sp"]
    assert breaker.element(0, select=True) == iec104.ioa(6001) + bytes([0x80])   # SCO: S/E select, OFF
    assert breaker.element(1) == iec104.ioa(6001) + bytes([0x01])                # execute ON, QU 0
    assert tap.element(10.0) == iec104.ioa(5001) + struct.pack("<fB", 10.0, 0)   # QOS: QL 0, execute
    counter = iec104.counter_objects(profile)[0]
    assert counter.encode(21873, 33) == iec104.ioa(4001) + struct.pack("<i", 21873) + bytes([1])
    assert counter.encode(-2, 31, adjusted=True)[3:] == struct.pack("<i", -2) + bytes([0x40 | 31])


def test_counter_freeze_advances_the_sequence_number_and_reset_adjusts_the_counters():
    plan = build_plan(scenario([RTU, MASTER]), "easy", "plan")
    station = next(a for a in plan.actors if a.id == "rtu_104").stations["rtu"]
    totals = iec104._Totals(station, 31)

    def read(total: float) -> tuple[int, int]:
        (raw,) = totals.read({"energy_import_mwh": total})
        return struct.unpack("<iB", raw[3:])

    assert read(100.4) == (100, 31)                       # never frozen: the running count
    totals.apply(iec104.FRZ_FREEZE, {"energy_import_mwh": 101.0})
    assert read(150.0) == (101, 0)                        # the frozen count; SQ wraps after 31
    totals.apply(iec104.FRZ_FREEZE_RESET, {"energy_import_mwh": 120.0})
    assert read(130.0) == (120, 0x40 | 1)                 # frozen before the reset, CA set once
    assert read(130.0) == (120, 1)
    totals.apply(iec104.FRZ_FREEZE, {"energy_import_mwh": 125.2})
    assert read(130.0) == (5, 2)                          # counted from the reset


def test_control_operations_and_counter_interrogation_are_planned_on_the_scenario_clock():
    plan = build_plan(scenario([RTU, CONTROL], duration="4m"), "easy", "control")
    master = [a for a in plan.actions if a.actor == "scada_104"]
    executes = [a for a in master if a.op == "iec104.execute"]
    terminations = [a for a in plan.actions if a.op == "iec104.terminate"]
    assert executes and len(terminations) == len(executes)
    for execute in executes:          # the RTU operates and terminates each executed command
        assert sum(1 for a in terminations if a.args["ioa"] == execute.args["ioa"] and 0 < a.t - execute.t < 1
                   and (a.actor, a.host) == ("rtu_104", "rtu")) == 1
    for select in (a for a in master if a.op == "iec104.select"):
        execute = next(a for a in executes if a.t > select.t and a.args["ioa"] == select.args["ioa"])
        assert execute.args["value"] == select.args["value"]
        assert 1 <= execute.t - select.t <= 4 < iec104.SELECT_TIMEOUT

    facts = plan.facts["scada_104"]
    switching = [o for o in facts["operations"] if o["kind"] == "switching"]
    assert switching and [o["value"] for o in switching] == [0, 1] * (len(switching) // 2)  # breaker back in
    setpoints = [o["value"] for o in facts["operations"] if o["kind"] == "setpoint"]
    assert len(setpoints) >= 3 and all(5 <= v <= 13 for v in setpoints)
    assert all(a != b for a, b in zip(setpoints, setpoints[1:]))

    interrogations = [a for a in master if a.op == "iec104.ci"]
    freezes, reads = interrogations[0::2], interrogations[1::2]
    assert len(freezes) == len(reads) == facts["counter_interrogations"] >= 3
    assert {a.args["qcc"] for a in freezes} == {0x45} and {a.args["qcc"] for a in reads} == {0x05}
    assert all(0 < (plan.start_epoch + f.t) % 60 < 0.5 and 1 <= r.t - f.t <= 3 for f, r in zip(freezes, reads))


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


def tshark_fields(pcap: Path, display_filter: str, *names: str, occurrence: str = "a") -> list[list[str]]:
    names = names or ("frame.number",)
    cmd = [find_tool("tshark"), "-n", "-r", str(pcap), "-Y", display_filter, "-T", "fields",
           "-E", "separator=|", "-E", f"occurrence={occurrence}", *[arg for n in names for arg in ("-e", n)]]
    return [line.split("|") for line in
            subprocess.run(cmd, capture_output=True, text=True, check=True).stdout.splitlines()]


def decoded_asdus(pcap: Path) -> list[dict]:
    """Every ASDU tshark decodes, in capture order: type, cause of transmission and information
    objects (tshark field -> value, nested trees flattened)."""
    cmd = [find_tool("tshark"), "-n", "-r", str(pcap), "-Y", "iec60870_asdu", "-T", "json", "--no-duplicate-keys",
           "-J", "frame iec60870_asdu"]
    packets = json.loads(subprocess.run(cmd, capture_output=True, text=True, check=True).stdout)

    def flat(tree: dict, into: dict) -> dict:
        for key, value in tree.items():
            if isinstance(value, dict):
                flat(value, into)
            else:
                into[key] = value
        return into

    out = []
    for packet in packets:
        layers = packet["_source"]["layers"]
        units = layers["iec60870_asdu"]
        for unit in units if isinstance(units, list) else [units]:
            out.append({"frame": int(layers["frame"]["frame.number"]), "type": int(unit["iec60870_asdu.typeid"]),
                        "cot": int(unit["iec60870_asdu.causetx"]),
                        "objects": [flat(v, {}) for k, v in unit.items() if k.startswith("IOA")]})
    return out


def assert_flow_control(pcap: Path) -> int:
    """N(S) counts up from 0 without gaps in both directions; N(R) never acknowledges more than
    was sent, and no side has more than k unacknowledged I-frames outstanding. Returns the number
    of (connection, sender) pairs."""
    sent: dict[tuple[str, str], int] = {}
    acked: dict[tuple[str, str], int] = {}          # (stream, sender) -> I-frames the peer acknowledged
    for stream, src, dst, kinds, txs, rxs in tshark_fields(pcap, "iec60870_104", "tcp.stream", "ip.src", "ip.dst",
                                                           "iec60870_104.type", "iec60870_104.tx",
                                                           "iec60870_104.rx"):
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
    return len(sent)


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
        return tshark_fields(pcap, display_filter, *names, occurrence=occurrence)

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
    # the system frequency stays inside its band. Monitored floats are measurands (IOA 2001-4000).
    server = next(a for a in plan.actors if a.id == "rtu_104")
    station = server.stations["rtu"]
    state = ProcessSim(station.profile, server.rng.child("rtu"), plan.start_hour).state
    expected = {o.ioa: struct.unpack("<f", struct.pack("<f", state[o.point.name]))[0]
                for o in station.objects if o.point.table == "holding"}
    frequency_ioa = next(o["ioa"] for o in rtu["objects"] if o["name"] == "frequency")
    floats: dict[int, list[float]] = {}
    for ioas, values in fields("iec60870_asdu.float", "iec60870_asdu.ioa", "iec60870_asdu.float"):
        measurands = [int(i) for i in ioas.split(",") if 2001 <= int(i) < iec104.COUNTER_BASE]
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

    assert assert_flow_control(pcap) == 4


@pytest.mark.skipif(not capture_tools, reason="requires tshark >= 4.4 and loopback capture rights")
def test_recorded_commands_and_counter_interrogation_decode_in_sequence(tmp_path, monkeypatch):
    monkeypatch.setenv("PCAPFORGE_CACHE", str(tmp_path / "cache"))
    plan = build_plan(scenario([RTU, CONTROL], duration="4m"), "easy", "control")
    recording, _ = recording_for(plan, use_cache=False)
    pcap = compose(plan, recording, tmp_path / "control.pcap", "control").path
    report = verify_capture(pcap)
    assert report.ok, [c for c in report.checks if not c["ok"]]
    assert assert_flow_control(pcap) == 2
    units = decoded_asdus(pcap)
    operations = plan.facts["scada_104"]["operations"]

    def element(unit: dict, name: str) -> str:
        (obj,) = unit["objects"]
        return obj[f"iec60870_asdu.{name}"]

    # Select-before-operate: select ACT / ACTCON (S/E 1), execute ACT / ACTCON (S/E 0), the breaker
    # status as return information (COT 11), ACTTERM - for every switching operation, in order.
    first = next(o for o in operations if o["kind"] == "switching")
    switching = [o for o in operations if o["kind"] == "switching" and o["ioa"] == first["ioa"]]
    command_ioa, status_ioa = first["ioa"], first["feedback_ioa"]
    seen = []
    for unit in units:
        address = int(unit["objects"][0]["iec60870_asdu.ioa"]) if unit["objects"] else None
        if unit["type"] == 45 and address == command_ioa:
            seen.append((45, unit["cot"], int(element(unit, "sco.se")), int(element(unit, "sco.on"))))
        elif unit["cot"] == 11 and address == status_ioa:
            seen.append((unit["type"], 11, None, int(element(unit, "siq.spi"))))
    assert seen == [step for o in switching for step in
                    ((45, 6, 1, o["value"]), (45, 7, 1, o["value"]), (45, 6, 0, o["value"]),
                     (45, 7, 0, o["value"]), (30, 11, None, o["value"]), (45, 10, 0, o["value"]))]

    # Setpoints: ACT / ACTCON / ACTTERM carry the planned value; the setpoint feedback returns it
    # (COT 11) whenever it changed, and every later report of the feedback shows it.
    server = next(a for a in plan.actors if a.id == "rtu_104")
    initial = ProcessSim(server.stations["rtu"].profile, server.rng.child("rtu"), plan.start_hour).state
    setpoints = [o for o in operations if o["kind"] == "setpoint"]
    values = [o["value"] for o in setpoints]
    commanded = [(unit["cot"], float(element(unit, "float"))) for unit in units if unit["type"] == 50]
    assert commanded == [(cot, v) for v in values for cot in (6, 7, 10)]
    feedback_ioa = setpoints[0]["feedback_ioa"]
    returned, latest = [], initial[setpoints[0]["point"]]
    for unit in units:
        for obj in unit["objects"]:
            if int(obj["iec60870_asdu.ioa"]) != feedback_ioa:
                continue
            value = float(obj["iec60870_asdu.float"])
            if unit["cot"] == 11:
                returned.append(value)
                latest = value
            else:
                assert value == latest
    assert returned == [v for before, v in zip([initial[setpoints[0]["point"]], *values], values) if v != before]

    # Counter interrogation: freeze (QCC 0x45) ACT / ACTCON / ACTTERM, then read (QCC 0x05) ACT /
    # ACTCON / integrated totals (COT 37) / ACTTERM; the BCR sequence number advances by one per
    # freeze and the energy count never decreases.
    interrogation = [(u["type"], u["cot"], int(element(u, "qcc"), 0) if u["type"] == 101 else None)
                     for u in units if u["type"] in (101, 15)]
    rounds = plan.facts["scada_104"]["counter_interrogations"]
    assert interrogation == [(101, 6, 0x45), (101, 7, 0x45), (101, 10, 0x45), (101, 6, 0x05), (101, 7, 0x05),
                             (15, 37, None), (101, 10, 0x05)] * rounds
    totals = [u["objects"][0] for u in units if u["type"] == 15]
    sequence = [int(t["iec60870_asdu.bcr.sq"]) for t in totals]
    assert all(b == (a + 1) % 32 for a, b in zip(sequence, sequence[1:]))
    counts = [int(t["iec60870_asdu.bcr.count"]) for t in totals]
    assert counts == sorted(counts) and 21873 <= counts[0] and counts[-1] <= 21873 + 2
    assert {(t["iec60870_asdu.ioa"], t["iec60870_asdu.bcr.cy"], t["iec60870_asdu.bcr.ca"],
             t["iec60870_asdu.bcr.iv"]) for t in totals} == {("4001", "0", "0", "0")}
