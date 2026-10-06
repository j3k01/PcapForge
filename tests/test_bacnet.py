"""BACnet/IP actors: planning, the hand-written encoding, and a recorded exchange decoded by tshark."""

import struct
import subprocess
from collections import Counter
from pathlib import Path

import pytest

import pcapforge.actors.bacnet  # noqa: F401  (registers bacnet.server / bacnet.client)
from pcapforge.actors import bacnet
from pcapforge.compose import compose
from pcapforge.plan import build_plan
from pcapforge.process import ProcessProfile
from pcapforge.record import recording_for
from pcapforge.scenario import Scenario, ScenarioError
from pcapforge.tools import MIN_TSHARK, find_tool, tshark_version
from pcapforge.verify import verify_capture


def scenario(actors, duration="10m"):
    doc = {
        "id": "test-bacnet", "title": "BACnet background", "line": "ot", "version": 1,
        "site": {"names": ["Testfield"], "codes": ["tst"]},
        "topology": {
            "sensor": "bms",
            "subnets": [{"id": "bms", "pool": "10.0.0.0/8", "prefix": 24}],
            "hosts": [
                {"id": "ddc", "count": 2, "device": "siemens-pxc", "subnet": "bms", "name": "PXC-{code}-{index:02d}"},
                {"id": "ows", "device": "windows-workstation", "subnet": "bms", "name": "BMS-OWS-01"},
            ],
        },
        "actors": actors,
        "difficulty": {"easy": {"duration": duration, "impairments": {"mid_session": False}, "vars": {}}},
    }
    return Scenario(Path("test-bacnet.yaml"), doc)


SERVER = {"id": "ddc_bacnet", "type": "bacnet.server", "hosts": "ddc", "params": {"process": "hvac_building"}}
CLIENT = {"id": "ows_bacnet", "type": "bacnet.client", "hosts": "ows",
          "params": {"targets": "ddc", "poll_s": 30, "whois_s": 240}}


def ops(plan):
    return Counter((a.actor, a.op) for a in plan.actions)


def test_plan_is_deterministic_and_covers_discovery_startup_polls_and_cov():
    plan = build_plan(scenario([SERVER, CLIENT]), "easy", "plan")
    again = build_plan(scenario([SERVER, CLIENT]), "easy", "plan")
    assert plan.digest() == again.digest()
    counts = ops(plan)
    assert counts[("ows_bacnet", "bacnet.whois")] == 3                 # startup + every 240 s in 10 min
    assert counts[("ddc_bacnet", "bacnet.iam")] == 2 * 3                # both controllers answer each Who-Is
    # 3 COV objects per controller, subscribed at startup and renewed at ~80 % of 300 s.
    assert counts[("ows_bacnet", "bacnet.subscribe")] == 2 * 3 * 3
    assert counts[("ddc_bacnet", "bacnet.cov")] > 2 * 100
    polls = [a for a in plan.actions if a.op == "bacnet.rpm" and a.phase == "main"]
    assert len(polls) >= 2 * 15
    assert all(set(props) == {bacnet.PRESENT_VALUE, bacnet.STATUS_FLAGS} for a in polls for *_, props in a.args["specs"])
    # The startup reads the device and the structured view probe that the PXC rejects.
    reads = [a.args["property"] for a in plan.actions if a.op == "bacnet.read" and a.args["target"] == "ddc1"]
    assert reads[:len(bacnet.DEVICE_READS)] == list(bacnet.DEVICE_READS)
    assert bacnet.STRUCTURED_OBJECT_LIST in reads and bacnet.OBJECT_LIST in reads


def test_invoke_ids_count_up_per_session_in_request_order():
    plan = build_plan(scenario([SERVER, CLIENT]), "easy", "invoke")
    for target in ("ddc1", "ddc2"):
        ids = [a.args["invoke"] for a in plan.actions if a.args.get("target") == target and "invoke" in a.args]
        assert len(ids) > 30
        assert all((b - a) % 256 == 1 for a, b in zip(ids, ids[1:]))


def test_facts_map_objects_to_points_units_and_device_identity():
    plan = build_plan(scenario([SERVER, {**CLIENT, "params": {**CLIENT["params"], "cov": ["zone1_temp"]}}]),
                      "easy", "facts")
    server = plan.facts["ddc_bacnet"]
    first, second = server["controllers"]
    assert second["device_instance"] == first["device_instance"] + 1
    assert first["vendor_id"] == 7 and first["model_name"] == "PXC5.E003"
    assert first["firmware_revision"] == "V6.00.025" and first["device_name"].startswith("PXC-")
    objects = {(o["type"], o["instance"]): o for o in first["objects"]}
    profile = ProcessProfile("hvac_building")
    assert len(objects) == len(profile.points)
    assert objects[("analog-input", 1)]["point"] == "outdoor_air_temp"
    assert (objects[("analog-input", 1)]["units"], objects[("analog-input", 1)]["units_id"]) == ("degrees-celsius", 62)
    assert objects[("analog-input", 3)]["units_id"] == 96                    # zone_co2 ppm
    assert objects[("analog-value", 1)]["units"] == "no-units"               # control mode
    assert objects[("binary-value", 1)]["point"] == "supply_fan_run" and "units" not in objects[("binary-value", 1)]
    client = plan.facts["ows_bacnet"]
    assert client["targets"][0]["cov"] == [{"type": "analog-input", "instance": 5, "point": "zone1_temp"}]
    assert (client["poll_s"], client["cov_lifetime_s"], client["whois_s"]) == (30.0, 300, 240.0)


def test_server_shares_the_modbus_process_and_validates_params():
    modbus = {"id": "plc_mb", "type": "modbus.server", "hosts": "ddc", "params": {"process": "water_treatment"}}
    plan = build_plan(scenario([modbus, {**SERVER, "params": {}}, CLIENT]), "easy", "shared")
    assert {c["process"] for c in plan.facts["ddc_bacnet"]["controllers"]} == {"water_treatment"}
    with pytest.raises(ScenarioError, match="runs process"):
        build_plan(scenario([modbus, SERVER, CLIENT]), "easy", "conflict")
    with pytest.raises(ScenarioError, match="cov_increment"):
        build_plan(scenario([{**SERVER, "params": {"process": "hvac_building", "cov_increment": 2}}, CLIENT]),
                   "easy", "bad-increment")
    with pytest.raises(ScenarioError, match="unknown points"):
        build_plan(scenario([SERVER, {**CLIENT, "params": {"targets": "ddc", "cov": ["no_such_point"]}}]),
                   "easy", "bad-cov")
    with pytest.raises(ScenarioError, match="no bacnet.server"):
        build_plan(scenario([SERVER, {**CLIENT, "params": {"targets": "ows"}}]), "easy", "no-server")


def test_tags_round_trip_including_extended_lengths():
    for size in (0, 4, 5, 253, 254, 600):
        encoded = bacnet.tag(3, bytes(size), context=True)
        reader = bacnet.Reader(encoded)
        assert reader.context(3) == bytes(size) and reader.done()
    assert bacnet.app_uint(1476) == b"\x22\x05\xc4"
    assert bacnet.app_object(bacnet.DEVICE, 188301) == b"\xc4" + struct.pack(">I", 8 << 22 | 188301)
    assert bacnet.app_bits(0x8, 4) == b"\x82\x04\x80"                 # status-flags: in-alarm only
    assert bacnet.app_string("AHU") == b"\x74\x00AHU"
    reader = bacnet.Reader(bacnet.opening(1) + bacnet.ctx_uint(0, 85) + bacnet.closing(1))
    reader.enter(1)
    assert reader.unsigned(0) == 85 and reader.leave(1) and reader.done()


def test_messages_carry_their_own_length_and_reach_the_apdu():
    request = bacnet.message(bacnet.read_property(7, (0, 3), bacnet.PRESENT_VALUE), expecting_reply=True)
    assert request[:2] == b"\x81\x0a" and struct.unpack(">H", request[2:4])[0] == len(request)
    assert request[4:6] == b"\x01\x04"
    assert bacnet.apdu_of(request) == bytes([0x00, 0x05, 7, bacnet.READ_PROPERTY]) + b"\x0c\x00\x00\x00\x03\x19\x55"
    who_is = bacnet.who_is()
    assert who_is == b"\x81\x0b\x00\x0c\x01\x20\xff\xff\x00\xff\x10\x08"
    assert bacnet.apdu_of(who_is) == b"\x10\x08"


def _controller(process="hvac_building", increment=0.02):
    return bacnet.Controller(host_id="ddc", instance=1001, name="PXC-01", description="test", vendor_name="Siemens",
                             vendor_id=7, model="PXC5.E003", firmware="V6.00.025", application="V1.00",
                             database_revision=12, objects=bacnet.objects_of(ProcessProfile(process), increment))


def test_controller_reads_values_and_reports_errors():
    controller = _controller()
    values = {"input": {"outdoor_air_temp": 40.0}, "discrete": {"zone1_high_temp": 1.0}}
    snapshot = lambda table: values[table]  # noqa: E731
    assert controller.read((0, 1), bacnet.PRESENT_VALUE, None, snapshot) == bacnet.app_real(40.0)
    assert controller.read((0, 1), bacnet.STATUS_FLAGS, None, snapshot) == bacnet.app_bits(bacnet.IN_ALARM, 4)
    assert controller.read((0, 1), bacnet.EVENT_STATE, None, snapshot) == bacnet.app_enum(bacnet.HIGH_LIMIT)
    assert controller.read((3, 1), bacnet.PRESENT_VALUE, None, snapshot) == bacnet.app_enum(1)
    count = len(controller.objects) + 1
    assert controller.read(controller.device, bacnet.OBJECT_LIST, 0, snapshot) == bacnet.app_uint(count)
    assert controller.read(controller.device, bacnet.OBJECT_LIST, 1, snapshot) == bacnet.app_object(8, 1001)
    for key, prop, index, code in [((0, 99), bacnet.PRESENT_VALUE, None, bacnet.UNKNOWN_OBJECT),
                                   ((3, 1), bacnet.UNITS, None, bacnet.UNKNOWN_PROPERTY),
                                   (controller.device, bacnet.OBJECT_LIST, count + 1, bacnet.INVALID_ARRAY_INDEX),
                                   (controller.device, bacnet.OBJECT_NAME, 1, bacnet.PROPERTY_IS_NOT_AN_ARRAY)]:
        with pytest.raises(bacnet.BacnetError) as exc:
            controller.read(key, prop, index, snapshot)
        assert exc.value.code == code
    ack = controller.rpm_ack([[0, 99, [(bacnet.PRESENT_VALUE, None)]]], snapshot)
    assert ack.endswith(bacnet.opening(5) + bacnet.app_enum(bacnet.OBJECT_ERROR)
                        + bacnet.app_enum(bacnet.UNKNOWN_OBJECT) + bacnet.closing(5) + bacnet.closing(1))


@pytest.mark.parametrize("process", ["hvac_building", "power_substation", "water_treatment", "wastewater_treatment"])
def test_rpm_chunks_cover_every_object_once_and_fit_one_message(process):
    controller = _controller(process)
    for props in (lambda o: bacnet.POLLED, lambda o: bacnet.POINT_DATABASE[o.type]):
        chunks = bacnet.rpm_chunks(controller, controller.objects, props)
        assert [tuple(spec[:2]) for chunk in chunks for spec in chunk] == [o.key for o in controller.objects]
        for chunk in chunks:
            refs = [[t, i, [(p, None) for p in ps]] for t, i, ps in chunk]
            ack = bacnet.message(bacnet.complex_ack(0, bacnet.READ_PROPERTY_MULTIPLE,
                                                    controller.rpm_ack(refs, controller.nominal)))
            assert len(ack) <= bacnet.MESSAGE_BUDGET


def test_units_follow_the_bacnet_engineering_units_enumeration():
    expected = {"degC": 62, "%": 98, "Pa": 53, "ppm": 96, "kV": 6, "A": 3, "MW": 49, "Hz": 27, "m3/h": 135,
                "mg/L": 215, "pH": 234, "cm": 118, "m": 31, "h": 71, "NTU": 233, "Mvar": 13, "MWh": 146, "": 95}
    assert {unit: bacnet.engineering_units(unit)[0] for unit in expected} == expected


capture_tools = (find_tool("tshark") and (find_tool("dumpcap") or find_tool("tcpdump"))
                 and tshark_version() >= MIN_TSHARK)


@pytest.mark.skipif(not capture_tools, reason="requires tshark >= 4.4 and loopback capture rights")
def test_recorded_bacnet_exchange_decodes_and_mirrors_the_process(tmp_path, monkeypatch):
    monkeypatch.setenv("PCAPFORGE_CACHE", str(tmp_path / "cache"))
    plan = build_plan(scenario([SERVER, CLIENT], duration="6m"), "easy", "e2e")
    recording, _ = recording_for(plan, use_cache=False)
    pcap = compose(plan, recording, tmp_path / "bacnet.pcap", "e2e").path
    report = verify_capture(pcap)
    assert report.ok, [c for c in report.checks if not c["ok"]]

    def fields(display_filter, *names):
        names = names or ("frame.number",)
        cmd = [find_tool("tshark"), "-n", "-r", str(pcap), "-Y", display_filter, "-T", "fields",
               "-E", "separator=|", *[arg for n in names for arg in ("-e", n)]]
        return [line.split("|") for line in
                subprocess.run(cmd, capture_output=True, text=True, check=True).stdout.splitlines()]

    assert not fields("_ws.malformed || _ws.expert.severity >= 8388608")
    assert {row[0] for row in fields("bacapp", "udp.srcport")} == {"47808"}
    count = Counter(a.op for a in plan.actions)
    assert len(fields("bacapp.unconfirmed_service == 8 && eth.dst == ff:ff:ff:ff:ff:ff")) == count["bacnet.whois"]
    assert len(fields("bacapp.unconfirmed_service == 0 && eth.dst == ff:ff:ff:ff:ff:ff")) == count["bacnet.iam"]
    assert len(fields("bacapp.type == 0 && bacapp.confirmed_service == 14")) == count["bacnet.rpm"]
    assert len(fields("bacapp.type == 3 && bacapp.confirmed_service == 14")) == count["bacnet.rpm"]
    assert len(fields("bacapp.type == 2 && bacapp.confirmed_service == 5")) == count["bacnet.subscribe"]
    assert len(fields("bacapp.type == 5")) == 2                    # structured-object-list probe per controller
    vendors = {row[0] for row in fields("bacapp.unconfirmed_service == 0", "bacapp.vendor_identifier")}
    assert vendors == {"7"}
    # Every RPM poll answers analog-input 1 (outdoor-air temperature) first, inside its daily band.
    polls = fields("bacapp.type == 3 && bacapp.confirmed_service == 14 && bacapp.present_value.real",
                   "bacapp.present_value.real")
    outdoor = [float(row[0].split(",")[0]) for row in polls]
    assert outdoor and all(10 <= value <= 34 for value in outdoor)
    notifications = fields("bacapp.unconfirmed_service == 2", "bacapp.present_value.real")
    assert len(notifications) >= count["bacnet.subscribe"]       # an initial notification per (re)subscription
