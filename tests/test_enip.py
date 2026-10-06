"""EtherNet/IP actors: planning, the Logix target's encoding, and a recorded session decoded by tshark."""

import socket
import struct
import subprocess
from pathlib import Path

import pytest

from pcapforge.actors import enip  # registers enip.server / enip.client
from pcapforge.compose import compose
from pcapforge.compose.enip import rewrite_list_identity
from pcapforge.plan import build_plan
from pcapforge.process import ProcessSim
from pcapforge.record import recording_for
from pcapforge.rng import Rng
from pcapforge.scenario import Scenario, ScenarioError
from pcapforge.tools import MIN_TSHARK, find_tool, tshark_version
from pcapforge.verify import verify_capture


def scenario(actors, plc_device="rockwell-compactlogix"):
    doc = {
        "id": "test-enip", "title": "EtherNet/IP background", "line": "ot", "version": 1,
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
    return Scenario(Path("test-enip.yaml"), doc)


ENIP_ACTORS = [
    {"id": "plc_enip", "type": "enip.server", "hosts": "plc", "params": {"process": "water_treatment"}},
    {"id": "hmi_enip", "type": "enip.client", "hosts": "hmi", "params": {"targets": "plc", "interval": 1.0}},
    {"id": "historian_enip", "type": "enip.client", "hosts": "historian",
     "params": {"targets": "plc", "interval": 10, "list_identity": False, "list_services": False}},
]


def _actor(plan, actor_id):
    return next(a for a in plan.actors if a.id == actor_id)


def test_plan_is_deterministic_and_reads_every_tag_each_cycle():
    plan = build_plan(scenario(ENIP_ACTORS), "easy", "plan")
    again = build_plan(scenario(ENIP_ACTORS), "easy", "plan")
    assert plan.digest() == again.digest()
    assert [(a.t, a.actor, a.host, a.op, a.args) for a in plan.actions] == \
        [(a.t, a.actor, a.host, a.op, a.args) for a in again.actions]

    hmi = _actor(plan, "hmi_enip")
    tags = [t.name for t in _actor(plan, "plc_enip").controllers["plc"].tags]
    assert [name for group in hmi.groups["plc"] for name in group] == tags
    reads = [a for a in plan.actions if a.actor == "hmi_enip" and a.op == "enip.read"]
    groups = len(hmi.groups["plc"])
    assert len(reads) % groups == 0 and 170 <= len(reads) // groups <= 181
    assert [a.args["group"] for a in reads] == list(range(groups)) * (len(reads) // groups)

    # The browse broadcast is answered by the controller itself, after the broadcast.
    browse = next(a for a in plan.actions if a.op == "enip.list_identity")
    reply = next(a for a in plan.actions if a.op == "enip.identity")
    assert browse.host == "hmi" and (reply.actor, reply.host) == ("plc_enip", "plc")
    assert reply.args == {"to": "hmi", "browser": "hmi_enip"} and reply.t > browse.t
    assert not any(a.op == "enip.list_identity" and a.host == "historian" for a in plan.actions)
    setup = [a.op for a in plan.actions if a.host == "historian" and a.phase == "setup"]
    assert setup == ["enip.connect", "enip.identify", "enip.forward_open"]
    first_read = min(a.t for a in plan.actions if a.host == "historian" and a.op == "enip.read")
    assert all(a.t < first_read for a in plan.actions if a.host == "historian" and a.phase == "setup")


def test_facts_name_identity_tags_and_connections():
    plan = build_plan(scenario(ENIP_ACTORS), "easy", "facts")
    server = plan.facts["plc_enip"]["controllers"][0]
    identity = server["identity"]
    assert {k: identity[k] for k in ("vendor_id", "device_type", "product_code", "product_name", "revision")} == {
        "vendor_id": 1, "device_type": 14, "product_code": 103, "product_name": "1769-L33ER/A LOGIX5333ER",
        "revision": "33.011"}
    tags = {t["tag"]: t for t in server["tags"]}
    assert tags["Clearwell_Level"] == {"tag": "Clearwell_Level", "point": "clearwell_level", "type": "REAL",
                                       "unit": "cm"}
    assert tags["Treated_Volume_M3"]["type"] == "DINT" and tags["Pump1_Run"]["type"] == "BOOL"
    # "spare" is both a coil and a discrete input: one tag each, told apart by the I/O suffix.
    assert {"Spare_DO", "Spare_DI"} <= set(tags) and "Spare" not in tags
    assert len(tags) == len(server["tags"])

    controller = _actor(plan, "plc_enip").controllers["plc"]
    client = plan.facts["hmi_enip"]
    assert client["interval_s"] == 1.0 and client["connection"]["rpi_ms"] == 2000
    session = client["sessions"][0]
    opened = next(a for a in plan.actions if a.op == "enip.forward_open" and a.host == "hmi")
    ot_id = controller.connection_id(opened.args["serial"], 1, opened.args["originator_serial"])
    assert session["ot_connection_id"] == f"0x{ot_id:08x}"
    assert session["to_connection_id"] == f"0x{opened.args['to_id']:08x}"


def test_server_params_and_device_are_validated():
    with pytest.raises(ScenarioError, match="not an EtherNet/IP device"):
        build_plan(scenario(ENIP_ACTORS, plc_device="siemens-s7-1200"), "easy", "wrong-device")
    with pytest.raises(ScenarioError, match="serial"):
        build_plan(scenario([{**ENIP_ACTORS[0], "params": {"process": "water_treatment", "serial": "xyz"}},
                             ENIP_ACTORS[1]]), "easy", "bad-serial")
    plan = build_plan(scenario([{**ENIP_ACTORS[0], "params": {"process": "water_treatment",
                                                              "serial": "0x00C0FFEE"}}, ENIP_ACTORS[1]]),
                      "easy", "serial")
    assert plan.facts["plc_enip"]["controllers"][0]["identity"]["serial"] == "0x00c0ffee"
    with pytest.raises(ScenarioError, match="no enip.server"):
        build_plan(scenario([ENIP_ACTORS[0], {**ENIP_ACTORS[1], "params": {"targets": "historian"}}]),
                   "easy", "no-server")


def test_server_on_a_modbus_plc_serves_its_process_and_rejects_another():
    modbus = {"id": "plc_mb", "type": "modbus.server", "hosts": "plc", "params": {"process": "water_treatment"}}
    plan = build_plan(scenario([modbus, {**ENIP_ACTORS[0], "params": {}}, ENIP_ACTORS[1]]), "easy", "shared")
    assert _actor(plan, "plc_enip").controllers["plc"].profile.id == "water_treatment"
    conflicting = {**ENIP_ACTORS[0], "params": {"process": "wastewater_treatment"}}
    with pytest.raises(ScenarioError, match="water_treatment"):
        build_plan(scenario([modbus, conflicting, ENIP_ACTORS[1]]), "easy", "shared")


# --- the controller's encapsulation / CIP target ------------------------------------------

class _Exchange:
    """Drives a LogixTarget the way EnipSession does, without sockets."""

    def __init__(self, target: enip.LogixTarget) -> None:
        self.target, self.session, self.context = target, 0, 0

    def send(self, command: int, data: bytes = b"") -> tuple[tuple, bytes, bytes]:
        self.context += 1
        request = enip.encap(command, data, self.session, struct.pack("<Q", self.context))
        reply = self.target.handle(request)
        header = enip.ENCAP.unpack_from(reply)
        assert header[0] == command and header[4] == struct.pack("<Q", self.context)
        assert len(reply) == enip.ENCAP.size + header[1]
        return header, reply[enip.ENCAP.size:], request


def _target(plan):
    """A controller's target over a process simulation; ``served`` keeps the values it was given."""
    controller = _actor(plan, "plc_enip").controllers["plc"]
    sim = ProcessSim(controller.profile, Rng("test-enip"), plan.start_hour)
    served: dict[str, dict[str, float]] = {}

    def values(table):
        served[table] = sim.values(table)
        return served[table]

    return enip.LogixTarget(controller, "127.77.0.9", values), served


def test_connected_reads_fit_the_connection_echo_the_sequence_and_carry_process_values():
    plan = build_plan(scenario(ENIP_ACTORS), "easy", "target")
    target, served = _target(plan)
    hmi = _actor(plan, "hmi_enip")
    x = _Exchange(target)
    header, body, _ = x.send(enip.CMD_REGISTER_SESSION, struct.pack("<HH", 1, 0))
    x.session = header[2]
    assert header[3] == 0 and x.session in target.sessions

    forward_open = enip.forward_open_request(0x11, 0x22, 0x3344, 0x55667788)
    _, body, _ = x.send(enip.CMD_SEND_RR_DATA, enip.rr_data(forward_open))
    reply = enip.parse_cpf(body[6:])[enip.ITEM_UNCONNECTED_DATA]
    assert reply[:4] == bytes([0xD4, 0, 0, 0])
    ot_id, to_id = struct.unpack_from("<II", reply, 4)
    assert ot_id == target.controller.connection_id(0x3344, 1, 0x55667788) and to_id == 0x22

    by_name = {t.name: t for t in target.controller.tags}
    for sequence, names in enumerate(hmi.groups["plc"], start=1):
        request = enip.multiple_read_request(names)
        _, body, sent = x.send(enip.CMD_SEND_UNIT_DATA, enip.unit_data(ot_id, sequence, request))
        items = enip.parse_cpf(body[6:])
        assert struct.unpack("<I", items[enip.ITEM_CONNECTED_ADDRESS])[0] == to_id
        data = items[enip.ITEM_CONNECTED_DATA]
        # Both directions stay inside the negotiated connection size (sequence count included).
        assert len(enip.parse_cpf(sent[enip.ENCAP.size + 6:])[enip.ITEM_CONNECTED_DATA]) <= enip.CONNECTION_SIZE
        assert len(data) <= enip.CONNECTION_SIZE
        assert struct.unpack_from("<H", data)[0] == sequence
        assert data[2:6] == bytes([0x8A, 0, 0, 0])
        replies = enip.unpack_services(data[6:])
        assert len(replies) == len(names)
        values = dict(served)
        served.clear()
        for name, embedded in zip(names, replies):
            tag = by_name[name]
            assert embedded[:4] == bytes([0xCC, 0, 0, 0])
            kind = struct.unpack_from("<H", embedded, 4)[0]
            assert kind == tag.type and len(embedded) == 6 + enip.VALUE_SIZE[kind]
            expected = values[tag.table][tag.point]
            if kind == enip.REAL:
                assert struct.unpack_from("<f", embedded, 6)[0] == pytest.approx(expected, rel=1e-6)
            elif kind == enip.DINT:
                assert struct.unpack_from("<i", embedded, 6)[0] == round(expected)
            else:
                assert embedded[6] == (1 if expected else 0)

    _, body, _ = x.send(enip.CMD_SEND_RR_DATA, enip.rr_data(enip.forward_close_request(0x3344, 0x55667788)))
    assert enip.parse_cpf(body[6:])[enip.ITEM_UNCONNECTED_DATA][:4] == bytes([0xCE, 0, 0, 0])
    assert not target.connections


def test_unknown_tags_sessions_and_services_get_cip_and_encapsulation_errors():
    plan = build_plan(scenario(ENIP_ACTORS), "easy", "errors")
    target, _ = _target(plan)
    x = _Exchange(target)
    header, _, _ = x.send(enip.CMD_SEND_RR_DATA, enip.rr_data(enip.read_tag_request("Clearwell_Level")))
    assert header[3] == enip.STATUS_INVALID_SESSION
    header, _, _ = x.send(enip.CMD_REGISTER_SESSION, struct.pack("<HH", 1, 0))
    x.session = header[2]
    request = enip.cip_request(enip.SVC_MULTIPLE_SERVICE, enip.ROUTER_PATH, enip.pack_services(
        [enip.read_tag_request("Clearwell_Level"), enip.read_tag_request("No_Such_Tag")]))
    _, body, _ = x.send(enip.CMD_SEND_RR_DATA, enip.rr_data(request))
    reply = enip.parse_cpf(body[6:])[enip.ITEM_UNCONNECTED_DATA]
    assert reply[:4] == bytes([0x8A, 0, enip.EMBEDDED_ERROR, 0])
    ok, missing = enip.unpack_services(reply[4:])
    assert ok[2] == enip.OK and missing[:4] == bytes([0xCC, 0, enip.PATH_UNKNOWN, 0])
    bad_path = enip.forward_open_request(1, 2, 3, 4)[:-6] + bytes([1, 3]) + enip.ROUTER_PATH  # slot 3
    _, body, _ = x.send(enip.CMD_SEND_RR_DATA, enip.rr_data(bad_path))
    reply = enip.parse_cpf(body[6:])[enip.ITEM_UNCONNECTED_DATA]
    assert reply[:6] == bytes([0xD4, 0, enip.CONNECTION_FAILURE, 1]) + struct.pack("<H", enip.EXT_INVALID_PATH)
    assert target.handle(enip.encap(enip.CMD_UNREGISTER_SESSION, b"", x.session)) is None
    assert x.session not in target.sessions


def test_identity_attributes_and_list_identity_socket_address():
    plan = build_plan(scenario(ENIP_ACTORS), "easy", "identity")
    target, _ = _target(plan)
    identity = target.controller.identity
    vendor, device_type, product, major, minor, status, serial, size = struct.unpack_from("<HHHBBHIB",
                                                                                       identity.attributes())
    assert (vendor, device_type, product, major, minor) == (1, 14, 103, 33, 11)
    assert identity.attributes()[15:] == b"1769-L33ER/A LOGIX5333ER" and size == 24
    assert f"0x{serial:08x}" == plan.facts["plc_enip"]["controllers"][0]["identity"]["serial"]

    reply = target.handle(enip.encap(enip.CMD_LIST_IDENTITY), udp=True)
    assert enip.ENCAP.unpack_from(reply)[0] == enip.CMD_LIST_IDENTITY
    item = enip.parse_cpf(reply[enip.ENCAP.size:])[enip.ITEM_IDENTITY]
    family, port, addr = struct.unpack_from(">HH4s", item, 2)
    # The recording listens on 14818, but the reply announces the well-known port.
    assert (family, port, socket.inet_ntoa(addr)) == (2, 44818, "127.77.0.9")
    assert item[18:] == identity.attributes() + bytes([enip.LOGIX_STATE])
    # Over UDP the target answers only the discovery commands.
    assert target.handle(enip.encap(enip.CMD_REGISTER_SESSION, struct.pack("<HH", 1, 0)), udp=True) is None

    remap = {socket.inet_aton("127.77.0.9"): socket.inet_aton("10.20.30.40")}.get
    rewritten = rewrite_list_identity(reply, remap)
    assert len(rewritten) == len(reply)
    item = enip.parse_cpf(rewritten[enip.ENCAP.size:])[enip.ITEM_IDENTITY]
    assert struct.unpack_from(">HH4s", item, 2) == (2, 44818, socket.inet_aton("10.20.30.40"))
    sin_addr = enip.ENCAP.size + 2 + 4 + 2 + 4   # item count, item header, version, family + port
    assert rewritten[:sin_addr] == reply[:sin_addr] and rewritten[sin_addr + 4:] == reply[sin_addr + 4:]
    # Two replies in one TCP payload are both rewritten; other commands and unmapped addresses stay.
    assert rewrite_list_identity(reply + reply, remap) == rewritten + rewritten
    assert rewrite_list_identity(reply, {}.get) == reply
    services = target.handle(enip.encap(enip.CMD_LIST_SERVICES))
    assert rewrite_list_identity(services, remap) == services


def test_read_groups_split_long_tag_lists_inside_the_connection_size():
    tags = [enip.Tag(f"Tag_{i:02d}_" + "x" * (i % 30), f"p{i}", "input", enip.REAL) for i in range(60)]
    for size in (120, 500):
        groups = enip.read_groups(tags, size)
        assert [t for g in groups for t in g] == tags
        for group in groups:
            names = [t.name for t in group]
            assert 2 + len(enip.multiple_read_request(names)) <= size
            assert 2 + 4 + 2 + sum(2 + 4 + 2 + enip.VALUE_SIZE[t.type] for t in group) <= size


capture_tools = (find_tool("tshark") and (find_tool("dumpcap") or find_tool("tcpdump"))
                 and tshark_version() >= MIN_TSHARK)


@pytest.mark.skipif(not capture_tools, reason="requires tshark >= 4.4 and loopback capture rights")
def test_recorded_enip_sessions_decode_and_mirror_the_process(tmp_path, monkeypatch):
    monkeypatch.setenv("PCAPFORGE_CACHE", str(tmp_path / "cache"))
    plan = build_plan(scenario(ENIP_ACTORS), "easy", "e2e")
    recording, _ = recording_for(plan, use_cache=False)
    pcap = compose(plan, recording, tmp_path / "enip.pcap", "e2e").path
    report = verify_capture(pcap)
    assert report.ok, [c for c in report.checks if not c["ok"]]

    def fields(display_filter, *names):
        names = names or ("frame.number",)
        cmd = [find_tool("tshark"), "-n", "-r", str(pcap), "-Y", display_filter, "-T", "fields",
               "-E", "separator=|", *[arg for n in names for arg in ("-e", n)]]
        return [line.split("|") for line in
                subprocess.run(cmd, capture_output=True, text=True, check=True).stdout.splitlines()]

    # Every planned read is one SendUnitData request and its response; sequence counts run 1, 2, ...
    # per connection and the controller echoes each one.
    planned_reads = sum(1 for a in plan.actions if a.op == "enip.read")
    requests = fields("enip.command == 0x0070 && tcp.dstport == 44818", "tcp.stream", "cip.seq")
    responses = fields("enip.command == 0x0070 && tcp.srcport == 44818", "tcp.stream", "cip.seq")
    assert len(requests) == len(responses) == planned_reads
    for rows in (requests, responses):
        streams: dict[str, list[int]] = {}
        for stream, seq in rows:
            streams.setdefault(stream, []).append(int(seq))
        assert len(streams) == 2
        assert all(seqs == list(range(1, len(seqs) + 1)) for seqs in streams.values())

    # One Class 3 connection per client, with the ids the answer key names.
    opened = fields("cip.cm.sc == 0x54 && tcp.srcport == 44818 && cip.genstat == 0", "cip.cm.ot_connid")
    facts = [s for actor in ("hmi_enip", "historian_enip") for s in plan.facts[actor]["sessions"]]
    assert sorted(int(row[0], 16) for row in opened) == sorted(int(s["ot_connection_id"], 16) for s in facts)
    names = fields("cip.id.product_name", "cip.id.product_name", "cip.id.vendor_id", "cip.id.product_code")
    assert len(names) == 2 and {tuple(r) for r in names} == {("1769-L33ER/A LOGIX5333ER", "0x0001", "103")}

    # The browse broadcast is answered unicast from 44818 to the browsing socket, and the reply
    # announces the controller's own address and the well-known port.
    browse = fields("enip.command == 0x0063 && udp.dstport == 44818", "udp.srcport", "ip.dst")
    assert len(browse) == 1 and browse[0][1].endswith(".255")
    answers = fields("enip.command == 0x0063 && udp.srcport == 44818", "udp.dstport", "ip.src", "enip.sinaddr",
                     "enip.sinport", "enip.lir.name")
    assert answers == [[browse[0][0], answers[0][1], answers[0][1], "44818", "1769-L33ER/A LOGIX5333ER"]]

    # Clearwell_Level (REAL) stays inside the process' plausible range in every response.
    levels = []
    for symbols, data in fields("enip.command == 0x0070 && tcp.srcport == 44818", "cip.symbol", "cip.data"):
        for symbol, value in zip(symbols.split(","), data.split(",")):
            if symbol == "Clearwell_Level":
                raw = bytes.fromhex(value.replace(":", ""))
                assert raw[:2] == b"\xca\x00"
                levels.append(struct.unpack("<f", raw[2:6])[0])
    assert levels and all(300 <= level <= 400 for level in levels)
