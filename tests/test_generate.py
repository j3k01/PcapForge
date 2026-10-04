"""End-to-end: record real loopback traffic, compose, and check the result with tshark/Scapy.

Needs Wireshark (tshark + dumpcap) and loopback capture rights; skipped otherwise.
"""

import hashlib
import json
import subprocess

import pytest
from scapy.layers.inet import IP, TCP, UDP
from scapy.utils import PcapReader

from pcapforge.compose import compose
from pcapforge.pipeline import generate
from pcapforge.plan import build_plan
from pcapforge.record import recording_for
from pcapforge.scenario import find
from pcapforge.tools import find_tool

SCENARIO = "ot-modbus-write-manipulation"
DURATION = 600.0

pytestmark = pytest.mark.skipif(
    not find_tool("tshark") or not (find_tool("dumpcap") or find_tool("tcpdump")),
    reason="requires tshark and dumpcap/tcpdump with loopback capture rights",
)


@pytest.fixture(scope="module", params=["easy", "medium", "hard"])
def generated(request, tmp_path_factory):
    out = tmp_path_factory.mktemp(request.param)
    result = generate(find(SCENARIO), request.param, "pytest", out, duration=DURATION)
    answers = json.loads(result.answers.read_text(encoding="utf-8"))
    return result, answers


def tshark_fields(pcap, display_filter, fields):
    cmd = [find_tool("tshark"), "-n", "-r", str(pcap), "-Y", display_filter, "-T", "fields",
           "-E", "separator=|"] + [arg for f in fields for arg in ("-e", f)]
    out = subprocess.run(cmd, capture_output=True, text=True, check=True).stdout
    return [line.split("|") for line in out.splitlines() if line]


def test_capture_passes_integrity_and_answer_key_checks(generated):
    result, _ = generated
    failed = [c for c in result.report.checks if not c["ok"]]
    assert result.report.ok, failed


def test_every_recorded_write_in_the_key_matches_the_frame_it_points_to(generated):
    result, answers = generated
    change = answers["facts"]["change"]
    for write in change["writes"]:
        frame = write["request"]["frame"]
        rows = tshark_fields(result.pcap, f"frame.number == {frame}",
                             ["ip.src", "ip.dst", "tcp.dstport", "modbus.func_code",
                              "modbus.reference_num", "modbus.regval_uint16", "frame.time_epoch"])
        assert len(rows) == 1, f"frame {frame} not found"
        src, dst, port, func, ref, value, epoch = rows[0]
        assert (src, dst, port) == (change["source"]["ip"], change["target"]["ip"], "502")
        assert int(func) == write["function"]
        assert int(ref) == write["address"]
        assert int(value.split(",")[0]) == write["raw"]
        assert abs(float(epoch) - write["request"]["epoch"]) < 1e-5


def test_timeline_is_ordered_and_inside_the_capture(generated):
    _, answers = generated
    epochs = [e["epoch"] for e in answers["timeline"]]
    assert epochs == sorted(epochs)
    first, last = answers["capture"]["start"], answers["capture"]["end"]
    assert all(first <= e["time"] <= last for e in answers["timeline"])


def test_checksums_hold_when_recomputed_by_scapy(generated):
    result, _ = generated
    checked = 0
    with PcapReader(str(result.pcap)) as reader:
        for index, pkt in enumerate(reader):
            if index >= 3000:
                break
            if IP not in pkt:
                continue
            ip = pkt[IP]
            fresh = IP(bytes(ip))
            del fresh.chksum
            layers = [l for l in (TCP, UDP) if l in fresh]
            for layer in layers:
                del fresh[layer].chksum
            rebuilt = IP(bytes(fresh))
            assert rebuilt.chksum == ip.chksum
            for layer in layers:
                assert rebuilt[layer].chksum == ip[layer].chksum
            checked += 1
    assert checked > 1000


def test_handout_does_not_reveal_an_unknown_source(generated):
    result, answers = generated
    source = answers["facts"]["change"]["source"]
    briefing = result.handout.read_text(encoding="utf-8")
    if source["role"] in ("rogue", "itpc"):
        assert source["ip"] not in briefing
        assert source["name"] not in briefing


def test_same_seed_is_byte_identical_and_new_seed_changes_presentation(tmp_path):
    scenario = find(SCENARIO)
    plan = build_plan(scenario, "easy", "repro", duration_override=300)
    recording, _ = recording_for(plan)
    digests, sources = [], []
    for seed, name in (("repro", "a"), ("repro", "b"), ("other", "c")):
        plan = build_plan(scenario, "easy", seed, base_seed="repro", duration_override=300)
        out = compose(plan, recording, tmp_path / f"{name}.pcap", seed)
        digests.append(hashlib.sha256(out.path.read_bytes()).hexdigest())
        sources.append(plan.topology.by_id["rogue"].ip)
    assert digests[0] == digests[1]
    assert digests[0] != digests[2]
    assert sources[0] != sources[2]
