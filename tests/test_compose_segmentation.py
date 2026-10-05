"""Composer TCP segmentation: messages larger than the path MSS leave as segment trains that
tshark reassembles without gaps, inside the receiver's window, with the answer key pointing at
the frame that carries the decoded PDU."""

import struct
import subprocess
from pathlib import Path

import pytest
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, TCP, UDP
from scapy.utils import RawPcapWriter

from pcapforge import ports
from pcapforge.compose import compose
from pcapforge.plan import build_plan
from pcapforge.record import MARKER_MAGIC
from pcapforge.scenario import Scenario
from pcapforge.tools import find_tool
from pcapforge.topology import MARKER_SINK
from pcapforge.verify import verify_capture

pytestmark = pytest.mark.skipif(not find_tool("tshark"), reason="requires tshark")

TXT_RECORDS = 60
MODBUS_READS = 2500  # pipelined requests: 30 000 bytes in one loopback segment


def scenario():
    doc = {
        "id": "test-segmentation", "title": "Segmentation", "line": "ot", "version": 1,
        "site": {"names": ["Testfield"], "codes": ["tst"]},
        "topology": {
            "sensor": "control",
            "subnets": [{"id": "control", "pool": "10.0.0.0/8", "prefix": 24},
                        {"id": "it", "pool": "172.16.0.0/12", "prefix": 24}],
            "hosts": [
                {"id": "firewall", "device": "fortigate", "subnets": ["control", "it"], "name": "fw-01",
                 "router": True},
                {"id": "plc", "device": "schneider-m340", "subnet": "control", "name": "plc-01"},
                {"id": "hmi", "device": "windows-workstation", "subnet": "control", "name": "HMI-01"},
                {"id": "dc", "device": "windows-server-vm", "subnet": "it", "name": "DC-01"},
            ],
        },
        "actors": [
            {"id": "plc_service", "type": "modbus.server", "hosts": "plc", "params": {"process": "water_treatment"}},
            {"id": "poll", "type": "modbus.poller", "hosts": "hmi", "params": {"targets": "plc", "interval": 5.0}},
        ],
        "difficulty": {"easy": {"duration": "2m", "vars": {}}},
    }
    return Scenario(Path("test-segmentation.yaml"), doc)


class Recording:
    """A loopback recording written by hand: every message is one segment (MSS 65495)."""

    def __init__(self) -> None:
        self.packets = []

    def marker(self, source: str, action_id: int) -> None:
        self.packets.append(IP(src=source, dst=MARKER_SINK) / UDP(sport=50000, dport=ports.MARKER)
                            / (MARKER_MAGIC + struct.pack("!I", action_id)))

    def connection(self, client: str, server: str, sport: int, dport: int, exchanges) -> None:
        """Handshake, then (request, response) pairs, each segment ACKed at once (Windows loopback)."""
        cseq, sseq = 1000, 5000

        def send(src, dst, sp, dp, seq, ack, flags, payload=b""):
            self.packets.append(IP(src=src, dst=dst) / TCP(sport=sp, dport=dp, seq=seq, ack=ack, flags=flags,
                                                         window=65535) / payload)

        send(client, server, sport, dport, cseq, 0, "S")
        send(server, client, dport, sport, sseq, cseq + 1, "SA")
        cseq, sseq = cseq + 1, sseq + 1
        send(client, server, sport, dport, cseq, sseq, "A")
        for request, response in exchanges:
            send(client, server, sport, dport, cseq, sseq, "PA", request)
            cseq += len(request)
            send(server, client, dport, sport, sseq, cseq, "A")
            send(server, client, dport, sport, sseq, cseq, "PA", response)
            sseq += len(response)
            send(client, server, sport, dport, cseq, sseq, "A")

    def write(self, path: Path) -> Path:
        with RawPcapWriter(str(path), linktype=101) as writer:  # raw IPv4
            for packet in self.packets:
                writer.write(bytes(packet))
        return path


def tshark(pcap, display_filter, *fields):
    cmd = [find_tool("tshark"), "-n", "-r", str(pcap), "-Y", display_filter, "-T", "fields", "-E", "separator=|",
           "-E", "occurrence=a", "-E", "aggregator=;", *[arg for f in fields for arg in ("-e", f)]]
    out = subprocess.run(cmd, capture_output=True, text=True, check=True).stdout
    return [line.split("|") for line in out.splitlines()]


@pytest.fixture(scope="module")
def composed(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("segmentation")
    plan = build_plan(scenario(), "easy", "segments")
    hosts = plan.topology.by_id
    hmi, plc, dc = hosts["hmi"].loopback, hosts["plc"].loopback, hosts["dc"].loopback
    first, second = [a for a in plan.actions if a.host == "hmi"][:2]

    query = DNS(id=0x4242, rd=1, qd=DNSQR(qname="big.example", qtype="TXT"))
    answer = DNS(id=0x4242, qr=1, aa=1, rd=1, ra=1, qd=DNSQR(qname="big.example", qtype="TXT"),
                 an=[DNSRR(rrname="big.example", type="TXT", rdata=[f"record {i:03d} " + "x" * 90])
                     for i in range(TXT_RECORDS)])
    dns_query, dns_answer = bytes(query), bytes(answer)
    reads = b"".join(struct.pack("!HHHBBHH", tid, 0, 6, 1, 3, 0, 4) for tid in range(MODBUS_READS))
    replies = b"".join(struct.pack("!HHHBBB", tid, 0, 11, 1, 3, 8) + bytes(8) for tid in range(MODBUS_READS))

    recording = Recording()
    recording.marker(hmi, first.id)
    recording.connection(hmi, dc, 50001, ports.DNS, [(len(dns_query).to_bytes(2, "big") + dns_query,
                                                      len(dns_answer).to_bytes(2, "big") + dns_answer)])
    recording.marker(hmi, second.id)
    recording.connection(hmi, plc, 50002, ports.MODBUS, [(reads, replies)])
    path = recording.write(tmp / "recording.pcap")
    result = compose(plan, path, tmp / "capture.pcap", "segments")
    return plan, result, len(dns_answer) + 2, (first.id, second.id)


def test_capture_is_clean_and_every_segment_fits_the_path_mss(composed):
    _, result, _, _ = composed
    report = verify_capture(result.path)
    assert report.ok, report.failed
    # schneider-m340 / Windows: MSS 1460, no timestamps.
    lengths = [int(row[0]) for row in tshark(result.path, "tcp.len > 0", "tcp.len")]
    assert max(lengths) == 1460
    gaps = tshark(result.path, "tcp.analysis.lost_segment || tcp.analysis.ack_lost_segment "
                               "|| tcp.analysis.out_of_order || tcp.analysis.duplicate_ack "
                               "|| tcp.analysis.retransmission", "frame.number")
    assert not gaps


def test_large_dns_answer_is_reassembled_from_full_segments_with_push_on_the_last(composed):
    _, result, answer_size, _ = composed
    rows = tshark(result.path, "dns.flags.response == 1", "tcp.reassembled.length", "tcp.segment.count",
                  "dns.count.answers")
    assert len(rows) == 1
    length, segments, answers = rows[0]
    assert (int(length), int(answers)) == (answer_size, TXT_RECORDS)
    assert int(segments) == -(-answer_size // 1460)
    pushes = tshark(result.path, "tcp.srcport == 53 && tcp.len > 0", "tcp.flags.push")
    assert [p[0] for p in pushes] == ["False"] * (int(segments) - 1) + ["True"]


def test_window_limited_burst_decodes_every_pipelined_request_and_receiver_acks_every_second_segment(composed):
    plan, result, _, (_, burst_action) = composed
    requests = tshark(result.path, "mbtcp && tcp.dstport == 502", "mbtcp.trans_id")
    assert sum(len(r[0].split(";")) for r in requests) == MODBUS_READS
    # The PLC's 8192-byte window bounds what the workstation has in flight.
    flight = [int(r[0]) for r in tshark(result.path, "tcp.dstport == 502 && tcp.len > 0",
                                        "tcp.analysis.bytes_in_flight")]
    assert max(flight) <= 8192
    acks = tshark(result.path, "tcp.srcport == 502 && tcp.len == 0 && tcp.flags.syn == 0", "tcp.ack")
    segments = len(tshark(result.path, "tcp.dstport == 502 && tcp.len > 0", "frame.number"))
    assert segments == -(-MODBUS_READS * 12 // 1460)
    assert len(acks) >= segments // 2
    # The action's frame is the one in which tshark decodes the end of the request.
    frame = result.action_frames[burst_action]
    last = tshark(result.path, "tcp.dstport == 502 && tcp.len > 0", "frame.number")[-1][0]
    assert frame == int(last)
