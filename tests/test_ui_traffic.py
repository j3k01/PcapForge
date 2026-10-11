"""The traffic overview classifies frames by EtherType / IP protocol / port behind VLAN tags,
buckets them by capture time, reads classic pcap and pcapng alike, and escapes run content."""

from __future__ import annotations

import datetime as dt
import http.client
import json
import struct
import threading
import time

import pytest

from pcapforge.compose.writer import write_pcap, write_pcapng
from pcapforge.ui import traffic
from pcapforge.ui.server import App, make_server

START = 1_700_000_000  # whole seconds: bucket boundaries are exact
MAC = b"\x00\x11\x22\x33\x44\x55\x00\x66\x77\x88\x99\xaa"


def _eth(ethertype: int, payload: bytes, tags: tuple[tuple[int, int], ...] = ()) -> bytes:
    """``tags``: (TPID, VLAN id) outer first."""
    header = MAC + b"".join(struct.pack(">HH", tpid, vid) for tpid, vid in tags)
    return header + struct.pack(">H", ethertype) + payload


def _ipv4(proto: int, payload: bytes) -> bytes:
    return struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0,
                       bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2])) + payload


def _ipv6(next_header: int, payload: bytes) -> bytes:
    return struct.pack(">IHBB16s16s", 6 << 28, len(payload), next_header, 64, b"\xfe\x80" + b"\x00" * 13 + b"\x01",
                       b"\xff\x02" + b"\x00" * 13 + b"\x16") + payload


def _tcp(sport: int, dport: int) -> bytes:
    return struct.pack(">HHIIBBHHH", sport, dport, 1, 0, 0x50, 0x18, 1024, 0, 0) + b"\x00\x01"


def _udp(sport: int, dport: int) -> bytes:
    return struct.pack(">HHHH", sport, dport, 12, 0) + b"abcd"


VLAN = ((0x8100, 120),)
QINQ = ((0x88A8, 7), (0x8100, 120))
HOP_BY_HOP_MLD = bytes([58, 0, 5, 2, 0, 0, 1, 0]) + bytes([143, 0, 0, 0, 0, 0, 0, 0])

# (seconds after START, frame, expected category); duration 10 s in 10 buckets of 1 s
FRAMES = [
    (-0.2, _eth(0x0800, _ipv4(17, _udp(40000, 123))), "ntp"),                       # before start: bucket 0
    (0.0, _eth(0x0800, _ipv4(6, _tcp(50000, 502))), "modbus"),                     # untagged request
    (0.999, _eth(0x0800, _ipv4(6, _tcp(502, 50000)), VLAN), "modbus"),            # VLAN 120 response
    (1.0, _eth(0x86DD, _ipv6(6, _tcp(51000, 102)), VLAN), "s7comm"),              # IPv6 over VLAN
    (2.5, _eth(0x0800, _ipv4(17, _udp(53, 41000)), QINQ), "dns"),                 # QinQ
    (3.0, _eth(0x0806, b"\x00\x01\x08\x00\x06\x04\x00\x01" + b"\x00" * 20, VLAN), "arp"),
    (4.0, _eth(0x86DD, _ipv6(0, HOP_BY_HOP_MLD)), "icmp/icmpv6"),                 # MLD behind hop-by-hop
    (5.0, _eth(0x86DD, _ipv6(17, _udp(47808, 47808)), VLAN), "bacnet"),
    (6.0, _eth(0x0800, _ipv4(17, _udp(2222, 2222))), "enip/cip"),
    (6.5, _eth(0x0800, _ipv4(6, _tcp(47808, 102))), "s7comm"),                    # client port collides: lower wins
    (7.0, _eth(0x0800, _ipv4(6, _tcp(50001, 8080))), "other"),
    (8.0, _eth(0x0800, _ipv4(17, _udp(5353, 5353)), VLAN), "llmnr/mdns/nbns/ssdp"),
    (8.5, _eth(0x86DD, _ipv6(17, _udp(546, 547))), "dhcp"),
    (9.999, _eth(0x88CC, b"\x02\x07\x04" + b"\x00" * 20), "other"),               # LLDP
    (10.0, _eth(0x0800, _ipv4(1, b"\x08\x00\x00\x00\x00\x01\x00\x01")), "icmp/icmpv6"),  # end: last bucket
]


def _bucket(offset: float) -> int:
    return min(max(int(offset), 0), 9)


def _write(path, writer) -> None:
    writer(path, [(round((START + offset) * 1_000_000), frame) for offset, frame, _ in FRAMES])


@pytest.mark.parametrize("writer", [write_pcap, write_pcapng], ids=["pcap", "pcapng"])
def test_scan_classifies_and_buckets_frames(tmp_path, writer):
    path = tmp_path / "capture.cap"
    _write(path, writer)
    data = traffic.scan(path, float(START), 10.0, buckets=10)
    assert data["packets"] == len(FRAMES) and data["width"] == 1.0
    expected: dict[str, list[int]] = {}
    for offset, _frame, category in FRAMES:
        expected.setdefault(category, [0] * 10)[_bucket(offset)] += 1
    assert data["rows"] == expected
    assert data["rows"]["modbus"] == [2] + [0] * 9       # 0.0 and 0.999 share bucket 0
    assert data["rows"]["s7comm"][1] == 1                 # 1.0 opens bucket 1
    assert data["rows"]["icmp/icmpv6"][9] == 1            # the frame at the very end stays in the chart


def test_classify_ignores_truncated_headers():
    frame = _eth(0x0800, _ipv4(6, _tcp(50000, 502)), VLAN)
    assert traffic.classify(frame, 0, len(frame)) == traffic.MODBUS
    assert traffic.classify(frame, 0, 14 + 4 + 20 + 2) == traffic.OTHER  # ports cut off
    assert traffic.classify(frame, 0, 10) == traffic.OTHER


def _iso(epoch: int) -> str:
    return dt.datetime.fromtimestamp(epoch, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _answers(sha: str) -> dict:
    return {
        "scenario": {"id": "ot-test", "title": "Test", "difficulty": "easy", "seed": "1", "base_seed": "1"},
        "capture": {"file": "capture.pcap", "packets": len(FRAMES), "duration_s": 10.0,
                    "start": _iso(START), "end": _iso(START + 10), "sha256": sha,
                    "sensor_subnet": "10.0.0.0/24", "sensor_clock": None},
        "topology": {"site_name": "Site", "domain": "site.local", "hosts": [],
                     "subnets": [{"id": "control", "cidr": "10.0.0.0/24", "gateway": "10.0.0.1", "sensor": True}]},
        "timeline": [{"epoch": START + 3.5, "frame": 7, "actor": "<i>actor</i>", "title": "<script>alert(1)</script>",
                      "techniques": ["T0855"], "incident": True}],
        "questions": [], "lang": "en",
    }


def _get(port: int, path: str, method: str = "GET") -> tuple[int, bytes]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    headers = {"Host": f"127.0.0.1:{port}"}
    if method == "POST":
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    conn.request(method, path, body="" if method == "POST" else None, headers=headers)
    response = conn.getresponse()
    body = response.read()
    conn.close()
    return response.status, body


def test_traffic_action_caches_scan_and_page_escapes_run_content(tmp_path):
    run = tmp_path / "ot-test_easy_1"
    (run / "siem").mkdir(parents=True)
    _write(run / "capture.pcap", write_pcap)
    (run / "answers.json").write_text(json.dumps(_answers("ab" * 32)), encoding="utf-8")
    flow = {"src": "10.0.0.1", "dest": "<b>10.0.0.2</b>", "dest_port": 502, "transport": "tcp",
            "app": "<img src=x>", "packets": 2, "bytes": 140, "duration": 0.999, "state": "established"}
    (run / "siem" / "flows.jsonl").write_text(json.dumps(flow) + "\nnot json\n", encoding="utf-8")
    server = make_server(App(tmp_path), "127.0.0.1", 0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    port = server.server_address[1]
    try:
        status, page = _get(port, "/runs/ot-test_easy_1")
        assert status == 200 and b'action="/runs/ot-test_easy_1/traffic"' in page and b"<svg class=\"traffic\"" not in page
        assert b"&lt;b&gt;10.0.0.2&lt;/b&gt;" in page and b"&lt;img src=x&gt;" in page and b"<img" not in page
        assert b"1 of 1 flows" in page

        assert _get(port, "/runs/ot-test_easy_1/traffic", "POST")[0] == 303
        deadline = time.monotonic() + 10
        while not (run / traffic.CACHE).is_file() and time.monotonic() < deadline:
            time.sleep(0.05)
        data = json.loads((run / traffic.CACHE).read_text(encoding="utf-8"))
        assert data["packets"] == len(FRAMES) and sum(data["rows"]["modbus"]) == 2

        status, page = _get(port, "/runs/ot-test_easy_1")
        assert status == 200 and b"<svg class=\"traffic\"" in page
        assert b"&lt;script&gt;alert(1)&lt;/script&gt;" in page and b"<script>alert" not in page
        assert b"&lt;i&gt;actor&lt;/i&gt;" in page and b'class="mark inc"' in page

        # a scan of another capture (or a damaged cache) is not drawn
        (run / "answers.json").write_text(json.dumps(_answers("cd" * 32)), encoding="utf-8")
        status, page = _get(port, "/runs/ot-test_easy_1")
        assert status == 200 and b"<svg class=\"traffic\"" not in page and b"traffic.json is outdated" in page
    finally:
        server.shutdown()
        server.server_close()
