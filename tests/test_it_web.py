"""Intranet HTTPS (Edge to IIS) and Windows Update against WSUS as they decode from a capture."""

import json
import subprocess

import pytest

from pcapforge.pipeline import generate
from pcapforge.scenario import find
from pcapforge.tools import MIN_TSHARK, find_tool, tshark_version

capture_tools = (find_tool("tshark") and (find_tool("dumpcap") or find_tool("tcpdump"))
                 and tshark_version() >= MIN_TSHARK)
CHROMIUM_JA4 = "t13d1516h2_8daaf6152771_d8a2da3f94cd"


def tshark(pcap, display_filter, *fields):
    out = subprocess.run([find_tool("tshark"), "-n", "-r", str(pcap), "-Y", display_filter, "-T", "fields",
                          "-E", "occurrence=a", *[arg for f in fields for arg in ("-e", f)]],
                         capture_output=True, text=True, check=True).stdout
    return [line.split("\t") for line in out.splitlines()]


@pytest.fixture(scope="module")
def run(tmp_path_factory):
    result = generate(find("it-baseline-operations"), "medium", "pytest-web", tmp_path_factory.mktemp("web"),
                      duration=900.0)
    assert result.report.ok, [c for c in result.report.checks if not c["ok"]]
    return result, json.loads(result.answers.read_text(encoding="utf-8"))


@pytest.mark.skipif(not capture_tools, reason="requires tshark >= 4.4 and dumpcap/tcpdump with loopback capture rights")
def test_edge_negotiates_tls_1_2_with_iis_and_the_chain_comes_from_the_domain_ca(run):
    result, answers = run
    web = answers["facts"]["web_service"]
    hellos = tshark(result.pcap, "tls.handshake.type == 1", "tls.handshake.ja4", "tls.handshake.extensions_server_name")
    assert hellos and {ja4 for ja4, _ in hellos} == {CHROMIUM_JA4}
    assert {sni for _, sni in hellos} <= set(web["sites"])
    servers = tshark(result.pcap, "tls.handshake.type == 2", "ip.dst", "tls.handshake.type", "tls.handshake.version",
                     "tls.handshake.ciphersuite", "tls.handshake.extensions_alpn_str", "tls.handshake.session_id",
                     "x509sat.uTF8String", "x509ce.dNSName")
    full = {}  # client -> session IDs of its full handshakes
    resumed = 0
    for client, types, version, suite, alpn, session, names, sans in servers:
        assert (version, suite, alpn) == ("0x0303", "0xc030", "h2")
        if "11" in types.split(","):
            issuer, subject = names.split(",")[:2]
            assert issuer == web["ca"]["name"] and subject == web["sites"][0]
            assert sans.split(",") == web["sites"]
            full.setdefault(client, set()).add(session)
        else:  # abbreviated handshake: a session ID of an earlier full handshake of the same client
            assert session in full.get(client, set())
            resumed += 1
    assert full and resumed > 0 and answers["facts"]["browsing"]["resumed"] > 0


@pytest.mark.skipif(not capture_tools, reason="requires tshark >= 4.4 and dumpcap/tcpdump with loopback capture rights")
def test_windows_update_scans_over_soap_and_bits_fetches_the_approved_file(run):
    result, answers = run
    update = answers["facts"]["update_service"]["update"]
    posts = tshark(result.pcap, 'http.request.method == "POST"', "http.user_agent", "http.request.line")
    actions = [line.split('SOAPAction: "', 1)[1].split('"', 1)[0].rsplit("/", 1)[1]
               for _, lines in posts for line in lines.split(",") if line.startswith("SOAPAction")]
    assert posts and all(agent.startswith("Windows-Update-Agent/") for agent, _ in posts)
    scan = ["GetConfig", "GetAuthorizationCookie", "GetCookie", "SyncUpdates", "GetExtendedUpdateInfo"]
    assert actions[:5] == scan and set(actions) == set(scan) | {"ReportEventBatch"}
    # The client and authorization services answer Xpress-compressed; Wireshark's own decoder unpacks them.
    bodies = tshark(result.pcap, 'http.content_encoding == "xpress"', "http.file_data")
    assert bodies and all(bytes.fromhex(data).startswith(b"<soap:Envelope") for (data,) in bodies)
    reports = tshark(result.pcap, 'http.request.uri contains "ReportingWebService"', "http.file_data")
    events = b"".join(bytes.fromhex(data) for (data,) in reports)
    assert reports and all(f"<EventID>{e}</EventID>".encode() in events for e in (141, 147, 162))
    gets = tshark(result.pcap, 'http.request.method in {"HEAD", "GET"}', "http.request.method", "http.request.uri",
                  "http.user_agent")
    assert gets and {(method, uri) for method, uri, _ in gets} == {("HEAD", update["path"]), ("GET", update["path"])}
    assert all(agent.startswith("Microsoft BITS/") for _, _, agent in gets)
    sizes = tshark(result.pcap, "http.response.code == 206", "http.content_length_header")
    assert sizes and {int(s) for (s,) in sizes} == {update["size"]}
