"""OPC UA actors: the optional-extra error, and a recorded session decoded by tshark."""

import datetime as dt
import importlib.util
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

import pytest

from pcapforge.compose import compose
from pcapforge.export import _ns_epoch
from pcapforge.plan import build_plan
from pcapforge.record import record, recording_for
from pcapforge.scenario import Scenario, ScenarioError
from pcapforge.tools import MIN_TSHARK, find_tool, tshark_version
from pcapforge.verify import verify_capture

# Service NodeIds (binary encoding) as tshark reports them in opcua.servicenodeid.numeric.
SERVICES = {446: "OpenSecureChannelRequest", 461: "CreateSessionRequest", 464: "CreateSessionResponse",
            467: "ActivateSessionRequest", 527: "BrowseRequest", 530: "BrowseResponse",
            631: "ReadRequest", 634: "ReadResponse", 787: "CreateSubscriptionRequest",
            751: "CreateMonitoredItemsRequest", 826: "PublishRequest", 829: "PublishResponse"}


def scenario(token_lifetime=3600):
    doc = {
        "id": "test-opcua", "title": "OPC UA background", "line": "ot", "version": 1,
        # Recording happens now; a capture year in the past exposes any wall-clock timestamp.
        "site": {"names": ["Testfield"], "codes": ["tst"], "year_range": [2025, 2025]},
        "topology": {
            "sensor": "control",
            "subnets": [{"id": "control", "pool": "10.0.0.0/8", "prefix": 24}],
            "hosts": [
                {"id": "plc", "count": 2, "device": "schneider-m340", "subnet": "control",
                 "name": "plc-{code}-{index:02d}"},
                {"id": "scada", "device": "scada-server-vm", "subnet": "control", "name": "SCADA-01"},
                {"id": "historian", "device": "windows-server-vm", "subnet": "control", "name": "HIST-01"},
            ],
        },
        "actors": [
            {"id": "plc_service", "type": "modbus.server", "hosts": "plc", "params": {"process": "water_treatment"}},
            {"id": "opcua_service", "type": "opcua.server", "hosts": "scada", "params": {"sources": "plc"}},
            {"id": "collector", "type": "opcua.client", "hosts": "historian",
             "params": {"server": "scada", "publishing_interval": 1.0, "keepalive_interval": 5.0,
                        "token_lifetime": token_lifetime}},
        ],
        "difficulty": {"easy": {"duration": "3m", "impairments": {"mid_session": False}, "vars": {}}},
    }
    return Scenario(Path("test-opcua.yaml"), doc)


def test_planning_needs_no_asyncua_and_recording_names_the_extra_before_capturing(monkeypatch, tmp_path):
    for name in [m for m in sys.modules if m == "asyncua" or m.startswith("asyncua.")] + ["asyncua"]:
        monkeypatch.setitem(sys.modules, name, None)
    plan = build_plan(scenario(), "easy", "no-extra")
    assert any(a.op == "opcua.publish" for a in plan.actions)
    out = tmp_path / "recordings" / "opcua.pcap"
    with pytest.raises(ScenarioError, match=r"opcua\.server needs asyncua: .*pip install 'pcapforge\[opcua\]'"):
        record(plan, out)
    assert not out.parent.exists()


capture_tools = (find_tool("tshark") and (find_tool("dumpcap") or find_tool("tcpdump"))
                 and tshark_version() >= MIN_TSHARK)


def _epoch(text: str) -> float:
    """tshark absolute time (ISO 8601, nanoseconds, Z or +hhmm) -> epoch seconds. Some 4.4 builds print
    OPC UA times as ``Sep 22, 2025 09:52:24.088022 UTC``, which the SIEM export also accepts."""
    if not text.strip()[:4].isdigit():
        return _ns_epoch(text.strip())
    text = re.sub(r"(\.\d{6})\d*", r"\1", text.strip())
    return dt.datetime.fromisoformat(text).timestamp()


@pytest.mark.skipif(not capture_tools or importlib.util.find_spec("asyncua") is None,
                    reason="requires asyncua (extra 'opcua'), tshark >= 4.4 and loopback capture rights")
def test_recorded_session_decodes_runs_on_the_scenario_clock_and_mirrors_the_process(tmp_path, monkeypatch):
    monkeypatch.setenv("PCAPFORGE_CACHE", str(tmp_path / "cache"))
    plan = build_plan(scenario(token_lifetime=60), "easy", "e2e")
    recording, _ = recording_for(plan, use_cache=False)
    plan.topology.assign_addresses(plan.rng.child("present"))
    pcap = compose(plan, recording, tmp_path / "opcua.pcap", "e2e").path
    report = verify_capture(pcap)
    assert report.ok, [c for c in report.checks if not c["ok"]]

    def fields(display_filter, *names):
        cmd = [find_tool("tshark"), "-n", "-r", str(pcap), "-Y", display_filter, "-T", "fields",
               "-E", "separator=|", "-E", "occurrence=a", "-E", "aggregator=;",
               *[arg for n in names for arg in ("-e", n)]]
        return [line.split("|") for line in
                subprocess.run(cmd, capture_output=True, text=True, check=True).stdout.splitlines()]

    rows = fields("opcua", "ip.src", "ip.dst", "tcp.len", "opcua.transport.type", "opcua.servicenodeid.numeric")
    ips = {h.id: h.ip for h in plan.topology.hosts}
    assert {frozenset(r[:2]) for r in rows} == {frozenset((ips["historian"], ips["scada"]))}
    assert Counter(r[3] for r in rows)["HEL"] == 1
    services = Counter(SERVICES.get(int(r[4]), r[4]) for r in rows if r[4])
    planned = Counter(a.op for a in plan.actions if a.actor == "collector")
    assert services["PublishRequest"] == services["PublishResponse"] == planned["opcua.publish"]
    assert services["ReadRequest"] == services["ReadResponse"] == planned["opcua.read"]
    assert services["BrowseRequest"] == services["BrowseResponse"] == planned["opcua.browse"]
    assert services["CreateSubscriptionRequest"] == 2  # one subscription per PLC
    assert services["CreateSessionRequest"] == services["ActivateSessionRequest"] == 1
    # Issue + one renewal per 45 s (75 % of the 60 s token lifetime).
    assert services["OpenSecureChannelRequest"] == 1 + planned["opcua.renew"] and planned["opcua.renew"] == 3

    # Every payload timestamp is on the scenario clock: headers and tokens within a second of
    # their frame, data values no later than their frame and no earlier than the server's boot.
    # (A null DateTime, e.g. the Browse view timestamp, is shown as the Unix epoch.)
    start = plan.start_epoch
    for frame, *stamps in fields("opcua", "frame.time_epoch", "opcua.Timestamp", "opcua.CreatedAt",
                                 "opcua.PublishTime", "opcua.CurrentTime"):
        for value in ";".join(stamps).split(";"):
            if value and _epoch(value) != 0:
                assert abs(_epoch(value) - float(frame)) < 1.0, (frame, value)
    for frame, *stamps in fields("opcua.datavalue.has_source_timestamp == 1", "frame.time_epoch",
                                 "opcua.datavalue.SourceTimestamp", "opcua.datavalue.ServerTimestamp"):
        for value in ";".join(stamps).split(";"):
            if value:
                assert start - 41 * 86400 <= _epoch(value) <= float(frame) + 1.0, (frame, value)

    # The first monitored item is PLC01's clearwell level: every published value is plausible.
    monitors = [a for a in plan.actions if a.op == "opcua.monitor"]
    assert monitors[0].args["nodes"][0] == "ns=2;s=PLC01.clearwell_level"
    levels = []
    for handles, doubles, booleans in fields("opcua.servicenodeid.numeric == 829", "opcua.ClientHandle",
                                             "opcua.Double", "opcua.Boolean"):
        if handles and not booleans and handles.split(";")[0] == "1":
            levels.append(float(doubles.split(";")[0]))
    assert len(levels) > 20 and all(300 <= level <= 400 for level in levels)
