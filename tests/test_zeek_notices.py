"""The run's Zeek detection script (detections.zeek_script, loaded by --zeek): on every incident scenario and
level notice.log flags the attacker and only the attacker, Modbus setpoints written out of band are named,
and normal operations (ot-baseline-operations) raise nothing. A scenario whose protocol needs an ICSNPP
package or pcapforge's IEC 104 analyzer is skipped when Zeek lacks it."""

import json
import subprocess

import pytest

from pcapforge.pipeline import generate
from pcapforge.scenario import discover
from pcapforge.tools import MIN_TSHARK, find_tool, tshark_version
from pcapforge.zeek import IEC104_SCRIPTS, find_zeek
from recordings import ensure_recorded

SEED, DURATION = "siem-queries", 600.0   # the recordings the SIEM and Zeek hunt tests cache
NEEDS = {"ot-bacnet-unauthorized-write": "packages/icsnpp-bacnet", "ot-enip-drive-manipulation": "packages/icsnpp-enip",
         "ot-iec104-command-injection": IEC104_SCRIPTS}

capture_tools = (find_tool("tshark") and (find_tool("dumpcap") or find_tool("tcpdump"))
                 and tshark_version() >= MIN_TSHARK)


def loadable(script: str) -> bool:
    proc = subprocess.run([*find_zeek(), "-b", "-e", f'event zeek_init() {{ print find_in_zeekpath("{script}") != ""; }}'],
                          capture_output=True, text=True, timeout=120, check=False)
    return proc.stdout.strip() == "T"


RUNS = [(sid, level) for sid in sorted(discover()) if sid.startswith("ot-") for level in ("easy", "medium", "hard")]


@pytest.mark.skipif(not capture_tools or not find_zeek(), reason="requires tshark >= 4.4, loopback capture and zeek")
@pytest.mark.parametrize("scenario_id,level", RUNS, ids=[f"{s}-{lv}" for s, lv in RUNS])
def test_notices_flag_the_attacker_only(scenario_id, level, tmp_path):
    if scenario_id in NEEDS and not loadable(NEEDS[scenario_id]):
        pytest.skip(f"Zeek lacks {NEEDS[scenario_id]}")
    ensure_recorded(discover()[scenario_id], level, SEED, DURATION, tmp_path / "recording")
    result = generate(discover()[scenario_id], level, SEED, tmp_path, duration=DURATION, zeek=True)
    assert result.report.ok, [c for c in result.report.checks if not c["ok"]]
    answers = json.loads(result.answers.read_text(encoding="utf-8"))
    path = result.directory / "zeek" / "notice.log"
    notices = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()] if path.exists() else []
    incidents = [answers["facts"][a["id"]] for a in answers["actors"]
                 if a["incident"] and "source" in answers["facts"].get(a["id"], {})]
    if not incidents:
        assert not notices, notices
        return
    attackers = {i["source"]["ip"] for i in incidents}
    assert notices, "the incident raised no notice"
    assert {n["src"] for n in notices} == attackers, notices
    change = answers["facts"].get("change")
    if change:  # out-of-band setpoint writes are named, whoever sent them
        band = {n["sub"] for n in notices if n["note"] == "Pcapforge::Modbus_Out_Of_Band_Write"}
        assert band == set(change["point_names"])
