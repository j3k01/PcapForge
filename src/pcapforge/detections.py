"""Detection content for a generated exercise: Suricata rules derived from the site model
and an instructor hunting guide (Wireshark / Splunk SPL / Kibana KQL per question).

Everything is derived from ``answers.json`` so ``pcapforge export`` can rebuild it for an
existing run: the ``actors`` section says which hosts are PLCs (``modbus.server``),
approved writers (``modbus.operator``) and SCADA clients (``modbus.poller``); the process
profile named in the PLC facts supplies the register map and normal bands.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pcapforge.export import host_ips
from pcapforge.process import ProcessProfile

SID_BASE = 9100000          # local sid range reserved for pcapforge (9100000-9199999)
SID_BAND_BASE = SID_BASE + 100
MODBUS_PORT = 502
WRITER_TYPES = ("modbus.operator",)
CLIENT_TYPES = ("modbus.poller", "modbus.operator")
DATASETS = ("flows", "modbus", "dns", "ntp", "name_resolution", "arp", "dhcp")


@dataclass(frozen=True)
class Rule:
    sid: int
    msg: str
    text: str
    purpose: str


def _hosts(answers: dict, types: tuple[str, ...]) -> list[str]:
    """Host ids of non-incident actors of the given types, in topology order."""
    wanted = {h for a in answers["actors"] if a["type"] in types and not a["incident"] for h in a["hosts"]}
    return [h["id"] for h in answers["topology"]["hosts"] if h["id"] in wanted]


def _addresses(ips: list[str]) -> str:
    return "[" + ",".join(ips) + "]"


def _number(value: float) -> str:
    return f"{value:g}"


def _rule(sid: int, header: str, msg: str, options: str, metadata: str, purpose: str) -> Rule:
    text = f'alert modbus {header} (msg:"{msg}"; {options} metadata: {metadata}; sid:{sid}; rev:1;)'
    return Rule(sid, msg, text, purpose)


def suricata_rules(answers: dict) -> list[Rule]:
    ips = host_ips(answers)
    names = {h["id"]: h["name"] for h in answers["topology"]["hosts"]}
    servers = [a for a in answers["actors"] if a["type"] == "modbus.server"]
    plcs = [ips[h] for a in servers for h in a["hosts"]]
    if not plcs:
        return []
    writers = [ips[h] for h in _hosts(answers, WRITER_TYPES)]
    clients = [ips[h] for h in _hosts(answers, CLIENT_TYPES)]
    to_plcs = f"{_addresses(plcs)} {MODBUS_PORT}"

    rules = []
    if writers:
        rules.append(_rule(
            SID_BASE + 1, f"!{_addresses(writers)} any -> {to_plcs}",
            "PCAPFORGE OT Modbus write from a host not approved to change PLC parameters",
            "modbus: access write;", "mitre_ics T0855",
            "Any Modbus write (functions 5, 6, 15, 16, 22, 23) from outside the approved writers: "
            + ", ".join(names[h] for h in _hosts(answers, WRITER_TYPES)) + "."))
    else:
        rules.append(_rule(
            SID_BASE + 1, f"any any -> {to_plcs}",
            "PCAPFORGE OT Modbus write to a PLC (site has no approved writer)",
            "modbus: access write;", "mitre_ics T0855",
            "Any Modbus write: this site has no approved writer."))
    source = f"!{_addresses(clients)}" if clients else "any"
    rules.append(_rule(
        SID_BASE + 2, f"{source} any -> {to_plcs}",
        "PCAPFORGE OT Modbus device identification from a host that is not a SCADA client",
        "modbus: function 43;", "mitre_ics T0888",
        "Read Device Identification (function 43) from a host other than "
        + (", ".join(names[h] for h in _hosts(answers, CLIENT_TYPES)) or "any approved client") + "."))

    sid = SID_BAND_BASE
    for actor in sorted(servers, key=lambda a: a["id"]):
        profile = ProcessProfile(answers["facts"][actor["id"]]["process"])
        dest = f"{_addresses([ips[h] for h in actor['hosts']])} {MODBUS_PORT}"
        for point in profile.table("holding"):
            if not (point.writable and point.normal):
                continue
            lo, hi = point.normal
            lo_raw = math.ceil(lo * point.scale - 1e-9)
            hi_raw = math.floor(hi * point.scale + 1e-9)
            unit = f" {point.unit}" if point.unit else ""
            # Suricata numbers Modbus addresses from 1: wire address + 1.
            where = f"modbus: access write holding, address {point.address + 1}"
            band = f"{_number(lo)}-{_number(hi)}{unit}"
            if hi_raw < 65535:
                rules.append(_rule(
                    sid, f"any any -> {dest}",
                    f"PCAPFORGE OT {point.name} written above normal band "
                    f"(holding {point.address} raw > {hi_raw} = {_number(hi)}{unit})",
                    f"{where}, value >{hi_raw};", f"mitre_ics T0836, pcapforge_point {point.name}",
                    f"{point.name} (holding {point.address}, band {band}) set above {hi_raw} raw."))
            sid += 1
            if lo_raw > 0:
                rules.append(_rule(
                    sid, f"any any -> {dest}",
                    f"PCAPFORGE OT {point.name} written below normal band "
                    f"(holding {point.address} raw < {lo_raw} = {_number(lo)}{unit})",
                    f"{where}, value <{lo_raw};", f"mitre_ics T0836, pcapforge_point {point.name}",
                    f"{point.name} (holding {point.address}, band {band}) set below {lo_raw} raw."))
            sid += 1
    return rules


def _rules_file(answers: dict, rules: list[Rule]) -> str:
    sc = answers["scenario"]
    ips = host_ips(answers)
    names = {h["id"]: h["name"] for h in answers["topology"]["hosts"]}

    def listing(types: tuple[str, ...]) -> str:
        hosts = _hosts(answers, types)
        return ", ".join(f"{names[h]} {ips[h]}" for h in hosts) or "none"

    plcs = [h for a in answers["actors"] if a["type"] == "modbus.server" for h in a["hosts"]]
    lines = [
        f"# pcapforge Suricata rules: {sc['id']} ({sc['difficulty']}, seed {sc['seed']})",
        f"# Site: {answers['topology']['site_name']} ({answers['topology']['domain']})",
        "#",
        "# Suricata's Modbus parser is disabled by default; enable it when running these rules:",
        "#   suricata -r capture.pcap -S suricata.rules -k none -l <log dir> \\",
        "#            --set app-layer.protocols.modbus.enabled=true",
        "# Modbus addresses in `modbus: access` are 1-based (wire address + 1); values are raw registers.",
        "#",
        f"# PLCs:                     {', '.join(f'{names[h]} {ips[h]}' for h in plcs) or 'none'}",
        f"# Approved writers:         {listing(WRITER_TYPES)}",
        f"# Approved Modbus clients:  {listing(CLIENT_TYPES)}",
        f"# sid range: {SID_BASE}-{SID_BASE + 99999} (local).",
        "",
    ]
    for rule in rules:
        lines += [f"# {rule.purpose}", rule.text, ""]
    return "\n".join(lines)


def _answer_text(value: Any) -> str:
    if isinstance(value, (list, dict)):
        return json.dumps(value, ensure_ascii=False)
    return str(value)


def _expect_text(expect: dict) -> str:
    parts = []
    if "count" in expect:
        parts.append(f"exactly {expect['count']}")
    if "min" in expect:
        parts.append(f"at least {expect['min']}")
    if "max" in expect:
        parts.append(f"at most {expect['max']}")
    return " and ".join(parts) + " frame(s)"


def _hunting(answers: dict, rules: list[Rule]) -> str:
    sc = answers["scenario"]
    lines = [
        f"# Hunting guide: {sc['title']}",
        "",
        f"Scenario `{sc['id']}`, difficulty `{sc['difficulty']}`, seed `{sc['seed']}`. "
        "Instructor material: contains the answers.",
        "",
        "Wireshark display filters come from the answer key and are machine-verified by "
        "`pcapforge verify` (expected frame counts shown). **SPL and KQL queries are generated "
        "from scenario templates and have not been machine-verified against Splunk or Elastic.**",
        "",
        "## Loading the SIEM export",
        "",
        "`siem/<dataset>.jsonl` holds one JSON event per line; `ts` is ISO-8601 UTC with microseconds.",
        "",
        "- Splunk: index each file with sourcetype `pcapforge:<dataset>` "
        "(e.g. `pcapforge:modbus`). `props.conf`:",
        "",
        "  ```ini",
        "  [pcapforge:modbus]",
        "  INDEXED_EXTRACTIONS = json",
        "  KV_MODE = none",
        "  TIMESTAMP_FIELDS = ts",
        "  TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%6NZ",
        "  TZ = UTC",
        "  ```",
        "",
        "- Elastic: one index per file named `pcapforge-<dataset>` (e.g. `pcapforge-modbus`); map "
        "`ts` to `@timestamp` (Kibana file upload: timestamp field `ts`). KQL queries run in a data "
        "view over that index.",
        "",
        "Datasets: " + ", ".join(f"`{d}`" for d in DATASETS) + ".",
        "",
        "## Suricata rules",
        "",
        "`suricata.rules` (run with `--set app-layer.protocols.modbus.enabled=true`):",
        "",
        "| sid | Fires on |",
        "|---|---|",
    ]
    lines += [f"| {r.sid} | {r.purpose.replace('|', '/')} |" for r in rules]
    lines += ["", "## Questions", ""]
    for index, question in enumerate(answers["questions"], 1):
        hunt = question.get("hunt", {})
        lines += [f"### {index}. [{question['id']}] {question['text']}", "",
                  f"**Answer:** `{_answer_text(question['answer'])}`", ""]
        if question.get("checks"):
            lines.append("**Wireshark** (verified):")
            lines.append("")
            for check in question["checks"]:
                lines.append(f"- `{check['filter']}` - {_expect_text(check['expect'])}")
            lines.append("")
        elif hunt.get("wireshark"):
            lines += ["**Wireshark** (hunting filter, no expected count):", "",
                      f"- `{hunt['wireshark']}`", ""]
        dataset = hunt.get("dataset", "modbus")
        if hunt.get("spl"):
            lines += ["**Splunk SPL** (not machine-verified):", "", "```spl", hunt["spl"], "```", ""]
        if hunt.get("kql"):
            lines += [f"**Kibana KQL** on `pcapforge-{dataset}` (not machine-verified):", "",
                      "```kql", hunt["kql"], "```", ""]
        if hunt.get("look_for"):
            lines += [f"**What to look for:** {hunt['look_for']}", ""]
    return "\n".join(lines)


def write_detections(answers: dict, out_dir: Path) -> dict[str, Path]:
    """Write ``suricata.rules`` and ``hunting.md`` for one run into ``out_dir``."""
    rules = suricata_rules(answers)
    out_dir.mkdir(parents=True, exist_ok=True)
    paths = {"suricata.rules": out_dir / "suricata.rules", "hunting.md": out_dir / "hunting.md"}
    paths["suricata.rules"].write_text(_rules_file(answers, rules), encoding="utf-8", newline="\n")
    paths["hunting.md"].write_text(_hunting(answers, rules), encoding="utf-8", newline="\n")
    return paths
