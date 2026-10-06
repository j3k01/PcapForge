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
import struct
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

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
            unit = f" {point.unit}" if point.unit else ""
            band = f"{_number(lo)}-{_number(hi)}{unit}"
            metadata = f"mitre_ics T0836, pcapforge_point {point.name}"
            if point.type == "float32":
                for side, limit, matches in (("above", hi, _float_above(point, hi)),
                                             ("below", lo, _float_below(point, lo) if lo > 0 else [])):
                    for options in matches:
                        rules.append(_rule(
                            sid, f"any any -> {dest}",
                            f"PCAPFORGE OT {point.name} written {side} normal band "
                            f"(holding {point.address} float32 {'>' if side == 'above' else '<'} {_number(limit)}{unit})",
                            options, metadata,
                            f"{point.name} (holding {point.address}-{point.address + 1}, FLOAT32 "
                            f"{'ABCD' if point.word_order == 'big' else 'CDAB'}, band {band}) set {side} "
                            f"{_number(limit)} by a Write Multiple Registers request starting at the point."))
                        sid += 1
                continue
            lo_raw = math.ceil(lo * point.scale - 1e-9)
            hi_raw = math.floor(hi * point.scale + 1e-9)
            # Suricata numbers Modbus addresses from 1: wire address + 1.
            where = f"modbus: access write holding, address {point.address + 1}"
            if hi_raw < 65535:
                rules.append(_rule(
                    sid, f"any any -> {dest}",
                    f"PCAPFORGE OT {point.name} written above normal band "
                    f"(holding {point.address} raw > {hi_raw} = {_number(hi)}{unit})",
                    f"{where}, value >{hi_raw};", metadata,
                    f"{point.name} (holding {point.address}, band {band}) set above {hi_raw} raw."))
            sid += 1
            if lo_raw > 0:
                rules.append(_rule(
                    sid, f"any any -> {dest}",
                    f"PCAPFORGE OT {point.name} written below normal band "
                    f"(holding {point.address} raw < {lo_raw} = {_number(lo)}{unit})",
                    f"{where}, value <{lo_raw};", metadata,
                    f"{point.name} (holding {point.address}, band {band}) set below {lo_raw} raw."))
            sid += 1
    return rules


# A float32 setpoint cannot be compared with Suricata's `modbus: ... value` (one 16-bit register),
# and Suricata does not combine the `modbus` keyword with payload keywords. These rules test the
# request bytes instead: a Write Multiple Registers (function 16, MBAP offset 7) of two registers
# starting at the point, whose data (offset 13) holds the float. For non-negative IEEE 754 values
# the bit pattern orders like the value, so an unsigned comparison against the band limit's bit
# pattern is exact; CDAB (low word first) needs the high word compared first, then the low word.
def _float_request(point) -> str:
    return f'content:"|10|"; offset:7; depth:1; byte_test:2,=,{point.address},8; byte_test:2,=,2,10;'


def _float_words(limit: float) -> tuple[int, int, int]:
    bits = struct.unpack(">I", struct.pack(">f", limit))[0]
    return bits, bits >> 16, bits & 0xFFFF


def _float_above(point, limit: float) -> list[str]:
    bits, high, low = _float_words(limit)
    base = _float_request(point)
    if point.word_order == "big":
        return [f"{base} byte_test:4,>,{bits},13;"]
    return [f"{base} byte_test:2,>,{high},15;",
            f"{base} byte_test:2,=,{high},15; byte_test:2,>,{low},13;"]


def _float_below(point, limit: float) -> list[str]:
    # Negative values have the sign bit set and compare as large unsigned numbers: not matched.
    bits, high, low = _float_words(limit)
    base = _float_request(point)
    if point.word_order == "big":
        return [f"{base} byte_test:4,<,{bits},13;"]
    return [f"{base} byte_test:2,<,{high},15;",
            f"{base} byte_test:2,=,{high},15; byte_test:2,<,{low},13;"]


# --- Sigma --------------------------------------------------------------------------
# SIEM-agnostic detections over the exported JSON-lines logs (one rule file per detection,
# https://sigmahq.io). The log source is the pcapforge SIEM export: `product: pcapforge`,
# `service` the dataset (e.g. `modbus`, `dhcp`), matching the sourcetype `pcapforge:<dataset>`
# the hunting guide loads the files under. Field names are the JSONL keys, so these run as
# written once the export is indexed; they are not tied to Splunk or Elastic.

SIGMA_NAMESPACE = uuid.UUID("b5e7c6d2-0a4f-5e8b-9c1d-7f3a2e6b4c80")  # stable rule ids per site+key


def _sigma_id(answers: dict, key: str) -> str:
    sc = answers["scenario"]
    return str(uuid.uuid5(SIGMA_NAMESPACE, f"{sc['id']}|{sc['difficulty']}|{sc['seed']}|{key}"))


def _sigma(answers: dict, *, key: str, title: str, description: str, service: str, level: str,
           detection: dict, tags: list[str], falsepositives: list[str], fields: list[str] | None,
           name: str | None = None) -> dict:
    """A Sigma detection rule. Base rules of a correlation carry a ``name`` and no ``fields``
    (pySigma's Splunk backend cannot append a field table to a correlation query)."""
    return {
        "title": title,
        "id": _sigma_id(answers, key),
        **({"name": name} if name else {}),
        "status": "experimental",
        "description": description,
        "references": ["https://github.com/j3k01/PcapForge"],
        "author": "pcapforge",
        "date": answers.get("capture", {}).get("start", "1970-01-01T00:00:00Z")[:10],
        "logsource": {"product": "pcapforge", "service": service},
        "detection": detection,
        **({"fields": fields} if fields else {}),
        "falsepositives": falsepositives,
        "level": level,
        "tags": tags,
    }


def _correlation(answers: dict, *, key: str, title: str, description: str, level: str, kind: str,
                 rules: list[str], group_by: list[str], timespan: str, condition: dict, generate: bool,
                 tags: list[str], falsepositives: list[str], field: str | None = None) -> dict:
    """A Sigma correlation rule (Sigma 2.0) over the named base rules. ``generate`` says whether
    the base rules are also converted on their own (true for detections that stand alone)."""
    correlation = {"type": kind, "rules": rules, "group-by": group_by, "timespan": timespan,
                   "generate": generate, "condition": {**({"field": field} if field else {}), **condition}}
    return {
        "title": title,
        "id": _sigma_id(answers, key),
        "status": "experimental",
        "description": description,
        "references": ["https://github.com/j3k01/PcapForge"],
        "author": "pcapforge",
        "date": answers.get("capture", {}).get("start", "1970-01-01T00:00:00Z")[:10],
        "correlation": correlation,
        "falsepositives": falsepositives,
        "level": level,
        "tags": tags,
    }


def _profile_points(answers: dict, servers: list[dict], table: str, predicate) -> list[str]:
    """Sorted names of the points of ``table`` in every PLC's register map that satisfy ``predicate``."""
    names = set()
    for actor in servers:
        profile = ProcessProfile(answers["facts"][actor["id"]]["process"])
        names.update(p.name for p in profile.table(table) if predicate(p))
    return sorted(names)


def sigma_rules(answers: dict) -> list[dict]:
    """Sigma detections derived from the site model, one dict per rule (same roles as the
    Suricata rules: PLCs = modbus.server, approved writers = modbus.operator, SCADA clients
    = modbus.poller + operators)."""
    ips = host_ips(answers)
    names = {h["id"]: h["name"] for h in answers["topology"]["hosts"]}
    servers = [a for a in answers["actors"] if a["type"] == "modbus.server"]
    plcs = [ips[h] for a in servers for h in a["hosts"]]
    if not plcs:
        return []
    writers = [ips[h] for h in _hosts(answers, WRITER_TYPES)]
    clients = [ips[h] for h in _hosts(answers, CLIENT_TYPES)]
    rules: list[dict] = []

    write_sel: dict = {"write": True, "dest": plcs}
    if writers:
        detection = {"writes": write_sel, "approved": {"src": writers}, "condition": "writes and not approved"}
        writer_names = ", ".join(names[h] for h in _hosts(answers, WRITER_TYPES))
        description = (f"A Modbus write (function 5, 6, 15, 16, 22, 23) to a PLC from a host other than "
                       f"the approved engineering workstation(s): {writer_names}.")
        fp = [f"Maintenance from a host other than {writer_names}."]
    else:
        detection = {"writes": write_sel, "condition": "writes"}
        description = "A Modbus write to a PLC. This site has no approved writer, so every write is notable."
        fp = ["Commissioning or maintenance writes."]
    rules.append(_sigma(
        answers, key="modbus-unapproved-writer", title="Modbus write from an unapproved host",
        description=description, service="modbus", level="high", detection=detection,
        tags=["attack.t0855", "attack.t0836"], falsepositives=fp,
        fields=["ts", "src", "dest", "function_code", "point", "value", "in_normal_band", "request_frame"]))

    rules.append(_sigma(
        answers, key="modbus-out-of-band-write", title="Modbus setpoint written outside its normal band",
        description="A Modbus write whose engineering value falls outside the point's normal operating "
                    "band (in_normal_band is false), as annotated from the PLC register map.",
        service="modbus", level="high",
        detection={"selection": {"write": True, "dest": plcs, "in_normal_band": False}, "condition": "selection"},
        tags=["attack.t0836"], falsepositives=["A legitimate but unusually large operator adjustment."],
        fields=["ts", "src", "dest", "point", "value", "unit", "request_frame"]))

    ident_sel = {"function_code": 43, "dest": plcs}
    if clients:
        ident = {"selection": ident_sel, "approved": {"src": clients}, "condition": "selection and not approved"}
        client_names = ", ".join(names[h] for h in _hosts(answers, CLIENT_TYPES))
        ident_desc = (f"Read Device Identification (function 43) sent to a PLC by a host other than the "
                      f"known SCADA / HMI / historian clients: {client_names}.")
    else:
        ident = {"selection": ident_sel, "condition": "selection"}
        ident_desc = "Read Device Identification (function 43) sent to a PLC."
    rules.append(_sigma(
        answers, key="modbus-device-identification", title="Modbus device identification from an unexpected host",
        description=ident_desc, service="modbus", level="medium", detection=ident,
        tags=["attack.t0888", "attack.t0846"],
        falsepositives=["An asset-inventory or vulnerability scan run by the OT team."],
        fields=["ts", "src", "dest", "function_code", "request_frame"]))

    conn_sel = {"dest_port": MODBUS_PORT, "dest": plcs}
    if clients:
        conn = {"selection": conn_sel, "approved": {"src": clients}, "condition": "selection and not approved"}
        conn_desc = (f"A TCP connection to a PLC's Modbus port (502) from a host other than the known SCADA / HMI "
                     f"/ historian clients: {', '.join(names[h] for h in _hosts(answers, CLIENT_TYPES))}. One host "
                     f"opening 502 to several PLCs in a short window is a Modbus service sweep.")
    else:
        conn = {"selection": conn_sel, "condition": "selection"}
        conn_desc = "A TCP connection to a PLC's Modbus port (502). One host opening 502 to several PLCs is a sweep."
    rules.append(_sigma(
        answers, key="modbus-connection-from-unexpected-host", title="Modbus connection from an unexpected host",
        description=conn_desc, service="flows", level="medium", detection=conn,
        tags=["attack.t0846"],
        falsepositives=["A new or reconfigured SCADA client, or an OT-team asset scan."],
        fields=["ts", "src", "dest", "dest_port", "state", "packets_out"]))

    # Port sweep (ot-modbus-discovery): one source trying 502 on several hosts, PLC or not. The swept
    # hosts answer with a RST (closed) or nothing (host firewall), so the flows carry any state.
    sweep = {"selection": {"dest_port": MODBUS_PORT}, "condition": "selection"}
    if clients:
        sweep = {"selection": {"dest_port": MODBUS_PORT}, "approved": {"src": clients},
                 "condition": "selection and not approved"}
    rules.append(_sigma(
        answers, key="modbus-port-502-attempt", title="Modbus port 502 connection attempt by a non-SCADA host",
        description="Any TCP flow to port 502 from a host other than the SCADA clients, PLC or not (base rule of "
                    "the Modbus port-sweep correlation).",
        service="flows", level="low", detection=sweep, tags=["attack.t0846"],
        falsepositives=["See the port-sweep correlation."], fields=None,
        name="pcapforge_modbus_port_attempt"))
    rules.append(_correlation(
        answers, key="modbus-port-sweep", title="Modbus/TCP port sweep of the control network",
        description="One host outside the SCADA clients opened (or tried) port 502 on at least three different "
                    "hosts within ten minutes: a Modbus service sweep (remote system discovery).",
        level="high", kind="value_count", rules=["pcapforge_modbus_port_attempt"], group_by=["src"],
        timespan="10m", condition={"gte": 3}, field="dest", generate=False, tags=["attack.t0846"],
        falsepositives=["An asset-inventory or vulnerability scan run by the OT team."]))

    # Register-map enumeration (discovery, and the writer's reconnaissance): oversized reads are
    # rejected with exception 2 before the real table sizes are found. SCADA polls never hit it.
    rules.append(_sigma(
        answers, key="modbus-illegal-data-address", title="Modbus read rejected with Illegal Data Address",
        description="A PLC answered a request with exception 2 (Illegal Data Address): the client asked for "
                    "registers outside the configured map, typical of register-map enumeration (point and tag "
                    "identification). The site's SCADA polls only read the configured map.",
        service="modbus", level="medium",
        detection={"selection": {"dest": plcs, "exception_code": 2}, "condition": "selection"},
        tags=["attack.t0861", "attack.t0888"],
        falsepositives=["A misconfigured new HMI or historian tag list."],
        fields=["ts", "src", "dest", "function_code", "address", "quantity", "request_frame"]))

    # Alarm suppression (ot-modbus-coil-manipulation): acknowledging or resetting alarms by writing
    # the PLC's alarm coil over the network instead of on the HMI.
    alarm_coils = _profile_points(answers, servers, "coils", lambda p: p.writable and "alarm" in p.name.split("_"))
    if alarm_coils:
        rules.append(_sigma(
            answers, key="modbus-alarm-acknowledge", title="Modbus alarm acknowledge or reset written to a PLC",
            description=f"A Modbus coil write to the PLC's alarm acknowledge / reset coil ({', '.join(alarm_coils)}). "
                        "Operators acknowledge alarms on the HMI; a network write clears the alarm state that "
                        "would otherwise show the effect of a forced actuator.",
            service="modbus", level="high",
            detection={"selection": {"write": True, "dest": plcs, "point": alarm_coils}, "condition": "selection"},
            tags=["attack.t0878"],
            falsepositives=["A SCADA system that acknowledges alarms through Modbus by design."],
            fields=["ts", "src", "dest", "function_code", "point", "request_frame"]))

    # Alarm masking (ot-modbus-alarm-masking): an alarm threshold written outside its band so the
    # alarm can no longer trip.
    thresholds = _profile_points(answers, servers, "holding",
                                 lambda p: p.writable and p.normal and "alarm" in p.name.split("_"))
    if thresholds:
        rules.append(_sigma(
            answers, key="modbus-alarm-threshold-out-of-band", title="Alarm threshold written outside its normal band",
            description="A Modbus write moved an alarm threshold of the PLC register map outside its normal band, "
                        "so the alarm it drives can no longer trip (alarm suppression); look for an out-of-band "
                        "setpoint change by the same source shortly after.",
            service="modbus", level="high",
            detection={"selection": {"write": True, "dest": plcs, "point": thresholds, "in_normal_band": False},
                       "condition": "selection"},
            tags=["attack.t0878", "attack.t0836"],
            falsepositives=["A threshold retuned during commissioning, recorded in a change ticket."],
            fields=["ts", "src", "dest", "point", "value", "unit", "request_frame"]))

    # Command replay (ot-modbus-command-replay): the same point set to the same value by more than
    # one host. Values stay in band; what differs is the source.
    rules.append(_sigma(
        answers, key="modbus-register-write", title="Modbus register write to a mapped point",
        description="Any Modbus holding-register write annotated with a register-map point (base rule of the "
                    "repeated-write correlation).",
        service="modbus", level="informational",
        detection={"selection": {"write": True, "dest": plcs, "function_code": [6, 16, 23], "point|exists": True},
                   "condition": "selection"},
        tags=["attack.t0855"], falsepositives=["See the repeated-write correlation."],
        fields=None, name="pcapforge_modbus_register_write"))
    rules.append(_correlation(
        answers, key="modbus-write-replayed", title="Same Modbus setpoint value written by more than one host",
        description="A PLC point was set to the same value by at least two different hosts within four hours. "
                    "Legitimate changes come from the engineering workstation; an identical command from a "
                    "second host is a replay of captured traffic (values stay in band, so band rules miss it).",
        level="high", kind="value_count", rules=["pcapforge_modbus_register_write"],
        group_by=["dest", "point", "value"], timespan="4h", condition={"gte": 2}, field="src", generate=False,
        tags=["attack.t0855", "attack.t0831"],
        falsepositives=["Two engineering workstations applying the same recipe value."]))

    if any(a["type"] == "dhcp.client" for a in answers["actors"]):
        rules.append(_sigma(
            answers, key="dhcp-new-host-on-control-lan", title="New host leased an address on the control LAN",
            description="A DHCP DISCOVER on the control segment: a host without a static address joined the "
                        "network. On an OT control LAN where every asset is normally statically addressed, a "
                        "new lease is worth confirming against the maintenance schedule.",
            service="dhcp", level="low",
            detection={"selection": {"message": "discover"}, "condition": "selection"},
            tags=["attack.t0842"],
            falsepositives=["A scheduled maintenance laptop or a newly commissioned device."],
            fields=["ts", "client_mac", "host_name", "vendor_class", "assigned_addr"]))
    return rules


def _sigma_files(answers: dict, rules: list[dict]) -> dict[str, str]:
    """File name -> YAML text for each Sigma rule. A correlation rule shares its file with the
    base rules it names, base rules first (multi-document YAML, as pySigma resolves references
    in load order)."""
    by_name = {r["name"]: r for r in rules if "name" in r}
    bundled = {n for r in rules if "correlation" in r for n in r["correlation"]["rules"]}
    out = {}
    for rule in rules:
        if rule.get("name") in bundled:
            continue
        docs = [by_name[n] for n in rule["correlation"]["rules"]] + [rule] if "correlation" in rule else [rule]
        name = rule["title"].lower().replace(" ", "_")
        name = "".join(c for c in name if c.isalnum() or c in "_-")
        out[f"{name}.yml"] = yaml.dump_all(docs, sort_keys=False, allow_unicode=True, default_flow_style=False)
    return out


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
        "# FLOAT32 setpoints are matched on the request bytes (byte_test on the IEEE 754 bit pattern of a",
        "# Write Multiple Registers that starts at the point; byte offsets count from the MBAP header).",
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
    sigma = sigma_rules(answers)
    if sigma:
        lines += ["", "## Sigma rules", "",
                  "`sigma/*.yml` (SIEM-agnostic, over the JSON-lines export; `logsource.service` is the "
                  "dataset, matching the sourcetype `pcapforge:<dataset>`). Convert with "
                  "[sigma-cli](https://github.com/SigmaHQ/sigma-cli), e.g. "
                  "`sigma convert -t splunk sigma/`:", "",
                  "| level | rule | fires on |", "|---|---|---|"]
        lines += [f"| {r['level']} | {r['title']} | {r['description'].replace('|', '/')} |" for r in sigma]
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
    """Write ``suricata.rules``, ``sigma/*.yml`` and ``hunting.md`` for one run into ``out_dir``."""
    rules = suricata_rules(answers)
    out_dir.mkdir(parents=True, exist_ok=True)
    paths = {"suricata.rules": out_dir / "suricata.rules", "hunting.md": out_dir / "hunting.md"}
    paths["suricata.rules"].write_text(_rules_file(answers, rules), encoding="utf-8", newline="\n")
    paths["hunting.md"].write_text(_hunting(answers, rules), encoding="utf-8", newline="\n")
    sigma = _sigma_files(answers, sigma_rules(answers))
    if sigma:
        sigma_dir = out_dir / "sigma"
        sigma_dir.mkdir(exist_ok=True)
        for name, text in sigma.items():
            path = sigma_dir / name
            path.write_text(text, encoding="utf-8", newline="\n")
            paths[f"sigma/{name}"] = path
    return paths
