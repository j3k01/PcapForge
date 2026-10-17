"""Zeek logs of a composed capture: run a local Zeek, or the official Docker image, over the pcap and
keep its JSON logs (``conn``, ``dns``, ``ntp``, ``dhcp``, ``modbus``, ``dnp3``, ``known_*``, ...) in
``<run>/zeek/`` next to the pcapforge JSONL export.

Zeek runs in deterministic mode (``-D``: connection uids and other random values are seeded with
zero), so the same capture always gives the same logs. ``Site::local_nets`` is the scenario's
subnets, which fills ``local_orig`` / ``local_resp`` in conn.log and the ``known_*`` logs. Besides the
base scripts, the Modbus policy scripts (master/slave pairs, register change tracking) and known
hosts / services are loaded.

Zeek has no analyzers for S7comm, OPC UA, BACnet, EtherNet/IP or IEC 60870-5-104. CISA's ICSNPP
packages add the first four (and detailed DNP3 control and object logs); pcapforge's own Spicy
analyzer (``zeek_analyzers/iec104``) adds IEC 104. Each one that is installed (``ANALYZERS_INSTALL``)
is loaded, the others are skipped, so the logs depend on what the Zeek installation has.
"""

from __future__ import annotations

import functools
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

from pcapforge.tools import ToolNotFound

IMAGE = "zeek/zeek:lts"   # official image (hub.docker.com/r/zeek/zeek); PCAPFORGE_ZEEK_IMAGE overrides it
SCRIPTS = (
    "policy/protocols/conn/known-hosts",
    "policy/protocols/conn/mac-logging",  # orig_l2_addr / resp_l2_addr in conn.log: the MACs on the wire
    "policy/protocols/conn/known-services",
    "policy/protocols/modbus/known-masters-slaves",
    "policy/protocols/modbus/track-memmap",
)
# zkg package -> pinned version (tag or commit): S7comm / COTP, OPC UA Binary, BACnet, EtherNet/IP and
# CIP (also class 0/1 I/O), and detailed DNP3 logging over Zeek's own DNP3 analyzer.
ICSNPP = {
    "icsnpp-s7comm": "7ebeb03a0f954541369361651d1c27d09a64b5a3",
    "icsnpp-opcua-binary": "v2.0.0",
    "icsnpp-bacnet": "804ecefa23f65de59cd4f955738361c45795724f",
    "icsnpp-enip": "808f90b0d834481a1368dbcad650f63c88550991",
    "icsnpp-dnp3": "b31dbadeceb1cbcda16aef89c650559cd177dd7e",
}
# pcapforge's IEC 60870-5-104 analyzer: Spicy grammar + event mapping (compiled into the Spicy module
# directory, which Zeek loads automatically) and the logging scripts (into the site directory).
IEC104_DIR = Path(__file__).parent / "zeek_analyzers" / "iec104"
IEC104_SCRIPTS = "pcapforge-iec104"
SITE_SCRIPT = "pcapforge-site.zeek"
LOCATIONS = ("/opt/zeek/bin/zeek", "/usr/local/zeek/bin/zeek")
TIMEOUT_S = 1800


class ZeekError(RuntimeError):
    pass


def find_zeek() -> list[str]:
    """Command prefix that runs Zeek: ``PCAPFORGE_ZEEK``, ``zeek`` on PATH or under /opt/zeek, on Windows
    a Zeek in the default WSL distribution, else empty (the caller falls back to Docker)."""
    if env := os.environ.get("PCAPFORGE_ZEEK"):
        return [env]
    if found := shutil.which("zeek"):
        return [found]
    if local := [path for path in LOCATIONS if Path(path).is_file()][:1]:
        return local
    return _wsl_zeek() if os.name == "nt" else []


@functools.cache
def _wsl_zeek() -> list[str]:
    """``wsl.exe -e <zeek>`` when the default WSL distribution has Zeek on PATH or under /opt/zeek."""
    wsl = shutil.which("wsl")
    if wsl is None:
        return []
    probe = 'command -v zeek || for p in "$@"; do [ -x "$p" ] && echo "$p" && break; done'
    try:
        proc = subprocess.run([wsl, "-e", "sh", "-c", probe, "sh", *LOCATIONS],
                              capture_output=True, timeout=120, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return []
    found = proc.stdout.decode("utf-8", "replace").strip().splitlines()
    return [wsl, "-e", found[0]] if proc.returncode == 0 and found and found[0].startswith("/") else []


def site_script(subnets: list[str]) -> str:
    lines = ["# Written by pcapforge for this capture: JSON logs and the scenario's subnets as local.",
             "redef LogAscii::use_json = T;"]
    if subnets:
        lines.append(f"redef Site::local_nets += {{ {', '.join(subnets)} }};")
    lines += [f"@load {script}" for script in SCRIPTS]
    # An ICSNPP package is loaded when zkg installed it (its scripts are in ZEEKPATH's site/packages),
    # the IEC 104 analyzer's logging when ANALYZERS_INSTALL put it into the site directory.
    for package in [f"packages/{name}" for name in ICSNPP] + [IEC104_SCRIPTS]:
        lines += [f'@if ( find_in_zeekpath("{package}") != "" )', f"@load {package}", "@endif"]
    return "\n".join(lines) + "\n"


# Zeek LTS from the security:zeek OBS packages into /opt/zeek, as in CI (Ubuntu 24.04, also the default WSL distribution).
_APT_INSTALL = ("echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_24.04/ /' "
                "> /etc/apt/sources.list.d/security:zeek.list && curl -fsSL "
                "https://download.opensuse.org/repositories/security:zeek/xUbuntu_24.04/Release.key "
                "| gpg --dearmor > /etc/apt/trusted.gpg.d/security_zeek.gpg && apt-get update "
                "&& apt-get install -y zeek-lts-core")
# As root after the above: zkg, plus the headers and cmake the ICSNPP plugins build with, then the
# pinned ICSNPP packages and pcapforge's IEC 104 analyzer (CI runs this; docs/siem.md shows it).
ANALYZERS_INSTALL = (
    "apt-get install -y zeek-lts-zkg cmake && export PATH=/opt/zeek/bin:$PATH "
    "&& zkg autoconfig --force && zkg refresh && "
    + " && ".join(f"zkg install --force --skiptests --version {version} {package}"
                  for package, version in ICSNPP.items())
    + f" && spicyz -o \"$(zeek-config --prefix)/lib/zeek/spicy/{IEC104_SCRIPTS}.hlto\" "
      f"'{IEC104_DIR.as_posix()}/iec104.spicy' '{IEC104_DIR.as_posix()}/iec104.evt'"
    + f" && mkdir -p \"$(zeek-config --site_dir)/{IEC104_SCRIPTS}\""
    + f" && cp '{IEC104_DIR.as_posix()}/'*.zeek \"$(zeek-config --site_dir)/{IEC104_SCRIPTS}/\"")


def install_hint() -> str:
    """One command that installs Zeek on this platform."""
    if os.name == "nt":
        return f'Windows, in WSL Ubuntu 24.04: wsl -u root -e sh -c "{_APT_INSTALL}"'
    if sys.platform == "darwin":
        return "macOS: brew install zeek"
    return f'Ubuntu 24.04: sudo sh -c "{_APT_INSTALL}"'


def require_zeek() -> None:
    """Fail fast when neither a local Zeek nor Docker is available."""
    if not find_zeek() and shutil.which("docker") is None:
        raise ToolNotFound("'zeek' not found: install Zeek (zeek on PATH, /opt/zeek/bin/zeek or PCAPFORGE_ZEEK; "
                           f"on Windows in WSL) or Docker for the zeek/zeek image. {install_hint()}")


def _command(pcap: Path, out_dir: Path) -> list[str]:
    """Zeek command line, run with ``out_dir`` as working directory (Zeek writes its logs there)."""
    require_zeek()
    local = find_zeek()
    if local:
        # Relative to the working directory, so a Zeek in WSL (which maps the Windows working directory to
        # /mnt/<drive>/...) reads the same file; absolute only when Windows puts them on different drives.
        try:
            target = Path(os.path.relpath(pcap.resolve(), out_dir.resolve())).as_posix()
        except ValueError:
            target = str(pcap.resolve())
        return [*local, "-D", "-r", target, SITE_SCRIPT]
    docker = shutil.which("docker")
    run_dir = pcap.resolve().parent
    inner = out_dir.resolve().relative_to(run_dir).as_posix()
    # Linux/macOS: write the logs as the calling user, not as the container's root.
    user = ["--user", f"{os.getuid()}:{os.getgid()}"] if hasattr(os, "getuid") else []
    image = os.environ.get("PCAPFORGE_ZEEK_IMAGE", IMAGE)
    command = [docker, "run", "--rm", "--network", "none", *user, "-v", f"{run_dir}:/pcapforge",
               "-w", f"/pcapforge/{inner}", image,
               "zeek", "-D", "-r", f"/pcapforge/{pcap.name}", SITE_SCRIPT]
    return command


def write_zeek_logs(pcap: Path, answers: dict, out_dir: Path) -> dict[str, Path]:
    """Run Zeek over ``pcap`` into ``out_dir`` (previous logs are replaced); log name -> path."""
    out_dir.mkdir(parents=True, exist_ok=True)
    for old in out_dir.glob("*.log"):
        old.unlink()
    subnets = [s["cidr"] for s in answers.get("topology", {}).get("subnets", [])]
    script = out_dir / SITE_SCRIPT
    script.write_text(site_script(subnets), encoding="utf-8")
    command = _command(pcap, out_dir)
    try:
        proc = subprocess.run(command, cwd=out_dir, capture_output=True, text=True, timeout=TIMEOUT_S, check=False)
    finally:
        script.unlink(missing_ok=True)
    if proc.returncode != 0:
        message = (proc.stderr or proc.stdout).strip().splitlines()
        raise ZeekError(f"zeek failed on {pcap.name}: {message[-1] if message else proc.returncode}")
    # packet_filter.log only records the BPF filter with the wall-clock time Zeek started: it says
    # nothing about the capture and would make two runs over the same pcap differ.
    (out_dir / "packet_filter.log").unlink(missing_ok=True)
    logs = {path.stem: path for path in sorted(out_dir.glob("*.log"))}
    _number_link_ids(logs.values())
    return logs


# ICSNPP's ENIP and OPC UA analyzers tie records of different logs together with ids drawn from
# std::random_device, which -D does not seed: the same capture gives other ids every run.
_LINK_ID = re.compile(rb'"((?:packet_correlation_id|[a-z_]*link_id))":"([0-9a-f]+)"')


def _number_link_ids(paths) -> None:
    """Replace the random link ids by their order of first appearance (same width, hex), so the links
    between logs stay and two runs over one capture give identical logs."""
    numbers: dict[bytes, bytes] = {}

    def number(match: re.Match) -> bytes:
        raw = match.group(2)
        new = numbers.get(raw)
        if new is None:
            new = numbers[raw] = f"{len(numbers) + 1:0{len(raw)}x}".encode()
        return b'"' + match.group(1) + b'":"' + new + b'"'

    for path in paths:
        data = path.read_bytes()
        if b"link_id" in data or b"packet_correlation_id" in data:
            path.write_bytes(_LINK_ID.sub(number, data))


# -- hunting queries over the logs (question `hunt.zeek`) ---------------------------------------
# A query names a log, `where` (field -> value, or a list: any of them; all fields must match),
# and either `show` (fields printed per matching record) or `count_by` (matches counted per
# combination of these fields). The hunting guide renders it as a jq command over the JSON log;
# `hunt_rows` evaluates the same query in Python.

def _field(name: str) -> str:
    return "." + json.dumps(name) if not name.isidentifier() else "." + name


def _select(where: dict) -> str:
    terms = []
    for name, value in where.items():
        values = value if isinstance(value, list) else [value]
        alternatives = [f"{_field(name)} == {json.dumps(v)}" for v in values]
        terms.append(alternatives[0] if len(alternatives) == 1 else "(" + " or ".join(alternatives) + ")")
    return " and ".join(terms)


def hunt_command(hunt: dict) -> str:
    """The jq command line that runs ``hunt`` over ``zeek/<log>.log``."""
    select = _select(hunt.get("where", {}))
    path = f"zeek/{hunt['log']}.log"
    if "count_by" in hunt:
        fields = hunt["count_by"]
        keys = ", ".join(_field(f) for f in fields)
        record = ", ".join(f"{json.dumps(f)}: .[0]{_field(f)}" for f in fields)
        program = (f"map(select({select})) | " if select else "") + \
            f"group_by([{keys}]) | map({{{record}, count: length}})[]"
        return f"jq -s -c '{program}' {path}"
    shown = ", ".join(_field(f) for f in hunt["show"])
    program = (f"select({select}) | " if select else "") + f"[{shown}]"
    return f"jq -c '{program}' {path}"


def _same(record_value, value) -> bool:
    # jq equality: true is not 1, 1 is 1.0
    if isinstance(record_value, bool) or isinstance(value, bool):
        return isinstance(record_value, bool) and isinstance(value, bool) and record_value == value
    return record_value == value


def hunt_rows(hunt: dict, records: list[dict]) -> list[list | dict]:
    """What ``hunt_command`` prints, one row per line (a list for ``show``, a dict for ``count_by``)."""
    matches = [r for r in records if all(
        any(_same(r.get(name), v) for v in (value if isinstance(value, list) else [value]))
        for name, value in hunt.get("where", {}).items())]
    if "count_by" not in hunt:
        return [[r.get(f) for f in hunt["show"]] for r in matches]
    groups: dict[str, list[dict]] = {}
    for r in matches:
        groups.setdefault(json.dumps([r.get(f) for f in hunt["count_by"]], sort_keys=True), []).append(r)
    return [{**{f: rows[0].get(f) for f in hunt["count_by"]}, "count": len(rows)}
            for _, rows in sorted(groups.items())]
