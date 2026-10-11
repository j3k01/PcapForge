"""Zeek logs of a composed capture: run a local Zeek, or the official Docker image, over the pcap and
keep its JSON logs (``conn``, ``dns``, ``ntp``, ``dhcp``, ``modbus``, ``dnp3``, ``known_*``, ...) in
``<run>/zeek/`` next to the pcapforge JSONL export.

Zeek runs in deterministic mode (``-D``: connection uids and other random values are seeded with
zero), so the same capture always gives the same logs. ``Site::local_nets`` is the scenario's
subnets, which fills ``local_orig`` / ``local_resp`` in conn.log and the ``known_*`` logs. Besides the
base scripts, the Modbus policy scripts (master/slave pairs, register change tracking) and known
hosts / services are loaded.
"""

from __future__ import annotations

import functools
import os
import shutil
import subprocess
import sys
from pathlib import Path

from pcapforge.tools import ToolNotFound

IMAGE = "zeek/zeek:lts"   # official image (hub.docker.com/r/zeek/zeek); PCAPFORGE_ZEEK_IMAGE overrides it
SCRIPTS = (
    "policy/protocols/conn/known-hosts",
    "policy/protocols/conn/known-services",
    "policy/protocols/modbus/known-masters-slaves",
    "policy/protocols/modbus/track-memmap",
)
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
    return "\n".join(lines) + "\n"


# Zeek LTS from the security:zeek OBS packages into /opt/zeek, as in CI (Ubuntu 24.04, also the default WSL distribution).
_APT_INSTALL = ("echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_24.04/ /' "
                "> /etc/apt/sources.list.d/security:zeek.list && curl -fsSL "
                "https://download.opensuse.org/repositories/security:zeek/xUbuntu_24.04/Release.key "
                "| gpg --dearmor > /etc/apt/trusted.gpg.d/security_zeek.gpg && apt-get update "
                "&& apt-get install -y zeek-lts-core")


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
    return {path.stem: path for path in sorted(out_dir.glob("*.log"))}
