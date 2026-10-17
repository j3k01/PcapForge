"""Recordings for tests that must run outside a private network namespace (the SIEM harness talks to
Splunk / Elasticsearch on localhost). On Linux a process without the loopback quickack route cannot
record (record._prepare_linux_loopback); such a missing recording is made in its own user and network
namespace (`unshare -rn`) first, so the test's generate() finds it in the cache."""

import os
import shutil
import subprocess
import sys

import pytest

from pcapforge.plan import build_plan
from pcapforge.record import QUICKACK_ROUTE, cached_recording

TIMEOUT_S = 1800


def _can_record_here() -> bool:
    if sys.platform != "linux" or os.geteuid() == 0:
        return True
    ip = shutil.which("ip", path=os.pathsep.join([os.environ.get("PATH", ""), "/usr/sbin", "/sbin"]))
    if ip is None:
        return False
    out = subprocess.run([ip, "route", "show", "table", "local", QUICKACK_ROUTE[1]],
                         capture_output=True, text=True, check=False).stdout
    return "quickack 1" in out


def ensure_recorded(scenario, difficulty: str, seed: str, duration: float, out_dir) -> None:
    """Record ``scenario`` / ``difficulty`` / ``seed`` / ``duration`` in its own namespace unless it is
    cached or this process can record it itself; fail at once (with the command) when that does not work."""
    if cached_recording(build_plan(scenario, difficulty, seed, duration_override=duration)) or _can_record_here():
        return
    command = [sys.executable, "-m", "pcapforge", "generate", "-s", scenario.id, "-d", difficulty,
               "--seed", seed, "--duration", f"{duration:g}s", "--no-verify", "-q", "--out", str(out_dir)]
    unshare = shutil.which("unshare")
    hint = f"record it first: unshare -rn {' '.join(command)}"
    if unshare is None:
        pytest.fail(f"{scenario.id} {difficulty}: no cached recording, no capture rights here and no unshare; {hint}")
    env = {**os.environ, "PYTHONPATH": os.pathsep.join(p for p in sys.path if p)}
    try:
        proc = subprocess.run([unshare, "-rn", *command], capture_output=True, text=True, timeout=TIMEOUT_S,
                              env=env, check=False)
    except subprocess.TimeoutExpired:
        pytest.fail(f"{scenario.id} {difficulty}: recording in its own namespace took over {TIMEOUT_S} s; {hint}")
    if proc.returncode != 0:
        tail = "\n".join((proc.stderr or proc.stdout).strip().splitlines()[-5:])
        pytest.fail(f"{scenario.id} {difficulty}: recording in its own namespace failed:\n{tail}\n{hint}")
