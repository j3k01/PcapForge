"""Locate external Wireshark / tcpdump binaries and check the tshark version."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from functools import cache
from pathlib import Path

# Answer-key filters read Write Single Register values (modbus.regval_uint16), which tshark
# decodes only from Wireshark 4.4 on; older versions show them as raw modbus.data bytes.
MIN_TSHARK = (4, 4)


class ToolNotFound(RuntimeError):
    pass


def _candidates() -> list[Path]:
    dirs: list[Path] = []
    if env := os.environ.get("PCAPFORGE_WIRESHARK_DIR"):
        dirs.append(Path(env))
    if sys.platform == "win32":
        for base in (os.environ.get("ProgramFiles"), os.environ.get("ProgramFiles(x86)")):
            if base:
                dirs.append(Path(base) / "Wireshark")
    elif sys.platform == "darwin":
        dirs.append(Path("/Applications/Wireshark.app/Contents/MacOS"))
    return dirs


@cache
def find_tool(name: str) -> str | None:
    if found := shutil.which(name):
        return found
    exe = f"{name}.exe" if sys.platform == "win32" else name
    for directory in _candidates():
        path = directory / exe
        if path.is_file():
            return str(path)
    return None


def require_tool(name: str) -> str:
    path = find_tool(name)
    if path is None:
        raise ToolNotFound(
            f"'{name}' not found. Install Wireshark (tshark/dumpcap) or set "
            "PCAPFORGE_WIRESHARK_DIR to its install directory."
        )
    return path


@cache
def tshark_version() -> tuple[int, int, int]:
    out = subprocess.run([require_tool("tshark"), "--version"], capture_output=True, text=True,
                         check=False).stdout
    match = re.search(r"(\d+)\.(\d+)\.(\d+)", out)
    if match is None:
        raise ToolNotFound(f"cannot read the tshark version from {out[:80]!r}")
    major, minor, patch = (int(part) for part in match.groups())
    return major, minor, patch


def require_answer_key_tshark() -> None:
    """Fail fast when tshark is too old to evaluate the answer-key filters."""
    version = tshark_version()
    if version < MIN_TSHARK:
        raise ToolNotFound(f"Wireshark >= {'.'.join(map(str, MIN_TSHARK))} required for answer-key "
                           f"verification; found {'.'.join(map(str, version))}")
