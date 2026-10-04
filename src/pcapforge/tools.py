"""Locate external Wireshark / tcpdump binaries."""

from __future__ import annotations

import os
import shutil
import sys
from functools import cache
from pathlib import Path


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
