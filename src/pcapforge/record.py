"""Live recording: run the planned actions against local services and capture loopback.

Every host owns an address in 127.77.0.0/16. Before each action the issuing host sends a
UDP marker (action id) to the marker sink; the composer uses markers to map packets back
to actions and is the only consumer of them.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from pcapforge import ports
from pcapforge.plan import Plan
from pcapforge.tools import find_tool, require_tool
from pcapforge.topology import LOOPBACK_NET, MARKER_SINK, SINKS

MARKER_MAGIC = b"PFMK"
CAPTURE_FILTER = f"net {LOOPBACK_NET}.0.0/16"
ROOTLESS = "unshare -rn pcapforge ..."
QUICKACK_ROUTE = ["local", f"{LOOPBACK_NET}.0.0/16", "dev", "lo", "table", "local", "quickack", "1"]


class RecordingError(RuntimeError):
    pass


@dataclass
class Clock:
    t: float = 0.0


@dataclass
class Runtime:
    plan: Plan
    clock: Clock = field(default_factory=Clock)
    sims: dict = field(default_factory=dict)
    clients: dict = field(default_factory=dict)
    servers: list = field(default_factory=list)
    transports: list = field(default_factory=list)

    def loopback(self, host_id: str) -> str:
        return self.plan.topology.by_id[host_id].loopback


def marker_payload(action_id: int) -> bytes:
    return MARKER_MAGIC + struct.pack("!I", action_id)


def parse_marker(payload: bytes) -> int | None:
    if len(payload) == 8 and payload[:4] == MARKER_MAGIC:
        return struct.unpack("!I", payload[4:])[0]
    return None


# --- capture backends ---------------------------------------------------------------

def loopback_interface() -> str:
    if sys.platform == "win32":
        return r"\Device\NPF_Loopback"
    if sys.platform == "darwin":
        return "lo0"
    return "lo"


class Capture:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.proc: subprocess.Popen | None = None
        self.log: list[str] = []

    def start(self) -> None:
        iface = loopback_interface()
        dumpcap = find_tool("dumpcap")
        if dumpcap:
            cmd = [dumpcap, "-i", iface, "-f", CAPTURE_FILTER, "-w", str(self.path), "-P", "-B", "128"]
            ready = "Capturing on"
        else:
            cmd = [require_tool("tcpdump"), "-i", iface, "-U", "-w", str(self.path), CAPTURE_FILTER]
            if sys.platform != "win32" and os.geteuid() == 0:
                # Run as root, tcpdump drops to its own user before opening the output file, which
                # then cannot write the cache (or, in a user namespace, cannot switch user at all).
                cmd[1:1] = ["-Z", "root"]
            ready = "listening on"
        flags = subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0
        self.proc = subprocess.Popen(cmd, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL, text=True,
                                     creationflags=flags)
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            line = self.proc.stderr.readline()
            if not line:
                break
            self.log.append(line.rstrip())
            if ready in line:
                threading.Thread(target=self._drain, daemon=True).start()
                time.sleep(0.5)
                return
        self.proc.kill()
        raise RecordingError("capture did not start:\n" + "\n".join(self.log) + _capture_hint())

    def _drain(self) -> None:
        for line in self.proc.stderr:
            self.log.append(line.rstrip())

    def stop(self) -> None:
        if self.proc is None:
            return
        if sys.platform == "win32":
            self.proc.send_signal(signal.CTRL_BREAK_EVENT)
        else:
            self.proc.send_signal(signal.SIGINT)
        try:
            self.proc.wait(15)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            raise RecordingError("capture process did not stop cleanly")


def _capture_hint() -> str:
    if sys.platform == "win32":
        return "\nHint: install Npcap with 'Support loopback traffic capture'."
    if sys.platform == "darwin":
        return f"\nHint: add loopback aliases, e.g. 'sudo ifconfig lo0 alias {LOOPBACK_NET}.0.10'."
    return (f"\nHint: run pcapforge in its own user and network namespace: {ROOTLESS}\n"
            "or grant capture rights: 'sudo setcap cap_net_raw,cap_net_admin=eip $(which dumpcap)'.")


def _prepare_linux_loopback() -> None:
    """Linux delays loopback ACKs and piggybacks them on the next segment, so a recording would
    hold almost no pure ACKs. The composer expects every segment acknowledged at once (as on
    Windows loopback) and models each device's delayed ACK itself; a local route with
    ``quickack 1`` for the recording network makes Linux acknowledge immediately. In a fresh
    network namespace (rootless recording) ``lo`` also starts down."""
    ip = shutil.which("ip", path=os.pathsep.join([os.environ.get("PATH", ""), "/usr/sbin", "/sbin"]))
    if ip is None:
        raise RecordingError("'ip' (iproute2) not found; recording uses it to prepare the loopback interface")

    def run(*args: str) -> subprocess.CompletedProcess:
        return subprocess.run([ip, *args], capture_output=True, text=True, check=False)

    steps = []
    flags = run("-o", "link", "show", "lo").stdout.partition("<")[2].partition(">")[0].split(",")
    if "UP" not in flags:
        steps.append(["link", "set", "lo", "up"])
    if "quickack 1" not in run("route", "show", "table", "local", QUICKACK_ROUTE[1]).stdout:
        steps.append(["route", "add", *QUICKACK_ROUTE])
    for step in steps:
        done = run(*step)
        if done.returncode != 0:
            raise RecordingError(
                f"'ip {' '.join(step)}' failed: {done.stderr.strip()}\n"
                f"Hint: run pcapforge in its own user and network namespace: {ROOTLESS}\n"
                f"or add the route once per boot: 'sudo ip route add {' '.join(QUICKACK_ROUTE)}'.")


# --- recording ---------------------------------------------------------------------

def _start_services(rt: Runtime) -> tuple[asyncio.AbstractEventLoop, threading.Thread]:
    loop = asyncio.new_event_loop()
    thread = threading.Thread(target=loop.run_forever, name="pcapforge-services", daemon=True)
    thread.start()

    async def boot() -> None:
        for name, port in sorted({pair for actor in rt.plan.actors for pair in actor.sinks}):
            transport, _ = await loop.create_datagram_endpoint(
                asyncio.DatagramProtocol, local_addr=(SINKS[name].loopback, port))
            rt.transports.append(transport)
        for actor in rt.plan.actors:
            if actor.is_server:
                await actor.serve(rt)

    asyncio.run_coroutine_threadsafe(boot(), loop).result(15)
    time.sleep(0.8)  # let listeners bind
    return loop, thread


def _stop_services(rt: Runtime, loop, thread) -> None:
    async def shutdown() -> None:
        for transport in rt.transports:
            transport.close()
        for server in rt.servers:
            await server.shutdown()

    try:
        asyncio.run_coroutine_threadsafe(shutdown(), loop).result(10)
        asyncio.run_coroutine_threadsafe(asyncio.sleep(0.2), loop).result(5)
    finally:
        loop.call_soon_threadsafe(loop.stop)
        thread.join(5)
        loop.close()


def record(plan: Plan, path: Path, progress: Callable[[int, int], None] | None = None) -> dict:
    logging.getLogger("pymodbus").setLevel(logging.CRITICAL)
    path.parent.mkdir(parents=True, exist_ok=True)
    if sys.platform == "linux":
        _prepare_linux_loopback()
    rt = Runtime(plan)
    actors = {a.id: a for a in plan.actors}
    capture = Capture(path)
    capture.start()
    sink = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    markers: dict[str, socket.socket] = {}
    loop = thread = None
    started = time.perf_counter()
    try:
        sink.bind((MARKER_SINK, ports.MARKER))
        loop, thread = _start_services(rt)
        total = len(plan.actions)
        for index, action in enumerate(plan.actions):
            rt.clock.t = action.t
            sock = markers.get(action.host)
            if sock is None:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.bind((rt.loopback(action.host), 0))
                markers[action.host] = sock
            sock.sendto(marker_payload(action.id), (MARKER_SINK, ports.MARKER))
            try:
                actors[action.actor].execute(action, rt)
            except Exception as exc:
                raise RecordingError(f"action {action.id} ({action.op} by {action.host}) failed: {exc}") from exc
            if progress and (index % 500 == 0 or index == total - 1):
                progress(index + 1, total)
        rt.clock.t = plan.duration + 2.0
        for actor in plan.actors:
            actor.close(rt)
        time.sleep(0.3)
    finally:
        if loop is not None:
            _stop_services(rt, loop, thread)
        for sock in markers.values():
            sock.close()
        sink.close()
        time.sleep(1.0)  # let the capture flush
        capture.stop()
    meta = {
        "digest": plan.digest(),
        "actions": len(plan.actions),
        "wall_seconds": round(time.perf_counter() - started, 3),
        "platform": sys.platform,
        "capture_log": capture.log[-3:],
    }
    path.with_suffix(".json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return meta


def cache_dir() -> Path:
    if env := os.environ.get("PCAPFORGE_CACHE"):
        return Path(env)
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    else:
        base = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))
    return base / "pcapforge"


def recording_for(plan: Plan, use_cache: bool = True,
                  progress: Callable[[int, int], None] | None = None) -> tuple[Path, bool]:
    """Path to a recording of ``plan``; records it unless a cached copy exists."""
    path = cache_dir() / "recordings" / plan.scenario.id / f"{plan.digest()}.pcap"
    if use_cache and path.is_file() and path.with_suffix(".json").is_file():
        return path, True
    tmp = path.with_name(path.stem + ".partial.pcap")
    record(plan, tmp, progress)
    os.replace(tmp, path)
    os.replace(tmp.with_suffix(".json"), path.with_suffix(".json"))
    return path, False
