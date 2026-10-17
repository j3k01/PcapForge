"""Validate a composed capture with tshark: integrity, no loopback leaks, protocol decodes and
every answer-key question check."""

from __future__ import annotations

import subprocess
import tempfile
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

from pcapforge.answers import sha256_file
from pcapforge.tools import require_answer_key_tshark, require_tool

# Validate checksums so bad ones surface as expert errors / checksum.status == 0.
PREFS = ["-o", "ip.check_checksum:TRUE", "-o", "tcp.check_checksum:TRUE", "-o", "udp.check_checksum:TRUE"]
PI_SEVERITY_MASK = 0x00F00000
PI_ERROR = 0x00800000
CHECKSUM_FIELDS = ["ip.checksum.status", "tcp.checksum.status", "udp.checksum.status", "icmpv6.checksum.status"]
ADDRESS_FIELDS = ["ip.src", "ip.dst", "ipv6.src", "ipv6.dst", "arp.src.proto_ipv4", "arp.dst.proto_ipv4", "dns.a",
                  "dns.aaaa", "nbdgm.src.ip", "enip.sinaddr"]
INTEGRITY_FIELDS = ["frame.number", "frame.protocols", "_ws.malformed", "_ws.expert.severity",
                    *CHECKSUM_FIELDS, *ADDRESS_FIELDS]
EXAMPLES = 10
TRANSPORTS = {"tcp", "udp", "sctp", "ip", "ipv6"}


class TsharkError(RuntimeError):
    def __init__(self, message: str, stderr: str = "") -> None:
        super().__init__(message)
        self.stderr = stderr


@dataclass
class VerifyReport:
    ok: bool = True
    checks: list[dict] = field(default_factory=list)

    def add(self, name: str, ok: bool, detail: str) -> None:
        self.checks.append({"name": name, "ok": bool(ok), "detail": detail})
        self.ok = self.ok and bool(ok)

    @property
    def failed(self) -> list[dict]:
        return [c for c in self.checks if not c["ok"]]


def _tshark(pcap: Path, args: list[str]) -> Iterator[str]:
    """Output lines of a tshark run, as tshark prints them (one per frame for ``-T fields``)."""
    cmd = [require_tool("tshark"), "-n", "-r", str(pcap), *PREFS, *args]
    with tempfile.TemporaryFile() as stderr:
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=stderr, encoding="utf-8", errors="replace")
        except OSError as exc:
            raise TsharkError(f"cannot run tshark: {exc}") from exc
        assert proc.stdout is not None
        with proc.stdout:
            for line in proc.stdout:
                yield line.rstrip("\r\n")
        if proc.wait() != 0:
            stderr.seek(0)
            text = stderr.read().decode("utf-8", "replace")
            raise TsharkError(f"tshark failed on {pcap.name}: {text.strip() or f'exit code {proc.returncode}'}", text)


def _frames(numbers: list[int]) -> str:
    shown = ", ".join(str(n) for n in numbers[:EXAMPLES])
    return shown + (f", ... ({len(numbers)} total)" if len(numbers) > EXAMPLES else "")


def _expert_errors(pcap: Path) -> str:
    try:
        lines = list(_tshark(pcap, ["-q", "-z", "expert,error"]))
    except TsharkError as exc:
        return str(exc)
    rows = [line.strip() for line in lines if line.strip() and not line.startswith(("=", "Errors"))]
    return "; ".join(rows[1:6])  # skip the column header


def _loopback(address: str) -> bool:
    """IPv4 127.0.0.0/8, IPv6 ::1 or an IPv4-mapped / -compatible loopback address."""
    return address.startswith(("127.", "::ffff:127.", "::127.")) or address == "::1"


def _integrity(pcap: Path, report: VerifyReport, answers: dict | None) -> None:
    args = ["-T", "fields", "-E", "separator=\t", "-E", "occurrence=a", "-E", "aggregator=,"]
    for name in INTEGRITY_FIELDS:
        args += ["-e", name]
    total = 0
    malformed, bad_checksum, expert, leaks, undecoded = [], [], [], [], []
    protocols: Counter[str] = Counter()
    for row in _tshark(pcap, args):
        total += 1
        frame = dict(zip(INTEGRITY_FIELDS, row.split("\t")))
        number = int(frame["frame.number"])
        stack = frame.get("frame.protocols", "").split(":")
        protocols.update(set(stack))
        if frame.get("_ws.malformed"):
            malformed.append(number)
        # Opaque content a dissector hands on (an SMB READ's file data) is decoded; "data" straight on
        # top of the transport is a payload no dissector understood.
        if stack[-1] == "data" and (len(stack) < 2 or stack[-2] in TRANSPORTS):
            undecoded.append(number)
        if any(sev and (int(sev) & PI_SEVERITY_MASK) == PI_ERROR
               for sev in frame.get("_ws.expert.severity", "").split(",")):
            expert.append(number)
        if any("0" in frame.get(name, "").split(",") for name in CHECKSUM_FIELDS):
            bad_checksum.append(number)
        if any(_loopback(addr) for name in ADDRESS_FIELDS for addr in frame.get(name, "").split(",")):
            leaks.append(number)

    report.add("frames", total > 0, f"{total} frames read")
    if answers is not None:
        expected = answers.get("capture", {}).get("packets")
        report.add("packet_count", expected == total, f"{total} frames, answer key says {expected}")
    report.add("malformed", not malformed,
               f"malformed frames: {_frames(malformed)}" if malformed else "no malformed frames")
    report.add("checksums", not bad_checksum,
               f"bad IP/TCP/UDP/ICMPv6 checksum in frames: {_frames(bad_checksum)}" if bad_checksum
               else "all IP/TCP/UDP/ICMPv6 checksums valid")
    report.add("expert_errors", not expert,
               f"expert errors in frames {_frames(expert)}: {_expert_errors(pcap)}" if expert
               else "no expert errors")
    report.add("loopback_leak", not leaks,
               f"loopback addresses (127.0.0.0/8, ::1) in frames: {_frames(leaks)}" if leaks
               else "no loopback addresses")
    report.add("decoded", not undecoded,
               f"undissected payload (data) in frames: {_frames(undecoded)}" if undecoded
               else "every payload decoded by a protocol dissector")
    ignore = {"frame", "eth", "ethertype", "null", "data"}
    summary = ", ".join(f"{p} {n}" for p, n in protocols.most_common() if p not in ignore and p)
    report.add("protocols", True, summary or "no protocols")


def _count_one(pcap: Path, display_filter: str) -> int | str:
    """Frames matching one display filter, or an error message."""
    try:
        return sum(1 for _ in _tshark(pcap, ["-Y", display_filter, "-T", "fields", "-e", "frame.number"]))
    except TsharkError as exc:
        return exc.stderr.strip().replace("\n", " ") or str(exc)


def count_matches(pcap: Path, filters: list[str]) -> dict[str, int | str]:
    """Frame count per display filter (or an error message for an invalid filter).

    All filters are evaluated in one tshark pass as boolean field expressions
    (Wireshark >= 4.4); filters tshark rejects there are retried one by one with ``-Y``
    so older tshark versions still work and invalid filters get a precise error.
    """
    pending = list(dict.fromkeys(filters))
    results: dict[str, int | str] = {}
    while pending:
        args = ["-T", "fields", "-E", "separator=\t"]
        for display_filter in pending:
            args += ["-e", f"!!({display_filter})"]
        counts = [0] * len(pending)
        try:
            for row in _tshark(pcap, args):
                for index, value in enumerate(row.split("\t")[:len(pending)]):
                    if value:
                        counts[index] += 1
        except TsharkError as exc:
            invalid = {line.strip() for line in exc.stderr.splitlines() if line.startswith("\t")}
            rejected = [f for f in pending if f"!!({f})" in invalid]
            if not rejected:
                raise
            for display_filter in rejected:
                results[display_filter] = _count_one(pcap, display_filter)
            pending = [f for f in pending if f not in rejected]
            continue
        results.update(zip(pending, counts))
        break
    return results


def _expect_ok(count: int, expect: dict) -> bool:
    return (("count" not in expect or count == expect["count"])
            and ("min" not in expect or count >= expect["min"])
            and ("max" not in expect or count <= expect["max"]))


def _questions(pcap: Path, report: VerifyReport, answers: dict) -> None:
    checks = [(q["id"], index, len(q.get("checks", [])), check)
              for q in answers.get("questions", []) for index, check in enumerate(q.get("checks", []))]
    if not checks:
        return
    try:
        counts = count_matches(pcap, [c["filter"] for *_, c in checks])
    except TsharkError as exc:
        report.add("questions", False, str(exc))
        return
    for qid, index, total, check in checks:
        name = f"question:{qid}" + (f"[{index}]" if total > 1 else "")
        result = counts[check["filter"]]
        expect = ", ".join(f"{k} {v}" for k, v in check["expect"].items())
        if isinstance(result, str):
            report.add(name, False, f"invalid filter: {result} | {check['filter']}")
        else:
            report.add(name, _expect_ok(result, check["expect"]),
                       f"{result} frames match (expect {expect}) | {check['filter']}")


def verify_capture(pcap: Path, answers: dict | None = None) -> VerifyReport:
    pcap = Path(pcap)
    if answers is not None:
        require_answer_key_tshark()
    report = VerifyReport()
    if not pcap.is_file():
        report.add("file", False, f"{pcap} does not exist")
        return report
    if answers is not None:
        expected = answers.get("capture", {}).get("sha256")
        actual = sha256_file(pcap)
        report.add("sha256", expected == actual,
                   f"sha256 {actual}" if expected == actual else f"sha256 {actual} != answer key {expected}")
    try:
        _integrity(pcap, report, answers)
    except TsharkError as exc:
        report.add("tshark", False, str(exc))
        return report
    if answers is not None:
        _questions(pcap, report, answers)
    return report
