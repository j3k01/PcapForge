"""Traffic overview of a run: per-protocol activity over the capture time and the top
conversations.

Reading a capture (up to a few GB) is too slow for a page load, so the run action ``traffic``
streams it once (classic pcap or pcapng, standard library only) into packet counts per protocol
and time bucket and caches them as ``<run>/traffic.json``; the run page draws an inline SVG strip
chart from that file. The conversations table comes from ``siem/flows.jsonl`` when the run has
been exported.
"""

from __future__ import annotations

import datetime as dt
import heapq
import json
import math
import mmap
import struct
import time
from pathlib import Path
from typing import Callable, Iterator
from urllib.parse import quote

from pcapforge import ports
from pcapforge.ui import views

CACHE = "traffic.json"
VERSION = 1
BUCKETS = 144
TOP_FLOWS = 15

CATEGORIES = ("modbus", "s7comm", "opcua", "iec104", "dnp3", "bacnet", "enip/cip", "dns", "ntp", "dhcp", "arp",
              "llmnr/mdns/nbns/ssdp", "icmp/icmpv6", "other")
(MODBUS, S7, OPCUA, IEC104, DNP3, BACNET, ENIP, DNS, NTP, DHCP, ARP, NAMES, ICMP, OTHER) = range(len(CATEGORIES))

_W = ports.WELL_KNOWN
# Output ports (the capture carries the well-known ports); TCP and UDP share the table.
PORT_CATEGORY = {_W[ports.MODBUS]: MODBUS, _W[ports.S7]: S7, _W[ports.OPCUA]: OPCUA, _W[ports.IEC104]: IEC104,
                 _W[ports.DNP3]: DNP3, _W[ports.BACNET]: BACNET, _W[ports.ENIP]: ENIP, _W[ports.ENIP_IO]: ENIP,
                 _W[ports.DNS]: DNS, _W[ports.NTP]: NTP,
                 _W[ports.DHCP_SERVER]: DHCP, _W[ports.DHCP_CLIENT]: DHCP,
                 _W[ports.DHCPV6_SERVER]: DHCP, _W[ports.DHCPV6_CLIENT]: DHCP,
                 _W[ports.LLMNR]: NAMES, _W[ports.MDNS]: NAMES, _W[ports.NBNS]: NAMES, _W[ports.NBDGM]: NAMES,
                 _W[ports.SSDP]: NAMES}

LINKTYPE_ETHERNET = 1
_VLAN = (0x8100, 0x88A8, 0x9100)
_IPV6_EXT = (0, 43, 60)  # hop-by-hop (MLD), routing, destination options: 8-octet units


# -- reading -------------------------------------------------------------------------------

def classify(buf, off: int, caplen: int) -> int:
    """Category of the Ethernet frame ``buf[off:off + caplen]``: EtherType (behind any 802.1Q /
    802.1ad tags), IPv4 / IPv6 (extension headers skipped), then the lower known TCP/UDP port."""
    end = off + caplen
    p = off + 14
    if p > end:
        return OTHER
    ethertype = (buf[p - 2] << 8) | buf[p - 1]
    while ethertype in _VLAN:
        p += 4
        if p > end:
            return OTHER
        ethertype = (buf[p - 2] << 8) | buf[p - 1]
    if ethertype == 0x0800:
        if p + 20 > end:
            return OTHER
        proto = buf[p + 9]
        if (buf[p + 6] & 0x1F) or buf[p + 7]:  # later fragment: no transport header
            return ICMP if proto == 1 else OTHER
        p += (buf[p] & 0x0F) * 4
    elif ethertype == 0x86DD:
        if p + 40 > end:
            return OTHER
        proto = buf[p + 6]
        p += 40
        while proto in _IPV6_EXT or proto == 44:
            if p + 8 > end:
                return OTHER
            if proto == 44:
                if ((buf[p + 2] << 8) | buf[p + 3]) & 0xFFF8:  # later fragment
                    return OTHER
                proto = buf[p]
                p += 8
            else:
                proto = buf[p]
                p += (buf[p + 1] + 1) * 8
    elif ethertype == 0x0806:
        return ARP
    else:
        return OTHER
    if proto == 6 or proto == 17:
        if p + 4 > end:
            return OTHER
        sport = (buf[p] << 8) | buf[p + 1]
        dport = (buf[p + 2] << 8) | buf[p + 3]
        lo, hi = (sport, dport) if sport < dport else (dport, sport)
        category = PORT_CATEGORY.get(lo)
        if category is None:
            category = PORT_CATEGORY.get(hi, OTHER)
        return category
    if proto == 1 or proto == 58:
        return ICMP
    return OTHER


def frames(buf) -> Iterator[tuple[float, int, int, int]]:
    """(timestamp in seconds, offset, captured length, link type) of every packet in a classic
    pcap or pcapng image ``buf`` (bytes or mmap); a truncated last record ends the walk."""
    size = len(buf)
    if size < 24:
        raise ValueError("not a pcap / pcapng file (too short)")
    magic = struct.unpack_from("<I", buf, 0)[0]
    if magic == 0x0A0D0D0A:
        yield from _pcapng(buf, size)
        return
    formats = {0xA1B2C3D4: ("<", 1e-6), 0xD4C3B2A1: (">", 1e-6), 0xA1B23C4D: ("<", 1e-9), 0x4D3CB2A1: (">", 1e-9)}
    if magic not in formats:
        raise ValueError(f"not a pcap / pcapng file (magic {magic:#010x})")
    order, resolution = formats[magic]
    linktype = struct.unpack_from(order + "I", buf, 20)[0] & 0xFFFF
    record = struct.Struct(order + "III")
    unpack = record.unpack_from
    off = 24
    while off + 16 <= size:
        sec, frac, caplen = unpack(buf, off)
        off += 16
        if off + caplen > size:
            return
        yield sec + frac * resolution, off, caplen, linktype
        off += caplen


def _pcapng(buf, size: int) -> Iterator[tuple[float, int, int, int]]:
    order = "<"
    interfaces: list[tuple[int, float, int]] = []   # (link type, resolution, offset in seconds)
    last = 0.0
    off = 0
    while off + 12 <= size:
        block_type, length = struct.unpack_from(order + "II", buf, off)
        if block_type == 0x0A0D0D0A:  # section header: byte order, fresh interface list
            order = "<" if struct.unpack_from("<I", buf, off + 8)[0] == 0x1A2B3C4D else ">"
            length = struct.unpack_from(order + "I", buf, off + 4)[0]
            interfaces = []
        if length < 12 or off + length > size:
            return
        if block_type == 6 or block_type == 2:  # enhanced / obsolete packet block
            if block_type == 6:
                iface, hi, lo, caplen = struct.unpack_from(order + "IIII", buf, off + 8)
            else:
                iface, _drops, hi, lo, caplen = struct.unpack_from(order + "HHIII", buf, off + 8)
            if iface < len(interfaces):
                linktype, resolution, base = interfaces[iface]
                last = ((hi << 32) | lo) * resolution + base
                yield last, off + 28, min(caplen, length - 32), linktype
        elif block_type == 3 and interfaces:    # simple packet block: no timestamp
            original = struct.unpack_from(order + "I", buf, off + 8)[0]
            yield last, off + 12, min(original, length - 16), interfaces[0][0]
        elif block_type == 1:                    # interface description
            interfaces.append(_interface(buf, off, length, order))
        off += length


def _interface(buf, off: int, length: int, order: str) -> tuple[int, float, int]:
    linktype = struct.unpack_from(order + "H", buf, off + 8)[0]
    resolution, base = 1e-6, 0
    p, end = off + 16, off + length - 4
    while p + 4 <= end:
        code, size = struct.unpack_from(order + "HH", buf, p)
        if code == 0:
            break
        if code == 9 and size >= 1:      # if_tsresol
            value = buf[p + 4]
            resolution = 2.0 ** -(value & 0x7F) if value & 0x80 else 10.0 ** -value
        elif code == 14 and size >= 8:   # if_tsoffset
            base = struct.unpack_from(order + "q", buf, p + 4)[0]
        p += 4 + size + (-size % 4)
    return linktype, resolution, base


def scan(path: Path, start: float, duration: float, buckets: int = BUCKETS,
         progress: Callable[[float], None] | None = None) -> dict:
    """Packets per category and time bucket. Bucket ``i`` covers
    ``[start + i * width, start + (i + 1) * width)`` with ``width = duration / buckets``; packets
    outside the window (reordered by impairments) count in the first / last bucket."""
    n = buckets
    inv = n / duration if duration > 0 else 0.0
    counts = [0] * (len(CATEGORIES) * n)
    packets = 0
    with open(path, "rb") as fh:
        size = fh.seek(0, 2)
        if size == 0:
            raise ValueError(f"{path.name}: empty file")
        with mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as buf:
            for ts, off, caplen, linktype in frames(buf):
                i = int((ts - start) * inv)
                if i < 0:
                    i = 0
                elif i >= n:
                    i = n - 1
                category = classify(buf, off, caplen) if linktype == LINKTYPE_ETHERNET else OTHER
                counts[category * n + i] += 1
                packets += 1
                if progress is not None and not packets & 0xFFFF:
                    progress(off / size)
    rows = {name: counts[k * n:(k + 1) * n] for k, name in enumerate(CATEGORIES) if any(counts[k * n:(k + 1) * n])}
    return {"version": VERSION, "start": start, "duration": duration, "buckets": n,
            "width": duration / n if n else 0.0, "packets": packets, "rows": rows}


def build(directory: Path, progress: Callable[[float], None] | None = None) -> str:
    """Run action ``traffic``: scan the run's capture into ``traffic.json``; a one-line outcome."""
    answers = json.loads((directory / "answers.json").read_text(encoding="utf-8"))
    capture = answers["capture"]
    began = time.perf_counter()
    start = dt.datetime.fromisoformat(capture["start"].replace("Z", "+00:00")).timestamp()
    data = scan(directory / capture["file"], start, float(capture["duration_s"]),
                progress=progress)
    seconds = time.perf_counter() - began
    data |= {"sha256": capture["sha256"], "seconds": round(seconds, 3)}
    tmp = directory / (CACHE + ".tmp")
    tmp.write_text(json.dumps(data, separators=(",", ":")), encoding="utf-8")
    tmp.replace(directory / CACHE)
    rate = data["packets"] / seconds / 1e6 if seconds > 0 else 0.0
    return f"{data['packets']} packets in {seconds:.2f} s ({rate:.2f} M packets/s), wrote {CACHE}"


def load(directory: Path, answers: dict) -> dict | None:
    """The cached scan, if it belongs to the run's current capture and has the expected shape."""
    try:
        data = json.loads((directory / CACHE).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or data.get("version") != VERSION \
            or data.get("sha256") != answers["capture"].get("sha256"):
        return None
    n, rows = data.get("buckets"), data.get("rows")
    numbers = all(isinstance(data.get(k), (int, float)) for k in ("start", "duration", "width", "seconds"))
    if not (numbers and isinstance(n, int) and n > 0 and isinstance(data.get("packets"), int)
            and isinstance(rows, dict) and set(rows) <= set(CATEGORIES)
            and all(isinstance(r, list) and len(r) == n and all(type(c) is int and c >= 0 for c in r)
                    for r in rows.values())):
        return None
    return data


# -- conversations -------------------------------------------------------------------------

_flows_cache: dict[Path, tuple[tuple[int, int], int, list[dict]]] = {}


def top_flows(path: Path, limit: int = TOP_FLOWS) -> tuple[int, list[dict]]:
    """(number of flows, the ``limit`` largest by packets) of a ``flows.jsonl``; cached per file
    version because a scan-heavy run has many thousand flows."""
    stat = path.stat()
    key = (stat.st_mtime_ns, stat.st_size)
    cached = _flows_cache.get(path)
    if cached and cached[0] == key:
        return cached[1], cached[2]
    total, records = 0, []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            try:
                record = json.loads(line)
                packets = int(record.get("packets") or 0)
            except (ValueError, TypeError, AttributeError):
                continue
            total += 1
            records.append((packets, total, record))
            if len(records) > 4 * limit:
                records = heapq.nlargest(limit, records)
    top = [r for _, _, r in heapq.nlargest(limit, records)]
    _flows_cache[path] = (key, total, top)
    return total, top


# -- rendering -----------------------------------------------------------------------------

W, LABEL_W, COUNT_W, ROW_H, TOP, AXIS = 1120, 160, 78, 15, 12, 22
LEVELS = 5
NICE_STEPS = (1, 2, 5, 10, 15, 30, 60, 120, 300, 600, 900, 1800, 3600, 7200, 10800, 21600, 43200, 86400)


def section(name: str, directory: Path, answers: dict) -> str:
    """The run page's traffic block: strip chart (or the scan button) and top conversations."""
    body = ["<h2>traffic</h2>"]
    data = load(directory, answers)
    if data is None:
        stale = (directory / CACHE).is_file()
        body.append('<div class="traffic-note">' + _scan_button(name, "scan") + '<span class="dim">'
                    + (f"{CACHE} is outdated; " if stale else "")
                    + f"reads the capture once (about 1 s per million packets) into {CACHE}</span></div>")
    else:
        body.append(chart_svg(data, answers.get("timeline", [])))
        width = float(data.get("width") or 0)
        body.append(f'<div class="traffic-note"><span class="dim small">shade: packets per '
                    f'{views.e(_short(width))} bucket, log scale &middot; markers: '
                    '<span class="alert">|</span> incident, | other answer-key events (hover for details) '
                    f'&middot; {data["packets"]:,} packets read in {data["seconds"]:.2f} s'
                    "</span>" + _scan_button(name, "rescan") + "</div>")
    flows = directory / "siem" / "flows.jsonl"
    if flows.is_file():
        total, top = top_flows(flows)
        body.append(f"<h2>top conversations ({len(top)} of {total:,} flows)</h2>" + _flows_table(top))
    return "".join(body)


def _scan_button(name: str, label: str) -> str:
    return (f'<form method="post" action="/runs/{quote(name)}/traffic">'
            f'<button type="submit">{views.e(label)}</button></form>')


def _short(seconds: float) -> str:
    """Compact relative time: 45s, 2m, 1m30s, 1h, 1h05m; fractions below ten seconds."""
    if seconds < 10 and seconds != int(seconds):
        return f"{seconds:.1f}s"
    s = int(round(seconds))
    h, rest = divmod(s, 3600)
    m, s = divmod(rest, 60)
    if h:
        return f"{h}h" + (f"{m:02d}m" if m else "")
    if m:
        return f"{m}m" + (f"{s:02d}s" if s else "")
    return f"{s}s"


def _level(count: int, peak: int) -> int:
    if peak <= 1:
        return LEVELS
    return min(LEVELS, 1 + int((LEVELS - 1) * math.log(count) / math.log(peak) + 0.5))


def chart_svg(data: dict, timeline: list[dict]) -> str:
    """One lane per protocol, one cell per time bucket shaded by packet count (log scale against
    the busiest bucket of the chart), packets per protocol on the right, ticks relative to the
    capture start and the answer-key timeline as vertical markers."""
    n = int(data["buckets"])
    duration = float(data["duration"]) or 1.0
    rows = [(name, data["rows"][name]) for name in CATEGORIES if name in data["rows"]]
    plot_w = W - LABEL_W - COUNT_W
    cell = plot_w / n
    lanes_h = len(rows) * ROW_H
    height = TOP + lanes_h + AXIS
    peak = max((max(counts) for _, counts in rows), default=0)
    width = duration / n
    parts = []
    for r, (name, counts) in enumerate(rows):
        y = TOP + r * ROW_H
        cells = "".join(
            f'<rect class="l{_level(c, peak)}" x="{LABEL_W + i * cell:.1f}" y="{y + 1}" width="{cell + 0.4:.1f}" '
            f'height="{ROW_H - 3}"><title>{name} +{_short(i * width)}: {c:,} packets</title></rect>'
            for i, c in enumerate(counts) if c > 0)
        parts.append(f'<g class="lane"><rect class="bg" x="{LABEL_W}" y="{y + 1}" width="{plot_w:.1f}" '
                     f'height="{ROW_H - 3}"/><text x="{LABEL_W - 8}" y="{y + ROW_H - 4}" text-anchor="end">'
                     f'{views.e(name)}</text>{cells}<text class="count" x="{W}" y="{y + ROW_H - 4}" '
                     f'text-anchor="end">{sum(counts):,}</text></g>')
    step = next((s for s in NICE_STEPS if duration / s <= 10), abs(duration) / 10)
    ticks, t = [], 0
    axis_y = TOP + lanes_h
    while t <= duration + 1e-9:
        x = LABEL_W + t / duration * plot_w
        anchor = "start" if t == 0 else "middle"
        ticks.append(f'<line x1="{x:.1f}" y1="{axis_y}" x2="{x:.1f}" y2="{axis_y + 4}"/>'
                     f'<text x="{x:.1f}" y="{axis_y + 16}" text-anchor="{anchor}">+{_short(t)}</text>')
        t += step
    parts.append(f'<g class="axis"><line x1="{LABEL_W}" y1="{axis_y}" x2="{LABEL_W + plot_w:.1f}" y2="{axis_y}"/>'
                 + "".join(ticks) + "</g>")
    start = float(data["start"])
    for event in sorted(timeline, key=lambda ev: bool(ev.get("incident"))):  # incidents drawn on top
        try:
            offset = float(event["epoch"]) - start
        except (KeyError, TypeError, ValueError):
            continue
        x = LABEL_W + min(max(offset, 0.0), duration) / duration * plot_w
        kind = "incident" if event.get("incident") else "event"
        tip = views.e(f"+{_short(offset)} {kind}: {event.get('title', '')} ({event.get('actor', '')}"
                      + (f", frame {event['frame']}" if event.get("frame") is not None else "") + ")")
        parts.append(f'<g class="mark{" inc" if event.get("incident") else ""}"><title>{tip}</title>'
                     f'<line x1="{x:.1f}" y1="2" x2="{x:.1f}" y2="{axis_y}"/>'
                     f'<rect x="{x - 2.5:.1f}" y="2" width="5" height="7"/>'
                     f'<line class="hit" x1="{x:.1f}" y1="0" x2="{x:.1f}" y2="{axis_y}"/></g>')
    return (f'<svg class="traffic" viewBox="0 0 {W} {height}" role="img" '
            'aria-label="packets per protocol over the capture time" shape-rendering="crispEdges">'
            + "".join(parts) + "</svg>")


def _flows_table(top: list[dict]) -> str:
    rows = []
    for f in top:
        port = f.get("dest_port")
        transport = views.e(f.get("transport") or "") + (f"/{views.e(port)}" if port is not None else "")
        rows.append(
            f'<tr><td>{views.e(f.get("src", ""))} <span class="dim">&rarr;</span> {views.e(f.get("dest", ""))}</td>'
            f'<td>{transport}</td><td>{views.e(f.get("app") or "")}</td>'
            f'<td class="num">{_int(f.get("packets")):,}</td><td class="num">{views.e(views._size(_int(f.get("bytes"))))}</td>'
            f'<td class="num">{views.e(_seconds(f.get("duration")))}</td><td class="dim">{views.e(f.get("state") or "")}</td></tr>')
    return ('<table class="grid"><thead><tr><th>src &rarr; dest</th><th>transport/port</th><th>app</th>'
            '<th class="num">packets</th><th class="num">bytes</th><th class="num">duration</th><th>state</th>'
            "</tr></thead><tbody>" + "".join(rows) + "</tbody></table>")


def _int(value) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _seconds(value) -> str:
    try:
        seconds = float(value or 0)
    except (TypeError, ValueError):
        return ""
    return f"{seconds:.2f}s" if seconds < 10 else views._duration(seconds)
