"""SIEM export: decode a composed capture once with tshark and write JSON-lines logs.

Every file in ``<run>/siem/`` holds one JSON object per line with a ``ts`` field
(ISO-8601 UTC, microseconds, ``Z``) usable as Splunk ``_time`` / Elastic ``@timestamp``,
plus ``epoch`` (float seconds) and Splunk-CIM style ``src`` / ``dest`` / ``src_port`` /
``dest_port`` / ``transport`` / ``app`` fields. Records are sorted by time, then frame.

All protocol decoding is done by tshark in a single pass; this module only groups the
decoded fields into flows and request/response transactions and, for Modbus writes,
looks the written registers up in the process register map from the answer key.
"""

from __future__ import annotations

import datetime as dt
import json
import subprocess
import tempfile
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

from pcapforge.answers import iso_utc
from pcapforge.process import BIT_TABLES, FUNCTION_TABLE, ProcessProfile
from pcapforge.tools import require_tool
from pcapforge.verify import TsharkError

MODBUS_PORT = 502
SEP = "\t"
AGG = "\x1f"  # occurrence aggregator: never part of a decoded value

FIELDS = [
    "frame.number", "frame.time_epoch", "frame.protocols", "eth.src", "eth.dst",
    "ip.src", "ip.dst", "ip.proto", "ip.len", "ipv6.src", "ipv6.dst", "ipv6.plen",
    "tcp.stream", "tcp.srcport", "tcp.dstport", "tcp.flags", "tcp.analysis.retransmission",
    "udp.stream", "udp.srcport", "udp.dstport",
    "arp.opcode", "arp.src.hw_mac", "arp.src.proto_ipv4", "arp.dst.hw_mac", "arp.dst.proto_ipv4",
    "mbtcp.trans_id", "mbtcp.unit_id", "modbus.func_code", "modbus.exception_code",
    "modbus.reference_num", "modbus.word_cnt", "modbus.bit_cnt", "modbus.regval_uint16",
    "modbus.write_reference_num", "modbus.write_word_cnt",
    "modbus.bitval", "modbus.data", "modbus.object_str_value",
    "dns.id", "dns.flags.response", "dns.flags.rcode", "dns.qry.name", "dns.qry.type",
    "dns.cname", "dns.a", "dns.aaaa", "dns.ptr.domain_name", "dns.resp.ttl",
    "nbns.id", "nbns.flags.response", "nbns.flags.opcode", "nbns.flags.rcode", "nbns.name",
    "nbns.type", "nbns.addr",
    "ntp.flags.vn", "ntp.flags.mode", "ntp.stratum", "ntp.refid", "ntp.org", "ntp.rec", "ntp.xmt",
    "http.request.method", "http.request.uri", "http.response.code", "http.request.line",
    "http.response.line",
    "browser.command", "browser.server", "nbdgm.source_name", "nbdgm.destination_name",
    "dhcp.option.dhcp", "dhcp.id", "dhcp.flags.bc", "dhcp.hw.mac_addr", "dhcp.ip.client", "dhcp.ip.your",
    "dhcp.option.requested_ip_address", "dhcp.option.dhcp_server_id", "dhcp.option.hostname",
    "dhcp.fqdn.name", "dhcp.option.vendor_class_id", "dhcp.option.ip_address_lease_time",
    "dhcp.option.router", "dhcp.option.domain_name_server", "dhcp.option.domain_name",
]
F = {name: index for index, name in enumerate(FIELDS)}

# Highest-layer tshark protocol name -> ``app`` label.
APPS = {
    "modbus": "modbus", "mbtcp": "modbus", "dns": "dns", "llmnr": "llmnr", "mdns": "mdns",
    "nbns": "nbns", "ssdp": "ssdp", "browser": "browser", "nbdgm": "nbdgm", "ntp": "ntp",
    "dhcp": "dhcp", "dhcpv6": "dhcpv6", "http": "http", "tls": "tls", "smb": "smb", "smb2": "smb", "ssh": "ssh",
    "icmp": "icmp", "icmpv6": "icmpv6", "snmp": "snmp", "syslog": "syslog", "opcua": "opcua", "s7comm": "s7comm",
}
NAME_RESOLUTION = ("llmnr", "nbns", "mdns", "ssdp", "browser")
TRANSPORTS = {"1": "icmp", "6": "tcp", "17": "udp", "58": "icmpv6"}

MODBUS_FUNCTIONS = {
    1: "read_coils", 2: "read_discrete_inputs", 3: "read_holding_registers",
    4: "read_input_registers", 5: "write_single_coil", 6: "write_single_register",
    7: "read_exception_status", 8: "diagnostics", 11: "get_comm_event_counter",
    15: "write_multiple_coils", 16: "write_multiple_registers", 17: "report_server_id",
    22: "mask_write_register", 23: "read_write_multiple_registers",
    43: "read_device_identification",
}
MODBUS_WRITES = {5, 6, 15, 16, 22, 23}
READ_FUNCTIONS = {1, 2, 3, 4}  # responses carry the register/bit values read (``values``)
MODBUS_EXCEPTIONS = {
    1: "illegal_function", 2: "illegal_data_address", 3: "illegal_data_value",
    4: "server_device_failure", 5: "acknowledge", 6: "server_device_busy",
    8: "memory_parity_error", 10: "gateway_path_unavailable", 11: "gateway_target_no_response",
}
DNS_TYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA",
             33: "SRV", 64: "SVCB", 65: "HTTPS", 255: "ANY"}
DNS_RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}
NBNS_TYPES = {32: "NB", 33: "NBSTAT"}
NBNS_OPCODES = {0: "query", 5: "registration", 6: "release", 7: "wack", 8: "refresh"}
NTP_MODES = {1: "symmetric_active", 2: "symmetric_passive", 3: "client", 4: "server",
             5: "broadcast", 6: "control", 7: "private"}
BROWSER_COMMANDS = {1: "host_announcement", 2: "announcement_request", 8: "election_request",
                    9: "get_backup_list_request", 10: "get_backup_list_response",
                    11: "become_backup", 12: "domain_announcement", 13: "master_announcement",
                    14: "reset_browser_state", 15: "local_master_announcement"}
DHCP_TYPES = {1: "discover", 2: "offer", 3: "request", 4: "decline", 5: "ack", 6: "nak", 7: "release",
              8: "inform"}


# --- tshark ------------------------------------------------------------------------

def _rows(pcap: Path) -> Iterator[list[str]]:
    """One tshark pass over the capture; yields the FIELDS columns of every frame."""
    cmd = [require_tool("tshark"), "-n", "-r", str(pcap), "-T", "fields", "-E", f"separator={SEP}",
           "-E", "occurrence=a", "-E", f"aggregator={AGG}", "-E", "quote=n"]
    for name in FIELDS:
        cmd += ["-e", name]
    with tempfile.TemporaryFile() as stderr:
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=stderr,
                                    encoding="utf-8", errors="replace")
        except OSError as exc:
            raise TsharkError(f"cannot run tshark: {exc}") from exc
        assert proc.stdout is not None
        with proc.stdout:
            for line in proc.stdout:
                row = line.rstrip("\r\n").split(SEP)
                if len(row) < len(FIELDS):
                    row += [""] * (len(FIELDS) - len(row))
                yield row
        if proc.wait() != 0:
            stderr.seek(0)
            message = stderr.read().decode("utf-8", "replace").strip()
            raise TsharkError(f"tshark failed on {pcap.name}: {message or proc.returncode}", message)


def _all(row: list[str], name: str) -> list[str]:
    value = row[F[name]]
    return value.split(AGG) if value else []


def _first(row: list[str], name: str) -> str:
    value = row[F[name]]
    return value.split(AGG, 1)[0] if value else ""


def _int(value: str) -> int | None:
    if not value:
        return None
    return int(value, 16) if value.startswith("0x") else int(value)


def _bool(value: str) -> bool:
    return value in ("1", "True", "true")


def _ns_epoch(text: str) -> float | None:
    """tshark absolute time -> epoch seconds. Wireshark 4.4+ prints UTC fields as
    ``2025-02-04T11:03:12.306270837Z``, older versions as ``Feb  4, 2025 11:03:12.306270837 UTC``."""
    if not text or text == "NULL":
        return None
    whole, _, frac = text.removesuffix(" UTC").rstrip("Z").partition(".")
    fmt = "%Y-%m-%dT%H:%M:%S" if "T" in whole else "%b %d, %Y %H:%M:%S"
    base = dt.datetime.strptime(whole, fmt).replace(tzinfo=dt.UTC).timestamp()
    return base + (float(f"0.{frac}") if frac else 0.0)


def _ms(seconds: float) -> float:
    return round(seconds * 1000.0, 3)


def _app(protocols: str) -> str | None:
    for name in reversed(protocols.split(":")):
        if name in APPS:
            return APPS[name]
    return None


def _stamp(epoch: float) -> dict:
    return {"ts": iso_utc(epoch), "epoch": round(epoch, 6)}


# --- register map --------------------------------------------------------------------

def host_ips(answers: dict) -> dict[str, str]:
    """Host id -> address the sensor sees (the sensor-subnet interface, else the first)."""
    sensor = next((s["id"] for s in answers["topology"]["subnets"] if s["sensor"]), None)
    ips = {}
    for host in answers["topology"]["hosts"]:
        iface = next((i for i in host["interfaces"] if i["subnet"] == sensor), host["interfaces"][0])
        ips[host["id"]] = iface["ip"]
    return ips


def register_maps(answers: dict) -> dict[str, ProcessProfile]:
    """PLC address -> process profile of the ``modbus.server`` actor serving it."""
    ips = host_ips(answers)
    maps: dict[str, ProcessProfile] = {}
    for actor in answers["actors"]:
        if actor["type"] != "modbus.server":
            continue
        profile = ProcessProfile(answers["facts"][actor["id"]]["process"])
        for host_id in actor["hosts"]:
            maps[ips[host_id]] = profile
    return maps


# --- aggregation ---------------------------------------------------------------------

@dataclass
class _Flow:
    key: tuple
    transport: str
    first_frame: int
    first: float
    last: float
    hosts: tuple[str, str]           # (a, b) as first seen
    ports: tuple[int | None, int | None]
    macs: dict[str, str] = field(default_factory=dict)
    packets: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    bytes: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    app: str | None = None
    syn_from: str | None = None      # sender of a SYN without ACK
    synack_from: str | None = None
    fin: bool = False
    rst: bool = False


def _is_service_port(port: int | None) -> bool:
    return port is not None and (port < 1024 or port in (1900, 5353, 5355, 3389, 8080, 8443))


class _Exporter:
    def __init__(self, answers: dict) -> None:
        self.maps = register_maps(answers)
        self.flows: dict[tuple, _Flow] = {}
        self.modbus: list[dict] = []
        self.modbus_pending: dict[tuple, deque[dict]] = defaultdict(deque)
        self.dns: list[dict] = []
        self.dns_pending: dict[tuple, deque[dict]] = defaultdict(deque)
        self.ntp: list[dict] = []
        self.ntp_pending: dict[tuple, list[dict]] = defaultdict(list)
        self.names: list[dict] = []
        self.arp: list[dict] = []
        self.dhcp: list[dict] = []

    # -- per frame -------------------------------------------------------------------
    def frame(self, row: list[str]) -> None:
        number = int(row[F["frame.number"]])
        epoch = float(row[F["frame.time_epoch"]])
        if row[F["arp.opcode"]]:
            self._arp(row, number, epoch)
        src, dst = _first(row, "ip.src") or _first(row, "ipv6.src"), _first(row, "ip.dst") or _first(row, "ipv6.dst")
        if not src:
            return
        protocols = row[F["frame.protocols"]]
        app = _app(protocols)
        if row[F["tcp.stream"]]:
            transport = "tcp"
            sport, dport = _int(_first(row, "tcp.srcport")), _int(_first(row, "tcp.dstport"))
            key = ("tcp", int(_first(row, "tcp.stream")))
        elif row[F["udp.stream"]]:
            transport = "udp"
            sport, dport = _int(_first(row, "udp.srcport")), _int(_first(row, "udp.dstport"))
            key = ("udp", int(_first(row, "udp.stream")))
        else:
            proto = _first(row, "ip.proto") or ("58" if "icmpv6" in protocols.split(":") else "")
            transport = TRANSPORTS.get(proto, proto)
            sport = dport = None
            key = (transport, *sorted((src, dst)))
        self._flow(row, key, transport, number, epoch, src, dst, sport, dport, app)

        conn = {"src": src, "src_port": sport, "dest": dst, "dest_port": dport}
        retransmission = bool(row[F["tcp.analysis.retransmission"]])
        if row[F["mbtcp.trans_id"]] and not retransmission:
            self._modbus(row, key, number, epoch, conn)
        elif app == "dns" and row[F["dns.id"]]:
            self._dns(row, key, transport, number, epoch, conn)
        elif app == "ntp" and row[F["ntp.flags.mode"]]:
            self._ntp(row, key, number, epoch, conn)
        elif app in NAME_RESOLUTION:
            self._name(row, app, number, epoch, conn)
        elif app == "dhcp" and row[F["dhcp.option.dhcp"]]:
            self._dhcp(row, number, epoch, conn)

    def _flow(self, row, key, transport, number, epoch, src, dst, sport, dport, app) -> None:
        flow = self.flows.get(key)
        if flow is None:
            flow = self.flows[key] = _Flow(key, transport, number, epoch, epoch, (src, dst), (sport, dport))
        flow.last = epoch
        flow.packets[src] += 1
        length = _first(row, "ip.len") or (40 + int(_first(row, "ipv6.plen")) if row[F["ipv6.plen"]] else 0)
        flow.bytes[src] += int(length)
        flow.macs.setdefault(src, _first(row, "eth.src"))
        if flow.app is None and app is not None:
            flow.app = app
        if transport == "tcp":
            flags = _int(_first(row, "tcp.flags")) or 0
            syn, ack = flags & 0x02, flags & 0x10
            if syn and not ack and flow.syn_from is None:
                flow.syn_from = src
            if syn and ack and flow.synack_from is None:
                flow.synack_from = src
            flow.fin |= bool(flags & 0x01)
            flow.rst |= bool(flags & 0x04)

    # -- flows -------------------------------------------------------------------------
    def _flow_record(self, flow: _Flow) -> dict:
        a, b = flow.hosts
        pa, pb = flow.ports
        # Initiator: SYN sender, else whoever got the SYN-ACK, else the side not on a
        # service port, else the first sender.
        if flow.syn_from is not None:
            client = flow.syn_from
        elif flow.synack_from is not None:
            client = b if flow.synack_from == a else a
        elif _is_service_port(pa) and not _is_service_port(pb):
            client = b
        else:
            client = a
        if client == a:
            src, dest, sport, dport = a, b, pa, pb
        else:
            src, dest, sport, dport = b, a, pb, pa
        if src == dest:  # same host both ends: directions are indistinguishable by address
            out_packets, in_packets = flow.packets[src], 0
            out_bytes, in_bytes = flow.bytes[src], 0
        else:
            out_packets, in_packets = flow.packets[src], flow.packets[dest]
            out_bytes, in_bytes = flow.bytes[src], flow.bytes[dest]
        if flow.transport == "tcp":
            if flow.rst and not flow.fin:
                state = "reset"
            elif flow.fin:
                state = "closed"
            elif flow.syn_from is None and flow.synack_from is None:
                state = "mid_session"
            elif flow.synack_from is not None:
                state = "established"
            else:
                state = "attempted"
        else:
            state = "bidirectional" if in_packets else "one_way"
        record = {
            **_stamp(flow.first),
            "src": src, "src_port": sport, "dest": dest, "dest_port": dport,
            "src_mac": flow.macs.get(src), "dest_mac": flow.macs.get(dest) if src != dest else None,
            "transport": flow.transport, "app": flow.app or "unknown",
            "duration": round(flow.last - flow.first, 6),
            "packets_out": out_packets, "packets_in": in_packets,
            "bytes_out": out_bytes, "bytes_in": in_bytes,
            "packets": out_packets + in_packets, "bytes": out_bytes + in_bytes,
            "state": state,
            "first_frame": flow.first_frame,
            "flow_id": "/".join(str(k) for k in flow.key),
        }
        if flow.transport == "tcp":
            record["syn_seen"] = flow.syn_from is not None or flow.synack_from is not None
        return record

    # -- modbus ------------------------------------------------------------------------
    def _modbus(self, row, key, number, epoch, conn) -> None:
        trans_ids = _all(row, "mbtcp.trans_id")
        units = _all(row, "mbtcp.unit_id")
        functions = _all(row, "modbus.func_code")
        is_request = conn["dest_port"] == MODBUS_PORT
        single = len(trans_ids) == 1
        for index, trans in enumerate(trans_ids):
            function = _int(functions[index]) if index < len(functions) else None
            pdu = {
                "trans_id": int(trans),
                "unit_id": _int(units[index]) if index < len(units) else None,
                "function_code": function,
            }
            if is_request:
                self._modbus_request(row, key, number, epoch, conn, pdu, single)
            else:
                self._modbus_response(row, key, number, epoch, conn, pdu, single)

    def _modbus_request(self, row, key, number, epoch, conn, pdu, single) -> None:
        function = pdu["function_code"]
        table = FUNCTION_TABLE.get(function)
        record = {
            **_stamp(epoch), **conn,
            "src_mac": _first(row, "eth.src"), "dest_mac": _first(row, "eth.dst"),
            "transport": "tcp", "app": "modbus",
            "unit_id": pdu["unit_id"], "trans_id": pdu["trans_id"],
            "function_code": function, "function": MODBUS_FUNCTIONS.get(function, f"function_{function}"),
            "write": function in MODBUS_WRITES, "table": table,
            "address": None, "quantity": None, "values": None,
            "exception_code": None, "exception": None, "response_time_ms": None,
            "request_frame": number, "response_frame": None,
        }
        if record["write"]:
            record.update({"point": None, "unit": None, "value": None, "in_normal_band": None})
        if single:
            if function == 23:  # read/write multiple: report the written range
                record["address"] = _int(_first(row, "modbus.write_reference_num"))
            else:
                record["address"] = _int(_first(row, "modbus.reference_num"))
            values: list[int] | None = None
            if function == 5:
                data = _first(row, "modbus.data")
                values = [1 if data.lower() == "ff00" else 0] if data else None
            elif function == 15:
                values = [1 if _bool(v) else 0 for v in _all(row, "modbus.bitval")]
            elif function in (6, 16, 23):
                values = [int(v) for v in _all(row, "modbus.regval_uint16")]
                if not values and function == 6 and (data := _first(row, "modbus.data")):
                    values = [int(data, 16)]  # Wireshark < 4.4 leaves the written value as raw bytes
            if function in (5, 6, 22):
                record["quantity"] = 1
            elif function == 23:
                record["quantity"] = _int(_first(row, "modbus.write_word_cnt"))
            elif table in BIT_TABLES:
                record["quantity"] = _int(_first(row, "modbus.bit_cnt"))
            elif table is not None:
                record["quantity"] = _int(_first(row, "modbus.word_cnt"))
            if record["write"]:
                record["values"] = values
                self._annotate_write(record)
        self.modbus.append(record)
        self.modbus_pending[(key, pdu["trans_id"])].append(record)

    def _annotate_write(self, record: dict) -> None:
        profile = self.maps.get(record["dest"])
        if profile is None or record["address"] is None or not record["values"]:
            return
        points = []
        for offset, raw in enumerate(record["values"]):
            point = profile.by_address.get((record["table"], record["address"] + offset))
            if point is None:
                points.append(None)
                continue
            value = point.decode(raw)
            points.append({"point": point.name, "unit": point.unit,
                           "value": round(value, 6),
                           "in_normal_band": point.in_normal(value) if point.normal else None})
        known = [p for p in points if p is not None]
        if not known:
            return
        if len(points) == 1:
            record.update(known[0])
            return
        record["point"] = [p["point"] if p else None for p in points]
        record["unit"] = [p["unit"] if p else None for p in points]
        record["value"] = [p["value"] if p else None for p in points]
        bands = [p["in_normal_band"] for p in known if p["in_normal_band"] is not None]
        record["in_normal_band"] = all(bands) if bands else None

    def _modbus_response(self, row, key, number, epoch, conn, pdu, single) -> None:
        pending = self.modbus_pending.get((key, pdu["trans_id"]))
        if pending:
            record = pending.popleft()
        else:  # response to a request sent before the capture started
            function = pdu["function_code"]
            record = {
                **_stamp(epoch), "src": conn["dest"], "src_port": conn["dest_port"],
                "dest": conn["src"], "dest_port": conn["src_port"],
                "src_mac": _first(row, "eth.dst"), "dest_mac": _first(row, "eth.src"),
                "transport": "tcp", "app": "modbus",
                "unit_id": pdu["unit_id"], "trans_id": pdu["trans_id"], "function_code": function,
                "function": MODBUS_FUNCTIONS.get(function, f"function_{function}"),
                "write": function in MODBUS_WRITES, "table": FUNCTION_TABLE.get(function),
                "address": None, "quantity": None, "values": None,
                "exception_code": None, "exception": None, "response_time_ms": None,
                "request_frame": None, "response_frame": None,
            }
            if record["write"]:
                record.update({"point": None, "unit": None, "value": None, "in_normal_band": None})
            self.modbus.append(record)
        record["response_frame"] = number
        if record["request_frame"] is not None:
            record["response_time_ms"] = _ms(epoch - record["epoch"])
        if single:
            exception = _int(_first(row, "modbus.exception_code"))
            if exception is not None:
                record["exception_code"] = exception
                record["exception"] = MODBUS_EXCEPTIONS.get(exception, f"exception_{exception}")
            identity = _all(row, "modbus.object_str_value")
            if identity:
                record["device_identity"] = identity
            if exception is None and record["function_code"] in READ_FUNCTIONS \
                    and pdu["function_code"] == record["function_code"]:
                if record["table"] in BIT_TABLES:
                    values = [1 if _bool(v) else 0 for v in _all(row, "modbus.bitval")]
                else:
                    values = [int(v) for v in _all(row, "modbus.regval_uint16")]
                # Bit responses are padded to whole bytes: keep only the requested quantity.
                record["values"] = (values[:record["quantity"]] if record["quantity"] is not None
                                    else values) or None

    # -- dns ---------------------------------------------------------------------------
    def _dns(self, row, key, transport, number, epoch, conn) -> None:
        trans = _int(_first(row, "dns.id"))
        if not _bool(_first(row, "dns.flags.response")):
            qtype = _int(_first(row, "dns.qry.type"))
            record = {
                **_stamp(epoch), **conn, "transport": transport, "app": "dns",
                "trans_id": trans, "query": _first(row, "dns.qry.name"),
                "qtype": DNS_TYPES.get(qtype, f"TYPE{qtype}") if qtype is not None else None,
                "rcode": None, "answers": [], "ttl": None, "response_time_ms": None,
                "query_frame": number, "response_frame": None,
            }
            self.dns.append(record)
            self.dns_pending[(key, trans)].append(record)
            return
        pending = self.dns_pending.get((key, trans))
        if pending:
            record = pending.popleft()
            record["response_time_ms"] = _ms(epoch - record["epoch"])
        else:
            qtype = _int(_first(row, "dns.qry.type"))
            record = {
                **_stamp(epoch), "src": conn["dest"], "src_port": conn["dest_port"],
                "dest": conn["src"], "dest_port": conn["src_port"], "transport": transport, "app": "dns",
                "trans_id": trans, "query": _first(row, "dns.qry.name"),
                "qtype": DNS_TYPES.get(qtype, f"TYPE{qtype}") if qtype is not None else None,
                "rcode": None, "answers": [], "ttl": None, "response_time_ms": None,
                "query_frame": None, "response_frame": None,
            }
            self.dns.append(record)
        rcode = _int(_first(row, "dns.flags.rcode")) or 0
        record["rcode"] = DNS_RCODES.get(rcode, f"RCODE{rcode}")
        record["answers"] = (_all(row, "dns.cname") + _all(row, "dns.a") + _all(row, "dns.aaaa")
                             + _all(row, "dns.ptr.domain_name"))
        ttls = [int(t) for t in _all(row, "dns.resp.ttl")]
        record["ttl"] = min(ttls) if ttls else None
        record["response_frame"] = number

    # -- ntp ---------------------------------------------------------------------------
    def _ntp(self, row, key, number, epoch, conn) -> None:
        mode = _int(_first(row, "ntp.flags.mode"))
        xmt = _first(row, "ntp.xmt")
        if mode in (1, 3):
            record = {
                **_stamp(epoch), **conn, "transport": "udp", "app": "ntp",
                "version": _int(_first(row, "ntp.flags.vn")), "mode": NTP_MODES.get(mode, str(mode)),
                "stratum": None, "refid": None, "server_time": None,
                "offset_ms": None, "response_time_ms": None,
                "request_frame": number, "response_frame": None,
            }
            record["_xmt"] = xmt
            self.ntp.append(record)
            self.ntp_pending[key].append(record)
            return
        org = _first(row, "ntp.org")
        pending = self.ntp_pending.get(key, [])
        match = next((r for r in pending if r["_xmt"] == org), pending[0] if pending else None)
        if match is None:
            match = {
                **_stamp(epoch), "src": conn["dest"], "src_port": conn["dest_port"],
                "dest": conn["src"], "dest_port": conn["src_port"], "transport": "udp", "app": "ntp",
                "version": _int(_first(row, "ntp.flags.vn")), "mode": NTP_MODES.get(mode, str(mode)),
                "stratum": None, "refid": None, "server_time": None,
                "offset_ms": None, "response_time_ms": None,
                "request_frame": None, "response_frame": None, "_xmt": "",
            }
            self.ntp.append(match)
        else:
            pending.remove(match)
            match["response_time_ms"] = _ms(epoch - match["epoch"])
        stratum = _int(_first(row, "ntp.stratum"))
        match["stratum"] = stratum
        match["refid"] = _refid(_first(row, "ntp.refid"), stratum)
        server_xmt = _ns_epoch(xmt)
        match["server_time"] = iso_utc(server_xmt) if server_xmt is not None else None
        t1, t2, t3 = _ns_epoch(org), _ns_epoch(_first(row, "ntp.rec")), server_xmt
        if None not in (t1, t2, t3) and match["request_frame"] is not None:
            # RFC 5905 clock offset of the client relative to the server.
            match["offset_ms"] = _ms(((t2 - t1) + (t3 - epoch)) / 2)
        match["response_frame"] = number

    # -- name resolution ---------------------------------------------------------------
    def _name(self, row, app, number, epoch, conn) -> None:
        record: dict[str, Any] = {**_stamp(epoch), **conn, "src_mac": _first(row, "eth.src"),
                                  "transport": "udp", "app": app}
        if app in ("llmnr", "mdns"):
            response = _bool(_first(row, "dns.flags.response"))
            qtype = _int(_first(row, "dns.qry.type"))
            record.update({
                "message": "response" if response else "query",
                "query": _first(row, "dns.qry.name"),
                "qtype": DNS_TYPES.get(qtype, f"TYPE{qtype}") if qtype is not None else None,
                "answers": _all(row, "dns.a") + _all(row, "dns.aaaa") + _all(row, "dns.ptr.domain_name"),
            })
        elif app == "nbns":
            response = _bool(_first(row, "nbns.flags.response"))
            opcode = _int(_first(row, "nbns.flags.opcode")) or 0
            qtype = _int(_first(row, "nbns.type"))
            record.update({
                "message": NBNS_OPCODES.get(opcode, f"opcode_{opcode}") + ("_response" if response else ""),
                "query": _first(row, "nbns.name"),
                "qtype": NBNS_TYPES.get(qtype, str(qtype)) if qtype is not None else None,
                "answers": _all(row, "nbns.addr"),
            })
        elif app == "ssdp":
            method = _first(row, "http.request.method")
            headers = _all(row, "http.request.line") + _all(row, "http.response.line")
            record.update({
                "message": method.lower() if method else "response",
                "query": _header(headers, "ST") or _header(headers, "NT"),
                "uri": _first(row, "http.request.uri") or None,
                "status": _int(_first(row, "http.response.code")),
                "usn": _header(headers, "USN"),
                "location": _header(headers, "LOCATION"),
            })
        else:  # browser
            command = _int(_first(row, "browser.command"))
            record.update({
                "message": BROWSER_COMMANDS.get(command, f"command_{command}"),
                "query": _first(row, "browser.server") or None,
                "source_name": _first(row, "nbdgm.source_name") or None,
                "destination_name": _first(row, "nbdgm.destination_name") or None,
            })
        record["frame"] = number
        self.names.append(record)

    # -- arp ---------------------------------------------------------------------------
    def _arp(self, row, number, epoch) -> None:
        opcode = _int(_first(row, "arp.opcode"))
        sender, target = _first(row, "arp.src.proto_ipv4"), _first(row, "arp.dst.proto_ipv4")
        self.arp.append({
            **_stamp(epoch),
            "operation": {1: "request", 2: "reply"}.get(opcode, str(opcode)),
            "src": sender, "src_mac": _first(row, "arp.src.hw_mac"),
            "dest": target, "dest_mac": _first(row, "arp.dst.hw_mac"),
            "eth_src": _first(row, "eth.src"), "eth_dst": _first(row, "eth.dst"),
            "gratuitous": sender == target,
            "probe": opcode == 1 and sender == "0.0.0.0",  # RFC 5227 address conflict detection
            "frame": number,
        })

    # -- dhcp --------------------------------------------------------------------------
    def _dhcp(self, row, number, epoch, conn) -> None:
        message = _int(_first(row, "dhcp.option.dhcp"))
        lease = _int(_first(row, "dhcp.option.ip_address_lease_time"))

        def address(name: str) -> str | None:
            value = _first(row, name)
            return None if value in ("", "0.0.0.0") else value

        self.dhcp.append({
            **_stamp(epoch),
            **conn,
            "transport": "udp",
            "app": "dhcp",
            "message": DHCP_TYPES.get(message, str(message)),
            "xid": _first(row, "dhcp.id") or None,
            "broadcast_flag": _bool(_first(row, "dhcp.flags.bc")),
            "client_mac": _first(row, "dhcp.hw.mac_addr") or None,
            "client_addr": address("dhcp.ip.client"),
            "assigned_addr": address("dhcp.ip.your"),
            "requested_addr": address("dhcp.option.requested_ip_address"),
            "server_id": address("dhcp.option.dhcp_server_id"),
            "host_name": _first(row, "dhcp.option.hostname") or None,
            "client_fqdn": _first(row, "dhcp.fqdn.name") or None,
            "vendor_class": _first(row, "dhcp.option.vendor_class_id") or None,
            "lease_time_s": lease,
            "router": _all(row, "dhcp.option.router"),
            "dns_servers": _all(row, "dhcp.option.domain_name_server"),
            "domain": _first(row, "dhcp.option.domain_name") or None,
            "eth_src": _first(row, "eth.src"),
            "frame": number,
        })

    # -- output ------------------------------------------------------------------------
    def records(self) -> dict[str, list[dict]]:
        flows = sorted((self._flow_record(f) for f in self.flows.values()),
                       key=lambda r: (r["epoch"], r["first_frame"]))
        for record in self.ntp:
            record.pop("_xmt", None)

        def frame_of(record: dict) -> int:
            for name in ("request_frame", "query_frame", "response_frame", "frame"):
                if record.get(name) is not None:
                    return record[name]
            return 0

        def ordered(records: list[dict]) -> list[dict]:
            return sorted(records, key=lambda r: (r["epoch"], frame_of(r)))

        return {
            "flows": flows,
            "modbus": ordered(self.modbus),
            "dns": ordered(self.dns),
            "ntp": ordered(self.ntp),
            "name_resolution": ordered(self.names),
            "arp": ordered(self.arp),
            "dhcp": ordered(self.dhcp),
        }


def _header(lines: list[str], name: str) -> str | None:
    """Value of one header from tshark's escaped SSDP header lines (``ST: x\\r\\n``)."""
    prefix = name.lower() + ":"
    for line in lines:
        if line.lower().startswith(prefix):
            return line[len(prefix):].replace("\\r\\n", "").strip() or None
    return None


def _refid(text: str, stratum: int | None) -> str | None:
    """Reference id: ASCII clock source at stratum 0/1, IPv4 address of the upstream otherwise."""
    if not text:
        return None
    hexdigits = text.replace(":", "")
    try:
        raw = bytes.fromhex(hexdigits)
    except ValueError:
        return text
    if stratum is not None and stratum <= 1:
        return raw.rstrip(b"\x00").decode("ascii", "replace") or None
    return ".".join(str(b) for b in raw) if len(raw) == 4 else text


def export_siem(pcap: Path, answers: dict, out_dir: Path) -> dict[str, Path]:
    """Decode ``pcap`` once with tshark and write ``<name>.jsonl`` files into ``out_dir``."""
    exporter = _Exporter(answers)
    for row in _rows(Path(pcap)):
        exporter.frame(row)
    out_dir.mkdir(parents=True, exist_ok=True)
    paths = {}
    for name, records in exporter.records().items():
        path = out_dir / f"{name}.jsonl"
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            for record in records:
                fh.write(json.dumps(record, ensure_ascii=False) + "\n")
        paths[f"{name}.jsonl"] = path
    return paths
