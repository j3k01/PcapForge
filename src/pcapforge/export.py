"""SIEM export: decode a composed capture once with tshark and write JSON-lines logs.

Every file in ``<run>/siem/`` holds one JSON object per line with a ``ts`` field
(ISO-8601 UTC, microseconds, ``Z``) usable as Splunk ``_time`` / Elastic ``@timestamp``,
plus ``epoch`` (float seconds) and Splunk-CIM style ``src`` / ``dest`` / ``src_port`` /
``dest_port`` / ``transport`` / ``app`` fields. Records are sorted by time, then frame.

The export streams: records are written once the capture has moved ``HORIZON_S`` past them
(responses come within seconds), so memory holds a window of records plus one entry per flow.

All protocol decoding is done by tshark in a single pass; this module only groups the
decoded fields into flows and request/response transactions and, for Modbus writes,
looks the written registers up in the process register map from the answer key. The
telecontrol / building / packaging protocols (``iec104``, ``dnp3``, ``bacnet``, ``enip``)
get one record per message; EtherNet/IP implicit I/O (UDP 2222) is summarised per
connection, direction and minute.
"""

from __future__ import annotations

import datetime as dt
import heapq
import itertools
import json
import math
import re
import struct
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
HORIZON_S = 300.0   # a record is final this long (capture time) after its own timestamp
FLUSH_EVERY_S = 5.0
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
    # IEC 60870-5-104: APCI, ASDU header, then one occurrence per information object of each element.
    "iec60870_104.type", "iec60870_104.utype", "iec60870_104.tx", "iec60870_104.rx",
    "iec60870_asdu.typeid", "iec60870_asdu.sq", "iec60870_asdu.numix", "iec60870_asdu.causetx",
    "iec60870_asdu.nega", "iec60870_asdu.test", "iec60870_asdu.oa", "iec60870_asdu.addr", "iec60870_asdu.ioa",
    "iec60870_asdu.siq", "iec60870_asdu.diq", "iec60870_asdu.qds", "iec60870_asdu.vti.v",
    "iec60870_asdu.bitstring", "iec60870_asdu.normval", "iec60870_asdu.scalval", "iec60870_asdu.float",
    "iec60870_asdu.bcr.count", "iec60870_asdu.bcr.sq", "iec60870_asdu.bcr.cy", "iec60870_asdu.bcr.ca",
    "iec60870_asdu.bcr.iv", "iec60870_asdu.sco", "iec60870_asdu.dco", "iec60870_asdu.rco", "iec60870_asdu.qos",
    "iec60870_asdu.qoi", "iec60870_asdu.qcc", "iec60870_asdu.qrp", "iec60870_asdu.cp56time",
    # DNP3: link addresses, application header, object headers, command objects (CROB, analog output).
    "dnp3.src", "dnp3.dst", "dnp3.al.fir", "dnp3.al.fin", "dnp3.al.con", "dnp3.al.uns", "dnp3.al.seq",
    "dnp3.al.func", "dnp3.al.iin", "dnp3.al.obj", "dnp3.al.index", "dnp3.ctl.op", "dnp3.ctl.trip",
    "dnp3.al.count", "dnp3.al.on_time", "dnp3.al.off_time", "dnp3.al.ctrlstatus",
    "dnp3.al.anaout.int", "dnp3.al.anaout.float", "dnp3.al.anaout.double",
    # BACnet/IP: BVLC, NPDU, APDU header and object / property ids; the raw UDP payload for the
    # WriteProperty value and priority, which tshark only shows as text.
    "bvlc.function", "bvlc.result", "bvlc.reg_ttl", "bvlc.fwd_ip", "bvlc.fwd_port", "bacnet.mesgtyp",
    "bacapp.type", "bacapp.confirmed_service", "bacapp.unconfirmed_service", "bacapp.invoke_id",
    "bacapp.objectType", "bacapp.instance_number", "bacapp.property_identifier",
    "bacapp.present_value.null", "bacapp.present_value.boolean", "bacapp.present_value.uint",
    "bacapp.present_value.int", "bacapp.present_value.real", "bacapp.present_value.double",
    "bacapp.present_value.enum_index", "bacapp.present_value.char_string",
    "bacapp.error_class", "bacapp.error_code", "bacapp.reject_reason", "bacapp.abort_reason",
    "bacapp.vendor_identifier", "udp.payload",
    # EtherNet/IP + CIP: encapsulation, CPF items, CIP service / path, Forward_Open / Forward_Close.
    "enip.command", "enip.session", "enip.status", "enip.cpf.cai.connid", "enip.cpf.sai.connid",
    "enip.cpf.sai.seq", "enip.lir.name", "cip.seq", "cip.sc", "cip.rr", "cip.class", "cip.instance",
    "cip.attribute", "cip.symbol", "cip.genstat", "cip.id.product_name",
    "cip.cm.ot_connid", "cip.cm.to_connid", "cip.cm.conn_serial_num", "cip.cm.vendor", "cip.cm.orig_serial_num",
    "cip.cm.otrpi", "cip.cm.torpi", "cip.cm.otapi", "cip.cm.toapi", "cip.cm.fwo.transport", "cip.cm.fwo.trigger",
    "cip.cm.fwo.type", "cip.cm.fwo.consize",
    # Kerberos KDC exchanges (the first msg_type is the message's; a TGS-REQ also carries its AP-REQ).
    "kerberos.msg_type", "kerberos.CNameString", "kerberos.SNameString", "kerberos.realm", "kerberos.crealm",
    "kerberos.error_code", "kerberos.padata_type",
    # SMB 2/3: header, tree and file names (tshark tracks them across the session), sizes.
    "smb2.cmd", "smb2.flags.response", "smb2.msg_id", "smb2.sesid", "smb2.tid", "smb2.nt_status", "smb2.tree",
    "smb2.share_type", "smb2.filename", "smb2.flags.signature", "smb2.dialect", "smb2.eof", "smb2.read_length",
]
F = {name: index for index, name in enumerate(FIELDS)}

# Highest-layer tshark protocol name -> ``app`` label.
APPS = {
    "modbus": "modbus", "mbtcp": "modbus", "dns": "dns", "llmnr": "llmnr", "mdns": "mdns",
    "nbns": "nbns", "ssdp": "ssdp", "browser": "browser", "nbdgm": "nbdgm", "ntp": "ntp",
    "dhcp": "dhcp", "dhcpv6": "dhcpv6", "http": "http", "tls": "tls", "smb": "smb", "smb2": "smb", "ssh": "ssh",
    "kerberos": "kerberos", "ldap": "ldap", "cldap": "ldap",
    "icmp": "icmp", "icmpv6": "icmpv6", "snmp": "snmp", "syslog": "syslog", "opcua": "opcua", "s7comm": "s7comm",
    "iec60870_104": "iec104", "iec60870_asdu": "iec104", "dnp3": "dnp3", "bvlc": "bacnet", "bacnet": "bacnet",
    "bacapp": "bacnet", "enip": "enip", "cip": "enip", "cipcm": "enip", "cipcls": "enip",
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
KERBEROS_PORT = 88
KRB_REQUESTS = {10: "AS", 12: "TGS"}
KRB_REPLIES = {11: "AS", 13: "TGS"}
KRB_ERROR = 30
KRB_ERRORS = {6: "KDC_ERR_C_PRINCIPAL_UNKNOWN", 7: "KDC_ERR_S_PRINCIPAL_UNKNOWN", 12: "KDC_ERR_POLICY",
              14: "KDC_ERR_ETYPE_NOSUPP", 18: "KDC_ERR_CLIENT_REVOKED", 23: "KDC_ERR_KEY_EXPIRED",
              24: "KDC_ERR_PREAUTH_FAILED", 25: "KDC_ERR_PREAUTH_REQUIRED", 32: "KRB_AP_ERR_TKT_EXPIRED",
              37: "KRB_AP_ERR_SKEW", 52: "KRB_ERR_RESPONSE_TOO_BIG", 68: "KDC_ERR_WRONG_REALM"}
PA_ENC_TIMESTAMP = 2
SMB2_COMMANDS = {0: "negotiate", 1: "session_setup", 2: "logoff", 3: "tree_connect", 4: "tree_disconnect",
                 5: "create", 6: "close", 7: "flush", 8: "read", 9: "write", 10: "lock", 11: "ioctl", 12: "cancel",
                 13: "echo", 14: "query_directory", 15: "change_notify", 16: "query_info", 17: "set_info",
                 18: "oplock_break"}
SMB2_SHARE_TYPES = {1: "disk", 2: "pipe", 3: "print"}

IEC104_PORT = 2404
DNP3_PORT = 20000
BACNET_PORT = 47808
ENIP_PORT, ENIP_IO_PORT = 44818, 2222
IEC104_U_FUNCTIONS = {0x01: "startdt_act", 0x02: "startdt_con", 0x04: "stopdt_act", 0x08: "stopdt_con",
                      0x10: "testfr_act", 0x20: "testfr_con"}
IEC104_TYPES = {
    1: "M_SP_NA_1", 2: "M_SP_TA_1", 3: "M_DP_NA_1", 4: "M_DP_TA_1", 5: "M_ST_NA_1", 6: "M_ST_TA_1",
    7: "M_BO_NA_1", 8: "M_BO_TA_1", 9: "M_ME_NA_1", 10: "M_ME_TA_1", 11: "M_ME_NB_1", 12: "M_ME_TB_1",
    13: "M_ME_NC_1", 14: "M_ME_TC_1", 15: "M_IT_NA_1", 16: "M_IT_TA_1", 17: "M_EP_TA_1", 18: "M_EP_TB_1",
    19: "M_EP_TC_1", 20: "M_PS_NA_1", 21: "M_ME_ND_1", 30: "M_SP_TB_1", 31: "M_DP_TB_1", 32: "M_ST_TB_1",
    33: "M_BO_TB_1", 34: "M_ME_TD_1", 35: "M_ME_TE_1", 36: "M_ME_TF_1", 37: "M_IT_TB_1", 38: "M_EP_TD_1",
    39: "M_EP_TE_1", 40: "M_EP_TF_1", 45: "C_SC_NA_1", 46: "C_DC_NA_1", 47: "C_RC_NA_1", 48: "C_SE_NA_1",
    49: "C_SE_NB_1", 50: "C_SE_NC_1", 51: "C_BO_NA_1", 58: "C_SC_TA_1", 59: "C_DC_TA_1", 60: "C_RC_TA_1",
    61: "C_SE_TA_1", 62: "C_SE_TB_1", 63: "C_SE_TC_1", 64: "C_BO_TA_1", 70: "M_EI_NA_1", 100: "C_IC_NA_1",
    101: "C_CI_NA_1", 102: "C_RD_NA_1", 103: "C_CS_NA_1", 104: "C_TS_NA_1", 105: "C_RP_NA_1", 106: "C_CD_NA_1",
    107: "C_TS_TA_1", 110: "P_ME_NA_1", 111: "P_ME_NB_1", 112: "P_ME_NC_1", 113: "P_AC_NA_1", 120: "F_FR_NA_1",
    121: "F_SR_NA_1", 122: "F_SC_NA_1", 123: "F_LS_NA_1", 124: "F_AF_NA_1", 125: "F_SG_NA_1", 126: "F_DR_TA_1",
    127: "F_SC_NB_1",
}
IEC104_CAUSES = {
    1: "periodic", 2: "background", 3: "spontaneous", 4: "initialized", 5: "request", 6: "activation",
    7: "activation_con", 8: "deactivation", 9: "deactivation_con", 10: "activation_term", 11: "return_remote",
    12: "return_local", 13: "file_transfer", 20: "interrogated_station",
    **{20 + g: f"interrogated_group_{g}" for g in range(1, 17)},
    37: "requested_counter_general", **{37 + g: f"requested_counter_group_{g}" for g in range(1, 5)},
    44: "unknown_type", 45: "unknown_cause", 46: "unknown_common_address", 47: "unknown_ioa",
}
# Type id -> (value element, quality element or None). Values are consumed per information object.
IEC104_VALUES = {
    **dict.fromkeys((1, 30), ("iec60870_asdu.siq", None)), **dict.fromkeys((3, 31), ("iec60870_asdu.diq", None)),
    **dict.fromkeys((5, 32), ("iec60870_asdu.vti.v", "iec60870_asdu.qds")),
    **dict.fromkeys((7, 33), ("iec60870_asdu.bitstring", "iec60870_asdu.qds")),
    **dict.fromkeys((9, 34), ("iec60870_asdu.normval", "iec60870_asdu.qds")),
    **dict.fromkeys((11, 35), ("iec60870_asdu.scalval", "iec60870_asdu.qds")),
    **dict.fromkeys((13, 36), ("iec60870_asdu.float", "iec60870_asdu.qds")),
    21: ("iec60870_asdu.normval", None), **dict.fromkeys((15, 37), ("iec60870_asdu.bcr.count", None)),
    **dict.fromkeys((45, 58), ("iec60870_asdu.sco", None)), **dict.fromkeys((46, 59), ("iec60870_asdu.dco", None)),
    **dict.fromkeys((47, 60), ("iec60870_asdu.rco", None)),
    **dict.fromkeys((48, 61), ("iec60870_asdu.normval", "iec60870_asdu.qos")),
    **dict.fromkeys((49, 62), ("iec60870_asdu.scalval", "iec60870_asdu.qos")),
    **dict.fromkeys((50, 63), ("iec60870_asdu.float", "iec60870_asdu.qos")),
    **dict.fromkeys((51, 64), ("iec60870_asdu.bitstring", None)),
    100: ("iec60870_asdu.qoi", None), 101: ("iec60870_asdu.qcc", None), 103: ("iec60870_asdu.cp56time", None),
    105: ("iec60870_asdu.qrp", None),
}
IEC104_TIMED = set(range(30, 41)) | set(range(58, 65)) | {107}   # one CP56Time2a tag per object
DNP3_FUNCTIONS = {
    0: "confirm", 1: "read", 2: "write", 3: "select", 4: "operate", 5: "direct_operate", 6: "direct_operate_nr",
    7: "immediate_freeze", 8: "immediate_freeze_nr", 9: "freeze_clear", 10: "freeze_clear_nr",
    11: "freeze_at_time", 12: "freeze_at_time_nr", 13: "cold_restart", 14: "warm_restart",
    15: "initialize_data", 16: "initialize_application", 17: "start_application", 18: "stop_application",
    19: "save_configuration", 20: "enable_unsolicited", 21: "disable_unsolicited", 22: "assign_class",
    23: "delay_measure", 24: "record_current_time", 25: "open_file", 26: "close_file", 27: "delete_file",
    28: "get_file_info", 29: "authenticate_file", 30: "abort_file", 31: "activate_config",
    32: "authenticate_request", 33: "authenticate_error", 129: "response", 130: "unsolicited_response",
    131: "authenticate_response",
}
DNP3_IIN = {0x0100: "broadcast", 0x0200: "class_1_events", 0x0400: "class_2_events", 0x0800: "class_3_events",
            0x1000: "need_time", 0x2000: "local_control", 0x4000: "device_trouble", 0x8000: "device_restart",
            0x0001: "no_func_code_support", 0x0002: "object_unknown", 0x0004: "parameter_error",
            0x0008: "event_buffer_overflow", 0x0010: "already_executing", 0x0020: "config_corrupt"}
DNP3_OPS = {0: "nul", 1: "pulse_on", 2: "pulse_off", 3: "latch_on", 4: "latch_off"}
DNP3_TRIP = {0: "nul", 1: "close", 2: "trip"}
BVLC_FUNCTIONS = {0: "bvlc_result", 1: "write_bdt", 2: "read_bdt", 3: "read_bdt_ack", 4: "forwarded_npdu",
                  5: "register_foreign_device", 6: "read_fdt", 7: "read_fdt_ack", 8: "delete_fdt_entry",
                  9: "distribute_broadcast_to_network", 10: "original_unicast_npdu",
                  11: "original_broadcast_npdu", 12: "secure_bvll"}
BVLC_RESULTS = {0x00: "successful", 0x10: "write_bdt_nak", 0x20: "read_bdt_nak", 0x30: "register_fd_nak",
                0x40: "read_fdt_nak", 0x50: "delete_fdt_entry_nak", 0x60: "distribute_broadcast_nak"}
BACNET_APDU_TYPES = {0: "confirmed_request", 1: "unconfirmed_request", 2: "simple_ack", 3: "complex_ack",
                     4: "segment_ack", 5: "error", 6: "reject", 7: "abort"}
BACNET_CONFIRMED = {
    0: "acknowledge_alarm", 1: "confirmed_cov_notification", 2: "confirmed_event_notification",
    3: "get_alarm_summary", 4: "get_enrollment_summary", 5: "subscribe_cov", 6: "atomic_read_file",
    7: "atomic_write_file", 8: "add_list_element", 9: "remove_list_element", 10: "create_object",
    11: "delete_object", 12: "read_property", 14: "read_property_multiple", 15: "write_property",
    16: "write_property_multiple", 17: "device_communication_control", 18: "confirmed_private_transfer",
    19: "confirmed_text_message", 20: "reinitialize_device", 26: "read_range", 28: "subscribe_cov_property",
    29: "get_event_information",
}
BACNET_UNCONFIRMED = {0: "i_am", 1: "i_have", 2: "unconfirmed_cov_notification",
                      3: "unconfirmed_event_notification", 4: "unconfirmed_private_transfer",
                      5: "unconfirmed_text_message", 6: "time_synchronization", 7: "who_has", 8: "who_is",
                      9: "utc_time_synchronization", 10: "write_group"}
BACNET_WRITES = {8, 9, 10, 11, 15, 16, 17, 20}   # confirmed services that change a device
BACNET_OBJECTS = {0: "analog-input", 1: "analog-output", 2: "analog-value", 3: "binary-input",
                  4: "binary-output", 5: "binary-value", 6: "calendar", 7: "command", 8: "device",
                  9: "event-enrollment", 10: "file", 11: "group", 12: "loop", 13: "multi-state-input",
                  14: "multi-state-output", 15: "notification-class", 16: "program", 17: "schedule",
                  18: "averaging", 19: "multi-state-value", 20: "trend-log"}
BACNET_PROPERTIES = {
    4: "active-text", 8: "all", 12: "application-software-version", 22: "cov-increment", 28: "description",
    36: "event-state", 44: "firmware-revision", 46: "inactive-text", 56: "local-date", 57: "local-time",
    62: "max-apdu-length-accepted", 65: "max-pres-value", 69: "min-pres-value", 70: "model-name",
    74: "number-of-states", 75: "object-identifier", 76: "object-list", 77: "object-name", 79: "object-type",
    80: "optional", 81: "out-of-service", 85: "present-value", 87: "priority-array",
    96: "protocol-object-types-supported", 97: "protocol-services-supported", 98: "protocol-version",
    103: "reliability", 104: "relinquish-default", 105: "required", 107: "segmentation-supported",
    110: "state-text", 111: "status-flags", 112: "system-status", 117: "units", 119: "utc-offset",
    120: "vendor-identifier", 121: "vendor-name", 139: "protocol-revision", 155: "database-revision",
}
ENIP_COMMANDS = {0x0000: "nop", 0x0004: "list_services", 0x0063: "list_identity", 0x0064: "list_interfaces",
                 0x0065: "register_session", 0x0066: "unregister_session", 0x006F: "send_rr_data",
                 0x0070: "send_unit_data", 0x0072: "indicate_status", 0x0073: "cancel"}
CIP_SERVICES = {
    0x01: "get_attributes_all", 0x02: "set_attributes_all", 0x03: "get_attribute_list",
    0x04: "set_attribute_list", 0x05: "reset", 0x06: "start", 0x07: "stop", 0x08: "create", 0x09: "delete",
    0x0A: "multiple_service_packet", 0x0D: "apply_attributes", 0x0E: "get_attribute_single",
    0x10: "set_attribute_single", 0x11: "find_next_object_instance", 0x15: "restore", 0x16: "save",
    0x17: "no_operation", 0x18: "get_member", 0x19: "set_member", 0x1A: "insert_member", 0x1B: "remove_member",
    0x1C: "group_sync", 0x4C: "read_tag", 0x4D: "write_tag", 0x4E: "read_modify_write_tag",
    0x52: "read_tag_fragmented", 0x53: "write_tag_fragmented", 0x55: "get_instance_attribute_list",
}
CIP_CM_CLASS = 0x06   # Connection Manager: its own meaning for the vendor-specific service codes
CIP_CM_SERVICES = {0x4E: "forward_close", 0x52: "unconnected_send", 0x54: "forward_open",
                   0x56: "get_connection_data", 0x57: "search_connection_data", 0x5A: "get_connection_owner",
                   0x5B: "large_forward_open"}
CIP_WRITES = {0x02, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x15, 0x16, 0x19, 0x1A, 0x1B, 0x4D, 0x4E, 0x53}
CIP_FORWARD_OPEN = {0x54, 0x5B}
CIP_TRIGGERS = {0: "cyclic", 1: "change_of_state", 2: "application"}
CIP_CONNECTION_TYPES = {0: "null", 1: "multicast", 2: "point_to_point"}


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


# JSON-lines files written as the capture streams by (flows.jsonl is written at the end).
DATASETS = ("modbus", "dns", "ntp", "name_resolution", "arp", "dhcp", "iec104", "dnp3", "bacnet", "enip",
            "kerberos", "smb")


class ExportError(RuntimeError):
    pass


def _frame_of(record: dict) -> int:
    for name in ("request_frame", "query_frame", "response_frame", "frame", "first_frame"):
        if record.get(name) is not None:
            return record[name]
    return 0


def _finish_record(record: dict) -> None:
    """Drop the exporter's working fields; per-minute I/O summaries get their interval stats."""
    record.pop("_xmt", None)
    intervals = record.pop("_intervals", None)
    if intervals:
        record["interval_ms_mean"] = _ms(sum(intervals) / len(intervals))
        record["interval_ms_min"] = _ms(min(intervals))
        record["interval_ms_max"] = _ms(max(intervals))


class _Dataset:
    """One ``<name>.jsonl``: records in (epoch, frame) order, written once they are final."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.file = open(path, "w", encoding="utf-8", newline="\n")
        self.heap: list[tuple[float, int, dict]] = []
        self.seq = itertools.count()
        self.mark = -math.inf

    def append(self, record: dict) -> None:
        if record["epoch"] < self.mark:
            raise ExportError(f"{self.path.stem} record at {record['epoch']:.6f} behind already written "
                              f"capture time {self.mark:.6f}")
        heapq.heappush(self.heap, (record["epoch"], next(self.seq), record))

    def flush(self, mark: float) -> None:
        """Write every record before ``mark`` (all records of one timestamp go together)."""
        heap, batch = self.heap, []
        while heap and heap[0][0] < mark:
            batch.append(heapq.heappop(heap))
        self.mark = max(self.mark, mark)
        batch.sort(key=lambda e: (e[0], _frame_of(e[2]), e[1]))
        write = self.file.write
        for _epoch, _seq, record in batch:
            _finish_record(record)
            write(json.dumps(record, ensure_ascii=False) + "\n")


class _Exporter:
    def __init__(self, answers: dict, out_dir: Path) -> None:
        self.maps = register_maps(answers)
        self.out_dir = out_dir
        self.datasets = {name: _Dataset(out_dir / f"{name}.jsonl") for name in DATASETS}
        self.flushed = -math.inf
        self.flows: dict[tuple, _Flow] = {}
        self.modbus = self.datasets["modbus"]
        self.modbus_pending: dict[tuple, deque[dict]] = defaultdict(deque)
        self.dns = self.datasets["dns"]
        self.dns_pending: dict[tuple, deque[dict]] = defaultdict(deque)
        self.ntp = self.datasets["ntp"]
        self.ntp_pending: dict[tuple, list[dict]] = defaultdict(list)
        self.names = self.datasets["name_resolution"]
        self.arp = self.datasets["arp"]
        self.dhcp = self.datasets["dhcp"]
        self.iec104 = self.datasets["iec104"]
        self.dnp3 = self.datasets["dnp3"]
        self.bacnet = self.datasets["bacnet"]
        self.enip = self.datasets["enip"]
        self.enip_io: dict[tuple, dict] = {}
        self.enip_io_last: dict[tuple, tuple[int | None, float]] = {}
        self.kerberos = self.datasets["kerberos"]
        self.kerberos_pending: dict[tuple, deque[dict]] = defaultdict(deque)
        self.smb = self.datasets["smb"]
        self.smb_pending: dict[tuple, deque[dict]] = defaultdict(deque)

    # -- per frame -------------------------------------------------------------------
    def frame(self, row: list[str]) -> None:
        number = int(row[F["frame.number"]])
        epoch = float(row[F["frame.time_epoch"]])
        if epoch - self.flushed >= FLUSH_EVERY_S:
            self.flushed = epoch
            self._flush(epoch - HORIZON_S)
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
        elif retransmission:
            return
        elif row[F["iec60870_104.type"]]:
            self._iec104(row, number, epoch, conn)
        elif row[F["dnp3.al.func"]]:
            self._dnp3(row, transport, number, epoch, conn)
        elif row[F["bvlc.function"]]:
            self._bacnet(row, number, epoch, conn)
        elif row[F["enip.command"]]:
            self._enip(row, transport, number, epoch, conn)
        elif row[F["enip.cpf.sai.connid"]] and transport == "udp":
            self._enip_io(row, number, epoch, conn)
        elif row[F["kerberos.msg_type"]] and KERBEROS_PORT in (sport, dport):
            self._kerberos(row, key, transport, number, epoch, conn)
        elif row[F["smb2.cmd"]]:
            self._smb(row, key, number, epoch, conn)

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
        # One entry per register-map point the write covers completely (a float32 spans two registers).
        points = [{"point": point.name, "register": profile.register_label(point),
                   "desc": point.desc or None, "unit": point.unit,
                   "value": round(value, 6),
                   "in_normal_band": point.in_normal(value) if point.normal else None}
                  for point, value in profile.decode_block(record["table"], record["address"], record["values"])]
        if not points:
            return
        if len(points) == 1:
            record.update(points[0])
            return
        for field_ in ("point", "register", "desc", "unit", "value"):
            record[field_] = [p[field_] for p in points]
        bands = [p["in_normal_band"] for p in points if p["in_normal_band"] is not None]
        record["in_normal_band"] = all(bands) if bands else None

    def _modbus_response(self, row, key, number, epoch, conn, pdu, single) -> None:
        pending = self.modbus_pending.get((key, pdu["trans_id"]))
        if pending:
            record = pending.popleft()
            if not pending:
                del self.modbus_pending[(key, pdu["trans_id"])]
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
            if not pending:
                del self.dns_pending[(key, trans)]
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

    # -- kerberos ----------------------------------------------------------------------
    def _kerberos(self, row, key, transport, number, epoch, conn) -> None:
        """One record per KDC exchange: the AS / TGS request and its reply or KRB-ERROR on the same
        socket / connection. A KRB-ERROR names no client and a TGS-REQ shows only its TGT's server
        name, so the client comes from the AS-REQ or the reply, the service from the reply."""
        msg_type = _int(_first(row, "kerberos.msg_type"))
        names = _all(row, "kerberos.SNameString")
        client = _first(row, "kerberos.CNameString") or None
        if msg_type in KRB_REQUESTS:
            record = {
                **_stamp(epoch), **conn, "src_mac": _first(row, "eth.src"), "transport": transport,
                "app": "kerberos", "request_type": KRB_REQUESTS[msg_type], "client": client,
                "realm": _first(row, "kerberos.realm") or None,
                "service": "/".join(names) if msg_type == 10 and names else None,
                "preauth": (str(PA_ENC_TIMESTAMP) in _all(row, "kerberos.padata_type")) if msg_type == 10 else None,
                "result": None, "error": None, "error_code": None, "response_time_ms": None,
                "request_frame": number, "response_frame": None,
            }
            self.kerberos.append(record)
            self.kerberos_pending[key].append(record)
            return
        if msg_type not in KRB_REPLIES and msg_type != KRB_ERROR:
            return
        pending = self.kerberos_pending.get(key)
        if pending:
            record = pending.popleft()
            record["response_time_ms"] = _ms(epoch - record["epoch"])
            if not pending:
                del self.kerberos_pending[key]
        else:  # the request fell before the capture
            record = {
                **_stamp(epoch), "src": conn["dest"], "src_port": conn["dest_port"], "dest": conn["src"],
                "dest_port": conn["src_port"], "src_mac": None, "transport": transport, "app": "kerberos",
                "request_type": KRB_REPLIES.get(msg_type), "client": None, "realm": None, "service": None,
                "preauth": None, "result": None, "error": None, "error_code": None, "response_time_ms": None,
                "request_frame": None,
            }
            self.kerberos.append(record)
        if msg_type == KRB_ERROR:
            code = _int(_first(row, "kerberos.error_code"))
            record.update(result="error", error_code=code, error=KRB_ERRORS.get(code, f"error_{code}"))
        else:
            record["result"] = "success"
        record["client"] = record["client"] or client
        record["realm"] = record["realm"] or _first(row, "kerberos.crealm") or _first(row, "kerberos.realm") or None
        if names:
            record["service"] = "/".join(names)
        record["response_frame"] = number

    # -- smb ---------------------------------------------------------------------------
    def _smb(self, row, key, number, epoch, conn) -> None:
        """One record per SMB2 request and its response (matched by message id on the connection)."""
        command = _int(_first(row, "smb2.cmd"))
        message_id = _int(_first(row, "smb2.msg_id"))
        response = _bool(_first(row, "smb2.flags.response"))
        share_type = _int(_first(row, "smb2.share_type"))
        details = {
            "tree": _unescaped(_first(row, "smb2.tree")) or None,
            "share_type": SMB2_SHARE_TYPES.get(share_type) if share_type is not None else None,
            "filename": _unescaped(_first(row, "smb2.filename")) or None,
            "dialect": _first(row, "smb2.dialect") or None,
            "file_size": _int(_first(row, "smb2.eof")) if command == 5 else None,   # CREATE: end of file
            "read_length": _int(_first(row, "smb2.read_length")),
        }
        pending = self.smb_pending.get((key, message_id))
        if not response:
            record = {
                **_stamp(epoch), **conn, "src_mac": _first(row, "eth.src"), "transport": "tcp", "app": "smb",
                "command": SMB2_COMMANDS.get(command, f"command_{command}"), "message_id": message_id,
                "session_id": _first(row, "smb2.sesid") or None, "signed": _bool(_first(row, "smb2.flags.signature")),
                **details, "status": None, "success": None, "response_time_ms": None, "request_frame": number,
                "response_frame": None,
            }
            self.smb.append(record)
            self.smb_pending[(key, message_id)].append(record)
            return
        if pending:
            record = pending.popleft()
            record["response_time_ms"] = _ms(epoch - record["epoch"])
            if not pending:
                del self.smb_pending[(key, message_id)]
        else:  # the request fell before the capture
            record = {
                **_stamp(epoch), "src": conn["dest"], "src_port": conn["dest_port"], "dest": conn["src"],
                "dest_port": conn["src_port"], "src_mac": None, "transport": "tcp", "app": "smb",
                "command": SMB2_COMMANDS.get(command, f"command_{command}"), "message_id": message_id,
                "signed": _bool(_first(row, "smb2.flags.signature")), **details, "status": None,
                "response_time_ms": None, "request_frame": None,
            }
            self.smb.append(record)
        record["session_id"] = _first(row, "smb2.sesid") or record.get("session_id")
        for name, value in details.items():
            if value is not None:
                record[name] = value
        status = _int(_first(row, "smb2.nt_status"))
        record["status"] = None if status is None else f"0x{status:08x}"
        record["success"] = status == 0
        record["response_frame"] = number

    # -- iec 60870-5-104 ---------------------------------------------------------------
    def _iec104(self, row, number, epoch, conn) -> None:
        """One record per APDU; several can share a TCP segment, so every element is taken from
        the frame's occurrence lists in order (I-frames carry N(S) and N(R), S-frames N(R))."""
        take = _Cursor(row)
        for apci_text in _all(row, "iec60870_104.type"):
            apci = _int(apci_text) or 0
            kind = "I" if not apci & 1 else ("S" if apci & 3 == 1 else "U")
            record = {
                **_stamp(epoch), **conn, "src_mac": _first(row, "eth.src"), "dest_mac": _first(row, "eth.dst"),
                "transport": "tcp", "app": "iec104",
                "apci": kind, "u_function": None, "send_seq": None, "recv_seq": None,
                "type_id": None, "type": None, "category": None, "cot": None, "cause": None,
                "negative": None, "test": None, "originator": None, "common_address": None,
                "sq": None, "num_objects": None, "ioa": [], "objects": [], "select": None,
                "frame": number,
            }
            if kind == "U":
                utype = _int(take("iec60870_104.utype"))
                record["u_function"] = IEC104_U_FUNCTIONS.get(utype, f"u_{utype}")
            elif kind == "S":
                record["recv_seq"] = _int(take("iec60870_104.rx"))
            else:
                record["send_seq"] = _int(take("iec60870_104.tx"))
                record["recv_seq"] = _int(take("iec60870_104.rx"))
                _asdu(record, take)
            self.iec104.append(record)

    # -- dnp3 --------------------------------------------------------------------------
    def _dnp3(self, row, transport, number, epoch, conn) -> None:
        """One record per reassembled application fragment. Object headers and command objects
        are attributed only when the frame holds a single fragment (tshark lists them per frame)."""
        functions = _all(row, "dnp3.al.func")
        single = len(functions) == 1
        take = _Cursor(row)
        for text in functions:
            function = _int(text)
            response = function is not None and function >= 129
            iin = _int(take("dnp3.al.iin")) if response else None
            record = {
                **_stamp(epoch), **conn, "src_mac": _first(row, "eth.src"), "dest_mac": _first(row, "eth.dst"),
                "transport": transport, "app": "dnp3",
                "link_src": _int(_first(row, "dnp3.src")), "link_dst": _int(_first(row, "dnp3.dst")),
                "function_code": function, "function": DNP3_FUNCTIONS.get(function, f"function_{function}"),
                "response": response,
                "fir": _bool(take("dnp3.al.fir")), "fin": _bool(take("dnp3.al.fin")),
                "con": _bool(take("dnp3.al.con")), "uns": _bool(take("dnp3.al.uns")),
                "seq": _int(take("dnp3.al.seq")),
                "iin": iin, "iin_flags": [name for bit, name in DNP3_IIN.items() if iin and iin & bit],
                "objects": None, "controls": [], "analog_outputs": [], "point_index": [],
                "frame": number,
            }
            if single:
                _dnp3_objects(row, record)
            self.dnp3.append(record)

    # -- bacnet ------------------------------------------------------------------------
    def _bacnet(self, row, number, epoch, conn) -> None:
        function = _int(_first(row, "bvlc.function"))
        apdu = _int(_first(row, "bacapp.type"))
        service = None
        if apdu in (0, 2, 3, 5):
            service = _int(_first(row, "bacapp.confirmed_service"))
            service_name = BACNET_CONFIRMED.get(service, f"confirmed_{service}") if service is not None else None
        elif apdu == 1:
            service = _int(_first(row, "bacapp.unconfirmed_service"))
            service_name = BACNET_UNCONFIRMED.get(service, f"unconfirmed_{service}") if service is not None else None
        else:
            service_name = None
        result = _int(_first(row, "bvlc.result"))
        objects = list(dict.fromkeys(zip((_int(t) for t in _all(row, "bacapp.objectType")),
                                         (_int(n) for n in _all(row, "bacapp.instance_number")))))
        main = next((o for o in objects if o[0] != 8), objects[0] if objects else None)
        device = next((o[1] for o in objects if o[0] == 8), None)
        properties = list(dict.fromkeys(_int(p) for p in _all(row, "bacapp.property_identifier")))
        record = {
            **_stamp(epoch), **conn, "src_mac": _first(row, "eth.src"), "dest_mac": _first(row, "eth.dst"),
            "transport": "udp", "app": "bacnet",
            "bvlc_function": function, "bvlc": BVLC_FUNCTIONS.get(function, f"bvlc_{function}"),
            "bvlc_result": BVLC_RESULTS.get(result, f"result_{result}") if result is not None else None,
            "ttl_s": _int(_first(row, "bvlc.reg_ttl")),
            "orig_src": _first(row, "bvlc.fwd_ip") or None, "orig_src_port": _int(_first(row, "bvlc.fwd_port")),
            "network_message": _int(_first(row, "bacnet.mesgtyp")),
            "apdu_type": BACNET_APDU_TYPES.get(apdu, f"apdu_{apdu}") if apdu is not None else None,
            "service_code": service, "service": service_name,
            "invoke_id": _int(_first(row, "bacapp.invoke_id")) if apdu not in (None, 1) else None,
            "write": apdu == 0 and service in BACNET_WRITES,
            "object_type": _bacnet_object_type(main[0]) if main else None,
            "instance": main[1] if main else None,
            "objects": [f"{_bacnet_object_type(t)}:{n}" for t, n in objects],
            "device": device,
            "property": _bacnet_property(properties[0]) if properties else None,
            "properties": [_bacnet_property(p) for p in properties],
            "value": _bacnet_value(row) if len(objects) <= 2 else None,
            "priority": None, "relinquish": None,
            "vendor_id": _int(_first(row, "bacapp.vendor_identifier")),
            "error_class": _int(_first(row, "bacapp.error_class")),
            "error_code": _int(_first(row, "bacapp.error_code")),
            "reject_reason": _int(_first(row, "bacapp.reject_reason")),
            "abort_reason": _int(_first(row, "bacapp.abort_reason")),
            "frame": number,
        }
        if apdu == 0 and service == 15 and (payload := _first(row, "udp.payload")):
            write = _bacnet_write_request(bytes.fromhex(payload.replace(":", "")))
            if write is not None:
                record.update(write)
        self.bacnet.append(record)

    # -- ethernet/ip -------------------------------------------------------------------
    def _enip(self, row, transport, number, epoch, conn) -> None:
        """One record per encapsulation message (explicit messaging, TCP or UDP 44818). CIP
        details are attributed only when the frame holds a single message."""
        commands = _all(row, "enip.command")
        sessions, statuses = _all(row, "enip.session"), _all(row, "enip.status")
        for index, text in enumerate(commands):
            command = _int(text)
            record = {
                **_stamp(epoch), **conn, "src_mac": _first(row, "eth.src"), "dest_mac": _first(row, "eth.dst"),
                "transport": transport, "app": "enip", "message": "explicit",
                "command_code": command, "command": ENIP_COMMANDS.get(command, f"command_0x{command:04x}"),
                "session": _hex32(sessions[index] if index < len(sessions) else ""),
                "status": _int(statuses[index]) if index < len(statuses) else None,
                "response": conn["src_port"] == ENIP_PORT,
                "connection_id": None, "sequence": None,
                "service_code": None, "service": None, "services": [],
                "class": None, "instance": None, "attribute": None, "tags": [],
                "general_status": None, "write": False, "identity": None,
                "frame": number,
            }
            if len(commands) == 1:
                _cip(row, record)
            self.enip.append(record)

    def _enip_io(self, row, number, epoch, conn) -> None:
        """Class 0/1 implicit I/O (UDP 2222) is cyclic - tens of packets a second per connection -
        so it is summarised per connection, direction and minute instead of one record a packet."""
        connid = _int(_first(row, "enip.cpf.sai.connid"))
        seq = _int(_first(row, "enip.cpf.sai.seq"))
        length = _first(row, "ip.len") or (40 + int(_first(row, "ipv6.plen")) if row[F["ipv6.plen"]] else 0)
        stream = (conn["src"], conn["src_port"], conn["dest"], conn["dest_port"], connid)
        window = int(epoch // 60)
        summary = self.enip_io.get((*stream, window))
        if summary is None:
            summary = self.enip_io[(*stream, window)] = {
                **_stamp(epoch), **conn, "src_mac": _first(row, "eth.src"), "dest_mac": _first(row, "eth.dst"),
                "transport": "udp", "app": "enip", "message": "io_summary",
                "window_start": iso_utc(window * 60), "window_s": 60, "connection_id": _hex32(str(connid)),
                "packets": 0, "bytes": 0, "first_seq": seq, "last_seq": seq, "seq_missing": 0, "seq_repeated": 0,
                "interval_ms_mean": None, "interval_ms_min": None, "interval_ms_max": None,
                "first_frame": number, "last_frame": number, "_intervals": [],
            }
            self.enip.append(summary)
        summary["packets"] += 1
        summary["bytes"] += int(length)
        summary["last_frame"] = number
        previous = self.enip_io_last.get(stream)
        if previous is not None:
            last_seq, last_epoch = previous
            summary["_intervals"].append(epoch - last_epoch)
            if seq is not None and last_seq is not None:
                step = (seq - last_seq) % (1 << 32)
                if step == 0 or step >= 1 << 31:   # duplicate or older than the last one seen
                    summary["seq_repeated"] += 1
                    self.enip_io_last[stream] = (last_seq, epoch)
                    return
                summary["seq_missing"] += step - 1
        summary["last_seq"] = seq
        self.enip_io_last[stream] = (seq, epoch)

    # -- output ------------------------------------------------------------------------
    def _flush(self, mark: float) -> None:
        # A request still unanswered behind the horizon stays unanswered: a reply that late is
        # matched as a response without request, and its record is already written.
        for pending in (self.modbus_pending, self.dns_pending, self.kerberos_pending, self.smb_pending):
            for key in [k for k, queue in pending.items() if queue[0]["epoch"] < mark]:
                queue = pending[key]
                while queue and queue[0]["epoch"] < mark:
                    queue.popleft()
                if not queue:
                    del pending[key]
        for key, queue in self.ntp_pending.items():
            if queue and queue[0]["epoch"] < mark:
                queue[:] = [r for r in queue if r["epoch"] >= mark]
        for key in [k for k in self.enip_io if k[-1] * 60 + 60 < mark]:
            del self.enip_io[key]   # its minute is over and the summary written
        for dataset in self.datasets.values():
            dataset.flush(mark)

    def finish(self) -> dict[str, Path]:
        """Write what is left and the flow records; ``<name>.jsonl`` -> path."""
        self._flush(math.inf)
        for dataset in self.datasets.values():
            dataset.file.close()
        flows = sorted((self._flow_record(f) for f in self.flows.values()),
                       key=lambda r: (r["epoch"], r["first_frame"]))
        path = self.out_dir / "flows.jsonl"
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            for record in flows:
                fh.write(json.dumps(record, ensure_ascii=False) + "\n")
        paths = {"flows.jsonl": path}
        paths.update({f"{name}.jsonl": d.path for name, d in self.datasets.items()})
        return paths

    def close(self) -> None:
        for dataset in self.datasets.values():
            dataset.file.close()


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


_ESCAPES = {"t": "\t", "n": "\n", "r": "\r"}


def _unescaped(text: str) -> str:
    """A string field as tshark ``-T fields`` prints it, with its backslash escapes undone (an SMB path
    ``\\\\dc\\SysVol`` comes out with every backslash doubled)."""
    return re.sub(r"\\(.)", lambda m: _ESCAPES.get(m[1], m[1]), text) if "\\" in text else text


# --- OT protocol helpers -------------------------------------------------------------

class _Cursor:
    """Hands out a frame's occurrences of each field in order, for PDUs that repeat inside one
    frame (APDUs in a TCP segment, information objects in an ASDU)."""

    def __init__(self, row: list[str]) -> None:
        self.row = row
        self.values: dict[str, list[str]] = {}
        self.position: dict[str, int] = defaultdict(int)

    def __call__(self, name: str) -> str:
        values = self.values.get(name)
        if values is None:
            values = self.values[name] = _all(self.row, name)
        index = self.position[name]
        self.position[name] = index + 1
        return values[index] if index < len(values) else ""


def _hex32(text: str) -> str | None:
    value = _int(text)
    return None if value is None else f"0x{value:08x}"


def _f32(value: float) -> float:
    """A float32 value without the noise digits of its double expansion."""
    return float(f"{value:.7g}")


_CP56 = re.compile(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3})")


def _cp56(text: str) -> str | None:
    """CP56Time2a carries no zone; tshark prints its fields with the local offset appended. The
    outstations encode UTC, so the fields are reported as UTC (millisecond resolution)."""
    match = _CP56.match(text)
    return f"{match[1]}Z" if match else (text or None)


def _iec104_category(type_id: int | None) -> str | None:
    if type_id is None:
        return None
    if type_id <= 44 or type_id == 70:
        return "monitor"
    if type_id <= 69:
        return "control"
    if 100 <= type_id <= 109:
        return "system"
    if 110 <= type_id <= 119:
        return "parameter"
    return "file" if 120 <= type_id <= 127 else None


def _iec104_value(type_id: int, raw: str) -> dict:
    """Value (and the qualifier octet's flags) of one information object."""
    if not raw:
        return {"value": None}
    if type_id in (1, 30, 3, 31):
        octet = _int(raw)
        return {"value": octet & (0x01 if type_id in (1, 30) else 0x03), "quality": octet & 0xF0,
                "invalid": bool(octet & 0x80)}
    if type_id in (45, 58, 46, 59, 47, 60):
        octet = _int(raw)
        return {"value": octet & (0x01 if type_id in (45, 58) else 0x03), "qualifier": (octet >> 2) & 0x1F,
                "select": bool(octet & 0x80)}
    if type_id == 101:
        octet = _int(raw)
        return {"value": octet & 0x3F, "freeze": octet >> 6}
    if type_id == 103:
        return {"value": _cp56(raw)}
    if type_id in (9, 34, 13, 36, 21, 48, 61, 50, 63):
        return {"value": _f32(float(raw))}
    return {"value": _int(raw)}


def _asdu(record: dict, take: _Cursor) -> None:
    """ASDU header and information objects of one I-frame into its record."""
    type_id = _int(take("iec60870_asdu.typeid"))
    sq = _bool(take("iec60870_asdu.sq"))
    count = _int(take("iec60870_asdu.numix")) or 0
    cot = _int(take("iec60870_asdu.causetx"))
    record.update({
        "type_id": type_id,
        "type": IEC104_TYPES.get(type_id, f"type_{type_id}") if type_id is not None else None,
        "category": _iec104_category(type_id),
        "cot": cot, "cause": IEC104_CAUSES.get(cot, f"cause_{cot}") if cot is not None else None,
        "negative": _bool(take("iec60870_asdu.nega")), "test": _bool(take("iec60870_asdu.test")),
        "originator": _int(take("iec60870_asdu.oa")), "common_address": _int(take("iec60870_asdu.addr")),
        "sq": sq, "num_objects": count,
    })
    value_field, quality_field = IEC104_VALUES.get(type_id, (None, None))
    objects = []
    for index in range(count):
        ioa = _int(take("iec60870_asdu.ioa"))
        if ioa is None and sq and objects:   # SQ=1: consecutive addresses after the first
            ioa = objects[0]["ioa"] + index
        obj: dict[str, Any] = {"ioa": ioa}
        if value_field:
            obj.update(_iec104_value(type_id, take(value_field)))
        if type_id in (15, 37):
            obj.update({"sequence": _int(take("iec60870_asdu.bcr.sq")), "carry": _bool(take("iec60870_asdu.bcr.cy")),
                        "adjusted": _bool(take("iec60870_asdu.bcr.ca")), "invalid": _bool(take("iec60870_asdu.bcr.iv"))})
        if quality_field == "iec60870_asdu.qos":
            qos = _int(take(quality_field)) or 0
            obj.update({"qualifier": qos & 0x7F, "select": bool(qos & 0x80)})
        elif quality_field:
            qds = _int(take(quality_field)) or 0
            obj.update({"quality": qds, "invalid": bool(qds & 0x80)})
        if type_id in IEC104_TIMED:
            obj["time"] = _cp56(take("iec60870_asdu.cp56time"))
        objects.append(obj)
    record["objects"] = objects
    record["ioa"] = [o["ioa"] for o in objects]
    if record["category"] == "control" and objects and "select" in objects[0]:
        record["select"] = any(o["select"] for o in objects)


def _dnp3_objects(row: list[str], record: dict) -> None:
    """Object headers (gGvV) and the control relay output / analog output command objects."""
    headers = [_int(o) for o in _all(row, "dnp3.al.obj")]
    record["objects"] = [f"g{o >> 8}v{o & 0xFF}" for o in headers if o is not None]
    ops = _all(row, "dnp3.ctl.op")
    outputs = (_all(row, "dnp3.al.anaout.float") or _all(row, "dnp3.al.anaout.double")
               or _all(row, "dnp3.al.anaout.int"))
    groups = [o >> 8 for o in headers if o is not None]
    # Output status objects (g10, g40) carry the same value elements as the command objects.
    ops = ops if 12 in groups else []
    outputs = outputs if 41 in groups else []
    if not ops and not outputs:
        return
    indexes = [_int(i) for i in _all(row, "dnp3.al.index")]
    statuses = [_int(s) for s in _all(row, "dnp3.al.ctrlstatus")]
    crob_first = 41 not in groups or 12 not in groups or groups.index(12) < groups.index(41)
    split = len(ops) if crob_first else len(outputs)
    first_idx, second_idx = indexes[:split], indexes[split:]
    first_st, second_st = statuses[:split], statuses[split:]
    crob_idx, ao_idx = (first_idx, second_idx) if crob_first else (second_idx, first_idx)
    crob_st, ao_st = (first_st, second_st) if crob_first else (second_st, first_st)
    trips, counts = _all(row, "dnp3.ctl.trip"), _all(row, "dnp3.al.count")
    on, off = _all(row, "dnp3.al.on_time"), _all(row, "dnp3.al.off_time")

    def at(values: list, i: int):
        return values[i] if i < len(values) else None

    record["controls"] = [{
        "index": at(crob_idx, i), "op": DNP3_OPS.get(_int(op), op),
        "trip": DNP3_TRIP.get(_int(at(trips, i) or "0")), "count": _int(at(counts, i) or ""),
        "on_ms": _int(at(on, i) or ""), "off_ms": _int(at(off, i) or ""), "status": at(crob_st, i),
    } for i, op in enumerate(ops)]
    record["analog_outputs"] = [{"index": at(ao_idx, i), "value": float(value), "status": at(ao_st, i)}
                                for i, value in enumerate(outputs)]
    record["point_index"] = [c["index"] for c in record["controls"]] + [a["index"] for a in record["analog_outputs"]]


def _bacnet_object_type(number: int | None) -> str | None:
    return None if number is None else BACNET_OBJECTS.get(number, str(number))


def _bacnet_property(number: int | None) -> str | None:
    return None if number is None else BACNET_PROPERTIES.get(number, str(number))


# Present-value elements in the order they are preferred; a single-object message carries one.
BACNET_VALUE_FIELDS = ("bacapp.present_value.real", "bacapp.present_value.double", "bacapp.present_value.uint",
                       "bacapp.present_value.int", "bacapp.present_value.enum_index",
                       "bacapp.present_value.boolean", "bacapp.present_value.char_string")


def _bacnet_value(row: list[str]) -> Any:
    for name in BACNET_VALUE_FIELDS:
        text = _first(row, name)
        if text:
            if name.endswith(("real", "double")):
                return _f32(float(text)) if name.endswith("real") else float(text)
            if name.endswith("boolean"):
                return _bool(text)
            return text if name.endswith("char_string") else _int(text)
    return None


def _bacnet_tag(data: bytes, i: int) -> tuple[int, bool, int, bytes, int]:
    """The BACnet tag at ``i``: (number, context-specific, LVT, content, next index). A context
    tag with LVT 6 / 7 is an opening / closing tag; an application BOOLEAN keeps its value in LVT."""
    head = data[i]
    i += 1
    number, context, lvt = head >> 4, bool(head & 0x08), head & 0x07
    if number == 15:
        number = data[i]
        i += 1
    if (context and lvt in (6, 7)) or (not context and number == 1):
        return number, context, lvt, b"", i
    length = lvt
    if lvt == 5:
        length = data[i]
        i += 1
        if length in (254, 255):
            size = 2 if length == 254 else 4
            length = int.from_bytes(data[i:i + size], "big")
            i += size
    if i + length > len(data):
        raise IndexError("BACnet tag past the end of the APDU")
    return number, context, lvt, data[i:i + length], i + length


def _bacnet_app_value(number: int, lvt: int, content: bytes) -> Any:
    if number == 0:
        return None
    if number == 1:
        return bool(lvt)
    if number in (2, 9):
        return int.from_bytes(content, "big")
    if number == 3:
        return int.from_bytes(content, "big", signed=True)
    if number == 4:
        return _f32(struct.unpack(">f", content)[0])
    if number == 5:
        return struct.unpack(">d", content)[0]
    if number == 7:   # character set octet first; 0 = UTF-8
        return content[1:].decode("utf-8", "replace")
    if number == 12:
        oid = int.from_bytes(content, "big")
        return f"{_bacnet_object_type(oid >> 22)}:{oid & 0x3FFFFF}"
    return content.hex()


def _bacnet_write_request(payload: bytes) -> dict | None:
    """Object, property, value and priority of a WriteProperty request (BVLC + NPDU + APDU)."""
    try:
        i = 10 if payload[1] == 4 else 4   # Forwarded-NPDU carries the 6-octet original source
        control = payload[i + 1]
        i += 2
        if control & 0x80:                 # network layer message: no APDU
            return None
        if control & 0x20:                 # DNET, DLEN, DADR
            i += 3 + payload[i + 2]
        if control & 0x08:                 # SNET, SLEN, SADR
            i += 3 + payload[i + 2]
        if control & 0x20:                 # hop count
            i += 1
        if payload[i] >> 4 != 0 or payload[i] & 0x08 or payload[i + 3] != 15:
            return None                    # not an unsegmented confirmed WriteProperty request
        i += 4
        out: dict[str, Any] = {"value": None, "priority": None, "relinquish": False}
        while i < len(payload):
            number, context, lvt, content, i = _bacnet_tag(payload, i)
            if not context:
                continue
            if number == 0:
                oid = int.from_bytes(content, "big")
                out.update({"object_type": _bacnet_object_type(oid >> 22), "instance": oid & 0x3FFFFF})
                out["objects"] = [f"{out['object_type']}:{out['instance']}"]
            elif number == 1:
                out["property"] = _bacnet_property(int.from_bytes(content, "big"))
                out["properties"] = [out["property"]]
            elif number == 2:
                out["array_index"] = int.from_bytes(content, "big")
            elif number == 3 and lvt == 6:
                values = []
                while True:
                    number, context, lvt, content, i = _bacnet_tag(payload, i)
                    if context and number == 3 and lvt == 7:
                        break
                    if not context:
                        values.append((number, _bacnet_app_value(number, lvt, content)))
                out["value"] = values[0][1] if len(values) == 1 else [v for _, v in values]
                out["relinquish"] = len(values) == 1 and values[0][0] == 0
            elif number == 4:
                out["priority"] = int.from_bytes(content, "big")
        return out
    except (IndexError, struct.error):
        return None


def _cip(row: list[str], record: dict) -> None:
    """CIP request / response of one explicit message into its record."""
    record["connection_id"] = _hex32(_first(row, "enip.cpf.cai.connid"))
    record["sequence"] = _int(_first(row, "cip.seq"))
    record["identity"] = _first(row, "enip.lir.name") or _first(row, "cip.id.product_name") or None
    codes = [_int(c) for c in _all(row, "cip.sc")]
    if not codes:
        return
    flags = _all(row, "cip.rr")
    klass = _int(_first(row, "cip.class"))
    outer = codes[0]
    connection_manager = klass == CIP_CM_CLASS and outer in CIP_CM_SERVICES
    response = bool(_int(flags[0])) if flags else record["response"]
    record.update({
        "response": response,
        "service_code": outer,
        "service": (CIP_CM_SERVICES[outer] if connection_manager
                    else CIP_SERVICES.get(outer, f"service_0x{outer:02x}")),
        # Distinct embedded requests of a Multiple Service Packet / Unconnected Send.
        "services": list(dict.fromkeys(CIP_SERVICES.get(c, f"service_0x{c:02x}") for c in codes[1:])),
        "class": klass,
        "instance": _int(_first(row, "cip.instance")),
        "attribute": _int(_first(row, "cip.attribute")),
        "tags": _all(row, "cip.symbol"),
        "general_status": _int(_first(row, "cip.genstat")) if response else None,
        "write": not response and any(c in CIP_WRITES for c in ([] if connection_manager else [outer]) + codes[1:]),
    })
    if connection_manager and outer in CIP_FORWARD_OPEN | {0x4E}:
        record.update({
            "connection_serial": _first(row, "cip.cm.conn_serial_num") or None,
            "originator_vendor": _int(_first(row, "cip.cm.vendor")),
            "originator_serial": _hex32(_first(row, "cip.cm.orig_serial_num")),
        })
    if connection_manager and outer in CIP_FORWARD_OPEN:
        types = [_int(t) for t in _all(row, "cip.cm.fwo.type")]
        sizes = [_int(s) for s in _all(row, "cip.cm.fwo.consize")]
        trigger = _int(_first(row, "cip.cm.fwo.trigger"))

        def ms(name: str) -> float | None:
            micros = _int(_first(row, name))
            return None if micros is None else micros / 1000

        record.update({
            "ot_connection_id": _hex32(_first(row, "cip.cm.ot_connid")),
            "to_connection_id": _hex32(_first(row, "cip.cm.to_connid")),
            "transport_class": _int(_first(row, "cip.cm.fwo.transport")),
            "trigger": CIP_TRIGGERS.get(trigger, trigger) if trigger is not None else None,
            "ot_connection_type": CIP_CONNECTION_TYPES.get(types[0]) if types else None,
            "to_connection_type": CIP_CONNECTION_TYPES.get(types[1]) if len(types) > 1 else None,
            "ot_size": sizes[0] if sizes else None, "to_size": sizes[1] if len(sizes) > 1 else None,
            "rpi_ot_ms": ms("cip.cm.otrpi"), "rpi_to_ms": ms("cip.cm.torpi"),
            "api_ot_ms": ms("cip.cm.otapi"), "api_to_ms": ms("cip.cm.toapi"),
        })


def export_siem(pcap: Path, answers: dict, out_dir: Path) -> dict[str, Path]:
    """Decode ``pcap`` once with tshark and write ``<name>.jsonl`` files into ``out_dir``."""
    out_dir.mkdir(parents=True, exist_ok=True)
    exporter = _Exporter(answers, out_dir)
    try:
        for row in _rows(Path(pcap)):
            exporter.frame(row)
        return exporter.finish()
    finally:
        exporter.close()
