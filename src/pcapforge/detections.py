"""Detection content for a generated exercise: Suricata rules derived from the site model
and an instructor hunting guide (Wireshark / Splunk SPL / Kibana KQL per question).

Everything is derived from ``answers.json`` so ``pcapforge export`` can rebuild it for an
existing run: the ``actors`` section says which hosts are PLCs (``modbus.server``),
approved writers (``modbus.operator``) and SCADA clients (``modbus.poller``); the process
profile named in the PLC facts supplies the register map and normal bands. For the
telecontrol / building / packaging protocols the outstations are the ``*.server`` (and
``enip.adapter``) hosts and the approved masters the non-incident ``iec104.client``,
``dnp3.client``, ``bacnet.client`` and ``enip.client`` / ``enip.scanner`` hosts.
"""

from __future__ import annotations

import json
import math
import struct
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from pcapforge.export import host_ips
from pcapforge.process import ProcessProfile
from pcapforge.zeek import hunt_command

SID_BASE = 9100000          # local sid range reserved for pcapforge (9100000-9199999)
SID_BAND_BASE = SID_BASE + 100
SID_OT_BASE = SID_BASE + 1000   # IEC 104 +0.., DNP3 +10.., BACnet +20.., EtherNet/IP +30..
SID_IT_BASE = SID_BASE + 2000   # IT line: DnsTunneling +0.., HttpsBeaconing +100.., ScanAuthFailures +200.., VolumetricFlood +300.., BulkUpload +400.., Kerberoasting +500.., SmbLateral +600.., LdapRecon +700.., RogueDhcp +800.., ItOtPivot +900.., ItOtZonePolicy +1000..
MODBUS_PORT = 502
WRITER_TYPES = ("modbus.operator",)
CLIENT_TYPES = ("modbus.poller", "modbus.operator")
DATASETS = ("flows", "modbus", "dns", "ntp", "name_resolution", "arp", "dhcp", "iec104", "dnp3", "bacnet", "enip",
            "kerberos", "smb", "tls", "http", "rdp")

IEC104_PORT, DNP3_PORT, BACNET_PORT, ENIP_PORT = 2404, 20000, 47808, 44818
IEC104_MASTER_TYPES, IEC104_SERVER_TYPES = ("iec104.client",), ("iec104.server",)
DNP3_MASTER_TYPES, DNP3_SERVER_TYPES = ("dnp3.client",), ("dnp3.server",)
BACNET_CLIENT_TYPES, BACNET_SERVER_TYPES = ("bacnet.client",), ("bacnet.server",)
ENIP_ORIGINATOR_TYPES, ENIP_TARGET_TYPES = ("enip.client", "enip.scanner"), ("enip.server", "enip.adapter")
# DNP3 requests that change the outstation (controls, writes, restarts, application / unsolicited /
# class configuration, time set) and the ones that only collect data (polls, counter freezes).
DNP3_CONTROL_FUNCTIONS = [2, 3, 4, 5, 6, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 24, 31]
DNP3_POLL_FUNCTIONS = [1, 7, 8, 9, 10, 11, 12]
BACNET_WRITE_SERVICES = [8, 9, 10, 11, 15, 16, 17, 20]   # list / object / property writes, DCC, reinitialize
SURICATA_PARSERS = {"modbus": "app-layer.protocols.modbus.enabled=true",
                    "dnp3": "app-layer.protocols.dnp3.enabled=yes",
                    "enip": "app-layer.protocols.enip.enabled=yes"}


@dataclass(frozen=True)
class Rule:
    sid: int
    msg: str
    text: str
    purpose: str


def _hosts(answers: dict, types: tuple[str, ...]) -> list[str]:
    """Host ids of non-incident actors of the given types, in topology order."""
    wanted = {h for a in answers["actors"] if a["type"] in types and not a["incident"] for h in a["hosts"]}
    return [h["id"] for h in answers["topology"]["hosts"] if h["id"] in wanted]


def _addresses(ips: list[str]) -> str:
    return "[" + ",".join(ips) + "]"


def _number(value: float) -> str:
    return f"{value:g}"


def _rule(sid: int, header: str, msg: str, options: str, metadata: str, purpose: str, proto: str = "modbus") -> Rule:
    text = f'alert {proto} {header} (msg:"{msg}"; {options} metadata: {metadata}; sid:{sid}; rev:1;)'
    return Rule(sid, msg, text, purpose)


def suricata_rules(answers: dict) -> list[Rule]:
    return (_modbus_rules(answers) + _ot_rules(answers) + _it_dns_tunnel_rules(answers)
            + _it_scan_auth_rules(answers) + _it_https_beacon_rules(answers)
            + _it_volumetric_flood_rules(answers)
            + _it_bulk_upload_rules(answers) + _it_kerberoasting_rules(answers) + _it_smb_lateral_rules(answers) + _it_ldap_recon_rules(answers) + _it_rogue_dhcp_rules(answers) + _it_ot_pivot_rules(answers) + _it_ot_zone_rules(answers))

def _it_smb_lateral_rules(answers: dict) -> list[Rule]:
    """SMB tree connect to an ADMIN$ administrative share of the lateral-movement incident
    (it-smb-lateral-movement). On this LAN a client's only SMB peer is the DC's SYSVOL share, so an
    ADMIN$ tree connect never happens in the office baseline and the rule is inert on it."""
    if not any(a["type"] == "smb.lateral" and a["incident"] for a in answers["actors"]):
        return []
    return [_rule(SID_IT_BASE + 600, "$HOME_NET any -> $HOME_NET 445",
                  "PCAPFORGE IT SMB tree connect to an ADMIN$ administrative share - possible lateral movement",
                  'flow:to_server,established; content:"|5c 00 41 00 44 00 4d 00 49 00 4e 00 24 00|"; fast_pattern;',
                  "mitre_attack T1021.002, mitre_attack T1078.002", proto="tcp",
                  purpose=("An SMB tree connect to a workstation's ADMIN$ share. On this LAN clients only "
                           "mount the DC's SYSVOL, so any ADMIN$ connect is lateral movement with a reused "
                           "credential; the office baseline never does it."))]


def _it_rogue_dhcp_rules(answers: dict) -> list[Rule]:
    """The rogue-DHCP incident (it-rogue-dhcp): a second, unauthorised DHCP server answering clients
    on the office segment. Its Offers and ACKs (a BOOTREPLY, UDP source port 67) come from the rogue's
    own address rather than the approved DHCP relay that forwards the legitimate server's replies. The
    rule names that source address, so it is inert on the office baseline and on every other site."""
    actor = next((a for a in answers["actors"] if a["type"] == "dhcp.server" and a["incident"]), None)
    if not actor:
        return []
    facts = answers["facts"].get(actor["id"], {})
    rogue_ip = (facts.get("hosts") or [{}])[0].get("ip")
    if not rogue_ip:
        return []
    return [_rule(SID_IT_BASE + 800, f"{_addresses([rogue_ip])} 67 -> any any",
                  "PCAPFORGE IT rogue DHCP server (BOOTREPLY from an unauthorised server on the LAN)",
                  'content:"|02 01 06|"; depth:3;',
                  "mitre_attack T1557, mitre_attack T1557.003", proto="udp",
                  purpose=("A DHCP Offer/ACK (a BOOTREPLY, UDP source port 67) sourced by a host that is not "
                           "the approved DHCP relay: a second, unauthorised DHCP server on the office segment "
                           "(DHCP spoofing). The legitimate replies come from the relay; the office baseline "
                           "has no other DHCP server."))]


def _it_ot_pivot_host_subnets(answers: dict):
    """(office source host id, office subnet cidr, control subnet cidr, control host IPs) of the
    IT-to-OT pivot incident (it-ot-pivot): the office host running the incident Modbus scanner /
    writer, and the control subnet its PLCs sit on. ``None`` when this is not that scenario (so the
    rules stay out of every other scenario's export)."""
    if answers["scenario"].get("line") != "it":
        return None
    servers = [a for a in answers["actors"] if a["type"] == "modbus.server"]
    pivot = next((a["hosts"][0] for a in answers["actors"]
                  if a["incident"] and a["type"] in ("modbus.scanner", "modbus.writer")), None)
    if not servers or pivot is None:
        return None
    hosts = {h["id"]: h for h in answers["topology"]["hosts"]}
    cidr = {s["id"]: s["cidr"] for s in answers["topology"]["subnets"]}
    office_subnet = hosts[pivot]["interfaces"][0]["subnet"]
    control_subnet = hosts[servers[0]["hosts"][0]]["interfaces"][0]["subnet"]
    control_ips = sorted(h["interfaces"][0]["ip"] for h in hosts.values()
                         if len(h["interfaces"]) == 1 and h["interfaces"][0]["subnet"] == control_subnet)
    return pivot, cidr[office_subnet], cidr[control_subnet], control_ips


def _it_ot_pivot_rules(answers: dict) -> list[Rule]:
    """The cross-zone pivot of the IT-to-OT incident (it-ot-pivot): a TCP connection from the office
    LAN into the OT control subnet, which the IT/OT firewall should not route. The rule names both
    subnet CIDRs, so it is inert on every other site and on both baselines (the office baseline has no
    control subnet; the OT baseline has no office subnet). The Modbus writes and the port-502 sweep are
    caught by the Modbus rules already generated for the PLCs."""
    found = _it_ot_pivot_host_subnets(answers)
    if found is None:
        return []
    _, office_cidr, control_cidr, _ = found
    return [_rule(
        SID_IT_BASE + 900, f"{office_cidr} any -> {control_cidr} any",
        "PCAPFORGE IT-to-OT pivot: TCP connection from the office LAN into the control network",
        "flow:to_server;", "mitre_attack T1046, mitre_ics T0886",
        "A TCP connection from an office-LAN host into the OT control subnet. Only the OT clients on "
        "the control network should reach the PLCs; a connection routed in from the office LAN crosses "
        "the IT/OT boundary and should never happen.", proto="tcp")]


def _it_ot_zone(answers: dict):
    """Zone model of a combined IT+OT site built on the it-ot-baseline-operations baseline: an office
    LAN, an industrial DMZ and a plant control network (subnets ``office`` / ``dmz`` / ``control``),
    with RDP jump host(s) in the DMZ. Returns (office cidr, dmz cidr, control cidr, jump-host IPs, DMZ
    host IPs, control host IPs), or ``None`` for every scenario without that DMZ zone model, so the
    rules stay out of the OT baseline, the office baseline and it-ot-pivot (which has no DMZ)."""
    if answers["scenario"].get("line") != "it":
        return None
    cidr = {s["id"]: s.get("cidr") for s in answers["topology"]["subnets"]}
    if not {"office", "dmz", "control"} <= set(cidr):
        return None
    hosts = answers["topology"]["hosts"]
    by_id = {h["id"]: h for h in hosts}

    def ip_on(host: dict, subnet: str):
        return next((i["ip"] for i in host["interfaces"] if i["subnet"] == subnet), None)

    def endpoint_ips(subnet: str) -> list[str]:
        return sorted(h["interfaces"][0]["ip"] for h in hosts
                      if len(h["interfaces"]) == 1 and h["interfaces"][0]["subnet"] == subnet)

    rdp_hosts = {h for a in answers["actors"] if a["type"] == "rdp.server" for h in a["hosts"]}
    jump_ips = sorted(ip for hid in rdp_hosts if hid in by_id and (ip := ip_on(by_id[hid], "dmz")))
    return cidr["office"], cidr["dmz"], cidr["control"], jump_ips, endpoint_ips("dmz"), endpoint_ips("control")


def _it_ot_zone_rules(answers: dict) -> list[Rule]:
    """Zone-segmentation policy of the combined IT+OT baseline (it-ot-baseline-operations), reusable by
    any incident layered on it: no office host reaches the control network directly, and RDP into the
    control network comes only from the DMZ jump host. Both are inert on this baseline (0 alerts) and
    on every scenario without the DMZ zone model."""
    found = _it_ot_zone(answers)
    if found is None:
        return []
    office_cidr, _dmz_cidr, control_cidr, jump_ips, _dmz_ips, _control_ips = found
    rules = [_rule(
        SID_IT_BASE + 1000, f"{office_cidr} any -> {control_cidr} any",
        "PCAPFORGE IT/OT zone policy: direct connection from the office LAN into the control network",
        "flow:to_server;", "mitre_attack T1046, mitre_ics T0886",
        "A TCP connection straight from the office LAN into the OT control network. The two zones are "
        "separated by the industrial DMZ, so office hosts reach the plant only through the DMZ jump host, "
        "never directly; this baseline never does it.", proto="tcp")]
    source = f"![{','.join(jump_ips)}]" if jump_ips else "any"
    rules.append(_rule(
        SID_IT_BASE + 1001, f"{source} any -> {control_cidr} 3389",
        "PCAPFORGE IT/OT zone policy: RDP into the control network from a host other than the DMZ jump host",
        "flow:to_server;", "mitre_attack T1021.001, mitre_ics T0886",
        "A Remote Desktop (TCP 3389) connection into the OT control network from a source that is not the "
        "DMZ jump host. Only the jump host opens RDP sessions to the engineering workstation; any other "
        "source is out of policy. The baseline's only inbound RDP comes from the jump host.", proto="tcp"))
    return rules


def _it_volumetric_flood_rules(answers: dict) -> list[Rule]:
    """The volumetric UDP flood of the volumetric-flood incident (it-volumetric-flood): a high rate of
    datagrams to the local sink (Discard, UDP 9). A threshold rule fires on >=50 datagrams to one
    destination in a second. The office baseline sends nothing to this port, so the rule is inert on it."""
    if not any(a["type"] == "sink.flood" and a["incident"] for a in answers["actors"]):
        return []
    ips = host_ips(answers)
    sinks = [ips[h] for a in answers["actors"] if a["type"] == "sink.server" for h in a["hosts"]]
    dest = _addresses(sinks) if sinks else "any"
    return [_rule(SID_IT_BASE + 300, f"any any -> {dest} 9",
                  "PCAPFORGE IT volumetric UDP flood to a sink service (>=50 datagrams/s to one host)",
                  "threshold: type both, track by_dst, count 50, seconds 1;",
                  "mitre_attack T1498, mitre_attack T1498.001",
                  "A high rate of UDP datagrams to the sink (Discard, port 9): at least 50 to one "
                  "destination within a second. A volumetric network flood (direct network flood); the "
                  "office baseline sends nothing to this port.", proto="udp")]


def _it_dns_tunnel_rules(answers: dict) -> list[Rule]:
    """DNS queries with a long base32-like leading label under the single fictional parent domain of
    the DNS-tunnelling incident (it-dns-tunneling): one host encoding data into subdomains. The
    ``content`` match on the parent keeps the rule inert on every other site and the baseline."""
    actor = next((a for a in answers["actors"] if a["type"] == "dns.tunnel" and a["incident"]), None)
    if not actor:
        return []
    facts = answers["facts"].get(actor["id"], {})
    parent, label_len = facts.get("domain"), facts.get("label_len")
    if not parent or not label_len:
        return []
    options = f'dns.query; content:"{parent}"; nocase; pcre:"/^[a-z2-7]{{{label_len},}}\\./i"; '
    purpose = (f"A DNS query whose leading label is {label_len}+ base32-like characters under {parent}: "
               "one host encoding data into subdomains of a single parent (DNS-based data transfer / "
               "exfiltration over DNS). No legitimate name on this site looks like this.")
    return [_rule(SID_IT_BASE, "any any -> any any",
                  f"PCAPFORGE IT DNS tunnelling: long encoded label under {parent}",
                  options, "mitre_attack T1071.004, mitre_attack T1048.003", purpose, proto="dns")]


def _it_https_beacon_rules(answers: dict) -> list[Rule]:
    """The periodic HTTPS check-ins of the beaconing incident (it-https-beaconing): a TLS
    ClientHello whose SNI is the one fictional beacon domain, from the beaconing host to the external
    service. The ``content`` match on that domain keeps the rule inert on every other site and the
    office baseline, where the SNIs are the intranet site names."""
    actor = next((a for a in answers["actors"] if a["type"] == "tls.beacon" and a["incident"]), None)
    if not actor:
        return []
    facts = answers["facts"].get(actor["id"], {})
    domain = facts.get("domain")
    src, dst = facts.get("source", {}).get("ip"), facts.get("destination", {}).get("ip")
    if not (domain and src and dst):
        return []
    return [_rule(SID_IT_BASE + 100, f"{_addresses([src])} any -> {_addresses([dst])} any",
                  f"PCAPFORGE IT HTTPS beaconing: periodic TLS check-in to {domain}",
                  f'flow:to_server; tls.sni; content:"{domain}"; nocase; endswith;',
                  "mitre_attack T1071.001, mitre_attack T1573", proto="tls",
                  purpose=(f"A TLS ClientHello to {domain} from the beaconing workstation. Benign browsing on "
                           "this site goes to the intranet site names; a steady cadence of check-ins to this "
                           "one external name is the beacon."))]


def _it_scan_auth_rules(answers: dict) -> list[Rule]:
    """Kerberos pre-authentication failures of the scan-and-brute-force incident
    (it-scan-auth-failures): a KRB-ERROR with KDC_ERR_PREAUTH_FAILED (24) is a wrong password. The
    office baseline never fails pre-authentication, so the rule is inert on it."""
    if not any(a["type"] == "kerberos.bruteforce" and a["incident"] for a in answers["actors"]):
        return []
    return [_rule(SID_IT_BASE + 200, "any any -> any any",
                  "PCAPFORGE IT Kerberos pre-authentication failure (KDC_ERR_PREAUTH_FAILED) - possible password guessing",
                  "krb5_err_code:24;", "mitre_attack T1110, mitre_attack T1110.003",
                  "A Kerberos AS-REQ failed pre-authentication (a wrong password). A burst of these from one "
                  "source is password guessing (one account) or spraying (many accounts).", proto="krb5")]


def _it_kerberoasting_rules(answers: dict) -> list[Rule]:
    """The Kerberoasting incident (it-kerberoasting): a Kerberos TGS-REQ offering RC4-HMAC (etype 23)
    as its only encryption type. Windows clients always offer AES first, so the RC4-only etype list
    of a roasting request never appears in the office baseline. The content matches the DER encoding
    of a KDC-REQ-BODY etype field holding the single INTEGER 23 (|a8 05 30 03 02 01 17|)."""
    if not any(a["type"] == "kerberos.roast" and a["incident"] for a in answers["actors"]):
        return []
    return [_rule(SID_IT_BASE + 500, "any any -> any 88",
                  "PCAPFORGE IT Kerberoasting: TGS-REQ requesting RC4-HMAC (etype 23) only",
                  'flow:to_server; content:"|a8 05 30 03 02 01 17|";',
                  "mitre_attack T1558.003", proto="tcp",
                  purpose=("A Kerberos TGS-REQ whose only offered encryption type is RC4-HMAC (etype 23). "
                           "Windows clients request AES; a run of RC4-only service-ticket requests from one "
                           "host is Kerberoasting (bulk service-ticket requests for offline cracking)."))]


def _it_ldap_recon_rules(answers: dict) -> list[Rule]:
    """The LDAP reconnaissance incident (it-ldap-reconnaissance): cleartext (unsealed) LDAP
    searchRequests whose filter asks for the accounts with a service principal name or the protected
    (adminCount=1) accounts - the tell-tale filters of AD reconnaissance tooling. The office
    baseline's LDAP is Kerberos-sealed, so these attribute names never appear in clear on it and the
    rules are inert; a sealed (hard) run shows the volume tell in the flow / LDAP-session counts
    instead. The content matches the DER of a present filter ([87] length-prefixed attribute) and of
    the (adminCount=1) equality (|04 0a|adminCount|04 01 31|)."""
    if not any(a["type"] == "ldap.recon" and a["incident"] for a in answers["actors"]):
        return []
    return [
        _rule(SID_IT_BASE + 700, "$HOME_NET any -> any 389",
              "PCAPFORGE IT LDAP reconnaissance: servicePrincipalName enumeration over cleartext LDAP",
              'flow:to_server,established; content:"|87 14|servicePrincipalName";',
              "mitre_attack T1087.002, mitre_attack T1558.003", proto="tcp",
              purpose=("An unsealed LDAP searchRequest with a present filter on servicePrincipalName: "
                       "enumerating the accounts that carry an SPN (a Kerberoasting target list). A "
                       "workstation reads the directory only over Kerberos-sealed LDAP.")),
        _rule(SID_IT_BASE + 701, "$HOME_NET any -> any 389",
              "PCAPFORGE IT LDAP reconnaissance: adminCount=1 enumeration over cleartext LDAP",
              'flow:to_server,established; content:"|04 0a|adminCount|04 01 31|";',
              "mitre_attack T1087.002, mitre_attack T1069.002", proto="tcp",
              purpose=("An unsealed LDAP searchRequest for the protected (adminCount=1) accounts: "
                       "enumerating the privileged principals of the domain.")),
    ]


def _it_bulk_upload_rules(answers: dict) -> list[Rule]:
    """The bulk upload of the exfiltration-equivalent incident (it-bulk-upload): a plain-HTTP POST
    (easy) or a TLS session (medium/hard) carrying a large upload to the external file host. Both
    rules name the external sink's address and the TLS one its SNI, so they are inert on every other
    site and the office baseline, which never talks to it."""
    actor = next((a for a in answers["actors"] if a["type"] == "http.uploader" and a["incident"]), None)
    sinks = [a for a in answers["actors"] if a["type"] == "http.sink"]
    if not actor or not sinks:
        return []
    ips = host_ips(answers)
    dst = _addresses([ips[h] for a in sinks for h in a["hosts"]])
    domain = answers["facts"].get(actor["id"], {}).get("domain")
    rules = [_rule(SID_IT_BASE + 400, f"$HOME_NET any -> {dst} any",
                   "PCAPFORGE IT bulk HTTP upload (POST) to an external file host",
                   'flow:to_server,established; http.method; content:"POST";',
                   "mitre_attack T1048.003, mitre_attack T1567", proto="http",
                   purpose=("A plain-HTTP POST to the external file host: a bulk upload in clear text "
                            "(obvious file name and Content-Type)."))]
    if domain:
        rules.append(_rule(SID_IT_BASE + 401, f"$HOME_NET any -> {dst} any",
                           f"PCAPFORGE IT bulk data upload over TLS to {domain}",
                           f'flow:to_server; tls.sni; content:"{domain}"; nocase;',
                           "mitre_attack T1048, mitre_attack T1567", proto="tls",
                           purpose=(f"A TLS session to {domain} (the external file host). The upload is "
                                    "visible only as TLS record sizes; its volume shows as bytes_out >> "
                                    "bytes_in in the flow summaries.")))
    return rules


def _it_dns_tunnel_sigma(answers: dict) -> list[dict]:
    """Sigma over the dns dataset for the DNS-tunnelling incident: a long base32-like leading label
    under the one fictional parent domain."""
    actor = next((a for a in answers["actors"] if a["type"] == "dns.tunnel" and a["incident"]), None)
    if not actor:
        return []
    facts = answers["facts"].get(actor["id"], {})
    parent, label_len = facts.get("domain"), facts.get("label_len")
    if not parent or not label_len:
        return []
    detection = {"selection": {"query|endswith": f".{parent}",
                               "query|re": f"^[a-z2-7]{{{label_len},}}\\."},
                 "condition": "selection"}
    return [_sigma(answers, key="it-dns-tunnelling-long-labels",
                   title=f"DNS tunnelling: long encoded labels under {parent}",
                   description=(f"DNS queries whose leading label is {label_len}+ base32-like characters under "
                                f"the single parent {parent}: one host encoding data into subdomains (DNS-based "
                                "data transfer / exfiltration over DNS)."),
                   service="dns", level="high", detection=detection,
                   tags=["attack.exfiltration", "attack.command_and_control", "attack.t1048.003", "attack.t1071.004"],
                   falsepositives=["A chatty client that encodes long tokens into subdomains (some AV or CDN clients)."],
                   fields=["ts", "src", "dest", "query", "qtype", "query_frame"])]


def _it_scan_auth_sigma(answers: dict) -> list[dict]:
    """Sigma for the scan-and-brute-force incident (it-scan-auth-failures): Kerberos
    pre-authentication failures correlated into brute force, and a TCP service-port sweep."""
    rules: list[dict] = []
    if any(a["type"] == "kerberos.bruteforce" and a["incident"] for a in answers["actors"]):
        rules.append(_sigma(
            answers, key="kerberos-preauth-failure", title="Kerberos pre-authentication failure",
            description="A Kerberos AS-REQ rejected with KDC_ERR_PREAUTH_FAILED (24): a wrong pre-authentication "
                        "secret (a bad password). Base rule of the brute-force correlation.",
            service="kerberos", level="low",
            detection={"selection": {"request_type": "AS", "result": "error", "error_code": 24}, "condition": "selection"},
            tags=["attack.t1110"],
            falsepositives=["A user mistyping a password; a service with a stale cached credential."],
            fields=None, name="pcapforge_kerberos_preauth_failure"))
        rules.append(_correlation(
            answers, key="kerberos-brute-force", title="Kerberos password guessing or spraying from one host",
            description="At least five Kerberos pre-authentication failures from one source within five minutes: "
                        "password guessing against one account, or spraying one guess across many accounts.",
            level="high", kind="value_count", rules=["pcapforge_kerberos_preauth_failure"], group_by=["src"],
            timespan="5m", condition={"gte": 5}, field="client", generate=False,
            tags=["attack.t1110", "attack.t1110.001", "attack.t1110.003"],
            falsepositives=["A misconfigured service account retrying a stale password."]))
    if any(a["type"] == "tcp.scanner" and a["incident"] for a in answers["actors"]):
        rules.append(_sigma(
            answers, key="tcp-service-probe", title="TCP connection to a server service port",
            description="A TCP connection (attempt) to a server-subnet service port (base rule of the "
                        "port-sweep correlation).",
            service="flows", level="informational",
            detection={"selection": {"transport": "tcp", "dest_port": [22, 135, 139, 3389, 88, 389, 445, 443, 8530]},
                       "condition": "selection"},
            tags=["attack.t1046"], falsepositives=["See the port-sweep correlation."],
            fields=None, name="pcapforge_tcp_service_probe"))
        rules.append(_correlation(
            answers, key="tcp-port-sweep", title="TCP port sweep of the server subnet",
            description="One host opened or tried at least five different service ports within ten minutes: a TCP "
                        "port sweep (network service discovery).",
            level="high", kind="value_count", rules=["pcapforge_tcp_service_probe"], group_by=["src"],
            timespan="10m", condition={"gte": 5}, field="dest_port", generate=False, tags=["attack.t1046"],
            falsepositives=["A vulnerability scan or asset inventory run by IT."]))
    return rules


def _it_kerberoasting_sigma(answers: dict) -> list[dict]:
    """Sigma for the Kerberoasting incident (it-kerberoasting): RC4-first service-ticket requests
    correlated into a bulk roast from one host."""
    if not any(a["type"] == "kerberos.roast" and a["incident"] for a in answers["actors"]):
        return []
    return [
        _sigma(answers, key="kerberos-rc4-service-ticket",
               title="Kerberos service ticket requested with RC4",
               description="A Kerberos TGS-REQ whose preferred (first-listed) encryption type is RC4-HMAC "
                           "(etype 23). Windows clients offer AES first; an RC4-first service-ticket request "
                           "is the signature of a Kerberoasting tool. Base rule of the correlation.",
               service="kerberos", level="medium",
               detection={"selection": {"request_type": "TGS", "etype_first": 23}, "condition": "selection"},
               tags=["attack.t1558.003", "attack.credential_access"],
               falsepositives=["A legacy application or appliance that still requests RC4 service tickets."],
               fields=None, name="pcapforge_kerberos_rc4_service_ticket"),
        _correlation(answers, key="kerberoasting",
                     title="Kerberoasting: many RC4 service tickets from one host",
                     description="One host requested RC4-HMAC service tickets for at least five distinct "
                                 "services (SPNs) within an hour: Kerberoasting. The office baseline requests "
                                 "AES service tickets only.",
                     level="high", kind="value_count", rules=["pcapforge_kerberos_rc4_service_ticket"],
                     group_by=["src"], timespan="1h", condition={"gte": 5}, field="service", generate=False,
                     tags=["attack.t1558.003", "attack.credential_access"],
                     falsepositives=["A vulnerability scanner enumerating Kerberos service tickets."]),
    ]


def _modbus_rules(answers: dict) -> list[Rule]:
    ips = host_ips(answers)
    names = {h["id"]: h["name"] for h in answers["topology"]["hosts"]}
    servers = [a for a in answers["actors"] if a["type"] == "modbus.server"]
    plcs = [ips[h] for a in servers for h in a["hosts"]]
    if not plcs:
        return []
    writers = [ips[h] for h in _hosts(answers, WRITER_TYPES)]
    clients = [ips[h] for h in _hosts(answers, CLIENT_TYPES)]
    to_plcs = f"{_addresses(plcs)} {MODBUS_PORT}"

    rules = []
    if writers:
        rules.append(_rule(
            SID_BASE + 1, f"!{_addresses(writers)} any -> {to_plcs}",
            "PCAPFORGE OT Modbus write from a host not approved to change PLC parameters",
            "modbus: access write;", "mitre_ics T0855",
            "Any Modbus write (functions 5, 6, 15, 16, 22, 23) from outside the approved writers: "
            + ", ".join(names[h] for h in _hosts(answers, WRITER_TYPES)) + "."))
    else:
        rules.append(_rule(
            SID_BASE + 1, f"any any -> {to_plcs}",
            "PCAPFORGE OT Modbus write to a PLC (site has no approved writer)",
            "modbus: access write;", "mitre_ics T0855",
            "Any Modbus write: this site has no approved writer."))
    source = f"!{_addresses(clients)}" if clients else "any"
    rules.append(_rule(
        SID_BASE + 2, f"{source} any -> {to_plcs}",
        "PCAPFORGE OT Modbus device identification from a host that is not a SCADA client",
        "modbus: function 43;", "mitre_ics T0888",
        "Read Device Identification (function 43) from a host other than "
        + (", ".join(names[h] for h in _hosts(answers, CLIENT_TYPES)) or "any approved client") + "."))

    sid = SID_BAND_BASE
    for actor in sorted(servers, key=lambda a: a["id"]):
        profile = ProcessProfile(answers["facts"][actor["id"]]["process"])
        dest = f"{_addresses([ips[h] for h in actor['hosts']])} {MODBUS_PORT}"
        for point in profile.table("holding"):
            if not (point.writable and point.normal):
                continue
            lo, hi = point.normal
            unit = f" {point.unit}" if point.unit else ""
            band = f"{_number(lo)}-{_number(hi)}{unit}"
            metadata = f"mitre_ics T0836, pcapforge_point {point.name}"
            if point.type == "float32":
                for side, limit, matches in (("above", hi, _float_above(point, hi)),
                                             ("below", lo, _float_below(point, lo) if lo > 0 else [])):
                    for options in matches:
                        rules.append(_rule(
                            sid, f"any any -> {dest}",
                            f"PCAPFORGE OT {point.name} written {side} normal band "
                            f"(holding {point.address} float32 {'>' if side == 'above' else '<'} {_number(limit)}{unit})",
                            options, metadata,
                            f"{point.name} (holding {point.address}-{point.address + 1}, FLOAT32 "
                            f"{'ABCD' if point.word_order == 'big' else 'CDAB'}, band {band}) set {side} "
                            f"{_number(limit)} by a Write Multiple Registers request starting at the point."))
                        sid += 1
                continue
            lo_raw = math.ceil(lo * point.scale - 1e-9)
            hi_raw = math.floor(hi * point.scale + 1e-9)
            # Suricata numbers Modbus addresses from 1: wire address + 1.
            where = f"modbus: access write holding, address {point.address + 1}"
            if hi_raw < 65535:
                rules.append(_rule(
                    sid, f"any any -> {dest}",
                    f"PCAPFORGE OT {point.name} written above normal band "
                    f"(holding {point.address} raw > {hi_raw} = {_number(hi)}{unit})",
                    f"{where}, value >{hi_raw};", metadata,
                    f"{point.name} (holding {point.address}, band {band}) set above {hi_raw} raw."))
            sid += 1
            if lo_raw > 0:
                rules.append(_rule(
                    sid, f"any any -> {dest}",
                    f"PCAPFORGE OT {point.name} written below normal band "
                    f"(holding {point.address} raw < {lo_raw} = {_number(lo)}{unit})",
                    f"{where}, value <{lo_raw};", metadata,
                    f"{point.name} (holding {point.address}, band {band}) set below {lo_raw} raw."))
            sid += 1
    return rules


# A float32 setpoint cannot be compared with Suricata's `modbus: ... value` (one 16-bit register),
# and Suricata does not combine the `modbus` keyword with payload keywords. These rules test the
# request bytes instead: a Write Multiple Registers (function 16, MBAP offset 7) of two registers
# starting at the point, whose data (offset 13) holds the float. For non-negative IEEE 754 values
# the bit pattern orders like the value, so an unsigned comparison against the band limit's bit
# pattern is exact; CDAB (low word first) needs the high word compared first, then the low word.
def _float_request(point) -> str:
    return f'content:"|10|"; offset:7; depth:1; byte_test:2,=,{point.address},8; byte_test:2,=,2,10;'


def _float_words(limit: float) -> tuple[int, int, int]:
    bits = struct.unpack(">I", struct.pack(">f", limit))[0]
    return bits, bits >> 16, bits & 0xFFFF


def _float_above(point, limit: float) -> list[str]:
    bits, high, low = _float_words(limit)
    base = _float_request(point)
    if point.word_order == "big":
        return [f"{base} byte_test:4,>,{bits},13;"]
    return [f"{base} byte_test:2,>,{high},15;",
            f"{base} byte_test:2,=,{high},15; byte_test:2,>,{low},13;"]


def _float_below(point, limit: float) -> list[str]:
    # Negative values have the sign bit set and compare as large unsigned numbers: not matched.
    bits, high, low = _float_words(limit)
    base = _float_request(point)
    if point.word_order == "big":
        return [f"{base} byte_test:4,<,{bits},13;"]
    return [f"{base} byte_test:2,<,{high},15;",
            f"{base} byte_test:2,=,{high},15; byte_test:2,<,{low},13;"]


# --- telecontrol / building / packaging protocols ---------------------------------------
# DNP3 and EtherNet/IP use Suricata's parsers (dnp3_func, cip_service; both parsers are
# disabled in the stock suricata.yaml). Suricata has no IEC 104 or BACnet parser, so those rules
# test the payload: an IEC 104 I-frame (start 0x68, control octet 1 bit 0 clear) has its type id
# at offset 6; a BACnet/IP Original-Unicast/Broadcast-NPDU without network-layer addressing has
# the APDU at offset 6 and a confirmed request's service choice at offset 9.

def _source(approved: list[str]) -> str:
    return f"!{_addresses(approved)}" if approved else "any"


def _who(names: list[str], role: str) -> str:
    return f"a host other than the {role} ({', '.join(names)})" if names else f"any host (the site has no {role})"


def _ot_rules(answers: dict) -> list[Rule]:
    ips = host_ips(answers)
    names = {h["id"]: h["name"] for h in answers["topology"]["hosts"]}
    rules: list[Rule] = []

    def role(types: tuple[str, ...]) -> tuple[list[str], list[str]]:
        hosts = _hosts(answers, types)
        return [ips[h] for h in hosts], [names[h] for h in hosts]

    rtus, _ = role(IEC104_SERVER_TYPES)
    if rtus:
        masters, who = role(IEC104_MASTER_TYPES)
        head = f"{_source(masters)} any -> {_addresses(rtus)} {IEC104_PORT}"
        i_frame = 'content:"|68|"; depth:1; byte_test:1,!&,1,2;'
        for offset, (low, high, what, msg, tag) in enumerate((
                (45, 64, "process command (type 45-64: single / double / regulating step, setpoint, bitstring)",
                 "IEC 104 control command", "T0855"),
                (100, 101, "interrogation (C_IC_NA_1 100) or counter interrogation (C_CI_NA_1 101)",
                 "IEC 104 interrogation", "T0861"),
                (105, 105, "reset process command (C_RP_NA_1 105)", "IEC 104 reset process command", "T0816"))):
            test = (f"byte_test:1,=,{low},6;" if low == high
                    else f"byte_test:1,>=,{low},6; byte_test:1,<=,{high},6;")
            rules.append(_rule(
                SID_OT_BASE + offset, head, f"PCAPFORGE OT {msg} from a host other than the SCADA master",
                f"{i_frame} {test}", f"mitre_ics {tag}",
                f"IEC 104 {what} sent to an RTU by {_who(who, 'SCADA master')}; only the first APDU of a "
                "TCP segment is tested.", proto="tcp"))

    outstations, _ = role(DNP3_SERVER_TYPES)
    if outstations:
        masters, who = role(DNP3_MASTER_TYPES)
        head = f"{_source(masters)} any -> {_addresses(outstations)} {DNP3_PORT}"
        for offset, (function, label, tag) in enumerate((
                ("select", "SELECT (3)", "T0855"), ("operate", "OPERATE (4)", "T0855"),
                ("direct_operate", "DIRECT_OPERATE (5)", "T0855"),
                ("direct_operate_nr", "DIRECT_OPERATE_NR (6)", "T0855"), ("write", "WRITE (2)", "T0836"),
                ("cold_restart", "COLD_RESTART (13)", "T0816"), ("warm_restart", "WARM_RESTART (14)", "T0816"),
                ("disable_unsolicited", "DISABLE_UNSOLICITED (21)", "T0815"))):
            rules.append(_rule(
                SID_OT_BASE + 10 + offset, head, f"PCAPFORGE OT DNP3 {label} from a host other than the master",
                f"dnp3_func:{function};", f"mitre_ics {tag}",
                f"DNP3 {label} request to an outstation from {_who(who, 'DNP3 master')}.", proto="dnp3"))

    controllers, _ = role(BACNET_SERVER_TYPES)
    if controllers:
        clients, who = role(BACNET_CLIENT_TYPES)
        head = f"{_source(clients)} any -> any {BACNET_PORT}"
        apdu = ('content:"|81|"; depth:1; byte_test:1,>=,10,1; byte_test:1,<=,11,1; byte_test:1,=,1,4; '
                "byte_test:1,!&,0xA8,5; byte_test:1,<,16,6; byte_test:1,!&,8,6;")
        for offset, (test, label, tag) in enumerate((
                ("byte_test:1,>=,15,9; byte_test:1,<=,16,9;", "WriteProperty / WritePropertyMultiple", "T0855"),
                ("byte_test:1,=,17,9;", "DeviceCommunicationControl", "T0815"),
                ("byte_test:1,=,20,9;", "ReinitializeDevice", "T0816"))):
            rules.append(_rule(
                SID_OT_BASE + 20 + offset, head, f"PCAPFORGE OT BACnet {label} from an unapproved host",
                f"{apdu} {test}", f"mitre_ics {tag}",
                f"BACnet {label} request from {_who(who, 'BMS workstations')} (local BACnet/IP NPDUs without "
                "network-layer addressing).", proto="udp"))
        rules.append(_rule(
            SID_OT_BASE + 23, head, "PCAPFORGE OT BACnet Register-Foreign-Device from an unapproved host",
            'content:"|81 05|"; depth:2;', "mitre_ics T0886",
            f"BVLC Register-Foreign-Device from {_who(who, 'BMS workstations')}: a foreign device receives "
            "every broadcast of the BACnet network through the BBMD.", proto="udp"))
        for offset, (code, label) in enumerate(((1, "Write-Broadcast-Distribution-Table"),
                                                (8, "Delete-Foreign-Device-Table-Entry"))):
            rules.append(_rule(
                SID_OT_BASE + 24 + offset, f"any any -> any {BACNET_PORT}",
                f"PCAPFORGE OT BACnet {label} (BBMD table change)",
                f'content:"|81 {code:02X}|"; depth:2;', "mitre_ics T0814",
                f"BVLC {label} from any host: changes how the BBMDs forward broadcasts. Never sent in "
                "normal operation of this site.", proto="udp"))

    targets, _ = role(ENIP_TARGET_TYPES)
    if targets:
        originators, who = role(ENIP_ORIGINATOR_TYPES)
        head = f"{_source(originators)} any -> {_addresses(targets)} {ENIP_PORT}"
        for offset, (service, label, tag) in enumerate((
                (0x4D, "Write_Tag", "T0855"), (0x53, "Write_Tag_Fragmented", "T0855"),
                (0x10, "Set_Attribute_Single", "T0836"), (0x02, "Set_Attributes_All", "T0836"),
                (0x04, "Set_Attribute_List", "T0836"), (0x05, "Reset", "T0816"),
                (0x54, "Forward_Open", "T0886"), (0x5B, "Large_Forward_Open", "T0886"))):
            option = f"cip_service:{service},6;" if service in (0x54, 0x5B) else f"cip_service:{service};"
            rules.append(_rule(
                SID_OT_BASE + 30 + offset, head, f"PCAPFORGE OT CIP {label} from an unapproved host",
                option, f"mitre_ics {tag}",
                f"CIP {label} (service 0x{service:02X}) to an EtherNet/IP device from "
                f"{_who(who, 'HMI / historian / scanner originators')}.", proto="enip"))
    return rules


# --- Sigma --------------------------------------------------------------------------
# SIEM-agnostic detections over the exported JSON-lines logs (one rule file per detection,
# https://sigmahq.io). The log source is the pcapforge SIEM export: `product: pcapforge`,
# `service` the dataset (e.g. `modbus`, `dhcp`), matching the sourcetype `pcapforge:<dataset>`
# the hunting guide loads the files under. Field names are the JSONL keys, so these run as
# written once the export is indexed; they are not tied to Splunk or Elastic.

SIGMA_NAMESPACE = uuid.UUID("b5e7c6d2-0a4f-5e8b-9c1d-7f3a2e6b4c80")  # stable rule ids per site+key


def _sigma_id(answers: dict, key: str) -> str:
    sc = answers["scenario"]
    return str(uuid.uuid5(SIGMA_NAMESPACE, f"{sc['id']}|{sc['difficulty']}|{sc['seed']}|{key}"))


def _sigma(answers: dict, *, key: str, title: str, description: str, service: str, level: str,
           detection: dict, tags: list[str], falsepositives: list[str], fields: list[str] | None,
           name: str | None = None) -> dict:
    """A Sigma detection rule. Base rules of a correlation carry a ``name`` and no ``fields``
    (pySigma's Splunk backend cannot append a field table to a correlation query)."""
    return {
        "title": title,
        "id": _sigma_id(answers, key),
        **({"name": name} if name else {}),
        "status": "experimental",
        "description": description,
        "references": ["https://github.com/j3k01/PcapForge"],
        "author": "pcapforge",
        "date": answers.get("capture", {}).get("start", "1970-01-01T00:00:00Z")[:10],
        "logsource": {"product": "pcapforge", "service": service},
        "detection": detection,
        **({"fields": fields} if fields else {}),
        "falsepositives": falsepositives,
        "level": level,
        "tags": tags,
    }


def _correlation(answers: dict, *, key: str, title: str, description: str, level: str, kind: str,
                 rules: list[str], group_by: list[str], timespan: str, condition: dict, generate: bool,
                 tags: list[str], falsepositives: list[str], field: str | None = None) -> dict:
    """A Sigma correlation rule (Sigma 2.0) over the named base rules. ``generate`` says whether
    the base rules are also converted on their own (true for detections that stand alone)."""
    correlation = {"type": kind, "rules": rules, "group-by": group_by, "timespan": timespan,
                   "generate": generate, "condition": {**({"field": field} if field else {}), **condition}}
    return {
        "title": title,
        "id": _sigma_id(answers, key),
        "status": "experimental",
        "description": description,
        "references": ["https://github.com/j3k01/PcapForge"],
        "author": "pcapforge",
        "date": answers.get("capture", {}).get("start", "1970-01-01T00:00:00Z")[:10],
        "correlation": correlation,
        "falsepositives": falsepositives,
        "level": level,
        "tags": tags,
    }


def _profile_points(answers: dict, servers: list[dict], table: str, predicate) -> list[str]:
    """Sorted names of the points of ``table`` in every PLC's register map that satisfy ``predicate``."""
    names = set()
    for actor in servers:
        profile = ProcessProfile(answers["facts"][actor["id"]]["process"])
        names.update(p.name for p in profile.table(table) if predicate(p))
    return sorted(names)


def _it_ldap_recon_sigma(answers: dict) -> list[dict]:
    """Sigma over the ldap dataset for the reconnaissance incident (it-ldap-reconnaissance): a
    cleartext LDAP searchRequest whose filter targets service principal names, the protected
    (adminCount=1) accounts or trusted domains - the tell-tale directory-enumeration queries. The
    office baseline reads the directory only over sealed LDAP, so no such filter is ever visible."""
    if not any(a["type"] == "ldap.recon" and a["incident"] for a in answers["actors"]):
        return []
    detection = {"selection": {"operation": "search_request",
                               "filter|contains": ["servicePrincipalName", "adminCount", "trustedDomain"]},
                 "condition": "selection"}
    return [_sigma(answers, key="it-ldap-reconnaissance-filters",
                   title="LDAP directory reconnaissance (SPN / adminCount / trust enumeration)",
                   description=("A cleartext LDAP searchRequest whose filter enumerates accounts with a "
                                "service principal name, the protected adminCount=1 accounts or the domain "
                                "trusts: Active Directory reconnaissance. A workstation reads the directory "
                                "only over Kerberos-sealed LDAP, so these filters never appear in clear."),
                   service="ldap", level="high", detection=detection,
                   tags=["attack.discovery", "attack.t1087.002", "attack.t1069.002", "attack.t1482"],
                   falsepositives=["A directory administration or audit tool that enumerates the directory "
                                   "over unsealed LDAP."],
                   fields=["ts", "src", "dest", "base", "filter", "entries", "request_frame"])]


def _it_https_beacon_sigma(answers: dict) -> list[dict]:
    """Sigma over the tls dataset for the beaconing incident (it-https-beaconing): TLS check-ins to
    the one fictional beacon domain from the beaconing host."""
    actor = next((a for a in answers["actors"] if a["type"] == "tls.beacon" and a["incident"]), None)
    if not actor:
        return []
    facts = answers["facts"].get(actor["id"], {})
    domain = facts.get("domain")
    src = facts.get("source", {}).get("ip")
    if not domain or not src:
        return []
    detection = {"selection": {"server_name": domain}, "condition": "selection"}
    return [_sigma(
        answers, key="it-https-beaconing", title=f"HTTPS beaconing to {domain}",
        description=(f"TLS sessions whose SNI is the single external name {domain}, contacted on a regular "
                     "cadence from one office workstation while its user is not browsing - the observable "
                     "pattern of command-and-control beaconing over HTTPS. Benign browsing on this site uses "
                     "the intranet site names."),
        service="tls", level="high", detection=detection,
        tags=["attack.command_and_control", "attack.t1071.001", "attack.t1573"],
        falsepositives=["A background service or updater that polls one external endpoint on a timer."],
        fields=["ts", "src", "dest", "server_name", "ja4", "cert_issuer", "client_hello_frame"])]


def _it_volumetric_flood_sigma(answers: dict) -> list[dict]:
    """Sigma for the volumetric-flood incident (it-volumetric-flood): a correlation over the flows
    dataset that fires when many UDP datagrams reach one destination's sink port within a minute."""
    if not any(a["type"] == "sink.flood" and a["incident"] for a in answers["actors"]):
        return []
    ips = host_ips(answers)
    sinks = [ips[h] for a in answers["actors"] if a["type"] == "sink.server" for h in a["hosts"]]
    selection: dict = {"transport": "udp", "dest_port": 9}
    if sinks:
        selection["dest"] = sinks
    rules = [_sigma(answers, key="it-flood-udp-sink-datagram",
                    title="UDP datagram to the sink service (volumetric-flood base rule)",
                    description="A one-way UDP datagram to the sink (Discard, port 9), the base rule of the "
                                "volumetric-flood correlation.",
                    service="flows", level="informational",
                    detection={"selection": selection, "condition": "selection"},
                    tags=["attack.t1498", "attack.t1498.001"],
                    falsepositives=["See the volumetric-flood correlation."], fields=None,
                    name="pcapforge_it_flood_datagram")]
    rules.append(_correlation(
        answers, key="it-volumetric-flood", title="Volumetric UDP flood to a local sink service",
        description="At least 500 UDP datagrams reached one destination's sink port (9) within a minute: a "
                    "volumetric network flood (direct network flood). The office baseline sends nothing to "
                    "this port.",
        level="high", kind="event_count", rules=["pcapforge_it_flood_datagram"], group_by=["dest"],
        timespan="1m", condition={"gte": 500}, generate=False, tags=["attack.t1498", "attack.t1498.001"],
        falsepositives=["A legitimate high-rate telemetry or backup stream to the collector."]))
    return rules


def _it_bulk_upload_sigma(answers: dict) -> list[dict]:
    """Sigma over the flows dataset for the bulk-upload incident (it-bulk-upload): TCP flows to the
    external file host, where one office host sends far more than it receives."""
    actor = next((a for a in answers["actors"] if a["type"] == "http.uploader" and a["incident"]), None)
    sinks = [a for a in answers["actors"] if a["type"] == "http.sink"]
    if not actor or not sinks:
        return []
    ips = host_ips(answers)
    dst = [ips[h] for a in sinks for h in a["hosts"]]
    return [_sigma(
        answers, key="it-bulk-upload", title="Large data upload to an external file host",
        description=("TCP flows from an office host to an external file host (dest outside the site "
                     "subnets), where the host sends far more than it receives (bytes_out >> bytes_in): "
                     "a bulk upload / possible data exfiltration. Downloads such as browsing and Windows "
                     "Update have the opposite ratio."),
        service="flows", level="high",
        detection={"selection": {"dest": dst, "transport": "tcp"}, "condition": "selection"},
        tags=["attack.exfiltration", "attack.t1048", "attack.t1567"],
        falsepositives=["A sanctioned backup or large file transfer to an approved external service."],
        fields=["ts", "src", "dest", "dest_port", "bytes_out", "bytes_in", "app"])]


def sigma_rules(answers: dict) -> list[dict]:
    """Sigma detections derived from the site model, one dict per rule (same roles as the
    Suricata rules)."""
    return (_modbus_sigma_rules(answers) + _ot_sigma_rules(answers) + _it_dns_tunnel_sigma(answers)
            + _it_scan_auth_sigma(answers) + _it_https_beacon_sigma(answers)
            + _it_volumetric_flood_sigma(answers)
            + _it_bulk_upload_sigma(answers) + _it_kerberoasting_sigma(answers) + _it_smb_lateral_sigma(answers) + _it_ldap_recon_sigma(answers) + _it_rogue_dhcp_sigma(answers) + _it_ot_pivot_sigma(answers) + _it_ot_zone_sigma(answers))


def _it_smb_lateral_sigma(answers: dict) -> list[dict]:
    """Sigma for the SMB lateral-movement incident (it-smb-lateral-movement): tree connects to the
    ADMIN$ administrative share, correlated into one source reaching many workstations."""
    if not any(a["type"] == "smb.lateral" and a["incident"] for a in answers["actors"]):
        return []
    rules = [_sigma(
        answers, key="smb-admin-share-tree-connect", title="SMB tree connect to an ADMIN$ administrative share",
        description="An SMB tree connect to a host's ADMIN$ administrative share. On this LAN clients only "
                    "mount the DC's SYSVOL, so this is the base rule of the lateral-movement correlation.",
        service="smb", level="medium",
        detection={"selection": {"command": "tree_connect", "tree|endswith": "ADMIN$"}, "condition": "selection"},
        tags=["attack.t1021.002", "attack.lateral_movement"],
        falsepositives=["An administrator managing a workstation over its admin share."],
        fields=None, name="pcapforge_smb_admin_share_tree_connect")]
    rules.append(_correlation(
        answers, key="smb-admin-share-fanout", title="One host reaching the admin shares of many workstations",
        description="One source opened the ADMIN$ administrative share of at least three workstations within "
                    "ten minutes: SMB lateral movement with a reused domain credential.",
        level="high", kind="value_count", rules=["pcapforge_smb_admin_share_tree_connect"], group_by=["src"],
        timespan="10m", condition={"gte": 3}, field="dest", generate=False,
        tags=["attack.t1021.002", "attack.t1078.002", "attack.lateral_movement"],
        falsepositives=["A management tool or script that touches many machines' admin shares."]))
    return rules


def _it_rogue_dhcp_sigma(answers: dict) -> list[dict]:
    """Sigma over the dhcp dataset for the rogue-DHCP incident (it-rogue-dhcp): a DHCP Offer or ACK
    whose server identifier (option 54) is not the approved DHCP server."""
    if not any(a["type"] == "dhcp.server" and a["incident"] for a in answers["actors"]):
        return []
    legit = next((a for a in answers["actors"] if a["type"] == "dhcp.server" and not a["incident"]), None)
    facts = answers["facts"].get(legit["id"], {}) if legit else {}
    approved = (facts.get("hosts") or [{}])[0].get("ip")
    if not approved:
        return []
    detection = {"selection": {"message": ["offer", "ack"]},
                 "filter_approved": {"server_id": approved},
                 "condition": "selection and not filter_approved"}
    return [_sigma(answers, key="it-rogue-dhcp-server", title="Rogue DHCP server on the LAN",
                   description=("A DHCP Offer or ACK whose server identifier (option 54) is not the approved "
                                "DHCP server: a second, unauthorised DHCP server answering clients on the office "
                                "segment (DHCP spoofing / adversary-in-the-middle)."),
                   service="dhcp", level="high", detection=detection,
                   tags=["attack.t1557", "attack.t1557.003"],
                   falsepositives=["A newly deployed or misconfigured DHCP server IT has not yet documented."],
                   fields=["ts", "src", "server_id", "eth_src", "assigned_addr", "router", "dns_servers", "frame"])]


def _it_ot_pivot_sigma(answers: dict) -> list[dict]:
    """Sigma over the flows dataset for the IT-to-OT pivot (it-ot-pivot): a TCP flow that reaches a
    host on the OT control subnet from a source that is not itself on the control network (the office
    host routed in through the IT/OT firewall). Control-internal polling is excluded by the source
    filter, so the rule fires only on the cross-zone connections."""
    found = _it_ot_pivot_host_subnets(answers)
    if found is None:
        return []
    _, _, _, control_ips = found
    detection = {"selection": {"dest": control_ips}, "internal": {"src": control_ips},
                 "condition": "selection and not internal"}
    return [_sigma(
        answers, key="it-ot-pivot-crosszone",
        title="Connection from the office LAN into the OT control network",
        description="A TCP flow to a host on the OT control subnet from a source outside that subnet: an "
                    "office-LAN host reaching the control network across the IT/OT firewall. Only the OT "
                    "clients on the control network should talk to the PLCs.",
        service="flows", level="high", detection=detection,
        tags=["attack.t1046", "attack.t0886", "attack.t0859"],
        falsepositives=["A new OT engineering or jump host that the firewall policy legitimately allows."],
        fields=["ts", "src", "dest", "dest_port", "transport", "state"])]


def _it_ot_zone_sigma(answers: dict) -> list[dict]:
    """Sigma over the flows dataset for the combined IT+OT baseline's zone policy (reusable by any
    incident layered on it-ot-baseline-operations): a flow into the control network from a source that
    is neither on the control network nor in the DMZ, and an RDP flow into the control network from
    anything but the DMZ jump host. Both are inert on this baseline."""
    found = _it_ot_zone(answers)
    if found is None:
        return []
    _office_cidr, _dmz_cidr, _control_cidr, jump_ips, dmz_ips, control_ips = found
    into_control = {"selection": {"dest": control_ips}, "internal": {"src": control_ips + dmz_ips},
                    "condition": "selection and not internal"}
    rdp_into_control = {"selection": {"dest": control_ips, "dest_port": 3389},
                        "approved": {"src": jump_ips}, "condition": "selection and not approved"}
    return [
        _sigma(answers, key="it-ot-zone-into-control",
               title="Connection into the OT control network from outside the control zone and DMZ",
               description="A flow to a host on the OT control network from a source that is neither on the "
                           "control network nor in the industrial DMZ: an IT / office host reaching the plant "
                           "directly. Only DMZ hosts (the jump host, the historian replica) bridge into control.",
               service="flows", level="high", detection=into_control,
               tags=["attack.t1046", "attack.t0886", "attack.t0859"],
               falsepositives=["A new DMZ relay or management host the segmentation policy legitimately allows."],
               fields=["ts", "src", "dest", "dest_port", "transport", "state"]),
        _sigma(answers, key="it-ot-zone-rdp-into-control",
               title="RDP into the OT control network from a host other than the DMZ jump host",
               description="A Remote Desktop flow (destination port 3389) into the OT control network from a "
                           "source other than the DMZ jump host. The jump host is the only approved RDP origin "
                           "for the engineering workstation; any other source is out of policy.",
               service="flows", level="high", detection=rdp_into_control,
               tags=["attack.t1021.001", "attack.t0886"],
               falsepositives=["A second, newly authorised jump host or a maintenance laptop in the DMZ."],
               fields=["ts", "src", "dest", "dest_port", "transport", "state"])]


def _ot_sigma_rules(answers: dict) -> list[dict]:
    """Commands, polls and connection set-up of the telecontrol / building / packaging protocols
    from hosts other than the approved masters (non-incident clients of the protocol)."""
    ips = host_ips(answers)
    names = {h["id"]: h["name"] for h in answers["topology"]["hosts"]}
    rules: list[dict] = []

    def role(types: tuple[str, ...]) -> tuple[list[str], str]:
        hosts = _hosts(answers, types)
        return [ips[h] for h in hosts], ", ".join(names[h] for h in hosts)

    def unexpected(*, key: str, title: str, what: str, service: str, level: str, selection: dict,
                   approved: list[str], who: str, label: str, tags: list[str], falsepositives: list[str],
                   fields: list[str]) -> None:
        if approved:
            detection = {"selection": selection, "approved": {"src": approved},
                         "condition": "selection and not approved"}
            description = f"{what} from a host other than the {label}: {who}."
        else:
            detection = {"selection": selection, "condition": "selection"}
            description = f"{what}. This site has no {label}, so every one is notable."
        rules.append(_sigma(answers, key=key, title=title, description=description, service=service,
                            level=level, detection=detection, tags=tags, falsepositives=falsepositives,
                            fields=fields))

    if _hosts(answers, IEC104_SERVER_TYPES):
        masters, who = role(IEC104_MASTER_TYPES)
        fields = ["ts", "src", "dest", "type", "cause", "ioa", "select", "frame"]
        unexpected(key="iec104-command-from-unexpected-host",
                   title="IEC 104 control command from a host other than the SCADA master",
                   what="An IEC 60870-5-104 process command (type 45-64: single / double command, regulating "
                        "step, setpoint, bitstring; select or execute) sent to an RTU",
                   service="iec104", level="high", selection={"category": "control", "dest_port": IEC104_PORT},
                   approved=masters, who=who, label="approved SCADA master(s)", tags=["attack.t0855"],
                   falsepositives=["A second control centre or a commissioning laptop not modelled as a master."],
                   fields=fields)
        unexpected(key="iec104-interrogation-from-unexpected-host",
                   title="IEC 104 interrogation or counter interrogation from an unexpected host",
                   what="An IEC 60870-5-104 general interrogation (C_IC_NA_1), counter interrogation (C_CI_NA_1), "
                        "read, clock synchronisation, test or reset process command (type 100-107) sent to an RTU",
                   service="iec104", level="medium",
                   selection={"type_id": list(range(100, 108)), "dest_port": IEC104_PORT},
                   approved=masters, who=who, label="approved SCADA master(s)", tags=["attack.t0861", "attack.t0801"],
                   falsepositives=["A protocol test set or gateway polling the RTU during maintenance."],
                   fields=fields)

    if _hosts(answers, DNP3_SERVER_TYPES):
        masters, who = role(DNP3_MASTER_TYPES)
        fields = ["ts", "src", "dest", "function", "objects", "point_index", "frame"]
        unexpected(key="dnp3-control-from-unexpected-host",
                   title="DNP3 control, write or restart from a host other than the master",
                   what="A DNP3 request that changes the outstation (select / operate / direct operate, write, "
                        "cold / warm restart, application control, enable / disable unsolicited, assign class, "
                        "time set)",
                   service="dnp3", level="high",
                   selection={"function_code": DNP3_CONTROL_FUNCTIONS, "dest_port": DNP3_PORT},
                   approved=masters, who=who, label="approved DNP3 master(s)",
                   tags=["attack.t0855", "attack.t0816", "attack.t0815"],
                   falsepositives=["An engineering laptop configuring the RTAC, not modelled as a master."],
                   fields=fields)
        unexpected(key="dnp3-poll-from-unexpected-host",
                   title="DNP3 poll or counter freeze from an unexpected host",
                   what="A DNP3 read (class / integrity poll) or counter freeze request sent to an outstation",
                   service="dnp3", level="medium",
                   selection={"function_code": DNP3_POLL_FUNCTIONS, "dest_port": DNP3_PORT},
                   approved=masters, who=who, label="approved DNP3 master(s)", tags=["attack.t0861", "attack.t0801"],
                   falsepositives=["A secondary master or protocol analyser polling the outstation."],
                   fields=fields)

    if _hosts(answers, BACNET_SERVER_TYPES):
        clients, who = role(BACNET_CLIENT_TYPES)
        unexpected(key="bacnet-write-from-unexpected-host", title="BACnet write or device control from an unapproved host",
                   what="A BACnet confirmed request that changes a device (WriteProperty, WritePropertyMultiple, "
                        "Add/RemoveListElement, Create/DeleteObject, DeviceCommunicationControl, ReinitializeDevice)",
                   service="bacnet", level="high",
                   selection={"apdu_type": "confirmed_request", "service_code": BACNET_WRITE_SERVICES},
                   approved=clients, who=who, label="BMS workstation(s)", tags=["attack.t0855", "attack.t0836"],
                   falsepositives=["A service technician's laptop overriding a point during maintenance."],
                   fields=["ts", "src", "dest", "service", "object_type", "instance", "property", "value",
                           "priority", "frame"])
        unexpected(key="bacnet-foreign-device-from-unexpected-host",
                   title="BACnet foreign-device registration from an unexpected host",
                   what="A BVLC Register-Foreign-Device to a BBMD (the registered host then receives every broadcast "
                        "of the BACnet network and can broadcast into it)",
                   service="bacnet", level="medium", selection={"bvlc_function": 5},
                   approved=clients, who=who, label="BMS workstation(s)", tags=["attack.t0886", "attack.t0846"],
                   falsepositives=["A new remote BMS server registering with the BBMD."],
                   fields=["ts", "src", "dest", "ttl_s", "frame"])
        rules.append(_sigma(
            answers, key="bacnet-bbmd-table-change", title="BACnet BBMD table changed over the network",
            description="A BVLC Write-Broadcast-Distribution-Table or Delete-Foreign-Device-Table-Entry: changes "
                        "which networks and foreign devices the BBMD forwards broadcasts to. Not part of normal "
                        "operation of this site.",
            service="bacnet", level="medium",
            detection={"selection": {"bvlc_function": [1, 8]}, "condition": "selection"},
            tags=["attack.t0814"], falsepositives=["BBMD commissioning, recorded in a change ticket."],
            fields=["ts", "src", "dest", "bvlc", "frame"]))

    if _hosts(answers, ENIP_TARGET_TYPES):
        originators, who = role(ENIP_ORIGINATOR_TYPES)
        fields = ["ts", "src", "dest", "service", "services", "class", "instance", "attribute", "tags", "frame"]
        unexpected(key="cip-write-from-unexpected-host", title="CIP write service from an unexpected host",
                   what="A CIP request that changes a device (Write_Tag, Write_Tag_Fragmented, Read_Modify_Write_Tag, "
                        "Set_Attribute_Single / List / All, Reset, Start, Stop, Create, Delete, ...), also inside a "
                        "Multiple Service Packet",
                   service="enip", level="high", selection={"write": True},
                   approved=originators, who=who, label="approved EtherNet/IP originators (HMI, historian, scanner)",
                   tags=["attack.t0855", "attack.t0836"],
                   falsepositives=["Studio 5000 / RSLinx on an engineering workstation not modelled as a client."],
                   fields=fields)
        unexpected(key="cip-forward-open-from-unexpected-host", title="CIP Forward_Open from an unexpected host",
                   what="A CIP Forward_Open / Large_Forward_Open request (opens a class 1 I/O or class 3 messaging "
                        "connection to the device)",
                   service="enip", level="medium",
                   selection={"service_code": [0x54, 0x5B], "response": False},
                   approved=originators, who=who, label="approved EtherNet/IP originators (HMI, historian, scanner)",
                   tags=["attack.t0886", "attack.t0855"],
                   falsepositives=["A new HMI or I/O scanner, or an engineering workstation going online."],
                   fields=["ts", "src", "dest", "service", "transport_class", "rpi_ot_ms", "rpi_to_ms",
                           "ot_connection_id", "to_connection_id", "frame"])
    return rules


def _modbus_sigma_rules(answers: dict) -> list[dict]:
    """Modbus (and DHCP) detections: PLCs = modbus.server, approved writers = modbus.operator,
    SCADA clients = modbus.poller + operators."""
    ips = host_ips(answers)
    names = {h["id"]: h["name"] for h in answers["topology"]["hosts"]}
    servers = [a for a in answers["actors"] if a["type"] == "modbus.server"]
    plcs = [ips[h] for a in servers for h in a["hosts"]]
    if not plcs:
        return []
    writers = [ips[h] for h in _hosts(answers, WRITER_TYPES)]
    clients = [ips[h] for h in _hosts(answers, CLIENT_TYPES)]
    rules: list[dict] = []

    write_sel: dict = {"write": True, "dest": plcs}
    if writers:
        detection = {"writes": write_sel, "approved": {"src": writers}, "condition": "writes and not approved"}
        writer_names = ", ".join(names[h] for h in _hosts(answers, WRITER_TYPES))
        description = (f"A Modbus write (function 5, 6, 15, 16, 22, 23) to a PLC from a host other than "
                       f"the approved engineering workstation(s): {writer_names}.")
        fp = [f"Maintenance from a host other than {writer_names}."]
    else:
        detection = {"writes": write_sel, "condition": "writes"}
        description = "A Modbus write to a PLC. This site has no approved writer, so every write is notable."
        fp = ["Commissioning or maintenance writes."]
    rules.append(_sigma(
        answers, key="modbus-unapproved-writer", title="Modbus write from an unapproved host",
        description=description, service="modbus", level="high", detection=detection,
        tags=["attack.t0855", "attack.t0836"], falsepositives=fp,
        fields=["ts", "src", "dest", "function_code", "point", "value", "in_normal_band", "request_frame"]))

    rules.append(_sigma(
        answers, key="modbus-out-of-band-write", title="Modbus setpoint written outside its normal band",
        description="A Modbus write whose engineering value falls outside the point's normal operating "
                    "band (in_normal_band is false), as annotated from the PLC register map.",
        service="modbus", level="high",
        detection={"selection": {"write": True, "dest": plcs, "in_normal_band": False}, "condition": "selection"},
        tags=["attack.t0836"], falsepositives=["A legitimate but unusually large operator adjustment."],
        fields=["ts", "src", "dest", "point", "value", "unit", "request_frame"]))

    ident_sel = {"function_code": 43, "dest": plcs}
    if clients:
        ident = {"selection": ident_sel, "approved": {"src": clients}, "condition": "selection and not approved"}
        client_names = ", ".join(names[h] for h in _hosts(answers, CLIENT_TYPES))
        ident_desc = (f"Read Device Identification (function 43) sent to a PLC by a host other than the "
                      f"known SCADA / HMI / historian clients: {client_names}.")
    else:
        ident = {"selection": ident_sel, "condition": "selection"}
        ident_desc = "Read Device Identification (function 43) sent to a PLC."
    rules.append(_sigma(
        answers, key="modbus-device-identification", title="Modbus device identification from an unexpected host",
        description=ident_desc, service="modbus", level="medium", detection=ident,
        tags=["attack.t0888", "attack.t0846"],
        falsepositives=["An asset-inventory or vulnerability scan run by the OT team."],
        fields=["ts", "src", "dest", "function_code", "request_frame"]))

    conn_sel = {"dest_port": MODBUS_PORT, "dest": plcs}
    if clients:
        conn = {"selection": conn_sel, "approved": {"src": clients}, "condition": "selection and not approved"}
        conn_desc = (f"A TCP connection to a PLC's Modbus port (502) from a host other than the known SCADA / HMI "
                     f"/ historian clients: {', '.join(names[h] for h in _hosts(answers, CLIENT_TYPES))}. One host "
                     f"opening 502 to several PLCs in a short window is a Modbus service sweep.")
    else:
        conn = {"selection": conn_sel, "condition": "selection"}
        conn_desc = "A TCP connection to a PLC's Modbus port (502). One host opening 502 to several PLCs is a sweep."
    rules.append(_sigma(
        answers, key="modbus-connection-from-unexpected-host", title="Modbus connection from an unexpected host",
        description=conn_desc, service="flows", level="medium", detection=conn,
        tags=["attack.t0846"],
        falsepositives=["A new or reconfigured SCADA client, or an OT-team asset scan."],
        fields=["ts", "src", "dest", "dest_port", "state", "packets_out"]))

    # Port sweep (ot-modbus-discovery): one source trying 502 on several hosts, PLC or not. The swept
    # hosts answer with a RST (closed) or nothing (host firewall), so the flows carry any state.
    sweep = {"selection": {"dest_port": MODBUS_PORT}, "condition": "selection"}
    if clients:
        sweep = {"selection": {"dest_port": MODBUS_PORT}, "approved": {"src": clients},
                 "condition": "selection and not approved"}
    rules.append(_sigma(
        answers, key="modbus-port-502-attempt", title="Modbus port 502 connection attempt by a non-SCADA host",
        description="Any TCP flow to port 502 from a host other than the SCADA clients, PLC or not (base rule of "
                    "the Modbus port-sweep correlation).",
        service="flows", level="low", detection=sweep, tags=["attack.t0846"],
        falsepositives=["See the port-sweep correlation."], fields=None,
        name="pcapforge_modbus_port_attempt"))
    rules.append(_correlation(
        answers, key="modbus-port-sweep", title="Modbus/TCP port sweep of the control network",
        description="One host outside the SCADA clients opened (or tried) port 502 on at least three different "
                    "hosts within ten minutes: a Modbus service sweep (remote system discovery).",
        level="high", kind="value_count", rules=["pcapforge_modbus_port_attempt"], group_by=["src"],
        timespan="10m", condition={"gte": 3}, field="dest", generate=False, tags=["attack.t0846"],
        falsepositives=["An asset-inventory or vulnerability scan run by the OT team."]))

    # Register-map enumeration (discovery, and the writer's reconnaissance): oversized reads are
    # rejected with exception 2 before the real table sizes are found. SCADA polls never hit it.
    rules.append(_sigma(
        answers, key="modbus-illegal-data-address", title="Modbus read rejected with Illegal Data Address",
        description="A PLC answered a request with exception 2 (Illegal Data Address): the client asked for "
                    "registers outside the configured map, typical of register-map enumeration (point and tag "
                    "identification). The site's SCADA polls only read the configured map.",
        service="modbus", level="medium",
        detection={"selection": {"dest": plcs, "exception_code": 2}, "condition": "selection"},
        tags=["attack.t0861", "attack.t0888"],
        falsepositives=["A misconfigured new HMI or historian tag list."],
        fields=["ts", "src", "dest", "function_code", "address", "quantity", "request_frame"]))

    # Alarm suppression (ot-modbus-coil-manipulation): acknowledging or resetting alarms by writing
    # the PLC's alarm coil over the network instead of on the HMI.
    alarm_coils = _profile_points(answers, servers, "coils", lambda p: p.writable and "alarm" in p.name.split("_"))
    if alarm_coils:
        rules.append(_sigma(
            answers, key="modbus-alarm-acknowledge", title="Modbus alarm acknowledge or reset written to a PLC",
            description=f"A Modbus coil write to the PLC's alarm acknowledge / reset coil ({', '.join(alarm_coils)}). "
                        "Operators acknowledge alarms on the HMI; a network write clears the alarm state that "
                        "would otherwise show the effect of a forced actuator.",
            service="modbus", level="high",
            detection={"selection": {"write": True, "dest": plcs, "point": alarm_coils}, "condition": "selection"},
            tags=["attack.t0878"],
            falsepositives=["A SCADA system that acknowledges alarms through Modbus by design."],
            fields=["ts", "src", "dest", "function_code", "point", "request_frame"]))

    # Alarm masking (ot-modbus-alarm-masking): an alarm threshold written outside its band so the
    # alarm can no longer trip.
    thresholds = _profile_points(answers, servers, "holding",
                                 lambda p: p.writable and p.normal and "alarm" in p.name.split("_"))
    if thresholds:
        rules.append(_sigma(
            answers, key="modbus-alarm-threshold-out-of-band", title="Alarm threshold written outside its normal band",
            description="A Modbus write moved an alarm threshold of the PLC register map outside its normal band, "
                        "so the alarm it drives can no longer trip (alarm suppression); look for an out-of-band "
                        "setpoint change by the same source shortly after.",
            service="modbus", level="high",
            detection={"selection": {"write": True, "dest": plcs, "point": thresholds, "in_normal_band": False},
                       "condition": "selection"},
            tags=["attack.t0878", "attack.t0836"],
            falsepositives=["A threshold retuned during commissioning, recorded in a change ticket."],
            fields=["ts", "src", "dest", "point", "value", "unit", "request_frame"]))

    # Command replay (ot-modbus-command-replay): the same point set to the same value by more than
    # one host. Values stay in band; what differs is the source.
    rules.append(_sigma(
        answers, key="modbus-register-write", title="Modbus register write to a mapped point",
        description="Any Modbus holding-register write annotated with a register-map point (base rule of the "
                    "repeated-write correlation).",
        service="modbus", level="informational",
        detection={"selection": {"write": True, "dest": plcs, "function_code": [6, 16, 23], "point|exists": True},
                   "condition": "selection"},
        tags=["attack.t0855"], falsepositives=["See the repeated-write correlation."],
        fields=None, name="pcapforge_modbus_register_write"))
    rules.append(_correlation(
        answers, key="modbus-write-replayed", title="Same Modbus setpoint value written by more than one host",
        description="A PLC point was set to the same value by at least two different hosts within four hours. "
                    "Legitimate changes come from the engineering workstation; an identical command from a "
                    "second host is a replay of captured traffic (values stay in band, so band rules miss it).",
        level="high", kind="value_count", rules=["pcapforge_modbus_register_write"],
        group_by=["dest", "point", "value"], timespan="4h", condition={"gte": 2}, field="src", generate=False,
        tags=["attack.t0855", "attack.t0831"],
        falsepositives=["Two engineering workstations applying the same recipe value."]))

    if any(a["type"] == "dhcp.client" for a in answers["actors"]):
        rules.append(_sigma(
            answers, key="dhcp-new-host-on-control-lan", title="New host leased an address on the control LAN",
            description="A DHCP DISCOVER on the control segment: a host without a static address joined the "
                        "network. On an OT control LAN where every asset is normally statically addressed, a "
                        "new lease is worth confirming against the maintenance schedule.",
            service="dhcp", level="low",
            detection={"selection": {"message": "discover"}, "condition": "selection"},
            tags=["attack.t0842"],
            falsepositives=["A scheduled maintenance laptop or a newly commissioned device."],
            fields=["ts", "client_mac", "host_name", "vendor_class", "assigned_addr"]))
    return rules


def _sigma_files(answers: dict, rules: list[dict]) -> dict[str, str]:
    """File name -> YAML text for each Sigma rule. A correlation rule shares its file with the
    base rules it names, base rules first (multi-document YAML, as pySigma resolves references
    in load order)."""
    by_name = {r["name"]: r for r in rules if "name" in r}
    bundled = {n for r in rules if "correlation" in r for n in r["correlation"]["rules"]}
    out = {}
    for rule in rules:
        if rule.get("name") in bundled:
            continue
        docs = [by_name[n] for n in rule["correlation"]["rules"]] + [rule] if "correlation" in rule else [rule]
        name = rule["title"].lower().replace(" ", "_")
        name = "".join(c for c in name if c.isalnum() or c in "_-")
        out[f"{name}.yml"] = yaml.dump_all(docs, sort_keys=False, allow_unicode=True, default_flow_style=False)
    return out


def _rules_file(answers: dict, rules: list[Rule]) -> str:
    sc = answers["scenario"]
    ips = host_ips(answers)
    names = {h["id"]: h["name"] for h in answers["topology"]["hosts"]}

    def listing(types: tuple[str, ...]) -> str:
        hosts = _hosts(answers, types)
        return ", ".join(f"{names[h]} {ips[h]}" for h in hosts) or "none"

    plcs = [h for a in answers["actors"] if a["type"] == "modbus.server" for h in a["hosts"]]
    lines = [
        f"# pcapforge Suricata rules: {sc['id']} ({sc['difficulty']}, seed {sc['seed']})",
        f"# Site: {answers['topology']['site_name']} ({answers['topology']['domain']})",
        "#",
        "# Suricata's Modbus parser is disabled by default; enable it when running these rules:",
        "#   suricata -r capture.pcap -S suricata.rules -k none -l <log dir> \\",
        "#            --set app-layer.protocols.modbus.enabled=true",
        "# Modbus addresses in `modbus: access` are 1-based (wire address + 1); values are raw registers.",
        "# FLOAT32 setpoints are matched on the request bytes (byte_test on the IEEE 754 bit pattern of a",
        "# Write Multiple Registers that starts at the point; byte offsets count from the MBAP header).",
        "#",
        f"# PLCs:                     {', '.join(f'{names[h]} {ips[h]}' for h in plcs) or 'none'}",
        f"# Approved writers:         {listing(WRITER_TYPES)}",
        f"# Approved Modbus clients:  {listing(CLIENT_TYPES)}",
        f"# sid range: {SID_BASE}-{SID_BASE + 99999} (local).",
        "",
    ]
    for rule in rules:
        lines += [f"# {rule.purpose}", rule.text, ""]
    return "\n".join(lines)


def _answer_text(value: Any) -> str:
    if isinstance(value, (list, dict)):
        return json.dumps(value, ensure_ascii=False)
    return str(value)


def _expect_text(expect: dict) -> str:
    parts = []
    if "count" in expect:
        parts.append(f"exactly {expect['count']}")
    if "min" in expect:
        parts.append(f"at least {expect['min']}")
    if "max" in expect:
        parts.append(f"at most {expect['max']}")
    return " and ".join(parts) + " frame(s)"


def _hunting(answers: dict, rules: list[Rule]) -> str:
    sc = answers["scenario"]
    lines = [
        f"# Hunting guide: {sc['title']}",
        "",
        f"Scenario `{sc['id']}`, difficulty `{sc['difficulty']}`, seed `{sc['seed']}`. "
        "Instructor material: contains the answers.",
        "",
        "Wireshark display filters come from the answer key and are machine-verified by "
        "`pcapforge verify` (expected frame counts shown). The SPL and KQL queries come from the "
        "scenario and are tested against Splunk and Elasticsearch loaded as described below; the "
        "Zeek queries are jq commands over the JSON logs `--zeek` writes (run them in the run "
        "directory), tested against Zeek 8 LTS with the ICSNPP packages.",
        "",
        "## Loading the SIEM export",
        "",
        "`siem/<dataset>.jsonl` holds one JSON event per line; `ts` is ISO-8601 UTC with microseconds.",
        "",
        "- Splunk: index each file with sourcetype `pcapforge:<dataset>` "
        "(e.g. `pcapforge:modbus`). `props.conf`:",
        "",
        "  ```ini",
        "  [pcapforge:modbus]",
        "  INDEXED_EXTRACTIONS = json",
        "  KV_MODE = none",
        "  TIMESTAMP_FIELDS = ts",
        "  TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%6NZ",
        "  TZ = UTC",
        "  # capture dates are drawn per seed and can lie months ahead of (or years behind) today",
        "  MAX_DAYS_HENCE = 3650",
        "  MAX_DAYS_AGO = 10951",
        "  ```",
        "",
        "- Elastic: one index per file named `pcapforge-<dataset>` (e.g. `pcapforge-modbus`); map "
        "`ts` to `@timestamp` (Kibana file upload: timestamp field `ts`). KQL queries run in a data "
        "view over that index.",
        "",
        "Datasets: " + ", ".join(f"`{d}`" for d in DATASETS) + ".",
        "",
        "## Suricata rules",
        "",
        "`suricata.rules` (run with `--set app-layer.protocols.modbus.enabled=true`):",
        "",
        "| sid | Fires on |",
        "|---|---|",
    ]
    lines += [f"| {r.sid} | {r.purpose.replace('|', '/')} |" for r in rules]
    sigma = sigma_rules(answers)
    if sigma:
        lines += ["", "## Sigma rules", "",
                  "`sigma/*.yml` (SIEM-agnostic, over the JSON-lines export; `logsource.service` is the "
                  "dataset, matching the sourcetype `pcapforge:<dataset>`). Convert with "
                  "[sigma-cli](https://github.com/SigmaHQ/sigma-cli), e.g. "
                  "`sigma convert -t splunk sigma/`:", "",
                  "| level | rule | fires on |", "|---|---|---|"]
        lines += [f"| {r['level']} | {r['title']} | {r['description'].replace('|', '/')} |" for r in sigma]
    lines += ["", "## Zeek notices", "",
              f"`{ZEEK_SCRIPT}` raises notices (`notice.log`) for the same roles as the Suricata rules; `--zeek` "
              "loads it. Run it yourself with `zeek -r capture.pcap pcapforge-ot.zeek` (IEC 104, BACnet and "
              "EtherNet/IP need pcapforge's IEC 104 analyzer and the ICSNPP packages):", "",
              "| notice | fires on |", "|---|---|",
              "| `Pcapforge::Unapproved_Modbus_Write` | Modbus write (functions 5, 6, 15, 16, 22, 23) to a PLC from a host that is not an approved writer |",
              "| `Pcapforge::Modbus_Device_Identification` | Read Device Identification (function 43) from a host that is not a SCADA client |",
              "| `Pcapforge::Modbus_Out_Of_Band_Write` | a holding-register setpoint written outside its normal band (UINT16 raw, FLOAT32 decoded) |",
              "| `Pcapforge::Unapproved_DNP3_Control` | DNP3 write, select / operate, restart or disable-unsolicited from a host other than the master |",
              "| `Pcapforge::Unapproved_IEC104_Command` | IEC 104 process command, interrogation or reset (activation) from a host other than the SCADA master |",
              "| `Pcapforge::Unapproved_BACnet_Write` | BACnet WriteProperty(Multiple), DeviceCommunicationControl or ReinitializeDevice from an unapproved host |",
              "| `Pcapforge::Unapproved_CIP_Service` | CIP Write_Tag, Set_Attribute*, Reset or Forward_Open from an unapproved originator |"]
    lines += ["", "## Questions", ""]
    for index, question in enumerate(answers["questions"], 1):
        hunt = question.get("hunt", {})
        lines += [f"### {index}. [{question['id']}] {question['text']}", "",
                  f"**Answer:** `{_answer_text(question['answer'])}`", ""]
        if question.get("checks"):
            lines.append("**Wireshark** (verified):")
            lines.append("")
            for check in question["checks"]:
                lines.append(f"- `{check['filter']}` - {_expect_text(check['expect'])}")
            lines.append("")
        elif hunt.get("wireshark"):
            lines += ["**Wireshark** (hunting filter, no expected count):", "",
                      f"- `{hunt['wireshark']}`", ""]
        dataset = hunt.get("dataset", "modbus")
        if hunt.get("spl"):
            lines += ["**Splunk SPL**:", "", "```spl", hunt["spl"], "```", ""]
        if hunt.get("kql"):
            lines += [f"**Kibana KQL** on `pcapforge-{dataset}`:", "",
                      "```kql", hunt["kql"], "```", ""]
        if hunt.get("zeek"):
            lines += [f"**Zeek** (`zeek/{hunt['zeek']['log']}.log`, with jq):", "",
                      "```sh", hunt_command(hunt["zeek"]), "```", ""]
        if hunt.get("look_for"):
            lines += [f"**What to look for:** {hunt['look_for']}", ""]
    return "\n".join(lines)

# --- Zeek ---------------------------------------------------------------------------
# The Suricata roles as a Zeek script: NOTICE (notice.log) for OT commands and writes from hosts
# outside the approved roles, and for Modbus setpoint writes outside the register map's normal
# band. Modbus and DNP3 use Zeek's own analyzers; IEC 104, BACnet and EtherNet/IP need pcapforge's
# IEC 104 analyzer and the ICSNPP packages, so their handlers are compiled only when those events
# exist. The sender of a BACnet / CIP message is the side `is_orig` names (ICSNPP's UDP 47808 flows
# can be oriented either way).

ZEEK_SCRIPT = "pcapforge-ot.zeek"
ZEEK_MODBUS_WRITES = (5, 6, 15, 16, 22, 23)
ZEEK_DNP3_CONTROLS = (2, 3, 4, 5, 6, 13, 14, 21)   # as the Suricata rules: write, select/operate, restarts, disable unsolicited
ZEEK_BACNET_EVENTS = ("bacnet_write_property", "bacnet_write_property_multiple", "bacnet_device_communication_control",
                      "bacnet_reinitialize_device")
ZEEK_CIP_SERVICES = (0x4D, 0x53, 0x10, 0x02, 0x04, 0x05, 0x54, 0x5B)


def _zeek_set(values) -> str:
    values = list(values)
    return "{ " + ", ".join(str(v) for v in values) + " }" if values else "set()"


def zeek_script(answers: dict) -> str:
    """Zeek detection script for one run (notice.log)."""
    ips = host_ips(answers)

    def role(types: tuple[str, ...]) -> list[str]:
        return [ips[h] for h in _hosts(answers, types)]

    plcs = [ips[h] for a in answers["actors"] if a["type"] == "modbus.server" for h in a["hosts"]]
    bands = []
    for actor in sorted((a for a in answers["actors"] if a["type"] == "modbus.server"), key=lambda a: a["id"]):
        profile = ProcessProfile(answers["facts"][actor["id"]]["process"])
        for host in actor["hosts"]:
            for point in profile.table("holding"):
                if not (point.writable and point.normal):
                    continue
                lo, hi = point.normal
                if point.type == "float32":
                    bands.append((ips[host], point.address, point.name, True, point.word_order == "big", lo, hi))
                else:
                    bands.append((ips[host], point.address, point.name, False, True,
                                  math.ceil(lo * point.scale - 1e-9), math.floor(hi * point.scale + 1e-9)))
    sc = answers["scenario"]
    lines = [
        f"# pcapforge detections for {sc['id']} ({sc['difficulty']}, seed {sc['seed']}): the Suricata rules' roles",
        "# as Zeek notices. Load it with the capture: zeek -r capture.pcap pcapforge-ot.zeek (with the ICSNPP",
        "# packages and pcapforge's IEC 104 analyzer installed for those protocols).",
        "",
        "@load base/frameworks/notice",
        "",
        "module Pcapforge;",
        "",
        "export {",
        "\tredef enum Notice::Type += {",
        "\t\tUnapproved_Modbus_Write,       ##< Modbus write from a host that is not an approved writer",
        "\t\tModbus_Device_Identification,  ##< Read Device Identification from a host that is not a SCADA client",
        "\t\tModbus_Out_Of_Band_Write,      ##< a setpoint written outside its normal band",
        "\t\tUnapproved_DNP3_Control,       ##< DNP3 control / write / restart from a host other than the master",
        "\t\tUnapproved_IEC104_Command,     ##< IEC 104 command from a host other than the SCADA master",
        "\t\tUnapproved_BACnet_Write,       ##< BACnet write / device control from an unapproved host",
        "\t\tUnapproved_CIP_Service,        ##< CIP write / reset / Forward_Open from an unapproved originator",
        "\t};",
        "",
        f"\tconst modbus_plcs: set[addr] = {_zeek_set(plcs)};",
        f"\tconst modbus_writers: set[addr] = {_zeek_set(role(WRITER_TYPES))};",
        f"\tconst modbus_clients: set[addr] = {_zeek_set(role(CLIENT_TYPES))};",
        f"\tconst dnp3_outstations: set[addr] = {_zeek_set(role(DNP3_SERVER_TYPES))};",
        f"\tconst dnp3_masters: set[addr] = {_zeek_set(role(DNP3_MASTER_TYPES))};",
        f"\tconst iec104_rtus: set[addr] = {_zeek_set(role(IEC104_SERVER_TYPES))};",
        f"\tconst iec104_masters: set[addr] = {_zeek_set(role(IEC104_MASTER_TYPES))};",
        f"\tconst bacnet_controllers: set[addr] = {_zeek_set(role(BACNET_SERVER_TYPES))};",
        f"\tconst bacnet_clients: set[addr] = {_zeek_set(role(BACNET_CLIENT_TYPES))};",
        f"\tconst enip_targets: set[addr] = {_zeek_set(role(ENIP_TARGET_TYPES))};",
        f"\tconst enip_originators: set[addr] = {_zeek_set(role(ENIP_ORIGINATOR_TYPES))};",
        "",
        "\t## Setpoint bands: [PLC, holding register] -> name, FLOAT32, ABCD word order, low, high",
        "\t## (raw register units for UINT16 points, engineering units for FLOAT32).",
        "\ttype Band: record { name: string; float32: bool; big: bool; low: double; high: double; };",
    ]
    default = "&default=Band($name=\"\", $float32=F, $big=T, $low=0.0, $high=0.0)"
    if bands:
        lines += ["\tconst bands: table[addr, count] of Band = {"]
        lines += [f"\t\t[{plc}, {address}] = Band($name=\"{name}\", $float32={'T' if f32 else 'F'}, "
                  f"$big={'T' if big else 'F'}, $low={float(lo)!r}, $high={float(hi)!r}),"
                  for plc, address, name, f32, big, lo, hi in bands]
        lines += [f"\t}} {default};"]
    else:
        lines += [f"\tconst bands: table[addr, count] of Band = table() {default};"]
    lines += ["}", ""]
    lines += [
        "function notify(note: Notice::Type, c: connection, src: addr, dst: addr, msg: string, sub: string)",
        "\t{",
        "\tNOTICE([$note=note, $conn=c, $src=src, $dst=dst, $msg=msg, $sub=sub,",
        "\t        $identifier=cat(src, dst, note, sub)]);",
        "\t}",
        "",
        "event modbus_message(c: connection, headers: ModbusHeaders, is_orig: bool)",
        "\t{",
        "\tif ( ! is_orig || c$id$resp_h !in modbus_plcs )",
        "\t\treturn;",
        f"\tif ( headers$function_code in set({', '.join(map(str, ZEEK_MODBUS_WRITES))}) && c$id$orig_h !in modbus_writers )",
        "\t\tnotify(Unapproved_Modbus_Write, c, c$id$orig_h, c$id$resp_h,",
        "\t\t       fmt(\"Modbus write (function %d) from %s, not an approved writer\", headers$function_code, c$id$orig_h),",
        "\t\t       fmt(\"function %d\", headers$function_code));",
        "\tif ( headers$function_code == 43 && c$id$orig_h !in modbus_clients )",
        "\t\tnotify(Modbus_Device_Identification, c, c$id$orig_h, c$id$resp_h,",
        "\t\t       fmt(\"Read Device Identification from %s, not a SCADA client\", c$id$orig_h), \"function 43\");",
        "\t}",
        "",
        "function check_band(c: connection, address: count, value: double)",
        "\t{",
        "\tlocal band = bands[c$id$resp_h, address];",
        "\tif ( band$name != \"\" && (value < band$low || value > band$high) )",
        "\t\tnotify(Modbus_Out_Of_Band_Write, c, c$id$orig_h, c$id$resp_h,",
        "\t\t       fmt(\"%s set to %s outside its normal band %s-%s\", band$name, value, band$low, band$high),",
        "\t\t       band$name);",
        "\t}",
        "",
        "event modbus_write_single_register_request(c: connection, headers: ModbusHeaders, address: count, value: count)",
        "\t{",
        "\tif ( ! bands[c$id$resp_h, address]$float32 )",
        "\t\tcheck_band(c, address, value);",
        "\t}",
        "",
        "event modbus_write_multiple_registers_request(c: connection, headers: ModbusHeaders, start_address: count,",
        "                                              registers: ModbusRegisters)",
        "\t{",
        "\tlocal i = 0;",
        "\twhile ( i < |registers| )",
        "\t\t{",
        "\t\tlocal band = bands[c$id$resp_h, start_address + i];",
        "\t\tif ( band$float32 && i + 1 < |registers| )",
        "\t\t\t{",
        "\t\t\tlocal high = band$big ? registers[i] : registers[i + 1];",
        "\t\t\tlocal low = band$big ? registers[i + 1] : registers[i];",
        "\t\t\tlocal bits = hexstr_to_bytestring(fmt(\"%04x%04x\", high, low));",
        "\t\t\tcheck_band(c, start_address + i, bytestring_to_float(bits));",
        "\t\t\ti += 2;",
        "\t\t\tnext;",
        "\t\t\t}",
        "\t\tif ( ! band$float32 )",
        "\t\t\tcheck_band(c, start_address + i, registers[i]);",
        "\t\t++i;",
        "\t\t}",
        "\t}",
        "",
        "event dnp3_application_request_header(c: connection, is_orig: bool, application: count, fc: count)",
        "\t{",
        f"\tif ( is_orig && c$id$resp_h in dnp3_outstations && c$id$orig_h !in dnp3_masters && fc in set({', '.join(map(str, ZEEK_DNP3_CONTROLS))}) )",
        "\t\tnotify(Unapproved_DNP3_Control, c, c$id$orig_h, c$id$resp_h,",
        "\t\t       fmt(\"DNP3 %s from %s, not the DNP3 master\", DNP3::function_codes[fc], c$id$orig_h),",
        "\t\t       DNP3::function_codes[fc]);",
        "\t}",
        "",
        "@ifdef ( PcapforgeIEC104::command )",
        "event PcapforgeIEC104::command(c: connection, is_orig: bool, type_id: count, cot: count, common_address: count,",
        "                               ioa: count, value: double, qualifier: count, select: bool)",
        "\t{",
        "\tif ( is_orig && cot % 64 == 6 && c$id$resp_h in iec104_rtus && c$id$orig_h !in iec104_masters",
        "\t     && ((type_id >= 45 && type_id <= 64) || type_id == 100 || type_id == 101 || type_id == 105) )",
        "\t\tnotify(Unapproved_IEC104_Command, c, c$id$orig_h, c$id$resp_h,",
        "\t\t       fmt(\"IEC 104 command type %d (IOA %d) from %s, not the SCADA master\", type_id, ioa, c$id$orig_h),",
        "\t\t       fmt(\"type %d ioa %d\", type_id, ioa));",
        "\t}",
        "@endif",
        "",
        "function bacnet(c: connection, is_orig: bool, what: string)",
        "\t{",
        "\tlocal src = is_orig ? c$id$orig_h : c$id$resp_h;",
        "\tlocal dst = is_orig ? c$id$resp_h : c$id$orig_h;",
        "\tif ( dst in bacnet_controllers && src !in bacnet_clients )",
        "\t\tnotify(Unapproved_BACnet_Write, c, src, dst, fmt(\"BACnet %s from %s, not a BMS workstation\", what, src), what);",
        "\t}",
        "",
    ]
    signatures = {
        "bacnet_write_property": ("invoke_id: count, object_type: count, instance_number: count, property_identifier: count, "
                                  "property_array_index: count, priority: count, property_value: string", "WriteProperty"),
        "bacnet_write_property_multiple": ("invoke_id: count", "WritePropertyMultiple"),
        "bacnet_device_communication_control": ("invoke_id: count, time_duration: count, enable_disable: count, "
                                                "password: string", "DeviceCommunicationControl"),
        "bacnet_reinitialize_device": ("invoke_id: count, reinitialized_state: count, password: string",
                                       "ReinitializeDevice"),
    }
    for event in ZEEK_BACNET_EVENTS:
        params, what = signatures[event]
        lines += [f"@ifdef ( {event} )", f"event {event}(c: connection, is_orig: bool, {params})",
                  "\t{", f"\tbacnet(c, is_orig, \"{what}\");", "\t}", "@endif", ""]
    lines += [
        "@ifdef ( cip_header )",
        "event cip_header(c: connection, is_orig: bool, packet_correlation_id: string, cip_sequence_count: count,",
        "                 service: count, response: bool, status: count, status_extended: count, class_id: count,",
        "                 instance_id: count, attribute_id: count, occurrence_count: count)",
        "\t{",
        "\tlocal src = is_orig ? c$id$orig_h : c$id$resp_h;",
        "\tlocal dst = is_orig ? c$id$resp_h : c$id$orig_h;",
        f"\tif ( ! response && service in set({', '.join(map(str, ZEEK_CIP_SERVICES))}) && dst in enip_targets && src !in enip_originators )",
        "\t\tnotify(Unapproved_CIP_Service, c, src, dst,",
        "\t\t       fmt(\"CIP service 0x%02x from %s, not an approved originator\", service, src),",
        "\t\t       fmt(\"service 0x%02x\", service));",
        "\t}",
        "@endif",
    ]
    return "\n".join(lines) + "\n"


def write_detections(answers: dict, out_dir: Path) -> dict[str, Path]:
    """Write ``suricata.rules``, ``sigma/*.yml``, ``pcapforge-ot.zeek`` and ``hunting.md`` for one run into ``out_dir``."""
    rules = suricata_rules(answers)
    out_dir.mkdir(parents=True, exist_ok=True)
    paths = {"suricata.rules": out_dir / "suricata.rules", "hunting.md": out_dir / "hunting.md",
             ZEEK_SCRIPT: out_dir / ZEEK_SCRIPT}
    paths["suricata.rules"].write_text(_rules_file(answers, rules), encoding="utf-8", newline="\n")
    paths[ZEEK_SCRIPT].write_text(zeek_script(answers), encoding="utf-8", newline="\n")
    paths["hunting.md"].write_text(_hunting(answers, rules), encoding="utf-8", newline="\n")
    sigma = _sigma_files(answers, sigma_rules(answers))
    if sigma:
        sigma_dir = out_dir / "sigma"
        sigma_dir.mkdir(exist_ok=True)
        for name, text in sigma.items():
            path = sigma_dir / name
            path.write_text(text, encoding="utf-8", newline="\n")
            paths[f"sigma/{name}"] = path
    return paths
