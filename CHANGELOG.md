# Changelog

## 0.3.0 - 2026-10-18

Seeds are not stable across versions: medium and hard exercises of the same seed differ from 0.2.0.

### Scenarios
- Incident scenarios on the non-Modbus OT protocols: `ot-iec104-command-injection` (unauthorized
  breaker control), `ot-dnp3-control-injection` (unauthorized control-relay commands),
  `ot-bacnet-unauthorized-write` (WriteProperty override at high priority) and
  `ot-enip-drive-manipulation` (unapproved Forward_Open + forced drive speed reference). Each is
  flagged by the existing "command / write / Forward_Open from an unexpected host" Suricata and Sigma
  rules for that protocol.
- `ot-modbus-discovery` (version 4): on medium the scanner is a Raspberry Pi on the control LAN instead
  of a routed laptop; it brings up IPv6 and announces itself over mDNS, and a new question asks for the
  announced name. Medium exercises of the same seed differ from version 3.

### Traffic realism
- The Raspberry Pi and Linux laptop profiles have IPv6 (Raspberry Pi OS: modified EUI-64, no temporary
  address; Ubuntu Desktop: stable-privacy identifiers and a temporary address) and run avahi-daemon,
  which announces their addresses over IPv4 and IPv6 mDNS when the interface comes up (shipped with the
  Pi scanner on medium of `ot-modbus-discovery`).
- IPv6 hosts that were up before the capture no longer show an interface start (DAD, Router Solicitations,
  MLD reports, SLAAC) at their first frame: their addresses are configured and Windows retransmits its
  DHCPv6 Solicit every two minutes. Only a host that arrives during the capture (a DHCP joiner, or topology
  `arrives: true`) starts its interface in it. Medium and hard captures change (scenario versions bumped).
- A Windows host that joins over DHCP and leaves again chatters only while it is connected: name lookups,
  SSDP and browser announcements start once its address is configured, its IPv6 interface (DHCPv6 back-off
  from the start) comes up with the link, and browser announcements start a minute apart and lengthen to
  12 minutes. `ot-modbus-write-manipulation` (medium/hard): the vendor's service laptop now chatters too.
- Active Directory domain background (`ad.dc`, `ad.member`) from a synthetic, seed-derived directory: the
  Windows hosts refresh their computer Group Policy every 90-120 minutes (CLDAP DC-locator ping, LDAP with
  a Kerberos GSS-SPNEGO bind and sealed searches, gpt.ini of every GPO from SYSVOL over signed SMB 3.1.1,
  the connection dropped after 10 idle minutes) and use cached Kerberos tickets, asking the KDC only when
  they expire (AS exchange with pre-authentication, retried over TCP after KRB_ERR_RESPONSE_TOO_BIG; TGS
  over TCP). On medium/hard of every OT scenario; over IPv6 on the dual-stack level. Zeek writes
  `kerberos.log`, `ldap.log`, `ldap_search.log`, `smb_mapping.log` and `smb_files.log` for it.
- `ot-baseline-operations` (medium/hard): an engineer logs on to the domain at the EWS during the shift;
  new questions on the logon account and the GPO file, and the dual-stack question on IPv6 services now
  includes Kerberos, LDAP and SMB.
- Verification no longer counts opaque content that a dissector hands on (an SMB read's file data) as an
  undissected payload.

### Detection engineering
- SIEM export: `siem/kerberos.jsonl` (one record per KDC exchange: request type, client account, service,
  pre-authentication, success or KRB-ERROR) and `siem/smb.jsonl` (one per SMB2 request/response: command,
  tree, file name, signing, NTSTATUS); Kerberos, LDAP and CLDAP flows carry their `app`. The baseline's
  logon and GPO questions have SPL, KQL and Zeek hunting queries.
- `--zeek` loads CISA's ICSNPP packages when they are installed (versions pinned in `zeek.py`, installed in
  CI): S7comm/COTP, OPC UA Binary, BACnet, EtherNet/IP/CIP and DNP3 control logs. Their random link ids
  are renumbered so the logs stay deterministic.
- IEC 60870-5-104 in Zeek: pcapforge's own Spicy analyzer writes `iec104.log` (one record per APDU) and
  `iec104_command.log` (one per command object); `zeek.ANALYZERS_INSTALL` builds it next to ICSNPP.
- The hunting guide has a Zeek query (a jq command over `zeek/<log>.log`) for every question a Zeek log
  can answer, tested on every scenario and level; `conn.log` now records the MACs on the wire.
- `detections/pcapforge-ot.zeek` (also loaded by `--zeek`): Zeek notices for OT writes and commands from
  hosts outside the approved roles and for Modbus setpoints written out of band; tested to flag the
  attacker and only the attacker on every scenario and level.
- The IEC 104 Zeek analyzer also recognises the protocol on non-standard ports (STARTDT / TESTFR handshake).
- The SPL/KQL and Zeek test harnesses record a missing recording in their own network namespace
  (`unshare -rn`) instead of failing deep inside the recorder.
- The hunting guide's SPL and KQL are tested against Splunk 10.6 and Elasticsearch 9.5 for every scenario
  and level (`tests/test_siem_queries.py`, CI job `siem-queries`).
- `ot-modbus-discovery`: the enumeration SPL searched `dest=` the scanner and matched nothing; it now
  searches the scanner's transactions and shows the exception.
- Splunk `props.conf` in the hunting guide adds `MAX_DAYS_HENCE` and `MAX_DAYS_AGO`: captures dated more than
  two days ahead were stamped with the indexing time.
- The IEC 104, DNP3, BACnet and EtherNet/IP SIEM records carry `src_mac` / `dest_mac`, as the Modbus
  records do; the new scenarios' source-MAC hunts rely on them.

## 0.2.0 - 2026-10-11

Seeds are not stable across versions: the same seed can give a different exercise than in 0.1.0.

### Scenarios
- `ot-modbus-discovery`: port-502 sweep, device identification and register-map enumeration, no writes.
- `ot-modbus-command-replay`: an unapproved host replays operator commands; every value stays in band.
- `ot-modbus-coil-manipulation`: coil writes force actuators, with alarm acknowledgement on medium/hard.
- `ot-modbus-alarm-masking`: an alarm threshold is moved out of band before the setpoint it guards.
- `ot-baseline-operations`: normal operations only, for baselining and false-positive tuning.

### Traffic realism
- Background protocols on medium/hard: IEC 60870-5-104, DNP3, BACnet/IP and EtherNet/IP (explicit
  messaging and class 1 I/O), each with SIEM datasets and detection rules.
- DHCPv4 end to end, TCP segmentation, SPAN artefacts (VLAN, duplicates, sensor drops) and host
  firewalls (filtered vs closed ports).
- IPv6: link-local baseline, Router Advertisements, SLAAC and Neighbor Discovery; a dual-stack site on
  hard, including the embedded Linux controllers.
- Process models: FLOAT32 points across two registers, register descriptions, vendor register numbering
  in the handout, more PLC vendors.
- Long captures stream through compose, verify and export: a 24 h hard run peaks at 0.93 GB.

### Training workflow
- `pcapforge ui`: local web UI for generation, class batches, run pages (network map, traffic chart,
  timeline, answer key, downloads per section) and the run actions; `--student` mode with answer forms,
  a class roster and access codes.
- `pcapforge report`: self-contained HTML debrief with process charts and class results.
- `pcapforge export-ctfd`: one CTFd challenge per question.
- Hints cost 20 % of a question's points when listed under `hints_used`.
- German (`--lang de`) next to Polish.

### Detection engineering
- Sigma rules over the SIEM export, with correlation rules for port sweeps and command replay.
- Suricata band rules for FLOAT32 setpoints.
- `--zeek`: deterministic Zeek JSON logs from a local Zeek, a Zeek in WSL (Windows) or the Docker image.

### Fixes and docs
- pymodbus pinned to 3.15.x: 3.16.0 cannot be imported without pyserial.
- MkDocs documentation site; the README is short, the details are in `docs/`.

## 0.1.0 - 2026-10-04

First release: `ot-modbus-write-manipulation` on three levels, answer keys verified with tshark, SIEM
export and Suricata rules, grading and packaging.
