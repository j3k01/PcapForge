# Changelog

## Unreleased
### Scenarios
- Incident scenarios on the non-Modbus OT protocols: `ot-iec104-command-injection` (unauthorized
  breaker control), `ot-dnp3-control-injection` (unauthorized control-relay commands),
  `ot-bacnet-unauthorized-write` (WriteProperty override at high priority) and
  `ot-enip-drive-manipulation` (unapproved Forward_Open + forced drive speed reference). Each is
  flagged by the existing "command / write / Forward_Open from an unexpected host" Suricata and Sigma
  rules for that protocol.

### Detection engineering
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
