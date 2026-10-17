# SIEM export and detection content

`--siem` (or `pcapforge export <run dir>` later) turns a run into a detection-engineering lab:

```console
$ pcapforge generate -s ot-modbus-write-manipulation -d easy --seed 42 --siem
$ pcapforge export out/ot-modbus-write-manipulation_easy_42
out/ot-modbus-write-manipulation_easy_42/detections/hunting.md
out/ot-modbus-write-manipulation_easy_42/detections/sigma/*.yml  (4 rules)
out/ot-modbus-write-manipulation_easy_42/detections/suricata.rules
out/ot-modbus-write-manipulation_easy_42/siem/arp.jsonl  (25 records)
out/ot-modbus-write-manipulation_easy_42/siem/dhcp.jsonl  (4 records)
out/ot-modbus-write-manipulation_easy_42/siem/dns.jsonl  (0 records)
out/ot-modbus-write-manipulation_easy_42/siem/flows.jsonl  (40 records)
out/ot-modbus-write-manipulation_easy_42/siem/modbus.jsonl  (3975 records)
out/ot-modbus-write-manipulation_easy_42/siem/name_resolution.jsonl  (0 records)
out/ot-modbus-write-manipulation_easy_42/siem/ntp.jsonl  (33 records)
```

`siem/` holds one JSON event per line, decoded by a single tshark pass:

| file | one record per | main fields |
|---|---|---|
| `flows.jsonl` | TCP connection / UDP 5-tuple exchange / other IP pair | `src`, `dest`, `src_port`, `dest_port`, `transport`, `app`, `duration`, `packets_out/in`, `bytes_out/in` (IP bytes), `state` (`established`, `mid_session` = no SYN seen, `closed` = FIN, `reset`; UDP `bidirectional` / `one_way`) |
| `modbus.jsonl` | request/response transaction | `unit_id`, `trans_id`, `function_code`, `function`, `write`, `table`, `address`, `quantity`, `values` (written raw registers for writes, read raw registers/bits for successful reads), `exception`, `response_time_ms`, `request_frame`; for writes to a PLC with a known register map, per point the write covers completely (a FLOAT32 takes two registers; a list when there are several): `point`, `register` (vendor number, e.g. 40009, or a pair such as 40003-40004), `desc`, `unit`, `value` (engineering, UINT16 / scale or the decoded FLOAT32), `in_normal_band` |
| `dns.jsonl` | query/response | `query`, `qtype`, `rcode`, `answers`, `ttl`, `response_time_ms` |
| `ntp.jsonl` | client request/server response | `version`, `stratum`, `refid`, `server_time`, `offset_ms`, `response_time_ms` |
| `name_resolution.jsonl` | LLMNR / NBNS / mDNS / SSDP / browser datagram | `app`, `message`, `query`, `qtype`, `answers` |
| `arp.jsonl` | ARP packet | `operation`, `src`, `src_mac`, `dest`, `dest_mac`, `gratuitous`, `probe` (RFC 5227 address conflict probe from 0.0.0.0) |
| `dhcp.jsonl` | DHCPv4 message | `message` (`discover`, `offer`, `request`, `ack`, `inform`, `release`, ...), `xid`, `client_mac`, `client_addr`, `assigned_addr`, `requested_addr`, `server_id`, `host_name`, `client_fqdn`, `vendor_class`, `lease_time_s`, `router`, `dns_servers`, `domain` |
| `iec104.jsonl` | IEC 60870-5-104 APDU (I, S or U frame) | `apci`, `u_function`, `send_seq`, `recv_seq`, `type_id`, `type`, `category` (`monitor`, `control`, `system`, ...), `cot`, `cause`, `negative`, `test`, `originator`, `common_address`, `ioa`, `objects` (decoded values, quality, time tags), `select` |
| `dnp3.jsonl` | DNP3 application fragment | `link_src`, `link_dst`, `function_code`, `function`, `response`, `fir`, `fin`, `con`, `uns`, `seq`, `iin`, `iin_flags`, `objects`, `controls`, `analog_outputs`, `point_index` |
| `bacnet.jsonl` | BACnet/IP message | `bvlc`, `bvlc_result`, `ttl_s`, `orig_src` (Forwarded-NPDU), `apdu_type`, `service`, `invoke_id`, `write`, `object_type`, `instance`, `objects`, `device`, `property`, `value`, `priority`, `relinquish`, error / reject / abort codes |
| `enip.jsonl` | EtherNet/IP encapsulation message, or per minute and direction a class 0/1 I/O summary (`message: io_summary`) | `command`, `session`, `status`, `response`, `connection_id`, `sequence`, `service`, `services`, `class`, `instance`, `attribute`, `tags`, `general_status`, `write`, `identity`; I/O: `packets`, `bytes`, `first_seq` / `last_seq`, `seq_missing`, `seq_repeated`, `interval_ms_mean/min/max` |

Every record has `ts` (ISO-8601 UTC, microseconds, `Z`) for Splunk `_time` / Elastic `@timestamp`
and `epoch`; field names follow the Splunk CIM (`src`, `dest`, `src_port`, `dest_port`, `transport`, `app`).
Modbus, IEC 104, DNP3, BACnet and EtherNet/IP records also carry `src_mac` / `dest_mac`, the MACs the
sensor saw (for a routed source, the router's).
A write from the easy run above:

```json
{"ts": "2025-03-22T11:45:36.016219Z", "src": "10.241.35.219", "src_port": 37312, "dest": "10.241.35.159", "dest_port": 502,
 "src_mac": "b8:27:eb:23:26:6d", "function_code": 6, "function": "write_single_register", "write": true, "table": "holding",
 "address": 8, "quantity": 1, "values": [1587], "response_time_ms": 5.318, "request_frame": 7209,
 "point": "pid_level_ti", "unit": "s", "value": 1587.0, "in_normal_band": false, ...}
```

Loading: in Splunk use sourcetype `pcapforge:<file stem>` (e.g. `pcapforge:modbus`) with
`INDEXED_EXTRACTIONS = json`, `TIMESTAMP_FIELDS = ts`, `TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%6NZ`,
`MAX_DAYS_HENCE = 3650` and `MAX_DAYS_AGO = 10951` (capture dates are drawn per seed and can lie months ahead;
with Splunk's default of 2 days those events get the indexing time); in Elastic use one index per file
(`pcapforge-modbus`, ...) with `ts` as the timestamp field.

`detections/` is generated from the site model in `answers.json`:
- `suricata.rules` (sids 9100000+): any Modbus write to a PLC from a host that is not an approved writer
  (hosts of `modbus.operator` actors), device identification (function 43) from a host that is not a
  SCADA client, and per writable holding register with a normal band, writes above / below the band
  (raw register units; a FLOAT32 setpoint is matched with `byte_test` on the IEEE 754 bit pattern of a
  Write Multiple Registers request that starts at the point). When the site runs them (sids 9101000+):
  IEC 104 commands, interrogations and reset process from a host other than the SCADA master; DNP3
  select / operate / direct operate, write, restarts and disable unsolicited from a non-master; BACnet
  WriteProperty(Multiple), DeviceCommunicationControl, ReinitializeDevice and Register-Foreign-Device from
  a host other than the BMS workstations, and BBMD table changes from anyone; CIP writes, resets and
  Forward_Open from a host other than the EtherNet/IP originators. Suricata's Modbus, DNP3 and ENIP
  parsers are off by default: `suricata -r capture.pcap -S suricata.rules --set
  app-layer.protocols.modbus.enabled=true --set app-layer.protocols.dnp3.enabled=yes --set
  app-layer.protocols.enip.enabled=yes -k none -l logs`.
- `sigma/*.yml`: SIEM-agnostic [Sigma](https://sigmahq.io) rules over the JSON-lines export
  (`logsource: {product: pcapforge, service: <dataset>}`): the unapproved-writer and device-identification
  rules (same roles as the Suricata ones), an out-of-band write rule keyed on the export's `in_normal_band`
  field, a connection-from-an-unexpected-host rule over the `flows` dataset, reads rejected with Illegal
  Data Address (register-map enumeration), an alarm-acknowledge / reset coil write and an alarm threshold
  written out of band (alarm suppression, from the PLC register map), and, when a `dhcp.client` runs, a
  new-host-on-the-control-LAN rule. Over the telecontrol, building and packaging datasets: IEC 104 commands
  and interrogations, DNP3 controls / writes and polls, BACnet writes and foreign-device registrations, and
  CIP writes and Forward_Open from hosts other than the approved masters, plus BBMD table changes. Two
  Sigma 2.0 correlation rules ship with their base rules in the same file: a port-502 sweep (one source,
  at least three hosts in ten minutes) and the same point set to the same value by two hosts within four
  hours (command replay). Convert with
  [sigma-cli](https://github.com/SigmaHQ/sigma-cli), e.g. `sigma convert -t splunk detections/sigma/`
  (correlations need a backend that supports them, e.g. `splunk` or `esql`; checked with sigma-cli 3.1).
  Every rule is evaluated against the export in the tests: each fires on its scenario's incident and
  none fires on `ot-baseline-operations`.
- `hunting.md`: per question, the answer, the verified Wireshark filters from the answer key, and a
  Splunk SPL search and Kibana KQL filter over the export with a "what to look for" note. The SPL/KQL
  come from the scenario's `hunt` blocks; `tests/test_siem_queries.py` runs them for every scenario and
  level against Splunk Enterprise 10.6 and Elasticsearch 9.5 (KQL through the Elasticsearch `kql` query;
  index mappings from the find-structure API that Kibana's file upload uses): each must run without
  errors and match events, and an answer that is a field value of the dataset must be in what it returns.
  The CI job `siem-queries` runs it against the official Docker images; locally set
  `PCAPFORGE_SPLUNK_URL` / `PCAPFORGE_SPLUNK_AUTH` and `PCAPFORGE_ELASTIC_URL` (see the module docstring).

On the hard level the unauthorized writes come from the approved engineering workstation, so only
the out-of-band rules fire; the unapproved-writer rule fires on easy and medium.

## Zeek logs

`--zeek` (on `generate` or `export`) runs [Zeek](https://zeek.org) over the capture and keeps its logs in
`zeek/`, one JSON object per line (`LogAscii::use_json`): `conn.log`, `dns.log`, `ntp.log`, `dhcp.log`,
`modbus.log`, `dnp3.log` and, from the policy scripts pcapforge loads, `known_hosts.log`,
`known_services.log`, `known_modbus.log` (Modbus masters and slaves) and `modbus_register_change.log`.
`Site::local_nets` is set to the scenario's subnets, so `local_orig` / `local_resp` and the `known_*`
logs describe the site. Zeek runs with `-D` (deterministic mode), so the same capture always gives
byte-identical logs; `packet_filter.log` (wall-clock start time only) is not kept. `conn.log` carries the
MACs on the wire (`orig_l2_addr`, `resp_l2_addr`, from `policy/protocols/conn/mac-logging`).

Zeek itself has no analyzer for S7comm, OPC UA, IEC 104, BACnet or EtherNet/IP. CISA's
[ICSNPP](https://github.com/cisagov/icsnpp) packages add four of them, and pcapforge loads every one of these
that zkg installed: `icsnpp-s7comm` (`s7comm.log`, `s7comm_read_szl.log`, `cotp.log`), `icsnpp-opcua-binary`
(`opcua_binary*.log`), `icsnpp-bacnet` (`bacnet.log`, `bacnet_property.log` with WriteProperty values),
`icsnpp-enip` (`enip.log`, `cip.log` with Forward_Open, `cip_io.log` per class 1 I/O packet) and
`icsnpp-dnp3` (`dnp3_control.log` with each select / operate and its point, `dnp3_objects.log`). IEC 104
comes from pcapforge's own Spicy analyzer (`src/pcapforge/zeek_analyzers/iec104`): `iec104.log` has one
record per APDU (I / S / U frame: sequence numbers, U function, type, cause, common address, the
information object addresses), `iec104_command.log` one per command object (single / double /
regulating step command, set point, interrogation, counter interrogation: IOA, value, qualifier,
select or execute). Field names follow `siem/iec104.jsonl`.

The ICSNPP versions are pinned in `src/pcapforge/zeek.py` (`ICSNPP`). Install everything as root after
Zeek with the `ANALYZERS_INSTALL` command there: zkg, cmake and the Zeek headers, a build of each ICSNPP
package, and `spicyz` compiling the IEC 104 analyzer into Zeek's Spicy module directory (loaded
automatically) with its logging scripts in the site directory. CI does the same; re-run it after
updating pcapforge so the installed analyzer matches. The ENIP and OPC UA packages draw the ids that link
their logs (`packet_correlation_id`, `*_link_id`) from the OS random source, which `-D` does not seed, so
pcapforge renumbers them in order of first appearance. The `zeek/zeek` image has none of these
(point `PCAPFORGE_ZEEK_IMAGE` at an image that has them).

The hunting guide gives a Zeek query per question where a Zeek log can show the answer: a `jq`
command over `zeek/<log>.log`, run from the run directory. `tests/test_zeek_hunts.py` runs every one
over the logs of every scenario and level, compares jq's output with pcapforge's own evaluation, and
checks that text answers found in the log are in the output.

`detections/pcapforge-ot.zeek` (written with the other detections, and loaded by `--zeek`) turns the
Suricata rules' roles into Zeek notices: `notice.log` names Modbus writes, device identification, DNP3
controls, IEC 104 commands, BACnet writes and CIP writes / Forward_Open from hosts outside the approved
roles, and Modbus setpoints written outside their normal band. On every scenario and level the notices
name the attacker and only the attacker (`tests/test_zeek_notices.py`); the baseline raises none. The IEC
104 analyzer also recognises the protocol on other ports by the STARTDT / TESTFR handshake.

Zeek is found as `PCAPFORGE_ZEEK` (path to the binary), `zeek` on `PATH` or `/opt/zeek/bin/zeek`, and on Windows
in the default WSL distribution (`zeek` on its `PATH` or `/opt/zeek/bin/zeek`, run through `wsl.exe`); otherwise
the official `zeek/zeek:lts` Docker image is used (`PCAPFORGE_ZEEK_IMAGE` overrides it; the container has
no network). Zeek does not run natively on Windows. In WSL Ubuntu 24.04 the packages CI uses install it to
`/opt/zeek` (`zeek-lts-core` from the `security:zeek` repository, see `.github/workflows/ci.yml`). When no Zeek
is found, the error message includes the install command for the platform (WSL Ubuntu 24.04 on Windows,
Ubuntu 24.04, Homebrew on macOS).

```console
$ pcapforge generate -s ot-baseline-operations -d medium --seed zeek-smoke --duration 10m --siem --zeek
$ pcapforge export out/ot-baseline-operations_medium_zeek-smoke --zeek
...
out/ot-baseline-operations_medium_zeek-smoke/zeek/bacnet.log  (189 records)
out/ot-baseline-operations_medium_zeek-smoke/zeek/bacnet_property.log  (7464 records)
out/ot-baseline-operations_medium_zeek-smoke/zeek/cip.log  (5282 records)
out/ot-baseline-operations_medium_zeek-smoke/zeek/cip_io.log  (10634 records)
out/ot-baseline-operations_medium_zeek-smoke/zeek/conn.log  (215 records)
out/ot-baseline-operations_medium_zeek-smoke/zeek/cotp.log  (1340 records)
out/ot-baseline-operations_medium_zeek-smoke/zeek/dns.log  (193 records)
out/ot-baseline-operations_medium_zeek-smoke/zeek/enip.log  (2644 records)
out/ot-baseline-operations_medium_zeek-smoke/zeek/known_hosts.log  (5 records)
out/ot-baseline-operations_medium_zeek-smoke/zeek/known_modbus.log  (6 records)
out/ot-baseline-operations_medium_zeek-smoke/zeek/known_services.log  (11 records)
out/ot-baseline-operations_medium_zeek-smoke/zeek/modbus.log  (14890 records)
out/ot-baseline-operations_medium_zeek-smoke/zeek/modbus_register_change.log  (5 records)
out/ot-baseline-operations_medium_zeek-smoke/zeek/ntp.log  (28 records)
out/ot-baseline-operations_medium_zeek-smoke/zeek/opcua_binary.log  (719 records)
out/ot-baseline-operations_medium_zeek-smoke/zeek/opcua_binary_read.log  (238 records)
...
out/ot-baseline-operations_medium_zeek-smoke/zeek/s7comm.log  (1340 records)
out/ot-baseline-operations_medium_zeek-smoke/zeek/s7comm_read_szl.log  (20 records)
```
