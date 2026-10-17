# Scenarios

| id | line | techniques | what happens |
|---|---|---|---|
| `ot-modbus-write-manipulation` | OT | T0855, T0836 (+T0888, T0861 with discovery) | An HMI and a historian poll the water-treatment PLCs (medium/hard: also a SCADA/OPC UA server, an S7comm-monitored S7-1500, a telecontrol outstation for the drawn process — IEC 60870-5-104, DNP3 or BACnet/IP — and EtherNet/IP tag reads from a CompactLogix). A host outside the approved change path writes setpoints outside their normal band. |
| `ot-modbus-discovery` | OT | T0846, T0888, T0861 | An HMI and a historian poll the PLCs. A host that is not a normal Modbus client sweeps the control subnet for port 502, then reads each PLC's device identification (function 43) and enumerates its register map (oversized reads rejected with illegal_data_address). Reconnaissance only — nothing is written. Easy and medium: a Raspberry Pi on the control LAN, which on medium also brings up IPv6 and announces itself over mDNS (avahi); hard: a laptop routed from the IT subnet. |
| `ot-modbus-command-replay` | OT | T0855, T0831 | An HMI and a historian poll the PLCs and the engineering workstation makes approved setpoint changes. An unapproved host re-sends copies of those operator commands (same register, same value) off-cycle, so every written value is inside the normal band — the tell is the source and the timing, not the value. |
| `ot-modbus-coil-manipulation` | OT | T0855, T0831 (+T0878 with ack) | An HMI and a historian poll the PLCs. An unapproved host writes Modbus coils (function 5 / 15) to force actuators out of their normal state — stop a pump, open a breaker, disable a fan — and on medium/hard acknowledges the resulting alarm to clear it. The status discretes that mirror each command flip. |
| `ot-modbus-alarm-masking` | OT | T0878, T0836, T0855 | An HMI and a historian poll the PLCs. An unapproved host first moves an alarm threshold out of band so it can no longer trip, then pushes the setpoint that threshold was guarding out of its normal band — so the harmful change raises no alarm. The order of the two writes is the tell. |
| `ot-baseline-operations` | OT | none (no incident) | Normal operations only: polling, OPC UA/S7 monitoring, telecontrol (IEC 104 / DNP3 / BACnet by process) and EtherNet/IP (medium/hard), approved operator changes, NTP/DNS/Windows chatter. Process drawn per seed on every level. For baselining exercises, false-positive tuning and anomaly-detection datasets. |

Difficulty levels of `ot-modbus-write-manipulation`:

| | easy | medium | hard |
|---|---|---|---|
| length | 15 min, ~14k packets | 45 min, ~199k packets | 2 h, ~694k packets |
| process | drinking water | drawn per seed: drinking water, wastewater, building HVAC or power substation | drawn per seed (same four) |
| PLCs | 2 | 2–4 Modbus (per seed) + 1 Siemens S7-1500 | 3–5 Modbus (per seed) + 1 Siemens S7-1500 |
| writer | unknown Raspberry Pi plugged into the control LAN during the capture (leases its address from the firewall's DHCP pool) | laptop on the IT subnet, routed through the firewall (gateway MAC) | the legitimate engineering workstation |
| discovery | identity read + register enumeration | yes | none |
| changes | burst of extreme values | spread over 20 min, moderate values | spread over 1 h, values just outside the band, mixed with 6 legitimate operator changes |
| OT background | HMI and historian poll the PLCs (Modbus/TCP) | + SCADA server polls the PLCs and serves them over OPC UA to the historian (one subscription per PLC: Publish every 2 s, ServerStatus Read every 5 s); HMI and historian read the S7-1500 over S7comm; the HMI is the telecontrol master of the process' outstation (IEC 60870-5-104 RTU at a substation with counter interrogations and in-band setpoint / switching commands, DNP3 RTAC at a water or wastewater plant reporting events unsolicited, two BACnet/IP controllers in a building with approved setpoint overrides and a BMS server on the plant IT network registered with the BBMD as a foreign device); HMI and historian read a CompactLogix over EtherNet/IP, which scans a PowerFlex 525 drive with class 1 I/O (UDP 2222, 100 ms) | + OPC UA secure-channel renewals |
| noise | NTP, ARP | + a vendor service laptop that joins over DHCP (DORA, ARP probes, DHCPINFORM) and releases its lease before leaving, DNS, Windows chatter (LLMNR, NBNS, mDNS, SSDP, browser announcements), IPv6 of the Windows hosts (LLMNR/mDNS over IPv6, DHCPv6 Solicits every 2 min from hosts up long before; the firewall's Router Advertisements with a ULA prefix; the laptop that joins shows its interface start: link-local DAD, Router Solicitation, MLDv2, SLAAC stable and temporary addresses, unicast Neighbor Discovery), retransmissions, capture starts mid-session, SPAN artefacts (VLAN 20, 0.2 % duplicated frames, 0.05 % sensor drops) | + a dual-stack site: the firewall advertises a global prefix (2001:db8::/32) and the DC as IPv6 DNS server (RDNSS), the DNS answers AAAA for the Windows PCs and servers, and their name lookups, NTP to the DC and the historian's OPC UA session run over IPv6 (from temporary to stable addresses, MSS 1440, Neighbor Unreachability Detection); PLC traffic stays IPv4. More retransmissions, twice the Windows chatter, VLAN 120, 0.5 % duplicates, 0.1 % drops |

## Languages

`--lang pl` (Polish) or `--lang de` (German) translates the student-facing prose: `briefing.md`, the question texts in `answers.json` and `submission_template.yaml`. Answers, filters and register names stay unchanged. Scenarios provide translations under `translations: {<lang>: {title, briefing, questions}}`; process profiles translate their title the same way. Register names and point descriptions are not translated.

## Writing a scenario

Scenarios are YAML files under `scenarios/<line>/<id>/scenario.yaml` (CC-BY-4.0). They are validated by
[`scenario.schema.json`](../src/pcapforge/scenario/scenario.schema.json); add the
`# yaml-language-server: $schema=...` header line for editor completion. The full authoring guide
(topology, actors, `${}` references and `when`, difficulty knobs, questions, testing checklist) is in
[CONTRIBUTING.md](../CONTRIBUTING.md#writing-a-scenario). The main sections:

```yaml
schema: pcapforge/scenario@1
id: ot-modbus-write-manipulation
line: ot
mitre:
  - {framework: ics, id: T0836, name: Modify Parameter}
topology:
  sensor: control                               # SPAN port location
  subnets: [{id: control, pool: 10.0.0.0/8, prefix: 24}]
  hosts:
    - {id: plc, count: "${vars.plc_count}", device: [schneider-m340, siemens-s7-1200], subnet: control}
actors:
  - {id: plc_service, type: modbus.server, hosts: plc, params: {process: water_treatment}}
  - {id: change, type: modbus.writer, hosts: "${vars.writer_host}", incident: true, params: {...}}
difficulty:
  easy: {duration: 15m, impairments: {retransmit_rate: 0}, vars: {plc_count: 2, writer_host: rogue}}
questions:
  - id: source_ip
    text: Which IP address issued the unauthorized Modbus write requests?
    answer: "${facts.change.source.ip}"
    check: {filter: "mbtcp && modbus.func_code in {5, 6, 15, 16} && ip.src == ${facts.change.source.ip}", expect: {min: 1}}
    hunt:                                       # optional, rendered into detections/hunting.md
      dataset: modbus
      spl: "index=* sourcetype=pcapforge:modbus write=true | stats count BY src, dest"
      kql: "write : true"
      look_for: Writers other than the engineering workstation.
```

## Built-in actor types

- `modbus.server`
- `modbus.poller`
- `modbus.operator`
- `modbus.writer`
- `dns.server`, `dns.client`
- `ntp.server`, `ntp.client`
- `s7.server`, `s7.client` (Siemens S7comm on ISO-TSAP port 102, optional extra `s7`): an S7-1200/1500 CPU whose data blocks mirror its process model (DB1 measurements and DB2 setpoints as REAL, DB3 status bits) and whose SZL identity (order code, firmware, module name, serial) follows the device profile; the client keeps one session per PLC (COTP connect, setup communication, SZL identification), reads the DBs with cyclic multi-item Read Var jobs and the CPU state (SZL 0x0424) every `szl_interval` seconds. `params: {process, rack, slot}` / `{targets, interval, jitter, dbs, identify, szl_interval}`
- `opcua.server`, `opcua.client` (OPC UA binary on port 4840, SecurityPolicy None, optional extra `opcua`): a SCADA / OPC UA server that publishes the process points of the PLCs in `sources` (hosts of a `modbus.server`) as tags `ns=2;s=PLC01.clearwell_level`, grouped per PLC into `Measurements`, `Setpoints`, `Commands` and `Status`, with values from the PLC's process model at the request's virtual time and its BuildInfo from the device profile's `identity`; the client (historian / MES collector) opens one long-lived session (Hello, OpenSecureChannel, CreateSession, ActivateSession, NamespaceArray read, browse of the tag tree), creates one subscription per PLC with monitored items per tag group, sends Publish requests every `publishing_interval`, reads ServerStatus State/CurrentTime every `keepalive_interval` and renews the secure channel at 75 % of `token_lifetime`. `params: {sources}` / `{server, publishing_interval, keepalive_interval, token_lifetime, jitter, application, product_uri}`
- `dhcp.server`, `dhcp.client` (DHCPv4, RFC 2131): the server (e.g. the firewall) leases addresses from `pool` on one subnet and hands out router, DNS, domain and NTP; static hosts on that subnet stay outside the pool. A client either holds a lease from before the capture and renews it at T1, or joins at `join` (DISCOVER / OFFER / REQUEST / ACK from 0.0.0.0 to 255.255.255.255, ARP address conflict detection, then a DHCPINFORM on Windows) and can leave at `leave` with a DHCPRELEASE. Message formats follow the OS client (`style`: `windows`, `dhcpcd`). `params: {subnet, pool, lease, dns, ntp}` / `{server, join, leave, release, style}`
- `iec104.server`, `iec104.client` (IEC 60870-5-104 on port 2404): a substation RTU whose information objects mirror its process (single points 1001+, measured short floats 2001+, setpoint feedback 3001+, integrated totals for totaliser points, single commands for writable coils and short-float setpoint commands for writable setpoints); it answers STARTDT / TESTFR, general interrogation (ACTCON, COT 20 data, ACTTERM), counter interrogation (freeze, then read: COT 37 totals with sequence numbers) and clock sync, executes commands on its process (select-before-operate for single commands; ACTCON, ACTTERM and the state change as return information), sends measured values periodically (COT 1, `cyclic_s`) and spontaneously with CP56Time2a time tags when a value moves beyond `deadband` (COT 3), and holds I-frames once k = 12 are unacknowledged. The master (SCADA) keeps one session per RTU: STARTDT, clock sync, GI, then S-frame acknowledgements about every `t2_s`, TESTFR after `t3_s` of silence, a periodic GI (`gi_interval_s`), counter interrogations (`counter_interval_s`) and in-band operator commands: setpoint changes (`setpoint_interval_s`) and switching (`switching_interval_s`; 0 disables either).
- `dnp3.server`, `dnp3.client` (DNP3 over TCP port 20000, polled by default): an RTAC outstation with binary inputs (g1v2, events g2v2), analog inputs (g30v5 float, events g32v7), counters (g20v1), binary output and analog output status (g10v2, g40v3) from its process, link-layer CRCs, IIN bits (restart, need time, class events) and event confirms. The master disables unsolicited, runs an integrity poll, clears the restart bit, synchronises time (record current time + write g50v3), then polls events every `event_s` and integrity every `integrity_s`. With `unsolicited: true` on both: the outstation opens each session with a null unsolicited response, the master enables unsolicited reporting of classes 1-3 after its startup, and the outstation scans its process every `scan_s` and reports events in unsolicited responses (own sequence numbers, each confirmed by the master; repeated after `confirm_timeout_s` without a confirm); event and integrity polls stay as a slow backstop.
- `bacnet.server`, `bacnet.client` (BACnet/IP on UDP 47808): building controllers (Siemens PXC) with analog-input / analog-value / binary-input / binary-value objects for the process points (BACnet engineering units, descriptions) and a device object from the device profile; Who-Is / I-Am broadcasts, ReadProperty and ReadPropertyMultiple, SubscribeCOV and unconfirmed COV notifications when a value moves by `cov_increment`, WriteProperty on commandable values (16-slot priority array over the relinquish default; the winner drives the process). The workstation discovers the controllers, reads the device and point database, subscribes to `cov` analog inputs, polls present values every `poll_s` and makes `writes` approved setpoint overrides at `write_priority` (read back, relinquished after `relinquish_s`). A client with `bbmd` sits on another subnet and registers as a foreign device with that controller (Register-Foreign-Device every `fd_ttl_s`, broadcasts via Distribute-Broadcast-To-Network, Forwarded-NPDUs both ways).
- `enip.server`, `enip.client` (EtherNet/IP explicit messaging on TCP/UDP 44818): a CompactLogix whose controller-scoped tags (REAL / DINT / BOOL) mirror its process; ListIdentity, ListServices, RegisterSession, Identity Get_Attribute_All, Forward_Open / Forward_Close (class 3) and connected Multiple Service Packet Read Tag requests with sequence counts. The HMI browses with a ListIdentity broadcast, opens one connection per controller and reads every tag each `interval`.
- `enip.scanner`, `enip.adapter` (EtherNet/IP class 1 implicit I/O on UDP 2222): the Logix (scanner) opens a point-to-point class 1 connection to a PowerFlex 525 drive's embedded adapter at a time drawn from `open_at` (seconds; RegisterSession, Forward_Open to the Assembly object), then O->T (Logic Command, speed reference from the controller's process) and T->O (Logic Status, feedback, Datalinks) run cyclically every `rpi_ms`; the composer continues the cyclic stream after the recorded first exchange.
- `windows.chatter` (names the site DNS does not know: NXDOMAIN, then LLMNR, NBNS and mDNS fallback; SSDP; browser host announcements; `params: {rate}`)

Device and OS-stack profiles are in [`profiles/devices.yaml`](../src/pcapforge/profiles/devices.yaml). Their OUIs are checked against Wireshark's manufacturer database. Process models are in [`profiles/processes/`](../src/pcapforge/profiles/processes/). New actors go in `src/pcapforge/actors/` and implement `plan()`, plus `serve()` for servers or `execute()` for clients. Actors that send one-way multicast or broadcast datagrams list the recording sinks they use in `sinks` (see `topology.SINKS`). Actors built on a third-party library declare it as an optional extra in `requires` and import it lazily. [CONTRIBUTING.md](../CONTRIBUTING.md#extending-the-engine) has the details.

## Process profiles

A `modbus.server` actor serves one process profile (`params: {process: <id>}`) from `src/pcapforge/profiles/processes/`. Each is a register map with normal bands and a deterministic process model, so polled values move over the virtual day and a written setpoint drives the measurements and alarm bits that depend on it:

- `water_treatment`: drinking-water clearwell and chlorination (level, chlorine residual, pH, pump speed, daily inlet/outlet flow).
- `wastewater_treatment`: activated-sludge aeration basin and clarifier. The DO setpoint and the daily influent curve drive blower speed, dissolved oxygen and effluent ammonia; return-sludge flow sets the sludge blanket level; plus pH, MLSS and alarm bits.
- `hvac_building`: AHU, three fan-coil zones and a chiller. A daily occupancy curve and outdoor temperature load the zones; zone temperatures track their setpoints while the fan-coil valves, CO2-driven outdoor-air damper, chilled-water return and chiller load absorb the load; plus fan and chiller status bits.
- `power_substation`: 33/11 kV transformer with on-load tap changer and four feeders. Feeder breaker commands (coils) are mirrored by status bits (discretes). The load curve drives feeder currents, power factor, Mvar and transformer oil/winding temperature. The tap-position setpoint moves the busbar voltage (1.25 % per step) and can trip the voltage alarms.
