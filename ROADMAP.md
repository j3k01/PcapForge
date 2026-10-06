# Roadmap

Current state:
- OT scenarios: a baseline (no incident) plus five incident scenarios — setpoint manipulation
  (`ot-modbus-write-manipulation`), device discovery (`ot-modbus-discovery`), command replay
  (`ot-modbus-command-replay`), coil manipulation (`ot-modbus-coil-manipulation`) and alarm masking
  (`ot-modbus-alarm-masking`); the process, PLC count and device pool are drawn per seed;
- protocols: Modbus/TCP, OPC UA, S7comm, IEC 60870-5-104, DNP3, BACnet/IP, EtherNet/IP (CIP), DHCPv4,
  DNS/NTP/ARP and Windows name-resolution chatter, plus an IPv6 link-local baseline;
- composer realism: causal retiming with TCP segmentation, SPAN artefacts (duplicates, drops, VLAN,
  sensor clock), a host-firewall model (filtered vs closed ports), and RFC-correct DHCP delivery;
- process models: per-point descriptions, a vendor (Modicon) register-numbering convention and
  IEEE 754 FLOAT32 points across two registers (ABCD or word-swapped CDAB per profile);
- SIEM export, Suricata and Sigma rules, grading, student/instructor packages, CTFd export,
  debrief report, Polish handouts; CI and releases on GitHub.

Effort: **S** = hours, **M** = 1–3 days, **L** = a week or more.
Status: `[ ]` open, `[~]` partly done, `[x]` done.

### Next up (open items, highest value first)
- Long captures (24 h, multi-million packets): streaming compose and memory profiling (section 1).
- Detection: Zeek output, validated SPL/KQL (section 5).
- IT line: benign HTTPS, DHCP and AD baselines, then IT scenarios (section 3).
- Platform: PyPI distribution name, Docker image, docs site, macOS check (section 6).

## 1. Realism of the traffic (highest value, fully defensive)

- [x] **IPv6 baseline on Windows hosts** (L), behind the scenario var `ipv6` (medium/hard). Windows hosts on the sensor segment get a link-local address with DAD, Router Solicitations and MLDv2 reports, synthesized like ARP. They also send LLMNR/mDNS over IPv6 (copies of the recorded datagrams) and recorded DHCPv6 Solicits. Still open: unicast IPv6 conversations and Router Advertisements (there is no IPv6 router in the model). Original notes on what real Windows machines show:
  - link-local addresses;
  - Router/Neighbor Solicitation and MLD reports;
  - DHCPv6 Solicit, and LLMNR/mDNS over IPv6.
- [x] **TCP segmentation in the composer** (M). Payloads larger than the path MSS go out as full segments with correct seq/ack and PSH only on the last. They are spaced at the sender's link rate and limited by the initial congestion window and the receiver's window; the receiver ACKs every second segment. The shipped OT scenarios contain no message above the MSS, so this is proven by `tests/test_compose_segmentation.py`.
- [x] **SPAN/sensor artefacts as difficulty knobs** (M): `impairments.span_duplicates`, `sensor_drop` and `vlan`. Frames the answer key refers to are never dropped or duplicated. Original scope:
  - duplicated frames (a SPAN that mirrors both directions);
  - sensor drops ("ACKed unseen segment");
  - 802.1Q VLAN tags;
  - sensor clock offset/drift: `impairments.clock_offset` and `clock_drift_ppm` (number or per-seed range); answers.json records the applied values under `capture.sensor_clock`.
- [x] **DHCPv4** (M): `dhcp.server` / `dhcp.client` actors with Windows and dhcpcd message formats; joins (DORA, ARP address conflict detection, DHCPINFORM), renewals at T1 and releases; static hosts stay outside the pool. `siem/dhcp.jsonl` in the SIEM export. In `ot-modbus-write-manipulation` the rogue Raspberry Pi (easy) leases its address when it is plugged in, and a vendor service laptop joins and leaves on medium/hard. Still open: DHCP on the IT side (not visible from the control-LAN sensor in the current scenarios).
- [x] **Firewalled / filtered ports** (M): the composer honours the stack's `drops_unsolicited` / `syn_rto_s` (`compose/_apply_host_firewall`), so a port sweep of a host-firewalled machine (Windows default) shows a retransmitted SYN and no reply (filtered) instead of a RST (closed). In `ot-modbus-discovery` the swept Windows hosts read as filtered and the PLCs' closed/listening ports differ.
- [ ] **Windows domain baseline** (L): Kerberos/LDAP/SMB to the DC using a *synthetic* local directory, e.g. a Samba AD container. Never the machine's real credentials.
- [ ] **Long captures** (M): 24 h and multi-million packets. Needs a streaming compose and memory profiling, and a check that recording time scales linearly.

## 2. OT content

- [x] **More OT incident scenarios** (the originally listed candidates are all shipped; more can be added):
  - [x] Modbus device discovery on the control subnet (T0846, T0888, T0861): `ot-modbus-discovery`
    (`modbus.scanner` actor — a port-502 subnet sweep, device identification and register enumeration,
    no writes);
  - [x] replay of captured legitimate commands (T0855, T0831): `ot-modbus-command-replay`
    (`modbus.replay` actor — re-sends the operator's writes verbatim from an unapproved host; values
    stay in-band, so detection pivots on source and timing);
  - [x] coil manipulation with alarm acknowledgement (T0855, T0831, T0878): `ot-modbus-coil-manipulation`
    (`modbus.coil_writer` actor — forces command coils and optionally writes the alarm_ack/reset coil);
  - [x] alarm-threshold masking followed by a setpoint change (T0878, T0836, T0855):
    `ot-modbus-alarm-masking` (`modbus.alarm_mask` actor — blinds an alarm threshold, then pushes the
    setpoint it guarded out of band, in that order).
- [x] **Baseline-only scenario** (S): `ot-baseline-operations` covers normal operation for all four process profiles, with no incident. The questions cover HMI, poll cycle, PLC count, read function codes, approved writes and writer, time source and OPC UA server.
- [x] **More protocols as background actors** (M each): IEC 60870-5-104 (`iec104.*`, substation RTU), DNP3 (`dnp3.*`, polled RTAC at water/wastewater plants), BACnet/IP (`bacnet.*`, building controllers with COV) and EtherNet/IP/CIP (`enip.*`, CompactLogix tag reads). Hand-written with the standard library rather than `c104` / `bacpypes3` (deterministic, no background timers); wired into `ot-baseline-operations` and `ot-modbus-write-manipulation` on medium/hard (`vars.telecontrol` picks the outstation for the drawn process, `vars.enip`). Still open: IEC 104 control commands and counter interrogation, DNP3 unsolicited responses, BACnet WriteProperty / BBMD, EtherNet/IP implicit I/O (UDP 2222), SIEM datasets and detection rules for these protocols.
- [x] **Process-model polish** (S): translated process titles (pl), point descriptions on every register, and a vendor register-numbering convention in the handout (`register_style`, Modicon 4xxxx/3xxxx/1xxxx; the wire stays 0-based). 32-bit floats across two registers: a point may be `type: float32` (IEEE 754 in two registers, profile `word_order` `big` = ABCD or `little` = CDAB); `power_substation` (ABCD) and `hvac_building` (CDAB) use them for their analog values. Facts carry the written words as `registers`, the SIEM export decodes per point, the handout map shows the type, and float setpoints get exact Suricata band rules (`byte_test` on the IEEE 754 bit pattern of a Write Multiple Registers request starting at the point).

## 3. IT line (benign equivalents only, see CONTRIBUTING.md)

- [ ] **IT background** (L): HTTPS browsing to local web servers with a private CA and realistic SNI/certificates, software updates, DHCP, AD traffic (see 1.).
- [ ] **IT scenarios** (M each, maintainer-authored, reviewed against the defensive policy):
  - periodic HTTPS check-ins to a local test server;
  - DNS-based data transfer to a local resolver;
  - port scan followed by authentication failures against local test services;
  - volumetric flood against a local sink;
  - bulk HTTP upload.

## 4. Training workflow

- [x] **Debrief report** (M): `pcapforge report <run> [--grades grades.json]` writes a self-contained HTML page (inline SVG, no external resources) with:
  - the incident timeline, with frame numbers;
  - before/after charts of the affected process values, from `siem/modbus.jsonl`;
  - the questions with answers, and the class score summary from `pcapforge grade --json`.
- [x] **Graded hints** (S): the submission template shows each hint with its cost (20 % of the points, rounded up, same as the CTFd export); students list the ids they used under `hints_used`, and `grade` deducts the cost (never below 0). Honour system for offline use.
- [x] **CTF platform export** (S): `pcapforge export-ctfd <run>` writes ctfcli `challenge.yml` files with static/regex flags, hint costs, and the capture attached to the first challenge. Still open: tested only by unit tests, not yet imported into a live CTFd instance.
- [ ] **More languages** (S per language): the UI strings in `i18n.py` and the scenario `translations`.

## 5. Detection engineering

- [~] **Suricata rules.** Generated rules exist and are tested against Suricata 7 in WSL. Still to do: confirm in the CI log that the Suricata tests run rather than being skipped.
- [ ] **Validate SPL/KQL hunting queries** (M) against real Splunk and Elastic, e.g. Docker images in a separate CI job.
- [ ] **Zeek output** (M): when `zeek` is available (or via Docker), produce real `conn.log`/`modbus.log`/`dns.log` alongside the pcapforge JSONL.
- [x] **Sigma rules** (S): `detections/sigma/*.yml` over the exported JSONL (`logsource: {product: pcapforge, service: <dataset>}`): unapproved writer, out-of-band write, device identification, Modbus connection from an unexpected host (flows dataset), new host on the control LAN (DHCP), and per scenario: reads rejected with Illegal Data Address (register enumeration, discovery), alarm acknowledge / reset coil write (coil manipulation), alarm threshold written out of band (alarm masking), plus two Sigma 2.0 correlations shipped with their base rules — a port-502 sweep (value_count of destinations per source, discovery) and the same point set to the same value by two hosts (command replay). Generated from `answers.json`; converted with sigma-cli 3.1 (splunk, esql); the tests evaluate every rule on the export of its scenario and on `ot-baseline-operations` (no hits).

## 6. Platform and project

- [~] **Publish to PyPI** (S): the wheel now ships the scenarios (`pcapforge._scenarios`), and a manual trusted-publishing workflow exists (`.github/workflows/publish.yml`). Still open: the name `pcapforge` is taken on PyPI by an unrelated project, so a distribution name has to be chosen before publishing.
- [ ] **Docker image** (M): Wireshark, Suricata and pcapforge with rootless capture, so Windows/macOS users don't need Npcap or WSL.
- [ ] **macOS support check** (S): loopback aliases for 127.77.0.0/16 and a CI job on `macos-latest`.
- [ ] **Docs site** (S): MkDocs with the scenario authoring guide, the actor/profile reference generated from code, and the answers.json schema.
- [ ] **LLM "director"** (M, optional): turn a text description into a draft scenario YAML that a human reviews and that `pcapforge validate` checks. It never generates packets.
- [ ] **Web UI** (L, optional): pick scenario, difficulty and seeds, then download the class packages.
- [~] **Repository housekeeping** (S; badges, Dependabot and issue templates done; GitHub description/topics and labels still open):
  - README badges (CI, release, license);
  - GitHub description and topics;
  - Dependabot;
  - issue templates ("new scenario", "realism bug");
  - "good first issue" labels.

## Known limitations

- Re-recording the same plan can differ by a few packets (OS stack timing). Answers are unaffected, and byte-identical output needs the cached recording.
- Wireshark ≥ 4.4 is required for answer-key verification (older versions don't decode Write Single Register values).
- Register names and point descriptions in handouts stay English even with `--lang pl` (process titles are translated).
