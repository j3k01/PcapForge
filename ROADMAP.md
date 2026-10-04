# Roadmap

State at v0.1.0:
- one OT scenario (`ot-modbus-write-manipulation`, easy/medium/hard; the process and PLC count are drawn per seed);
- Modbus/TCP, OPC UA and S7comm, plus DNS/NTP/ARP and Windows name-resolution chatter;
- SIEM export, Suricata rules, grading, student/instructor packages, Polish handouts;
- CI and releases on GitHub.

Effort: **S** = hours, **M** = 1–3 days, **L** = a week or more.
Status: `[ ]` open, `[~]` partly done.

## 1. Realism of the traffic (highest value, fully defensive)

- [ ] **IPv6 baseline on Windows hosts** (L). Real Windows machines always show:
  - link-local addresses;
  - Router/Neighbor Solicitation and MLD reports;
  - DHCPv6 Solicit, and LLMNR/mDNS over IPv6.

  Needs IPv6 support in the composer (headers, checksums, L2 multicast mapping, visibility). This is the most visible gap for an experienced analyst.
- [ ] **TCP segmentation in the composer** (M): split payloads larger than the MSS into several segments with correct seq/ack. This removes the "every message fits in one segment" limit (today it constrains OPC UA) and allows bulk transfers.
- [ ] **SPAN/sensor artefacts as difficulty knobs** (M):
  - duplicated frames (a SPAN that mirrors both directions);
  - sensor drops ("ACKed unseen segment");
  - 802.1Q VLAN tags;
  - sensor clock offset/drift.
- [ ] **DHCPv4** (M): leases and renewals for DHCP-managed hosts (IT side of the OT DMZ, laptops); static IPs stay on the control LAN.
- [ ] **Windows domain baseline** (L): Kerberos/LDAP/SMB to the DC using a *synthetic* local directory, e.g. a Samba AD container. Never the machine's real credentials.
- [ ] **Long captures** (M): 24 h and multi-million packets. Needs a streaming compose and memory profiling, and a check that recording time scales linearly.

## 2. OT content

- [ ] **More OT incident scenarios**, authored by maintainers. Automated AI-assisted authoring of new incident behaviour is often stopped by content filters, so these are best written by hand and then reviewed. Candidates:
  - coil manipulation with alarm acknowledgement: T0831, T0878;
  - Modbus device discovery on the control subnet: T0846, T0888;
  - replay of captured legitimate commands;
  - alarm-threshold masking followed by a setpoint change.
- [x] **Baseline-only scenario** (S): `ot-baseline-operations` covers normal operation for all four process profiles, with no incident. The questions cover HMI, poll cycle, PLC count, read function codes, approved writes and writer, time source and OPC UA server.
- [ ] **More protocols as background actors** (M each): IEC 60870-5-104 (`c104`), BACnet/IP (`bacpypes3`), EtherNet/IP/CIP, DNP3.
- [~] **Process-model polish** (S): translated process titles (pl: done); still open: point descriptions, more device profiles (ABB, Honeywell, Phoenix Contact), and per-vendor register-map styles (1-based addressing, 32-bit floats across two registers).

## 3. IT line (benign equivalents only, see CONTRIBUTING.md)

- [ ] **IT background** (L): HTTPS browsing to local web servers with a private CA and realistic SNI/certificates, software updates, DHCP, AD traffic (see 1.).
- [ ] **IT scenarios** (M each, maintainer-authored, reviewed against the defensive policy):
  - periodic HTTPS check-ins to a local test server;
  - DNS-based data transfer to a local resolver;
  - port scan followed by authentication failures against local test services;
  - volumetric flood against a local sink;
  - bulk HTTP upload.

## 4. Training workflow

- [ ] **Debrief report** (M): `pcapforge report <run>` builds a static HTML page with:
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
- [ ] **Sigma rules** (S) over the exported JSONL, for SIEM-agnostic detections.

## 6. Platform and project

- [ ] **Publish to PyPI** (S): check that the `pcapforge` name is free; add a trusted-publishing workflow on tags.
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
- The process title and register names in handouts are English even with `--lang pl`.
