# pcapforge — design notes

Defensive training-data generator: produces labeled PCAPs + answer keys for SOC /
detection-engineering exercises. All traffic comes from benign services and clients
(real OS TCP/IP stack on loopback); no malware, implants or payloads.

## Pipeline

1. **Plan** (deterministic from `--seed`): topology (subnets, hosts, MAC/vendor, OS
   profile), ordered action list with virtual timestamps, process-model parameters,
   facts for the answer key. `behavior_seed` (recorded behaviour) can be shared via
   `--base-seed` so many students reuse one recording; `seed` drives presentation.
2. **Record**: every host gets its own address in `127.77.0.0/16`. Servers (pymodbus
   `SimDevice`, NTP, DNS, asyncua OPC UA, python-snap7 S7) run in one asyncio thread; the orchestrator executes actions
   sequentially, sending a UDP marker (`<host-ip> -> 127.77.0.1:9999`) before each
   action. Capture: dumpcap (`\Device\NPF_Loopback` on Windows, `lo` on Linux) or
   tcpdump. On Linux the recorder first brings `lo` up if needed and adds
   `local 127.77.0.0/16 dev lo table local quickack 1` (immediate ACKs, see Linux results).
   Recording is cached by plan hash → byte-identical output for the same seed.
3. **Compose**:
   - flow assignment: a client-sent payload/SYN/FIN packet binds its flow to the latest
     marker, as does a server payload when the marker is the server host's own action
     (server-initiated data); other server replies and pure ACKs inherit the flow's current action;
   - causal retime: packets keep recorded order; gaps replaced by
     latency-to-sensor (per host) + processing time (per profile) + jitter;
   - rewrite: IP/MAC/ports (15020→502, 15353→53, 15123→123, 14840→4840, 10102→102, 12404→2404, 20020→20000,
     17808→47808, 14818→44818), ephemeral ports per OS
     profile, ISN per flow, TTL (−1 per routed hop), IP-ID behaviour, TCP options /
     window per OS profile, checksums recomputed;
   - L2: sensor = SPAN on one subnet; routed packets carry gateway MAC; ARP synthesized
     for on-segment pairs;
   - impairments: loss-after-sensor retransmissions (shift rest of flow by RTO);
   - setup/teardown actions of persistent sessions may be dropped (capture starts
     mid-session);
   - merge in Python (deterministic order, frame numbers known for answers.json).
4. **Answers**: facts + timeline events resolved to absolute UTC time and frame number;
   questions templated from facts (`${facts.x.y}`), each with a tshark display filter
   check used by tests.
5. **Verify**: tshark — checksums good, no malformed/expert errors, protocol decodes,
   every question check matches the pcap.

## Spike results (Windows 11, Npcap 1.88, pymodbus 3.15, tshark 4.6.7)

- Non-admin loopback capture works; capture filter `net 127.77.0.0/16`; 0 drops at
  ~6k pkt/s; ~0.17 ms per Modbus transaction → 10k actions ≈ 2 s.
- Clean dumpcap stop on Windows: start with `CREATE_NEW_PROCESS_GROUP`, send
  `CTRL_BREAK_EVENT`; first stderr line `Capturing on ...` = ready.
- Loopback artefacts to normalize: TTL 128, MSS 65495, WS=256, immediate ACKs,
  non-502 port (tshark cannot classify query/response until port is 502).
- pymodbus 3.15: use `SimDevice`/`SimData` (`ModbusDeviceContext` deprecated, removed
  in v4). Non-shared tuple `(coils, di, hr, ir)`. `action(fc, start, addr, count, regs,
  set_values)` is async; mutate `regs[addr-start+i]` for live process values; for writes
  it is called with `set_values` then again with `None`. Writes to unmapped addresses →
  exception code 2. FC43 device identification works via `identity=`.
  Pin `pymodbus~=3.15.0`: 3.16.0 cannot be imported without pyserial (`NameError: name 'pyserial'`).

## Linux results (WSL 2 Ubuntu 24.04, kernel 6.18, pymodbus 3.15, tshark 4.6.6 from ppa:wireshark-dev/stable, Suricata 7.0.3)

- Rootless: `unshare -rn pcapforge ...` / `unshare -rn pytest` make the user root of a private user +
  network namespace; dumpcap and tcpdump capture its `lo` (Ethernet link type, zeroed MACs; the
  composer strips it) and the recorder can configure it. No sudo, setcap or Docker.
- Linux loopback delays and piggybacks ACKs (pingpong mode), so a Modbus poll recording had 24 pure
  ACKs instead of ~5.7k and easy composed to ~8k packets instead of ~14k. The composer assumes the
  Windows behaviour (every segment ACKed at once, delayed ACK modelled per device); the `quickack 1`
  route restores it: easy seed 42 composes to 13 739 packets with the first write in frame 7197, as in
  the README's Windows run.
- dumpcap 4.2 has no `-F`; `-P` (classic pcap) works on 4.2 to 4.6. tcpdump run as root switches to
  user `tcpdump` before opening the output file (failed in the namespace): `-Z root` when euid is 0.
- Wireshark < 4.4 does not decode Write Single Register values (`modbus.data` only) and prints
  absolute times as `Mar 22, 2025 11:38:00.7 UTC`; answer-key verification requires 4.4
  (`tools.MIN_TSHARK`), the SIEM export also handles 4.2 (identical JSONL for seed 42 on all levels).
- Debian/Ubuntu's `suricata.yaml` enables the unix command socket under `/var/run`; offline runs as a
  normal user need `--set unix-command.enabled=no` with `--init-errors-fatal`.

## Scenario format

YAML per scenario (`scenarios/<line>/<id>/scenario.yaml`, CC-BY-4.0), validated by
`src/pcapforge/scenario/scenario.schema.json`. Sections: metadata, `mitre`, `topology`
(subnets from pools, hosts by role/profile), `actors` (type + params, `${vars.*}`
references), `difficulty` (`easy|medium|hard` → `vars` + standard knobs: duration,
background ratio, event spread, impairments), `questions`. Device and process profiles
live in `src/pcapforge/profiles/` so scenarios stay engine-agnostic.

## OT difficulty ideas (first scenario)

- easy: new unknown host, burst of clearly out-of-range writes, short capture.
- medium: host from IT subnet via firewall (gateway MAC), writes spread over ~30 min,
  mixed with reads.
- hard: writes from the legitimate engineering workstation, interleaved with legitimate
  operator writes, values only slightly outside the normal band, multi-hour capture.

## Status (resume point)

Done and committed (verify with `git log --oneline`):
- foundation: `pyproject.toml`, licenses, `rng.py`, `tools.py`, `ports.py`
- `profiles/` (devices/stacks with verified OUIs, `processes/water_treatment.yaml`), `process.py`
- `scenario/` loader + JSON schema (actor key is `hosts`; tshark set syntax needs commas `{5, 6}`)
- `scenarios/ot/modbus-write-manipulation/scenario.yaml`
- `topology.py` — world (hosts, devices, site name/code/domain: these appear in DNS payloads)
  from the behaviour seed; `assign_addresses(rng)` (IPs/MACs) from the presentation seed
- `plan.py` — `build_plan(scenario, difficulty, seed, base_seed, duration_override)`,
  `start_epoch` (behaviour level: NTP payloads carry it), `digest()` = recording cache key
- `actors/` — `modbus.server|poller|operator|writer`, `dns.server|client`, `ntp.server|client`,
  `dhcp.server|client` (DHCPv4 over real UDP sockets between the loopback addresses; the composer
  rewrites addresses and chaddr / client id, delivers DORA as 0.0.0.0 → 255.255.255.255 broadcasts or
  unicast to yiaddr by the broadcast flag, and adds RFC 5227 ARP probes / announcements after the ACK
  of a new lease, see `compose/dhcp.py`),
  `windows.chatter` (LLMNR, NBNS, mDNS, SSDP M-SEARCH, browser host announcements; timing,
  ports and payloads checked against a Windows 10 capture). Lookups only use names the site
  DNS zone does not resolve; hosts with a `dns.client` first query the site server for
  `name.<domain>` (shared `dns.query_server`), get NXDOMAIN and fall back 5–30 ms later
- link-local destinations: `topology.SINKS` are loopback stand-ins (`127.77.0.2-5`) for
  224.0.0.252, 224.0.0.251, 239.255.255.250 and the sender's subnet broadcast; actors
  declare the `(sink, port)` pairs they use and the recorder binds discard sockets there (no
  ICMP unreachable). Stack profiles carry `link_local` TTL/DF (Windows: LLMNR 1, SSDP 4,
  mDNS 255, broadcasts 128, no DF); devices with `browser` announce themselves.
- `record.py` — `recording_for(plan)` → cached pcap (DLT_NULL on Windows) + `.json` meta.
  Verified: easy plan = 4020 actions, 20 025 packets, 0 drops, ~3.7 s wall.
- `compose/` — `compose(plan, recording, out, seed, fmt)` → `ComposeResult` (spec below).
  Verified with tshark: 0 malformed/checksum/expert errors on easy and medium; ~120k pkt/s.

Status: first scenario complete end-to-end (compose/, answers.py, verify.py, cli.py, tests, README, CI),
with Windows background chatter on medium/hard (`vars.chatter`, `vars.chatter_rate`) and industrial
background protocols on medium/hard: S7comm (`vars.s7`) and a SCADA OPC UA server with a historian
subscription (`vars.opcua`), see below.
- SIEM export + detection content (`generate --siem`, `pcapforge export <run>`):
  - `export.py` — one tshark pass (`-T fields`, ~70 fields, occurrence aggregator `\x1f`), streamed and
    aggregated in Python into `siem/{flows,modbus,dns,ntp,name_resolution,arp,dhcp,iec104,dnp3,bacnet,enip}.jsonl`.
    IEC 104 gives one record per APDU (several share a TCP segment), DNP3 one per reassembled fragment,
    BACnet one per BVLC message (WriteProperty values and priority decoded from the payload), EtherNet/IP one
    per encapsulation message plus a per-minute, per-direction summary of class 0/1 I/O. Modbus pairs
    request/response by (TCP stream, transaction id) because exception responses carry no
    `modbus.request_frame`; TCP retransmissions are skipped. Writes are annotated from the register map
    of the PLC's process profile.
  - `detections.py` — `suricata.rules`, `sigma/*.yml` and `hunting.md` from `answers.json` alone. The
    Sigma rules (SIEM-agnostic, `logsource.service` = dataset) mirror the Suricata roles over the JSONL
    export plus an out-of-band write rule (on the export's `in_normal_band`) and, with a `dhcp.client`, a
    new-host-on-the-control-LAN rule; ids are a stable uuid5 of scenario+difficulty+seed+key. answers.json now has
    `actors` (id, type, incident, host ids) so roles come from actor types: PLCs = `modbus.server`,
    approved writers = non-incident `modbus.operator`, SCADA clients = `modbus.poller` + operators.
    The scenario's `operator_changes` actor is present at every level (count 0 on easy) so the approved
    writer is always modelled. Suricata `modbus: access ... address` is 1-based (wire address + 1;
    see `rust/src/modbus/detect.rs` tests); band rules use raw register units.
  - questions may carry a templated `hunt` block (`dataset`, `wireshark`, `spl`, `kql`, `look_for`),
    copied resolved into answers.json.
  - Verified locally: invariants in tests (out-of-band writes == incident writes, flows sum to IP
    packets/bytes); SPL/KQL run against Splunk and Elasticsearch (`tests/test_siem_queries.py`). Suricata test verified on Linux (Suricata 7.0.3): seed 42
    gives one band alert per incident write (fc 6 and 16), none for operator writes, and the
    unapproved-writer rule once per incident write on easy/medium, never on hard.
  - `zeek.py` (`--zeek`) — Zeek over the composed pcap with `-D` (deterministic: uids seeded with zero),
    JSON logs, `Site::local_nets` from the answer key's subnets and the Modbus / known-hosts policy scripts,
    written into `zeek/` through a generated site script; local binary first, else the `zeek/zeek:lts` image
    (`--network none`, run as the calling user). `packet_filter.log` is dropped (wall-clock time only).
    Verified with Zeek 8.0.10 LTS (OBS packages extracted user-space in WSL): incident writes appear once
    each in modbus.log at their frame time; on easy Zeek's Modbus requests equal the JSONL export, no
    weird.log; two runs give identical logs.
- Grading and packaging (`pcapforge grade`, `pcapforge package`):
  - `grade.py` — every run gets `submission_template.yaml` (question ids with null answers, text as
    comments). Submissions are YAML/JSON maps (student = file stem) or a class CSV
    (`student,question,answer`; repeated rows form a list). YAML is loaded with only the null resolver,
    so unquoted MACs (YAML 1.1 sexagesimal ints), `no`/`yes` and times stay strings. Scoring by question
    type: `ip`/`mac` normalised, `number` exact or `tolerance`, `timestamp` within `tolerance_s` (naive =
    UTC), `set` Jaccard (|∩|/|∪|), `map` matched keys / |key union| with 0.5 % relative numeric tolerance,
    `text` case/whitespace-folded against `answer` + `accept`. Unknown ids are reported, not scored.
  - `package.py` — student zip is an allow-list (capture, briefing, template; the template is
    rendered from answers.json for older runs without one), instructor zip is the whole run; members
    sorted with a fixed timestamp, so zips are byte-identical. `release.yml` packages every run.
- Linux: full suite (120 tests incl. Suricata, OPC UA and S7comm; `pip install -e .[test,opcua,s7]`) passes
  rootless under `unshare -rn pytest`; see Linux results.
- Industrial background protocols (medium/hard only, `vars.s7` / `vars.opcua`; easy's plan digest is
  unchanged). Their libraries are optional extras (`pyproject.toml`: `opcua` = asyncua 2.x, `s7` =
  python-snap7 3.x); actors declare `requires = (module, distribution, extra)` and import lazily, and
  `record()` calls `actors.base.check_requirements` before capturing, so a core install fails in about a
  second with one line per missing extra and its `pip install` command.
  - **S7comm** (`actors/s7.py`): the PLC side is a python-snap7 3.x server subclass bound to the host's
    loopback address on port 10102 (mapped to 102). DB reads refresh the block from the process simulation at
    the action's virtual time (shared with a `modbus.server` on the same host, so both protocols report the same
    plant); SZL 0x0011/0x001C/0x0424 answers and the largest PDU the CPU accepts (240 on S7-1200, 960 on
    S7-1500; the client proposes 480) follow the device profile. The client is a small hand-written S7comm
    client because snap7's client cannot bind a source address; it frames COTP/S7 PDUs itself and keeps request
    sizes inside the negotiated PDU.
  - **OPC UA** (`actors/opcua.py`): `scada` (device `scada-server-vm`, BuildInfo from its `identity`) runs an
    asyncua `Server` subclass on loopback port 14840 (mapped to 4840) with one folder per source PLC and one
    tag group per process table; it also polls the PLCs over Modbus (`scada_io_poll`, 2 s). The historian's
    `opcua.client` drives asyncua's `UASocketProtocol` directly from its own event-loop thread, one service per
    action, with no asyncua background tasks. Back-to-back recording rules out wall-clock timers: the server's
    subscription loops are cancelled and a Publish request is answered at once by the session's next
    subscription in creation order (data changes since its last publish, or a keep-alive), which matches the
    client's per-subscription publish phases; the composer therefore sees ordinary request/response pairs.
    Request/response header timestamps, DataValue timestamps, PublishTime, the security token's CreatedAt and
    ServerStatus come from the scenario clock (host skew ±8 ms, server boot 2–40 days before the capture);
    nonces come from the behaviour seed, session/token counters are reset per recording, and the Browse view
    timestamp is null, so two recordings of a plan carry identical OPC UA bytes. Messages stay below one
    1460-byte MSS (asyncua has no BrowseNext, so the client browses one tag group per request; one subscription
    per PLC; CreateMonitoredItems per tag group); the composer does not segment. Seed 42, `--siem`: medium
    198 636 packets (OPC UA on 4840: 15 115 frames; 4 044 Publish and 539 Read request/response pairs), hard
    693 656 (52 647; 14 396 Publish, 1 439 Read, 2 OpenSecureChannel Renew), both verified.
- Telecontrol and Logix background (medium/hard, `vars.telecontrol` / `vars.enip`; conditions joined with
  `and` pick the outstation for the drawn process). All four are hand-written with the standard library,
  deterministic (identifiers from the behaviour seed, payload times from the scenario clock) and verified
  against tshark 4.6 dissectors (no malformed frames, no expert errors):
  - **IEC 60870-5-104** (`actors/iec104.py`): RTU `abb-rtu560` on a substation; GI, clock sync, TESTFR,
    periodic (COT 1) and spontaneous (COT 3, CP56Time2a) measured values with k/w flow control; counter
    interrogation (freeze, then read integrated totals with sequence numbers); single commands
    (select-before-operate) and short-float setpoint commands from the master, executed on the process and
    returned as return information (COT 11).
  - **DNP3** (`actors/dnp3.py`): RTAC `sel-rtac` at water/wastewater plants; link CRCs, integrity and
    class 1/2/3 event polls, IIN restart / need-time handling. Polled by default; the shipped scenarios run
    the unsolicited profile (null unsolicited response at session start, ENABLE_UNSOLICITED after the
    startup, event reports from the outstation's own `dnp3.scan` actions with their own sequence numbers,
    confirmed by the master inside the same action). One scan samples the process once: the reports that
    drain its events do not sample again, since a second sample at the same virtual time would draw fresh
    measurement noise and invent events.
  - **BACnet/IP** (`actors/bacnet.py`): two `siemens-pxc` controllers in a building; Who-Is / I-Am broadcasts,
    ReadProperty(Multiple), SubscribeCOV and unconfirmed COV notifications; WriteProperty on commandable
    values (priority array, relinquish). A BMS server on the plant IT subnet is a foreign device of pxc-01
    (BBMD: foreign-device table, Distribute-Broadcast-To-Network, Forwarded-NPDUs); the composer rewrites the
    originating B/IP address inside Forwarded-NPDUs to the announced address (`compose/bacnet.py`).
  - **EtherNet/IP** (`actors/enip.py`): `rockwell-compactlogix`; ListIdentity browse (the composer rewrites
    the reply's sin_addr, `compose/enip.py`, and answers the browse socket's final port), RegisterSession,
    Forward_Open class 3, connected Multiple Service Packet Read Tag polling. Class 1 implicit I/O: the
    Logix (`enip.scanner`) opens a connection to a `rockwell-powerflex525` (`enip.adapter`) and the first
    O->T / T->O pair is recorded on UDP 12222 (mapped to 2222); `compose/enip.cyclic_io` continues the
    stream every RPI for the rest of the capture from the same line program and drive model.
  - Server-initiated messages (IEC 104 periodic/spontaneous data, DNP3 unsolicited responses, BACnet I-Am
    and COV, the ENIP ListIdentity reply) are actions of the *server* actor on its own host; `assign_flows`
    binds a server packet with payload to the current action when that action belongs to the server's host,
    so it is timed at the action's virtual time. Server actors run those sends on `Runtime.loop`.
  - Detections (`detections.py`, sids 9101000+ and Sigma over the new datasets): commands, interrogations,
    polls, writes and connection set-up of these protocols from hosts other than the approved masters /
    originators, BACnet foreign-device registration and BBMD table changes. Suricata needs its DNP3 and
    ENIP parsers enabled (`SURICATA_PARSERS`).
  - Incident actors on these protocols (`iec104.command_injection`, `dnp3.control_injection`,
    `bacnet.write_injection`, `enip.io_injection`; scenarios `ot-iec104-command-injection`,
    `ot-dnp3-control-injection`, `ot-bacnet-unauthorized-write`, `ot-enip-drive-manipulation`): an
    unapproved host issues select-before-operate commands, WriteProperty at a high priority or a
    Forward_Open with forced class 1 output, against the background outstation / controller / drive. Their
    types are not in the approved-role tuples of `detections.py`, so the existing "command / write /
    Forward_Open from a host other than the approved master" Suricata and Sigma rules flag them; no new
    rules. The OT datasets carry `src_mac` / `dest_mac` like `modbus.jsonl`, for the source-MAC hunts.
    SPL/KQL checked by `tests/test_siem_queries.py`; a recording missing from the cache must be made
    under `unshare -rn` first, because the harness runs outside the namespace to reach the backends.
- IPv6 (`compose/ipv6.py`, `vars.ipv6`): besides the Windows link-local baseline, the sensor segment's
  firewall (`fortigate`, `ipv6_router` in devices.yaml with FortiOS defaults) sends Router Advertisements
  with a seeded ULA /64; Windows hosts form SLAAC stable and temporary addresses (MLDv2 joins, DAD) and run
  unicast Neighbor Discovery with the router (address resolution after the RA, the router's one NUD probe
  5 s later). Hosts never send from the SLAAC addresses, as on a real IPv4 site with a ULA-only RA: no AAAA
  records, and Windows' prefix policy (RFC 6724) ranks IPv4 above ULA, so nothing uses the router and no
  later NUD happens.
- Dual-stack site (`dualstack.py`, `compose/ipv6.GlobalAddresses`, `vars.ipv6: dual` on hard of
  `ot-baseline-operations` and `ot-modbus-write-manipulation`): a global /64 from 2001:db8::/32 (RFC 3849)
  per subnet the IPv6 router serves, a stable and a temporary address per Windows PC / server (devices
  with a `browser` profile), configured before the capture. The DNS server answers AAAA for them in the
  recording with the IPv4-mapped loopback address and the composer writes the stable address there.
  `assign_flows` marks a conversation between two dual-stack hosts `Flow.v6` unless it is BACnet/IP,
  EtherNet/IP or DHCP: in the shipped scenarios NTP to the DC, the historian's OPC UA session and name
  lookups at the DC. The RAs list the dual-stack DNS servers the dual-stack hosts query in an RDNSS option
  (lifetime `rdnss_lifetime`); Windows queries an interface's IPv6 DNS servers before its IPv4 ones. Such
  flows get an IPv6 header (client temporary -> server stable address, hop limit from the stack TTL,
  flow label 0), MSS 1440 in the handshake and in segmentation, Ethertype 86dd, and Neighbor
  Unreachability Detection instead of ARP: caches are warm at the capture start; a STALE entry
  (reachability older than ReachableTime) probed 5 s after use with a unicast NS / NA, except by a
  Windows endpoint of a TCP connection (forward progress confirms). The router probes the hosts it
  forwards to the same way. PLCs (also embedded Windows ones) stay IPv4.
- Linux desktops (`profiles.Device.ipv6`: devices.yaml `ipv6` may override fields of the stack's IPv6, or turn
  it off with `false`): `raspberry-pi` keeps the linux stack's modified EUI-64 and no temporary address
  (Raspberry Pi OS Bookworm with NetworkManager), `linux-laptop` has stable-privacy identifiers and a temporary
  address (Ubuntu Desktop). Both have `mdns: avahi`: `compose/avahi.py` is a small discrete-event model of
  avahi 0.8 (announcers per record and interface, probe and response schedulers with their defer, jitter and
  history times, packing of pending jobs into one packet) fed by the interface start, the DHCP bind time
  (`compose/dhcp.Dhcp.bound`) and the SLAAC addresses' DAD. Runs inside `Ipv6.finish`, so only with the
  scenario's IPv6 on; no shipped scenario puts these devices on the sensor segment at such a level.
- FLOAT32 registers: profile points may be `type: float32` (two registers, profile `word_order` big = ABCD or
  little = CDAB); `power_substation` and `hvac_building` use them. `Point.encode` returns the register words,
  `ProcessProfile.decode_block` decodes whole points from a read/write block (half a float is skipped), and a
  write covering one word of a float replaces only that word. S7 DBs lay out one REAL per point (index-based).
- Web UI (`ui/`, `pcapforge ui`): `http.server` with a thread per request; HTML rendered server-side
  (`views.py`, everything escaped), one stylesheet and one script (header rain, job polling) as package data,
  no frontend build and no extra dependency. Long work runs in `jobs.Jobs`, a single worker thread in
  submission order (recordings share the loopback range and the cache); `generate`'s progress callback
  feeds the job log, `recording i/n` lines drive the progress bar. Run files are served only from inside a
  run directory (resolved path check); `Host` is checked on loopback binds (DNS rebinding) and every POST's
  `Origin` must match it.
  Student mode (`ui/student.py`, `--student`) is a separate handler class: no instructor route exists in
  it; question views are built from an allow-list (id, text, type, points, hint), downloads are limited to
  the student-zip files, submissions are written atomically as `<run>/submissions/<name>.yaml` in the
  `grade` format. The traffic strip chart (`ui/traffic.py`) streams the capture once (memory-mapped, pcap /
  pcapng, VLAN / QinQ, IPv6 extension headers, classification by `ports.WELL_KNOWN`) into 144 buckets and
  caches them in `traffic.json` keyed by the capture's SHA-256 (about 1 s per million packets).
  `ui/roster.py`: `<out>/roster.json` {login: name, salted PBKDF2-HMAC-SHA256 code hash}; sessions are
  `login|expiry|HMAC(secret, login|expiry|salt)` cookies (secret `<out>/.ui-secret`), so a code reset ends
  the student's sessions; the student identity of every request comes from the verified cookie.
Next: IT-line scenarios (ROADMAP.md).

### Composer spec
Input: recording pcap, plan, presentation rng (`Rng("pcapforge", scenario, difficulty, seed).child("present")`).
1. Parse classic pcap with a buffered reader (pcapng via `RawPcapReader`); strip link layer
   (DLT_NULL 4 bytes / Ethernet 14 / Linux cooked) → IPv4 bytes.
2. Markers: UDP to `MARKER_SINK:9999`, payload `PFMK`+u32 action id → set `current_action`; drop.
3. Flow key = sorted 5-tuple. Client side = SYN sender (TCP) / first sender (UDP). A client
   packet with payload/SYN/FIN binds the flow to `current_action`; others inherit the flow's action.
   Packets before the first marker or of `teardown` actions are dropped; `setup` actions are dropped
   when `impairments.mid_session` is true (capture starts mid-session).
4. Causal retime per action: first packet at `start_epoch + action.t`; each next packet:
   same sender → +10–60 µs; direction change → + latency(sender) [per-host sensor latency:
   same subnet 0.1–0.4 ms, routed +0.3–0.8 ms via `forwarding_ms`] + reaction:
   payload after peer payload → device `processing_ms` lognormal; pure ACK → stack
   `delayed_ack`; SYN-ACK → 30–80 µs. Enforce per-flow monotonic time.
5. Retransmission (`retransmit_rate`): duplicate a TCP data segment at t+RTO (Windows 300 ms,
   Linux 200 ms+RTT, vxworks 500 ms) and shift the rest of that action/flow by RTO.
6. Visibility: keep only packets `topology.visible(src, dst)`.
7. Header rebuild (struct, own checksums): IPv4 (stack TTL − routed hops, DF, IP-ID global or
   per-flow), ports via `ports.WELL_KNOWN`, ephemeral ports per stack (`ephemeral_ports`,
   `port_allocation`), ISN per flow from rng, TCP options rebuilt per stack on SYN/SYN-ACK
   (`syn_options`, MSS, WS, timestamps when both sides support), window per stack.
   DNS answers: rewrite A-record rdata loopback → final IP (same length).
8. L2 via `topology.l2_view(src, dst)`; synthesize ARP who-has/is-at for on-segment pairs
   before first contact and again after 30–120 s idle (Windows/Linux cache aging).
9. Merge by time (stable on emission order), write classic pcap (Ethernet, µs) or pcapng; return
   action id → first request frame number for the answer key.

Streaming (long captures): every stage is a generator over a time-ordered stream with a bounded
look-behind, so memory holds minutes of the capture, not all of it, and the output is the same as a
global sort would give (checked byte for byte against the former in-memory composer on every
scenario, level and two seeds, plus a 2 h hard run):
- `assign_flows` yields packets in recorded order; the `Retimer` places them and releases packets
  more than `retime.HORIZON_S` (300 s) behind the latest action start, in (time, recorded order)
  order from a heap. A delayed ACK whose timer ran out behind the horizon is released at its due
  time (no later segment of its flow can carry it) while the flow's clock learns of it as before.
  Anything that would land behind already released time raises `ComposeError`;
- per-flow state (retime clock, negotiated options, header state, IPv6 twin port, firewall kinds)
  lives on the `Flow`, so it is freed with the flow;
- the host firewall (`firewall.HostFirewall`) and the cyclic EtherNet/IP I/O (`enip.CyclicIo`) are
  release stages of the `Retimer`: they see every timed packet as it is placed and decide / add as
  it leaves the heap, by which time a refused connection has shown its RST and a recorded first I/O
  exchange is complete; the cyclic I/O times are drawn per side up front into compact arrays (same
  draw order) and the stream packets are generated one at a time into the heap;
- frames of timeline packets arrive in order (a queue); ARP / interface-start / ACD / IPv6-copy
  frames (up to `FRAME_HORIZON_S` early) go through a heap, merged in exact (time, index) order.
  Without IPv6 hosts they go straight through the SPAN model to the writer; with IPv6 they are
  spooled to a temporary file first and the final pass merges in the router / SLAAC / ND frames
  (they need the capture's first and last time). Frames are numbered on
  the way; frame info (action id and request / control / segment flags) is one packed int;
- `verify` reads tshark output line by line; the SIEM export writes each record once the capture is
  `export.HORIZON_S` past it (requests unanswered for that long stay unanswered) and keeps only the
  flow table to the end; `Plan.digest` hashes the actions one by one; the answer key's per-action
  frame numbers and times are compact arrays (`compose.ActionIndex`), not dicts;
- the plan: `Action` has slots and no separate insertion counter (its `id` is the insertion order
  until `finalize` sorts stably by time and renumbers), and `Plan.add` shares equal argument dicts
  of scalars, so a poll repeated millions of times costs one dict (actors that change an action's
  arguments later assign a new dict); about 0.15 KB per action.

Implementation notes (where `compose/` refines the spec):
- a delayed pure ACK whose timer would fire after the sender's next segment is not emitted
  (piggybacked); loopback window updates (same seq/ack pure ACK) are dropped since the
  composed windows are constant;
- UDP: each new action on a 5-tuple is a new exchange (new client socket → new ephemeral port),
  unless the action has `resend: true` (retransmission on the socket of an earlier action:
  LLMNR / NBNS / SSDP repeats keep their source port);
- datagrams to a sink: the peer is the `Sink`; final destination is the group or the sender's
  subnet broadcast, Ethernet dst the group MAC (01:00:5e + low 23 bits) or ff:ff:ff:ff:ff:ff,
  no ARP, never routed (visible only when the sender is on the sensor subnet), TTL/DF from the
  stack's `link_local`; the NetBIOS datagram header's source IP is rewritten like DNS A records;
- RTO comes from the stack profile (`rto: {min_ms, plus_rtt}`);
- mid-session captures start with warm ARP caches; actions without client payload
  (connect/close) report their SYN/FIN frame.
