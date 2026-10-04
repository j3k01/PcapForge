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
   `SimDevice`, NTP, DNS) run in one asyncio thread; the orchestrator executes actions
   sequentially, sending a UDP marker (`<host-ip> -> 127.77.0.1:9999`) before each
   action. Capture: dumpcap (`\Device\NPF_Loopback` on Windows, `lo` on Linux) or
   tcpdump. Recording is cached by plan hash → byte-identical output for the same seed.
3. **Compose**:
   - flow assignment: a client-sent payload/SYN/FIN packet binds its flow to the latest
     marker; server replies and pure ACKs inherit the flow's current action;
   - causal retime: packets keep recorded order; gaps replaced by
     latency-to-sensor (per host) + processing time (per profile) + jitter;
   - rewrite: IP/MAC/ports (15020→502, 15353→53, 15123→123), ephemeral ports per OS
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
  Pin `pymodbus~=3.15`.

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
  Verified: easy plan = 4018 actions, 20 020 packets, 0 drops, 2.9 s wall.
- `compose/` — `compose(plan, recording, out, seed, fmt)` → `ComposeResult` (spec below).
  Verified with tshark: 0 malformed/checksum/expert errors on easy and medium; ~120k pkt/s.

Status: first scenario complete end-to-end (compose/, answers.py, verify.py, cli.py, tests, README, CI),
with Windows background chatter on medium/hard (`vars.chatter`, `vars.chatter_rate`).
Next: IT-line scenarios (README roadmap).

### Composer spec
Input: recording pcap, plan, presentation rng (`Rng("pcapforge", scenario, difficulty, seed).child("present")`).
1. Parse with `RawPcapReader`; strip link layer (DLT_NULL 4 bytes / Ethernet 14) → IPv4 bytes.
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
9. Merge sort by time (stable), write classic pcap (Ethernet, µs) or pcapng; return
   action id → first request frame number for the answer key.

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
