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

Done and committed:
- `pyproject.toml`, licenses, `rng.py` (named seeded streams), `tools.py` (tshark/dumpcap lookup)
- `profiles/devices.yaml` (stacks: windows/linux/vxworks; devices with verified OUIs),
  `profiles/processes/water_treatment.yaml`, `process.py` (virtual-time process model)
- `scenario/` loader + JSON schema; YAML key is `hosts` (not `on`: YAML 1.1 parses it as bool)
- `scenarios/ot/modbus-write-manipulation/scenario.yaml` (easy/medium/hard, questions with tshark checks)
- `topology.py` (world from behaviour seed, addressing from presentation seed, sensor L2 view),
  `plan.py` (Action/Event/Plan, `build_plan`, recording digest)

Next, in order:
1. `actors/` — registry (`create_actor`), base class (`plan()`, `serve(rt)`, `execute(action, rt)`,
   `close(rt)`, `is_server`, `incident`), `modbus.py` (server, poller, operator, writer),
   `dns.py`, `ntp.py`; record ports in `ports.py` (15020→502, 15353→53, 15123→123).
   pymodbus bit tables: packed LSB-first, bit `i` is `regs[i // 16] >> (i % 16) & 1`.
2. `record.py` — dumpcap/tcpdump backend, asyncio server thread, marker per action, cache.
3. `compose/` — flow assignment, causal retime, header rebuild (struct, own checksums), ARP, write.
4. `answers.py` (expand `$host` / `$action` refs, questions, register-map handout), `verify.py`.
5. `cli.py`, tests, README, CI.
