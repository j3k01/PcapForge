# Contributing to pcapforge

pcapforge generates labeled training captures for blue teams, SOC analysts and detection engineers.
Contributions of scenarios, protocols, device profiles, detections and fixes are welcome. This guide
covers the scope rules, the development setup, how to write a scenario, how to extend the engine, and
what to check before opening a pull request.

## Defensive policy

pcapforge only ever produces traffic between benign local clients and services on `127.77.0.0/16`.
The composer then rewrites the addresses into a fictional site. Nothing it runs may be able to act
against a real system.

In scope:
- benign clients and servers that speak a real protocol correctly (Modbus/TCP, DNS, NTP, HTTP, ...);
- behaviour patterns an analyst has to recognise: writes from an unexpected host, out-of-band setpoints,
  scanning cadence, beaconing intervals, lookups of odd names, authentication failures, volume anomalies;
- detection content (Suricata rules, SIEM queries, hunting notes) and analyst questions;
- realism work: device and OS-stack profiles, timing, impairments, topology.

Out of scope, and pull requests containing it will be closed:
- malware, implants, droppers, loaders, C2 frameworks, exploit code, shellcode or working payloads, even
  "disarmed" ones;
- traffic that exploits a vulnerability or triggers one in a parser;
- anything that sends packets to addresses outside the recording loopback range, or that would work
  unchanged against a real host;
- real credentials, real customer or site data, real captures from production networks.

**The benign-equivalent rule.** When a scenario needs something that looks malicious, produce the
*observable pattern* with a benign implementation instead of the real tool. Examples:
- a "rogue engineering tool" is an ordinary Modbus client that writes out-of-band values;
- "beaconing" is a client fetching a static page from a local test server at a jittered interval;
- "DNS tunnelling" is a client querying long random labels from a local resolver that answers NXDOMAIN
  or fixed records;
- "exfiltration" is an upload of random bytes to a local sink.

If the pattern cannot be produced without weaponised code, the scenario does not belong in pcapforge.
When in doubt, open an issue describing the observable pattern before writing code.

## Development setup

Requirements:
- Python 3.13;
- Wireshark **4.4 or newer** (`tshark` and `dumpcap`). The answer-key filters and verification need it:
  older versions do not decode Modbus Write Single Register values. Ubuntu 24.04 ships 4.2, so add
  `ppa:wireshark-dev/stable` there;
- loopback capture rights (below).

```console
$ git clone <your fork> && cd pcapforge
$ python -m venv .venv
$ .venv/bin/pip install -e .[test,opcua,s7]  # Windows: .venv\Scripts\pip install -e .[test,opcua,s7]
$ pcapforge validate
$ pytest -q
```

**Windows.** Install Wireshark with Npcap and keep *Support loopback traffic* selected (the installer
default). pcapforge captures `\Device\NPF_Loopback`; administrator rights are not needed.

**Linux, rootless (recommended).** Run pcapforge and the tests in a private user and network namespace:

```console
$ unshare -rn pcapforge generate -s ot-modbus-write-manipulation -d easy --seed 42
$ unshare -rn pytest -q
```

Inside the namespace you are root of your own `lo`, so dumpcap/tcpdump can capture it and pcapforge adds
the `quickack 1` route for `127.77.0.0/16` itself (immediate loopback ACKs; without it Linux piggybacks
ACKs and captures lose most pure ACKs). This needs unprivileged user namespaces; Ubuntu 23.10+ can
restrict them with AppArmor (`kernel.apparmor_restrict_unprivileged_userns`). Without a namespace:
`sudo setcap cap_net_raw,cap_net_admin=eip $(which dumpcap)` and, once per boot,
`sudo ip route add local 127.77.0.0/16 dev lo table local quickack 1`.

**macOS.** Add loopback aliases for the `127.77.0.0/16` addresses first.

The end-to-end tests are skipped when tshark 4.4+ or capture rights are missing, and the Suricata test
when `suricata` is not on PATH. A green run with skips is not enough for changes that touch recording,
composing, the answer key or detections: run the full suite on a machine (or WSL/CI) that has them.

## Writing a scenario

### File layout

```
scenarios/<line>/<id>/scenario.yaml
```

- `<line>` is `ot` or `it` and must match the `line:` field.
- `<id>` is lowercase kebab-case, starts with the line (`ot-modbus-write-manipulation`) and matches `id:`.
- Scenarios are licensed CC-BY-4.0; set `license: CC-BY-4.0` and `authors:`.
- Start the file with the schema header line so editors complete and validate keys:

```yaml
# yaml-language-server: $schema=../../../src/pcapforge/scenario/scenario.schema.json
schema: pcapforge/scenario@1
```

Scenarios outside the repository are found with `--scenarios-dir DIR` or `PCAPFORGE_SCENARIOS`
(path list), or by passing the path to `scenario.yaml` as `--scenario`.

### Metadata and briefing

`title`, `summary` (instructor-facing), `briefing` (student-facing; placeholders `{site_name}`, `{domain}`,
`{sensor_subnet}`, `{process_title}`), `mitre` (framework `enterprise`/`ics`/`mobile`, technique id and name;
an entry may carry `when`; an empty list is allowed for baseline scenarios without an incident),
`tags`, `version` (bump it when the recorded behaviour changes: it is part of the
recording cache key). The optional `site` block lists site names, codes, a domain, start hours,
weekdays and a year range the seed picks from.

The briefing must not give away the answers: describe the site and the normal roles ("only the
engineering workstation changes setpoints"), never the attacker.

Optional `translations: {pl: {title, briefing, questions: {<id>: {text, hint}}}}` provides the student-facing
prose for `pcapforge generate --lang pl`. Answers, filters and register names are never translated. A test
checks that every question has a translation, so translate all of them.

### Topology, hosts and devices

```yaml
topology:
  sensor: control                                # the subnet whose switch SPAN port is captured
  subnets:
    - {id: control, pool: 10.0.0.0/8, prefix: 24}  # the seed picks a /24 from the pool
    - {id: dmz, cidr: 192.168.50.0/24}             # or a fixed CIDR
  hosts:
    - {id: firewall, device: fortigate, subnets: [control, dmz], name: "fw-{code}-01", router: true}
    - {id: plc, count: "${vars.plc_count}", device: [schneider-m340, siemens-s7-1200],
       subnet: control, name: "plc-{code}-{index:02d}"}
    - {id: rogue, device: raspberry-pi, subnet: control, name: raspberrypi, when: "vars.writer_host == 'rogue'"}
```

- `id` is a role; `count` creates several instances (`plc` then means all of them in actor `hosts`/`targets`).
- `device` is a profile name from `src/pcapforge/profiles/devices.yaml`, or a list the seed picks from.
  The device decides vendor MAC OUIs, the OS stack (TTL, TCP options, ephemeral ports, delayed ACK,
  retransmission timeout), application processing latency and, for field devices, the identity it reports.
- `name` templates: `{code}`, `{CODE}` (site code), `{index}` (instance number, format specs allowed).
- A host on two subnets with `router: true` forwards between them; traffic it routes reaches the sensor
  with its MAC and a decremented TTL.
- Only traffic visible from the sensor subnet ends up in the capture.

### Actors and params

```yaml
actors:
  - {id: plc_service, type: modbus.server, hosts: plc, params: {process: water_treatment}}
  - id: scada_poll
    type: modbus.poller
    hosts: hmi
    params: {targets: plc, interval: "${vars.hmi_interval}", jitter: 0.03}
  - id: change
    type: modbus.writer
    hosts: "${vars.writer_host}"
    incident: true                               # its events form the answer-key timeline
    params: {targets: plc, writes: "${vars.writes}", deviation: "${vars.deviation}"}
```

- `type` selects an actor class (the README lists the built-in ones; the class docstrings and `param()`
  calls in `src/pcapforge/actors/` document their params).
- `hosts` names the host ids that run the actor; `targets`/`server` params name the hosts it talks to.
- Numeric params usually accept a scalar or a `[low, high]` range the seed draws from.
- Exactly the actors of the incident have `incident: true`; background actors make the noise the
  analyst has to see through. Keep a background actor present at every level (count 0 is fine) when the
  site model needs to know about its role, e.g. the approved writer used by the detections.

### `${}` references and `when`

- `${vars.x}` reads a difficulty variable; `${facts.<actor id>.<path>}` reads a fact an actor produced
  while planning (questions only). Paths may index lists: `${facts.change.writes[0].point}`.
- A string that is exactly one reference keeps the value's type (number, list, map); a reference inside
  a longer string is interpolated as text (booleans as `true`/`false`).
- `when` (hosts, actors, MITRE entries, questions) accepts `path`, `not path` or
  `"path == 'value'"` / `"path != 'value'"`. A missing path is false.

### Difficulty knobs

```yaml
difficulty:
  easy:
    duration: 15m                                # 90, 90s, 15m, 2h
    impairments: {retransmit_rate: 0.0, mid_session: false}
    vars: {plc_count: 2, writer_host: rogue, deviation: extreme, operator_writes: 0}
  hard:
    duration: 2h
    impairments: {retransmit_rate: 0.001, mid_session: true}
    vars: {plc_count: 4, writer_host: ews, deviation: subtle, operator_writes: 6}
```

- `duration`: capture length; longer captures bury the incident in more background.
- `impairments.retransmit_rate` (at most 0.05): TCP data segments lost after the sensor and retransmitted.
- `impairments.mid_session`: the capture starts after persistent sessions were opened (no handshakes).
- `impairments.span_duplicates` (at most 0.05): share of frames the SPAN session mirrors twice.
  `impairments.sensor_drop` (at most 0.02): share of frames the sensor misses; frames the answer key
  refers to are always kept. `impairments.vlan` (1–4094): 802.1Q VLAN id on every frame.
- `impairments.clock_offset` (s) and `impairments.clock_drift_ppm`: sensor clock error, a number or a
  `[lo, hi]` range drawn per seed. Frame times and every time in the answer key carry it; payload clocks
  (NTP, OPC UA) keep the true site time, so analysts can measure the skew.
- `vars.ipv6` (passed to `windows.chatter` as `ipv6`): IPv6 link-local baseline of the Windows hosts on
  the sensor segment (DAD, Router Solicitation, MLDv2, LLMNR/mDNS over IPv6, DHCPv6 Solicit).
- `vars`: everything else, consumed through `${vars.*}` and `when`. Good knobs make the incident harder
  to *find*, not just bigger: a source that blends in (approved host, routed host behind a gateway MAC),
  values just outside the normal band, events spread over a longer window, legitimate look-alike activity,
  more protocol noise.
- Per-seed variation: a var written as `{choose: [a, b, c]}` picks one item per seed, and `{range: [lo, hi]}`
  picks an integer. Use this for the story structure (process profile, PLC count, device pool such as
  `plc_devices`), so that every seed is a qualitatively different exercise. Host `device:` and `count:`
  accept `${vars.*}`.

Provide all three levels unless a level would be meaningless, and describe them in the README table.

### Facts, questions, `check` and `hunt`

Actors write facts during planning; `$host` references expand to `id`, `role`, `name`, `fqdn`, `ip`,
`mac`, `observed_mac` (the MAC the sensor sees, i.e. the gateway's for routed hosts), `vendor`,
`device`; action references expand to `frame`, `time` (ISO UTC), `epoch`. Questions turn facts into the
answer key:

```yaml
questions:
  - id: first_write
    text: At what time (UTC) was the first unauthorized write request sent?
    answer: "${facts.change.first_write.time}"
    type: timestamp
    tolerance_s: 1
    points: 10
    check:
      filter: "frame.number == ${facts.change.first_write.frame} && modbus.func_code in {5, 6, 15, 16}"
      expect: {count: 1}
    hunt:
      dataset: modbus
      spl: "index=* sourcetype=pcapforge:modbus write=true in_normal_band=false | sort _time | head 1"
      kql: "write : true and in_normal_band : false"
      look_for: The earliest out-of-band write.
```

- `type` decides how `pcapforge grade` scores an answer: `ip`, `mac`, `number`, `timestamp`
  (`tolerance_s`), `set` (partial credit), `map` (partial credit per key, 0.5 % numeric tolerance) or
  `text` (default; alternatives in `accept`). Pick the most specific type: `ip`/`mac` accept any spelling
  of the address.
- `points` defaults to 10. `tolerance` (absolute) applies to `number` answers. `hint` is shown in the
  submission template and costs 20 % of the points (rounded up) when the student lists the question under
  `hints_used`. `pcapforge export-ctfd` uses the same cost.
- `check` is a Wireshark display filter plus `expect` (`count`, `min`, `max`) that proves the answer is in
  the capture. Every question that can be proven from packets needs one; `foreach: facts.x.list` repeats
  the check per item with `${item.*}`. Display-filter sets need commas: `{5, 6, 15, 16}`.
- `hunt` (optional) is rendered into `detections/hunting.md`: the SIEM `dataset`, a `wireshark` filter for
  questions without a check, `spl`, `kql` and `look_for`. SPL/KQL are not machine-verified; run them
  against the export once.
- A question must be answerable from the capture plus the briefing alone.

### Validate

```console
$ pcapforge validate scenarios/ot/my-scenario/scenario.yaml
$ pcapforge show ot-my-scenario
```

`validate` checks the schema and dry-runs planning on every difficulty (without recording). Then
generate each level and read the result like a student would.

## Extending the engine

### A new actor

1. Add a class to a module in `src/pcapforge/actors/` (or a new module, imported in
   `actors/__init__.py:_load_builtin`) and decorate it with `@register`; set `type = "<protocol>.<role>"`.
2. `plan()` appends actions with `self.plan_.add(t, self.id, host.id, "<op>", **args)` at virtual times
   inside `plan.duration`, draws all randomness from `self.rng` (or `self.rng.child(...)`), and stores the
   facts questions need in `self.plan_.facts[self.id]` (use `host_ref()` / action references, not raw
   addresses). Incident actors also call `self.plan_.event(...)` for the timeline.
3. Servers set `is_server = True` and implement `async serve(rt)` binding to `host.loopback`; clients
   implement `execute(action, rt)` using `rt.loopback(host_id)` and real sockets or protocol libraries.
   Use the recording ports from `pcapforge.ports` (the composer maps them to well-known ports).
4. Actors that send one-way multicast or broadcast datagrams declare the `(sink, port)` pairs in `sinks`
   (see `topology.SINKS`).
5. The same plan must give the same actions: no wall-clock time, no unseeded randomness, no iteration
   over unordered sets. Action args are part of the recording cache key.
6. A third-party protocol library is an optional extra in `pyproject.toml`
   (`[project.optional-dependencies]`): set `requires = (import name, distribution, extra)` on the actor
   and import the library only inside `serve()` / `execute()` via `actors.base.optional_import`, so a
   core install still plans every scenario and the recorder stops before capturing with the install
   command. Enable such actors in a scenario only behind a difficulty variable.
7. If the protocol needs SIEM fields or Suricata rules, extend `export.py` / `detections.py`.
8. Document the actor in the README's built-in actor list.

### A new device or OS stack

Add an entry under `devices:` (or `stacks:`) in `src/pcapforge/profiles/devices.yaml`: `vendor`, `ouis`,
`stack`, `processing_ms: {median, sigma}`, and `identity` for field devices. OUIs must belong to the
vendor in Wireshark's manufacturer database (`tshark -G manuf`). Stack values (TTL, DF, IP-ID behaviour,
MSS, window, SYN options, ephemeral port range and allocation, delayed ACK, RTO, link-local TTLs) should
come from a real capture of that OS; note the source in a comment.

### A new process profile

Add `src/pcapforge/profiles/processes/<id>.yaml` with `id`, `title`, `unit_id` and the Modbus tables
(`coils`, `discrete`, `holding`, `input`). Points have `address`, `name`, `unit`, `scale`, `nominal`,
`normal` (the operating band; writes outside it are the anomaly), `writable` and an optional `model`
(`const`, `follow`, `daily`, `walk`, `counter`, `above`/`below`; see the header of
`water_treatment.yaml`). Reference it from a `modbus.server` actor with `params: {process: <id>}`. The
register map is printed in the student briefing.
Optional `translations: {pl: {title: ...}}` gives the localized process title used in handouts.

## Testing checklist

Before opening a pull request:
- [ ] `pcapforge validate` passes.
- [ ] Every difficulty generates and verifies: `pcapforge generate -s <id> -d <level> --seed 42` prints
      `verified` for `easy`, `medium` and `hard` (no malformed frames, bad checksums, expert errors or
      loopback leaks; every question's `check` matches).
- [ ] The answer key is right, not just consistent: open the capture in Wireshark and answer the questions
      from `briefing.md` alone. Fill in `submission_template.yaml` with your answers and run
      `pcapforge grade answers.json <your file>`: it should score full marks.
- [ ] The briefing does not reveal the incident's source, values or times.
- [ ] Determinism: the same seed gives the same `answers.json` (and, with a cached recording, a
      byte-identical capture); a different seed changes addresses, names and timing.
- [ ] Tests for new behaviour cover invariants an analyst would notice (e.g. every incident write is out of
      band, the key's frame numbers point at the right packets), not implementation details.
- [ ] `pytest -q` passes; for recording, composer, answer-key or detection changes, also on Linux
      (`unshare -rn pytest -q`) and with Suricata installed when rules change.
- [ ] README updated (scenario table, difficulty table, actor list) when you add user-visible features.

## Licensing

- Code is licensed under [Apache-2.0](LICENSE).
- Scenarios (`scenarios/`) and profiles (`src/pcapforge/profiles/`) are licensed under
  [CC-BY-4.0](scenarios/LICENSE).

By contributing you agree that your contribution is released under these licenses. Only contribute
material you have the right to license this way: profile values measured from your own captures or public
documentation are fine; vendor documents, proprietary captures and customer data are not.
