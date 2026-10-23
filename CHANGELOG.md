# Changelog

## Unreleased

### Scenarios
- `it-ldap-reconnaissance`: Active Directory reconnaissance over LDAP (MITRE ATT&CK T1087.002,
  T1069.002, T1482) on the office-LAN baseline. A host that is not a normal directory client binds to
  the domain controller over LDAP and enumerates the directory — all users, the accounts with a
  service principal name (`(servicePrincipalName=*)`), the protected (`(adminCount=1)`) accounts, the
  members of Domain Admins and the domain's trusts (`(objectClass=trustedDomain)`). New `ldap.recon`
  actor and an additive `ReconDirectory` the DC serves (opt-in `Directory.recon_dir`; the office
  baseline is unchanged). The baseline's LDAP is Kerberos-sealed, so easy and medium model a tool run
  with explicit credentials over an unsealed (simple-bind) LDAP session where every filter and
  returned entry is readable — easy in a burst, medium with the MS-ADTS paged-results control and
  spread out over the capture; hard binds with the account's Kerberos ticket (GSS-SPNEGO, sealed) like
  a member, so the filters are opaque and the tell is volume and timing — round after round of LDAP
  sessions to the DC, each pulling large sealed responses. New `ldap` SIEM dataset (one record per
  bind and per search request/response, with base, scope, reconstructed filter and entry count), Zeek
  `ldap` / `ldap_search` hunts, Suricata content rules on the cleartext SPN and adminCount filters and
  a Sigma rule over the ldap dataset.
- `it-smb-lateral-movement`: SMB lateral movement across the office workstations (MITRE ATT&CK
  T1021.002, T1078.002, T1083) on the office-LAN baseline. One source host authenticates once with a
  single domain account (a Kerberos AS exchange) and then, host after host, asks the KDC for a
  `cifs/<workstation>` service ticket and opens an SMB 3.1.1 session to the administrative shares
  (ADMIN$, IPC$, C$), listing the share and logging off — the benign equivalent of admin-share access
  with a reused credential (no service install, no remote execution). New `smb.server` actor gives the
  workstations an SMB server role for this scenario only (reusing the DC's Kerberos directory and the
  `smb2` codecs, so `it-baseline-operations` is unchanged) and new `smb.lateral` source actor; `smb2`
  gained QUERY_DIRECTORY, a directory CREATE and an SMB2 ERROR response (STATUS_ACCESS_DENIED). easy:
  every workstation in about a minute from an uninventoried host; medium: a subset buried in the normal
  SYSVOL Group Policy traffic; hard: a handful of targets over two hours from a legitimate admin
  workstation, one of which refuses the ADMIN$ connection. Questions on the source host, the account,
  the number of targets, the first target and time, the share name and (hard) which target denied
  access; a Suricata rule on any ADMIN$ tree connect and a Sigma value_count correlation (one source
  reaching the admin shares of many workstations) over the smb dataset.
- `it-ot-pivot`: an IT-to-OT pivot (MITRE ATT&CK T1046; ATT&CK for ICS T0886, T0846, T0888, T0855, T0836)
  on the office-LAN baseline joined to a plant control network across the IT/OT firewall — the first
  scenario that spans both lines. One office workstation routes into the control subnet, sweeps it for
  Modbus/TCP, reads device identification from the PLCs it finds and writes a setpoint outside its normal
  band, reusing the `modbus.scanner` and `modbus.writer` actors and the water/wastewater/HVAC/substation
  process models. easy is a loud sweep of the whole control subnet then a write, captured on the office
  switch; medium a targeted connect to the PLCs (read then write); hard puts the sensor on the OT side,
  with a low-and-slow sweep (new optional `spread` on `modbus.scanner`) and one subtle out-of-band write
  whose frames arrive routed carrying the firewall's MAC. The scenario's `topology.sensor` is drawn per
  level through `${vars.sensor}` (the engine now resolves variable references in the sensor subnet).
  Questions on the IT source host (IP and, on the office switch, name), the PLCs scanned, the register and
  value written, whether the value is out of band, the first cross-zone frame and the firewall MAC the PLC
  sees. The incident is detected by the existing Modbus Suricata/Sigma/Zeek rules (unapproved writer,
  out-of-band write, device identification, port-502 sweep) plus a new IT→OT cross-zone rule over flows
  (Suricata and Sigma): a TCP connection from the office LAN into the control subnet.
- `it-rogue-dhcp`: a rogue DHCP server (MITRE ATT&CK T1557, T1557.003) on the office-LAN baseline. A
  Raspberry Pi running dnsmasq, plugged into the office segment, answers clients' Discovers and Requests
  before the firewall-relayed Windows Server Offer arrives, so hosts that join during the capture take its
  lease and come up with the rogue's own default gateway and DNS resolver — a benign local simulation of
  DHCP spoofing (no interception of real traffic). `dhcp.server` gained a `rogue` flag (a second server on
  a subnet that already has one, leaving its pool alone), `router`/`mask` option overrides and a `dnsmasq`
  reply format; the affected hosts resolve a few names at the rogue's own `dns.server` on medium/hard.
  easy: an obvious rogue (a Raspberry Pi OUI and a wrong subnet mask) with several new PCs; medium: only
  the router and DNS differ, with a few lookups at the rogue resolver; hard: it appears late, affects a
  single host and hands out a very short lease. Questions on the rogue's IP, MAC and vendor, the router and
  DNS it offers, the subnet mask (easy), the clients that accepted its lease, its first Offer and the
  legitimate server identifier for contrast; a Suricata rule on the rogue's port-67 replies (a BOOTREPLY
  from an unauthorised server) and a Sigma rule over the dhcp dataset on the unapproved server identifier.
- `it-kerberoasting`: Kerberoasting (MITRE ATT&CK T1558.003) on the office-LAN baseline. A signed-in
  domain user on a managed workstation logs on (a Kerberos AS exchange) and then, in a burst, requests
  service tickets (TGS-REQ) for many service accounts' SPNs asking for RC4-HMAC (etype 23) where a
  Windows client offers AES first, so the KDC answers with RC4-encrypted service tickets (Zeek cipher
  `rc4-hmac`) an attacker would crack offline — benign: correct Kerberos on the loopback, opaque ticket
  bytes, nothing cracked. The synthetic directory (`actors/ad.py`) gained opt-in service accounts with
  SPNs (the `ad.dc` `directory: {service_accounts: N}` param; `it-baseline-operations` unchanged) and the
  KDC issues the service ticket in the requested etype; a new `kerberos.roast` actor drives the run. The
  Kerberos SIEM export gained `etype`/`etype_first` (the requested encryption types). easy: many SPNs in
  seconds, RC4 only, from one host; medium: fewer, interleaved with legitimate AES service tickets; hard:
  the requests spread low-and-slow across the two-hour capture with the user also doing normal domain
  work. Questions on the requesting host, the signed-in account, the number of SPNs, the requested etype,
  the first request and one targeted service; a Suricata rule on a TGS-REQ offering RC4 only and a Sigma
  value_count correlation (one host requesting RC4 service tickets for many distinct SPNs) over the
  kerberos dataset.

### Detection engineering
- SIEM export: new `siem/ldap.jsonl` (binds and searches: base, scope, filter when unsealed, entries);
  `kerberos.jsonl` gains `etype` / `etype_first` (the encryption types a request offers).
- `tests/test_siem_queries.py`: fresh Splunk index names per session (re-creating a just-deleted index
  raced with Splunk's asynchronous removal and left it empty), one-record files sampled twice for
  Elasticsearch's find-structure API (it needs two lines), and timestamp answers match within the
  question's `tolerance_s`, as grading does.

## 0.4.0 - 2026-10-22

Seeds are not stable across versions: the plans of the existing scenarios (actions, timing, answers) are
unchanged from 0.3.0, but captures with a DHCP joiner can differ (see Traffic realism).

### Scenarios
- `it-baseline-operations`, the first IT-line scenario: an office LAN as the working day starts, captured on
  the office switch. The domain controller on the server subnet is the DHCP server behind the firewall's
  DHCP relay, office PCs boot and confirm their leases, a new PC (not in the asset inventory) leases its
  first address; the workstations browse the intranet over HTTPS and scan for Windows updates at WSUS
  (medium/hard: BITS downloads an approved Defender update); NTP and DNS at the DC and (medium/hard)
  Windows chatter, IPv6 and the Active Directory domain with an employee's logon. Questions on DHCP and its
  relay, the rebooted and the new host, the DHCPINFORM option, the logon account, the intranet sites, their
  CA and cipher suite, the WSUS server and port, its SOAP calls and the downloaded update.
- `it-dns-tunneling`: DNS-based data transfer to a local resolver (MITRE ATT&CK T1071.004, T1048.003) on
  the office-LAN background. The `dns.tunnel` actor makes one workstation send a run of DNS queries whose
  leading label carries base32-encoded chunks of an opaque fake payload (`rng.label_bytes`) under a single
  fictional parent domain, all through the site resolver (the DC), which forwards them like any external
  name and answers SERVFAIL — no bytes leave the loopback range, only the observable pattern. easy: a
  high-rate burst of long TXT labels; medium: a moderate rate of A/AAAA with shorter labels; hard:
  low-and-slow A queries with near-normal labels interleaved with ordinary lookups. Questions on the
  tunnelling host, the parent domain, the record type, the approximate bytes moved and the first encoded
  query, with a Suricata rule and a Sigma rule (dns dataset) on the long labels under the parent.
- `it-https-beaconing`: periodic HTTPS check-ins from an office PC to an external-looking service
  (MITRE ATT&CK T1071.001, T1573) on the office-LAN background — the benign equivalent of C2 beaconing
  (a TLS client fetching a small static page from a local test server at a jittered interval). New
  `tls.beacon_server` actor (a TLS 1.2 endpoint serving a tiny page for a fictional domain, with a
  certificate from a fictional public CA rather than the domain's AD CS root) and `tls.beacon` actor
  (one workstation resolves that domain through the site DNS and checks in through the firewall at a
  regular interval, reusing Edge's ClientHello from `tls.py`). easy: a short fixed interval with a
  distinctive SNI; medium: a jittered interval and a per-seed plausible SNI; hard: a long jittered
  interval with TLS session resumption so the beacon blends with the Edge/WSUS background and only the
  cadence stands out. Questions on the beaconing host (IP / MAC), the destination domain and IP, the
  interval (with tolerance), the first check-in time and the check-in count, with a TLS-SNI Suricata
  rule and a Sigma rule over the tls dataset. The site DNS now resolves dotted host aliases as full
  external FQDNs (an A record to the host), so a scenario's fictional external domain resolves through
  the DC; background DNS clients enumerate only site-domain names, so the baseline is unchanged.
- `it-volumetric-flood`: a volumetric network flood against a local sink (MITRE ATT&CK T1498, T1498.001) on
  the office-LAN background. New `sink.server` actor (a benign Discard sink, RFC 863, on UDP 9 that drops
  what it receives so the flood draws no ICMP replies) and `sink.flood` actor (one or more office hosts send
  a bounded, high-rate burst of opaque UDP datagrams to the sink; each datagram is planned at its own time,
  so the measured packet rate in the capture follows the plan and every datagram is its own one-packet flow
  in the SIEM export). No amplification, reflection or spoofing. easy: one source at a constant rate; medium:
  several sources; hard: a ramping rate inside a two-hour background. Questions on the target IP / port /
  protocol, the source host(s), the start and end of the burst, the peak packets per second and the total
  volume, with a Suricata threshold rule and a Sigma event_count correlation over the flows dataset.
- `it-bulk-upload`: a bulk data upload to an external file host (MITRE ATT&CK T1048, T1567) on the
  office-LAN background — the benign equivalent of data exfiltration (opaque random bytes to a local sink).
  New `http.sink` actor (an external-looking file host accepting uploads over plain HTTP 80 and HTTPS 443,
  answering each with a small 200 OK; its fictional cloud domains are dotted DNS aliases the site DNS
  resolves) and `http.uploader` actor (one office PC resolves such a domain and uploads `rng.label_bytes`
  through the firewall). easy: one large plain-HTTP POST with an obvious file name and
  `Content-Type: application/octet-stream`; medium: several HTTPS uploads visible only as TLS record sizes
  and the SNI; hard: uploads spread across the two-hour capture and sized to blend with the WSUS/BITS
  download volume, so the tell is the upload/download ratio (bytes_out ≫ bytes_in) to the one external
  destination. Questions on the uploading host, the destination IP and domain, the number of uploads, the
  total bytes (with tolerance), the first upload time and (easy) the file name, with Suricata POST and
  TLS-SNI rules and a Sigma rule over the flows dataset. Number-answer `tolerance` is now carried into
  `answers.json`, and `ports.HTTP` (80) was added for the plain-HTTP sink.
- `it-scan-auth-failures`: a port scan followed by authentication failures against local test services
  (MITRE ATT&CK T1046, T1110, T1110.001, T1110.003) on the office-LAN background. New `tcp.scanner` actor
  (a host not in the asset inventory runs a TCP connect sweep of common IT ports on the server subnet: the
  domain controller's Kerberos / LDAP / SMB answer as open, while host-firewalled ports stay silent with a
  retransmitted SYN — `compose/firewall.py`) and `kerberos.bruteforce` actor (repeated Kerberos AS-REQ
  pre-authentication attempts against the KDC that fail with KDC_ERR_PREAUTH_FAILED (24); the encrypted
  timestamp is opaque `rng.label_bytes` sealed with a wrong key, so the KDC's HMAC check rejects it — no
  real cryptography). easy brute-forces one account; medium/hard spray a guess across many accounts over
  spaced rounds; hard lands one final guess (the KDC issues a ticket-granting ticket). Questions on the
  scanning host, the hosts and ports probed, the open ports, the targeted account(s), the failure count,
  the KDC error code and whether a logon succeeded (and which account), with a krb5 Suricata rule on the
  pre-auth failures and Sigma brute-force and port-sweep correlations over the kerberos and flows datasets.
  Added `ports.SCAN_SSH` / `SCAN_RPC` / `SCAN_NETBIOS` / `SCAN_RDP` (22 / 135 / 139 / 3389) for the sweep's
  closed-port probes.

### Traffic realism
- `dhcp.server` `style: windows`: the Windows Server DHCP role (Windows option order, 8-day default lease,
  the client FQDN answered in the ACK). The router option is the subnet's router when the server does not
  route itself.
- DHCP relay: a `dhcp.server` scope for a subnet the server host is not on is served through that subnet's
  router (giaddr, hops, the relay's own address and stack on the clients' side; relay to server port 67 to
  67 on the server's side, with relay agent information option 82 — circuit ID VLAN / module / port and
  the client's MAC as remote ID, the format FortiOS documents — which the server echoes). One host can
  serve several scopes.
- `dhcp.client` `reboot`: a joining host that held a lease confirms it (INIT-REBOOT: broadcast Request with
  the requested address, no server identifier, no Discover).
- `https.server` / `https.client`: intranet sites on IIS (Windows Server 2019, TLS 1.2) with an AD CS
  certificate, browsed by Edge (Chromium ClientHello, JA4 `t13d1516h2_8daaf6152771_d8a2da3f94cd`) over
  HTTP/2; no real cryptography, the handshake structure is exact and Zeek / Wireshark parse the chain. A
  later connection to a site resumes the browser's TLS session (session ID, abbreviated handshake) for
  2 hours.
- `wsus.server` / `wsus.client`: Windows Update Agent scans against WSUS (SOAP over HTTP on 8530, protocol
  version 2.4) with Xpress-compressed replies (`xpress.py`, [MS-WUSP] 2.1.1; Wireshark decompresses
  them), ReportEventBatch reporting (events 141, 147, 162) and BITS content downloads.
- Topology hosts: `aliases` (further A records in the site DNS), `role` and `inventory: false` for the
  students' asset inventory.
- `dns.client` and `ntp.client` of a host that joins over DHCP start once its address is configured and
  stop when it leaves; they talked from the capture start before.
- The ARP exchange a unicast reply needs no longer lands before the broadcast it answers (a DHCPINFORM's
  ACK); captures with a DHCP joiner can change.

### Detection engineering
- SIEM export: `siem/tls.jsonl` (one record per TLS handshake: SNI, JA4, version, cipher, ALPN, certificate
  subject / issuer / SAN) and `siem/http.jsonl` (one per HTTP/1.1 request and response: method, URI, host,
  user agent, SOAPAction, range, status, content type and encoding, sizes); `dhcp.jsonl` has `relay_addr`.
- Zeek hunts (`hunt.zeek`) take `endswith` (field -> suffix), e.g. every query under one DNS parent domain.

### Training workflow
- `pcapforge export-ctfd` is checked against a live CTFd 3.8.8 (ctfcli 0.1.8). Timestamp flags now accept
  every second within the question's `tolerance_s`, as `pcapforge grade` does; they accepted only the
  answer's own second, so a student one second off was right in `grade` and wrong in CTFd.

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
