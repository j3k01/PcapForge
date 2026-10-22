"""Benign HTTPS beaconing: the *observable pattern* of C2 check-ins produced with a real TLS
client, never any implant (CONTRIBUTING "benign-equivalent rule": "beaconing is a client fetching a
static page from a local test server at a jittered interval").

One office workstation opens a TLS 1.2 connection to an external-looking server at a regular
interval (optionally with jitter), fetches a small static page and closes it again. The server
runs on a subnet behind the firewall and answers for a fictional domain the site DNS resolves, so
to the analyst the check-ins look like beaconing to the Internet: a rare destination the rest of
the office never talks to, a distinctive SNI and a conspicuously regular cadence. The handshake is
Chromium's (``tls.py``), the same ClientHello Edge uses for the intranet sites, so on the hard
level the beacon blends with the browser and WSUS traffic and only the periodicity gives it away.

Nothing here weaponised: the "page" is a few hundred random bytes of application data, the
certificate is a synthetic chain from a fictional public CA (``x509.py``), and every address stays
on ``127.77.0.0/16`` until the composer rewrites it.
"""

from __future__ import annotations

from pcapforge import ports
from pcapforge.actors import register, tls, x509
from pcapforge.actors.base import Actor
from pcapforge.actors.dns import query_server
from pcapforge.actors.scripted import ScriptedConnection, ScriptedServer
from pcapforge.plan import action_ref, host_ref
from pcapforge.scenario import ScenarioError

DAY = 86400.0
DNS_TTL = 1200.0          # the A record's TTL the site DNS answers (dns.py)
SESSION_LIFETIME = 7200.0  # BoringSSL TLS 1.2 session lifetime, reused on resumed check-ins
MIN_GAP = 2.0             # keep jittered check-ins monotonic and non-overlapping


@register
class BeaconServer(Actor):
    """The external-looking server a beacon checks in with: a TLS 1.2 endpoint that serves a tiny
    static page for a fictional domain. The domain is drawn per seed from the ``domains`` param (or a
    dotted DNS alias already on the host) and registered as a full external FQDN the site DNS
    resolves to this host. Its certificate comes from a fictional public CA, not the domain's AD CS
    root, so the chain is itself a tell. Params: ``domains`` (candidate FQDNs), ``issuer`` (CA CN)."""

    type = "tls.beacon_server"
    is_server = True

    def plan(self) -> None:
        plan = self.plan_
        if len(self.hosts) != 1:
            raise ScenarioError(f"{self.type} '{self.id}' runs on exactly one host")
        host = self.hosts[0]
        candidates = self.param("domains") or [a for a in host.aliases if "." in a]
        candidates = [c.lower() for c in ([candidates] if isinstance(candidates, str) else candidates)]
        if not candidates or any("." not in c for c in candidates):
            raise ScenarioError(
                f"{self.type} '{self.id}': needs 'domains' (full external FQDNs) or a dotted host alias")
        self.fqdn = self.rng.choice(sorted(candidates))
        # Register the fictional domain in the site DNS zone (an A record to this host) so the
        # beacon's lookups resolve; it travels in the recording key through the host's aliases.
        if self.fqdn not in [a.lower() for a in host.aliases]:
            host.aliases.append(self.fqdn)
        rng = self.rng
        start = plan.start_epoch
        issuer = self.param("issuer", "Acme Public TLS RSA CA G2")
        registrable = ".".join(self.fqdn.split(".")[-2:])
        ca = x509.root_ca(issuer, registrable, round(start - rng.uniform(2.0, 6.0) * 365 * DAY))
        cert = x509.web_server(ca, issuer, host.name, registrable, [self.fqdn],
                               round(start - rng.uniform(30.0, 300.0) * DAY))
        self.chain = [cert.der, ca.der]
        self.server = ScriptedServer()
        plan.facts[self.id] = {
            "hosts": [host_ref(host.id)],
            "domain": self.fqdn,
            "issuer": issuer,
            "port": ports.WELL_KNOWN[ports.HTTPS],
            "tls_version": "TLS 1.2",
            "cipher_suite": tls.SUITE_NAMES[tls.SCHANNEL_SUITE],
            "certificate": {"subject": cert.subject, "issuer": cert.issuer, "serial": cert.serial,
                            "dns_names": [self.fqdn], "not_before": cert.not_before,
                            "not_after": cert.not_after},
        }

    async def serve(self, rt) -> None:
        await self.server.start(rt, self.hosts[0].loopback, ports.HTTPS)


@register
class BeaconClient(Actor):
    """A workstation beaconing to a :class:`BeaconServer` at a regular interval. Params: ``server``
    (the beacon server host), ``dns`` (the resolver), ``interval`` (nominal seconds between
    check-ins, a scalar or ``[lo, hi]`` drawn per seed), ``jitter`` (fraction of the interval the
    actual time wanders by, 0 for an exact cadence), ``start`` (fraction of the capture at which the
    first check-in falls, ``[lo, hi]``), ``resume`` (reuse the TLS session on later check-ins),
    ``request`` / ``response`` (application-data sizes, ``[lo, hi]``)."""

    type = "tls.beacon"

    def plan(self) -> None:
        plan = self.plan_
        topo = plan.topology
        if len(self.hosts) != 1:
            raise ScenarioError(f"{self.type} '{self.id}' runs on exactly one host (the beaconing PC)")
        host = self.hosts[0]
        server = next((a for a in plan.actors if isinstance(a, BeaconServer)
                       and a.hosts[0].id in {h.id for h in topo.select(self.param("server"))}), None)
        if server is None:
            raise ScenarioError(f"{self.type} '{self.id}': no tls.beacon_server on {self.param('server')}")
        self._server = server
        server_id = server.hosts[0].id
        resolver = topo.select(self.param("dns"))[0].id
        rng = self.rng.child(host.id)

        lo, hi = self.span(self.param("interval", [60.0, 60.0]))
        interval = lo if lo == hi else rng.uniform(lo, hi)
        jitter = float(self.param("jitter", 0.0))
        start_lo, start_hi = self.span(self.param("start", [0.03, 0.1]))
        req_lo, req_hi = (int(v) for v in self.span(self.param("request", [120, 320])))
        resp_lo, resp_hi = (int(v) for v in self.span(self.param("response", [200, 900])))
        resume = bool(self.param("resume", False))

        begin, end = self.connected(host)
        nominal = begin + (end - begin) * rng.uniform(start_lo, start_hi)
        resolved_at = -DNS_TTL
        session_conn, session_at = None, 0.0
        checkins: list[dict] = []
        conn = 0
        prev = None
        while nominal < end:
            t = nominal + (rng.uniform(-jitter, jitter) * interval if jitter else 0.0)
            if prev is not None:
                t = max(t, prev + MIN_GAP)
            if t >= end:
                break
            if resolved_at + DNS_TTL <= t:
                plan.add(t, self.id, host.id, "beacon.resolve", name=server.fqdn, server=resolver,
                         txid=rng.randrange(1, 65536), txid6=rng.randrange(1, 65536))
                resolved_at = t
                t += rng.uniform(0.002, 0.02)
            conn += 1
            use = session_conn if resume and session_conn is not None and t - session_at < SESSION_LIFETIME else None
            if use is None:
                session_conn, session_at = conn, t
            action = plan.add(t, self.id, host.id, "beacon.checkin", server=server_id, conn=conn,
                              resume=use, request=rng.randint(req_lo, req_hi),
                              response=rng.randint(resp_lo, resp_hi), order=rng.sample(range(16), 16))
            plan.event(action, self.id, f"HTTPS check-in to {server.fqdn}", ["T1071.001", "T1573"],
                       destination=server.fqdn, interval_s=round(interval, 3), resumed=use is not None)
            checkins.append({"request": action_ref(action), "conn": conn})
            prev = t
            nominal += interval

        if not checkins:
            raise ScenarioError(f"{self.type} '{self.id}': no check-in fits in the capture window")
        plan.facts[self.id] = {
            "source": host_ref(host.id),
            "destination": host_ref(server_id),
            "domain": server.fqdn,
            "interval_s": round(interval, 3),
            "jitter": jitter,
            "checkin_count": len(checkins),
            "first_checkin": checkins[0]["request"],
            "last_checkin": checkins[-1]["request"],
            "checkins": checkins,
        }

    def _label(self, host: str, conn: int) -> str:
        return f"beacon\x1f{self.rng.key}\x1f{host}\x1f{conn}"

    def execute(self, action, rt) -> None:
        a = action.args
        if action.op == "beacon.resolve":
            query_server(rt, action.host, a["server"], a["name"], "A", a["txid"])
            query_server(rt, action.host, a["server"], a["name"], "AAAA", a["txid6"])
            return
        server = self._server
        label = self._label(action.host, a["conn"])
        conn = ScriptedConnection(rt, server.server, rt.loopback(action.host), rt.loopback(a["server"]),
                                  ports.HTTPS)
        order = a["order"]
        if a["resume"] is None:
            conn.exchange(tls.client_hello(server.fqdn, label, lambda n: order[:n]),
                          tls.server_flight(label, server.chain))
            conn.exchange(tls.client_finish(label) + tls.application_data(f"{label}\x1freq", a["request"]),
                          tls.server_finish(label) + tls.application_data(f"{label}\x1fresp", a["response"]))
        else:
            session = tls.session_id(self._label(action.host, a["resume"]))
            conn.exchange(tls.client_hello(server.fqdn, label, lambda n: order[:n], session),
                          tls.server_resume(label, session))
            conn.exchange(tls.client_resume_finish(label) + tls.application_data(f"{label}\x1freq", a["request"]),
                          tls.application_data(f"{label}\x1fresp", a["response"]))
        conn.close()
