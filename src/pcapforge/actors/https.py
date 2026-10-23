"""Intranet web sites over HTTPS: IIS on Windows Server with an AD CS certificate, and Microsoft Edge on
the workstations (TLS 1.2 handshakes and record sizes from ``tls.py``, HTTP/2 inside).

What a browser does on the wire for one visit: it resolves the site name (A and AAAA through the
site DNS), opens a TCP connection to port 443 and runs a full TLS 1.2 handshake with SNI and ALPN
h2 (False Start: its first request rides with its Finished), loads the page, then the page's
resources on the same connection, a smaller set on later page views of the same visit (browser
cache). IIS (http.sys) closes a connection that has been idle for its connectionTimeout of
120 s: an HTTP/2 GOAWAY, then the TCP close. A page view within that time reuses the connection.
The names are cached for the DNS TTL the site DNS gives (1200 s). A later connection to a site
resumes the TLS session of the last full handshake with it (abbreviated handshake, session ID)
while that session is younger than BoringSSL's default TLS 1.2 session lifetime of 2 hours;
Schannel keeps its server sessions for 10 hours (ServerCacheTime), so the browser's limit decides.

HTTP/2 framing sizes: the client preface (24 bytes), SETTINGS (4 settings), WINDOW_UPDATE and a
first HEADERS block of 290-430 bytes, later requests' HPACK-compressed HEADERS of 50-120 bytes;
the server's SETTINGS (3 settings) and SETTINGS ACK, response HEADERS of 110-190 bytes and DATA
frames of at most 16384 bytes, each with a 9-byte frame header.
"""

from __future__ import annotations

import asyncio

from pcapforge import ports
from pcapforge.actors import register, tls, x509
from pcapforge.actors.base import Actor
from pcapforge.actors.dns import query_server
from pcapforge.actors.scripted import ScriptedConnection, ScriptedServer
from pcapforge.plan import action_ref, host_ref
from pcapforge.scenario import ScenarioError

IDLE_TIMEOUT = 120.0     # IIS connectionTimeout: http.sys closes an idle connection
DNS_TTL = 1200.0         # what the site DNS answers (dns.py)
SESSION_LIFETIME = 7200.0  # BoringSSL SSL_DEFAULT_SESSION_TIMEOUT for TLS 1.2 sessions
FRAME = 9                # HTTP/2 frame header
PREFACE = 24
GOAWAY = FRAME + 8
DAY = 86400.0

# Per page: (HTML bytes, resources on the first view [count range, bytes range], on later views).
PROFILES = {
    "portal": ((18_000, 60_000), (5, 10), (1_500, 120_000), (0, 2)),
    "helpdesk": ((6_000, 25_000), (3, 6), (1_000, 60_000), (0, 1)),
}


def _data(size: int) -> int:
    """Bytes of ``size`` bytes of body in DATA frames."""
    return size + FRAME * max(1, -(-size // 16384))


@register
class HttpsServer(Actor):
    """IIS web sites on the host's DNS aliases, with a server certificate from the site's AD CS
    enterprise root CA. Params: ``ca`` (host the CA runs on, e.g. the DC), ``sites``
    ({alias: profile}, profiles ``portal`` / ``helpdesk``; default every alias as a portal),
    ``tickets`` (issue RFC 5077 session tickets; default false, as Schannel/IIS uses its session-ID
    cache)."""

    type = "https.server"
    is_server = True

    def plan(self) -> None:
        plan = self.plan_
        topo = plan.topology
        if len(self.hosts) != 1:
            raise ScenarioError(f"{self.type} '{self.id}' runs on exactly one host")
        host = self.hosts[0]
        sites = self.param("sites") or {alias: "portal" for alias in host.aliases}
        unknown = [s for s in sites if s not in host.aliases]
        if unknown or not sites:
            raise ScenarioError(f"{self.type} '{self.id}': sites must be DNS aliases of '{host.id}' ({unknown})")
        if any(p not in PROFILES for p in sites.values()):
            raise ScenarioError(f"{self.type} '{self.id}': site profiles are {', '.join(PROFILES)}")
        ca_host = topo.select(self.param("ca"))[0]
        rng = self.rng
        netbios = topo.domain.split(".")[0][:15]
        self.ca_name = x509.ca_name(netbios, ca_host.name)
        start = plan.start_epoch
        self.ca = x509.root_ca(self.ca_name, topo.domain, round(start - rng.uniform(1.5, 4.0) * 365 * DAY))
        self.sites = {f"{alias.lower()}.{topo.domain}": profile for alias, profile in sites.items()}
        names = list(self.sites)
        self.certificate = x509.web_server(self.ca, self.ca_name, ca_host.name, topo.domain, names,
                                           round(start - rng.uniform(30, 600) * DAY))
        self.chain = [self.certificate.der, self.ca.der]
        self.tickets = bool(self.param("tickets", False))
        self.server = ScriptedServer()
        cert = self.certificate
        plan.facts[self.id] = {
            "hosts": [host_ref(host.id)],
            "sites": names,
            "ca": {"name": self.ca_name, "host": host_ref(ca_host.id), "subject": self.ca.subject,
                   "serial": self.ca.serial},
            "certificate": {"subject": cert.subject, "issuer": cert.issuer, "serial": cert.serial,
                            "dns_names": names, "not_before": cert.not_before, "not_after": cert.not_after},
            "tls_version": "TLS 1.2",
            "cipher_suite": tls.SUITE_NAMES[tls.SCHANNEL_SUITE],
            "alpn": "h2",
        }

    async def serve(self, rt) -> None:
        await self.server.start(rt, self.hosts[0].loopback, ports.HTTPS)


class _Browser:
    """A host's open connection to one site during recording."""

    def __init__(self, conn: ScriptedConnection, label: str) -> None:
        self.conn = conn
        self.label = label
        self.records = 0

    def data(self, size: int) -> bytes:
        self.records += 1
        return tls.application_data(f"{self.label}\x1f{self.records}", size)


@register
class HttpsClient(Actor):
    """Microsoft Edge on Windows workstations browsing intranet sites. Params: ``servers`` (hosts of an
    ``https.server``), ``dns`` (the resolver), ``visits_per_hour`` ([lo, hi] per host), ``pages``
    ([lo, hi] page views per visit), ``think`` ([lo, hi] seconds between page views)."""

    type = "https.client"

    def plan(self) -> None:
        plan = self.plan_
        topo = plan.topology
        servers = [a for a in plan.actors if isinstance(a, HttpsServer)
                   and a.hosts[0].id in {h.id for h in topo.select(self.param("servers"))}]
        if not servers:
            raise ScenarioError(f"{self.type} '{self.id}': no https.server on {self.param('servers')}")
        sites = [(fqdn, profile, server) for server in servers for fqdn, profile in server.sites.items()]
        resolver = topo.select(self.param("dns"))[0].id
        rate_lo, rate_hi = self.span(self.param("visits_per_hour", [2, 6]))
        pages_lo, pages_hi = (int(v) for v in self.span(self.param("pages", [1, 4])))
        think = self.span(self.param("think", [8, 90]))
        clients, visited = [], set()
        for host in self.hosts:
            if host.device.stack.name != "windows":
                raise ScenarioError(f"{self.type} needs Windows hosts; '{host.id}' runs {host.device.stack.name}")
            rng = self.rng.child(host.id)
            begin, end = self.connected(host)
            if host.present is not None and host.arrives:
                begin += rng.uniform(60.0, 600.0)  # the user logs on and opens the browser
            rate = rng.uniform(rate_lo, rate_hi) / 3600.0
            resolved: dict[str, float] = {}
            open_: dict[str, tuple[int, float]] = {}   # fqdn -> (connection number, last activity)
            sessions: dict[str, tuple[int, float]] = {}  # fqdn -> (full handshake connection, its time)
            connections, visits, resumed = 0, [], 0
            t = begin + rng.uniform(0.0, min(1.0 / rate, 0.4 * max(end - begin, 0.0)))
            while t < end:
                fqdn, profile, server = sites[rng.randrange(len(sites))]
                target = server.hosts[0].id
                for name, (number, last) in list(open_.items()):
                    if last + IDLE_TIMEOUT <= t:
                        plan.add(last + IDLE_TIMEOUT, self.id, host.id, "https.timeout", site=name, conn=number)
                        del open_[name]
                first_action = None
                if resolved.get(fqdn, -DNS_TTL) + DNS_TTL <= t:
                    first_action = plan.add(t, self.id, host.id, "https.resolve", name=fqdn, server=resolver,
                                            txid=rng.randrange(1, 65536), txid6=rng.randrange(1, 65536))
                    resolved[fqdn] = t
                    t += rng.uniform(0.002, 0.02)
                html, first_count, resource, later_count = PROFILES[profile]
                for page in range(rng.randint(pages_lo, pages_hi)):
                    if t >= end and page:
                        break
                    count = rng.randint(*(first_count if page == 0 else later_count))
                    page_args = {
                        "html": rng.randint(*html),
                        "headers": [rng.randint(110, 190) for _ in range(count + 1)],
                        "resources": [rng.randint(*resource) for _ in range(count)],
                        "requests": [rng.randint(50, 120) for _ in range(count + 1)],
                    }
                    if fqdn not in open_:
                        connections += 1
                        number = connections
                        held = sessions.get(fqdn)
                        resume = held[0] if held and t - held[1] < SESSION_LIFETIME else None
                        if resume is None:
                            sessions[fqdn] = (number, t)
                        else:
                            resumed += 1
                        action = plan.add(t, self.id, host.id, "https.connect", site=fqdn, server=target,
                                          conn=number, resume=resume, first_request=rng.randint(290, 430),
                                          order=rng.sample(range(16), 16), **page_args)
                    else:
                        number = open_[fqdn][0]
                        action = plan.add(t, self.id, host.id, "https.page", site=fqdn, conn=number, **page_args)
                    first_action = first_action or action
                    open_[fqdn] = (number, t + 1.5)
                    visited.add(fqdn)
                    t += rng.uniform(*think)
                visits.append({"site": fqdn, "server": host_ref(target), "first": action_ref(first_action)})
                t += rng.expovariate(rate)
            for name, (number, last) in open_.items():
                at = last + IDLE_TIMEOUT
                plan.add(at if at < plan.duration else plan.duration + 1.0, self.id, host.id, "https.timeout",
                         site=name, conn=number, **({} if at < plan.duration else {"phase": "teardown"}))
            clients.append({"host": host_ref(host.id), "visits": visits, "connections": connections,
                            "resumed": resumed})
        self._servers = {s.hosts[0].id: s for s in servers}
        self._site_server = {fqdn: server for fqdn, _, server in sites}
        plan.facts[self.id] = {"clients": clients, "sites_visited": sorted(visited),
                               "resumed": sum(c["resumed"] for c in clients),
                               "hosts": [host_ref(h.id) for h in self.hosts]}

    def _label(self, host: str, site: str, conn: int) -> str:
        return f"https\x1f{self.rng.key}\x1f{host}\x1f{site}\x1f{conn}"

    # -- recording ------------------------------------------------------------------
    def execute(self, action, rt) -> None:
        a = action.args
        key = (self.id, action.host, a.get("site"), a.get("conn"))
        if action.op == "https.resolve":
            query_server(rt, action.host, a["server"], a["name"], "A", a["txid"])
            query_server(rt, action.host, a["server"], a["name"], "AAAA", a["txid6"])
            return
        if action.op == "https.timeout":
            browser = rt.clients.pop(key)
            browser.conn.server_close(browser.data(GOAWAY))
            return
        if action.op == "https.connect":
            server = self._site_server[a["site"]]
            label = self._label(action.host, a["site"], a["conn"])
            conn = ScriptedConnection(rt, server.server, rt.loopback(action.host), rt.loopback(a["server"]),
                                      ports.HTTPS)
            browser = rt.clients[key] = _Browser(conn, label)
            order = a["order"]
            # The server sends its SETTINGS, acknowledges the client's, then answers the first request.
            first = PREFACE + FRAME + 24 + FRAME + 4 + FRAME + a["first_request"]
            answer = (browser.data(FRAME + 18 + FRAME + 4 + FRAME)
                      + browser.data(FRAME + a["headers"][0] + _data(a["html"])))
            if a["resume"] is None:
                conn.exchange(tls.client_hello(a["site"], label, lambda n: order[:n]),
                              tls.server_flight(label, server.chain, tickets=server.tickets))
                # False Start: the first request goes with the client's Finished.
                conn.exchange(tls.client_finish(label) + browser.data(first),
                              tls.server_finish(label, ticket=server.tickets) + answer)
            elif server.tickets:
                # RFC 5077 resumption: the stored ticket plus a fresh session ID the server echoes.
                ticket = tls.session_ticket(self._label(action.host, a["site"], a["resume"]))
                session = tls.client_session(label)
                conn.exchange(tls.client_hello(a["site"], label, lambda n: order[:n], ticket=ticket),
                              tls.server_resume(label, session))
                conn.exchange(tls.client_resume_finish(label) + browser.data(first), answer)
            else:
                session = tls.session_id(self._label(action.host, a["site"], a["resume"]))
                conn.exchange(tls.client_hello(a["site"], label, lambda n: order[:n], session),
                              tls.server_resume(label, session))
                conn.exchange(tls.client_resume_finish(label) + browser.data(first), answer)
            self._resources(browser, a, settings_ack=True)
            return
        browser = rt.clients[key]
        browser.conn.exchange(browser.data(FRAME + a["requests"][0]),
                              browser.data(FRAME + a["headers"][0] + _data(a["html"])))
        self._resources(browser, a, settings_ack=False)

    @staticmethod
    def _resources(browser: _Browser, a: dict, settings_ack: bool) -> None:
        """The page's resources: the requests in one flight, the responses as they complete."""
        if not a["resources"]:
            if settings_ack:
                browser.conn.exchange(browser.data(FRAME), b"")
            return
        request = sum(FRAME + size for size in a["requests"][1:]) + (FRAME if settings_ack else 0)
        reply = b"".join(browser.data(FRAME + head + _data(body))
                         for head, body in zip(a["headers"][1:], a["resources"]))
        browser.conn.exchange(browser.data(request), reply)

    def close(self, rt) -> None:
        for key in [k for k in rt.clients if k[0] == self.id]:
            rt.clients.pop(key).conn.close()
