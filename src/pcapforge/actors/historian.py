"""Historian replication across the industrial DMZ: the plant (control-network) historian pushes its
collected time-series to a replica historian in the DMZ, over HTTPS/REST, on a fixed schedule.

This is how a generic historian / AVEVA PI-to-PI style replication looks from the plant side: the
control-network historian keeps one authenticated TLS session open to the DMZ replica's REST endpoint
(PI Web API and most historian REST APIs ship with a self-signed certificate by default) and, every
replication interval, POSTs the batch of point values it has buffered since the last push. The
request grows with the number of tags and samples in the batch; the reply is a small JSON
acknowledgement. The payload is opaque inside TLS - what an analyst sees is a steady, periodic
exchange from the control network to the DMZ, always in the same direction, never the reverse.

``historian.replica`` (the DMZ endpoint) and ``historian.replication`` (the control-side pusher) are
reusable building blocks: an incident scenario can change the cadence, the batch size or the
direction, or add a second replication target, without touching the recorder.
"""

from __future__ import annotations

from pcapforge import ports
from pcapforge.actors import register, tls, x509
from pcapforge.actors.base import Actor
from pcapforge.actors.scripted import ScriptedConnection, ScriptedServer
from pcapforge.plan import action_ref, host_ref
from pcapforge.scenario import ScenarioError

DAY = 86400.0
POST_HEADER = 520          # TLS-wrapped HTTP POST request line + headers (host, auth, content-type, length)
PER_SAMPLE = 46            # compact JSON of one {tag, timestamp, value, quality} sample, roughly
RESPONSE_BYTES = 180       # the replica's "202 Accepted" JSON acknowledgement


@register
class HistorianReplica(Actor):
    """The DMZ replica historian: an HTTPS/REST endpoint the plant historian replicates into. Presents
    a self-signed appliance certificate (the historian product's default). Runs on one host."""

    type = "historian.replica"
    is_server = True

    def plan(self) -> None:
        plan = self.plan_
        if len(self.hosts) != 1:
            raise ScenarioError(f"{self.type} '{self.id}' runs on exactly one host")
        host = self.hosts[0]
        self.fqdn = f"{host.name.lower()}.{plan.topology.domain}"
        # Issued some months back and still valid during the capture (a 1-year appliance certificate).
        not_before = round(plan.start_epoch - self.rng.uniform(30, 330) * DAY)
        self.certificate = x509.self_signed(self.fqdn, not_before)
        self.chain = [self.certificate.der]
        self.path = self.param("path", "/piwebapi/streamsets/recorded")
        self.server = ScriptedServer()
        cert = self.certificate
        plan.facts[self.id] = {
            "hosts": [host_ref(host.id)],
            "fqdn": self.fqdn,
            "port": ports.WELL_KNOWN[ports.HTTPS],
            "path": self.path,
            "certificate": {"subject": cert.subject, "issuer": cert.issuer, "serial": cert.serial,
                            "self_signed": True, "not_before": cert.not_before, "not_after": cert.not_after},
            "tls_version": "TLS 1.2",
            "cipher_suite": tls.SUITE_NAMES[tls.SCHANNEL_SUITE],
        }

    async def serve(self, rt) -> None:
        await self.server.start(rt, self.hosts[0].loopback, ports.HTTPS)


class _Channel:
    """The plant historian's open replication session to the DMZ replica during recording."""

    def __init__(self, conn: ScriptedConnection, label: str) -> None:
        self.conn = conn
        self.label = label
        self.records = 0

    def data(self, size: int) -> bytes:
        self.records += 1
        return tls.application_data(f"{self.label}\x1f{self.records}", size)


@register
class HistorianReplication(Actor):
    """The control-network historian pushing its buffered points to the DMZ replica on a fixed
    schedule. Params: ``server`` (host running ``historian.replica``), ``interval`` (replication period
    in seconds), ``tags`` (points per batch, [lo, hi]), ``start`` ([lo, hi] fraction of the capture the
    session opens), ``jitter`` (fractional jitter on the cadence, default 0.02)."""

    type = "historian.replication"

    def plan(self) -> None:
        plan = self.plan_
        topo = plan.topology
        servers = {a.hosts[0].id: a for a in plan.actors if isinstance(a, HistorianReplica)}
        target = topo.select(self.param("server"))
        if len(target) != 1:
            raise ScenarioError(f"{self.type} '{self.id}': 'server' must name exactly one replica host")
        target = target[0]
        if target.id not in servers:
            raise ScenarioError(f"{self.type} '{self.id}': no historian.replica on '{target.id}'")
        self._servers = servers
        self._server_fqdn = servers[target.id].fqdn
        interval = float(self.param("interval", 60.0))
        tags_lo, tags_hi = (int(v) for v in self.span(self.param("tags", [200, 400])))
        start_span = self.span(self.param("start", [0.02, 0.08]))
        jitter = float(self.param("jitter", 0.02))

        channels = []
        for host in self.hosts:
            rng = self.rng.child(host.id)
            begin, end = self.connected(host)
            window = max(end - begin, 1.0)
            t0 = begin + rng.uniform(*start_span) * window
            order = rng.sample(range(16), 16)
            connect = plan.add(t0, self.id, host.id, "hist.connect", server=target.id,
                               server_name=self._server_fqdn, order=order)
            pushes = 0
            t = t0 + rng.uniform(interval * 0.5, interval)
            while t < end - 0.5:
                samples = rng.randint(tags_lo, tags_hi)
                request = POST_HEADER + samples * PER_SAMPLE
                plan.add(t, self.id, host.id, "hist.push", server=target.id,
                         request=request, response=RESPONSE_BYTES, samples=samples)
                pushes += 1
                t += interval * rng.uniform(1.0 - jitter, 1.0 + jitter)
            plan.add(min(end - 0.2, t), self.id, host.id, "hist.close", server=target.id)
            channels.append({"source": host_ref(host.id), "target": host_ref(target.id),
                             "connect": action_ref(connect), "pushes": pushes})
        plan.facts[self.id] = {
            "channels": channels,
            "source": host_ref(self.hosts[0].id),
            "target": host_ref(target.id),
            "server_fqdn": self._server_fqdn,
            "port": ports.WELL_KNOWN[ports.HTTPS],
            "interval_s": interval,
        }

    # -- recording -----------------------------------------------------------------
    def execute(self, action, rt) -> None:
        a = action.args
        key = (self.id, action.host, a["server"])
        if action.op == "hist.connect":
            server = self._servers[a["server"]]
            label = f"hist\x1f{self.rng.key}\x1f{action.host}\x1f{a['server']}"
            conn = ScriptedConnection(rt, server.server, rt.loopback(action.host),
                                      rt.loopback(server.hosts[0].id), ports.HTTPS)
            order = a["order"]
            conn.exchange(tls.client_hello(a["server_name"], label, lambda n: order[:n]),
                          tls.server_flight(label, server.chain))
            conn.exchange(tls.client_finish(label), tls.server_finish(label))
            rt.clients[key] = _Channel(conn, label)
            return
        if action.op == "hist.push":
            channel = rt.clients[key]
            channel.conn.exchange(channel.data(a["request"]), channel.data(a["response"]))
            return
        channel = rt.clients.pop(key, None)
        if channel is not None:
            channel.conn.server_close(channel.data(23))

    def close(self, rt) -> None:
        for key in [k for k in rt.clients if k[0] == self.id]:
            rt.clients.pop(key).conn.close()
