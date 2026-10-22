"""Bulk upload to an external file host: the benign equivalent of data exfiltration.

An office PC sends opaque random bytes (``rng.label_bytes``) to a fictional cloud file host through
the firewall. Nothing weaponised runs; the scenario reproduces the *observable pattern* only - one
host pushing far more than it receives to a single external destination (CONTRIBUTING, "the
benign-equivalent rule").

What the three difficulty levels put on the wire:

* easy   - one large plain-HTTP ``POST`` with an obvious file name and ``Content-Type``
  (``application/octet-stream``). The file name, host header and byte count are all in clear text.
* medium - several uploads over HTTPS. Only the TLS record sizes are visible, exactly like the
  intranet browsing in the background; the SNI names the external host.
* hard   - uploads spread over the whole capture and sized to blend with the WSUS / BITS download
  volume. The tell is the upload/download ratio: the exfil destination is the only one this host
  sends far more to than it receives from (bytes_out vs bytes_in in the flow summaries).

The upload sink (``http.sink``) is a benign server on an external-looking subnet; it accepts the
uploads over plain HTTP (port 80) and HTTPS (port 443) and answers each with a small ``200 OK``.
Its fictional domain names are dotted DNS aliases of the host, so the site DNS resolves them.
"""

from __future__ import annotations

from pcapforge import ports
from pcapforge.actors import register, tls, x509
from pcapforge.actors.base import Actor
from pcapforge.actors.dns import query_server
from pcapforge.actors.scripted import ScriptedConnection, ScriptedServer
from pcapforge.plan import action_ref, host_ref
from pcapforge.rng import label_bytes
from pcapforge.scenario import ScenarioError

DAY = 86400.0
MIN_UPLOAD = 200_000  # a single upload is at least this many bytes

# Obvious archive / database-dump file names for the plain-HTTP upload (easy).
FILENAMES = ("financials-export.zip", "customer-db-backup.sql.gz", "hr-records-2026.zip",
             "project-archive.7z", "quarterly-report.tar.gz", "mailbox-export.pst.zip",
             "crm-dump.csv.gz", "design-docs.tar.zst")
UPLOAD_AGENT = "python-requests/2.31.0"


def _http_ok() -> bytes:
    return (b"HTTP/1.1 200 OK\r\nServer: nginx\r\nDate: Thu, 01 Jan 1970 00:00:00 GMT\r\n"
            b"Content-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")


def _split(total: int, count: int, rng) -> list[int]:
    """Split ``total`` bytes across ``count`` uploads, each at least ``MIN_UPLOAD``."""
    if count <= 1:
        return [max(MIN_UPLOAD, total)]
    weights = [rng.uniform(0.6, 1.4) for _ in range(count)]
    scale = sum(weights)
    return [max(MIN_UPLOAD, round(total * w / scale)) for w in weights]


@register
class UploadSink(Actor):
    """Benign external file host that accepts the uploads over plain HTTP (port 80) and HTTPS
    (port 443). The host needs at least one dotted DNS alias (a full external FQDN) the site DNS
    resolves to it; those are the destination names the uploads carry."""

    type = "http.sink"
    is_server = True

    def plan(self) -> None:
        plan = self.plan_
        if len(self.hosts) != 1:
            raise ScenarioError(f"{self.type} '{self.id}' runs on exactly one host")
        host = self.hosts[0]
        self.domains = sorted(a for a in host.aliases if "." in a)
        if not self.domains:
            raise ScenarioError(f"{self.type} '{self.id}': host '{host.id}' needs a dotted external FQDN alias")
        rng = self.rng
        start = plan.start_epoch
        # A public-CA-like chain for the HTTPS uploads. The issuer is never asked about, so the
        # certificate bytes are opaque; it only has to parse and carry the SNI names.
        ca_name = "GlobalSign Cloud Services Root CA"
        self.ca = x509.root_ca(ca_name, "cloud-ca.example", round(start - rng.uniform(2.0, 6.0) * 365 * DAY))
        self.certificate = x509.web_server(self.ca, ca_name, host.name, "cloud-ca.example", self.domains,
                                           round(start - rng.uniform(30, 300) * DAY))
        self.chain = [self.certificate.der, self.ca.der]
        self.server = ScriptedServer()
        plan.facts[self.id] = {"hosts": [host_ref(host.id)], "domains": self.domains}

    async def serve(self, rt) -> None:
        await self.server.start(rt, self.hosts[0].loopback, ports.HTTP)
        await self.server.start(rt, self.hosts[0].loopback, ports.HTTPS)


@register
class HttpUploader(Actor):
    """An office PC bulk-uploading opaque random bytes to an ``http.sink`` host. Params: ``server``
    (the sink host), ``dns`` (the resolver), ``mode`` (``plain`` plain-HTTP POSTs, or ``tls`` HTTPS
    uploads; default ``tls``), ``uploads`` ([lo, hi] number of uploads), ``megabytes`` ([lo, hi]
    total MB uploaded across them), ``start`` ([lo, hi] fraction of the host's window the first
    upload begins at), ``spread`` (fraction of the window the uploads are spread over)."""

    type = "http.uploader"

    def plan(self) -> None:
        plan = self.plan_
        topo = plan.topology
        host = self.hosts[0]
        wanted = {h.id for h in topo.select(self.param("server"))}
        sink = next((a for a in plan.actors if isinstance(a, UploadSink) and a.hosts[0].id in wanted), None)
        if sink is None:
            raise ScenarioError(f"{self.type} '{self.id}': no http.sink on {self.param('server')}")
        self._sink = sink
        sink_id = sink.hosts[0].id
        resolver = topo.select(self.param("dns"))[0].id
        rng = self.rng
        mode = self.param("mode", "tls")
        if mode not in ("plain", "tls"):
            raise ScenarioError(f"{self.type} '{self.id}': mode must be 'plain' or 'tls'")
        domain = rng.choice(sink.domains)

        up_lo, up_hi = (int(v) for v in self.span(self.param("uploads", [1, 1])))
        mb_lo, mb_hi = self.span(self.param("megabytes", [4, 12]))
        count = rng.randint(up_lo, up_hi)
        sizes = _split(round(rng.uniform(mb_lo, mb_hi) * 1_000_000), count, rng)

        begin, end = self.connected(host)
        span_s = max(end - begin, 1.0)
        start_lo, start_hi = self.span(self.param("start", [0.15, 0.4]))
        window = span_s * float(self.param("spread", 0.3))
        origin = begin + span_s * rng.uniform(start_lo, start_hi)
        origin = min(origin, max(begin, end - window - 10.0))
        times = sorted(origin + rng.uniform(0.0, window) for _ in range(count))

        # The tool looks the external name up once before it starts (one DNS A query).
        resolve_at = max(begin, times[0] - rng.uniform(0.5, 2.0))
        plan.add(resolve_at, self.id, host.id, "upload.resolve", server=resolver, name=domain,
                 txid=rng.randrange(1, 65536))

        filename = rng.choice(FILENAMES) if mode == "plain" else None
        uploads = []
        for conn, (t, size) in enumerate(zip(times, sizes), start=1):
            if mode == "plain":
                action = plan.add(t, self.id, host.id, "upload.post", server_host=sink_id, conn=conn,
                                  size=size, name=domain, uri=f"/upload/{filename}", filename=filename)
            else:
                action = plan.add(t, self.id, host.id, "upload.tls", server_host=sink_id, conn=conn,
                                  size=size, name=domain, order=rng.sample(range(16), 16),
                                  headers=rng.randint(260, 520), resp_hdr=rng.randint(90, 160),
                                  resp=rng.randint(40, 120))
            uploads.append({"size": size, "request": action_ref(action)})
            plan.event(action, self.id, f"Bulk upload #{conn} to {domain} ({size} bytes)",
                       ["T1048", "T1567"], bytes=size, domain=domain, upload=conn)

        first = min((u["request"] for u in uploads), key=lambda r: r["$action"].t)
        plan.facts[self.id] = {
            "source": host_ref(host.id),
            "dest": host_ref(sink_id),
            "domain": domain,
            "mode": mode,
            "upload_count": count,
            "total_bytes": sum(sizes),
            "uploads": uploads,
            "first": first,
            "filename": filename,
        }

    # -- recording ------------------------------------------------------------------
    def _label(self, host: str, conn: int) -> str:
        return f"upload\x1f{self.rng.key}\x1f{host}\x1f{conn}"

    def _post_bytes(self, a: dict, body: bytes) -> bytes:
        head = (f"POST {a['uri']} HTTP/1.1\r\n"
                f"Host: {a['name']}\r\n"
                f"User-Agent: {UPLOAD_AGENT}\r\n"
                f"Accept: */*\r\n"
                f"Content-Type: application/octet-stream\r\n"
                f"Content-Disposition: attachment; filename=\"{a['filename']}\"\r\n"
                f"Content-Length: {len(body)}\r\n"
                f"Connection: close\r\n\r\n")
        return head.encode() + body

    def execute(self, action, rt) -> None:
        a = action.args
        if action.op == "upload.resolve":
            query_server(rt, action.host, a["server"], a["name"], "A", a["txid"])
            return
        src, dst = rt.loopback(action.host), rt.loopback(a["server_host"])
        label = self._label(action.host, a["conn"])
        if action.op == "upload.post":
            conn = ScriptedConnection(rt, self._sink.server, src, dst, ports.HTTP)
            conn.exchange(self._post_bytes(a, label_bytes(f"{label}\x1fbody", a["size"])), _http_ok())
            conn.close()
            return
        # upload.tls: an HTTPS upload, body visible only as TLS record sizes.
        order = a["order"]
        conn = ScriptedConnection(rt, self._sink.server, src, dst, ports.HTTPS)
        conn.exchange(tls.client_hello(a["name"], label, lambda n: order[:n]),
                      tls.server_flight(label, self._sink.chain))
        # False Start: the upload's request headers ride with the client's Finished.
        conn.exchange(tls.client_finish(label) + tls.application_data(f"{label}\x1fhdr", a["headers"]),
                      tls.server_finish(label) + tls.application_data(f"{label}\x1frhdr", a["resp_hdr"]))
        # The upload body, then the server's 200 OK.
        conn.exchange(tls.application_data(f"{label}\x1fbody", a["size"]),
                      tls.application_data(f"{label}\x1fresp", a["resp"]))
        conn.close()
