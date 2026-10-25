"""Remote Desktop (MS-RDPBCGR) over TLS: an office engineer's mstsc session to a DMZ jump host, and
the jump host's onward session into the plant control network (to the engineering workstation).

What RDP puts on the wire before the screen traffic starts, and what an analyst can read:

1. The client opens TCP 3389 and sends an X.224 Connection Request inside a TPKT. Its *cookie* is
   cleartext: ``Cookie: mstshash=<user>\\r\\n`` carries the user the client is about to log on as,
   and the RDP Negotiation Request asks for TLS (PROTOCOL_SSL) and CredSSP/NLA (PROTOCOL_HYBRID).
2. The server answers with an X.224 Connection Confirm whose RDP Negotiation Response selects the
   security protocol (CredSSP here).
3. A TLS 1.2 handshake follows (record sizes and the handshake flights from ``tls.py``); the server
   presents the self-signed certificate Windows Remote Desktop generates for its own host name.
4. Everything after that - the CredSSP/NLA exchange that authenticates the user (Kerberos or NTLM
   inside SPNEGO), the MCS connection, the capability exchange and then the interactive session's
   input and screen updates - is opaque TLS application data. We size those records like an
   interactive session: small client input records, larger server screen-update records, at a steady
   cadence for the length of the session.

The cookie is the one field worth hunting on: it names the account, in the clear, in the first
packet of every connection. ``rdp.server`` / ``rdp.client`` are reusable building blocks; an
incident scenario layered on top only has to point a new ``rdp.client`` at a control-network host,
or change the account, source or target of an existing one.
"""

from __future__ import annotations

import struct

from pcapforge import ports
from pcapforge.actors import register, tls, x509
from pcapforge.actors.base import Actor
from pcapforge.actors.scripted import ScriptedConnection, ScriptedServer
from pcapforge.plan import action_ref, host_ref
from pcapforge.scenario import ScenarioError

DAY = 86400.0
# RDP Negotiation (MS-RDPBCGR 2.2.1.1.1 / 2.2.1.2.1).
PROTOCOL_SSL, PROTOCOL_HYBRID, PROTOCOL_HYBRID_EX = 0x00000001, 0x00000002, 0x00000008
TYPE_RDP_NEG_REQ, TYPE_RDP_NEG_RSP = 0x01, 0x02
PROTO_NAMES = {PROTOCOL_SSL: "SSL", PROTOCOL_HYBRID: "CredSSP (HYBRID)", PROTOCOL_HYBRID_EX: "HYBRID_EX"}


def _proto_names(mask: int) -> list[str]:
    return [name for bit, name in PROTO_NAMES.items() if mask & bit]


def _tpkt(payload: bytes) -> bytes:
    """A TPKT (RFC 1006) envelope: version 3, reserved 0, 16-bit total length."""
    return b"\x03\x00" + struct.pack("!H", 4 + len(payload)) + payload


def connection_request(user: str, protocols: int) -> bytes:
    """TPKT + X.224 Connection Request with the routing cookie (``mstshash=<user>``) and the RDP
    Negotiation Request asking for ``protocols`` (PROTOCOL_SSL | PROTOCOL_HYBRID for NLA)."""
    cookie = f"Cookie: mstshash={user}\r\n".encode()
    neg_req = struct.pack("<BBHI", TYPE_RDP_NEG_REQ, 0x00, 8, protocols)
    body = b"\xe0\x00\x00\x00\x00\x00" + cookie + neg_req   # CR+CDT, DST-REF, SRC-REF, class 0
    return _tpkt(bytes((len(body),)) + body)


def connection_confirm(selected: int, src_ref: int = 0x1234) -> bytes:
    """TPKT + X.224 Connection Confirm with the RDP Negotiation Response selecting a protocol."""
    neg_rsp = struct.pack("<BBHI", TYPE_RDP_NEG_RSP, 0x00, 8, selected)
    body = b"\xd0\x00\x00" + struct.pack(">H", src_ref) + b"\x00" + neg_rsp
    return _tpkt(bytes((len(body),)) + body)


@register
class RdpServer(Actor):
    """A Remote Desktop host (a DMZ jump host, or an engineering workstation in the control network)
    listening on TCP 3389. It presents the self-signed certificate Windows generates for its own host
    name. Runs on exactly one host; point one ``rdp.server`` at each RDP target."""

    type = "rdp.server"
    is_server = True

    def plan(self) -> None:
        plan = self.plan_
        if len(self.hosts) != 1:
            raise ScenarioError(f"{self.type} '{self.id}' runs on exactly one host")
        host = self.hosts[0]
        self.fqdn = f"{host.name.lower()}.{plan.topology.domain}"
        # Issued some months back and still valid (a 1-year certificate Windows renews before expiry).
        not_before = round(plan.start_epoch - self.rng.uniform(30, 330) * DAY)
        self.certificate = x509.self_signed(self.fqdn, not_before)
        self.chain = [self.certificate.der]
        self.server = ScriptedServer()
        cert = self.certificate
        plan.facts[self.id] = {
            "hosts": [host_ref(host.id)],
            "fqdn": self.fqdn,
            "port": ports.WELL_KNOWN[ports.RDP],
            "certificate": {"subject": cert.subject, "issuer": cert.issuer, "serial": cert.serial,
                            "self_signed": True, "not_before": cert.not_before, "not_after": cert.not_after},
            "tls_version": "TLS 1.2",
            "cipher_suite": tls.SUITE_NAMES[tls.SCHANNEL_SUITE],
        }

    async def serve(self, rt) -> None:
        await self.server.start(rt, self.hosts[0].loopback, ports.RDP)


class _Session:
    """One host's open RDP connection during recording; unique opaque TLS records per step."""

    def __init__(self, conn: ScriptedConnection, label: str) -> None:
        self.conn = conn
        self.label = label
        self.records = 0

    def data(self, size: int) -> bytes:
        self.records += 1
        return tls.application_data(f"{self.label}\x1f{self.records}", size)


@register
class RdpClient(Actor):
    """A Remote Desktop client: one or more interactive sessions from the actor's host(s) to a single
    RDP server, during the working day. Params: ``target`` (host running an ``rdp.server``), ``account``
    (the user in the ``mstshash`` cookie), ``start`` ([lo, hi] fraction of the capture when a session
    opens), ``duration`` ([lo, hi] session length in seconds), ``interval`` (seconds between interactive
    bursts), ``sessions`` (sessions per host, default 1), ``nla`` (request CredSSP/NLA, default true),
    ``via`` (id of an earlier ``rdp.client`` whose target is this actor's host: the onward hop of a jump
    host, so each session opens after and closes before an inbound session of that actor; ``start`` is
    then ignored)."""

    type = "rdp.client"

    def plan(self) -> None:
        plan = self.plan_
        topo = plan.topology
        targets = topo.select(self.param("target"))
        if len(targets) != 1:
            raise ScenarioError(f"{self.type} '{self.id}': 'target' must name exactly one RDP server host")
        target = targets[0]
        servers = {a.hosts[0].id: a for a in plan.actors if isinstance(a, RdpServer)}
        if target.id not in servers:
            raise ScenarioError(f"{self.type} '{self.id}': no rdp.server on '{target.id}'")
        self._servers = servers
        self._server_fqdn = servers[target.id].fqdn
        self.target_id = target.id
        self.windows: list[tuple[float, float]] = []   # (open, close) of every session, for onward hops
        inbound = self._inbound(self.param("via"))
        account = self.param("account")
        if not account:
            raise ScenarioError(f"{self.type} '{self.id}': 'account' (the mstshash user) is required")
        requested = PROTOCOL_SSL | (PROTOCOL_HYBRID if self.param("nla", True) else 0)
        selected = PROTOCOL_HYBRID if self.param("nla", True) else PROTOCOL_SSL
        start_span = self.span(self.param("start", [0.1, 0.3]))
        duration_span = self.span(self.param("duration", [180, 480]))
        interval = float(self.param("interval", 4.0))
        count = int(self.param("sessions", 1))

        sessions = []
        for host in self.hosts:
            rng = self.rng.child(host.id)
            begin, end = self.connected(host)
            window = max(end - begin, 1.0)
            for index in range(count):
                number = index + 1
                if inbound is None:
                    t0 = begin + rng.uniform(*start_span) * window
                    t_end = min(t0 + rng.uniform(*duration_span), end - 1.0)
                else:
                    # The onward hop runs inside an inbound session to this host: the user logs on to
                    # the jump host, opens the next RDP session from its desktop, and closes it first.
                    lo, hi = inbound[index % len(inbound)]
                    t0 = lo + min(rng.uniform(15.0, 60.0), 0.25 * (hi - lo))
                    t_end = min(t0 + rng.uniform(*duration_span), hi - min(rng.uniform(2.0, 10.0), 0.1 * (hi - lo)))
                if t_end <= t0:
                    t_end = min(t0 + interval * 3, end - 0.5)
                order = rng.sample(range(16), 16)
                # CredSSP/NLA inside TLS: SPNEGO negotiate/challenge, authenticate + pubKeyAuth, then
                # the encrypted TSCredentials and the server's ack.
                credssp = [[rng.randint(220, 320), rng.randint(300, 420)],
                           [rng.randint(90, 160), rng.randint(1500, 2100)],
                           [rng.randint(1600, 2200), rng.randint(90, 160)]]
                # MCS connect / capability exchange, then the first full desktop bitmap.
                initial = [rng.randint(900, 2600), rng.randint(20000, 90000)]
                connect = plan.add(t0, self.id, host.id, "rdp.connect", target=target.id, conn=number,
                                   user=account, requested=requested, selected=selected,
                                   server_name=self._server_fqdn, order=order, credssp=credssp,
                                   initial=initial)
                bursts = 0
                t = t0 + rng.uniform(1.0, interval)
                while t < t_end:
                    client_size = rng.randint(40, 260)
                    server_size = (rng.randint(240, 22000) if rng.random() < 0.8
                                   else rng.randint(60, 320))  # most bursts repaint, some are cursor only
                    plan.add(t, self.id, host.id, "rdp.input", target=target.id, conn=number,
                             client=client_size, server=server_size)
                    bursts += 1
                    t += rng.uniform(interval * 0.5, interval * 1.5)
                plan.add(t_end, self.id, host.id, "rdp.close", target=target.id, conn=number)
                self.windows.append((t0, t_end))
                sessions.append({"source": host_ref(host.id), "target": host_ref(target.id),
                                 "account": account, "connect": action_ref(connect),
                                 "requested_protocols": _proto_names(requested),
                                 "selected_protocol": _proto_names(selected)[0], "bursts": bursts})
        plan.facts[self.id] = {
            "sessions": sessions,
            "account": account,
            "source": host_ref(self.hosts[0].id),
            "target": host_ref(target.id),
            "server_fqdn": self._server_fqdn,
            "port": ports.WELL_KNOWN[ports.RDP],
            "session_count": len(sessions),
        }

    def _inbound(self, via) -> list[tuple[float, float]] | None:
        """The session windows of the ``via`` client arriving at this actor's (single) host, or None."""
        if not via:
            return None
        source = next((a for a in self.plan_.actors if a.id == via), None)
        if not isinstance(source, RdpClient) or not hasattr(source, "windows"):
            raise ScenarioError(f"{self.type} '{self.id}': 'via' must name an rdp.client declared before it")
        if len(self.hosts) != 1 or source.target_id != self.hosts[0].id:
            raise ScenarioError(f"{self.type} '{self.id}': 'via' client '{via}' must target this actor's one host")
        if not source.windows:
            raise ScenarioError(f"{self.type} '{self.id}': 'via' client '{via}' has no sessions")
        return source.windows

    # -- recording -----------------------------------------------------------------
    def execute(self, action, rt) -> None:
        a = action.args
        key = (self.id, action.host, a["conn"])
        if action.op == "rdp.connect":
            server = self._servers[a["target"]]
            label = f"rdp\x1f{self.rng.key}\x1f{action.host}\x1f{a['target']}\x1f{a['conn']}"
            conn = ScriptedConnection(rt, server.server, rt.loopback(action.host),
                                      rt.loopback(server.hosts[0].id), ports.RDP)
            # X.224 Connection Request (cleartext cookie) -> Connection Confirm.
            conn.exchange(connection_request(a["user"], a["requested"]), connection_confirm(a["selected"]))
            order = a["order"]
            conn.exchange(tls.client_hello(a["server_name"], label, lambda n: order[:n]),
                          tls.server_flight(label, server.chain))
            conn.exchange(tls.client_finish(label), tls.server_finish(label))
            sess = rt.clients[key] = _Session(conn, label)
            for creq, cresp in a["credssp"]:
                conn.exchange(sess.data(creq), sess.data(cresp))
            conn.exchange(sess.data(a["initial"][0]), sess.data(a["initial"][1]))
            return
        if action.op == "rdp.input":
            sess = rt.clients[key]
            sess.conn.exchange(sess.data(a["client"]), sess.data(a["server"]))
            return
        # rdp.close: the server sends a final record and closes the connection.
        sess = rt.clients.pop(key, None)
        if sess is not None:
            sess.conn.server_close(sess.data(23))

    def close(self, rt) -> None:
        for key in [k for k in rt.clients if k[0] == self.id]:
            rt.clients.pop(key).conn.close()
