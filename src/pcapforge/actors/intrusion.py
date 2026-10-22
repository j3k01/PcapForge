"""Intrusion actors for the IT line: a benign-equivalent TCP port sweep and a Kerberos
authentication brute-force / password spray.

Both are the *observable pattern* only, produced with correct protocol clients on the recording
loopback (CONTRIBUTING.md "benign-equivalent rule"); nothing here is an exploit or a real attack
tool.

* ``tcp.scanner`` walks a list of common IT service ports on the server subnet with bare TCP
  connects (SYN, read the answer, close). A listening service answers with a SYN/ACK (the port
  reads *open*); a port with no service is refused with a RST on the loopback and the host firewall
  stage (``compose/firewall.py``) turns that into *filtered* for a Windows target that drops
  unsolicited SYNs. This is how a sweep tells a listening host from a firewalled one.
* ``kerberos.bruteforce`` sends Kerberos AS-REQ pre-authentication attempts to the domain
  controller with a wrong key, so the KDC answers KRB-ERROR KDC_ERR_PREAUTH_FAILED (24) - the
  wire signature of password guessing (one account, ``brute-force``) or spraying one guess across
  many accounts (``spray``). On hard one final attempt uses the real key and the KDC issues a TGT
  (one guess lands). No real cryptography: the encrypted timestamp is opaque bytes from
  ``rng.label_bytes`` and the KDC compares HMACs, exactly as the AD background does.
"""

from __future__ import annotations

import socket
import struct

from pcapforge import ports
from pcapforge.actors import der, kerberos as krb, register
from pcapforge.actors.ad import USER_NAMES, DomainController
from pcapforge.actors.base import Actor
from pcapforge.plan import action_ref, host_ref
from pcapforge.rng import label_bytes
from pcapforge.scenario import ScenarioError

SOCKET_TIMEOUT = 5.0
PROBE_TIMEOUT = 0.5


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise RuntimeError("connection closed by the domain controller")
        data += chunk
    return data


# --- TCP port sweep -------------------------------------------------------------------

@register
class TcpScanner(Actor):
    """Reconnaissance from a host that is not a normal client of the servers: a TCP connect sweep of
    common IT service ports across the server subnet (MITRE ATT&CK T1046 Network Service Discovery).
    No payload is sent - this is discovery only. Params: ``targets`` (hosts to scan),
    ``start`` (fraction of the capture the sweep begins at)."""

    type = "tcp.scanner"

    # Recording ports a service listens on, by the server actor that serves it. A scanned host reads
    # "open" on these when it runs the actor. Only the domain controller's own async services are
    # swept: a bare connect to them is cleanly handled as EOF. (The intranet HTTPS and WSUS sites run
    # on a scripted TCP server that expects a client-driven exchange, so they are left out of the
    # probe set rather than stranding a half-open handler.)
    SERVICE_PORTS = {
        "ad.dc": (ports.KERBEROS, ports.LDAP, ports.SMB),
    }
    # Ports the sweep also probes but no service of the site serves (closed / filtered on the wire).
    CLOSED_PORTS = (ports.SCAN_SSH, ports.SCAN_RPC, ports.SCAN_NETBIOS, ports.SCAN_RDP)

    def plan(self) -> None:
        plan, rng = self.plan_, self.rng
        host = self.hosts[0]
        targets = sorted(plan.topology.select(self.param("targets")), key=lambda h: h.id)
        if not targets:
            raise ScenarioError(f"{self.type} '{self.id}': no targets to scan")
        service_ports = sorted({p for group in self.SERVICE_PORTS.values() for p in group})
        scan_ports = sorted(set(service_ports) | set(self.CLOSED_PORTS))
        start_lo, start_hi = self.span(self.param("start", [0.2, 0.4]))
        t = plan.duration * rng.uniform(start_lo, start_hi)
        first = None
        open_found: set[int] = set()
        per_host = []
        for target in targets:
            listening = self._listening(plan, target.id)
            opened = []
            for port in scan_ports:
                action = plan.add(t, self.id, host.id, "tcp.probe", target=target.id, port=port)
                first = first or action
                if port in listening:
                    well_known = ports.WELL_KNOWN[port]
                    open_found.add(well_known)
                    opened.append(well_known)
                t += rng.uniform(0.03, 0.25)
            per_host.append({"host": host_ref(target.id), "open_ports": sorted(opened)})
            t += rng.uniform(0.1, 0.6)
        plan.facts[self.id] = {
            "source": host_ref(host.id),
            "targets": [host_ref(target.id) for target in targets],
            "host_count": len(targets),
            "scanned_ports": sorted(ports.WELL_KNOWN[p] for p in scan_ports),
            "port_count": len(scan_ports),
            "open_ports": sorted(open_found),
            "open_count": len(open_found),
            "per_host": per_host,
            "scan_start": action_ref(first) if first else None,
        }
        if first:
            plan.event(first, self.id, "TCP port sweep of the server subnet", ["T1046"],
                       host_count=len(targets), open_ports=sorted(open_found))

    def _listening(self, plan, host_id: str) -> set[int]:
        open_ports: set[int] = set()
        for actor in plan.actors:
            if actor.type in self.SERVICE_PORTS and host_id in {h.id for h in actor.hosts}:
                open_ports.update(self.SERVICE_PORTS[actor.type])
        return open_ports

    def execute(self, action, rt) -> None:
        a = action.args
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(PROBE_TIMEOUT)
        try:
            sock.bind((rt.loopback(action.host), 0))
            sock.connect((rt.loopback(a["target"]), a["port"]))
        except OSError:
            pass
        finally:
            sock.close()


# --- Kerberos authentication brute force / password spray -----------------------------

@register
class KerberosBruteforce(Actor):
    """Repeated Kerberos AS-REQ pre-authentication failures against the domain controller
    (MITRE ATT&CK T1110 Brute Force): ``mode: brute-force`` tries many guesses against one account,
    ``mode: spray`` tries a guess against many accounts over spaced rounds (to avoid lockout). Each
    failed attempt draws KRB-ERROR KDC_ERR_PREAUTH_FAILED (24). With ``success: true`` one final
    attempt uses the real key and the KDC issues a TGT (a guessed credential lands).

    Params: ``dc`` (host running ``ad.dc``), ``accounts`` (list of sAMAccountNames, or an integer
    count drawn from the directory's user names), ``passwords`` (guesses per account), ``mode``,
    ``success``, ``start`` / ``spread`` (fraction of the capture)."""

    type = "kerberos.bruteforce"

    def plan(self) -> None:
        plan, rng = self.plan_, self.rng
        host = self.hosts[0]
        dc_host = plan.topology.select(self.param("dc"))[0]
        self.dc = next((a for a in plan.actors
                        if isinstance(a, DomainController) and a.hosts[0].id == dc_host.id), None)
        if self.dc is None:
            raise ScenarioError(f"{self.type} '{self.id}': '{dc_host.id}' runs no ad.dc")
        d = self.dc.directory

        accounts = self.param("accounts")
        if isinstance(accounts, int):
            accounts = list(USER_NAMES[:accounts])
        elif not accounts:
            accounts = [USER_NAMES[0]]
        accounts = [str(a) for a in accounts]
        passwords = int(self.param("passwords", 1))
        mode = self.param("mode", "spray")
        success = bool(self.param("success", False))

        start_lo, start_hi = self.span(self.param("start", [0.4, 0.6]))
        spread = float(self.param("spread", 0.35))
        begin = plan.duration * rng.uniform(start_lo, start_hi)
        window = max(0.0, min(1.0, spread)) * plan.duration
        window = min(window, plan.duration - begin - 1.0)

        # One failed AS-REQ per (round, account); rounds are spaced across the window so a spray
        # stays under the lockout threshold. Order is deterministic.
        attempts: list[tuple[str, int]] = []
        for round_index in range(max(1, passwords)):
            for account in accounts:
                attempts.append((account, round_index))
        step = window / max(1, len(attempts))
        t = begin
        failures = []
        first_fail = last_fail = None
        for index, (account, round_index) in enumerate(attempts):
            nonce = _nonce(self.id, account, index)
            action = plan.add(t, self.id, host.id, "krb.as_fail", account=account, nonce=nonce)
            first_fail = first_fail or action
            last_fail = action
            failures.append({"account": account, "request": action_ref(action)})
            t += step + rng.uniform(0.0, step * 0.4 if step else 0.5)

        compromised = accounts[-1] if success else None
        success_action = None
        if success:
            t = min(t + rng.uniform(1.0, 5.0), plan.duration - 0.5)
            success_action = plan.add(t, self.id, host.id, "krb.as_success", account=compromised,
                                      nonce=_nonce(self.id, compromised, "success"))

        plan.event(first_fail, self.id,
                   f"Kerberos password {'spray' if mode == 'spray' else 'guessing'} against the KDC begins",
                   ["T1110"], account=accounts[0], target=host_ref(dc_host.id))
        if success_action is not None:
            plan.event(success_action, self.id, f"Kerberos pre-authentication succeeds for {compromised}",
                       ["T1110"], account=compromised)

        plan.facts[self.id] = {
            "source": host_ref(host.id),
            "dc": host_ref(dc_host.id),
            "realm": d.realm,
            "mode": mode,
            "accounts": sorted(set(accounts)),
            "account_count": len(set(accounts)),
            "failure_count": len(failures),
            "attempt_count": len(failures) + (1 if success else 0),
            "error_code": krb.KDC_ERR_PREAUTH_FAILED,
            "error_name": "KDC_ERR_PREAUTH_FAILED",
            "protocol": "kerberos",
            "succeeded": success,
            "succeeded_text": "yes" if success else "no",
            "compromised": compromised,
            "first_failure": action_ref(first_fail),
            "last_failure": action_ref(last_fail),
            "success_request": action_ref(success_action) if success_action is not None else None,
            "failures": failures,
        }

    # recording ------------------------------------------------------------------
    def execute(self, action, rt) -> None:
        d = self.dc.directory
        host = rt.plan.topology.by_id[action.host]
        a = action.args
        client = a["account"]
        if action.op == "krb.as_fail":
            key = label_bytes(f"wrong-pw\x1f{client}\x1f{a['nonce']}", 32)
        elif action.op == "krb.as_success":
            key = d.key(client)
        else:
            raise ValueError(f"unknown operation {action.op}")
        message = self._as_req(d, host, client, key, a["nonce"])
        reply = self._exchange(host.loopback, self.dc.hosts[0].loopback, message)
        tag = der.read(reply)[0]
        if action.op == "krb.as_fail":
            if not _is_error(reply, krb.KDC_ERR_PREAUTH_FAILED):
                raise RuntimeError(f"AS brute-force of {client}: expected KDC_ERR_PREAUTH_FAILED")
        elif tag != 0x60 | krb.AS_REP:
            raise RuntimeError(f"AS success of {client}: expected an AS-REP from the KDC")

    def _as_req(self, d, host, client: str, key: bytes, nonce: int) -> bytes:
        cname = krb.principal(krb.NT_PRINCIPAL, client)
        body = krb.req_body(krb.KDC_OPT_AS, d.realm, krb.principal(krb.NT_SRV_INST, *d.spn("krbtgt")),
                            nonce, cname=cname, addresses=krb.netbios_address(host.name))
        stamp = krb.seal(f"pa-ts\x1f{client}\x1f{nonce}", krb.enc_timestamp_size(), key)
        pa = [krb.padata(krb.PA_ENC_TIMESTAMP, krb.encrypted(krb.AES256, stamp)),
              krb.padata(krb.PA_PAC_REQUEST, der.seq(der.ctx(0, der.boolean(True))))]
        return krb.kdc_req(krb.AS_REQ, pa, body)

    def _exchange(self, source: str, dc_ip: str, message: bytes) -> bytes:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(SOCKET_TIMEOUT)
        try:
            sock.bind((source, 0))
            sock.connect((dc_ip, ports.KERBEROS))
            sock.sendall(krb.tcp_frame(message))
            size = struct.unpack("!I", _recv_exact(sock, 4))[0]
            return _recv_exact(sock, size)
        finally:
            sock.close()


def _nonce(*parts: object) -> int:
    return int.from_bytes(label_bytes("\x1f".join(str(p) for p in parts), 4), "big") & 0x7FFFFFFF


def _is_error(reply: bytes, code: int) -> bool:
    tag, content, _ = der.read(reply)
    if tag != 0x60 | krb.KRB_ERROR:
        return False
    return der.to_int(der.fields(der.read(content)[1])[6]) == code
