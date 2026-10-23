"""Active Directory reconnaissance over LDAP (it-ldap-reconnaissance).

A host that is not a normal client of the directory enumerates it over LDAP: all users, the
accounts that carry a service principal name, the protected (``adminCount=1``) accounts, the
members of Domain Admins and the domain's trusts - the observable pattern of AD reconnaissance
tools (BloodHound / ``ldapsearch`` collectors), produced with a plain LDAP client and a synthetic
directory served by the domain controller (CONTRIBUTING.md "benign-equivalent rule").

The directory is a self-contained ``ReconDirectory`` the recon actor builds deterministically and
attaches to the DC's ``Directory`` (opt-in ``recon_dir``); it never changes the baseline. Three
tells, one per difficulty:

* **easy** - the client binds unsealed (LDAP simple bind) and sends tell-tale filters in cleartext
  (``(objectClass=user)``, ``(servicePrincipalName=*)``, ``(adminCount=1)``, the Domain Admins
  group, ``(objectClass=trustedDomain)``) seconds apart; every filter and every returned entry is
  readable on the wire.
* **medium** - the same filters, each pulled with the MS-ADTS paged-results control and spread out
  over the capture, so the enumeration hides in time.
* **hard** - the client binds with Kerberos (GSS-SPNEGO, sealed), exactly like a legitimate member,
  so the filters are opaque; the tell is volume and timing: one host opens round after round of
  LDAP sessions to the DC, each pulling large sealed responses.

No real cryptography or credentials: the sealed binds reuse the AD background's opaque
``label_bytes`` ciphertext and the DC's ticket machinery.
"""

from __future__ import annotations

import socket
import struct

from pcapforge import ports
from pcapforge.actors import kerberos as krb, ldap, register
from pcapforge.actors.ad import (Directory, DomainController, _Member, _read_ldap, _recv_exact, _tcp)
from pcapforge.actors.base import Actor
from pcapforge.plan import action_ref, host_ref
from pcapforge.rng import label_bytes
from pcapforge.scenario import ScenarioError

USER_POOL = ("a.nowak", "j.kowalski", "m.wisniewska", "p.zielinski", "k.lewandowska", "t.wojcik",
             "j.smith", "m.jones", "r.miller", "s.davis", "l.becker", "f.schulz", "e.kowalczyk",
             "d.novak", "h.wagner", "o.lewandowski", "n.schmidt", "w.kaczmarek", "b.andersson",
             "c.dubois", "g.rossi", "v.petrov", "a.muller", "p.nowakowski")
# Service accounts and the service principal names they carry (what a Kerberoasting pass looks for).
SERVICE_SPECS = (
    ("svc_sql", lambda dom: [f"MSSQLSvc/sql01.{dom}:1433", f"MSSQLSvc/sql01.{dom}"]),
    ("svc_web", lambda dom: [f"HTTP/web01.{dom}", f"HTTP/intranet.{dom}"]),
    ("svc_backup", lambda dom: [f"CIFS/fs01.{dom}"]),
    ("svc_exch", lambda dom: [f"exchangeMDB/mail01.{dom}"]),
    ("svc_app", lambda dom: [f"TERMSRV/app01.{dom}"]),
    ("svc_scan", lambda dom: [f"HOST/scan01.{dom}", f"RestrictedKrbHost/scan01.{dom}"]),
)
# Fictional forest trusts a recon pass discovers (trustedDomain objects under CN=System).
TRUST_SPECS = (("contoso.local", "CONTOSO"), ("partner.example", "PARTNER"), ("legacy.lan", "LEGACY"))

PERSON_CLASSES = [b"top", b"person", b"organizationalPerson", b"user"]
GROUP_CLASSES = [b"top", b"group"]
TRUST_CLASSES = [b"top", b"leaf", b"trustedDomain"]
ATTR_SET = ["sAMAccountName", "distinguishedName", "displayName", "servicePrincipalName",
            "adminCount", "memberOf", "objectClass"]
STEP_SEARCH = (0.05, 0.25)                 # easy: gap between back-to-back cleartext searches (s)
STEP_KRB = (0.01, 0.03)
PAGE_SIZE = 3


def _display(first_last: str) -> str:
    parts = first_last.replace(".", " ").split()
    return " ".join(p.capitalize() for p in parts)


class _Object:
    """One directory object: its DN, ordered (attribute, values) list and a match index."""

    __slots__ = ("dn", "attrs", "_index")

    def __init__(self, dn: str, attrs: list[tuple[str, list[bytes]]]) -> None:
        self.dn = dn
        self.attrs = attrs
        self._index: dict[str, list[bytes]] = {}
        for name, values in attrs:
            self._index.setdefault(name.lower(), []).extend(values)

    def matches(self, filt: bytes) -> bool:
        return ldap.filter_matches(filt, self._index)

    def entry(self, message_id: int, wanted: list[str]) -> bytes:
        keep = {w.lower() for w in wanted}
        attrs = [(n, v) for n, v in self.attrs if not keep or n.lower() in keep or n.lower() == "objectclass"]
        return ldap.search_entry(message_id, self.dn, attrs)


class ReconDirectory:
    """A synthetic directory the DC serves to a reconnaissance client, plus the ordered list of
    searches the client runs and the facts the answer key needs."""

    def __init__(self, base: str, domain: str, rng, *, n_users: int, n_service: int,
                 n_admins: int, n_trusts: int, sealed_accounts=()) -> None:
        self.base = base
        self.domain = domain
        self.users_dn = f"CN=Users,{base}"
        self.system_dn = f"CN=System,{base}"
        self.da_dn = f"CN=Domain Admins,{self.users_dn}"
        self.sealed_accounts = set(sealed_accounts)

        people = list(USER_POOL[:n_users])
        services = [spec for spec in SERVICE_SPECS[:n_service]]
        admins = ["Administrator"] + people[:max(0, n_admins - 1)]

        self.objects: list[_Object] = []
        self.people_sams: list[str] = []
        self.service_sams: list[str] = []
        self.admin_members: list[str] = []

        def user_dn(sam: str) -> str:
            return f"CN={sam},{self.users_dn}"

        for sam in ["Administrator"] + people:
            member_of = [b"CN=Domain Users," + self.users_dn.encode()]
            attrs = [("objectClass", list(PERSON_CLASSES)),
                     ("cn", [sam.encode()]), ("name", [sam.encode()]),
                     ("sAMAccountName", [sam.encode()]),
                     ("userPrincipalName", [f"{sam}@{domain}".encode()]),
                     ("displayName", [_display(sam).encode()]),
                     ("userAccountControl", [b"512"])]
            if sam in admins:
                attrs.append(("adminCount", [b"1"]))
                member_of.append(self.da_dn.encode())
                self.admin_members.append(sam)
            attrs.append(("memberOf", member_of))
            self.objects.append(_Object(user_dn(sam), attrs))
            self.people_sams.append(sam)

        for sam, spn in services:
            spns = [s.encode() for s in spn(domain)]
            attrs = [("objectClass", list(PERSON_CLASSES)),
                     ("cn", [sam.encode()]), ("name", [sam.encode()]),
                     ("sAMAccountName", [sam.encode()]),
                     ("userPrincipalName", [f"{sam}@{domain}".encode()]),
                     ("displayName", [_display(sam.replace('_', ' ')).encode()]),
                     ("servicePrincipalName", spns),
                     ("memberOf", [b"CN=Domain Users," + self.users_dn.encode()]),
                     ("userAccountControl", [b"512"])]
            self.objects.append(_Object(user_dn(sam), attrs))
            self.service_sams.append(sam)

        members = [user_dn(sam).encode() for sam in self.admin_members]
        self.objects.append(_Object(self.da_dn, [
            ("objectClass", list(GROUP_CLASSES)), ("cn", [b"Domain Admins"]), ("name", [b"Domain Admins"]),
            ("sAMAccountName", [b"Domain Admins"]), ("adminCount", [b"1"]),
            ("groupType", [b"-2147483646"]), ("member", members)]))
        for group in ("Domain Users", "Enterprise Admins"):
            self.objects.append(_Object(f"CN={group},{self.users_dn}", [
                ("objectClass", list(GROUP_CLASSES)), ("cn", [group.encode()]),
                ("sAMAccountName", [group.encode()]), ("groupType", [b"-2147483646"])]))

        self.trusts: list[str] = []
        for partner, flat in TRUST_SPECS[:n_trusts]:
            self.trusts.append(partner)
            self.objects.append(_Object(f"CN={partner},{self.system_dn}", [
                ("objectClass", list(TRUST_CLASSES)), ("cn", [partner.encode()]),
                ("trustPartner", [partner.encode()]), ("flatName", [flat.encode()]),
                ("trustDirection", [b"3"]), ("trustType", [b"2"]), ("trustAttributes", [b"8"])]))

        self.searches = self._searches()
        self.entry_total = sum(len(s["dn_list"]) for s in self.searches)

    # ---- the ordered reconnaissance searches --------------------------------------
    def _searches(self) -> list[dict]:
        def spec(base, scope, filt, text, wanted):
            matches = [o for o in self._scoped(base, scope) if o.matches(filt)]
            return {"base": base, "scope": scope, "filter": filt, "text": text, "attrs": wanted,
                    "dn_list": [o.dn for o in matches]}
        user = ldap.equality("objectClass", b"user")
        group = ldap.equality("objectClass", b"group")
        return [
            spec(self.base, ldap.SCOPE_SUBTREE, ldap.and_filter(user, ldap.present("sAMAccountName")),
                 "(&(objectClass=user)(sAMAccountName=*))", ATTR_SET),
            spec(self.base, ldap.SCOPE_SUBTREE, ldap.present("servicePrincipalName"),
                 "(servicePrincipalName=*)", ["sAMAccountName", "servicePrincipalName"]),
            spec(self.base, ldap.SCOPE_SUBTREE, ldap.equality("adminCount", b"1"),
                 "(adminCount=1)", ["sAMAccountName", "adminCount"]),
            spec(self.da_dn, ldap.SCOPE_BASE, ldap.and_filter(group, ldap.present("member")),
                 "(&(objectClass=group)(member=*))", ["member", "sAMAccountName"]),
            spec(self.system_dn, ldap.SCOPE_SUBTREE, ldap.equality("objectClass", b"trustedDomain"),
                 "(objectClass=trustedDomain)", ["trustPartner", "flatName", "trustDirection"]),
        ]

    def _scoped(self, base: str, scope: int) -> list[_Object]:
        base = base.lower()
        if scope == ldap.SCOPE_BASE:
            return [o for o in self.objects if o.dn.lower() == base]
        return [o for o in self.objects if o.dn.lower().endswith(base)]

    @property
    def spn_filter(self) -> str:
        return self.searches[1]["text"]

    # ---- serving ------------------------------------------------------------------
    def _results(self, base: str, scope: int, filt: bytes) -> list[_Object]:
        return [o for o in self._scoped(base, scope) if o.matches(filt)]

    async def serve_unsealed(self, reader, writer, next_id: int) -> None:
        """Answer the client's cleartext SearchRequests (honouring the paged-results control) with
        SearchResultEntry / SearchResultDone until it unbinds or drops the connection."""
        buffered = b""
        while True:
            while (size := ldap.message_size(buffered)) is None or len(buffered) < size:
                chunk = await reader.read(65536)
                if not chunk:
                    return
                buffered += chunk
            message, buffered = buffered[:size], buffered[size:]
            message_id, op, content = ldap.parse(message)
            if op == ldap.UNBIND_REQUEST:
                return
            if op != ldap.SEARCH_REQUEST:
                continue
            base, scope, filt, wanted = ldap.search_parts(content)
            results = self._results(base, scope, filt)
            paged = ldap.paged_cookie(message)
            if paged is None:
                for obj in results:
                    writer.write(obj.entry(message_id, wanted))
                writer.write(ldap.search_done(message_id))
            else:
                page, cookie = paged
                offset = int.from_bytes(cookie, "big") if cookie else 0
                for obj in results[offset:offset + page]:
                    writer.write(obj.entry(message_id, wanted))
                nxt = offset + page
                done_cookie = nxt.to_bytes(4, "big") if nxt < len(results) else b""
                writer.write(ldap.search_done(message_id, controls=ldap.paged_control(0, done_cookie)))
            await writer.drain()

    def sealed_script(self, next_id: int) -> list[tuple[bytes, bytes]]:
        """One (request, reply) pair per reconnaissance search: the DC's sealed loop wraps each reply.
        The reply bytes are the real SearchResultEntry/Done (large), so the wrapped responses carry
        realistic sizes even though an analyst cannot read them."""
        script = []
        mid = next_id
        for search in self.searches:
            reply = b"".join(o.entry(mid, search["attrs"]) for o in self._results(
                search["base"], search["scope"], search["filter"]))
            reply += ldap.search_done(mid)
            script.append((search["filter"], reply))
            mid += 1
        return script


def _read_search_result(sock: socket.socket) -> int:
    """Read SearchResultEntry messages until the SearchResultDone; return the entry count and the
    paged cookie carried on the Done (empty when the enumeration is complete)."""
    buffered = b""
    entries = 0
    while True:
        while (size := ldap.message_size(buffered)) is None or len(buffered) < size:
            chunk = sock.recv(65536)
            if not chunk:
                raise RuntimeError("LDAP connection closed by the domain controller")
            buffered += chunk
        message, buffered = buffered[:size], buffered[size:]
        _, op, _ = ldap.parse(message)
        if op == ldap.SEARCH_ENTRY:
            entries += 1
        elif op == ldap.SEARCH_DONE:
            return entries, (ldap.paged_cookie(message) or (0, b""))[1]


@register
class LdapReconnaissance(Actor):
    """A reconnaissance client that enumerates the AD directory over LDAP (MITRE ATT&CK T1087.002
    Account Discovery: Domain Account, T1069.002 Permission Groups Discovery: Domain Groups,
    T1482 Domain Trust Discovery).

    Params: ``dc`` (host running ``ad.dc``), ``account`` (the account the client binds as; defaults
    to a directory user), ``sealed`` (hard: Kerberos GSS-SPNEGO sealed binds), ``paged`` (medium:
    paged-results control), ``rounds`` (sealed enumeration rounds, the volume tell), ``start`` /
    ``spread`` (fraction of the capture the enumeration begins at / is spread over), and the
    directory sizes ``users`` / ``services`` / ``admins`` / ``trusts``."""

    type = "ldap.recon"

    def plan(self) -> None:
        plan, rng = self.plan_, self.rng
        host = self.hosts[0]
        dc_host = plan.topology.select(self.param("dc"))[0]
        self.dc = next((a for a in plan.actors
                        if isinstance(a, DomainController) and a.hosts[0].id == dc_host.id), None)
        if self.dc is None:
            raise ScenarioError(f"{self.type} '{self.id}': '{dc_host.id}' runs no ad.dc")
        d = self.dc.directory

        self.sealed = bool(self.param("sealed", False))
        self.paged = bool(self.param("paged", False))
        account = self.param("account") or USER_POOL[1]
        self.account = str(account)
        recon = ReconDirectory(d.base, d.domain, rng.child("directory"),
                               n_users=int(self.param("users", 8)),
                               n_service=int(self.param("services", 3)),
                               n_admins=int(self.param("admins", 3)),
                               n_trusts=int(self.param("trusts", 1)),
                               sealed_accounts=[self.account] if self.sealed else [])
        self.recon = recon
        d.recon_dir = recon

        bind_name = f"{self.account}@{d.domain}"
        start_lo, start_hi = self.span(self.param("start", [0.15, 0.3]))
        spread = float(self.param("spread", 0.0))
        begin = plan.duration * rng.uniform(start_lo, start_hi)
        window = max(0.0, min(1.0, spread)) * plan.duration
        window = min(window, max(0.0, plan.duration - begin - 1.0))

        searches, first_search = [], None
        if self.sealed:
            rounds = int(self.param("rounds", 6))
            t = begin
            plan.add(t, self.id, host.id, "recon.kinit", account=self.account)
            t += rng.uniform(*STEP_KRB)
            step = window / max(1, rounds)
            for index in range(rounds):
                action = plan.add(t, self.id, host.id, "recon.session", account=self.account,
                                  bind=bind_name, searches=len(recon.searches))
                first_search = first_search or action
                t += step + rng.uniform(0.0, step * 0.3 if step else 1.0)
        else:
            t = begin
            plan.add(t, self.id, host.id, "recon.open", bind=bind_name)
            t += rng.uniform(*STEP_KRB)
            step = window / max(1, len(recon.searches)) if window else 0.0
            for index, search in enumerate(recon.searches):
                action = plan.add(t, self.id, host.id, "recon.search", index=index,
                                  filter=search["text"], paged=self.paged)
                searches.append({"filter": search["text"], "entries": len(search["dn_list"]),
                                 "request": action_ref(action)})
                first_search = first_search or action
                t += (step if step else rng.uniform(*STEP_SEARCH))
            plan.add(min(t, plan.duration - 0.2), self.id, host.id, "recon.close")

        plan.event(first_search, self.id, "LDAP directory reconnaissance from an unexpected host",
                   ["T1087.002", "T1069.002", "T1482"], host=host_ref(host.id), account=self.account)

        plan.facts[self.id] = {
            "source": host_ref(host.id),
            "dc": host_ref(dc_host.id),
            "domain": d.domain,
            "account": self.account,
            "bind_name": bind_name,
            "sealed": self.sealed,
            "spn_filter": recon.spn_filter,
            "entry_count": recon.entry_total,
            "domain_admins": sorted(recon.admin_members),
            "domain_admins_count": len(recon.admin_members),
            "domain_admins_dn": recon.da_dn,
            "service_accounts": sorted(recon.service_sams),
            "trusts": sorted(recon.trusts),
            "rounds": int(self.param("rounds", 0)) if self.sealed else 0,
            "session_count": int(self.param("rounds", 6)) if self.sealed else 1,
            "searches": searches,
            "first_search": action_ref(first_search),
        }

    # ---- recording ----------------------------------------------------------------
    def execute(self, action, rt) -> None:
        d = self.dc.directory
        host = rt.plan.topology.by_id[action.host]
        a = action.args
        op = action.op
        key = (self.id, action.host)
        if op == "recon.open":
            sock = _tcp(host.loopback, d.dc.loopback, ports.LDAP)
            sock.sendall(ldap.bind_simple(1, a["bind"]))
            _read_ldap(sock, 1)
            rt.clients[key] = {"sock": sock, "mid": 2}
        elif op == "recon.search":
            self._unsealed_search(rt.clients[key], d, a["index"], a["paged"])
        elif op == "recon.close":
            conn = rt.clients.pop(key, None)
            if conn is not None:
                conn["sock"].sendall(ldap.unbind(conn["mid"]))
                conn["sock"].close()
        elif op == "recon.kinit":
            member = _Member(rt, d, host)
            started = rt.plan.start_epoch + rt.clock.t
            member.as_request(self.account, preauth=False, tcp=False, started=started)
            member.as_request(self.account, preauth=True, tcp=False, started=started)
            member.as_request(self.account, preauth=True, tcp=True, started=started)
            tgt = d.ticket(self.account, d.spn("krbtgt"), rt.clock.t)
            member.tgs_exchange(self.account, tgt, d.spn("ldap"))
        elif op == "recon.session":
            self._sealed_session(rt, d, host, a)
        else:
            raise ValueError(f"unknown operation {op}")

    def _unsealed_search(self, conn: dict, d: Directory, index: int, paged: bool) -> None:
        sock, search = conn["sock"], self.recon.searches[index]
        cookie = b""
        while True:
            controls = ldap.paged_control(PAGE_SIZE, cookie) if paged else b""
            sock.sendall(ldap.search(conn["mid"], search["base"], search["scope"], search["filter"],
                                     search["attrs"], controls=controls))
            _, cookie = _read_search_result(sock)
            conn["mid"] += 1
            if not paged or not cookie:
                break

    def _sealed_session(self, rt, d: Directory, host, a: dict) -> None:
        sock = _tcp(host.loopback, d.dc.loopback, ports.LDAP)
        try:
            sock.sendall(d.root_dse(1)[0])            # rootDSE SearchRequest (cleartext)
            _read_ldap(sock, 2)
            ticket = d.ticket(self.account, d.spn("ldap"), rt.clock.t)
            member = _Member(rt, d, host)
            token, issued = member.gss_token(self.account, ticket)
            sock.sendall(ldap.bind_sasl(2, "GSS-SPNEGO", token))
            _read_ldap(sock, 1)
            seq = _nonce(issued.label, "recon-initiator")
            count = a["searches"]
            for index in range(count):
                request = ldap.search(3 + index, d.base, ldap.SCOPE_SUBTREE, ldap.present("objectClass"), [])
                token = krb.wrap_token(f"ldap-recon\x1f{issued.label}\x1f{index}\x1fc", len(request),
                                       False, seq + index)
                sock.sendall(struct.pack("!I", len(token)) + token)
                size = struct.unpack("!I", _recv_exact(sock, 4))[0]
                _recv_exact(sock, size)
            token = krb.wrap_token(f"ldap-recon\x1f{issued.label}\x1f{count}\x1fc", len(ldap.unbind(3 + count)),
                                   False, seq + count)
            sock.sendall(struct.pack("!I", len(token)) + token)
        finally:
            sock.close()

    def close(self, rt) -> None:
        for key in [k for k in rt.clients if k[0] == self.id]:
            conn = rt.clients.pop(key)
            if isinstance(conn, dict):
                conn["sock"].close()


def _nonce(*parts: object) -> int:
    return int.from_bytes(label_bytes("\x1f".join(str(p) for p in parts), 4), "big") & 0x7FFFFFFF

