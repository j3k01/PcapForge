r"""SMB lateral-movement incident actors for the IT line (MITRE ATT&CK T1021.002 SMB/Windows Admin
Shares, T1078.002 Valid Accounts: Domain Accounts).

The *observable pattern* only, produced with the correct Kerberos / SMB 3.1.1 clients and servers on
the recording loopback (CONTRIBUTING.md "benign-equivalent rule"); nothing here is an exploit, a
service install or a remote execution.

* ``smb.server`` gives the office workstations an SMB 3.1.1 server role for this scenario (the office
  baseline never runs it, so its output is unchanged). It reuses the DC's Kerberos directory to accept
  a ``cifs/<workstation>`` service ticket and answers NEGOTIATE / SESSION_SETUP, TREE_CONNECT to the
  administrative shares (ADMIN$, C$, IPC$), a directory listing (CREATE / QUERY_DIRECTORY / CLOSE) and
  LOGOFF. A workstation named by ``deny`` refuses the ADMIN$ / C$ tree connect with
  STATUS_ACCESS_DENIED.
* ``smb.lateral`` is one source host that authenticates once with one domain account (a Kerberos AS
  exchange, so the account is on the wire), then, for each target workstation, asks the KDC for a
  ``cifs/<target>`` service ticket (TGS) and opens an SMB session to ``\\<target>\ADMIN$`` (and IPC$ /
  C$), lists the share and logs off - admin-share access fanning out across many hosts in a short
  window, the signature of lateral movement with a reused domain credential. No file is read or
  written and no service is created.
"""

from __future__ import annotations

import asyncio
import struct

from pcapforge import ports
from pcapforge.actors import kerberos as krb, register, smb2
from pcapforge.actors.ad import (
    DomainController, _Member, _SmbConnection, _Stopper, _read_exact,
)
from pcapforge.actors.base import Actor
from pcapforge.plan import action_ref, host_ref
from pcapforge.rng import label_bytes
from pcapforge.scenario import ScenarioError

# Admin-style domain accounts a stolen-credential lateral movement might reuse (plain person accounts,
# no "$"); one is picked per seed when the scenario does not name one.
ADMIN_ACCOUNTS = ("svc_backup", "adm.helpdesk", "da_jkowalski", "svc_sccm", "adm.desktop", "t2.admin")
ADMIN_SHARES = ("ADMIN$", "C$", "IPC$")
# Client step gaps (s), longer than the exchange they wait for takes.
STEP_UDP = (0.004, 0.012)
STEP_RETRY = (0.002, 0.006)
STEP_TCP = (0.008, 0.025)
STEP_SMB = (0.01, 0.04)


@register
class SmbServer(Actor):
    """SMB 3.1.1 server role on the workstations for an admin-share lateral-movement scenario.

    Params: ``dc`` (host running ``ad.dc``; its directory supplies the Kerberos keys and the
    workstations' machine accounts), ``deny`` (host selector whose ADMIN$ / C$ tree connects are
    refused with STATUS_ACCESS_DENIED)."""

    type = "smb.server"
    is_server = True

    def plan(self) -> None:
        plan = self.plan_
        dc_host = plan.topology.select(self.param("dc"))[0]
        self.dc = next((a for a in plan.actors if isinstance(a, DomainController)
                        and a.hosts[0].id == dc_host.id), None)
        if self.dc is None:
            raise ScenarioError(f"{self.type} '{self.id}': '{dc_host.id}' runs no ad.dc")
        deny = self.param("deny")
        self._deny = {h.id for h in plan.topology.select(deny)} if deny else set()
        plan.facts[self.id] = {"hosts": [host_ref(h.id) for h in self.hosts], "shares": list(ADMIN_SHARES),
                               "denied": [host_ref(h) for h in sorted(self._deny)]}

    async def serve(self, rt) -> None:
        self.rt = rt
        self.d = self.dc.directory
        for host in self.hosts:
            denied = host.id in self._deny
            handler = (lambda h, dn: (lambda reader, writer: self._smb_stream(h, dn, reader, writer)))(host, denied)
            server = await asyncio.start_server(handler, host.loopback, ports.SMB)
            rt.servers.append(_Stopper(server))

    def _now(self) -> float:
        return self.plan_.start_epoch + self.rt.clock.t

    def _accept(self, token: bytes):
        """(ticket holder, SPNEGO accept token with the AP-REP) for a SESSION_SETUP's cifs ticket."""
        tkt_cipher, authenticator = krb.ap_req_parts(krb.spnego_ap_req(token))
        holder = self.d.holder(tkt_cipher, "cifs")
        if holder is None or not krb.sealed_by(authenticator, holder.session):
            raise RuntimeError("SMB AP-REQ with a ticket the workstation cannot decrypt")
        cipher = krb.seal(f"ap-rep\x1f{holder.label}\x1f{self.rt.clock.t}", krb.ap_rep_part_size(), holder.session)
        return holder, krb.neg_token_resp(krb.krb5_token(krb.TOK_AP_REP, krb.ap_rep(cipher)))

    async def _smb_stream(self, host, denied: bool, reader, writer) -> None:
        d = self.d
        sessions: dict[int, str] = {}       # session id -> ticket label (signing)
        files: dict[bytes, str] = {}
        next_tree = 1
        try:
            while (head := await _read_exact(reader, 4)) is not None:
                message = await _read_exact(reader, struct.unpack("!I", head)[0])
                if message is None:
                    break
                h = smb2.parse_header(message)
                body = message[smb2.HEADER_SIZE:]
                command, mid, session_id, tree_id = h["command"], h["message_id"], h["session_id"], h["tree_id"]
                label = sessions.get(session_id)
                status = smb2.STATUS_SUCCESS
                if command == smb2.NEGOTIATE:
                    salt = label_bytes(f"smb-salt\x1f{host.id}\x1f{self.rt.clock.t}\x1f{mid}", 32)
                    reply = smb2.negotiate_response(d.server_guid.bytes_le, self._now(), krb.neg_token_init2(), salt)
                elif command == smb2.SESSION_SETUP:
                    holder, token = self._accept(smb2.security_buffer(body))
                    session_id = int.from_bytes(label_bytes(f"smb-session\x1f{host.id}\x1f{holder.label}", 8),
                                                "little") | 1
                    sessions[session_id] = label = holder.label
                    reply = smb2.session_setup_response(token)
                elif command == smb2.TREE_CONNECT:
                    share = smb2.tree_connect_path(body).rsplit("\\", 1)[1].upper()
                    tree_id = next_tree
                    next_tree += 4
                    if denied and share in ("ADMIN$", "C$"):
                        status = smb2.STATUS_ACCESS_DENIED
                        reply = smb2.error_response()
                    elif share == "IPC$":
                        reply = smb2.tree_connect_response(smb2.SHARE_PIPE, 0x30, 0, 0x001F00A9)
                    else:
                        reply = smb2.tree_connect_response(smb2.SHARE_DISK, 0x00000800, 0x00000008, 0x001F01FF)
                elif command == smb2.CREATE:
                    file_id = label_bytes(f"smb-dir\x1f{host.id}\x1f{label}\x1f{mid}", 16)
                    files[file_id] = "dir"
                    disk_id = label_bytes(f"smb-vol\x1f{host.id}", 8) + d.server_guid.bytes_le[:8]
                    now = self._now()
                    reply = smb2.create_dir_response(file_id, (now, now, now, now), 0x001F01FF, disk_id)
                elif command == smb2.QUERY_DIRECTORY:
                    now = self._now()
                    entries = smb2.dir_entries([(name, (now, now, now, now), 0, smb2.ATTRIBUTE_DIRECTORY)
                                                for name in (".", "..", "System32", "Temp")])
                    reply = smb2.query_directory_response(entries)
                elif command == smb2.CLOSE:
                    files.pop(smb2.file_id_of(body, smb2.CLOSE), None)
                    reply = smb2.close_response()
                elif command == smb2.TREE_DISCONNECT:
                    reply = smb2.empty()
                elif command == smb2.LOGOFF:
                    sessions.pop(session_id, None)
                    reply = smb2.empty()
                else:
                    raise RuntimeError(f"unexpected SMB2 command {command}")
                signature = (label_bytes(f"smb-sig\x1f{label}\x1f{mid}\x1fs", 16)
                             if label is not None and command != smb2.NEGOTIATE else None)
                reply_header = smb2.header(command, mid, response=True, status=status, credits=max(1, h["credits"]),
                                           tree_id=tree_id, session_id=session_id, signature=signature,
                                           credit_charge=0 if command == smb2.NEGOTIATE else 1)
                writer.write(smb2.frame(reply_header + reply))
                await writer.drain()
        finally:
            writer.close()


@register
class SmbLateral(Actor):
    """One source host reaching the administrative shares of many workstations with one domain account.

    Params: ``dc`` (host running ``ad.dc``), ``account`` (sAMAccountName; one is drawn per seed when
    omitted), ``targets`` (candidate workstation hosts), ``count`` (how many to reach: an integer or
    ``all``), ``start`` / ``spread`` (fraction of the capture the access begins at and the window it
    spreads over), ``deny_target`` (true: one target refuses ADMIN$ access)."""

    type = "smb.lateral"

    def plan(self) -> None:
        plan, rng = self.plan_, self.rng
        if len(self.hosts) != 1:
            raise ScenarioError(f"{self.type} '{self.id}' runs on exactly one source host")
        source = self.hosts[0]
        dc_host = plan.topology.select(self.param("dc"))[0]
        self.dc = next((a for a in plan.actors if isinstance(a, DomainController)
                        and a.hosts[0].id == dc_host.id), None)
        if self.dc is None:
            raise ScenarioError(f"{self.type} '{self.id}': '{dc_host.id}' runs no ad.dc")
        d = self.dc.directory
        account = str(self.param("account") or rng.choice(ADMIN_ACCOUNTS))

        pool = [h for h in sorted(plan.topology.select(self.param("targets")), key=lambda h: h.id)
                if h.id != source.id]
        if not pool:
            raise ScenarioError(f"{self.type} '{self.id}': no target workstations")
        count = self.param("count", "all")
        n = len(pool) if count in ("all", None) else max(1, min(int(count), len(pool)))
        targets = rng.sample(pool, len(pool))[:n]        # deterministic visit order
        # The workstation configured to refuse access (its smb.server denies ADMIN$ / C$) must be one
        # of the ones reached, so the access-denied answer is in the capture.
        deny_cfg = self.param("deny_target")
        denied_host = deny_cfg if (deny_cfg and deny_cfg in {h.id for h in pool}) else None
        if denied_host and denied_host not in {h.id for h in targets}:
            targets = targets[:max(0, n - 1)] + [plan.topology.by_id[denied_host]]

        start_lo, start_hi = self.span(self.param("start", [0.1, 0.3]))
        begin = plan.duration * rng.uniform(start_lo, start_hi)
        spread = max(0.0, min(1.0, float(self.param("spread", 0.05))))

        # One Kerberos AS exchange exposes the account: no-preauth probe, pre-auth over UDP
        # (KRB_ERR_RESPONSE_TOO_BIG), pre-auth over TCP (the AS-REP with the TGT).
        t = begin
        as_started = round(t, 6)
        for preauth, tcp, gap in ((False, False, STEP_UDP), (True, False, STEP_RETRY), (True, True, STEP_TCP)):
            plan.add(t, self.id, source.id, "smb.as", account=account, preauth=preauth, tcp=tcp, started=as_started)
            t += rng.uniform(*gap)
        tgt_time = round(t, 6)

        enum_begin = t
        window = min(spread * plan.duration, max(0.0, plan.duration - enum_begin - 2.0))
        per = window / max(1, len(targets))

        first_enum = None
        target_facts = []
        for index, target in enumerate(targets):
            base = enum_begin + per * index + (rng.uniform(0.0, per * 0.3) if per else 0.0)
            tgs = plan.add(base, self.id, source.id, "smb.tgs", account=account, target=target.id, tgt=tgt_time)
            setup = plan.add(base + rng.uniform(*STEP_TCP), self.id, source.id, "smb.setup", account=account,
                             target=target.id, svc=round(tgs.t, 6))
            enum = plan.add(setup.t + rng.uniform(*STEP_SMB), self.id, source.id, "smb.enum", account=account,
                            target=target.id, denied=target.id == denied_host)
            first_enum = first_enum or enum
            target_facts.append({"host": host_ref(target.id), "tree_connect": action_ref(enum),
                                 "denied": target.id == denied_host})

        plan.facts[self.id] = {
            "source": host_ref(source.id),
            "dc": host_ref(dc_host.id),
            "account": account,
            "realm": d.realm,
            "share": "ADMIN$",
            "shares": list(ADMIN_SHARES),
            "target_count": len(targets),
            "targets": [host_ref(target.id) for target in targets],
            "first_target": host_ref(targets[0].id),
            "first_tree_connect": action_ref(first_enum) if first_enum else None,
            "denied_target": host_ref(denied_host) if denied_host else None,
            "denied_text": (plan.topology.by_id[denied_host].name if denied_host else "none"),
            "per_target": target_facts,
        }
        if first_enum:
            plan.event(first_enum, self.id, f"{account} reaches the admin shares of {len(targets)} workstations",
                       ["T1021.002", "T1078.002"], account=account, target_count=len(targets),
                       source=host_ref(source.id))

    def execute(self, action, rt) -> None:
        a = action.args
        d = self.dc.directory
        source = rt.plan.topology.by_id[action.host]
        member = _Member(rt, d, source)
        op = action.op
        account = a["account"]
        if op == "smb.as":
            member.as_request(account, a["preauth"], a["tcp"], rt.plan.start_epoch + a["started"])
            return
        target = rt.plan.topology.by_id[a["target"]]
        spn = d.spn("cifs", target)
        key = (self.id, a["target"])
        if op == "smb.tgs":
            tgt = d.ticket(account, d.spn("krbtgt"), a["tgt"])
            member.tgs_exchange(account, tgt, spn)
        elif op == "smb.setup":
            conn = rt.clients[key] = _SmbConnection(source.loopback, target.loopback,
                                                    f"{self.id}\x1f{target.id}\x1f{action.t}")
            guid = label_bytes(f"smb-client-guid\x1f{source.id}", 16)
            salt = label_bytes(f"smb-salt\x1f{source.id}\x1f{target.id}\x1f{action.t}", 32)
            conn.call(smb2.NEGOTIATE, smb2.negotiate_request(guid, salt, f"{target.name}.{d.domain}".lower()))
            ticket = d.ticket(account, spn, a["svc"])
            token, issued = member.gss_token(account, ticket)
            header, _ = conn.call(smb2.SESSION_SETUP, smb2.session_setup_request(token), credits=33)
            conn.session = {"id": header["session_id"], "label": issued.label}
        elif op == "smb.enum":
            conn = rt.clients.pop(key)
            self._enum(conn, target, d, a["denied"])
            conn.close()
        else:
            raise ValueError(f"unknown operation {op}")

    def _enum(self, conn, target, d, denied: bool) -> None:
        session = conn.session
        fqdn = f"{target.name}.{d.domain}".lower()
        trees = []
        admin_denied = False
        for share in ADMIN_SHARES:
            header, _ = conn.call(smb2.TREE_CONNECT, smb2.tree_connect_request(f"\\\\{fqdn}\\{share}"), session)
            if header["status"] != smb2.STATUS_SUCCESS:
                if share == "ADMIN$":
                    admin_denied = True
                continue
            tree_id = header["tree_id"]
            trees.append(tree_id)
            if share != "IPC$":
                self._list(conn, session, tree_id)
        if admin_denied != denied:
            raise RuntimeError(f"ADMIN$ on {target.id}: expected {'deny' if denied else 'allow'}, got the opposite")
        for tree_id in trees:
            conn.call(smb2.TREE_DISCONNECT, smb2.empty(), session, tree_id)
        conn.call(smb2.LOGOFF, smb2.empty(), session)

    def _list(self, conn, session, tree_id: int) -> None:
        _, body = conn.call(smb2.CREATE, smb2.create_dir_request(""), session, tree_id)
        file_id = body[64:80]
        conn.call(smb2.QUERY_DIRECTORY, smb2.query_directory_request(file_id), session, tree_id)
        conn.call(smb2.CLOSE, smb2.close_request(file_id), session, tree_id)

    def close(self, rt) -> None:
        for key in [k for k in rt.clients if k[0] == self.id]:
            rt.clients.pop(key).close()
