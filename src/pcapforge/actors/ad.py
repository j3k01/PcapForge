"""Active Directory background of Windows domain members: a domain controller (KDC, CLDAP, LDAP and
the SYSVOL share over SMB 2/3) and its members' Group Policy refreshes and interactive logons.

The directory is synthetic: names, GUIDs, SIDs and keys are derived from the scenario seed, nothing
comes from a real domain, and no real cipher runs (``kerberos`` explains the opaque ciphertext). The
simulators share the ``Directory``: the DC finds the client and session key of a ticket by its
ciphertext, the way a real KDC / service would by decrypting it.
"""

from __future__ import annotations

import asyncio
import hashlib
import socket
import struct
import uuid
from dataclasses import dataclass

from pcapforge import ports
from pcapforge.actors import der, kerberos as krb, ldap, register, smb2
from pcapforge.actors.base import Actor
from pcapforge.plan import action_ref, host_ref
from pcapforge.rng import label_bytes
from pcapforge.scenario import ScenarioError

DDP_GUID = "{31B2F340-016D-11D2-945F-00C04FB984F9}"   # Default Domain Policy (fixed in every domain)
DDP_MACHINE_EXT = ("[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{53D6AB1B-2488-11D1-A28C-00C04FB94F17}]"
                   "[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]"
                   "[{B1BE8D72-6EAC-11D2-A4EA-00C04F79F83A}{53D6AB1B-2488-11D1-A28C-00C04FB94F17}]")
OT_MACHINE_EXT = ("[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72-3407-48AE-BA88-E8213C6761F1}]"
                  "[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]")
COMPUTER_OU, USER_OU = "OT Systems", "OT Users"
ROOT_DSE_ATTRIBUTES = ["dnsHostName", "defaultNamingContext", "rootDomainNamingContext", "configurationNamingContext",
                       "schemaNamingContext", "dsServiceName", "supportedSASLMechanisms", "supportedLDAPVersion",
                       "supportedCapabilities", "domainControllerFunctionality"]
GPO_ATTRIBUTES = ["displayName", "gPCFileSysPath", "versionNumber", "flags", "gPCFunctionalityVersion",
                  "gPCMachineExtensionNames", "gPCUserExtensionNames"]
SUPPORTED_CAPABILITIES = ["1.2.840.113556.1.4.800", "1.2.840.113556.1.4.1670", "1.2.840.113556.1.4.1791",
                          "1.2.840.113556.1.4.1935", "1.2.840.113556.1.4.2080", "1.2.840.113556.1.4.2237"]
FUNCTIONAL_LEVEL = "7"                     # Windows Server 2016
KRBTGT_KVNO = 2
GROUPS = {"computer": 2, "user": 5}        # group RIDs in the PAC
GP_INTERVAL, GP_OFFSET = 5400.0, 1800.0    # background refresh: 90 min + up to 30 min random offset
KEEP_CONN = 600.0                          # LanmanWorkstation KeepConn: an idle SMB connection is dropped
SERVICES = ("ldap", "cifs")                # tickets a Group Policy refresh uses
SOCKET_TIMEOUT = 5.0
SASL_HEADER = 4


# --- directory ------------------------------------------------------------------------

@dataclass(frozen=True)
class Gpo:
    guid: str
    name: str
    version: int                # user version << 16 | machine version
    linked: str                 # DN of the container it is linked to
    machine_ext: str | None
    user_ext: str | None
    created: float
    changed: float

    def ini(self, gpmc: bool) -> bytes:
        """gpt.ini in SYSVOL (GPMC adds the display name it was created with)."""
        text = f"[General]\r\nVersion={self.version}\r\n"
        if gpmc:
            text += "displayName=New Group Policy Object\r\n"
        return text.encode("ascii")


@dataclass(frozen=True)
class Account:
    sam: str                    # sAMAccountName: "HMI-STW-01$" or "a.nowak"
    kind: str                   # "computer" | "user"
    dn: str
    chain: tuple[str, ...]      # containers Group Policy reads gPLink from: OU, domain, site
    gpos: tuple[Gpo, ...]       # GPOs that apply (Group Policy reads their gpt.ini)


@dataclass(frozen=True)
class Issued:
    client: str
    service: tuple[str, ...]
    session: bytes              # session key the KDC put in the ticket
    label: str


class Directory:
    """Synthetic AD domain of the site, served by one DC."""

    def __init__(self, topology, dc, rng, start_epoch: float) -> None:
        self.topology = topology
        self.domain = topology.domain
        self.realm = self.domain.upper()
        self.netbios = self.domain.split(".")[0].upper()[:15]
        self.dc = dc
        self.dc_fqdn = f"{dc.name}.{self.domain}".lower()
        self.dc_sam = f"{dc.name.upper()[:15]}$"
        self.base = ldap.domain_dn(self.domain)
        self.config = f"CN=Configuration,{self.base}"
        self.site_dn = f"CN={ldap.DEFAULT_SITE},CN=Sites,{self.config}"
        self.secret = rng.getrandbits(128).to_bytes(16, "big")
        self.domain_guid = uuid.UUID(int=rng.getrandbits(128), version=4)
        self.server_guid = uuid.UUID(int=rng.getrandbits(128), version=4)
        self.dc_kvno = rng.randint(2, 40)
        built = start_epoch - rng.uniform(1.5, 6.0) * 365 * 86400
        ou_dn = f"OU={COMPUTER_OU},{self.base}"
        ot_guid = "{" + str(uuid.UUID(int=rng.getrandbits(128), version=4)).upper() + "}"
        self.gpos = (
            Gpo(DDP_GUID, "Default Domain Policy", rng.randint(0, 3) << 16 | rng.randint(3, 30), self.base,
                DDP_MACHINE_EXT, None, built, built + rng.uniform(0.1, 0.9) * (start_epoch - built)),
            Gpo(ot_guid, f"{topology.site_code.upper()} OT Workstation Baseline", rng.randint(2, 40), ou_dn,
                OT_MACHINE_EXT, None, built + 86400 * rng.uniform(1, 60),
                start_epoch - rng.uniform(5, 200) * 86400),
        )
        self.issued: dict[bytes, Issued] = {}

    # accounts and keys
    def account(self, sam: str) -> Account:
        if sam.endswith("$"):
            ou = f"OU={COMPUTER_OU},{self.base}"
            return Account(sam, "computer", f"CN={sam[:-1]},{ou}", (ou, self.base, self.site_dn), self.gpos)
        ou = f"OU={USER_OU},{self.base}"
        return Account(sam, "user", f"CN={sam},{ou}", (ou, self.base, self.site_dn),
                       tuple(g for g in self.gpos if g.linked == self.base))

    def key(self, sam: str) -> bytes:
        return hashlib.sha256(self.secret + b"key\x1f" + sam.encode()).digest()

    def salt(self, sam: str) -> str:
        if sam.endswith("$"):
            return f"{self.realm}host{sam[:-1].lower()}.{self.domain}"
        return f"{self.realm}{sam}"

    def spn(self, service: str, host=None) -> tuple[str, ...]:
        if service == "krbtgt":
            return ("krbtgt", self.realm)
        if service == "ldap":
            return ("ldap", self.dc_fqdn, self.domain)
        if service == "cifs":
            return ("cifs", self.dc_fqdn)
        return (service, f"{host.name}.{self.domain}".lower())

    def _owner(self, spn: tuple[str, ...]) -> tuple[str, int]:
        """(account, kvno) whose key encrypts tickets for ``spn``."""
        if spn[0] == "krbtgt":
            return "krbtgt", KRBTGT_KVNO
        fqdn = spn[1]
        host = next(h for h in self.topology.hosts if f"{h.name}.{self.domain}".lower() == fqdn)
        return f"{host.name.upper()[:15]}$", (self.dc_kvno if host.id == self.dc.id else 2)

    def ticket(self, client: str, spn: tuple[str, ...], issued: float) -> bytes:
        """Ticket for ``client`` to ``spn`` issued ``issued`` seconds into the capture (also tickets
        from before it, which the member still holds); the same bytes on both sides."""
        label = f"{self.realm}\x1f{client}\x1f{'/'.join(spn)}\x1f{issued:.6f}"
        account = self.account(client)
        cname = krb.principal(krb.NT_PRINCIPAL, client)
        pac = krb.pac_size(client, f"{client}@{self.domain}", self.domain, GROUPS[account.kind])
        owner, kvno = self._owner(spn)
        cipher = krb.seal("ticket\x1f" + label, krb.enc_ticket_part_size(self.realm, cname, pac), self.key(owner))
        session = hashlib.sha256(self.secret + b"session\x1f" + label.encode()).digest()
        self.issued[cipher] = Issued(client, spn, session, label)
        return krb.ticket(self.realm, krb.principal(krb.NT_SRV_INST, *spn), kvno, cipher)

    def holder(self, ticket_cipher: bytes, spn_kind: str) -> Issued | None:
        """Client of a ticket the service ``spn_kind`` can decrypt, else None."""
        issued = self.issued.get(ticket_cipher)
        if issued is None or issued.service[0] != spn_kind:
            return None
        owner, _ = self._owner(issued.service)
        return issued if krb.sealed_by(ticket_cipher, self.key(owner)) else None

    # LDAP content
    def root_dse(self, message_id: int) -> tuple[bytes, bytes]:
        request = ldap.search(message_id, "", ldap.SCOPE_BASE, ldap.present("objectClass"), ROOT_DSE_ATTRIBUTES)
        values = {
            "dnsHostName": [self.dc_fqdn], "defaultNamingContext": [self.base], "rootDomainNamingContext": [self.base],
            "configurationNamingContext": [self.config], "schemaNamingContext": [f"CN=Schema,{self.config}"],
            "dsServiceName": [f"CN=NTDS Settings,CN={self.dc.name.upper()},CN=Servers,{self.site_dn}"],
            "supportedSASLMechanisms": ["GSSAPI", "GSS-SPNEGO", "EXTERNAL", "DIGEST-MD5"],
            "supportedLDAPVersion": ["3", "2"], "supportedCapabilities": SUPPORTED_CAPABILITIES,
            "domainControllerFunctionality": [FUNCTIONAL_LEVEL]}
        entry = ldap.search_entry(message_id, "", [(a, [v.encode() for v in values[a]]) for a in ROOT_DSE_ATTRIBUTES])
        return request, entry + ldap.search_done(message_id)

    def policy_searches(self, account: Account, first_id: int) -> list[tuple[bytes, bytes]]:
        """(request, reply) LDAP messages of a Group Policy refresh: the account's DN, the gPLink of every
        container above it, then the GPO objects that apply."""
        out = []
        mid = first_id
        request = ldap.search(mid, self.base, ldap.SCOPE_SUBTREE, ldap.equality("sAMAccountName", account.sam.encode()),
                              ["distinguishedName"])
        out.append((request, ldap.search_entry(mid, account.dn, [("distinguishedName", [account.dn.encode()])])
                    + ldap.search_done(mid)))
        for container in account.chain:
            mid += 1
            request = ldap.search(mid, container, ldap.SCOPE_BASE, ldap.present("objectClass"), ["gPLink", "gPOptions"])
            links = "".join(f"[LDAP://cn={g.guid},cn=policies,cn=system,{self.base};0]"
                            for g in self.gpos if g.linked == container)
            attrs = [("gPLink", [links.encode()])] if links else []
            out.append((request, ldap.search_entry(mid, container, attrs) + ldap.search_done(mid)))
        mid += 1
        policies = f"CN=Policies,CN=System,{self.base}"
        request = ldap.search(mid, policies, ldap.SCOPE_ONE,
                              ldap.or_filter(*(ldap.equality("cn", g.guid.encode()) for g in account.gpos)),
                              GPO_ATTRIBUTES)
        reply = b""
        for gpo in account.gpos:
            attrs = [("displayName", [gpo.name.encode()]),
                     ("gPCFileSysPath", [f"\\\\{self.domain}\\SysVol\\{self.domain}\\Policies\\{gpo.guid}".encode()]),
                     ("versionNumber", [str(gpo.version).encode()]), ("flags", [b"0"]),
                     ("gPCFunctionalityVersion", [b"2"])]
            if gpo.machine_ext:
                attrs.append(("gPCMachineExtensionNames", [gpo.machine_ext.encode()]))
            if gpo.user_ext:
                attrs.append(("gPCUserExtensionNames", [gpo.user_ext.encode()]))
            reply += ldap.search_entry(mid, f"CN={gpo.guid},{policies}", attrs)
        out.append((request, reply + ldap.search_done(mid)))
        return out

    def gpt_ini(self, name: str) -> tuple[Gpo, bytes] | None:
        for gpo in self.gpos:
            if name.lower() == self.gpt_path(gpo).lower():
                return gpo, gpo.ini(gpmc=gpo.guid != DDP_GUID)
        return None

    def gpt_path(self, gpo: Gpo) -> str:
        return f"{self.domain}\\Policies\\{gpo.guid}\\gpt.ini"


def _int31(*parts: object) -> int:
    return int.from_bytes(label_bytes("\x1f".join(str(p) for p in parts), 4), "big") & 0x7FFFFFFF


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise RuntimeError("connection closed by the domain controller")
        data += chunk
    return data


def _tcp(source: str, target: str, port: int) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.settimeout(SOCKET_TIMEOUT)
        sock.bind((source, 0))
        sock.connect((target, port))
    except BaseException:
        sock.close()
        raise
    return sock


async def _read_exact(reader: asyncio.StreamReader, size: int) -> bytes | None:
    try:
        return await reader.readexactly(size)
    except (asyncio.IncompleteReadError, ConnectionError):
        return None


# --- domain controller ------------------------------------------------------------------

class _Datagrams(asyncio.DatagramProtocol):
    def __init__(self, answer) -> None:
        self.answer = answer

    def connection_made(self, transport) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, addr) -> None:
        reply = self.answer(data)
        if reply is not None:
            self.transport.sendto(reply, addr)


class _Stopper:
    """Adapter for ``Runtime.servers`` (which awaits ``shutdown()``)."""

    def __init__(self, server) -> None:
        self.server = server

    async def shutdown(self) -> None:
        self.server.close()


@register
class DomainController(Actor):
    """Active Directory DC: KDC (UDP / TCP 88), CLDAP DC locator (UDP 389), LDAP with Kerberos
    (GSS-SPNEGO, sealed) on TCP 389 and SYSVOL over SMB 3.1.1 (TCP 445)."""

    type = "ad.dc"
    is_server = True

    def plan(self) -> None:
        if len(self.hosts) != 1:
            raise ScenarioError(f"{self.type} '{self.id}' runs on exactly one host")
        dc = self.hosts[0]
        self.directory = Directory(self.plan_.topology, dc, self.rng.child("directory"), self.plan_.start_epoch)
        d = self.directory
        self.plan_.facts[self.id] = {"host": host_ref(dc.id), "domain": d.domain, "realm": d.realm,
                                     "netbios_domain": d.netbios, "gpos": [g.name for g in d.gpos]}

    async def serve(self, rt) -> None:
        loop = asyncio.get_running_loop()
        address = self.hosts[0].loopback
        self.rt = rt
        for answer, port in ((lambda data: self.kdc(data, tcp=False), ports.KERBEROS), (self.cldap, ports.LDAP)):
            transport, _ = await loop.create_datagram_endpoint(lambda answer=answer: _Datagrams(answer),
                                                               local_addr=(address, port))
            rt.transports.append(transport)
        for handler, port in ((self._kdc_stream, ports.KERBEROS), (self._ldap_stream, ports.LDAP),
                              (self._smb_stream, ports.SMB)):
            server = await asyncio.start_server(handler, address, port)
            rt.servers.append(_Stopper(server))

    def _now(self) -> float:
        return self.plan_.start_epoch + self.rt.clock.t

    # KDC
    def kdc(self, message: bytes, tcp: bool) -> bytes:
        d = self.directory
        req = krb.parse_kdc_req(message)
        now = self._now()
        sname = krb.principal(krb.NT_SRV_INST, *req["sname"][1])
        if req["msg_type"] == krb.AS_REQ:
            client = req["cname"][1][0]
            krbtgt = krb.principal(krb.NT_SRV_INST, "krbtgt", d.realm)
            timestamp = req["padata"].get(krb.PA_ENC_TIMESTAMP)
            if timestamp is None:
                hints = der.seq(krb.padata(krb.PA_ETYPE_INFO2, krb.etype_info2([(krb.AES256, d.salt(client))])),
                                krb.padata(krb.PA_ENC_TIMESTAMP, b""), krb.padata(krb.PA_PK_AS_REQ, b""),
                                krb.padata(krb.PA_PK_AS_REP_OLD, b""))
                return krb.krb_error(krb.KDC_ERR_PREAUTH_REQUIRED, now, _int31(now, client) % 1000000, d.realm,
                                     krbtgt, hints)
            if not krb.sealed_by(krb.enc_timestamp_cipher(timestamp), d.key(client)):
                return krb.krb_error(krb.KDC_ERR_PREAUTH_FAILED, now, 0, d.realm, krbtgt)
            tkt = d.ticket(client, d.spn("krbtgt"), self.rt.clock.t)
            enc = krb.seal(f"as-rep\x1f{client}\x1f{now}", krb.enc_kdc_rep_part_size(False, req["nonce"], d.realm,
                                                                                   krbtgt), d.key(client))
            pa = [krb.padata(krb.PA_ETYPE_INFO2, krb.etype_info2([(krb.AES256, d.salt(client))]))]
            reply = krb.kdc_rep(krb.AS_REP, pa, d.realm, krb.principal(krb.NT_PRINCIPAL, client), tkt,
                                krb.encrypted(krb.AES256, enc, 2))
        else:
            tgt_cipher, authenticator = krb.ap_req_parts(req["padata"][krb.PA_TGS_REQ])
            holder = d.holder(tgt_cipher, "krbtgt")
            if holder is None or not krb.sealed_by(authenticator, holder.session):
                raise RuntimeError("TGS-REQ with a ticket the KDC did not issue")
            spn = tuple(req["sname"][1])
            tkt = d.ticket(holder.client, spn, self.rt.clock.t)
            enc = krb.seal(f"tgs-rep\x1f{holder.client}\x1f{'/'.join(spn)}\x1f{now}",
                           krb.enc_kdc_rep_part_size(True, req["nonce"], d.realm, sname), holder.session)
            reply = krb.kdc_rep(krb.TGS_REP, None, d.realm, krb.principal(krb.NT_PRINCIPAL, holder.client), tkt,
                                krb.encrypted(krb.AES256, enc))
        if not tcp and len(reply) > krb.UDP_LIMIT:
            return krb.krb_error(krb.KRB_ERR_RESPONSE_TOO_BIG, now, _int31(now, "big") % 1000000, d.realm, sname)
        return reply

    async def _kdc_stream(self, reader, writer) -> None:
        try:
            while (head := await _read_exact(reader, 4)) is not None:
                message = await _read_exact(reader, struct.unpack("!I", head)[0])
                if message is None:
                    break
                writer.write(krb.tcp_frame(self.kdc(message, tcp=True)))
                await writer.drain()
        finally:
            writer.close()

    # CLDAP
    def cldap(self, data: bytes) -> bytes | None:
        d = self.directory
        message_id, op, _ = ldap.parse(data)
        if op != ldap.SEARCH_REQUEST:
            return None
        blob = ldap.netlogon_response(d.domain_guid.bytes_le, d.domain, d.domain, d.dc_fqdn, d.netbios,
                                      d.dc.name.upper()[:15])
        return ldap.cldap_reply(message_id, blob)

    # GSS-API (Kerberos in SPNEGO) acceptor shared by LDAP and SMB
    def accept(self, token: bytes, service: str) -> tuple[Issued, bytes]:
        """(ticket holder, SPNEGO accept token with the AP-REP) for the client's first SPNEGO token."""
        tkt_cipher, authenticator = krb.ap_req_parts(krb.spnego_ap_req(token))
        holder = self.directory.holder(tkt_cipher, service)
        if holder is None or not krb.sealed_by(authenticator, holder.session):
            raise RuntimeError(f"{service} AP-REQ with a ticket the DC cannot decrypt")
        cipher = krb.seal(f"ap-rep\x1f{holder.label}\x1f{self.rt.clock.t}", krb.ap_rep_part_size(), holder.session)
        return holder, krb.neg_token_resp(krb.krb5_token(krb.TOK_AP_REP, krb.ap_rep(cipher)))

    # LDAP
    async def _ldap_stream(self, reader, writer) -> None:
        d = self.directory
        try:
            buffered = b""
            script: list[tuple[bytes, bytes]] | None = None
            label = ""
            while script is None:
                while (size := ldap.message_size(buffered)) is None or len(buffered) < size:
                    chunk = await reader.read(65536)
                    if not chunk:
                        return
                    buffered += chunk
                message, buffered = buffered[:size], buffered[size:]
                message_id, op, content = ldap.parse(message)
                if op == ldap.SEARCH_REQUEST:
                    writer.write(d.root_dse(message_id)[1])
                elif op == ldap.BIND_REQUEST:
                    sasl = der.children(der.children(content)[2][1])
                    holder, token = self.accept(sasl[1][1], "ldap")
                    writer.write(ldap.bind_response(message_id, token))
                    script = d.policy_searches(d.account(holder.client), message_id + 1)
                    label = holder.label
                await writer.drain()
            index = 0
            seq = _int31(label, "acceptor-seq")
            while (head := await _read_exact(reader, SASL_HEADER)) is not None:
                if await _read_exact(reader, struct.unpack("!I", head)[0]) is None:
                    break
                if index >= len(script):            # the sealed unbind: close the connection
                    break
                reply = script[index][1]
                token = krb.wrap_token(f"ldap\x1f{label}\x1f{index}\x1fs", len(reply), True, seq)
                writer.write(struct.pack("!I", len(token)) + token)
                await writer.drain()
                index += 1
                seq += 1
        finally:
            writer.close()

    # SMB
    async def _smb_stream(self, reader, writer) -> None:
        d = self.directory
        sessions: dict[int, str] = {}           # session id -> ticket label (signing)
        trees: dict[int, str] = {}
        files: dict[bytes, bytes] = {}
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
                if command == smb2.NEGOTIATE:
                    salt = label_bytes(f"smb-salt\x1f{self.rt.clock.t}\x1f{mid}", 32)
                    reply = smb2.negotiate_response(d.server_guid.bytes_le, self._now(), krb.neg_token_init2(), salt)
                elif command == smb2.SESSION_SETUP:
                    holder, token = self.accept(smb2.security_buffer(body), "cifs")
                    session_id = int.from_bytes(label_bytes(f"smb-session\x1f{holder.label}", 8), "little") | 1
                    sessions[session_id] = label = holder.label
                    reply = smb2.session_setup_response(token)
                elif command == smb2.TREE_CONNECT:
                    path = smb2.tree_connect_path(body)
                    tree_id = next_tree
                    next_tree += 4
                    trees[tree_id] = path.rsplit("\\", 1)[1].upper()
                    if trees[tree_id] == "IPC$":
                        reply = smb2.tree_connect_response(smb2.SHARE_PIPE, 0x30, 0, 0x001F01FF)
                    else:
                        reply = smb2.tree_connect_response(smb2.SHARE_DISK, 0x00000800, 0x00000008, 0x001200A9)
                elif command == smb2.IOCTL:
                    path = body[58:].decode("utf-16-le").split("\x00", 1)[0]
                    reply = smb2.dfs_referral_response(path, [f"\\{d.dc_fqdn}\\SysVol"])
                elif command == smb2.CREATE:
                    found = d.gpt_ini(smb2.create_name(body))
                    if found is None:
                        raise RuntimeError(f"SMB CREATE of an unknown file {smb2.create_name(body)!r}")
                    gpo, data = found
                    file_id = label_bytes(f"smb-file\x1f{label}\x1f{mid}", 16)
                    files[file_id] = data
                    disk_id = label_bytes(f"smb-disk\x1f{gpo.guid}", 8) + d.server_guid.bytes_le[:8]
                    reply = smb2.create_response(file_id, (gpo.created, gpo.changed, gpo.changed, gpo.changed),
                                                 len(data), 0x001200A9, disk_id)
                elif command == smb2.READ:
                    reply = smb2.read_response(files[smb2.file_id_of(body, smb2.READ)])
                elif command == smb2.CLOSE:
                    files.pop(smb2.file_id_of(body, smb2.CLOSE), None)
                    reply = smb2.close_response()
                elif command == smb2.TREE_DISCONNECT:
                    trees.pop(tree_id, None)
                    reply = smb2.empty()
                elif command == smb2.LOGOFF:
                    sessions.pop(session_id, None)
                    reply = smb2.empty()
                else:
                    raise RuntimeError(f"unexpected SMB2 command {command}")
                signature = (label_bytes(f"smb-sig\x1f{label}\x1f{mid}\x1fs", 16)
                             if label is not None and command != smb2.NEGOTIATE else None)
                header = smb2.header(command, mid, response=True, credits=max(1, h["credits"]), tree_id=tree_id,
                                     session_id=session_id, signature=signature,
                                     credit_charge=0 if command == smb2.NEGOTIATE else 1)
                writer.write(smb2.frame(header + reply))
                await writer.drain()
        finally:
            writer.close()


# --- domain members ---------------------------------------------------------------------

class _SmbConnection:
    """A member's SMB 3.1.1 connection to the DC's SYSVOL, with one session per account."""

    def __init__(self, source: str, dc: str, label: str) -> None:
        self.sock = _tcp(source, dc, ports.SMB)
        self.label = label
        self.message_id = 0
        self.sessions: dict[str, dict] = {}     # account -> {id, label, ipc, sysvol}

    def call(self, command: int, body: bytes, session: dict | None = None, tree_id: int = 0,
             credits: int = 1) -> tuple[dict, bytes]:
        signature = None
        if session is not None and command != smb2.SESSION_SETUP:
            signature = label_bytes(f"smb-sig\x1f{session['label']}\x1f{self.message_id}\x1fc", 16)
        header = smb2.header(command, self.message_id, credits=credits, tree_id=tree_id,
                             session_id=session["id"] if session else 0, signature=signature,
                             credit_charge=0 if command == smb2.NEGOTIATE else 1)
        self.message_id += 1
        self.sock.sendall(smb2.frame(header + body))
        size = struct.unpack("!I", _recv_exact(self.sock, 4))[0]
        reply = _recv_exact(self.sock, size)
        return smb2.parse_header(reply), reply[smb2.HEADER_SIZE:]

    def close(self) -> None:
        self.sock.close()


class _Member:
    """Client side of one host: Kerberos, LDAP and SMB exchanges with the DC."""

    def __init__(self, rt, directory: Directory, host) -> None:
        self.rt = rt
        self.d = directory
        self.host = host
        self.source = host.loopback
        self.dc = directory.dc.loopback

    def now(self) -> float:
        return self.rt.plan.start_epoch + self.rt.clock.t

    # Kerberos
    def _kdc(self, message: bytes, tcp: bool) -> bytes:
        """One KDC exchange over UDP or over a TCP connection of its own (Windows sends a request over
        UDP while it fits MaxPacketSize and retries over TCP after KRB_ERR_RESPONSE_TOO_BIG)."""
        if not tcp:
            if len(message) > krb.UDP_LIMIT:
                raise RuntimeError(f"a {len(message)}-byte Kerberos request goes over TCP")
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sock.settimeout(SOCKET_TIMEOUT)
                sock.bind((self.source, 0))
                sock.sendto(message, (self.dc, ports.KERBEROS))
                return sock.recv(65535)
            finally:
                sock.close()
        sock = _tcp(self.source, self.dc, ports.KERBEROS)
        try:
            sock.sendall(krb.tcp_frame(message))
            size = struct.unpack("!I", _recv_exact(sock, 4))[0]
            return _recv_exact(sock, size)
        finally:
            sock.close()

    def as_request(self, client: str, preauth: bool, tcp: bool, started: float) -> None:
        """One request of the AS exchange that started at epoch ``started``: without pre-authentication
        (KDC_ERR_PREAUTH_REQUIRED), with the encrypted timestamp over UDP (KRB_ERR_RESPONSE_TOO_BIG: the
        AS-REP carries a PAC) or the same request over TCP (AS-REP with the TGT)."""
        d = self.d
        cname = krb.principal(krb.NT_PRINCIPAL, client)
        body = krb.req_body(krb.KDC_OPT_AS, d.realm, krb.principal(krb.NT_SRV_INST, *d.spn("krbtgt")),
                            _int31(client, "as", started, preauth), cname=cname,
                            addresses=krb.netbios_address(self.host.name))
        pa = [krb.padata(krb.PA_PAC_REQUEST, der.seq(der.ctx(0, der.boolean(True))))]
        if preauth:
            stamp = krb.seal(f"pa-ts\x1f{client}\x1f{started}", krb.enc_timestamp_size(), d.key(client))
            pa.insert(0, krb.padata(krb.PA_ENC_TIMESTAMP, krb.encrypted(krb.AES256, stamp)))
        reply = self._kdc(krb.kdc_req(krb.AS_REQ, pa, body), tcp)
        expected = (krb.AS_REP if tcp else krb.KRB_ERR_RESPONSE_TOO_BIG) if preauth else krb.KDC_ERR_PREAUTH_REQUIRED
        if expected == krb.AS_REP:
            ok = der.read(reply)[0] == 0x60 | krb.AS_REP
        else:
            ok = _is_error(reply, expected)
        if not ok:
            raise RuntimeError(f"AS exchange of {client}: unexpected KDC reply (expected {expected})")

    def tgs_exchange(self, client: str, tgt: bytes, spn: tuple[str, ...]) -> bytes:
        d = self.d
        now = self.now()
        session = d.issued[krb.ticket_cipher(tgt)].session
        authenticator = krb.seal(f"tgs-auth\x1f{client}\x1f{'/'.join(spn)}\x1f{now}",
                                 krb.authenticator_size(d.realm, krb.principal(krb.NT_PRINCIPAL, client), False),
                                 session)
        pa = [krb.padata(krb.PA_TGS_REQ, krb.ap_req(0, tgt, authenticator)),
              krb.padata(krb.PA_PAC_OPTIONS, der.seq(der.ctx(0, der.flags32(krb.PAC_OPT_BRANCH_AWARE))))]
        body = krb.req_body(krb.KDC_OPT_TGS, d.realm, krb.principal(krb.NT_SRV_INST, *spn),
                            _int31(client, "tgs", spn, now))
        reply = self._kdc(krb.kdc_req(krb.TGS_REQ, pa, body), tcp=True)
        if der.read(reply)[0] != 0x60 | krb.TGS_REP:
            raise RuntimeError(f"TGS exchange for {'/'.join(spn)} failed")
        return der.fields(der.read(der.read(reply)[1])[1])[5]

    def gss_token(self, client: str, ticket: bytes) -> tuple[bytes, Issued]:
        d = self.d
        issued = d.issued[krb.ticket_cipher(ticket)]
        authenticator = krb.seal(f"gss-auth\x1f{issued.label}\x1f{self.now()}",
                                 krb.authenticator_size(d.realm, krb.principal(krb.NT_PRINCIPAL, client), True),
                                 issued.session)
        ap = krb.ap_req(krb.AP_OPT_MUTUAL, ticket, authenticator)
        return krb.neg_token_init(krb.krb5_token(krb.TOK_AP_REQ, ap)), issued

    # DC locator
    def cldap_ping(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.settimeout(SOCKET_TIMEOUT)
            sock.bind((self.source, 0))
            message_id = _int31(self.host.id, "cldap", self.now()) % 0xFFFF + 1
            sock.sendto(ldap.cldap_ping(message_id, self.d.domain, self.host.name.upper()[:15]),
                        (self.dc, ports.LDAP))
            sock.recv(65535)
        finally:
            sock.close()

    # LDAP
    def ldap_session(self, account: Account, ticket: bytes) -> None:
        d = self.d
        sock = _tcp(self.source, self.dc, ports.LDAP)
        try:
            request, _ = d.root_dse(1)
            sock.sendall(request)
            _read_ldap(sock, 2)                                   # entry, done
            token, issued = self.gss_token(account.sam, ticket)
            sock.sendall(ldap.bind_sasl(2, "GSS-SPNEGO", token))
            _read_ldap(sock, 1)
            seq = _int31(issued.label, "initiator-seq")
            script = d.policy_searches(account, 3)
            requests = [request for request, _ in script] + [ldap.unbind(3 + len(script))]
            for index, request in enumerate(requests):
                token = krb.wrap_token(f"ldap\x1f{issued.label}\x1f{index}\x1fc", len(request), False, seq + index)
                sock.sendall(struct.pack("!I", len(token)) + token)
                if index < len(script):
                    size = struct.unpack("!I", _recv_exact(sock, SASL_HEADER))[0]
                    _recv_exact(sock, size)
        finally:
            sock.close()

    # SMB
    def smb_session(self, conn: _SmbConnection, account: Account, ticket: bytes) -> dict:
        token, issued = self.gss_token(account.sam, ticket)
        header, body = conn.call(smb2.SESSION_SETUP, smb2.session_setup_request(token), credits=33)
        session = {"id": header["session_id"], "label": issued.label}
        header, _ = conn.call(smb2.TREE_CONNECT, smb2.tree_connect_request(f"\\\\{self.d.dc_fqdn}\\IPC$"), session)
        session["ipc"] = header["tree_id"]
        conn.call(smb2.IOCTL, smb2.dfs_referral_request(f"\\{self.d.domain}\\SysVol"), session, session["ipc"])
        header, _ = conn.call(smb2.TREE_CONNECT, smb2.tree_connect_request(f"\\\\{self.d.dc_fqdn}\\SysVol"), session)
        session["sysvol"] = header["tree_id"]
        conn.sessions[account.sam] = session
        return session

    def read_policies(self, conn: _SmbConnection, account: Account) -> None:
        session = conn.sessions[account.sam]
        for gpo in account.gpos:
            header, body = conn.call(smb2.CREATE, smb2.create_request(self.d.gpt_path(gpo)), session,
                                     session["sysvol"])
            file_id = body[64:80]
            size = struct.unpack_from("<Q", body, 48)[0]
            conn.call(smb2.READ, smb2.read_request(file_id, size), session, session["sysvol"])
            conn.call(smb2.CLOSE, smb2.close_request(file_id), session, session["sysvol"])

    def smb_close(self, conn: _SmbConnection) -> None:
        for session in conn.sessions.values():
            conn.call(smb2.TREE_DISCONNECT, smb2.empty(), session, session["sysvol"])
            conn.call(smb2.TREE_DISCONNECT, smb2.empty(), session, session["ipc"])
            conn.call(smb2.LOGOFF, smb2.empty(), session)
        conn.close()


def _is_error(reply: bytes, code: int) -> bool:
    tag, content, _ = der.read(reply)
    if tag != 0x60 | krb.KRB_ERROR:
        return False
    return der.to_int(der.fields(der.read(content)[1])[6]) == code


def _read_ldap(sock: socket.socket, count: int) -> None:
    buffered = b""
    while count:
        while (size := ldap.message_size(buffered)) is None or len(buffered) < size:
            chunk = sock.recv(65536)
            if not chunk:
                raise RuntimeError("LDAP connection closed by the domain controller")
            buffered += chunk
        buffered = buffered[size:]
        count -= 1


@register
class DomainMember(Actor):
    """Windows domain members of the DC on ``dc``.

    Every member refreshes its computer Group Policy in the background (every 90 minutes plus a random
    offset of up to 30): a CLDAP DC-locator ping, an LDAP session (rootDSE, then a Kerberos bind with
    sealed searches of the computer's DN, the gPLink of its OU / domain / site and the GPO objects) and
    the gpt.ini of every GPO from SYSVOL over SMB 3.1.1, on a connection Windows keeps open until it has
    been idle for KeepConn (10 minutes). Kerberos tickets come from a cache: a member got its TGT up to
    10 hours before the capture and asks for a new one (AS exchange with pre-authentication) only when
    it has expired, and for an ldap/ or cifs/ service ticket (TGS exchange) only when it holds none.
    ``logon`` ({host, user, at}) adds an interactive logon of ``user`` at ``at`` (fraction of the
    capture): AS exchange, a ticket for the workstation itself, then the user's Group Policy, refreshed
    on its own timer from then on.
    """

    type = "ad.member"

    def plan(self) -> None:
        plan = self.plan_
        topo = plan.topology
        dc_host = topo.select(self.param("dc"))[0]
        self.dc = next((a for a in plan.actors if isinstance(a, DomainController) and a.hosts[0].id == dc_host.id),
                       None)
        if self.dc is None:
            raise ScenarioError(f"{self.type} '{self.id}': '{dc_host.id}' runs no ad.dc")
        logon = self.param("logon")
        logon_hosts = {h.id for h in topo.select(logon["host"])} if logon else set()
        if logon_hosts - {h.id for h in self.hosts}:
            raise ScenarioError(f"{self.type} '{self.id}': logon.host must be one of its hosts")
        logons, refreshes = [], []
        for host in self.hosts:
            if host.device.stack.name != "windows":
                raise ScenarioError(f"{self.type} needs Windows hosts; '{host.id}' runs {host.device.stack.name}")
            rng = self.rng.child(host.id)
            start, end = host.present or (0.0, plan.duration)
            machine = f"{host.name.upper()[:15]}$"
            events = [(t, "ad.gp_refresh", machine) for t in _refresh_times(rng.child("machine"), start, end)]
            if host.id in logon_hosts:
                user = logon.get("user") or rng.choice(USER_NAMES)
                at = start + rng.uniform(*self.span(logon.get("at", [0.2, 0.6]))) * (end - start)
                first = at + rng.uniform(*LOGON_TO_POLICY)
                events += [(at, "ad.logon", user), (first, "ad.gp_refresh", user)]
                events += [(t, "ad.gp_refresh", user)
                           for t in _refresh_times(rng.child("user"), first, end, first_due=False)]
            for kind, action in self._plan_host(host, sorted(events), rng.child("tickets"), end):
                if kind == "ad.logon":
                    logons.append({"host": host_ref(host.id), "user": action.args["account"],
                                   "action": action_ref(action)})
                    plan.event(action, self.id, f"{action.args['account']} logs on at {host.name}", [],
                               host=host_ref(host.id), user=action.args["account"])
                else:
                    refreshes.append(action_ref(action))
        d = self.dc.directory
        plan.facts[self.id] = {"dc": host_ref(dc_host.id), "domain": d.domain, "realm": d.realm,
                               "members": [host_ref(h.id) for h in self.hosts], "logons": logons,
                               "gp_refreshes": refreshes}

    def _plan_host(self, host, events, rng, end: float) -> list:
        """(event kind, first action) of every logon / Group Policy refresh of one member. Each exchange is
        an action of its own, a step after the one it waits for: the tickets an event finds in the cache
        decide its Kerberos exchanges, the SMB connection's idle time when it is dropped."""
        plan = self.plan_
        dc = self.dc.hosts[0].id
        machine = f"{host.name.upper()[:15]}$"
        tgt = -rng.uniform(0.0, krb.TICKET_LIFETIME)
        cache = {machine: {"tgt": tgt, **{s: rng.uniform(tgt, 0.0) for s in SERVICES if rng.random() < 0.9}}}
        firsts = []
        smb_open, smb_sessions, close_at = False, set(), 0.0
        for t, kind, account in events:
            if smb_open and t >= close_at:
                plan.add(close_at, self.id, host.id, "ad.smb_close", dc=dc)
                smb_open, smb_sessions = False, set()
            steps: list[tuple[str, dict, tuple[float, float]]] = [("ad.cldap", {}, STEP_UDP)]
            tickets = cache.setdefault(account, {})
            # Logon, or an expired TGT (which takes its service tickets with it: they end with it at the
            # latest): AS exchange. With a PAC the AS-REP exceeds the 1465-byte UDP limit and every TGS-REQ
            # does, so the pre-authenticated AS-REQ is retried over TCP and TGS-REQs go over TCP at once.
            if kind == "ad.logon" or "tgt" not in tickets or tickets["tgt"] + krb.TICKET_LIFETIME <= t:
                tickets.clear()
                steps += [("ad.as", {"preauth": False, "tcp": False}, STEP_UDP),
                          ("ad.as", {"preauth": True, "tcp": False}, STEP_RETRY),
                          ("ad.as", {"preauth": True, "tcp": True}, STEP_TCP)]
            if kind == "ad.logon":
                steps.append(("ad.tgs", {"service": "host"}, STEP_TCP))
            else:
                new_session = account not in smb_sessions
                if "ldap" not in tickets:
                    steps.append(("ad.tgs", {"service": "ldap"}, STEP_TCP))
                steps.append(("ad.ldap", {}, STEP_LDAP))
                if new_session and "cifs" not in tickets:
                    steps.append(("ad.tgs", {"service": "cifs"}, STEP_TCP))
                steps.append(("ad.smb", {"connect": not smb_open, "session": new_session}, STEP_UDP))
                smb_open = True
                smb_sessions.add(account)
            first = None
            as_started = None
            for op, args, gap in steps:
                if op == "ad.as":
                    as_started = args["started"] = as_started if as_started is not None else round(t, 6)
                elif op == "ad.tgs":
                    args["tgt"] = tickets.get("tgt")
                elif op in ("ad.ldap", "ad.smb"):
                    args["ticket"] = tickets.get("ldap" if op == "ad.ldap" else "cifs")
                action = plan.add(t, self.id, host.id, op, dc=dc, account=account, **args)
                if op == "ad.as" and args["tcp"]:
                    tickets["tgt"] = action.t
                elif op == "ad.tgs" and args["service"] != "host":
                    tickets[args["service"]] = action.t
                elif op == "ad.smb":
                    close_at = action.t + KEEP_CONN + rng.uniform(0.0, 30.0)
                first = first or action
                t += rng.uniform(*gap)
            firsts.append((kind, first))
        if smb_open:
            if close_at < end:
                plan.add(close_at, self.id, host.id, "ad.smb_close", dc=dc)
            else:
                plan.add(plan.duration + 1.0, self.id, host.id, "ad.smb_close", phase="teardown", dc=dc)
        return firsts

    def execute(self, action, rt) -> None:
        a = action.args
        d = self.dc.directory
        host = rt.plan.topology.by_id[action.host]
        member = _Member(rt, d, host)
        key = (self.id, action.host)
        op = action.op
        if op == "ad.smb_close":
            member.smb_close(rt.clients.pop(key))
            return
        account = d.account(a["account"])
        if op == "ad.cldap":
            member.cldap_ping()
        elif op == "ad.as":
            member.as_request(account.sam, a["preauth"], a["tcp"], rt.plan.start_epoch + a["started"])
        elif op == "ad.tgs":
            tgt = d.ticket(account.sam, d.spn("krbtgt"), a["tgt"])
            member.tgs_exchange(account.sam, tgt, d.spn(a["service"], host))
        elif op == "ad.ldap":
            member.ldap_session(account, d.ticket(account.sam, d.spn("ldap"), a["ticket"]))
        elif op == "ad.smb":
            if a["connect"]:
                conn = rt.clients[key] = _SmbConnection(host.loopback, d.dc.loopback, f"{host.id}\x1f{action.t}")
                client_guid = label_bytes(f"smb-client-guid\x1f{host.id}", 16)
                salt = label_bytes(f"smb-salt\x1f{host.id}\x1f{action.t}", 32)
                conn.call(smb2.NEGOTIATE, smb2.negotiate_request(client_guid, salt, d.dc_fqdn))
            conn = rt.clients[key]
            if a["session"]:
                member.smb_session(conn, account, d.ticket(account.sam, d.spn("cifs"), a["ticket"]))
            member.read_policies(conn, account)
        else:
            raise ValueError(f"unknown operation {op}")

    def close(self, rt) -> None:
        for key in [k for k in rt.clients if k[0] == self.id]:
            rt.clients.pop(key).close()


USER_NAMES = ("a.nowak", "j.kowalski", "m.wisniewska", "p.zielinski", "k.lewandowska", "t.wojcik",
              "j.smith", "m.jones", "r.miller", "s.davis", "l.becker", "f.schulz")
LOGON_TO_POLICY = (2.0, 6.0)               # logon -> the user's first Group Policy processing (s)
# Client delay from one exchange to the next, longer than the exchange it waits for takes (s).
STEP_UDP = (0.004, 0.012)                  # after a datagram exchange
STEP_RETRY = (0.002, 0.006)                # KRB_ERR_RESPONSE_TOO_BIG -> the same request over TCP
STEP_TCP = (0.008, 0.025)                  # after a Kerberos exchange over its own TCP connection
STEP_LDAP = (0.04, 0.12)                   # after the LDAP session


def _refresh_times(rng, start: float, end: float, first_due: bool = True) -> list[float]:
    """Background Group Policy refreshes in [start, end): every 90 minutes plus a random offset of up to
    30; the first one falls anywhere in its interval (``first_due``) or a full interval after ``start``."""
    times = []
    interval = GP_INTERVAL + rng.uniform(0.0, GP_OFFSET)
    t = start + (rng.uniform(0.0, interval) if first_due else interval)
    while t < end:
        times.append(t)
        t += GP_INTERVAL + rng.uniform(0.0, GP_OFFSET)
    return times
