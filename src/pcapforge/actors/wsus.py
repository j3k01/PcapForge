"""Windows Server Update Services: the Windows Update Agent of each workstation scans against the site's WSUS
server over plain HTTP on port 8530 ([MS-WUSP]), and downloads approved update content with BITS.

Scan (one keep-alive connection, SOAP 1.1 over HTTP/1.1): GetConfig and GetCookie on
/ClientWebService/client.asmx, GetAuthorizationCookie on /SimpleAuthWebService/SimpleAuth.asmx,
SyncUpdates, and GetExtendedUpdateInfo when an approved update applies. The message bodies follow
the [MS-WUSP] section 4 examples; the server's replies the IIS / ASP.NET headers and bodies of
GoSecure's pywsus (a WSUS server Windows clients accept). The approved update is a Microsoft
Defender Antivirus security intelligence update (KB2267602), whose file BITS fetches from
/Content/<last two hex digits of its SHA-1>/<SHA-1>.exe: a HEAD, then a GET for the whole file.
IIS closes the idle connections after its connectionTimeout of 120 s.

Workstations that boot during the capture scan 5 to 15 minutes after their address is configured;
ones that were running scan with the probability of their 22-hour detection interval falling into
the capture. Not modelled: the Windows Update Agent self-update check, RegisterComputer, driver
synchronization and event reporting (ReportEventBatch); response compression (xpress).
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import uuid

from pcapforge import ports
from pcapforge.actors import register
from pcapforge.actors.base import Actor
from pcapforge.actors.dns import query_server
from pcapforge.actors.kerberos import stream
from pcapforge.actors.scripted import ScriptedConnection, ScriptedServer
from pcapforge.plan import action_ref, host_ref
from pcapforge.scenario import ScenarioError

PORT = ports.WELL_KNOWN[ports.WSUS]
USER_AGENT = "Windows-Update-Agent/10.0.10011.16384 Client-Protocol/1.40"
BITS_AGENT = "Microsoft BITS/7.8"
DETECTION_INTERVAL = 22 * 3600.0     # Automatic Updates detection frequency (default 22 hours)
IDLE_TIMEOUT = 120.0
DNS_TTL = 1200.0
NS_CLIENT = "http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService"
NS_AUTH = "http://www.microsoft.com/SoftwareDistribution/Server/SimpleAuthWebService"
CLIENT_PATH, AUTH_PATH = "/ClientWebService/client.asmx", "/SimpleAuthWebService/SimpleAuth.asmx"
ENVELOPE = ('<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" '
            'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema"'
            '{extra}><soap:Body>{body}</soap:Body></soap:Envelope>')
SOAPENC = ' xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/"'
DEFENDER_KB = "2267602"


def _iso(epoch: float, digits: int = 3) -> str:
    stamp = dt.datetime.fromtimestamp(epoch, dt.UTC)
    return stamp.strftime("%Y-%m-%dT%H:%M:%S") + (f".{stamp.microsecond:06d}"[:digits + 1] if digits else "") + "Z"


def _http_date(epoch: float) -> str:
    return dt.datetime.fromtimestamp(int(epoch), dt.UTC).strftime("%a, %d %b %Y %H:%M:%S GMT")


def _b64(label: str, size: int) -> str:
    return base64.b64encode(stream(label, size)).decode()


def request(path: str, host: str, action: str, body: str) -> bytes:
    data = body.encode()
    head = (f"POST {path} HTTP/1.1\r\nCache-Control: no-cache\r\nConnection: Keep-Alive\r\nPragma: no-cache\r\n"
            f"Content-Type: text/xml; charset=utf-8\r\nUser-Agent: {USER_AGENT}\r\n"
            f'SOAPAction: "{action}"\r\nContent-Length: {len(data)}\r\nHost: {host}:{PORT}\r\n\r\n')
    return head.encode() + data


def response(body: str, epoch: float) -> bytes:
    data = body.encode()
    head = ("HTTP/1.1 200 OK\r\nCache-Control: private\r\nContent-Type: text/xml; charset=utf-8\r\n"
            "Server: Microsoft-IIS/10.0\r\nX-AspNet-Version: 4.0.30319\r\nX-Powered-By: ASP.NET\r\n"
            f"Date: {_http_date(epoch)}\r\nContent-Length: {len(data)}\r\n\r\n")
    return head.encode() + data


@register
class WsusServer(Actor):
    """WSUS on IIS (port 8530). Params: ``update`` (an approved Microsoft Defender Antivirus security
    intelligence update clients download: true / false, default false), ``update_size`` ([lo, hi] bytes)."""

    type = "wsus.server"
    is_server = True

    def plan(self) -> None:
        plan = self.plan_
        if len(self.hosts) != 1:
            raise ScenarioError(f"{self.type} '{self.id}' runs on exactly one host")
        host = self.hosts[0]
        self.fqdn = f"{host.name.lower()}.{plan.topology.domain}"
        self.server = ScriptedServer()
        rng = self.rng
        self.update = None
        if self.param("update", False):
            size = rng.randint(*(int(v) for v in self.span(self.param("update_size", [600_000, 2_400_000]))))
            digest = hashlib.sha1(stream(f"wsus-file\x1f{rng.key}", 64)).hexdigest()
            version = f"1.{rng.randint(441, 449)}.{rng.randint(100, 999)}.0"
            self.update = {
                "kb": DEFENDER_KB,
                "title": f"Security Intelligence Update for Microsoft Defender Antivirus - KB{DEFENDER_KB} "
                         f"(Version {version}) - Current Channel (Broad)",
                "file": f"{digest}.exe",
                "path": f"/Content/{digest[-2:].upper()}/{digest}.exe",
                "sha1": digest,
                "size": size,
                "revision": rng.randint(200_000_000, 299_999_999),
                "deployment": rng.randint(300_000, 999_999),
                "update_id": str(uuid.UUID(bytes=stream(f"wsus-update\x1f{rng.key}", 16), version=4)),
                "modified": plan.start_epoch - rng.uniform(3600.0, 20 * 3600.0),
            }
        plan.facts[self.id] = {"hosts": [host_ref(host.id)], "fqdn": self.fqdn, "port": PORT,
                               "url": f"http://{self.fqdn}:{PORT}", "update": self.update}

    async def serve(self, rt) -> None:
        await self.server.start(rt, self.hosts[0].loopback, ports.WSUS)


@register
class WsusClient(Actor):
    """Windows Update Agent scans against a ``wsus.server``. Params: ``server``, ``dns`` (the resolver),
    ``scan_after`` ([lo, hi] seconds from a booting host's configured address to its scan, default [300, 900])."""

    type = "wsus.client"

    def plan(self) -> None:
        plan = self.plan_
        topo = plan.topology
        server_host = topo.select(self.param("server"))[0]
        server = next((a for a in plan.actors if isinstance(a, WsusServer) and a.hosts[0].id == server_host.id), None)
        if server is None:
            raise ScenarioError(f"{self.type} '{self.id}': '{server_host.id}' runs no wsus.server")
        self.wsus = server
        resolver = topo.select(self.param("dns"))[0].id
        scan_after = self.span(self.param("scan_after", [300, 900]))
        scans, downloads = [], []
        for host in self.hosts:
            rng = self.rng.child(host.id)
            begin, end = self.connected(host)
            if host.present is not None and host.arrives:
                at = begin + rng.uniform(*scan_after)
            else:
                chance = min(1.0, (end - begin) / DETECTION_INTERVAL)
                at = begin + rng.uniform(0.0, end - begin) if rng.random() < chance else None
            if at is None or at >= end:
                continue
            client_id = str(uuid.UUID(bytes=stream(f"wsus-client\x1f{self.rng.key}\x1f{host.id}", 16), version=4))
            common = {"wsus": server_host.id, "client_id": client_id, "fqdn": f"{host.name.lower()}.{topo.domain}"}
            plan.add(at, self.id, host.id, "wsus.resolve", name=server.fqdn, server=resolver,
                     txid=rng.randrange(1, 65536), txid6=rng.randrange(1, 65536))
            scan = plan.add(at + rng.uniform(0.005, 0.03), self.id, host.id, "wsus.scan", **common)
            plan.add(min(at + 5.0 + IDLE_TIMEOUT, plan.duration + 1.0), self.id, host.id, "wsus.timeout",
                     conn="scan", **({"phase": "teardown"} if at + 5.0 + IDLE_TIMEOUT >= plan.duration else {}))
            scans.append({"host": host_ref(host.id), "scan": action_ref(scan)})
            if server.update is not None:
                when = at + rng.uniform(20.0, 90.0)
                if when < end:
                    download = plan.add(when, self.id, host.id, "wsus.download", **common)
                    close = when + 10.0 + IDLE_TIMEOUT
                    plan.add(min(close, plan.duration + 1.0), self.id, host.id, "wsus.timeout", conn="download",
                             **({"phase": "teardown"} if close >= plan.duration else {}))
                    downloads.append({"host": host_ref(host.id), "download": action_ref(download)})
        plan.facts[self.id] = {"server": host_ref(server_host.id), "scans": scans, "downloads": downloads,
                               "scanned": [s["host"] for s in scans],
                               "soap_actions": ["GetConfig", "GetAuthorizationCookie", "GetCookie", "SyncUpdates"]
                               + (["GetExtendedUpdateInfo"] if server.update else [])}

    # -- recording ------------------------------------------------------------------
    def execute(self, action, rt) -> None:
        a = action.args
        if action.op == "wsus.resolve":
            query_server(rt, action.host, a["server"], a["name"], "A", a["txid"])
            query_server(rt, action.host, a["server"], a["name"], "AAAA", a["txid6"])
            return
        key = (self.id, action.host, a.get("conn", "scan" if action.op == "wsus.scan" else "download"))
        if action.op == "wsus.timeout":
            rt.clients.pop(key).server_close()
            return
        conn = rt.clients[key] = ScriptedConnection(rt, self.wsus.server, rt.loopback(action.host),
                                                    rt.loopback(a["wsus"]), ports.WSUS)
        now = rt.plan.start_epoch + rt.clock.t
        if action.op == "wsus.scan":
            for path, soap_action, body, reply in self._scan(a, now):
                conn.exchange(request(path, self.wsus.fqdn, soap_action, body), response(reply, now))
        else:
            self._download(conn, now)

    def _scan(self, a: dict, now: float) -> list[tuple[str, str, str, str]]:
        """(path, SOAPAction, request body, response body) of one detection."""
        label = f"{self.rng.key}\x1f{a['client_id']}"
        update = self.wsus.update
        last_change = _iso(now - 3 * 86400.0, 2)
        expire = _iso(now + 86400.0, 7)
        auth = _b64(f"wsus-auth\x1f{label}", 456)
        cookie = _b64(f"wsus-cookie\x1f{label}", 168)
        envelope = lambda body: ENVELOPE.format(extra=SOAPENC, body=body)  # noqa: E731
        reply = lambda body: ENVELOPE.format(extra="", body=body)  # noqa: E731
        config = (f'<GetConfigResponse xmlns="{NS_CLIENT}"><GetConfigResult><LastChange>{last_change}</LastChange>'
                  "<IsRegistrationRequired>true</IsRegistrationRequired><AuthInfo><AuthPlugInInfo>"
                  "<PlugInID>SimpleTargeting</PlugInID><ServiceUrl>SimpleAuthWebService/SimpleAuth.asmx</ServiceUrl>"
                  "<Parameter /></AuthPlugInInfo></AuthInfo><Properties>"
                  + "".join(f"<ConfigurationProperty><Name>{n}</Name><Value>{v}</Value></ConfigurationProperty>"
                            for n, v in (("MaxExtendedUpdatesPerRequest", 50), ("ProtocolVersion", "3.2"),
                                         ("IsInventoryRequired", 0), ("ClientReportingLevel", 2)))
                  + "</Properties></GetConfigResult></GetConfigResponse>")
        calls = [
            (CLIENT_PATH, f"{NS_CLIENT}/GetConfig",
             envelope(f'<GetConfig xmlns="{NS_CLIENT}"><protocolVersion>1.0</protocolVersion></GetConfig>'),
             reply(config)),
            (AUTH_PATH, f"{NS_AUTH}/GetAuthorizationCookie",
             envelope(f'<GetAuthorizationCookie xmlns="{NS_AUTH}"><clientId>{a["client_id"]}</clientId>'
                      f'<targetGroupName /><dnsName>{a["fqdn"]}</dnsName></GetAuthorizationCookie>'),
             reply(f'<GetAuthorizationCookieResponse xmlns="{NS_AUTH}"><GetAuthorizationCookieResult>'
                   f"<PlugInId>SimpleTargeting</PlugInId><CookieData>{auth}</CookieData>"
                   "</GetAuthorizationCookieResult></GetAuthorizationCookieResponse>")),
            (CLIENT_PATH, f"{NS_CLIENT}/GetCookie",
             envelope(f'<GetCookie xmlns="{NS_CLIENT}"><authCookies xmlns:q1="{NS_CLIENT}" '
                      'soapenc:arrayType="q1:AuthorizationCookie[1]"><AuthorizationCookie>'
                      f"<PlugInId>SimpleTargeting</PlugInId><CookieData>{auth}</CookieData></AuthorizationCookie>"
                      f'</authCookies><oldCookie xsi:nil="true" /><lastChange>{last_change}</lastChange>'
                      f"<currentTime>{_iso(now, 0)}</currentTime><protocolVersion>1.8</protocolVersion></GetCookie>"),
             reply(f'<GetCookieResponse xmlns="{NS_CLIENT}"><GetCookieResult><Expiration>{expire}</Expiration>'
                   f"<EncryptedData>{cookie}</EncryptedData></GetCookieResult></GetCookieResponse>")),
        ]
        sync_request = envelope(
            f'<SyncUpdates xmlns="{NS_CLIENT}"><cookie><Expiration>{expire}</Expiration>'
            f"<EncryptedData>{cookie}</EncryptedData></cookie><parameters><ExpressQuery>false</ExpressQuery>"
            '<InstalledNonLeafUpdateIDs xsi:nil="true" /><OtherCachedUpdateIDs xsi:nil="true" />'
            '<SystemSpec xsi:nil="true" /><CachedDriverIDs xsi:nil="true" /><SkipSoftwareSync>false</SkipSoftwareSync>'
            "</parameters></SyncUpdates>")
        new_updates = ""
        if update is not None:
            new_updates = (f"<UpdateInfo><ID>{update['revision']}</ID><Deployment><ID>{update['deployment']}</ID>"
                           f"<Action>Install</Action><IsAssigned>true</IsAssigned><LastChangeTime>{last_change}"
                           "</LastChangeTime><AutoSelect>0</AutoSelect><AutoDownload>0</AutoDownload>"
                           "<SupersedenceBehavior>0</SupersedenceBehavior><FlagBitmask>0</FlagBitmask></Deployment>"
                           f"<IsLeaf>true</IsLeaf><Xml>&lt;UpdateIdentity UpdateID=\"{update['update_id']}\" "
                           "RevisionNumber=\"200\" /&gt;&lt;Properties UpdateType=\"Software\" /&gt;</Xml></UpdateInfo>")
        calls.append((CLIENT_PATH, f"{NS_CLIENT}/SyncUpdates", sync_request, reply(
            f'<SyncUpdatesResponse xmlns="{NS_CLIENT}"><SyncUpdatesResult><NewUpdates>{new_updates}</NewUpdates>'
            f"<Truncated>false</Truncated><NewCookie><Expiration>{expire}</Expiration><EncryptedData>{cookie}"
            "</EncryptedData></NewCookie><DriverSyncNotNeeded>true</DriverSyncNotNeeded></SyncUpdatesResult>"
            "</SyncUpdatesResponse>")))
        if update is not None:
            digest = base64.b64encode(bytes.fromhex(update["sha1"])).decode()
            files = (f"&lt;Files&gt;&lt;File Digest=\"{digest}\" DigestAlgorithm=\"SHA1\" FileName=\"{update['file']}\" "
                     f"Size=\"{update['size']}\" Modified=\"{_iso(update['modified'])}\" /&gt;&lt;/Files&gt;")
            calls.append((CLIENT_PATH, f"{NS_CLIENT}/GetExtendedUpdateInfo", envelope(
                f'<GetExtendedUpdateInfo xmlns="{NS_CLIENT}"><cookie><Expiration>{expire}</Expiration>'
                f"<EncryptedData>{cookie}</EncryptedData></cookie><revisionIDs><int>{update['revision']}</int>"
                "</revisionIDs><infoTypes><XmlUpdateFragmentType>Extended</XmlUpdateFragmentType>"
                "<XmlUpdateFragmentType>LocalizedProperties</XmlUpdateFragmentType></infoTypes><locales>"
                "<string>en-US</string><string>en</string></locales></GetExtendedUpdateInfo>"), reply(
                f'<GetExtendedUpdateInfoResponse xmlns="{NS_CLIENT}"><GetExtendedUpdateInfoResult><Updates>'
                f"<Update><ID>{update['revision']}</ID><Xml>&lt;ExtendedProperties DefaultPropertiesLanguage=\"en\" "
                f"MaxDownloadSize=\"{update['size']}\" MinDownloadSize=\"{update['size']}\"&gt;"
                f"&lt;KBArticleID&gt;{update['kb']}&lt;/KBArticleID&gt;&lt;/ExtendedProperties&gt;{files}</Xml></Update>"
                f"<Update><ID>{update['revision']}</ID><Xml>&lt;LocalizedProperties&gt;&lt;Language&gt;en"
                f"&lt;/Language&gt;&lt;Title&gt;{update['title']}&lt;/Title&gt;&lt;/LocalizedProperties&gt;</Xml>"
                f"</Update></Updates><FileLocations><FileLocation><FileDigest>{digest}</FileDigest>"
                f"<Url>http://{self.wsus.fqdn}:{PORT}{update['path']}</Url></FileLocation></FileLocations>"
                "</GetExtendedUpdateInfoResult></GetExtendedUpdateInfoResponse>")))
        return calls

    def _download(self, conn: ScriptedConnection, now: float) -> None:
        """BITS: a HEAD for the size, then a GET for the whole file."""
        update = self.wsus.update
        size = update["size"]
        common = (f"Accept: */*\r\nAccept-Encoding: identity\r\nUser-Agent: {BITS_AGENT}\r\n"
                  f"Host: {self.wsus.fqdn}:{PORT}\r\n")
        etag = f'"{update["sha1"][:16]}:0"'
        server = (f"Last-Modified: {_http_date(update['modified'])}\r\nAccept-Ranges: bytes\r\nETag: {etag}\r\n"
                  f"Server: Microsoft-IIS/10.0\r\nX-Powered-By: ASP.NET\r\nDate: {_http_date(now)}\r\n")
        head = f"HEAD {update['path']} HTTP/1.1\r\nConnection: Keep-Alive\r\n{common}\r\n".encode()
        head_reply = (f"HTTP/1.1 200 OK\r\nContent-Length: {size}\r\nContent-Type: application/octet-stream\r\n"
                      f"{server}\r\n").encode()
        conn.exchange(head, head_reply)
        get = (f"GET {update['path']} HTTP/1.1\r\nConnection: Keep-Alive\r\n{common}"
               f"Range: bytes=0-{size - 1}\r\n\r\n").encode()
        get_reply = (f"HTTP/1.1 206 Partial Content\r\nContent-Type: application/octet-stream\r\n{server}"
                     f"Content-Range: bytes 0-{size - 1}/{size}\r\nContent-Length: {size}\r\n\r\n").encode()
        conn.exchange(get, get_reply + stream(f"wsus-content\x1f{update['sha1']}", size))

    def close(self, rt) -> None:
        for key in [k for k in rt.clients if k[0] == self.id]:
            rt.clients.pop(key).close()
