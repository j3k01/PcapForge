"""OPC UA (binary ``opc.tcp``, SecurityPolicy None) server and client actors backed by asyncua.

``opcua.server`` is a SCADA / OPC UA server that mirrors the process points of the PLCs it
reads (``params.sources``, hosts of a ``modbus.server``): every PLC is a folder ``PLC01`` with
tag groups (``Measurements``, ``Setpoints``, ``Commands``, ``Status``) and one variable per
point, ``ns=2;s=PLC01.clearwell_level``, whose value is read from the PLC's process
simulation at the request's virtual time.

``opcua.client`` is a historian / MES collector: Hello, OpenSecureChannel, CreateSession,
ActivateSession, a NamespaceArray read and a browse of the tag tree, then one subscription
per PLC (CreateSubscription, CreateMonitoredItems per tag group) serviced by Publish requests
every publishing interval, a ServerStatus watchdog Read and OpenSecureChannel renewals at
75 % of the token lifetime. The session stays open; its teardown is dropped like Modbus ones.

Recording runs back to back, so nothing may run on wall-clock timers: the server's
subscription timers are stopped and a Publish request is answered at once with what changed
since the subscription's last publish (or a keep-alive), as for a late subscription. All
timestamps in the payload (request/response headers, DataValues, PublishTime, security
token, ServerStatus) come from the scenario clock; nonces come from the behaviour seed.
Requests stay small (browse one tag group at a time, one subscription per PLC, monitored
items created per tag group); larger messages are segmented by the composer.
"""

from __future__ import annotations

import asyncio
import dataclasses
import datetime as dt
import logging
import threading
from dataclasses import dataclass

from pcapforge import ports
from pcapforge.actors import register
from pcapforge.actors.base import Actor, optional_import
from pcapforge.actors.modbus import serving_profile
from pcapforge.plan import host_ref
from pcapforge.process import BIT_TABLES, Point
from pcapforge.scenario import ScenarioError

REQUIRES = ("asyncua", "asyncua", "opcua")
NAMESPACE_INDEX = 2  # 0: OPC UA, 1: the server's application URI, 2: the tag namespace
# Process tables -> tag group folder of the SCADA server.
GROUPS = (("input", "Measurements"), ("holding", "Setpoints"), ("coils", "Commands"), ("discrete", "Status"))
OBJECTS_FOLDER = "i=85"
NAMESPACE_ARRAY = "i=2255"
SERVER_STATE = "i=2259"
CURRENT_TIME = "i=2258"
SERVER_START_TIME = "i=2257"
SERVER_STATUS = "i=2256"
TOKEN_RENEWAL = 0.75        # clients renew the secure channel at 75 % of the token lifetime
SESSION_TIMEOUT_MS = 3_600_000
CLIENT_TIMEOUT_S = 10.0     # TimeoutHint of the client's requests


def build_info(host) -> dict[str, str]:
    """BuildInfo the server reports: the device profile's ``identity`` over generic values."""
    return {"ManufacturerName": host.device.vendor, "ProductName": "OPC UA Server",
            "ProductUri": f"urn:{host.device.name}:opcua-server", "SoftwareVersion": "1.0.0",
            "BuildNumber": "1", "BuildDate": "2024-01-01", **host.device.identity}


def _asyncua(actor_type: str):
    optional_import(actor_type, *REQUIRES)
    from asyncua import ua

    logging.getLogger("asyncua").setLevel(logging.CRITICAL)
    return ua


def _utc(epoch: float) -> dt.datetime:
    return dt.datetime.fromtimestamp(epoch, dt.UTC)


# --- address space shared by server and client plans ---------------------------------

@dataclass(frozen=True)
class Tag:
    node: str       # string NodeId identifier in the tag namespace
    name: str
    point: Point


@dataclass(frozen=True)
class TagGroup:
    node: str
    name: str
    table: str
    tags: tuple[Tag, ...]


@dataclass(frozen=True)
class DeviceFolder:
    host_id: str
    name: str
    groups: tuple[TagGroup, ...]


def device_folders(plan, sources) -> list[DeviceFolder]:
    """Tag tree of a SCADA server reading ``sources`` (hosts that run a ``modbus.server``)."""
    folders = []
    for host in sources:
        profile = serving_profile(plan, host.id)
        name = f"{host.group.upper()}{host.index:02d}"
        groups = []
        for table, group in GROUPS:
            tags = tuple(Tag(f"{name}.{p.name}", p.name, p) for p in profile.table(table) if p.name != "spare")
            if tags:
                groups.append(TagGroup(f"{name}.{group}", group, table, tags))
        folders.append(DeviceFolder(host.id, name, tuple(groups)))
    return folders


def tag_node(identifier: str) -> str:
    return f"ns={NAMESPACE_INDEX};s={identifier}"


# --- server --------------------------------------------------------------------------

@register
class OpcUaServer(Actor):
    """SCADA / OPC UA server VM publishing the PLC process points as OPC UA variables."""

    type = "opcua.server"
    is_server = True
    requires = REQUIRES

    def plan(self) -> None:
        plan = self.plan_
        self.sources = plan.topology.select(self.param("sources"))
        if not self.sources:
            raise ScenarioError(f"{self.id}: opcua.server needs 'sources' (PLC hosts)")
        self.devices = device_folders(plan, self.sources)
        plan.facts[self.id] = {
            "hosts": [host_ref(h.id) for h in self.hosts],
            "sources": [host_ref(h.id) for h in self.sources],
            "endpoints": [endpoint_url(h) for h in self.hosts],
            "devices": [d.name for d in self.devices],
            "tags": sum(len(g.tags) for d in self.devices for g in d.groups),
        }

    async def serve(self, rt) -> None:
        _asyncua(self.type)
        from asyncua.server.internal_session import InternalSession

        # Session ids and authentication tokens are class-wide counters: start every
        # recording from the same values so a recording does not depend on the ones before.
        InternalSession._counter = 10
        InternalSession._auth_counter = 1000
        for host in self.hosts:
            server = await _start_server(self, host, rt)
            rt.servers.append(_Stopper(server))


def endpoint_url(host) -> str:
    """Endpoint the server is configured with (its host name)."""
    return f"opc.tcp://{host.name}:{ports.WELL_KNOWN[ports.OPCUA]}"


def client_url(topology, host) -> str:
    """Endpoint a client dials: the server's FQDN in the site domain."""
    return f"opc.tcp://{host.name.lower()}.{topology.domain}:{ports.WELL_KNOWN[ports.OPCUA]}"


class _Stopper:
    """The recorder shuts servers down with ``await server.shutdown()``."""

    def __init__(self, server) -> None:
        self.server = server

    async def shutdown(self) -> None:
        await self.server.stop()


class _ServerContext:
    """Virtual clock, nonces and process values of one OPC UA server host."""

    def __init__(self, actor: OpcUaServer, host, rt) -> None:
        from asyncua import ua

        self.ua = ua
        self.rt = rt
        self.start_epoch = actor.plan_.start_epoch
        rng = actor.rng.child(host.id)
        self.clock_rng = rng.child("clock")
        self.nonce_rng = rng.child("nonce")
        self.skew = rng.uniform(-0.008, 0.008)        # host clock offset (domain w32time keeps it small)
        self.boot = self.start_epoch - rng.uniform(2, 40) * 86400.0
        self.devices = {d.name: d for d in actor.devices}
        self.refreshed: dict[str, float] = {}
        self.now = _utc(self.start_epoch)
        self.server = None

    def stamp(self) -> None:
        """Server time of the request being processed: arrival plus a little processing."""
        self.now = _utc(self.start_epoch + self.rt.clock.t + self.skew + self.clock_rng.uniform(0.0002, 0.0015))

    def nonce(self) -> bytes:
        return self.nonce_rng.randbytes(32)

    def current_time(self, nodeid, attr):
        ua = self.ua
        return ua.DataValue(ua.Variant(self.now, ua.VariantType.DateTime),
                            SourceTimestamp=self.now, ServerTimestamp=self.now)

    def devices_of(self, identifiers) -> list[str]:
        prefix = {str(i).split(".", 1)[0] for i in identifiers}
        return [name for name in self.devices if name in prefix]

    async def refresh(self, names) -> None:
        """Copy the PLCs' current process values into their tags (once per action)."""
        ua = self.ua
        t = self.rt.clock.t
        for name in names:
            if self.refreshed.get(name) == t:
                continue
            self.refreshed[name] = t
            device = self.devices[name]
            sim = self.rt.sims[device.host_id]  # the source's modbus.server (checked when planning)
            sim.advance(t)
            for group in device.groups:
                raw = sim.read(group.table)
                for tag in group.tags:
                    variant = _variant(ua, tag.point, raw[tag.point.address])
                    value = ua.DataValue(variant, SourceTimestamp=self.now, ServerTimestamp=self.now)
                    await self.server.write_attribute_value(ua.NodeId(tag.node, NAMESPACE_INDEX), value)


def _variant(ua, point: Point, raw: int):
    if point.table in BIT_TABLES:
        return ua.Variant(bool(raw), ua.VariantType.Boolean)
    return ua.Variant(point.decode(raw), ua.VariantType.Double)


async def _start_server(actor: OpcUaServer, host, rt):
    from asyncua import Server, ua
    from asyncua.server.binary_server_asyncio import BinaryServer, OPCUAProtocol
    from asyncua.server.uaprocessor import UaProcessor

    context = _ServerContext(actor, host, rt)
    publish = ua.NodeId(ua.ObjectIds.PublishRequest_Encoding_DefaultBinary)
    read = ua.NodeId(ua.ObjectIds.ReadRequest_Encoding_DefaultBinary)
    create_subscription = ua.NodeId(ua.ObjectIds.CreateSubscriptionRequest_Encoding_DefaultBinary)
    create_items = ua.NodeId(ua.ObjectIds.CreateMonitoredItemsRequest_Encoding_DefaultBinary)

    class Processor(UaProcessor):
        """UaProcessor on the scenario clock with publishing driven by Publish requests."""

        def __init__(self, *args) -> None:
            super().__init__(*args)
            self.turn = 0
            self.subscription_devices: dict[int, list[str]] = {}

        async def process(self, header, body):
            context.stamp()
            return await super().process(header, body)

        def send_response(self, requesthandle, seqhdr, response, msgtype=ua.MessageType.SecureMessage):
            now = context.now
            if getattr(response, "ResponseHeader", None) is not None:
                response.ResponseHeader.Timestamp = now
            if isinstance(response, ua.OpenSecureChannelResponse):
                response.Parameters.SecurityToken.CreatedAt = now
            elif isinstance(response, ua.PublishResponse):
                response.Parameters.NotificationMessage.PublishTime = now
            elif isinstance(response, (ua.CreateSessionResponse, ua.ActivateSessionResponse)):
                response.Parameters.ServerNonce = context.nonce()
                if self.session is not None:
                    self.session.nonce = response.Parameters.ServerNonce
            super().send_response(requesthandle, seqhdr, response, msgtype)

        async def _process_message(self, typeid, requesthdr, seqhdr, body):
            if typeid == publish and self.session is not None:
                await self._prepare_publish()
            elif typeid == read:
                params = _decode(ua.ReadParameters, body)
                await context.refresh(context.devices_of(r.NodeId.Identifier for r in params.NodesToRead
                                                         if r.NodeId.NamespaceIndex == NAMESPACE_INDEX))
            elif typeid == create_items:
                params = _decode(ua.CreateMonitoredItemsParameters, body)
                names = context.devices_of(i.ItemToMonitor.NodeId.Identifier for i in params.ItemsToCreate)
                known = self.subscription_devices.setdefault(params.SubscriptionId, [])
                known.extend(n for n in names if n not in known)
                await context.refresh(names)
            result = await super()._process_message(typeid, requesthdr, seqhdr, body)
            if typeid == create_subscription and self.session is not None:
                for sub in self.session.subscription_service.subscriptions.values():
                    if sub._task is not None:
                        # No wall-clock publishing timer: Publish requests drive publishing.
                        sub._task.cancel()
                        sub._task = None
            return result

        async def _prepare_publish(self) -> None:
            """Let the next subscription of the session answer this Publish request at once:
            with its queued data changes or, when nothing changed, a keep-alive."""
            session = self.session
            subs = sorted((s for s in session.subscription_service.subscriptions.values()
                           if s.session_id == session.session_id), key=lambda s: s.data.SubscriptionId)
            if not subs:
                return
            sub = subs[self.turn % len(subs)]
            self.turn += 1
            await context.refresh(self.subscription_devices.get(sub.data.SubscriptionId, ()))
            if not (sub._startup or sub._triggered_datachanges or sub._triggered_events):
                sub._keep_alive_count = sub.data.RevisedMaxKeepAliveCount + 1
            self._publish_results_subs = {sub.data.SubscriptionId: True}

    class Protocol(OPCUAProtocol):
        def connection_made(self, transport) -> None:
            super().connection_made(transport)
            if self.processor is not None:
                self.processor = Processor(self.iserver, self.transport, self.limits)
                self.processor.set_policies(self.policies)

    class Binary(BinaryServer):
        def _make_protocol(self):
            return Protocol(iserver=self.iserver, policies=self._policies, clients=self.clients,
                            closing_tasks=self.closing_tasks, limits=self.limits)

    class ScadaServer(Server):
        async def start(self) -> None:
            await self._setup_server_nodes()
            await self.iserver.start()
            self.bserver = Binary(self.iserver, *self.socket_address, self.limits)
            self.bserver.set_policies(self._policies)
            await self.bserver.start()

    identity = build_info(host)
    server = ScadaServer()
    context.server = server
    await server.init()
    server.disable_clock()
    server.set_endpoint(endpoint_url(host))
    server.socket_address = (host.loopback, ports.OPCUA)
    server.set_server_name(f"{identity['ProductName']}@{host.name}")
    server.product_uri = identity["ProductUri"]
    server.manufacturer_name = identity["ManufacturerName"]
    server.application_type = ua.ApplicationType.Server
    server.set_security_policy([ua.SecurityPolicyType.NoSecurity])
    server.set_identity_tokens([ua.AnonymousIdentityToken, ua.UserNameIdentityToken])
    server.set_match_discovery_client_ip(False)
    await server.set_application_uri(f"urn:{host.name}:SCADA:OpcUaServer")
    await server.set_build_info(identity["ProductUri"], identity["ManufacturerName"], identity["ProductName"],
                                identity["SoftwareVersion"], identity["BuildNumber"],
                                dt.datetime.fromisoformat(identity["BuildDate"]).replace(tzinfo=dt.UTC))
    namespace = await server.register_namespace(f"urn:{host.name}:SCADA:Tags")
    if namespace != NAMESPACE_INDEX:
        raise RuntimeError(f"tag namespace got index {namespace}, expected {NAMESPACE_INDEX}")
    objects = server.nodes.objects
    for device in actor.devices:
        folder = await objects.add_folder(ua.NodeId(device.name, namespace), ua.QualifiedName(device.name, namespace))
        for group in device.groups:
            node = await folder.add_folder(ua.NodeId(group.node, namespace), ua.QualifiedName(group.name, namespace))
            for tag in group.tags:
                variant = _variant(ua, tag.point, tag.point.encode(tag.point.nominal))
                await node.add_variable(ua.NodeId(tag.node, namespace), ua.QualifiedName(tag.name, namespace),
                                        variant.Value, variant.VariantType)
    await server.start()
    _scrub_timestamps(ua, server, context)
    server.set_attribute_value_callback(ua.NodeId.from_string(CURRENT_TIME), context.current_time)
    return server


def _decode(cls, body):
    from asyncua.ua.ua_binary import struct_from_binary

    return struct_from_binary(cls, body.copy())


def _scrub_timestamps(ua, server, context: _ServerContext) -> None:
    """Values written while the server was set up carry wall-clock timestamps; give them
    the server's (virtual) boot time instead, so no recording-time date reaches the wire."""
    boot = _utc(context.boot)
    for nodedata in server.iserver.aspace._nodes.values():
        attribute = nodedata.attributes.get(ua.AttributeIds.Value)
        value = attribute.value if attribute is not None else None
        if value is None or (value.SourceTimestamp is None and value.ServerTimestamp is None):
            continue
        attribute.value = dataclasses.replace(
            value, SourceTimestamp=boot if value.SourceTimestamp is not None else None,
            ServerTimestamp=boot if value.ServerTimestamp is not None else None)
    start = server.iserver.aspace._nodes[ua.NodeId.from_string(SERVER_START_TIME)].attributes[ua.AttributeIds.Value]
    start.value = dataclasses.replace(start.value, Value=ua.Variant(boot, ua.VariantType.DateTime))
    status = server.iserver.aspace._nodes[ua.NodeId.from_string(SERVER_STATUS)].attributes[ua.AttributeIds.Value]
    if status.value is not None and status.value.Value is not None:
        inner = dataclasses.replace(status.value.Value.Value, StartTime=boot, CurrentTime=boot)
        status.value = dataclasses.replace(status.value, Value=ua.Variant(inner, status.value.Value.VariantType))


def _server_actor(plan, host_id: str) -> OpcUaServer:
    for actor in plan.actors:
        if isinstance(actor, OpcUaServer) and any(h.id == host_id for h in actor.hosts):
            return actor
    raise ScenarioError(f"no opcua.server runs on host '{host_id}'")


# --- client --------------------------------------------------------------------------

@register
class OpcUaClient(Actor):
    """Historian / MES collector: one long-lived session with a subscription per PLC."""

    type = "opcua.client"
    requires = REQUIRES

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._sessions: dict[str, _ClientSession] = {}

    def plan(self) -> None:
        plan = self.plan_
        targets = plan.topology.select(self.param("server"))
        if len(targets) != 1:
            raise ScenarioError(f"{self.id}: opcua.client 'server' must name exactly one host")
        server_host = targets[0]
        devices = _server_actor(plan, server_host.id).devices
        interval = float(self.param("publishing_interval", 1.0))
        keepalive = float(self.param("keepalive_interval", 5.0))
        lifetime = float(self.param("token_lifetime", 3600.0))
        jitter = float(self.param("jitter", 0.01))
        for host in self.hosts:
            rng = self.rng.child(host.id)
            t = rng.uniform(0.3, 2.0)

            def add(op: str, gap: tuple[float, float] = (0.002, 0.02), **args):
                nonlocal t
                t += rng.uniform(*gap)
                return plan.add(t, self.id, host.id, op, phase="setup", server=server_host.id, **args)

            opened = add("opcua.connect", gap=(0.0, 0.0)).t
            add("opcua.open", gap=(0.0005, 0.003), lifetime_ms=int(lifetime * 1000))
            add("opcua.create_session", gap=(0.0005, 0.004),
                application=self.param("application", "Historian OPC UA Collector"),
                product_uri=self.param("product_uri", "urn:plant-automation:historian:opcua-collector"))
            add("opcua.activate_session", gap=(0.0005, 0.004))
            add("opcua.read", nodes=[NAMESPACE_ARRAY, SERVER_STATE])
            add("opcua.browse", node=OBJECTS_FOLDER, gap=(0.01, 0.08))
            for device in devices:
                add("opcua.browse", node=tag_node(device.name), gap=(0.005, 0.05))
                for group in device.groups:
                    add("opcua.browse", node=tag_node(group.node), gap=(0.005, 0.05))
            for index, device in enumerate(devices):
                add("opcua.subscribe", index=index, interval_ms=interval * 1000.0, gap=(0.005, 0.03))
                for group in device.groups:
                    add("opcua.monitor", index=index, sampling_ms=interval * 1000.0,
                        nodes=[tag_node(tag.node) for tag in group.tags])
            # Each subscription's publishing timer runs at its own phase inside the cycle;
            # phases ascend with the subscription index (the server answers in that order).
            offsets = sorted(rng.uniform(0.0, 0.6 * interval) for _ in devices)
            cycle = t + rng.uniform(0.05, interval)
            first = cycle
            while cycle < plan.duration:
                for offset in offsets:
                    if cycle + offset < plan.duration:
                        plan.add(cycle + offset, self.id, host.id, "opcua.publish", server=server_host.id)
                cycle += rng.jitter(interval, jitter)
            if keepalive > 0:
                tick = first + rng.uniform(0.0, keepalive)
                while tick < plan.duration:
                    plan.add(tick, self.id, host.id, "opcua.read", server=server_host.id,
                             nodes=[SERVER_STATE, CURRENT_TIME])
                    tick += rng.jitter(keepalive, jitter)
            renew = opened + TOKEN_RENEWAL * lifetime
            while renew < plan.duration:
                plan.add(renew, self.id, host.id, "opcua.renew", server=server_host.id,
                         lifetime_ms=int(lifetime * 1000))
                renew += TOKEN_RENEWAL * lifetime
            plan.add(plan.duration + 1.0, self.id, host.id, "opcua.close", phase="teardown",
                     server=server_host.id)
        plan.facts[self.id] = {
            "hosts": [host_ref(h.id) for h in self.hosts],
            "server": host_ref(server_host.id),
            "endpoint": client_url(plan.topology, server_host),
            "subscriptions": len(devices),
            "publishing_interval_s": interval,
            "keepalive_interval_s": keepalive,
        }

    def execute(self, action, rt) -> None:
        if self._loop is None:
            _asyncua(self.type)
            # The client gets its own event loop thread: the recorder's caller may already
            # run an event loop on this one.
            self._loop = asyncio.new_event_loop()
            self._thread = threading.Thread(target=self._loop.run_forever, name=f"pcapforge-{self.id}",
                                            daemon=True)
            self._thread.start()
        session = self._sessions.get(action.host)
        if session is None:
            if action.op != "opcua.connect":
                raise RuntimeError(f"{action.op} before opcua.connect")
            session = self._sessions[action.host] = _ClientSession(self, action.host, action.args["server"], rt)
        handler = getattr(session, action.op.removeprefix("opcua."), None)
        if handler is None:
            raise ValueError(f"unknown op {action.op}")
        self._run(handler(**{k: v for k, v in action.args.items() if k != "server"}))
        if action.op == "opcua.close":
            del self._sessions[action.host]

    def _run(self, coro):
        return asyncio.run_coroutine_threadsafe(coro, self._loop).result(2 * CLIENT_TIMEOUT_S)

    def close(self, rt) -> None:
        if self._loop is None:
            return

        async def drop_all(sessions) -> None:
            for session in sessions:
                session.drop()
            await asyncio.sleep(0.05)

        self._run(drop_all(list(self._sessions.values())))
        self._sessions.clear()
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(5)
        self._loop.close()
        self._loop = self._thread = None


class _ClientSession:
    """One client's TCP connection, secure channel, session and subscriptions."""

    def __init__(self, actor: OpcUaClient, host_id: str, server_id: str, rt) -> None:
        from asyncua import ua

        self.ua = ua
        self.actor = actor
        self.rt = rt
        topology = actor.plan_.topology
        self.host = topology.by_id[host_id]
        self.server = topology.by_id[server_id]
        self.url = client_url(topology, self.server)
        rng = actor.rng.child(host_id).child("session")
        self.rng = rng
        self.skew = rng.uniform(-0.008, 0.008)
        self.protocol = None
        self.policy_id = "anonymous"
        self.subscriptions: dict[int, int] = {}
        self.acks: list = []
        self.handles = 0

    def now(self) -> dt.datetime:
        return _utc(self.actor.plan_.start_epoch + self.rt.clock.t + self.skew)

    # -- transport --------------------------------------------------------------------
    async def connect(self) -> None:
        from asyncua.client.ua_client import UASocketProtocol
        from asyncua.common.connection import TransportLimits
        from asyncua.common.utils import wait_for
        from asyncua.crypto.security_policies import SecurityPolicyNone
        from asyncua.ua.ua_binary import uatcp_to_binary

        ua = self.ua
        loop = asyncio.get_running_loop()
        _, self.protocol = await loop.create_connection(
            lambda: UASocketProtocol(CLIENT_TIMEOUT_S, SecurityPolicyNone(), TransportLimits(65535, 65535, 0, 0)),
            self.server.loopback, ports.OPCUA, local_addr=(self.host.loopback, 0))
        hello = ua.Hello(ProtocolVersion=0, ReceiveBufferSize=65535, SendBufferSize=65535,
                         MaxMessageSize=16_777_216, MaxChunkCount=0, EndpointUrl=self.url)
        ack = loop.create_future()
        self.protocol._callbackmap[0] = ack
        self.protocol.transport.write(uatcp_to_binary(ua.MessageType.Hello, hello))
        await wait_for(ack, CLIENT_TIMEOUT_S)

    async def _secure_channel(self, request_type, lifetime_ms: int) -> None:
        ua = self.ua
        params = ua.OpenSecureChannelParameters(
            ClientProtocolVersion=0, RequestType=request_type, SecurityMode=ua.MessageSecurityMode.None_,
            ClientNonce=b"", RequestedLifetime=lifetime_ms)
        request = ua.OpenSecureChannelRequest(Parameters=params)
        request.RequestHeader.Timestamp = self.now()
        protocol = self.protocol
        protocol._open_secure_channel_exchange = params
        try:
            await asyncio.wait_for(protocol._send_request(request, CLIENT_TIMEOUT_S, ua.MessageType.SecureOpen),
                                   CLIENT_TIMEOUT_S)
        finally:
            protocol._open_secure_channel_exchange = None

    async def open(self, lifetime_ms: int) -> None:
        await self._secure_channel(self.ua.SecurityTokenRequestType.Issue, lifetime_ms)

    async def renew(self, lifetime_ms: int) -> None:
        await self._secure_channel(self.ua.SecurityTokenRequestType.Renew, lifetime_ms)

    async def _call(self, request, response_cls):
        from asyncua.ua.ua_binary import struct_from_binary

        request.RequestHeader.Timestamp = self.now()
        data = await self.protocol.send_request(request, CLIENT_TIMEOUT_S)
        response = struct_from_binary(response_cls, data)
        response.ResponseHeader.ServiceResult.check()
        return response.Parameters if hasattr(response, "Parameters") else response

    # -- session ----------------------------------------------------------------------
    async def create_session(self, application: str, product_uri: str) -> None:
        ua = self.ua
        description = ua.ApplicationDescription(
            ApplicationUri=f"urn:{self.host.name}:Historian:OpcUaCollector", ProductUri=product_uri,
            ApplicationName=ua.LocalizedText(application, "en-US"), ApplicationType=ua.ApplicationType.Client)
        params = ua.CreateSessionParameters(
            ClientDescription=description, EndpointUrl=self.url, SessionName=f"{application} {self.host.name}",
            ClientNonce=self.rng.randbytes(32), RequestedSessionTimeout=SESSION_TIMEOUT_MS,
            MaxResponseMessageSize=16_777_216)
        result = await self._call(ua.CreateSessionRequest(Parameters=params), ua.CreateSessionResponse)
        self.protocol.authentication_token = result.AuthenticationToken
        for endpoint in result.ServerEndpoints:
            for token in endpoint.UserIdentityTokens:
                if token.TokenType == ua.UserTokenType.Anonymous:
                    self.policy_id = token.PolicyId

    async def activate_session(self) -> None:
        ua = self.ua
        params = ua.ActivateSessionParameters(
            LocaleIds=["en-US"], UserIdentityToken=ua.AnonymousIdentityToken(PolicyId=self.policy_id))
        await self._call(ua.ActivateSessionRequest(Parameters=params), ua.ActivateSessionResponse)

    async def read(self, nodes: list[str]) -> None:
        ua = self.ua
        params = ua.ReadParameters(MaxAge=0, TimestampsToReturn=ua.TimestampsToReturn.Both, NodesToRead=[
            ua.ReadValueId(NodeId=ua.NodeId.from_string(node), AttributeId=ua.AttributeIds.Value) for node in nodes])
        await self._call(ua.ReadRequest(Parameters=params), ua.ReadResponse)

    async def browse(self, node: str) -> None:
        ua = self.ua
        description = ua.BrowseDescription(
            NodeId=ua.NodeId.from_string(node), BrowseDirection=ua.BrowseDirection.Forward,
            ReferenceTypeId=ua.NodeId(ua.ObjectIds.HierarchicalReferences), IncludeSubtypes=True,
            NodeClassMask=0, ResultMask=ua.BrowseResultMask.All)
        # The default view: no view id, and a null (1601-01-01) timestamp, not "now".
        view = ua.ViewDescription(Timestamp=ua.get_win_epoch())
        params = ua.BrowseParameters(View=view, RequestedMaxReferencesPerNode=0, NodesToBrowse=[description])
        await self._call(ua.BrowseRequest(Parameters=params), ua.BrowseResponse)

    async def subscribe(self, index: int, interval_ms: float) -> None:
        ua = self.ua
        params = ua.CreateSubscriptionParameters(
            RequestedPublishingInterval=interval_ms, RequestedLifetimeCount=300, RequestedMaxKeepAliveCount=10,
            MaxNotificationsPerPublish=0, PublishingEnabled=True, Priority=0)
        result = await self._call(ua.CreateSubscriptionRequest(Parameters=params), ua.CreateSubscriptionResponse)
        self.subscriptions[index] = result.SubscriptionId

    async def monitor(self, index: int, sampling_ms: float, nodes: list[str]) -> None:
        ua = self.ua
        items = []
        for node in nodes:
            self.handles += 1
            items.append(ua.MonitoredItemCreateRequest(
                ItemToMonitor=ua.ReadValueId(NodeId=ua.NodeId.from_string(node), AttributeId=ua.AttributeIds.Value),
                MonitoringMode=ua.MonitoringMode.Reporting,
                RequestedParameters=ua.MonitoringParameters(
                    ClientHandle=self.handles, SamplingInterval=sampling_ms, QueueSize=1, DiscardOldest=True)))
        params = ua.CreateMonitoredItemsParameters(
            SubscriptionId=self.subscriptions[index], TimestampsToReturn=ua.TimestampsToReturn.Both,
            ItemsToCreate=items)
        await self._call(ua.CreateMonitoredItemsRequest(Parameters=params), ua.CreateMonitoredItemsResponse)

    async def publish(self) -> None:
        ua = self.ua
        params = ua.PublishParameters(SubscriptionAcknowledgements=self.acks)
        self.acks = []
        result = await self._call(ua.PublishRequest(Parameters=params), ua.PublishResponse)
        if result.NotificationMessage.NotificationData:
            self.acks.append(ua.SubscriptionAcknowledgement(
                SubscriptionId=result.SubscriptionId, SequenceNumber=result.NotificationMessage.SequenceNumber))

    async def close(self) -> None:
        ua = self.ua
        await self._call(ua.CloseSessionRequest(DeleteSubscriptions=True), ua.CloseSessionResponse)
        request = ua.CloseSecureChannelRequest()
        request.RequestHeader.Timestamp = self.now()
        # The server answers CloseSecureChannel by closing the socket (Part 6, 7.1.4).
        self.protocol._send_request(request, CLIENT_TIMEOUT_S, ua.MessageType.SecureClose).cancel()
        self.drop()
        await asyncio.sleep(0.01)

    def drop(self) -> None:
        if self.protocol is not None and self.protocol.transport is not None:
            self.protocol.transport.close()
        self.protocol = None
