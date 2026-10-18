"""DHCPv4: message format, how the composer delivers the recorded exchanges, and address conflict detection."""

import socket
from types import SimpleNamespace

import pytest

from pcapforge import ports
from pcapforge.actors.dhcp import (
    ACK, BOOTREPLY, BOOTREQUEST, BROADCAST_FLAG, CLIENT_ID, DISCOVER, HOST_NAME, INFORM, MESSAGE_TYPE, MIN_SIZE,
    OFFER, RELEASE, REQUEST, ROUTER, SERVER_ID, encode, parse, placeholder_mac,
)
from pcapforge.compose import dhcp
from pcapforge.compose.packets import UDP
from pcapforge.rng import Rng

CLIENT_LOOPBACK, SERVER_LOOPBACK = "127.77.0.20", "127.77.0.12"
CHADDR = placeholder_mac(CLIENT_LOOPBACK)
ip = socket.inet_aton


def message(op, kind, *, flags=0, ciaddr="0.0.0.0", yiaddr="0.0.0.0", options=()):
    return encode(op, 0x1234ABCD, CHADDR, [(MESSAGE_TYPE, bytes((kind,))), *options], flags=flags,
                  ciaddr=ip(ciaddr), yiaddr=ip(yiaddr))


def packet(payload, side, style="dhcpcd", server_port=ports.DHCP_SERVER):
    flow = SimpleNamespace(proto=UDP, server_port=server_port, hosts=(SimpleNamespace(id="laptop"),
                                                                       SimpleNamespace(id="firewall")))
    return SimpleNamespace(flow=flow, side=side, payload=payload, time=100.0,
                           action=SimpleNamespace(args={"style": style}))


def test_messages_round_trip_and_are_padded_to_the_bootp_minimum():
    payload = message(BOOTREQUEST, DISCOVER, flags=BROADCAST_FLAG,
                      options=[(CLIENT_ID, b"\x01" + CHADDR), (HOST_NAME, b"raspberrypi")])
    assert len(payload) == MIN_SIZE
    parsed = parse(payload)
    assert (parsed.op, parsed.xid, parsed.type, parsed.flags) == (BOOTREQUEST, 0x1234ABCD, DISCOVER, BROADCAST_FLAG)
    assert parsed.chaddr == CHADDR and parsed.options[HOST_NAME] == b"raspberrypi"
    assert parse(b"\x01" * 100) is None and parse(bytes(300)) is None  # too short / no magic cookie


def test_a_client_without_an_address_broadcasts_from_0_0_0_0():
    for kind in (DISCOVER, REQUEST):
        assert dhcp.delivery(packet(message(BOOTREQUEST, kind), 0)) == dhcp.Delivery(dhcp.UNSPECIFIED_BYTES, True)
    # DHCPINFORM: from its own address to the limited broadcast address.
    assert dhcp.delivery(packet(message(BOOTREQUEST, INFORM, ciaddr="10.1.2.3"), 0)) == dhcp.Delivery(None, True)
    # Renewal and release: ordinary unicast to the server (with ARP when needed).
    assert dhcp.delivery(packet(message(BOOTREQUEST, REQUEST, ciaddr="10.1.2.3"), 0)) is None
    assert dhcp.delivery(packet(message(BOOTREQUEST, RELEASE, ciaddr="10.1.2.3"), 0)) is None


def test_the_server_answers_on_broadcast_only_when_the_client_asked_for_it():
    offer = message(BOOTREPLY, OFFER, yiaddr="10.1.2.3")
    assert dhcp.delivery(packet(offer, 1)) == dhcp.Delivery(None, False)  # unicast to yiaddr, no ARP
    flagged = message(BOOTREPLY, OFFER, flags=BROADCAST_FLAG, yiaddr="10.1.2.3")
    assert dhcp.delivery(packet(flagged, 1, style="windows")) == dhcp.Delivery(None, True)
    renewed = message(BOOTREPLY, ACK, ciaddr="10.1.2.3", yiaddr="10.1.2.3")
    assert dhcp.delivery(packet(renewed, 1)) is None


def test_other_udp_traffic_is_not_dhcp():
    assert dhcp.delivery(packet(message(BOOTREQUEST, DISCOVER), 0, server_port=ports.DNS)) is None
    assert dhcp.delivery(packet(b"not a bootp message", 0)) is None


def test_rewrite_puts_the_final_addresses_and_the_client_mac_into_the_payload():
    final = {ip(CLIENT_LOOPBACK): ip("10.1.2.200"), ip(SERVER_LOOPBACK): ip("10.1.2.1")}
    mac = bytes.fromhex("b827eb23266d")
    payload = message(BOOTREPLY, ACK, yiaddr=CLIENT_LOOPBACK,
                      options=[(SERVER_ID, ip(SERVER_LOOPBACK)), (ROUTER, ip(SERVER_LOOPBACK) + ip("127.0.0.1")),
                               (CLIENT_ID, b"\x01" + CHADDR)])
    out = parse(dhcp.rewrite(payload, final.get, mac))
    assert out.yiaddr == ip("10.1.2.200") and out.ciaddr == bytes(4)
    assert out.chaddr == mac and out.options[CLIENT_ID] == b"\x01" + mac
    assert out.options[SERVER_ID] == ip("10.1.2.1")
    assert out.options[ROUTER] == ip("10.1.2.1") + ip("127.0.0.1")  # unknown addresses stay


def acd_frames(style):
    iface = SimpleNamespace(subnet="control", mac="b8:27:eb:23:26:6d", ip="10.1.2.200")
    topology = SimpleNamespace(sensor="control", address_towards=lambda host, peer: iface)
    plan = SimpleNamespace(topology=topology, actions=[])
    ack = packet(message(BOOTREPLY, ACK, yiaddr="10.1.2.200"), 1, style=style)
    return dhcp.Dhcp(plan, Rng("test", "dhcp")).after(ack)


def arp_fields(frame):
    return frame[22:28].hex(), socket.inet_ntoa(frame[28:32]), socket.inet_ntoa(frame[38:42])


def test_a_new_lease_is_probed_with_arp_before_it_is_announced():
    for style, probes, announcements, wait in (("dhcpcd", 3, 2, 2.0), ("windows", 3, 1, 1.0)):
        frames = acd_frames(style)
        assert len(frames) == probes + announcements
        assert all(f[:6] == b"\xff" * 6 and len(f) == 60 for _, f in frames)
        fields = [arp_fields(f) for _, f in frames]
        assert fields[:probes] == [("b827eb23266d", "0.0.0.0", "10.1.2.200")] * probes
        assert fields[probes:] == [("b827eb23266d", "10.1.2.200", "10.1.2.200")] * announcements
        times = [t for t, _ in frames]
        assert times == sorted(times) and times[0] >= 100.0
        assert times[probes] - times[probes - 1] >= wait * 0.99  # ANNOUNCE_WAIT


def test_only_the_ack_of_a_new_lease_triggers_address_conflict_detection():
    iface = SimpleNamespace(subnet="control", mac="b8:27:eb:23:26:6d", ip="10.1.2.200")
    topology = SimpleNamespace(sensor="control", address_towards=lambda host, peer: iface)
    leases = dhcp.Dhcp(SimpleNamespace(topology=topology, actions=[]), Rng("test", "dhcp"))
    assert leases.after(packet(message(BOOTREPLY, OFFER, yiaddr="10.1.2.200"), 1)) == []
    assert leases.after(packet(message(BOOTREPLY, ACK, ciaddr="10.1.2.200", yiaddr="10.1.2.200"), 1)) == []
    assert leases.after(packet(message(BOOTREQUEST, REQUEST), 0)) == []


def test_a_windows_host_that_joins_and_leaves_chatters_only_while_connected():
    from pcapforge.actors.dhcp import DISCOVER_OP
    from pcapforge.plan import build_plan
    from pcapforge.scenario import find

    plan = build_plan(find("ot-modbus-write-manipulation"), "medium", "joiner")
    laptop = next(h for h in plan.topology.hosts if h.group == "svc_laptop")
    joined = next(a.t for a in plan.actions if a.op == DISCOVER_OP and a.host == laptop.id)
    left = next(a.t for a in plan.actions if a.op == "dhcp.release" and a.host == laptop.id)
    assert laptop.arrives and laptop.present == pytest.approx((joined, left), abs=1e-6)
    chatter = [a for a in plan.actions if a.actor == "laptop_chatter"]
    assert chatter and all(joined < a.t < left for a in chatter)
    # Name resolution, discovery and announcements wait until its address is configured.
    assert min(a.t for a in chatter if a.op != "dhcpv6.solicit") >= joined + 6.0
    # Its IPv6 interface comes up with the link; the DHCPv6 client starts over (RFC 8415 backoff).
    solicits = [a for a in chatter if a.op == "dhcpv6.solicit"]
    assert solicits and joined <= solicits[0].args["up"] < joined + 0.5
    assert solicits[0].args["elapsed"] == 0 and solicits[1].t - solicits[0].t < 2.0
    # Browser announcements of a freshly started host: one minute apart, then a minute longer each time.
    announced = [a for a in chatter if a.op == "browser.announce"]
    assert [a.args["period_ms"] for a in announced[:3]] == [60000, 120000, 180000]
    assert all(p.args["period_ms"] / 1000 <= b.t - p.t <= p.args["period_ms"] / 1000 + 2.5
               for p, b in zip(announced, announced[1:]))


def it_plan(level="medium", seed="dhcp"):
    from pcapforge.plan import build_plan
    from pcapforge.scenario import find

    return build_plan(find("it-baseline-operations"), level, seed)


def test_a_windows_server_orders_its_options_like_windows_and_answers_the_client_fqdn():
    from pcapforge.actors.dhcp import CLIENT_FQDN, PARAMETERS, REQUESTED_IP, STYLES, _DhcpServerProtocol

    plan = it_plan()
    server = next(a for a in plan.actors if a.id == "dhcp_service")
    pc = plan.topology.by_id["pc1"]
    sent = []
    protocol = _DhcpServerProtocol([server], server.hosts[0].loopback)
    protocol.transport = SimpleNamespace(sendto=lambda data, addr: sent.append(parse(data)))
    chaddr = placeholder_mac(pc.loopback)
    asked = (PARAMETERS, bytes(STYLES["windows"].parameters))
    fqdn = b"\x00\x00\x00" + f"{pc.name}.{plan.topology.domain}".encode()
    protocol.datagram_received(encode(BOOTREQUEST, 1, chaddr, [(MESSAGE_TYPE, bytes((DISCOVER,))), asked]), None)
    protocol.datagram_received(encode(BOOTREQUEST, 2, chaddr, [(MESSAGE_TYPE, bytes((REQUEST,))),
                                                              (REQUESTED_IP, ip(pc.loopback)), (CLIENT_FQDN, fqdn),
                                                              asked]), None)
    offer, ack = sent
    assert list(offer.options) == [53, 1, 58, 59, 51, 54, 3, 6, 15]
    assert list(ack.options) == [53, 58, 59, 51, 54, 1, 81, 3, 6, 15]
    assert ack.options[CLIENT_FQDN] == b"\x00\xff\xff" + fqdn[3:]
    assert int.from_bytes(ack.options[51], "big") == 8 * 86400  # the Windows Server scope default
    # The DC does not route: the gateway it hands out is the subnet's router.
    assert ack.options[ROUTER] == ip(plan.topology.by_id["firewall"].loopback)


def test_a_host_that_held_a_lease_confirms_it_and_talks_only_once_its_address_is_configured():
    from pcapforge.actors.base import JOIN_SETTLE
    from pcapforge.actors.dhcp import REBOOT_OP

    plan = it_plan()
    for pc in plan.topology.groups["pc"]:
        own = sorted((a for a in plan.actions if a.host == pc.id), key=lambda a: a.t)
        joined = own[0]
        assert joined.op == REBOOT_OP and pc.arrives and pc.present[0] == pytest.approx(joined.t, abs=1e-6)
        assert not any(a.op in ("dhcp.discover", "dhcp.request") for a in own)  # INIT-REBOOT, no DORA
        talk = [a for a in own if a.actor in ("name_lookups", "time_sync", "windows_chatter")
                and a.op != "dhcpv6.solicit"]
        assert talk and min(a.t for a in talk) >= joined.t + JOIN_SETTLE


def test_a_relay_agent_carries_the_exchange_between_the_client_subnet_and_the_server():
    plan = it_plan()
    topo = plan.topology
    topo.assign_addresses(Rng("test", "addresses"))
    dc, pc, fw = topo.by_id["dc"], topo.by_id["pc1"], topo.by_id["firewall"]
    giaddr = ip(fw.interface_on("office").ip)
    leases = dhcp.Dhcp(plan, Rng("test", "dhcp"))
    flow = SimpleNamespace(proto=UDP, server_port=ports.DHCP_SERVER, hosts=(pc, dc))

    def at(payload, side):
        return leases.delivery(SimpleNamespace(flow=flow, side=side, payload=payload))

    discover = message(BOOTREQUEST, DISCOVER, flags=BROADCAST_FLAG)
    offer = message(BOOTREPLY, OFFER, flags=BROADCAST_FLAG, yiaddr="10.1.2.3",
                    options=[(51, (3600).to_bytes(4, "big"))])
    renewal = message(BOOTREQUEST, REQUEST, ciaddr="10.1.2.3")
    # On the clients' subnet: the client broadcasts, the relay answers from its address there.
    topo.sensor = "office"
    assert at(discover, 0) == dhcp.Delivery(dhcp.UNSPECIFIED_BYTES, True)
    reply = at(offer, 1)
    assert (reply.source, reply.broadcast, reply.relay, reply.giaddr) == (giaddr, True, fw, giaddr)
    assert reply.agent_info is None  # the relay strips option 82 before the clients' side
    assert at(renewal, 0) is None  # a client with an address talks to the server directly
    # On the server's subnet: relay to server and back, unicast port 67 to 67, giaddr set.
    topo.sensor = "servers"
    forwarded = at(discover, 0)
    assert forwarded.source == ip(fw.interface_on("servers").ip) and not forwarded.broadcast
    assert (forwarded.ports, forwarded.giaddr, forwarded.hops, forwarded.relay) == ((67, 67), giaddr, 1, fw)
    answered = at(offer, 1)
    assert (answered.dest, answered.ports, answered.relay, answered.broadcast) == (giaddr, (67, 67), None, False)
    # Option 82 toward the server and in its echo: circuit ID (VLAN 0, relay, port), remote ID (the client's MAC).
    mac = bytes.fromhex(pc.interface_on("office").mac.replace(":", ""))
    port = fw.subnets.index("office") + 1
    assert forwarded.agent_info == answered.agent_info == b"\x01\x04\x00\x00\x00" + bytes((port,)) + b"\x02\x06" + mac
    padded = dhcp.with_agent_info(discover, forwarded.agent_info)
    assert len(padded) == len(discover) and parse(padded).options[82] == forwarded.agent_info
    assert list(parse(padded).options)[-1] == 82
