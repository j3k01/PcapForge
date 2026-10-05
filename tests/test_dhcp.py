"""DHCPv4: message format, how the composer delivers the recorded exchanges, and address conflict detection."""

import socket
from types import SimpleNamespace

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
