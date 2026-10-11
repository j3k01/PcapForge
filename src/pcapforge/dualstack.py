"""Dual-stack site (scenario var ``ipv6: dual``): which hosts have global IPv6 addresses and which
of their conversations go over IPv6.

The router of a subnet that has an ``ipv6_router`` device advertises a global prefix there. The
Windows PCs and servers on such subnets (devices with a ``browser`` profile) were configured
(SLAAC) long before the capture, and the site DNS publishes their AAAA records. Windows prefers a
global IPv6 destination to IPv4 (RFC 6724 default policy: ``::/0`` precedence 40 over
``::ffff:0:0/96`` 35), so a Windows client that reaches another dual-stack Windows host by name
uses IPv6: in the shipped scenarios time sync with the DC and the historian's OPC UA session to
the SCADA server. DNS itself stays on the IPv4 resolver the hosts got over DHCPv4 / static
configuration (the RAs carry no RDNSS). PLCs (also those on embedded Windows), RTUs, drives and
building controllers are IPv4 only, and BACnet/IP and EtherNet/IP are IPv4 protocols, so
everything else stays IPv4. A host that joins the segment during the capture keeps IPv4 for its
conversations.

This is the plan-level decision; ``compose/ipv6.py`` draws the addresses and builds the frames.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pcapforge import ports
from pcapforge.actors.dhcp import JOIN_OP

if TYPE_CHECKING:
    from pcapforge.plan import Plan
    from pcapforge.topology import Host

DUAL = "dual"
# Recording ports of conversations that stay IPv4 between dual-stack hosts.
IPV4_ONLY = frozenset({ports.DNS, ports.BACNET, ports.ENIP, ports.ENIP_IO, ports.DHCP_SERVER, ports.DHCP_CLIENT})


def enabled(plan: Plan) -> bool:
    return plan.vars.get("ipv6") == DUAL


def routed_by_ipv6_router(plan: Plan, subnet: str) -> bool:
    """Whether the subnet's router advertises IPv6 (its device has ``ipv6_router``)."""
    return any(h.router and subnet in h.subnets and h.device.ipv6_router is not None for h in plan.topology.hosts)


def hosts(plan: Plan) -> frozenset[str]:
    """Ids of the hosts with global IPv6 addresses from before the capture (empty unless dual)."""
    if not enabled(plan):
        return frozenset()
    joining = {a.host for a in plan.actions if a.op == JOIN_OP}
    return frozenset(
        h.id for h in plan.topology.hosts
        if h.device.stack.ipv6 is not None and h.device.browser is not None and not h.router
        and h.id not in joining and routed_by_ipv6_router(plan, h.subnets[0]))


def carries(dual: frozenset[str], client: Host, server, server_port: int) -> bool:
    """Whether a recorded conversation between ``client`` and ``server`` goes over IPv6."""
    return (getattr(server, "id", None) in dual and client.id in dual and server_port not in IPV4_ONLY
            and client.id != server.id)
