"""Unprivileged ports used while recording, mapped to their well-known ports on output."""

MODBUS = 15020
DNS = 15353
NTP = 15123
NBNS = 15137
NBDGM = 15138
SSDP = 11900
MDNS = 25353
LLMNR = 15355
S7 = 10102        # ISO-TSAP (S7comm over RFC 1006)
OPCUA = 14840     # OPC UA binary (opc.tcp)
IEC104 = 12404    # IEC 60870-5-104
DNP3 = 20020      # DNP3 over TCP
BACNET = 17808    # BACnet/IP (UDP, BVLC)
ENIP = 14818      # EtherNet/IP encapsulation (CIP explicit messaging, TCP and UDP)
ENIP_IO = 12222   # EtherNet/IP implicit (class 0/1) I/O, UDP
DHCPV6_CLIENT = 20546
DHCPV6_SERVER = 20547
DHCP_SERVER = 10067  # BOOTP / DHCPv4 server
DHCP_CLIENT = 10068  # BOOTP / DHCPv4 client
KERBEROS = 10088     # Kerberos KDC (UDP and TCP)
LDAP = 10389         # LDAP (TCP) and CLDAP (UDP)
SMB = 10445          # SMB 2/3 direct TCP
HTTPS = 10443        # HTTP over TLS
HTTP = 10080         # plain HTTP (external file host / upload sink)
WSUS = 18530         # WSUS HTTP (commonPort and contentPort)
DISCARD = 10009      # Discard protocol (RFC 863) sink service, UDP/TCP
# Ports a reconnaissance TCP sweep probes but no pcapforge service serves. Mapped to their
# well-known numbers so the sweep reads as 22 / 135 / 139 / 3389 on output (closed or, on a
# host that drops unsolicited SYNs, filtered).
SCAN_SSH = 10022
SCAN_RPC = 10135
SCAN_NETBIOS = 10139
SCAN_RDP = 13389
MARKER = 9999

WELL_KNOWN = {MODBUS: 502, DNS: 53, NTP: 123, NBNS: 137, NBDGM: 138, SSDP: 1900, MDNS: 5353, LLMNR: 5355,
              S7: 102, OPCUA: 4840, IEC104: 2404, DNP3: 20000, BACNET: 47808, ENIP: 44818, ENIP_IO: 2222,
              DHCPV6_CLIENT: 546, DHCPV6_SERVER: 547, DHCP_SERVER: 67, DHCP_CLIENT: 68, KERBEROS: 88, LDAP: 389,
              SMB: 445, HTTPS: 443, HTTP: 80, WSUS: 8530, DISCARD: 9}
WELL_KNOWN.update({SCAN_SSH: 22, SCAN_RPC: 135, SCAN_NETBIOS: 139, SCAN_RDP: 3389})
