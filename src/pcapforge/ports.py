"""Unprivileged ports used while recording, mapped to their well-known ports on output."""

MODBUS = 15020
DNS = 15353
NTP = 15123
NBNS = 15137
NBDGM = 15138
SSDP = 11900
MDNS = 25353
LLMNR = 15355
MARKER = 9999

WELL_KNOWN = {MODBUS: 502, DNS: 53, NTP: 123, NBNS: 137, NBDGM: 138, SSDP: 1900, MDNS: 5353, LLMNR: 5355}
