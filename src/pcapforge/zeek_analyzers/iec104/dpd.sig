# IEC 60870-5-104 on any TCP port: a connection opens with the controlling station's STARTDT act
# (or a TESTFR act on an idle link), a 4-octet U-frame 68 04 <function> 00 00 00, answered by the
# controlled station's STARTDT / TESTFR con.

signature dpd_pcapforge_iec104_client {
  ip-proto == tcp
  payload /^\x68\x04[\x07\x43]\x00\x00\x00/
  tcp-state originator
}

signature dpd_pcapforge_iec104_server {
  ip-proto == tcp
  payload /^\x68\x04[\x0b\x83]\x00\x00\x00/
  tcp-state responder
  requires-reverse-signature dpd_pcapforge_iec104_client
  enable "PcapforgeIEC104"
}
