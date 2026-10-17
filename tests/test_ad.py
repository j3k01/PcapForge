"""Active Directory background: the member's ticket cache and SMB connection reuse, the KDC's
answers, and a recorded logon with its Group Policy processing."""

import json
import subprocess
from types import SimpleNamespace

import pytest

from pcapforge.actors import ad, der, kerberos as krb
from pcapforge.pipeline import generate
from pcapforge.plan import build_plan
from pcapforge.scenario import find
from pcapforge.tools import MIN_TSHARK, find_tool, tshark_version

SCENARIO = "ot-baseline-operations"


def member_actions(plan):
    return [a for a in plan.actions if a.op.startswith("ad.")]


@pytest.mark.parametrize("difficulty,seed", [("medium", "1"), ("hard", "1"), ("hard", "2"), ("hard", "3")])
def test_members_use_cached_tickets_until_they_expire_and_reuse_an_smb_connection_while_it_is_open(difficulty, seed):
    plan = build_plan(find(SCENARIO), difficulty, seed)
    issued = {}                                    # (host, account, kind) -> time the ticket was obtained
    smb_open: dict[str, float] = {}                # host -> time of the connection's last use
    for a in member_actions(plan):
        args = a.args
        if a.op == "ad.as" and args["tcp"]:
            issued[(a.host, args["account"], "tgt")] = a.t
        elif a.op == "ad.tgs":
            # A TGS-REQ presents a TGT that is still valid: from before the capture or from an AS exchange.
            assert args["tgt"] < 0 or args["tgt"] == issued[(a.host, args["account"], "tgt")]
            assert a.t < args["tgt"] + krb.TICKET_LIFETIME
            issued[(a.host, args["account"], args["service"])] = a.t
        elif a.op in ("ad.ldap", "ad.smb") and (a.op == "ad.ldap" or args["session"]):
            service = "ldap" if a.op == "ad.ldap" else "cifs"
            # The service ticket is the one just obtained, or one held from before the capture.
            assert args["ticket"] < 0 or args["ticket"] == issued[(a.host, args["account"], service)]
        if a.op == "ad.smb":
            assert args["connect"] == (a.host not in smb_open)
            if not args["connect"]:
                assert a.t - smb_open[a.host] < ad.KEEP_CONN + 30.0
            smb_open[a.host] = a.t
        elif a.op == "ad.smb_close":
            last_use = smb_open.pop(a.host)
            assert a.phase == "teardown" or a.t - last_use >= ad.KEEP_CONN
    facts = plan.facts["domain_members"]
    assert len(facts["logons"]) == 1 and not facts["logons"][0]["user"].endswith("$")


def test_a_logon_runs_the_whole_as_exchange_and_its_first_policy_refresh_asks_for_service_tickets():
    plan = build_plan(find(SCENARIO), "medium", "1")
    logon = plan.facts["domain_members"]["logons"][0]
    user = logon["user"]
    steps = [a for a in member_actions(plan) if a.args.get("account") == user]
    kinds = [(a.op, a.args.get("preauth"), a.args.get("tcp"), a.args.get("service")) for a in steps[:9]]
    assert kinds == [("ad.cldap", None, None, None),
                     ("ad.as", False, False, None), ("ad.as", True, False, None), ("ad.as", True, True, None),
                     ("ad.tgs", None, None, "host"),
                     ("ad.cldap", None, None, None), ("ad.tgs", None, None, "ldap"), ("ad.ldap", None, None, None),
                     ("ad.tgs", None, None, "cifs")]
    assert all(a.t < b.t for a, b in zip(steps, steps[1:]))


@pytest.fixture()
def domain():
    plan = build_plan(find(SCENARIO), "medium", "kdc")
    dc = next(a for a in plan.actors if a.type == "ad.dc")
    rt = SimpleNamespace(plan=plan, clock=SimpleNamespace(t=50.0), clients={})
    dc.rt = rt
    member = ad._Member(rt, dc.directory, plan.topology.by_id["ews"])
    return dc, member


def as_request(dc, client, key):
    d = dc.directory
    body = krb.req_body(krb.KDC_OPT_AS, d.realm, krb.principal(krb.NT_SRV_INST, *d.spn("krbtgt")), 1,
                        cname=krb.principal(krb.NT_PRINCIPAL, client))
    pa = []
    if key is not None:
        stamp = krb.seal("stamp", krb.enc_timestamp_size(), key)
        pa.append(krb.padata(krb.PA_ENC_TIMESTAMP, krb.encrypted(krb.AES256, stamp)))
    return krb.kdc_req(krb.AS_REQ, pa, body)


def error_code(reply):
    return der.to_int(der.fields(der.read(der.read(reply)[1])[1])[6])


def test_the_kdc_asks_for_pre_authentication_and_rejects_a_wrong_key(domain):
    dc, _ = domain
    d = dc.directory
    reply = dc.kdc(as_request(dc, "a.nowak", None), tcp=False)
    assert error_code(reply) == krb.KDC_ERR_PREAUTH_REQUIRED
    assert d.salt("a.nowak").encode() in reply                       # PA-ETYPE-INFO2 tells the salt
    reply = dc.kdc(as_request(dc, "a.nowak", d.key("j.smith")), tcp=True)
    assert error_code(reply) == krb.KDC_ERR_PREAUTH_FAILED


def test_an_as_rep_with_a_pac_is_too_big_for_udp_and_its_tgt_is_accepted_by_the_kdc(domain):
    dc, member = domain
    d = dc.directory
    request = as_request(dc, "EWS-STW-01$", d.key("EWS-STW-01$"))
    assert error_code(dc.kdc(request, tcp=False)) == krb.KRB_ERR_RESPONSE_TOO_BIG
    reply = dc.kdc(request, tcp=True)
    assert der.read(reply)[0] == 0x60 | krb.AS_REP
    tgt = der.fields(der.read(der.read(reply)[1])[1])[5]
    assert d.holder(krb.ticket_cipher(tgt), "krbtgt").client == "EWS-STW-01$"
    member._kdc = lambda message, tcp: dc.kdc(message, tcp)
    ticket = member.tgs_exchange("EWS-STW-01$", tgt, d.spn("ldap"))
    assert d.holder(krb.ticket_cipher(ticket), "ldap").service == d.spn("ldap")


def test_the_kdc_refuses_a_ticket_it_did_not_issue(domain):
    dc, member = domain
    d = dc.directory
    forged = krb.ticket(d.realm, krb.principal(krb.NT_SRV_INST, *d.spn("krbtgt")), 2,
                        krb.seal("forged", 900, d.key("someone-else")))
    d.issued[krb.ticket_cipher(forged)] = ad.Issued("EWS-STW-01$", d.spn("krbtgt"), b"k" * 32, "forged")
    member._kdc = lambda message, tcp: dc.kdc(message, tcp)
    with pytest.raises(RuntimeError):
        member.tgs_exchange("EWS-STW-01$", forged, d.spn("ldap"))


capture_tools = (find_tool("tshark") and (find_tool("dumpcap") or find_tool("tcpdump"))
                 and tshark_version() >= MIN_TSHARK)


def tshark(pcap, display_filter, *fields):
    out = subprocess.run([find_tool("tshark"), "-n", "-r", str(pcap), "-Y", display_filter, "-T", "fields",
                          *[arg for f in fields for arg in ("-e", f)]],
                         capture_output=True, text=True, check=True).stdout
    return [line.split("\t") for line in out.splitlines()]


@pytest.mark.skipif(not capture_tools, reason="requires tshark >= 4.4 and dumpcap/tcpdump with loopback capture rights")
def test_a_recorded_logon_and_its_group_policy_decode_as_windows_sends_them(tmp_path):
    result = generate(find(SCENARIO), "medium", "pytest-ad", tmp_path, duration=900.0)
    assert result.report.ok, [c for c in result.report.checks if not c["ok"]]
    answers = json.loads(result.answers.read_text(encoding="utf-8"))
    logon = answers["facts"]["domain_members"]["logons"][0]
    user, ews = logon["user"], logon["host"]["ip"]
    pcap = result.pcap

    # AS-REQ without pre-authentication, with it over UDP (reply too big), then over TCP. KRB-ERRORs carry
    # no client name: take the EWS's AS messages from the user's first AS-REQ on.
    rows = tshark(pcap, f'ip.addr == {ews} && kerberos.msg_type in {{10, 11, 30}}', "kerberos.msg_type",
                  "kerberos.error_code", "tcp.port", "kerberos.padata_type", "kerberos.CNameString")
    start = next(i for i, row in enumerate(rows) if row[4] == user)
    exchange = rows[start:start + 6]
    assert [(row[0], row[1]) for row in exchange] == [("10", ""), ("30", "25"), ("10", ""), ("30", "52"),
                                                       ("10", ""), ("11", "")]
    assert [bool(row[2]) for row in exchange] == [False] * 4 + [True] * 2
    assert "2" in exchange[2][3].split(",") and "2" not in exchange[0][3].split(",")

    # The user's service tickets, then a Kerberos-authenticated LDAP bind and SMB session from the EWS.
    names = {name for row in tshark(pcap, f'kerberos.msg_type == 12 && ip.src == {ews}', "kerberos.SNameString")
             for name in row[0].split(",")}                # the TGT's krbtgt name, then the requested one
    assert {"host", "ldap", "cifs"} <= names
    assert tshark(pcap, f'ldap.mechanism == "GSS-SPNEGO" && ip.src == {ews}', "frame.number")
    assert tshark(pcap, f'smb2.cmd == 1 && kerberos.msg_type == 14 && ip.src == {ews}', "frame.number")
    # Every GPO's gpt.ini, opened on a signed session (tshark 4.6 names the file on the Create response).
    opened = tshark(pcap, 'smb2.cmd == 5 && smb2.flags.response == 1', "smb2.filename", "smb2.flags.signature")
    assert opened and all(name.endswith("gpt.ini") and signed in ("1", "True") for name, signed in opened)
