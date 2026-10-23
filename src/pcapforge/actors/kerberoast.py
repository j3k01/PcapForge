"""Kerberoasting (MITRE ATT&CK T1558.003).

A domain user on a managed workstation logs on normally (an AS exchange that yields a TGT) and then,
in a short burst, asks the KDC for Kerberos service tickets (TGS-REQ) for many service accounts'
Service Principal Names, requesting RC4-HMAC (etype 23) where a Windows client offers AES first. The
KDC answers with a TGS-REP whose service ticket is encrypted under the service account's key with the
requested etype; an attacker would crack those offline. This is the *observable pattern* only
(CONTRIBUTING.md "benign-equivalent rule"): the directory keys and ticket bytes are opaque
``rng.label_bytes`` output, there is no real cipher and nothing is cracked. The requests are normal,
correct Kerberos on the recording loopback; the tell is that one host asks for a run of RC4 service
tickets for distinct SPNs.

``easy`` requests many SPNs in seconds, RC4 only, from one host; ``medium`` requests fewer, interleaved
with legitimate AES service tickets; ``hard`` spreads the requests low-and-slow across the whole
capture with the user also doing normal domain work, RC4 only for the targeted service accounts.
"""

from __future__ import annotations

from pcapforge.actors import kerberos as krb, register
from pcapforge.actors.ad import USER_NAMES, DomainController, _Member
from pcapforge.actors.base import Actor
from pcapforge.plan import action_ref, host_ref
from pcapforge.scenario import ScenarioError

STEP_LOGON = (0.05, 0.25)       # logon -> the first service-ticket request (s)
NORMAL_SERVICES = ("ldap", "cifs")


@register
class KerberosRoast(Actor):
    """Kerberoasting from a domain workstation: a logon (AS exchange) then a burst of TGS-REQs for
    service accounts' SPNs, asking for RC4-HMAC.

    Params: ``dc`` (host running ``ad.dc`` with service accounts enabled), ``user`` (the logged-on
    account; drawn from the directory's user names when omitted), ``targets`` (how many SPNs to
    request; all enabled service accounts by default), ``normal_tickets`` (legitimate AES service
    tickets interleaved with the roast), ``start`` / ``spread`` (fraction of the capture: a tight
    spread is a burst, a wide one is low-and-slow)."""

    type = "kerberos.roast"

    def plan(self) -> None:
        plan, rng = self.plan_, self.rng
        host = self.hosts[0]
        if host.device.stack.name != "windows":
            raise ScenarioError(f"{self.type} needs a Windows host; '{host.id}' runs {host.device.stack.name}")
        dc_host = plan.topology.select(self.param("dc"))[0]
        self.dc = next((a for a in plan.actors
                        if isinstance(a, DomainController) and a.hosts[0].id == dc_host.id), None)
        if self.dc is None:
            raise ScenarioError(f"{self.type} '{self.id}': '{dc_host.id}' runs no ad.dc")
        d = self.dc.directory
        service_accounts = list(d.service_accounts)
        if not service_accounts:
            raise ScenarioError(f"{self.type} '{self.id}': the ad.dc on '{dc_host.id}' serves no service accounts; "
                                "enable them with its 'directory: {service_accounts: N}' param")

        user = self.param("user") or rng.choice(USER_NAMES)
        targets = min(int(self.param("targets", len(service_accounts))), len(service_accounts))
        rng.shuffle(service_accounts)
        chosen = service_accounts[:max(1, targets)]
        normal = int(self.param("normal_tickets", 0))

        start_lo, start_hi = self.span(self.param("start", [0.3, 0.5]))
        spread = max(0.0, min(1.0, float(self.param("spread", 0.05))))
        begin = plan.duration * rng.uniform(start_lo, start_hi)
        window = max(0.0, min(spread * plan.duration, plan.duration - begin - 1.0))
        tgt_time = -rng.uniform(300.0, krb.TICKET_LIFETIME * 0.5)   # a TGT cached from an earlier logon

        # The logon (AS exchange) that obtains the user's TGT, then the service-ticket requests: the
        # RC4 roast of each chosen SPN, optionally interleaved with legitimate AES service tickets.
        plan.add(begin, self.id, host.id, "krb.logon", user=user)
        events = [("roast", sa) for sa in chosen] + [("normal", None) for _ in range(normal)]
        rng.shuffle(events)
        step = window / max(1, len(events))
        t = begin + rng.uniform(*STEP_LOGON)
        roasts, first_roast = [], None
        for kind, sa in events:
            if kind == "roast":
                action = plan.add(t, self.id, host.id, "krb.roast", user=user, spn=list(sa.spn),
                                  target=sa.sam, tgt=tgt_time)
                roasts.append({"account": sa.sam, "spn": "/".join(sa.spn), "request": action_ref(action)})
                first_roast = first_roast or action
            else:
                plan.add(t, self.id, host.id, "krb.normal_tgs", user=user,
                         service=rng.choice(NORMAL_SERVICES), tgt=tgt_time)
            t += step + rng.uniform(0.0, step * 0.5 if step else 0.5)

        plan.event(first_roast, self.id,
                   f"{user} requests RC4 service tickets for {len(chosen)} SPNs from {host.name} (Kerberoasting)",
                   ["T1558.003"], host=host_ref(host.id), user=user, spn_count=len(chosen))
        plan.facts[self.id] = {
            "source": host_ref(host.id),
            "dc": host_ref(dc_host.id),
            "user": user,
            "realm": d.realm,
            "etype": krb.RC4_HMAC,
            "etype_name": "rc4-hmac",
            "spn_count": len(chosen),
            "service_count": len(chosen),
            "services": ["/".join(sa.spn) for sa in chosen],
            "accounts": [sa.sam for sa in chosen],
            "target_account": chosen[0].sam,
            "target_spn": "/".join(chosen[0].spn),
            "target_spn_class": chosen[0].spn[0],
            "target_spn_host": chosen[0].spn[1],
            "first_request": action_ref(first_roast),
            "requests": roasts,
        }

    def execute(self, action, rt) -> None:
        d = self.dc.directory
        host = rt.plan.topology.by_id[action.host]
        member = _Member(rt, d, host)
        a = action.args
        if action.op == "krb.logon":
            member.as_request(a["user"], preauth=True, tcp=True, started=rt.plan.start_epoch + action.t)
            return
        tgt = d.ticket(a["user"], d.spn("krbtgt"), a["tgt"])
        if action.op == "krb.roast":
            member.tgs_exchange(a["user"], tgt, tuple(a["spn"]), etypes=(krb.RC4_HMAC,))
        elif action.op == "krb.normal_tgs":
            member.tgs_exchange(a["user"], tgt, d.spn(a["service"]))
        else:
            raise ValueError(f"unknown operation {action.op}")
