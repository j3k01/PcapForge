"""Answer key (``answers.json``) and student handout (``briefing.md``) for a composed capture."""

from __future__ import annotations

import datetime as dt
import hashlib
from pathlib import Path
from typing import TYPE_CHECKING, Any

from pcapforge import __version__
from pcapforge.plan import Action, Plan
from pcapforge.process import ProcessProfile
from pcapforge.scenario import ScenarioError, evaluate_when, lookup, resolve
from pcapforge.topology import Host

if TYPE_CHECKING:
    from pcapforge.compose import ComposeResult

SCHEMA = "pcapforge/answers@1"
DEFAULT_POINTS = 10


def iso_utc(epoch: float) -> str:
    return dt.datetime.fromtimestamp(epoch, dt.UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sensor_subnet(plan: Plan) -> str:
    return str(plan.topology.subnets[plan.topology.sensor].network)


class _Expander:
    """Deep-copies plan data, replacing ``$host`` / ``$action`` references with answer values."""

    def __init__(self, plan: Plan, result: ComposeResult) -> None:
        self.plan = plan
        self.result = result
        topo = plan.topology
        # The source MAC the sensor sees depends only on the sender's side of the SPAN
        # port, so any host on the sensor subnet serves as the peer.
        self.sensor_peer = next((h for h in topo.hosts if topo.sensor in h.subnets), None)

    def host(self, host_id: str) -> dict:
        topo = self.plan.topology
        host: Host = topo.by_id[host_id]
        iface = host.interface_on(topo.sensor) or host.interfaces[0]
        observed = topo.l2_view(host, self.sensor_peer or host)[0]
        return {
            "id": host.id,
            "role": host.group,
            "name": host.name,
            "fqdn": f"{host.name.lower()}.{topo.domain}",
            "ip": iface.ip,
            "mac": iface.mac,
            "observed_mac": observed,
            "vendor": host.device.vendor,
            "device": host.device.name,
        }

    def action(self, action: Action) -> dict:
        frame = self.result.action_frames.get(action.id)
        epoch = self.result.action_times.get(action.id)
        return {
            "action": action.id,
            "frame": frame,
            "time": iso_utc(epoch) if epoch is not None else None,
            "epoch": round(epoch, 6) if epoch is not None else None,
        }

    def __call__(self, value: Any) -> Any:
        if isinstance(value, dict):
            if set(value) == {"$host"}:
                return self.host(value["$host"])
            if set(value) == {"$action"}:
                return self.action(value["$action"])
            return {k: self(v) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [self(v) for v in value]
        if isinstance(value, Action):
            return self.action(value)
        return value


def _questions(plan: Plan, ctx: dict) -> list[dict]:
    out = []
    for spec in plan.scenario.doc["questions"]:
        if not evaluate_when(spec.get("when"), ctx):
            continue
        try:
            entry: dict[str, Any] = {
                "id": spec["id"],
                "text": resolve(spec["text"], ctx),
                "type": spec.get("type", "text"),
                "answer": resolve(spec["answer"], ctx),
            }
            if "accept" in spec:
                entry["accept"] = resolve(spec["accept"], ctx)
            if "tolerance_s" in spec:
                entry["tolerance_s"] = spec["tolerance_s"]
            entry["points"] = spec.get("points", DEFAULT_POINTS)
            if "hint" in spec:
                entry["hint"] = resolve(spec["hint"], ctx)
            checks = []
            if "check" in spec:
                if "foreach" in spec:
                    items = lookup(ctx, spec["foreach"])
                    if not isinstance(items, list):
                        raise ScenarioError(f"foreach '{spec['foreach']}' is not a list")
                    contexts = [{**ctx, "item": item} for item in items]
                else:
                    contexts = [ctx]
                for item_ctx in contexts:
                    check = resolve(spec["check"], item_ctx)
                    checks.append({"filter": check["filter"],
                                   "expect": {k: int(v) for k, v in check["expect"].items()}})
            entry["checks"] = checks
            if "hunt" in spec:
                entry["hunt"] = resolve(spec["hunt"], ctx)
        except ScenarioError as exc:
            raise ScenarioError(f"question '{spec['id']}': {exc}") from None
        out.append(entry)
    return out


def build_answers(plan: Plan, result: ComposeResult) -> dict:
    topo = plan.topology
    expand = _Expander(plan, result)
    facts = expand(plan.facts)
    ctx = {"vars": plan.vars, "facts": facts}
    incident_actors = {a.id for a in plan.actors if a.incident}

    timeline = []
    for event in plan.events:
        epoch = result.action_times.get(event.action.id)
        if epoch is None:
            continue
        timeline.append({
            "time": iso_utc(epoch),
            "epoch": round(epoch, 6),
            "frame": result.action_frames.get(event.action.id),
            "actor": event.actor,
            "title": event.title,
            "techniques": list(event.techniques),
            "details": expand(event.details),
            "incident": event.actor in incident_actors,
        })
    timeline.sort(key=lambda e: (e["epoch"], e["frame"] or 0))

    iocs = []
    for actor in plan.actors:
        if not actor.incident:
            continue
        actor_facts = facts.get(actor.id, {})
        for role in ("source", "target"):
            host = actor_facts.get(role)
            if not isinstance(host, dict) or "ip" not in host:
                continue
            iocs.append({"type": "ip", "value": host["ip"], "role": role, "actor": actor.id})
            iocs.append({"type": "mac", "value": host["observed_mac"] if role == "source" else host["mac"],
                         "role": role, "actor": actor.id})
            iocs.append({"type": "hostname", "value": host["name"], "role": role, "actor": actor.id})
        for event in timeline:
            if event["incident"] and event["actor"] == actor.id:
                iocs.append({"type": "event", "value": event["title"], "actor": actor.id,
                             "time": event["time"], "frame": event["frame"],
                             "techniques": event["techniques"]})

    doc = plan.scenario.doc
    return {
        "schema": SCHEMA,
        "generator": {"name": "pcapforge", "version": __version__},
        "scenario": {
            "id": plan.scenario.id,
            "title": plan.scenario.title,
            "line": plan.scenario.line,
            "difficulty": plan.difficulty,
            "seed": plan.seed,
            "base_seed": plan.base_seed,
            "summary": " ".join(doc.get("summary", "").split()),
        },
        "capture": {
            "file": result.path.name,
            "sha256": sha256_file(result.path),
            "packets": result.packets,
            "start": iso_utc(result.first_epoch),
            "end": iso_utc(result.last_epoch),
            "duration_s": round(result.last_epoch - result.first_epoch, 6),
            "sensor_subnet": sensor_subnet(plan),
        },
        "topology": {
            "site_name": topo.site_name,
            "domain": topo.domain,
            "subnets": topo.describe_subnets(),
            "hosts": topo.describe(),
        },
        "actors": [{"id": a.id, "type": a.type, "incident": a.incident, "hosts": [h.id for h in a.hosts]}
                   for a in plan.actors],
        "mitre": [{k: v for k, v in m.items() if k != "when"}
                  for m in doc.get("mitre", []) if evaluate_when(m.get("when"), ctx)],
        "facts": facts,
        "iocs": iocs,
        "timeline": timeline,
        "questions": _questions(plan, ctx),
    }


# --- handout -----------------------------------------------------------------------

def _cell(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def _table(header: list[str], rows: list[list[Any]]) -> list[str]:
    lines = ["| " + " | ".join(header) + " |", "|" + "|".join("---" for _ in header) + "|"]
    lines += ["| " + " | ".join(_cell(c) for c in row) + " |" for row in rows]
    return lines


def _number(value: float) -> str:
    return f"{value:g}"


def write_handout(plan: Plan, answers: dict, out_dir: Path) -> Path:
    """Student-facing ``briefing.md``: briefing, asset inventory, register maps, questions."""
    topo = plan.topology
    subnet = answers["capture"]["sensor_subnet"]
    lines = [f"# {plan.scenario.title}", ""]

    briefing = plan.scenario.doc.get("briefing") or plan.scenario.doc.get("summary", "")
    process = plan.vars.get("process")
    title = ProcessProfile(process).title if isinstance(process, str) else ""
    process_title = title[:1].lower() + title[1:]
    for key, value in (("site_name", topo.site_name), ("domain", topo.domain), ("sensor_subnet", subnet),
                       ("process_title", process_title)):
        briefing = briefing.replace("{" + key + "}", value)
    lines += [briefing.strip(), ""]

    capture = answers["capture"]
    lines += [f"Capture: `{capture['file']}` ({capture['packets']} packets, "
              f"SHA-256 `{capture['sha256']}`).", ""]

    used = {h.id for a in plan.actors if not a.incident for h in a.hosts}
    lines += ["## Asset inventory", ""]
    rows = []
    for host in topo.hosts:
        if host.id in used or host.router:
            rows.append([host.name, host.group, ", ".join(i.ip for i in host.interfaces), host.device.vendor])
    lines += _table(["Name", "Role", "IP", "Vendor"], rows) + [""]

    lines += ["## Network", ""]
    lines += _table(["Subnet", "CIDR", "Gateway", "Capture point"],
                    [[s["id"], s["cidr"], s["gateway"] or "-", "yes" if s["sensor"] else ""]
                     for s in answers["topology"]["subnets"]]) + [""]

    profiles: dict[str, tuple[ProcessProfile, list[str]]] = {}
    for actor in plan.actors:
        if actor.type != "modbus.server":
            continue
        name = actor.param("process")
        profile, hosts = profiles.setdefault(name, (ProcessProfile(name), []))
        hosts.extend(h.name for h in actor.hosts)
    for profile, hosts in profiles.values():
        lines += [f"## Register map: {profile.title}", "",
                  f"Modbus unit id {profile.unit_id}; served by {', '.join(hosts)}. "
                  "Addresses are 0-based; engineering value = raw register value / scale.", ""]
        rows = []
        for table in ("coils", "discrete", "holding", "input"):
            for point in profile.table(table):
                band = f"{_number(point.normal[0])} – {_number(point.normal[1])}" if point.normal else "-"
                rows.append([table, point.address, point.name, point.unit or "-", _number(point.scale),
                             band, "yes" if point.writable else "no"])
        lines += _table(["Table", "Address", "Name", "Unit", "Scale", "Normal band", "Writable"], rows) + [""]

    lines += ["## Questions", ""]
    for index, question in enumerate(answers["questions"], 1):
        lines.append(f"{index}. **[{question['id']}]** {question['text']} *({question['points']} points)*")
    lines.append("")

    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "briefing.md"
    path.write_text("\n".join(lines), encoding="utf-8")
    return path
