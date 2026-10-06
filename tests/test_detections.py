"""Sigma rules derived from the site model (built from answers.json alone), and a baseline capture
on which none of them may fire."""

import uuid

import pytest
import yaml

from pcapforge.detections import sigma_rules, write_detections
from pcapforge.pipeline import generate
from pcapforge.scenario import find
from pcapforge.tools import MIN_TSHARK, find_tool, tshark_version
from sigma_eval import correlation_groups, hits, load_rules


def answers(with_writer=True, with_dhcp=True):
    """Minimal answers.json: two PLCs, SCADA clients, optional approved writer and DHCP client."""
    actors = [
        {"id": "plc_service", "type": "modbus.server", "incident": False, "hosts": ["plc1", "plc2"]},
        {"id": "scada_poll", "type": "modbus.poller", "incident": False, "hosts": ["hmi"]},
        {"id": "historian_poll", "type": "modbus.poller", "incident": False, "hosts": ["historian"]},
        {"id": "change", "type": "modbus.writer", "incident": True, "hosts": ["rogue"]},
    ]
    if with_writer:
        actors.insert(3, {"id": "operator_changes", "type": "modbus.operator", "incident": False, "hosts": ["ews"]})
    if with_dhcp:
        actors.append({"id": "rogue_join", "type": "dhcp.client", "incident": True, "hosts": ["rogue"]})
    hosts = {"plc1": "10.0.0.10", "plc2": "10.0.0.11", "hmi": "10.0.0.20", "historian": "10.0.0.21",
             "ews": "10.0.0.22", "rogue": "10.0.0.99"}
    return {
        "scenario": {"id": "ot-test", "title": "T", "difficulty": "easy", "seed": "42"},
        "capture": {"start": "2025-03-22T11:00:00Z"},
        "topology": {"site_name": "Testville", "domain": "test.local",
                     "subnets": [{"id": "control", "sensor": True}],
                     "hosts": [{"id": h, "name": h.upper(),
                                "interfaces": [{"subnet": "control", "ip": ip}]} for h, ip in hosts.items()]},
        "facts": {"plc_service": {"process": "water_treatment"}},
        "actors": actors,
        "questions": [],
    }


def by_title(rules):
    return {r["title"]: r for r in rules}


def test_each_rule_is_valid_sigma_with_a_deterministic_id():
    a = answers()
    rules = sigma_rules(a)
    titles = by_title(rules)
    assert "Modbus write from an unapproved host" in titles
    assert "Modbus setpoint written outside its normal band" in titles
    assert "Modbus device identification from an unexpected host" in titles
    assert "Modbus connection from an unexpected host" in titles
    assert "New host leased an address on the control LAN" in titles
    ids = [r["id"] for r in rules]
    assert len(set(ids)) == len(ids)
    names = {r["name"] for r in rules if "name" in r}
    for rule in rules:
        assert uuid.UUID(rule["id"])  # valid UUID
        if "correlation" in rule:
            # A correlation only names base rules that exist.
            assert set(rule["correlation"]["rules"]) <= names
            continue
        assert rule["logsource"]["product"] == "pcapforge"
        assert "condition" in rule["detection"]
        # The condition only names selection blocks that exist in the detection.
        blocks = {k for k in rule["detection"] if k != "condition"}
        for token in rule["detection"]["condition"].replace("not ", "").replace("and", " ").split():
            assert token in blocks
    # Ids are stable across runs but differ per seed.
    assert sigma_rules(a)[0]["id"] == rules[0]["id"]
    other = answers()
    other["scenario"]["seed"] = "999"
    assert sigma_rules(other)[0]["id"] != rules[0]["id"]


def test_approved_writers_and_clients_are_excluded_by_the_filter():
    rules = by_title(sigma_rules(answers()))
    write = rules["Modbus write from an unapproved host"]["detection"]
    assert write["writes"] == {"write": True, "dest": ["10.0.0.10", "10.0.0.11"]}
    assert write["approved"] == {"src": ["10.0.0.22"]}  # ews
    assert write["condition"] == "writes and not approved"
    ident = rules["Modbus device identification from an unexpected host"]["detection"]
    assert ident["approved"] == {"src": ["10.0.0.20", "10.0.0.21", "10.0.0.22"]}
    conn = rules["Modbus connection from an unexpected host"]["detection"]
    assert conn["selection"] == {"dest_port": 502, "dest": ["10.0.0.10", "10.0.0.11"]}
    assert conn["approved"] == {"src": ["10.0.0.20", "10.0.0.21", "10.0.0.22"]}
    assert rules["Modbus connection from an unexpected host"]["logsource"]["service"] == "flows"


def test_without_an_approved_writer_every_write_fires():
    rules = by_title(sigma_rules(answers(with_writer=False)))
    write = rules["Modbus write from an unapproved host"]["detection"]
    assert "approved" not in write and write["condition"] == "writes"


def test_no_dhcp_rule_when_no_dhcp_client_actor():
    titles = by_title(sigma_rules(answers(with_dhcp=False)))
    assert "New host leased an address on the control LAN" not in titles


def test_no_rules_without_a_modbus_server():
    a = answers()
    a["actors"] = [x for x in a["actors"] if x["type"] != "modbus.server"]
    assert sigma_rules(a) == []


def test_alarm_rules_name_the_alarm_points_of_the_register_map():
    rules = by_title(sigma_rules(answers()))  # water_treatment: alarm_ack coil, three *_alarm thresholds
    ack = rules["Modbus alarm acknowledge or reset written to a PLC"]["detection"]["selection"]
    assert ack["point"] == ["alarm_ack"]
    threshold = rules["Alarm threshold written outside its normal band"]["detection"]["selection"]
    assert threshold["point"] == ["chlorine_high_alarm", "level_high_alarm", "level_low_alarm"]
    assert threshold["in_normal_band"] is False


def test_write_detections_emits_parseable_sigma_files_with_bases_before_their_correlation(tmp_path):
    paths = write_detections(answers(), tmp_path)
    sigma = {k: p for k, p in paths.items() if k.startswith("sigma/")}
    assert len(sigma) == 10
    for path in sigma.values():
        docs = list(yaml.safe_load_all(path.read_text(encoding="utf-8")))
        *bases, last = docs
        if "correlation" in last:
            # pySigma resolves a correlation's references in load order: its bases come first.
            assert [b["name"] for b in bases] == last["correlation"]["rules"]
        else:
            assert not bases
        for doc in bases + ([] if "correlation" in last else [last]):
            assert {"title", "id", "logsource", "detection", "level", "tags"} <= set(doc)
    assert "## Sigma rules" in paths["hunting.md"].read_text(encoding="utf-8")


capture_tools = (find_tool("tshark") and (find_tool("dumpcap") or find_tool("tcpdump"))
                 and tshark_version() >= MIN_TSHARK)


@pytest.mark.skipif(not capture_tools, reason="requires tshark >= 4.4 and dumpcap/tcpdump with loopback capture rights")
@pytest.mark.parametrize("seed", ["fp-1", "fp-2"])
def test_no_sigma_rule_fires_on_normal_operations(tmp_path, seed):
    result = generate(find("ot-baseline-operations"), "easy", seed, tmp_path, duration=300.0, siem=True)
    rules = load_rules(result.directory / "detections" / "sigma")
    siem = result.directory / "siem"
    bases = {n for r in rules.values() if "correlation" in r for n in r["correlation"]["rules"]}
    fired = {}
    for title, rule in rules.items():
        if rule.get("name") in bases:
            continue  # correlation building blocks, not converted on their own
        found = correlation_groups(rule, rules, siem) if "correlation" in rule else hits(rule, siem)
        if found:
            fired[title] = found
    assert not fired
