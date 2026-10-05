"""Sigma rules derived from the site model (no capture needed: built from answers.json alone)."""

import uuid

import yaml

from pcapforge.detections import sigma_rules, write_detections


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
    assert "New host leased an address on the control LAN" in titles
    ids = [r["id"] for r in rules]
    assert len(set(ids)) == len(ids)
    for rule in rules:
        assert uuid.UUID(rule["id"])  # valid UUID
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


def test_write_detections_emits_parseable_sigma_files(tmp_path):
    paths = write_detections(answers(), tmp_path)
    sigma = {k: p for k, p in paths.items() if k.startswith("sigma/")}
    assert len(sigma) == 4
    for path in sigma.values():
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert {"title", "id", "logsource", "detection", "level", "tags"} <= set(doc)
    assert "## Sigma rules" in paths["hunting.md"].read_text(encoding="utf-8")
