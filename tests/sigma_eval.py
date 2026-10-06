"""Evaluate the Sigma rules pcapforge generates against its JSON-lines SIEM export (tests only).

Covers the subset the generator emits: selections of field equality (a list means any of), the
`exists` modifier, conditions `a`, `a and not b`, and `value_count` correlations (sliding window).
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

import yaml

UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def load_rules(sigma_dir: Path) -> dict[str, dict]:
    """Title -> rule document, for every document of every file (correlations and their bases)."""
    rules = {}
    for path in sorted(sigma_dir.glob("*.yml")):
        for doc in yaml.safe_load_all(path.read_text(encoding="utf-8")):
            rules[doc["title"]] = doc
    return rules


def events(siem_dir: Path, service: str) -> list[dict]:
    with open(siem_dir / f"{service}.jsonl", encoding="utf-8") as fh:
        return [json.loads(line) for line in fh]


def _field(event: dict, key: str, expected) -> bool:
    name, _, modifier = key.partition("|")
    value = event.get(name)
    if modifier == "exists":
        return (value is not None) == bool(expected)
    assert not modifier, f"unsupported modifier {modifier}"
    wanted = expected if isinstance(expected, list) else [expected]
    present = value if isinstance(value, list) else [value]
    return any(v == w for v in present for w in wanted)


def matches(rule: dict, event: dict) -> bool:
    detection = rule["detection"]
    result = True
    for term in detection["condition"].split(" and "):
        negate = term.startswith("not ")
        block = detection[term.removeprefix("not ")]
        hit = all(_field(event, key, expected) for key, expected in block.items())
        result = result and (hit != negate)
    return result


def hits(rule: dict, siem_dir: Path) -> list[dict]:
    return [e for e in events(siem_dir, rule["logsource"]["service"]) if matches(rule, e)]


def correlation_groups(rule: dict, rules: dict[str, dict], siem_dir: Path) -> dict[tuple, set]:
    """Group-by key -> distinct ``field`` values of the first window that meets a value_count
    correlation's condition; groups that never meet it are left out."""
    corr = rule["correlation"]
    assert corr["type"] == "value_count"
    by_name = {r["name"]: r for r in rules.values() if "name" in r}
    span = float(corr["timespan"][:-1]) * UNITS[corr["timespan"][-1]]
    field, minimum = corr["condition"]["field"], corr["condition"]["gte"]
    grouped: dict[tuple, list[dict]] = defaultdict(list)
    for name in corr["rules"]:
        for event in hits(by_name[name], siem_dir):
            grouped[tuple(json.dumps(event.get(g)) for g in corr["group-by"])].append(event)
    fired = {}
    for key, group in grouped.items():
        group.sort(key=lambda e: e["epoch"])
        for i, first in enumerate(group):
            window = {json.dumps(e.get(field)) for e in group[i:] if e["epoch"] - first["epoch"] <= span}
            if len(window) >= minimum:
                fired[key] = {json.loads(v) for v in window}
                break
    return fired
