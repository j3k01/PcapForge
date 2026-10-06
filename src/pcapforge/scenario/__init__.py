"""Scenario loading, validation and `${...}` template resolution."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from typing import Any

import jsonschema
import yaml

SCHEMA_PATH = Path(__file__).with_name("scenario.schema.json")
DIFFICULTIES = ("easy", "medium", "hard")

_REF = re.compile(r"\$\{([^}]+)\}")
_PATH_TOKEN = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)|\[(\d+)\]")
_DURATION = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*(ms|s|m|h|d)?\s*$")
_WHEN = re.compile(r"^\s*(not\s+)?([A-Za-z_][\w.\[\]]*)\s*(?:(==|!=)\s*'([^']*)')?\s*$")


class ScenarioError(ValueError):
    pass


def parse_duration(value: Any) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    match = _DURATION.match(str(value))
    if not match:
        raise ScenarioError(f"invalid duration '{value}' (use e.g. 90, 90s, 15m, 2h)")
    number = float(match.group(1))
    return number * {"ms": 0.001, "s": 1, None: 1, "m": 60, "h": 3600, "d": 86400}[match.group(2)]


def lookup(ctx: dict, path: str) -> Any:
    current: Any = ctx
    path = path.strip()
    for part in path.split("."):
        for match in _PATH_TOKEN.finditer(part):
            key, index = match.groups()
            try:
                current = current[int(index)] if index is not None else current[key]
            except (KeyError, IndexError, TypeError):
                raise ScenarioError(f"unresolved reference '{path}'") from None
    return current


def resolve(value: Any, ctx: dict) -> Any:
    """Substitute `${a.b[0].c}` references. A string that is exactly one reference keeps
    the referenced value's type; otherwise references are interpolated as text."""
    if isinstance(value, str):
        whole = _REF.fullmatch(value.strip())
        if whole:
            return lookup(ctx, whole.group(1))
        return _REF.sub(lambda m: _to_text(lookup(ctx, m.group(1))), value)
    if isinstance(value, list):
        return [resolve(v, ctx) for v in value]
    if isinstance(value, dict):
        return {k: resolve(v, ctx) for k, v in value.items()}
    return value


def _to_text(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def evaluate_when(expr: Any, ctx: dict) -> bool:
    """``path``, ``not path``, ``path == 'x'``, ``path != 'x'``, or several joined with ``and``."""
    if expr is None:
        return True
    if isinstance(expr, bool):
        return expr
    return all(_condition(term, ctx) for term in str(expr).split(" and "))


def _condition(term: str, ctx: dict) -> bool:
    match = _WHEN.match(term)
    if not match:
        raise ScenarioError(f"unsupported condition '{term}' (use 'path', 'not path', \"path == 'x'\", "
                            "joined with 'and')")
    negate, path, op, literal = match.groups()
    try:
        value = lookup(ctx, path)
    except ScenarioError:
        value = None
    if op == "==":
        result = _to_text(value) == literal
    elif op == "!=":
        result = _to_text(value) != literal
    else:
        result = bool(value)
    return not result if negate else result


@cache
def _schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


@dataclass
class Scenario:
    path: Path
    doc: dict

    @property
    def id(self) -> str:
        return self.doc["id"]

    @property
    def title(self) -> str:
        return self.doc["title"]

    @property
    def line(self) -> str:
        return self.doc["line"]

    @property
    def difficulties(self) -> list[str]:
        return [d for d in DIFFICULTIES if d in self.doc["difficulty"]]

    def level(self, difficulty: str) -> dict:
        if difficulty not in self.doc["difficulty"]:
            raise ScenarioError(f"scenario '{self.id}' has no difficulty '{difficulty}' "
                                f"(available: {', '.join(self.difficulties)})")
        return self.doc["difficulty"][difficulty]


def validate(doc: dict, source: str = "<scenario>") -> None:
    validator = jsonschema.Draft202012Validator(_schema())
    errors = sorted(validator.iter_errors(doc), key=lambda e: list(e.absolute_path))
    if errors:
        lines = [f"  {'/'.join(map(str, e.absolute_path)) or '<root>'}: {e.message}" for e in errors]
        raise ScenarioError(f"{source} is not a valid scenario:\n" + "\n".join(lines))
    hosts = {h["id"] for h in doc["topology"]["hosts"]}
    subnets = {s["id"] for s in doc["topology"]["subnets"]}
    if doc["topology"]["sensor"] not in subnets:
        raise ScenarioError(f"{source}: sensor subnet '{doc['topology']['sensor']}' is not defined")
    for host in doc["topology"]["hosts"]:
        for subnet in host.get("subnets", [host.get("subnet")]):
            if subnet not in subnets and "${" not in str(subnet):
                raise ScenarioError(f"{source}: host '{host['id']}' uses unknown subnet '{subnet}'")
    for actor in doc["actors"]:
        targets = actor["hosts"] if isinstance(actor["hosts"], list) else [actor["hosts"]]
        for target in targets:
            if target not in hosts and "${" not in target:
                raise ScenarioError(f"{source}: actor '{actor['id']}' runs on unknown host '{target}'")
    for name, level in doc["difficulty"].items():
        parse_duration(level["duration"])


def load(path: Path) -> Scenario:
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    validate(doc, str(path))
    return Scenario(path=path, doc=doc)


def search_paths(extra: Path | None = None) -> list[Path]:
    paths = []
    if extra:
        paths.append(extra)
    if env := os.environ.get("PCAPFORGE_SCENARIOS"):
        paths.extend(Path(p) for p in env.split(os.pathsep))
    paths.append(Path.cwd() / "scenarios")
    paths.append(Path(__file__).resolve().parents[3] / "scenarios")   # source checkout
    paths.append(Path(__file__).resolve().parents[1] / "_scenarios")  # installed wheel
    seen, unique = set(), []
    for p in paths:
        key = p.resolve()
        if key not in seen and p.is_dir():
            seen.add(key)
            unique.append(p)
    return unique


def discover(extra: Path | None = None) -> dict[str, Scenario]:
    found: dict[str, Scenario] = {}
    for root in search_paths(extra):
        for path in sorted(root.rglob("scenario.yaml")):
            scenario = load(path)
            found.setdefault(scenario.id, scenario)
    return found


def find(ref: str, extra: Path | None = None) -> Scenario:
    candidate = Path(ref)
    if candidate.suffix in (".yaml", ".yml") and candidate.is_file():
        return load(candidate)
    scenarios = discover(extra)
    if ref not in scenarios:
        known = ", ".join(sorted(scenarios)) or "none found"
        raise ScenarioError(f"unknown scenario '{ref}' (available: {known})")
    return scenarios[ref]
