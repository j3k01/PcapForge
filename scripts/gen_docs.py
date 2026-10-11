"""Reference pages and repository pages for the MkDocs site (``mkdocs.yml`` loads this as a hook).

The reference pages are generated from the code and data files on every build, so they cannot
drift: the CLI from ``pcapforge.cli.build_parser()``, actor types from the ``pcapforge.actors``
registry, device and process profiles from ``src/pcapforge/profiles``, the scenario schema and
the ``answers.json`` structure. README.md, CONTRIBUTING.md and ROADMAP.md are included from the
repository root as they are (single source of truth); relative links in them are rewritten to the
matching site page, or to the file on GitHub when the target is not part of the site.

Standalone use writes the generated pages to a directory for inspection::

    python scripts/gen_docs.py <out dir>
"""

from __future__ import annotations

import argparse
import ast
import inspect
import json
import os
import posixpath
import re
import sys
import textwrap
from pathlib import Path, PurePosixPath
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent.parent
REPO_URL = "https://github.com/j3k01/PcapForge"
BRANCH = "main"

# Repository files that become site pages: repository path -> page path inside docs/.
ROOT_PAGES = {"README.md": "index.md", "CONTRIBUTING.md": "contributing.md", "ROADMAP.md": "roadmap.md"}


# --- markdown helpers ----------------------------------------------------------------------

_CODE = re.compile(r"``(.+?)``|`([^`]+)`")


def md(text: Any) -> str:
    """Inline markdown for prose from docstrings and help texts: ``rst`` literals become code spans,
    HTML-special characters outside code are escaped, newlines are folded."""
    text = " ".join(str(text).split())
    out, pos = [], 0
    for m in _CODE.finditer(text):
        out.append(_escape(text[pos:m.start()]))
        out.append("`" + (m.group(1) or m.group(2)) + "`")
        pos = m.end()
    out.append(_escape(text[pos:]))
    return "".join(out)


def _escape(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("|", "\\|")


def code(value: Any) -> str:
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
    text = " ".join(text.split()).replace("|", "\\|")
    fence = "``" if "`" in text else "`"
    return f"{fence}{text}{fence}" if text else ""


def table(header: list[str], rows: list[list[str]]) -> list[str]:
    lines = ["| " + " | ".join(header) + " |", "|" + "|".join("---" for _ in header) + "|"]
    lines += ["| " + " | ".join(cell or " " for cell in row) + " |" for row in rows]
    return lines + [""]


def page(title: str, intro: str, body: list[str]) -> str:
    return "\n".join([f"# {title}", "", intro, "", *body]).rstrip() + "\n"


GENERATED = ("Generated from the source on every documentation build by `scripts/gen_docs.py`; "
             "do not edit by hand.")


# --- CLI -----------------------------------------------------------------------------------

def _option_rows(parser: argparse.ArgumentParser) -> list[list[str]]:
    formatter = parser._get_formatter()
    rows = []
    for action in parser._actions:
        if isinstance(action, (argparse._HelpAction, argparse._SubParsersAction)):
            continue
        if action.option_strings:
            name = ", ".join(code(o) for o in action.option_strings)
            if action.nargs != 0:
                name += " " + code(formatter._format_args(action, action.metavar or action.dest.upper()))
        else:
            name = code(formatter._format_args(action, action.metavar or action.dest))
        default = action.default
        shown = "" if (default in (None, False, argparse.SUPPRESS) or not action.option_strings
                       or isinstance(action, argparse._VersionAction)) else code(str(default))
        choices = ", ".join(code(str(c)) for c in action.choices) if action.choices else ""
        required = "yes" if action.required else ""
        help_ = md(formatter._expand_help(action)) if action.help else ""
        rows.append([name, required, shown, choices, help_])
    return rows


def cli_page() -> str:
    from pcapforge.cli import build_parser

    os.environ["COLUMNS"] = "100"  # argparse wraps usage lines at the terminal width
    parser = build_parser()
    subparsers = next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction))
    helps = {a.dest: a.help for a in subparsers._choices_actions}
    header = ["argument", "required", "default", "choices", "description"]

    body = ["```text", parser.format_usage().strip(), "```", "", md(parser.description or ""), "",
            "Global options (before the subcommand):", "", *table(header, _option_rows(parser)),
            "## Subcommands", ""]
    body += table(["command", "description"],
                  [[f"[`{name}`](#pcapforge-{name})", md(helps.get(name, ""))] for name in subparsers.choices])
    for name, sub in subparsers.choices.items():
        body += [f"## pcapforge {name}", "", md(helps.get(name, "")), "",
                 "```text", sub.format_usage().strip(), "```", ""]
        rows = _option_rows(sub)
        body += table(header, rows) if rows else ["No arguments.", ""]
    return page("CLI reference", "Every `pcapforge` subcommand with its arguments. " + GENERATED, body)


# --- actors --------------------------------------------------------------------------------

def _param_reads(node: ast.AST) -> dict[str, str]:
    """``<a>.param("name", default)``, ``<a>.params.get("name", ...)`` and ``<a>.params["name"]``
    with a literal name, mapped to the source of the default ('' when there is none). ``<a>`` is
    ``self`` in a class and the first parameter of a module-level helper (the actor it is given);
    reads from other actors (``other.param(...)``) do not count."""
    if isinstance(node, ast.ClassDef):
        owner = "self"
    else:
        positional = node.args.posonlyargs + node.args.args
        owner = positional[0].arg if positional else None

    def is_owner(expr: ast.AST) -> bool:
        return isinstance(expr, ast.Name) and expr.id == owner

    def is_params(expr: ast.AST) -> bool:
        return isinstance(expr, ast.Attribute) and expr.attr == "params" and is_owner(expr.value)

    found: dict[str, str] = {}
    for n in ast.walk(node):
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.args \
                and isinstance(n.args[0], ast.Constant) and isinstance(n.args[0].value, str):
            f = n.func
            if (f.attr == "param" and is_owner(f.value)) or (f.attr == "get" and is_params(f.value)):
                default = ast.unparse(n.args[1]) if len(n.args) > 1 else ""
                if not found.get(n.args[0].value):
                    found[n.args[0].value] = default
        elif isinstance(n, ast.Subscript) and is_params(n.value) \
                and isinstance(n.slice, ast.Constant) and isinstance(n.slice.value, str):
            found.setdefault(n.slice.value, "")
    return found


_module_cache: dict[str, tuple[ast.Module, dict[str, ast.AST]]] = {}


def _module(mod) -> tuple[ast.Module, dict[str, ast.AST]]:
    if mod.__name__ not in _module_cache:
        tree = ast.parse(inspect.getsource(mod))
        defs = {n.name: n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))}
        _module_cache[mod.__name__] = tree, defs
    return _module_cache[mod.__name__]


def actor_params(cls) -> dict[str, str]:
    """Params an actor class reads: its own methods and those of its pcapforge base classes, plus
    module-level helpers of the same modules that those methods call (transitively)."""
    from pcapforge.actors.base import Actor

    params: dict[str, str] = {}
    for klass in cls.__mro__:
        if klass is Actor or not issubclass(klass, Actor):
            continue
        _, defs = _module(sys.modules[klass.__module__])
        todo, seen = [defs[klass.__name__]], {klass.__name__}
        while todo:
            node = todo.pop()
            for name, default in _param_reads(node).items():
                if not params.get(name):
                    params[name] = default
            for n in ast.walk(node):
                if isinstance(n, ast.Name) and n.id in defs and n.id not in seen \
                        and isinstance(defs[n.id], (ast.FunctionDef, ast.AsyncFunctionDef)):
                    seen.add(n.id)
                    todo.append(defs[n.id])
    return dict(sorted(params.items()))


def actors_page() -> str:
    from pcapforge.actors import REGISTRY, actor_types

    types = actor_types()
    body = table(["type", "role", "class", "optional extra"],
                 [[f"[`{t}`](#{t.replace('.', '')})", "server" if REGISTRY[t].is_server else "client",
                   code(f"{REGISTRY[t].__module__}.{REGISTRY[t].__name__}"),
                   code(f"pcapforge[{REGISTRY[t].requires[2]}]") if REGISTRY[t].requires else ""]
                  for t in types])
    for t in types:
        cls = REGISTRY[t]
        doc = inspect.cleandoc(cls.__doc__) if cls.__doc__ else ""  # own docstring only, not Actor's
        body += [f"## {t}", ""]
        body += [md(p) + "\n" for p in doc.split("\n\n")] if doc else ["No description.", ""]
        params = actor_params(cls)
        if params:
            body += ["Params read by the actor (`actors[].params`):", ""]
            body += table(["param", "default in code"], [[code(k), code(v)] for k, v in params.items()])
        else:
            body += ["The actor reads no params.", ""]
    intro = ("Actor types usable as `actors[].type` in a scenario, from the `pcapforge.actors` registry. "
             "Params are found by static analysis of the actor class and the module-level helpers it "
             "calls; a default that depends on other values shows the expression from the code. "
             + GENERATED)
    return page("Actor types", intro, body)


# --- profiles ------------------------------------------------------------------------------

def _profiles_dir() -> Path:
    from pcapforge.profiles import PROFILE_DIR
    return PROFILE_DIR


def devices_page() -> str:
    doc = yaml.safe_load((_profiles_dir() / "devices.yaml").read_text(encoding="utf-8"))
    stacks, devices = doc["stacks"], doc["devices"]
    body = ["## Devices", ""]
    rows = []
    for name in sorted(devices):
        d = devices[name]
        identity = d.get("identity") or {}
        extras = [k for k in ("browser", "ipv6_router", "forwarding_ms") if k in d]
        rows.append([code(name), md(d["vendor"]), f"[`{d['stack']}`](#stack-{d['stack']})",
                     ", ".join(code(o) for o in d["ouis"]), str(d["link_mbps"]),
                     str(d["processing_ms"]["median"]),
                     md(" ".join(str(identity[k]) for k in ("ProductCode", "MajorMinorRevision") if k in identity)),
                     ", ".join(code(e) for e in extras)])
    body += table(["device", "vendor", "stack", "MAC OUIs", "link Mbps", "processing ms (median)",
                   "reported identity", "also"], rows)
    body += ["## Network stacks", ""]
    for name in sorted(stacks):
        s = stacks[name]
        body += [f'<a id="stack-{name}"></a>', "", f"### {name}", ""]
        body += table(["field", "value"], [[code(k), code(v)] for k, v in s.items()])
    intro = ("Device and network-stack profiles from `src/pcapforge/profiles/devices.yaml` "
             "(`topology.hosts[].device` in a scenario). The comment block at the top of that file "
             "explains every field. " + GENERATED)
    return page("Device profiles", intro, body)


def processes_page() -> str:
    names = sorted(p.stem for p in (_profiles_dir() / "processes").glob("*.yaml"))
    tables = (("holding", "holding registers"), ("input", "input registers"),
              ("coils", "coils"), ("discrete", "discrete inputs"))
    body = table(["profile", "title"], [[f"[`{n}`](#{n})", md(_process(n)["title"])] for n in names])
    for name in names:
        p = _process(name)
        body += [f"## {name}", "", md(p["title"]), ""]
        facts = [("Modbus unit id", code(p.get("unit_id", ""))),
                 ("word order", code(p.get("word_order", "big"))),
                 ("register style", code(p.get("register_style", ""))),
                 ("poll groups", "; ".join(code(g) for g in p.get("poll_groups", []))),
                 ("operator-adjustable", ", ".join(code(a["name"]) for a in p.get("operator_adjustable", []))),
                 ("translations", ", ".join(code(lang) for lang in sorted(p.get("translations", {}))))]
        body += table(["setting", "value"], [[k, v] for k, v in facts if v])
        for key, label in tables:
            points = p.get(key) or []
            if not points:
                continue
            body += [f"### {label.capitalize()}", ""]
            body += table(["address", "name", "data type", "unit", "scale", "nominal", "normal", "writable", "model",
                           "description"],
                          [[str(pt["address"]), code(pt["name"]),
                            code(pt.get("type", "bool" if key in ("coils", "discrete") else "uint16")),
                            md(pt.get("unit", "")), str(pt.get("scale", "")),
                            str(pt.get("nominal", "")), code(pt["normal"]) if "normal" in pt else "",
                            "yes" if pt.get("writable") else "",
                            code((pt.get("model") or {}).get("type", "")), md(pt.get("desc", ""))]
                           for pt in points])
    intro = ("Physical-process models from `src/pcapforge/profiles/processes/` "
             "(`params.process` of `modbus.server`). Addresses are 0-based wire addresses; the comment "
             "block at the top of each file explains the models. " + GENERATED)
    return page("Process profiles", intro, body)


def _process(name: str) -> dict:
    from pcapforge.profiles import process_doc
    return process_doc(name)


# --- scenario schema -----------------------------------------------------------------------

def _type(schema: dict) -> str:
    if "$ref" in schema:
        name = schema["$ref"].rsplit("/", 1)[-1]
        return f"[{name}](#{name})"
    if "oneOf" in schema and "type" not in schema:
        return " or ".join(_type(s) for s in schema["oneOf"])
    if "const" in schema:
        return "const"
    t = schema.get("type")
    if t is None:
        values = schema.get("enum", [])
        t = "string" if values and all(isinstance(v, str) for v in values) else "any"
    if isinstance(t, list):
        t = " or ".join(t)
    if t == "array" and isinstance(schema.get("items"), dict):
        return f"array of {_type(schema['items'])}"
    return t


_NOTES = (("const", "value"), ("enum", "one of"), ("pattern", "pattern"), ("minimum", "min"),
          ("exclusiveMinimum", "greater than"), ("maximum", "max"), ("minItems", "min items"),
          ("maxItems", "max items"), ("minLength", "min length"), ("minProperties", "min properties"),
          ("default", "default"))


def _notes(schema: dict) -> str:
    parts = [md(schema["description"])] if "description" in schema else []
    for target in [schema, schema.get("items") if isinstance(schema.get("items"), dict) else {}]:
        for key, label in _NOTES:
            if key in target:
                value = target[key]
                shown = ", ".join(code(v) for v in value) if key == "enum" else code(value)
                parts.append(f"{label}: {shown}")
        variants = target.get("oneOf", [])
        if variants and all(set(v) == {"required"} for v in variants):
            parts.append("set exactly one of: " + " / ".join(
                " + ".join(code(k) for k in v["required"]) for v in variants))
    if schema.get("additionalProperties") is False:
        parts.append("no other keys")
    return "; ".join(parts)


def _schema_rows(schema: dict, path: str, required: bool, rows: list[list[str]]) -> None:
    if path:
        rows.append([code(path), _type(schema), "yes" if required else "", _notes(schema)])
    variants = [schema] + [s for s in schema.get("oneOf", []) if isinstance(s, dict)]
    for variant in variants:
        node = variant
        suffix = ""
        if node.get("type") == "array" and isinstance(node.get("items"), dict):
            node, suffix = node["items"], "[]"
        req = set(node.get("required", []))
        for key, sub in (node.get("properties") or {}).items():
            _schema_rows(sub, f"{path}{suffix}.{key}".lstrip("."), key in req, rows)
        for pattern, sub in (node.get("patternProperties") or {}).items():
            _schema_rows(sub, f"{path}{suffix}.<{pattern}>".lstrip("."), False, rows)
        extra = node.get("additionalProperties")
        if isinstance(extra, dict):
            _schema_rows(extra, f"{path}{suffix}.<name>".lstrip("."), False, rows)


def schema_page() -> str:
    from pcapforge.scenario import SCHEMA_PATH

    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    rows: list[list[str]] = []
    _schema_rows(schema, "", False, rows)
    body = ["Paths use `[]` for array items and `<...>` for free-form keys (a key pattern or a name).", "",
            *table(["path", "type", "required", "notes"], rows), "## Definitions", ""]
    for name, sub in schema.get("$defs", {}).items():
        body += [f"### {name}", ""]
        variants = sub.get("oneOf", [])
        notes = "; ".join(f"{_type(v)} ({_notes(v)})" if _notes(v) else _type(v) for v in variants)
        body += table(["type", "notes"], [[_type(sub), notes if any(map(_notes, variants)) else _notes(sub)]])
    body += ["## Full schema", "", "```json", json.dumps(schema, indent=2, ensure_ascii=False), "```"]
    intro = (f"{md(schema.get('title', ''))}. Scenario files are validated against "
             "`src/pcapforge/scenario/scenario.schema.json` (`$id` " + code(schema.get("$id", "")) + "). "
             "Actor `params` are free-form here; the [actor reference](actors.md) lists the params each "
             "type reads. " + GENERATED)
    return page("Scenario schema", intro, body)


# --- answers.json --------------------------------------------------------------------------

ANSWER_KEYS = {
    "schema": "Format identifier and version of the answer key.",
    "generator": "`name` and `version` of the pcapforge build that wrote the file.",
    "scenario": "`id`, `title`, `line` (OT/IT), `difficulty`, `seed`, `base_seed` and the one-line `summary`.",
    "capture": "The capture file: `file`, `sha256`, `packets`, `start` / `end` (ISO 8601 UTC), "
               "`duration_s`, the `sensor_subnet` and the `sensor_clock` (`offset_s`, `drift_ppm`).",
    "topology": "`site_name`, `domain`, `subnets` and `hosts` (id, role, name, FQDN, IP, MAC, the MAC the "
                "sensor observed, vendor, device, IPv6 addresses).",
    "actors": "Every actor of the run: `id`, `type`, `incident` and the `hosts` it ran on.",
    "mitre": "ATT&CK techniques of the scenario whose `when` condition holds for this run.",
    "facts": "Values the actors recorded while planning (per actor id); questions and `check`/`hunt` "
             "filters reference them.",
    "iocs": "Indicators of the incident actors: IP, MAC and hostname per host role, plus their events.",
    "timeline": "Events in time order: `time`, `epoch`, `frame` number in the capture, `actor`, `title`, "
                "`techniques`, `details` and whether the event belongs to the `incident`.",
    "questions": "Resolved questions: `id`, `text`, `type`, `answer`, `points`, `hint`, the tshark `checks` "
                 "that verify the answer and the `hunt` hints.",
    "lang": "Language of the student texts (`generate --lang`), set by the pipeline when it localises the key.",
}


def answers_page() -> str:
    import pcapforge.answers as answers

    tree = ast.parse(inspect.getsource(answers))
    build = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "build_answers")
    returned = next(n.value for n in ast.walk(build) if isinstance(n, ast.Return) and isinstance(n.value, ast.Dict))
    keys = [k.value for k in returned.keys if isinstance(k, ast.Constant)]
    rows = []
    for key in keys:
        node = returned.values[keys.index(key)]
        if isinstance(node, ast.ListComp):
            node = node.elt
        sub = [k.value for k in node.keys if isinstance(k, ast.Constant)] if isinstance(node, ast.Dict) else []
        rows.append([code(key), md(ANSWER_KEYS.get(key, "")), ", ".join(code(s) for s in sub)])
    rows.append([code("lang"), md(ANSWER_KEYS["lang"]), ""])
    missing = sorted(set(keys) - set(ANSWER_KEYS))
    if missing:
        raise RuntimeError(f"answers.json keys without a description in scripts/gen_docs.py: {missing}")
    body = [f"Current format: {code(answers.SCHEMA)}.", "", *table(["key", "content", "fields"], rows)]
    intro = ("Top-level structure of the instructor answer key `answers.json` that `pcapforge generate` "
             "writes next to the capture (built by `pcapforge.answers.build_answers`). " + GENERATED)
    return page("answers.json", intro, body)


REFERENCE = {
    "reference/cli.md": cli_page,
    "reference/actors.md": actors_page,
    "reference/devices.md": devices_page,
    "reference/processes.md": processes_page,
    "reference/scenario-schema.md": schema_page,
    "reference/answers.md": answers_page,
}


# --- links of repository pages -------------------------------------------------------------

_LINK = re.compile(r"(\]\()([^)\s]+)(\))")
_FENCE = re.compile(r"^\s*(```|~~~)")


def rewrite_links(text: str, repo_path: str, page_path: str) -> str:
    """Rewrite relative links of a page whose source is ``repo_path`` (repository-relative) and that
    is served as ``page_path`` (docs-relative): repository pages map to their site page, other
    repository files to GitHub. Links inside fenced code blocks are left alone."""
    pages = {**ROOT_PAGES, **{f"docs/{p}": p for p in _docs_pages()}}

    def fix(m: re.Match) -> str:
        target = m.group(2)
        if re.match(r"^[a-z][a-z0-9+.-]*:|^#|^/", target, re.I):
            return m.group(0)
        path, _, anchor = target.partition("#")
        resolved = posixpath.normpath(posixpath.join(posixpath.dirname(repo_path), path))
        if resolved.startswith(".."):
            return m.group(0)
        if resolved in pages:
            new = posixpath.relpath(pages[resolved], posixpath.dirname(page_path) or ".")
        elif (ROOT / resolved).exists():
            kind = "tree" if (ROOT / resolved).is_dir() else "blob"
            new = f"{REPO_URL}/{kind}/{BRANCH}/{resolved}"
        else:
            return m.group(0)
        return f"{m.group(1)}{new}{'#' + anchor if anchor else ''}{m.group(3)}"

    out, fenced = [], False
    for line in text.splitlines(keepends=True):
        if _FENCE.match(line):
            fenced = not fenced
        out.append(line if fenced or _FENCE.match(line) else _LINK.sub(fix, line))
    return "".join(out)


_ITEM = re.compile(r"^( *)(?:[-*+]|\d+\.) ")


def gfm_lists(text: str) -> str:
    """The repository Markdown is written for GitHub (CommonMark): a list may start right after a
    paragraph line and nested items are indented by the width of the parent marker (2-3 spaces).
    Python-Markdown needs a blank line before the list and 4 spaces per nesting level, so insert the
    blank line and re-indent list items by depth. Fenced code blocks are left alone."""
    out: list[str] = []
    stack: list[int] = []  # marker indents of the open list levels
    fenced = False
    for line in text.splitlines():
        if _FENCE.match(line):
            fenced = not fenced
        item = None if fenced else _ITEM.match(line)
        if item:
            indent = len(item.group(1))
            if not stack or indent <= stack[0]:
                if not stack and out and out[-1].strip() and not out[-1].lstrip().startswith("|"):
                    out.append("")
                stack = [indent]
            else:
                while stack[-1] > indent:
                    stack.pop()
                if stack[-1] < indent:
                    stack.append(indent)
            line = " " * (4 * (len(stack) - 1)) + line[indent:]
        elif not fenced and stack and line.strip() and not line.startswith(" ") and out and not out[-1].strip():
            stack = []  # an unindented paragraph after a blank line ends the list
        out.append(line)
    return "\n".join(out) + ("\n" if text.endswith("\n") else "")



def _docs_pages() -> list[str]:
    docs = ROOT / "docs"
    return sorted(p.relative_to(docs).as_posix() for p in docs.rglob("*.md"))


# --- MkDocs hook ---------------------------------------------------------------------------

def on_files(files, config):
    from mkdocs.structure.files import File

    for repo_path, page_path in ROOT_PAGES.items():
        text = (ROOT / repo_path).read_text(encoding="utf-8")
        files.append(File.generated(config, page_path, content=rewrite_links(text, repo_path, page_path)))
    for page_path, build in REFERENCE.items():
        files.append(File.generated(config, page_path, content=build()))
    return files


def on_page_markdown(markdown, page, config, files):
    """Pages that live in docs/ link to repository files with ``../`` paths; send those to GitHub.
    Every page gets its GitHub-style lists normalised for Python-Markdown."""
    if page.file.generated_by is None:
        markdown = rewrite_links(markdown, f"docs/{page.file.src_uri}", page.file.src_uri)
    return gfm_lists(markdown)


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print(textwrap.dedent(__doc__).strip().splitlines()[-1].strip(), file=sys.stderr)
        return 2
    out = Path(argv[0])
    for page_path, build in REFERENCE.items():
        target = out / PurePosixPath(page_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(build(), encoding="utf-8", newline="\n")
        print(target)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
