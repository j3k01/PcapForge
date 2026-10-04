"""Command-line interface: `pcapforge list|show|validate|generate|verify|export|grade|package`."""

from __future__ import annotations

import argparse
import json
import sys
import textwrap
from pathlib import Path

from pcapforge import __version__
from pcapforge.scenario import DIFFICULTIES, ScenarioError, discover, find, load, parse_duration
from pcapforge.tools import ToolNotFound


def _scenarios_dir(args) -> Path | None:
    return Path(args.scenarios_dir) if args.scenarios_dir else None


def cmd_list(args) -> int:
    scenarios = discover(_scenarios_dir(args))
    if not scenarios:
        print("no scenarios found", file=sys.stderr)
        return 1
    width = max(len(s) for s in scenarios)
    for sid, sc in sorted(scenarios.items()):
        techniques = ",".join(m["id"] for m in sc.doc["mitre"] if "when" not in m)
        print(f"{sid:<{width}}  {sc.line.upper():<2}  {'/'.join(sc.difficulties):<16}  {techniques:<14}  {sc.title}")
    return 0


def cmd_show(args) -> int:
    sc = find(args.scenario, _scenarios_dir(args))
    doc = sc.doc
    print(f"{sc.id}  ({sc.line.upper()}, v{doc.get('version', 1)}, {doc.get('license', '')})")
    print(sc.title)
    print(textwrap.fill(doc["summary"].strip(), 88))
    print("\nMITRE ATT&CK:")
    for m in doc["mitre"]:
        cond = f"   [when {m['when']}]" if "when" in m else ""
        print(f"  {m['framework']:<10} {m['id']:<10} {m['name']}{cond}")
    print("\nDifficulty levels:")
    for name in sc.difficulties:
        level = sc.level(name)
        knobs = ", ".join(f"{k}={v}" for k, v in level.get("vars", {}).items())
        print(f"  {name:<7} duration={level['duration']}  impairments={level.get('impairments', {})}")
        print(textwrap.fill(knobs, 88, initial_indent="          ", subsequent_indent="          "))
    print(f"\nQuestions: {len(doc['questions'])}   Source: {sc.path}")
    return 0


def cmd_validate(args) -> int:
    paths = [Path(p) for p in args.paths] or [s.path for s in discover(_scenarios_dir(args)).values()]
    failed = 0
    for path in paths:
        try:
            sc = load(path)
            from pcapforge.plan import build_plan
            for difficulty in sc.difficulties:
                build_plan(sc, difficulty, "validate", duration_override=min(
                    600.0, parse_duration(sc.level(difficulty)["duration"])))
            print(f"ok    {path}")
        except (ScenarioError, KeyError, ValueError) as exc:
            failed += 1
            print(f"FAIL  {path}\n{exc}")
    return 1 if failed else 0


def _seeds(args) -> list[str]:
    if args.seeds_file:
        lines = Path(args.seeds_file).read_text(encoding="utf-8").splitlines()
        return [line.strip() for line in lines if line.strip() and not line.startswith("#")]
    if args.count > 1:
        return [f"{args.seed}-{i:02d}" for i in range(1, args.count + 1)]
    return [args.seed]


def cmd_generate(args) -> int:
    from pcapforge.pipeline import generate

    sc = find(args.scenario, _scenarios_dir(args))
    duration = parse_duration(args.duration) if args.duration else None
    status = 0
    for seed in _seeds(args):
        def progress(msg: str, seed=seed) -> None:
            if not args.quiet:
                print(f"  [{seed}] {msg}", file=sys.stderr, flush=True)

        out = generate(sc, args.difficulty, seed, Path(args.out), base_seed=args.base_seed,
                       fmt=args.format, use_cache=not args.no_cache, duration=duration,
                       verify=not args.no_verify, siem=args.siem, progress=progress)
        verdict = "not verified" if out.report is None else ("verified" if out.report.ok else "VERIFY FAILED")
        print(f"{out.pcap}  ({out.packets} packets, {verdict})")
        if out.exports:
            print(f"{out.directory / 'siem'}  {out.directory / 'detections'}")
        if out.report is not None and not out.report.ok:
            status = 2
            for check in out.report.checks:
                if not check["ok"]:
                    print(f"    FAIL {check['name']}: {check['detail']}", file=sys.stderr)
    return status


def cmd_verify(args) -> int:
    from pcapforge.verify import verify_capture

    answers = json.loads(Path(args.answers).read_text(encoding="utf-8")) if args.answers else None
    report = verify_capture(Path(args.pcap), answers)
    for check in report.checks:
        print(f"{'ok  ' if check['ok'] else 'FAIL'}  {check['name']}: {check['detail']}")
    return 0 if report.ok else 2


def cmd_export(args) -> int:
    from pcapforge.pipeline import export_run

    directory = Path(args.run_dir)
    if not (directory / "answers.json").is_file():
        print(f"error: {directory} has no answers.json (not a pcapforge run directory)", file=sys.stderr)
        return 1
    for _name, path in sorted(export_run(directory).items()):
        if path.suffix == ".jsonl":
            with open(path, encoding="utf-8") as fh:
                print(f"{path}  ({sum(1 for _ in fh)} records)")
        else:
            print(path)
    return 0


def cmd_grade(args) -> int:
    from pcapforge.grade import GradeError, format_report, grade, load_submissions

    try:
        answers = json.loads(Path(args.answers).read_text(encoding="utf-8"))
        report = grade(answers, load_submissions([Path(p) for p in args.submissions]))
    except (OSError, json.JSONDecodeError, KeyError, GradeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print(format_report(report), end="")
    return 0


def cmd_package(args) -> int:
    from pcapforge.package import PackageError, package_run

    out = Path(args.out) if args.out else None
    for run_dir in args.run_dirs:
        try:
            for path in package_run(Path(run_dir), out):
                print(path)
        except (OSError, KeyError, PackageError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pcapforge", description=(
        "Generate realistic, labeled PCAPs with answer keys for blue-team training."))
    parser.add_argument("--version", action="version", version=f"pcapforge {__version__}")
    parser.add_argument("--scenarios-dir", help="additional directory with scenario.yaml files")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("list", help="list available scenarios").set_defaults(func=cmd_list)

    p = sub.add_parser("show", help="describe a scenario")
    p.add_argument("scenario")
    p.set_defaults(func=cmd_show)

    p = sub.add_parser("validate", help="validate scenario files (schema + dry-run planning)")
    p.add_argument("paths", nargs="*")
    p.set_defaults(func=cmd_validate)

    p = sub.add_parser("generate", help="generate capture + answers.json + briefing.md + submission_template.yaml")
    p.add_argument("--scenario", "-s", required=True, help="scenario id or path to scenario.yaml")
    p.add_argument("--difficulty", "-d", choices=DIFFICULTIES, default="medium")
    p.add_argument("--seed", default="1", help="any string; same seed = same exercise")
    p.add_argument("--count", type=int, default=1, help="generate N variants: <seed>-01..N")
    p.add_argument("--seeds-file", help="one seed per line (e.g. student logins)")
    p.add_argument("--base-seed", help="share the recorded behaviour across seeds (faster batches)")
    p.add_argument("--out", "-o", default="out")
    p.add_argument("--format", choices=("pcap", "pcapng"), default="pcap")
    p.add_argument("--duration", help="override capture length, e.g. 20m")
    p.add_argument("--no-cache", action="store_true", help="always record fresh")
    p.add_argument("--no-verify", action="store_true", help="skip tshark verification")
    p.add_argument("--siem", action="store_true",
                   help="also write siem/*.jsonl logs and detections/ (Suricata rules, hunting guide)")
    p.add_argument("--quiet", "-q", action="store_true")
    p.set_defaults(func=cmd_generate)

    p = sub.add_parser("verify", help="check a capture (and optionally its answer key) with tshark")
    p.add_argument("pcap")
    p.add_argument("--answers", "-a")
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("export", help="(re)create siem/ and detections/ for an existing run directory")
    p.add_argument("run_dir", help="directory containing the capture and answers.json")
    p.set_defaults(func=cmd_export)

    p = sub.add_parser("grade", help="score student submissions against answers.json")
    p.add_argument("answers", help="the run's answers.json")
    p.add_argument("submissions", nargs="+",
                   help="YAML/JSON {question_id: answer} per student, or a CSV with student,question,answer")
    p.add_argument("--json", action="store_true", help="print the full report as JSON")
    p.set_defaults(func=cmd_grade)

    p = sub.add_parser("package", help="write <run>-student.zip and <run>-instructor.zip")
    p.add_argument("run_dirs", nargs="+", metavar="run_dir", help="run directory from generate")
    p.add_argument("--out", "-o", help="output directory (default: next to the run directory)")
    p.set_defaults(func=cmd_package)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (ScenarioError, ToolNotFound) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
