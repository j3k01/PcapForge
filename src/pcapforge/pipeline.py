"""End-to-end generation: plan -> record (cached) -> compose -> answer key -> verify."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from pcapforge.answers import build_answers, write_handout
from pcapforge.compose import compose
from pcapforge.detections import write_detections
from pcapforge.export import export_siem
from pcapforge.plan import build_plan
from pcapforge.record import recording_for
from pcapforge.scenario import Scenario
from pcapforge.tools import require_answer_key_tshark
from pcapforge.verify import VerifyReport, verify_capture


@dataclass
class Generated:
    directory: Path
    pcap: Path
    answers: Path
    handout: Path
    packets: int
    cached_recording: bool
    report: VerifyReport | None
    exports: dict[str, Path] = field(default_factory=dict)


def slug(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", text).strip("_") or "seed"


def write_exports(pcap: Path, answers: dict, directory: Path) -> dict[str, Path]:
    """SIEM logs into ``<run>/siem/`` and detection content into ``<run>/detections/``."""
    paths = {f"siem/{name}": path for name, path in export_siem(pcap, answers, directory / "siem").items()}
    paths.update({f"detections/{name}": path
                  for name, path in write_detections(answers, directory / "detections").items()})
    return paths


def export_run(directory: Path) -> dict[str, Path]:
    """(Re)create the SIEM export and detection content of an existing run directory."""
    answers = json.loads((directory / "answers.json").read_text(encoding="utf-8"))
    return write_exports(directory / answers["capture"]["file"], answers, directory)


def generate(scenario: Scenario, difficulty: str, seed: str, out_root: Path, *,
             base_seed: str | None = None, fmt: str = "pcap", use_cache: bool = True,
             duration: float | None = None, verify: bool = True, siem: bool = False,
             progress: Callable[[str], None] = lambda _msg: None) -> Generated:
    if verify:
        require_answer_key_tshark()  # before spending time on recording and composing
    plan = build_plan(scenario, difficulty, seed, base_seed=base_seed, duration_override=duration)
    progress(f"plan: {len(plan.actions)} actions, recording key {plan.digest()}")

    def on_record(done: int, total: int) -> None:
        progress(f"recording {done}/{total}")

    recording, cached = recording_for(plan, use_cache=use_cache, progress=on_record)
    progress("recording: " + ("cache hit" if cached else "captured"))

    directory = out_root / f"{scenario.id}_{difficulty}_{slug(str(seed))}"
    directory.mkdir(parents=True, exist_ok=True)
    pcap = directory / f"capture.{'pcapng' if fmt == 'pcapng' else 'pcap'}"
    result = compose(plan, recording, pcap, str(seed), fmt=fmt)
    progress(f"composed {result.packets} packets")

    answers = build_answers(plan, result)
    answers_path = directory / "answers.json"
    answers_path.write_text(json.dumps(answers, indent=2, ensure_ascii=False), encoding="utf-8")
    handout = write_handout(plan, answers, directory)

    report = verify_capture(pcap, answers) if verify else None
    exports = write_exports(pcap, answers, directory) if siem else {}
    if exports:
        progress(f"exported {len(exports)} SIEM / detection files")
    return Generated(directory, pcap, answers_path, handout, result.packets, cached, report, exports)
