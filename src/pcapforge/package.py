"""Hand-out packaging of a run directory: a student zip without any answer material, an instructor zip
with everything."""

from __future__ import annotations

import json
import shutil
import zipfile
from pathlib import Path

from pcapforge.grade import TEMPLATE_NAME, submission_template

# Fixed member metadata so the same run directory always gives byte-identical zips.
_ZIP_DATE = (1980, 1, 1, 0, 0, 0)
_FILE_MODE = 0o644 << 16


class PackageError(ValueError):
    """The directory is not a complete pcapforge run."""


def _member(zf: zipfile.ZipFile, name: str, source: Path | None = None, data: bytes | None = None) -> None:
    info = zipfile.ZipInfo(name, date_time=_ZIP_DATE)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = _FILE_MODE
    with zf.open(info, "w") as dst:
        if source is not None:
            with open(source, "rb") as src:
                shutil.copyfileobj(src, dst, 1 << 20)
        else:
            dst.write(data or b"")


def _write_zip(path: Path, prefix: str, files: list[tuple[str, Path]], template: bytes | None) -> None:
    """``files`` are (relative name, source); ``template`` is added when the run has no template file."""
    members = list(files)
    with zipfile.ZipFile(path, "w") as zf:
        if template is not None:
            members.append((TEMPLATE_NAME, None))
        for name, source in sorted(members, key=lambda m: m[0]):
            if source is None:
                _member(zf, f"{prefix}/{name}", data=template)
            else:
                _member(zf, f"{prefix}/{name}", source)


def package_run(run_dir: Path, out_dir: Path | None = None) -> tuple[Path, Path]:
    """Write ``<run>-student.zip`` (capture, briefing.md, submission_template.yaml) and
    ``<run>-instructor.zip`` (the whole run directory) into ``out_dir`` (default: next to the run)."""
    name = run_dir.resolve().name
    answers_path = run_dir / "answers.json"
    if not answers_path.is_file():
        raise PackageError(f"{run_dir} has no answers.json (not a pcapforge run directory)")
    answers = json.loads(answers_path.read_text(encoding="utf-8"))
    capture = run_dir / answers["capture"]["file"]
    briefing = run_dir / "briefing.md"
    for required in (capture, briefing):
        if not required.is_file():
            raise PackageError(f"{run_dir} has no {required.name}")
    if out_dir is None:  # next to the run; Path(".").parent is "." itself
        out_dir = run_dir.parent if run_dir.parent.resolve() == run_dir.resolve().parent else run_dir.resolve().parent
    if out_dir.resolve().is_relative_to(run_dir.resolve()):
        raise PackageError(f"the output directory must be outside the run directory {run_dir}")
    has_template = (run_dir / TEMPLATE_NAME).is_file()
    template = None if has_template else submission_template(answers).encode("utf-8")
    student = [(capture.name, capture), (briefing.name, briefing)]
    if has_template:
        student.append((TEMPLATE_NAME, run_dir / TEMPLATE_NAME))
    instructor = [(p.relative_to(run_dir).as_posix(), p) for p in sorted(run_dir.rglob("*")) if p.is_file()]

    out_dir.mkdir(parents=True, exist_ok=True)
    student_zip, instructor_zip = out_dir / f"{name}-student.zip", out_dir / f"{name}-instructor.zip"
    _write_zip(student_zip, name, student, template)
    _write_zip(instructor_zip, name, instructor, template)
    return student_zip, instructor_zip
