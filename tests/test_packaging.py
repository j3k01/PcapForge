"""The wheel must contain every code package and the scenarios (packages are listed explicitly)."""

import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_every_source_package_and_the_scenarios_are_packaged():
    config = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["tool"]["setuptools"]
    listed = set(config["packages"])
    src = ROOT / "src"
    found = {".".join(p.parent.relative_to(src).parts) for p in src.rglob("__init__.py")}
    assert found <= listed, f"add to pyproject [tool.setuptools] packages: {sorted(found - listed)}"
    assert config["package-dir"]["pcapforge._scenarios"] == "scenarios"
    assert any((ROOT / "scenarios").rglob("scenario.yaml"))
