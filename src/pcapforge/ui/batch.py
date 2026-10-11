"""Batches in the web UI: the seed list of a class (one generation per seed, like
``--seeds-file``) and the runs page, filtered by scenario / level and grouped per batch with a
``package all`` action."""

from __future__ import annotations

from urllib.parse import quote, urlencode

from pcapforge.scenario import DIFFICULTIES
from pcapforge.ui.views import _runs_table, e

MAX_SEEDS = 200
MAX_SEED_LEN = 64


def parse_seed(text: str, field: str) -> str:
    seed = text.strip()
    if len(seed) > MAX_SEED_LEN:
        raise ValueError(f"{field}: at most {MAX_SEED_LEN} characters")
    return seed


def parse_seeds(text: str) -> list[str]:
    """One seed per line; blank lines and ``#`` comment lines are skipped. Too many seeds, too long
    ones and duplicates (also seeds that would write the same run directory) raise ``ValueError``."""
    from pcapforge.pipeline import slug

    seeds: list[str] = []
    seen: dict[str, tuple[int, str]] = {}
    for number, line in enumerate(text.splitlines(), 1):
        seed = line.strip()
        if not seed or seed.startswith("#"):
            continue
        seed = parse_seed(seed, f"seeds line {number}")
        key = slug(seed)
        if key in seen:
            first, other = seen[key]
            same = "" if other == seed else f" (both write the run directory ..._{key})"
            raise ValueError(f"seeds line {number}: {seed!r} duplicates line {first}: {other!r}{same}")
        seen[key] = (number, seed)
        seeds.append(seed)
        if len(seeds) > MAX_SEEDS:
            raise ValueError(f"seeds: at most {MAX_SEEDS} per batch")
    return seeds


# -- runs page -------------------------------------------------------------------------

def matching(items: list[dict], scenario: str, level: str) -> list[dict]:
    """Runs of ``scenario`` at ``level``; an empty filter matches every run."""
    return [r for r in items
            if (not scenario or r["scenario"] == scenario) and (not level or r["difficulty"] == level)]


def _level_key(level: str) -> tuple[int, str]:
    return (DIFFICULTIES.index(level), "") if level in DIFFICULTIES else (len(DIFFICULTIES), level)


def _select(name: str, values: list[str], selected: str) -> str:
    options = "".join(f'<option{" selected" if v == selected else ""}>{e(v)}</option>' for v in values)
    return f'<label>{e(name)} <select name="{e(name)}"><option value="">all</option>{options}</select></label>'


def runs_page(items: list[dict], scenario: str, level: str) -> str:
    """All runs (``items``, newest first) filtered by ``scenario`` / ``level``, one group per
    scenario and level, each with a ``package all`` button."""
    if not items:
        return '<h1>runs</h1><p>No runs yet. Pick a scenario and <a href="/">generate</a> one.</p>'
    scenarios = sorted({r["scenario"] for r in items} | ({scenario} if scenario else set()))
    levels = sorted({r["difficulty"] for r in items} | ({level} if level else set()), key=_level_key)
    shown = matching(items, scenario, level)
    body = ['<h1>runs</h1><form class="gen filter" method="get" action="/runs">',
            _select("scenario", scenarios, scenario), _select("level", levels, level),
            f'<span class="dim">{len(shown)} of {len(items)} runs</span>',
            '<a href="/runs">clear</a><button type="submit">filter</button></form>']
    if not shown:
        body.append("<p>No runs match the filter.</p>")
    groups: dict[tuple[str, str], list[dict]] = {}
    for r in shown:
        groups.setdefault((r["scenario"], r["difficulty"]), []).append(r)
    for (sc, lv), group in groups.items():
        query = urlencode({"scenario": sc, "level": lv})
        body.append(
            f'<div class="group"><h2><a href="/scenarios/{quote(sc)}">{e(sc)}</a> &middot; '
            f'<a href="/runs?{e(query)}">{e(lv)}</a> &middot; {len(group)} run{"s" if len(group) != 1 else ""}</h2>'
            f'<form method="post" action="/package-all"><input type="hidden" name="scenario" value="{e(sc)}">'
            f'<input type="hidden" name="level" value="{e(lv)}">'
            f'<button type="submit" title="student and instructor zip of every run of this group">'
            f'package all</button></form></div>' + _runs_table(group))
    return "".join(body)
