"""Class roster of the student mode: ``<out>/roster.json`` and the signed student sessions.

``roster.json`` maps each login to ``{"name", "code_hash", "salt"}``: the access code is stored
only as a PBKDF2-HMAC-SHA256 hash with a per-student salt, so the instructor UI shows a code once
(when it is issued) and never again. While the file exists, ``pcapforge ui --student`` asks for
login + code and keeps the student signed in with a cookie ``login|expiry|mac`` (HMAC-SHA256 with
the random server secret ``<out>/.ui-secret``); the mac also covers the student's salt, so a
reset or removal ends the sessions of that login.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import tempfile
import threading
import time
from pathlib import Path

from pcapforge.pipeline import slug
from pcapforge.ui.views import e

ROSTER = "roster.json"
SECRET = ".ui-secret"
ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # no I/O/0/1
ITERATIONS = 200_000
SESSION_S = 12 * 3600
MAX_STUDENTS = 500
MAX_NAME = 64
RESERVED = {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)), *(f"lpt{i}" for i in range(1, 10))}
_LOGIN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
_LOCK = threading.Lock()  # read-modify-write of roster.json by the instructor UI's request threads
_DUMMY_SALT = secrets.token_bytes(16)


class RosterError(ValueError):
    pass


# -- roster file -----------------------------------------------------------------------

def path(out: Path) -> Path:
    return out / ROSTER


def load(out: Path) -> dict[str, dict] | None:
    """The roster, or None when ``roster.json`` does not exist; an unreadable one raises ``RosterError``."""
    try:
        text = path(out).read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise RosterError(f"{ROSTER}: {exc}") from exc
    try:
        data = json.loads(text)
        if not isinstance(data, dict) or not all(
                isinstance(v, dict) and {"name", "code_hash", "salt"} <= set(v) for v in data.values()):
            raise ValueError("expected {login: {name, code_hash, salt}}")
        for v in data.values():
            bytes.fromhex(v["salt"])
    except (ValueError, TypeError) as exc:
        raise RosterError(f"{ROSTER}: {exc}") from exc
    return data


def names(out: Path) -> dict[str, str]:
    """``{login: display name}`` for the instructor's tables; empty without a readable roster."""
    try:
        return {login: str(v["name"]) for login, v in (load(out) or {}).items()}
    except RosterError:
        return {}


def _write_atomic(target: Path, text: str) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=target.parent, prefix=".", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        os.replace(tmp, target)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def save(out: Path, roster: dict[str, dict]) -> None:
    _write_atomic(path(out), json.dumps(roster, indent=2, ensure_ascii=False) + "\n")


# -- logins and codes ------------------------------------------------------------------

def clean_login(raw: str) -> str | None:
    """A login that is its own file name (``submissions/<login>.yaml``) and run seed, or None."""
    login = raw.strip()
    if not _LOGIN.fullmatch(login) or slug(login) != login or login.split(".")[0].lower() in RESERVED:
        return None
    return login


def clean_display(raw: str) -> str | None:
    name = " ".join(raw.split())
    return name if len(name) <= MAX_NAME and name.isprintable() else None


def find(roster: dict[str, dict], login: str) -> str | None:
    """The roster key of ``login`` (case-insensitive: submission files must not differ only in case)."""
    wanted = login.strip().casefold()
    return next((key for key in roster if key.casefold() == wanted), None)


def new_code() -> str:
    return "-".join("".join(secrets.choice(ALPHABET) for _ in range(4)) for _ in range(3))


def _hash(code: str, salt: bytes) -> str:
    canonical = "".join(code.split()).replace("-", "").upper()
    return hashlib.pbkdf2_hmac("sha256", canonical.encode("utf-8"), salt, ITERATIONS).hex()


def _entry(name: str, code: str) -> dict:
    salt = secrets.token_bytes(16)
    return {"name": name, "code_hash": _hash(code, salt), "salt": salt.hex()}


def check(roster: dict[str, dict], login: str, code: str) -> str | None:
    """The roster login when ``code`` is its access code, else None (an unknown login costs the same hash)."""
    key = find(roster, login)
    entry = roster.get(key) if key else None
    digest = _hash(code, bytes.fromhex(entry["salt"]) if entry else _DUMMY_SALT)
    ok = hmac.compare_digest(digest, entry["code_hash"] if entry else "0" * len(digest))
    return key if ok and entry else None


def parse_list(text: str) -> list[tuple[str, str | None]]:
    """``login`` or ``login, Display Name`` per line; blank lines and ``#`` comments are skipped.
    Every bad line is reported at once (``RosterError``)."""
    items: list[tuple[str, str | None]] = []
    errors: list[str] = []
    seen: dict[str, int] = {}
    for number, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        raw_login, _, raw_name = line.partition(",")
        login, name = clean_login(raw_login), clean_display(raw_name)
        if login is None:
            errors.append(f"line {number}: login {raw_login.strip()!r}: 1-64 of A-Z a-z 0-9 . _ - "
                          "(starting with a letter or digit)")
            continue
        if name is None:
            errors.append(f"line {number}: name: at most {MAX_NAME} printable characters")
            continue
        if login.casefold() in seen:
            errors.append(f"line {number}: {login!r} repeats line {seen[login.casefold()]}")
            continue
        seen[login.casefold()] = number
        items.append((login, name or None))
    if errors:
        raise RosterError("\n".join(errors))
    if not items:
        raise RosterError("no logins: one per line, optionally followed by a comma and the display name")
    return items


def add(out: Path, text: str) -> tuple[list[dict], list[dict]]:
    """Add the pasted students with a new code each; logins already in the roster keep their code
    (a given name replaces theirs). Returns (issued ``{login, name, code}``, kept ``{login, name}``)."""
    items = parse_list(text)
    with _LOCK:
        roster = load(out) or {}
        issued, kept = [], []
        for login, name in items:
            key = find(roster, login)
            if key is not None:
                if name:
                    roster[key]["name"] = name
                kept.append({"login": key, "name": roster[key]["name"]})
                continue
            code = new_code()
            roster[login] = _entry(name or login, code)
            issued.append({"login": login, "name": name or login, "code": code})
        if len(roster) > MAX_STUDENTS:
            raise RosterError(f"at most {MAX_STUDENTS} students in a roster")
        save(out, roster)
    return issued, kept


def reset(out: Path, login: str) -> dict:
    """A new code for ``login`` (the old one and its sessions stop working)."""
    with _LOCK:
        roster = load(out) or {}
        key = find(roster, login)
        if key is None:
            raise RosterError(f"{login!r} is not in the roster")
        code = new_code()
        roster[key] = _entry(roster[key]["name"], code)
        save(out, roster)
    return {"login": key, "name": roster[key]["name"], "code": code}


def remove(out: Path, login: str) -> None:
    """Drop ``login`` (its submissions stay); an empty roster still requires codes."""
    with _LOCK:
        roster = load(out) or {}
        key = find(roster, login)
        if key is None:
            raise RosterError(f"{login!r} is not in the roster")
        del roster[key]
        save(out, roster)


# -- sessions --------------------------------------------------------------------------

def server_secret(out: Path) -> bytes:
    """``<out>/.ui-secret`` (created on first use, owner-only where the OS supports it)."""
    target = out / SECRET
    try:
        return bytes.fromhex(target.read_text(encoding="ascii").strip())
    except FileNotFoundError:
        pass
    value = secrets.token_bytes(32)
    out.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    except FileExistsError:  # another request created it first
        return bytes.fromhex(target.read_text(encoding="ascii").strip())
    with os.fdopen(fd, "w", encoding="ascii") as fh:
        fh.write(value.hex())
    return value


def _mac(key: bytes, login: str, expiry: int, salt: str) -> str:
    return hmac.new(key, f"{login}|{expiry}|{salt}".encode("utf-8"), hashlib.sha256).hexdigest()


def sign(key: bytes, roster: dict[str, dict], login: str, now: float | None = None) -> str:
    expiry = int(now if now is not None else time.time()) + SESSION_S
    return f"{login}|{expiry}|{_mac(key, login, expiry, roster[login]['salt'])}"


def session_login(key: bytes, roster: dict[str, dict], value: str, now: float | None = None) -> str | None:
    """The login of a valid, unexpired session cookie of a student still in the roster, else None."""
    parts = value.split("|")
    if len(parts) != 3 or not parts[1].isdigit():
        return None
    login, expiry, mac = parts[0], int(parts[1]), parts[2]
    entry = roster.get(login)
    if entry is None or expiry < (now if now is not None else time.time()):
        return None
    return login if hmac.compare_digest(mac, _mac(key, login, expiry, entry["salt"])) else None


# -- instructor pages ------------------------------------------------------------------

_INTRO = ('<p class="dim">While <code>roster.json</code> exists in the output directory, '
          "<code>pcapforge ui --student</code> asks for login + access code; without it, students type any "
          "name (honour system). Only hashes of the codes are stored: a code is shown once, when it is "
          "issued; a lost code is reset, not looked up. The submission file of a student is "
          "<code>submissions/&lt;login&gt;.yaml</code>.</p>")


def _post(action: str, login: str, label: str) -> str:
    return (f'<form method="post" action="/students/{action}">'
            f'<input type="hidden" name="login" value="{e(login)}"><button type="submit">{e(label)}</button></form>')


def students_page(roster: dict[str, dict] | None, error: str = "") -> str:
    body = ["<h1>students</h1>", _INTRO]
    if error:
        body.append(f'<pre class="err">{e(error)}</pre>')
    if roster is None:
        body.append('<p>No roster yet: students sign in by name (honour system).</p>')
    else:
        rows = "".join(f"<tr><td><code>{e(login)}</code></td><td>{e(v['name'])}</td><td><div class=\"group\">"
                       f"{_post('reset', login, 'reset code')}{_post('remove', login, 'remove')}</div></td></tr>"
                       for login, v in sorted(roster.items(), key=lambda kv: kv[0].casefold()))
        body.append(f"<h2>roster ({len(roster)})</h2>")
        body.append('<table class="grid"><thead><tr><th>login</th><th>name</th><th></th></tr></thead>'
                    f"<tbody>{rows}</tbody></table>" if roster
                    else '<p class="alert">The roster is empty: nobody can sign in to the student mode. '
                         "Add students, or delete roster.json to return to the honour system.</p>")
        if roster:
            seeds = "\n".join(sorted(roster, key=str.casefold))
            body += ['<details><summary>logins as a seed list</summary>'
                     '<p class="dim small">Paste into the batch seeds of a scenario (generate &rarr; batch): one run '
                     "per student, and each student's exercise list shows only their own run.</p>"
                     f'<textarea readonly rows="{min(12, len(roster) + 1)}" cols="40" spellcheck="false">'
                     f"{e(seeds)}</textarea></details>"]
    body += ["<h2>add students</h2>",
             '<form method="post" action="/students/add"><p><label>logins, one per line: <code>login</code> or '
             '<code>login, Display Name</code><br><textarea name="logins" rows="8" cols="50" spellcheck="false" '
             'required placeholder="# class 3b&#10;alice, Alice Adams&#10;bob"></textarea></label></p>'
             '<p class="dim small">Each new login gets a random access code, shown once on the next page; logins '
             "already in the roster keep theirs. Blank lines and # comments are skipped. Use the same logins as "
             "the seed list of a class batch.</p><button type=\"submit\">add students</button></form>"]
    return "".join(body)


def codes_page(issued: list[dict], kept: list[dict]) -> str:
    body = ["<h1>access codes</h1>"]
    if issued:
        rows = "".join(f"<tr><td><code>{e(x['login'])}</code></td><td>{e(x['name'])}</td>"
                       f"<td><code>{e(x['code'])}</code></td></tr>" for x in issued)
        body += ['<p class="alert">Shown once: print or copy these codes now. Only their hashes are stored; '
                 "a lost code can only be reset.</p>",
                 '<table class="grid codes"><thead><tr><th>login</th><th>name</th><th>code</th></tr></thead>'
                 f"<tbody>{rows}</tbody></table>"]
    if kept:
        body.append('<p class="dim">Already in the roster (code unchanged): '
                    + ", ".join(f"<code>{e(x['login'])}</code>" for x in kept) + "</p>")
    body.append('<p><a href="/students">back to the roster</a> &middot; <span class="dim">students sign in '
                "to the student mode (<code>pcapforge ui --student</code>) with login + code</span></p>")
    return "".join(body)
