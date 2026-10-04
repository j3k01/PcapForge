"""Student-facing languages: handout and submission-template strings, scenario translations.

Answers, filters and identifiers stay language-neutral; only prose is translated. Scenarios
provide their own prose under `translations: {<lang>: {title, briefing, questions: {id: {text, hint}}}}`.
"""

from __future__ import annotations

import copy

from pcapforge.scenario import resolve

LANGS = ("en", "pl")

UI = {
    "en": {
        "capture": "Capture: `{file}` ({packets} packets, SHA-256 `{sha256}`).",
        "asset_inventory": "Asset inventory",
        "inventory_cols": ["Name", "Role", "IP", "Vendor"],
        "network": "Network",
        "network_cols": ["Subnet", "CIDR", "Gateway", "Capture point"],
        "yes": "yes",
        "no": "no",
        "register_map": "Register map: {title}",
        "regmap_note": "Modbus unit id {unit}; served by {hosts}. Addresses are 0-based; "
                       "engineering value = raw register value / scale.",
        "regmap_cols": ["Table", "Address", "Name", "Unit", "Scale", "Normal band", "Writable"],
        "questions": "Questions",
        "points": "points",
        "tmpl_title": "# pcapforge submission: {title}",
        "tmpl_howto": [
            "# Write each answer after its colon; quote answers that contain ': ' or start with '[' or '{'.",
            "# Save under your name (e.g. jane-doe.yaml); your instructor grades it with",
            "#   pcapforge grade answers.json jane-doe.yaml",
        ],
        "tmpl_answer": "answer",
        "tmpl_hint": "Hint (using it costs {cost} points):",
        "tmpl_hints_used": ["# Honour system: list the ids of every question whose hint you read, e.g. [source_ip]."],
        "formats": {
            "ip": "an IP address",
            "mac": "a MAC address",
            "number": "a number",
            "timestamp": "a UTC time, ISO 8601: YYYY-MM-DDTHH:MM:SS.ffffffZ",
            "set": "a list: [a, b, c]",
            "map": "a map: {name: value, name: value}",
        },
    },
    "pl": {
        "capture": "Nagranie: `{file}` ({packets} pakietów, SHA-256 `{sha256}`).",
        "asset_inventory": "Inwentarz zasobów",
        "inventory_cols": ["Nazwa", "Rola", "IP", "Producent"],
        "network": "Sieć",
        "network_cols": ["Podsieć", "CIDR", "Brama", "Punkt nagrywania"],
        "yes": "tak",
        "no": "nie",
        "register_map": "Mapa rejestrów: {title}",
        "regmap_note": "Modbus unit id {unit}; obsługiwane przez {hosts}. Adresy liczone od 0; "
                       "wartość inżynierska = surowa wartość rejestru / skala.",
        "regmap_cols": ["Tabela", "Adres", "Nazwa", "Jednostka", "Skala", "Zakres normalny", "Zapisywalny"],
        "questions": "Pytania",
        "points": "pkt",
        "tmpl_title": "# Odpowiedzi pcapforge: {title}",
        "tmpl_howto": [
            "# Wpisz odpowiedź po dwukropku; odpowiedzi zawierające ': ' lub zaczynające się od '[' lub '{' ujmij w cudzysłów.",
            "# Zapisz plik pod swoim nazwiskiem (np. jan-kowalski.yaml); prowadzący oceni go poleceniem",
            "#   pcapforge grade answers.json jan-kowalski.yaml",
        ],
        "tmpl_answer": "odpowiedź",
        "tmpl_hint": "Podpowiedź (skorzystanie kosztuje {cost} pkt):",
        "tmpl_hints_used": ["# Uczciwie: wpisz identyfikatory pytań, których podpowiedzi przeczytałeś, np. [source_ip]."],
        "formats": {
            "ip": "adres IP",
            "mac": "adres MAC",
            "number": "liczba",
            "timestamp": "czas UTC, ISO 8601: RRRR-MM-DDTGG:MM:SS.ffffffZ",
            "set": "lista: [a, b, c]",
            "map": "mapa: {nazwa: wartość, nazwa: wartość}",
        },
    },
}


def ui(lang: str) -> dict:
    return UI.get(lang, UI["en"])


def scenario_text(scenario_doc: dict, lang: str) -> dict:
    """Translated title/briefing/questions for ``lang`` (empty when not provided)."""
    if lang == "en":
        return {}
    return scenario_doc.get("translations", {}).get(lang, {})


def localize_answers(answers: dict, scenario_doc: dict, lang: str, ctx: dict) -> dict:
    """Copy of ``answers`` with question prose in ``lang``; answers/checks unchanged."""
    out = copy.deepcopy(answers)
    out["lang"] = lang
    texts = scenario_text(scenario_doc, lang)
    if "title" in texts:
        out["scenario"]["title"] = texts["title"]
    for question in out["questions"]:
        translated = texts.get("questions", {}).get(question["id"], {})
        for key in ("text", "hint"):
            if key in translated:
                question[key] = resolve(translated[key], ctx)
    return out
