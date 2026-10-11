"""Student-facing languages: handout and submission-template strings, scenario translations.

Answers, filters and identifiers stay language-neutral; only prose is translated. Scenarios
provide their own prose under `translations: {<lang>: {title, briefing, questions: {id: {text, hint}}}}`.
"""

from __future__ import annotations

import copy

from pcapforge.scenario import resolve

LANGS = ("en", "pl", "de")

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
        "regmap_note": "Modbus unit id {unit}; served by {hosts}. {addressing}; "
                       "engineering value of a UINT16 = raw register value / scale.",
        "regmap_float_big": "A FLOAT32 is an IEEE 754 single-precision value in two consecutive registers, "
                            "high word first (ABCD).",
        "regmap_float_little": "A FLOAT32 is an IEEE 754 single-precision value in two consecutive registers, "
                               "low word first (CDAB, word-swapped).",
        "regmap_addr_zero": "Addresses are 0-based",
        "regmap_addr_vendor": "Register numbers follow the vendor convention (e.g. 40001 = holding "
                              "register 0 on the wire); filters and the answer key use the 0-based wire address",
        "regmap_cols": ["Table", "Register", "Name", "Description", "Unit", "Type", "Scale", "Normal band",
                        "Writable"],
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
        "st_mode": "student mode",
        "st_exercises": "exercises",
        "st_who": "Who are you?",
        "st_name": "name or login",
        "st_continue": "continue",
        "st_honour": "Mode: honour system. There is no password: the name labels your submissions for the "
                     "instructor; when it is the seed of your exercise (e.g. your login), you only see your own runs.",
        "st_roster": "Mode: class roster. Sign in with your login and the access code from your instructor; "
                     "you stay signed in for 12 hours in this browser.",
        "st_login": "login",
        "st_code": "access code",
        "st_sign_in": "sign in",
        "st_bad_login": "Unknown login or wrong access code.",
        "st_bad_name": "Use 1-{max} printable characters with at least one letter or digit (A-Z, 0-9).",
        "st_signed_in": "signed in as",
        "st_sign_out": "sign out",
        "st_none": "No exercises in this directory yet.",
        "st_mine": "your exercises (seed = your login)",
        "st_all": "all exercises (none has your login as its seed)",
        "st_list_cols": ["exercise", "level", "seed", "packets", "length", "status"],
        "st_done": "submitted",
        "st_open": "open",
        "st_meta": ["scenario", "level / seed", "capture", "window", "sha-256"],
        "st_packets": "packets",
        "st_downloads": "downloads",
        "st_briefing": "briefing",
        "st_questions": "questions ({n})",
        "st_hint": "hint",
        "st_used_hint": "I used this hint (-{cost} {points})",
        "st_prefilled": "Your last submission ({saved}) is filled in; submitting again replaces it.",
        "st_hint_note": "Hints are honour-system too: tick the ones you read.",
        "st_submit": "submit",
        "st_set_placeholder": "one per line",
        "st_map_placeholder": "name = value, one per line",
        "st_submitted": "submitted",
        "st_saved": "Your answers to {title} were saved ({saved}). You can change them and submit again until "
                    "your instructor collects them.",
        "st_graded_later": "Your instructor grades the submissions.",
        "st_score": "score",
        "st_result_cols": ["#", "question", "result", "score", "hint"],
        "st_results": {"correct": "correct", "partial": "partial", "wrong": "wrong", "blank": "blank"},
        "st_not_found": "No such page.",
        "st_broken": "This exercise cannot be read. Tell your instructor.",
        "st_roster_broken": "The class roster cannot be read. Tell your instructor.",
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
        "regmap_note": "Modbus unit id {unit}; obsługiwane przez {hosts}. {addressing}; "
                       "wartość inżynierska UINT16 = surowa wartość rejestru / skala.",
        "regmap_float_big": "FLOAT32 to wartość IEEE 754 pojedynczej precyzji w dwóch kolejnych rejestrach, "
                            "najpierw słowo starsze (ABCD).",
        "regmap_float_little": "FLOAT32 to wartość IEEE 754 pojedynczej precyzji w dwóch kolejnych rejestrach, "
                               "najpierw słowo młodsze (CDAB, zamienione słowa).",
        "regmap_addr_zero": "Adresy liczone od 0",
        "regmap_addr_vendor": "Numery rejestrów według konwencji producenta (np. 40001 = rejestr holding 0 "
                              "na łączu); filtry i klucz odpowiedzi używają adresu 0-based z łącza",
        "regmap_cols": ["Tabela", "Rejestr", "Nazwa", "Opis", "Jednostka", "Typ", "Skala", "Zakres normalny",
                        "Zapisywalny"],
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
        "st_mode": "tryb studenta",
        "st_exercises": "ćwiczenia",
        "st_who": "Kim jesteś?",
        "st_name": "imię i nazwisko lub login",
        "st_continue": "dalej",
        "st_honour": "Tryb: zasada zaufania. Nie ma hasła: imię podpisuje Twoje odpowiedzi dla prowadzącego; "
                     "jeśli jest ziarnem (seed) Twojego ćwiczenia (np. Twój login), widzisz tylko swoje ćwiczenia.",
        "st_roster": "Tryb: lista grupy. Zaloguj się loginem i kodem dostępu od prowadzącego; "
                     "pozostajesz zalogowany w tej przeglądarce przez 12 godzin.",
        "st_login": "login",
        "st_code": "kod dostępu",
        "st_sign_in": "zaloguj",
        "st_bad_login": "Nieznany login lub błędny kod dostępu.",
        "st_bad_name": "Użyj 1-{max} drukowalnych znaków, w tym co najmniej jednej litery lub cyfry (A-Z, 0-9).",
        "st_signed_in": "zalogowano jako",
        "st_sign_out": "wyloguj",
        "st_none": "W tym katalogu nie ma jeszcze ćwiczeń.",
        "st_mine": "Twoje ćwiczenia (seed = Twój login)",
        "st_all": "wszystkie ćwiczenia (żadne nie ma Twojego loginu jako seed)",
        "st_list_cols": ["ćwiczenie", "poziom", "seed", "pakiety", "długość", "status"],
        "st_done": "wysłane",
        "st_open": "otwarte",
        "st_meta": ["scenariusz", "poziom / seed", "nagranie", "okno czasowe", "sha-256"],
        "st_packets": "pakietów",
        "st_downloads": "pliki do pobrania",
        "st_briefing": "opis zadania",
        "st_questions": "pytania ({n})",
        "st_hint": "podpowiedź",
        "st_used_hint": "Skorzystałem z tej podpowiedzi (-{cost} {points})",
        "st_prefilled": "Wpisano Twoje ostatnie odpowiedzi ({saved}); ponowne wysłanie je zastąpi.",
        "st_hint_note": "Podpowiedzi też działają na zasadzie zaufania: zaznacz te, które przeczytałeś.",
        "st_submit": "wyślij",
        "st_set_placeholder": "jedna wartość w wierszu",
        "st_map_placeholder": "nazwa = wartość, jedna para w wierszu",
        "st_submitted": "wysłano",
        "st_saved": "Twoje odpowiedzi do {title} zostały zapisane ({saved}). Możesz je zmieniać i wysyłać ponownie, "
                    "dopóki prowadzący ich nie zbierze.",
        "st_graded_later": "Odpowiedzi ocenia prowadzący.",
        "st_score": "wynik",
        "st_result_cols": ["#", "pytanie", "ocena", "punkty", "podpowiedź"],
        "st_results": {"correct": "poprawna", "partial": "częściowa", "wrong": "błędna", "blank": "brak"},
        "st_not_found": "Nie ma takiej strony.",
        "st_broken": "Nie można odczytać tego ćwiczenia. Powiadom prowadzącego.",
        "st_roster_broken": "Nie można odczytać listy grupy. Powiadom prowadzącego.",
        "formats": {
            "ip": "adres IP",
            "mac": "adres MAC",
            "number": "liczba",
            "timestamp": "czas UTC, ISO 8601: RRRR-MM-DDTGG:MM:SS.ffffffZ",
            "set": "lista: [a, b, c]",
            "map": "mapa: {nazwa: wartość, nazwa: wartość}",
        },
    },
    "de": {
        "capture": "Mitschnitt: `{file}` ({packets} Pakete, SHA-256 `{sha256}`).",
        "asset_inventory": "Anlageninventar",
        "inventory_cols": ["Name", "Rolle", "IP", "Hersteller"],
        "network": "Netzwerk",
        "network_cols": ["Subnetz", "CIDR", "Gateway", "Mitschnittpunkt"],
        "yes": "ja",
        "no": "nein",
        "register_map": "Registertabelle: {title}",
        "regmap_note": "Modbus Unit-ID {unit}; bereitgestellt von {hosts}. {addressing}; "
                       "physikalischer Wert eines UINT16 = Rohwert des Registers / Skalierung.",
        "regmap_float_big": "Ein FLOAT32 ist ein IEEE-754-Wert einfacher Genauigkeit in zwei aufeinanderfolgenden "
                            "Registern, höherwertiges Wort zuerst (ABCD).",
        "regmap_float_little": "Ein FLOAT32 ist ein IEEE-754-Wert einfacher Genauigkeit in zwei aufeinanderfolgenden "
                               "Registern, niederwertiges Wort zuerst (CDAB, Wörter vertauscht).",
        "regmap_addr_zero": "Adressen beginnen bei 0",
        "regmap_addr_vendor": "Registernummern folgen der Herstellerkonvention (z. B. 40001 = Holding-Register 0 "
                              "auf der Leitung); Filter und Lösungsschlüssel verwenden die 0-basierte Leitungsadresse",
        "regmap_cols": ["Tabelle", "Register", "Name", "Beschreibung", "Einheit", "Typ", "Skalierung",
                        "Normalbereich", "Beschreibbar"],
        "questions": "Fragen",
        "points": "Pkt.",
        "tmpl_title": "# pcapforge-Abgabe: {title}",
        "tmpl_howto": [
            "# Antwort jeweils nach dem Doppelpunkt eintragen; Antworten mit ': ' oder beginnend mit '[' oder '{' in Anführungszeichen setzen.",
            "# Unter eigenem Namen speichern (z. B. max-mustermann.yaml); die Lehrkraft bewertet sie mit",
            "#   pcapforge grade answers.json max-mustermann.yaml",
        ],
        "tmpl_answer": "Antwort",
        "tmpl_hint": "Hinweis (Nutzung kostet {cost} Pkt.):",
        "tmpl_hints_used": ["# Ehrensache: IDs aller Fragen auflisten, deren Hinweis gelesen wurde, z. B. [source_ip]."],
        "st_mode": "Studentenmodus",
        "st_exercises": "Übungen",
        "st_who": "Wer bist du?",
        "st_name": "Name oder Login",
        "st_continue": "weiter",
        "st_honour": "Modus: Ehrensache. Es gibt kein Passwort: Der Name kennzeichnet deine Abgaben für die "
                     "Lehrkraft; ist er der Seed deiner Übung (z. B. dein Login), siehst du nur deine eigenen Übungen.",
        "st_roster": "Modus: Kursliste. Melde dich mit deinem Login und dem Zugangscode der Lehrkraft an; "
                     "du bleibst in diesem Browser 12 Stunden angemeldet.",
        "st_login": "Login",
        "st_code": "Zugangscode",
        "st_sign_in": "anmelden",
        "st_bad_login": "Unbekannter Login oder falscher Zugangscode.",
        "st_bad_name": "1-{max} druckbare Zeichen verwenden, mindestens ein Buchstabe oder eine Ziffer (A-Z, 0-9).",
        "st_signed_in": "angemeldet als",
        "st_sign_out": "abmelden",
        "st_none": "In diesem Verzeichnis gibt es noch keine Übungen.",
        "st_mine": "deine Übungen (Seed = dein Login)",
        "st_all": "alle Übungen (keine hat deinen Login als Seed)",
        "st_list_cols": ["Übung", "Stufe", "Seed", "Pakete", "Dauer", "Status"],
        "st_done": "abgegeben",
        "st_open": "offen",
        "st_meta": ["Szenario", "Stufe / Seed", "Mitschnitt", "Zeitfenster", "SHA-256"],
        "st_packets": "Pakete",
        "st_downloads": "Downloads",
        "st_briefing": "Aufgabenstellung",
        "st_questions": "Fragen ({n})",
        "st_hint": "Hinweis",
        "st_used_hint": "Ich habe diesen Hinweis genutzt (-{cost} {points})",
        "st_prefilled": "Deine letzte Abgabe ({saved}) ist eingetragen; eine neue Abgabe ersetzt sie.",
        "st_hint_note": "Auch Hinweise sind Ehrensache: kreuze die an, die du gelesen hast.",
        "st_submit": "abgeben",
        "st_set_placeholder": "ein Wert pro Zeile",
        "st_map_placeholder": "Name = Wert, einer pro Zeile",
        "st_submitted": "abgegeben",
        "st_saved": "Deine Antworten zu {title} wurden gespeichert ({saved}). Du kannst sie ändern und erneut "
                    "abgeben, bis die Lehrkraft sie einsammelt.",
        "st_graded_later": "Die Lehrkraft bewertet die Abgaben.",
        "st_score": "Punktzahl",
        "st_result_cols": ["#", "Frage", "Ergebnis", "Punkte", "Hinweis"],
        "st_results": {"correct": "richtig", "partial": "teilweise", "wrong": "falsch", "blank": "leer"},
        "st_not_found": "Diese Seite gibt es nicht.",
        "st_broken": "Diese Übung kann nicht gelesen werden. Bitte der Lehrkraft Bescheid geben.",
        "st_roster_broken": "Die Kursliste kann nicht gelesen werden. Bitte der Lehrkraft Bescheid geben.",
        "formats": {
            "ip": "eine IP-Adresse",
            "mac": "eine MAC-Adresse",
            "number": "eine Zahl",
            "timestamp": "eine UTC-Zeit, ISO 8601: JJJJ-MM-TTThh:mm:ss.ffffffZ",
            "set": "eine Liste: [a, b, c]",
            "map": "eine Zuordnung: {Name: Wert, Name: Wert}",
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
