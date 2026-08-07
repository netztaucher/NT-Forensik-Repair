#!/usr/bin/env python3
"""NT-Forensik — Abgleich installierter WordPress-Bestandteile gegen bekannte
Schwachstellen.

Liest den Datenbestand unter rezepte/wordpress/daten/ und eine Bestandsliste auf der
Standardeingabe und meldet, welcher Bestandteil in einen bekannten
Verwundbarkeitsbereich faellt.

    typ<TAB>slug<TAB>version        (Eingabe, typ = core|plugin|theme)
    ZUSTAND<TAB>typ<TAB>slug<TAB>version<TAB>bereich<TAB>behoben<TAB>cve<TAB>kev<TAB>quelle

Zustaende: BETROFFEN, SAUBER, UNBEWERTBAR. Der dritte ist kein Nebenschauplatz —
eine unlesbare Version darf nicht als "nicht betroffen" durchgehen.

    lib/wp_schwachstellen.py --daten <verzeichnis> < bestand.tsv
    lib/wp_schwachstellen.py --selbsttest

WARUM EIN EIGENER VERSIONSVERGLEICH

Das Joomla-Verfahren (j_vernum in module/12_joomla.sh) presst "a.b.c" in eine
Zahl aabbbccc. Fuer Joomla traegt das: dort sind Versionen dreistellig und rein
numerisch. Bei WordPress-Plugins traegt es nicht. Verbreitet sind vierstellige
Fassungen (1.2.3.4) und Vorabkennungen (2.0-beta1, 3.1-RC2); j_vernum liefert
dafuer 0, was den Vergleich ueberspringt. Bei Joomla ist das die richtige
Vorsicht, bei WordPress waeren es massenhaft Nicht-Bewertungen.

Umgesetzt ist deshalb die Semantik von PHPs version_compare — die Ordnung, die
WordPress selbst benutzt, wenn es Fassungen vergleicht. Sie ist nicht semver:

    1.0-dev < 1.0a1 < 1.0b1 < 1.0RC1 < 1.0 < 1.0pl1

Die Umsetzung ist gegen die echte PHP-Funktion geprueft (siehe
werkzeuge/version_compare_gegentest.sh). Wer hier etwas aendert, laesst den
Gegentest laufen, statt sich auf das eigene Sprachgefuehl zu verlassen.
"""

import argparse
import os
import sys

# ── Versionsvergleich nach PHP-Semantik ─────────────────────────────────
# Portierung von php_canonicalize_version und php_version_compare aus
# ext/standard/versioning.c. Absichtlich nah am Original gehalten und nicht
# "aufgeraeumt": jede Abweichung waere eine stille Verhaltensaenderung, und
# genau davon haengt ab, ob ein Kunde eine Warnung bekommt oder nicht.

_SONDERFORMEN = (
    ("dev", 0), ("alpha", 1), ("a", 1), ("beta", 2), ("b", 2),
    ("RC", 3), ("rc", 3), ("#", 4), ("pl", 5), ("p", 5),
)


def _vorzeichen(n):
    return (n > 0) - (n < 0)


def _kanonisch(version):
    """Trennzeichen vereinheitlichen und Ziffern von Buchstaben trennen.

    '1.0-beta2' wird zu '1.0.beta.2', '1.0RC1' zu '1.0.RC.1'. Erst dadurch
    vergleichen sich Vorabkennungen ueberhaupt stellenweise.
    """
    if not version:
        return ""
    aus = [version[0]]
    lp = version[0]
    for zeichen in version[1:]:
        lq = aus[-1]
        if zeichen in "-_+":
            lp = "."
            if lq != ".":
                aus.append(".")
        elif (zeichen.isdigit() and not lp.isdigit() and lp != ".") or \
             (not zeichen.isdigit() and zeichen != "." and lp.isdigit()):
            if lq != ".":
                aus.append(".")
            aus.append(zeichen)
            lp = zeichen
        elif not zeichen.isalnum() and zeichen != ".":
            if lq != ".":
                aus.append(".")
            lp = "."
        elif zeichen == ".":
            if lq != ".":
                aus.append(".")
            lp = "."
        else:
            aus.append(zeichen)
            lp = zeichen
    return "".join(aus)


def _ordnung(teil):
    # Praefixvergleich in Tabellenreihenfolge: 'alpha' steht vor 'a', sonst
    # wuerde 'alpha1' als 'a' gelesen. Unbekanntes rangiert unter allem
    # anderen (-1) — eine unbekannte Kennung ist aelter als 'dev'.
    for name, ordnung in _SONDERFORMEN:
        if teil.startswith(name):
            return ordnung
    return -1


def _sonderform_vergleich(a, b):
    return _vorzeichen(_ordnung(a) - _ordnung(b))


def _fuehrende_zahl(teil):
    i = 0
    while i < len(teil) and teil[i].isdigit():
        i += 1
    return int(teil[:i]) if i else 0


def version_vergleich(v1, v2):
    """-1, 0 oder 1 — wie PHPs version_compare($v1, $v2)."""
    if not v1 or not v2:
        if not v1 and not v2:
            return 0
        return 1 if v1 else -1

    a = v1 if v1.startswith("#") else _kanonisch(v1)
    b = v2 if v2.startswith("#") else _kanonisch(v2)
    ta = a.split(".")
    tb = b.split(".")

    i = 0
    gemeinsam = min(len(ta), len(tb))
    while i < gemeinsam:
        x, y = ta[i], tb[i]
        # Abgebrochen wird, wenn der REST leer ist — nicht, wenn die Stelle
        # leer ist. Der Unterschied ist real und beide Faelle kommen vor:
        #
        #   '1.0-'  wird zu '1.0.'  → letzte Stelle leer, Rest erschoepft:
        #           PHP verlaesst die Schleife und wendet die Restregel an.
        #           version_compare('1.0-','1.0-') ist deshalb -1, nicht 0.
        #   '.1'    wird zu '.1'    → ERSTE Stelle leer, Rest noch da:
        #           die leere Stelle wird ganz normal als Sonderform
        #           verglichen, version_compare('.1','.1') ist 0.
        #
        # Wer nur auf "Stelle leer" prueft, dreht den zweiten Fall auf -1.
        if (x == "" and i == len(ta) - 1) or (y == "" and i == len(tb) - 1):
            break
        x_zahl = x[:1].isdigit()
        y_zahl = y[:1].isdigit()
        if x_zahl and y_zahl:
            ergebnis = _vorzeichen(_fuehrende_zahl(x) - _fuehrende_zahl(y))
        elif not x_zahl and not y_zahl:
            ergebnis = _sonderform_vergleich(x, y)
        elif x_zahl:
            ergebnis = _sonderform_vergleich("#N#", y)
        else:
            ergebnis = _sonderform_vergleich(x, "#N#")
        if ergebnis:
            return ergebnis
        i += 1

    # Eine Fassung hat noch eine Stelle. Eine weitere Ziffernstelle macht sie
    # neuer (1.0.1 > 1.0), eine weitere Kennung aelter (1.0.beta < 1.0).
    if len(ta) > i:
        rest = ta[i]
        return 1 if rest[:1].isdigit() else version_vergleich(rest, "#N#")
    if len(tb) > i:
        rest = tb[i]
        return -1 if rest[:1].isdigit() else version_vergleich("#N#", rest)
    return 0


# ── Intervalle ──────────────────────────────────────────────────────────

def intervall_trifft(version, von, von_inklusiv, bis, bis_inklusiv):
    """Liegt `version` im Bereich? '*' als Grenze heisst 'offen'.

    Die Grenzen sind einzeln offen oder geschlossen — das ist die Form, in der
    Wordfence seine affected_versions fuehrt, und sie laesst sich nicht auf
    'kleiner als' verkuerzen: '>= 2.0 und <= 2.4.1' und '>= 2.0 und < 2.4.1'
    unterscheiden sich genau um die Fassung, in der die Luecke behoben wurde.
    """
    if von not in ("", "*"):
        c = version_vergleich(version, von)
        if c < 0 or (c == 0 and not von_inklusiv):
            return False
    if bis not in ("", "*"):
        c = version_vergleich(version, bis)
        if c > 0 or (c == 0 and not bis_inklusiv):
            return False
    return True


def _wahr(wert):
    return str(wert).strip().lower() in ("1", "true", "ja", "yes")


# ── Datenbestand ────────────────────────────────────────────────────────

SPALTEN = ("slug", "von", "von_inkl", "bis", "bis_inkl", "behoben",
           "cve", "cvss", "kev", "quelle")


def bestand_laden(verzeichnis):
    """TSV-Tabellen einlesen. Rueckgabe: {typ: {slug: [eintrag, ...]}}."""
    tabellen = {
        "core": os.path.join(verzeichnis, "vuln", "wp-core.tsv"),
        "plugin": os.path.join(verzeichnis, "vuln", "wp-plugins.tsv"),
        "theme": os.path.join(verzeichnis, "vuln", "wp-themes.tsv"),
    }
    daten = {typ: {} for typ in tabellen}
    for typ, pfad in tabellen.items():
        if not os.path.isfile(pfad):
            continue
        with open(pfad, encoding="utf-8", errors="replace") as fh:
            for zeile in fh:
                zeile = zeile.rstrip("\n")
                if not zeile or zeile.startswith("#"):
                    continue
                felder = zeile.split("\t")
                if len(felder) < len(SPALTEN):
                    felder += [""] * (len(SPALTEN) - len(felder))
                eintrag = dict(zip(SPALTEN, felder))
                daten[typ].setdefault(eintrag["slug"], []).append(eintrag)
    return daten


def pruefen(daten, typ, slug, version):
    """Einen installierten Bestandteil bewerten. Liefert Ergebniszeilen."""
    if typ not in daten:
        return [("UNBEWERTBAR", typ, slug, version, "", "", "", "",
                 "unbekannter Typ")]
    if not daten[typ]:
        return [("UNBEWERTBAR", typ, slug, version, "", "", "", "",
                 "kein Datenbestand für diesen Typ")]
    if not version:
        return [("UNBEWERTBAR", typ, slug, version, "", "", "", "",
                 "keine Version ermittelbar")]

    eintraege = daten[typ].get(slug)
    if eintraege is None:
        # Kein Eintrag heisst NICHT "sicher", sondern "keine bekannte
        # Schwachstelle im vorliegenden Bestand". Der Unterschied zaehlt, wenn
        # der Bestand alt ist oder das Plugin gar nicht erfasst wird.
        return [("SAUBER", typ, slug, version, "", "", "", "",
                 "kein Eintrag im Datenbestand")]

    treffer = []
    for e in eintraege:
        if intervall_trifft(version, e["von"], _wahr(e["von_inkl"]),
                            e["bis"], _wahr(e["bis_inkl"])):
            bereich = "%s%s … %s%s" % (
                "[" if _wahr(e["von_inkl"]) else "(", e["von"] or "*",
                e["bis"] or "*", "]" if _wahr(e["bis_inkl"]) else ")")
            treffer.append(("BETROFFEN", typ, slug, version, bereich,
                            e["behoben"], e["cve"], e["kev"], e["quelle"]))
    if treffer:
        return treffer
    return [("SAUBER", typ, slug, version, "", "", "", "",
             "%d Eintrag/Einträge geprüft, keiner trifft" % len(eintraege))]


# ── Selbsttest ──────────────────────────────────────────────────────────

# Die Versionspaare stammen aus der PHP-Dokumentation, aus der Testdatei von
# PHP selbst und aus Fassungen, die real in WordPress-Plugins vorkommen.
# Erwartungswerte sind mit `php -r 'echo version_compare(...);'` erzeugt, nicht
# von Hand gesetzt — siehe werkzeuge/version_compare_gegentest.sh.
_VERSIONSFAELLE = (
    ("1.0", "1.0", 0), ("1.0", "1.1", -1), ("1.1", "1.0", 1),
    ("1.0.0", "1.0", 1), ("1.0", "1.0.0", -1),
    ("1.2.3.4", "1.2.3.3", 1), ("1.2.3.4", "1.2.3.4", 0),
    ("1.0-beta", "1.0", -1), ("1.0", "1.0-beta", 1),
    ("1.0-alpha", "1.0-beta", -1), ("1.0-beta", "1.0-rc", -1),
    ("1.0-rc1", "1.0-rc2", -1), ("1.0", "1.0pl1", -1),
    ("1.0-dev", "1.0-alpha", -1),
    ("2.0", "2.0.0", -1), ("5.3.3", "5.3.3", 0),
    ("1.0.0-beta2", "1.0.0-beta10", -1),
    ("3.1RC2", "3.1", -1), ("1.0a1", "1.0b1", -1),
    ("6.4.1", "6.4", 1), ("0.9", "1.0", -1),
)

# Intervalle: (version, von, von_inkl, bis, bis_inkl, erwartet)
_INTERVALLFAELLE = (
    ("5.3.1", "*", False, "5.3.2", False, True),    # < 5.3.2
    ("5.3.2", "*", False, "5.3.2", False, False),   # Grenze exklusiv
    ("5.3.2", "*", False, "5.3.2", True, True),     # Grenze inklusiv
    ("2.5", "2.0", True, "3.0", True, True),
    ("2.0", "2.0", True, "3.0", True, True),
    ("2.0", "2.0", False, "3.0", True, False),
    ("1.9", "2.0", True, "3.0", True, False),
    ("3.1", "2.0", True, "3.0", True, False),
    ("9.9", "*", False, "*", False, True),          # jede Fassung betroffen
    ("1.0-beta", "*", False, "1.0", False, True),   # Vorab liegt davor
    ("1.0", "*", False, "1.0", False, False),
    ("1.2.3.4", "1.2.3", True, "1.2.4", False, True),
)


def selbsttest():
    fehler = 0
    for v1, v2, erwartet in _VERSIONSFAELLE:
        ist = version_vergleich(v1, v2)
        if ist != erwartet:
            print("FEHLER  version_vergleich(%r, %r) = %d, erwartet %d"
                  % (v1, v2, ist, erwartet))
            fehler += 1
    for version, von, vi, bis, bi, erwartet in _INTERVALLFAELLE:
        ist = intervall_trifft(version, von, vi, bis, bi)
        if ist != erwartet:
            print("FEHLER  intervall_trifft(%r, %r,%s, %r,%s) = %s, erwartet %s"
                  % (version, von, vi, bis, bi, ist, erwartet))
            fehler += 1

    # Bewertung gegen einen kleinen, hier definierten Bestand.
    daten = {
        "plugin": {
            "beispiel": [
                {"slug": "beispiel", "von": "*", "von_inkl": "0",
                 "bis": "1.5", "bis_inkl": "0", "behoben": "1.5",
                 "cve": "CVE-2026-0001", "cvss": "9.8", "kev": "ja",
                 "quelle": "https://example.invalid/1"},
            ],
        },
        "theme": {},
        "core": {},
    }
    faelle = (
        (("plugin", "beispiel", "1.4"), "BETROFFEN"),
        (("plugin", "beispiel", "1.5"), "SAUBER"),
        (("plugin", "beispiel", ""), "UNBEWERTBAR"),
        (("plugin", "anderes", "1.0"), "SAUBER"),
        (("theme", "irgendein", "1.0"), "UNBEWERTBAR"),
    )
    for (typ, slug, version), erwartet in faelle:
        ist = pruefen(daten, typ, slug, version)[0][0]
        if ist != erwartet:
            print("FEHLER  pruefen(%s, %s, %r) = %s, erwartet %s"
                  % (typ, slug, version, ist, erwartet))
            fehler += 1

    gesamt = len(_VERSIONSFAELLE) + len(_INTERVALLFAELLE) + len(faelle)
    if fehler:
        print("Selbsttest: %d von %d Fällen fehlgeschlagen" % (fehler, gesamt))
        return 1
    print("Selbsttest: %d Fälle, alle bestanden" % gesamt)
    return 0


def main():
    p = argparse.ArgumentParser(add_help=True, description=__doc__)
    p.add_argument("--daten", help="Verzeichnis rezepte/wordpress/daten")
    p.add_argument("--selbsttest", action="store_true")
    args = p.parse_args()

    if args.selbsttest:
        return selbsttest()
    if not args.daten:
        p.error("--daten oder --selbsttest angeben")

    daten = bestand_laden(args.daten)
    for zeile in sys.stdin.read().splitlines():
        if not zeile.strip():
            continue
        felder = zeile.split("\t")
        typ = felder[0] if felder else ""
        slug = felder[1] if len(felder) > 1 else ""
        version = felder[2] if len(felder) > 2 else ""
        for ergebnis in pruefen(daten, typ, slug, version):
            print("\t".join(ergebnis))
    return 0


if __name__ == "__main__":
    sys.exit(main())
