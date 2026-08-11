#!/usr/bin/env python3
"""NT-Forensik — installierte Composer-Pakete aus vendor/composer/installed.json.

    lib/composer_bestand.py <installed.json>
    composer<TAB>vendor/paket<TAB>fassung

Eigene Datei und kein Here-Doc im Rezept: das Rezept enthaelt bereits ein
Python-Programm im Here-Doc (_wp_plugin_integritaet), und zwei davon in einer
Datei sind eine Falle — der Abschluss des einen beendet beim Bearbeiten
regelmaessig das andere.
"""
import json
import sys


def main():
    if len(sys.argv) < 2:
        return 0
    try:
        with open(sys.argv[1], encoding="utf-8", errors="replace") as fh:
            roh = json.load(fh)
    except (OSError, ValueError):
        # Eine unlesbare installed.json ist kein Befund und kein Fehler des
        # Laufs — sie kommt bei halb entpackten Plugins vor.
        return 0

    pakete = roh.get("packages") if isinstance(roh, dict) else roh
    for paket in pakete or []:
        if not isinstance(paket, dict):
            continue
        name = str(paket.get("name", "")).strip().lower()
        if not name:
            continue
        ver = str(paket.get("version", "")).strip()
        # Composer schreibt Fassungen haeufig mit fuehrendem "v" ("v6.5.8"),
        # die Advisories nicht. Ohne diese Zeile ginge jedes solche Paket mit
        # einem Praefix in den Versionsvergleich, das dort nichts zu suchen hat.
        if ver[:1] in ("v", "V"):
            ver = ver[1:]
        # Entwicklungsstaende ("dev-main", "9999999-dev") sind nicht
        # vergleichbar. Als leere Fassung landen sie bei UNBEWERTBAR — richtig.
        # Sie stillschweigend als sauber zu behandeln waere es nicht.
        if ver.startswith("dev-") or ver.startswith("9999999"):
            ver = ""
        print("composer\t%s\t%s" % (name, ver))
    return 0


if __name__ == "__main__":
    sys.exit(main())
