#!/usr/bin/env bash
# ============================================================
# WP-PLESK-FORENSIK.SH
# Die Fassung steht an EINER Stelle: TOOL_VERSION in lib/konfig.sh.
# Forensische Analyse nach WordPress/Plesk Sicherheitsvorfall
#
# Verwendung: sudo bash wp_plesk_forensik.sh [--domain d|--path p|--global] [--yara]
#
# Ablage (fest):
#   /root/wartungsscripte/                     ← Skript-Basis (wird angelegt)
#   /root/wartungsscripte/forensik/<LAUF>/     ← ein Ordner pro Lauf
#     ├── kunde/                               ← WEITERGABEFÄHIG
#     │   ├── kundenbericht.md                 ← lesbar für den Kunden
#     │   ├── befunde_details.md               ← Anlage, relative Pfade
#     │   ├── root_aussage.md                  ← nur bei --nur-root
#     │   └── abschlussbericht.pdf             ← optional
#     └── betreiber/                           ← NICHT WEITERGEBEN
#         ├── technik_bericht.md               ← vollständig, auch serverweit
#         ├── bsi_meldung.md                   ← Entwurf
#         ├── dsgvo_meldung.md                 ← Entwurf, eigener Meldeweg
#         ├── findings.json                    ← Eingabe für die Bereinigung
#         ├── lauf.log                         ← Ausführungsprotokoll
#         └── belege/                          ← Rohdaten, gehasht, UNMASKIERT
#             ├── 00_manifest.txt              ← Chain-of-Custody
#             ├── NN_*.txt / logs_sicherung.tar.gz
#             └── SHA256SUMS
#
#   Dazu zwei Archive: <LAUF>_kunde.tar.gz und <LAUF>_betreiber.tar.gz.
#   Die Trennung ist der Punkt: ein einziges Archiv lädt dazu ein, es als
#   Ganzes weiterzureichen — samt fremder vhosts und unmaskierter Rohbelege.
#
# Autor: netztaucher | digital
# Nur read-only Analyse. Keine Lösch-/Schreiboperationen im Webspace.
# ============================================================

# Kein set -e/pipefail: Collector-Skript muss bei Einzel-Fehlern (SIGPIPE durch
# `cmd | head`, fehlende Logs, leere greps) weiterlaufen und IMMER Berichte liefern.
set -u


# ── Eigenes Verzeichnis bestimmen ────────────────────────────
# Alles wird relativ zum Skript geladen. Damit laeuft das Werkzeug sowohl
# aus dem Repository als auch aus der installierten Kopie unter BASE_DIR.
SELF_PATH="$(readlink -f "$0" 2>/dev/null || echo "$0")"
SELF_DIR="$(dirname "$SELF_PATH")"

# Aufrufargumente sichern, BEVOR irgendetwas eingebunden wird.
# 'source' aus einer Funktion heraus setzt $@ auf die Argumente der Funktion,
# nicht auf die des Skripts — die Kommandozeile käme in lib/konfig.sh sonst
# nie an. Deshalb wird sie hier festgehalten und dort daraus gelesen.
NT_ARGV=("$@")

lade() {   # lade <relativer Pfad> — bricht mit klarer Meldung ab statt still zu scheitern
  local f="${SELF_DIR}/$1"
  if [[ ! -r "$f" ]]; then
    echo "Fehler: ${1} fehlt oder ist nicht lesbar (erwartet unter ${SELF_DIR}/)." >&2
    echo "        Skript und die Ordner lib/ und module/ gehoeren zusammen." >&2
    exit 3
  fi
  # shellcheck disable=SC1090
  source "$f"
}

lade lib/konfig.sh     # Pfade, Argumente, Laufordner, Selbst-Installation
lade lib/befunde.sh    # Vorgabewerte aller Befund-Variablen
lade lib/muster.sh     # Signaturen, Selbstausschluss
lade lib/kern.sh       # Ausgabe- und Beleg-Funktionen
lade lib/rezepte.sh    # Rahmen für die Prüfrezepte unter rezepte/
lade lib/menue.sh      # Startmenü (nur wenn kein Prüfumfang angegeben wurde)

# ── Startmenü ────────────────────────────────────────────────
# Nur wenn kein Prüfumfang angegeben wurde. Ein Scope-Argument ist eine
# eindeutige Anweisung und läuft immer direkt durch — sonst wäre jeder
# bestehende Aufruf über SSH oder aus einem Cronjob gebrochen.
if menue_faellig; then
  if [[ -t 0 ]]; then
    menue_starten
  else
    menue_ohne_terminal   # erklärt und beendet mit Code 2, statt zu warten
  fi
fi

# Erst jetzt steht fest, was geprüft wird — das Menü kann Umfang und Domain
# geändert haben, und der Laufordner trägt die Domain im Namen.
# Die Abschnittsauswahl wird davor geprüft: eine unbekannte Nummer soll den
# Lauf beenden, bevor ein Laufordner mit einem leeren Bericht darin entsteht.
modul_auswahl_pruefen
scan_path_bestimmen
ablage_einrichten

# ── Banner ───────────────────────────────────────────────────
# Die Kunst selbst steht in lib/konfig.sh, damit --help sie ebenfalls zeigen
# kann — dort wird die Hilfe ausgegeben, lange bevor dieser Punkt erreicht ist.
banner_zeigen

if [[ "$SCOPE_MODE" == "abo" ]]; then
  echo -e "${BOLD}Analysiert:${NC}  Abo ${ABO_USER} — ${#SCAN_PATHS[@]} Verzeichnis(se):"
  for _p in "${SCAN_PATHS[@]}"; do echo -e "               ${_p}"; done
else
  echo -e "${BOLD}Analysiert:${NC}  ${DOMAIN:-alle Domains}"
fi
echo -e "${BOLD}Lauf:${NC}        ${RUN_LABEL}"
echo -e "${BOLD}Ablage:${NC}      ${RUN_DIR}"
echo -e "${BOLD}Datum:${NC}       $(date)\n"

# Der haeufigste Irrtum: --path sieht aus, als begrenze es den ganzen Lauf.
# Es begrenzt aber nur die Abschnitte, die den Pfad ueberhaupt auswerten.
# Ohne diesen Hinweis landen bei einem Shared-Host hunderte fremde vhosts im
# Bericht, und das faellt erst auf, wenn er fertig ist.
if [[ "$SCOPE_MODE" == "path" && "$MODUL_NUR" != "ebene:website" ]]; then
  echo -e "${YLW}Hinweis:${NC}     --path begrenzt nur die Abschnitte 7, 11 und 12."
  echo -e "             Die serverweiten Abschnitte prüfen weiterhin den ganzen Server."
  echo -e "             Nur ein Kunde? ${BOLD}--web<NN>${NC} statt --path.\n"
fi

# ── Chain-of-Custody Manifest ────────────────────────────────
cat > "${BELEGE_DIR}/00_manifest.txt" <<MANIFEST
CHAIN-OF-CUSTODY MANIFEST
=========================
Lauf-ID:        ${RUN_LABEL}
Server:         $(hostname -f 2>/dev/null || hostname)
Server-IP:      $(hostname -I 2>/dev/null | awk '{print $1}' || echo "n/a")
Domain:         ${DOMAIN:-alle Domains}
Beginn (UTC):   $(date -u +"%Y-%m-%dT%H:%M:%SZ")
Beginn (lokal): $(date)
Ausführender:   root (via $(who am i 2>/dev/null | awk '{print $1}' || echo "unbekannt"))
Tool:           wp_plesk_forensik.sh v${TOOL_VERSION}
Modus:          read-only, keine Veränderungen am Webspace

Alle Belege in diesem Ordner sind maschinell erhoben.
Integrität: siehe SHA256SUMS (wird am Ende des Laufs erzeugt).
MANIFEST

# ── Technik-Bericht Header ───────────────────────────────────
cat > "$REPORT_FILE" <<HEADER
# Forensik-Bericht (Technik): WordPress/Plesk Sicherheitsvorfall

| | |
|---|---|
| **Lauf-ID** | ${RUN_LABEL} |
| **Domain** | ${DOMAIN:-Alle Domains} |
| **Analysiert am** | $(date) |
| **Server** | $(hostname -f 2>/dev/null || hostname) |
| **Erstellt durch** | wp_plesk_forensik.sh v${TOOL_VERSION} |
| **Belege** | ${BELEGE_DIR} |

---

> **Hinweis:** Dieser Bericht ist maschinell erstellt und ersetzt keine manuelle Prüfung durch einen Sicherheitsexperten.

---
HEADER

# Ein Testlauf muss sich vom echten Lauf unterscheiden lassen — sonst wird der
# Pruefstand selbst zur Fehlerquelle. Der Vermerk steht bewusst ganz oben und
# nicht in einer Fussnote.
if [[ "${TESTLAUF:-0}" == "1" ]]; then
  cat >> "$REPORT_FILE" <<'TESTHINWEIS'
> ⚠️ **TESTLAUF — kein Befund dieses Berichts ist belastbar.**
> Erzeugt ohne Root-Rechte gegen einen synthetischen Verzeichnisbaum
> (`werkzeuge/goldmuster.sh`). Die serverweiten Abschnitte hatten keinen
> Zugriff auf ihre Quellen. Dieses Dokument dient ausschliesslich dem
> Vergleich zweier Programmstaende und darf niemandem vorgelegt werden.

---
TESTHINWEIS
fi

# ============================================================

# ── Pruefabschnitte ──────────────────────────────────────────
# Reihenfolge ist bedeutsam: Abschnitt 13 fasst die Funde der vorherigen
# zusammen, Abschnitt 14 schreibt daraus die Berichte.
MODULE_GELAUFEN=""
MODULE_UEBERSPRUNGEN=""

# Ein Abschnitt darf sich auf mehrere Dateien verteilen: liegt neben
# module/NN_name.sh ein Verzeichnis module/NN_name/, werden dessen *.sh nach
# dem Hauptmodul in Glob-Reihenfolge nachgeladen.
#
# Warum ueberhaupt: 14_berichte.sh war 976 Zeilen lang und erzeugte sieben
# verschiedene Dokumente, 12_joomla.sh 1083 Zeilen mit elf Unterabschnitten.
# In Dateien dieser Groesse laesst sich nichts mehr chirurgisch aendern.
#
# Warum so und nicht mit einem zweiten Mechanismus: die Metadaten bleiben am
# Hauptmodul, modul_gewaehlt entscheidet weiterhin EINMAL fuer die ganze
# Gruppe. --nur 14 und --ohne 12 verhalten sich damit unveraendert; ein
# Unterabschnitt ist kein eigener Abschnitt, sondern ein Stueck desselben.
modul_teile_laden() {   # modul_teile_laden <hauptmodul-pfad>
  local unterordner="${1%.sh}"
  [[ -d "$unterordner" ]] || return 0
  local teil
  for teil in "$unterordner"/*.sh; do
    [[ -r "$teil" ]] || continue
    lade "module/$(basename "$unterordner")/$(basename "$teil")"
  done
}

for _modul in "${SELF_DIR}"/module/*.sh; do
  [[ -r "$_modul" ]] || continue
  _nr=$(modul_feld "$_modul" nummer)
  if modul_gewaehlt "$_nr" "$(modul_feld "$_modul" ebene)"; then
    MODULE_GELAUFEN+="${_nr} "
    # Belegstufe vor JEDEM Modul zuruecksetzen (#1). Die Module werden
    # nacheinander in denselben Interpreter gezogen; ohne diese Zeile erbte ein
    # Modul ohne eigene Angabe die Einstufung des vorherigen — und zwar
    # unsichtbar. `betreiber` ist die sichere Richtung: ein Beleg, der
    # faelschlich intern bleibt, ist aergerlich; einer, der faelschlich
    # mitgeht, ist ein Datenschutzverstoss.
    BELEG_STUFE=betreiber
    lade "module/$(basename "$_modul")"
    modul_teile_laden "$_modul"
  else
    _t="${_nr}. $(modul_feld "$_modul" titel)"
    MODULE_UEBERSPRUNGEN+="${_t}"$'\n'
    echo -e "  ${CYN}übersprungen:${NC} ${_t}"
  fi
done

# Ein Teillauf darf sich nicht wie ein vollständiges Ergebnis lesen.
if [[ -n "$MODULE_UEBERSPRUNGEN" ]]; then
  {
    printf '\n> **Eingeschränkter Lauf.** Die folgenden Prüfabschnitte wurden auf '
    printf 'ausdrückliche Auswahl hin NICHT ausgeführt. Ihre Ergebnisse fehlen '
    printf 'in diesem Bericht — das ist keine Entwarnung für diese Bereiche:\n>\n'
    while IFS= read -r _z; do [[ -n "$_z" ]] && printf '> - %s\n' "$_z"; done <<< "$MODULE_UEBERSPRUNGEN"
    printf '\n'
  } >> "$REPORT_FILE"
fi
