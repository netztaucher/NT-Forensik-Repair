#!/usr/bin/env bash
# =============================================================================
# lizenz-pruefstand.sh — prüft das Lizenz-Gate vor dem Wordfence-Bestand (#8)
# =============================================================================
# Warum das ein Prüfstand sein muss und keine Merkliste:
#
# Sobald ein Wordfence-Bestand im öffentlichen Repository liegt, ist er
# ausgeliefert — und die Auflagen gelten ab diesem Augenblick, nicht ab dem
# nächsten Release. Ein Punkt auf einer Merkliste hält genau bis zu dem Tag, an
# dem es eilig ist.
#
# Geprüft werden BEIDE Richtungen. Eine Sperre, die immer zuschlägt, bestünde
# einen Test, der nur das Zuschlagen prüft — und wäre unbrauchbar, weil dann
# nie ein Bestand entstünde.
#
# Nutzung:  werkzeuge/lizenz-pruefstand.sh
# Rückgabe: 0 wenn alle Soll-Werte erreicht wurden, sonst 1
# =============================================================================
set -uo pipefail

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/.." && pwd)"
ARBEIT="${LIZENZ_PRUEFSTAND_DIR:-${TMPDIR:-/tmp}/nt-lizenz-pruefstand}"
RED='\033[0;31m'; GRN='\033[0;32m'; NC='\033[0m'
FEHLER=0
pok()   { echo -e "  ${GRN}✓${NC} $1"; }
pfehl() { echo -e "  ${RED}✗${NC} $1"; FEHLER=$((FEHLER+1)); }

rm -rf "$ARBEIT"; mkdir -p "$ARBEIT"
echo "Lizenz-Prüfstand — darf ein Wordfence-Bestand entstehen?"
echo

WERKZEUG="${SELF_DIR}/werkzeuge/wordpress-daten-update.sh"
LIC="${SELF_DIR}/rezepte/wordpress/daten/LICENSE"

# ── Die Funktion aus dem Original holen ─────────────────────────────────────
# Nicht nachbauen: eine Kopie driftet weg, und dann prüft der Prüfstand sich
# selbst. Dasselbe Vorgehen wie im Auswahl-Prüfstand von NT-Repair.
FKT="${ARBEIT}/gate.sh"
sed -n '/^lizenz_gate() {/,/^}/p'     "$WERKZEUG" >  "$FKT"
sed -n '/^lizenz_schreiben() {/,/^}/p' "$WERKZEUG" >> "$FKT"
if ! grep -q 'PLATZHALTER' "$FKT" || ! grep -q "copyrights" "$FKT" \
   || [[ "$(tail -1 "$FKT")" != "}" ]]; then
  echo "  Konnte lizenz_gate()/lizenz_schreiben() nicht aus dem Werkzeug"
  echo "  herauslösen — Prüfstand wertlos."
  exit 1
fi
meldung() { echo "  $*"; }
fehler()  { echo "  FEHLER: $*" >&2; }
# shellcheck source=/dev/null
source "$FKT"
pok "lizenz_gate() und lizenz_schreiben() eingebunden"

# ── Ein Feed-Ausschnitt zum Anfassen ────────────────────────────────────────
# Nicht der echte Abzug (150 MB), sondern die kleinste Form, die dieselben
# Felder trägt. Der Lizenztext ist hier erfunden — geprüft wird, ob er
# UNVERÄNDERT durchgereicht wird, nicht ob er stimmt.
LIZ_TEXT='Beispiellizenz: reproduce this notice in any such copy.'
feed_bauen() {   # <zieldatei> <lizenztext fuer satz 2 (leer = wie satz 1)>
  local ziel="$1" abweichend="${2:-}"
  python3 - "$ziel" "$LIZ_TEXT" "$abweichend" <<'PY'
import json, sys
ziel, text, abweichend = sys.argv[1], sys.argv[2], sys.argv[3]
def satz(uuid, lizenz):
    return {"id": uuid, "title": "Beispiel", "cve": "CVE-2026-1",
            "software": [{"type": "plugin", "slug": "beispiel",
                          "affected_versions": {"* - 1.0": {
                              "from_version": "*", "from_inclusive": True,
                              "to_version": "1.0", "to_inclusive": True}}}],
            "references": ["https://beispiel.invalid/%s" % uuid],
            "copyrights": {"message": "This record contains material that is subject to copyright",
                           "defiant": {"notice": "Copyright 2012-2026 Beispiel Inc.",
                                       "license": lizenz,
                                       "license_url": "https://beispiel.invalid/terms"}}}
d = {"aaaaaaaa-0000-0000-0000-000000000001": satz("aaaaaaaa-0000-0000-0000-000000000001", text),
     "aaaaaaaa-0000-0000-0000-000000000002": satz("aaaaaaaa-0000-0000-0000-000000000002", abweichend or text)}
json.dump(d, open(ziel, "w", encoding="utf-8"))
PY
}

# ── Zustand 1: die eingecheckte LICENSE ─────────────────────────────────────
# Seit v3.14 ist sie erzeugt, nicht mehr von Hand gepflegt. Sie MUSS deshalb
# öffnen — und sie muss beide Rechteinhaber führen. Eine LICENSE, die nur
# Defiant nennt, deckt die CVE-Anteile nicht.
DATEN="$(dirname "$LIC")"
if lizenz_gate 2>/dev/null; then
  pok "die eingecheckte LICENSE öffnet das Gate"
else
  pfehl "die eingecheckte LICENSE sperrt — es entstünde nie ein Bestand"
fi
for partei in defiant mitre; do
  if grep -qi "^${partei}$" "$LIC"; then
    pok "LICENSE führt ${partei}"
  else
    pfehl "LICENSE führt ${partei} NICHT — die Auflage ist nicht erfüllt"
  fi
done

# ── Zustand 2: Datei fehlt ganz ─────────────────────────────────────────────
DATEN="${ARBEIT}/leer"; mkdir -p "$DATEN"
if ! lizenz_gate 2>/dev/null; then
  pok "fehlende LICENSE sperrt"
else
  pfehl "ohne LICENSE wird nicht gesperrt"
fi

# ── Zustand 3: ein Gerüst sperrt weiterhin ──────────────────────────────────
# Die Sperre bleibt bestehen, auch wenn sie im Normalbetrieb nicht mehr greift.
# Sie ist jetzt die Nachkontrolle: schlägt lizenz_schreiben fehl und läuft der
# Ablauf trotzdem weiter, muss hier Schluss sein.
DATEN="${ARBEIT}/geruest"; mkdir -p "$DATEN"
printf 'Kopf\n\n[LIZENZTEXT IM WORTLAUT EINSETZEN]\n\nPLATZHALTER — Zeile entfernen.\n' \
  > "${DATEN}/LICENSE"
if ! lizenz_gate 2>/dev/null; then
  pok "ein Gerüst sperrt"
else
  pfehl "ein Gerüst sperrt NICHT — ein Abruf würde ungedeckt ausliefern"
fi

# ── Zustand 4: halb ausgefüllt ──────────────────────────────────────────────
# Der wahrscheinlichste Fehler von Hand: die PLATZHALTER-Zeile wird gelöscht,
# weil sie so aussieht, als sei sie das Einzige. Die Klammern bleiben stehen.
DATEN="${ARBEIT}/halb"; mkdir -p "$DATEN"
printf 'Kopf\n\n[LIZENZTEXT IM WORTLAUT EINSETZEN]\n' > "${DATEN}/LICENSE"
if ! lizenz_gate 2>/dev/null; then
  pok "gelöschte PLATZHALTER-Zeile allein öffnet das Gate nicht"
else
  pfehl "ein halb ausgefülltes Gerüst öffnet das Gate"
fi

# ── lizenz_schreiben: der Text muss aus dem Feed kommen ─────────────────────
# Die Gegenprobe zum Ganzen. Wird der Lizenztext nicht WÖRTLICH übernommen,
# sondern zusammengefasst, umgebrochen oder aus dem Skript ergänzt, ist die
# Auflage "reproduce this license" nicht erfüllt — und niemand merkt es.
DATEN="${ARBEIT}/aus_feed"; mkdir -p "$DATEN"
feed_bauen "${ARBEIT}/feed_gut.json"
if lizenz_schreiben "${ARBEIT}/feed_gut.json" >/dev/null 2>&1; then
  pok "ein einheitlicher Feed erzeugt eine LICENSE"
else
  pfehl "ein einheitlicher Feed erzeugt KEINE LICENSE — es entstünde nie ein Bestand"
fi
if grep -qF "$LIZ_TEXT" "${DATEN}/LICENSE" 2>/dev/null; then
  pok "der Lizenztext steht wörtlich in der erzeugten LICENSE"
else
  pfehl "der Lizenztext wurde verändert übernommen — 'reproduce' ist nicht erfüllt"
fi
if lizenz_gate 2>/dev/null; then
  pok "die erzeugte LICENSE öffnet das Gate"
else
  pfehl "die erzeugte LICENSE sperrt — Erzeugung und Gate widersprechen sich"
fi

# ── lizenz_schreiben: zwei Fassungen im selben Bestand ──────────────────────
# §5c behält eine einseitige Änderung der Bedingungen vor. Läuft eine Änderung
# an, stehen im selben Abzug zwei Fassungen. Ein Bestand mit zwei Fassungen
# lässt sich nicht mit einer ausliefern — das MUSS auffallen und nicht mit der
# erstbesten Fassung geglättet werden.
DATEN="${ARBEIT}/uneinig"; mkdir -p "$DATEN"
feed_bauen "${ARBEIT}/feed_uneinig.json" 'Beispiellizenz, zweite Fassung.'
if ! lizenz_schreiben "${ARBEIT}/feed_uneinig.json" >/dev/null 2>&1; then
  pok "zwei Lizenzfassungen im selben Bestand brechen ab"
else
  pfehl "zwei Lizenzfassungen werden stillschweigend auf eine geglättet"
fi
if [[ ! -f "${DATEN}/LICENSE" ]]; then
  pok "nach dem Abbruch liegt keine LICENSE — nichts wird halb geschrieben"
else
  pfehl "trotz Abbruch wurde eine LICENSE geschrieben"
fi

# ── lizenz_schreiben: Feed ohne copyrights ──────────────────────────────────
# Der Fall, der still durchginge: Wordfence entfernt das Feld, das Werkzeug
# schreibt eine LICENSE ohne Text, und ausgeliefert wird trotzdem.
DATEN="${ARBEIT}/ohne_cr"; mkdir -p "$DATEN"
printf '{"aaaaaaaa-0000-0000-0000-000000000001":{"id":"x","software":[]}}' \
  > "${ARBEIT}/feed_ohne.json"
if ! lizenz_schreiben "${ARBEIT}/feed_ohne.json" >/dev/null 2>&1; then
  pok "ein Feed ohne 'copyrights' bricht ab"
else
  pfehl "ein Feed ohne 'copyrights' erzeugt trotzdem eine LICENSE"
fi

# ── Das Werkzeug selbst: kein Bestand ohne Lizenz ───────────────────────────
# Der Weg, nicht nur die Funktion. Scheitert die Lizenz, darf keine einzige
# vuln/*.tsv entstehen — Rückgabewert 2 und ein leeres Zielverzeichnis.
WERK_TEST="${ARBEIT}/werk"; mkdir -p "${WERK_TEST}/vuln"
DATEN_ALT="$DATEN"
env NT_DATEN_DIR="$WERK_TEST" bash "$WERKZEUG" --aus-datei "${ARBEIT}/feed_ohne.json" \
  >/dev/null 2>&1
RC=$?
if [[ "$RC" -eq 2 ]]; then
  pok "--aus-datei bricht ohne Lizenztext ab (Rückgabewert 2)"
else
  pfehl "--aus-datei läuft ohne Lizenztext durch (Rückgabewert ${RC})"
fi
if ! ls "${WERK_TEST}"/vuln/*.tsv >/dev/null 2>&1; then
  pok "nach dem Abbruch liegt kein Bestand — nichts wird ungedeckt geschrieben"
else
  pfehl "trotz Abbruch wurde ein Bestand geschrieben — ungedeckte Auslieferung"
fi
DATEN="$DATEN_ALT"

# Und die Gegenprobe dazu: --kev darf NICHT gesperrt sein. Der CISA-Katalog ist
# ein Werk einer US-Behörde, gemeinfrei, ohne Auflagen. Ein Gate davor wäre
# falsch und würde den einzigen heute pflegbaren Teil blockieren.
if grep -A3 -- '--kev)' "$WERKZEUG" | grep -q 'lizenz_gate'; then
  pfehl "--kev hängt am Lizenz-Gate — der CISA-Katalog ist gemeinfrei"
else
  pok "--kev hängt nicht am Gate (gemeinfrei, keine Auflagen)"
fi

# ── Leere Tabellen sind kein Bestand ────────────────────────────────────────
# Nach einem Testlauf lagen drei vuln/*.tsv mit NUR Kopfzeilen im Repository.
# Sie sahen aus wie ein Bestand, enthielten aber nichts — und der Abgleich
# haette gegen nichts verglichen: jedes Plugin waere als SAUBER
# zurueckgekommen, also als stille Entwarnung. Der gefaehrlichste Zustand von
# allen, weil er nach Pruefung aussieht.
LEER="${ARBEIT}/leere_tabellen"; mkdir -p "${LEER}/vuln"
printf '# nur eine Kopfzeile\n' > "${LEER}/vuln/wp-plugins.tsv"
if ! grep -rhv '^#' "${LEER}"/vuln/*.tsv 2>/dev/null | grep -q .; then
  pok "eine Tabelle aus nur Kopfzeilen gilt nicht als Bestand"
else
  pfehl "eine Tabelle aus nur Kopfzeilen gilt als Bestand — stille Entwarnung"
fi
# Gegenprobe: mit einer einzigen Datenzeile MUSS sie als Bestand gelten.
printf 'beispiel\t*\t0\t1.0\t0\t1.0\tCVE-2026-1\t5.0\t\thttps://x.invalid\n' \
  >> "${LEER}/vuln/wp-plugins.tsv"
if grep -rhv '^#' "${LEER}"/vuln/*.tsv 2>/dev/null | grep -q .; then
  pok "eine einzige Datenzeile genügt als Bestand"
else
  pfehl "auch mit Datenzeile wird kein Bestand erkannt — der Abgleich liefe nie"
fi
# Und die eingecheckte Lage. Bis v3.13 galt hier das Gegenteil — es durfte gar
# keine vuln/*.tsv geben, weil das Gate zu war. Seit der Bestand liegt, kehrt
# sich die Prüfung um: er muss da sein UND Datenzeilen führen. Eine Tabelle aus
# nur Kopfzeilen wäre die stille Entwarnung von oben, diesmal im Repository.
ECHT="${SELF_DIR}/rezepte/wordpress/daten/vuln"
for t in wp-core wp-plugins wp-themes; do
  if [[ -s "${ECHT}/${t}.tsv" ]] && grep -qv '^#' "${ECHT}/${t}.tsv"; then
    pok "${t}.tsv liegt vor und führt Datenzeilen"
  else
    pfehl "${t}.tsv fehlt oder besteht nur aus Kopfzeilen — der Abgleich liefe leer"
  fi
done
# Die Vermerke müssen mit im Manifest stehen: sie sind der Teil der Lieferung,
# der die Weitergabe deckt.
for d in LICENSE NOTICE; do
  if grep -q "  \./${d}\$" "${SELF_DIR}/rezepte/wordpress/daten/MANIFEST.sha256" 2>/dev/null; then
    pok "${d} ist von MANIFEST.sha256 gedeckt"
  else
    pfehl "${d} fehlt im MANIFEST — die Lieferung ist nur halb gesichert"
  fi
done

echo
if [[ "$FEHLER" -eq 0 ]]; then
  echo -e "${GRN}Alle Soll-Werte erreicht.${NC}"
  exit 0
fi
echo -e "${RED}${FEHLER} Abweichung(en).${NC}"
exit 1
