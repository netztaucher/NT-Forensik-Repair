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
sed -n '/^lizenz_gate() {/,/^}/p' "$WERKZEUG" > "$FKT"
if ! grep -q 'PLATZHALTER' "$FKT" || [[ "$(tail -1 "$FKT")" != "}" ]]; then
  echo "  Konnte lizenz_gate() nicht aus dem Werkzeug herauslösen — Prüfstand wertlos."
  exit 1
fi
fehler() { echo "  FEHLER: $*" >&2; }
# shellcheck source=/dev/null
source "$FKT"
pok "lizenz_gate() aus wordpress-daten-update.sh eingebunden"

# ── Zustand 1: das eingecheckte Gerüst ──────────────────────────────────────
# So, wie die Datei heute im Repository steht. Sie MUSS sperren — sonst wäre
# schon der nächste Abruf eine ungedeckte Auslieferung.
DATEN="$(dirname "$LIC")"
if ! lizenz_gate 2>/dev/null; then
  pok "das eingecheckte Gerüst sperrt"
else
  pfehl "das eingecheckte Gerüst sperrt NICHT — ein Abruf würde ungedeckt ausliefern"
fi

# ── Zustand 2: Datei fehlt ganz ─────────────────────────────────────────────
DATEN="${ARBEIT}/leer"; mkdir -p "$DATEN"
if ! lizenz_gate 2>/dev/null; then
  pok "fehlende LICENSE sperrt"
else
  pfehl "ohne LICENSE wird nicht gesperrt"
fi

# ── Zustand 3: ausgefüllt ───────────────────────────────────────────────────
# Die Gegenprobe. Ohne sie wäre eine Sperre, die immer zuschlägt, genauso
# bestanden — und es entstünde nie ein Bestand.
DATEN="${ARBEIT}/fertig"; mkdir -p "$DATEN"
sed -e 's/\[DATUM EINTRAGEN\]/2026-08-12/' \
    -e 's/\[STAND EINTRAGEN\]/26.01.2026/' \
    -e 's/\[COPYRIGHT-VERMERK VON DEFIANT, INC. IM WORTLAUT EINSETZEN\]/(hier stuende der Vermerk)/' \
    -e 's/\[LIZENZTEXT IM WORTLAUT EINSETZEN — vollstaendig, nicht sinngemaess\]/(hier stuende der Text)/' \
    -e '/^PLATZHALTER/d' \
    "$LIC" > "${DATEN}/LICENSE"
if lizenz_gate 2>/dev/null; then
  pok "eine ausgefüllte LICENSE öffnet das Gate"
else
  pfehl "auch eine ausgefüllte LICENSE sperrt — es entstünde nie ein Bestand"
fi

# ── Zustand 4: halb ausgefüllt ──────────────────────────────────────────────
# Der wahrscheinlichste Fehler: die PLATZHALTER-Zeile wird gelöscht, weil sie
# so aussieht, als sei sie das Einzige. Die Klammern darüber bleiben stehen.
DATEN="${ARBEIT}/halb"; mkdir -p "$DATEN"
sed -e '/^PLATZHALTER/d' "$LIC" > "${DATEN}/LICENSE"
if ! lizenz_gate 2>/dev/null; then
  pok "gelöschte PLATZHALTER-Zeile allein öffnet das Gate nicht"
else
  pfehl "ein halb ausgefülltes Gerüst öffnet das Gate"
fi

# ── Das Werkzeug selbst ─────────────────────────────────────────────────────
# Nicht nur die Funktion, sondern der Weg dorthin: alle drei Schalter, die
# einen Wordfence-Bestand schreiben würden, müssen am Gate scheitern.
for schalter in --wordfence --alles; do
  bash "$WERKZEUG" "$schalter" >/dev/null 2>&1
  if [[ "$?" -eq 2 ]]; then
    pok "${schalter} bricht am Gate ab (Rückgabewert 2)"
  else
    pfehl "${schalter} läuft am Gate vorbei"
  fi
done
# --aus-datei ebenso — auch ein gespeicherter Feed ist ein Wordfence-Bestand.
printf '{}' > "${ARBEIT}/feed.json"
bash "$WERKZEUG" --aus-datei "${ARBEIT}/feed.json" >/dev/null 2>&1
if [[ "$?" -eq 2 ]]; then
  pok "--aus-datei bricht am Gate ab"
else
  pfehl "--aus-datei läuft am Gate vorbei — ein gespeicherter Feed ist derselbe Bestand"
fi

# Und die Gegenprobe dazu: --kev darf NICHT gesperrt sein. Der CISA-Katalog ist
# ein Werk einer US-Behörde, gemeinfrei, ohne Auflagen. Ein Gate davor wäre
# falsch und würde den einzigen heute pflegbaren Teil blockieren.
if grep -A3 -- '--kev)' "$WERKZEUG" | grep -q 'lizenz_gate'; then
  pfehl "--kev hängt am Lizenz-Gate — der CISA-Katalog ist gemeinfrei"
else
  pok "--kev hängt nicht am Gate (gemeinfrei, keine Auflagen)"
fi

echo
if [[ "$FEHLER" -eq 0 ]]; then
  echo -e "${GRN}Alle Soll-Werte erreicht.${NC}"
  exit 0
fi
echo -e "${RED}${FEHLER} Abweichung(en).${NC}"
exit 1
