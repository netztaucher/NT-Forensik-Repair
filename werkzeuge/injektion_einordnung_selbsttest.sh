#!/usr/bin/env bash
# ============================================================
# NT-Forensik — Selbsttest der Einordnung der 7.15-Rangfolge (#42)
# ------------------------------------------------------------
#   werkzeuge/injektion_einordnung_selbsttest.sh [13d_webshell_einordnung.sh]
#
# WOZU
#
# Abschnitt 7.15 stellt eine Rangfolge für die Sichtung auf. Sie meldet keinen
# Befund — sie bestimmt, wohin ein Mensch zuerst sieht. Auf dem Serverlauf vom
# 03.09.2026 lagen 7.619 ihrer 48.290 Einträge (15,8 %) unter einem Kern, den
# derselbe Lauf als unverändert bestätigt hatte.
#
# Geprüft wird in BEIDE Richtungen. Ein Filter, der nur "entlastet" prüft, wäre
# durch "entlastet alles" zu bestehen — und das wäre die stille Entwarnung,
# gegen die der ganze Abschnitt gebaut ist.
#
# 7.15 liefert Zeilen "<pfad><TAB><punkte><TAB><merkmale>", nicht den
# "=== pfad ==="-Block der Musterstufen. Genau diese Formatnaht ist hier der
# Prüfgegenstand: der Pfad steht vor dem ERSTEN Tabulator, alles dahinter muss
# unverändert mitwandern.
#
# Läuft ohne Prüfbaum, ohne WordPress und ohne Netz.
# ============================================================
set -uo pipefail
MODUL="${1:-$(cd "$(dirname "$0")/.." && pwd)/module/13d_webshell_einordnung.sh}"
SELF_DIR="$(cd "$(dirname "$0")/.." && pwd)"
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
fail=0

BELEGE_DIR="$TMP"
eval "$(sed -n '/^_inj_einordnen()/,/^}$/p' "$MODUL")"
[[ "$(type -t _inj_einordnen)" == "function" ]] \
  || { echo "FEHLER: _inj_einordnen nicht aus $MODUL lösbar"; exit 1; }

# Kern von Kunde 3 ist geprüft, der von Kunde 4 nicht. Eine bestätigte
# Plugin-Datei steht einzeln in der Dateiliste.
printf '%s\n' "$TMP/k3" > "$TMP/kern.txt"
printf '%s\n' "$TMP/k3/wp-content/plugins/p/bestaetigt.php" > "$TMP/dateien.txt"
_WL="$TMP/dateien.txt"; _WL_KERN="$TMP/kern.txt"
# Die Abweichung aus verify-checksums: trotz Kernfreigabe NICHT entlasten.
_AUSN="$TMP/k3/wp-includes/load.php"

zeilen() { printf '%s\t4\tDICHTE=120,RANDLAGE\n' "$@"; }

pruefe() {   # <pfad> <soll: WEG|BLEIBT> <beschreibung>
  local weg rest
  _inj_einordnen "$(zeilen "$1")"
  weg=$(printf '%s' "$_I_WEG" | grep -c . || true)
  rest=$(printf '%s' "$_I_REST" | grep -c . || true)
  local ist="BLEIBT"; [[ "${weg:-0}" -gt 0 ]] && ist="WEG"
  if [[ "$ist" == "$2" ]]; then printf '  OK     %-46s -> %s\n' "$3" "$ist"
  else printf '  FEHLER %-46s -> %s (erwartet %s, rest=%s weg=%s)\n' "$3" "$ist" "$2" "$rest" "$weg"; fail=1; fi
}

echo "=== Einordnung der 7.15-Rangfolge"
pruefe "$TMP/k3/wp-includes/gross.php"                  WEG    "unter geprüftem Kern -> entlastet"
pruefe "$TMP/k4/wp-includes/gross.php"                  BLEIBT "unter UNGEPRÜFTEM Kern -> bleibt"
pruefe "$TMP/k3/wp-includes/load.php"                   BLEIBT "Abweichung trotz Kernfreigabe -> bleibt"
pruefe "$TMP/k3/wp-content/plugins/p/bestaetigt.php"    WEG    "bestätigte Plugin-Datei -> entlastet"
pruefe "$TMP/k3/wp-content/uploads/fremd.php"           BLEIBT "ausserhalb Kern und Liste -> bleibt"

echo "=== Format und Bilanz"
# Alles dahinter muss unverändert mitwandern — die Rangfolge lebt von Punkten
# und Merkmalen, ein Filter, der nur Pfade zurückgibt, zerstört sie.
_inj_einordnen "$(zeilen "$TMP/k4/wp-includes/a.php")"
if [[ "$_I_REST" == *$'\t4\tDICHTE=120,RANDLAGE'* ]]; then
  echo "  OK     Punkte und Merkmale bleiben an der Zeile"
else echo "  FEHLER Zeilenrest verloren: $_I_REST"; fail=1; fi

# Der Fall, an dem die Musterstufen-Aufteilung einmal gescheitert ist: wenn
# ALLES entlastet wird, muss die Restliste wirklich leer sein — nicht alles
# enthalten.
_inj_einordnen "$(zeilen "$TMP/k3/wp-includes/a.php" "$TMP/k3/wp-includes/b.php")"
if [[ -z "$_I_REST" && "$_I_NW" -eq 2 && "$_I_N" -eq 0 ]]; then
  echo "  OK     alles entlastet -> Restliste leer, Bilanz 0/2"
else echo "  FEHLER alles entlastet: rest='${_I_REST}' n=$_I_N nw=$_I_NW"; fail=1; fi

# Ohne Listen darf NICHTS entlastet werden: ein ausgefallenes
# verify-checksums ist keine Freigabe.
_WL="/nicht/vorhanden"; _WL_KERN="/nicht/vorhanden"
_inj_einordnen "$(zeilen "$TMP/k3/wp-includes/a.php")"
if [[ "$_I_NW" -eq 0 && "$_I_N" -eq 1 ]]; then
  echo "  OK     ohne Listen entlastet nichts"
else echo "  FEHLER ohne Listen: n=$_I_N nw=$_I_NW"; fail=1; fi

# Leere Eingabe: keine Zeile, keine Zahl, kein Absturz.
_inj_einordnen ""
if [[ "$_I_N" -eq 0 && "$_I_NW" -eq 0 ]]; then
  echo "  OK     leere Eingabe -> 0/0"
else echo "  FEHLER leere Eingabe: n=$_I_N nw=$_I_NW"; fail=1; fi

[[ $fail -eq 0 ]] && echo "=> ALLE BESTANDEN" || echo "=> FEHLGESCHLAGEN"
exit $fail
