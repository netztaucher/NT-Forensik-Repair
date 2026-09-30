#!/usr/bin/env bash
# ============================================================
# NT-Forensik — Selbsttest von werkzeuge/bestand-alter.sh (#129)
# ------------------------------------------------------------
#   werkzeuge/bestand_alter_selbsttest.sh
#
# Beide Richtungen: ein frischer Bestand muss gruen bleiben, ein alter rot
# werden. Ein Test, der nur "warnt" prueft, waere durch "warnt immer" zu
# bestehen — dann ginge die Warnung im Rauschen unter.
# Die Daten werden relativ zu heute erzeugt; der Test altert nicht.
# ============================================================
set -uo pipefail
W="$(cd "$(dirname "$0")" && pwd)/bestand-alter.sh"
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
fail=0

vor() { date -u -d "-$1 days" +%Y-%m-%d 2>/dev/null || date -u -v-"$1"d +%Y-%m-%d; }
fall() { # <name> <erwarteter rc> <inhalt der ersten Zeile> [env...]
  local name="$1" soll="$2" zeile="$3"; shift 3
  printf '%s | erzeugt von werkzeuge/wordpress-daten-update.sh\nwp-core.tsv 1 Zeile(n)\n' "$zeile" > "$TMP/VERSION"
  local aus rc; aus=$(env "$@" bash "$W" "$TMP/VERSION"); rc=$?
  if [[ "$rc" == "$soll" ]]; then echo "ok    $name (rc=$rc): $aus"
  else echo "FEHLER $name: rc=$rc, erwartet $soll — $aus"; fail=1; fi
}

fall "5 Tage alt"                       0 "$(vor 5)"
fall "20 Tage alt, knapp unter 21"      0 "$(vor 20)"
fall "21 Tage alt, Schwelle erreicht"   1 "$(vor 21)"
fall "22 Tage alt"                      1 "$(vor 22)"
fall "49 Tage alt (Stand 30.09.2026)"   1 "$(vor 49)"
fall "Grenze 60 verschiebt Schwelle"    0 "$(vor 49)" WP_DATEN_MAX_TAGE=60
fall "kein Datum"                       2 "unbekannt"
aus=$(bash "$W" "$TMP/gibt-es-nicht"); rc=$?
if [[ $rc == 2 ]]; then echo "ok    Datei fehlt (rc=2)"; else echo "FEHLER Datei fehlt: rc=$rc — $aus"; fail=1; fi

# Meldungstext: WARNUNG und UEBER DER MARKE auseinanderhalten
aus=$(bash "$W" <(printf '%s |\n' "$(vor 22)")); [[ "$aus" == WARNUNG:* ]] || { echo "FEHLER Text 22 Tage: $aus"; fail=1; }
aus=$(bash "$W" <(printf '%s |\n' "$(vor 31)")); [[ "$aus" == "UEBER DER MARKE:"* ]] || { echo "FEHLER Text 31 Tage: $aus"; fail=1; }

exit $fail
