#!/usr/bin/env bash
# ============================================================
# NT-Forensik — Alter des Schwachstellen-Bestands pruefen (#129)
# ------------------------------------------------------------
#   werkzeuge/bestand-alter.sh <VERSION-datei>
#
# WOZU
#
# Das Rezept bricht seinen Abgleich ab, sobald der Bestand aelter als
# WP_DATEN_MAX_TAGE ist (rezepte/wordpress/rezept.sh, Standard 30). Das ist
# richtig, aber leise: am 30.09.2026 stand der Bestand auf main 49 Tage,
# weil der Daten-PR sieben Wochen offen lag, waehrend der Wochenlauf viermal
# gruen war. Dieses Werkzeug warnt VOR der Marke, mit Vorlauf fuer mindestens
# einen weiteren Wochenlauf.
#
# Schwelle = WP_DATEN_MAX_TAGE - BESTAND_VORLAUF_TAGE (Standard 30 - 9 = 21).
# Die 30 ist derselbe Standard wie im Rezept; wer ihn dort aendert, setzt
# WP_DATEN_MAX_TAGE, und beide Stellen folgen.
#
# Rueckgabe: 0 = unter der Schwelle · 1 = Schwelle erreicht oder Marke
#            ueberschritten · 2 = Datei fehlt oder Datum nicht lesbar.
# Datumsrechnung wie im Rezept (GNU date, Rueckfall BSD date).
# ============================================================
set -uo pipefail
datei="${1:-}"
[[ -r "$datei" ]] || { echo "bestand-alter: VERSION-Datei fehlt oder nicht lesbar: ${datei:-—}"; exit 2; }

max="${WP_DATEN_MAX_TAGE:-30}"
vorlauf="${BESTAND_VORLAUF_TAGE:-9}"
schwelle=$(( max - vorlauf ))

stand=$(sed -nE 's/^([0-9]{4}-[0-9]{2}-[0-9]{2}).*/\1/p' "$datei" | head -1)
[[ -n "$stand" ]] || { echo "bestand-alter: kein Datum (JJJJ-MM-TT) in der ersten Zeile von $datei"; exit 2; }
sek=$(date -u -d "$stand" +%s 2>/dev/null || date -u -j -f %Y-%m-%d "$stand" +%s 2>/dev/null) \
  || { echo "bestand-alter: Datum nicht lesbar: $stand"; exit 2; }
alter=$(( ( $(date -u +%s) - sek ) / 86400 ))

text="Bestand vom ${stand}, ${alter} Tage alt (Warnschwelle ${schwelle}, Abbruch des Abgleichs ueber ${max})"
if (( alter > max )); then
  echo "UEBER DER MARKE: ${text} — der WordPress-Abgleich laeuft nicht."; exit 1
elif (( alter >= schwelle )); then
  echo "WARNUNG: ${text} — Daten-PR pruefen und mergen."; exit 1
fi
echo "ok: ${text}"
