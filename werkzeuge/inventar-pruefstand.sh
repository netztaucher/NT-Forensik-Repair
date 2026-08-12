#!/usr/bin/env bash
# =============================================================================
# inventar-pruefstand.sh — prüft das Datei-Inventar aus lib/kern.sh (#25)
# =============================================================================
# Warum ein eigener Prüfstand:
#
# Die Referenz unter pruefstand/referenz/ hält von den Belegen nur die
# DATEINAMEN fest, nicht deren Inhalt. `00_dateien.tsv` ist ein Beleg — der
# Inhalt wäre also von keinem Vergleich gedeckt. Und er ist nicht irgendein
# Inhalt: er ist die einzige Aufzeichnung, die eine Quarantäne überlebt.
#
# Geprüft wird das, was das Inventar leisten SOLL, nicht seine Formatierung:
# dass sich eine verschobene Datei über dev+inode als dieselbe wiedererkennen
# lässt, und dass ein Bruch dieser Kette sichtbar wird statt still zu bleiben.
#
# Zu jedem Nachweis gehört eine Gegenprobe. Eine Prüfung, die nur zeigt, dass
# etwas erkannt WIRD, lässt offen, ob die Funktion überhaupt unterscheidet.
#
# Nutzung:  werkzeuge/inventar-pruefstand.sh
# Rückgabe: 0 wenn alle Soll-Werte erreicht wurden, sonst 1
# =============================================================================

set -uo pipefail

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/.." && pwd)"
ARBEIT="${INVENTAR_PRUEFSTAND_DIR:-${TMPDIR:-/tmp}/nt-inventar-pruefstand}"

RED='\033[0;31m'; GRN='\033[0;32m'; NC='\033[0m'
FEHLER=0

# lib/kern.sh definiert selbst ok/warn/info und erwartet REPORT_FILE sowie die
# Farb- und Zählvariablen. Eigene Helfer deshalb NACH dem Einbinden und unter
# eigenem Namen — sonst gehen sie stillschweigend an die Bibliothek verloren.
BOLD=''; BLU=''; CYN=''; YLW=''
N_OK=0; N_WARN=0; N_CRIT=0; N_INFO=0
TOOL_VERSION="pruefstand"
rm -rf "$ARBEIT"; mkdir -p "$ARBEIT"
REPORT_FILE="${ARBEIT}/bericht.md"; : > "$REPORT_FILE"
# shellcheck source=/dev/null
source "${SELF_DIR}/lib/kern.sh"
pok()   { echo -e "  ${GRN}✓${NC} $1"; }
pfehl() { echo -e "  ${RED}✗${NC} $1"; FEHLER=$((FEHLER+1)); }

echo "Inventar-Prüfstand — Zeitstempel über die Quarantäne hinweg"
echo "  Arbeit: $ARBEIT"
echo

BAUM="${ARBEIT}/baum"; QUAR="${ARBEIT}/quarantaene"
mkdir -p "$BAUM" "$QUAR"

# ── Der Prüfgegenstand ──────────────────────────────────────────────────────
# Eine zurückdatierte Datei (die Signatur einer Webshell, die sich alt stellt)
# und eine unauffällige daneben als Gegenprobe.
printf '<?php // Pruefstand\n' > "${BAUM}/shell.php"
touch -t 202001010000 "${BAUM}/shell.php"
printf '<?php // Pruefstand\n' > "${BAUM}/normal.php"

INV="${ARBEIT}/00_dateien.tsv"
N=$(datei_inventar "$INV" "$BAUM")

# ── Grundform ───────────────────────────────────────────────────────────────
if [[ "${N:-0}" -eq 2 ]]; then
  pok "Inventar erfasst beide Dateien (${N})"
else
  pfehl "Inventar erfasst ${N:-0} statt 2 Dateien"
fi

zeile() {   # <dateiname> — die Inventarzeile dazu
  awk -F'\t' -v f="$1" '!/^#/ && $10 ~ ("/" f "$")' "$INV" | head -1
}
feld() { printf '%s' "$2" | cut -f"$1"; }

Z_SHELL=$(zeile shell.php)
if [[ -n "$Z_SHELL" ]]; then
  pok "Zeile zur zurückdatierten Datei vorhanden"
else
  pfehl "Keine Zeile zur zurückdatierten Datei — der Rest ist nicht prüfbar"
  exit 1
fi

# Kopfzeile: ohne sie ist die Datei in fünf Jahren nicht mehr lesbar.
for marke in "Erhoben:" "dev" "inode" "crtime" "Sekunden seit 1970"; do
  if grep -qF "$marke" "$INV"; then
    pok "Kopf nennt '${marke}'"
  else
    pfehl "Kopf nennt '${marke}' NICHT"
  fi
done

# ── ctime ist das Signal, nicht crtime ──────────────────────────────────────
# `touch` kann die ctime nicht setzen; der Kern setzt sie bei jeder
# Inode-Änderung auf jetzt. "mtime deutlich älter als ctime" ist damit das
# eigentliche Kennzeichen einer Rückdatierung — und genau das, was ein
# Verschieben in die Quarantäne überschreibt.
M_SHELL=$(feld 7 "$Z_SHELL"); C_SHELL=$(feld 8 "$Z_SHELL")
if [[ "$M_SHELL" =~ ^[0-9]+$ && "$C_SHELL" =~ ^[0-9]+$ ]] \
   && (( C_SHELL - M_SHELL > 86400 )); then
  pok "Rückdatierung im Inventar erkennbar (ctime $(( (C_SHELL - M_SHELL) / 86400 )) Tage nach mtime)"
else
  pfehl "Rückdatierung im Inventar NICHT erkennbar (mtime=${M_SHELL}, ctime=${C_SHELL})"
fi
# Gegenprobe: die unauffällige Datei darf diesen Abstand nicht zeigen.
Z_NORM=$(zeile normal.php)
M_N=$(feld 7 "$Z_NORM"); C_N=$(feld 8 "$Z_NORM")
if [[ "$M_N" =~ ^[0-9]+$ ]] && (( C_N - M_N <= 86400 )); then
  pok "unauffällige Datei zeigt keinen Abstand zwischen mtime und ctime"
else
  pfehl "auch die unauffällige Datei zeigt einen Abstand — das Merkmal trägt nichts"
fi

# ── Die Kette: Verschieben ──────────────────────────────────────────────────
# `mv` im selben Dateisystem behält den Inode. Damit lässt sich die Datei in
# der Quarantäne als dieselbe wiedererkennen — und die aufgezeichneten
# Zeitstempel gelten weiter, obwohl die LEBENDE ctime durch das Verschieben
# überschrieben wurde.
I_VOR=$(feld 2 "$Z_SHELL"); D_VOR=$(feld 1 "$Z_SHELL")
# Eine Sekunde warten, sonst faellt das Verschieben in dieselbe Sekunde wie die
# Erhebung und die Ueberschreibung der ctime waere nicht messbar — der Test
# wuerde bestehen, ohne etwas gezeigt zu haben.
sleep 1
mv "${BAUM}/shell.php" "${QUAR}/shell.php"
INV2="${ARBEIT}/nach_verschieben.tsv"
datei_inventar "$INV2" "$QUAR" >/dev/null
Z_NACH=$(awk -F'\t' '!/^#/ && $10 ~ /shell\.php$/' "$INV2" | head -1)
I_NACH=$(feld 2 "$Z_NACH"); D_NACH=$(feld 1 "$Z_NACH")

if [[ -n "$I_NACH" && "$I_VOR" == "$I_NACH" && "$D_VOR" == "$D_NACH" ]]; then
  pok "nach dem Verschieben über dev+inode als dieselbe Datei wiedererkennbar"
else
  pfehl "Inode nach dem Verschieben verändert (${D_VOR}/${I_VOR} → ${D_NACH:-?}/${I_NACH:-?}) — die Kette reisst"
fi

# Und der Beleg, warum das Inventar überhaupt nötig ist: die ctime ist jetzt
# überschrieben. Wer sie nicht vorher aufgezeichnet hat, hat sie nicht mehr.
C_NACH=$(feld 8 "$Z_NACH")
if [[ "$C_NACH" =~ ^[0-9]+$ ]] && (( C_NACH > C_SHELL )); then
  pok "die lebende ctime ist durch das Verschieben überschrieben — nur das Inventar hat sie noch"
else
  pfehl "die ctime hat das Verschieben unverändert überstanden — dann misst dieser Prüfstand nicht, was er soll"
fi

# ── Die Gegenprobe: Kopieren bricht die Kette, und das muss auffallen ───────
printf '<?php // Pruefstand\n' > "${BAUM}/zweite.php"
INV3="${ARBEIT}/vor_kopie.tsv"
datei_inventar "$INV3" "$BAUM" >/dev/null
Z_K_VOR=$(awk -F'\t' '!/^#/ && $10 ~ /zweite\.php$/' "$INV3" | head -1)
I_K_VOR=$(feld 2 "$Z_K_VOR")
cp "${BAUM}/zweite.php" "${QUAR}/zweite.php"
INV4="${ARBEIT}/nach_kopie.tsv"
datei_inventar "$INV4" "$QUAR" >/dev/null
Z_K_NACH=$(awk -F'\t' '!/^#/ && $10 ~ /zweite\.php$/' "$INV4" | head -1)
I_K_NACH=$(feld 2 "$Z_K_NACH")
if [[ -n "$I_K_NACH" && "$I_K_VOR" != "$I_K_NACH" ]]; then
  pok "nach dem Kopieren weicht der Inode ab — der Bruch der Kette ist sichtbar"
else
  pfehl "nach dem Kopieren derselbe Inode (${I_K_VOR} / ${I_K_NACH:-?}) — ein Bruch bliebe unbemerkt"
fi

# ── crtime: vorhanden oder ausdrücklich nicht messbar ───────────────────────
# Nie leer. Ein leeres Feld liest sich wie "kein Befund", nicht wie "nicht
# messbar" — derselbe Fehlertyp, den der vierte Zustand im Bericht abfängt.
LEER=$(awk -F'\t' '!/^#/ && $9 == ""' "$INV" | grep -c . || true)
if [[ "${LEER:-0}" -eq 0 ]]; then
  pok "Anlegezeit ist überall gefüllt (Wert oder '-')"
else
  pfehl "${LEER} Zeile(n) mit leerer Anlegezeit — von 'kein Befund' nicht zu unterscheiden"
fi

echo
if [[ "$FEHLER" -eq 0 ]]; then
  echo -e "${GRN}Alle Soll-Werte erreicht.${NC}"
  exit 0
fi
echo -e "${RED}${FEHLER} Abweichung(en).${NC}"
exit 1
