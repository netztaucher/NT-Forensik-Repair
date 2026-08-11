#!/usr/bin/env bash
# =============================================================================
# kern-pruefstand.sh — prüft die Zeitstempel-Auswertung in lib/kern.sh
# =============================================================================
# Warum ein dritter Prüfstand neben goldmuster.sh und baumscan-pruefstand.sh:
#
# datei_steckbrief() schreibt ausschliesslich in Belegdateien. Die Referenz
# unter pruefstand/referenz/ hält von den Belegen nur die DATEINAMEN fest
# (belege_dateiliste.txt), nicht deren Inhalt. Damit ist der gesamte Inhalt
# eines Belegs — und ein Beleg ist das, was am Ende vor Gericht getragen
# werden soll — von keinem Vergleich gedeckt. Man kann jede Zeile darin
# ändern oder entfernen, ohne dass ein Prüfstand ausschlägt.
#
# Hier stehen Soll-Werte statt eines Referenzvergleichs: bei "erkennt die
# Funktion eine Rückdatierung" ist die richtige Antwort vorher bekannt.
#
# Zu jedem Nachweis gehört eine Gegenprobe. Eine Prüfung, die nur zeigt, dass
# etwas gemeldet WIRD, lässt offen, ob die Funktion überhaupt unterscheidet —
# eine Zeile, die immer erscheint, ist kein Nachweis.
#
# Nutzung:  werkzeuge/kern-pruefstand.sh
# Rückgabe: 0 wenn alle Soll-Werte erreicht wurden, sonst 1
# =============================================================================

set -uo pipefail

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/.." && pwd)"
ARBEIT="${KERN_PRUEFSTAND_DIR:-${TMPDIR:-/tmp}/nt-kern-pruefstand}"

RED='\033[0;31m'; GRN='\033[0;32m'; NC='\033[0m'
FEHLER=0

# lib/kern.sh setzt beim Einbinden nichts in Gang, definiert aber Funktionen,
# die REPORT_FILE, die Farbvariablen und die Zaehler erwarten. Alles wird hier
# gestellt.
BOLD=''; BLU=''; CYN=''; YLW=''
N_OK=0; N_WARN=0; N_CRIT=0; N_INFO=0
rm -rf "$ARBEIT"; mkdir -p "$ARBEIT"
REPORT_FILE="${ARBEIT}/bericht.md"; : > "$REPORT_FILE"
# shellcheck source=/dev/null
source "${SELF_DIR}/lib/kern.sh"

# NACH dem Einbinden und unter eigenem Namen: lib/kern.sh definiert selbst ein
# ok(), das in den Bericht schreibt und N_OK hochzaehlt. Wer seine Helfer
# davor und gleichnamig anlegt, verliert sie stillschweigend an die Bibliothek
# — der erste Entwurf dieses Prüfstands tat das und brach bei der zweiten
# Ausgabezeile ab.
pok()   { echo -e "  ${GRN}✓${NC} $1"; }
pfehl() { echo -e "  ${RED}✗${NC} $1"; FEHLER=$((FEHLER+1)); }

echo "Kern-Prüfstand — Zeitstempel in Belegen"
echo "  Arbeit: $ARBEIT"
echo

# ── datei_meta: crtime ──────────────────────────────────────────────────────
# Die Anlegezeit ist nicht überall zu haben — ext4 führt sie, meldet sie aber
# nur bei ausreichend grossem Inode. Geprüft wird deshalb nicht ein Datum,
# sondern dass die Funktion nie leer bleibt: ein leeres Feld im Beleg sieht
# aus wie "kein Befund", nicht wie "nicht messbar".
printf 'inhalt\n' > "${ARBEIT}/normal.php"
CR=$(datei_meta "${ARBEIT}/normal.php" crtime)
if [[ -n "$CR" ]]; then
  pok "datei_meta crtime liefert eine Aussage: ${CR}"
else
  pfehl "datei_meta crtime liefert eine LEERE Zeichenkette — im Beleg nicht von 'kein Befund' zu unterscheiden"
fi
for feld in mtime ctime groesse eigner rechte; do
  W=$(datei_meta "${ARBEIT}/normal.php" "$feld")
  [[ -n "$W" ]] || pfehl "datei_meta $feld ist leer"
done
pok "datei_meta liefert mtime, ctime, groesse, eigner, rechte"

# ── datei_steckbrief: alle drei Zeitstempel ─────────────────────────────────
AUS=$(datei_steckbrief "Prüfstand" "inhalt" "${ARBEIT}/normal.php")
for marke in "(mtime)" "(ctime)" "(crtime)"; do
  if grep -qF "$marke" <<<"$AUS"; then
    pok "Steckbrief führt ${marke}"
  else
    pfehl "Steckbrief führt ${marke} NICHT"
  fi
done

# ── Rückdatierung ───────────────────────────────────────────────────────────
# `touch -t` setzt die mtime in die Vergangenheit; die ctime bleibt auf jetzt.
# Genau die Signatur, die eine zurückdatierte Webshell hinterlässt.
printf 'inhalt\n' > "${ARBEIT}/zurueckdatiert.php"
touch -t 202001010000 "${ARBEIT}/zurueckdatiert.php"
AUS_ALT=$(datei_steckbrief "Prüfstand" "inhalt" "${ARBEIT}/zurueckdatiert.php")
if grep -q "Rueckdatierung" <<<"$AUS_ALT"; then
  pok "Rückdatierung wird gemeldet"
else
  pfehl "Rückdatierung wird NICHT gemeldet — mtime 2020, ctime heute"
fi
# Gegenprobe: an einer frisch geschriebenen Datei darf der Hinweis fehlen.
if grep -q "Rueckdatierung" <<<"$AUS"; then
  pfehl "Rückdatierung wird auch an einer unauffälligen Datei gemeldet — der Hinweis trägt nichts"
else
  pok "unauffällige Datei bekommt keinen Rückdatierungs-Hinweis"
fi

# ── Nachbarvergleich (touch -r) ─────────────────────────────────────────────
# `touch -r nachbar.php shell.php` übernimmt die mtime sekundengenau. Bei
# normaler Arbeit entstehen keine zwei Dateien in derselben Sekunde.
mkdir -p "${ARBEIT}/paar"
printf 'a\n' > "${ARBEIT}/paar/original.php"
printf 'inhalt\n' > "${ARBEIT}/paar/shell.php"
touch -r "${ARBEIT}/paar/original.php" "${ARBEIT}/paar/shell.php"
AUS_PAAR=$(datei_steckbrief "Prüfstand" "inhalt" "${ARBEIT}/paar/shell.php")
if grep -q "Gleiche mtime wie" <<<"$AUS_PAAR"; then
  pok "übernommene mtime wird gemeldet"
else
  pfehl "übernommene mtime wird NICHT gemeldet — touch -r bliebe unsichtbar"
fi

# Gegenprobe zur oberen Schranke: eine Entpackung schreibt viele Dateien in
# dieselbe Sekunde. Das ist normal und darf NICHT gemeldet werden — sonst
# trägt jeder entpackte Ordner den Hinweis und niemand liest ihn mehr.
mkdir -p "${ARBEIT}/entpackt"
printf 'inhalt\n' > "${ARBEIT}/entpackt/datei.php"
for i in 1 2 3 4 5 6 7 8; do printf 'x\n' > "${ARBEIT}/entpackt/n${i}.php"; done
touch -r "${ARBEIT}/entpackt/datei.php" "${ARBEIT}/entpackt"/n*.php
AUS_VIEL=$(datei_steckbrief "Prüfstand" "inhalt" "${ARBEIT}/entpackt/datei.php")
if grep -q "Gleiche mtime wie" <<<"$AUS_VIEL"; then
  pfehl "acht gleichzeitige Dateien werden gemeldet — eine Entpackung erzeugt so einen Fehlalarm"
else
  pok "flächige Gleichzeitigkeit (8 Dateien) wird nicht gemeldet"
fi

echo
if [[ "$FEHLER" -eq 0 ]]; then
  echo -e "${GRN}Alle Soll-Werte erreicht.${NC}"
  exit 0
fi
echo -e "${RED}${FEHLER} Abweichung(en).${NC}"
exit 1
