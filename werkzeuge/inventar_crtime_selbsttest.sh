#!/usr/bin/env bash
# ============================================================
# NT-Forensik — Selbsttest: nicht messbare Anlegezeit im Inventar (7.0)
# ------------------------------------------------------------
#   werkzeuge/inventar_crtime_selbsttest.sh [lib/kern.sh] [07_dateisystem.sh]
#
# Test:     ja - dieses Skript, find/stat-Attrappen ohne Server · NT-Forensik-Repair#141
# Rueckweg: entfällt - liest nur
#
# WOZU
#
# Am 21.10.2026 (web68/cletus) stand in belege/00_dateien.tsv in JEDER Zeile
# crtime -1: GNU-find meldet so eine Anlegezeit, die das Dateisystem nicht
# herausgibt. datei_inventar machte nur aus leer und 0 ein "-", und 7.0
# zaehlte alles ausser "-" als Anlegezeit — der Bericht meldete 18541 Dateien
# "mit Anlegezeit", obwohl keine einzige messbar war. Wer danach die
# Chronologie auf die crtime stuetzt, stuetzt sie auf 31.12.1969.
#
# Ein echtes ext4 ohne grosse Inodes steht weder auf dem Arbeitsplatz noch in
# der CI. Deshalb liefern Attrappen von find und stat genau die Rohzeilen,
# die der Server lieferte — die Bereinigung und die Zaehlung laufen echt.
#
# Geprueft wird in BEIDE Richtungen. "crtime ist immer -" bestuende jeden
# Test, der nur nach "-" fragt:
#   1. GNU-Zweig: -1, -1.0000000000, 0, leer und -5 werden zu "-"
#   2. GNU-Zweig: eine echte Zeit bleibt (ohne Bruchteil) stehen
#   3. Gegenprobe: eine NEGATIVE mtime bleibt stehen — sie ist echt
#      (touch -d 1969) und genau der Befund einer plumpen Rueckdatierung
#   4. BSD-Zweig (NT_INVENTAR_BSD=1): dieselbe Bereinigung
#   5. Zaehlung aus 7.0 — die Zeile wird aus dem Modul gelesen, nicht
#      abgeschrieben: zaehlt nur die echte Zeit, auch in einem Alt-Beleg,
#      in dem die -1 noch steht
# ============================================================
set -uo pipefail
WURZEL="$(cd "$(dirname "$0")/.." && pwd)"
KERN="${1:-${WURZEL}/lib/kern.sh}"
MODUL="${2:-${WURZEL}/module/07_dateisystem.sh}"
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
fail=0
ok_()   { echo "  ✓ $1"; }
fehl_() { echo "  ✗ $1"; fail=$((fail+1)); }

# lib/kern.sh erwartet den Rahmen des Hauptskripts.
BOLD=''; BLU=''; CYN=''; YLW=''; RED=''; GRN=''; NC=''
N_OK=0; N_WARN=0; N_CRIT=0; N_INFO=0
TOOL_VERSION="selbsttest"
REPORT_FILE="${TMP}/bericht.md"; : > "$REPORT_FILE"
# shellcheck source=/dev/null
source "$KERN"

# ── Attrappen ───────────────────────────────────────────────────────────────
# Rohzeilen wie vom Server: dev inode modus eigner gruppe groesse mtime ctime
# crtime pfad. Die erste ist die Beispielzeile aus #141.
BIN="${TMP}/bin"; mkdir -p "$BIN"
cat > "${TMP}/roh.tsv" <<'ROH'
2051	134509913	644	web68	psacln	48993	1361952335.1234567890	1711144782.9950781560	-1	/var/www/vhosts/x/german.php.bak
2051	2	644	web68	psacln	1	1361952335	1711144782	-1.0000000000	/var/www/vhosts/x/minus_bruch.php
2051	3	644	web68	psacln	1	1361952335	1711144782	0	/var/www/vhosts/x/null.php
2051	4	644	web68	psacln	1	1361952335	1711144782		/var/www/vhosts/x/leer.php
2051	5	644	web68	psacln	1	1361952335	1711144782	-5	/var/www/vhosts/x/negativ.php
2051	6	644	web68	psacln	1	1361952335	1711144782	1711144700.5000000000	/var/www/vhosts/x/echt.php
2051	7	644	web68	psacln	1	-31536000.2500000000	1711144782	-1	/var/www/vhosts/x/vor1970.php
ROH
# find: die Faehigkeitsabfrage (-maxdepth 0 -printf '') besteht, -printf
# liefert die Rohzeilen, -print0 einen Pfad fuer den BSD-Zweig.
cat > "${BIN}/find" <<ATTRAPPE
#!/usr/bin/env bash
case " \$* " in
  *" -maxdepth 0 "*) exit 0 ;;
  *" -print0 "*)     printf 'x\\0' ;;
  *" -printf "*)     cat "${TMP}/roh.tsv" ;;
esac
ATTRAPPE
# stat: der BSD-Zweig ruft stat -f '<format>' <pfade...> ueber xargs.
# BSD-stat schreibt ganze Sekunden; die Bruchteile fallen deshalb hier weg,
# die nicht messbaren Werte (-1, 0, leer, -5) bleiben roh.
cat > "${BIN}/stat" <<ATTRAPPE
#!/usr/bin/env bash
awk -F'\\t' 'BEGIN{OFS="\\t"} {for (i = 7; i <= 9; i++) sub(/\\..*/, "", \$i); print}' "${TMP}/roh.tsv"
ATTRAPPE
chmod +x "${BIN}/find" "${BIN}/stat"

crt() {   # <inventar> <inode> → crtime-Feld
  awk -F'\t' -v i="$2" '!/^#/ && $2 == i {print $9; exit}' "$1"
}
mt() {    # <inventar> <inode> → mtime-Feld
  awk -F'\t' -v i="$2" '!/^#/ && $2 == i {print $7; exit}' "$1"
}

pruefe_zweig() {   # <name> <inventar>
  local name="$1" inv="$2" ino w
  for ino in 134509913 2 3 4 5 7; do
    w=$(crt "$inv" "$ino")
    if [[ "$w" == "-" ]]; then
      ok_ "${name}: nicht messbare Anlegezeit (Inode ${ino}) steht als '-'"
    else
      fehl_ "${name}: Inode ${ino} traegt crtime '${w}' statt '-' — liest sich wie eine Zeit"
    fi
  done
  w=$(crt "$inv" 6)
  if [[ "$w" == "1711144700" ]]; then
    ok_ "${name}: echte Anlegezeit bleibt stehen (${w})"
  else
    fehl_ "${name}: echte Anlegezeit verloren oder verfaelscht ('${w}' statt 1711144700)"
  fi
  w=$(mt "$inv" 7)
  if [[ "$w" == "-31536000" ]]; then
    ok_ "${name}: negative mtime bleibt stehen (${w}) — die Rueckdatierung bleibt im Beleg"
  else
    fehl_ "${name}: negative mtime wurde zu '${w}' — der Befund einer Rueckdatierung ist weg"
  fi
}

echo "Selbsttest Inventar-crtime (#141)"

# ── 1-3: GNU-Zweig ──────────────────────────────────────────────────────────
INV="${TMP}/00_dateien.tsv"
N=$(PATH="${BIN}:${PATH}" datei_inventar "$INV" /var/www/vhosts/x)
if [[ "${N:-0}" -eq 7 ]]; then ok_ "GNU-Zweig: 7 Zeilen erfasst"
else fehl_ "GNU-Zweig: ${N:-0} statt 7 Zeilen erfasst"; fi
pruefe_zweig "GNU-Zweig" "$INV"

# ── 4: BSD-Zweig ────────────────────────────────────────────────────────────
INV_BSD="${TMP}/bsd.tsv"
N=$(PATH="${BIN}:${PATH}" NT_INVENTAR_BSD=1 datei_inventar "$INV_BSD" /var/www/vhosts/x)
if [[ "${N:-0}" -eq 7 ]]; then ok_ "BSD-Zweig: 7 Zeilen erfasst"
else fehl_ "BSD-Zweig: ${N:-0} statt 7 Zeilen erfasst"; fi
pruefe_zweig "BSD-Zweig" "$INV_BSD"

# ── 5: Zaehlung in 7.0 ──────────────────────────────────────────────────────
# Das awk-Programm wird aus der Zeile INVENTAR_CRT=$(awk ...) des Moduls
# geschnitten. Abgeschrieben wuerde der Test gruen bleiben, waehrend das
# Modul weiter falsch zaehlt.
PROG=$(sed -n "s/^ *INVENTAR_CRT=\$(awk -F'\\\\t' '\\([^']*\\)'.*/\\1/p" "$MODUL" | head -1)
if [[ -z "$PROG" ]]; then
  fehl_ "Zaehlzeile INVENTAR_CRT=\$(awk ...) in ${MODUL##*/} nicht gefunden — Test passt nicht mehr zum Modul"
else
  n=$(awk -F'\t' "$PROG" "$INV")
  if [[ "$n" == "1" ]]; then ok_ "7.0 zaehlt im neuen Inventar 1 Anlegezeit (nur die echte)"
  else fehl_ "7.0 zaehlt im neuen Inventar ${n} statt 1 Anlegezeit"; fi
  # Alt-Beleg: so lag er am 21.10.2026 vor, mit -1 im Feld.
  { echo "# Alt-Beleg"; cut -f1-8 "${TMP}/roh.tsv" | head -1 | awk -F'\t' 'BEGIN{OFS="\t"}{print $0, "-1", "/a.php"}'
    printf '1\t2\t644\tu\tg\t1\t1\t1\t1711144700\t/b.php\n'; } > "${TMP}/alt.tsv"
  n=$(awk -F'\t' "$PROG" "${TMP}/alt.tsv")
  if [[ "$n" == "1" ]]; then ok_ "7.0 zaehlt im Alt-Beleg mit -1 nur die echte Anlegezeit (1)"
  else fehl_ "7.0 zaehlt im Alt-Beleg ${n} statt 1 — die -1 gilt als Anlegezeit"; fi
fi

echo
if [[ "$fail" -eq 0 ]]; then echo "Alle Soll-Werte erreicht."; exit 0; fi
echo "${fail} Abweichung(en)."; exit 1
