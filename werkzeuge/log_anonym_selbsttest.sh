#!/usr/bin/env bash
# ============================================================
# NT-Forensik — Selbsttest: anonymisierte Zugriffsprotokolle (Abschnitt 4)
# ------------------------------------------------------------
#   werkzeuge/log_anonym_selbsttest.sh [04_webtraffic.sh] [50_findings_json.sh]
#
# Test:     ja - dieses Skript, kuenstliche Protokolle voll/anonymisiert/gemischt ohne Server · NT-Forensik-Repair#142
# Rueckweg: entfällt - liest nur
#
# WOZU
#
# Am 21.10.2026 (web68/cletus) stand der Angreifer-Request bis 06:43 mit
# 43.250.53.42 im Protokoll. Die Plesk-Rotation schrieb ihn als 43.250.53.0
# weiter, und genau diese Netzadresse trugen IOC-Liste, Kundenbericht und
# BSI-Meldung — NT-Repair haette ein /24 als Einzel-IP gesperrt.
#
# Geprueft wird in BEIDE Richtungen. Ein Test, der nur "meldet jetzt ⚪"
# prueft, waere durch "meldet immer ⚪" zu bestehen:
#   1. volles Protokoll, Angreifer 43.250.53.42
#      → kein ⚪, logs_anonymisiert 0, keine Datei ausgewiesen
#   2. volles Protokoll, Angreifer zufaellig auf .0 (198.51.100.0)
#      → kein ⚪: .0 allein ist kein Beleg fuer Kuerzung
#   3. aktuelles Protokoll gekuerzt, Angreifer 43.250.53.0
#      → ⚪ "IOC-Adressen nur als /24", logs_anonymisiert 1
#   4. gemischt: aktuelle Datei voll, .gz-Rotation unter system/ gekuerzt
#      → kein ⚪, Hinweis "Rotationen gekuerzt", Datei je Datei im Beleg;
#        haengt ein spaeterer Abschnitt (13e) 43.250.53.0 an die IOC-Liste,
#        steht in findings.json logs_anonymisiert 1
#   5. Urteilsfunktion direkt: IPv6 gekuerzt, zu wenig Zeilen, halb gekuerzt
#
# Der Abschnitt laeuft vollstaendig — nur der Rahmen (Berichtsausgabe,
# Belegablage, Geltungsbereich) ist durch Attrappen ersetzt.
# ============================================================
set -uo pipefail
WURZEL="$(cd "$(dirname "$0")/.." && pwd)"
MODUL="${1:-${WURZEL}/module/04_webtraffic.sh}"
JSON_MODUL="${2:-${WURZEL}/module/14_berichte/50_findings_json.sh}"
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
fail=0

# Echte Zaehlfunktionen aus dem Kern, keine Nachbauten.
eval "$(sed -n '/^count_grep() {/,/^}/p'   "${WURZEL}/lib/kern.sh")"
eval "$(sed -n '/^count_grep_i() {/,/^}/p' "${WURZEL}/lib/kern.sh")"

# Genau der Ausdruck aus findings.json, nicht nachgebaut: die Zeile wird aus
# dem Exportmodul gelesen und hier ausgewertet.
JSON_AUSDRUCK=$(grep -F '"logs_anonymisiert":' "$JSON_MODUL" | sed -E 's/^[^:]*: //; s/,[[:space:]]*$//')

zeile() {          # <ip> <request>
  printf '%s - - [21/Oct/2026:06:11:00 +0200] "%s HTTP/1.1" 200 7084 "-" "Mozilla/5.0"\n' "$1" "$2"
}
fuell() {          # <anzahl> <anonym:0|1>  → Hintergrundverkehr
  local i
  for ((i = 1; i <= $1; i++)); do
    if [[ "$2" == 1 ]]; then zeile "198.51.$((i % 250)).0" "GET /seite-$i/"
    else zeile "198.51.$((i % 250)).$(( (i % 253) + 1 ))" "GET /seite-$i/"; fi
  done
}

# Ein Lauf des Abschnitts in einer Subshell; Meldungen als "schwere|text" in
# $1/meldungen, Kennwerte in $1/werte.
# SC2034: die Variablen liest der eingebundene Abschnitt, nicht dieses Skript.
# shellcheck disable=SC2034
lauf() {           # <fallverzeichnis> [nachtrag-ioc]
  local F="$1" NACH="${2:-}"
  (
    MELD="$F/meldungen"; : > "$MELD"
    h1() { :; }; h2() { :; }; code() { :; }
    info()   { printf 'info|%s\n'   "$1" >> "$MELD"; }
    ok()     { printf 'ok|%s\n'     "$1" >> "$MELD"; }
    warn()   { printf 'warn|%s\n'   "$1" >> "$MELD"; }
    crit()   { printf 'crit|%s\n'   "$1" >> "$MELD"; }
    unklar() { printf 'unklar|%s\n' "$1" >> "$MELD"; }
    evidence() { printf '%s\n' "$2" > "$F/beleg_$1.txt"; }
    scope_vhost_dirs() { printf '%s\n' "$F/vhosts/kunde.example"; }
    VHOSTS_DIR="$F/vhosts"; DOMAIN=""; REPORT_FILE="$F/bericht.md"
    CYN=""; NC=""
    # shellcheck disable=SC1090
    source "$MODUL"
    # Spaeterer Abschnitt (13e/12) haengt eine Adresse an — wie im Anlassfall.
    [[ -n "$NACH" ]] && ATTACK_IPS_UNIQ="${ATTACK_IPS_UNIQ:-}"$'\n'"$NACH"
    printf 'LOGS_ANONYMISIERT=%s\n' "$LOGS_ANONYMISIERT" > "$F/werte"
    printf 'JSON=%s\n' "$(eval "echo $JSON_AUSDRUCK")" >> "$F/werte"
  ) > "$F/stdout" 2> "$F/stderr"
}

baum() { mkdir -p "$TMP/$1/vhosts/kunde.example/logs"; printf '%s\n' "$TMP/$1/vhosts/kunde.example/logs"; }

pruefe() {         # <fall> <name> <schwere> <muster> [nicht]
  local F="$TMP/$1" name="$2" s="$3" m="$4" neg="${5:-}"
  if grep -F -- "${s}|" "$F/meldungen" | grep -qF -- "$m"; then
    if [[ "$neg" == nicht ]]; then
      printf '  FEHLER %-58s -> unerwartet: %s\n' "$name" "$(grep -F -- "${s}|" "$F/meldungen" | grep -F -- "$m" | head -1 | cut -c1-110)"; fail=1
    else printf '  OK     %-58s\n' "$name"; fi
  else
    if [[ "$neg" == nicht ]]; then printf '  OK     %-58s\n' "$name"
    else
      printf '  FEHLER %-58s -> fehlt [%s] %s\n' "$name" "$s" "$m"; fail=1
      sed 's/^/           /' "$F/meldungen" | cut -c1-160
      [[ -s "$F/stderr" ]] && sed 's/^/   stderr: /' "$F/stderr" | head -5
    fi
  fi
}
wert() {           # <fall> <name> <schluessel=wert>
  if grep -qxF -- "$3" "$TMP/$1/werte" 2>/dev/null; then printf '  OK     %-58s\n' "$2"
  else printf '  FEHLER %-58s -> erwartet %s, ist: %s\n' "$2" "$3" "$(tr '\n' ' ' < "$TMP/$1/werte" 2>/dev/null)"; fail=1; fi
}
beleg() {          # <fall> <name> <muster> [nicht]
  local B="$TMP/$1/beleg_zugriffsprotokolle_anonymisiert.txt"
  if grep -qF -- "$3" "$B" 2>/dev/null; then
    if [[ "${4:-}" == nicht ]]; then printf '  FEHLER %-58s\n' "$2"; fail=1; else printf '  OK     %-58s\n' "$2"; fi
  else
    if [[ "${4:-}" == nicht ]]; then printf '  OK     %-58s\n' "$2"; else printf '  FEHLER %-58s -> fehlt %s\n' "$2" "$3"; fail=1; fi
  fi
}

POST_SHELL="POST /wp-content/uploads/2026/10/x.php"

echo "=== Fall 1: volles Protokoll, Angreifer 43.250.53.42"
L=$(baum f1)
{ fuell 200 0; zeile 43.250.53.42 "$POST_SHELL"; } > "$L/access_ssl_log"
lauf "$TMP/f1"
pruefe f1 "Webshell-POST erkannt (Rahmen laeuft)"            crit   "Verdächtige POST-Requests"
pruefe f1 "kein ⚪ /24"                                       unklar "nur als /24" nicht
pruefe f1 "kein Hinweis auf gekuerzte Protokolle"           info   "anonymisiert" nicht
wert   f1 "LOGS_ANONYMISIERT=0"                             "LOGS_ANONYMISIERT=0"
wert   f1 "findings.json logs_anonymisiert 0"               "JSON=0"
beleg  f1 "kein Beleg zugriffsprotokolle_anonymisiert"      "access_ssl_log" nicht

echo "=== Fall 2: volles Protokoll, Angreifer zufaellig auf .0"
L=$(baum f2)
{ fuell 200 0; zeile 198.51.100.0 "$POST_SHELL"; } > "$L/access_ssl_log"
lauf "$TMP/f2"
pruefe f2 "kein ⚪ /24 bei einzelner .0-Adresse"              unklar "nur als /24" nicht
wert   f2 "LOGS_ANONYMISIERT=0"                             "LOGS_ANONYMISIERT=0"
wert   f2 "findings.json logs_anonymisiert 0"               "JSON=0"

echo "=== Fall 3: aktuelles Protokoll gekuerzt, Angreifer 43.250.53.0"
L=$(baum f3)
{ fuell 200 1; zeile 43.250.53.0 "$POST_SHELL"; } > "$L/access_ssl_log"
lauf "$TMP/f3"
pruefe f3 "⚪ IOC-Adressen nur als /24"                       unklar "IOC-Adressen nur als /24"
pruefe f3 "Adresse im Befund"                               unklar "43.250.53.0"
wert   f3 "LOGS_ANONYMISIERT=1"                             "LOGS_ANONYMISIERT=1"
wert   f3 "findings.json logs_anonymisiert 1"               "JSON=1"
beleg  f3 "Datei im Beleg als anonymisiert"                 "anonymisiert"

echo "=== Fall 4: gemischt — aktuelle Datei voll, .gz-Rotation unter system/ gekuerzt"
L=$(baum f4)
{ fuell 200 0; zeile 43.250.53.42 "$POST_SHELL"; } > "$L/access_ssl_log"
SYS="$TMP/f4/vhosts/system/kunde.example/logs"; mkdir -p "$SYS"
{ fuell 300 1; zeile 43.250.53.0 "$POST_SHELL"; } | gzip -c > "$SYS/access_ssl_log.processed.1.gz"
lauf "$TMP/f4"
pruefe f4 "kein ⚪ — IOC aus voller Datei"                    unklar "nur als /24" nicht
pruefe f4 "Hinweis Rotationen gekuerzt"                     info   "Rotationen gekuerzt: kunde.example"
beleg  f4 "Rotation je Datei im Beleg"                      "access_ssl_log.processed.1.gz"
beleg  f4 "aktuelle Datei NICHT im Beleg"                   "logs/access_ssl_log	" nicht
wert   f4 "LOGS_ANONYMISIERT=0"                             "LOGS_ANONYMISIERT=0"
wert   f4 "findings.json 0 ohne .0-IOC"                     "JSON=0"
lauf "$TMP/f4" "      1 43.250.53.0"
wert   f4 "findings.json 1, wenn 13e 43.250.53.0 anhaengt"  "JSON=1"

echo "=== Fall 5: Urteilsfunktion direkt"
eval "$(sed -n '/^log_anonym_lesen() {/,/^}/p;/^log_anonym_urteil() {/,/^}/p' "$MODUL")"
urteil() {         # <datei> <name> <erwartet>
  local u; u=$(log_anonym_urteil "$1" | awk '{print $3}')
  if [[ "$u" == "$3" ]]; then printf '  OK     %-58s\n' "$2"
  else printf '  FEHLER %-58s -> erwartet %s, ist %s\n' "$2" "$3" "$u"; fail=1; fi
}
for i in $(seq 1 50); do zeile "2a01:4f8:c17:$i::" "GET /"; done > "$TMP/v6_anon"
for i in $(seq 1 50); do zeile "2a01:4f8:c17:$i::1a$i" "GET /"; done > "$TMP/v6_voll"
fuell 5 1 > "$TMP/wenig"
{ fuell 50 1; fuell 50 0; } > "$TMP/halb"
fuell 100 1 | bzip2 -c > "$TMP/anon.bz2" 2>/dev/null || true
urteil "$TMP/v6_anon" "IPv6 gekuerzt → anonymisiert"              anonymisiert
urteil "$TMP/v6_voll" "IPv6 voll → voll"                          voll
urteil "$TMP/wenig"   "5 Zeilen → ohne_urteil"                    ohne_urteil
urteil "$TMP/halb"    "halb gekuerzt → gemischt"                  gemischt
if command -v bzip2 >/dev/null 2>&1; then urteil "$TMP/anon.bz2" "bz2-Rotation gekuerzt → anonymisiert" anonymisiert; fi

echo
if [[ "$fail" -eq 0 ]]; then echo "ERGEBNIS: alle Faelle bestanden"; exit 0
else echo "ERGEBNIS: FEHLER"; exit 1; fi
