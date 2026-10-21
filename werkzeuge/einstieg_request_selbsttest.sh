#!/usr/bin/env bash
# ============================================================
# NT-Forensik — Selbsttest: Einstiegsweg aus dem Zugriffsprotokoll (13e.5)
# ------------------------------------------------------------
#   werkzeuge/einstieg_request_selbsttest.sh [13e_ursachensuche.sh]
#
# Test:     ja - dieses Skript, Wegwerf-Baum ohne Server · NT-Forensik-Repair#135
# Rueckweg: entfällt - liest nur
#
# WOZU
#
# Am 21.10.2026 (web68/cletus) entstand das Schad-Plugin hero-hub/ in
# derselben Sekunde, in der UpdraftCentral ("WordPress/6.4; class-udrpc.php")
# per POST auf die Seite zugriff. 13e meldete trotzdem "Einstiegsweg nicht
# bestimmbar": entschieden hatte allein der aelteste Beleg, eine Altdatei
# von 2013, und gegen die frischen Funde wurde nie ein Protokoll gehalten.
#
# Geprueft wird in BEIDE Richtungen. Ein Test, der nur "meldet jetzt crit"
# prueft, waere durch "meldet immer crit" zu bestehen:
#   1. udrpc-POST in derselben Sekunde (Log als .gz-Rotation unter system/)
#      → crit "Einstiegsweg: UpdraftCentral", IP in ATTACK_IPS_UNIQ,
#        kein "nicht bestimmbar"
#   2. Protokoll deckt die Datei ab, aber in ±2 s nur ein GET ohne Kennung
#      → kein crit, unklar "nicht bestimmen"
#   3. Datei liegt vor dem Protokollfenster
#      → bisherige Aussage "Der aelteste Beleg liegt vor dem verfuegbaren
#        Protokollfenster", kein crit
#   4. Plugin ohne Fundlisten-Eintrag, angelegt zeitgleich mit udrpc-POST
#      → warn "Plugin-/Theme-Anlage", kein crit, keine IOC-Adresse
#
# Der Abschnitt laeuft vollstaendig — nur der Rahmen (Berichtsausgabe,
# Belegablage, Geltungsbereich) ist durch Attrappen ersetzt. Die Zeitstempel
# der Dateien sind echt: birth laesst sich nicht setzen, also werden die
# Protokollzeilen auf die gemessene ctime geschrieben, nicht umgekehrt.
# ============================================================
set -uo pipefail
WURZEL="$(cd "$(dirname "$0")/.." && pwd)"
MODUL="${1:-${WURZEL}/module/13e_ursachensuche.sh}"
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
fail=0

# Echte Zeitfunktionen aus dem Kern, keine Nachbauten: genau ihre
# GNU/BSD-Verzweigung ist hier mitzupruefen.
eval "$(sed -n '/^datei_meta() {/,/^}/p'   "${WURZEL}/lib/kern.sh")"
eval "$(sed -n '/^datei_epoche() {/,/^}/p' "${WURZEL}/lib/kern.sh")"

epoche_ctime() { stat -c %Z "$1" 2>/dev/null || stat -f %c "$1"; }
apache_zeit()  {   # Sekunden → Apache-Stempel in lokaler Zeit
  LC_ALL=C date -d "@$1" '+%d/%b/%Y:%H:%M:%S %z' 2>/dev/null \
    || LC_ALL=C date -r "$1" '+%d/%b/%Y:%H:%M:%S %z'
}
zeile() {          # <epoche> <ip> <request> <ua>
  printf '%s - - [%s] "%s HTTP/1.1" 200 7084 "-" "%s"\n' "$2" "$(apache_zeit "$1")" "$3" "$4"
}

# Ein Lauf des Abschnitts in einer Subshell; die Meldungen landen als
# "schwere|text" in $1/meldungen, die IOC-Liste in $1/iocs.
# SC2034: die Variablen liest der eingebundene Abschnitt, nicht dieses Skript.
# shellcheck disable=SC2034
lauf() {           # <fallverzeichnis> <belastete-datei|->
  local F="$1" BEL="$2"
  (
    MELD="$F/meldungen"; : > "$MELD"
    h2()     { :; }
    info()   { printf 'info|%s\n'   "$1" >> "$MELD"; }
    ok()     { printf 'ok|%s\n'     "$1" >> "$MELD"; }
    warn()   { printf 'warn|%s\n'   "$1" >> "$MELD"; }
    crit()   { printf 'crit|%s\n'   "$1" >> "$MELD"; }
    unklar() { printf 'unklar|%s\n' "$1" >> "$MELD"; }
    code()   { :; }
    evidence() { printf '%s\n' "$2" > "$F/beleg_$1.txt"; }
    werkzeug_da() { command -v "$1" >/dev/null 2>&1; }
    scope_vhost_dirs() { printf '%s\n' "$F/vhosts/kunde.example"; }
    VHOSTS_DIR="$F/vhosts"
    NT_AUTHLOG_ATTRAPPE="$F/auth.log"; : > "$NT_AUTHLOG_ATTRAPPE"
    ATTACK_IPS_UNIQ=""
    DROPPER_DETAIL=""; [[ "$BEL" != "-" ]] && DROPPER_DETAIL="$BEL"
    WEBSHELL_NAMEN=""; CORE_SNE=""; CORE_INJECT_HITS=""; DISGUISED_PAYLOADS=""
    SIGNATUR_TREFFER=""; NC_MALWARE=""; JOOMLA_MALWARE=""; ZEITANKER=""
    # shellcheck disable=SC1090
    source "$MODUL"
    printf '%s\n' "$ATTACK_IPS_UNIQ" > "$F/iocs"
  ) 2> "$F/stderr"
}

baum() {           # <fall> → legt vhost an, gibt Plugin-Datei aus
  local F="$TMP/$1" P
  P="$F/vhosts/kunde.example/httpdocs/wp-content/plugins/hero-hub"
  mkdir -p "$P" "$F/vhosts/kunde.example/logs"
  printf '<?php /* hero-hub */\n' > "$P/hero-hub.php"
  # Alte mtime wie bei einem Archiv, das seine Zeitstempel mitbringt.
  touch -t 202401010000 "$P/hero-hub.php"
  printf '%s\n' "$P/hero-hub.php"
}

pruefe() {         # <fall> <name> <schwere> <muster> [nicht]
  local F="$TMP/$1" name="$2" s="$3" m="$4" neg="${5:-}"
  if grep -qF -- "${s}|" "$F/meldungen" && grep -F -- "${s}|" "$F/meldungen" | grep -qF -- "$m"; then
    if [[ "$neg" == nicht ]]; then
      printf '  FEHLER %-58s -> unerwartet: %s\n' "$name" "$(grep -F -- "${s}|" "$F/meldungen" | grep -F -- "$m" | head -1 | cut -c1-110)"; fail=1
    else
      printf '  OK     %-58s\n' "$name"
    fi
  else
    if [[ "$neg" == nicht ]]; then
      printf '  OK     %-58s\n' "$name"
    else
      printf '  FEHLER %-58s -> fehlt [%s] %s\n' "$name" "$s" "$m"; fail=1
      sed 's/^/           /' "$F/meldungen" | cut -c1-160
      [[ -s "$F/stderr" ]] && sed 's/^/   stderr: /' "$F/stderr" | head -5
    fi
  fi
}

UA_UDRPC="WordPress/6.4; class-udrpc.php"
UA_BROWSER="Mozilla/5.0 (Windows NT 10.0; Win64; x64)"

echo "=== Fall 1: udrpc-POST in derselben Sekunde, Protokoll als .gz unter system/"
D=$(baum f1); T=$(epoche_ctime "$D")
SYS="$TMP/f1/vhosts/system/kunde.example/logs"; mkdir -p "$SYS"
{ zeile $(( T - 3600 )) 198.51.100.7 "GET /" "$UA_BROWSER"
  zeile $(( T - 1 ))    198.51.100.7 "GET /wp-content/themes/x/style.css" "$UA_BROWSER"
  zeile "$T"            203.0.113.42 "POST /" "$UA_UDRPC"
  zeile $(( T + 30 ))   198.51.100.7 "GET /kontakt/" "$UA_BROWSER"
} | gzip -c > "$SYS/access_ssl_log.processed.1.gz"
: > "$TMP/f1/vhosts/kunde.example/logs/access_ssl_log"
lauf "$TMP/f1" "$D"
pruefe f1 "crit Einstiegsweg UpdraftCentral"                crit   "Einstiegsweg: UpdraftCentral"
pruefe f1 "Adresse im Befund"                               crit   "von 203.0.113.42"
pruefe f1 "Datei im Befund"                                 crit   "hero-hub/hero-hub.php"
pruefe f1 "kein 'nicht bestimmbar'"                         unklar "nicht bestimmen" nicht
pruefe f1 "Browser-GET wird nicht zum Einstiegsweg"         crit   "198.51.100.7" nicht
if grep -qF 203.0.113.42 "$TMP/f1/iocs"; then printf '  OK     %-58s\n' "IP in ATTACK_IPS_UNIQ"
else printf '  FEHLER %-58s\n' "IP in ATTACK_IPS_UNIQ"; fail=1; fi
if grep -qF '▶ POST' "$TMP/f1/beleg_ursache_einstieg_requests.txt" 2>/dev/null; then printf '  OK     %-58s\n' "POST im Beleg hervorgehoben"
else printf '  FEHLER %-58s\n' "POST im Beleg hervorgehoben"; fail=1; fi

echo "=== Fall 2: Protokoll deckt ab, in ±2 s nur ein GET ohne Kennung"
D=$(baum f2); T=$(epoche_ctime "$D")
{ zeile $(( T - 3600 )) 198.51.100.7 "GET /" "$UA_BROWSER"
  zeile "$T"            198.51.100.7 "GET /bild.jpg" "$UA_BROWSER"
  zeile $(( T + 3600 )) 203.0.113.42 "POST /" "$UA_UDRPC"
} > "$TMP/f2/vhosts/kunde.example/logs/access_ssl_log"
lauf "$TMP/f2" "$D"
pruefe f2 "kein crit"                                       crit   "Einstiegsweg" nicht
pruefe f2 "unklar: nicht bestimmbar"                        unklar "Einstiegsweg laesst sich aus den vorhandenen Quellen nicht bestimmen"
pruefe f2 "nicht die Satzform 'vor dem Fenster'"            unklar "liegt vor dem verfuegbaren Protokollfenster" nicht

echo "=== Fall 3: Datei liegt vor dem Protokollfenster"
D=$(baum f3); T=$(epoche_ctime "$D")
{ zeile $(( T + 3600 )) 203.0.113.42 "POST /" "$UA_UDRPC"
  zeile $(( T + 3700 )) 198.51.100.7 "GET /" "$UA_BROWSER"
} > "$TMP/f3/vhosts/kunde.example/logs/access_ssl_log"
lauf "$TMP/f3" "$D"
pruefe f3 "bisherige Aussage"                               unklar "Der aelteste Beleg liegt vor dem verfuegbaren Protokollfenster — der Einstiegsweg laesst sich aus den vorhandenen Quellen nicht bestimmen"
pruefe f3 "kein crit"                                       crit   "Einstiegsweg" nicht

echo "=== Fall 4: Plugin ohne Fundlisten-Eintrag, zeitgleich mit udrpc-POST"
# 13e sucht nur in vhosts, in denen etwas belastet ist. Die belastete Datei
# muss hier also existieren, darf aber nicht selbst im Fenster liegen — sonst
# traefe der udrpc-Request SIE und der Fall pruefte wieder Fall 1. Eine ctime
# laesst sich nicht zurueckdatieren; deshalb entsteht sie zuerst, und das
# Protokoll beginnt erst nach ihr.
ALT="$TMP/f4/vhosts/kunde.example/httpdocs/wp-admin/alt.php"
mkdir -p "$(dirname "$ALT")"; printf '<?php\n' > "$ALT"
sleep 3
D=$(baum f4); T=$(epoche_ctime "$(dirname "$D")")
{ zeile $(( T - 1 )) 198.51.100.7 "GET /" "$UA_BROWSER"
  zeile "$T"         203.0.113.42 "POST /" "$UA_UDRPC"
} > "$TMP/f4/vhosts/kunde.example/logs/access_ssl_log"
lauf "$TMP/f4" "$ALT"
pruefe f4 "warn Plugin-Anlage mit Kennung"                  warn   "Plugin-/Theme-Anlage"
pruefe f4 "kein crit (nicht belastet)"                      crit   "Einstiegsweg" nicht
if grep -qF 203.0.113.42 "$TMP/f4/iocs"; then printf '  FEHLER %-58s\n' "keine IOC-Adresse ohne Belastung"; fail=1
else printf '  OK     %-58s\n' "keine IOC-Adresse ohne Belastung"; fi

[[ $fail -eq 0 ]] && echo "=> ALLE BESTANDEN" || echo "=> FEHLGESCHLAGEN"
exit $fail
