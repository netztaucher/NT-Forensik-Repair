#!/usr/bin/env bash
# ============================================================
# NT-Forensik — Selbsttest der Dropper-Entlastung in 13d (#136)
# ------------------------------------------------------------
#   werkzeuge/dropper_entlastung_selbsttest.sh [13d_webshell_einordnung.sh]
#
# Test:     ja - dieser Selbsttest selbst, laeuft ohne Server · NT-Forensik-Repair#136
# Rueckweg: entfällt - liest nur
#
# WOZU
#
# Lauf web68 vom 21.10.2026: "🔴 Webshells/Dropper gefunden: 1 Datei(en)
# (1 gegen amtliche Prüfsummen entlastet)". Die kritische Datei war
# advanced-ads/includes/ads/class-ad-plain.php, byteweise das Original von
# wordpress.org — und stand trotzdem in actionable.webshell_dropper, aus dem
# NT-Repair seine Quarantaene-Kandidaten zieht.
#
# Die Nachpruefung ergab: entlastet war eine ANDERE Datei (Kern), die
# Plugin-Datei blieb, weil der Lauf ohne --online keine Plugin-Pruefsummen
# hatte. Dieser Test haelt deshalb beide Haelften fest:
#
#   1. Liegt die amtliche Bestaetigung vor, verschwindet die Datei aus
#      Zaehlung, crit und der Liste fuer actionable — und bleibt im Beleg,
#      mit Vermerk.
#   2. Liegt sie NICHT vor, bleibt die Datei kritisch (keine Entlastung ohne
#      Pruefung) — aber der Bericht sagt, dass die Plugin-Pruefung fehlte.
#
# Geprueft wird das GANZE Modul, nicht eine herausgeloeste Funktion: der
# Fehler, um den es geht, waere eine Reihenfolge (Liste vor Entlastung
# befuellt, Zaehlung vor Abzug), und die sieht man nur im Ablauf. Der Rahmen
# (h2, crit, evidence …) wird durch Attrappen ersetzt. Ohne Server, ohne Netz.
# ============================================================
set -uo pipefail
MODUL="${1:-$(cd "$(dirname "$0")/.." && pwd)/module/13d_webshell_einordnung.sh}"
WURZEL="$(cd "$(dirname "$0")/.." && pwd)"
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
fail=0

command -v python3 >/dev/null 2>&1 || { echo "FEHLER: python3 fehlt — 13d braucht es"; exit 1; }

V="$TMP/vhosts/web68.example/httpdocs"
PLUGIN="$V/wp-content/plugins/advanced-ads/includes/ads/class-ad-plain.php"
KERN="$V/wp-includes/class-wp-simplepie-sanitize-kses.php"
FREMD="$V/wp-content/uploads/2026/10/x.php"

block() {   # <pfad>... — je Pfad ein Absatz im Format aus 7.3
  # Wie in 7.3 (DROPPER_DETAIL+="$entry"$'\n'): jeder Absatz endet mit einem
  # Zeilenumbruch. Ueber $(…) zusammengesetzt, ginge er verloren und der
  # naechste Kopf klebte an der Trefferzeile.
  local p
  for p in "$@"; do
    printf '=== %s ===\nGröße: 2356 B | SHA256: 7d239fe8\nTreffer: 36:eval( %s\n' "$p" "'?>"
  done
}

# Fuehrt 13d in einer Unterschale aus und schreibt das Ergebnis als
# Schluessel=Wert-Zeilen nach $TMP/erg. Jede Stufe bekommt frischen Zustand.
lauf() {   # <dropper_detail> <plugin-whitelist-inhalt> <want_online>
  local detail="$1" wl="$2" online="$3"
  rm -rf "$TMP/run"; mkdir -p "$TMP/run/belege"
  printf '%s' "$wl" > "$TMP/run/.pruefsummen_bestaetigt.txt"
  printf '%s\n' "$V" > "$TMP/run/.pruefsummen_kern.txt"   # Kern geprueft
  # SC2034: die Variablen liest das per `source` eingebundene Modul.
  # shellcheck disable=SC2034
  (
    RUN_DIR="$TMP/run"; BELEGE_DIR="$TMP/run/belege"; SELF_DIR="$WURZEL"
    REPORT_FILE="$TMP/run/bericht.md"; : > "$REPORT_FILE"
    DROPPER_MAX_BYTES=3000; WANT_ONLINE="$online"
    NF_OHNE_INJEKTIONSMASS=1
    DROPPER_DETAIL="$detail"; WEBSHELL_COUNT=$(printf '%s' "$detail" | grep -c '^=== ' || true)
    CRIT=""; OKS=""; INFOS=""; BELEG_N=0
    h2()   { :; }
    code() { :; }
    warn() { :; }
    crit() { CRIT+="$1"$'\n'; }
    ok()   { OKS+="$1"$'\n'; }
    info() { INFOS+="$1"$'\n'; }
    evidence() { BELEG_N=$((BELEG_N+1)); printf '%s\n' "$2" > "$BELEGE_DIR/$1.txt"; }
    # shellcheck source=/dev/null
    source "$MODUL"
    # Dieselbe Ableitung wie module/14_berichte/50_findings_json.sh fuer
    # actionable.webshell_dropper: die Pfade aus DROPPER_DETAIL.
    ACTIONABLE=$(printf '%s\n' "${DROPPER_DETAIL:-}" | grep '^=== ' | sed 's/^=== //; s/ ===$//' || true)
    {
      printf 'CRIT=%s\n' "$(printf '%s' "$CRIT" | tr '\n' ' ')"
      printf 'OK=%s\n'   "$(printf '%s' "$OKS"  | tr '\n' ' ')"
      printf 'INFO=%s\n' "$(printf '%s' "$INFOS" | tr '\n' ' ')"
      printf 'ACTIONABLE=%s\n' "$(printf '%s' "$ACTIONABLE" | tr '\n' ' ')"
      printf 'COUNT=%s\nENTLASTET=%s\nROH=%s\nUNGEPRUEFT=%s\n' \
        "${WEBSHELL_COUNT:-}" "${WEBSHELL_ENTLASTET:-}" "${WEBSHELL_COUNT_ROH:-}" "${WEBSHELL_PLUGIN_UNGEPRUEFT:-}"
    } > "$TMP/erg"
  )
}
wert() { grep "^$1=" "$TMP/erg" | head -1 | cut -d= -f2-; }

soll() {   # <beschreibung> <bedingung als Ausdruck>
  if eval "$2"; then printf '  OK     %s\n' "$1"
  else printf '  FEHLER %s\n         (%s)\n' "$1" "$2"; fail=1; fi
}

echo "=== Anlassfall mit Pluginpruefung: die eine Datei ist amtlich bestaetigt"
lauf "$(block "$PLUGIN")" "$PLUGIN"$'\n' 1
soll "kein crit"                          '[[ -z "$(wert CRIT)" ]]'
soll "nicht in actionable"                '[[ "$(wert ACTIONABLE)" != *class-ad-plain.php* ]]'
soll "Zaehler 0, entlastet 1, roh 1"      '[[ "$(wert COUNT)" == 0 && "$(wert ENTLASTET)" == 1 && "$(wert ROH)" == 1 ]]'
soll "Entwarnung nennt die Entlastung"    '[[ "$(wert OK)" == *"1 Mustertreffer waren gegen amtliche Prüfsummen"* ]]'
soll "Beleg behaelt die Datei"            'grep -q "class-ad-plain.php" "$TMP/run/belege/webshell_dropper_entlastet.txt"'
soll "Beleg traegt den Vermerk"           'grep -q "AMTLICH ENTLASTET" "$TMP/run/belege/webshell_dropper_entlastet.txt"'
soll "kein kritischer Beleg"              '[[ ! -e "$TMP/run/belege/webshell_dropper_kritisch.txt" ]]'

echo "=== Gemischt: Kern entlastet, fremde Datei bleibt"
lauf "$(block "$KERN" "$FREMD")" "" 1
soll "crit fuer genau 1 Datei"            '[[ "$(wert CRIT)" == *"gefunden: 1 Datei(en)"* ]]'
soll "Wortlaut: entlastete NICHT mitgezaehlt" '[[ "$(wert CRIT)" == *"1 weitere(r) Mustertreffer"*"nicht mitgezählt"* ]]'
soll "actionable = nur die fremde Datei"  '[[ "$(wert ACTIONABLE)" == "$FREMD" ]]'
soll "entlastete Kern-Datei nicht in actionable" '[[ "$(wert ACTIONABLE)" != *simplepie* ]]'
soll "Zaehler 1, entlastet 1, roh 2"      '[[ "$(wert COUNT)" == 1 && "$(wert ENTLASTET)" == 1 && "$(wert ROH)" == 2 ]]'
soll "kritischer Beleg ohne Kern-Datei"   '! grep -q simplepie "$TMP/run/belege/webshell_dropper_kritisch.txt"'
soll "kein Offline-Hinweis mit --online"  '[[ "$(wert INFO)" != *"ohne --online"* ]]'

echo "=== Anlassfall wie gelaufen: ohne --online, keine Plugin-Pruefsummen"
lauf "$(block "$KERN" "$PLUGIN")" "" 0
soll "bleibt crit (keine Entlastung ohne Pruefung)" '[[ "$(wert CRIT)" == *"gefunden: 1 Datei(en)"* ]]'
soll "bleibt in actionable"               '[[ "$(wert ACTIONABLE)" == *class-ad-plain.php* ]]'
soll "Bericht nennt die fehlende Pruefung" '[[ "$(wert INFO)" == *"1 davon liegen in Plugin-Verzeichnissen"*"ohne --online"* ]]'
soll "Zaehler fuer die Luecke = 1"        '[[ "$(wert UNGEPRUEFT)" == 1 ]]'

echo "=== Gegenprobe: ohne Listen entlastet nichts"
(
  # Dieselbe Naht wie im Modul: beide Listen gelten als nicht vorhanden. Dann
  # darf weder die Kern- noch die Plugin-Datei entlastet werden — sonst waere
  # nicht belegt, dass oben der Filter wirkte und nicht ein Fehler im Ablauf.
  NT_PRUEFSTAND_OHNE_PMF_WHITELIST=1; export NT_PRUEFSTAND_OHNE_PMF_WHITELIST
  lauf "$(block "$KERN" "$PLUGIN")" "$PLUGIN"$'\n' 1
)
soll "beide crit"                         '[[ "$(wert CRIT)" == *"gefunden: 2 Datei(en)"* ]]'
soll "beide in actionable"                '[[ "$(wert ACTIONABLE)" == *simplepie* && "$(wert ACTIONABLE)" == *class-ad-plain.php* ]]'
soll "nichts entlastet"                   '[[ "$(wert ENTLASTET)" == 0 ]]'

[[ $fail -eq 0 ]] && echo "=> ALLE BESTANDEN" || echo "=> FEHLGESCHLAGEN"
exit $fail
