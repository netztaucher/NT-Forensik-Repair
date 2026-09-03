#!/usr/bin/env bash
# ============================================================
# NT-Forensik — Selbsttest der Hub-SSO-Befundklasse (rezept_konfig)
# ------------------------------------------------------------
#   werkzeuge/hub_sso_selbsttest.sh [rezept.sh]
#
# WOZU
#
# Die Klasse entscheidet aus drei Angaben (Plugin-Fassung, SSO-Schalter,
# Schluessel-Zustand) ueber crit/warn/ok. Jede einzelne Verzweigung ist
# plausibel; falsch wird erst die Kombination. Beim Einbruch vom 28.08.2026
# war die Lage "Fassung 5.0.0, SSO scharf, Site verbunden" — sie muss crit
# ergeben, und "Fassung 5.0.2, SSO aus" darf es nicht.
#
# Besonders die Altfassungen: 4.11.x fuehrt 'userid' OHNE 'enabled'. Wer das
# als "aus" liest, erklaert genau die Instanz fuer sicher, die am 01.09. ein
# zweites Mal uebernommen wurde.
#
# Der Test laeuft ohne Datenbank und ohne WordPress: der Rahmen wird durch
# Attrappen ersetzt, die Instanz ist ein Wegwerf-Verzeichnis.
# ============================================================
set -uo pipefail
REZEPT="${1:-$(cd "$(dirname "$0")/.." && pwd)/rezepte/wordpress/rezept.sh}"
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
fail=0

# --- Attrappen des Rahmens -------------------------------------------------
LETZTE=""
befund_melden() { LETZTE="$3|$4"; }          # <app> <kat> <schwere> <text> ...
evidence()      { :; }
REZ_PFX="wp_"
SELF_DIR="$(cd "$(dirname "$REZEPT")/../.." && pwd)"   # fuer lib/wp_schwachstellen.py
# _db_sql wird je Fall neu gesetzt

# Nur die zu testenden Funktionen laden (kein voller Rezept-Lauf).
eval "$(sed -n '/^_ver_kleiner()/,/^}/p'   "$REZEPT")"
eval "$(sed -n '/^_wp_haertung_hub_sso()/,/^}$/p' "$REZEPT")"

baue_instanz() {   # <version|-> <konstante 0|1>
  local ver="$1" konst="$2"
  REZ_PFAD="$TMP/inst.$RANDOM"; REZ_KURZ="test.example"
  mkdir -p "$REZ_PFAD/wp-content/plugins/wpmudev-updates"
  printf '<?php\n' > "$REZ_PFAD/wp-config.php"
  [[ "$konst" == "1" ]] && printf "define( 'WPMUDEV_DISABLE_SSO', true );\n" >> "$REZ_PFAD/wp-config.php"
  if [[ "$ver" != "-" ]]; then
    printf '<?php\n/*\n * Plugin Name: WPMU DEV Dashboard\n * Version: %s\n */\n' "$ver" \
      > "$REZ_PFAD/wp-content/plugins/wpmudev-updates/update-notifications.php"
  fi
}
ohne_plugin() { REZ_PFAD="$TMP/leer.$RANDOM"; REZ_KURZ="test.example"; mkdir -p "$REZ_PFAD"; printf '<?php\n' > "$REZ_PFAD/wp-config.php"; }

pruefe() {   # <name> <erwartete-schwere> <erwartetes-textmuster>
  local name="$1" erw_s="$2" erw_t="$3"
  local s="${LETZTE%%|*}" t="${LETZTE#*|}"
  if [[ "$s" == "$erw_s" ]] && [[ "$t" == *"$erw_t"* ]]; then
    printf '  OK     %-46s -> %s\n' "$name" "$s"
  else
    printf '  FEHLER %-46s -> [%s] %s\n' "$name" "$s" "${t:0:90}"; fail=1
  fi
}

# Eigene Namen (T_*): rezept_konfig deklariert selbst `local sso keylen`, und
# durch Bashs dynamisches Scoping wuerde die Attrappe sonst die LEEREN locals
# der aufrufenden Funktion lesen statt der Testwerte.
lauf() {   # <sso-option> <keylen>
  T_SSO="$1"; T_KEYLEN="$2"
  _db_sql() { case "$1" in wpmudev_sso) printf '%s\n' "$T_SSO";; wpmudev_key) printf '%s\n' "$T_KEYLEN";; esac; }
  LETZTE=""; _wp_haertung_hub_sso
}

SSO_AN='a:4:{s:7:"enabled";b:1;s:6:"userid";i:1;}'
SSO_AUS='a:4:{s:7:"enabled";b:0;s:6:"userid";i:1;}'
SSO_ALT='a:3:{s:6:"userid";i:1;}'          # 4.11.x: userid ohne enabled

echo "=== _wp_haertung_hub_sso — Fallmatrix"
baue_instanz 5.0.0 1; lauf "$SSO_AN" 64;  pruefe "Konstante gesetzt sticht alles"        ok    "hart abgeschaltet"
baue_instanz 5.0.0 0; lauf "$SSO_AN" 64;  pruefe "5.0.0 + SSO scharf"                    crit  "CVE-2026-76581"
baue_instanz 5.0.1 0; lauf "$SSO_AN" 64;  pruefe "5.0.1 + SSO scharf"                    crit  "CVE-2026-76581"
baue_instanz 4.11.28 0; lauf "$SSO_ALT" 64; pruefe "4.11.28 userid ohne enabled = scharf" crit  "CVE-2026-76581"
baue_instanz 5.0.0 0; lauf "$SSO_AUS" 0;  pruefe "5.0.0 unverbunden, leerer Schluessel"   crit  "CVE-2026-15459"
baue_instanz 5.0.1 0; lauf "$SSO_AUS" 64; pruefe "5.0.1 + SSO aus"                        warn  "veraltet"
baue_instanz 5.0.2 0; lauf "$SSO_AN" 64;  pruefe "5.0.2 + SSO scharf = Haertung"          warn  "Hub-SSO scharf"
baue_instanz 5.0.2 0; lauf "$SSO_AUS" 64; pruefe "5.0.2 + SSO aus"                        ok    "nicht scharf"
baue_instanz - 0;     lauf "$SSO_AN" 64;  pruefe "Version nicht lesbar"                   unklar "nicht bewertbar"
ohne_plugin;          lauf "$SSO_AN" 64;  [[ -z "$LETZTE" ]] && printf '  OK     %-46s -> keine Meldung\n' "kein Dashboard installiert" || { printf '  FEHLER kein Dashboard -> %s\n' "$LETZTE"; fail=1; }

[[ $fail -eq 0 ]] && echo "=> ALLE BESTANDEN" || echo "=> FEHLGESCHLAGEN"
exit $fail
