#!/usr/bin/env bash
# ============================================================
# NT-Forensik — Selbsttest der WordPress-Härtungsprüfungen (#85)
# ------------------------------------------------------------
#   werkzeuge/haertung_selbsttest.sh [rezept.sh]
#
# WOZU
#
# Der Einbruch vom 28.08.2026 brauchte keinen Exploit. Er brauchte drei
# offene Schalter, die das Werkzeug bis dahin nicht prüfte: die REST-
# Benutzerliste, den offenen Anlage-Endpunkt und Application Passwords, die
# jede Passwortrotation überleben. Dazu kam ein vierter, den niemand auf dem
# Zettel hat: sechs Administrator-Konten mit Adressen auf zwei frei
# registrierbaren Tippfehler-Domains.
#
# Geprüft wird in beide Richtungen — der offene Zustand muss melden, der
# gehärtete darf nicht. Eine Härtungsprüfung, die immer warnt, wird ignoriert
# und ist damit wertlos.
#
# Läuft ohne Datenbank, ohne WordPress und ohne Netz: Rahmen und Datenbank
# sind Attrappen, die Instanz ist ein Wegwerf-Verzeichnis.
# ============================================================
set -uo pipefail
REZEPT="${1:-$(cd "$(dirname "$0")/.." && pwd)/rezepte/wordpress/rezept.sh}"
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
fail=0

MELDUNGEN=""
befund_melden() { MELDUNGEN+="$2|$3|$4"$'\n'; }   # <kat>|<schwere>|<text>
evidence() { :; }
code() { :; }
werkzeug_da() { return 1; }        # kein dig -> Domain-Prüfung bleibt unklar
REZ_PFX="wp_"; REZ_KURZ="test.example"; WANT_ONLINE=0
eval "$(sed -n '/^datei_meta()/,/^}$/p' "$(dirname "$REZEPT")/../../lib/kern.sh" 2>/dev/null)" 2>/dev/null || \
  datei_meta() { case "$2" in rechte) stat -c %a "$1" 2>/dev/null || stat -f '%OLp' "$1";; esac; }

for f in _wp_haertung_app_passwords _wp_haertung_admin_domains _wp_haertung_rest_enum _wp_haertung_wpconfig; do
  eval "$(sed -n "/^${f}()/,/^}\$/p" "$REZEPT")"
done

erwarte() {   # <muster> <soll-schwere> <beschreibung>
  local s; s=$(printf '%s\n' "$MELDUNGEN" | awk -F'|' -v m="$1" '$3 ~ m {print $2; exit}')
  if [[ "$s" == "$2" ]]; then printf '  OK     %-48s -> %s\n' "$3" "$s"
  else printf '  FEHLER %-48s -> %s (erwartet %s)\n' "$3" "${s:-nichts}" "$2"; fail=1; fi
}

echo "=== Application Passwords"
REZ_PFAD="$TMP/i1"; mkdir -p "$REZ_PFAD"
_db_sql() { [[ "$1" == wp_app_passwords ]] && printf 'admin\t8\nredakteur\t4\n'; }
MELDUNGEN=""; _wp_haertung_app_passwords
erwarte "Application Password" warn "vorhandene Anwendungspasswörter melden"
_db_sql() { :; }
MELDUNGEN=""; _wp_haertung_app_passwords
erwarte "keine Application Passwords" ok "keine vergeben -> kein Befund"

echo "=== Adressdomains der Administratoren"
_db_sql() { [[ "$1" == wp_admin_mail_domains ]] && printf 'beispiel.example\n'; }
MELDUNGEN=""; _wp_haertung_admin_domains
erwarte "nicht geprüft" unklar "ohne --online/dig ehrlich unklar"

echo "=== REST-Benutzerliste"
_db_sql() { [[ "$1" == wp_home ]] && printf 'https://beispiel.example\n'; }
MELDUNGEN=""; WANT_ONLINE=0; _wp_haertung_rest_enum
erwarte "nicht geprüft" unklar "ohne --online ehrlich unklar"

echo "=== wp-config.php"
REZ_PFAD="$TMP/i2"; mkdir -p "$REZ_PFAD"
printf '<?php\n$table_prefix = "wp_";\n' > "$REZ_PFAD/wp-config.php"; chmod 644 "$REZ_PFAD/wp-config.php"
MELDUNGEN=""; _wp_haertung_wpconfig
erwarte "Härtungspunkt" warn "Editor offen + weltlesbar -> warn"
printf '<?php\ndefine( '"'"'DISALLOW_FILE_EDIT'"'"', true );\n' > "$REZ_PFAD/wp-config.php"; chmod 640 "$REZ_PFAD/wp-config.php"
MELDUNGEN=""; _wp_haertung_wpconfig
erwarte "gehärtet" ok "Editor gesperrt + Rechte eng -> ok"
printf '<?php\ndefine( '"'"'DISALLOW_FILE_EDIT'"'"', true );\ndefine( '"'"'WP_DEBUG'"'"', true );\n' > "$REZ_PFAD/wp-config.php"; chmod 640 "$REZ_PFAD/wp-config.php"
MELDUNGEN=""; _wp_haertung_wpconfig
erwarte "Härtungspunkt" warn "WP_DEBUG an -> warn"

[[ $fail -eq 0 ]] && echo "=> ALLE BESTANDEN" || echo "=> FEHLGESCHLAGEN"
exit $fail
