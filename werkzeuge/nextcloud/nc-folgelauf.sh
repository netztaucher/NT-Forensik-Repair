#!/usr/bin/env bash
# =============================================================================
# nc-folgelauf.sh — nach dem Update: Inventur der Geheimnisse, DB-Passwort rotieren, Geräte abmelden
# =============================================================================
# Test:     ja - werkzeuge/nextcloud/nextcloud_selbsttest.sh (Attrappen, CI) und werkzeuge/nextcloud/probelauf/probelauf.sh (echte Nextcloud 27.1.11/28.0.14 im Wegwerf-Container) · NT-Forensik-Repair#165
# Rueckweg: ja - db: Prüfstand 24.11.2026, Rückweg bei scheiternder Prüfung gelaufen (alter Wert in MariaDB und config.php wieder aktiv); abmelden: nicht umkehrbar (gewollt, Nutzer melden sich neu an) · NT-Forensik-Repair#165
#
#   nc-folgelauf.sh <inventur|db|abmelden> --domain <domain> --abo <systembenutzer> [--ip <ip>] [--ausfuehren]
#
#   inventur  liest nur: Geheimnis-Schlüssel in config.php (Namen), DB-Zugang (ohne Wert),
#             Zahl der Konten, Admins, Geräte-Tokens, Mail-App-Konten, LDAP, externe Speicher, SMTP.
#   db        Lex Clavis für das Nextcloud-DB-Passwort: Neu -> Setzen (ALTER USER über Pipe an
#             `plesk db`) -> config.php -> Prüfen (status.php, Login 200) -> Kill-Proof (alter Wert
#             ERROR 1045). Jeder Fehler: Rückweg (config.php aus Sicherung, alter Wert in MariaDB).
#             Trockenlauf: Wächter auf config.php, Inventur, alter Wert meldet sich an.
#   abmelden  alle Geräte, App-Passwörter und Sitzungen aller Konten löschen
#             (occ user:auth-tokens:delete, gibt es erst ab NC 28).
#
# Werte nur in Variablen und MYSQL_PWD (mysql --no-defaults); Ausgabe nur sha256-12.
# Die Sicherung <quarantaene>/config.php.vor-rotation hält danach alte Werte: nach Abschluss
# mit `nc-abschluss.sh quarantaene` löschen.
# =============================================================================
set -u
HIER="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=werkzeuge/nextcloud/lib.sh
. "$HIER/lib.sh"
NC_KUERZEL=folgelauf

nc_args "$@"
TEIL=${NC_REST[0]:-}; [ ${#NC_REST[@]} -le 1 ] || nc_abbruch "zu viele Argumente: ${NC_REST[*]}"
case "$TEIL" in inventur|db|abmelden) ;; *) nc_abbruch "Teil fehlt: inventur|db|abmelden";; esac
nc_init
pgrep -f 'updater\.phar|nc-stufenupdate\.sh' >/dev/null 2>&1 && nc_abbruch "Update läuft noch" 9
[ "$NC_LOS" = 1 ] || echo "TROCKENLAUF (mit --ausfuehren wird geändert)"
DBNAME=$(nc_cfg dbname); PFX=$(nc_cfg dbtableprefix)
q(){ plesk db -Ne "$1" 2>/dev/null; }
qi(){ q "$1" || echo 'keine Tabelle'; }   # nur Inventur: fehlende Tabelle sichtbar machen

inventur(){
  nc_h "Inventur (nur Namen, keine Werte)"
  echo "Geheimnis-Schlüssel in config.php: $(grep -oE "^[[:space:]]*'[a-z_]*(pass|secret|salt|key|token)[a-z_]*'" "$NC_C" | tr -d " '" | sort -u | tr '\n' ' ')"
  echo "dbtype=$(nc_cfg dbtype) dbhost=$(nc_cfg dbhost) dbname=$DBNAME dbuser=$(nc_cfg dbuser) prefix=$PFX"
  echo "Nutzerkonten: $(qi "SELECT COUNT(*) FROM \`$DBNAME\`.\`${PFX}users\`") · Admins: $(qi "SELECT COUNT(*) FROM \`$DBNAME\`.\`${PFX}group_user\` WHERE gid='admin'")"
  echo "Geräte-Tokens/App-Passwörter: $(qi "SELECT COUNT(*) FROM \`$DBNAME\`.\`${PFX}authtoken\`")"
  echo "Mail-App-Konten (Passwort mit 'secret' verschlüsselt): $(qi "SELECT COUNT(*) FROM \`$DBNAME\`.\`${PFX}mail_accounts\`")"
  echo "LDAP mit Bind-Passwort: $(qi "SELECT COUNT(*) FROM \`$DBNAME\`.\`${PFX}appconfig\` WHERE appid='user_ldap' AND configkey LIKE '%ldap_agent_password' AND configvalue<>''")"
  echo "Externe Speicher: $(qi "SELECT COUNT(*) FROM \`$DBNAME\`.\`${PFX}external_mounts\`")"
  echo "SMTP: mode=$(nc_cfg mail_smtpmode) host=$(nc_cfg mail_smtphost) port=$(nc_cfg mail_smtpport) auth=$(nc_cfg mail_smtpauth) konto=$(nc_cfg mail_smtpname) — Passwort liegt lesbar in config.php: $([ -n "$(nc_cfg mail_smtppassword)" ] && echo ja || echo nein)"
}

case "$TEIL" in
inventur) inventur ;;

db)
  nc_h "Wächter: config.php darf nur das \$CONFIG-Array enthalten"
  if grep -qE 'eval|base64_decode|system\(|exec\(|passthru|shell_exec|\$_(GET|POST|REQUEST|COOKIE|SERVER)|include|require|file_get_contents|curl_' "$NC_C"; then
    grep -nE 'eval|base64_decode|system\(|exec\(|passthru|shell_exec|\$_|include|require|file_get|curl_' "$NC_C" | cut -c1-120
    nc_abbruch "verdächtiger Code in config.php — von Hand prüfen" 2
  fi
  inventur
  DBTYPE=$(nc_cfg dbtype); DBHOST=$(nc_cfg dbhost); DBUSER=$(nc_cfg dbuser); OLD=$(nc_cfg dbpassword)
  [ "$DBTYPE" = mysql ] && [ -n "$OLD" ] && [ -n "$DBUSER" ] || nc_abbruch "Inventur unvollständig (nur MySQL/MariaDB), keine Rotation" 3
  printf '%s' "$DBUSER" | grep -Eq '^[A-Za-z0-9_.-]+$' || nc_abbruch "DB-Benutzer ungültig" 3
  dbtest(){ MYSQL_PWD="$1" mysql --no-defaults -h "${DBHOST%%:*}" -u "$DBUSER" "$DBNAME" -Nse 'SELECT 1' 2>/dev/null; }
  [ "$(dbtest "$OLD")" = 1 ] || nc_abbruch "alter Wert meldet sich schon jetzt nicht an" 5
  echo "alter Wert meldet sich an (fp $(nc_fp "$OLD"))"
  [ "$NC_LOS" = 1 ] || exit 0

  nc_h "Neu"
  install -d -m 700 "$NC_Q"
  S=$NC_Q/config.php.vor-rotation; cp -a "$NC_C" "$S"; chmod 600 "$S"
  NEW=$(nc_neuwert); [ ${#NEW} -eq 32 ] || nc_abbruch "Erzeugung" 4
  echo "neu fp $(nc_fp "$NEW") (alt fp $(nc_fp "$OLD"))"
  # Wert nur in der Pipe; printf ist ein Builtin
  sqlpw(){ local v="${1//\'/\'\'}" hh
    for hh in $(q "SELECT host FROM mysql.user WHERE user='$DBUSER'"); do
      printf "ALTER USER '%s'@'%s' IDENTIFIED BY '%s';\n" "$DBUSER" "$hh" "$v" | plesk db
    done; }
  rueckweg(){ echo "RUECKWEG: $*"; cp -a "$S" "$NC_C"; sqlpw "$OLD"
    echo "alter Wert wieder aktiv: $([ "$(dbtest "$OLD")" = 1 ] && echo ja || echo 'NEIN — sofort von Hand')"
    nc_log "DB-Passwort-Rotation FEHLGESCHLAGEN ($*), Rückweg ausgeführt"; exit 6; }

  nc_h "Setzen"
  sqlpw "$NEW"
  [ "$(dbtest "$NEW")" = 1 ] || rueckweg "neuer Wert an MariaDB nicht aktiv"
  [ "$(dbtest "")" = 1 ] && rueckweg "leeres Passwort wird angenommen"
  NEW="$NEW" python3 - "$NC_C" <<'PY' || rueckweg "config.php nicht geschrieben"
import os, re, sys
p = sys.argv[1]; s = open(p, encoding="utf-8").read()
n, k = re.subn(r"('dbpassword'\s*=>\s*')[^']*(')", lambda m: m.group(1) + os.environ["NEW"] + m.group(2), s, count=1)
if k != 1: sys.exit(1)
open(p, "w", encoding="utf-8").write(n)
PY
  chown --reference="$S" "$NC_C" 2>/dev/null; chmod --reference="$S" "$NC_C" 2>/dev/null
  [ "$(nc_fp "$(nc_cfg dbpassword)")" = "$(nc_fp "$NEW")" ] || rueckweg "config.php enthält nicht den neuen Wert"

  nc_h "Prüfen"
  sleep "${NC_PAUSE:-2}"
  nc_web_ok || rueckweg "Nextcloud antwortet nicht korrekt"

  nc_h "Kill-Proof"
  KP=$(MYSQL_PWD="$OLD" mysql --no-defaults -h "${DBHOST%%:*}" -u "$DBUSER" "$DBNAME" -Nse 'SELECT 1' 2>&1 | grep -oE 'ERROR [0-9]+ \([0-9A-Z]+\)' | head -1)
  echo "alter Wert: ${KP:-ANGENOMMEN}"
  case "$KP" in "ERROR 1045"*) echo "Kill-Proof bestanden (Access denied)";; *) rueckweg "alter Wert wird nicht abgelehnt";; esac
  unset OLD NEW
  nc_log "Nextcloud-DB-Passwort ($DBUSER) rotiert: MariaDB + config.php, status.php und Login 200, alter Wert abgelehnt (ERROR 1045). Plesk-Datensatz nicht synchron. Sicherung $S (enthält alte Werte, nach Abschluss löschen)"
  ;;

abmelden)
  nc_h "alle Geräte, App-Passwörter und Sitzungen abmelden"
  echo "Tokens vorher: $(q "SELECT COUNT(*) FROM \`$DBNAME\`.\`${PFX}authtoken\`")"
  nc_occ list user 2>/dev/null | grep -q 'user:auth-tokens:delete' || nc_abbruch "occ user:auth-tokens:delete fehlt (erst ab NC 28) — erst aktualisieren" 3
  KONTEN=$(nc_occ user:list --output=json 2>/dev/null | python3 -c 'import json,sys; [print(u) for u in json.load(sys.stdin)]')
  echo "Konten: $(printf '%s\n' "$KONTEN" | grep -c .)"
  [ "$NC_LOS" = 1 ] || exit 0
  JETZT=$(date +%s); N=0
  while IFS= read -r u; do
    [ -n "$u" ] || continue
    nc_occ user:auth-tokens:delete "$u" --last-used-before="$JETZT" >/dev/null 2>&1 && N=$((N+1))
  done <<< "$KONTEN"
  echo "Konten bearbeitet: $N · Tokens nachher: $(q "SELECT COUNT(*) FROM \`$DBNAME\`.\`${PFX}authtoken\`")"
  nc_log "Geräte/App-Passwörter/Sitzungen von $N Konten abgemeldet (occ user:auth-tokens:delete --last-used-before=$JETZT)"
  ;;
esac
