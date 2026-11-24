#!/usr/bin/env bash
# =============================================================================
# nc-rotation-server.sh — Server-Teil der Rotation (Plesk + Nextcloud); neue Werte NUR über stdin
# =============================================================================
# Test:     ja - werkzeuge/nextcloud/nextcloud_selbsttest.sh (Attrappen, CI); liste, nutzer, smtpcfg zusätzlich gegen echte Nextcloud im werkzeuge/nextcloud/probelauf/probelauf.sh (echte Nextcloud 27.1.11/28.0.14 im Wegwerf-Container) · NT-Forensik-Repair#165
# Rueckweg: nein - smtpcfg: Rückweg (config.php aus Sicherung) im Prüfstand 24.11.2026 gelaufen; postfach (alten Wert zurücksetzen), abo, pleskadmin, mailapp brauchen Plesk, IMAP bzw. Mail-App und sind nur mit Attrappen geprüft; nutzer/abo/pleskadmin: alter Wert unbekannt, Rückweg = erneut setzen · NT-Forensik-Repair#167
#
# Wird von nc-rotation-mac.sh per ssh aufgerufen. Ein Wert kommt nie als Argument.
#
#   nc-rotation-server.sh <modus> --domain <domain> --abo <systembenutzer> [--ip <ip>] [--ausfuehren]
#   nc-rotation-server.sh postfach --postfach <adresse> [--imap-host 127.0.0.1] [--ausfuehren]
#
#   liste       liest: Nextcloud-Konten mit Rolle (uid<TAB>admin|nutzer)
#   abo         stdin NEU            Systembenutzer des Abos (PSA_PASSWORD). Kill-Proof: neuer Wert
#                                    passt zum shadow-Hash, alter Hash ersetzt.
#   smtpalt     liest: gibt den aktuellen mail_smtppassword auf stdout aus — NUR in eine Pipe
#   smtpcfg     stdin NEU            mail_smtppassword in config.php (Sicherung, Prüfung, Rückweg)
#   nutzer      stdin uid<TAB>NEU je Zeile   Nextcloud-Konten (OC_PASS + --password-from-env).
#                                    Prüfung: Hash ersetzt + WebDAV PROPFIND 207 mit neuem Wert.
#   pleskadmin  stdin NEU            Plesk-Administrator. Prüfung: API 200 mit neuem Wert. Den alten
#                                    Wert kennt niemand: "nicht feststellbar", nie "bestanden".
#   mailapp     stdin NEU            Postfach-Wert im Konto der Mail-App (--postfach <adresse>),
#                                    verschlüsselt über OCP\Server::get(ICrypto) (NC 35), zurückgelesen.
#   postfach    stdin NEU, ALT       läuft auf dem MAILSERVER: alter Wert meldet sich per IMAP an ->
#                                    setzen -> neuer Wert ok -> alter abgelehnt (Kill-Proof). Scheitert
#                                    der neue Wert, wird der alte zurückgesetzt.
#
# Ohne --ausfuehren: Trockenlauf, liest nichts von stdin, ändert nichts.
# Ausgaben auf stderr, Belege nur als sha256-12, jede Massnahme in /root/changelog.md.
# =============================================================================
set -u
HIER="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=werkzeuge/nextcloud/lib.sh
. "$HIER/lib.sh"
NC_KUERZEL=rotation

nc_args "$@"
MODUS=${NC_REST[0]:-}; POSTFACH=""; IMAP=127.0.0.1
set -- ${NC_REST[@]+"${NC_REST[@]:1}"}
while [ $# -gt 0 ]; do
  [ $# -ge 2 ] || nc_abbruch "Wert fehlt für $1"
  case "$1" in --postfach) POSTFACH=$2;; --imap-host) IMAP=$2;; *) nc_abbruch "unbekannter Schalter: $1";; esac; shift 2
done
[ -z "$POSTFACH" ] || printf '%s' "$POSTFACH" | grep -Eq '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+$' || nc_abbruch "Postfach ungültig"
trocken(){ [ "$NC_LOS" = 1 ] || { echo "TROCKENLAUF $MODUS: $*" >&2; exit 0; }; }
lies_neu(){ IFS= read -r NEU || true; [ ${#NEU} -ge 24 ] || nc_abbruch "kein neuer Wert auf stdin (mind. 24 Zeichen)" 2; }

# --- Postfach: läuft ohne Nextcloud, auf dem Mailserver -----------------------
if [ "$MODUS" = postfach ]; then
  [ -n "$POSTFACH" ] || nc_abbruch "--postfach fehlt"
  # IMAP-Anmeldung über curl, Zugang über stdin. rc 0 = ok, 67 = abgelehnt
  imap(){ local rc; nc_curl_user "$POSTFACH" "$1" | curl -s -k --max-time 20 -K - -o /dev/null "imaps://$IMAP/" ; rc=$?
    case $rc in 0) echo ok;; 67) echo abgelehnt;; *) echo "fehler rc $rc";; esac; }
  trocken "Postfach $POSTFACH wird über Plesk gesetzt, Kill-Proof per IMAP an $IMAP"
  lies_neu; IFS= read -r ALT || true
  a=$([ -n "$ALT" ] && imap "$ALT" || echo "kein alter Wert"); echo "alter Wert vorher: $a (fp $(nc_fp "$ALT"))" >&2
  PSA_PASSWORD="$NEU" plesk bin mail -u "$POSTFACH" -passwd "" >/dev/null || nc_abbruch "Plesk lehnt ab, nichts geändert" 3
  sleep "${NC_PAUSE:-2}"; n=$(imap "$NEU"); o=$([ -n "$ALT" ] && imap "$ALT" || echo "nicht prüfbar")
  echo "neuer Wert: $n · alter Wert nachher: $o" >&2
  if [ "$n" != ok ]; then
    [ -n "$ALT" ] && PSA_PASSWORD="$ALT" plesk bin mail -u "$POSTFACH" -passwd "" >/dev/null
    nc_log "Postfach $POSTFACH: neuer Wert scheiterte ($n), alter Wert zurück"; exit 4
  fi
  [ "$o" = abgelehnt ] && k="Kill-Proof bestanden" || k="Kill-Proof OFFEN ($o)"
  nc_log "Postfach $POSTFACH rotiert (fp $(nc_fp "$NEU")), IMAP neu ok, alter Wert vorher $a, nachher $o: $k"
  [ "$o" = abgelehnt ] || exit 5
  exit 0
fi

nc_init
pgrep -f 'updater\.phar|nc-stufenupdate\.sh|nc-folgelauf\.sh' >/dev/null 2>&1 && nc_abbruch "Update-/Folgelauf aktiv" 9
DB=$(nc_cfg dbname); P=$(nc_cfg dbtableprefix)

case "$MODUS" in
liste)
  ADM=$(nc_occ group:list --output=json 2>/dev/null | python3 -c 'import json,sys; [print(u) for u in json.load(sys.stdin).get("admin",[])]')
  nc_occ user:list --output=json 2>/dev/null | python3 -c 'import json,sys; [print(u) for u in json.load(sys.stdin)]' \
    | while IFS= read -r u; do printf '%s\n' "$ADM" | grep -qxF "$u" && printf '%s\tadmin\n' "$u" || printf '%s\tnutzer\n' "$u"; done ;;

abo)
  A=$(getent shadow "$NC_U" | cut -d: -f2); echo "alter Hash fp $(nc_fp "$A")" >&2
  trocken "Systembenutzer $NC_U über plesk bin subscription"
  lies_neu
  PSA_PASSWORD="$NEU" plesk bin subscription --update "$NC_D" -passwd "" >/dev/null || nc_abbruch "Plesk lehnt ab, nichts geändert" 3
  N=$(getent shadow "$NC_U" | cut -d: -f2); echo "neuer Hash fp $(nc_fp "$N")" >&2
  [ "$A" != "$N" ] || nc_abbruch "Hash unverändert" 5
  printf '%s' "$NEU" | nc_shadow_passt "$N"; r=$?
  case $r in
    0) abgl="neuer Wert passt zum Hash";;
    2) abgl="Abgleich nicht prüfbar (Hash-Verfahren), nur Ersetzung belegt";;
    *) nc_abbruch "neuer Wert passt nicht zum Hash" 4;;
  esac
  nc_log "Systembenutzer $NC_U rotiert (Plesk), $abgl, alter Hash ersetzt (fp $(nc_fp "$A") -> $(nc_fp "$N")) => alter Wert abgelehnt" ;;

smtpalt)
  trocken "würde den aktuellen SMTP-Wert in eine Pipe schreiben"
  [ -t 1 ] && nc_abbruch "smtpalt schreibt nur in eine Pipe, nicht ins Terminal" 2
  nc_cfg mail_smtppassword | tr -d '\n' ;;

smtpcfg)
  trocken "mail_smtppassword in $NC_C (mail_smtpauth=$(nc_cfg mail_smtpauth))"
  lies_neu
  install -d -m 700 "$NC_Q"; S="$NC_Q/config.php.vor-smtp-$(date +%s)"; cp -a "$NC_C" "$S"; chmod 600 "$S"
  NEU="$NEU" python3 - "$NC_C" <<'PY' || { cp -a "$S" "$NC_C"; nc_abbruch "config.php nicht geschrieben, zurück" 3; }
import os, re, sys
p = sys.argv[1]; s = open(p, encoding="utf-8").read(); v = os.environ["NEU"]
n, k = re.subn(r"('mail_smtppassword'\s*=>\s*')[^']*(')", lambda m: m.group(1) + v + m.group(2), s, count=1)
if k != 1: sys.exit(1)
open(p, "w", encoding="utf-8").write(n)
PY
  chown --reference="$S" "$NC_C" 2>/dev/null; chmod --reference="$S" "$NC_C" 2>/dev/null
  if [ "$(nc_fp "$(nc_cfg mail_smtppassword)")" != "$(nc_fp "$NEU")" ] || ! nc_web_ok >&2; then
    cp -a "$S" "$NC_C"; nc_abbruch "Prüfung gescheitert, config.php zurück" 4
  fi
  echo "mail_smtpauth=$(nc_cfg mail_smtpauth) (leer/0: Nextcloud meldet sich nicht an, Wert nur hinterlegt)" >&2
  nc_log "SMTP-Wert in config.php ersetzt (fp $(nc_fp "$NEU")), status.php ok, Sicherung $S (enthält alte Werte, nach Abschluss löschen)" ;;

nutzer)
  trocken "Nextcloud-Konten aus stdin (uid<TAB>Wert) über occ user:resetpassword --password-from-env"
  hash(){ local q=${1//\'/\'\'}; plesk db -Ne "SELECT password FROM \`$DB\`.\`${P}users\` WHERE uid='$q'"; }
  fehler=0
  while IFS=$'\t' read -r uid pw; do
    [ -n "$uid" ] && [ ${#pw} -ge 24 ] || continue
    A=$(hash "$uid")
    ( cd "$NC_W" && OC_PASS="$pw" runuser -u "$NC_U" --whitelist-environment=OC_PASS -- "$(nc_phpbin)" -d memory_limit="$NC_MEM" occ --no-interaction user:resetpassword --password-from-env "$uid" ) >/dev/null 2>&1 \
      || { echo "  $uid: FEHLER beim Setzen" >&2; fehler=1; continue; }
    N=$(hash "$uid")
    pfad=$(python3 -c 'import sys,urllib.parse; print(urllib.parse.quote(sys.argv[1]))' "$uid")
    c=$(nc_curl_user "$uid" "$pw" | curl -sk -K - -o /dev/null -w '%{http_code}' --max-time 20 ${NC_RESOLVE[@]+"${NC_RESOLVE[@]}"} -X PROPFIND -H 'Depth: 0' "https://$NC_D/remote.php/dav/files/$pfad/")
    [ "$A" != "$N" ] && h=ersetzt || h=UNVERAENDERT
    echo "  $uid: Hash $h, Anmeldung mit neuem Wert WebDAV HTTP $c" >&2
    nc_log "Nextcloud-Konto $uid rotiert, Hash $h (fp $(nc_fp "$A") -> $(nc_fp "$N")), WebDAV mit neuem Wert HTTP $c"
    [ "$h" = ersetzt ] && [ "$c" = 207 ] || fehler=1
  done
  exit $((fehler * 4)) ;;

pleskadmin)
  trocken "Plesk-Administrator über plesk bin admin --set-admin-password"
  lies_neu
  install -d -m 700 "$NC_Q"
  S="$NC_Q/psa.shadow.vor-admin-$(date +%s)"; cp -a "$NC_PSA_SHADOW" "$S"; chmod 600 "$S"
  # Der Hash liegt in psa.accounts ohne direkten Verweis: Fingerabdruck aller Zeilen vorher/nachher
  snap(){ plesk db -Ne "SELECT id, LEFT(SHA2(password,256),12) FROM accounts ORDER BY id" 2>/dev/null; }
  A=$(snap)
  PSA_PASSWORD="$NEU" plesk bin admin --set-admin-password -passwd "" >/dev/null || nc_abbruch "Plesk lehnt ab, nichts geändert" 3
  N=$(snap); geaendert=$(diff <(echo "$A") <(echo "$N") | grep '^>' | awk '{print $2}' | tr '\n' ' ')
  c=$(nc_curl_user admin "$NEU" | curl -sk -K - -o /dev/null -w '%{http_code}' --max-time 20 "https://127.0.0.1:8443/api/v2/server")
  plesk db -Ne 'SELECT 1' >/dev/null 2>&1 && dbok=ja || dbok=NEIN
  nc_mysql_admin -Ne 'SELECT 1' >/dev/null 2>&1 && myok=ja || myok=NEIN
  [ -n "$geaendert" ] && h="ersetzt (accounts.id $geaendert)" || h="nicht feststellbar"
  echo "Plesk-API mit neuem Wert HTTP $c · plesk db $dbok · MySQL-admin $myok · gespeicherter Hash $h" >&2
  [ "$c" = 200 ] || nc_abbruch "Anmeldung mit neuem Wert scheitert" 4
  nc_log "Plesk-Administrator rotiert, API mit neuem Wert 200, gespeicherter Hash $h, plesk db $dbok, MySQL-admin $myok; Ablehnung des alten Werts nicht feststellbar. Sicherung $S (nach Abschluss löschen)" ;;

mailapp)
  [ -n "$POSTFACH" ] || nc_abbruch "--postfach fehlt"
  trocken "Mail-App-Konto $POSTFACH (inbound/outbound) verschlüsselt neu setzen"
  lies_neu
  printf '%s' "$NEU" | ( cd "$NC_W" && NC_POSTFACH="$POSTFACH" runuser -u "$NC_U" --whitelist-environment=NC_POSTFACH -- "$(nc_phpbin)" -d memory_limit="$NC_MEM" -r '
    require "lib/base.php"; $v=stream_get_contents(STDIN); $m=getenv("NC_POSTFACH");
    $c=\OCP\Server::get(\OCP\Security\ICrypto::class); $db=\OCP\Server::get(\OCP\IDBConnection::class);
    $q=$db->getQueryBuilder(); $q->select("id","inbound_password")->from("mail_accounts")->where($q->expr()->eq("email",$q->createNamedParameter($m)));
    $r=$q->executeQuery()->fetchAll(); if(count($r)!==1){fwrite(STDERR,"Konto nicht eindeutig (".count($r).")\n");exit(3);}
    $alt=$c->decrypt($r[0]["inbound_password"]); fwrite(STDERR,"alter App-Wert fp ".substr(hash("sha256",$alt),0,12)."\n");
    $u=$db->getQueryBuilder(); $u->update("mail_accounts")->set("inbound_password",$u->createNamedParameter($c->encrypt($v)))->set("outbound_password",$u->createNamedParameter($c->encrypt($v)))->where($u->expr()->eq("id",$u->createNamedParameter((int)$r[0]["id"])))->executeStatement();
    $q2=$db->getQueryBuilder(); $q2->select("inbound_password","outbound_password")->from("mail_accounts")->where($q2->expr()->eq("id",$q2->createNamedParameter((int)$r[0]["id"])));
    $n=$q2->executeQuery()->fetch(); $ok=hash_equals($v,$c->decrypt($n["inbound_password"])) && hash_equals($v,$c->decrypt($n["outbound_password"]));
    fwrite(STDERR,"neuer App-Wert fp ".substr(hash("sha256",$v),0,12).", zurückgelesen ".($ok?"gleich":"UNGLEICH")."\n"); exit($ok?0:4);' ) \
    || nc_abbruch "Mail-App-Konto nicht gesetzt" 4
  nc_log "Mail-App-Konto $POSTFACH auf neuen Postfach-Wert gesetzt (fp $(nc_fp "$NEU")), verschlüsselt gespeichert und zurückgelesen" ;;

*) nc_abbruch "Modus fehlt: liste|abo|smtpalt|smtpcfg|nutzer|pleskadmin|mailapp|postfach" ;;
esac
