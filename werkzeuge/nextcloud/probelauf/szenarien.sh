#!/bin/bash
# =============================================================================
# szenarien.sh — läuft IM Prüfstand-Container: Erfolg und Rückweg der Nextcloud-Werkzeuge
# gegen eine echte Nextcloud (#165). Gestartet von probelauf.sh, nie auf einem Kundenserver.
# =============================================================================
# Test:     ja - ist selbst der Test; Lauf 24.11.2026 im Protokoll · NT-Forensik-Repair#165
# Rueckweg: entfällt - ändert nur den Wegwerf-Container
#
# Erwartung je Fall als Rückgabewert; jede Abweichung zählt als Fehler. Am Ende: kein
# Geheimnis des Prüfstands steht in einem Protokoll oder im changelog.
# =============================================================================
set -u
cd /root/werkzeuge || exit 2
W=/var/www/vhosts/$DOMAIN/httpdocs; C=$W/config/config.php; P=/root/protokoll; mkdir -p "$P"
A=(--domain "$DOMAIN" --abo "$ABO" --ip 127.0.0.1)
U=("${A[@]}" --php-wechsel 99:8.2 --max-stufen 1)   # nur PHP 8.2 im Prüfstand
FEHLER=0
occ(){ runuser -u "$ABO" -- php8.2 "$W/occ" "$@"; }
gen(){ openssl rand -base64 48 | tr -dc 'A-Za-z0-9' | cut -c1-32; }
fp(){ printf '%s' "$1" | sha256sum | cut -c1-12; }
cfg(){ sed -nE "s/^[[:space:]]*'$1' => '([^']*)'.*/\1/p" "$C"; }
ver(){ sed -nE "s/.*OC_VersionString = '([^']+)'.*/\1/p" "$W/version.php"; }
# fall <nr-name> <soll-rc> <befehl...>  (stdin wird durchgereicht)
fall(){ local n=$1 soll=$2 rc; shift 2
  "$@" > "$P/$n.txt" 2>&1; rc=$?
  if [ "$rc" = "$soll" ]; then echo "ok     $n (rc $rc)"; else echo "FEHLER $n: rc $rc, erwartet $soll"; FEHLER=1; tail -15 "$P/$n.txt"; fi; }
soll(){ if eval "$1"; then echo "ok     $2"; else echo "FEHLER $2"; FEHLER=1; fi; }
GEHEIM=()   # alle Werte, die nirgends stehen dürfen

GEHEIM+=("$(cat /etc/psa/.psa.shadow)" "$(cat /root/nc-admin.pass)" "$(cfg dbpassword)")
echo "Nextcloud $(ver), PHP $(php8.2 -r 'echo PHP_VERSION;')"

# ── Stufenupdate ────────────────────────────────────────────────────────────
mkdir -p "$W/probe-fremd" && echo x > "$W/probe-fremd/x" && chown -R "$ABO:" "$W/probe-fremd"
fall 01-update-trocken 0 bash nc-stufenupdate.sh "${U[@]}"
fall 02-update-rueckweg-vor-code 4 bash nc-stufenupdate.sh "${U[@]}" --ausfuehren
soll '[ "$(ver)" = 27.1.11 ] && [ -d "$W/probe-fremd" ]' "Rückweg 1: Version 27.1.11, httpdocs aus Sicherung"
fall 03-update-stufe 0 bash nc-stufenupdate.sh "${U[@]}" --fremd probe-fremd --ausfuehren
soll '[ "$(ver | cut -d. -f1)" = 28 ]' "Stufe: Hauptversion 28"
for h in $(plesk db -Ne "SELECT host FROM mysql.user WHERE user='$(cfg dbuser)'"); do
  echo "REVOKE ALTER, CREATE, DROP, INDEX ON \`$(cfg dbname)\`.* FROM '$(cfg dbuser)'@'$h';" | plesk db >/dev/null 2>&1
done
VOR=$(ver)
fall 04-update-rueckweg-nach-code 4 bash nc-stufenupdate.sh "${U[@]}" --ausfuehren
soll 'grep -q "ALTER command denied" "$P/04-update-rueckweg-nach-code.txt" && [ "$(ver)" = "$VOR" ]' "Rückweg 2: Code getauscht, Migration verweigert, zurück auf $VOR"
for h in $(plesk db -Ne "SELECT host FROM mysql.user WHERE user='$(cfg dbuser)'"); do
  echo "GRANT ALL PRIVILEGES ON \`$(cfg dbname)\`.* TO '$(cfg dbuser)'@'$h';" | plesk db >/dev/null 2>&1
done

# ── Folgelauf ───────────────────────────────────────────────────────────────
ALTFP=$(fp "$(cfg dbpassword)")
occ maintenance:mode --on >/dev/null
fall 05-db-rueckweg 6 bash nc-folgelauf.sh db "${A[@]}" --ausfuehren
occ maintenance:mode --off >/dev/null
soll '[ "$(fp "$(cfg dbpassword)")" = "$ALTFP" ] && grep -q "alter Wert wieder aktiv: ja" "$P/05-db-rueckweg.txt"' "DB-Rückweg: alter Wert in config.php und MariaDB aktiv"
fall 06-db-rotation 0 bash nc-folgelauf.sh db "${A[@]}" --ausfuehren
soll 'grep -q "Kill-Proof bestanden" "$P/06-db-rotation.txt" && [ "$(fp "$(cfg dbpassword)")" != "$ALTFP" ]' "DB-Rotation: neuer Wert, alter ERROR 1045"
GEHEIM+=("$(cfg dbpassword)")
fall 07-inventur 0 bash nc-folgelauf.sh inventur "${A[@]}"
fall 08-abmelden 0 bash nc-folgelauf.sh abmelden "${A[@]}" --ausfuehren

# ── Abschluss ───────────────────────────────────────────────────────────────
curl -fsSL -o /tmp/notes.tgz https://github.com/nextcloud-releases/notes/releases/download/v4.9.3/notes.tar.gz \
  && tar -C "$W/apps" -xzf /tmp/notes.tgz && chown -R "$ABO:" "$W/apps/notes" && occ app:enable notes >/dev/null
fall 09-cron 0 bash nc-abschluss.sh cron "${A[@]}" --ausfuehren
soll '[ "$(occ config:app:get core backgroundjobs_mode)" = cron ] && [ -f /etc/cron.d/nextcloud-$ABO ]' "cron: Datei da, Modus cron"
rm /etc/cron.d/nextcloud-"$ABO"; soll '[ ! -e /etc/cron.d/nextcloud-$ABO ]' "cron-Rückweg: rm entfernt den Job"
bash nc-abschluss.sh cron "${A[@]}" --ausfuehren >/dev/null 2>&1
chown -R root:root "$W/apps/notes"; chmod -R go-w "$W/apps/notes"    # Abo darf den App-Ordner nicht schreiben -> app:update ohne Wirkung
fall 10-appupdate-rueckweg 4 bash nc-abschluss.sh appupdate "${A[@]}" --ausfuehren
soll 'grep -q "<version>4.9.3" "$W/apps/notes/appinfo/info.xml"' "appupdate-Rückweg: notes wieder 4.9.3"
chown -R "$ABO:" "$W/apps/notes"
fall 11-appupdate 0 bash nc-abschluss.sh appupdate "${A[@]}" --ausfuehren
soll '! grep -q "<version>4.9.3" "$W/apps/notes/appinfo/info.xml"' "appupdate: notes aktualisiert"

# ── Rotation ohne Plesk: liste, nutzer (WebDAV), smtpcfg (mit Rückweg) ───────
ALT=$(gen); GEHEIM+=("$ALT")
( cd "$W" && ALT="$ALT" runuser -u "$ABO" --whitelist-environment=ALT -- php8.2 -r 'require "lib/base.php"; \OC::$server->getConfig()->setSystemValue("mail_smtppassword", getenv("ALT"));' )
PW=$(gen); GEHEIM+=("$PW"); OC_PASS="$PW" runuser -u "$ABO" --whitelist-environment=OC_PASS -- php8.2 "$W/occ" user:add --password-from-env probenutzer >/dev/null
fall 12-liste 0 bash nc-rotation-server.sh liste "${A[@]}" --ausfuehren
occ maintenance:mode --on >/dev/null
N=$(gen); GEHEIM+=("$N")
fall 13-smtpcfg-rueckweg 4 bash nc-rotation-server.sh smtpcfg "${A[@]}" --ausfuehren <<< "$N"
occ maintenance:mode --off >/dev/null
soll '[ "$(fp "$(cfg mail_smtppassword)")" = "$(fp "$ALT")" ]' "smtpcfg-Rückweg: config.php wieder alt"
N=$(gen); GEHEIM+=("$N")
fall 14-smtpcfg 0 bash nc-rotation-server.sh smtpcfg "${A[@]}" --ausfuehren <<< "$N"
soll '[ "$(fp "$(cfg mail_smtppassword)")" = "$(fp "$N")" ]' "smtpcfg: neuer Wert"
N=$(gen); GEHEIM+=("$N")
fall 15-nutzer 0 bash nc-rotation-server.sh nutzer "${A[@]}" --ausfuehren < <(printf 'probenutzer\t%s\n' "$N")
c=$(printf 'user = "probenutzer:%s"\n' "$PW" | curl -sk -K - -o /dev/null -w '%{http_code}' --resolve "$DOMAIN:443:127.0.0.1" -X PROPFIND -H 'Depth: 0' "https://$DOMAIN/remote.php/dav/files/probenutzer/")
echo "alter Wert probenutzer: WebDAV HTTP $c" >> "$P/15-nutzer.txt"
soll '[ "$c" = 401 ] && grep -q "HTTP 207" "$P/15-nutzer.txt"' "nutzer: neuer Wert 207, alter 401 (Kill-Proof)"
for m in abo pleskadmin; do
  fall "16-$m-ohne-plesk" 3 bash nc-rotation-server.sh "$m" "${A[@]}" --ausfuehren <<< "$(gen)"
done

# ── Quarantäne zuletzt (alte Werte der Rotation) ────────────────────────────
fall 17-quarantaene 0 bash nc-abschluss.sh quarantaene "${A[@]}" --ausfuehren
soll '! ls /root/quarantaene/nc-$DOMAIN/ | grep -q "^config.php.vor-"' "quarantaene: Geheimnis-Kopien gelöscht"

cp /root/changelog.md "$P/changelog.md"
LECK=0
for v in "${GEHEIM[@]}"; do
  [ -n "$v" ] || continue
  if grep -rqF -- "$v" "$P"; then echo "FEHLER Geheimnis fp $(fp "$v") steht im Protokoll"; LECK=1; FEHLER=1; fi
done
[ "$LECK" = 0 ] && echo "ok     kein Geheimnis (${#GEHEIM[@]} Werte) in Protokoll oder changelog"
echo "Ende: Nextcloud $(ver), Fehler: $FEHLER"
exit "$FEHLER"
