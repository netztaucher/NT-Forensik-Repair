#!/usr/bin/env bash
# =============================================================================
# probelauf.sh — die Nextcloud-Werkzeuge gegen eine ECHTE Nextcloud im Wegwerf-Container prüfen (#165)
# =============================================================================
# Test:     ja - Lauf 24.11.2026 auf dem Arbeitsplatz (Docker, arm64), alle Fälle grün, Protokoll in NT-Forensik-Repair#165
# Rueckweg: ja - Container und Abbild werden am Ende entfernt (docker rm -f, docker rmi), im Lauf 24.11.2026 gelaufen · NT-Forensik-Repair#165
#
#   bash werkzeuge/nextcloud/probelauf/probelauf.sh [<protokoll-ordner>] [--behalten]
#
# Baut ein Abbild (Debian, PHP 8.2, MariaDB, Apache, Nextcloud 27.1.11 in Plesk-Anordnung),
# installiert Nextcloud ohne Wert-Argument (autoconfig.php), kopiert werkzeuge/nextcloud hinein
# und führt szenarien.sh aus: Stufenupdate (zwei Rückwege, eine echte Stufe 27 -> 28),
# DB-Rotation (Rückweg + Kill-Proof 1045), Abmelden, cron, appupdate (Rückweg + Erfolg),
# Rotation ohne Plesk (liste, nutzer, smtpcfg mit Rückweg), Quarantäne.
# Danach liegt das Protokoll im Protokoll-Ordner (Vorgabe ./nc-probelauf-<datum>), Container
# und Abbild sind entfernt (mit --behalten bleiben sie stehen).
#
# Braucht Docker und Netz (Nextcloud-Paket, Updater-Server, App-Store). Nie gegen einen Kundenserver:
# alles läuft im Container. Was Plesk selbst braucht (Abo, Postfach, Plesk-Admin), bildet
# plesk-attrappe NICHT nach; diese Wege bleiben hier ungeprüft.
# =============================================================================
set -u
HIER="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ZIEL=""; BEHALTEN=0
for a in "$@"; do case "$a" in --behalten) BEHALTEN=1;; -h|--help) sed -n '2,/^set /{/^#/p;}' "$0" | sed -E 's/^# ?//'; exit 0;; *) ZIEL=$a;; esac; done
ZIEL=${ZIEL:-./nc-probelauf-$(date +%Y%m%d-%H%M)}
NAME=nc-probelauf-$$; BILD=nt-nc-probelauf:$$
weg(){ [ "$BEHALTEN" = 1 ] && { echo "Container $NAME bleibt (--behalten)"; return; }
  docker rm -f "$NAME" >/dev/null 2>&1; docker rmi "$BILD" >/dev/null 2>&1
  docker ps -a --format '{{.Names}}' | grep -qx "$NAME" && echo "WARNUNG: Container $NAME nicht entfernt" || echo "Container und Abbild entfernt"; }
trap weg EXIT
command -v docker >/dev/null || { echo "ABBRUCH: docker fehlt"; exit 2; }

echo "== Abbild bauen"; docker build -q -t "$BILD" "$HIER" >/dev/null || { echo "ABBRUCH: Abbild"; exit 2; }
echo "== Container starten"; docker run -d --name "$NAME" "$BILD" >/dev/null || exit 2
for _ in $(seq 1 60); do docker exec "$NAME" test -s /etc/psa/.psa.shadow 2>/dev/null && docker exec "$NAME" pgrep -x apache2 >/dev/null && break; sleep 2; done

echo "== Nextcloud installieren (autoconfig, Werte nur in Dateien)"
docker exec -i "$NAME" bash <<'EOF' || { echo "ABBRUCH: Installation"; exit 3; }
set -u; export W=/var/www/vhosts/$DOMAIN/httpdocs
echo "127.0.0.1 $DOMAIN" >> /etc/hosts
umask 077; openssl rand -base64 48 | tr -dc 'A-Za-z0-9' | cut -c1-32 > /root/nc-admin.pass
php8.2 -r '$c=["dbtype"=>"mysql","dbname"=>"nc_probe","dbuser"=>"admin","dbpass"=>trim(file_get_contents("/etc/psa/.psa.shadow")),
 "dbhost"=>"localhost","dbtableprefix"=>"oc_","adminlogin"=>"probeadmin","adminpass"=>trim(file_get_contents("/root/nc-admin.pass")),
 "directory"=>getenv("W")."/data"]; file_put_contents(getenv("W")."/config/autoconfig.php","<?php\n\$AUTOCONFIG = ".var_export($c,true).";\n");'
chown "$ABO:$ABO" "$W/config/autoconfig.php"
curl -sk -o /dev/null --max-time 600 "https://$DOMAIN/index.php"
curl -sk "https://$DOMAIN/status.php" | grep -q '"installed":true'
EOF

echo "== Werkzeuge kopieren und Szenarien ausführen"
docker exec "$NAME" mkdir -p /root/werkzeuge
docker cp "$HIER/../." "$NAME:/root/werkzeuge/" >/dev/null
docker exec "$NAME" bash /root/werkzeuge/probelauf/szenarien.sh; RC=$?
mkdir -p "$ZIEL"; docker cp "$NAME:/root/protokoll/." "$ZIEL/" >/dev/null
echo "== Protokoll: $ZIEL · Ergebnis: $([ "$RC" = 0 ] && echo grün || echo "ROT ($RC)")"
exit "$RC"
