#!/usr/bin/env bash
# =============================================================================
# nc-stufenupdate.sh — Nextcloud stufenweise aktualisieren, je Stufe mit Sicherung und Rückweg
# =============================================================================
# Test:     ja - werkzeuge/nextcloud/nextcloud_selbsttest.sh (Attrappen, CI) und werkzeuge/nextcloud/probelauf/probelauf.sh (echte Nextcloud 27.1.11/28.0.14 im Wegwerf-Container) · NT-Forensik-Repair#165
# Rueckweg: ja - Prüfstand 24.11.2026: Rückweg vor dem Code-Tausch (Updater rc 255) und nach dem Code-Tausch (29.0.16, Migration verweigert) je gesund zurück auf die Stufe davor · NT-Forensik-Repair#165
#
#   nc-stufenupdate.sh --domain <domain> --abo <systembenutzer> [--ip <ip>]
#                      [--app-entfernen <app>]... [--fremd <eintrag>]...
#                      [--php-wechsel <major>:<x.y>]... [--max-stufen 12] [--ausfuehren]
#
# Ohne --ausfuehren: Trockenlauf. Zeigt Version, PHP, Platz, Gesundheit, Fremd-Apps,
# zu entfernende Apps, Fremdeinträge und liegengebliebene Updater-Zustände. Ändert nichts.
#
# Mit --ausfuehren, je Stufe (Lex Mutatio): Sicherung (DB-Dump + httpdocs-tar unter
# <arbeit>/update-sicherung) -> updater.phar --no-upgrade -> occ upgrade, app:update,
# add-missing-* -> Prüfung (status.php, Login 200, version.php gestiegen) -> bei Fehler
# Rückweg dieser Stufe (httpdocs aus tar, DB aus Dump).
#
#   --app-entfernen   App deaktivieren und ihr Verzeichnis in die Quarantäne verschieben,
#                     z. B. richdocumentscode (proxy.php wirkt auch bei deaktivierter App).
#   --fremd           Eintrag in httpdocs, der die Updater-Prüfung "expected files" sprengt;
#                     wird mit Beleg (Liste + sha256) in die Quarantäne verschoben. Vorgabe: cgi-bin.
#   --php-wechsel     beim Erreichen der Hauptversion auf diese PHP-Version umstellen
#                     (Handler der Domain, Modulabgleich vorher). Vorgabe: 28:8.3.
#                     Grenzen (lib/versioncheck.php, gemessen 23.11.2026): NC27 <= 8.2,
#                     NC28-30 <= 8.3, NC31-32 <= 8.4, NC33-34 8.2-8.5, NC35 >= 8.3.
#   --arbeit, --quarantaene   Ablagen, Vorgabe /root/nc-ir/<domain>, /root/quarantaene/nc-<domain>
#
# Gelernt im Vorfall 23.11.2026:
# - Der Updater-Unterprozess erbt -d memory_limit nicht: PHP_INI_SCAN_DIR mit eigener ini,
#   Updater nur mit --no-upgrade, occ upgrade danach selbst.
# - Nach einem Rollback steht data/updater-<id>/.step auf "end"; der Updater meldet dann in
#   einer Sekunde Erfolg, ohne Dateien zu tauschen. Vor jedem Aufruf beiseitelegen.
# - "Kein Update" gilt nur bei "No update available". Sonst entscheidet version.php.
#
# Rückgabe: 0 fertig · 2 schon vorher ungesund · 3 Sicherung gescheitert · 4 Stufe
# zurückgerollt (gesund) · 5 Updater ohne Wirkung · 6 Rückweg NICHT gesund (sofort von Hand)
# =============================================================================
set -u
HIER="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=werkzeuge/nextcloud/lib.sh
. "$HIER/lib.sh"
NC_KUERZEL=update

nc_args "$@"
ENTFERNEN=(); FREMD=(); WECHSEL=(); MAX=12; set -- ${NC_REST[@]+"${NC_REST[@]}"}
while [ $# -gt 0 ]; do
  [ $# -ge 2 ] || nc_abbruch "Wert fehlt für $1"
  case "$1" in
    --app-entfernen) ENTFERNEN+=("$2");;
    --fremd) FREMD+=("$2");;
    --php-wechsel) WECHSEL+=("$2");;
    --max-stufen) MAX=$2;;
    *) nc_abbruch "unbekannter Schalter: $1";;
  esac; shift 2
done
[ ${#FREMD[@]} -gt 0 ] || FREMD=(cgi-bin)
[ ${#WECHSEL[@]} -gt 0 ] || WECHSEL=(28:8.3)
for a in ${ENTFERNEN[@]+"${ENTFERNEN[@]}"} "${FREMD[@]}"; do
  printf '%s' "$a" | grep -Eq '^[A-Za-z0-9_.-]+$' || nc_abbruch "Name ungültig: $a"
done
nc_init
B=$NC_ARBEIT/update-sicherung
DB=$(nc_cfg dbname); DD=$(nc_cfg datadirectory)

nc_h "0 Vorbedingungen ($([ "$NC_LOS" = 1 ] && echo AUSFUEHREN || echo TROCKENLAUF))"
echo "Version: $(nc_ver) · DB: $DB · PHP-Handler: $NC_PHPV ($(nc_phpbin))"
echo "Platz: httpdocs $(du -sh "$NC_W" 2>/dev/null | cut -f1) · frei $(df -h "$NC_V" | awk 'NR==2{print $4}')"
GESUND=1; nc_web_ok || GESUND=0
for a in ${ENTFERNEN[@]+"${ENTFERNEN[@]}"}; do
  for d in "$NC_W/apps/$a" "$NC_W/custom_apps/$a"; do [ -d "$d" ] && echo "zu entfernen: $d"; done
done
for f in "${FREMD[@]}"; do [ -e "$NC_W/$f" ] && echo "Fremdeintrag: $NC_W/$f"; done
for s in "$DD"/updater-*/.step; do [ -f "$s" ] && echo "liegengebliebener Updater-Zustand: $s ($(cat "$s"))"; done
echo "PHP-Wechsel: ${WECHSEL[*]}"
if [ "$NC_LOS" != 1 ]; then
  [ "$GESUND" = 1 ] && echo "TROCKENLAUF: nichts geändert. Mit --ausfuehren starten." || echo "TROCKENLAUF: Nextcloud ist schon jetzt NICHT gesund — Update würde nicht starten."
  exit 0
fi
[ "$GESUND" = 1 ] || nc_abbruch "Nextcloud schon vor dem Update nicht gesund" 2

install -d -m 700 "$B" "$NC_Q"
exec > >(tee -a "$NC_ARBEIT/update.txt") 2>&1
nc_occ app:list --shipped=false > "$B/apps-vorher.txt" 2>&1
echo "Fremd-Apps vorher: $(grep -c '^  - ' "$B/apps-vorher.txt")"

for a in ${ENTFERNEN[@]+"${ENTFERNEN[@]}"}; do
  nc_occ app:disable "$a" >/dev/null 2>&1
  for d in "$NC_W/apps/$a" "$NC_W/custom_apps/$a"; do
    [ -d "$d" ] && mv "$d" "$NC_Q/$a-$(date +%s)" && nc_log "U0 App $a deaktiviert, Verzeichnis $d nach $NC_Q verschoben"
  done
done
for f in "${FREMD[@]}"; do
  [ -e "$NC_W/$f" ] || continue
  echo "Beleg $f:"; find "$NC_W/$f" -exec ls -ld {} \; | sed 's/^/  /'
  find "$NC_W/$f" -type f -exec sh -c 'for x; do printf "  %s  %s\n" "$(openssl dgst -sha256 -r "$x" | cut -d" " -f1)" "$x"; done' sh {} +
  mv "$NC_W/$f" "$NC_Q/httpdocs-$f-$(date +%s)" && nc_log "U0 httpdocs/$f nach $NC_Q verschoben (blockiert Updater, Beleg im Log)"
done

php_wechsel(){   # <ziel x.y>
  local ziel=$1 alt=$NC_PHPV neu altbin neubin miss
  altbin=$(nc_phpbin); neubin=$NC_PHP_WURZEL/$ziel/bin/php
  [ -x "$neubin" ] || { echo "PHP $ziel fehlt ($neubin)"; return 1; }
  miss=$(comm -23 <("$altbin" -m | sort -u) <("$neubin" -m | sort -u) | grep -v '^\[' | tr '\n' ' ')
  [ -z "${miss// /}" ] || { echo "in PHP $ziel fehlen Module: $miss"; return 1; }
  neu=$(printf '%s' "$alt" | sed -E "s/php-?[0-9]{2,3}/php${ziel/./}/")
  [ "$neu" != "$alt" ] || { echo "Handler $alt nicht umschreibbar"; return 1; }
  plesk bin domain --update "$NC_D" -php_handler_id "$neu" >/dev/null 2>&1 || { echo "Handler $neu nicht setzbar"; return 1; }
  sleep "${NC_PAUSE:-3}"; NC_PHPV=$neu
  if nc_web_ok; then nc_log "U PHP-Handler $alt -> $neu"; return 0; fi
  plesk bin domain --update "$NC_D" -php_handler_id "$alt" >/dev/null 2>&1; NC_PHPV=$alt; echo "zurück auf $alt"; return 1
}

vnum(){ printf '%s' "${1:-0.0}" | awk -F. '{print $1*100+$2}'; }
i=0
while [ "$i" -lt "$MAX" ]; do
  i=$((i+1)); VOR=$(nc_ver); nc_h "Stufe $i: von $VOR"
  for w in "${WECHSEL[@]}"; do
    maj=${w%%:*}; ziel=${w#*:}
    if [ "${VOR%%.*}" = "$maj" ] && [ "$(vnum "$(nc_phpversion)")" -lt "$(vnum "$ziel")" ]; then
      nc_h "PHP $(nc_phpversion) -> $ziel"
      php_wechsel "$ziel" || { nc_log "U PHP-Wechsel auf $ziel gescheitert, Lauf endet auf $VOR"; exit 4; }
    fi
  done
  echo "-- Sicherung"
  nc_dump "$B/s$i-db-$VOR.sql.gz" "$DB" && tar -C "$NC_V" -czf "$B/s$i-httpdocs-$VOR.tgz" httpdocs || nc_abbruch "Sicherung fehlgeschlagen" 3
  nc_log "U$i Sicherung vor Update von $VOR: $B/s$i-*"
  for s in "$DD"/updater-*/.step; do
    [ -f "$s" ] || continue; z=$(cat "$s"); mv "$s" "$s.nc-ir-$(date +%s)"; echo "  Updater-Zustand $s beiseitegelegt: $z"
  done
  ( cd "$NC_W" && nc_php updater/updater.phar --no-interaction --no-upgrade ) > "$B/s$i-updater.txt" 2>&1
  RC=$?; grep -vE '^[[:space:]]*$' "$B/s$i-updater.txt" | tail -25; NACH=$(nc_ver)
  if [ "$NACH" = "$VOR" ] && [ "$RC" = 0 ] && grep -qi 'no update available' "$B/s$i-updater.txt"; then
    echo "Kein weiteres Update verfügbar."; nc_occ maintenance:mode --off >/dev/null 2>&1; break
  fi
  if [ "$NACH" = "$VOR" ] && [ "$RC" = 0 ]; then
    nc_occ maintenance:mode --off >/dev/null 2>&1
    nc_log "U$i Updater meldet Erfolg, version.php unverändert ($VOR): ohne Wirkung, Lauf beendet"; exit 5
  fi
  if [ "$RC" = 0 ]; then
    echo "-- Nacharbeiten"
    nc_occ upgrade 2>&1 | tail -6; nc_occ app:update --all 2>&1 | tail -8
    for x in indices columns primary-keys; do nc_occ "db:add-missing-$x" 2>&1 | tail -1; done
    nc_occ maintenance:mode --off >/dev/null 2>&1; sleep "${NC_PAUSE:-2}"
    if nc_web_ok; then nc_log "U$i Update $VOR -> $NACH ok (status.php, Login 200)"; continue; fi
  fi
  nc_h "ROLLBACK Stufe $i (Updater rc=$RC, Version $NACH)"
  nc_occ maintenance:mode --on >/dev/null 2>&1
  mv "$NC_W" "$NC_V/httpdocs.fehlschlag-$i-$(date +%s)" && tar -C "$NC_V" -xzf "$B/s$i-httpdocs-$VOR.tgz" && nc_restore "$B/s$i-db-$VOR.sql.gz"
  nc_occ maintenance:mode --off >/dev/null 2>&1; sleep "${NC_PAUSE:-2}"
  if nc_web_ok && [ "$(nc_ver)" = "$VOR" ]; then nc_log "U$i FEHLGESCHLAGEN ($VOR -> $NACH), Rückweg auf $VOR gesund"; exit 4; fi
  nc_log "U$i FEHLGESCHLAGEN, Rückweg NICHT gesund — sofort von Hand"; exit 6
done

nc_h "Abschluss auf $(nc_ver)"
nc_occ status 2>&1 | grep -v instanceid | head -8
nc_occ update:check 2>&1 | tail -3
nc_occ app:update --showonly 2>&1 | tail -5
echo "-- Kern-Integrität"; nc_occ integrity:check-core 2>&1 | head -40
nc_occ app:list --shipped=false > "$B/apps-nachher.txt" 2>&1
an(){ sed -n '/^Enabled/,/^Disabled/p' "$1" | grep '^  - ' | cut -d: -f1; }
echo "-- vom Upgrade deaktivierte Fremd-Apps:"; diff <(an "$B/apps-vorher.txt") <(an "$B/apps-nachher.txt") | grep '^<' || echo "  keine"
nc_web_ok && nc_log "U Abschluss: Nextcloud $(nc_ver), PHP-Handler $NC_PHPV, Sicherungen $B"
nc_h fertig
