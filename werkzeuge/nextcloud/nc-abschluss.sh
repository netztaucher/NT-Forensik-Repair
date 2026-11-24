#!/usr/bin/env bash
# =============================================================================
# nc-abschluss.sh — Abschluss nach dem Vorfall: Hintergrundjobs, App-Updates, Quarantäne-Kopien
# =============================================================================
# Test:     ja - werkzeuge/nextcloud/nextcloud_selbsttest.sh (Attrappen, CI) und werkzeuge/nextcloud/probelauf/probelauf.sh (echte Nextcloud 27.1.11/28.0.14 im Wegwerf-Container) · NT-Forensik-Repair#165
# Rueckweg: ja - Prüfstand 24.11.2026: cron per rm /etc/cron.d/nextcloud-<abo> zurück; appupdate-Rückweg (App-Ordner + DB) bei App-Update ohne Wirkung gelaufen; quarantaene: entfällt (gelöscht, Werte rotiert) · NT-Forensik-Repair#165
#
#   nc-abschluss.sh <cron|appupdate|quarantaene> --domain <domain> --abo <systembenutzer> [--ausfuehren]
#
#   cron        Hintergrundjobs ohne Crontab des Abos: /etc/cron.d/nextcloud-<abo> startet cron.php
#               alle 5 min als root über `runuser -u <abo>`. Das Abo bleibt in /etc/cron.deny und kann
#               keine Crontab mehr schreiben (so kam im Vorfall die Persistenz). Prüfung: Probelauf
#               cron.php rc 0 und lastcron rückt vor. Steht der Modus nicht auf cron, wird er umgestellt.
#   appupdate   ausstehende App-Updates mit Sicherung (DB + apps, custom_apps), Prüfung (kein vorher
#               offenes Update mehr offen, cron.php rc 0, lastcron rückt vor), bei Fehler Rückweg.
#               Anlass 24.11.2026: groupfolders 23.0.1 brach cron.php ab. Ohne Wartungsmodus: occ
#               upgrade verweigert dort, und app:update meldet "updated" mit rc 0 auch ohne Wirkung
#               (beides gemessen im Prüfstand, #165).
#   quarantaene Kopien mit alten, rotierten Geheimnissen löschen (shred -u):
#               <quarantaene>/config.php.vor-*, <quarantaene>/psa.shadow.vor-*. Beweise bleiben liegen.
#
# Ohne --ausfuehren: Trockenlauf. Pfade für den Selbsttest: NC_CRON_D, NC_CRON_DENY.
# =============================================================================
set -u
HIER="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=werkzeuge/nextcloud/lib.sh
. "$HIER/lib.sh"
NC_KUERZEL=abschluss

nc_args "$@"
TEIL=${NC_REST[0]:-}; [ ${#NC_REST[@]} -le 1 ] || nc_abbruch "zu viele Argumente: ${NC_REST[*]}"
case "$TEIL" in cron|appupdate|quarantaene) ;; *) nc_abbruch "Teil fehlt: cron|appupdate|quarantaene";; esac
nc_init
CF=${NC_CRON_D:-/etc/cron.d}/nextcloud-$NC_U; DENY=${NC_CRON_DENY:-/etc/cron.deny}
[ "$NC_LOS" = 1 ] || echo "TROCKENLAUF (mit --ausfuehren wird geändert)"
lastcron(){ nc_occ config:app:get core lastcron 2>/dev/null | tail -1; }
zeit(){ date -u -d "@$1" +%FT%TZ 2>/dev/null || date -u -r "$1" +%FT%TZ 2>/dev/null || echo "$1"; }
cronlauf(){ ( cd "$NC_W" && nc_php -f cron.php ); }

case "$TEIL" in
cron)
  MODUS=$(nc_occ config:app:get core backgroundjobs_mode 2>/dev/null | tail -1)
  echo "Modus: ${MODUS:-ajax (Vorgabe)} · letzter Lauf: $(zeit "$(lastcron)")"
  grep -qx "$NC_U" "$DENY" 2>/dev/null && echo "$NC_U in $DENY: ja (bleibt)" || echo "WARNUNG: $NC_U steht NICHT in $DENY"
  ZEILE="*/5 * * * * root runuser -u $NC_U -- $(nc_phpbin) -d memory_limit=1024M -f $NC_W/cron.php >/dev/null 2>&1"
  echo "Ziel $CF:"; echo "  $ZEILE"
  [ "$NC_LOS" = 1 ] || exit 0
  install -d -m 700 "$NC_Q"
  [ -e "$CF" ] && cp -a "$CF" "$NC_Q/nextcloud-$NC_U.cron.vor-$(date +%s)"
  printf '# Nextcloud-Hintergrundjobs %s (nc-abschluss.sh)\n# %s steht bewusst in /etc/cron.deny; der Job laeuft ueber root -> runuser.\n%s\n' "$NC_D" "$NC_U" "$ZEILE" > "$CF"
  chmod 644 "$CF"
  # Ohne Eintrag gilt ajax (frische Instanz im Prüfstand #165): ausdrücklich auf cron stellen
  [ "$MODUS" = cron ] || { nc_occ background:cron >/dev/null 2>&1 && nc_log "Hintergrundjob-Modus ${MODUS:-ajax} -> cron"; }
  vor=$(lastcron); sleep "${NC_PAUSE:-1}"; cronlauf >/dev/null 2>&1; rc=$?; nach=$(lastcron)
  if [ "$rc" = 0 ] && [ "${nach:-0}" -gt "${vor:-0}" ]; then
    nc_log "Nextcloud-Cron an ($CF, alle 5 min, runuser $NC_U, Abo bleibt in cron.deny); Probelauf ok, lastcron $(zeit "$nach")"
  else nc_log "Nextcloud-Cron: Datei angelegt, Probelauf FEHLER (rc $rc, lastcron unverändert) — appupdate prüfen"; exit 3; fi ;;

appupdate)
  B=$NC_ARBEIT/update-sicherung; DB=$(nc_cfg dbname)
  echo "Ausstehende App-Updates:"; OFFEN=$(nc_occ app:update --showonly 2>/dev/null | grep -i 'new version')
  N=$(printf '%s\n' "$OFFEN" | grep -c .); [ "$N" -gt 0 ] || { echo "  keine"; exit 0; }
  printf '%s\n' "$OFFEN" | sed 's/^/  /'
  [ "$NC_LOS" = 1 ] || exit 0
  install -d -m 700 "$B"; S=$(date +%s)
  ORDNER=apps; [ -d "$NC_W/custom_apps" ] && ORDNER="apps custom_apps"
  # shellcheck disable=SC2086
  nc_dump "$B/a$S-db.sql.gz" "$DB" && tar -C "$NC_W" -czf "$B/a$S-apps.tgz" $ORDNER || nc_abbruch "Sicherung" 3
  nc_log "App-Update Sicherung: $B/a$S-db.sql.gz, $B/a$S-apps.tgz ($ORDNER, $N Updates ausstehend)"
  # Kein Wartungsmodus: app:update migriert selbst, und `occ upgrade` verweigert im Wartungsmodus
  # (Prüfstand #165). upgrade nur, wenn danach noch ein DB-Upgrade offen ist.
  nc_occ app:update --all > "$B/a$S-update.txt" 2>&1; urc=$?
  if nc_occ status --output=json 2>/dev/null | grep -q '"needsDbUpgrade":true'; then nc_occ upgrade >> "$B/a$S-update.txt" 2>&1 || urc=9; fi
  vor=$(lastcron); sleep "${NC_PAUSE:-1}"; cronlauf > "$B/a$S-cron.txt" 2>&1; crc=$?; nach=$(lastcron)
  # app:update meldet "updated" mit rc 0 auch dann, wenn der App-Ordner nicht beschreibbar war
  # (Prüfstand #165): erfolgreich ist nur, was danach nicht mehr als offen gemeldet wird.
  NOCH=$(nc_occ app:update --showonly 2>/dev/null | grep -i 'new version' | grep -xF -f <(printf '%s\n' "$OFFEN"))
  if [ "$urc" = 0 ] && [ -z "$NOCH" ] && [ "$crc" = 0 ] && [ "${nach:-0}" -gt "${vor:-0}" ]; then
    nc_log "App-Updates eingespielt ($N), cron.php ok, lastcron $(zeit "$nach")"
  else
    echo "FEHLER (update rc $urc, cron rc $crc, weiter offen: ${NOCH:-nichts}): Rückweg"
    head -3 "$B/a$S-cron.txt" | cut -c1-200
    nc_occ maintenance:mode --on >/dev/null 2>&1
    for o in $ORDNER; do mv "$NC_W/$o" "$NC_W/$o.fehlschlag-$S" || nc_abbruch "$o nicht beiseite" 6; done
    tar -C "$NC_W" -xzf "$B/a$S-apps.tgz" && nc_restore "$B/a$S-db.sql.gz"
    nc_occ maintenance:mode --off >/dev/null 2>&1
    if ! nc_web_ok; then nc_log "App-Update FEHLER, Rückweg aus a$S NICHT gesund — sofort von Hand"; exit 6; fi
    nc_log "App-Update FEHLER (update rc $urc, cron rc $crc, offen: ${NOCH:-nichts}), Rückweg $ORDNER + DB aus a$S eingespielt"; exit 4
  fi ;;

quarantaene)
  L=$(ls -1 "$NC_Q"/config.php.vor-* "$NC_Q"/psa.shadow.vor-* 2>/dev/null)
  [ -n "$L" ] || { echo "nichts zu löschen"; exit 0; }
  printf '%s\n' "$L" | while IFS= read -r f; do echo "  $f $(wc -c < "$f" | tr -d ' ') B"; done
  [ "$NC_LOS" = 1 ] || exit 0
  printf '%s\n' "$L" | while IFS= read -r f; do shred -u "$f"; done
  rest=$(ls -1 "$NC_Q"/config.php.vor-* "$NC_Q"/psa.shadow.vor-* 2>/dev/null | wc -l | tr -d ' ')
  [ "$rest" = 0 ] || nc_abbruch "$rest Dateien übrig" 3
  nc_log "Quarantäne-Kopien mit rotierten Geheimnissen gelöscht (shred): $(printf '%s\n' "$L" | xargs -n1 basename | tr '\n' ' ')" ;;
esac
