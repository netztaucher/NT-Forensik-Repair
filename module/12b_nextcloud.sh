# shellcheck shell=bash
# @nummer:  12b
# @titel:   Nextcloud-Prüfung
# @frage:   Ist eine Nextcloud-Installation übernommen oder ihre .htaccess manipuliert?
# @kosten:  gering — Dateisuche und occ, etwa 10 s je Installation
# @ebene:   website
#
# Grundlage: die Bereinigung einer echten, uebernommenen Instanz
# (interne Zuarbeit aus einem realen Vorfall, 08/2026). Die Muster
# hier stammen aus diesem Fall, nicht aus einer Sammlung im Netz.
#
# Der Angriff arbeitete WordPress-artig: eine Root-.htaccess, die PHP pauschal
# sperrt und genau die eigenen Dateien freigibt, dazu verschachtelte
# Verzeichnisse (config/config/, data/data/) mit je einer index.php und
# cache.php. Eine Nextcloud, die so praepariert ist, faellt im Betrieb nur
# dadurch auf, dass Clients keine Verbindung mehr bekommen — im Apache-Log
# steht dann AH01797 auf remote.php oder ocs/v2.php, was wie ein
# Rechteproblem aussieht und keines ist.

h1 "12b. NEXTCLOUD-PRÜFUNG"

# Installationen finden. version.php neben occ ist das verlaessliche Paar;
# die occ-Datei allein liegt auch in Sicherungskopien.
# Sicherungskopien des eingebauten Updaters sind vollstaendige Nextcloud-Baeume
# und von einer laufenden Instanz nur am Pfad zu unterscheiden. Ohne Filter
# vervielfacht jeder Befund sich um die Zahl der Sicherungen.
NC_KOPIE='/updater-[a-z0-9]+/backups/|/[a-z0-9_-]*backups?/|/\.?(quarantaene|quarantine|old|bak)/'

NC_INSTALLS=""; NC_KOPIEN=0
while IFS= read -r _occ; do
  _d="$(dirname "$_occ")"
  [[ -f "${_d}/version.php" && -d "${_d}/apps" ]] || continue
  if printf '%s' "$_d" | grep -qE "$NC_KOPIE"; then
    NC_KOPIEN=$((NC_KOPIEN + 1)); continue
  fi
  NC_INSTALLS+="${_d}"$'\n'
done < <(find "${SCAN_PATHS[@]}" -maxdepth 6 -name occ -type f 2>/dev/null | nf_strip_self)
NC_INSTALLS=$(printf '%s\n' "$NC_INSTALLS" | grep -vE '^$' | sort -u || true)
# Eine Sicherung, die Schadcode enthaelt, stellt ihn beim Zurueckspielen wieder
# her. Uebersprungen heisst deshalb: genannt, nicht verschwiegen.
[[ "$NC_KOPIEN" -gt 0 ]] && warn "${NC_KOPIEN} Nextcloud-Sicherungskopie(n) nicht geprüft — sie werden nicht ausgeliefert, würden Schadcode beim Zurückspielen aber wiederherstellen"

if [[ -z "$NC_INSTALLS" ]]; then
  ok "Keine Nextcloud-Installation im Prüfumfang"
else
NC_COUNT=$(printf '%s\n' "$NC_INSTALLS" | grep -c . || true)
info "Nextcloud-Installationen: ${NC_COUNT}"
code "$NC_INSTALLS"

# Legitime Pfade, die wie eine Verschachtelung aussehen, aber keine sind.
# Ohne diese Ausnahmen meldet die Pruefung bei JEDER gesunden Instanz Funde —
# und lib/composer/composer zu entfernen erzeugt einen Fatal Error.
NC_LEGITIM='/lib/composer/composer/|/3rdparty/phpseclib/phpseclib/phpseclib/|/apps/[^/]+/vendor/'

while IFS= read -r NCDIR; do
  [[ -n "$NCDIR" ]] || continue
  _kurz="${NCDIR#"$VHOSTS_DIR"/}"
  h2 "12b.1 ${_kurz}"

  _ver=$(grep -oE "\\\$OC_Version *= *array *\( *[0-9,\ ]+" "${NCDIR}/version.php" 2>/dev/null \
         | grep -oE '[0-9]+(, *[0-9]+)*' | tr -d ' ' | tr ',' '.' | head -1)
  info "Fassung: ${_ver:-unbekannt}"

  # ── Root-.htaccess ──────────────────────────────────────────
  # Das aussagekraeftigste Einzelmerkmal. Eine Nextcloud-.htaccess enthaelt
  # Rewrites fuer remote.php und .well-known; eine uebernommene enthaelt eine
  # WordPress-Freigabeliste, in der die Dateien des Angreifers stehen.
  NC_HT="${NCDIR}/.htaccess"
  if [[ -r "$NC_HT" ]]; then
    _mal=$(grep -nEi 'filefuns|adminfuns|cjfuns|classsmtps|wp-login\.php|Order allow,deny' "$NC_HT" 2>/dev/null | head -6 || true)
    if [[ -n "$_mal" ]]; then
      crit "${_kurz}: Root-.htaccess trägt Angreifer-Merkmale (Freigabeliste mit fremden Dateinamen)" web
      code "$_mal"
      NC_HTACCESS_MAL+="${NC_HT}"$'\n'
      evidence "nextcloud_htaccess_$(echo "$_kurz" | tr '/.' '__')" \
        "$(datei_steckbrief 'Root-.htaccess mit WordPress-Freigabeliste — bei Nextcloud nie legitim' \
           'filefuns|adminfuns|cjfuns|classsmtps|wp-login\.php|Order allow,deny' "$NC_HT")"
    elif ! grep -qE 'remote\.php|well-known' "$NC_HT" 2>/dev/null; then
      warn "${_kurz}: Root-.htaccess ohne Nextcloud-Rewrites (remote.php / .well-known) — vermutlich ersetzt"
      NC_HTACCESS_MAL+="${NC_HT}"$'\n'
    else
      ok "${_kurz}: Root-.htaccess sieht nach Nextcloud aus"
    fi
  else
    warn "${_kurz}: keine Root-.htaccess vorhanden — Zugriffsschutz und Rewrites fehlen"
  fi

  # ── Bekannte Dropper-Namen ──────────────────────────────────
  _drop=$(find "$NCDIR" -maxdepth 5 -type f \( -name 'filefuns.php' -o -name 'adminfuns.php' \
            -o -name 'cjfuns.php' -o -name 'classsmtps.php' \) 2>/dev/null \
          | grep -vE "$NC_LEGITIM" || true)
  if [[ -n "$_drop" ]]; then
    crit "${_kurz}: bekannte Schaddateien der Nextcloud-Kampagne gefunden" web
    code "$_drop"
    NC_MALWARE+="$_drop"$'\n'
  else
    ok "${_kurz}: keine bekannten Schaddateien"
  fi

  # ── Verschachtelte Verzeichnisse ────────────────────────────
  # config/config/, data/data/ und Verwandte. In einer gesunden Instanz gibt es
  # das nicht; die Ausnahmeliste faengt die Faelle ab, in denen es doch normal ist.
  _nest=""
  for _n in config data images ocs dist core apps; do
    _t=$(find "$NCDIR" -maxdepth 4 -type d -path "*/${_n}/${_n}" 2>/dev/null | grep -vE "$NC_LEGITIM" || true)
    [[ -n "$_t" ]] && _nest+="$_t"$'\n'
  done
  _nest=$(printf '%s\n' "$_nest" | grep -vE '^$' || true)
  if [[ -n "$_nest" ]]; then
    crit "${_kurz}: verschachtelte Verzeichnisse (z. B. config/config) — typisch für diese Kampagne" web
    code "$_nest"
    NC_NESTED+="$_nest"$'\n'
  else
    ok "${_kurz}: keine verschachtelten Verzeichnisse"
  fi

  # ── Aufgeblaehte index.php ──────────────────────────────────
  # Die echte ist rund 3,7 KB. Die praeparierte war 50 KB gross und enthielt
  # goto-Spruenge und hexkodierte Zeichenketten.
  if [[ -f "${NCDIR}/index.php" ]]; then
    _sz=$(wc -c < "${NCDIR}/index.php" | tr -d ' ')
    if [[ "$_sz" -gt 20000 ]]; then
      crit "${_kurz}: index.php ist ${_sz} Bytes gross (Nextcloud liefert rund 3.700)" web
      NC_MALWARE+="${NCDIR}/index.php"$'\n'
      evidence "nextcloud_index_$(echo "$_kurz" | tr '/.' '__')" \
        "$(datei_steckbrief 'index.php um ein Vielfaches zu gross — Nextcloud liefert rund 3.700 Bytes' \
           'goto |\\\\x[0-9a-f]{2}|eval|base64_decode' "${NCDIR}/index.php")"
    else
      ok "${_kurz}: index.php unauffällig (${_sz} Bytes)"
    fi
  fi

  # ── Kern-Integritaet ueber occ ──────────────────────────────
  # Das Gegenstueck zu 'wp core verify-checksums'. Es findet Dateien, die im
  # Kern nichts zu suchen haben — genau die Klasse, die Signaturscanner
  # uebersieht, weil an ihr nichts auffaellig aussieht.
  _owner=$(stat -c %U "$NCDIR" 2>/dev/null || echo "")
  _php=$(command -v php 2>/dev/null || ls /opt/plesk/php/*/bin/php 2>/dev/null | sort -V | tail -1)
  if [[ -z "$_owner" || -z "$_php" ]]; then
    unklar "${_kurz}: Eigentümer oder PHP nicht ermittelbar — Kern-Integrität nicht geprüft" web
  else
    # Probe vor der Messung, wie in Abschnitt 12c. Ohne sie galt eine leere
    # Ausgabe als "keine Abweichung" — dabei antwortet occ bei unpassender
    # PHP-Fassung mit einer HTML-Meldung auf STDOUT und Rueckgabewert 0, und
    # bei aktivem Wartungsmodus mit gar nichts. Beides sah aus wie ein
    # sauberer Kern.
    _probe=$(sudo -u "$_owner" "$_php" -d memory_limit=1024M "${NCDIR}/occ" status --output=json 2>/dev/null || true)
    if ! printf '%s' "$_probe" | python3 -c "import json,sys;json.load(sys.stdin)" 2>/dev/null; then
      _grund=$(printf '%s' "$_probe" | sed 's/<br\/*>/ /g' | tr -d '\n' | cut -c1-120)
      unklar "${_kurz}: occ liefert keine verwertbare Antwort — Kern-Integrität nicht geprüft${_grund:+ (${_grund})}" web
    else
      _int=$(sudo -u "$_owner" "$_php" -d memory_limit=1024M "${NCDIR}/occ" integrity:check-core 2>/dev/null | head -40 || true)
      if [[ -z "$_int" ]]; then
        ok "${_kurz}: occ integrity:check-core meldet keine Abweichung"
      else
        crit "${_kurz}: occ integrity:check-core meldet Abweichungen im Kern" web
        code "$(printf '%s\n' "$_int" | head -20)"
        NC_INTEGRITY+="=== ${_kurz} ==="$'\n'"$_int"$'\n'
        evidence "nextcloud_integritaet_$(echo "$_kurz" | tr '/.' '__')" "$_int"
      fi
    fi
  fi
done <<< "$NC_INSTALLS"

# ── Apache-Marker ─────────────────────────────────────────────
# AH01797 auf remote.php oder ocs/v2.php sieht wie ein Rechteproblem aus und
# ist fast immer eine manipulierte .htaccess. Der Hinweis spart die falsche
# Fehlersuche in der Nextcloud-Konfiguration.
NC_AH=$(grep -rhoE 'AH01797[^"]*\/(remote|status)\.php|AH01797[^"]*\/ocs\/v2\.php' \
        /var/www/vhosts/system/*/logs/error_log 2>/dev/null | head -5 || true)
if [[ -n "$NC_AH" ]]; then
  warn "Apache meldet AH01797 auf Nextcloud-Endpunkten — deutet auf eine manipulierte .htaccess, nicht auf fehlende Rechte"
  code "$NC_AH"
fi
fi