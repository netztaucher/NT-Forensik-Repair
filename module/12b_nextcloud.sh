# @nummer:  12b
# @titel:   Nextcloud-Prüfung
# @frage:   Ist eine Nextcloud-Installation übernommen oder ihre .htaccess manipuliert?
# @kosten:  gering — Dateisuche und occ, etwa 10 s je Installation
# @ebene:   website
#
# Grundlage: die Bereinigung einer echten, uebernommenen Instanz
# (/root/docs/nextcloud-cleanup-htaccess-guide.md auf einem Produktivsystem, 08/2026). Die Muster
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
NC_INSTALLS=""
while IFS= read -r _occ; do
  _d="$(dirname "$_occ")"
  [[ -f "${_d}/version.php" && -d "${_d}/apps" ]] && NC_INSTALLS+="${_d}"$'\n'
done < <(find "${SCAN_PATHS[@]}" -maxdepth 6 -name occ -type f 2>/dev/null | nf_strip_self)
NC_INSTALLS=$(printf '%s\n' "$NC_INSTALLS" | grep -vE '^$' | sort -u || true)

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

while IFS= read -r NC; do
  [[ -n "$NC" ]] || continue
  _kurz="${NC#"$VHOSTS_DIR"/}"
  h2 "12b.1 ${_kurz}"

  _ver=$(grep -oE "\\\$OC_Version *= *array *\( *[0-9,\ ]+" "${NC}/version.php" 2>/dev/null \
         | grep -oE '[0-9]+(, *[0-9]+)*' | tr -d ' ' | tr ',' '.' | head -1)
  info "Fassung: ${_ver:-unbekannt}"

  # ── Root-.htaccess ──────────────────────────────────────────
  # Das aussagekraeftigste Einzelmerkmal. Eine Nextcloud-.htaccess enthaelt
  # Rewrites fuer remote.php und .well-known; eine uebernommene enthaelt eine
  # WordPress-Freigabeliste, in der die Dateien des Angreifers stehen.
  NC_HT="${NC}/.htaccess"
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
  _drop=$(find "$NC" -maxdepth 5 -type f \( -name 'filefuns.php' -o -name 'adminfuns.php' \
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
    _t=$(find "$NC" -maxdepth 4 -type d -path "*/${_n}/${_n}" 2>/dev/null | grep -vE "$NC_LEGITIM" || true)
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
  if [[ -f "${NC}/index.php" ]]; then
    _sz=$(wc -c < "${NC}/index.php" | tr -d ' ')
    if [[ "$_sz" -gt 20000 ]]; then
      crit "${_kurz}: index.php ist ${_sz} Bytes gross (Nextcloud liefert rund 3.700)" web
      NC_MALWARE+="${NC}/index.php"$'\n'
      evidence "nextcloud_index_$(echo "$_kurz" | tr '/.' '__')" \
        "$(datei_steckbrief 'index.php um ein Vielfaches zu gross — Nextcloud liefert rund 3.700 Bytes' \
           'goto |\\\\x[0-9a-f]{2}|eval|base64_decode' "${NC}/index.php")"
    else
      ok "${_kurz}: index.php unauffällig (${_sz} Bytes)"
    fi
  fi

  # ── Kern-Integritaet ueber occ ──────────────────────────────
  # Das Gegenstueck zu 'wp core verify-checksums'. Es findet Dateien, die im
  # Kern nichts zu suchen haben — genau die Klasse, die Signaturscanner
  # uebersieht, weil an ihr nichts auffaellig aussieht.
  _owner=$(stat -c %U "$NC" 2>/dev/null || echo "")
  _php=$(command -v php 2>/dev/null || ls /opt/plesk/php/*/bin/php 2>/dev/null | sort -V | tail -1)
  if [[ -n "$_owner" && -n "$_php" ]]; then
    _int=$(sudo -u "$_owner" "$_php" -d memory_limit=1024M "${NC}/occ" integrity:check-core 2>/dev/null | head -40 || true)
    if [[ -z "$_int" ]]; then
      ok "${_kurz}: occ integrity:check-core meldet keine Abweichung"
    else
      crit "${_kurz}: occ integrity:check-core meldet Abweichungen im Kern" web
      code "$(printf '%s\n' "$_int" | head -20)"
      NC_INTEGRITY+="=== ${_kurz} ==="$'\n'"$_int"$'\n'
      evidence "nextcloud_integritaet_$(echo "$_kurz" | tr '/.' '__')" "$_int"
    fi
  else
    info "${_kurz}: occ nicht ausführbar (Eigentümer oder PHP nicht ermittelbar) — Kern nicht geprüft"
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
