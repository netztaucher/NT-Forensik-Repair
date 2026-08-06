# NT-Forensik — Abschnitt 11: WordPress-Datenbank
#
# @nummer:  11
# @titel:   WordPress-Datenbank
# @frage:   Ist eine WordPress-Installation übernommen?
# @kosten:  mittel — je Installation
# @ebene:   website
#
# Wird vom Runner eingebunden, nicht einzeln ausgefuehrt.
# Vorgabewerte der hier gefuellten Variablen: lib/befunde.sh

h1 "11. WORDPRESS-DATENBANK-PRÜFUNG"
# ============================================================
# Findet WordPress-Installationen, liest DB-Zugang aus wp-config.php und
# prüft die Datenbank auf Angreifer-Spuren: fremde Admin-Konten, manipulierte
# Optionen (siteurl/home, auto_prepend), verdächtige aktive Plugins,
# heimlich zu Admin erhobene Nutzer. Read-only (nur SELECT).

WPDB_FLAGS=0


# wp-cli + PHP-Binary erkennen (Fallback wenn direkter mysql-Zugang scheitert;
# Lehre aus einem Kundenvorfall 2026-07: mysql-Connect schlug fehl, DB-Prüfung wurde
# komplett übersprungen und 4 Angreifer-Admins übersehen).
WP_CLI=$(command -v wp 2>/dev/null || true)
PHP_BIN=$(command -v php 2>/dev/null || ls /opt/plesk/php/*/bin/php 2>/dev/null | tail -1 || true)
CURRENT_WP_PATH=""   # wird je Installation in der Schleife gesetzt

# Ein WP-Config-Wert extrahieren: wpconf_get <file> <KONSTANTE>
# Auskommentierte Zeilen (// # * /*) werden übersprungen — sonst greift head -1
# fälschlich einen alten, auskommentierten define()-Wert (z. B. Migrations-Reste
# wie eine veraltete DB_NAME) und die Prüfung landet auf der falschen Datenbank.
wpconf_get() {
  grep -vE '^[[:space:]]*(//|#|\*|/\*)' "$1" 2>/dev/null \
    | grep -oP "define\(\s*['\"]$2['\"]\s*,\s*['\"]\K[^'\"]*" 2>/dev/null | head -1
}

# wp-cli als Datei-Eigentümer der Installation ausführen (Plesk-tauglich).
wp_cli() {  # $@ = wp-cli-Argumente; nutzt CURRENT_WP_PATH
  [[ -n "$WP_CLI" && -n "$PHP_BIN" && -n "$CURRENT_WP_PATH" ]] || return 1
  local owner; owner=$(stat -c %U "${CURRENT_WP_PATH}/wp-config.php" 2>/dev/null || echo root)
  sudo -u "$owner" "$PHP_BIN" "$WP_CLI" "$@" --path="$CURRENT_WP_PATH" --skip-plugins --skip-themes 2>/dev/null
}

# SQL gegen eine WP-DB ausführen. Nutzt Plesk-Admin, sonst WP-Creds, sonst wp-cli.
wp_sql() {
  local db="$1" user="$2" pass="$3" host="$4" query="$5"
  if [[ -n "$PLESK_MYSQL_PW" ]]; then
    MYSQL_PWD="$PLESK_MYSQL_PW" mysql -u admin -N -e "USE \`$db\`; $query" 2>/dev/null && return 0
  fi
  MYSQL_PWD="$pass" mysql -h "${host%%:*}" -u "$user" -N -e "$query" "$db" 2>/dev/null && return 0
  # Fallback: wp-cli nutzt die DB-Zugangsdaten der Installation selbst.
  wp_cli db query "$query" --skip-column-names 2>/dev/null
}

# Suchen wird ausschliesslich im Scope. Frueher stand hier eine Verzweigung
# ueber $DOMAIN, die ohne Domain auf ${VHOSTS_DIR} zurueckfiel — womit --path
# und --webNN wirkungslos waren und auf einem Shared-Host alle Installationen
# des Servers im Bericht landeten.
WP_CONFIGS=$(find "${SCAN_PATHS[@]}" -maxdepth 5 -name wp-config.php 2>/dev/null || true)

if [[ -z "$WP_CONFIGS" ]]; then
  h2 "11.1 WordPress-Installationen"
  info "Keine wp-config.php im Scan-Pfad gefunden — keine DB-Prüfung"
else
  WP_COUNT=$(echo "$WP_CONFIGS" | grep -c . || true)
  h2 "11.1 Gefundene WordPress-Installationen"
  info "WordPress-Installationen: $WP_COUNT"
  code "$WP_CONFIGS"

  WPDB_REPORT=""
  while IFS= read -r cfg; do
    [[ -f "$cfg" ]] || continue
    site=$(echo "$cfg" | sed "s|${VHOSTS_DIR}/||;s|/wp-config.php||")
    CURRENT_WP_PATH=$(dirname "$cfg")
    db=$(wpconf_get "$cfg" DB_NAME)
    du=$(wpconf_get "$cfg" DB_USER)
    dp=$(wpconf_get "$cfg" DB_PASSWORD)
    dh=$(wpconf_get "$cfg" DB_HOST); dh=${dh:-localhost}
    pfx=$(grep -oP '\$table_prefix\s*=\s*['"'"'"]\K[^'"'"'"]*' "$cfg" 2>/dev/null | head -1); pfx=${pfx:-wp_}
    [[ -z "$db" ]] && continue

    echo -e "  ${CYN}DB-Prüfung:${NC} $site (db=$db, prefix=$pfx)"
    echo -e "\n#### $site  (DB: \`$db\`, Prefix: \`$pfx\`)\n" >> "$REPORT_FILE"

    # ── Kern-Integrität & Doorway-Familie (läuft auch OHNE DB-Verbindung) ──
    # Lehre aus einem Kundenvorfall: der Signatur-Webshell-Scan (§7.3) übersieht
    # goto-obfuskierte Doorways, getarnte Nicht-PHP-Payloads und @include-Core-
    # Injektionen. verify-checksums + Doorway-Signatur decken die Familie auf.
    if [[ -n "$WP_CLI" ]]; then
      CHK=$(wp_cli core verify-checksums 2>&1 | grep "Warning:" || true)
      cmod=$(echo "$CHK" | grep -c "doesn.t verify" 2>/dev/null || echo 0)
      csne=$(echo "$CHK" | grep -c "should not exist" 2>/dev/null || echo 0)
      if [[ "${cmod:-0}" -gt 0 ]]; then
        crit "$site: ${cmod} veränderte WordPress-Core-Datei(en) — Injektion/Manipulation (verify-checksums)" web
        MODLIST=$(echo "$CHK" | grep "doesn.t verify" | sed "s|.*checksum: |${CURRENT_WP_PATH}/|")
        code "$(echo "$MODLIST" | head -30)"
        CORE_INJECTED+="$MODLIST"$'\n'
        evidence "core_veraendert_$(echo "$site" | tr '/.' '__')" "$MODLIST"
      else
        ok "$site: WordPress-Core unverändert (verify-checksums)"
      fi
      if [[ "${csne:-0}" -gt 0 ]]; then
        warn "$site: ${csne} Core-fremde Datei(en) in wp-admin/wp-includes (Doorway/Backups) — prüfen"
        SNELIST=$(echo "$CHK" | grep "should not exist" | sed "s|.*exist: |${CURRENT_WP_PATH}/|")
        CORE_SNE+="$SNELIST"$'\n'
        evidence "core_fremde_dateien_$(echo "$site" | tr '/.' '__')" "$SNELIST"
      fi
    fi
    # Doorway-.htaccess-Signatur (FilesMatch erlaubt nur index.php|cache.php)
    DW=$(find "$CURRENT_WP_PATH" -name ".htaccess" -size -400c 2>/dev/null \
         | while read -r hf; do grep -qF "(index.php|cache.php)" "$hf" 2>/dev/null && dirname "$hf"; done || true)
    if [[ -n "$DW" ]]; then
      dwn=$(echo "$DW" | grep -c . || true)
      crit "$site: ${dwn} Doorway-Verzeichnis(se) (cache.php/index.php-Injector-Signatur)" web
      code "$(echo "$DW" | head -30)"
      DOORWAY_DIRS+="$DW"$'\n'
      evidence "doorway_dirs_$(echo "$site" | tr '/.' '__')" "$DW"
    else
      ok "$site: keine Doorway-.htaccess-Signatur"
    fi
    # Bootstrap-Injektion @include base64_decode() in PHP-Dateien
    CI=$(grep -rlF "include base64_decode" "$CURRENT_WP_PATH" --include="*.php" 2>/dev/null | head -40 || true)
    if [[ -n "$CI" ]]; then
      cin=$(echo "$CI" | grep -c . || true)
      crit "$site: ${cin} Datei(en) mit @include base64_decode() — getarnte Payload-Nachladung" web
      code "$(echo "$CI" | head -20)"
      CORE_INJECT_HITS+="$CI"$'\n'
      evidence "core_include_injektion_$(echo "$site" | tr '/.' '__')" "$CI"
    else
      ok "$site: keine @include base64_decode()-Injektion"
    fi

    # ── ALLE Plugins + mu-Plugins bewerten (nicht nur aktive) ──────────
    # Lehre aus einem Kundenvorfall: bösartige Plugins deaktivieren/verstecken sich
    # selbst und tauchen NICHT in active_plugins auf. Filesystem-Scan über den
    # gesamten plugins/- und mu-plugins/-Ordner (mu-Plugins laufen IMMER).
    PLUG_DIRS="$CURRENT_WP_PATH/wp-content/plugins $CURRENT_WP_PATH/wp-content/mu-plugins"
    # Ausschlüsse für die (unschärferen) Verhaltens-Signaturen — legitime Plugins,
    # die pre_user_query/wp_create_user/base64 regulär nutzen (WooCommerce-Ökosystem,
    # REST-APIs, Membership/Backup/SEO). Fake-Signatur + $_-eval brauchen das NICHT.
    PLUG_EXCL="/woocommerce/|/woocommerce-legacy-rest-api/|/woo-order-export|/woo-|/wordpress-seo|/jetpack/|/updraftplus/|/members|/user-role|/backwpup|/wordfence|/ithemes"
    # a) TIER 1 (CRIT, hohe Konfidenz): Fake-Signatur (Author: WordPress + wordpress.org/plugins)
    #    ODER direkter eval(base64_decode($_GET/POST/REQUEST/COOKIE)) — beides praktisch nie legitim.
    FAKE_PLUGINS=$(grep -rlE "^[[:space:]]*Author:[[:space:]]*WordPress[[:space:]]*$" $PLUG_DIRS --include="*.php" 2>/dev/null \
      | while read -r pf; do grep -qF "wordpress.org/plugins/" "$pf" 2>/dev/null && echo "$pf"; done || true)
    EVAL_BD=$(grep -rlE "eval\(\s*base64_decode\(\s*\\\$_(POST|GET|REQUEST|COOKIE)" $PLUG_DIRS --include="*.php" 2>/dev/null \
      | grep -viE "$PLUG_EXCL" || true)
    # File-Manager-Webshells (TinyFileManager/elFinder/FilesMan/H3K/b374k/WSO) — praktisch nie legitim im Plugin-Ordner
    FILEMGR=$(grep -rlE "tinyfilemanager|Tiny File Manager|\bFilesMan\b|elFinderConnector|H3K \||b374k|WSO[0-9. ]+shell" $PLUG_DIRS --include="*.php" 2>/dev/null \
      | grep -viE "$PLUG_EXCL|/vendor/" || true)
    SUSP_PLUG=$(printf '%s\n%s\n%s\n' "$FAKE_PLUGINS" "$EVAL_BD" "$FILEMGR" | grep -vE '^$' | sort -u || true)
    if [[ -n "$SUSP_PLUG" ]]; then
      spn=$(echo "$SUSP_PLUG" | grep -c . || true)
      crit "$site: ${spn} bösartige(s) Plugin/mu-Plugin (Fake-Signatur / eval(base64(\$_...)) / File-Manager-Webshell) — auch inaktive!" web
      code "$(echo "$SUSP_PLUG" | sed "s|$CURRENT_WP_PATH/||" | head -30)"
      SUSP_PLUGINS+="$SUSP_PLUG"$'\n'
      evidence "boesartige_plugins_$(echo "$site" | tr '/.' '__')" "$SUSP_PLUG"
    else
      ok "$site: keine bösartigen Plugins/mu-Plugins (alle bewertet, auch inaktive)"
    fi
    # b) TIER 2 (WARN, Review): Admin-Hide-/Recreation-Hooks — oft legitim (Membership),
    #    daher nur Warnung mit manueller Prüfung.
    REVIEW_PLUG=$(grep -rlE "pre_user_query|function[[:space:]]+create_admin|ensure_plugin_active" $PLUG_DIRS --include="*.php" 2>/dev/null \
      | grep -viE "$PLUG_EXCL" || true)
    # bereits als bösartig (Tier 1) gemeldete herausfiltern
    if [[ -n "$SUSP_PLUG" ]]; then
      REVIEW_PLUG=$(printf '%s\n' "$REVIEW_PLUG" | grep -vFf <(printf '%s\n' "$SUSP_PLUG") || true)
    fi
    if [[ -n "$REVIEW_PLUG" ]]; then
      warn "$site: Plugin(s) mit Admin-/Sichtbarkeits-Hooks (pre_user_query/create_admin) — Inhalt prüfen (oft legitim)" web
      code "$(echo "$REVIEW_PLUG" | sed "s|$CURRENT_WP_PATH/||" | head -20)"
      evidence "plugins_review_$(echo "$site" | tr '/.' '__')" "$REVIEW_PLUG"
    fi
    # c) mu-Plugins immer auflisten (laufen ohne Aktivierung)
    MU_LIST=$(find "$CURRENT_WP_PATH/wp-content/mu-plugins" -maxdepth 1 -name "*.php" 2>/dev/null || true)
    if [[ -n "$MU_LIST" ]]; then
      info "$site: mu-Plugins vorhanden (laufen immer — einzeln prüfen):"
      code "$(echo "$MU_LIST" | sed "s|$CURRENT_WP_PATH/||")"
      MU_PLUGINS+="$MU_LIST"$'\n'
      evidence "mu_plugins_$(echo "$site" | tr '/.' '__')" "$(echo "$MU_LIST" | xargs -r ls -la 2>/dev/null)"
    fi
    # ── Manipulierte .htaccess (Malware-Whitelist) ────────────────────
    # Malware ersetzt die .htaccess durch FilesMatch, das ALLE .php sperrt außer
    # einer Whitelist mit Webshell-Namen — blockiert legitime wp-admin-Seiten (403).
    BAD_HTA=$(find "$CURRENT_WP_PATH" -name ".htaccess" 2>/dev/null | while read -r hf; do
      grep -qE "adminfuns|chtmlfuns|classsmtps|comfunctions|postnews|schallfuns|epinyins|siteheads|hplfuns|moddofuns" "$hf" 2>/dev/null && echo "$hf"; done || true)
    if [[ -n "$BAD_HTA" ]]; then
      crit "$site: manipulierte .htaccess (Malware-Whitelist mit Webshell-Namen — bricht Admin/403)" web
      code "$(echo "$BAD_HTA" | sed "s|$CURRENT_WP_PATH/||")"
      TAMPERED_HTACCESS+="$BAD_HTA"$'\n'
      evidence "manipulierte_htaccess_$(echo "$site" | tr '/.' '__')" "$(echo "$BAD_HTA" | while read -r h; do echo "=== $h ==="; head -5 "$h"; done)"
    fi

    # Verbindungstest (nach Integritäts-Checks; wp-cli-Fallback greift jetzt)
    if ! wp_sql "$db" "$du" "$dp" "$dh" "SELECT 1;" >/dev/null 2>&1; then
      warn "$site: keine DB-Verbindung (Zugang prüfen) — DB-Abfragen übersprungen (Integrität oben wurde geprüft)"
      continue
    fi

    # a) Administrator-Konten
    ADMINS=$(wp_sql "$db" "$du" "$dp" "$dh" \
      "SELECT u.ID, u.user_login, u.user_email, u.user_registered FROM ${pfx}users u
       JOIN ${pfx}usermeta m ON u.ID=m.user_id
       WHERE m.meta_key='${pfx}capabilities' AND m.meta_value LIKE '%administrator%';")
    ADMIN_N=$(echo "$ADMINS" | grep -c . || true)
    info "Administrator-Konten: ${ADMIN_N:-0}"
    code "$ADMINS"
    WPDB_REPORT+="=== $site — Admins ($ADMIN_N) ==="$'\n'"$ADMINS"$'\n'

    # b) Kürzlich (DAYS_BACK) registrierte Admins = hochverdächtig
    NEW_ADMINS=$(wp_sql "$db" "$du" "$dp" "$dh" \
      "SELECT u.user_login, u.user_registered FROM ${pfx}users u
       JOIN ${pfx}usermeta m ON u.ID=m.user_id
       WHERE m.meta_key='${pfx}capabilities' AND m.meta_value LIKE '%administrator%'
       AND u.user_registered > DATE_SUB(NOW(), INTERVAL ${DAYS_BACK} DAY);")
    if [[ -n "$NEW_ADMINS" ]]; then
      crit "$site: Kürzlich angelegte(s) Administrator-Konto(en) — Angreifer-Verdacht" web
      code "$NEW_ADMINS"
      evidence "wpdb_neue_admins_$(echo "$site" | tr '/.' '__')" "$NEW_ADMINS"
      ROGUE_ADMINS+="=== $site ==="$'\n'"$NEW_ADMINS"$'\n'
      WPDB_FLAGS=$((WPDB_FLAGS+1))
    else
      ok "$site: keine kürzlich angelegten Admins"
    fi

    # c) siteurl / home — Redirect-Hijack
    URLS=$(wp_sql "$db" "$du" "$dp" "$dh" \
      "SELECT option_name, option_value FROM ${pfx}options WHERE option_name IN ('siteurl','home');")
    code "$URLS"
    if echo "$URLS" | grep -qiE "siteurl|home" && echo "$URLS" | grep -vqiE "$(echo "$site" | cut -d/ -f1)"; then
      # Nur Hinweis — Subdomains/CDNs möglich; nicht automatisch kritisch
      info "siteurl/home ggf. abweichend vom Domainnamen — manuell verifizieren"
    fi

    # d) Verdächtige Options: auto_prepend/append, unbekannte aktive Plugins
    SUSP_OPT=$(wp_sql "$db" "$du" "$dp" "$dh" \
      "SELECT option_name FROM ${pfx}options
       WHERE option_value LIKE '%base64_decode%' OR option_value LIKE '%eval(%'
          OR option_name LIKE '%auto_prepend%' OR option_name LIKE '%auto_append%';")
    if [[ -n "$SUSP_OPT" ]]; then
      crit "$site: verdächtige Optionen (base64/eval/auto_prepend) in ${pfx}options" web
      code "$SUSP_OPT"
      evidence "wpdb_verd_optionen_$(echo "$site" | tr '/.' '__')" "$SUSP_OPT"
      WPDB_FLAGS=$((WPDB_FLAGS+1))
    else
      ok "$site: keine verdächtigen auto_prepend/eval-Optionen"
    fi

    # e) Aktive Plugins auflisten (Abgleich mit bekannten Angriffs-Plugins)
    ACTIVE_PLUGINS=$(wp_sql "$db" "$du" "$dp" "$dh" \
      "SELECT option_value FROM ${pfx}options WHERE option_name='active_plugins';")
    if echo "$ACTIVE_PLUGINS" | grep -qiE "fileorganizer|filemanager|wp-file-manager"; then
      warn "$site: Dateimanager-Plugin aktiv (fileorganizer/filemanager) — häufiger Angriffs-Vektor, prüfen" web
    fi
    evidence "wpdb_active_plugins_$(echo "$site" | tr '/.' '__')" "$ACTIVE_PLUGINS"
  done <<< "$WP_CONFIGS"

  [[ -n "$WPDB_REPORT" ]] && evidence "wpdb_admin_uebersicht" "$WPDB_REPORT"

  h2 "11.9 WordPress-DB-Verdikt"
  if [[ "$WPDB_FLAGS" -eq 0 ]]; then
    WPDB_VERDICT="🟢 **Keine Angreifer-Spuren in den WordPress-Datenbanken** (keine neuen Admins, keine manipulierten Optionen)."
    ok "WP-DB-VERDIKT: unauffällig"
  else
    WPDB_VERDICT="🔴 **WordPress-Datenbank(en) auffällig** (${WPDB_FLAGS} Befund(e)) — fremde Admins/Optionen prüfen und bereinigen."
    crit "WP-DB-VERDIKT: ${WPDB_FLAGS} Befund(e)" web
  fi
  echo -e "\n$WPDB_VERDICT\n" >> "$REPORT_FILE"
fi

h2 "11.10 WP Toolkit — Instanz-Status (Plesk-eigene Bewertung, read-only)"
# Das Plesk WP Toolkit führt pro WordPress-Instanz Buch — u.a. ob sie als
# infiziert oder defekt gilt (es erkennt auch nicht dazugehörende Dateien).
# Wir LESEN diese Bewertung (kein Scan, keine Änderung) und melden infizierte
# Instanzen. Scope-aware über ${SCAN_PATH}; ergänzt die eigene DB-/Core-Prüfung
# um Plesks autoritative Sicht.
if command -v plesk &>/dev/null && command -v python3 &>/dev/null; then
    WPTK_JSON=$(plesk ext wp-toolkit --list -format json 2>/dev/null || true)
    WPTK_REPORT=$(SCOPE_PATH="$SCAN_PATH" VHOSTS="$VHOSTS_DIR" python3 -c '
import sys, os, json
try: d = json.loads(sys.stdin.read())
except Exception: sys.exit(0)
if not isinstance(d, list): sys.exit(0)
sp = os.environ.get("SCOPE_PATH", ""); vh = os.environ.get("VHOSTS", "/var/www/vhosts")
glob = (sp == vh or not sp)
insc = lambda x: glob or str(x.get("fullPath","")).startswith(sp)
scoped = [x for x in d if insc(x)]
inf = [x for x in scoped if x.get("infected")]
brk = [x for x in scoped if x.get("broken")]
print("INF=%d BRK=%d TOTAL=%d" % (len(inf), len(brk), len(scoped)))
for x in inf[:40]: print("INFECTED %s  %s" % (x.get("fullPath"), x.get("siteUrl","")))
' <<<"$WPTK_JSON")
    WPTK_HEAD=$(printf '%s\n' "$WPTK_REPORT" | grep '^INF=' || true)
    WPTK_INF=$(printf '%s\n' "$WPTK_REPORT" | grep '^INFECTED' || true)
    WPTK_N=$(printf '%s' "$WPTK_HEAD" | sed -E 's/^INF=([0-9]+).*/\1/')
    if [[ "${WPTK_N:-0}" -gt 0 ]]; then
        crit "WP Toolkit stuft ${WPTK_N} WordPress-Instanz(en) als infiziert ein" web
        code "$WPTK_INF"
        evidence "wptk_infected" "$WPTK_REPORT"
        WPTK_INFECTED="$WPTK_INF"
    elif [[ -n "$WPTK_HEAD" ]]; then
        ok "WP Toolkit: keine als infiziert markierten Instanzen im Scope (${WPTK_HEAD})"
    else
        info "WP Toolkit lieferte keine auswertbare Instanzliste"
    fi
else
    info "WP Toolkit / python3 nicht verfügbar — Plesk-Instanzbewertung nicht abgefragt"
fi

# ============================================================
