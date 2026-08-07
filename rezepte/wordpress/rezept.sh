# shellcheck shell=bash
# ============================================================
# NT-Forensik — Prüfrezept WordPress: die Haken
# ------------------------------------------------------------
# Nur das, was der Rahmen nicht kann. Finden, Kopienfilter, Selbstausschluss,
# Werkzeug-Probe, Signaturen, Datenbankzugang samt Präfix-Härtung und Verdikt
# macht lib/rezepte.sh.
#
# Ersetzt module/11_wordpress.sh (425 Zeilen). Drei Dinge, die dort fehlten,
# leistet jetzt der Rahmen — nicht dieses Rezept:
#
#   Sicherungskopien filtern   fehlte ganz
#   Selbstausschluss           fehlte
#   Präfix-Härtung             fehlte; Joomla hatte sie seit jeher
#
# Aufgerufen wird je Installation mit $REZ_PFAD, $REZ_KURZ; nach
# rezept_db_zugang zusätzlich $REZ_DB, $REZ_PFX und die Funktion rezept_sql.
# ============================================================

# wp-cli wird als Eigentümer der Installation ausgeführt (Plesk-tauglich).
_wp() {
  local owner; owner=$(datei_meta "${REZ_PFAD}/wp-config.php" eigner)
  owner="${owner%%:*}"; owner="${owner:-root}"
  sudo -u "$owner" "$REZ_PHP" "$REZ_WERKZEUG" "$@" \
       --path="$REZ_PFAD" --skip-plugins --skip-themes 2>/dev/null
}
REZ_CLI_SQL="_wp db query --skip-column-names"

# ── Kern-Integrität und die Doorway-Familie ──────────────────
# Der Signatur-Webshell-Scan übersieht goto-obfuskierte Doorways, als Nicht-PHP
# getarnte Nutzlasten und @include-Injektionen. verify-checksums plus
# Doorway-Signatur decken die Familie auf.
#
# Die Werkzeug-Probe hat der Rahmen gezogen; eine leere Ausgabe heißt hier
# wirklich 'keine Abweichung' und nicht 'wp-cli ist gescheitert'.
rezept_kern() {
  local CHK cmod csne LISTE
  CHK=$(_wp core verify-checksums 2>&1 | grep "Warning:" || true)
  cmod=$(echo "$CHK" | grep -c "doesn.t verify" 2>/dev/null || echo 0)
  csne=$(echo "$CHK" | grep -c "should not exist" 2>/dev/null || echo 0)

  if [[ "${cmod:-0}" -gt 0 ]]; then
    LISTE=$(echo "$CHK" | grep "doesn.t verify" | sed "s|.*checksum: |${REZ_PFAD}/|")
    befund_melden wordpress kern crit "${REZ_KURZ}: ${cmod} veränderte Core-Datei(en) — Injektion oder Manipulation" "$REZ_PFAD" web
    code "$(echo "$LISTE" | head -30)"
    evidence "wp_core_veraendert_$(echo "$REZ_KURZ" | tr '/.' '__')" "$LISTE"
  else
    befund_melden wordpress kern ok "${REZ_KURZ}: WordPress-Core unverändert (verify-checksums)" "$REZ_PFAD"
  fi

  if [[ "${csne:-0}" -gt 0 ]]; then
    LISTE=$(echo "$CHK" | grep "should not exist" | sed "s|.*exist: |${REZ_PFAD}/|")
    befund_melden wordpress kern warn "${REZ_KURZ}: ${csne} Core-fremde Datei(en) in wp-admin/wp-includes — prüfen" "$REZ_PFAD" web
    evidence "wp_core_fremd_$(echo "$REZ_KURZ" | tr '/.' '__')" "$LISTE"
  fi
}

# ── Dateibasierte Merkmale ───────────────────────────────────
rezept_sonder() {
  # Doorway-.htaccess: eine FilesMatch-Regel, die nur index.php und cache.php
  # zulässt. Kleine Datei, eindeutige Signatur.
  local DW
  DW=$(find "$REZ_PFAD" -name ".htaccess" -size -400c 2>/dev/null \
       | while read -r hf; do grep -qF "(index.php|cache.php)" "$hf" 2>/dev/null && dirname "$hf"; done || true)
  if [[ -n "$DW" ]]; then
    befund_melden wordpress schadcode crit "${REZ_KURZ}: $(echo "$DW" | grep -c .) Doorway-Verzeichnis(se) (cache.php/index.php-Signatur)" "$(echo "$DW" | head -1)" web
    code "$(echo "$DW" | head -30)"
  else
    befund_melden wordpress schadcode ok "${REZ_KURZ}: keine Doorway-.htaccess-Signatur" "$REZ_PFAD"
  fi

  # Bootstrap-Injektion: @include base64_decode() lädt die Nutzlast bei jedem
  # Seitenaufruf nach, ohne dass im Code etwas Auffälliges steht.
  local CI
  CI=$(grep -rlF "include base64_decode" "$REZ_PFAD" --include="*.php" 2>/dev/null | head -40 || true)
  if [[ -n "$CI" ]]; then
    befund_melden wordpress schadcode crit "${REZ_KURZ}: $(echo "$CI" | grep -c .) Datei(en) mit @include base64_decode() — getarnte Payload-Nachladung" "$(echo "$CI" | head -1)" web
    code "$(echo "$CI" | head -20)"
    evidence "wp_include_injektion_$(echo "$REZ_KURZ" | tr '/.' '__')" "$CI"
  else
    befund_melden wordpress schadcode ok "${REZ_KURZ}: keine @include base64_decode()-Injektion" "$REZ_PFAD"
  fi

  # mu-Plugins laufen IMMER, ohne Aktivierung und ohne in der Pluginliste zu
  # erscheinen. Bösartige Plugins deaktivieren oder verstecken sich selbst und
  # tauchen deshalb nicht in active_plugins auf — geprüft wird das Dateisystem.
  local MU
  MU=$(find "${REZ_PFAD}/wp-content/mu-plugins" -maxdepth 1 -name '*.php' 2>/dev/null | head -20 || true)
  if [[ -n "$MU" ]]; then
    befund_melden wordpress schadcode warn "${REZ_KURZ}: $(echo "$MU" | grep -c .) mu-Plugin(s) — laufen ohne Aktivierung und erscheinen in keiner Pluginliste" "$(echo "$MU" | head -1)" web
    code "$MU"
  fi

  # Manipulierte .htaccess mit Freigabeliste. Abschnitt 13b prüft das
  # gründlicher und für jede Anwendung; hier bleibt der schnelle Namensabgleich,
  # weil er ohne Einordnung auskommt.
  local BAD
  BAD=$(find "$REZ_PFAD" -name ".htaccess" 2>/dev/null | while read -r hf; do
          grep -qE "adminfuns|chtmlfuns|classsmtps|comfunctions|postnews|schallfuns|epinyins|siteheads|hplfuns|moddofuns" "$hf" 2>/dev/null && echo "$hf"; done || true)
  if [[ -n "$BAD" ]]; then
    befund_melden wordpress schadcode crit "${REZ_KURZ}: manipulierte .htaccess (Freigabeliste mit Webshell-Namen)" "$(echo "$BAD" | head -1)" web
    code "$(echo "$BAD" | sed "s|${REZ_PFAD}/||")"
  fi
}

# ── Datenbank ────────────────────────────────────────────────
# Read-only, ausschließlich SELECT. Der Rahmen hat den Zugang aufgebaut und
# das Präfix gehärtet — ohne diese Härtung ging der Wert aus wp-config.php roh
# in die Abfragen, und wer die Datei schreiben kann, bekam damit beliebiges SQL
# in ein Werkzeug, das als root läuft.
rezept_db() {
  if ! werkzeug_da mysql && [[ -z "${REZ_WERKZEUG:-}" ]]; then
    befund_melden wordpress datenbank unklar "${REZ_KURZ}: weder mysql-Client noch wp-cli vorhanden — Datenbank nicht geprüft" "$REZ_PFAD" web
    return 0
  fi
  rezept_db_zugang "${REZEPT_DIR}/wordpress" "${REZ_PFAD}/wp-config.php" || return 0
  if ! rezept_sql "SELECT 1;" >/dev/null 2>&1; then
    befund_melden wordpress datenbank warn "${REZ_KURZ}: keine DB-Verbindung (Zugang prüfen) — Datenbankabfragen übersprungen" "${REZ_PFAD}/wp-config.php" web
    return 0
  fi

  # a) Kürzlich angelegte Administratoren. Der eindeutigste Einzelbefund: ein
  # Admin, der erst nach dem Vorfall entstand, ist praktisch nie legitim.
  local NEU
  NEU=$(rezept_sql "SELECT u.user_login, u.user_email, u.user_registered FROM ${REZ_PFX}users u
         JOIN ${REZ_PFX}usermeta m ON u.ID=m.user_id
         WHERE m.meta_key='${REZ_PFX}capabilities' AND m.meta_value LIKE '%administrator%'
         AND u.user_registered > DATE_SUB(NOW(), INTERVAL ${DAYS_BACK} DAY);")
  if [[ -n "$NEU" ]]; then
    befund_melden wordpress datenbank crit "${REZ_KURZ}: kürzlich angelegte(s) Administrator-Konto(en) — Angreifer-Verdacht" "$REZ_PFAD" web
    code "$NEU"
    evidence "wp_neue_admins_$(echo "$REZ_KURZ" | tr '/.' '__')" "$NEU"
  else
    befund_melden wordpress datenbank ok "${REZ_KURZ}: keine kürzlich angelegten Administratoren" "$REZ_PFAD"
  fi

  # b) Admins mit angreifertypischem Namen oder Adresse. Bewusst getrennt vom
  # Befund oben: das ist ein Verdacht, kein Beleg — eine automatische
  # Bereinigung darf diese Konten nie anfassen.
  local VERDACHT
  VERDACHT=$(rezept_sql "SELECT u.user_login, u.user_email FROM ${REZ_PFX}users u
              JOIN ${REZ_PFX}usermeta m ON u.ID=m.user_id
              WHERE m.meta_key='${REZ_PFX}capabilities' AND m.meta_value LIKE '%administrator%'
              AND (u.user_login REGEXP '${WP_ADMIN_LOGIN_CRIT:-^(wpadmin|admin[0-9]+)$}'
                OR u.user_email REGEXP '${WP_ADMIN_MAIL_CRIT:-@(mail\\\\.ru|yandex)}');")
  if [[ -n "$VERDACHT" ]]; then
    befund_melden wordpress datenbank warn "${REZ_KURZ}: Administrator mit angreifertypischem Namen oder Adresse — Verdacht, kein Beleg" "$REZ_PFAD" web
    code "$VERDACHT"
  fi

  # c) Manipulierte Optionen. siteurl/home weisen auf einen Redirect-Hijack,
  # auto_prepend_file auf eine dauerhaft nachgeladene Nutzlast.
  local OPT
  OPT=$(rezept_sql "SELECT option_name, LEFT(option_value,120) FROM ${REZ_PFX}options
         WHERE option_name IN ('siteurl','home')
            OR option_value LIKE '%auto_prepend_file%'
            OR option_value LIKE '%base64_decode%';")
  [[ -n "$OPT" ]] && { info "${REZ_KURZ}: Optionen (siteurl/home und Auffälligkeiten):"; code "$OPT"; }
}

# ── Verdikt ──────────────────────────────────────────────────
rezept_verdikt() {
  local n; n=$(printf '%s' "${BEFUNDE:-}" | grep -c $'^wordpress\t.*\tcrit\t' || true)
  if [[ "${n:-0}" -gt 0 ]]; then
    verdikt_melden wordpress "$n" "🔴 ${n} kritische WordPress-Befunde — Kompromittierung belegt oder dringend abzuklären."
  elif printf '%s' "${UNKNOWN_LIST:-}" | grep -q 'wordpress\|WordPress\|Datenbank nicht geprüft'; then
    verdikt_melden wordpress 0 "⚪ WordPress teilweise nicht prüfbar — kein Befund, aber auch keine Entwarnung."
  else
    verdikt_melden wordpress 0 "🟢 Keine Angreifer-Spuren in den WordPress-Installationen."
  fi
}
