# shellcheck shell=bash
# NT-Forensik — Abschnitt 11: WordPress-Datenbank
#
# @nummer:  11
# @titel:   WordPress-Datenbank
# @frage:   Ist eine WordPress-Installation übernommen?
# @kosten:  HOCH mit --online — ein Prüfsummenabruf je Plugin; sonst mittel
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

# Die installierte Version eines Plugins aus dem Plugin-Kopf lesen.
# NICHT aus readme.txt: der dortige "Stable tag" ist die im Verzeichnis als
# stabil markierte Fassung, nicht die installierte. Ein Abgleich dagegen
# meldet jede veraltete Installation mit der falschen Versionsnummer.
# Der Kopf steht in der Hauptdatei — der .php im obersten Ordner, die
# "Plugin Name:" fuehrt. Auskommentierte Zeilen zu ueberspringen waere hier
# falsch: der Kopf STEHT in einem Block-Kommentar.
# sed -nE statt grep -oP, damit die Funktion auch auf dem macOS-Pruefstand
# laeuft — dieselbe Ueberlegung wie hinter datei_meta in lib/kern.sh.
wp_plugin_version() {  # $1 = Plugin-Verzeichnis; gibt "hauptdatei\tversion" aus
  local dir="$1" f ver
  for f in "$dir"/*.php; do
    [[ -f "$f" ]] || continue
    grep -qiE '^[[:space:]]*\*?[[:space:]]*Plugin Name[[:space:]]*:' "$f" 2>/dev/null || continue
    ver=$(sed -nE 's/^[[:space:]]*\*?[[:space:]]*[Vv]ersion[[:space:]]*:[[:space:]]*([^[:space:]]+).*/\1/p' "$f" 2>/dev/null | head -1)
    [[ -n "${ver:-}" ]] && { printf '%s\t%s\n' "$f" "$ver"; return 0; }
  done
  return 1
}

# Plugin-Integritaet gegen die Pruefsummen von wordpress.org.
#
# Warum nicht `wp plugin verify-checksums`: das Kommando zaehlt die Plugins
# ueber die WordPress-Laufzeit auf. Genau darueber nimmt sich ein
# manipuliertes Plugin per all_plugins-Filter selbst aus der Pruefung —
# derselbe Grund, aus dem die Signaturpruefung weiter unten den Plugin-Ordner
# direkt liest statt active_plugins zu befragen. Ausserdem deckt es weder
# mu-Plugins (checksum-command #27) noch Themes ab und gibt die
# Pruefsummendatei nicht als Beleg heraus.
#
# Netzzugriff nur mit --online, protokolliert ueber nf_fetch. Ein Aufruf von
# python3 je Installation, nicht je Datei.
wp_plugin_integritaet() {  # $1 = site-Label
  local site="$1" pdir slug rel ver liste ergebnis cachedir ziel
  local n_mod n_soft n_extra n_unver n_geprueft n_fehlt
  [[ -d "${CURRENT_WP_PATH}/wp-content/plugins" ]] || return 0

  cachedir="${RUN_DIR}/.online/plugin-checksums"
  mkdir -p "$cachedir"
  liste=$(mktemp "${RUN_DIR}/.wpint.XXXXXX")

  for pdir in "${CURRENT_WP_PATH}"/wp-content/plugins/*/; do
    [[ -d "$pdir" ]] || continue
    pdir="${pdir%/}"
    slug=$(basename "$pdir")
    if ! rel=$(wp_plugin_version "$pdir"); then
      WP_PLUGIN_UNVERIFIABLE+="${site}/${slug}"$'\t'"keine Version im Plugin-Kopf"$'\n'
      continue
    fi
    ver="${rel##*$'\t'}"
    ziel="${cachedir}/${slug}-${ver}.json"
    if [[ ! -s "$ziel" ]] \
       && ! nf_fetch "https://downloads.wordpress.org/plugin-checksums/${slug}/${ver}.json" "$ziel"; then
      rm -f "$ziel"
      # Kein Pruefsummensatz. Zwei Ursachen, hier nicht unterscheidbar: das
      # Plugin liegt nicht im wordpress.org-Verzeichnis (Premium, Fork,
      # Eigenbau), oder die Fassung ist dort nicht veroeffentlicht. Beides
      # heisst: nicht messbar — nicht: unauffaellig.
      WP_PLUGIN_UNVERIFIABLE+="${site}/${slug} ${ver}"$'\t'"kein Prüfsummensatz bei wordpress.org"$'\n'
      continue
    fi
    printf '%s\t%s\t%s\t%s\n' "$slug" "$ver" "$pdir" "$ziel" >> "$liste"
  done

  if [[ ! -s "$liste" ]]; then rm -f "$liste"; return 0; fi

  ergebnis=$(python3 - "$liste" <<'PY' 2>/dev/null || true
import hashlib, json, os, sys

# Als Code gewertete Endungen. Eine Abweichung darin ist eine Codeaenderung am
# ausgelieferten Plugin und damit ein kritischer Befund; alles andere
# (readme.txt, Uebersetzungen, Stilvorlagen, Bilder) ist eine weiche
# Abweichung. wp-cli zieht dieselbe Grenze ueber seinen --strict-Schalter.
CODE = {".php", ".phtml", ".php5", ".php7", ".inc", ".js", ".mjs"}

def passt(soll, ist_md5, ist_sha):
    # Das Format erlaubt je Datei MEHRERE gueltige Pruefsummen (Whitelist).
    # Ein 1:1-Vergleich wuerde hier Falsch-Positive erzeugen.
    for schluessel, ist in (("md5", ist_md5), ("sha256", ist_sha)):
        wert = soll.get(schluessel)
        if wert is None:
            continue
        kandidaten = wert if isinstance(wert, list) else [wert]
        if any(str(k).lower() == ist for k in kandidaten):
            return True
    return False

for zeile in open(sys.argv[1], encoding="utf-8", errors="replace").read().splitlines():
    teile = zeile.split("\t")
    if len(teile) != 4:
        continue
    slug, ver, pdir, jsondatei = teile
    try:
        with open(jsondatei, encoding="utf-8", errors="replace") as fh:
            soll_dateien = (json.load(fh) or {}).get("files") or {}
    except Exception:
        print("\t".join(["UNVER", slug, ver, "Prüfsummendatei nicht lesbar"]))
        continue
    if not soll_dateien:
        print("\t".join(["UNVER", slug, ver, "Prüfsummendatei ohne Dateiliste"]))
        continue

    gesehen = set()
    for wurzel, _dirs, dateien in os.walk(pdir):
        for name in dateien:
            voll = os.path.join(wurzel, name)
            if os.path.islink(voll):
                continue
            rel = os.path.relpath(voll, pdir)
            gesehen.add(rel)
            soll = soll_dateien.get(rel)
            if soll is None:
                # Nicht im Pruefsummensatz. Nur PHP ist erwaehnenswert — alles
                # andere sind ueberwiegend Zwischenspeicher und Protokolle.
                if os.path.splitext(name)[1].lower() in CODE:
                    print("\t".join(["EXTRA", slug, ver, rel]))
                continue
            try:
                with open(voll, "rb") as fh:
                    roh = fh.read()
            except Exception:
                continue
            if not passt(soll, hashlib.md5(roh).hexdigest(),
                               hashlib.sha256(roh).hexdigest()):
                art = "MOD" if os.path.splitext(name)[1].lower() in CODE else "SOFT"
                print("\t".join([art, slug, ver, rel]))

    for rel in sorted(set(soll_dateien) - gesehen):
        print("\t".join(["FEHLT", slug, ver, rel]))

    print("\t".join(["GEPRUEFT", slug, ver, str(len(soll_dateien))]))
PY
  )
  rm -f "$liste"

  n_geprueft=$(printf '%s\n' "$ergebnis" | grep -c '^GEPRUEFT' || true)
  n_mod=$(printf   '%s\n' "$ergebnis" | grep -c '^MOD'    || true)
  n_soft=$(printf  '%s\n' "$ergebnis" | grep -c '^SOFT'   || true)
  n_extra=$(printf '%s\n' "$ergebnis" | grep -c '^EXTRA'  || true)
  n_unver=$(printf '%s\n' "$ergebnis" | grep -c '^UNVER'  || true)
  n_fehlt=$(printf '%s\n' "$ergebnis" | grep -c '^FEHLT'  || true)
  WP_PLUGIN_CHECKED=$((WP_PLUGIN_CHECKED + ${n_geprueft:-0}))

  if [[ "${n_mod:-0}" -gt 0 ]]; then
    local liste_mod
    liste_mod=$(printf '%s\n' "$ergebnis" | awk -F'\t' -v p="${CURRENT_WP_PATH}/wp-content/plugins/" \
                '$1=="MOD"{print p $2 "/" $4}')
    crit "$site: ${n_mod} veränderte Plugin-Codedatei(en) gegenüber wordpress.org — Injektion prüfen" web
    code "$(printf '%s\n' "$liste_mod" | head -30)"
    WP_PLUGIN_MODIFIED+="$liste_mod"$'\n'
    WP_INTEGRITY_FLAGS=$((WP_INTEGRITY_FLAGS+1))
    # Steckbrief statt blosser Pfadliste: Groesse, Aenderungszeit und SHA256
    # sind das, was eine Neuinstallation spaeter belegbar macht.
    local _sb=""
    while IFS= read -r _md; do
      [[ -n "$_md" && -r "$_md" ]] || continue
      _sb+=$(datei_steckbrief "Prüfsumme weicht von der Fassung auf wordpress.org ab" \
                              '<\?php|eval|base64_decode' "$_md")$'\n'
    done <<< "$(printf '%s\n' "$liste_mod" | head -20)"
    evidence "wp_plugin_veraendert_$(echo "$site" | tr '/.' '__')" "${_sb:-$liste_mod}"
  fi

  if [[ "${n_soft:-0}" -gt 0 ]]; then
    warn "$site: ${n_soft} veränderte Nicht-Codedatei(en) in Plugins (readme, Übersetzungen, Stilvorlagen) — meist harmlos, im Zweifel prüfen"
    WP_PLUGIN_SOFT+="$(printf '%s\n' "$ergebnis" | awk -F'\t' -v p="${CURRENT_WP_PATH}/wp-content/plugins/" \
                       '$1=="SOFT"{print p $2 "/" $4}')"$'\n'
  fi

  if [[ "${n_extra:-0}" -gt 0 ]]; then
    # Vorerst nur Hinweis: Plugins legen auch legitim PHP an (Zwischenspeicher,
    # index.php-Wachen). Erst nach Messung an echten Installationen hochstufen.
    info "$site: ${n_extra} PHP-Datei(en) in Plugin-Ordnern ohne Eintrag im Prüfsummensatz — Übersicht im Beleg"
    WP_PLUGIN_EXTRA_PHP+="$(printf '%s\n' "$ergebnis" | awk -F'\t' -v p="${CURRENT_WP_PATH}/wp-content/plugins/" \
                            '$1=="EXTRA"{print p $2 "/" $4}')"$'\n'
    evidence "wp_plugin_zusatz_php_$(echo "$site" | tr '/.' '__')" \
             "$(printf '%s\n' "$ergebnis" | awk -F'\t' '$1=="EXTRA"{print $2 "/" $4}')"
  fi

  if [[ "${n_fehlt:-0}" -gt 0 ]]; then
    warn "$site: ${n_fehlt} im Prüfsummensatz geführte Plugin-Datei(en) fehlen auf der Platte"
    evidence "wp_plugin_fehlende_dateien_$(echo "$site" | tr '/.' '__')" \
             "$(printf '%s\n' "$ergebnis" | awk -F'\t' '$1=="FEHLT"{print $2 "/" $4}')"
  fi

  if [[ "${n_unver:-0}" -gt 0 ]]; then
    WP_PLUGIN_UNVERIFIABLE+="$(printf '%s\n' "$ergebnis" | awk -F'\t' -v s="$site" \
                              '$1=="UNVER"{print s "/" $2 " " $3 "\t" $4}')"$'\n'
  fi

  if [[ "${n_mod:-0}" -eq 0 && "${n_geprueft:-0}" -gt 0 ]]; then
    ok "$site: ${n_geprueft} Plugin(s) gegen wordpress.org geprüft — keine veränderte Codedatei"
  fi
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

  # wpconf_get und das Praefix-Auslesen brauchen grep mit PCRE (-P). Fehlt die
  # Unterstuetzung — busybox-grep, BSD-grep, manche Minimal-Container —,
  # liefern beide leer, und die Schleife ueberspringt jede Installation mit
  # '[[ -z "$db" ]] && continue' vollstaendig lautlos. Ein Server mit 40
  # Instanzen haette dann einen Bericht ohne eine einzige Datenbankpruefung und
  # ohne Hinweis darauf.
  # Die Pruefung steht bewusst HIER und nicht am Modulanfang: ohne gefundene
  # wp-config.php gibt es nichts zu lesen, und ein ⚪ waere dann selbst falsch —
  # ein unberechtigtes "nicht messbar" blockiert die gruene Ampel genauso
  # unberechtigt, wie ein falsches ✅ sie freigibt.
  if ! echo "x" | grep -qoP 'x' 2>/dev/null; then
    unklar "grep ohne PCRE-Unterstützung (-P) — Zugangsdaten aus wp-config.php nicht lesbar, keine Datenbank-Prüfung möglich" web
    WPDB_VERDICT="⚪ Datenbank-Prüfung nicht möglich: grep beherrscht kein -P (PCRE)."
  fi

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
    # Vor der Messung eine Probe. Ohne sie war der haeufigste Ausgang dieses
    # Blocks eine Falschaussage: scheitert wp-cli (fehlendes PHP, kein sudo,
    # falscher Eigentuemer), ist CHK leer, cmod=0, und der Bericht bescheinigt
    # einen unveraenderten Kern, der nie geprueft wurde. 'core version' ist die
    # billigste Abfrage, deren Antwort sich pruefen laesst — sie muss mit einer
    # Versionsnummer beginnen. Vorbild: Abschnitt 12c fuer occ.
    _wp_bereit=0
    if [[ -z "$WP_CLI" ]]; then
      unklar "$site: wp-cli nicht installiert — Kern-Integrität nicht geprüft" web
    elif [[ -z "$PHP_BIN" ]]; then
      unklar "$site: kein PHP-Interpreter gefunden — Kern-Integrität nicht geprüft" web
    else
      _wpv=$(wp_cli core version | tr -d '\r' | head -1)
      if [[ "$_wpv" =~ ^[0-9]+\.[0-9]+ ]]; then
        _wp_bereit=1
        info "$site: WordPress ${_wpv} (wp-cli antwortet)"
      else
        unklar "$site: wp-cli liefert keine verwertbare Antwort — Kern-Integrität nicht geprüft${_wpv:+ (${_wpv:0:80})}" web
      fi
    fi

    if [[ "$_wp_bereit" -eq 1 ]]; then
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

    # ── Plugin-Integrität gegen wordpress.org ─────────────────────────
    # Findet veränderte Dateien, nicht nur veraltete Fassungen. Für eine
    # Forensik ist das die stärkere Aussage: eine alte Version ist ein Risiko,
    # eine veränderte Plugin-Datei ist ein Befund.
    #
    # Ohne --online ein info und kein ⚪: der Betreiber hat die Netzabfrage
    # bewusst nicht angefordert, das ist eine Entscheidung über den Prüfumfang
    # und keine gescheiterte Messung. Dieselbe Linie zieht Abschnitt 7 beim
    # abgeschalteten YARA-Scan. Das ⚪ kommt in 11.8 — dort, wo eine
    # angeforderte Messung ohne Ergebnis blieb.
    if [[ "${WANT_ONLINE:-0}" != "1" ]]; then
      info "$site: Plugin-Integrität nicht geprüft — die Prüfsummen von wordpress.org brauchen --online"
      WP_PLUGIN_SKIPPED=$((WP_PLUGIN_SKIPPED+1))
    elif ! werkzeug_da python3; then
      unklar "$site: python3 fehlt — Plugin-Integrität nicht prüfbar" web
      WP_PLUGIN_SKIPPED=$((WP_PLUGIN_SKIPPED+1))
    else
      wp_plugin_integritaet "$site"
    fi

    # Themes haben KEINE Prüfsummenquelle: downloads.wordpress.org führt nur
    # plugin-checksums, einen theme-checksums-Pfad gibt es nicht (HTTP 404,
    # nachgeprüft am 06.08.2026). Das gehört ausgesprochen, sonst liest sich
    # die fehlende Prüfung wie eine bestandene.
    THEME_LIST=$(find "${CURRENT_WP_PATH}/wp-content/themes" -maxdepth 1 -mindepth 1 -type d 2>/dev/null || true)
    if [[ -n "$THEME_LIST" ]]; then
      WP_THEMES_UNVERIFIABLE+="$THEME_LIST"$'\n'
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
      # Beleg mit Fundstelle statt blosser Pfadliste. Welche der drei
      # Signaturgruppen angeschlagen hat, entscheidet ueber die Bewertung:
      # eine Fake-Signatur ist praktisch beweisend, ein elFinder-Treffer kann
      # auch die mitgelieferte Bibliothek eines echten Dateimanager-Plugins
      # sein. Ohne diese Angabe ist der Befund nicht bewertbar.
      _steckbriefe=""
      while IFS= read -r _pf; do
        [[ -n "$_pf" && -r "$_pf" ]] || continue
        if grep -qF "$_pf" <<<"$FAKE_PLUGINS" 2>/dev/null; then
          _steckbriefe+=$(datei_steckbrief \
            "Gefaelschte Plugin-Signatur (Author: WordPress + Verweis auf wordpress.org/plugins) — praktisch nie legitim" \
            "^[[:space:]]*Author:[[:space:]]*WordPress|wordpress\.org/plugins/" "$_pf")$'\n'
        elif grep -qF "$_pf" <<<"$EVAL_BD" 2>/dev/null; then
          _steckbriefe+=$(datei_steckbrief \
            "eval(base64_decode(\$_GET/POST/REQUEST/COOKIE)) — Ausfuehrung von Angreifereingaben, nie legitim" \
            "eval\(\s*base64_decode\(\s*\\\$_(POST|GET|REQUEST|COOKIE)" "$_pf")$'\n'
        else
          _steckbriefe+=$(datei_steckbrief \
            "Dateimanager-/Webshell-Signatur. ACHTUNG: elFinder und TinyFileManager werden auch von legitimen Plugins mitgeliefert (z. B. wp-file-manager) — Plugin-Herkunft und Fassung pruefen, bevor bewertet wird" \
            "tinyfilemanager|Tiny File Manager|\bFilesMan\b|elFinderConnector|H3K \||b374k|WSO[0-9. ]+shell" "$_pf")$'\n'
        fi
      done <<< "$SUSP_PLUG"
      evidence "boesartige_plugins_$(echo "$site" | tr '/.' '__')" \
        "Bewertete Verzeichnisse: ${PLUG_DIRS}

${_steckbriefe}
Hinweis zur Bewertung: eine gefaelschte Plugin-Signatur oder ein
eval(base64_decode(\$_...)) sind fuer sich genommen belastend. Ein Treffer auf
eine Dateimanager-Bibliothek ist es NICHT — dort entscheidet, ob das Plugin
regulaer installiert wurde und ob die getroffenen Dateien dasselbe
Aenderungsdatum tragen wie der Rest des Plugins."
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

    # Verbindungstest (nach Integritäts-Checks; wp-cli-Fallback greift jetzt).
    # Fehlender mysql-Client und falsche Zugangsdaten wurden bisher beide als
    # warn gemeldet — dabei ist das eine ein Werkzeugproblem des Pruefenden und
    # das andere moeglicherweise ein Befund. Der Bericht muss das trennen:
    # ohne Client wurde die Datenbank nicht geprueft, mit Client und ohne
    # Zugang stimmen die hinterlegten Zugangsdaten nicht.
    if ! werkzeug_da mysql && [[ -z "$WP_CLI" ]]; then
      unklar "$site: weder mysql-Client noch wp-cli vorhanden — Datenbank nicht geprüft" web
      continue
    fi
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
      ok "$site: keine kürzlich angelegten Admins (Alterskriterium)"
    fi

    # c) Namens- und Adressmuster über ALLE Admins, unabhängig vom Alter.
    # Das Alterskriterium allein hat auf einem echten Kundensystem versagt:
    # "adminbackup <adminbackup@wordpress.org>" war 13 Monate alt und wurde
    # deshalb nicht gemeldet — der Bericht gab an dieser Stelle Entwarnung.
    # Ein Angreifer, der lange unentdeckt bleibt, ist nicht harmloser.
    #
    # Die Treffer landen NICHT in ROGUE_ADMINS. Dort stehen Konten, deren
    # Anlagezeitpunkt sie belastet; ein Namensmuster ist ein Verdacht, kein
    # Beweis. Ein Werkzeug, das daraufhin automatisch Konten entfernt, würde
    # irgendwann den Betreiber aussperren, der sein Konto "wpservice" nennt.
    MATCH_CRIT=$(echo "$ADMINS" | awk -F'\t' 'NF>=3 {print}' \
      | awk -F'\t' -v l="$WP_ADMIN_LOGIN_CRIT" -v m="$WP_ADMIN_MAIL_CRIT" \
          'tolower($2) ~ l || tolower($3) ~ m {print}' || true)
    MATCH_WARN=$(echo "$ADMINS" | awk -F'\t' 'NF>=3 {print}' \
      | awk -F'\t' -v l="$WP_ADMIN_LOGIN_WARN" -v m="$WP_ADMIN_MAIL_WARN" \
          'tolower($2) ~ l || tolower($3) ~ m {print}' || true)
    # Was Stufe 1 schon belastet, muss Stufe 2 nicht zusätzlich melden.
    [[ -n "$MATCH_CRIT" ]] && MATCH_WARN=$(comm -23 <(sort <<<"$MATCH_WARN") <(sort <<<"$MATCH_CRIT") | grep -vE '^$' || true)

    if [[ -n "$MATCH_CRIT" ]]; then
      crit "$site: Administrator-Konto mit angreifertypischem Namen oder erfundener Adresse — unabhängig vom Alter prüfen" web
      code "$MATCH_CRIT"
      evidence "wpdb_admin_muster_$(echo "$site" | tr '/.' '__')" \
        "Kriterium Login: ${WP_ADMIN_LOGIN_CRIT}
Kriterium Mail:  ${WP_ADMIN_MAIL_CRIT}

Treffer (ID / Login / Mail / registriert):
${MATCH_CRIT}"
      SUSPECT_ADMINS+="=== $site ==="$'\n'"$MATCH_CRIT"$'\n'
      WPDB_FLAGS=$((WPDB_FLAGS+1))
    elif [[ -n "$MATCH_WARN" ]]; then
      warn "$site: Administrator-Konto mit auffälligem Namensmuster — erklärbar, aber prüfen"
      code "$MATCH_WARN"
      SUSPECT_ADMINS+="=== $site (nur Hinweis) ==="$'\n'"$MATCH_WARN"$'\n'
    else
      ok "$site: kein Administrator-Konto mit angreifertypischem Namen oder erfundener Adresse"
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

  h2 "11.8 Plugin-Integrität — Zusammenfassung"
  # Der Abschnitt sagt ausdrücklich, worauf sich das Urteil stützt und was
  # ungeprüft blieb. Ein Bericht, in dem nur die Treffer stehen, lässt die
  # Lücken wie Entwarnung aussehen.
  #
  # Das ⚪ wird BEWUSST zu EINEM Befund je Lauf zusammengefasst, nicht je
  # Plugin gemeldet. Premium- und Eigenbau-Plugins gibt es auf fast jeder
  # Kundenseite; ein ⚪ pro Stück würde die Kundenampel dauerhaft blockieren
  # und den vierten Zustand zu Rauschen machen, das niemand mehr liest.
  n_pmod=$(printf '%s\n' "${WP_PLUGIN_MODIFIED:-}"     | grep -c . || true)
  n_punv=$(printf '%s\n' "${WP_PLUGIN_UNVERIFIABLE:-}" | grep -c . || true)
  n_tunv=$(printf '%s\n' "${WP_THEMES_UNVERIFIABLE:-}" | grep -c . || true)
  if [[ "${WANT_ONLINE:-0}" != "1" ]]; then
    WP_INTEGRITY_VERDICT="⚪ **Plugin-Integrität nicht geprüft** — der Abgleich gegen die Prüfsummen von wordpress.org verlangt \`--online\`."
    info "Plugin-Integrität nicht geprüft (ohne --online) — kein Ergebnis, weder gut noch schlecht"
  else
    info "Geprüfte Plugins: ${WP_PLUGIN_CHECKED:-0} · veränderte Codedateien: ${n_pmod:-0} · ohne Prüfsummensatz: ${n_punv:-0} · Themes ohne Prüfsummenquelle: ${n_tunv:-0}"
    if [[ "${n_punv:-0}" -gt 0 || "${n_tunv:-0}" -gt 0 ]]; then
      unklar "Unversehrtheit von ${n_punv} Plugin(s) und ${n_tunv} Theme(s) nicht feststellbar — für sie veröffentlicht wordpress.org keine Prüfsummen (Premium, Fork, Eigenbau; Themes grundsätzlich)" web
      [[ -n "${WP_PLUGIN_UNVERIFIABLE:-}" ]] && evidence "wp_plugin_nicht_messbar" "${WP_PLUGIN_UNVERIFIABLE}"
    fi
    if [[ "${n_pmod:-0}" -gt 0 ]]; then
      WP_INTEGRITY_VERDICT="🔴 **${n_pmod} veränderte Plugin-Codedatei(en)** gegenüber den Prüfsummen von wordpress.org. Betroffene Plugins neu installieren, veränderte Dateien vorher sichern."
    elif [[ "${WP_PLUGIN_CHECKED:-0}" -eq 0 ]]; then
      # Grün setzt einen Nenner voraus. Wurde kein einziges Plugin verglichen,
      # ist "keine veränderte Datei" eine Aussage über die leere Menge — und
      # liest sich trotzdem wie eine bestandene Prüfung. Der Fall tritt real
      # ein: die Schleife bricht oberhalb per `continue` ab, wenn sich die
      # Zugangsdaten aus wp-config.php nicht lesen lassen, und erreicht die
      # Integritätsprüfung dann gar nicht.
      WP_INTEGRITY_VERDICT="⚪ **Plugin-Integrität ohne Ergebnis** — trotz \`--online\` wurde kein Plugin verglichen. Mögliche Ursache: die Installation wurde vor der Prüfung übersprungen (wp-config.php nicht lesbar) oder es ist kein Plugin vorhanden."
      unklar "Plugin-Integrität angefordert, aber kein Plugin verglichen — kein Ergebnis" web
    else
      WP_INTEGRITY_VERDICT="🟢 **Keine veränderte Plugin-Codedatei** in ${WP_PLUGIN_CHECKED} geprüften Plugins. Nicht geprüft: ${n_punv} Plugin(s) ohne Prüfsummensatz, ${n_tunv} Theme(s), sowie alle mu-Plugins — für diese ist das keine Entwarnung."
    fi
  fi
  echo -e "\n$WP_INTEGRITY_VERDICT\n" >> "$REPORT_FILE"

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