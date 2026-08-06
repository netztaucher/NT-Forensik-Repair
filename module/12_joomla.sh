# NT-Forensik — Abschnitt 12: Joomla-Prüfung
#
# @nummer:  12
# @titel:   Joomla-Prüfung
# @frage:   Ist eine Joomla-Installation angreifbar oder übernommen?
# @kosten:  mittel — Prüfsummen etwa 4 s je Installation
# @ebene:   website
#
# Wird vom Runner eingebunden, nicht einzeln ausgefuehrt.
# Vorgabewerte der hier gefuellten Variablen: lib/befunde.sh

h1 "12. JOOMLA-PRÜFUNG"
# ============================================================
# Joomla-Pendant zu Abschnitt 11. Findet Joomla-Installationen, bestimmt die
# Version aus mehreren unabhängigen Quellen, prüft die Härtung der
# configuration.php und den API-Zugriffsschutz. Read-only.
#
# Warum das eigenständig neben §7 (Dateisystem) stehen muss: Joomla-typische
# Übernahmen hinterlassen Spuren, die eine generische Webshell-Signatur nicht
# sieht — eine Version im Lückenbereich, eine gehärtete Einstellung, die nicht
# gesetzt ist, ein API-Endpunkt, der Zugangsdaten im Klartext ausliefert.
#
# Steht bewusst VOR §13 ROOT: 12.4 hängt Angreifer-IPs an ATTACK_IPS_UNIQ an,
# die §13 gegen erfolgreiche Root-Logins kreuzt.

# Einen Wert aus configuration.php lesen: jconf_get <datei> <variable-ohne-$>
# Auskommentierte Zeilen überspringen (gleicher Fallstrick wie bei wpconf_get:
# ein alter, auskommentierter Wert würde sonst den echten überdecken).
# Joomla 3 schreibt gequotete Strings ('0'), Joomla 4+ native Werte (false) —
# beide Schreibweisen müssen durch dieselbe Regex.
jconf_get() {
  grep -vE '^[[:space:]]*(//|#|\*|/\*)' "$1" 2>/dev/null \
    | grep -oP "public\s+\\\$$2\s*=\s*['\"]?\K[^'\";]*" 2>/dev/null | head -1
}

# Joomla-Wahrheitswert: '0', 0, '', false, 'false' sind falsch, alles andere wahr.
# OHNE das wird '$debug = true' (Joomla 4+) stumm übersehen, weil ein Vergleich
# gegen '1' nicht greift.
j_truthy() {
  case "$(printf '%s' "${1:-}" | tr 'A-Z' 'a-z' | tr -d ' ')" in
    ''|0|'0'|false|no|none) return 1 ;;
    *) return 0 ;;
  esac
}

# SQL gegen eine Joomla-Datenbank. Spiegelt wp_sql (Zeile ~1866): Stufe 1
# Plesk-Admin-Zugang, Stufe 2 die Zugangsdaten aus configuration.php. Eine
# dritte Stufe gibt es nicht — Joomla hat kein Gegenstück zu wp-cli, das
# freies SQL ausführen könnte (cli/joomla.php kann das nicht). Nur SELECT.
j_sql() {
  local db="$1" user="$2" pass="$3" host="$4" query="$5"
  if [[ -n "${PLESK_MYSQL_PW:-}" ]]; then
    MYSQL_PWD="$PLESK_MYSQL_PW" mysql -u admin -N -e "USE \`$db\`; $query" 2>/dev/null && return 0
  fi
  MYSQL_PWD="$pass" mysql -h "${host%%:*}" -u "$user" -N -e "$query" "$db" 2>/dev/null
}

# Version "a.b.c" in eine vergleichbare Zahl wandeln (aabbbccc).
# Nicht rein numerische Versionen ergeben 0 → Aufrufer überspringt sie,
# statt zu raten (siehe FP-Disziplin in docs/erkennung.md).
j_vernum() {
  local v="${1:-}" a b c
  [[ "$v" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+) ]] || { echo 0; return; }
  a="${BASH_REMATCH[1]}"; b="${BASH_REMATCH[2]}"; c="${BASH_REMATCH[3]}"
  echo $(( a * 1000000 + b * 1000 + c ))
}

h2 "12.1 Gefundene Joomla-Installationen"

# configuration.php allein ist viel zu unscharf — fast jedes PHP-Projekt hat
# eine. Erst 'class JConfig' macht daraus zuverlässig eine Joomla-Installation.
_jfound=""
while IFS= read -r c; do
  [[ -f "$c" ]] || continue
  grep -qE '^[[:space:]]*(final[[:space:]]+)?class[[:space:]]+JConfig\b' "$c" 2>/dev/null || continue
  # Backup-/Quarantäne-Kopien sind keine Live-Installation. Gleiche Logik wie
  # der Imunify-Tap in 8.15 — sonst erzeugt jede Altkopie eigene Befunde.
  if printf '%s' "$c" | grep -qiE '/(schadcode|quarant[^/]*|backup|_?bak|altkopie|sicherung|old|kopie)(/|_|\.)'; then
    JOOMLA_SKIPPED=$((JOOMLA_SKIPPED+1)); continue
  fi
  _jfound+="$c"$'\n'
done < <(find "${SCAN_PATHS[@]}" -maxdepth 5 -name configuration.php 2>/dev/null | nf_strip_self)
JOOMLA_CONFIGS=$(printf '%s' "$_jfound")
JOOMLA_COUNT=$(printf '%s\n' "$JOOMLA_CONFIGS" | grep -c . || true)

# Alter des mitgelieferten Datenbestands sichtbar machen — ein stiller Lauf
# gegen einen jahrealten Stand wäre die gefährlichste Form von "unauffällig".
if [[ -f "${JOOMLA_DATA_DIR}/VERSION" ]]; then
  J_DATA_STAMP=$(head -1 "${JOOMLA_DATA_DIR}/VERSION" 2>/dev/null | cut -d'|' -f1 | tr -d ' ')
  if [[ -n "$J_DATA_STAMP" ]]; then
    _jds=$(date -d "$J_DATA_STAMP" +%s 2>/dev/null || echo 0)
    [[ "$_jds" -gt 0 ]] && JOOMLA_DATA_AGE=$(( ( $(date +%s) - _jds ) / 86400 ))
  fi
fi

if [[ "$JOOMLA_COUNT" -eq 0 ]]; then
  info "Keine Joomla-Installation im Scan-Pfad gefunden — keine Joomla-Prüfung"
  [[ "$JOOMLA_SKIPPED" -gt 0 ]] && info "(${JOOMLA_SKIPPED} Backup-/Altkopie(n) übersprungen)"
else
  info "Joomla-Installationen: $JOOMLA_COUNT"
  [[ "$JOOMLA_SKIPPED" -gt 0 ]] && info "${JOOMLA_SKIPPED} Backup-/Altkopie(n) übersprungen (nicht als Live-Installation gewertet)"
  code "$JOOMLA_CONFIGS"
  if [[ -n "$J_DATA_STAMP" ]]; then
    info "Joomla-Datenbestand: Stand ${J_DATA_STAMP} (${JOOMLA_DATA_AGE} Tage alt)"
    [[ "$JOOMLA_DATA_AGE" -gt 180 ]] && \
      warn "Joomla-Datenbestand ist ${JOOMLA_DATA_AGE} Tage alt — aktualisieren (werkzeuge/joomla-daten-update.sh) oder Lauf mit --online wiederholen"
  else
    info "Kein Joomla-Datenbestand unter ${JOOMLA_DATA_DIR} — versionsabhängige Prüfungen eingeschränkt"
  fi

  while IFS= read -r cfg; do
    [[ -f "$cfg" ]] || continue
    site=$(echo "$cfg" | sed "s|${VHOSTS_DIR}/||;s|/configuration.php||")
    CURRENT_J_PATH=$(dirname "$cfg")
    jpfx=$(jconf_get "$cfg" dbprefix); jpfx=${jpfx:-jos_}
    # Das Präfix stammt aus einer Datei des GEPRÜFTEN Systems und wird unten in
    # SQL-Abfragen eingesetzt. Auf einer kompromittierten Installation kann es
    # beliebiger Text sein — deshalb hart auf Tabellennamen-Zeichen begrenzen,
    # sonst prüft das Forensik-Werkzeug selbst untergeschobenes SQL aus.
    if [[ ! "$jpfx" =~ ^[A-Za-z0-9_]+$ ]]; then
      warn "$site: Ungültiges Tabellenpräfix in der Konfiguration (\"${jpfx}\") — Datenbank-Prüfungen werden übersprungen" web
      jpfx=""
    fi

    echo -e "  ${CYN}Joomla-Prüfung:${NC} $site (prefix=${jpfx:-ungültig})"
    echo -e "\n#### $site  (Prefix: \`$jpfx\`)\n" >> "$REPORT_FILE"

    # ── 12.2 Version aus mehreren unabhängigen Quellen ────────
    # Angreifer, die eine Installation hintertüren, halten diese Quellen selten
    # konsistent — die Abweichung ist deshalb selbst ein Befund.
    jver=""; jver_src=""
    jxml="${CURRENT_J_PATH}/administrator/manifests/files/joomla.xml"
    if [[ -f "$jxml" ]]; then
      # Nur das <version>-ELEMENT, nicht das version="3.6"-Attribut am
      # <extension>-Tag — das ist die Manifest-Schemaversion, nicht die CMS-Version.
      jver=$(grep -oP '<version>\s*\K[0-9][^<[:space:]]*' "$jxml" 2>/dev/null | head -1)
      [[ -n "$jver" ]] && jver_src="joomla.xml"
    fi
    jvphp="${CURRENT_J_PATH}/libraries/src/Version.php"
    jver2=""
    if [[ -f "$jvphp" ]]; then
      _ma=$(grep -oP 'const\s+MAJOR_VERSION\s*=\s*\K[0-9]+' "$jvphp" 2>/dev/null | head -1)
      _mi=$(grep -oP 'const\s+MINOR_VERSION\s*=\s*\K[0-9]+' "$jvphp" 2>/dev/null | head -1)
      _pa=$(grep -oP 'const\s+PATCH_VERSION\s*=\s*\K[0-9]+' "$jvphp" 2>/dev/null | head -1)
      [[ -n "$_ma" && -n "$_mi" && -n "$_pa" ]] && jver2="${_ma}.${_mi}.${_pa}"
    fi
    # Joomla 3.0–3.7: eigene Datei mit RELEASE/DEV_LEVEL. In 3.8.0 wurde sie
    # GELÖSCHT — ab 3.8 gilt derselbe Pfad wie bei 4/5/6. Deshalb nur als
    # Rückfall heranziehen, wenn beide Quellen oben nichts geliefert haben.
    jvold="${CURRENT_J_PATH}/libraries/cms/version/version.php"
    if [[ -z "$jver" && -z "$jver2" && -f "$jvold" ]]; then
      _rel=$(grep -oP '(const|public\s+\$)\s*RELEASE\s*=\s*.\K[0-9.]+' "$jvold" 2>/dev/null | head -1)
      _dev=$(grep -oP '(const|public\s+\$)\s*DEV_LEVEL\s*=\s*.\K[0-9]+' "$jvold" 2>/dev/null | head -1)
      [[ -n "$_rel" ]] && { jver="${_rel}.${_dev:-0}"; jver_src="version.php (Joomla ≤3.7)"; }
    fi
    [[ -z "$jver" && -n "$jver2" ]] && { jver="$jver2"; jver_src="Version.php"; }

    if [[ -z "$jver" ]]; then
      warn "$site: Joomla-Version nicht bestimmbar (weder joomla.xml noch Version.php lesbar)" web
    else
      info "Joomla-Version: ${jver} (Quelle: ${jver_src})"
      JOOMLA_VERSIONS+="${site}"$'\t'"${jver}"$'\t'"${jver_src}"$'\n'

      # Kreuzvergleich der Dateiquellen
      if [[ -n "$jver2" && -n "$jxml" && -f "$jxml" && "$jver" != "$jver2" ]]; then
        _m1=$(printf '%s' "$jver"  | cut -d. -f1,2)
        _m2=$(printf '%s' "$jver2" | cut -d. -f1,2)
        if [[ "$_m1" != "$_m2" ]]; then
          crit "$site: Joomla-Versionsangaben widersprechen sich (joomla.xml ${jver} vs. Version.php ${jver2}) — Manipulation oder abgebrochene Migration" web
          JOOMLA_FLAGS=$((JOOMLA_FLAGS+1))
        else
          warn "$site: Joomla-Patchstand uneinheitlich (joomla.xml ${jver} vs. Version.php ${jver2}) — unvollständiges Update oder Restore" web
        fi
      fi

      # EOL-Bewertung. Beide alten Zweige sind ohne Sicherheitspatches:
      # 3.10 seit 2023-08 (kostenpflichtige eLTS lief 2025-02 aus), 4.4 seit
      # 2025-10-14 mit 4.4.14 als Endstand. Advisories aus 2026 nennen weiter
      # 3.0.0 als betroffen, ohne dass ein Fix auf irgendeinem Kanal existiert.
      jmaj=$(printf '%s' "$jver" | cut -d. -f1)
      jmin=$(printf '%s' "$jver" | cut -d. -f2)
      jnum=$(j_vernum "$jver")
      case "$jmaj" in
        1|2)
          crit "$site: Joomla ${jver} ist seit Jahren ohne Sicherheitspatches — Neuaufbau statt Update einplanen" web
          JOOMLA_FLAGS=$((JOOMLA_FLAGS+1)) ;;
        3)
          crit "$site: Joomla ${jver} erhält seit August 2023 keine Sicherheitspatches mehr (auch die kostenpflichtige Verlängerung endete Februar 2025) — die Installation ist dauerhaft angreifbar und läuft zudem nur auf einem ebenfalls veralteten PHP" web
          JOOMLA_FLAGS=$((JOOMLA_FLAGS+1)) ;;
        4)
          crit "$site: Joomla ${jver} erhält seit dem 14.10.2025 keine Sicherheitspatches mehr (4.4.14 war der letzte Stand) — Umstieg auf Joomla 5 nötig" web
          JOOMLA_FLAGS=$((JOOMLA_FLAGS+1)) ;;
        5)
          # 5.4.7 (Stand 07/2026) ist der gepflegte Stand des 5er-Zweigs.
          if [[ "$jnum" -gt 0 && "$jnum" -lt $(j_vernum "5.4.7") ]]; then
            warn "$site: Joomla ${jver} ist nicht auf dem aktuellen Sicherheitsstand des 5er-Zweigs (5.4.7 oder neuer) — Update einplanen" web
          else
            ok "$site: Joomla ${jver} — unterstützter Zweig, aktueller Patchstand"
          fi ;;
        6)
          if [[ "$jnum" -gt 0 && "$jnum" -lt $(j_vernum "6.1.2") ]]; then
            warn "$site: Joomla ${jver} ist nicht auf dem aktuellen Sicherheitsstand des 6er-Zweigs (6.1.2 oder neuer) — Update einplanen" web
          else
            ok "$site: Joomla ${jver} — unterstützter Zweig, aktueller Patchstand"
          fi ;;
        *)
          info "$site: Joomla-Zweig ${jmaj}.${jmin} nicht bewertbar" ;;
      esac
    fi

    # ── 12.3 Härtung der configuration.php ────────────────────
    jweak=""
    _jerr=$(jconf_get "$cfg" error_reporting)
    case "$(printf '%s' "${_jerr:-}" | tr 'A-Z' 'a-z')" in
      ''|none|default) : ;;
      *) jweak+="error_reporting=${_jerr} (Fehlermeldungen mit Pfaden und SQL-Fragmenten werden an Besucher ausgeliefert)"$'\n' ;;
    esac
    j_truthy "$(jconf_get "$cfg" debug)" && \
      jweak+="debug aktiv (Debug-Konsole mit SQL, Sitzungsdaten und Serverpfaden für JEDEN Besucher sichtbar)"$'\n'
    _jsec=$(jconf_get "$cfg" secret)
    if [[ "$_jsec" == "FBVtggIk5lAzEU9H" ]]; then
      crit "$site: configuration.php nutzt den ausgelieferten Standard-Sicherheitsschlüssel — CSRF-Token und Sitzungen sind fälschbar, sofortiger Wechsel nötig" web
      JOOMLA_FLAGS=$((JOOMLA_FLAGS+1))
    elif [[ -n "$_jsec" && "${#_jsec}" -lt 16 ]]; then
      jweak+="secret nur ${#_jsec} Zeichen lang (zu kurz für fälschungssichere CSRF-Token)"$'\n'
    fi
    [[ "$(jconf_get "$cfg" force_ssl)" == "0" ]] && \
      jweak+="force_ssl=0 (Anmeldedaten und Sitzungs-Cookies können unverschlüsselt übertragen werden)"$'\n'
    [[ "$jpfx" == "jos_" || "$jpfx" == "joomla_" ]] && \
      jweak+="Standard-Tabellenpräfix ${jpfx} (macht SQL-Injection-Angriffe zielgenau ohne Vorab-Erkundung)"$'\n'
    if j_truthy "$(jconf_get "$cfg" cors)" && [[ "$(jconf_get "$cfg" cors_allow_origin)" == "*" ]]; then
      jweak+="CORS für beliebige Fremdseiten geöffnet (cors_allow_origin=*) — vergrößert die Angriffsfläche der /api-Schnittstelle erheblich"$'\n'
    fi
    j_truthy "$(jconf_get "$cfg" shared_session)" && \
      jweak+="shared_session aktiv (eine Lücke im öffentlichen Bereich erreicht direkt die Administrator-Sitzung)"$'\n'
    _jsm=$(jconf_get "$cfg" session_metadata)
    if [[ -n "$_jsm" ]] && ! j_truthy "$_jsm"; then
      jweak+="session_metadata abgeschaltet — Joomla protokolliert keine Sitzungs-Metadaten mehr; bei einem Vorfall fehlt damit ein zentraler Nachweisweg"$'\n'
    fi
    j_truthy "$(jconf_get "$cfg" behind_loadbalancer)" && \
      jweak+="behind_loadbalancer aktiv — Joomla vertraut der übermittelten Absender-IP; ohne echten vorgeschalteten Proxy sind alle IP-Protokolle fälschbar und als Beweis wertlos"$'\n'

    # tmp_path/log_path: Joomlas WERKSEINSTELLUNG liegt unter dem Webverzeichnis.
    # Ein Test auf "unterhalb docroot" allein würde auf JEDER Installation
    # anschlagen. Befund nur, wenn das Verzeichnis auch ungeschützt ist.
    for _pv in tmp_path log_path; do
      _pd=$(jconf_get "$cfg" "$_pv")
      [[ -n "$_pd" && -d "$_pd" ]] || continue
      case "$_pd" in
        "${CURRENT_J_PATH}"/*)
          if ! grep -qriE '(Deny from all|Require all denied|<files|<directory)' "${_pd}/.htaccess" "${_pd}/web.config" 2>/dev/null; then
            jweak+="${_pv} liegt im Webverzeichnis (${_pd#"$CURRENT_J_PATH"/}) und ist nicht per .htaccess gesperrt — Inhalte sind über den Browser abrufbar"$'\n'
          fi ;;
      esac
    done

    # Strukturprüfung: configuration.php darf NICHTS als die JConfig-Klasse mit
    # Zuweisungen enthalten. Ausführbarer Code darin ist die exakte Form der
    # "Rusty Joomla"-Backdoor (eval eines POST-Parameters in der Konfigdatei).
    if grep -qEi '(\beval[[:space:]]*\(|\bassert[[:space:]]*\(|create_function|base64_decode|gzinflate|preg_replace[[:space:]]*\([^)]*/e|\$_(POST|GET|REQUEST|COOKIE)|shell_exec|passthru|proc_open|php://input)' "$cfg" 2>/dev/null; then
      crit "$site: configuration.php enthält ausführbaren Code — die Konfigurationsdatei wurde als Hintertür umgebaut" web
      JOOMLA_FLAGS=$((JOOMLA_FLAGS+1))
      evidence "joomla_config_backdoor_$(echo "$site" | tr '/.' '__')" "$(grep -nEi '(\beval[[:space:]]*\(|\bassert[[:space:]]*\(|base64_decode|\$_(POST|GET|REQUEST|COOKIE)|shell_exec)' "$cfg" 2>/dev/null | head -20)"
    fi
    # Geschwisterdateien: der Webserver liefert .bak/.old oft im Klartext aus —
    # und darin stehen die DB-Zugangsdaten.
    _jbak=$(find "$CURRENT_J_PATH" -maxdepth 1 -type f \
              \( -name 'configuration.php.*' -o -name 'configuration.*.php' -o -name 'configuration.php~' \) 2>/dev/null || true)
    if [[ -n "$_jbak" ]]; then
      crit "$site: Sicherungskopie der Konfigurationsdatei im Webverzeichnis — enthält die Datenbank-Zugangsdaten im Klartext und ist ggf. per Browser abrufbar" web
      JOOMLA_FLAGS=$((JOOMLA_FLAGS+1))
      code "$_jbak"
    fi

    if [[ -n "$jweak" ]]; then
      while IFS= read -r _w; do
        [[ -n "$_w" ]] && warn "$site: $_w" web
      done <<< "$jweak"
      JOOMLA_CONFIG_WEAK+="=== $site ==="$'\n'"$jweak"
    else
      ok "$site: Konfigurations-Härtung unauffällig"
    fi

    # ── 12.4 Ungeschützter API-Zugriff auf die Konfiguration ──
    # CVE-2023-23752 (Joomla 4.0.0–4.2.7): der Endpunkt
    # /api/index.php/v1/config/application?public=true liefert die komplette
    # Konfiguration inklusive DB-Zugangsdaten im Klartext an JEDEN
    # unauthentifizierten Aufrufer. Steht seit Januar 2024 im KEV-Katalog der
    # US-Cyberbehörde CISA, wird also nachweislich aktiv ausgenutzt.
    if [[ -n "${jver:-}" ]]; then
      jnum=$(j_vernum "$jver")
      if [[ "$jnum" -ge $(j_vernum "4.0.0") && "$jnum" -le $(j_vernum "4.2.7") ]]; then
        crit "$site: Joomla ${jver} gibt über eine ungeschützte Schnittstelle die Datenbank-Zugangsdaten an jeden Aufrufer heraus (CVE-2023-23752, nachweislich aktiv ausgenutzt) — Zugangsdaten als abgeflossen behandeln und zwingend wechseln" web
        JOOMLA_FLAGS=$((JOOMLA_FLAGS+1))

        # Gegenprobe im Zugriffsprotokoll. Der "200"-Filter ist entscheidend:
        # Überwachungswerkzeuge rufen /api/index.php/v1/ regelmäßig legitim ab
        # und bekommen 401 — nur ein 200 auf genau diesem Endpunkt belegt,
        # dass tatsächlich Daten herausgegeben wurden.
        _jvhost=$(printf '%s' "$site" | cut -d/ -f1)
        J_LEAK=$(grep -hE '/api/index\.php/v1/config/application' \
                   "${VHOSTS_DIR}/${_jvhost}/logs/"access*log* 2>/dev/null \
                 | grep -F 'public=true' | grep -E '" 200 ' | head -50 || true)
        if [[ -n "$J_LEAK" ]]; then
          crit "$site: Der Abruf der Zugangsdaten ist im Zugriffsprotokoll nachweisbar (erfolgreiche Antworten) — der Datenabfluss hat stattgefunden" web
          JOOMLA_FLAGS=$((JOOMLA_FLAGS+1))
          code "$(printf '%s' "$J_LEAK" | head -10)"
          evidence "joomla_api_leak_$(echo "$site" | tr '/.' '__')" "$J_LEAK"
          JOOMLA_LOG_IOC+="$J_LEAK"$'\n'
          _jips=$(printf '%s' "$J_LEAK" | grep -oE '^([0-9]{1,3}\.){3}[0-9]{1,3}' | sort | uniq -c | sort -rn || true)
          [[ -n "$_jips" ]] && ATTACK_IPS_UNIQ="${ATTACK_IPS_UNIQ:-}"$'\n'"$_jips"
        else
          info "Kein erfolgreicher Abruf dieses Endpunkts in den vorliegenden Protokollen — das schließt einen Abfluss aber nicht aus (Protokolle reichen nur begrenzt zurück)"
        fi
      elif [[ "$jnum" -ge $(j_vernum "4.0.0") && "$jnum" -le $(j_vernum "5.4.3") ]] \
        || [[ "$jnum" -ge $(j_vernum "6.0.0") && "$jnum" -le $(j_vernum "6.0.3") ]]; then
        # CVE-2026-23899 — Nachfolger derselben Schwachstellenklasse, benötigt
        # aber einen gültigen API-Token, daher eine Stufe niedriger.
        warn "$site: Joomla ${jver} ist von einer Schwachstelle im Konfigurations-Endpunkt betroffen (CVE-2026-23899) — Update auf 5.4.4 bzw. 6.0.4 oder neuer" web
      fi
    fi

    # ── 12.5 Kern-Integrität (Prüfsummen-Vergleich) ───────────
    # Das Gegenstück zu "wp core verify-checksums" bei WordPress. Joomla
    # veröffentlicht keine Prüfsummen je Datei, deshalb erzeugen wir sie
    # selbst aus den offiziellen Paketen (werkzeuge/joomla-daten-update.sh).
    #
    # Zwei Fragen: Wurde eine Kerndatei verändert? Und liegt in einem reinen
    # Kern-Verzeichnis eine Datei, die dort nicht hingehört? Letzteres ist die
    # klassische Ablagestelle für Hintertüren, die wie Kern aussehen sollen.
    if [[ -n "${jver:-}" ]]; then
      h2 "12.5 Kern-Integrität — $site"
      jzweig=$(printf '%s' "$jver" | cut -d. -f1,2)
      jmanifest="${JOOMLA_DATA_DIR}/coresums/${jzweig}.tsv.gz"
      jman_hat_version=0
      if [[ -f "$jmanifest" ]]; then
        gzip -dc "$jmanifest" 2>/dev/null | sed -n 's/^# Fassungen: //p' | head -1 \
          | tr ',' '\n' | grep -qxF "$jver" && jman_hat_version=1
      fi

      # Fehlt die Fassung im mitgelieferten Bestand, kann --online das
      # offizielle Paket nachladen. Das sind rund 30 MB — deshalb nur auf
      # ausdrücklichen Wunsch, und der Abruf wird protokolliert.
      jman_online=""
      if [[ "$jman_hat_version" -eq 0 && "${WANT_ONLINE:-0}" == "1" ]]; then
        jman_online="${RUN_DIR}/.online/joomla_${jver}"
        mkdir -p "$jman_online"
        info "Kein Prüfsummen-Satz für Joomla ${jver} vorhanden — lade das offizielle Paket nach (--online)"
        if nf_fetch "https://github.com/joomla/joomla-cms/releases/download/${jver}/Joomla_${jver}-Stable-Full_Package.tar.gz" "${jman_online}/paket.tgz" \
           && tar xzf "${jman_online}/paket.tgz" -C "$jman_online" 2>/dev/null; then
          rm -f "${jman_online}/paket.tgz"
        else
          warn "Offizielles Joomla-Paket ${jver} nicht abrufbar — Kern-Integrität nicht geprüft"
          rm -rf "$jman_online"; jman_online=""
        fi
      fi

      if [[ "$jman_hat_version" -eq 0 && -z "$jman_online" ]]; then
        warn "$site: Für Joomla ${jver} liegt kein Prüfsummen-Satz vor — die Unversehrtheit des Programmkerns wurde NICHT geprüft (mit --online nachladbar)"
      elif ! command -v python3 >/dev/null 2>&1; then
        info "python3 fehlt — Prüfsummen-Vergleich übersprungen"
      else
        # Ein einziger Python-Lauf je Installation. 9800 Dateien einzeln über
        # sha256sum zu hashen wäre 20- bis 40-mal langsamer und würde das
        # Verfahren praktisch unbrauchbar machen.
        jdiff=$(JROOT="$CURRENT_J_PATH" JMAN="$jmanifest" JVER="$jver" \
                JPAKET="${jman_online:-}" JAUSN="${JOOMLA_DATA_DIR}/coresums/ausnahmen.tsv" python3 <<'PY'
import os, re, gzip, hashlib, sys

wurzel  = os.environ["JROOT"]
manifest= os.environ.get("JMAN", "")
version = os.environ["JVER"]
paket   = os.environ.get("JPAKET", "")
ausn_d  = os.environ.get("JAUSN", "")

squash = re.compile(rb"[\n\r\t\v\f ]+")

def hashe(p):
    try:
        roh = open(p, "rb").read()
    except OSError:
        return None, None
    return (hashlib.sha256(roh).hexdigest(),
            hashlib.sha256(squash.sub(b" ", roh)).hexdigest())

# Soll-Zustand: entweder aus dem mitgelieferten Manifest oder aus dem
# nachgeladenen Originalpaket.
soll = {}
if paket and os.path.isdir(paket):
    for wz, verz, dateien in os.walk(paket):
        verz[:] = [d for d in verz if os.path.relpath(os.path.join(wz, d), paket) != "installation"]
        for d in dateien:
            vp = os.path.join(wz, d)
            rel = os.path.relpath(vp, paket)
            h, hs = hashe(vp)
            if h:
                soll[rel] = (h, hs)
elif manifest and os.path.isfile(manifest):
    with gzip.open(manifest, "rt") as f:
        for z in f:
            if z.startswith("#"):
                continue
            t = z.rstrip("\n").split("\t")
            if len(t) < 4:
                continue
            rel, h, hs, fassungen = t[0], t[1], t[2], t[3]
            if fassungen == "*" or version in fassungen.split(","):
                soll[rel] = (h, hs)
if not soll:
    print("KEINDATEN")
    sys.exit(0)

# Vom Betreiber freigegebene Abweichungen (etwa ein selbst eingespielter Patch)
ausnahmen = set()
for kandidat in (ausn_d, os.path.join(wurzel, ".nt-forensik-ausnahmen.tsv")):
    if kandidat and os.path.isfile(kandidat):
        for z in open(kandidat):
            if z.startswith("#") or not z.strip():
                continue
            t = z.rstrip("\n").split("\t")
            if len(t) >= 2:
                ausnahmen.add((t[0], t[1]))

# Nie vergleichen: was der Betreiber selbst pflegt oder was zur Laufzeit entsteht.
NIE = re.compile(r"^(configuration\.php|\.htaccess|web\.config|\.user\.ini|robots\.txt|"
                 r"cache/|tmp/|logs/|images/|administrator/cache/|administrator/logs/)")

veraendert, fehlend, leerraum = [], [], 0
for rel, (h, hs) in soll.items():
    if NIE.match(rel):
        continue
    vp = os.path.join(wurzel, rel)
    if not os.path.isfile(vp):
        fehlend.append(rel)
        continue
    ist, ist_s = hashe(vp)
    if ist == h:
        continue
    # Zweite Chance: nur Leerraum unterschiedlich (CRLF, Tabs, angehaengte
    # Leerzeichen). Wird erst bei Abweichung berechnet und ist deshalb in der
    # Praxis kostenlos — ueber 99 % passen schon roh.
    if ist_s == hs:
        leerraum += 1
        continue
    if (rel, ist) in ausnahmen:
        continue
    veraendert.append(rel)

# Kernfremde Dateien NUR in Verzeichnissen, die ausschliesslich Kern enthalten
# duerfen. In components/, modules/, plugins/, templates/, language/ und media/
# liegen legitim Dritt-Erweiterungen — dort waere jede Meldung Rauschen.
REIN = ("includes", "administrator/includes", "libraries/src", "libraries/vendor",
        "api", "cli", "layouts")
# ... aber auch INNERHALB dieser Zweige gibt es Stellen, an die Erweiterungen
# und Sprachpakete regulaer installieren. Ohne diese Ausnahmen meldet jede
# gewachsene Installation ihre Zusatzpakete als Hintertuer — auf einem realen
# Kundensystem waren es Akeeba Backup unter api/components/ und ein deutsches
# Sprachpaket unter api/language/ (Vorfall 2026-08-05).
REIN_AUS = re.compile(r"^(api/components/|api/language/|api/modules/|"
                      r"libraries/vendor/composer/|layouts/plugins/)")
fremd = []
for basis in REIN:
    bp = os.path.join(wurzel, basis)
    if not os.path.isdir(bp):
        continue
    for wz, verz, dateien in os.walk(bp):
        for d in dateien:
            vp = os.path.join(wz, d)
            rel = os.path.relpath(vp, wurzel)
            if rel not in soll and not NIE.match(rel) and not REIN_AUS.match(rel):
                fremd.append(rel)

print("STATISTIK\t%d\t%d\t%d\t%d\t%d" % (len(soll), len(veraendert), len(fehlend), len(fremd), leerraum))
for r in sorted(veraendert)[:200]:
    print("VERAENDERT\t%s" % os.path.join(wurzel, r))
for r in sorted(fremd)[:200]:
    print("FREMD\t%s" % os.path.join(wurzel, r))
for r in sorted(fehlend)[:50]:
    print("FEHLT\t%s" % r)
PY
) || true

        if [[ "$jdiff" == "KEINDATEN" || -z "$jdiff" ]]; then
          info "Kein auswertbarer Prüfsummen-Satz — Kern-Integrität nicht geprüft"
        else
          _stat=$(printf '%s\n' "$jdiff" | grep '^STATISTIK' | head -1)
          _geprueft=$(printf '%s' "$_stat" | cut -f2)
          _nmod=$(printf '%s' "$_stat" | cut -f3)
          _nfehlt=$(printf '%s' "$_stat" | cut -f4)
          _nfremd=$(printf '%s' "$_stat" | cut -f5)
          _nlr=$(printf '%s' "$_stat" | cut -f6)
          info "${_geprueft} Kern-Dateien verglichen${_nlr:+ (${_nlr} nur mit abweichenden Zeilenenden/Leerzeichen — nicht gewertet)}"

          _mod=$(printf '%s\n' "$jdiff" | sed -n 's/^VERAENDERT\t//p')
          _fremd=$(printf '%s\n' "$jdiff" | sed -n 's/^FREMD\t//p')
          _fehlt=$(printf '%s\n' "$jdiff" | sed -n 's/^FEHLT\t//p')

          if [[ "${_nmod:-0}" -gt 0 ]]; then
            crit "$site: ${_nmod} veränderte Datei(en) im Joomla-Programmkern — der Kern wurde nachträglich bearbeitet, das ist der übliche Weg für dauerhaft eingeschleusten Schadcode" web
            JOOMLA_FLAGS=$((JOOMLA_FLAGS+1))
            JOOMLA_CORE_MODIFIED+="$_mod"$'\n'
            code "$(printf '%s' "$_mod" | sed "s|${CURRENT_J_PATH}/||" | head -20)"
            evidence "joomla_kern_veraendert_$(echo "$site" | tr '/.' '__')" "$_mod"
          fi
          if [[ "${_nfremd:-0}" -gt 0 ]]; then
            crit "$site: ${_nfremd} kernfremde Datei(en) in Verzeichnissen, die nur Programmcode von Joomla enthalten dürfen — typische Ablage für getarnte Hintertüren" web
            JOOMLA_FLAGS=$((JOOMLA_FLAGS+1))
            JOOMLA_CORE_UNKNOWN+="$_fremd"$'\n'
            code "$(printf '%s' "$_fremd" | sed "s|${CURRENT_J_PATH}/||" | head -20)"
            evidence "joomla_kern_fremd_$(echo "$site" | tr '/.' '__')" "$_fremd"
          fi
          if [[ "${_nfehlt:-0}" -gt 0 ]]; then
            warn "$site: ${_nfehlt} Datei(en) des Programmkerns fehlen — unvollständiges Update oder gelöschte Dateien" web
            code "$(printf '%s' "$_fehlt" | head -15)"
          fi
          [[ "${_nmod:-0}" -eq 0 && "${_nfremd:-0}" -eq 0 && "${_nfehlt:-0}" -eq 0 ]] && \
            ok "$site: Programmkern unverändert (${_geprueft} Dateien geprüft)"
        fi
      fi
    fi

    # ── 12.6 Datenbank-Prüfung ────────────────────────────────
    # Läuft NACH den Dateiprüfungen: scheitert die DB-Verbindung, sind die
    # Befunde oben trotzdem erhoben. (Lehre aus §11, Zeile ~1786: ein
    # fehlgeschlagener mysql-Connect ließ dort vier Angreifer-Admins durch.)
    jdb=$(jconf_get "$cfg" db)
    jdu=$(jconf_get "$cfg" user)
    jdp=$(jconf_get "$cfg" password)
    jdh=$(jconf_get "$cfg" host); jdh=${jdh:-localhost}

    if [[ -z "$jdb" || -z "$jpfx" ]]; then
      info "$site: kein Datenbankname bzw. kein gültiges Präfix — Datenbank-Prüfung übersprungen"
    elif ! j_sql "$jdb" "$jdu" "$jdp" "$jdh" "SELECT 1;" >/dev/null 2>&1; then
      warn "$site: keine Datenbank-Verbindung — Datenbank-Prüfungen übersprungen (die Dateiprüfungen oben sind erfolgt)"
    else
      h2 "12.6 Datenbank-Prüfung — $site"

      # (a) System-Plugins. PluginHelper::importPlugin('system') läuft im
      # Bootstrap VOR dem Routing und VOR jeder Rechteprüfung — eine aktive
      # Zeile lädt plugins/system/<element>/ bei JEDEM Aufruf der Seite.
      # Deshalb die bevorzugte Stelle für dauerhaften Zugriff.
      #
      # ABER: 20–40 aktive System-Plugins sind auf einer gepflegten Seite
      # normal (Akeeba, RSFirewall, Regular Labs …). Die reine Bedingung ist
      # KEIN Befund. Kritisch nur bei einem von drei harten Indikatoren.
      # ACHTUNG Leerfelder: die Auswertung unten liest die Zeilen mit
      # IFS=$'\t'. Bash fasst aufeinanderfolgende Tabulatoren zu EINEM Trenner
      # zusammen — ein leeres Feld mitten in der Zeile würde alle folgenden
      # Spalten verschieben. Deshalb liefert jede Abfrage für potenziell leere
      # Spalten das Füllzeichen '-' statt eines Leerstrings.
      jsysrows=$(j_sql "$jdb" "$jdu" "$jdp" "$jdh" \
        "SELECT extension_id, element, enabled, protected, locked, ordering, IF(manifest_cache IS NULL OR manifest_cache='','-',manifest_cache) FROM ${jpfx}extensions WHERE type='plugin' AND folder='system' AND enabled=1;" 2>/dev/null || true)
      jsys_n=$(printf '%s\n' "$jsysrows" | grep -c . || true)
      if [[ "$jsys_n" -gt 0 ]]; then
        info "$jsys_n aktive System-Plugins (werden bei jedem Seitenaufruf geladen)"

        # Ein leeres manifest_cache gilt als Hinweis auf eine per SQL eingefügte
        # Zeile — aber NUR relativ zur selben Installation. Joomlas base.sql
        # liefert die Kern-Erweiterungen selbst mit leerem manifest_cache aus;
        # auf einer frisch aufgesetzten Seite ist das Feld also flächendeckend
        # leer und beweist nichts. Erst wenn die Mehrheit der Plugins ein
        # gefülltes Manifest hat, ist eine leere Zeile eine echte Abweichung.
        # (Ohne diese Selbstkalibrierung meldet die Prüfung jedes Kern-Plugin
        # einer Neuinstallation als Hintertür.)
        jmc_ok=0
        while IFS=$'\t' read -r _eid _el _en _prot _lock _ord _mc; do
          [[ -n "${_el:-}" ]] || continue
          [[ "$_mc" != "-" && "$_mc" != "{}" ]] && jmc_ok=$((jmc_ok+1))
        done <<< "$jsysrows"
        jmc_aussagekraeftig=0
        [[ $(( jmc_ok * 100 / jsys_n )) -ge 60 ]] && jmc_aussagekraeftig=1

        jsys_bad=""
        while IFS=$'\t' read -r _eid _el _en _prot _lock _ord _mc; do
          [[ -n "${_el:-}" ]] || continue
          _reason=""
          # 1) Verzeichnis fehlt -> die Zeile verweist ins Leere. Zuerst
          #    prüfen: existiert das Verzeichnis, ist es ein normales Plugin,
          #    egal was im manifest_cache steht.
          if [[ ! -d "${CURRENT_J_PATH}/plugins/system/${_el}" ]]; then
            _reason="ohne zugehöriges Verzeichnis auf der Platte"
          # 2) Verzeichnis vorhanden, enthält aber Schadcode-Muster.
          #    PATTERN_REGEX aus 7.3 wiederverwenden — eine Pflegestelle.
          elif [[ -n "${PATTERN_REGEX:-}" ]] && grep -rlPi "${PATTERN_REGEX}" "${CURRENT_J_PATH}/plugins/system/${_el}" --include="*.php" >/dev/null 2>&1; then
            _reason="mit Schadcode-Muster im Plugin-Verzeichnis"
          # 3) Manifest fehlt, obwohl alle anderen eines haben (s. o.)
          elif [[ "$jmc_aussagekraeftig" -eq 1 ]] \
            && { [[ "$_mc" == "-" || "$_mc" == "{}" ]] || ! printf '%s' "$_mc" | python3 -c 'import sys,json; json.loads(sys.stdin.read())' >/dev/null 2>&1; }; then
            _reason="ohne Installationspaket, während alle übrigen Plugins eines haben (per Datenbank eingefügt)"
          fi
          # Zusatzangaben, nur ergänzend zu einem der Gründe oben. Für sich
          # genommen ist beides unauffällig: Kern-Erweiterungen sind regulär
          # als geschützt markiert.
          if [[ -n "$_reason" ]]; then
            [[ "${_prot:-0}" == "1" || "${_lock:-0}" == "1" ]] && _reason+=", zusätzlich gegen Löschen/Deaktivieren gesperrt"
            [[ "${_ord:-0}" =~ ^-[0-9]+$ && "${_ord#-}" -gt 100 ]] && _reason+=", auf höchste Ausführungspriorität gesetzt"
            jsys_bad+="${_el} — ${_reason}"$'\n'
          fi
        done <<< "$jsysrows"
        if [[ -n "$jsys_bad" ]]; then
          while IFS= read -r _b; do
            [[ -n "$_b" ]] && crit "$site: System-Plugin ${_b} — läuft bei jedem Seitenaufruf mit" web
          done <<< "$jsys_bad"
          JOOMLA_FLAGS=$((JOOMLA_FLAGS+1))
          JOOMLA_SYS_PLUGINS+="=== $site ==="$'\n'"$jsys_bad"
          evidence "joomla_systemplugins_$(echo "$site" | tr '/.' '__')" "$jsysrows"
        else
          ok "$site: aktive System-Plugins alle mit Installationspaket und Verzeichnis"
        fi
      fi

      # (b) Super-User. Gruppe 8 NICHT hartkodieren: Joomla erlaubt weitere
      # Gruppen mit core.admin, und Untergruppen erben das Recht. Autoritativ
      # ist die Rechtetabelle des Wurzel-Assets.
      jrules=$(j_sql "$jdb" "$jdu" "$jdp" "$jdh" "SELECT rules FROM ${jpfx}assets WHERE id=1;" 2>/dev/null | head -1 || true)
      jadming=$(printf '%s' "$jrules" | python3 -c '
import sys, json
try:
    r = json.loads(sys.stdin.read() or "{}")
    print(",".join(str(g) for g, v in (r.get("core.admin") or {}).items() if str(v) in ("1", "True", "true")))
except Exception:
    pass' 2>/dev/null || true)
      if [[ -z "$jadming" ]]; then
        info "Rechtetabelle des Wurzel-Assets nicht lesbar — Super-User-Prüfung auf die Standardgruppe 8 zurückgesetzt"
        jadming="8"
      fi
      # Untergruppen über den verschachtelten Baum (lft/rgt) mitnehmen
      jallg=$(j_sql "$jdb" "$jdu" "$jdp" "$jdh" \
        "SELECT DISTINCT g2.id FROM ${jpfx}usergroups g1 JOIN ${jpfx}usergroups g2 ON g2.lft >= g1.lft AND g2.rgt <= g1.rgt WHERE g1.id IN (${jadming});" 2>/dev/null | tr '\n' ',' | sed 's/,$//' || true)
      jallg="${jallg:-$jadming}"
      info "Super-User-Gruppen (inkl. Untergruppen): ${jallg}"

      jsuper=$(j_sql "$jdb" "$jdu" "$jdp" "$jdh" \
        "SELECT u.id, u.username, IF(u.email='','-',u.email), u.registerDate, IFNULL(u.lastvisitDate,'nie'), u.block, IF(u.activation IS NULL OR u.activation='','-',u.activation), IF(u.password REGEXP '^[0-9a-f]{32}\$' OR u.password='', 'SCHWACH', 'ok') FROM ${jpfx}users u JOIN ${jpfx}user_usergroup_map m ON u.id=m.user_id WHERE m.group_id IN (${jallg}) GROUP BY u.id ORDER BY u.registerDate DESC;" 2>/dev/null || true)
      jsuper_n=$(printf '%s\n' "$jsuper" | grep -c . || true)
      if [[ "$jsuper_n" -gt 0 ]]; then
        info "${jsuper_n} Konto/Konten mit Super-User-Rechten"
        evidence "joomla_superuser_$(echo "$site" | tr '/.' '__')" "$jsuper"
        # Kritisch nur bei der vollständigen Kombination: frisch angelegt,
        # freigeschaltet, nicht gesperrt und nie über die Oberfläche benutzt.
        # Ein einzelnes Merkmal trifft auch auf legitime Konten zu.
        while IFS=$'\t' read -r _id _un _em _reg _lv _blk _act _pw; do
          [[ -n "${_un:-}" ]] || continue
          # '-' = Feld ist leer, also freigeschaltet (siehe Füllzeichen oben)
          if [[ "${_blk:-1}" == "0" && "${_act:-}" == "-" && "${_lv:-}" == "nie" ]]; then
            _regs=$(date -d "${_reg:-1970-01-01}" +%s 2>/dev/null || echo 0)
            _cut=$(( $(date +%s) - DAYS_BACK * 86400 ))
            if [[ "$_regs" -gt "$_cut" ]]; then
              crit "$site: Super-User \"${_un}\" (${_em}) wurde am ${_reg%% *} angelegt, ist freigeschaltet und hat sich nie angemeldet — typisches Muster eines vom Angreifer hinterlegten Zweitzugangs" web
              JOOMLA_FLAGS=$((JOOMLA_FLAGS+1))
              JOOMLA_ROGUE_SUPER+="${_id}"$'\t'"${_un}"$'\t'"${_em}"$'\t'"${_reg}"$'\n'
            fi
          fi
          if [[ "${_pw:-ok}" == "SCHWACH" ]]; then
            crit "$site: Super-User \"${_un}\" hat kein oder ein veraltet gespeichertes Passwort — das Konto ist praktisch ungeschützt" web
            JOOMLA_FLAGS=$((JOOMLA_FLAGS+1))
          fi
        done <<< "$jsuper"
        [[ -z "$JOOMLA_ROGUE_SUPER" ]] && ok "$site: keine neu angelegten, unbenutzten Super-User im Prüfzeitraum"
      fi

      # (c) Rechtetabelle: Verwaltungsrechte für Öffentlich/Registriert wären
      # gleichbedeutend mit "jeder darf administrieren".
      jaclbad=$(j_sql "$jdb" "$jdu" "$jdp" "$jdh" \
        "SELECT id, name FROM ${jpfx}assets WHERE rules LIKE '%\"core.admin\":{%\"1\":1%' OR rules LIKE '%\"core.admin\":{%\"2\":1%' OR rules LIKE '%\"core.manage\":{%\"1\":1%';" 2>/dev/null || true)
      if [[ -n "$jaclbad" ]]; then
        crit "$site: Verwaltungsrechte sind an die Gruppe \"Öffentlich\" oder \"Registriert\" vergeben — nicht angemeldete Besucher haben Administrationsrechte" web
        JOOMLA_FLAGS=$((JOOMLA_FLAGS+1))
        code "$jaclbad"
        evidence "joomla_acl_$(echo "$site" | tr '/.' '__')" "$jaclbad"
      else
        ok "$site: keine Verwaltungsrechte an offene Benutzergruppen vergeben"
      fi

      # (d) Sitzungstabelle. Nur die bekannten Gadget-Ketten suchen — ein
      # blankes "O:" trifft jedes serialisierte Objekt und wäre wertlos.
      # Bei anderem Sitzungsspeicher ist die Tabelle leer, dann gar nicht prüfen.
      jsh=$(jconf_get "$cfg" session_handler)
      if [[ -z "$jsh" || "$jsh" == "database" ]]; then
        jsess=$(j_sql "$jdb" "$jdu" "$jdp" "$jdh" \
          "SELECT session_id, IFNULL(userid,0), IFNULL(username,''), LENGTH(data) FROM ${jpfx}session WHERE data LIKE '%JDatabaseDriverMysqli%' OR data LIKE '%JSimplepieFactory%' OR data LIKE '%disconnectHandlers%';" 2>/dev/null || true)
        if [[ -n "$jsess" ]]; then
          crit "$site: In der Sitzungstabelle stehen Angriffsmuster zur Codeausführung — es wurde versucht, über eine manipulierte Sitzung Schadcode auszuführen" web
          JOOMLA_FLAGS=$((JOOMLA_FLAGS+1))
          JOOMLA_SESSION_HITS+="$jsess"$'\n'
          evidence "joomla_session_$(echo "$site" | tr '/.' '__')" "$jsess"
        else
          ok "$site: keine Angriffsmuster in der Sitzungstabelle"
        fi
      else
        info "Sitzungen werden nicht in der Datenbank gespeichert (${jsh}) — Sitzungsprüfung entfällt"
      fi

      # (e) Vorlagen-Parameter. WICHTIGSTE Prüfung der aktuellen Bedrohungslage:
      # die Helix3-Kampagne (CVE-2026-49049) legt ihre Nutzlast AUSSCHLIESSLICH
      # hier ab, in den Feldern für eigenes CSS/JavaScript, die die Vorlage
      # direkt in die Seite schreibt. Ein reiner Dateiscan meldet eine
      # verunstaltete Seite deshalb als sauber.
      jtpl=$(j_sql "$jdb" "$jdu" "$jdp" "$jdh" \
        "SELECT id, template, client_id, home, title FROM ${jpfx}template_styles WHERE params REGEXP '<script|</script|javascript:|eval\\\\(|atob\\\\(|document\\\\.write|base64,|innerHTML|z-index:2147483647|Hacked by|AntonKill';" 2>/dev/null || true)
      if [[ -n "$jtpl" ]]; then
        crit "$site: In den Vorlagen-Einstellungen der Datenbank steht eingeschleustes Skript — solcher Code überlebt jede Wiederherstellung der Dateien und wird auf der Seite ausgeliefert" web
        JOOMLA_FLAGS=$((JOOMLA_FLAGS+1))
        JOOMLA_TPL_PARAMS+="$jtpl"$'\n'
        code "$jtpl"
        evidence "joomla_template_params_$(echo "$site" | tr '/.' '__')" \
          "$(j_sql "$jdb" "$jdu" "$jdp" "$jdh" "SELECT id, template, home, LEFT(params,2000) FROM ${jpfx}template_styles;" 2>/dev/null || true)"
      else
        ok "$site: Vorlagen-Einstellungen ohne eingeschleusten Skriptcode"
      fi

      # (f) Module. <script>/<iframe> allein wäre massiver Fehlalarm —
      # "Eigenes HTML" ist genau das Werkzeug für Analyse- und Marketing-Codes.
      # Deshalb zusätzlich ein Verschleierungs- oder Versteckmerkmal verlangen.
      jmod=$(j_sql "$jdb" "$jdu" "$jdp" "$jdh" \
        "SELECT id, title, module, position FROM ${jpfx}modules WHERE published=1 AND (content REGEXP 'eval\\\\(|atob\\\\(|String\\\\.fromCharCode|document\\\\.write\\\\(unescape|left:[[:space:]]*-9999|display:[[:space:]]*none[^;]*<a |<\\\\?php');" 2>/dev/null || true)
      if [[ -n "$jmod" ]]; then
        crit "$site: Veröffentlichte Module enthalten verschleierten oder versteckten Fremdcode — typisch für Spam-Verlinkung oder das Abgreifen von Eingaben" web
        JOOMLA_FLAGS=$((JOOMLA_FLAGS+1))
        JOOMLA_MOD_CUSTOM+="$jmod"$'\n'
        code "$jmod"
        evidence "joomla_module_inject_$(echo "$site" | tr '/.' '__')" "$jmod"
      else
        ok "$site: keine verschleierten Inhalte in veröffentlichten Modulen"
      fi
      # Erweiterungen, die PHP in Inhalten ausführbar machen, ändern die
      # Tragweite jedes Content-Fundes — deshalb als Kontext ausweisen.
      jphpext=$(j_sql "$jdb" "$jdu" "$jdp" "$jdh" \
        "SELECT element FROM ${jpfx}extensions WHERE enabled=1 AND element IN ('sourcerer','directphp','jumi','phpmod','php');" 2>/dev/null || true)
      [[ -n "$jphpext" ]] && \
        warn "$site: Erweiterung(en) $(printf '%s' "$jphpext" | tr '\n' ' ') machen PHP-Code in Artikeln und Modulen ausführbar — jeder eingeschleuste Inhalt wird damit zu ausführbarem Programmcode" web

      # (g) Anmelde-Token. Eine gültige Zeile meldet ohne Passwort UND ohne
      # zweiten Faktor an und überlebt einen Passwortwechsel. Das Kernfeature
      # "Angemeldet bleiben" füllt die Tabelle aber legitim — Befund nur, wenn
      # das zugehörige Plugin gar nicht aktiv ist (dann wurde eingefügt).
      jrem=$(j_sql "$jdb" "$jdu" "$jdp" "$jdh" \
        "SELECT COUNT(*) FROM ${jpfx}extensions WHERE type='plugin' AND folder='system' AND element='remember' AND enabled=1;" 2>/dev/null | head -1 || true)
      jkeys=$(j_sql "$jdb" "$jdu" "$jdp" "$jdh" \
        "SELECT user_id, series, time, IFNULL(uastring,'') FROM ${jpfx}user_keys;" 2>/dev/null || true)
      jkeys_n=$(printf '%s\n' "$jkeys" | grep -c . || true)
      if [[ "$jkeys_n" -gt 0 && "${jrem:-1}" == "0" ]]; then
        warn "$site: ${jkeys_n} dauerhafte(r) Anmelde-Token vorhanden, obwohl die Funktion \"Angemeldet bleiben\" abgeschaltet ist — die Einträge wurden nachträglich eingefügt und erlauben Anmeldung ohne Passwort" web
        JOOMLA_USER_KEYS+="$jkeys"$'\n'
        evidence "joomla_user_keys_$(echo "$site" | tr '/.' '__')" "$jkeys"
      elif [[ "$jkeys_n" -gt 0 ]]; then
        info "${jkeys_n} Anmelde-Token (\"Angemeldet bleiben\") — bei einer Bereinigung mit zurücksetzen"
      fi
    fi

    # ── 12.7 Abgleich mit bekannten Schwachstellen ────────────
    # Zwei getrennte Quellen: der Programmkern gegen die Meldungen des
    # Joomla-Sicherheitsteams, die Erweiterungen gegen die Liste verwundbarer
    # Erweiterungen plus eine handgepflegte Tabelle der Fälle mit belegter
    # Massenausnutzung (die aktuelle Welle ist neuer als der Feed).
    #
    # Bewusst NICHT über die NVD: eine Abfrage nach der Joomla-Kennung liefert
    # dort hunderte Treffer, darunter Komponenten-Lücken von 2006 — als
    # Prädikat unbrauchbar.
    h2 "12.7 Abgleich mit bekannten Schwachstellen — $site"
    if [[ ! -d "$JOOMLA_DATA_DIR" ]]; then
      info "Kein Schwachstellen-Datenbestand unter ${JOOMLA_DATA_DIR} — Abgleich übersprungen (werkzeuge/joomla-daten-update.sh)"
    else
      # Kern
      _corecve="${JOOMLA_DATA_DIR}/cve/joomla-core.tsv"
      if [[ -f "$_corecve" && -n "${jver:-}" ]]; then
        jnum=$(j_vernum "$jver")
        if [[ "$jnum" -gt 0 ]]; then
          _hits=""
          while IFS=$'\t' read -r _lo _hi _cve _sev _typ; do
            [[ "${_lo:0:1}" == "#" || -z "${_cve:-}" ]] && continue
            _lonum=$(j_vernum "$_lo"); _hinum=$(j_vernum "$_hi")
            [[ "$_lonum" -gt 0 && "$jnum" -ge "$_lonum" && "$jnum" -le "$_hinum" ]] || continue
            _hits+="${_cve}"$'\t'"${_sev:-}"$'\t'"${_typ:-}"$'\n'
          done < "$_corecve"
          if [[ -n "$_hits" ]]; then
            _n=$(printf '%s\n' "$_hits" | grep -c . || true)
            _hoch=$(printf '%s' "$_hits" | grep -ciE '	High	|	Critical	' || true)
            if [[ "${_hoch:-0}" -gt 0 ]]; then
              crit "$site: Joomla ${jver} ist von ${_n} bekannten Schwachstellen betroffen, davon ${_hoch} mit hoher Schwere — Update ist die einzige Abhilfe" web
              JOOMLA_FLAGS=$((JOOMLA_FLAGS+1))
            else
              warn "$site: Joomla ${jver} ist von ${_n} bekannten Schwachstellen betroffen — Update einplanen" web
            fi
            code "$(printf '%s' "$_hits" | sort -u | head -15)"
            evidence "joomla_kern_cve_$(echo "$site" | tr '/.' '__')" "$(printf '%s' "$_hits" | sort -u)"
            JOOMLA_VULN_EXT+="$(printf 'Kern %s: %s' "$jver" "$(printf '%s' "$_hits" | cut -f1 | sort -u | tr '\n' ' ')")"$'\n'
          else
            ok "$site: keine bekannten Kern-Schwachstellen für Joomla ${jver}"
          fi
        fi
      fi

      # Erweiterungen — braucht die Datenbank für den Bestand
      if [[ -n "${jdb:-}" && -n "${jpfx:-}" ]] && j_sql "$jdb" "$jdu" "$jdp" "$jdh" "SELECT 1;" >/dev/null 2>&1; then
        # ACHTUNG element-Form: #__extensions führt Komponenten/Module/Pakete
        # MIT Präfix (com_/mod_/pkg_), Plugins und Templates aber OHNE
        # (Plugin "helix3" + folder "ajax", Template "shaper_helix3"). Die
        # Vergleichstabellen sind deshalb auf genau diese Form gebracht; bei
        # Plugins wird zusätzlich der Ordner verglichen, weil derselbe
        # Elementname in mehreren Ordnern vorkommen kann.
        _extrows=$(j_sql "$jdb" "$jdu" "$jdp" "$jdh" \
          "SELECT element, type, IF(folder IS NULL OR folder='','-',folder), enabled, IF(manifest_cache IS NULL OR manifest_cache='','-',manifest_cache) FROM ${jpfx}extensions WHERE type IN ('component','module','plugin','package','template') AND protected=0;" 2>/dev/null || true)
        # Versionen in einem einzigen Python-Aufruf aus den Manifesten ziehen
        _extver=$(printf '%s' "$_extrows" | python3 -c '
import sys, json
for zeile in sys.stdin.read().splitlines():
    t = zeile.split("\t")
    if len(t) < 5:
        continue
    el, typ, folder, en, mc = t[0], t[1], t[2], t[3], t[4]
    v = ""
    if mc not in ("-", "", "{}"):
        try:
            v = str((json.loads(mc) or {}).get("version", "") or "")
        except Exception:
            v = ""
    print("\t".join([el, typ, folder, en, v or "-"]))
' 2>/dev/null || true)

        _vuln=""
        _krit="${JOOMLA_DATA_DIR}/cve/joomla-ext-kritisch.tsv"
        _vel="${JOOMLA_DATA_DIR}/vel/vel.tsv"
        while IFS=$'\t' read -r _el _typ _folder _en _v; do
          [[ -n "${_el:-}" ]] || continue
          _vnum=$(j_vernum "$_v")

          # a) Tabelle der Fälle mit belegter Massenausnutzung
          if [[ -f "$_krit" ]]; then
            while IFS=$'\t' read -r _kel _kfolder _kmax _kfix _kcve _kkev _khinweis; do
              [[ "${_kel:0:1}" == "#" || -z "${_kel:-}" ]] && continue
              [[ "$_kel" == "$_el" ]] || continue
              # Ordner nur vergleichen, wenn die Tabelle einen nennt — sonst
              # würde ein Eintrag ohne Ordnerangabe nie zutreffen.
              [[ -z "${_kfolder:-}" || "${_kfolder}" == "${_folder}" ]] || continue
              # Version unbekannt -> melden, aber als Prüfhinweis: die
              # Erweiterung ist da, der Stand nicht feststellbar.
              if [[ "$_vnum" -eq 0 ]]; then
                warn "$site: Erweiterung ${_el} ist installiert und war von einer aktiv ausgenutzten Lücke betroffen (${_kcve}); der installierte Stand ist nicht auslesbar — bitte manuell auf mindestens ${_kfix} prüfen" web
                _vuln+="${_el}"$'\t'"unbekannt"$'\t'"${_kcve}"$'\n'
              elif [[ "$_vnum" -le "$(j_vernum "$_kmax")" ]]; then
                if [[ "${_kkev}" == "ja" ]]; then
                  crit "$site: ${_el} ${_v} — ${_khinweis} Diese Lücke wird nachweislich aktiv ausgenutzt (${_kcve}). Sofort auf ${_kfix} aktualisieren." web
                else
                  crit "$site: ${_el} ${_v} — ${_khinweis} (${_kcve}) Auf ${_kfix} aktualisieren." web
                fi
                JOOMLA_FLAGS=$((JOOMLA_FLAGS+1))
                _vuln+="${_el}"$'\t'"${_v}"$'\t'"${_kcve}"$'\n'
              fi
            done < "$_krit"
          fi

          # b) Liste verwundbarer Erweiterungen
          if [[ -f "$_vel" ]]; then
            while IFS=$'\t' read -r _vell _veltyp _velf _velname _velpatch _velstatus _velcve _velurl; do
              [[ "${_vell:0:1}" == "#" || -z "${_vell:-}" ]] && continue
              [[ "$_vell" == "$_el" ]] || continue
              [[ -z "${_velf:-}" || "${_velf}" == "-" || "${_velf}" == "${_folder}" ]] || continue
              if [[ "$_velstatus" == "Live" ]]; then
                # Kein Patch verfügbar — die einzige Abhilfe ist Entfernen.
                if [[ "${_en:-0}" == "1" ]]; then
                  crit "$site: Erweiterung ${_el} steht auf der Liste verwundbarer Joomla-Erweiterungen und es existiert keine korrigierte Fassung — die Erweiterung muss entfernt werden" web
                  JOOMLA_FLAGS=$((JOOMLA_FLAGS+1))
                else
                  warn "$site: Erweiterung ${_el} steht ohne verfügbare Korrektur auf der Schwachstellenliste (derzeit deaktiviert) — entfernen statt liegenlassen" web
                fi
                _vuln+="${_el}"$'\t'"${_v}"$'\t'"kein Patch"$'\n'
              elif [[ -n "$_velpatch" && "$_vnum" -gt 0 ]]; then
                _pnum=$(j_vernum "$_velpatch")
                if [[ "$_pnum" -gt 0 && "$_vnum" -lt "$_pnum" ]]; then
                  warn "$site: Erweiterung ${_el} ${_v} ist älter als die korrigierte Fassung ${_velpatch}${_velcve:+ (${_velcve})} — aktualisieren" web
                  _vuln+="${_el}"$'\t'"${_v}"$'\t'"< ${_velpatch}"$'\n'
                fi
              fi
            done < "$_vel"
          fi
        done <<< "$_extver"

        if [[ -n "$_vuln" ]]; then
          JOOMLA_VULN_EXT+="$_vuln"
          evidence "joomla_verwundbare_erweiterungen_$(echo "$site" | tr '/.' '__')" "$_vuln"
        else
          ok "$site: keine Erweiterung mit bekannter offener Schwachstelle"
        fi

        # Webservices vergrößern die Angriffsfläche der 2026er Kern-Lücken
        # erheblich — als Kontext ausweisen, nicht als eigener Befund.
        _ws=$(j_sql "$jdb" "$jdu" "$jdp" "$jdh" \
          "SELECT COUNT(*) FROM ${jpfx}extensions WHERE type='plugin' AND folder='webservices' AND enabled=1;" 2>/dev/null | head -1 || true)
        [[ "${_ws:-0}" -gt 0 ]] && \
          info "${_ws} aktive Webservice-Bausteine — sie vergrößern die Angriffsfläche mehrerer Kern-Schwachstellen; abschalten, wenn die Programmschnittstelle nicht gebraucht wird"
      fi
    fi

    # ── 12.8 Joomla-typische Schaddateien ─────────────────────
    h2 "12.8 Joomla-typische Schaddateien — $site"
    jmal=""

    # Stärkste Regel, praktisch fehlalarmfrei: eine Datei, die der Webserver
    # als PHP ausführt, trägt in den ersten Bytes eine Bild-Kennung. Genau so
    # sehen die über die JCE-/Bildupload-Lücken abgelegten Hintertüren aus
    # (getarnt als GIF, um die Upload-Prüfung zu bestehen). Einen legitimen
    # Fall dafür gibt es nicht.
    while IFS= read -r f; do
      [[ -f "$f" ]] || continue
      case "$(head -c4 "$f" 2>/dev/null | od -An -tx1 | tr -d ' \n')" in
        47494638|89504e47|ffd8ffe0|ffd8ffe1|ffd8ffdb)
          jmal+="$f"$'\n' ;;
      esac
    done < <(find "$CURRENT_J_PATH" -type f \
               \( -iname '*.php' -o -iname '*.phtml' -o -iname '*.php[3-8]' -o -iname '*.phar' \) \
               -newermt "-${DAYS_BACK} days" 2>/dev/null | nf_strip_self)

    # PHP im BILD-Verzeichnis. Dort hat ausführbarer Code nichts zu suchen —
    # images/ nimmt Uploads auf, das ist die klassische Ablage der
    # JCE-/Medien-Uploadlücken. Hier genügt die blosse Anwesenheit.
    # Der Guard-Filter aus 7.2 hält die winzigen Schutzdateien heraus.
    while IFS= read -r f; do
      [[ -f "$f" ]] || continue
      fsize=$(stat -c%s "$f" 2>/dev/null || echo 999999)
      if [[ "$fsize" -lt 200 ]] && head -c 200 "$f" 2>/dev/null \
         | grep -qiE "silence is golden|browsing the directory is not allowed|restricted access|^<\?php[[:space:]]*$"; then
        continue
      fi
      [[ "$fsize" -lt 400 ]] && grep -qiE "_JEXEC|die\(.Restricted access" "$f" 2>/dev/null && continue
      jmal+="$f"$'\n'
    done < <(find "$CURRENT_J_PATH"/images \
               -type f \( -iname '*.php' -o -iname '*.phtml' -o -iname '*.php[3-8]' -o -iname '*.phar' \) \
               2>/dev/null | nf_strip_self)

    # Zwischenablage, Zwischenspeicher und media/: hier ist PHP NORMAL.
    # Joomla legt seinen Zwischenspeicher als .php-Dateien ab (zwei Formate:
    # '<?php die("Access Denied"); ?>#x#…' und '<?php defined(\'_JEXEC\')…
    # return […]'), der Installer entpackt Erweiterungen nach tmp/install_*,
    # und Erweiterungen liefern Code unter media/ aus.
    # Die Anwesenheit einer PHP-Datei ist deshalb KEIN Befund — nur ihr
    # Inhalt. Ohne diese Unterscheidung meldete ein realer Kundenshop 3455
    # legitime Dateien als Schadcode (Vorfall 2026-08-05).
    if [[ -n "${PATTERN_REGEX:-}" ]]; then
      while IFS= read -r f; do
        [[ -f "$f" ]] && jmal+="$f"$'\n'
      done < <(grep -rlPi "${PATTERN_REGEX}" \
                 "$CURRENT_J_PATH"/tmp "$CURRENT_J_PATH"/cache \
                 "$CURRENT_J_PATH"/administrator/cache "$CURRENT_J_PATH"/media \
                 --include='*.php' --include='*.phtml' --include='*.php[3-8]' --include='*.phar' \
                 2>/dev/null | nf_strip_self)
    fi

    # Zurückgebliebene Installer-Verzeichnisse. Der Joomla-Installer entpackt
    # jedes Paket nach tmp/install_<hex>/ und räumt danach auf — bleibt es
    # liegen, steht der vollständige Quellcode der Erweiterung dauerhaft in
    # einem web-erreichbaren Verzeichnis. Das ist ein Hygiene- und
    # Informationsleck, aber KEIN Schadcode: deshalb eine Meldung je
    # Verzeichnis statt tausender Dateibefunde.
    _inst=$(find "$CURRENT_J_PATH/tmp" -maxdepth 1 -type d -name 'install_*' 2>/dev/null || true)
    if [[ -n "$_inst" ]]; then
      _n=$(printf '%s\n' "$_inst" | grep -c . || true)
      warn "$site: ${_n} zurückgebliebene(s) Installations-Verzeichnis(se) unter tmp/ — sie enthalten den vollständigen Quellcode installierter Erweiterungen und sind über den Browser erreichbar; nach einem Update aufräumen" web
      code "$(printf '%s' "$_inst" | sed "s|${CURRENT_J_PATH}/||")"
    fi

    # Gemischte Groß-/Kleinschreibung der Endung (.pHp) — reine Umgehung von
    # Upload-Filtern, in einer gewachsenen Installation gibt es das nicht.
    while IFS= read -r f; do
      [[ -f "$f" ]] && jmal+="$f"$'\n'
    done < <(find "$CURRENT_J_PATH" -type f -name '*.[pP][hH][pP]' ! -name '*.php' 2>/dev/null | nf_strip_self)

    # Ausführbarer Code VOR der Zugriffssperre in den Einstiegsdateien.
    # Jede Joomla-Datei beginnt mit Kommentar und defined('_JEXEC') or die;
    # Steht davor Code, wurde die Datei vorne aufgebohrt.
    for _entry in index.php administrator/index.php api/index.php includes/framework.php; do
      _ep="${CURRENT_J_PATH}/${_entry}"
      [[ -f "$_ep" ]] || continue
      _guard=$(grep -n "_JEXEC\|JPATH_BASE" "$_ep" 2>/dev/null | head -1 | cut -d: -f1)
      [[ -n "$_guard" ]] || continue
      if head -n "$((_guard - 1))" "$_ep" 2>/dev/null \
         | grep -qEi '(\beval[[:space:]]*\(|base64_decode|gzinflate|\$_(POST|GET|REQUEST|COOKIE)|@?include[[:space:]]*\(|file_get_contents[[:space:]]*\([[:space:]]*.php://input)'; then
        jmal+="$_ep"$'\n'
      fi
    done

    # Das Installationsverzeichnis gehört nach dem Aufsetzen gelöscht —
    # bleibt es liegen, kann die Seite darüber neu aufgesetzt und übernommen
    # werden.
    if [[ -d "${CURRENT_J_PATH}/installation" ]]; then
      crit "$site: Das Installationsverzeichnis ist noch vorhanden — darüber lässt sich die Seite neu aufsetzen und übernehmen; es muss gelöscht werden" web
      JOOMLA_FLAGS=$((JOOMLA_FLAGS+1))
    fi

    # jDownloads CVE-2026-61900: ein im Paket vergessener Test-Uploader ohne
    # jede Rechte- oder Sitzungsprüfung. Die reine Existenz der Datei genügt.
    _jdl="${CURRENT_J_PATH}/administrator/components/com_jdownloads/assets/upload/upload-handler.php"
    if [[ -f "$_jdl" ]]; then
      crit "$site: Die Erweiterung jDownloads enthält eine ungeschützte Upload-Datei, über die jeder ohne Anmeldung Dateien hochladen kann (CVE-2026-61900) — auf 4.1.6 aktualisieren" web
      JOOMLA_FLAGS=$((JOOMLA_FLAGS+1))
      jmal+="$_jdl"$'\n'
    fi

    # Automatisch vorgeschaltete PHP-Datei: eine der unauffälligsten
    # Dauerzugriffs-Methoden, weil kein einziger Aufruf sie sichtbar macht.
    _prep=$(grep -rlE '(auto_prepend_file|auto_append_file)' \
              "$CURRENT_J_PATH" --include='.htaccess' --include='.user.ini' --include='php.ini' 2>/dev/null | head -20 || true)
    if [[ -n "$_prep" ]]; then
      crit "$site: In der Server-Konfiguration wird eine PHP-Datei automatisch vor jedem Seitenaufruf geladen — typische, von aussen unsichtbare Hintertür" web
      JOOMLA_FLAGS=$((JOOMLA_FLAGS+1))
      code "$_prep"
      evidence "joomla_auto_prepend_$(echo "$site" | tr '/.' '__')" "$_prep"
    fi

    # Sicherungsarchive ausserhalb des Backup-Verzeichnisses: ein per Browser
    # erreichbares .jpa enthält die komplette Seite inklusive Datenbank und
    # aller Passwort-Hashes.
    _arch=$(find "$CURRENT_J_PATH" -maxdepth 3 -type f \( -iname '*.jpa' -o -iname '*.jps' -o -iname '*.j01' \) \
              2>/dev/null | grep -viE 'com_akeeba[a-z]*/backup/' | head -20 || true)
    if [[ -n "$_arch" ]]; then
      crit "$site: Sicherungsarchiv der Seite ausserhalb des geschützten Backup-Ordners — es enthält Datenbank und Passwörter und ist ggf. über den Browser abrufbar" web
      JOOMLA_FLAGS=$((JOOMLA_FLAGS+1))
      code "$_arch"
    fi

    jmal=$(printf '%s' "$jmal" | grep -v '^$' | sort -u || true)
    if [[ -n "$jmal" ]]; then
      _n=$(printf '%s\n' "$jmal" | grep -c . || true)
      crit "$site: ${_n} Schaddatei(en) mit Joomla-typischem Muster — als Bild getarnte oder in Medienordnern abgelegte Hintertüren" web
      JOOMLA_FLAGS=$((JOOMLA_FLAGS+1))
      JOOMLA_MALWARE+="$jmal"$'\n'
      code "$(printf '%s' "$jmal" | head -20)"
      evidence "joomla_schaddateien_$(echo "$site" | tr '/.' '__')" \
        "$(while IFS= read -r f; do [[ -f "$f" ]] && printf '%s  %s  %s\n' "$(stat -c%s "$f" 2>/dev/null)" "$(date -d "@$(stat -c%Y "$f" 2>/dev/null)" +%F 2>/dev/null)" "$f"; done <<< "$jmal")"
    else
      ok "$site: keine Joomla-typischen Schaddateien gefunden"
    fi

    # ── 12.9 Angriffsspuren in den Zugriffsprotokollen ────────
    # WICHTIG in der Formulierung: ein Protokolleintrag belegt den VERSUCH,
    # nicht den Erfolg. Nur zusammen mit einem Dateifund wird daraus ein
    # kritischer Befund.
    _jvhost=$(printf '%s' "$site" | cut -d/ -f1)
    _jlogs=$(ls "${VHOSTS_DIR}/${_jvhost}/logs/"access*log* 2>/dev/null || true)
    if [[ -n "$_jlogs" ]]; then
      _ioc=$(grep -hoiE 'BOT/0\.1 \(BOT for JCE\)|icagenda-batch/1\.0|task=profiles\.import|task=asset(\.|%2e)uploadCustomIcon|option=com_users&task=user\.register|plugin=helix3' \
               "${VHOSTS_DIR}/${_jvhost}/logs/"access*log* 2>/dev/null | sort | uniq -c | sort -rn || true)
      if [[ -n "$_ioc" ]]; then
        if [[ -n "$jmal" ]]; then
          crit "$site: In den Zugriffsprotokollen stehen Aufrufe bekannter Joomla-Angriffswege — zusammen mit den gefundenen Schaddateien ist das der belegte Angriffsweg" web
          JOOMLA_FLAGS=$((JOOMLA_FLAGS+1))
        else
          warn "$site: In den Zugriffsprotokollen stehen Aufrufe bekannter Joomla-Angriffswege — das belegt Angriffsversuche, nicht deren Erfolg" web
        fi
        code "$_ioc"
        JOOMLA_LOG_IOC+="$_ioc"$'\n'
        evidence "joomla_log_ioc_$(echo "$site" | tr '/.' '__')" "$_ioc"
      else
        ok "$site: keine bekannten Joomla-Angriffsmuster in den Zugriffsprotokollen"
      fi
    fi

  done <<< "$JOOMLA_CONFIGS"
fi

# ── 12.10 Joomla-Verdikt ──────────────────────────────────────
if [[ "$JOOMLA_COUNT" -gt 0 ]]; then
  h2 "12.10 Joomla-Verdikt"
  if [[ "$JOOMLA_FLAGS" -eq 0 ]]; then
    JOOMLA_VERDICT="🟢 **Keine Angreifer-Spuren in den Joomla-Installationen** — Version schlüssig, Konfiguration ohne kritische Schwächen, kein Hinweis auf einen Datenabfluss über die Programmschnittstelle."
    ok "JOOMLA-VERDIKT: unauffällig"
  else
    JOOMLA_VERDICT="🔴 **Joomla-Installation(en) auffällig** (${JOOMLA_FLAGS} kritische(r) Befund(e)) — Version, Konfiguration und Zugangsdaten prüfen und bereinigen."
    crit "JOOMLA-VERDIKT: ${JOOMLA_FLAGS} kritische(r) Befund(e)" web
  fi
  echo -e "\n$JOOMLA_VERDICT\n" >> "$REPORT_FILE"
fi

# Netzabrufe ausweisen — ein Lauf, der das Netz berührt hat, darf nicht
# behaupten, rein lokal gewesen zu sein.
if [[ -n "$ONLINE_FETCHES" ]]; then
  h2 "12.11 Netzabrufe dieses Laufs (--online)"
  info "Dieser Lauf hat $(printf '%s\n' "$ONLINE_FETCHES" | grep -c . || true) Abruf(e) aus dem Netz durchgeführt."
  code "$ONLINE_FETCHES"
  evidence "online_abrufe" "$ONLINE_FETCHES"
fi

# ============================================================
