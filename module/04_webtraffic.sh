# shellcheck shell=bash
# NT-Forensik — Abschnitt 4: Web-Traffic-Analyse
#
# @nummer:  4
# @titel:   Web-Traffic-Analyse
# @frage:   Welche Angriffsversuche stehen in den Zugriffsprotokollen?
# @kosten:  mittel — abhängig von der Protokollgröße
# @ebene:   website
#
# Wird vom Runner eingebunden, nicht einzeln ausgefuehrt.
# Vorgabewerte der hier gefuellten Variablen: lib/befunde.sh

# Belegstufe dieses Abschnitts (#1). Bewusst `server` und nicht `kunde`, obwohl die Belege nach Domain benannt
# sind: im Betreiberlauf stehen darin die Logzeilen ALLER Domains, auch
# fremder. Was davon zum Kunden darf, entscheidet die Maskierung im Paket.
BELEG_STUFE=server

h1 "4. WEB-TRAFFIC ANALYSE"
# ============================================================

h2 "4.1 Access-Logs auf Angriffsmuster prüfen"

TOTAL_SCANNER_HITS=0
TOTAL_SHELL_POSTS=0
ATTACK_IPS_ALL=""

# ── Anonymisierte Zugriffsprotokolle (#142) ─────────────────
# Plesk kann die Client-Adressen bei der Logrotation kuerzen ("Anonymize IPs
# during log rotation", Tools & Settings > Server Settings — serverweit, nicht
# je Abo): IPv4 verliert das letzte Oktett, IPv6 die letzte Gruppe. Die
# aktuelle Datei bleibt voll, erst die Rotation ist gekuerzt.
#
# Anlass 21.10.2026 web68/cletus: Bis 06:43 stand der Angreifer-Request mit
# 43.250.53.42 im access_ssl_log.processed. Nach der Rotation lag nur noch
# 43.250.53.0 in .processed.1.gz — und genau das trugen IOC-Liste,
# Kundenbericht und BSI-Meldung weiter. NT-Repair haette eine Netzadresse als
# Einzel-IP gesperrt, und ein /24 ist kein Indikator, sondern 256 Nachbarn.
#
# Die Einstellung selbst wird NICHT ausgelesen: Plesk bietet dafuer keine
# CLI, und wo sie in der psa-Datenbank steht, ist nicht belegt. Gemessen wird
# deshalb, was zaehlt — die Dateien. In einem vollen Protokoll endet etwa
# jede 256. IPv4-Adresse auf .0; ab 95 % ist die Datei gekuerzt, ab 20 %
# gemischt (eine .processed-Datei, in die Plesk schon gekuerzte Zeilen
# geschrieben hat). Unter 10 Adressen gibt es kein Urteil.
LOGS_ANONYMISIERT=0   # 1 = IOC-Adressen auf .0 aus gekuerzten Protokollen
ANON_IOC_IPS=""       # genau diese Adressen
ANON_DATEIEN=""       # Datei<TAB>gekuerzt/gesamt<TAB>Urteil, nur auffaellige
ANON_GEMISCHT_VHOSTS="" # aktuelle Datei voll, Rotation gekuerzt

log_anonym_lesen() {    # <protokoll> → Klartext, gleich ob rotiert und gepackt
  case "$1" in
    *.gz)  gzip  -dc -- "$1" 2>/dev/null ;;
    *.bz2) bzip2 -dc -- "$1" 2>/dev/null ;;
    *.xz)  xz    -dc -- "$1" 2>/dev/null ;;
    *)     cat       -- "$1" 2>/dev/null ;;
  esac
}

# Die ersten 2000 Zeilen reichen fuer das Urteil — eine Rotation ist ganz
# oder gar nicht gekuerzt, und 475 vhosts mit je zehn .gz voll zu entpacken
# waere der teuerste Schritt des Abschnitts.
log_anonym_urteil() {   # <protokoll> → "gekuerzt gesamt urteil"
  { log_anonym_lesen "$1" | head -n 2000 || true; } | awk '
    $1 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ { n++; if ($1 ~ /\.0$/) a++; next }
    $1 ~ /^[0-9A-Fa-f:]+$/ && $1 ~ /:/      { n++; if ($1 ~ /(::|:0)$/) a++ }
    END {
      u = "voll"
      if (n < 10)               u = "ohne_urteil"
      else if (a * 100 >= n * 95) u = "anonymisiert"
      else if (a * 100 >= n * 20) u = "gemischt"
      printf "%d %d %s\n", a, n, u
    }'
}

# Zugriffsprotokolle eines vhosts an beiden Plesk-Orten, jede Datei einmal
# (<vhost>/logs und system/<d>/logs sind dieselbe Datei).
log_anonym_dateien() {  # <vhost-verzeichnis>
  local vd="$1" d f k gesehen=""
  for d in "${vd}/logs" "${VHOSTS_DIR:-/var/www/vhosts}/system/$(basename "$vd")/logs"; do
    [[ -d "$d" ]] || continue
    for f in "$d"/*access*log*; do
      [[ -f "$f" ]] || continue
      k=$(stat -c '%d:%i' "$f" 2>/dev/null || stat -f '%d:%i' "$f" 2>/dev/null || printf '%s' "$f")
      case " ${gesehen} " in *" ${k} "*) continue ;; esac
      gesehen+=" ${k}"
      printf '%s\n' "$f"
    done
  done
}

# Je Datei ausweisen, nicht je vhost: der Normalfall ist gerade die Mischung
# — aktuelle Datei voll, alle Rotationen gekuerzt. Dann gilt die volle
# Adresse nur noch bis zur naechsten Rotation.
log_anonym_vhost() {    # <vhost-verzeichnis> <label>
  local f a n u voll=0 gek=0
  while IFS= read -r f; do
    [[ -n "$f" ]] || continue
    read -r a n u < <(log_anonym_urteil "$f")
    case "$u" in
      anonymisiert|gemischt)
        ANON_DATEIEN+="${f}"$'\t'"${a}/${n}"$'\t'"${u}"$'\n'
        gek=1 ;;
      voll) [[ "$f" == *.gz || "$f" == *.bz2 || "$f" == *.xz || "$f" == *.[0-9] ]] || voll=1 ;;
    esac
  done < <(log_anonym_dateien "$1")
  if [[ "$voll" -eq 1 && "$gek" -eq 1 ]]; then ANON_GEMISCHT_VHOSTS+="$2"$'\n'; fi
  return 0
}

analyze_access_log() {
  local logfile="$1"
  local domain_label="$2"

  if [[ ! -f "$logfile" ]]; then return; fi

  echo -e "  ${CYN}Analysiere:${NC} $logfile"
  echo -e "\n#### $domain_label — $(basename "$logfile")\n" >> "$REPORT_FILE"

  # Gekuerzt oder gemischt? Dann sind .0-Adressen aus DIESER Datei keine
  # Einzel-IPs (#142). Eine Datei ohne Urteil zaehlt als voll.
  local anon_urteil
  anon_urteil=$(log_anonym_urteil "$logfile" | awk '{print $3}')

  # SQLMap / bekannte Scanner
  local scanner_hits
  scanner_hits=$(count_grep_i "sqlmap|nikto|havij|acunetix|nessus|openvas|masscan|zgrab|nuclei" "$logfile")
  TOTAL_SCANNER_HITS=$((TOTAL_SCANNER_HITS + scanner_hits))
  if [[ "$scanner_hits" -gt 0 ]]; then
    crit "$domain_label: Scanner-Aktivität erkannt ($scanner_hits Treffer)" web
    local scanner_lines
    scanner_lines=$(grep -iE "sqlmap|nikto|havij|acunetix|nessus|nuclei" "$logfile" 2>/dev/null | head -20 || true)
    code "$scanner_lines"
    evidence "scanner_${domain_label}" "$scanner_lines"
    ATTACK_IPS_ALL+=$(echo "$scanner_lines" | awk '{print $1}')$'\n'
    [[ "$anon_urteil" == anonymisiert || "$anon_urteil" == gemischt ]] && \
      ANON_IOC_IPS+=$(echo "$scanner_lines" | awk '$1 ~ /\.0$/ {print $1}')$'\n'
  else
    ok "$domain_label: Keine bekannten Scanner-User-Agents"
  fi

  # Webshell-typische POST-Requests
  local shell_posts
  shell_posts=$(count_grep "POST.*(wp-content/uploads|eval|base64|cmd=|shell=)" "$logfile")
  TOTAL_SHELL_POSTS=$((TOTAL_SHELL_POSTS + shell_posts))
  if [[ "$shell_posts" -gt 0 ]]; then
    crit "$domain_label: Verdächtige POST-Requests ($shell_posts)" web
    local shell_lines
    shell_lines=$(grep -E "POST.*(wp-content/uploads|eval|base64)" "$logfile" 2>/dev/null | head -20 || true)
    code "$shell_lines"
    evidence "shell_posts_${domain_label}" "$shell_lines"
    ATTACK_IPS_ALL+=$(echo "$shell_lines" | awk '{print $1}')$'\n'
    [[ "$anon_urteil" == anonymisiert || "$anon_urteil" == gemischt ]] && \
      ANON_IOC_IPS+=$(echo "$shell_lines" | awk '$1 ~ /\.0$/ {print $1}')$'\n'
  else
    ok "$domain_label: Keine offensichtlichen Webshell-POST-Requests"
  fi

  # 4xx/5xx Anomalien
  local error_count
  error_count=$(count_grep " (4[0-9]{2}|5[0-9]{2}) " "$logfile")
  info "HTTP-Fehler gesamt: $error_count"

  # Top-IPs
  local top_ips
  top_ips=$(awk '{print $1}' "$logfile" 2>/dev/null | LC_ALL=C sort | uniq -c | LC_ALL=C sort -rn | awk 'NR<=10' || true)
  info "Top-IPs nach Request-Anzahl:"
  code "$top_ips"

  # wp-login Brute-Force
  local wplogin
  wplogin=$(count_grep "POST.*wp-login\.php" "$logfile")
  if [[ "$wplogin" -gt 20 ]]; then
    warn "$domain_label: Möglicher wp-login Brute-Force ($wplogin POST-Requests)" web
    local wp_ips
    wp_ips=$(grep -E "POST.*wp-login" "$logfile" 2>/dev/null | awk '{print $1}' | LC_ALL=C sort | uniq -c | LC_ALL=C sort -rn | awk 'NR<=10' || true)
    code "$wp_ips"
    evidence "wplogin_bruteforce_${domain_label}" "$wp_ips"
  else
    ok "$domain_label: wp-login unauffällig ($wplogin POSTs)"
  fi

  # xmlrpc-Angriffe
  local xmlrpc
  xmlrpc=$(count_grep "POST.*xmlrpc\.php" "$logfile")
  if [[ "$xmlrpc" -gt 50 ]]; then
    warn "$domain_label: xmlrpc.php-Angriffe möglich ($xmlrpc POSTs)" web
  fi
}

if [[ -n "$DOMAIN" ]]; then
  for log in \
    "${VHOSTS_DIR}/${DOMAIN}/logs/access_log" \
    "${VHOSTS_DIR}/${DOMAIN}/logs/access_log_processed" \
    "${VHOSTS_DIR}/${DOMAIN}/logs/access_ssl_log" \
    "${VHOSTS_DIR}/${DOMAIN}/logs/proxy_access_log" \
    "${VHOSTS_DIR}/${DOMAIN}/logs/proxy_access_ssl_log"; do
    analyze_access_log "$log" "$DOMAIN"
  done
  log_anonym_vhost "${VHOSTS_DIR}/${DOMAIN}" "$DOMAIN"
else
  # Nur die Verzeichnisse des Scopes. Vorher lief die Schleife immer ueber
  # ${VHOSTS_DIR}/*, sodass --path und --webNN hier ohne Wirkung blieben.
  while IFS= read -r domain_dir; do
    [[ -d "$domain_dir" ]] || continue
    d=$(basename "$domain_dir")
    [[ "$d" == "system" || "$d" == "chroot" ]] && continue
    for log in "$domain_dir/logs/access_log" "$domain_dir/logs/access_ssl_log"; do
      analyze_access_log "$log" "$d"
    done
    log_anonym_vhost "$domain_dir" "$d"
  done < <(scope_vhost_dirs)
fi

# Angreifer-IP-Liste konsolidieren (für BSI-Meldung / IOCs)
ATTACK_IPS_UNIQ=$(echo "$ATTACK_IPS_ALL" | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' \
  | LC_ALL=C sort | uniq -c | LC_ALL=C sort -rn | awk 'NR<=20' || true)
if [[ -n "$ATTACK_IPS_UNIQ" ]]; then
  evidence "angreifer_ips_konsolidiert" "$ATTACK_IPS_UNIQ"
fi

# Gekuerzte Protokolle ausweisen (#142). ⚪ nur, wenn die IOC-Liste wirklich
# eine Netzadresse traegt — sonst blockierte ein serverweit gekuerzter
# Plesk jede gruene Ampel, auch ohne einen einzigen Angreifer. Der Kennwert
# geht nach findings.json (metrics.logs_anonymisiert), damit NT-Repair eine
# .0-Adresse nicht als Einzel-IP sperrt.
ANON_IOC_IPS=$(printf '%s\n' "$ANON_IOC_IPS" | grep -E '^[0-9]+(\.[0-9]+){3}$' | LC_ALL=C sort -u || true)
if [[ -n "$ANON_DATEIEN" ]]; then
  evidence "zugriffsprotokolle_anonymisiert" "$(printf 'datei\tgekuerzt/gesamt\turteil\n%s' "$ANON_DATEIEN")"
fi
if [[ -n "$ANON_IOC_IPS" ]]; then
  LOGS_ANONYMISIERT=1
  unklar "IOC-Adressen nur als /24 — Zugriffsprotokolle anonymisiert ($(printf '%s\n' "$ANON_IOC_IPS" | paste -sd, - | sed 's/,/, /g')); volle Adresse nicht mehr im Protokoll" web
elif [[ -n "$ANON_DATEIEN" ]]; then
  info "Zugriffsprotokolle anonymisiert (Plesk-Logrotation kuerzt auf /24) — $(printf '%s' "$ANON_DATEIEN" | grep -c .) Datei(en), Beleg zugriffsprotokolle_anonymisiert"
fi
if [[ -n "$ANON_GEMISCHT_VHOSTS" ]]; then
  info "Aktuelles Protokoll voll, Rotationen gekuerzt: $(printf '%s' "$ANON_GEMISCHT_VHOSTS" | paste -sd, - | sed 's/,/, /g') — volle Adressen nur bis zur naechsten Plesk-Rotation, Roh-Protokolle jetzt sichern (docs/incident-response.md)"
fi

# ============================================================