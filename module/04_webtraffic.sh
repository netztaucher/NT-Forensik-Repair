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

h1 "4. WEB-TRAFFIC ANALYSE"
# ============================================================

h2 "4.1 Access-Logs auf Angriffsmuster prüfen"

TOTAL_SCANNER_HITS=0
TOTAL_SHELL_POSTS=0
ATTACK_IPS_ALL=""

analyze_access_log() {
  local logfile="$1"
  local domain_label="$2"

  if [[ ! -f "$logfile" ]]; then return; fi

  echo -e "  ${CYN}Analysiere:${NC} $logfile"
  echo -e "\n#### $domain_label — $(basename "$logfile")\n" >> "$REPORT_FILE"

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
  else
    ok "$domain_label: Keine offensichtlichen Webshell-POST-Requests"
  fi

  # 4xx/5xx Anomalien
  local error_count
  error_count=$(count_grep " (4[0-9]{2}|5[0-9]{2}) " "$logfile")
  info "HTTP-Fehler gesamt: $error_count"

  # Top-IPs
  local top_ips
  top_ips=$(awk '{print $1}' "$logfile" 2>/dev/null | sort | uniq -c | sort -rn | head -10 || true)
  info "Top-IPs nach Request-Anzahl:"
  code "$top_ips"

  # wp-login Brute-Force
  local wplogin
  wplogin=$(count_grep "POST.*wp-login\.php" "$logfile")
  if [[ "$wplogin" -gt 20 ]]; then
    warn "$domain_label: Möglicher wp-login Brute-Force ($wplogin POST-Requests)" web
    local wp_ips
    wp_ips=$(grep -E "POST.*wp-login" "$logfile" 2>/dev/null | awk '{print $1}' | sort | uniq -c | sort -rn | head -10 || true)
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
  done < <(scope_vhost_dirs)
fi

# Angreifer-IP-Liste konsolidieren (für BSI-Meldung / IOCs)
ATTACK_IPS_UNIQ=$(echo "$ATTACK_IPS_ALL" | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' \
  | sort | uniq -c | sort -rn | head -20 || true)
if [[ -n "$ATTACK_IPS_UNIQ" ]]; then
  evidence "angreifer_ips_konsolidiert" "$ATTACK_IPS_UNIQ"
fi

# ============================================================