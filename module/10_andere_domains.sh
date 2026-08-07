# shellcheck shell=bash
# NT-Forensik — Abschnitt 10: Andere Domains
#
# @nummer:  10
# @titel:   Andere Domains
# @frage:   Sind weitere Kunden auf demselben Server mitbetroffen?
# @kosten:  gering bis mittel
# @ebene:   system
#
# Wird vom Runner eingebunden, nicht einzeln ausgefuehrt.
# Vorgabewerte der hier gefuellten Variablen: lib/befunde.sh

h1 "10. ANDERE DOMAINS AUF DEM SERVER"
# ============================================================

h2 "10.1 Alle Plesk-Domains"
ALL_DOMAINS=""
DOMAIN_COUNT=0
if [[ -d "$VHOSTS_DIR" ]]; then
  ALL_DOMAINS=$(find "$VHOSTS_DIR" -maxdepth 1 -mindepth 1 -type d ! -name system ! -name chroot -printf "%f\n" 2>/dev/null | sort || ls "$VHOSTS_DIR")
  DOMAIN_COUNT=$(echo "$ALL_DOMAINS" | grep -c . || true)
  info "Domains auf dem Server: $DOMAIN_COUNT"
  code "$ALL_DOMAINS"
  evidence "alle_domains" "$ALL_DOMAINS"
fi

h2 "10.2 Scanner-Aktivität bei anderen Domains"
if [[ -d "$VHOSTS_DIR" ]]; then
  echo -e "\n| Domain | Scanner-Hits | Shell-POSTs |" >> "$REPORT_FILE"
  echo -e "|---|---|---|" >> "$REPORT_FILE"
  CROSS_DOMAIN=""
  for domain_dir in "$VHOSTS_DIR"/*/; do
    d=$(basename "$domain_dir")
    [[ "$d" == "system" || "$d" == "chroot" ]] && continue
    log="$domain_dir/logs/access_log"
    if [[ -f "$log" ]]; then
      SCANNERS=$(count_grep_i "sqlmap|nikto|havij" "$log")
      SHELLS=$(count_grep "POST.*(wp-content/uploads|eval|base64)" "$log")
      echo "| $d | $SCANNERS | $SHELLS |" >> "$REPORT_FILE"
      CROSS_DOMAIN+="$d Scanner=$SCANNERS Shell-POSTs=$SHELLS"$'\n'
      if [[ "$SCANNERS" -gt 0 || "$SHELLS" -gt 0 ]]; then
        warn "$d: Scanner=$SCANNERS, Shell-POSTs=$SHELLS"
      fi
    fi
  done
  [[ -n "$CROSS_DOMAIN" ]] && evidence "scanner_alle_domains" "$CROSS_DOMAIN"
fi

# ============================================================