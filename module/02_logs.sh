# shellcheck shell=bash
# NT-Forensik — Abschnitt 2: Logs sichern
#
# @nummer:  2
# @titel:   Logs sichern
# @frage:   Sind die Protokolle gesichert, bevor die Rotation sie vernichtet?
# @kosten:  HOCH — archiviert alle Serverlogs; auf Servern mit vielen Vhosts sehr langsam
# @ebene:   system
#
# Wird vom Runner eingebunden, nicht einzeln ausgefuehrt.
# Vorgabewerte der hier gefuellten Variablen: lib/befunde.sh

h1 "2. LOGS SICHERN"
# ============================================================

h2 "2.1 Log-Archiv erstellen"
echo -e "  ${YLW}Erstelle Log-Archiv (kann einen Moment dauern...)${NC}"

LOG_PATHS=(
  "/var/log/auth.log"
  "/var/log/auth.log.1"
  "/var/log/secure"
  "/var/log/messages"
  "/var/log/syslog"
  "/var/log/fail2ban.log"
  "/var/log/modsec_audit.log"
  "/var/log/proftpd"
  "/var/log/vsftpd.log"
  "/var/log/maillog"
  "${PLESK_LOG_DIR}"
)

# Domain-spezifische Logs (Plesk: /var/www/vhosts/<domain>/logs/)
if [[ -n "$DOMAIN" && -d "${VHOSTS_DIR}/${DOMAIN}/logs" ]]; then
  LOG_PATHS+=("${VHOSTS_DIR}/${DOMAIN}/logs")
elif [[ -d "$VHOSTS_DIR" ]]; then
  while IFS= read -r d; do
    [[ -d "$d/logs" ]] && LOG_PATHS+=("$d/logs")
  done < <(find "$VHOSTS_DIR" -maxdepth 1 -mindepth 1 -type d 2>/dev/null)
fi

EXISTING_LOGS=()
for p in "${LOG_PATHS[@]}"; do
  [[ -e "$p" ]] && EXISTING_LOGS+=("$p")
done

if [[ ${#EXISTING_LOGS[@]} -gt 0 ]]; then
  tar czf "$LOG_ARCHIVE" "${EXISTING_LOGS[@]}" 2>/dev/null || true
  ok "Log-Archiv erstellt: $LOG_ARCHIVE"
  ARCHIVE_SIZE=$(du -sh "$LOG_ARCHIVE" 2>/dev/null | cut -f1)
  info "Archivgröße: $ARCHIVE_SIZE"
  code "$(tar tzf "$LOG_ARCHIVE" 2>/dev/null | head -30)"
  evidence "log_archiv_inhalt" "$(tar tzf "$LOG_ARCHIVE" 2>/dev/null)"
else
  warn "Keine Logs zum Archivieren gefunden"
fi

# ============================================================