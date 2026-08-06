# NT-Forensik — Abschnitt 3: Zugriffs-Analyse
#
# @nummer:  3
# @titel:   Zugriffs-Analyse
# @frage:   Wer hat sich angemeldet, und wurde ein Zugang durchprobiert?
# @kosten:  gering
# @ebene:   system
#
# Wird vom Runner eingebunden, nicht einzeln ausgefuehrt.
# Vorgabewerte der hier gefuellten Variablen: lib/befunde.sh

h1 "3. ZUGRIFFS-ANALYSE"
# ============================================================

h2 "3.1 SSH-Logins (letzte 50)"
SSH_LOGINS=$(last -n 50 2>/dev/null || true)
code "$SSH_LOGINS"
evidence "ssh_logins_last50" "$SSH_LOGINS"

ROOT_LOGINS=$(echo "$SSH_LOGINS" | grep "^root" || true)
if [[ -n "$ROOT_LOGINS" ]]; then
  warn "Root-Logins gefunden (Details: technik_bericht.md §3.1)"
  code "$ROOT_LOGINS"
else
  ok "Keine direkten Root-Logins via 'last'"
fi

h2 "3.2 Fehlgeschlagene SSH-Versuche"
AUTH_LOG=""
for log in /var/log/auth.log /var/log/secure; do
  [[ -f "$log" ]] && AUTH_LOG="$log" && break
done

SSH_FAILED_COUNT=0
TOP_FAIL_IPS=""
if [[ -n "$AUTH_LOG" ]]; then
  SSH_FAILED_COUNT=$(count_grep "Failed password|Invalid user|authentication failure" "$AUTH_LOG")
  info "Fehlversuche gesamt: $SSH_FAILED_COUNT"

  TOP_FAIL_IPS=$(grep -E "Failed password|Invalid user" "$AUTH_LOG" 2>/dev/null \
    | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' \
    | sort | uniq -c | sort -rn | head -10 || true)

  if [[ -n "$TOP_FAIL_IPS" ]]; then
    warn "SSH-Brute-Force-Aktivität: $SSH_FAILED_COUNT Fehlversuche"
    code "$TOP_FAIL_IPS"
    evidence "ssh_bruteforce_top_ips" "$TOP_FAIL_IPS"
  fi

  ACCEPTED=$(grep "Accepted" "$AUTH_LOG" 2>/dev/null | tail -20 || true)
  if [[ -n "$ACCEPTED" ]]; then
    info "Erfolgreiche SSH-Authentifizierungen (letzte 20):"
    code "$ACCEPTED"
    evidence "ssh_erfolgreiche_logins" "$ACCEPTED"
  fi
else
  warn "Auth-Log nicht gefunden (/var/log/auth.log oder /var/log/secure)"
fi

h2 "3.3 Plesk Panel-Logins"
if [[ -f "$PLESK_PANEL_LOG" ]]; then
  PANEL_LOGINS=$(grep -iE "login|auth|session" "$PLESK_PANEL_LOG" 2>/dev/null | tail -30 || true)
  if [[ -n "$PANEL_LOGINS" ]]; then
    code "$PANEL_LOGINS"
    evidence "plesk_panel_logins" "$PANEL_LOGINS"
  else
    info "Keine Login-Einträge im Panel-Log gefunden"
  fi
else
  warn "Plesk Panel-Log nicht gefunden: $PLESK_PANEL_LOG"
  info "Manuell prüfen: Plesk → Tools & Einstellungen → Aktionsprotokoll"
fi

h2 "3.4 FTP-Zugriffe"
FTP_LOG=""
for log in /var/log/proftpd/proftpd.log /var/log/vsftpd.log /var/log/pure-ftpd/transfer.log; do
  [[ -f "$log" ]] && FTP_LOG="$log" && break
done

if [[ -n "$FTP_LOG" ]]; then
  FTP_IPS=$(awk '{print $NF}' "$FTP_LOG" 2>/dev/null | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' \
    | sort | uniq -c | sort -rn | head -15 || true)
  info "FTP-Zugriffs-IPs (häufigste):"
  code "$FTP_IPS"
  FTP_RECENT=$(tail -30 "$FTP_LOG" 2>/dev/null || true)
  code "$FTP_RECENT"
  evidence "ftp_zugriffe" "TOP-IPs:
$FTP_IPS

LETZTE EINTRÄGE:
$FTP_RECENT"
else
  warn "Kein FTP-Log gefunden — möglicherweise kein FTP-Dienst oder andere Konfiguration"
fi

# ============================================================
