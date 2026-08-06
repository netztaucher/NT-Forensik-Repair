# NT-Forensik — Abschnitt 9: Sicherheits-Dienste
#
# Wird vom Runner eingebunden, nicht einzeln ausgefuehrt.
# Vorgabewerte der hier gefuellten Variablen: lib/befunde.sh

h1 "9. SICHERHEITS-DIENSTE"
# ============================================================

h2 "9.1 Fail2ban Status"
if command -v fail2ban-client &>/dev/null; then
  F2B_STATUS=$(fail2ban-client status 2>/dev/null || echo "Nicht erreichbar")
  ok "Fail2ban installiert: $(fail2ban-client version 2>/dev/null || true)"
  code "$F2B_STATUS"
  JAILS=$(echo "$F2B_STATUS" | grep "Jail list" | sed 's/.*Jail list://;s/,/ /g' | xargs || true)
  for jail in $JAILS; do
    code "$(fail2ban-client status "$jail" 2>/dev/null | head -10)"
  done
  evidence "fail2ban_status" "$F2B_STATUS"
else
  warn "Fail2ban nicht installiert — dringend empfohlen"
fi

h2 "9.2 ModSecurity"
MODSEC_CONF=""
for f in /etc/apache2/mods-enabled/security2.conf /etc/nginx/modsec/modsecurity.conf; do
  [[ -f "$f" ]] && MODSEC_CONF="$f" && break
done

if [[ -n "$MODSEC_CONF" ]]; then
  ok "ModSecurity-Konfiguration gefunden: $MODSEC_CONF"
  code "$(grep -E "^SecRuleEngine|^SecRequestBodyAccess" "$MODSEC_CONF" 2>/dev/null || true)"
  if [[ -f /var/log/modsec_audit.log ]]; then
    MODSEC_ALERTS=$(wc -l < /var/log/modsec_audit.log 2>/dev/null || echo "0")
    info "ModSecurity Audit-Log-Einträge: $MODSEC_ALERTS"
    code "$(tail -20 /var/log/modsec_audit.log 2>/dev/null || true)"
  fi
else
  warn "ModSecurity nicht aktiv oder Konfig nicht gefunden"
fi

h2 "9.3 Firewall (iptables/ufw/firewalld)"
if command -v ufw &>/dev/null; then
  FW_STATUS=$(ufw status verbose 2>/dev/null || true)
elif command -v firewall-cmd &>/dev/null; then
  FW_STATUS=$(firewall-cmd --list-all 2>/dev/null || true)
elif command -v iptables &>/dev/null; then
  FW_STATUS=$(iptables -L -n --line-numbers 2>/dev/null | head -40 || true)
else
  FW_STATUS="Kein bekanntes Firewall-Tool gefunden"
  warn "$FW_STATUS"
fi
code "$FW_STATUS"
evidence "firewall_status" "$FW_STATUS"

# ============================================================
