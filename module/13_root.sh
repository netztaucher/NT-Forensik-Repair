# shellcheck shell=bash
# NT-Forensik — Abschnitt 13: Root- & Eskalations-Prüfung
#
# @nummer:  13
# @titel:   Root- & Eskalations-Prüfung
# @frage:   War der Vorfall auf die Website begrenzt oder ist der Server betroffen?
# @kosten:  gering
# @ebene:   system
#
# Wird vom Runner eingebunden, nicht einzeln ausgefuehrt.
# Vorgabewerte der hier gefuellten Variablen: lib/befunde.sh

# Belegstufe dieses Abschnitts (#1). Root-Logins, sudo-Eskalation, SSH-Schluessel: das ist der Server des
# Betreibers. Es gehoert in den Betreiberbericht und darf, wo es einen
# Kundenbefund traegt, maskiert mitgehen.
BELEG_STUFE=server

h1 "13. ROOT- & ESKALATIONS-PRÜFUNG"
# ============================================================
# Zentrale Frage: Hat ein Angreifer Root-Rechte erlangt oder blieb der
# Vorfall auf Web-User-Ebene? Konsolidiert Login-, Key-, sudo- und
# Binär-Integritätsdaten zu einem Root-Verdikt.

ROOT_FLAGS=0          # >0 => Root-Kompromittierung nicht ausgeschlossen
ROOT_NOTES=""

h2 "13.1 Erfolgreiche Root-Logins (IP + Auth-Methode)"
ROOT_LOGIN_LINES=$(grep -hE "Accepted (password|publickey) for root" /var/log/auth.log* /var/log/secure* 2>/dev/null || true)
ROOT_LOGIN_IPS=$(echo "$ROOT_LOGIN_LINES" | grep -oE "from [0-9.]+" | awk '{print $2}' | sort -u || true)
if [[ -n "$ROOT_LOGIN_IPS" ]]; then
  info "Distinct-IPs mit erfolgreichem Root-Login:"
  code "$ROOT_LOGIN_IPS"
  # Root-Login per Passwort = Härtungslücke (Brute-Force-Angriffsfläche)
  ROOT_PW=$(echo "$ROOT_LOGIN_LINES" | grep -c "Accepted password for root" || true)
  if [[ "${ROOT_PW:-0}" -gt 0 ]]; then
    warn "Root-Login per PASSWORT aktiv ($ROOT_PW Anmeldungen) — auf Key-only umstellen (PermitRootLogin prohibit-password)"
    ROOT_NOTES+="- Root-Login per Passwort ist aktiviert (Härtungslücke)."$'\n'
  fi
  evidence "root_logins_erfolgreich" "$ROOT_LOGIN_LINES"
else
  info "Keine erfolgreichen Root-Logins in vorliegenden Auth-Logs (ggf. Log-Reichweite beachten)"
fi

# Abgleich Angreifer-IP (falls aus Web-Analyse bekannt) gegen Root-Logins
if [[ -n "${ATTACK_IPS_UNIQ:-}" ]]; then
  ATTACK_IP_LIST=$(echo "$ATTACK_IPS_UNIQ" | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' || true)
  ROOT_HIT=""
  while IFS= read -r aip; do
    [[ -z "$aip" ]] && continue
    if echo "$ROOT_LOGIN_IPS" | grep -qF "$aip"; then ROOT_HIT+="$aip "; fi
    # Auch: Angreifer-IP je in auth.log (SSH-Kontakt)?
  done <<< "$ATTACK_IP_LIST"
  if [[ -n "$ROOT_HIT" ]]; then
    crit "Angreifer-IP(s) mit Root-Login gefunden: $ROOT_HIT — ROOT KOMPROMITTIERT"
    ROOT_FLAGS=$((ROOT_FLAGS+1))
    ROOT_NOTES+="- Angreifer-IP $ROOT_HIT hat sich erfolgreich als root angemeldet."$'\n'
  else
    ok "Keine Web-Angreifer-IP unter den Root-Login-IPs"
  fi
fi

h2 "13.2 /root/.ssh/authorized_keys (Root-SSH-Schlüssel)"
if [[ -f /root/.ssh/authorized_keys ]]; then
  ROOT_KEYS=$(while read -r l; do [[ -z "$l" ]] && continue; echo "$l" | ssh-keygen -lf /dev/stdin 2>/dev/null || echo "unparsebar: ${l:0:50}"; done < /root/.ssh/authorized_keys)
  RK_MTIME=$(stat -c %y /root/.ssh/authorized_keys 2>/dev/null | cut -d. -f1)
  info "Root-Keys (Fingerprint / Kommentar), Datei geändert: $RK_MTIME"
  code "$ROOT_KEYS"
  evidence "root_authorized_keys" "geändert: $RK_MTIME"$'\n'"$ROOT_KEYS"
  # Kürzlich geändert?
  RK_RECENT=$(find /root/.ssh/authorized_keys -mtime -"$DAYS_BACK" 2>/dev/null || true)
  if [[ -n "$RK_RECENT" ]]; then
    warn "/root/.ssh/authorized_keys in den letzten ${DAYS_BACK} Tagen geändert — Keys gegen bekannte Admin-/Plesk-Keys verifizieren (Plesk-SSH-Terminal schreibt seinen Key beim Öffnen neu)"
    ROOT_NOTES+="- Root-authorized_keys kürzlich geändert ($RK_MTIME) — verifizieren."$'\n'
  fi
else
  info "Keine /root/.ssh/authorized_keys vorhanden"
fi

h2 "13.3 Web-User-SSH-Keys serverweit (Fremd-Key-Persistenz?)"
# Angreifer-Persistenz auf Web-User-Ebene: fremde Keys in vhost-.ssh.
# Plesk-eigene 'plesk-ssh-terminal'-Keys sind gutartig (Panel-Terminal).
WEBUSER_KEYS=""
FOREIGN_KEYS=""
while IFS= read -r f; do
  [[ -f "$f" ]] || continue
  u=$(echo "$f" | cut -d/ -f5)
  while read -r l; do
    [[ -z "$l" ]] && continue
    fp=$(echo "$l" | ssh-keygen -lf /dev/stdin 2>/dev/null || echo "unparsebar ${l:0:40}")
    WEBUSER_KEYS+="$u : $fp"$'\n'
    echo "$fp" | grep -q "plesk-ssh-terminal" || FOREIGN_KEYS+="$u : $fp"$'\n'
  done < "$f" 2>/dev/null
done < <(find "$VHOSTS_DIR" -maxdepth 3 -name authorized_keys 2>/dev/null)
if [[ -n "$WEBUSER_KEYS" ]]; then
  code "$WEBUSER_KEYS"
  evidence "webuser_ssh_keys" "$WEBUSER_KEYS"
fi
if [[ -n "$FOREIGN_KEYS" ]]; then
  crit "Nicht-Plesk-SSH-Keys bei Web-Usern — mögliche Angreifer-Persistenz, verifizieren"
  code "$FOREIGN_KEYS"
  evidence "webuser_fremde_keys" "$FOREIGN_KEYS"
  ROOT_FLAGS=$((ROOT_FLAGS+1))
  ROOT_NOTES+="- Fremde (Nicht-Plesk) SSH-Keys bei Web-Usern gefunden."$'\n'
else
  ok "Nur Plesk-eigene SSH-Keys bei Web-Usern (keine Fremd-Key-Persistenz)"
fi

h2 "13.4 Privilege-Escalation (sudo/su durch Nicht-Root)"
# WICHTIG — nur der CALLER zählt: Eskalation ist ein Web-/Systemnutzer, der sudo
# AUFRUFT (Caller = webNN). Die alte Regex 'sudo:.*web[0-9]' traf auch 'USER=webNN'
# in der Ziel-Angabe und meldete damit jeden gewoehnlichen Plesk-Aufruf.
# im TARGET-Feld — das ist root, der Rechte an einen Web-User ABGIBT (legitim),
# u.a. NT-Forensik selbst (`sudo -u webNN wp core verify-checksums` in §11) und
# jeder Plesk-interne root→User-Aufruf. Ergebnis war ein Root-Fehlalarm auf
# sauberen Servern (Self-Kontamination). Wir ankern daher auf die Caller-Position.
SUDO_ESC=$(grep -hE "sudo:[[:space:]]+(www-data|psacln|psaserv|web[0-9]+)[[:space:]]+:" /var/log/auth.log* /var/log/secure* 2>/dev/null | head -20 || true)
SU_ESC=$(grep -hE "su(\[[0-9]+\])?:.*session opened for user root by (www-data|psacln|psaserv|web[0-9]+)" /var/log/auth.log* /var/log/secure* 2>/dev/null | head -20 || true)
if [[ -n "$SUDO_ESC" || -n "$SU_ESC" ]]; then
  crit "Rechteausweitung durch Web-/Systemnutzer erkannt"
  code "$SUDO_ESC
$SU_ESC"
  evidence "privilege_escalation" "$SUDO_ESC
$SU_ESC"
  ROOT_FLAGS=$((ROOT_FLAGS+1))
  ROOT_NOTES+="- sudo/su-Eskalation durch Nicht-Root-Nutzer in Logs."$'\n'
else
  ok "Keine sudo/su-Rechteausweitung durch Web-/Systemnutzer in Logs"
fi

h2 "13.5 Binär-Integrität als Rootkit-Indikator (Rückverweis 8.6)"
if [[ -n "${PKG_MODIFIED:-}" ]]; then
  crit "System-Binaries weichen von Paketdatenbank ab (siehe 8.6) — Rootkit-Verdacht"
  ROOT_FLAGS=$((ROOT_FLAGS+1))
  ROOT_NOTES+="- Manipulierte System-Binaries (dpkg -V)."$'\n'
else
  ok "Kern-Binaries unverändert (dpkg -V, siehe 8.6) — kein Rootkit-Hinweis"
fi
# ld.so.preload-Ergebnis aus 6.7 fließt bereits in die Warnungen ein.

h2 "13.6 Root-Verdikt"
if [[ "$ROOT_FLAGS" -eq 0 ]]; then
  ROOT_VERDICT="🟢 **Keine Hinweise auf Root-Kompromittierung.** Erfolgreiche Root-Logins nur von bekannten/legitimen Quellen, keine Fremd-SSH-Keys (root oder Web-User), keine Rechteausweitung durch Web-Nutzer, System-Binaries unverändert. Ein etwaiger Vorfall ist nach aktueller Beweislage auf Web-User-Ebene begrenzt."
  ok "ROOT-VERDIKT: keine Root-Kompromittierung nachweisbar"
else
  ROOT_VERDICT="🔴 **Root-Kompromittierung NICHT ausgeschlossen** (${ROOT_FLAGS} Indikator(en)). Sofort: Server als kompromittiert behandeln, Neuaufsetzen erwägen, alle Root-Zugänge rotieren."
  crit "ROOT-VERDIKT: Root-Kompromittierung möglich ($ROOT_FLAGS Indikatoren)"
fi
echo -e "\n$ROOT_VERDICT\n" >> "$REPORT_FILE"
[[ -n "$ROOT_NOTES" ]] && code "$ROOT_NOTES"
evidence "root_verdikt" "Flags: $ROOT_FLAGS
$ROOT_VERDICT

$ROOT_NOTES"

# Kunden-taugliche Root-Aussage (v3.5): im Kundenbericht dürfen KEINE
# Root-Details stehen (keine IPs, Pfade, Indikatorenzahl, keine
# „Server-neu-aufsetzen"-Anweisung — das ist Sache des Betreibers). Nur die
# generische Aussage betroffen/nicht betroffen. Der volle ROOT_VERDICT bleibt
# in Technik- und BSI-Bericht.
if [[ "$ROOT_FLAGS" -eq 0 ]]; then
  ROOT_CUSTOMER_HINT="🟢 Die Prüfung ergab **keine Hinweise**, dass über Ihren Webauftritt hinaus die Serverebene betroffen ist. Ein etwaiger Vorfall ist nach aktueller Beweislage auf Ihre Website begrenzt."
else
  ROOT_CUSTOMER_HINT="🟠 Es bestehen Hinweise, dass **auch die Serverebene betroffen** sein könnte. Diese liegen dem Serverbetreiber vor und werden dort gesondert behandelt. Für Ihren Webauftritt gelten die Sofortmaßnahmen in Abschnitt 2."
fi


# Konsolidiert alle Relay-/Prozess-Befunde zu einer klaren Aussage —
# analog zum bestehenden ROOT_VERDICT.
RELAY_FLAGS=0
[[ -n "$GSOCKET_HITS"       ]] && RELAY_FLAGS=$((RELAY_FLAGS+3))
[[ -n "$MASQ_BINARIES"      ]] && RELAY_FLAGS=$((RELAY_FLAGS+3))
[[ -n "$FILELESS_PROCS"     ]] && RELAY_FLAGS=$((RELAY_FLAGS+3))
[[ -n "$KTHREAD_FAKES"      ]] && RELAY_FLAGS=$((RELAY_FLAGS+2))
[[ -n "$YARA_HITS"          ]] && RELAY_FLAGS=$((RELAY_FLAGS+2))
[[ -n "$SSH_LOGIN_HOOKS"    ]] && RELAY_FLAGS=$((RELAY_FLAGS+2))
[[ -n "$RELAY_CONNECTIONS"  ]] && RELAY_FLAGS=$((RELAY_FLAGS+1))
[[ -n "$ORPHAN_SHELLS"      ]] && RELAY_FLAGS=$((RELAY_FLAGS+1))

if   [[ "$RELAY_FLAGS" -ge 3 ]]; then
    RELAY_VERDICT="🔴 **Interaktive Backdoor nachgewiesen.** Es bestehen Hinweise auf einen aktiven, ausgehenden Fernzugriffskanal (Relay-Backdoor). Ein solcher Kanal umgeht Firewall und NAT vollständig und ist von außen nicht als offener Port sichtbar. Das System ist als vollständig kompromittiert zu behandeln; ein Entfernen einzelner Dateien genügt nicht."
elif [[ "$RELAY_FLAGS" -ge 1 ]]; then
    RELAY_VERDICT="🟡 **Backdoor-Verdacht.** Einzelne Indikatoren für einen Fernzugriffskanal gefunden, aber keine eindeutige Signatur. Befunde manuell verifizieren, bevor bereinigt wird."
else
    RELAY_VERDICT="🟢 **Kein Hinweis auf eine Relay-Backdoor.** Weder Signaturen, getarnte Binaries, fileless Prozesse noch untypische ausgehende Verbindungen gefunden. (Kein Ausschluss: ein inaktiver Kanal ist zum Scanzeitpunkt unsichtbar — dauerhafte Erkennung nur über auditd, siehe haertung/audit-backdoor.rules.)"
fi

echo -e "\n### Verdikt Relay-Backdoor\n\n${RELAY_VERDICT}\n" >> "$REPORT_FILE"


# ============================================================