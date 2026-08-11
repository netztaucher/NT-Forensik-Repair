# shellcheck shell=bash
# NT-Forensik — Abschnitt 5: Benutzer & Rechte
#
# @nummer:  5
# @titel:   Benutzer & Rechte
# @frage:   Gibt es unerwartete Konten, Rechte oder hinterlegte Schlüssel?
# @kosten:  gering
# @ebene:   system
#
# Wird vom Runner eingebunden, nicht einzeln ausgefuehrt.
# Vorgabewerte der hier gefuellten Variablen: lib/befunde.sh

# Belegstufe dieses Abschnitts (#1). Konten, Schluessel und sudo-Regeln des Servers.
BELEG_STUFE=server

h1 "5. BENUTZER & RECHTE"
# ============================================================

h2 "5.1 Shell-fähige Benutzer (nicht nologin)"
SHELL_USERS=$(grep -vE "nologin|false|sync|halt|shutdown" /etc/passwd 2>/dev/null \
  | awk -F: '{print $1, $6, $7}' || true)
code "$SHELL_USERS"
evidence "shell_benutzer" "$SHELL_USERS"
SHELL_USER_COUNT=$(echo "$SHELL_USERS" | grep -c . || true)
if [[ "${SHELL_USER_COUNT:-0}" -gt 5 ]]; then
  warn "$SHELL_USER_COUNT Benutzer mit Shell-Zugang — bitte manuell prüfen"
fi

h2 "5.2 Benutzer mit UID 0 (root-Äquivalent)"
ROOT_EQUIV=$(awk -F: '($3==0){print $1}' /etc/passwd)
if [[ $(echo "$ROOT_EQUIV" | wc -l) -gt 1 ]]; then
  crit "Mehrere UID-0-Benutzer gefunden: $(echo "$ROOT_EQUIV" | tr '\n' ' ')"
else
  ok "Nur root hat UID 0"
fi
code "$ROOT_EQUIV"

h2 "5.3 Sudo-Berechtigungen"
SUDOERS=$(grep -vE "^#|^$" /etc/sudoers 2>/dev/null || echo "Nicht lesbar")
code "$SUDOERS"
if [[ -d /etc/sudoers.d ]]; then
  SUDOERS_D=$(ls -la /etc/sudoers.d/ 2>/dev/null || echo "Leer")
  code "$SUDOERS_D"
fi
evidence "sudoers" "$SUDOERS
---
$(cat /etc/sudoers.d/* 2>/dev/null || true)"

h2 "5.4 Authorized SSH-Keys (alle Benutzer)"
AUTH_KEYS=$(find /home /root "$VHOSTS_DIR" -maxdepth 4 -name "authorized_keys" 2>/dev/null \
  | while read -r f; do echo "=== $f (geändert: $(stat -c %y "$f" 2>/dev/null)) ==="; cat "$f" 2>/dev/null; done || true)
if [[ -n "$AUTH_KEYS" ]]; then
  info "Gefundene authorized_keys — auf unbekannte Schlüssel prüfen:"
  code "$AUTH_KEYS"
  evidence "ssh_authorized_keys" "$AUTH_KEYS"
fi
# Kürzlich geänderte authorized_keys = möglicher Persistenz-Einbau
RECENT_KEYS=$(find /home /root "$VHOSTS_DIR" -maxdepth 4 -name "authorized_keys" -mtime -"$DAYS_BACK" 2>/dev/null || true)
if [[ -n "$RECENT_KEYS" ]]; then
  warn "authorized_keys in den letzten ${DAYS_BACK} Tagen geändert — Schlüssel verifizieren!"
  code "$(echo "$RECENT_KEYS" | xargs -r ls -la 2>/dev/null)"
else
  ok "Keine kürzlich geänderten authorized_keys"
fi

h2 "5.5 FTP-Benutzer in Plesk"
if command -v /usr/local/psa/bin/ftpuser &>/dev/null; then
  FTP_USERS=$(/usr/local/psa/bin/ftpuser --list 2>/dev/null || echo "Nicht abfragbar")
  code "$FTP_USERS"
  evidence "plesk_ftp_benutzer" "$FTP_USERS"
else
  warn "Plesk ftpuser-Tool nicht gefunden — manuell in Plesk prüfen"
fi

h2 "5.6 SSH-Login-Hooks (~/.ssh/rc, /etc/ssh/sshrc)"
# Diese beiden Dateien werden bei JEDEM SSH-Login ausgeführt, noch bevor
# die Shell startet. Sie tauchen in keiner Prozessliste und in keinem
# Cron auf und werden bei einer Bereinigung fast immer übersehen —
# der Angreifer ist nach dem nächsten Login wieder da.
SSH_HOOKS_FOUND=""
if [[ -f /etc/ssh/sshrc ]]; then
    crit "/etc/ssh/sshrc existiert — wird bei jedem SSH-Login serverweit ausgeführt"
    code "$(cat /etc/ssh/sshrc 2>/dev/null)"
    SSH_HOOKS_FOUND+="=== /etc/ssh/sshrc ==="$'\n'"$(cat /etc/ssh/sshrc 2>/dev/null)"$'\n'
    SSH_LOGIN_HOOKS+="/etc/ssh/sshrc"$'\n'
fi

USER_SSH_RC=$(find /root /home "$VHOSTS_DIR" -maxdepth 5 -type f -path "*/.ssh/rc" 2>/dev/null || true)
if [[ -n "$USER_SSH_RC" ]]; then
    crit "SSH-Login-Hook(s) in Benutzerverzeichnissen gefunden — Persistenz ohne Cron/systemd"
    while IFS= read -r hk; do
        [[ -f "$hk" ]] || continue
        info "Hook: $hk (geändert: $(stat -c %y "$hk" 2>/dev/null | cut -d. -f1))"
        code "$(cat "$hk" 2>/dev/null)"
        SSH_HOOKS_FOUND+="=== $hk ==="$'\n'"$(cat "$hk" 2>/dev/null)"$'\n'
        SSH_LOGIN_HOOKS+="$hk"$'\n'
    done <<< "$USER_SSH_RC"
elif [[ -z "$SSH_HOOKS_FOUND" ]]; then
    ok "Keine SSH-Login-Hooks (~/.ssh/rc, /etc/ssh/sshrc)"
fi
[[ -n "$SSH_HOOKS_FOUND" ]] && evidence "ssh_login_hooks" "$SSH_HOOKS_FOUND"

h2 "5.7 authorized_keys mit erzwungenen Kommandos"
# Ein Schlüssel mit command="..." führt bei Login ein festes Kommando aus.
# Legitim für Backup-/Deploy-Keys (rrsync, borg) — aber auch eine elegante
# Backdoor, die in einer Sichtprüfung der Keys leicht durchrutscht.
FORCED_CMD_KEYS=$(find /root /home "$VHOSTS_DIR" -maxdepth 5 -name "authorized_keys" -type f 2>/dev/null \
    | while read -r ak; do
        grep -HnE '^(command=|.*,command=|no-pty|permitopen=)' "$ak" 2>/dev/null || true
      done || true)
if [[ -n "$FORCED_CMD_KEYS" ]]; then
    warn "SSH-Schlüssel mit erzwungenem Kommando/Optionen — gegen Backup-/Deploy-Zwecke abgleichen"
    code "$FORCED_CMD_KEYS"
    evidence "ssh_forced_commands" "$FORCED_CMD_KEYS"
else
    ok "Keine authorized_keys mit erzwungenen Kommandos"
fi

# ============================================================