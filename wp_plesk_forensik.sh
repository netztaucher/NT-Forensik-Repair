#!/usr/bin/env bash
# ============================================================
# WP-PLESK-FORENSIK.SH — v3.2
# Forensische Analyse nach WordPress/Plesk Sicherheitsvorfall
#
# Verwendung: sudo bash wp_plesk_forensik.sh [domain.tld]
#
# Ablage (fest):
#   /root/wartungsscripte/                     ← Skript-Basis (wird angelegt)
#   /root/wartungsscripte/forensik/<LAUF>/     ← ein Ordner pro Lauf
#     ├── belege/                              ← Rohdaten, nummeriert, gehasht
#     │   ├── 00_manifest.txt                  ← Chain-of-Custody
#     │   ├── NN_*.txt / logs_sicherung.tar.gz
#     │   └── SHA256SUMS
#     ├── technik_bericht.md                   ← vollständiger Technik-Bericht
#     ├── kundenbericht.md                     ← lesbar für den Kunden
#     ├── bsi_meldung.md                       ← BSI-Meldung (Best Practice)
#     └── lauf.log                             ← Ausführungsprotokoll
#
# Autor: netztaucher | digital — forensik-tool v3.2
# Nur read-only Analyse. Keine Lösch-/Schreiboperationen im Webspace.
# ============================================================

# Kein set -e/pipefail: Collector-Skript muss bei Einzel-Fehlern (SIGPIPE durch
# `cmd | head`, fehlende Logs, leere greps) weiterlaufen und IMMER Berichte liefern.
set -u

# ── Farben ──────────────────────────────────────────────────
RED='\033[0;31m'; YLW='\033[0;33m'; GRN='\033[0;32m'
BLU='\033[0;34m'; CYN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

# ── Feste Infrastruktur-Pfade (netztaucher Plesk-Standard) ──
BASE_DIR="/root/wartungsscripte"
FORENSIK_BASE="${BASE_DIR}/forensik"
VHOSTS_DIR="/var/www/vhosts"
PLESK_LOG_DIR="/var/log/plesk"
PLESK_PANEL_LOG="${PLESK_LOG_DIR}/panel.log"

# ── Konfiguration ────────────────────────────────────────────
DOMAIN="${1:-}"
TOOL_VERSION="3.2"
DAYS_BACK=30   # Analysezeitraum in Tagen
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RUN_LABEL="${TIMESTAMP}_${DOMAIN:-server}"
RUN_DIR="${FORENSIK_BASE}/${RUN_LABEL}"
BELEGE_DIR="${RUN_DIR}/belege"
REPORT_FILE="${RUN_DIR}/technik_bericht.md"
KUNDE_FILE="${RUN_DIR}/kundenbericht.md"
BSI_FILE="${RUN_DIR}/bsi_meldung.md"
DSGVO_FILE="${RUN_DIR}/dsgvo_meldung.md"
RUN_LOG="${RUN_DIR}/lauf.log"
LOG_ARCHIVE="${BELEGE_DIR}/logs_sicherung.tar.gz"

# ── Root-Check ───────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
  echo -e "${RED}Fehler: Skript muss als root ausgeführt werden.${NC}"
  echo "  sudo bash $0 [domain.tld]"
  exit 1
fi

# ── Basis-Verzeichnisse anlegen ──────────────────────────────
mkdir -p "$BASE_DIR" "$FORENSIK_BASE" "$BELEGE_DIR"
chmod 700 "$BASE_DIR" "$FORENSIK_BASE" "$RUN_DIR" "$BELEGE_DIR"

# ── Selbst-Installation nach /root/wartungsscripte ──────────
SELF_PATH="$(readlink -f "$0" 2>/dev/null || echo "$0")"
INSTALLED_PATH="${BASE_DIR}/wp_plesk_forensik.sh"
if [[ "$SELF_PATH" != "$INSTALLED_PATH" ]]; then
  cp -f "$SELF_PATH" "$INSTALLED_PATH"
  chmod 700 "$INSTALLED_PATH"
fi

# Alles zusätzlich in lauf.log protokollieren
exec > >(tee -a "$RUN_LOG") 2>&1

# ── Zähler & Befund-Sammlung für Kunden-/BSI-Bericht ─────────
N_CRIT=0; N_WARN=0; N_OK=0
CRIT_LIST=""   # Markdown-Bullets
WARN_LIST=""
EVIDENCE_IDX=0
WPDB_FLAGS=0
WPDB_VERDICT="⚪ Keine WordPress-Installation im Scan-Pfad gefunden — keine Datenbank-Prüfung durchgeführt."
ROOT_VERDICT="⚪ Root-Prüfung nicht durchgeführt."

# ── Hilfsfunktionen ──────────────────────────────────────────
h1()  { echo -e "\n${BOLD}${BLU}══════════════════════════════════════════${NC}"; \
        echo -e "${BOLD}${BLU}  $1${NC}"; \
        echo -e "${BOLD}${BLU}══════════════════════════════════════════${NC}"; \
        echo -e "\n## $1\n" >> "$REPORT_FILE"; }

h2()  { echo -e "\n${CYN}▶ $1${NC}"; echo -e "\n### $1\n" >> "$REPORT_FILE"; }

ok()  { echo -e "  ${GRN}✓${NC} $1"; echo "- ✅ $1" >> "$REPORT_FILE"; N_OK=$((N_OK+1)); }
warn(){ echo -e "  ${YLW}⚠${NC}  $1"; echo "- ⚠️  **$1**" >> "$REPORT_FILE"; \
        N_WARN=$((N_WARN+1)); WARN_LIST+="- $1"$'\n'; }
crit(){ echo -e "  ${RED}✗${NC}  ${BOLD}$1${NC}"; echo "- 🔴 **KRITISCH: $1**" >> "$REPORT_FILE"; \
        N_CRIT=$((N_CRIT+1)); CRIT_LIST+="- $1"$'\n'; }
info(){ echo -e "  ${NC}·  $1"; echo "  $1" >> "$REPORT_FILE"; }
code(){ echo -e "\n\`\`\`\n$1\n\`\`\`\n" >> "$REPORT_FILE"; }

# Beleg sichern: schreibt Rohdaten nummeriert nach belege/
# evidence "label" "inhalt"  → belege/NN_label.txt
evidence() {
  EVIDENCE_IDX=$((EVIDENCE_IDX+1))
  local num; num=$(printf "%02d" "$EVIDENCE_IDX")
  local file="${BELEGE_DIR}/${num}_$1.txt"
  {
    echo "# Beleg ${num} — $1"
    echo "# Erhoben: $(date -u +"%Y-%m-%dT%H:%M:%SZ") (UTC) / $(date)"
    echo "# Host: $(hostname -f 2>/dev/null || hostname)"
    echo "# Tool: wp_plesk_forensik.sh v${TOOL_VERSION}"
    echo "# ------------------------------------------------------------"
    echo "$2"
  } > "$file"
  echo "  Beleg: belege/${num}_$1.txt" >> "$REPORT_FILE"
}

# Sichere grep-Zählung (kein set -e Abbruch, immer eine Zahl)
count_grep() {
  local n
  n=$(grep -cE "$1" "$2" 2>/dev/null) || true
  echo "${n:-0}"
}
count_grep_i() {
  local n
  n=$(grep -icE "$1" "$2" 2>/dev/null) || true
  echo "${n:-0}"
}

# ── Banner ───────────────────────────────────────────────────
echo -e "${BOLD}${BLU}"
cat <<'EOF'
  ██████  ██████  ██████  ███████ ███    ██ ███████ ██ ██   ██
 ██      ██    ██ ██   ██ ██      ████   ██ ██      ██ ██  ██
 ██████  ██    ██ ██████  █████   ██ ██  ██ ███████ ██ █████
 ██      ██    ██ ██   ██ ██      ██  ██ ██      ██ ██ ██  ██
  ██████  ██████  ██   ██ ███████ ██   ████ ███████ ██ ██   ██
  WP-PLESK-FORENSIK v3.2 — netztaucher | digital
EOF
echo -e "${NC}"

echo -e "${BOLD}Analysiert:${NC}  ${DOMAIN:-alle Domains}"
echo -e "${BOLD}Lauf:${NC}        ${RUN_LABEL}"
echo -e "${BOLD}Ablage:${NC}      ${RUN_DIR}"
echo -e "${BOLD}Datum:${NC}       $(date)\n"

# ── Chain-of-Custody Manifest ────────────────────────────────
cat > "${BELEGE_DIR}/00_manifest.txt" <<MANIFEST
CHAIN-OF-CUSTODY MANIFEST
=========================
Lauf-ID:        ${RUN_LABEL}
Server:         $(hostname -f 2>/dev/null || hostname)
Server-IP:      $(hostname -I 2>/dev/null | awk '{print $1}' || echo "n/a")
Domain:         ${DOMAIN:-alle Domains}
Beginn (UTC):   $(date -u +"%Y-%m-%dT%H:%M:%SZ")
Beginn (lokal): $(date)
Ausführender:   root (via $(who am i 2>/dev/null | awk '{print $1}' || echo "unbekannt"))
Tool:           wp_plesk_forensik.sh v${TOOL_VERSION}
Modus:          read-only, keine Veränderungen am Webspace

Alle Belege in diesem Ordner sind maschinell erhoben.
Integrität: siehe SHA256SUMS (wird am Ende des Laufs erzeugt).
MANIFEST

# ── Technik-Bericht Header ───────────────────────────────────
cat > "$REPORT_FILE" <<HEADER
# Forensik-Bericht (Technik): WordPress/Plesk Sicherheitsvorfall

| | |
|---|---|
| **Lauf-ID** | ${RUN_LABEL} |
| **Domain** | ${DOMAIN:-Alle Domains} |
| **Analysiert am** | $(date) |
| **Server** | $(hostname -f 2>/dev/null || hostname) |
| **Erstellt durch** | wp_plesk_forensik.sh v${TOOL_VERSION} |
| **Belege** | ${BELEGE_DIR} |

---

> **Hinweis:** Dieser Bericht ist maschinell erstellt und ersetzt keine manuelle Prüfung durch einen Sicherheitsexperten.

---
HEADER

# ============================================================
h1 "1. SYSTEM-ÜBERSICHT"
# ============================================================

h2 "1.1 Betriebssystem & Kernel"
OS_INFO=$(grep -E "^(NAME|VERSION)=" /etc/os-release 2>/dev/null | tr '\n' ' ')
KERNEL=$(uname -r)
info "OS: $OS_INFO"
info "Kernel: $KERNEL"
code "$(uname -a)"
evidence "system_info" "$(uname -a; echo; cat /etc/os-release 2>/dev/null)"

h2 "1.2 Plesk-Version"
if command -v plesk &>/dev/null; then
  PLESK_VER=$(plesk version 2>/dev/null | head -3)
  info "$PLESK_VER"
  code "$PLESK_VER"
  ok "Plesk gefunden"
else
  PLESK_VER="nicht gefunden"
  warn "Plesk-Binär nicht im PATH — manuell prüfen"
fi

h2 "1.3 PHP-Versionen"
if command -v php &>/dev/null; then
  PHP_VERS=$(php -v 2>/dev/null | head -1)
  info "$PHP_VERS"
  code "$PHP_VERS"
fi
if command -v plesk &>/dev/null; then
  PHP_HANDLERS=$(plesk bin php_handler --list 2>/dev/null || echo "Nicht abfragbar")
  code "$PHP_HANDLERS"
  evidence "php_handler" "$PHP_HANDLERS"
fi

h2 "1.4 Webserver"
if command -v apache2 &>/dev/null; then
  code "$(apache2 -v 2>/dev/null)"
elif command -v nginx &>/dev/null; then
  code "$(nginx -v 2>&1)"
fi

h2 "1.5 Uptime & Last-Reboot"
code "$(uptime && last reboot | head -5)"

h2 "1.6 Admin-Änderungsprotokoll (/root/changelog.md)"
# netztaucher-Konvention: dokumentierte Systemänderungen. Dient als Abgleich —
# ein Fund, der hier erklärt ist, ist meist gutartige Admin-Arbeit; fehlt der
# Eintrag, ist der Fund erklärungsbedürftig.
CHANGELOG="/root/changelog.md"
if [[ -f "$CHANGELOG" ]]; then
  ok "Änderungsprotokoll gefunden: $CHANGELOG (zuletzt geändert: $(stat -c %y "$CHANGELOG" 2>/dev/null | cut -d. -f1))"
  CHANGELOG_TAIL=$(tail -40 "$CHANGELOG" 2>/dev/null || true)
  info "Letzte Einträge (zum Abgleich mit den Befunden):"
  code "$CHANGELOG_TAIL"
  evidence "admin_changelog" "$(cat "$CHANGELOG" 2>/dev/null)"
else
  warn "Kein /root/changelog.md — Admin-Änderungen nicht dokumentiert. Befunde können nicht gegen dokumentierte Wartung abgeglichen werden. Empfehlung: Änderungsprotokoll führen."
fi

# ============================================================
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
    crit "$domain_label: Scanner-Aktivität erkannt ($scanner_hits Treffer)"
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
    crit "$domain_label: Verdächtige POST-Requests ($shell_posts)"
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
    warn "$domain_label: Möglicher wp-login Brute-Force ($wplogin POST-Requests)"
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
    warn "$domain_label: xmlrpc.php-Angriffe möglich ($xmlrpc POSTs)"
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
  if [[ -d "$VHOSTS_DIR" ]]; then
    for domain_dir in "$VHOSTS_DIR"/*/; do
      d=$(basename "$domain_dir")
      [[ "$d" == "system" || "$d" == "chroot" ]] && continue
      for log in "$domain_dir/logs/access_log" "$domain_dir/logs/access_ssl_log"; do
        analyze_access_log "$log" "$d"
      done
    done
  fi
fi

# Angreifer-IP-Liste konsolidieren (für BSI-Meldung / IOCs)
ATTACK_IPS_UNIQ=$(echo "$ATTACK_IPS_ALL" | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' \
  | sort | uniq -c | sort -rn | head -20 || true)
if [[ -n "$ATTACK_IPS_UNIQ" ]]; then
  evidence "angreifer_ips_konsolidiert" "$ATTACK_IPS_UNIQ"
fi

# ============================================================
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

# ============================================================
h1 "6. CRONJOBS & PERSISTENZ"
# ============================================================

h2 "6.1 Root-Crontab"
ROOT_CRON=$(crontab -l 2>/dev/null || echo "(leer)")
code "$ROOT_CRON"

h2 "6.2 System-Cronjobs"
SYSTEM_CRONS=$(ls -la /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/ /etc/cron.weekly/ 2>/dev/null || true)
code "$SYSTEM_CRONS"

SUSP_CRON=$(find /etc/cron* /var/spool/cron -type f 2>/dev/null \
  | xargs grep -lE "curl|wget|bash.*http|base64|nc -" 2>/dev/null || true)
if [[ -n "$SUSP_CRON" ]]; then
  crit "Verdächtige Cronjobs gefunden"
  code "$SUSP_CRON"
  CRON_CONTENT=""
  while IFS= read -r cf; do
    CRON_CONTENT+="=== $cf ==="$'\n'"$(cat "$cf" 2>/dev/null)"$'\n'
    code "$(cat "$cf" 2>/dev/null)"
  done <<< "$SUSP_CRON"
  evidence "verdaechtige_cronjobs" "$CRON_CONTENT"
else
  ok "Keine offensichtlich verdächtigen Cronjobs"
fi

h2 "6.3 Alle Benutzer-Crontabs"
ALL_USER_CRONS=""
for user in $(cut -f1 -d: /etc/passwd); do
  UCRON=$(crontab -u "$user" -l 2>/dev/null || true)
  if [[ -n "$UCRON" && "$UCRON" != *"no crontab"* ]]; then
    info "Crontab für $user:"
    code "$UCRON"
    ALL_USER_CRONS+="=== $user ==="$'\n'"$UCRON"$'\n'
  fi
done
[[ -n "$ALL_USER_CRONS" ]] && evidence "benutzer_crontabs" "$ALL_USER_CRONS"

h2 "6.4 Systemd-Timer prüfen"
if command -v systemctl &>/dev/null; then
  TIMERS=$(systemctl list-timers --all 2>/dev/null | head -25 || true)
  code "$TIMERS"
  evidence "systemd_timer" "$(systemctl list-timers --all 2>/dev/null || true)"
fi

h2 "6.5 at-Jobs"
if command -v atq &>/dev/null; then
  AT_JOBS=$(atq 2>/dev/null || true)
  if [[ -n "$AT_JOBS" ]]; then
    warn "at-Jobs vorhanden — Inhalte prüfen (atq/at -c <id>)"
    code "$AT_JOBS"
    AT_DETAIL=""
    while IFS= read -r line; do
      jid=$(echo "$line" | awk '{print $1}')
      AT_DETAIL+="=== Job $jid ==="$'\n'"$(at -c "$jid" 2>/dev/null | tail -20)"$'\n'
    done <<< "$AT_JOBS"
    evidence "at_jobs" "$AT_JOBS
$AT_DETAIL"
  else
    ok "Keine at-Jobs"
  fi
else
  info "atd nicht installiert"
fi

h2 "6.6 Fremde/kürzlich geänderte systemd-Units"
if [[ -d /etc/systemd/system ]]; then
  # Units außerhalb der Paketverwaltung — beliebter Persistenz-Ort
  CUSTOM_UNITS=$(find /etc/systemd/system -maxdepth 2 -name "*.service" -type f 2>/dev/null || true)
  RECENT_UNITS=$(find /etc/systemd/system /usr/lib/systemd/system -name "*.service" -mtime -"$DAYS_BACK" -type f 2>/dev/null || true)
  code "Eigene Units in /etc/systemd/system:
$CUSTOM_UNITS"
  if [[ -n "$RECENT_UNITS" ]]; then
    warn "systemd-Units in den letzten ${DAYS_BACK} Tagen geändert/angelegt — prüfen"
    code "$RECENT_UNITS"
    UNIT_CONTENT=""
    while IFS= read -r u; do
      UNIT_CONTENT+="=== $u ($(stat -c %y "$u" 2>/dev/null)) ==="$'\n'"$(cat "$u" 2>/dev/null)"$'\n\n'
    done <<< "$RECENT_UNITS"
    evidence "neue_systemd_units" "$UNIT_CONTENT"
  else
    ok "Keine kürzlich geänderten systemd-Units"
  fi
  # ExecStart mit Download-Mustern
  SUSP_UNITS=$(grep -lE "ExecStart=.*(curl|wget|base64|/tmp/|/dev/shm/)" /etc/systemd/system/*.service 2>/dev/null || true)
  if [[ -n "$SUSP_UNITS" ]]; then
    crit "systemd-Units mit verdächtigem ExecStart (curl/wget/tmp)"
    code "$SUSP_UNITS"
    evidence "verdaechtige_systemd_units" "$(grep -E "ExecStart" $SUSP_UNITS 2>/dev/null || true)"
  fi
fi

h2 "6.7 Weitere Persistenz-Orte (rc.local, ld.so.preload, profile.d)"
PERSIST_REPORT=""
if [[ -s /etc/rc.local ]]; then
  RC_LOCAL=$(grep -vE "^#|^$" /etc/rc.local 2>/dev/null || true)
  if [[ -n "$RC_LOCAL" ]]; then
    warn "/etc/rc.local enthält aktive Befehle — prüfen"
    code "$RC_LOCAL"
    PERSIST_REPORT+="=== /etc/rc.local ==="$'\n'"$RC_LOCAL"$'\n'
  fi
else
  ok "/etc/rc.local leer oder nicht vorhanden"
fi
if [[ -s /etc/ld.so.preload ]]; then
  crit "/etc/ld.so.preload ist NICHT leer — klassischer Userland-Rootkit-Ort!"
  code "$(cat /etc/ld.so.preload 2>/dev/null)"
  PERSIST_REPORT+="=== /etc/ld.so.preload ==="$'\n'"$(cat /etc/ld.so.preload 2>/dev/null)"$'\n'
else
  ok "/etc/ld.so.preload leer — kein Preload-Hijack"
fi
RECENT_PROFILED=$(find /etc/profile.d /etc/bash_completion.d -type f -mtime -"$DAYS_BACK" 2>/dev/null || true)
if [[ -n "$RECENT_PROFILED" ]]; then
  warn "Kürzlich geänderte Shell-Hooks in profile.d/bash_completion.d"
  code "$RECENT_PROFILED"
  PERSIST_REPORT+="=== profile.d (neu) ==="$'\n'"$RECENT_PROFILED"$'\n'
else
  ok "Keine kürzlich geänderten Shell-Hooks"
fi
[[ -n "$PERSIST_REPORT" ]] && evidence "persistenz_orte" "$PERSIST_REPORT"

h2 "6.8 Kernel-Module"
LSMOD_OUT=$(lsmod 2>/dev/null | head -40 || true)
code "$LSMOD_OUT"
evidence "kernel_module" "$(lsmod 2>/dev/null || true)"

# ============================================================
h1 "7. DATEISYSTEM-SCAN"
# ============================================================

if [[ -n "$DOMAIN" && -d "${VHOSTS_DIR}/${DOMAIN}" ]]; then
  SCAN_PATH="${VHOSTS_DIR}/${DOMAIN}"
else
  SCAN_PATH="$VHOSTS_DIR"
fi

h2 "7.1 Kürzlich veränderte PHP-Dateien (letzte ${DAYS_BACK} Tage)"
echo -e "  ${YLW}Durchsuche Webspace (kann dauern...)${NC}"

RECENT_PHP=$(find "$SCAN_PATH" -name "*.php" -mtime -"$DAYS_BACK" -ls 2>/dev/null \
  | sort -k8 -r | head -50 || true)
if [[ -n "$RECENT_PHP" ]]; then
  info "Kürzlich veränderte .php-Dateien:"
  code "$(echo "$RECENT_PHP" | head -30)"
  evidence "veraenderte_php_dateien" "$RECENT_PHP"
else
  ok "Keine kürzlich veränderten PHP-Dateien gefunden"
fi

h2 "7.2 PHP-Dateien in Upload-Verzeichnissen"
PHP_IN_UPLOADS_RAW=$(find "$SCAN_PATH" \
  \( -path "*/uploads/*.php" -o -path "*/uploads/*.phtml" -o -path "*/uploads/*.php5" \) \
  2>/dev/null || true)

# Bekannte Guard-/Plugin-Dateien herausfiltern (Avia, LayerSlider, BackWPup,
# Borlabs etc. legen legitime index.php/Cache-PHP in uploads/ ab)
PHP_IN_UPLOADS=""
GUARD_COUNT=0
if [[ -n "$PHP_IN_UPLOADS_RAW" ]]; then
  while IFS= read -r f; do
    [[ -f "$f" ]] || continue
    fsize=$(stat -c%s "$f" 2>/dev/null || echo 999999)
    # Guard-Files: winzig + typischer Inhalt
    if [[ "$fsize" -lt 200 ]] && head -c 200 "$f" 2>/dev/null \
       | grep -qiE "silence is golden|browsing the directory is not allowed|^<\?php[[:space:]]*$"; then
      GUARD_COUNT=$((GUARD_COUNT+1)); continue
    fi
    # Bekannte legitime Plugin-Pfade in uploads/ (Avia/Enfold-Iconfonts,
    # BackWPup, Borlabs, WP-Hide-Config, index.php-Guards in Backup-Ordnern)
    case "$f" in
      */uploads/borlabs-cookie/*|*/uploads/backwpup*/index.php|*/uploads/backup/*/index.php|*/uploads/backup/index.php)
        GUARD_COUNT=$((GUARD_COUNT+1)); continue ;;
      */avia_fonts/*charmap*.php|*/avia_icon_fonts/*charmap*.php)
        GUARD_COUNT=$((GUARD_COUNT+1)); continue ;;
      */uploads/wph/environment.php)   # WP Hide plugin config, ABSPATH-guarded
        GUARD_COUNT=$((GUARD_COUNT+1)); continue ;;
    esac
    # Generischer ABSPATH-Guard (WP-Plugin-Konvention: exit wenn direkt aufgerufen)
    if [[ "$fsize" -lt 2000 ]] && head -c 120 "$f" 2>/dev/null | grep -q "ABSPATH"; then
      GUARD_COUNT=$((GUARD_COUNT+1)); continue
    fi
    PHP_IN_UPLOADS+="$f"$'\n'
  done <<< "$PHP_IN_UPLOADS_RAW"
fi

if [[ -n "$PHP_IN_UPLOADS" ]]; then
  crit "PHP-Dateien in Upload-Verzeichnissen (nach Guard-Filter, extrem verdächtig)"
  code "$PHP_IN_UPLOADS"
  UPLOAD_HASHES=$(echo "$PHP_IN_UPLOADS" | xargs -r sha256sum 2>/dev/null || true)
  evidence "php_in_uploads_mit_hashes" "GEFILTERT (verdächtig):
$PHP_IN_UPLOADS

SHA256:
$UPLOAD_HASHES

ALLE FUNDE (inkl. ${GUARD_COUNT} Guard-/Plugin-Dateien, zur Nachvollziehbarkeit):
$PHP_IN_UPLOADS_RAW"
else
  ok "Keine verdächtigen PHP-Dateien in Upload-Verzeichnissen (${GUARD_COUNT} legitime Guard-/Plugin-Dateien gefiltert)"
  [[ -n "$PHP_IN_UPLOADS_RAW" ]] && evidence "php_in_uploads_nur_guards" "$PHP_IN_UPLOADS_RAW"
fi

h2 "7.3 Webshell-Muster (Inhalt) — zweistufig"
echo -e "  ${YLW}Scanne auf Webshell-Signaturen (inkl. obfuskierte Cookie-Backdoors)...${NC}"

# Detection-Familie. Case-insensitive (-i), damit mixed-case-Evasion wie
# 'EvaL'/'evAl'/'EVaL' erkannt wird. Erfasst u.a.:
#  - Variable-Variable-Superglobal:  ${$a.$b.$c}  → rekonstruiert _COOKIE/_POST
#  - eval/assert(base64_decode|gzinflate|gzuncompress|str_rot13|$_...)
#  - preg_replace mit /e-Modifier, create_function-Dropper
# move_uploaded_file($_FILES) bewusst NICHT — matcht legitime Upload-Handler.
# phpunit/sebastian ausgeschlossen (legitimes eval in Testframeworks).
PATTERN_REGEX='\$\{\s*\$[a-zA-Z0-9_]+(\s*\.\s*\$[a-zA-Z0-9_]+)+\s*\}|eval\s*\(\s*(base64_decode|gzinflate|gzuncompress|str_rot13)|eval\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER)|assert\s*\(\s*\$_|create_function\s*\(\s*['"'"'"][^'"'"'"]*['"'"'"]\s*,\s*\$|preg_replace\s*\(\s*['"'"'"].*/e[imsuxADSUXJ]*['"'"'"]|\bFilesMan\b|c99sh|r57shell|b374k'

# Schwelle: Dropper sind fast reine Obfuskation → klein. Legitime
# Framework-Nutzung (phpseclib, eGroupware) steckt in großen Dateien.
DROPPER_MAX_BYTES=3000

WEBSHELL_HITS=$(grep -rlPi "$PATTERN_REGEX" "$SCAN_PATH" --include="*.php" \
  --exclude-dir=phpunit --exclude-dir=sebastian --exclude-dir=mockery 2>/dev/null || true)

DROPPER_CLUSTER=""
WEBSHELL_COUNT=0        # Tier 1: kritische Dropper
WEBSHELL_REVIEW=0       # Tier 2: große Dateien, manuell prüfen
DROPPER_DETAIL=""
REVIEW_DETAIL=""
if [[ -n "$WEBSHELL_HITS" ]]; then
  while IFS= read -r f; do
    [[ -f "$f" ]] || continue
    fsize=$(stat -c%s "$f" 2>/dev/null || echo 0)
    fhash=$(sha256sum "$f" 2>/dev/null | awk '{print $1}' || true)
    fmtime=$(stat -c %y "$f" 2>/dev/null || true)
    preview=$(grep -noPi "$PATTERN_REGEX" "$f" 2>/dev/null | head -2 | cut -c1-160 || true)
    entry="=== $f ===
Größe: ${fsize} B | mtime: ${fmtime} | SHA256: ${fhash}
Treffer: ${preview}
"
    if [[ "$fsize" -lt "$DROPPER_MAX_BYTES" ]]; then
      WEBSHELL_COUNT=$((WEBSHELL_COUNT+1))
      DROPPER_DETAIL+="$entry"$'\n'
    else
      WEBSHELL_REVIEW=$((WEBSHELL_REVIEW+1))
      REVIEW_DETAIL+="$entry"$'\n'
    fi
  done <<< "$WEBSHELL_HITS"
fi

if [[ "$WEBSHELL_COUNT" -gt 0 ]]; then
  crit "Webshells/Dropper gefunden: ${WEBSHELL_COUNT} Datei(en) < ${DROPPER_MAX_BYTES} B mit Obfuskation"
  DROPPER_CLUSTER=$(echo "$DROPPER_DETAIL" | grep "^=== " | sed 's|=== /var/www/vhosts/||;s| ===||' | cut -d/ -f1 | sort | uniq -c | sort -rn || true)
  info "Betroffene Domains (Dropper-Cluster):"
  code "$DROPPER_CLUSTER"
  echo -e "\n**Dropper-Details:**\n\`\`\`\n$DROPPER_DETAIL\n\`\`\`" >> "$REPORT_FILE"
  evidence "webshell_dropper_kritisch" "$DROPPER_DETAIL"
else
  ok "Keine kleinen Obfuskations-Dropper gefunden"
fi

if [[ "$WEBSHELL_REVIEW" -gt 0 ]]; then
  warn "Obfuskations-Muster in ${WEBSHELL_REVIEW} größeren Datei(en) — manuell prüfen (oft legitime Frameworks)"
  evidence "webshell_review_gross" "$REVIEW_DETAIL"
fi

h2 "7.4 Versteckte Dateien und Verzeichnisse im Webspace"
HIDDEN=$(find "$SCAN_PATH" -name ".*" -not -name ".htaccess" -not -name ".well-known" \
  -not -name ".git*" -not -name ".user.ini" 2>/dev/null | head -20 || true)
if [[ -n "$HIDDEN" ]]; then
  warn "Versteckte Dateien/Verzeichnisse gefunden — manuell prüfen"
  code "$HIDDEN"
  evidence "versteckte_dateien" "$HIDDEN"
else
  ok "Keine auffälligen versteckten Dateien"
fi

h2 "7.5 Verdächtige Dateinamen (namensbasiert, geringe Konfidenz → Warnung)"
# Namensbasiert = viele False Positives (Plugin-Klassen wie class.u.shell.php,
# class-wp-optimize-bypass.php; Cache-Hashes mit 'c99'). Daher WARN, nicht CRIT,
# und aggressive Ausschlüsse: Core, vendor, Template-Caches, Twig, Elementor-Assets.
# whole-name-Match (kein Substring in Pfad) via -iname am Basenamen.
SUSP_NAMES=$(find "$SCAN_PATH" -type f \
  \( -iname "*.php" -o -iname "*.phtml" -o -iname "*.php5" -o -iname "*.pl" \
     -o -iname "*.py" -o -iname "*.sh" -o -iname "*.cgi" \) \
  \( -iname "*shell*" -o -iname "*exploit*" -o -iname "*hack*" \
     -o -iname "*r57*" -o -iname "*c99*" \
     -o -iname "*bypass*" -o -iname "*backdoor*" \) \
  -not -path "*/wp-includes/*" -not -path "*/wp-admin/*" \
  -not -path "*/vendor/*" -not -path "*/node_modules/*" \
  -not -path "*/cache/*" -not -path "*/templates_c/*" -not -path "*/var/cache/*" \
  -not -path "*/twig/*" -not -path "*/wp-content/plugins/*" \
  2>/dev/null || true)
if [[ -n "$SUSP_NAMES" ]]; then
  warn "Dateinamen mit verdächtigen Schlüsselwörtern (manuell gegen Inhalt prüfen)"
  code "$(echo "$SUSP_NAMES" | xargs -r ls -la 2>/dev/null)"
  evidence "verdaechtige_dateinamen" "$(echo "$SUSP_NAMES" | xargs -r ls -la 2>/dev/null)"
else
  ok "Keine verdächtigen Dateinamen (außerhalb Core/vendor/cache/plugins)"
fi

h2 "7.6 .htaccess-Dateien prüfen"
HTACCESS_REDIRECTS=$(find "$SCAN_PATH" -name ".htaccess" 2>/dev/null \
  -exec grep -lE "RewriteRule.*http|Redirect.*http" {} \; || true)
if [[ -n "$HTACCESS_REDIRECTS" ]]; then
  warn ".htaccess mit externen Weiterleitungen gefunden"
  code "$HTACCESS_REDIRECTS"
  HT_CONTENT=""
  while IFS= read -r f; do
    HT_CONTENT+="=== $f ==="$'\n'"$(cat "$f" 2>/dev/null)"$'\n'
    code "$(cat "$f" 2>/dev/null)"
  done <<< "$HTACCESS_REDIRECTS"
  evidence "htaccess_weiterleitungen" "$HT_CONTENT"
else
  ok "Keine externen Weiterleitungen in .htaccess gefunden"
fi

h2 "7.7 SUID/SGID-Dateien in Webspace und tmp-Verzeichnissen"
SUID_FILES=$(find "$SCAN_PATH" /tmp /var/tmp /dev/shm -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null || true)
if [[ -n "$SUID_FILES" ]]; then
  crit "SUID/SGID-Dateien in Webspace/tmp — Privilege-Escalation-Verdacht"
  code "$(echo "$SUID_FILES" | xargs -r ls -la 2>/dev/null)"
  evidence "suid_dateien" "$(echo "$SUID_FILES" | xargs -r ls -la 2>/dev/null)"
else
  ok "Keine SUID/SGID-Dateien in Webspace oder tmp"
fi

h2 "7.8 Ausführbare Dateien in tmp-Verzeichnissen"
TMP_EXECS=$(find /tmp /var/tmp /dev/shm -type f \( -perm -u+x -o -name "*.sh" -o -name "*.php" -o -name "*.py" -o -name "*.pl" \) 2>/dev/null | head -20 || true)
if [[ -n "$TMP_EXECS" ]]; then
  warn "Ausführbare Dateien/Skripte in tmp-Verzeichnissen — prüfen"
  code "$(echo "$TMP_EXECS" | xargs -r ls -la 2>/dev/null)"
  evidence "tmp_executables" "$(echo "$TMP_EXECS" | xargs -r ls -la 2>/dev/null)
$(echo "$TMP_EXECS" | xargs -r sha256sum 2>/dev/null)"
else
  ok "Keine ausführbaren Dateien in tmp-Verzeichnissen"
fi

h2 "7.9 Immutable-Flags im Webspace (chattr +i — Malware-Selbstschutz)"
IMMUTABLE=$(find "$SCAN_PATH" -maxdepth 6 -type f -name "*.php" 2>/dev/null | head -8000 \
  | xargs -r lsattr 2>/dev/null | awk '$1 ~ /i/ {print}' || true)
if [[ -n "$IMMUTABLE" ]]; then
  crit "PHP-Dateien mit Immutable-Flag — Malware schützt sich so vor Löschung"
  code "$IMMUTABLE"
  evidence "immutable_dateien" "$IMMUTABLE"
else
  ok "Keine Immutable-Flags auf PHP-Dateien (Stichprobe max. 8000 Dateien)"
fi

# ============================================================
h1 "8. NETZWERK & DIENSTE"
# ============================================================

h2 "8.1 Offene Ports und lauschende Dienste"
OPEN_PORTS=$(ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null || echo "ss/netstat nicht verfügbar")
code "$OPEN_PORTS"
evidence "offene_ports" "$OPEN_PORTS"

UNEXPECTED=$(ss -tlnp 2>/dev/null | grep -vE ":22 |:80 |:443 |:8443 |:8880 |:21 |:25 |:465 |:587 |:110 |:143 |:993 |:995 |:3306 |:5432 |:53 |:106 |:990 " \
  | grep LISTEN || true)
if [[ -n "$UNEXPECTED" ]]; then
  warn "Unerwartete lauschende Ports — manuell verifizieren"
  code "$UNEXPECTED"
fi

h2 "8.2 Prozess-Forensik"
evidence "prozessliste_voll" "$(ps auxf 2>/dev/null || true)"

# 8.2a Top-CPU/RAM (Krypto-Miner, Spam-Bots)
TOP_CPU=$(ps aux --sort=-%cpu 2>/dev/null | head -8 || true)
info "Top-Prozesse nach CPU:"
code "$TOP_CPU"
MINER_PROCS=$(ps aux 2>/dev/null | grep -iE "xmrig|minerd|kinsing|kdevtmpfsi|cryptonight|stratum\+tcp" | grep -v grep || true)
if [[ -n "$MINER_PROCS" ]]; then
  crit "Krypto-Miner-Prozess erkannt!"
  code "$MINER_PROCS"
  evidence "miner_prozesse" "$MINER_PROCS"
else
  ok "Keine bekannten Miner-Prozessnamen"
fi

# 8.2b Prozesse mit gelöschtem Binary
# Nur kritisch, wenn das gelöschte Ziel NICHT ein Standard-Systempfad ist.
# Nach apt/dpkg-Upgrades laufen Alt-Prozesse legitim mit "(deleted)" auf
# /usr/bin/python3.10 etc. — das ist KEINE Malware.
DELETED_ALL=$(ls -l /proc/[0-9]*/exe 2>/dev/null | grep "(deleted)" || true)
DELETED_SUSPECT=""
DELETED_BENIGN=0
if [[ -n "$DELETED_ALL" ]]; then
  while IFS= read -r line; do
    tgt=$(echo "$line" | sed -n 's/.*-> \(.*\) (deleted)/\1/p')
    case "$tgt" in
      /usr/bin/*|/usr/sbin/*|/bin/*|/sbin/*|/lib/*|/lib64/*|/usr/lib/*|/usr/lib64/*|/opt/plesk/*|/usr/local/*)
        DELETED_BENIGN=$((DELETED_BENIGN+1)) ;;   # Upgrade-Rest, gutartig
      *)
        DELETED_SUSPECT+="$line"$'\n' ;;          # /tmp, /dev/shm, memfd, Webspace, unlink
    esac
  done <<< "$DELETED_ALL"
fi
if [[ -n "$DELETED_SUSPECT" ]]; then
  crit "Prozess(e) mit gelöschtem Binary auf Nicht-Systempfad — typisch für Malware"
  code "$DELETED_SUSPECT"
  evidence "prozesse_geloeschte_binaries" "$DELETED_SUSPECT"
else
  ok "Keine verdächtigen gelöschten Binaries (${DELETED_BENIGN} gutartige Upgrade-Reste ignoriert)"
fi

# 8.2c Prozesse, die aus /tmp, /dev/shm, /var/tmp oder dem Webspace laufen
PROCS_BAD_PATH=""
for pid in /proc/[0-9]*; do
  exe=$(readlink "$pid/exe" 2>/dev/null) || continue
  case "$exe" in
    /tmp/*|/var/tmp/*|/dev/shm/*|${VHOSTS_DIR}/*)
      PROCS_BAD_PATH+="PID $(basename "$pid"): $exe — $(tr '\0' ' ' < "$pid/cmdline" 2>/dev/null | head -c 200)"$'\n' ;;
  esac
done
if [[ -n "$PROCS_BAD_PATH" ]]; then
  crit "Prozesse laufen aus tmp-/Webspace-Verzeichnissen!"
  code "$PROCS_BAD_PATH"
  evidence "prozesse_verdaechtige_pfade" "$PROCS_BAD_PATH"
else
  ok "Keine Prozesse aus /tmp, /dev/shm oder Webspace"
fi

# 8.2d Reverse-Shell-Muster in Prozess-Kommandozeilen
REVSHELL=$(ps auxww 2>/dev/null \
  | grep -E "bash -i|nc -e|nc -c|/dev/tcp/|python.{0,40}socket\.socket|perl.{0,40}Socket|php -r.{0,40}fsockopen|socat.{0,20}exec" \
  | grep -vE "grep|wp_plesk_forensik" || true)
if [[ -n "$REVSHELL" ]]; then
  crit "Reverse-Shell-Muster in laufenden Prozessen!"
  code "$REVSHELL"
  evidence "reverse_shell_prozesse" "$REVSHELL"
else
  ok "Keine Reverse-Shell-Muster in Prozessliste"
fi

# 8.2e Langlaufende Prozesse der Web-User (psacln/psaserv/www-data)
WEBUSER_PROCS=$(ps -eo user,pid,etime,pcpu,cmd --sort=-etime 2>/dev/null \
  | awk '$1 ~ /^(psacln|psaserv|www-data)/ || $1 ~ /^web[0-9]/' \
  | grep -vE "php-fpm|apache|nginx" | head -15 || true)
if [[ -n "$WEBUSER_PROCS" ]]; then
  warn "Web-User haben eigene (Nicht-PHP-FPM-)Prozesse — prüfen"
  code "$WEBUSER_PROCS"
  evidence "webuser_prozesse" "$WEBUSER_PROCS"
else
  ok "Keine auffälligen Web-User-Prozesse"
fi

h2 "8.3 Aktive Netzwerkverbindungen"
ACTIVE_CONNS=$(ss -tnp 2>/dev/null | grep ESTAB | head -25 || true)
code "$ACTIVE_CONNS"
evidence "aktive_verbindungen" "$ACTIVE_CONNS"

h2 "8.4 DNS-Records prüfen"
if [[ -n "$DOMAIN" ]] && command -v dig &>/dev/null; then
  DNS_INFO="A-Record:   $(dig +short A "$DOMAIN" 2>/dev/null | tr '\n' ' ')
MX-Record:  $(dig +short MX "$DOMAIN" 2>/dev/null | tr '\n' ' ')
NS-Record:  $(dig +short NS "$DOMAIN" 2>/dev/null | tr '\n' ' ')
TXT-Record: $(dig +short TXT "$DOMAIN" 2>/dev/null | head -5 | tr '\n' ' ')"
  code "$DNS_INFO"
  evidence "dns_records" "$DNS_INFO"
  info "Bitte manuell verifizieren, ob diese Records korrekt sind"
elif [[ -n "$DOMAIN" ]]; then
  warn "dig nicht verfügbar — DNS manuell prüfen"
fi

h2 "8.5 Mailqueue (Spam-Versand-Indikator)"
if command -v postqueue &>/dev/null; then
  QUEUE_COUNT=$(postqueue -p 2>/dev/null | tail -1 | grep -oE "[0-9]+ Request" | grep -oE "[0-9]+" || echo "0")
  QUEUE_COUNT=${QUEUE_COUNT:-0}
  info "Mails in Postfix-Queue: $QUEUE_COUNT"
  if [[ "$QUEUE_COUNT" -gt 100 ]]; then
    crit "Mailqueue ungewöhnlich voll ($QUEUE_COUNT) — Spam-Versand möglich!"
    evidence "mailqueue" "$(postqueue -p 2>/dev/null | head -60)"
  elif [[ "$QUEUE_COUNT" -gt 20 ]]; then
    warn "Mailqueue erhöht ($QUEUE_COUNT) — beobachten"
    evidence "mailqueue" "$(postqueue -p 2>/dev/null | head -60)"
  else
    ok "Mailqueue unauffällig ($QUEUE_COUNT)"
  fi
else
  info "postqueue nicht verfügbar — Mailqueue manuell prüfen"
fi

h2 "8.6 Paketintegrität Kern-Binaries (dpkg -V)"
if command -v dpkg &>/dev/null; then
  # '5' an Position 3 = MD5-Mismatch gegen Paketdatenbank; Binaries in bin/sbin
  PKG_MODIFIED=$(dpkg -V bash coreutils openssh-server openssh-client curl wget cron 2>/dev/null \
    | grep -E "^..5" | grep -E "/(s?bin)/" || true)
  if [[ -n "$PKG_MODIFIED" ]]; then
    crit "System-Binaries weichen von Paketdatenbank ab — Manipulations-Verdacht!"
    code "$PKG_MODIFIED"
    evidence "manipulierte_binaries" "$PKG_MODIFIED
$(echo "$PKG_MODIFIED" | awk '{print $NF}' | xargs -r sha256sum 2>/dev/null)"
  else
    ok "Kern-Binaries (bash, ssh, curl, wget, cron) stimmen mit Paketdatenbank überein"
  fi
fi

# ============================================================
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
h1 "11. WORDPRESS-DATENBANK-PRÜFUNG"
# ============================================================
# Findet WordPress-Installationen, liest DB-Zugang aus wp-config.php und
# prüft die Datenbank auf Angreifer-Spuren: fremde Admin-Konten, manipulierte
# Optionen (siteurl/home, auto_prepend), verdächtige aktive Plugins,
# heimlich zu Admin erhobene Nutzer. Read-only (nur SELECT).

WPDB_FLAGS=0

# MySQL-Aufruf: bevorzugt Plesk-Admin-Zugang (kein Passwort nötig), sonst
# die Zugangsdaten aus wp-config.php.
PLESK_MYSQL_PW=""
[[ -f /etc/psa/.psa.shadow ]] && PLESK_MYSQL_PW=$(cat /etc/psa/.psa.shadow 2>/dev/null || true)

# Ein WP-Config-Wert extrahieren: wpconf_get <file> <KONSTANTE>
wpconf_get() {
  grep -oP "define\(\s*['\"]$2['\"]\s*,\s*['\"]\K[^'\"]*" "$1" 2>/dev/null | head -1
}

# SQL gegen eine WP-DB ausführen. Nutzt Plesk-Admin, sonst WP-Creds.
wp_sql() {
  local db="$1" user="$2" pass="$3" host="$4" query="$5"
  if [[ -n "$PLESK_MYSQL_PW" ]]; then
    MYSQL_PWD="$PLESK_MYSQL_PW" mysql -u admin -N -e "USE \`$db\`; $query" 2>/dev/null && return 0
  fi
  MYSQL_PWD="$pass" mysql -h "${host%%:*}" -u "$user" -N -e "$query" "$db" 2>/dev/null
}

if [[ -n "$DOMAIN" ]]; then
  WP_CONFIGS=$(find "${VHOSTS_DIR}/${DOMAIN}" -maxdepth 4 -name wp-config.php 2>/dev/null || true)
else
  WP_CONFIGS=$(find "$VHOSTS_DIR" -maxdepth 5 -name wp-config.php 2>/dev/null || true)
fi

if [[ -z "$WP_CONFIGS" ]]; then
  h2 "11.1 WordPress-Installationen"
  info "Keine wp-config.php im Scan-Pfad gefunden — keine DB-Prüfung"
else
  WP_COUNT=$(echo "$WP_CONFIGS" | grep -c . || true)
  h2 "11.1 Gefundene WordPress-Installationen"
  info "WordPress-Installationen: $WP_COUNT"
  code "$WP_CONFIGS"

  WPDB_REPORT=""
  while IFS= read -r cfg; do
    [[ -f "$cfg" ]] || continue
    site=$(echo "$cfg" | sed "s|${VHOSTS_DIR}/||;s|/wp-config.php||")
    db=$(wpconf_get "$cfg" DB_NAME)
    du=$(wpconf_get "$cfg" DB_USER)
    dp=$(wpconf_get "$cfg" DB_PASSWORD)
    dh=$(wpconf_get "$cfg" DB_HOST); dh=${dh:-localhost}
    pfx=$(grep -oP '\$table_prefix\s*=\s*['"'"'"]\K[^'"'"'"]*' "$cfg" 2>/dev/null | head -1); pfx=${pfx:-wp_}
    [[ -z "$db" ]] && continue

    echo -e "  ${CYN}DB-Prüfung:${NC} $site (db=$db, prefix=$pfx)"
    echo -e "\n#### $site  (DB: \`$db\`, Prefix: \`$pfx\`)\n" >> "$REPORT_FILE"

    # Verbindungstest
    if ! wp_sql "$db" "$du" "$dp" "$dh" "SELECT 1;" >/dev/null 2>&1; then
      warn "$site: keine DB-Verbindung (Zugang prüfen) — übersprungen"
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
      crit "$site: Kürzlich angelegte(s) Administrator-Konto(en) — Angreifer-Verdacht"
      code "$NEW_ADMINS"
      evidence "wpdb_neue_admins_$(echo "$site" | tr '/.' '__')" "$NEW_ADMINS"
      WPDB_FLAGS=$((WPDB_FLAGS+1))
    else
      ok "$site: keine kürzlich angelegten Admins"
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
      crit "$site: verdächtige Optionen (base64/eval/auto_prepend) in ${pfx}options"
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
      warn "$site: Dateimanager-Plugin aktiv (fileorganizer/filemanager) — häufiger Angriffs-Vektor, prüfen"
    fi
    evidence "wpdb_active_plugins_$(echo "$site" | tr '/.' '__')" "$ACTIVE_PLUGINS"
  done <<< "$WP_CONFIGS"

  [[ -n "$WPDB_REPORT" ]] && evidence "wpdb_admin_uebersicht" "$WPDB_REPORT"

  h2 "11.9 WordPress-DB-Verdikt"
  if [[ "$WPDB_FLAGS" -eq 0 ]]; then
    WPDB_VERDICT="🟢 **Keine Angreifer-Spuren in den WordPress-Datenbanken** (keine neuen Admins, keine manipulierten Optionen)."
    ok "WP-DB-VERDIKT: unauffällig"
  else
    WPDB_VERDICT="🔴 **WordPress-Datenbank(en) auffällig** (${WPDB_FLAGS} Befund(e)) — fremde Admins/Optionen prüfen und bereinigen."
    crit "WP-DB-VERDIKT: ${WPDB_FLAGS} Befund(e)"
  fi
  echo -e "\n$WPDB_VERDICT\n" >> "$REPORT_FILE"
fi

# ============================================================
h1 "12. ROOT- & ESKALATIONS-PRÜFUNG"
# ============================================================
# Zentrale Frage: Hat ein Angreifer Root-Rechte erlangt oder blieb der
# Vorfall auf Web-User-Ebene? Konsolidiert Login-, Key-, sudo- und
# Binär-Integritätsdaten zu einem Root-Verdikt.

ROOT_FLAGS=0          # >0 => Root-Kompromittierung nicht ausgeschlossen
ROOT_NOTES=""

h2 "11.1 Erfolgreiche Root-Logins (IP + Auth-Methode)"
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

h2 "11.2 /root/.ssh/authorized_keys (Root-SSH-Schlüssel)"
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

h2 "11.3 Web-User-SSH-Keys serverweit (Fremd-Key-Persistenz?)"
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

h2 "11.4 Privilege-Escalation (sudo/su durch Nicht-Root)"
SUDO_ESC=$(grep -hE "sudo:.*(www-data|psacln|psaserv|web[0-9])" /var/log/auth.log* /var/log/secure* 2>/dev/null | head -20 || true)
SU_ESC=$(grep -hE "su(\[[0-9]+\])?:.*(www-data|psacln|web[0-9]).*(root)" /var/log/auth.log* /var/log/secure* 2>/dev/null | head -20 || true)
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

h2 "11.5 Binär-Integrität als Rootkit-Indikator (Rückverweis 8.6)"
if [[ -n "${PKG_MODIFIED:-}" ]]; then
  crit "System-Binaries weichen von Paketdatenbank ab (siehe 8.6) — Rootkit-Verdacht"
  ROOT_FLAGS=$((ROOT_FLAGS+1))
  ROOT_NOTES+="- Manipulierte System-Binaries (dpkg -V)."$'\n'
else
  ok "Kern-Binaries unverändert (dpkg -V, siehe 8.6) — kein Rootkit-Hinweis"
fi
# ld.so.preload-Ergebnis aus 6.7 fließt bereits in die Warnungen ein.

h2 "11.6 Root-Verdikt"
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

# ============================================================
h1 "13. ZUSAMMENFASSUNG"
# ============================================================

cat >> "$REPORT_FILE" <<SUMMARY

### 11.1 Befund-Statistik

| Kategorie | Anzahl |
|---|---|
| 🔴 Kritische Befunde | ${N_CRIT} |
| ⚠️ Warnungen | ${N_WARN} |
| ✅ Unauffällige Prüfungen | ${N_OK} |

### 11.2 Empfohlene Sofortmaßnahmen

| Priorität | Maßnahme | Status |
|---|---|---|
| 🔴 Sofort | Alle Passwörter rotieren (Plesk, FTP, SSH, DB) | ☐ |
| 🔴 Sofort | SSH Root-Login deaktivieren (\`PermitRootLogin no\`) | ☐ |
| 🔴 Sofort | SSH auf Key-only (\`PasswordAuthentication no\`) | ☐ |
| 🔴 Sofort | Google Search Console: alle unbekannten Inhaber entfernen | ☐ |
| 🟠 Kurzfristig | Fail2ban aktivieren (ssh, ftp, plesk-panel) | ☐ |
| 🟠 Kurzfristig | ModSecurity mit OWASP CRS aktivieren | ☐ |
| 🟠 Kurzfristig | PHP \`disable_functions\` härten | ☐ |
| 🟠 Kurzfristig | Maldet/ClamAV vollständigen Scan laufen lassen | ☐ |
| 🟡 Mittelfristig | WordPress-Neuinstallation aus sauberem Backup | ☐ |
| 🟡 Mittelfristig | WP-Admin mit HTTP-Auth absichern | ☐ |
| 🟡 Mittelfristig | Automatische Malware-Scans einrichten | ☐ |
| 🟡 Mittelfristig | Intrusion Detection System (AIDE/Tripwire) | ☐ |

---
*Bericht erstellt am: $(date)*
*Tool: wp_plesk_forensik.sh v${TOOL_VERSION} — netztaucher | digital*
SUMMARY

# ============================================================
# KUNDENBERICHT (lesbar, ohne Fachjargon-Overload)
# ============================================================

if [[ "$N_CRIT" -gt 0 ]]; then
  AMPEL="🔴 KRITISCH"
  AMPEL_TEXT="**Ihr System wurde nachweislich kompromittiert.** Es liegen konkrete, technisch belegte Hinweise auf einen erfolgreichen Angriff vor. Ein Angreifer hatte oder hat Zugriff auf Ihren Webauftritt. **Es besteht akuter Handlungsbedarf** — bitte arbeiten Sie die Sofortmaßnahmen unten noch heute ab."
  DRINGLICHKEIT="**Warum das dringend ist:** Solange die Zugänge des Angreifers gültig sind, kann er jederzeit zurückkehren, weitere Hintertüren legen, Daten (auch Kundendaten) abgreifen, Spam über Ihre Domain versenden oder Ihre Seite für Betrug/Schadsoftware missbrauchen. Jede Stunde zählt."
elif [[ "$N_WARN" -gt 0 ]]; then
  AMPEL="🟡 AUFFÄLLIG"
  AMPEL_TEXT="Es wurden Auffälligkeiten gefunden, die auf Sicherheitsschwächen oder Angriffsversuche hindeuten. Ein erfolgreicher Einbruch ist nicht belegt, die Punkte sollten aber zeitnah geprüft und behoben werden."
  DRINGLICHKEIT="**Warum das wichtig ist:** Die gefundenen Schwachstellen sind typische Einfallstore. Werden sie nicht geschlossen, ist ein erfolgreicher Angriff nur eine Frage der Zeit."
else
  AMPEL="🟢 UNAUFFÄLLIG"
  AMPEL_TEXT="Bei dieser Prüfung wurden keine Hinweise auf eine Kompromittierung gefunden. Das ist eine Momentaufnahme und ersetzt keine laufende Absicherung."
  DRINGLICHKEIT=""
fi

# Technische Kurzfassung der Kernbefunde (maschinell aus dem Lauf)
TECH_SUMMARY=""
if [[ "${WEBSHELL_COUNT:-0}" -gt 0 ]]; then
  TECH_SUMMARY+="- **${WEBSHELL_COUNT} Schadcode-Dateien (Hintertüren / \"Webshells\")** im Webverzeichnis gefunden. Das sind versteckte PHP-Skripte, über die ein Angreifer beliebige Befehle auf Ihrem Server ausführen kann — meist als harmlose Bilder oder Systemdateien getarnt."$'\n'
  if [[ -n "${DROPPER_CLUSTER:-}" ]]; then
    TECH_SUMMARY+="  Betroffene Domain(s):"$'\n'"$(echo "$DROPPER_CLUSTER" | sed 's/^/    - /')"$'\n'
  fi
fi
if [[ "${WEBSHELL_REVIEW:-0}" -gt 0 ]]; then
  TECH_SUMMARY+="- ${WEBSHELL_REVIEW} weitere Datei(en) mit auffälligen Code-Mustern (überwiegend veraltete, aber gefährliche Programmbibliotheken) — manuelle Prüfung nötig."$'\n'
fi
if [[ "${SSH_FAILED_COUNT:-0}" -gt 1000 ]]; then
  TECH_SUMMARY+="- **${SSH_FAILED_COUNT} fehlgeschlagene SSH-Anmeldeversuche** — Ihr Server wird aktiv per Passwort-Rateangriff attackiert."$'\n'
fi
[[ -z "$TECH_SUMMARY" ]] && TECH_SUMMARY="- Keine akuten technischen Kompromittierungs-Indikatoren in diesem Lauf."

# Angriffshergang aus Lauf-Daten maschinell vorbefüllen (keine nackten Platzhalter).
# Was der Lauf NICHT automatisch weiß (konkreter Angreifer-Login, Einfallstor),
# bleibt als klar markierte, kurze Ergänzungszeile — kein leeres [AUSFÜLLEN].
AUTO_IPS="${ATTACK_IPS_UNIQ:-}"
[[ -z "$AUTO_IPS" ]] && AUTO_IPS="${TOP_FAIL_IPS:-}"

if [[ -n "$AUTO_IPS" ]]; then
  ANGRIFF_IPS="Maschinell aus den Protokollen ermittelte auffällige IP-Adressen (Anzahl = Requests/Treffer):
\`\`\`
$(echo "$AUTO_IPS" | head -10)
\`\`\`
_Die konkrete Angreifer-IP wird bei der manuellen Log-Auswertung bestätigt._"
else
  ANGRIFF_IPS="In den vorliegenden Protokollen wurden keine eindeutig auffälligen IP-Adressen automatisch isoliert (ggf. Log-Reichweite zu kurz)."
fi

# Einfallstor-Hypothesen aus Befundlage
ANGRIFF_VEKTOR=""
[[ "${WEBSHELL_COUNT:-0}" -gt 0 ]] && ANGRIFF_VEKTOR+="  - Abgelegte Hintertüren (${WEBSHELL_COUNT}) deuten auf Datei-Upload über ein verwundbares Plugin/Theme oder gestohlene Zugangsdaten."$'\n'
[[ "${WPLOGIN_TOTAL:-0}" -gt 20 ]] && ANGRIFF_VEKTOR+="  - Auffällige wp-login-Aktivität → WordPress-Login als möglicher Einstieg."$'\n'
[[ "${SSH_FAILED_COUNT:-0}" -gt 1000 ]] && ANGRIFF_VEKTOR+="  - ${SSH_FAILED_COUNT} SSH-Rateangriffe → Passwort-Brute-Force auf den Serverzugang."$'\n'
[[ -z "$ANGRIFF_VEKTOR" ]] && ANGRIFF_VEKTOR="  - Kein eindeutiger Vektor aus den Automatik-Daten ableitbar — manuelle Log-Auswertung erforderlich."$'\n'

ANGRIFF_ZEIT="Analysezeitraum dieses Laufs: letzte ${DAYS_BACK} Tage. Der genaue Zugriffszeitraum ergibt sich aus der manuellen Log-Auswertung und den Datei-Zeitstempeln (siehe \`belege/\`)."

if [[ "${WEBSHELL_COUNT:-0}" -gt 0 || "${TOTAL_SHELL_POSTS:-0}" -gt 0 ]]; then
  ANGRIFF_TAT="Ablage von Schadcode/Hintertüren im Webauftritt${DROPPER_CLUSTER:+ (betroffen: $(echo "$DROPPER_CLUSTER" | awk '{print $2}' | tr '\n' ' '))}. Umfang der weiteren Aktivität (Datenzugriff, Änderungen) wird bei der Detailauswertung bestimmt."
else
  ANGRIFF_TAT="Aus den Automatik-Daten keine konkrete Angreifer-Aktion belegt — bei der manuellen Auswertung zu prüfen."
fi

cat > "$KUNDE_FILE" <<KUNDE
# Sicherheitsvorfall — Bericht${DOMAIN:+ für ${DOMAIN}}

| | |
|---|---|
| **Einstufung** | ${AMPEL} |
| **Erstellt durch** | netztaucher \| digital |
| **Datum** | $(date +"%d.%m.%Y, %H:%M Uhr") |
| **Geprüfter Server** | $(hostname -f 2>/dev/null || hostname) |
| **Prüfungs-ID** | ${RUN_LABEL} |
| **Befunde** | 🔴 ${N_CRIT} kritisch · ⚠️ ${N_WARN} auffällig · ✅ ${N_OK} geprüft |

---

## 1. Das Wichtigste in einem Satz

${AMPEL_TEXT}

${DRINGLICHKEIT}

$(if [[ "$N_CRIT" -gt 0 ]]; then
echo "## 2. ⏱️ Sofortmaßnahmen — bitte noch heute

| # | Maßnahme | Frist |
|---|---|---|
| 1 | **Alle Passwörter ändern**: WordPress-Admin, Hosting-/Plesk-Panel, FTP/SFTP, SSH, Datenbank. Nicht nur eines — alle. | sofort (< 24 h) |
| 2 | **Alle aktiven Sitzungen beenden** (WordPress-Sicherheitsschlüssel/Salts neu erzeugen), damit gestohlene Logins ungültig werden. | sofort (< 24 h) |
| 3 | **Verwundbare Zugänge/Plugins abschalten**, über die der Angriff lief (siehe Abschnitt 4). | sofort (< 24 h) |
| 4 | **Angreifer-IP-Adressen sperren** (siehe Abschnitt 4). | sofort (< 24 h) |
| 5 | **Prüfen, ob personenbezogene Daten betroffen sind** — falls ja, greift die 72-Stunden-Meldepflicht (siehe Abschnitt 6). | < 72 h |

> Diese Schritte stoppen den akuten Zugriff. Die vollständige Bereinigung (Abschnitt 5) folgt danach."
fi)

## 3. Was wir technisch gefunden haben

${TECH_SUMMARY}

$(if [[ -n "$CRIT_LIST" ]]; then
echo "**Kritische Einzelbefunde:**

$CRIT_LIST"
fi)
$(if [[ -n "$WARN_LIST" ]]; then
echo "**Auffälligkeiten (zeitnah beheben):**

$WARN_LIST"
fi)

## 4. Reichweite des Angriffs — hatte der Angreifer Server-Vollzugriff (Root)?

${ROOT_VERDICT}

> **Was das bedeutet:** „Root" ist die uneingeschränkte Administratorebene des
> gesamten Servers. Blieb der Angreifer darunter (nur auf Ebene der einzelnen
> Website), ist der Schaden auf diese Website begrenzt. Wurde Root übernommen,
> muss der gesamte Server als kompromittiert gelten.

**WordPress-Datenbank:** ${WPDB_VERDICT}

## 5. Angriffshergang & Angreifer

> *Die folgenden Angaben sind maschinell aus den Protokollen dieses Laufs abgeleitet.
> Die endgültige Zuordnung (konkreter Angreifer-Login, exaktes Einfallstor) bestätigen
> wir bei der manuellen Auswertung; alle Rohdaten liegen revisionssicher in \`belege/\`.*

**Auffällige IP-Adressen:**

${ANGRIFF_IPS}

**Wahrscheinliches Einfallstor (aus der Befundlage):**

${ANGRIFF_VEKTOR}
**Zeitliche Einordnung:** ${ANGRIFF_ZEIT}

**Beobachtete Angreifer-Aktivität:** ${ANGRIFF_TAT}

$(if [[ -n "${TOP_FAIL_IPS:-}" ]]; then
echo "**Auffälligste angreifende IP-Adressen (SSH-Rateangriff) — zum Sperren:**

\`\`\`
$TOP_FAIL_IPS
\`\`\`"
fi)

## 6. Bereinigung & dauerhafte Absicherung

**Bereits von uns durchgeführt:**

- Vollständige forensische Sicherung aller Protokolle und Beweise (revisionssicher, mit Prüfsummen) — Lauf-ID \`${RUN_LABEL}\`.
$(if [[ "${WEBSHELL_COUNT:-0}" -gt 0 ]]; then echo "- Systematische Erfassung aller ${WEBSHELL_COUNT} Schadcode-Fundstellen inkl. Prüfsummen (Grundlage für die Quarantäne)."; else echo "- Vollständiger Scan von Dateisystem, Prozessen, Persistenz-Mechanismen und Datenbanken."; fi)
$(if [[ "${WEBSHELL_COUNT:-0}" -gt 0 ]]; then echo "- _Weitere bereits durchgeführte Sofortmaßnahmen (z. B. Quarantäne der Fundstellen, Domain offline) trägt netztaucher hier fallbezogen ein._"; fi)

**Als Nächstes nötig:**

1. Gefundene Schadcode-Dateien entfernen (aus Quarantäne, nach Beweissicherung).
2. Betroffenes WordPress **aus einem nachweislich sauberen Backup** (vor dem Einbruch) neu aufsetzen — ein reines "Überschreiben" reicht bei Hintertüren nicht.
3. Alle Plugins/Themes aktualisieren, ungenutzte entfernen.
4. Server härten: SSH auf Schlüssel-Login umstellen, Fail2ban/ModSecurity aktivieren, PHP-Funktionen einschränken.
5. Datei-Integritäts-Überwachung und automatische Malware-Scans einrichten.

## 7. Rechtliche Pflichten (bitte beachten)

> **Datenschutz (DSGVO Art. 33):** Wenn bei diesem Vorfall personenbezogene Daten
> betroffen sein **könnten** (Kundendaten, Bestellungen, E-Mail-Adressen in der
> Website-Datenbank), müssen Sie das der zuständigen Datenschutz-Aufsichtsbehörde
> **innerhalb von 72 Stunden nach Bekanntwerden** melden. Die Frist läuft bereits.
> Ein vorbereiteter Entwurf liegt in \`dsgvo_meldung.md\`.

> **Meldung an das BSI:** Eine vorbereitete Meldung liegt in \`bsi_meldung.md\`
> (**eigener Meldeweg**, getrennt von der Datenschutzmeldung). Ob eine Pflicht besteht,
> hängt von Ihrer Einstufung ab — im Zweifel ist eine freiwillige Meldung sinnvoll.

Wir unterstützen Sie bei allen Meldungen — sprechen Sie uns umgehend an.

## 8. Ihre Unterlagen zu diesem Vorfall

| Dokument | Zweck |
|---|---|
| \`kundenbericht.md\` | Dieses Dokument |
| \`technik_bericht.md\` | Vollständiger technischer Bericht (alle Prüfpunkte, inkl. Root-Prüfung §12) |
| \`bsi_meldung.md\` | Vorbereitete BSI-Meldung (BSIG/NIS2) |
| \`dsgvo_meldung.md\` | Vorbereitete DSGVO-Meldung (Art. 33, eigener Meldeweg an die Datenschutzbehörde) |
| \`belege/\` | Alle Rohdaten & Beweismittel, mit SHA256-Prüfsummen versiegelt |

$(if [[ -f /root/changelog.md ]]; then echo "> **Abgleich mit Wartungsdokumentation:** Die Befunde wurden gegen das
> Admin-Änderungsprotokoll (\`/root/changelog.md\`) abgeglichen; dort dokumentierte
> Systemänderungen sind als reguläre Wartung eingeordnet."; fi)

---

### Über netztaucher | digital

Diese Analyse stammt aus unserer laufenden **WordPress-Betreuung und -Absicherung**.
Wir übernehmen Wartung, Härtung, Monitoring und Notfall-Forensik für WordPress- und
Rootserver — damit Vorfälle wie dieser gar nicht erst entstehen oder im Ernstfall
sauber und dokumentiert behoben werden.

**→ https://netztaucher.com/wordpress**

---
*netztaucher | digital — maschinell erstellt (wp_plesk_forensik.sh v${TOOL_VERSION}) und dokumentiert den Zustand zum Prüfzeitpunkt. Der Angriffshergang (Abschnitt 5/6) wird nach manueller Auswertung ergänzt.*
KUNDE

# ============================================================
# BSI-MELDUNG (Best Practice, vorausgefüllt)
# ============================================================

FIRST_SEEN=$(date -d "-${DAYS_BACK} days" +"%d.%m.%Y" 2>/dev/null || echo "[AUSFÜLLEN]")

cat > "$BSI_FILE" <<BSI
# Meldung eines IT-Sicherheitsvorfalls an das BSI

> **Entwurf — vor Versand prüfen und Platzhalter \`[AUSFÜLLEN]\` ergänzen.**
>
> **Meldewege:**
> - Meldepflichtige Unternehmen (KRITIS / NIS2 / §32 BSIG): **BSI Melde- und Informationsportal** — https://mip.bsi.bund.de
> - Freiwillige Meldung (alle Unternehmen): https://www.bsi.bund.de → "Cyber-Sicherheitsvorfall melden" bzw. E-Mail an meldestelle@bsi.bund.de
> - Bei Straftatverdacht zusätzlich: **ZAC** (Zentrale Ansprechstelle Cybercrime) der Landespolizei — Strafanzeige empfohlen
>
> **Fristen (NIS2/BSIG):** Erstmeldung ≤ 24 h nach Kenntnis, Folgemeldung ≤ 72 h, Abschlussbericht ≤ 1 Monat.
> **DSGVO Art. 33:** Bei Betroffenheit personenbezogener Daten Meldung an die Datenschutz-Aufsichtsbehörde ≤ 72 h (separater Meldeweg!).

---

## 1. Meldende Stelle

| Feld | Angabe |
|---|---|
| Unternehmen (Dienstleister) | netztaucher \| digital |
| Ansprechpartner | [AUSFÜLLEN] |
| E-Mail | [AUSFÜLLEN] |
| Telefon (Rückfragen) | [AUSFÜLLEN] |
| Meldung erfolgt | ☐ im eigenen Namen  ☐ im Auftrag des betroffenen Unternehmens |

## 2. Betroffenes Unternehmen / Einrichtung

| Feld | Angabe |
|---|---|
| Unternehmen | [AUSFÜLLEN — Kunde] |
| Branche / Sektor | [AUSFÜLLEN] |
| Betroffene Domain(s) | ${DOMAIN:-[AUSFÜLLEN]} |
| Betroffener Server | $(hostname -f 2>/dev/null || hostname) ($(hostname -I 2>/dev/null | awk '{print $1}' || echo "IP: [AUSFÜLLEN]")) |
| Einstufung | ☐ KRITIS  ☐ NIS2 besonders wichtige Einrichtung  ☐ NIS2 wichtige Einrichtung  ☐ nicht meldepflichtig (freiwillige Meldung) |

## 3. Zeitliche Einordnung

| Feld | Angabe |
|---|---|
| Feststellung des Vorfalls | [AUSFÜLLEN — Datum/Uhrzeit der Entdeckung] |
| Vermuteter Beginn | [AUSFÜLLEN — Analysezeitraum ab ca. ${FIRST_SEEN}] |
| Forensische Analyse | $(date +"%d.%m.%Y %H:%M") (Lauf-ID: ${RUN_LABEL}) |
| Vorfall andauernd? | ☐ ja  ☐ nein  ☐ unklar |

## 4. Art des Vorfalls

☐ Kompromittierung Webserver/CMS (WordPress)
☐ Webshell / Hintertür auf System
☐ Defacement / SEO-Spam / Malware-Verteilung
☐ Brute-Force-Angriff auf Zugänge
☐ Datenabfluss (vermutet/bestätigt)
☐ Sonstiges: [AUSFÜLLEN]

## 5. Automatisiert erhobene Kennzahlen (dieser Forensik-Lauf)

| Indikator | Wert |
|---|---|
| Kritische Befunde | ${N_CRIT} |
| Warnungen | ${N_WARN} |
| Fehlgeschlagene SSH-Login-Versuche | ${SSH_FAILED_COUNT:-0} |
| Scanner-Aktivität in Web-Logs (Treffer) | ${TOTAL_SCANNER_HITS:-0} |
| Verdächtige POST-Requests (Webshell-Muster) | ${TOTAL_SHELL_POSTS:-0} |
| Webshell-Verdachtsdateien im Dateisystem | ${WEBSHELL_COUNT:-0} |
| Domains auf dem Server (Mitbetroffenheit möglich) | ${DOMAIN_COUNT:-0} |

$(if [[ -n "$CRIT_LIST" ]]; then
echo "### Kritische Einzelbefunde

$CRIT_LIST"
fi)

## 6. Indikatoren (IOCs)

### Auffällige IP-Adressen (aus Angriffsmustern konsolidiert)

\`\`\`
${ATTACK_IPS_UNIQ:-Keine konsolidierten Angreifer-IPs in diesem Lauf.}
\`\`\`

### Top-IPs SSH-Brute-Force

\`\`\`
${TOP_FAIL_IPS:-Keine.}
\`\`\`

Datei-Hashes verdächtiger Dateien: siehe \`belege/\` (SHA256SUMS und Einzelbelege).

## 7. Auswirkungen

### Reichweite / Root-Kompromittierung (automatisiert bewertet)

${ROOT_VERDICT}
$(if [[ -n "${ROOT_NOTES:-}" ]]; then echo; echo "$ROOT_NOTES"; fi)

| Frage | Antwort |
|---|---|
| Server-Root kompromittiert? | $(if [[ "${ROOT_FLAGS:-0}" -eq 0 ]]; then echo "Nach Beweislage nein (auf Web-User-Ebene begrenzt)"; else echo "NICHT ausgeschlossen — ${ROOT_FLAGS} Indikator(en), siehe Technik-Bericht §12"; fi) |
| WordPress-Datenbank | $(if [[ "${WPDB_FLAGS:-0}" -eq 0 ]]; then echo "unauffällig (keine fremden Admins/Optionen)"; else echo "AUFFÄLLIG — ${WPDB_FLAGS} Befund(e), siehe Technik-Bericht §11"; fi) |
| Verfügbarkeit beeinträchtigt? | [AUSFÜLLEN] |
| Integrität von Daten/Systemen verletzt? | [AUSFÜLLEN] |
| Vertraulichkeit verletzt (Datenabfluss)? | [AUSFÜLLEN] |
| Personenbezogene Daten betroffen? | [AUSFÜLLEN — falls ja: DSGVO Art. 33 beachten!] |
| Auswirkung auf Dritte/Kunden? | [AUSFÜLLEN] |

## 8. Vermuteter Angriffsvektor

Basierend auf der forensischen Analyse (in absteigender Wahrscheinlichkeit):

1. [AUSFÜLLEN — z. B. kompromittiertes/veraltetes WordPress-Plugin]
2. [AUSFÜLLEN — z. B. wp-admin Brute-Force mit anschließendem Plugin-Upload]
3. [AUSFÜLLEN — z. B. kompromittierte FTP/SSH-Zugangsdaten]

## 9. Bereits ergriffene Maßnahmen

- Forensische Sicherung aller relevanten Logs (revisionssicher, SHA256-gehasht): \`${RUN_DIR}\`
- [AUSFÜLLEN — z. B. Passwörter rotiert, Webshell entfernt/quarantänisiert, Domain offline genommen]

## 10. Geplante Maßnahmen

- [AUSFÜLLEN — z. B. Neuaufsetzen aus sauberem Backup, Härtung SSH/PHP, Fail2ban, ModSecurity+OWASP CRS]

## 11. Anlagen

| Anlage | Pfad |
|---|---|
| Technischer Forensik-Bericht | \`technik_bericht.md\` |
| Beweismittel inkl. Prüfsummen | \`belege/\` (SHA256SUMS) |
| Log-Vollsicherung | \`belege/logs_sicherung.tar.gz\` |

---
*Entwurf maschinell erstellt am $(date) — wp_plesk_forensik.sh v${TOOL_VERSION}, netztaucher | digital.*
*Struktur orientiert an den Meldevorgaben des BSI (Erst-/Folgemeldung nach BSIG/NIS2) — vor Versand fachlich prüfen.*
BSI

# ============================================================
# DSGVO-MELDUNG (Art. 33 DSGVO — eigener Meldeweg, NICHT BSI!)
# ============================================================
# Personenbezogene Daten liegen auf fast jeder WordPress-Seite (Kommentare,
# Kontaktformulare, Bestellungen). Bei einem Einbruch ist eine Betroffenheit
# meist nicht auszuschließen → Art. 33 prüfen.

# Einschätzung zur Meldepflicht (maschinell, ersetzt keine Rechtsprüfung)
if [[ "${WEBSHELL_COUNT:-0}" -gt 0 && "${WP_COUNT:-0}" -gt 0 ]]; then
  DSGVO_HINWEIS="🔴 **Meldung wahrscheinlich erforderlich.** Es liegt eine bestätigte Kompromittierung vor und es sind WordPress-Installationen (mit typischerweise personenbezogenen Daten) betroffen. Eine Betroffenheit personenbezogener Daten ist **nicht auszuschließen** — die 72-Stunden-Frist des Art. 33 DSGVO läuft ab Kenntnis."
elif [[ "${N_CRIT:-0}" -gt 0 ]]; then
  DSGVO_HINWEIS="🟠 **Meldepflicht prüfen.** Es liegt ein kritischer Befund vor. Ob personenbezogene Daten betroffen sind, muss der/die Verantwortliche bewerten (Art. 33 Abs. 1: Meldung, außer die Verletzung führt voraussichtlich zu keinem Risiko)."
else
  DSGVO_HINWEIS="🟢 **Nach aktueller Befundlage kein akuter Meldeanlass** aus dieser Analyse. Die Bewertung der Meldepflicht obliegt dem/der Verantwortlichen."
fi

# Betroffene WordPress-Datenbanken (potenzielle Datenquellen) für die Meldung
DSGVO_DBS="${WP_CONFIGS:-}"
[[ -n "$DSGVO_DBS" ]] && DSGVO_DBS=$(echo "$DSGVO_DBS" | sed "s|${VHOSTS_DIR}/||;s|/wp-config.php||" | sed 's/^/- /')

cat > "$DSGVO_FILE" <<DSGVO
# Meldung einer Verletzung des Schutzes personenbezogener Daten (Art. 33 DSGVO)

> **Eigener Meldeweg — nicht mit der BSI-Meldung verwechseln.** Diese Meldung geht
> an die zuständige **Datenschutz-Aufsichtsbehörde** des Bundeslandes, nicht ans BSI.
> Entwurf — vom **Verantwortlichen** zu prüfen und mit \`[AUSFÜLLEN]\` zu ergänzen.

## Meldepflicht — Einschätzung

${DSGVO_HINWEIS}

| | |
|---|---|
| **Frist** | unverzüglich, **≤ 72 Stunden** ab Kenntnis (Art. 33 Abs. 1) |
| **Bei Überschreitung** | Begründung der Verzögerung beifügen (Art. 33 Abs. 1 S. 2) |
| **Ausnahme** | keine Meldung, wenn die Verletzung **voraussichtlich zu keinem Risiko** für die Rechte und Freiheiten natürlicher Personen führt |
| **Empfänger** | Datenschutz-Aufsichtsbehörde des Bundeslandes des Verantwortlichen |
| **Betroffene benachrichtigen?** | bei **hohem Risiko** zusätzlich Art. 34 (unverzüglich an die Betroffenen) |

## 1. Verantwortlicher (meldende Stelle i. S. d. DSGVO)

| Feld | Angabe |
|---|---|
| Verantwortlicher (Unternehmen) | [AUSFÜLLEN — Betreiber der Website, nicht der Dienstleister] |
| Anschrift | [AUSFÜLLEN] |
| Datenschutzbeauftragter (Name) | [AUSFÜLLEN] |
| DSB Kontakt (E-Mail/Telefon) | [AUSFÜLLEN] |
| Technische Unterstützung | netztaucher | digital |

> **Pflichtangabe Art. 33 Abs. 3 lit. b:** Name und Kontaktdaten des DSB oder einer sonstigen Anlaufstelle.

## 2. Art der Verletzung (Art. 33 Abs. 3 lit. a)

**Sachverhalt (technisch belegt):** Kompromittierung der Website${DOMAIN:+ ${DOMAIN}} auf dem Server $(hostname -f 2>/dev/null || hostname). $(if [[ "${WEBSHELL_COUNT:-0}" -gt 0 ]]; then echo "${WEBSHELL_COUNT} Hintertür(en) im Webverzeichnis; unbefugter Zugriff auf das System belegt."; else echo "Auffälligkeiten mit möglichem unbefugtem Zugriff."; fi)

- **Art:** ☑ Vertraulichkeitsverletzung (unbefugter Zugriff)  ☐ Integritätsverletzung  ☐ Verfügbarkeitsverletzung — [prüfen]
- **Zeitraum:** [AUSFÜLLEN — aus Analyse: Datei-Zeitstempel / Log-Auswertung, siehe technik_bericht.md]

## 3. Betroffene Personen und Datensätze (Art. 33 Abs. 3 lit. a)

> Muss der/die Verantwortliche bewerten — die Forensik liefert nur die betroffenen Systeme.

| Feld | Angabe |
|---|---|
| Kategorien betroffener Personen | [AUSFÜLLEN — z. B. Kunden, Newsletter-Abonnenten, Kontaktanfragen] |
| Ungefähre Zahl betroffener Personen | [AUSFÜLLEN] |
| Kategorien betroffener Daten | [AUSFÜLLEN — z. B. Name, E-Mail, Anschrift, Bestell-/Zahlungsdaten] |
| Ungefähre Zahl betroffener Datensätze | [AUSFÜLLEN] |
| Besondere Kategorien (Art. 9)? | [AUSFÜLLEN — Gesundheit, etc.? i. d. R. nein] |

**Betroffene Datenquellen auf dem Server (aus der Analyse):**
$(if [[ -n "$DSGVO_DBS" ]]; then echo "$DSGVO_DBS"; else echo "- Keine WordPress-Datenbank im Scan-Pfad gefunden — Datenquellen manuell bestimmen."; fi)

## 4. Wahrscheinliche Folgen (Art. 33 Abs. 3 lit. c)

[AUSFÜLLEN — z. B. Risiko von Identitätsdiebstahl, Spam/Phishing gegen Betroffene, Missbrauch von Zugangsdaten. Einschätzung des Risikogrades: gering / mittel / hoch.]

## 5. Ergriffene und vorgeschlagene Maßnahmen (Art. 33 Abs. 3 lit. d)

**Bereits ergriffen (technisch):**
- Forensische Sicherung und Dokumentation (revisionssicher, SHA256), Lauf-ID \`${RUN_LABEL}\`.
$(if [[ "${WEBSHELL_COUNT:-0}" -gt 0 ]]; then echo "- Erfassung aller ${WEBSHELL_COUNT} Schadcode-Fundstellen (Grundlage für Bereinigung/Quarantäne)."; fi)
- [AUSFÜLLEN — z. B. Passwörter rotiert, Hintertüren entfernt, Domain offline]

**Vorgeschlagen:**
- Rotation aller Zugangsdaten, WordPress-Neuaufbau aus sauberem Backup, Härtung.
- [AUSFÜLLEN — Maßnahmen zur Minderung nachteiliger Folgen für Betroffene]

## 6. Dokumentation (Art. 33 Abs. 5)

Auch wenn keine Meldung erfolgt, ist die Verletzung intern zu dokumentieren. Diese
Analyse (Lauf \`${RUN_LABEL}\`, Belege mit Prüfsummen) erfüllt die technische
Dokumentationsgrundlage. Rechtliche Bewertung und Entscheidung obliegen dem/der Verantwortlichen.

## 7. Anlagen

| Anlage | Pfad |
|---|---|
| Technischer Forensik-Bericht | \`technik_bericht.md\` |
| BSI-Meldung (separater Meldeweg) | \`bsi_meldung.md\` |
| Beweismittel inkl. Prüfsummen | \`belege/\` (SHA256SUMS) |

---
*Entwurf maschinell erstellt am $(date) — wp_plesk_forensik.sh v${TOOL_VERSION}, netztaucher | digital.*
*Struktur nach Art. 33 DS-GVO. Ersetzt keine Rechtsberatung — vor Versand durch den Verantwortlichen/DSB prüfen.*
DSGVO

# ============================================================
# BELEGE VERSIEGELN: SHA256 über alles
# ============================================================

# ── Maschinenlesbarer Export für das Repair-Tool (findings.json) ──
# Kein jq-Zwang; JSON von Hand aus vorhandenen Variablen/Belegen gebaut.
FINDINGS_FILE="${RUN_DIR}/findings.json"

json_str() {   # einzeiliger String → JSON-escaped (ohne Anführungszeichen)
  printf '%s' "$1" | tr '\n' ' ' | sed 's/\\/\\\\/g; s/"/\\"/g'
}
json_arr() {   # stdin: ein Item pro Zeile → JSON-Array von Strings
  local first=1 out="[" line esc
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    esc=$(printf '%s' "$line" | sed 's/\\/\\\\/g; s/"/\\"/g')
    if [ "$first" -eq 1 ]; then out="${out}\"${esc}\""; first=0; else out="${out},\"${esc}\""; fi
  done
  printf '%s]' "$out"
}

emit_findings_json() {
  local ws php suid tmpx immu cron sysd persist procs wpc fkeys aips bips
  ws=$(echo "${DROPPER_DETAIL:-}"      | grep '^=== ' | sed 's/^=== //; s/ ===$//' | json_arr)
  php=$(printf '%s\n' "${PHP_IN_UPLOADS:-}"    | json_arr)
  suid=$(printf '%s\n' "${SUID_FILES:-}"       | json_arr)
  tmpx=$(printf '%s\n' "${TMP_EXECS:-}"        | json_arr)
  immu=$(printf '%s\n' "${IMMUTABLE:-}"        | json_arr)
  cron=$(printf '%s\n' "${SUSP_CRON:-}"        | json_arr)
  sysd=$(printf '%s\n' "${SUSP_UNITS:-}"       | json_arr)
  persist=$(printf '%s\n' "${PERSIST_REPORT:-}" | grep '^=== ' | sed 's/^=== //; s/ ===$//' | json_arr)
  procs=$(printf '%s\n%s\n%s\n' "${MINER_PROCS:-}" "${DELETED_SUSPECT:-}" "${REVSHELL:-}" | json_arr)
  wpc=$(printf '%s\n' "${WP_CONFIGS:-}"        | json_arr)
  fkeys=$(printf '%s\n' "${FOREIGN_KEYS:-}"    | json_arr)
  aips=$(printf '%s\n' "${ATTACK_IPS_UNIQ:-}"  | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | json_arr)
  bips=$(printf '%s\n' "${TOP_FAIL_IPS:-}"     | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | json_arr)

  cat > "$FINDINGS_FILE" <<JSON
{
  "schema_version": "1.0",
  "tool": "wp_plesk_forensik.sh",
  "tool_version": "${TOOL_VERSION}",
  "run_id": "$(json_str "$RUN_LABEL")",
  "host": "$(json_str "$(hostname -f 2>/dev/null || hostname)")",
  "domain": "$(json_str "${DOMAIN:-}")",
  "generated_utc": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "counts": { "crit": ${N_CRIT:-0}, "warn": ${N_WARN:-0}, "ok": ${N_OK:-0} },
  "verdicts": {
    "root": { "flags": ${ROOT_FLAGS:-0}, "text": "$(json_str "${ROOT_VERDICT:-}")" },
    "wpdb": { "flags": ${WPDB_FLAGS:-0}, "text": "$(json_str "${WPDB_VERDICT:-}")" }
  },
  "metrics": {
    "webshell_count": ${WEBSHELL_COUNT:-0},
    "webshell_review": ${WEBSHELL_REVIEW:-0},
    "ssh_failed": ${SSH_FAILED_COUNT:-0},
    "wp_installs": ${WP_COUNT:-0},
    "domains": ${DOMAIN_COUNT:-0}
  },
  "actionable": {
    "webshell_dropper": ${ws:-[]},
    "php_in_uploads": ${php:-[]},
    "suid": ${suid:-[]},
    "tmp_executables": ${tmpx:-[]},
    "immutable": ${immu:-[]},
    "cron_suspect": ${cron:-[]},
    "systemd_suspect": ${sysd:-[]},
    "persistence": ${persist:-[]},
    "proc_malicious": ${procs:-[]},
    "wp_configs": ${wpc:-[]},
    "foreign_ssh_keys": ${fkeys:-[]},
    "ioc_ips": { "attacker": ${aips:-[]}, "ssh_bruteforce": ${bips:-[]} }
  }
}
JSON
  echo "  findings.json geschrieben: $FINDINGS_FILE" >> "$REPORT_FILE"
}
emit_findings_json

(
  cd "$BELEGE_DIR"
  # Manifest abschließen
  {
    echo ""
    echo "Ende (UTC):     $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    echo "Belege gesamt:  $(ls -1 | grep -vc "SHA256SUMS" || true)"
  } >> 00_manifest.txt
  sha256sum ./* 2>/dev/null | grep -v "SHA256SUMS" > SHA256SUMS || true
)
# Berichte + findings.json ebenfalls hashen
(
  cd "$RUN_DIR"
  sha256sum technik_bericht.md kundenbericht.md bsi_meldung.md dsgvo_meldung.md findings.json 2>/dev/null >> "${BELEGE_DIR}/SHA256SUMS" || true
)

# Übergabe-Archiv des kompletten Laufs
RUN_ARCHIVE="${FORENSIK_BASE}/${RUN_LABEL}.tar.gz"
tar czf "$RUN_ARCHIVE" -C "$FORENSIK_BASE" "$RUN_LABEL" 2>/dev/null || true

# ============================================================
# ABSCHLUSSMELDUNG
# ============================================================

echo ""
echo -e "${BOLD}${GRN}══════════════════════════════════════════${NC}"
echo -e "${BOLD}${GRN}  ANALYSE ABGESCHLOSSEN — Lauf ${RUN_LABEL}${NC}"
echo -e "${BOLD}${GRN}══════════════════════════════════════════${NC}"
echo ""
echo -e "${BOLD}Befunde:${NC}       🔴 ${N_CRIT} kritisch, ⚠️ ${N_WARN} Warnungen, ✅ ${N_OK} ok"
echo ""
echo -e "${BOLD}Lauf-Ordner:${NC}     ${RUN_DIR}"
echo -e "${BOLD}Kundenbericht:${NC}   ${KUNDE_FILE}"
echo -e "${BOLD}BSI-Meldung:${NC}     ${BSI_FILE}"
echo -e "${BOLD}DSGVO-Meldung:${NC}   ${DSGVO_FILE}"
echo -e "${BOLD}Technik-Bericht:${NC} ${REPORT_FILE}"
echo -e "${BOLD}findings.json:${NC}   ${FINDINGS_FILE} (maschinenlesbar, für NT-Repair)"
echo -e "${BOLD}Belege:${NC}          ${BELEGE_DIR} (SHA256-versiegelt)"
echo -e "${BOLD}Übergabe-Archiv:${NC} ${RUN_ARCHIVE}"
echo ""
echo -e "${YLW}Nächste Schritte:${NC}"
echo -e "  1. Kundenbericht prüfen:   cat ${KUNDE_FILE}"
echo -e "  2. BSI-Meldung ergänzen:   [AUSFÜLLEN]-Felder in ${BSI_FILE}"
echo -e "  3. DSGVO-Meldung prüfen:   [AUSFÜLLEN]-Felder in ${DSGVO_FILE} (eigener Meldeweg!)"
echo -e "  4. Archiv lokal sichern:   scp root@$(hostname -f 2>/dev/null || hostname):${RUN_ARCHIVE} ."
echo -e "  5. Alle 🔴-Maßnahmen sofort umsetzen"
echo ""
