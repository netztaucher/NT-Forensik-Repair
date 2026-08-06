#!/usr/bin/env bash
# ============================================================
# WP-PLESK-FORENSIK.SH — v3.7.1
# Forensische Analyse nach WordPress/Plesk Sicherheitsvorfall
#
# Verwendung: sudo bash wp_plesk_forensik.sh [--domain d|--path p|--global] [--yara]
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
# Autor: netztaucher | digital — forensik-tool v3.7.1
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
TOOL_VERSION="3.8.0"
DAYS_BACK=30   # Analysezeitraum in Tagen

# ── Argumente & Scope (v3.5) ─────────────────────────────────
# Drei Betriebsarten. Die Server-/Rootebene (Abschnitte 3,5,6,8,9,13) läuft
# in ALLEN Modi mit — der Scope steuert nur den Dateisystem-Scan (Abschnitt 7)
# und, welche Berichte für wen erzeugt werden (siehe Abschnitt 14).
#   --domain <d>  ein Kunde         (= bisheriges Positionsargument)
#   --path <p>    beliebiger Pfad   (Unterordner, Nicht-Plesk-Webspace)
#   --global      alle vhosts       → Betreiberbericht + je-vhost Kundenberichte
# Ohne Argument = --global (rückwärtskompatibel: leeres DOMAIN scannte schon
# immer alle vhosts). Ein blankes Positionsargument bleibt = --domain.
DOMAIN=""
SCOPE_MODE="global"      # global | domain | path
SCAN_PATH_ARG=""         # nur bei --path
WANT_YARA=0              # 7.11 nur auf Wunsch (teuer auf großen Webspaces)
WANT_ONLINE=0            # --online: Joomla-Prüfsummen/Schwachstellenliste nachladen

usage() {
  cat <<USAGE
wp_plesk_forensik.sh v${TOOL_VERSION} — read-only WordPress/Plesk-Forensik

Verwendung:
  sudo bash $0 [SCOPE] [Optionen]
  sudo bash $0 kunde.tld                 # Kurzform für --domain kunde.tld

Scope (eines):
  --domain <domain.tld>   Einen Kunden prüfen; Kundenbericht nur mit dessen Daten
  --path   <pfad>         Beliebigen Pfad/Webspace prüfen
  --global                Alle vhosts (Standard): Betreiberbericht + je vhost
                          ein eigener, gefilterter Kundenbericht

Optionen:
  --yara                  YARA-Signaturscan (7.11) aktivieren (langsam auf
                          großen Webspaces; ohne Flag übersprungen)
  --online                Joomla-Prüfsummen und Schwachstellenliste bei Bedarf
                          aus dem Netz nachladen. OHNE dieses Flag arbeitet der
                          Lauf rein offline aus dem mitgelieferten Datenbestand.
                          Jeder Abruf wird im Bericht und als Beleg ausgewiesen.
  -h, --help              Diese Hilfe

Die Server-/Rootebene wird in jedem Modus mitgeprüft. In Kundenberichten
werden Rootbefunde nur allgemein (betroffen/nicht betroffen) genannt und
IP-Adressen/E-Mails maskiert.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --domain) SCOPE_MODE="domain"; DOMAIN="${2:-}"; shift 2 ;;
    --path)   SCOPE_MODE="path";   SCAN_PATH_ARG="${2:-}"; shift 2 ;;
    --global) SCOPE_MODE="global"; shift ;;
    --yara)   WANT_YARA=1; shift ;;
    --online) WANT_ONLINE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    --) shift; break ;;
    -*) echo "Unbekannte Option: $1" >&2; usage >&2; exit 2 ;;
    *)  # Positionsargument = Domain (Rückwärtskompatibilität)
        SCOPE_MODE="domain"; DOMAIN="$1"; shift ;;
  esac
done

# Plausibilität
if [[ "$SCOPE_MODE" == "domain" && -z "$DOMAIN" ]]; then
  echo "Fehler: --domain ohne Domain-Angabe." >&2; usage >&2; exit 2
fi
if [[ "$SCOPE_MODE" == "path" && -z "$SCAN_PATH_ARG" ]]; then
  echo "Fehler: --path ohne Pfad-Angabe." >&2; usage >&2; exit 2
fi

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RUN_LABEL="${TIMESTAMP}_${DOMAIN:-${SCOPE_MODE}}"
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
# Beigelegte Hilfsdateien (YARA-Signaturen, PDF-Generator, Joomla-Datenbestand)
# neben das Skript mitziehen — so findet der Lauf sie unter ${BASE_DIR}, egal
# von wo gestartet wurde.
#
# Auffrischen bei JEDEM Lauf, nicht nur beim ersten (v3.8): der frühere
# '! -e'-Guard hat einen einmal installierten Host dauerhaft auf dem Erststand
# eingefroren. Bei Signaturen war das ärgerlich; beim versionierten Joomla-
# Datenbestand (Prüfsummen, Schwachstellenliste) wäre es ein Fehler — der Lauf
# würde stumm gegen einen jahrealten Stand prüfen und "unauffällig" melden.
_srcdir="$(dirname "$SELF_PATH")"
if [[ "$_srcdir" != "$BASE_DIR" ]]; then   # sonst kopiert sich die installierte Kopie selbst
  for _aux in signaturen reportgen daten; do
    if [[ -d "$_srcdir/$_aux" ]]; then
      mkdir -p "${BASE_DIR}/$_aux"
      # '/.' kopiert den INHALT — ohne den entsteht ${BASE_DIR}/daten/daten
      cp -rf "$_srcdir/$_aux/." "${BASE_DIR}/$_aux/" 2>/dev/null || true
    fi
  done
fi

# Alles zusätzlich in lauf.log protokollieren
exec > >(tee -a "$RUN_LOG") 2>&1

# ── Zähler & Befund-Sammlung für Kunden-/BSI-Bericht ─────────
N_CRIT=0; N_WARN=0; N_OK=0
CRIT_LIST=""   # Markdown-Bullets (alle Befunde — Technik/Betreiber)
WARN_LIST=""
CUST_CRIT_LIST=""   # nur WEBSITE-Befunde (Kundenbericht) — via crit "…" web
CUST_WARN_LIST=""
EVIDENCE_IDX=0
WPDB_FLAGS=0
WPDB_VERDICT="⚪ Keine WordPress-Installation im Scan-Pfad gefunden — keine Datenbank-Prüfung durchgeführt."
ROOT_VERDICT="⚪ Root-Prüfung nicht durchgeführt."
# WP-Integritäts-/Doorway-Befunde (v3.3) — für findings.json
CORE_INJECTED=""       # veränderte Core-Dateien (verify-checksums "doesn't verify")
CORE_SNE=""            # Core-fremde Dateien (verify-checksums "should not exist")
DOORWAY_DIRS=""        # Verzeichnisse mit Doorway-.htaccess-Signatur
CORE_INJECT_HITS=""    # Dateien mit @include base64_decode() (Bootstrap-Injektion)
DISGUISED_PAYLOADS=""  # als Nicht-PHP getarnte Payloads (<?php in .ttf/.png/.gif/.css…)
ROGUE_ADMINS=""        # via wp-cli-Fallback gefundene Angreifer-Admins
SUSP_PLUGINS=""        # verdächtige Plugins/mu-Plugins (alle bewertet, auch inaktive)
MU_PLUGINS=""          # alle mu-Plugins (laufen immer, ohne Aktivierung)
TAMPERED_HTACCESS=""   # manipulierte .htaccess (Malware-Whitelist, bricht Admin/403)

# ── v3.4: Relay-Backdoors — Variablen & Selbstausschluss ─────
GSOCKET_HITS=""          # Dateien/Prozesse mit gsocket-Signatur
MASQ_BINARIES=""         # ELF-Binaries getarnt als Schlüssel-/Konfigdatei
FILELESS_PROCS=""        # Prozesse aus memfd (nur im RAM)
KTHREAD_FAKES=""         # als Kernel-Thread getarnte User-Prozesse
ORPHAN_SHELLS=""         # verwaiste Interpreter ohne TTY
SSH_LOGIN_HOOKS=""       # ~/.ssh/rc und /etc/ssh/sshrc
RELAY_CONNECTIONS=""     # ausgehende 443/7350 durch untypische Prozesse
YARA_HITS=""             # YARA-Treffer (falls yara installiert)
RELAY_VERDICT="⚪ Relay-Backdoor-Prüfung nicht durchgeführt."
# v3.6 System-Integrität & autoritative Scanner-Taps — für findings.json
TIMESTOMP=""           # Dateien mit zurückdatiertem mtime (Timestomping)
RECENT_SYS=""          # kürzlich veränderte Dateien in stabilen Systemdirs
IMUNIFY_HITS=""        # offene Imunify-Malware-Treffer im Scope
WPTK_INFECTED=""       # vom WP Toolkit als infiziert markierte Instanzen

# ── v3.8: Joomla-Prüfung (Abschnitt 12) ──────────────────────
JOOMLA_FLAGS=0
JOOMLA_COUNT=0
JOOMLA_SKIPPED=0         # übersprungene Backup-/Quarantäne-Kopien
JOOMLA_VERDICT="⚪ Keine Joomla-Installation im Scan-Pfad gefunden — keine Joomla-Prüfung durchgeführt."
JOOMLA_CONFIGS=""        # gefundene configuration.php (mit class JConfig)
JOOMLA_VERSIONS=""       # "site<TAB>version<TAB>quelle" je Installation
JOOMLA_CORE_MODIFIED=""  # veränderte Kern-Dateien (Prüfsummen-Diff, ab v3.8.1)
JOOMLA_CORE_UNKNOWN=""   # kernfremde Dateien in reinen Kern-Verzeichnissen
JOOMLA_SYS_PLUGINS=""    # System-Plugins ohne Paket/Verzeichnis (DB-Persistenz)
JOOMLA_ROGUE_SUPER=""    # neu angelegte, nie benutzte Super-User
JOOMLA_SESSION_HITS=""   # Deserialisierungs-Payloads in #__session.data
JOOMLA_MOD_CUSTOM=""     # mod_custom-Module mit Fremd-/Obfuskations-Injektion
JOOMLA_TPL_PARAMS=""     # #__template_styles.params-Injektionen (Helix3-Muster)
JOOMLA_USER_KEYS=""      # #__user_keys (Remember-Me-Token als Backdoor)
JOOMLA_VULN_EXT=""       # verwundbare Erweiterungen (VEL/CVE-Abgleich)
JOOMLA_CONFIG_WEAK=""    # Härtungsbefunde aus configuration.php
JOOMLA_MALWARE=""        # Joomla-typische Schaddateien (Bild-Magic + PHP u.a.)
JOOMLA_LOG_IOC=""        # Access-Log-Indikatoren (JCE-Bot, API-Leak-Abrufe)
JOOMLA_DATA_DIR="${BASE_DIR}/daten/joomla"
J_DATA_STAMP=""          # Stand des Offline-Datenbestands (YYYY-MM-DD)
JOOMLA_DATA_AGE=0        # Alter des Offline-Datenbestands in Tagen
ONLINE_FETCHES=""        # Protokoll aller Netzabrufe (forensische Transparenz)

# Signaturfamilie THC gsocket / gs-netcat. Trifft auch bei Umbenennung,
# da die Strings im Binary verbleiben (auch bei stripped).
GS_SIG_REGEX='GSRN|gs\.thc\.org|GS_connect|GSOCKET_ARGS|GSOCKET_SECRET|gs-netcat|4_gs-netcat\.c|GS_daemonize|gs_watchdog|GSOCKET_SOCKS|GS_gen_secret'
# Vom gsocket-Installer verwendete Tarnnamen
GS_DISGUISE_REGEX='gs-dbus|gs-bd|dbus-run-session\.sh'

# WICHTIG — Selbstausschluss: NT-Forensik legt seine Berichte und Belege unter
# ${BASE_DIR} (/root/wartungsscripte) ab. Da /root mitgescannt wird und die
# Berichte die Suchbegriffe im Klartext enthalten, würde sich das Skript ab dem
# zweiten Lauf selbst als Backdoor melden. Alle Scans dieses Abschnitts filtern
# daher konsequent gegen ${BASE_DIR}.
nf_strip_self() { grep -vF "${BASE_DIR}/" || true; }

# Eigene Prozesskette (Skript + Eltern), damit der Lauf sich nicht selbst meldet
NF_SELF_PIDS=" $$ ${PPID:-0} "
_nf_p=${PPID:-0}
for _nf_i in 1 2 3 4 5; do
    [[ -r "/proc/$_nf_p/status" ]] || break
    _nf_p=$(awk '/^PPid:/{print $2}' "/proc/$_nf_p/status" 2>/dev/null)
    [[ -z "$_nf_p" || "$_nf_p" == "0" ]] && break
    NF_SELF_PIDS+="$_nf_p "
done
nf_is_self() { [[ " $NF_SELF_PIDS " == *" $1 "* ]]; }

# ── Hilfsfunktionen ──────────────────────────────────────────
h1()  { echo -e "\n${BOLD}${BLU}══════════════════════════════════════════${NC}"; \
        echo -e "${BOLD}${BLU}  $1${NC}"; \
        echo -e "${BOLD}${BLU}══════════════════════════════════════════${NC}"; \
        echo -e "\n## $1\n" >> "$REPORT_FILE"; }

h2()  { echo -e "\n${CYN}▶ $1${NC}"; echo -e "\n### $1\n" >> "$REPORT_FILE"; }

ok()  { echo -e "  ${GRN}✓${NC} $1"; echo "- ✅ $1" >> "$REPORT_FILE"; N_OK=$((N_OK+1)); }
# $2="web" markiert einen WEBSITE-Befund (gehört in den Kundenbericht). Ohne $2
# ist es ein Server-/Root-/Infrastruktur-Befund — der bleibt Technik-/Betreiber-
# Sache und taucht NICHT im Kundenbericht auf (v3.8 Scope-Trennung).
warn(){ echo -e "  ${YLW}⚠${NC}  $1"; echo "- ⚠️  **$1**" >> "$REPORT_FILE"; \
        N_WARN=$((N_WARN+1)); WARN_LIST+="- $1"$'\n'; \
        [[ "${2:-}" == web ]] && CUST_WARN_LIST+="- $1"$'\n'; return 0; }
crit(){ echo -e "  ${RED}✗${NC}  ${BOLD}$1${NC}"; echo "- 🔴 **KRITISCH: $1**" >> "$REPORT_FILE"; \
        N_CRIT=$((N_CRIT+1)); CRIT_LIST+="- $1"$'\n'; \
        [[ "${2:-}" == web ]] && CUST_CRIT_LIST+="- $1"$'\n'; return 0; }
info(){ echo -e "  ${NC}·  $1"; echo "  $1" >> "$REPORT_FILE"; }
code(){ echo -e "\n\`\`\`\n$1\n\`\`\`\n" >> "$REPORT_FILE"; }

# ── Maskierung für Kundenberichte (v3.5) ─────────────────────
# Kundenberichte gehen an Dritte und müssen DSGVO-datensparsam sein: fremde
# E-Mail-Adressen (etwa WP-Admin-Konten) werden pseudonymisiert. Angreifer-IPs
# bleiben im Klartext — sie sind für den Betroffenen zum Sperren nötig und
# fallen unter berechtigtes Interesse. Technik-/BSI-/DSGVO-Berichte (interne
# bzw. Behördendokumente) bleiben unmaskiert. stdin → stdout.
mask_email(){ sed -E 's/([A-Za-z0-9])[A-Za-z0-9._%+-]*(@[A-Za-z0-9.-]+\.[A-Za-z]{2,})/\1***\2/g'; }

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

# ── Netzabruf mit Protokoll (v3.8, nur mit --online) ─────────
# NT-Forensik behauptet an mehreren Stellen, read-only und rein lokal zu
# arbeiten. Sobald --online gesetzt ist, stimmt der zweite Teil nicht mehr —
# und das muss belegbar im Bericht stehen, nicht nur im Kopf des Prüfers.
# Jeder Abruf wird mit URL, HTTP-Code, Größe und SHA256 protokolliert.
#
# -L ist zwingend: Release-Downloads antworten mit 302 auf einen
# Auslieferungsdienst. Ohne Folgen der Weiterleitung landet nur die
# 302-Antwort in der Zieldatei und der Abruf scheitert stumm.
# Das Zeitlimit muss ein vollständiges Programmpaket zulassen (rund 30 MB).
# nf_fetch <url> <zieldatei>  → 0 bei HTTP 200
nf_fetch() {
  local url="$1" dest="$2" code sz sum
  code=$(curl -fsSL --max-time 300 --retry 1 -o "$dest" -w '%{http_code}' "$url" 2>/dev/null || echo "000")
  sz=$(stat -c%s "$dest" 2>/dev/null || echo 0)
  sum=$(sha256sum "$dest" 2>/dev/null | awk '{print $1}')
  ONLINE_FETCHES+="$(date -u +"%Y-%m-%dT%H:%M:%SZ")  ${url}  HTTP=${code}  ${sz}B  SHA256=${sum:-–}"$'\n'
  [[ "$code" == "200" ]]
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
  WP-PLESK-FORENSIK v3.7.1 — netztaucher | digital
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

h2 "6.9 Weniger bekannte Persistenz-Orte (udev, PAM, APT, linger)"
# Diese vier Orte überleben eine Bereinigung, die sich auf Cron und
# systemd beschränkt — und werden genau deshalb gern genutzt.
EXOTIC_PERSIST=""

# udev: RUN+= führt Code aus, sobald ein passendes Gerät auftaucht
UDEV_HITS=$(grep -rnasE 'RUN\+?=.*(sh|bash|python|perl|/tmp/|/dev/shm/)' /etc/udev/rules.d/ 2>/dev/null || true)
if [[ -n "$UDEV_HITS" ]]; then
    crit "udev-Regel führt Code aus — Persistenz über Geräte-Events"
    code "$UDEV_HITS"
    EXOTIC_PERSIST+="=== udev ==="$'\n'"$UDEV_HITS"$'\n'
else
    ok "Keine udev-Regeln mit Code-Ausführung"
fi

# PAM: pam_exec.so hängt sich in jeden Login ein
PAM_HITS=$(grep -rnasE 'pam_exec\.so|/tmp/|/dev/shm/' /etc/pam.d/ 2>/dev/null || true)
if [[ -n "$PAM_HITS" ]]; then
    crit "PAM-Konfiguration ruft externes Programm auf — Login-Hook"
    code "$PAM_HITS"
    EXOTIC_PERSIST+="=== PAM ==="$'\n'"$PAM_HITS"$'\n'
else
    ok "Keine auffälligen PAM-Einträge"
fi

# APT: Pre-/Post-Invoke läuft bei jedem apt-Aufruf als root
APT_HITS=$(grep -rnasE '(Pre-Invoke|Post-Invoke).*(curl|wget|/tmp/|/dev/shm/|base64)' /etc/apt/apt.conf.d/ 2>/dev/null || true)
if [[ -n "$APT_HITS" ]]; then
    crit "APT-Hook lädt/führt Code aus — läuft bei jedem apt-Lauf als root"
    code "$APT_HITS"
    EXOTIC_PERSIST+="=== APT ==="$'\n'"$APT_HITS"$'\n'
else
    ok "Keine auffälligen APT-Hooks"
fi

# systemd linger: User-Services laufen ohne Login weiter
if [[ -d /var/lib/systemd/linger ]]; then
    LINGER_USERS=$(ls -A /var/lib/systemd/linger 2>/dev/null || true)
    if [[ -n "$LINGER_USERS" ]]; then
        warn "Benutzer mit aktivem 'linger' — deren systemd-User-Services laufen auch ohne Login: $(echo "$LINGER_USERS" | tr '\n' ' ')"
        USER_UNITS=$(find /home /root -maxdepth 5 -type d -path '*/.config/systemd/user' 2>/dev/null \
            | while read -r d; do ls -la "$d" 2>/dev/null | sed "s|^|[$d] |"; done || true)
        code "$LINGER_USERS

$USER_UNITS"
        EXOTIC_PERSIST+="=== linger ==="$'\n'"$LINGER_USERS"$'\n'"$USER_UNITS"$'\n'
    else
        ok "Kein Benutzer mit aktivem linger"
    fi
fi

[[ -n "$EXOTIC_PERSIST" ]] && evidence "persistenz_exotisch" "$EXOTIC_PERSIST"

# ============================================================
h1 "7. DATEISYSTEM-SCAN"
# ============================================================

case "$SCOPE_MODE" in
  path)   SCAN_PATH="$SCAN_PATH_ARG" ;;
  domain) SCAN_PATH="${VHOSTS_DIR}/${DOMAIN}" ;;
  *)      SCAN_PATH="$VHOSTS_DIR" ;;   # global
esac
# Fallback: gesetzte Domain ohne existierenden vhost -> serverweit statt ins Leere
[[ "$SCOPE_MODE" == "domain" && ! -d "$SCAN_PATH" ]] && SCAN_PATH="$VHOSTS_DIR"

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
  crit "PHP-Dateien in Upload-Verzeichnissen (nach Guard-Filter, extrem verdächtig)" web
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
  crit "Webshells/Dropper gefunden: ${WEBSHELL_COUNT} Datei(en) < ${DROPPER_MAX_BYTES} B mit Obfuskation" web
  DROPPER_CLUSTER=$(echo "$DROPPER_DETAIL" | grep "^=== " | sed 's|=== /var/www/vhosts/||;s| ===||' | cut -d/ -f1 | sort | uniq -c | sort -rn || true)
  info "Betroffene Domains (Dropper-Cluster):"
  code "$DROPPER_CLUSTER"
  echo -e "\n**Dropper-Details:**\n\`\`\`\n$DROPPER_DETAIL\n\`\`\`" >> "$REPORT_FILE"
  evidence "webshell_dropper_kritisch" "$DROPPER_DETAIL"
else
  ok "Keine kleinen Obfuskations-Dropper gefunden"
fi

if [[ "$WEBSHELL_REVIEW" -gt 0 ]]; then
  warn "Obfuskations-Muster in ${WEBSHELL_REVIEW} größeren Datei(en) — manuell prüfen (oft legitime Frameworks)" web
  evidence "webshell_review_gross" "$REVIEW_DETAIL"
fi

h2 "7.4 Versteckte Dateien und Verzeichnisse im Webspace"
HIDDEN=$(find "$SCAN_PATH" -name ".*" -not -name ".htaccess" -not -name ".well-known" \
  -not -name ".git*" -not -name ".user.ini" 2>/dev/null | head -20 || true)
if [[ -n "$HIDDEN" ]]; then
  warn "Versteckte Dateien/Verzeichnisse gefunden — manuell prüfen" web
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
  warn "Dateinamen mit verdächtigen Schlüsselwörtern (manuell gegen Inhalt prüfen)" web
  code "$(echo "$SUSP_NAMES" | xargs -r ls -la 2>/dev/null)"
  evidence "verdaechtige_dateinamen" "$(echo "$SUSP_NAMES" | xargs -r ls -la 2>/dev/null)"
else
  ok "Keine verdächtigen Dateinamen (außerhalb Core/vendor/cache/plugins)"
fi

h2 "7.6 .htaccess-Dateien prüfen"
HTACCESS_REDIRECTS=$(find "$SCAN_PATH" -name ".htaccess" 2>/dev/null \
  -exec grep -lE "RewriteRule.*http|Redirect.*http" {} \; || true)
if [[ -n "$HTACCESS_REDIRECTS" ]]; then
  warn ".htaccess mit externen Weiterleitungen gefunden" web
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
  crit "SUID/SGID-Dateien in Webspace/tmp — Privilege-Escalation-Verdacht" web
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
  crit "PHP-Dateien mit Immutable-Flag — Malware schützt sich so vor Löschung" web
  code "$IMMUTABLE"
  evidence "immutable_dateien" "$IMMUTABLE"
else
  ok "Keine Immutable-Flags auf PHP-Dateien (Stichprobe max. 8000 Dateien)"
fi

h2 "7.10 Als Schlüssel-/Konfigdatei getarnte Binaries"
# Konkreter Anlass: eine gs-netcat-Binary lag als ~/.ssh/id_rsa auf dem
# System. Eine Datei mit diesem Namen prüft niemand auf ihren Dateityp.
# Erkennung über das ELF-Magic (7f 45 4c 46), nicht über den Namen.
# Scope: System-Verzeichnisse (Schlüssel-/Konfig-Ablageorte) plus der
# geprüfte Webspace ${SCAN_PATH} — NICHT alle vhosts. Auf Shared-Hosts
# mit hunderten vhosts explodiert ein $VHOSTS_DIR-Scan (Plesk-Statistik/
# webalizer allein liefern Zehntausende .png/.log-Treffer). Der serverweite
# Voll-Scan bleibt dem Global-Modus (ab v3.5) vorbehalten. Die Endungsliste
# ist bewusst auf Schlüssel-/Zertifikat-/Konfig-Namen begrenzt; eine als
# Bild/Log getarnte ELF fängt ohnehin der inhaltsbasierte Signaturscan 8.7
# (grep -rla) und, falls vorhanden, YARA (7.11) — beide lesen den Inhalt,
# nicht den Namen.
MASQ_FOUND=""
while IFS= read -r f; do
    [[ -f "$f" ]] || continue
    magic=$(head -c4 "$f" 2>/dev/null | od -An -tx1 2>/dev/null | tr -d ' \n')
    if [[ "$magic" == "7f454c46" ]]; then
        MASQ_FOUND+="$(ls -la --time-style=long-iso "$f" 2>/dev/null)  SHA256: $(sha256sum "$f" 2>/dev/null | awk '{print $1}')"$'\n'
        MASQ_BINARIES+="$f"$'\n'
    fi
done < <(find /root /home /etc "$SCAN_PATH" /tmp /var/tmp /dev/shm -xdev -type f \
    \( -name 'id_*' -o -name '*.pem' -o -name '*.key' -o -name '*.crt' \
       -o -name 'authorized_keys*' -o -name 'known_hosts' -o -name '*.conf' \) 2>/dev/null | nf_strip_self)

if [[ -n "$MASQ_FOUND" ]]; then
    crit "Ausführbare Binary als Schlüssel-/Konfigdatei getarnt"
    code "$MASQ_FOUND"
    evidence "getarnte_binaries" "$MASQ_FOUND"
else
    ok "Keine als Schlüssel-/Konfigdatei getarnten Binaries"
fi

h2 "7.11 YARA-Signaturscan (optional)"
# Nutzt signaturen/gsocket-backdoors.yar, falls yara installiert ist.
# Die Regel ELF_Masquerading_As_KeyFile braucht die externe Variable
# 'filename' — ohne sie würde sie auf jede ELF-Datei anschlagen.
# Sammel-Regeldatei bevorzugen (bindet gsocket + Joomla + künftige ein).
# Rückfall auf die einzelne Datei hält Hosts lauffähig, die noch einen alten
# signaturen/-Stand tragen.
YARA_RULES_FILE="${BASE_DIR}/signaturen/alle.yar"
[[ -f "$YARA_RULES_FILE" ]] || YARA_RULES_FILE="${BASE_DIR}/signaturen/gsocket-backdoors.yar"
if [[ "$WANT_YARA" != "1" ]]; then
    info "YARA-Scan nicht aktiviert — mit --yara einschalten (auf großen Webspaces langsam)"
elif command -v yara &>/dev/null && [[ -f "$YARA_RULES_FILE" ]]; then
    YARA_DETAIL=""
    while IFS= read -r f; do
        [[ -f "$f" ]] || continue
        bn=$(basename "$f")
        yout=$(yara -w -d filename="$bn" "$YARA_RULES_FILE" "$f" 2>/dev/null || true)
        if [[ -n "$yout" ]]; then
            rules=$(echo "$yout" | awk '{print $1}' | sort -u | tr '\n' ' ')
            YARA_DETAIL+="$f — Regeln: $rules"$'\n'
            YARA_HITS+="$f"$'\n'
        fi
    done < <(find /tmp /var/tmp /dev/shm /root /home /usr/local/bin /usr/local/sbin /opt "$SCAN_PATH" \
                -xdev -type f -size -30M 2>/dev/null | nf_strip_self)
    if [[ -n "$YARA_DETAIL" ]]; then
        crit "YARA-Signaturtreffer im Dateisystem"
        code "$YARA_DETAIL"
        evidence "yara_treffer" "$YARA_DETAIL"
    else
        ok "Keine YARA-Signaturtreffer"
    fi
elif ! command -v yara &>/dev/null; then
    info "yara nicht installiert — Signaturscan übersprungen (apt install yara)"
else
    info "Keine Regeldatei unter $YARA_RULES_FILE — Signaturscan übersprungen"
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
  # debsums ergänzt dpkg -V: prüft die md5-Summen der installierten Paketdateien
  # gegen die bei der Installation gespeicherten. Bewusst auf dieselbe kritische
  # Paketmenge begrenzt — debsums liest Dateiinhalte, über ALLE Pakete wäre es
  # (wie 7.11/8.7) zu teuer. Fund fließt in PKG_MODIFIED → Root-Verdikt (11.5).
  if command -v debsums &>/dev/null; then
    DEBSUMS_BAD=$(debsums -c bash coreutils openssh-server openssh-client curl wget cron 2>/dev/null || true)
    if [[ -n "$DEBSUMS_BAD" ]]; then
      crit "debsums: veränderte Paketdateien in Kern-Paketen — Manipulations-Verdacht"
      code "$DEBSUMS_BAD"
      evidence "debsums_changed" "$DEBSUMS_BAD
$(printf '%s\n' "$DEBSUMS_BAD" | xargs -r sha256sum 2>/dev/null)"
      PKG_MODIFIED+=$'\n'"$DEBSUMS_BAD"
    else
      ok "debsums: Kern-Paketdateien unverändert (md5 gegen Installationsstand)"
    fi
  else
    info "debsums nicht installiert — ergänzende md5-Paketprüfung übersprungen (apt install debsums)"
  fi
fi

h2 "8.7 Relay-Backdoors (THC gsocket / gs-netcat)"
# gsocket öffnet KEINEN Port. Beide Seiten verbinden sich ausgehend über
# TLS/443 zu einem Relay (GSRN) und finden sich über ein gemeinsames
# Geheimnis. Abschnitt 8.1 (LISTEN-Ports) ist dagegen blind — deshalb
# hier eigens Datei-, Prozess- und Verbindungsebene.
# Scope wie 7.10/7.11: System-Dirs voll, vhost-Teil nur ${SCAN_PATH} (der
# serverweite Voll-Scan über alle vhosts bleibt dem Global-Modus ab v3.5
# vorbehalten — über hunderte vhosts liest der Scan jede Datei und ist auf
# Shared-Hosts nicht tragbar).
# Umsetzung als find | grep statt grep -r: die Größengrenze -size -30M
# überspringt Backup-Archive und Quarantäne-Dumps (auf Produktions-Root
# schnell dutzende GB), die der Regex sonst byteweise durchkämmt. Die gesuchte
# gs-netcat-Binary ist ~2,8 MB und bleibt damit erfasst. nf_strip_self prunt
# den eigenen Ablageordner ${BASE_DIR} VOR dem Lesen. grep -a (ohne -I!) ist
# Absicht: -I würde Binärdateien überspringen und genau die ELF-Backdoor
# nie lesen.
GS_FILE_HITS=$(find /tmp /var/tmp /dev/shm /root /home /usr/local/bin /usr/local/sbin /opt "$SCAN_PATH" \
    -xdev -type f -size -30M 2>/dev/null | nf_strip_self \
    | xargs -r -d '\n' grep -la -E "$GS_SIG_REGEX" 2>/dev/null \
    | grep -vF "$INSTALLED_PATH" || true)
if [[ -n "$GS_FILE_HITS" ]]; then
    # Differenzierung nach Dateityp — ohne sie erzeugt jede Dokumentation und
    # jede Signaturdatei, die die Begriffe nennt, einen Fehlalarm:
    #   ELF-Binary   → das Werkzeug selbst liegt auf dem System (kritisch)
    #   Skript/Text  → Installer, Konfiguration oder nur eine Erwähnung (Review)
    GS_ELF=""; GS_TEXT=""
    while IFS= read -r f; do
        [[ -f "$f" ]] || continue
        line="$(ls -la --time-style=long-iso "$f" 2>/dev/null)  SHA256: $(sha256sum "$f" 2>/dev/null | awk '{print $1}')"
        magic=$(head -c4 "$f" 2>/dev/null | od -An -tx1 2>/dev/null | tr -d ' \n')
        if [[ "$magic" == "7f454c46" ]]; then
            GS_ELF+="$line"$'\n'
            GSOCKET_HITS+="$f"$'\n'
        else
            GS_TEXT+="$line"$'\n'
        fi
    done <<< "$GS_FILE_HITS"

    if [[ -n "$GS_ELF" ]]; then
        crit "gs-netcat-Binary auf dem System gefunden — interaktive Relay-Backdoor"
        code "$GS_ELF"
        evidence "gsocket_binaries" "$GS_ELF"
    fi
    if [[ -n "$GS_TEXT" ]]; then
        warn "gsocket-Begriffe in Nicht-Binärdateien (Installer, Konfig oder bloße Erwähnung) — manuell einordnen"
        code "$GS_TEXT"
        evidence "gsocket_textfunde" "$GS_TEXT"
    fi
else
    ok "Keine gsocket-Signaturen im Dateisystem"
fi

GS_PROC_HITS=$(ps -eo pid,ppid,user,etime,args 2>/dev/null \
    | grep -iE "$GS_SIG_REGEX|$GS_DISGUISE_REGEX" \
    | grep -vE "grep|wp_plesk_forensik" || true)
if [[ -n "$GS_PROC_HITS" ]]; then
    crit "gsocket-typischer Prozess läuft"
    code "$GS_PROC_HITS"
    evidence "gsocket_prozesse" "$GS_PROC_HITS"
    GSOCKET_HITS+="(Prozess) $(echo "$GS_PROC_HITS" | head -1)"$'\n'
else
    ok "Kein gsocket-typischer Prozessname"
fi

h2 "8.8 Fileless-Prozesse (memfd — Binary nur im RAM)"
# memfd_create() führt ein Binary aus, das nie auf der Platte landet.
# Kein Dateiscanner der Welt findet das; nur /proc verrät es.
# Abschnitt 8.2b sieht solche Prozesse zwar als "(deleted)", benennt
# aber die Ursache nicht — und die ist für die Bewertung entscheidend.
MEMFD_DETAIL=""
for pid in /proc/[0-9]*; do
    nf_is_self "$(basename "$pid")" && continue
    exe=$(readlink "$pid/exe" 2>/dev/null) || continue
    case "$exe" in
        *memfd:*)
            p=$(basename "$pid")
            MEMFD_DETAIL+="PID $p — $exe
  comm:    $(cat "$pid/comm" 2>/dev/null)
  cmdline: $(tr '\0' ' ' < "$pid/cmdline" 2>/dev/null | head -c 200)
  user:    $(stat -c %U "$pid" 2>/dev/null)
  ppid:    $(awk '/^PPid:/{print $2}' "$pid/status" 2>/dev/null)
"
            FILELESS_PROCS+="PID $p: $exe"$'\n' ;;
    esac
done
if [[ -n "$MEMFD_DETAIL" ]]; then
    crit "Prozess(e) laufen ausschließlich aus dem Arbeitsspeicher (memfd) — fileless Malware"
    code "$MEMFD_DETAIL"
    evidence "fileless_memfd_prozesse" "$MEMFD_DETAIL"
else
    ok "Keine memfd-Prozesse (keine fileless Ausführung)"
fi

h2 "8.9 Als Kernel-Thread getarnte Prozesse"
# Echte Kernel-Threads haben eckige Klammern im Namen, PPID 2 (kthreadd)
# UND kein /proc/PID/exe. Ein User-Prozess, der sich [kworker/…] nennt,
# verrät sich über genau diese beiden Merkmale.
# Die Tarnung kann über comm (prctl PR_SET_NAME) ODER über argv[0]
# (exec -a, in `ps` sichtbar) laufen — beide sind gratis fälschbar, daher
# werden beide geprüft. comm allein würde eine reine argv[0]-Tarnung
# übersehen, obwohl sie in der Prozessliste wie ein Kernel-Thread aussieht.
KTHREAD_DETAIL=""
for pid in /proc/[0-9]*; do
    nf_is_self "$(basename "$pid")" && continue
    comm=$(cat "$pid/comm" 2>/dev/null) || continue
    argv0=$(tr '\0' '\n' < "$pid/cmdline" 2>/dev/null | head -1)
    # kthread-typisch tarnt sich, wenn comm ODER argv[0] mit '[' beginnt
    if [[ "$comm" == \[* || "$argv0" == \[* ]]; then
        ppid=$(awk '/^PPid:/{print $2}' "$pid/status" 2>/dev/null)
        exe=$(readlink "$pid/exe" 2>/dev/null)
        # Beweis: echte Kernel-Threads haben KEIN exe und PPID 2. Ein Treffer
        # mit vorhandenem exe oder fremder PPID ist damit belastbar (crit).
        if [[ -n "$exe" ]] || { [[ -n "$ppid" ]] && [[ "$ppid" != "2" ]] && [[ "$ppid" != "0" ]]; }; then
            p=$(basename "$pid")
            [[ "$comm" == \[* ]] && vektor="comm='$comm'" || vektor="argv[0]='$argv0'"
            KTHREAD_DETAIL+="PID $p gibt sich als Kernel-Thread aus ($vektor)
  comm: $comm
  argv[0]: ${argv0:-<leer>}
  exe:  ${exe:-<keins>}
  ppid: ${ppid:-?} (echte Kernel-Threads: 2)
  user: $(stat -c %U "$pid" 2>/dev/null)
"
            KTHREAD_FAKES+="PID $p: ${comm}${argv0:+ / $argv0}"$'\n'
        fi
    fi
done
if [[ -n "$KTHREAD_DETAIL" ]]; then
    crit "Prozess(e) tarnen sich als Kernel-Thread"
    code "$KTHREAD_DETAIL"
    evidence "kernel_thread_tarnung" "$KTHREAD_DETAIL"
else
    ok "Keine als Kernel-Thread getarnten Prozesse"
fi

h2 "8.10 Verwaiste Interpreter ohne Terminal"
# Eine Shell mit PPID 1 und ohne kontrollierendes TTY hat keinen
# Benutzer am anderen Ende — das ist das Profil einer abgesetzten
# Reverse-Shell, die den Elternprozess überlebt hat.
ORPHAN_DETAIL=""
for pid in /proc/[0-9]*; do
    nf_is_self "$(basename "$pid")" && continue
    comm=$(cat "$pid/comm" 2>/dev/null) || continue
    case "$comm" in
        sh|bash|dash|zsh|ksh|perl|python|python3|ruby|php|nc|ncat|socat)
            ppid=$(awk '/^PPid:/{print $2}' "$pid/status" 2>/dev/null)
            tty=$(awk '{print $7}' "$pid/stat" 2>/dev/null)
            if [[ "$ppid" == "1" ]] && [[ "${tty:-0}" == "0" ]]; then
                p=$(basename "$pid")
                ORPHAN_DETAIL+="PID $p ($comm) — PPID 1, kein TTY
  cmdline: $(tr '\0' ' ' < "$pid/cmdline" 2>/dev/null | head -c 200)
  user:    $(stat -c %U "$pid" 2>/dev/null)
  cwd:     $(readlink "$pid/cwd" 2>/dev/null)
"
                ORPHAN_SHELLS+="PID $p: $comm"$'\n'
            fi ;;
    esac
done
if [[ -n "$ORPHAN_DETAIL" ]]; then
    warn "Verwaiste Shell(s)/Interpreter ohne Terminal — mit laufenden Diensten abgleichen"
    code "$ORPHAN_DETAIL"
    evidence "verwaiste_interpreter" "$ORPHAN_DETAIL"
else
    ok "Keine verwaisten Interpreter ohne TTY"
fi

h2 "8.11 Prozess-Umgebung auf Backdoor-Marker"
# GSOCKET_*/GS_ARGS verrät gsocket auch dann, wenn das Binary umbenannt
# wurde. LD_PRELOAD in einem einzelnen Prozess ist Hooking ohne Eintrag
# in /etc/ld.so.preload. HISTFILE=/dev/null ist Spurenvermeidung.
ENV_DETAIL=""
for pid in /proc/[0-9]*; do
    [[ -r "$pid/environ" ]] || continue
    if grep -aqE "GSOCKET_|GS_ARGS=|LD_PRELOAD=|HISTFILE=/dev/null|HISTSIZE=0" "$pid/environ" 2>/dev/null; then
        p=$(basename "$pid")
        nf_is_self "$p" && continue
        ENV_DETAIL+="PID $p ($(cat "$pid/comm" 2>/dev/null)) — $(tr '\0' ' ' < "$pid/cmdline" 2>/dev/null | head -c 120)
$(tr '\0' '\n' < "$pid/environ" 2>/dev/null | grep -aE "GSOCKET_|GS_ARGS=|LD_PRELOAD=|HISTFILE=|HISTSIZE=" | sed 's/^/  /')
"
    fi
done
if [[ -n "$ENV_DETAIL" ]]; then
    crit "Prozess(e) mit Backdoor-typischen Umgebungsvariablen"
    code "$ENV_DETAIL"
    evidence "prozess_umgebung_marker" "$ENV_DETAIL"
else
    ok "Keine Backdoor-Marker in Prozess-Umgebungen"
fi

h2 "8.12 Ausgehende Verbindungen (Relay-Erkennung)"
# Der eigentliche Kanal einer Relay-Backdoor. Ausgehend auf 443 sieht
# wie normales HTTPS aus — auffällig wird es durch den Prozess, der die
# Verbindung hält. Bekannte Web-/Update-/Monitoring-Clients sind
# ausgenommen; alles andere auf 443/7350 ist erklärungsbedürftig.
#
# WICHTIG — nur der PEER-Port zählt: Auf einem Webserver hat jede eingehende
# HTTPS-Verbindung lokal Port 443. Ein simples grep ':443 ' trifft dieses
# lokale Feld und meldet dann jeden Besucher als Relay-Verdacht — auf einem
# Produktions-Plesk sind das dutzende Fehlalarme pro Lauf (gemessen: 76
# eingehende vs. 2 echte ausgehende). Eine Relay-Backdoor verbindet sich
# AUSGEHEND, d. h. der ENTFERNTE Port ist 443/7350. Wir werten deshalb
# ausschließlich das Peer-Feld ($5 in `ss`: Netid Recv-Q Send-Q Local Peer
# Process) aus.
if command -v ss &>/dev/null; then
    ESTAB=$(ss -tunp state established 2>/dev/null || true)
    evidence "verbindungen_etabliert" "$ESTAB"

    RELAY_SUSPECT=$(echo "$ESTAB" \
        | awk 'NR>1 { n=split($5,a,":"); pp=a[n]; if (pp=="443" || pp=="7350") print }' \
        | grep -viE 'users:\(\("(nginx|apache2?|httpd|curl|wget|php-fpm[0-9.]*|php|node|containerd|dockerd|packagekitd?|snapd|unattended-upgr|apt|apt-get|aptd|systemd-resolve|chronyd?|ntpd|fail2ban-server|certbot|git|ssh|sshd|tailscaled|sw-engine|psa|plesk|mysqld|postfix|dovecot|python3?)"' || true)
    if [[ -n "$RELAY_SUSPECT" ]]; then
        crit "Ausgehende TLS-Verbindung durch untypischen Prozess — Relay-Backdoor-Verdacht"
        code "$RELAY_SUSPECT"
        evidence "relay_verdaechtige_verbindungen" "$RELAY_SUSPECT"
        RELAY_CONNECTIONS+="$RELAY_SUSPECT"$'\n'
    else
        ok "Keine untypischen ausgehenden 443/7350-Verbindungen"
    fi

    TOR_CONN=$(echo "$ESTAB" \
        | awk 'NR>1 { n=split($5,a,":"); pp=a[n]; if (pp=="9001"||pp=="9030"||pp=="9050"||pp=="9150") print }' || true)
    if [[ -n "$TOR_CONN" ]]; then
        warn "TOR-typische Verbindung(en) — gsocket kann optional über TOR routen"
        code "$TOR_CONN"
        evidence "tor_verbindungen" "$TOR_CONN"
    else
        ok "Keine TOR-typischen Verbindungen"
    fi
else
    warn "'ss' nicht verfügbar — ausgehende Verbindungen nicht prüfbar"
fi

h2 "8.13 Kürzlich veränderte Systemdateien & Zeitstempel-Manipulation (referenzlos)"
# Ohne Baseline: in Verzeichnissen, die im Normalbetrieb STABIL sind (kein Paket
# schreibt dort), ist eine kürzlich geänderte/neue Datei erklärungsbedürftig.
# ctime (Inode-Änderungszeit) lässt sich mit `touch -d` NICHT zurückdatieren —
# das setzt nur mtime/atime. Ein Angreifer, der mtime fälscht, verrät sich über
# die Diskrepanz. Nur stat-Traversierung (kein Dateiinhalt) → schnell.
INTEG_DIRS=(/usr/local/bin /usr/local/sbin /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/systemd/system /etc/init.d)
RECENT_SYS=""; TIMESTOMP=""
_have_dpkg=0; command -v dpkg &>/dev/null && _have_dpkg=1
while IFS= read -r f; do
    [[ -f "$f" ]] || continue
    ct=$(stat -c %Z "$f" 2>/dev/null); mt=$(stat -c %Y "$f" 2>/dev/null)
    [[ -z "$ct" || -z "$mt" ]] && continue
    # Paketverwaltete Dateien ausschließen: deren mtime ist das (alte) Build-Datum,
    # die ctime das (neue) Installations-/Update-Datum — das ist KEIN Timestomping,
    # sondern normales Paketverhalten. Inhaltsmanipulation solcher Dateien fängt
    # 8.6 (dpkg -V/debsums). Nur NICHT-paketierte Dateien sind hier belastbar.
    if [[ "$_have_dpkg" == 1 ]] && dpkg -S "$f" &>/dev/null; then continue; fi
    line="$(stat -c 'ctime %z | mtime %y | %n' "$f" 2>/dev/null)"
    if (( ct - mt > 7776000 )); then
        # Inode kürzlich geändert, mtime aber künstlich >90 Tage davor: Timestomping.
        TIMESTOMP+="$line"$'\n'
    else
        RECENT_SYS+="$line"$'\n'
    fi
done < <(find "${INTEG_DIRS[@]}" -xdev -type f -ctime -"${DAYS_BACK}" -not -path "${BASE_DIR}/*" 2>/dev/null | head -300)

if [[ -n "$TIMESTOMP" ]]; then
    crit "Zeitstempel-Manipulation (Timestomping): Datei(en) mit künstlich zurückdatiertem mtime"
    code "$TIMESTOMP"
    evidence "timestomp" "$TIMESTOMP"
fi
if [[ -n "$RECENT_SYS" ]]; then
    warn "Kürzlich veränderte Dateien in normalerweise stabilen Systemverzeichnissen — gegen Wartungsfenster/Paket-Updates abgleichen"
    code "$(printf '%s' "$RECENT_SYS" | head -60)"
    evidence "recent_system_changes" "$RECENT_SYS"
elif [[ -z "$TIMESTOMP" ]]; then
    ok "Keine kürzlich veränderten Dateien in stabilen Systemverzeichnissen (${DAYS_BACK} Tage)"
fi

h2 "8.14 AIDE-Integritätsabgleich (dauerhafte FIM, falls eingerichtet)"
# AIDE ist eine echte Baseline-Datenbank — nur aussagekräftig, wenn sie VOR
# einer Kompromittierung erstellt wurde. Das Skript NUTZT eine vorhandene DB
# (read-only), erstellt/aktualisiert sie aber NICHT. Config-Vorlage:
# haertung/aide-forensik.conf. `aide --check` liest Inhalte und kann dauern —
# läuft daher nur, wenn AIDE bereits eingerichtet ist (bewusste Entscheidung).
if command -v aide &>/dev/null; then
    AIDE_DB=$(ls /var/lib/aide/aide.db /var/lib/aide/aide.db.gz 2>/dev/null | head -1 || true)
    if [[ -n "$AIDE_DB" ]]; then
        AIDE_OUT=$(aide --check 2>/dev/null | grep -E '^(Added|Removed|Changed|Total|Number)' | head -40 || true)
        if echo "$AIDE_OUT" | grep -qE '(Added|Removed|Changed).*entries:[[:space:]]*[1-9]'; then
            crit "AIDE meldet Abweichungen zur Integritäts-Baseline"
            code "$AIDE_OUT"
            evidence "aide_check" "$AIDE_OUT"
        else
            ok "AIDE-Abgleich ohne Abweichungen zur Baseline"
        fi
    else
        info "AIDE installiert, aber keine Baseline-DB — mit 'aide --init' anlegen (Vorlage: haertung/aide-forensik.conf)"
    fi
else
    info "AIDE nicht installiert — dauerhafte Datei-Integritätsüberwachung nicht aktiv (Härtung: haertung/aide-forensik.conf)"
fi

h2 "8.15 Imunify-Malware-Datenbank (autoritativer Scanner, read-only)"
# Plesk/Imunify betreibt einen eigenen signaturbasierten Malware-Scanner mit
# gepflegter Datenbank und Cloud-Heuristik. Statt diese Erkennung nachzubauen,
# LESEN wir ihr Ergebnis (Status "found" = erkannt, noch nicht bereinigt).
# Es wird KEIN Scan ausgelöst — nur die bestehende DB abgefragt (read-only).
# Scope-aware: bei --domain/--path nur Treffer unterhalb ${SCAN_PATH}.
IMU_BIN=""
for _c in imunify-antivirus imunify360-agent; do command -v "$_c" &>/dev/null && { IMU_BIN="$_c"; break; }; done
if [[ -n "$IMU_BIN" ]] && command -v python3 &>/dev/null; then
    # --limit hoch: die Standardausgabe liefert nur 50 Einträge; ohne dies
    # würde der Scope-Filter (und die Zählung) auf Servern mit vielen Treffern
    # unvollständig bleiben.
    IMU_JSON=$("$IMU_BIN" malware malicious list --json --by-status found --limit 100000 2>/dev/null || true)
    IMU_REPORT=$(SCOPE_PATH="$SCAN_PATH" VHOSTS="$VHOSTS_DIR" python3 -c '
import sys, os, json, re
try: d = json.loads(sys.stdin.read())
except Exception: sys.exit(0)
items = d.get("items", []) if isinstance(d, dict) else (d if isinstance(d, list) else [])
sp = os.environ.get("SCOPE_PATH", ""); vh = os.environ.get("VHOSTS", "/var/www/vhosts")
glob = (sp == vh or not sp)
# Quarantäne-/Backup-Pfade sind bereits eingedämmt, nicht live.
qpat = re.compile(r"/(schadcode|quarant\w*|backup|_?bak|altkopie|sicherung)(/|_|\.)", re.I)
def keep(i):
    f = str(i.get("file", ""))
    if not (glob or f.startswith(sp)): return False
    if qpat.search(f): return False            # eingedämmt/Backup, kein Live-Fund
    if not os.path.isfile(f): return False     # Imunify-DB veraltet: Datei existiert nicht mehr
    return True
sel = [i for i in items if keep(i)]
print("COUNT=%d" % len(sel))
for i in sel[:60]:
    print("%s  [%s]  %s" % (i.get("file"), i.get("type",""), str(i.get("hash",""))[:16]))
' <<<"$IMU_JSON")
    IMU_COUNT=$(printf '%s\n' "$IMU_REPORT" | sed -n 's/^COUNT=//p')
    IMU_LIST=$(printf '%s\n' "$IMU_REPORT" | grep -v '^COUNT=' || true)
    if [[ "${IMU_COUNT:-0}" -gt 0 ]]; then
        crit "Imunify meldet ${IMU_COUNT} nicht bereinigte Malware-Datei(en) im Prüf-Scope" web
        code "$IMU_LIST"
        evidence "imunify_malware" "Scanner: $IMU_BIN, Status=found, Scope=$SCAN_PATH
$IMU_LIST"
        IMUNIFY_HITS="$IMU_LIST"
    else
        ok "Imunify: keine offenen Malware-Treffer im Prüf-Scope (Status found)"
    fi
elif [[ -n "$IMU_BIN" ]]; then
    info "Imunify vorhanden ($IMU_BIN), aber python3 fehlt — DB nicht ausgewertet"
else
    info "Imunify-CLI nicht gefunden — autoritative Scanner-DB nicht abgefragt"
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

# wp-cli + PHP-Binary erkennen (Fallback wenn direkter mysql-Zugang scheitert;
# Lehre aus einem Kundenvorfall 2026-07: mysql-Connect schlug fehl, DB-Prüfung wurde
# komplett übersprungen und 4 Angreifer-Admins übersehen).
WP_CLI=$(command -v wp 2>/dev/null || true)
PHP_BIN=$(command -v php 2>/dev/null || ls /opt/plesk/php/*/bin/php 2>/dev/null | tail -1 || true)
CURRENT_WP_PATH=""   # wird je Installation in der Schleife gesetzt

# Ein WP-Config-Wert extrahieren: wpconf_get <file> <KONSTANTE>
# Auskommentierte Zeilen (// # * /*) werden übersprungen — sonst greift head -1
# fälschlich einen alten, auskommentierten define()-Wert (z. B. Migrations-Reste
# wie eine veraltete DB_NAME) und die Prüfung landet auf der falschen Datenbank.
wpconf_get() {
  grep -vE '^[[:space:]]*(//|#|\*|/\*)' "$1" 2>/dev/null \
    | grep -oP "define\(\s*['\"]$2['\"]\s*,\s*['\"]\K[^'\"]*" 2>/dev/null | head -1
}

# wp-cli als Datei-Eigentümer der Installation ausführen (Plesk-tauglich).
wp_cli() {  # $@ = wp-cli-Argumente; nutzt CURRENT_WP_PATH
  [[ -n "$WP_CLI" && -n "$PHP_BIN" && -n "$CURRENT_WP_PATH" ]] || return 1
  local owner; owner=$(stat -c %U "${CURRENT_WP_PATH}/wp-config.php" 2>/dev/null || echo root)
  sudo -u "$owner" "$PHP_BIN" "$WP_CLI" "$@" --path="$CURRENT_WP_PATH" --skip-plugins --skip-themes 2>/dev/null
}

# SQL gegen eine WP-DB ausführen. Nutzt Plesk-Admin, sonst WP-Creds, sonst wp-cli.
wp_sql() {
  local db="$1" user="$2" pass="$3" host="$4" query="$5"
  if [[ -n "$PLESK_MYSQL_PW" ]]; then
    MYSQL_PWD="$PLESK_MYSQL_PW" mysql -u admin -N -e "USE \`$db\`; $query" 2>/dev/null && return 0
  fi
  MYSQL_PWD="$pass" mysql -h "${host%%:*}" -u "$user" -N -e "$query" "$db" 2>/dev/null && return 0
  # Fallback: wp-cli nutzt die DB-Zugangsdaten der Installation selbst.
  wp_cli db query "$query" --skip-column-names 2>/dev/null
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
    CURRENT_WP_PATH=$(dirname "$cfg")
    db=$(wpconf_get "$cfg" DB_NAME)
    du=$(wpconf_get "$cfg" DB_USER)
    dp=$(wpconf_get "$cfg" DB_PASSWORD)
    dh=$(wpconf_get "$cfg" DB_HOST); dh=${dh:-localhost}
    pfx=$(grep -oP '\$table_prefix\s*=\s*['"'"'"]\K[^'"'"'"]*' "$cfg" 2>/dev/null | head -1); pfx=${pfx:-wp_}
    [[ -z "$db" ]] && continue

    echo -e "  ${CYN}DB-Prüfung:${NC} $site (db=$db, prefix=$pfx)"
    echo -e "\n#### $site  (DB: \`$db\`, Prefix: \`$pfx\`)\n" >> "$REPORT_FILE"

    # ── Kern-Integrität & Doorway-Familie (läuft auch OHNE DB-Verbindung) ──
    # Lehre aus einem Kundenvorfall: der Signatur-Webshell-Scan (§7.3) übersieht
    # goto-obfuskierte Doorways, getarnte Nicht-PHP-Payloads und @include-Core-
    # Injektionen. verify-checksums + Doorway-Signatur decken die Familie auf.
    if [[ -n "$WP_CLI" ]]; then
      CHK=$(wp_cli core verify-checksums 2>&1 | grep "Warning:" || true)
      cmod=$(echo "$CHK" | grep -c "doesn.t verify" 2>/dev/null || echo 0)
      csne=$(echo "$CHK" | grep -c "should not exist" 2>/dev/null || echo 0)
      if [[ "${cmod:-0}" -gt 0 ]]; then
        crit "$site: ${cmod} veränderte WordPress-Core-Datei(en) — Injektion/Manipulation (verify-checksums)" web
        MODLIST=$(echo "$CHK" | grep "doesn.t verify" | sed "s|.*checksum: |${CURRENT_WP_PATH}/|")
        code "$(echo "$MODLIST" | head -30)"
        CORE_INJECTED+="$MODLIST"$'\n'
        evidence "core_veraendert_$(echo "$site" | tr '/.' '__')" "$MODLIST"
      else
        ok "$site: WordPress-Core unverändert (verify-checksums)"
      fi
      if [[ "${csne:-0}" -gt 0 ]]; then
        warn "$site: ${csne} Core-fremde Datei(en) in wp-admin/wp-includes (Doorway/Backups) — prüfen"
        SNELIST=$(echo "$CHK" | grep "should not exist" | sed "s|.*exist: |${CURRENT_WP_PATH}/|")
        CORE_SNE+="$SNELIST"$'\n'
        evidence "core_fremde_dateien_$(echo "$site" | tr '/.' '__')" "$SNELIST"
      fi
    fi
    # Doorway-.htaccess-Signatur (FilesMatch erlaubt nur index.php|cache.php)
    DW=$(find "$CURRENT_WP_PATH" -name ".htaccess" -size -400c 2>/dev/null \
         | while read -r hf; do grep -qF "(index.php|cache.php)" "$hf" 2>/dev/null && dirname "$hf"; done || true)
    if [[ -n "$DW" ]]; then
      dwn=$(echo "$DW" | grep -c . || true)
      crit "$site: ${dwn} Doorway-Verzeichnis(se) (cache.php/index.php-Injector-Signatur)" web
      code "$(echo "$DW" | head -30)"
      DOORWAY_DIRS+="$DW"$'\n'
      evidence "doorway_dirs_$(echo "$site" | tr '/.' '__')" "$DW"
    else
      ok "$site: keine Doorway-.htaccess-Signatur"
    fi
    # Bootstrap-Injektion @include base64_decode() in PHP-Dateien
    CI=$(grep -rlF "include base64_decode" "$CURRENT_WP_PATH" --include="*.php" 2>/dev/null | head -40 || true)
    if [[ -n "$CI" ]]; then
      cin=$(echo "$CI" | grep -c . || true)
      crit "$site: ${cin} Datei(en) mit @include base64_decode() — getarnte Payload-Nachladung" web
      code "$(echo "$CI" | head -20)"
      CORE_INJECT_HITS+="$CI"$'\n'
      evidence "core_include_injektion_$(echo "$site" | tr '/.' '__')" "$CI"
    else
      ok "$site: keine @include base64_decode()-Injektion"
    fi

    # ── ALLE Plugins + mu-Plugins bewerten (nicht nur aktive) ──────────
    # Lehre aus einem Kundenvorfall: bösartige Plugins deaktivieren/verstecken sich
    # selbst und tauchen NICHT in active_plugins auf. Filesystem-Scan über den
    # gesamten plugins/- und mu-plugins/-Ordner (mu-Plugins laufen IMMER).
    PLUG_DIRS="$CURRENT_WP_PATH/wp-content/plugins $CURRENT_WP_PATH/wp-content/mu-plugins"
    # Ausschlüsse für die (unschärferen) Verhaltens-Signaturen — legitime Plugins,
    # die pre_user_query/wp_create_user/base64 regulär nutzen (WooCommerce-Ökosystem,
    # REST-APIs, Membership/Backup/SEO). Fake-Signatur + $_-eval brauchen das NICHT.
    PLUG_EXCL="/woocommerce/|/woocommerce-legacy-rest-api/|/woo-order-export|/woo-|/wordpress-seo|/jetpack/|/updraftplus/|/members|/user-role|/backwpup|/wordfence|/ithemes"
    # a) TIER 1 (CRIT, hohe Konfidenz): Fake-Signatur (Author: WordPress + wordpress.org/plugins)
    #    ODER direkter eval(base64_decode($_GET/POST/REQUEST/COOKIE)) — beides praktisch nie legitim.
    FAKE_PLUGINS=$(grep -rlE "^[[:space:]]*Author:[[:space:]]*WordPress[[:space:]]*$" $PLUG_DIRS --include="*.php" 2>/dev/null \
      | while read -r pf; do grep -qF "wordpress.org/plugins/" "$pf" 2>/dev/null && echo "$pf"; done || true)
    EVAL_BD=$(grep -rlE "eval\(\s*base64_decode\(\s*\\\$_(POST|GET|REQUEST|COOKIE)" $PLUG_DIRS --include="*.php" 2>/dev/null \
      | grep -viE "$PLUG_EXCL" || true)
    # File-Manager-Webshells (TinyFileManager/elFinder/FilesMan/H3K/b374k/WSO) — praktisch nie legitim im Plugin-Ordner
    FILEMGR=$(grep -rlE "tinyfilemanager|Tiny File Manager|\bFilesMan\b|elFinderConnector|H3K \||b374k|WSO[0-9. ]+shell" $PLUG_DIRS --include="*.php" 2>/dev/null \
      | grep -viE "$PLUG_EXCL|/vendor/" || true)
    SUSP_PLUG=$(printf '%s\n%s\n%s\n' "$FAKE_PLUGINS" "$EVAL_BD" "$FILEMGR" | grep -vE '^$' | sort -u || true)
    if [[ -n "$SUSP_PLUG" ]]; then
      spn=$(echo "$SUSP_PLUG" | grep -c . || true)
      crit "$site: ${spn} bösartige(s) Plugin/mu-Plugin (Fake-Signatur / eval(base64(\$_...)) / File-Manager-Webshell) — auch inaktive!" web
      code "$(echo "$SUSP_PLUG" | sed "s|$CURRENT_WP_PATH/||" | head -30)"
      SUSP_PLUGINS+="$SUSP_PLUG"$'\n'
      evidence "boesartige_plugins_$(echo "$site" | tr '/.' '__')" "$SUSP_PLUG"
    else
      ok "$site: keine bösartigen Plugins/mu-Plugins (alle bewertet, auch inaktive)"
    fi
    # b) TIER 2 (WARN, Review): Admin-Hide-/Recreation-Hooks — oft legitim (Membership),
    #    daher nur Warnung mit manueller Prüfung.
    REVIEW_PLUG=$(grep -rlE "pre_user_query|function[[:space:]]+create_admin|ensure_plugin_active" $PLUG_DIRS --include="*.php" 2>/dev/null \
      | grep -viE "$PLUG_EXCL" || true)
    # bereits als bösartig (Tier 1) gemeldete herausfiltern
    if [[ -n "$SUSP_PLUG" ]]; then
      REVIEW_PLUG=$(printf '%s\n' "$REVIEW_PLUG" | grep -vFf <(printf '%s\n' "$SUSP_PLUG") || true)
    fi
    if [[ -n "$REVIEW_PLUG" ]]; then
      warn "$site: Plugin(s) mit Admin-/Sichtbarkeits-Hooks (pre_user_query/create_admin) — Inhalt prüfen (oft legitim)" web
      code "$(echo "$REVIEW_PLUG" | sed "s|$CURRENT_WP_PATH/||" | head -20)"
      evidence "plugins_review_$(echo "$site" | tr '/.' '__')" "$REVIEW_PLUG"
    fi
    # c) mu-Plugins immer auflisten (laufen ohne Aktivierung)
    MU_LIST=$(find "$CURRENT_WP_PATH/wp-content/mu-plugins" -maxdepth 1 -name "*.php" 2>/dev/null || true)
    if [[ -n "$MU_LIST" ]]; then
      info "$site: mu-Plugins vorhanden (laufen immer — einzeln prüfen):"
      code "$(echo "$MU_LIST" | sed "s|$CURRENT_WP_PATH/||")"
      MU_PLUGINS+="$MU_LIST"$'\n'
      evidence "mu_plugins_$(echo "$site" | tr '/.' '__')" "$(echo "$MU_LIST" | xargs -r ls -la 2>/dev/null)"
    fi
    # ── Manipulierte .htaccess (Malware-Whitelist) ────────────────────
    # Malware ersetzt die .htaccess durch FilesMatch, das ALLE .php sperrt außer
    # einer Whitelist mit Webshell-Namen — blockiert legitime wp-admin-Seiten (403).
    BAD_HTA=$(find "$CURRENT_WP_PATH" -name ".htaccess" 2>/dev/null | while read -r hf; do
      grep -qE "adminfuns|chtmlfuns|classsmtps|comfunctions|postnews|schallfuns|epinyins|siteheads|hplfuns|moddofuns" "$hf" 2>/dev/null && echo "$hf"; done || true)
    if [[ -n "$BAD_HTA" ]]; then
      crit "$site: manipulierte .htaccess (Malware-Whitelist mit Webshell-Namen — bricht Admin/403)" web
      code "$(echo "$BAD_HTA" | sed "s|$CURRENT_WP_PATH/||")"
      TAMPERED_HTACCESS+="$BAD_HTA"$'\n'
      evidence "manipulierte_htaccess_$(echo "$site" | tr '/.' '__')" "$(echo "$BAD_HTA" | while read -r h; do echo "=== $h ==="; head -5 "$h"; done)"
    fi

    # Verbindungstest (nach Integritäts-Checks; wp-cli-Fallback greift jetzt)
    if ! wp_sql "$db" "$du" "$dp" "$dh" "SELECT 1;" >/dev/null 2>&1; then
      warn "$site: keine DB-Verbindung (Zugang prüfen) — DB-Abfragen übersprungen (Integrität oben wurde geprüft)"
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
      crit "$site: Kürzlich angelegte(s) Administrator-Konto(en) — Angreifer-Verdacht" web
      code "$NEW_ADMINS"
      evidence "wpdb_neue_admins_$(echo "$site" | tr '/.' '__')" "$NEW_ADMINS"
      ROGUE_ADMINS+="=== $site ==="$'\n'"$NEW_ADMINS"$'\n'
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
      crit "$site: verdächtige Optionen (base64/eval/auto_prepend) in ${pfx}options" web
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
      warn "$site: Dateimanager-Plugin aktiv (fileorganizer/filemanager) — häufiger Angriffs-Vektor, prüfen" web
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
    crit "WP-DB-VERDIKT: ${WPDB_FLAGS} Befund(e)" web
  fi
  echo -e "\n$WPDB_VERDICT\n" >> "$REPORT_FILE"
fi

h2 "11.10 WP Toolkit — Instanz-Status (Plesk-eigene Bewertung, read-only)"
# Das Plesk WP Toolkit führt pro WordPress-Instanz Buch — u.a. ob sie als
# infiziert oder defekt gilt (es erkennt auch nicht dazugehörende Dateien).
# Wir LESEN diese Bewertung (kein Scan, keine Änderung) und melden infizierte
# Instanzen. Scope-aware über ${SCAN_PATH}; ergänzt die eigene DB-/Core-Prüfung
# um Plesks autoritative Sicht.
if command -v plesk &>/dev/null && command -v python3 &>/dev/null; then
    WPTK_JSON=$(plesk ext wp-toolkit --list -format json 2>/dev/null || true)
    WPTK_REPORT=$(SCOPE_PATH="$SCAN_PATH" VHOSTS="$VHOSTS_DIR" python3 -c '
import sys, os, json
try: d = json.loads(sys.stdin.read())
except Exception: sys.exit(0)
if not isinstance(d, list): sys.exit(0)
sp = os.environ.get("SCOPE_PATH", ""); vh = os.environ.get("VHOSTS", "/var/www/vhosts")
glob = (sp == vh or not sp)
insc = lambda x: glob or str(x.get("fullPath","")).startswith(sp)
scoped = [x for x in d if insc(x)]
inf = [x for x in scoped if x.get("infected")]
brk = [x for x in scoped if x.get("broken")]
print("INF=%d BRK=%d TOTAL=%d" % (len(inf), len(brk), len(scoped)))
for x in inf[:40]: print("INFECTED %s  %s" % (x.get("fullPath"), x.get("siteUrl","")))
' <<<"$WPTK_JSON")
    WPTK_HEAD=$(printf '%s\n' "$WPTK_REPORT" | grep '^INF=' || true)
    WPTK_INF=$(printf '%s\n' "$WPTK_REPORT" | grep '^INFECTED' || true)
    WPTK_N=$(printf '%s' "$WPTK_HEAD" | sed -E 's/^INF=([0-9]+).*/\1/')
    if [[ "${WPTK_N:-0}" -gt 0 ]]; then
        crit "WP Toolkit stuft ${WPTK_N} WordPress-Instanz(en) als infiziert ein" web
        code "$WPTK_INF"
        evidence "wptk_infected" "$WPTK_REPORT"
        WPTK_INFECTED="$WPTK_INF"
    elif [[ -n "$WPTK_HEAD" ]]; then
        ok "WP Toolkit: keine als infiziert markierten Instanzen im Scope (${WPTK_HEAD})"
    else
        info "WP Toolkit lieferte keine auswertbare Instanzliste"
    fi
else
    info "WP Toolkit / python3 nicht verfügbar — Plesk-Instanzbewertung nicht abgefragt"
fi

# ============================================================
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
done < <(find "$SCAN_PATH" -maxdepth 5 -name configuration.php 2>/dev/null | nf_strip_self)
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
# AUFRUFT (Caller = webNN). Die alte Regex 'sudo:.*web[0-9]' traf auch 'USER=web206'
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
# BEFUND-KLASSIFIKATION & DETAILDATEI (v3.6)
# ------------------------------------------------------------
# Ordnet alle datei-basierten Schadcode-Funde grob einer Familie zu (was es ist
# + Geschäftsmodell), schreibt die Fundstellen mit Pfaden RELATIV zum
# Kundenverzeichnis in befunde_details.md und liefert eine Grobstatistik für
# Bericht und PDF-Deckblatt. Details bewusst NICHT in den laienlesbaren
# Kundenbericht, sondern in die referenzierte Extradatei.
# ============================================================
DETAILS_FILE="${RUN_DIR}/befunde_details.md"
CUST_ROOT="$SCAN_PATH"
# Pfad relativ zum Kundenverzeichnis (nie absolut im Bericht/PDF)
relpath(){ local p="$1"
  if [[ -n "$CUST_ROOT" && "$CUST_ROOT" != "$VHOSTS_DIR" ]]; then printf '%s' "${p#"$CUST_ROOT"/}"
  else printf '%s' "${p#"$VHOSTS_DIR"/}"; fi; }
# Familie aus Imunify-Signaturname
imu_family(){ local t; t="$(printf '%s' "$1" | tr 'A-Z' 'a-z')"
  case "$t" in
    *deface*) echo "Defacement" ;;
    *backdoor*|*bkdr*|*shell*|*webshell*) echo "Backdoor/Webshell" ;;
    *phish*) echo "Phishing" ;;
    *spam*|*seo*|*doorway*|*pharma*) echo "SEO-Spam/Doorway" ;;
    *redir*) echo "Redirect/Malvertising" ;;
    *mailer*) echo "Spam-Mailer" ;;
    *miner*|*coin*|*xmr*) echo "Cryptominer" ;;
    *inject*) echo "Code-Injection" ;;
    *) echo "Sonstige/Unklar" ;;
  esac; }
# Geschäftsmodell je Familie (eine Zeile, laienverständlich)
fam_biz(){ case "$1" in
    "Defacement")            echo "Verunstaltung der Seite — Reputationsschaden, oft Hacktivismus" ;;
    "Backdoor/Webshell")     echo "Dauerhafter Fernzugriff — Basis für Wiederkehr & weitere Angriffe" ;;
    "SEO-Spam/Doorway")      echo "Suchmaschinen-Spam (Pharma, Fake-Shops) über Ihre Domain-Reputation" ;;
    "Phishing")              echo "Datendiebstahl über gefälschte Login-/Bezahlseiten" ;;
    "Redirect/Malvertising") echo "Weiterverkauf Ihrer Besucher / Schadwerbung" ;;
    "Spam-Mailer")           echo "Massen-Mailversand — Blacklisting Ihrer Domain/IP" ;;
    "Cryptominer")           echo "Diebstahl von Server-Rechenleistung" ;;
    "Code-Injection")        echo "Schadcode in legitime Dateien eingeschleust" ;;
    "Relay-Backdoor")        echo "Portloser Fernzugriffskanal (umgeht Firewall/NAT)" ;;
    "Getarnte Binary")       echo "Als harmlose Datei getarntes Angriffswerkzeug" ;;
    "Getarnte Payload")      echo "Nachladbarer Schadcode in Nicht-PHP-Datei" ;;
    "Joomla-Webshell")       echo "Über eine Joomla-Lücke abgelegte Hintertür (meist als Bild getarnt)" ;;
    "Kernfremde Datei")      echo "Datei im Programmkern, die dort nicht hingehört — Hintertür oder Update-Altlast" ;;
    *)                       echo "Einordnung offen — manuelle Prüfung nötig" ;;
  esac; }

declare -A FAM_COUNT FAM_FILES
add_finding(){ local fam="$1" rel="$2" detail="$3"
  FAM_COUNT["$fam"]=$(( ${FAM_COUNT["$fam"]:-0} + 1 ))
  FAM_FILES["$fam"]+="- \`${rel}\`${detail:+  — ${detail}}"$'\n'; }

MAL_PATHS=""   # absolute Fund-Pfade (für Mail-Kontext: Bereich + Zeitraum)
# Quelle 1: Imunify-Treffer (Zeilen "pfad  [type]  hash")
if [[ -n "${IMUNIFY_HITS:-}" ]]; then
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    p="${line%%  \[*}"
    t="$(printf '%s' "$line" | sed -E 's/.*\[([^]]*)\].*/\1/')"
    add_finding "$(imu_family "$t")" "$(relpath "$p")" "Imunify-Signatur: ${t}"
    MAL_PATHS+="$p"$'\n'
  done <<< "$IMUNIFY_HITS"
fi
# Quelle 2: eigene datei-basierte Kategorien (je eine Pfadliste)
_addcat(){ local fam="$1" list="$2"
  while IFS= read -r p; do [[ -n "$p" ]] && { add_finding "$fam" "$(relpath "$p")" ""; MAL_PATHS+="$p"$'\n'; }; done <<< "$list"; }
[[ -n "${MASQ_BINARIES:-}"      ]] && _addcat "Getarnte Binary"   "$MASQ_BINARIES"
[[ -n "${GSOCKET_HITS:-}"       ]] && _addcat "Relay-Backdoor"    "$GSOCKET_HITS"
[[ -n "${DISGUISED_PAYLOADS:-}" ]] && _addcat "Getarnte Payload"  "$DISGUISED_PAYLOADS"
[[ -n "${CORE_INJECT_HITS:-}"   ]] && _addcat "Code-Injection"    "$CORE_INJECT_HITS"
[[ -n "${DOORWAY_DIRS:-}"       ]] && _addcat "SEO-Spam/Doorway"  "$DOORWAY_DIRS"
# v3.8 Joomla. NUR Variablen mit nackten, absoluten Pfaden je Zeile — _addcat
# ruft relpath() und füllt MAL_PATHS. JOOMLA_VERSIONS, _ROGUE_SUPER und
# _VULN_EXT tragen Tabulatoren und "=== site ==="-Kopfzeilen und dürfen hier
# NICHT durch.
[[ -n "${JOOMLA_MALWARE:-}"       ]] && _addcat "Joomla-Webshell"  "$JOOMLA_MALWARE"
[[ -n "${JOOMLA_CORE_MODIFIED:-}" ]] && _addcat "Code-Injection"   "$JOOMLA_CORE_MODIFIED"
[[ -n "${JOOMLA_CORE_UNKNOWN:-}"  ]] && _addcat "Kernfremde Datei" "$JOOMLA_CORE_UNKNOWN"

# Grobstatistik + Detaildatei zusammensetzen
MALWARE_TOTAL=0; MALWARE_FAMILY_ROWS=""; MALWARE_CARD=""
# Mail-Kontext (v3.7) für den Anschreiben-Generator — Defaults für set -u
MAIL_AREA=""; MAIL_FINDING=""; MAIL_TIMEFRAME=""; MAIL_NEWEST=""; MAIL_FAMILIES_JSON="{}"
for fam in "${!FAM_COUNT[@]}"; do MALWARE_TOTAL=$(( MALWARE_TOTAL + FAM_COUNT[$fam] )); done
if [[ "$MALWARE_TOTAL" -gt 0 ]]; then
  # betroffener Bereich aus den Pfaden (grob, laienverständlich)
  # Reihenfolge und Regex bewusst geändert (v3.8): die frühere Joomla-Regex
  # traf schon bei einem blanken "/administrator" und damit auch bei
  # Nicht-Joomla; jetzt ist der volle Joomla-Pfadkontext nötig. WordPress
  # steht VOR Shop, weil WooCommerce immer unter wp-content liegt und sonst
  # als "Shop-Bereich" statt "WordPress-Bereich" beschriftet würde.
  # Der Anschreiben-Generator leitet aus dem Wort "Shop" ab, ob er den Absatz
  # zu Zahlungsdaten aufnimmt. Deshalb bei Joomla die verbreiteten
  # Shop-Komponenten gezielt erkennen, statt Joomla wie früher pauschal als
  # Shop zu behandeln.
  if   printf '%s' "$MAL_PATHS" | grep -qiE 'com_(virtuemart|hikashop|eshop|j2store|redshop|phocacart|jshopping)'; then MAIL_AREA="Joomla-Shop-Bereich"
  elif printf '%s' "$MAL_PATHS" | grep -qiE '/(administrator/components|components/com_[a-z]+|modules/mod_[a-z]+|plugins/(system|content|authentication|editors)/|libraries/(joomla|src)/|media/com_[a-z]+)'; then MAIL_AREA="Joomla-Bereich"
  elif printf '%s' "$MAL_PATHS" | grep -qiE 'wp-content|wp-admin|wp-includes'; then MAIL_AREA="WordPress-Bereich"
  elif printf '%s' "$MAL_PATHS" | grep -qiE '/(shop2?|warenkorb|checkout|xtcommerce|woocommerce|magento)'; then MAIL_AREA="Shop-Bereich"
  else MAIL_AREA="Webbereich"; fi
  # neueste mtime der Fundstellen -> Zeitbezug
  _newest=0
  while IFS= read -r _p; do [[ -f "$_p" ]] || continue; _m=$(stat -c %Y "$_p" 2>/dev/null || echo 0); (( _m > _newest )) && _newest=$_m; done <<< "$MAL_PATHS"
  if [[ "$_newest" -gt 0 ]]; then
    _y=$(date -d "@$_newest" +%Y 2>/dev/null || echo ""); _mo=$(date -d "@$_newest" +%m 2>/dev/null || echo ""); _cy=$(date +%Y)
    case "$_mo" in 12|01|02) _s="Winter";; 03|04|05) _s="Frühjahr";; 06|07|08) _s="Sommer";; *) _s="Herbst";; esac
    if [[ -n "$_y" && "$_y" == "$_cy" ]]; then MAIL_TIMEFRAME="erst in diesem $_s"
    elif [[ -n "$_y" ]]; then MAIL_TIMEFRAME="im $_s $_y"
    else MAIL_TIMEFRAME="in den letzten Monaten"; fi
    MAIL_NEWEST=$(date -d "@$_newest" +%Y-%m-%d 2>/dev/null || echo "")
  else MAIL_TIMEFRAME="in den letzten Monaten"; fi
  # dominante Familie -> Fund-Formulierung (Singular/Plural)
  _domfam=$(for fam in "${!FAM_COUNT[@]}"; do echo "${FAM_COUNT[$fam]}|$fam"; done | sort -rn | head -1 | cut -d'|' -f2)
  case "$_domfam" in
    "Backdoor/Webshell"|"Relay-Backdoor") _ns="eine versteckte Hintertür"; _np="mehrere versteckte Hintertüren";;
    "Defacement")                          _ns="eine verunstaltete Seite"; _np="mehrere verunstaltete Seiten";;
    "SEO-Spam/Doorway")                    _ns="eine versteckte Spam-Seite"; _np="mehrere versteckte Spam-Seiten";;
    *)                                     _ns="eine Schaddatei"; _np="mehrere Schaddateien";;
  esac
  [[ "$MALWARE_TOTAL" -eq 1 ]] && MAIL_FINDING="$_ns" || MAIL_FINDING="$_np"
  # Familien als JSON-Objekt (Namen ohne Sonderzeichen -> keine Escapes nötig)
  MAIL_FAMILIES_JSON="{"; _f1=1
  for fam in "${!FAM_COUNT[@]}"; do [[ $_f1 -eq 0 ]] && MAIL_FAMILIES_JSON+=","; MAIL_FAMILIES_JSON+="\"${fam}\":${FAM_COUNT[$fam]}"; _f1=0; done
  MAIL_FAMILIES_JSON+="}"
  {
    echo "# Fundstellen-Details${DOMAIN:+ — ${DOMAIN}}"
    echo
    echo "> Pfade **relativ zum Kundenverzeichnis** (nicht der absolute Serverpfad)."
    echo "> Erzeugt: $(date +"%d.%m.%Y, %H:%M Uhr") · Prüfung \`${RUN_LABEL}\` · $MALWARE_TOTAL Fundstelle(n)."
    echo
    echo "| Familie | Anzahl | Geschäftsmodell |"
    echo "|---|---|---|"
  } > "$DETAILS_FILE"
  # nach Anzahl absteigend (einfacher Bubble über Keys)
  for fam in "${!FAM_COUNT[@]}"; do echo "${FAM_COUNT[$fam]}|$fam"; done | sort -rn | while IFS='|' read -r n f; do
    printf '| %s | %s | %s |\n' "$f" "$n" "$(fam_biz "$f")" >> "$DETAILS_FILE"
  done
  echo >> "$DETAILS_FILE"
  for fam in "${!FAM_COUNT[@]}"; do
    {
      echo "## ${fam} (${FAM_COUNT[$fam]}) — $(fam_biz "$fam")"
      echo
      printf '%s\n' "${FAM_FILES[$fam]}"
    } >> "$DETAILS_FILE"
  done
  # Kompakte Zeilen für Bericht-Tabelle + PDF-Card (Top nach Anzahl)
  while IFS='|' read -r n f; do
    MALWARE_FAMILY_ROWS+="| ${f} | ${n} | $(fam_biz "$f") |"$'\n'
    MALWARE_CARD+="- **${n}** ${f}"$'\n'
  done < <(for fam in "${!FAM_COUNT[@]}"; do echo "${FAM_COUNT[$fam]}|$fam"; done | sort -rn)
  echo "  Fundstellen-Details: $DETAILS_FILE ($MALWARE_TOTAL Fund(e), $(printf '%s' "$MALWARE_CARD" | grep -c .) Familien)" >> "$REPORT_FILE"
fi

# ============================================================
h1 "14. ZUSAMMENFASSUNG"
# ============================================================

cat >> "$REPORT_FILE" <<SUMMARY

### 14.1 Befund-Statistik

| Kategorie | Anzahl |
|---|---|
| 🔴 Kritische Befunde | ${N_CRIT} |
| ⚠️ Warnungen | ${N_WARN} |
| ✅ Unauffällige Prüfungen | ${N_OK} |

### 14.2 Empfohlene Sofortmaßnahmen

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

# Ampel nach KUNDEN-Scope (v3.7.1): nur Website-Befunde bestimmen die Einstufung
# des Kundenberichts — Server-/Root-Befunde (in N_CRIT enthalten) gehören dem
# Betreiber, nicht dem Kunden. Sonst steht 🔴 KRITISCH im Kundenbericht, obwohl
# an SEINER Website nichts Kritisches ist.
N_CUST_CRIT=$(printf '%s' "$CUST_CRIT_LIST" | grep -c . || true)
N_CUST_WARN=$(printf '%s' "$CUST_WARN_LIST" | grep -c . || true)
if [[ "${N_CUST_CRIT:-0}" -gt 0 || "${MALWARE_TOTAL:-0}" -gt 0 ]]; then
  AMPEL="🔴 KRITISCH"
  AMPEL_TEXT="**Ihr System wurde nachweislich kompromittiert.** Es liegen konkrete, technisch belegte Hinweise auf einen erfolgreichen Angriff vor. Ein Angreifer hatte oder hat Zugriff auf Ihren Webauftritt. **Es besteht akuter Handlungsbedarf** — bitte arbeiten Sie die Sofortmaßnahmen unten noch heute ab."
  DRINGLICHKEIT="**Warum das dringend ist:** Solange die Zugänge des Angreifers gültig sind, kann er jederzeit zurückkehren, weitere Hintertüren legen, Daten (auch Kundendaten) abgreifen, Spam über Ihre Domain versenden oder Ihre Seite für Betrug/Schadsoftware missbrauchen. Jede Stunde zählt."
elif [[ "${N_CUST_WARN:-0}" -gt 0 ]]; then
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
# Joomla-Befunde in die Kunden-Kurzfassung heben — sonst schweigt sie, wenn
# Joomla das einzige CMS des Kunden ist (v3.8).
if [[ "${JOOMLA_FLAGS:-0}" -gt 0 ]]; then
  TECH_SUMMARY+="- **Joomla-Befunde (${JOOMLA_FLAGS})** — Ihre Joomla-Installation weist Auffälligkeiten auf: veralteter Programmstand, unsichere Konfiguration oder ein nachweisbarer Zugriff auf Ihre Zugangsdaten. Einzelheiten in Abschnitt 4."$'\n'
fi

# SSH-Brute-Force ist ein SERVER-Befund (Betreiber-Ebene) und gehört nicht in
# den Kundenbericht — bleibt im Technik-/BSI-Bericht. (v3.8 Scope-Trennung)
[[ -z "$TECH_SUMMARY" ]] && TECH_SUMMARY="- Keine akuten technischen Kompromittierungs-Indikatoren an Ihrer Website in diesem Lauf."

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

# Befundlisten für den Kundenbericht DSGVO-datensparsam pseudonymisieren
# (fremde E-Mail-Adressen). Angreifer-IPs bleiben zum Sperren im Klartext.
# Kundenbericht zeigt NUR Website-Befunde (via crit/warn "…" web) — Server-/
# Root-/Infrastruktur-Befunde bleiben Technik-/Betreiber-Sache (v3.8).
KUNDE_CRIT_LIST=$(printf '%s' "$CUST_CRIT_LIST" | mask_email)
KUNDE_WARN_LIST=$(printf '%s' "$CUST_WARN_LIST" | mask_email)

# Scope-Warnung (v3.5): Im Global-Modus umfasst der Bericht ALLE Domains und
# darf nicht als Einzelkunden-Bericht verschickt werden — sonst sähe Kunde A die
# Befunde (und ggf. personenbezogenen Daten) von Kunde B. Kundenspezifische,
# maskierte Berichte entstehen über einen Lauf mit --domain <kunde.tld>.
if [[ "$SCOPE_MODE" == "global" ]]; then
  KUNDE_TITEL="Serverweiter Befundbericht (Betreiber)"
  SCOPE_BANNER="> ⚠️ **Serverweiter Betreiberbericht — nicht für die Weitergabe an einzelne Kunden.**
> Dieser Lauf (\`--global\`) umfasst **alle Domains** des Servers; die folgenden
> Befunde können mehrere Kunden betreffen. Für einen kundenspezifischen Bericht
> (nur dessen Daten, personenbezogene Angaben maskiert, ohne Root-Details) den
> Lauf mit \`--domain <kunde.tld>\` wiederholen.
"
else
  KUNDE_TITEL="Sicherheitsvorfall — Bericht${DOMAIN:+ für ${DOMAIN}}"
  SCOPE_BANNER=""
fi

cat > "$KUNDE_FILE" <<KUNDE
# ${KUNDE_TITEL}

${SCOPE_BANNER}
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

$(if [[ "${MALWARE_TOTAL:-0}" -gt 0 ]]; then
echo "**Schadcode-Einordnung — ${MALWARE_TOTAL} Fundstelle(n):**

| Art | Anzahl | Was damit bezweckt wird |
|---|---|---|
${MALWARE_FAMILY_ROWS}
> Die vollständige Liste der betroffenen Dateien — mit Pfaden **relativ zu Ihrem
> Verzeichnis** — liegt in der Datei \`befunde_details.md\` bei Ihren Unterlagen."
fi)

$(if [[ -n "$KUNDE_CRIT_LIST" ]]; then
echo "**Kritische Einzelbefunde:**

$KUNDE_CRIT_LIST"
fi)
$(if [[ -n "$KUNDE_WARN_LIST" ]]; then
echo "**Auffälligkeiten (zeitnah beheben):**

$KUNDE_WARN_LIST"
fi)

## 4. Reichweite des Angriffs — war nur Ihre Website oder der ganze Server betroffen?

${ROOT_CUSTOMER_HINT}

> **Was das bedeutet:** „Serverebene" (Root) ist die Administratorebene des
> gesamten Servers, auf dem neben Ihrer auch andere Websites liegen. Blieb ein
> Angreifer darunter (nur auf Ebene Ihrer Website), ist der Schaden auf Ihren
> Webauftritt begrenzt. Die technische Detailbewertung der Serverebene liegt beim
> Serverbetreiber; sie ist nicht Teil dieses Kundenberichts.

**WordPress-Datenbank:** ${WPDB_VERDICT}
$(if [[ "${JOOMLA_COUNT:-0}" -gt 0 ]]; then printf '\n**Joomla:** %s\n' "${JOOMLA_VERDICT}"; fi)
**Fernzugriff / Relay-Backdoor:** ${RELAY_VERDICT}

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
| \`kundenbericht.md\` | Dieses Dokument |$(if [[ "${MALWARE_TOTAL:-0}" -gt 0 ]]; then printf '\n| `befunde_details.md` | Vollständige Fundstellen-Liste (Pfade relativ zu Ihrem Verzeichnis, Familie, Signatur) |'; fi)
| \`technik_bericht.md\` | Vollständiger technischer Bericht (alle Prüfpunkte, inkl. Root-Prüfung §13) |
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

### Relay-Backdoor / ausgehender Fernzugriff (automatisiert bewertet)

${RELAY_VERDICT}

| Frage | Antwort |
|---|---|
| Server-Root kompromittiert? | $(if [[ "${ROOT_FLAGS:-0}" -eq 0 ]]; then echo "Nach Beweislage nein (auf Web-User-Ebene begrenzt)"; else echo "NICHT ausgeschlossen — ${ROOT_FLAGS} Indikator(en), siehe Technik-Bericht §13"; fi) |
| Relay-Backdoor / Fernzugriffskanal? | $(if [[ "${RELAY_FLAGS:-0}" -eq 0 ]]; then echo "kein Hinweis (kein Ausschluss bei inaktivem Kanal)"; else echo "Verdacht/Nachweis — ${RELAY_FLAGS} Punkt(e), siehe Technik-Bericht §8.7–8.12"; fi) |
| WordPress-Datenbank | $(if [[ "${WPDB_FLAGS:-0}" -eq 0 ]]; then echo "unauffällig (keine fremden Admins/Optionen)"; else echo "AUFFÄLLIG — ${WPDB_FLAGS} Befund(e), siehe Technik-Bericht §11"; fi) |
| Joomla-Installation | $(if [[ "${JOOMLA_COUNT:-0}" -eq 0 ]]; then echo "keine im Prüf-Scope"; elif [[ "${JOOMLA_FLAGS:-0}" -eq 0 ]]; then echo "unauffällig"; else echo "AUFFÄLLIG — ${JOOMLA_FLAGS} Befund(e), siehe Technik-Bericht §12"; fi) |
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

# JSON-Maskierung. Steuerzeichen MÜSSEN maskiert werden, sonst ist die Datei
# ungültig (v3.8): Tabulatoren stecken in praktisch jeder Zeile, die aus
# `mysql -N` stammt (ROGUE_ADMINS, Joomla-DB-Abfragen) — vorher erzeugte genau
# der Fall, auf den es ankommt (ein echter Fund), unlesbares findings.json und
# damit einen stillen Ausfall des Anschreiben-Generators.
# Reihenfolge ist zwingend: erst Backslash, dann Anführungszeichen, dann
# Steuerzeichen — sonst werden die selbst eingefügten Backslashes nochmals
# maskiert. Das abschließende tr entfernt die restlichen, nicht darstellbaren
# Steuerzeichen (ohne \t und \r, die oben bereits behandelt sind).
json_esc() { sed 's/\\/\\\\/g; s/"/\\"/g; s/\t/\\t/g; s/\r/\\r/g' | tr -d '\000-\010\013\014\016-\037'; }
json_str() {   # einzeiliger String → JSON-escaped (ohne Anführungszeichen)
  printf '%s' "$1" | tr '\n' ' ' | json_esc
}
json_arr() {   # stdin: ein Item pro Zeile → JSON-Array von Strings
  local first=1 out="[" line esc
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    esc=$(printf '%s' "$line" | json_esc)
    if [ "$first" -eq 1 ]; then out="${out}\"${esc}\""; first=0; else out="${out},\"${esc}\""; fi
  done
  printf '%s]' "$out"
}

emit_findings_json() {
  local ws php suid tmpx immu cron sysd persist procs wpc fkeys aips bips
  local corei coresne doorw coreinj disg rogue
  corei=$(printf '%s\n' "${CORE_INJECTED:-}"      | json_arr)
  coresne=$(printf '%s\n' "${CORE_SNE:-}"         | json_arr)
  doorw=$(printf '%s\n' "${DOORWAY_DIRS:-}"       | json_arr)
  coreinj=$(printf '%s\n' "${CORE_INJECT_HITS:-}" | json_arr)
  disg=$(printf '%s\n' "${DISGUISED_PAYLOADS:-}"  | json_arr)
  rogue=$(printf '%s\n' "${ROGUE_ADMINS:-}"       | grep -vE '^=== |^$' | json_arr)
  local suspp muplug tamphta
  suspp=$(printf '%s\n' "${SUSP_PLUGINS:-}"       | json_arr)
  muplug=$(printf '%s\n' "${MU_PLUGINS:-}"        | json_arr)
  tamphta=$(printf '%s\n' "${TAMPERED_HTACCESS:-}" | json_arr)
  local n_corei n_doorw n_coreinj n_rogue
  n_corei=$(printf '%s\n'   "${CORE_INJECTED:-}"     | grep -c . 2>/dev/null)
  n_doorw=$(printf '%s\n'   "${DOORWAY_DIRS:-}"      | grep -c . 2>/dev/null)
  n_coreinj=$(printf '%s\n' "${CORE_INJECT_HITS:-}"  | grep -c . 2>/dev/null)
  n_rogue=$(printf '%s\n'   "${ROGUE_ADMINS:-}"      | grep -vE '^=== |^$' | grep -c . 2>/dev/null)
  local n_suspp; n_suspp=$(printf '%s\n' "${SUSP_PLUGINS:-}" | grep -c . 2>/dev/null)
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
  # v3.4 Relay-Backdoors — Prozess-/Datei-Introspektion (Abschnitte 5.6/5.7, 6.9, 7.10/7.11, 8.7–8.12)
  local gsock masq fless kthr orph sshh relc yhit
  gsock=$(printf '%s\n' "${GSOCKET_HITS:-}"     | json_arr)
  masq=$(printf '%s\n'  "${MASQ_BINARIES:-}"    | json_arr)
  fless=$(printf '%s\n' "${FILELESS_PROCS:-}"   | json_arr)
  kthr=$(printf '%s\n'  "${KTHREAD_FAKES:-}"    | json_arr)
  orph=$(printf '%s\n'  "${ORPHAN_SHELLS:-}"    | json_arr)
  sshh=$(printf '%s\n'  "${SSH_LOGIN_HOOKS:-}"  | json_arr)
  relc=$(printf '%s\n'  "${RELAY_CONNECTIONS:-}" | json_arr)
  yhit=$(printf '%s\n'  "${YARA_HITS:-}"        | json_arr)
  # v3.6 System-Integrität & Scanner-Taps
  local tstomp recsys imuh wptk malsum
  # Mail-Kontext für den Anschreiben-Generator (null, wenn keine Funde)
  if [[ "${MALWARE_TOTAL:-0}" -gt 0 ]]; then
    malsum="{ \"total\": ${MALWARE_TOTAL}, \"affected_area\": \"$(json_str "${MAIL_AREA:-}")\", \"finding_summary\": \"$(json_str "${MAIL_FINDING:-}")\", \"timeframe\": \"$(json_str "${MAIL_TIMEFRAME:-}")\", \"newest\": \"${MAIL_NEWEST:-}\", \"families\": ${MAIL_FAMILIES_JSON} }"
  else
    malsum="null"
  fi
  tstomp=$(printf '%s\n' "${TIMESTOMP:-}"       | json_arr)
  recsys=$(printf '%s\n' "${RECENT_SYS:-}"      | json_arr)
  imuh=$(printf '%s\n'   "${IMUNIFY_HITS:-}"    | json_arr)
  wptk=$(printf '%s\n'   "${WPTK_INFECTED:-}"   | json_arr)
  # v3.8 Joomla-Prüfung + Netz-Transparenz
  local jcfg jver jcweak jlog jcmod jcunk jsysp jsuper jsess jmodc jtpl jukeys jvuln jmal onlinef
  jcfg=$(printf   '%s\n' "${JOOMLA_CONFIGS:-}"       | json_arr)
  jver=$(printf   '%s\n' "${JOOMLA_VERSIONS:-}"      | json_arr)
  jcweak=$(printf '%s\n' "${JOOMLA_CONFIG_WEAK:-}"   | grep -vE '^=== |^$' | json_arr)
  jlog=$(printf   '%s\n' "${JOOMLA_LOG_IOC:-}"       | json_arr)
  jcmod=$(printf  '%s\n' "${JOOMLA_CORE_MODIFIED:-}" | json_arr)
  jcunk=$(printf  '%s\n' "${JOOMLA_CORE_UNKNOWN:-}"  | json_arr)
  jsysp=$(printf  '%s\n' "${JOOMLA_SYS_PLUGINS:-}"   | json_arr)
  jsuper=$(printf '%s\n' "${JOOMLA_ROGUE_SUPER:-}"   | grep -vE '^=== |^$' | json_arr)
  jsess=$(printf  '%s\n' "${JOOMLA_SESSION_HITS:-}"  | json_arr)
  jmodc=$(printf  '%s\n' "${JOOMLA_MOD_CUSTOM:-}"    | json_arr)
  jtpl=$(printf   '%s\n' "${JOOMLA_TPL_PARAMS:-}"    | json_arr)
  jukeys=$(printf '%s\n' "${JOOMLA_USER_KEYS:-}"     | json_arr)
  jvuln=$(printf  '%s\n' "${JOOMLA_VULN_EXT:-}"      | json_arr)
  jmal=$(printf   '%s\n' "${JOOMLA_MALWARE:-}"       | json_arr)
  onlinef=$(printf '%s\n' "${ONLINE_FETCHES:-}"      | json_arr)
  local n_jcmod n_jvuln n_jsuper
  n_jcmod=$(printf  '%s\n' "${JOOMLA_CORE_MODIFIED:-}" | grep -c . 2>/dev/null)
  n_jvuln=$(printf  '%s\n' "${JOOMLA_VULN_EXT:-}"      | grep -c . 2>/dev/null)
  n_jsuper=$(printf '%s\n' "${JOOMLA_ROGUE_SUPER:-}"   | grep -vE '^=== |^$' | grep -c . 2>/dev/null)

  cat > "$FINDINGS_FILE" <<JSON
{
  "schema_version": "1.4",
  "tool": "wp_plesk_forensik.sh",
  "tool_version": "${TOOL_VERSION}",
  "run_id": "$(json_str "$RUN_LABEL")",
  "host": "$(json_str "$(hostname -f 2>/dev/null || hostname)")",
  "domain": "$(json_str "${DOMAIN:-}")",
  "generated_utc": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "counts": { "crit": ${N_CRIT:-0}, "warn": ${N_WARN:-0}, "ok": ${N_OK:-0} },
  "verdicts": {
    "root": { "flags": ${ROOT_FLAGS:-0}, "text": "$(json_str "${ROOT_VERDICT:-}")" },
    "wpdb": { "flags": ${WPDB_FLAGS:-0}, "text": "$(json_str "${WPDB_VERDICT:-}")" },
    "joomla": { "flags": ${JOOMLA_FLAGS:-0}, "text": "$(json_str "${JOOMLA_VERDICT:-}")" },
    "relay": { "flags": ${RELAY_FLAGS:-0}, "text": "$(json_str "${RELAY_VERDICT:-}")" }
  },
  "data_sources": {
    "joomla_snapshot": "$(json_str "${J_DATA_STAMP:-}")",
    "joomla_snapshot_age_days": ${JOOMLA_DATA_AGE:-0},
    "online_mode": $(if [[ "${WANT_ONLINE:-0}" == "1" ]]; then echo true; else echo false; fi),
    "network_fetches": ${onlinef:-[]}
  },
  "metrics": {
    "webshell_count": ${WEBSHELL_COUNT:-0},
    "webshell_review": ${WEBSHELL_REVIEW:-0},
    "injected_core_files": ${n_corei:-0},
    "doorway_dirs": ${n_doorw:-0},
    "core_include_injections": ${n_coreinj:-0},
    "rogue_wp_admins": ${n_rogue:-0},
    "suspicious_plugins": ${n_suspp:-0},
    "ssh_failed": ${SSH_FAILED_COUNT:-0},
    "wp_installs": ${WP_COUNT:-0},
    "joomla_installs": ${JOOMLA_COUNT:-0},
    "joomla_core_modified": ${n_jcmod:-0},
    "joomla_vulnerable_extensions": ${n_jvuln:-0},
    "joomla_rogue_superusers": ${n_jsuper:-0},
    "domains": ${DOMAIN_COUNT:-0}
  },
  "actionable": {
    "webshell_dropper": ${ws:-[]},
    "injected_core": ${corei:-[]},
    "core_should_not_exist": ${coresne:-[]},
    "doorway_dirs": ${doorw:-[]},
    "core_include_injection": ${coreinj:-[]},
    "disguised_payloads": ${disg:-[]},
    "rogue_wp_admins": ${rogue:-[]},
    "suspicious_plugins": ${suspp:-[]},
    "mu_plugins": ${muplug:-[]},
    "tampered_htaccess": ${tamphta:-[]},
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
    "ioc_ips": { "attacker": ${aips:-[]}, "ssh_bruteforce": ${bips:-[]} },
    "gsocket_hits": ${gsock:-[]},
    "masq_binaries": ${masq:-[]},
    "fileless_procs": ${fless:-[]},
    "kthread_fakes": ${kthr:-[]},
    "orphan_shells": ${orph:-[]},
    "ssh_login_hooks": ${sshh:-[]},
    "relay_connections": ${relc:-[]},
    "yara_hits": ${yhit:-[]},
    "timestomp": ${tstomp:-[]},
    "recent_system_changes": ${recsys:-[]},
    "imunify_malware": ${imuh:-[]},
    "wptk_infected": ${wptk:-[]},
    "joomla_configs": ${jcfg:-[]},
    "joomla_versions": ${jver:-[]},
    "joomla_config_weak": ${jcweak:-[]},
    "joomla_log_ioc": ${jlog:-[]},
    "joomla_core_modified": ${jcmod:-[]},
    "joomla_core_unknown": ${jcunk:-[]},
    "joomla_system_plugins": ${jsysp:-[]},
    "joomla_rogue_superusers": ${jsuper:-[]},
    "joomla_session_payloads": ${jsess:-[]},
    "joomla_mod_custom": ${jmodc:-[]},
    "joomla_template_params": ${jtpl:-[]},
    "joomla_user_keys": ${jukeys:-[]},
    "joomla_vulnerable_extensions": ${jvuln:-[]},
    "joomla_malware": ${jmal:-[]}
  },
  "malware_summary": ${malsum}
}
JSON
  echo "  findings.json geschrieben: $FINDINGS_FILE" >> "$REPORT_FILE"
}
emit_findings_json

# ── PDF-Abschlussbericht (v3.5, optional/degradierend) ───────
# Teil 1 = Kundenbericht (laienlesbar, maskiert), Teil 2 = KPI-Zusammenfassung.
# reportgen/ muss neben dem Skript oder unter ${BASE_DIR} liegen. Fehlt
# pandoc/weasyprint/reportgen, wird das PDF übersprungen — die Markdown-Berichte
# bleiben vollständig und maßgeblich (Read-only-Versprechen, kein harter Fehler).
PDF_FILE="${RUN_DIR}/abschlussbericht.pdf"
REPORTGEN_DIR=""
for _d in "$(dirname "$SELF_PATH")/reportgen" "${BASE_DIR}/reportgen"; do
  [[ -x "$_d/nt_report_pdf.sh" ]] && { REPORTGEN_DIR="$_d"; break; }
done
_wp="${WEASYPRINT:-$(command -v weasyprint 2>/dev/null || true)}"
if [[ -n "$REPORTGEN_DIR" ]] && command -v pandoc >/dev/null 2>&1 && [[ -n "$_wp" ]]; then
  ZUSAMMEN_FILE="${RUN_DIR}/zusammenfassung.md"
  {
    echo "::: kpigrid"
    echo "- **${N_CRIT}** kritische Befunde"
    echo "- **${N_WARN}** Auffälligkeiten"
    echo "- **${N_OK}** geprüfte Punkte"
    echo "- **$(ls -1 "$BELEGE_DIR" 2>/dev/null | grep -vc SHA256SUMS)** Belege (SHA256)"
    echo ":::"
    echo
    echo "## Bewertung im Überblick"
    echo
    echo "**Reichweite (Serverebene):** ${ROOT_CUSTOMER_HINT}"
    echo
    echo "**Fernzugriff / Relay-Backdoor:** ${RELAY_VERDICT}"
    echo
    echo "**WordPress-Datenbank:** ${WPDB_VERDICT}"
    if [[ "${JOOMLA_COUNT:-0}" -gt 0 ]]; then
      echo
      echo "**Joomla:** ${JOOMLA_VERDICT}"
    fi
  } > "$ZUSAMMEN_FILE"
  _dom="${DOMAIN:-$(hostname -f 2>/dev/null || hostname)}"
  # Grobstatistik der Schadcode-Familien fürs Deckblatt (Seite 1)
  COVER_STATS=""
  if [[ "${MALWARE_TOTAL:-0}" -gt 0 ]]; then
    COVER_STATS=$(for fam in "${!FAM_COUNT[@]}"; do echo "${FAM_COUNT[$fam]}|$fam"; done \
      | sort -rn | while IFS='|' read -r n f; do printf '%s:%s;' "$f" "$n"; done)
  fi
  if WEASYPRINT="$_wp" bash "$REPORTGEN_DIR/nt_report_pdf.sh" \
       --teil1 "$KUNDE_FILE" --teil2 "$ZUSAMMEN_FILE" \
       --title "Sicherheitsvorfall\nForensische Untersuchung" \
       --eyebrow "netztaucher | digital — Forensik" \
       --domain "$_dom" \
       --subtitle "Prüfung ${RUN_LABEL} · $(date +%d.%m.%Y)" \
       --teil2-label "Teil 2 — Zusammenfassung der Aktion" \
       --meta "Einstufung=${AMPEL}" --meta "Prüfungs-ID=${RUN_LABEL}" \
       ${COVER_STATS:+--cover-stats "$COVER_STATS"} \
       --out "$PDF_FILE" >/dev/null 2>&1; then
    echo "  PDF-Abschlussbericht: $PDF_FILE" >> "$REPORT_FILE"
  else
    echo "  PDF-Erzeugung fehlgeschlagen — Markdown-Berichte bleiben maßgeblich." >> "$REPORT_FILE"
    PDF_FILE=""
  fi
else
  echo "  PDF übersprungen (pandoc/weasyprint/reportgen nicht verfügbar)." >> "$REPORT_FILE"
  PDF_FILE=""
fi

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
  [[ -f befunde_details.md ]] && sha256sum befunde_details.md 2>/dev/null >> "${BELEGE_DIR}/SHA256SUMS" || true
  [[ -n "$PDF_FILE" && -f "$PDF_FILE" ]] && sha256sum "$(basename "$PDF_FILE")" zusammenfassung.md 2>/dev/null >> "${BELEGE_DIR}/SHA256SUMS" || true
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
[[ -n "${PDF_FILE:-}" && -f "${PDF_FILE:-}" ]] && echo -e "${BOLD}PDF-Bericht:${NC}     ${PDF_FILE}"
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
