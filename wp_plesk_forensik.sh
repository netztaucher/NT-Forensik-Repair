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


# ── Eigenes Verzeichnis bestimmen ────────────────────────────
# Alles wird relativ zum Skript geladen. Damit laeuft das Werkzeug sowohl
# aus dem Repository als auch aus der installierten Kopie unter BASE_DIR.
SELF_PATH="$(readlink -f "$0" 2>/dev/null || echo "$0")"
SELF_DIR="$(dirname "$SELF_PATH")"

lade() {   # lade <relativer Pfad> — bricht mit klarer Meldung ab statt still zu scheitern
  local f="${SELF_DIR}/$1"
  if [[ ! -r "$f" ]]; then
    echo "Fehler: ${1} fehlt oder ist nicht lesbar (erwartet unter ${SELF_DIR}/)." >&2
    echo "        Skript und die Ordner lib/ und module/ gehoeren zusammen." >&2
    exit 3
  fi
  # shellcheck disable=SC1090
  source "$f"
}

lade lib/konfig.sh     # Pfade, Argumente, Laufordner, Selbst-Installation
lade lib/befunde.sh    # Vorgabewerte aller Befund-Variablen
lade lib/muster.sh     # Signaturen, Selbstausschluss
lade lib/kern.sh       # Ausgabe- und Beleg-Funktionen

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

# ── Pruefabschnitte ──────────────────────────────────────────
# Reihenfolge ist bedeutsam: Abschnitt 13 fasst die Funde der vorherigen
# zusammen, Abschnitt 14 schreibt daraus die Berichte.
MODULE_GELAUFEN=""
MODULE_UEBERSPRUNGEN=""

for _modul in "${SELF_DIR}"/module/*.sh; do
  [[ -r "$_modul" ]] || continue
  _nr=$(modul_feld "$_modul" nummer)
  if modul_gewaehlt "$_nr" "$(modul_feld "$_modul" ebene)"; then
    MODULE_GELAUFEN+="${_nr} "
    lade "module/$(basename "$_modul")"
  else
    _t="${_nr}. $(modul_feld "$_modul" titel)"
    MODULE_UEBERSPRUNGEN+="${_t}"$'\n'
    echo -e "  ${CYN}übersprungen:${NC} ${_t}"
  fi
done

# Ein Teillauf darf sich nicht wie ein vollständiges Ergebnis lesen.
if [[ -n "$MODULE_UEBERSPRUNGEN" ]]; then
  {
    printf '\n> **Eingeschränkter Lauf.** Die folgenden Prüfabschnitte wurden auf '
    printf 'ausdrückliche Auswahl hin NICHT ausgeführt. Ihre Ergebnisse fehlen '
    printf 'in diesem Bericht — das ist keine Entwarnung für diese Bereiche:\n>\n'
    while IFS= read -r _z; do [[ -n "$_z" ]] && printf '> - %s\n' "$_z"; done <<< "$MODULE_UEBERSPRUNGEN"
    printf '\n'
  } >> "$REPORT_FILE"
fi
