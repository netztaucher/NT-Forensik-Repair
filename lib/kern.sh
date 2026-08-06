# ============================================================
# NT-Forensik — Ausgabe- und Beleg-Funktionen
# ------------------------------------------------------------
# Die Primitiven, auf denen jeder Pruefabschnitt aufsetzt: Ueberschriften,
# Befundzeilen mit Schweregrad, Codebloecke, Beweissicherung, Maskierung fuer
# Kundenberichte und der protokollierte Netzabruf.
# 
# Der zweite Parameter 'web' bei warn/crit ist tragend: nur so markierte
# Befunde erscheinen im Kundenbericht.
# ============================================================

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
