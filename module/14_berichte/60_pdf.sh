# shellcheck shell=bash
# NT-Forensik — Abschnitt 14, Teil: PDF-Abschlussbericht (optional, degradierend)
#
# Unterabschnitt von module/14_berichte.sh. Wird vom Runner nach dem
# Hauptmodul geladen (siehe modul_teile_laden in wp_plesk_forensik.sh) und
# teilt sich dessen Variablen. Nicht einzeln ausfuehrbar.

# ── PDF-Abschlussbericht (v3.5, optional/degradierend) ───────
# Teil 1 = Kundenbericht (laienlesbar, maskiert), Teil 2 = KPI-Zusammenfassung.
# reportgen/ muss neben dem Skript oder unter ${BASE_DIR} liegen. Fehlt
# pandoc/weasyprint/reportgen, wird das PDF übersprungen — die Markdown-Berichte
# bleiben vollständig und maßgeblich (Read-only-Versprechen, kein harter Fehler).
PDF_FILE="${KUNDE_DIR}/abschlussbericht.pdf"
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
