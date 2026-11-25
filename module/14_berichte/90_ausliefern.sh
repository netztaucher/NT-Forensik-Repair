# shellcheck shell=bash
# NT-Forensik — Abschnitt 14, Teil: Archive und Abschlussmeldung
#
# Unterabschnitt von module/14_berichte.sh. Wird vom Runner nach dem
# Hauptmodul geladen und teilt sich dessen Variablen. Nicht einzeln ausfuehrbar.
#
# Die Maskierung ist hier bewusst NICHT mehr enthalten — sie steht in 55, weil
# sie vor dem PDF-Bau laufen muss.

# ── Berichte hashen ──────────────────────────────────────────
# Nach der Maskierung, damit die Pruefsummen zur ausgelieferten Fassung passen.
# Ein Hash ueber eine Fassung, die so nie das Haus verlassen hat, belegt nichts.
(
  cd "$RUN_DIR" || exit 0
  for _h in kunde/kundenbericht.md kunde/befunde_details.md kunde/root_aussage.md \
            betreiber/technik_bericht.md betreiber/bsi_meldung.md \
            betreiber/dsgvo_meldung.md betreiber/findings.json; do
    [[ -f "$_h" ]] && sha256sum "$_h" 2>/dev/null >> "${BELEGE_DIR}/SHA256SUMS"
  done
  [[ -n "${PDF_FILE:-}" && -f "${PDF_FILE:-}" ]] && \
    sha256sum "kunde/$(basename "$PDF_FILE")" 2>/dev/null >> "${BELEGE_DIR}/SHA256SUMS"
) || true

# ── Zwei Archive statt einem ─────────────────────────────────
# Ein einziges Archiv laedt dazu ein, es als Ganzes weiterzureichen — samt
# Technik-Bericht mit fremden vhosts und samt unmaskierter Rohbelege. Getrennte
# Archive machen die Entscheidung, was der Kunde bekommt, zu einer bewussten.
KUNDE_ARCHIVE="${FORENSIK_BASE}/${RUN_LABEL}_kunde.tar.gz"
BETREIBER_ARCHIVE="${FORENSIK_BASE}/${RUN_LABEL}_betreiber.tar.gz"
tar czf "$KUNDE_ARCHIVE"     -C "$RUN_DIR" kunde     2>/dev/null || true
tar czf "$BETREIBER_ARCHIVE" -C "$RUN_DIR" betreiber 2>/dev/null || true
# Alter Name, damit bestehende Skripte und Ablaeufe nicht ins Leere greifen.
RUN_ARCHIVE="$KUNDE_ARCHIVE"

# ============================================================
# ABSCHLUSSMELDUNG
# ============================================================

echo ""
echo -e "${BOLD}${GRN}══════════════════════════════════════════${NC}"
echo -e "${BOLD}${GRN}  ANALYSE ABGESCHLOSSEN — Lauf ${RUN_LABEL}${NC}"
echo -e "${BOLD}${GRN}══════════════════════════════════════════${NC}"
echo ""
echo -e "${BOLD}Befunde:${NC}       🔴 ${N_CRIT} kritisch, ⚠️ ${N_WARN} Warnungen, ✅ ${N_OK} ok, ⚪ ${N_UNKNOWN} nicht messbar"
if [[ "${N_UNKNOWN:-0}" -gt 0 ]]; then
  echo -e "${YLW}               ${N_UNKNOWN} Prüfung(en) ohne Ergebnis — das ist keine Entwarnung.${NC}"
  printf '%s' "$UNKNOWN_LIST" | while IFS= read -r _z; do
    [[ -n "$_z" ]] && echo -e "                 ${_z#- }"
  done
fi
echo ""
echo -e "${BOLD}Lauf-Ordner:${NC}     ${RUN_DIR}"
echo ""
echo -e "${BOLD}${GRN}  kunde/${NC}  — weitergabefähig"
echo -e "    Kundenbericht:   ${KUNDE_FILE}"
[[ -f "${KUNDE_DIR}/befunde_details.md" ]] && echo -e "    Befund-Details:  ${KUNDE_DIR}/befunde_details.md"
[[ -f "${KUNDE_DIR}/root_aussage.md" ]]    && echo -e "    Root-Aussage:    ${KUNDE_DIR}/root_aussage.md"
[[ -n "${PDF_FILE:-}" && -f "${PDF_FILE:-}" ]] && echo -e "    PDF-Bericht:     ${PDF_FILE}"
echo -e "    Archiv:          ${KUNDE_ARCHIVE}"
echo ""
echo -e "${BOLD}${YLW}  betreiber/${NC} — NICHT weitergeben"
echo -e "    Technik-Bericht: ${REPORT_FILE}"
echo -e "    BSI-Meldung:     ${BSI_FILE}"
echo -e "    DSGVO-Meldung:   ${DSGVO_FILE}"
echo -e "    findings.json:   ${FINDINGS_FILE} (Eingabe für die Bereinigung)"
echo -e "    Belege:          ${BELEGE_DIR} (SHA256-versiegelt, unmaskiert)"
echo -e "    Archiv:          ${BETREIBER_ARCHIVE}"
echo ""
echo -e "${YLW}Nächste Schritte:${NC}"
echo -e "  1. Kundenbericht prüfen:   cat ${KUNDE_FILE}"
echo -e "  2. BSI-Meldung ergänzen:   [AUSFÜLLEN]-Felder in ${BSI_FILE}"
echo -e "  3. DSGVO-Meldung prüfen:   [AUSFÜLLEN]-Felder in ${DSGVO_FILE} (eigener Meldeweg!)"
echo -e "  4. Kundenunterlagen holen (Befehl auf der naechsten Zeile, ganz markieren):"
# Das Ziel steht ausgeschrieben statt als einzelnem '.'. Ein Punkt am Zeilenende
# ist beim Kopieren unsichtbar und geht regelmaessig verloren — scp bekommt dann
# nur eine Quelle und antwortet mit seiner Usage-Meldung, was wie ein Fehler im
# Aufruf aussieht und keiner ist.
echo -e "     ${BOLD}scp root@$(hostname -f 2>/dev/null || hostname):${KUNDE_ARCHIVE} ~/Downloads/${NC}"
echo -e "  5. Alle 🔴-Maßnahmen sofort umsetzen"
echo ""
