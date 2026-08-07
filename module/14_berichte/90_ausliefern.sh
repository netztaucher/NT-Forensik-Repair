# shellcheck shell=bash
# NT-Forensik — Abschnitt 14, Teil: Maskierung, Archiv, Abschlussmeldung
#
# Unterabschnitt von module/14_berichte.sh. Wird vom Runner nach dem
# Hauptmodul geladen (siehe modul_teile_laden in wp_plesk_forensik.sh) und
# teilt sich dessen Variablen. Nicht einzeln ausfuehrbar.

# ── Fremdkunden aus den weiterzugebenden Dokumenten halten ───
# Vor dem Hashen, damit die Pruefsummen zur ausgelieferten Fassung passen.
# Ein Bericht ueber EINEN Kunden darf keine Daten anderer Kunden enthalten;
# auf einem Shared-Host mit 482 vhosts standen in einem Lauf ueber ein
# einzelnes Abo 112 fremde Kennungen in 17 Abschnitten.
#
# Die Belege unter belege/ bleiben bewusst UNMASKIERT: sie sind Beweismittel
# und gehoeren dem Betreiber, nicht in eine Kundenuebergabe. Wer das Paket
# weitergibt, gibt die Berichte weiter, nicht die Rohbelege.
if [[ "$SCOPE_MODE" != "global" ]]; then
  echo -e "\n${BOLD}Datenschutz${NC}"
  for _dok in technik_bericht.md kundenbericht.md befunde_details.md root_aussage.md lauf.log; do
    [[ -f "${RUN_DIR}/${_dok}" ]] || continue
    printf '  %-24s' "$_dok"
    nf_fremdkunden_maskieren "${RUN_DIR}/${_dok}" || echo "  (nichts zu maskieren)"
  done
fi

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
echo -e "${BOLD}Befunde:${NC}       🔴 ${N_CRIT} kritisch, ⚠️ ${N_WARN} Warnungen, ✅ ${N_OK} ok, ⚪ ${N_UNKNOWN} nicht messbar"
if [[ "${N_UNKNOWN:-0}" -gt 0 ]]; then
  echo -e "${YLW}               ${N_UNKNOWN} Prüfung(en) ohne Ergebnis — das ist keine Entwarnung.${NC}"
  printf '%s' "$UNKNOWN_LIST" | while IFS= read -r _z; do
    [[ -n "$_z" ]] && echo -e "                 ${_z#- }"
  done
fi
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
echo -e "  4. Archiv lokal sichern (Befehl auf der naechsten Zeile, ganz markieren):"
# Das Ziel steht ausgeschrieben statt als einzelnem '.'. Ein Punkt am Zeilenende
# ist beim Kopieren unsichtbar und geht regelmaessig verloren — scp bekommt dann
# nur eine Quelle und antwortet mit seiner Usage-Meldung, was wie ein Fehler im
# Aufruf aussieht und keiner ist.
echo -e "     ${BOLD}scp root@$(hostname -f 2>/dev/null || hostname):${RUN_ARCHIVE} ~/Downloads/${NC}"
echo -e "  5. Alle 🔴-Maßnahmen sofort umsetzen"
echo ""
