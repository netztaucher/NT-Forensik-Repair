# shellcheck shell=bash
# NT-Forensik — Abschnitt 14, Teil: Fremdkunden maskieren
#
# Unterabschnitt von module/14_berichte.sh. Wird vom Runner nach dem
# Hauptmodul geladen und teilt sich dessen Variablen. Nicht einzeln ausfuehrbar.
#
# ------------------------------------------------------------
# WARUM DIESE DATEI DIE NUMMER 55 TRAEGT
#
# Sie muss nach allen erzeugten Dokumenten laufen (10-50) und VOR dem PDF (60).
# Bis v3.10 lief die Maskierung ganz am Ende: das PDF wurde damit aus der
# UNMASKIERTEN Fassung des Kundenberichts gebaut, waehrend das Markdown daneben
# maskiert war. Zwei Dokumente mit demselben Namen und unterschiedlichem
# Inhalt — und ausgeliefert wurde regelmaessig das PDF.
#
# Ein Bericht ueber EINEN Kunden darf keine Daten anderer Kunden enthalten. Auf
# einem Shared-Host mit 482 vhosts standen in einem Lauf ueber ein einzelnes
# Abo 112 fremde Kennungen in 17 Abschnitten.
#
# Die Rohbelege unter belege/ bleiben UNMASKIERT. Sie sind Beweismittel und
# liegen deshalb in der Betreiberspur, die nicht weitergegeben wird.
# findings.json bleibt ebenfalls unmaskiert — der Reparaturteil braucht die
# echten Pfade, sonst greift er ins Leere.

echo -e "\n${BOLD}Datenschutz${NC}"

# Im Global-Modus ist der Betreiber der Adressat und alle vhosts sind sein
# Gegenstand — dort gibt es keine "fremden" Kunden, die zu maskieren waeren.
if [[ "$SCOPE_MODE" == "global" ]]; then
  info "Betreiber-Lauf über alle vhosts — keine Maskierung (alle Daten gehören dem Betreiber)."
else
  # Beide Spuren. Die Betreiberspur wird mitmaskiert, weil aus ihr die
  # Behoerden-Entwuerfe stammen: eine DSGVO-Meldung an eine Aufsichtsbehoerde
  # darf nicht die Domainliste unbeteiligter Kunden enthalten.
  for _spur_dok in \
      "kunde/kundenbericht.md" \
      "kunde/befunde_details.md" \
      "kunde/root_aussage.md" \
      "betreiber/technik_bericht.md" \
      "betreiber/bsi_meldung.md" \
      "betreiber/dsgvo_meldung.md" \
      "betreiber/lauf.log"; do
    [[ -f "${RUN_DIR}/${_spur_dok}" ]] || continue
    printf '  %-34s' "$_spur_dok"
    nf_fremdkunden_maskieren "${RUN_DIR}/${_spur_dok}" || echo "  (nichts zu maskieren)"
  done
fi
