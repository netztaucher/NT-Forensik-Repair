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
    # Kein '|| echo "(nichts zu maskieren)"' mehr. Genau das stand hier bis
    # v3.12 und meldete die VERWEIGERUNG der Maskierung als Erfolg: die
    # Funktion gibt 1 zurueck, wenn sie den eigenen Bezug nicht bestimmen kann
    # und deshalb lieber gar nicht maskiert. Der unmaskierte Bericht ging
    # daraufhin raus, und im Protokoll stand, es sei nichts zu tun gewesen.
    if ! nf_fremdkunden_maskieren "${RUN_DIR}/${_spur_dok}"; then
      echo ""
      MASKIERUNG_FEHLER+="${_spur_dok}"$'\n'
    fi
  done
fi

# ── Endpruefung vor der Auslieferung ─────────────────────────
# Der Riegel in befund_melden greift nur dort, wo ein Pfad uebergeben wurde.
# Nicht jeder Befund hat einen, und Fliesstext kann eine fremde Kennung
# enthalten, die keinem Pfad entstammt. Diese Pruefung schaut deshalb auf das
# FERTIGE Dokument — sie ist die letzte Gelegenheit, bevor es das Haus
# verlaesst.
if [[ "$SCOPE_MODE" != "global" ]]; then
  _rest=""
  for _kd in "${KUNDE_DIR}"/*.md; do
    [[ -f "$_kd" ]] || continue
    # Dieselbe Erkennung wie die Maskierung, nur ohne zu schreiben. Bewusst
    # keine eigene, engere Pruefung: die erste Fassung kannte nur vhost-Pfade
    # und webNN-Kennungen und meldete "sauber", waehrend eine blanke URL eines
    # fremden Kunden im Kundenbericht stand.
    _t=$(nf_fremdkunden_maskieren "$_kd" pruefen) || \
      _rest+="${_kd##*/}: $(printf '%s' "$_t" | tr '\n' ' ')"$'\n'
  done

  if [[ -n "$_rest" ]]; then
    echo ""
    crit "Kundenspur enthält fremde Kennungen — Auslieferung abgebrochen"
    code "$_rest"
    {
      echo ""
      echo -e "${RED}ABBRUCH:${NC} In den Kundendokumenten stehen Kennungen, die nicht zum"
      echo    "         geprüften Umfang gehören. Sie werden NICHT ausgeliefert."
      echo    "         Die Betreiberspur bleibt vollständig:"
      echo    "         ${BETREIBER_DIR}"
      printf '%s' "$_rest" | sed 's/^/         /'
    } >&2
    rm -f "${KUNDE_DIR}"/*.md "${KUNDE_DIR}"/*.pdf 2>/dev/null || true
    cat > "${KUNDE_DIR}/00_ABBRUCH.txt" <<'ABBRUCH'
AUSLIEFERUNG ABGEBROCHEN.

In den Kundendokumenten standen Kennungen, die nicht zum geprueften Umfang
gehoeren — Pfade, Domains, Systemkonten oder Mailadressen anderer Kunden
desselben Servers. Sie wurden geloescht, statt sie auszuliefern.

Die vollstaendigen Ergebnisse liegen unveraendert in betreiber/.
Ursache pruefen, beheben, Lauf wiederholen.
ABBRUCH
  else
    ok "Kundenspur enthält keine fremden Kennungen"
  fi
fi

# ── Was zurueckgehalten wurde, gehoert in den Bericht ─────────
if [[ -n "${KANAL_VERWEIGERT:-}" ]]; then
  h2 "Zurückgehaltene Befunde"
  info "Diese Befunde liegen außerhalb des geprüften Umfangs und wurden deshalb NICHT in den Kundenbericht übernommen. Sie stehen vollständig hier."
  code "$(printf '%s' "$KANAL_VERWEIGERT")"
fi

if [[ -n "${MASKIERUNG_FEHLER:-}" ]]; then
  crit "Maskierung fehlgeschlagen — Dokumente NICHT freigabefähig"
  code "$(printf '%s' "$MASKIERUNG_FEHLER")"
fi
