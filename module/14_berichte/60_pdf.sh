# shellcheck shell=bash
# Test:     ja - werkzeuge/kundenpaket-pruefstand.sh (Lauf mit Fixture, PDFs, Seiten, Interna) · NT-Forensik-Repair#149
# Rueckweg: entfällt - schreibt nur in den eigenen Laufordner
# NT-Forensik — Abschnitt 14, Teil: Kundenpaket im Designsystem NT Docs (optional, degradierend)
#
# Unterabschnitt von module/14_berichte.sh. Wird vom Runner nach dem
# Hauptmodul geladen (siehe modul_teile_laden in wp_plesk_forensik.sh) und
# teilt sich dessen Variablen. Nicht einzeln ausfuehrbar.
#
# Seit dem Standard vom 21.10.2026 (#149) entstehen hier drei Kunden-PDFs im
# Designsystem NT Docs statt des frueheren abschlussbericht.pdf:
#   kunde/NT-Sicherheitsbericht_<Kunde>_<Datum>.pdf
#   kunde/NT-Dokumentation_DSGVO-Art33_<Kunde>_<Datum>.pdf
#   kunde/NT-Einordnung_BSI-Meldung_<Kunde>_<Datum>.pdf
# Seitenbilder und Pruefbericht liegen beim Betreiber (betreiber/kundenpaket_pruefung/),
# nie beim Kunden. Ohne Fall-Datei sind die Dokumente ein Entwurf aus dem Lauf;
# betreiber/kundenpaket_fall.entwurf.json ist die Vorlage, um Kunde, Erzaehlung
# und Bereinigung nachzutragen und reportgen/kundenpaket.py erneut aufzurufen.
#
# Fehlt WeasyPrint, wird uebersprungen: die Markdown-Berichte bleiben
# vollstaendig (Read-only-Versprechen, kein harter Fehler).

KUNDENPAKET_PDFS=()   # von 90_ausliefern gelesen (Pruefsummen, Abschlussmeldung)

# Grundlage fuer die Fundliste im Bericht: die Fundstellen aus 05_einordnung,
# bereits je Datei einmal, mit Familie und Pfad. relpath() rechnet je nach
# Umfang vom Kundenordner oder vom vhosts-Ordner aus; die Kopfzeile nennt die
# Basis, damit reportgen/kundenpaket.py den Pfad eindeutig zuordnen kann.
{
  printf '#basis\t%s\n' "$( [[ -n "${CUST_ROOT:-}" && "${CUST_ROOT:-}" != "$VHOSTS_DIR" ]] && printf '%s' "$CUST_ROOT" || printf '%s' "$VHOSTS_DIR")"
  printf '%s' "${FUNDE:-}"
} > "${BETREIBER_DIR}/kundenpaket_funde.tsv"

# Python mit WeasyPrint finden: $NT_WEASYPRINT_PY, sonst der Interpreter hinter
# $WEASYPRINT bzw. `weasyprint` im PATH, sonst ~/.venvs/weasyprint (reportgen/README.md).
_kp_py="${NT_WEASYPRINT_PY:-}"
if [[ -z "$_kp_py" ]]; then
  _wp="${WEASYPRINT:-$(command -v weasyprint 2>/dev/null || true)}"
  [[ -n "$_wp" && "$_wp" != */* ]] && _wp="$(command -v "$_wp" 2>/dev/null || true)"
  if [[ -n "$_wp" && -f "$_wp" ]]; then
    _kp_py="$(head -1 "$_wp" | sed -n 's/^#![[:space:]]*//p' | awk '{print $1}')"
  fi
fi
[[ -z "$_kp_py" && -x "${HOME}/.venvs/weasyprint/bin/python" ]] && _kp_py="${HOME}/.venvs/weasyprint/bin/python"
REPORTGEN_DIR=""
for _d in "$(dirname "$SELF_PATH")/reportgen" "${BASE_DIR}/reportgen"; do
  [[ -f "$_d/kundenpaket.py" ]] && { REPORTGEN_DIR="$_d"; break; }
done

# Pruefstand-Laeufe (NT_TESTLAUF=1) bauen kein PDF: die Referenz von
# werkzeuge/goldmuster.sh soll nicht davon abhaengen, ob auf dem Rechner
# WeasyPrint liegt. Das Kundenpaket hat seinen eigenen Pruefstand.
if [[ "${NT_TESTLAUF:-}" == "1" && "${NT_KUNDENPAKET_IM_TESTLAUF:-}" != "1" ]]; then
  echo "  Kundenpaket übersprungen (Prüfstand-Lauf)." >> "$REPORT_FILE"
elif [[ "${SCOPE_MODE:-}" == "global" ]]; then
  echo "  Kundenpaket übersprungen (Betreiberlauf über alle vhosts, kein einzelner Kunde)." >> "$REPORT_FILE"
elif [[ -n "$REPORTGEN_DIR" && -n "$_kp_py" ]] && "$_kp_py" -c 'import weasyprint' >/dev/null 2>&1; then
  _kp_args=(--lauf "$RUN_DIR" --ziel "$KUNDE_DIR"
            --pruefung "${BETREIBER_DIR}/kundenpaket_pruefung"
            --entwurf "${BETREIBER_DIR}/kundenpaket_fall.entwurf.json")
  [[ -n "${NT_KUNDENFALL:-}" && -f "${NT_KUNDENFALL:-}" ]] && _kp_args+=(--fall "$NT_KUNDENFALL")
  "$_kp_py" "$REPORTGEN_DIR/kundenpaket.py" "${_kp_args[@]}" \
      > "${BETREIBER_DIR}/kundenpaket_pruefung.log" 2>&1
  _kp_rc=$?
  while IFS= read -r _p; do KUNDENPAKET_PDFS+=("$_p"); done \
    < <(find "$KUNDE_DIR" -maxdepth 1 -name 'NT-*.pdf' 2>/dev/null | sort)
  case "$_kp_rc" in
    0) echo "  Kundenpaket (NT Docs): ${#KUNDENPAKET_PDFS[@]} PDF(s) in kunde/, Seiten als Bild: betreiber/kundenpaket_pruefung/seiten/" >> "$REPORT_FILE" ;;
    3) echo "  Kundenpaket: Interna in den Kunden-PDFs — NICHT ausliefern (betreiber/kundenpaket_pruefung.log)." >> "$REPORT_FILE" ;;
    2) echo "  Kundenpaket: Satz- oder Regelfehler — Seiten prüfen (betreiber/kundenpaket_pruefung.log)." >> "$REPORT_FILE" ;;
    *) echo "  Kundenpaket fehlgeschlagen — Markdown-Berichte bleiben maßgeblich (betreiber/kundenpaket_pruefung.log)." >> "$REPORT_FILE" ;;
  esac
else
  echo "  Kundenpaket übersprungen (WeasyPrint oder reportgen/kundenpaket.py nicht verfügbar)." >> "$REPORT_FILE"
fi
