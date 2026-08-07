# shellcheck shell=bash
# NT-Forensik — Abschnitt 12r: Prüfrezepte
#
# @nummer:  12r
# @titel:   Anwendungs-Prüfrezepte
# @frage:   Ist eine der geprüften Anwendungen übernommen oder unzureichend gehärtet?
# @kosten:  mittel; HOCH mit --online — dann ein Prüfsummenabruf je WP-Plugin
# @ebene:   website
#
# Die Nummer liegt vor 14, weil Abschnitt 14 die Berichte schreibt. Ein
# Prüfabschnitt mit höherer Nummer läuft danach, und seine Befunde erscheinen
# in keinem Dokument.
#
# Wird vom Runner eingebunden, nicht einzeln ausgefuehrt.

h1 "12r. ANWENDUNGS-PRÜFREZEPTE"

if [[ ! -d "$REZEPT_DIR" ]]; then
  info "Kein Rezept-Verzeichnis vorhanden (${REZEPT_DIR}) — keine anwendungsspezifische Prüfung"
else

# --nur-nextcloud & Co. setzen REZEPT_NUR. Ohne Angabe laufen alle Rezepte.
_rz_gelaufen=0
for _rz in "${REZEPT_DIR}"/*/; do
  _rz="${_rz%/}"
  _app="$(basename "$_rz")"
  [[ -r "${_rz}/rezept.conf" ]] || continue
  if [[ -n "${REZEPT_NUR:-}" ]]; then
    case ",${REZEPT_NUR}," in *",${_app},"*) : ;; *) continue ;; esac
  fi
  if [[ -n "${REZEPT_OHNE:-}" ]]; then
    case ",${REZEPT_OHNE}," in *",${_app},"*) continue ;; esac
  fi

  _name="$(rezept_feld "$_rz" name)"; _name="${_name:-$_app}"

  # Installationen finden. Marker, Bestaetigung, Kopienfilter und
  # Selbstausschluss macht der Rahmen — einheitlich fuer jedes Rezept.
  _roh="$(rezept_installationen "$_rz")"
  REZEPT_KOPIEN=$(printf '%s\n' "$_roh" | sed -n 's/^KOPIEN=//p' | head -1)
  _inst=$(printf '%s\n' "$_roh" | grep -v '^KOPIEN=' | grep -vE '^$' || true)

  if [[ -z "$_inst" ]]; then
    # Kein Befund, aber auch kein Schweigen: dass ein Rezept lief und nichts
    # fand, ist eine Aussage. Dass es gar nicht lief, waere eine andere.
    ok "${_name}: keine Installation im Prüfumfang"
    continue
  fi
  _rz_gelaufen=$((_rz_gelaufen + 1))

  _n=$(printf '%s\n' "$_inst" | grep -c . || true)
  h2 "12r.${_rz_gelaufen} ${_name}"
  info "Installationen: ${_n}"
  code "$_inst"
  # Sicherungskopien einheitlich als Warnung — die Begruendung galt immer schon
  # fuer alle Anwendungen: eine Sicherung mit Schadcode stellt ihn beim
  # Zurueckspielen wieder her.
  [[ "${REZEPT_KOPIEN:-0}" -gt 0 ]] && \
    warn "${_name}: ${REZEPT_KOPIEN} Sicherungskopie(n) nicht geprüft — sie werden nicht ausgeliefert, würden Schadcode beim Zurückspielen aber wiederherstellen"

  # Haken laden, falls vorhanden. Erst hier, damit ein Rezept ohne gefundene
  # Installation gar keinen Code ausfuehrt.
  # shellcheck disable=SC1090
  [[ -r "${_rz}/rezept.sh" ]] && source "${_rz}/rezept.sh"

  _werkzeug="$(rezept_feld "$_rz" werkzeug)"
  _probe="$(rezept_feld "$_rz" werkzeug_probe)"

  while IFS= read -r REZ_PFAD; do
    [[ -n "$REZ_PFAD" ]] || continue
    REZ_KURZ="${REZ_PFAD#"$VHOSTS_DIR"/}"
    h2 "12r.${_rz_gelaufen}.x ${REZ_KURZ}"

    # Fassung nennen, wo die Deklaration sagt, wie sie zu lesen ist.
    _vd="$(rezept_feld "$_rz" version_datei)"
    _vr="$(rezept_feld "$_rz" version_regex)"
    if [[ -n "$_vd" && -n "$_vr" && -f "${REZ_PFAD}/${_vd}" ]]; then
      _ver=$(grep -oE "$_vr" "${REZ_PFAD}/${_vd}" 2>/dev/null \
             | grep -oE '[0-9]+(, *[0-9]+)*' | tr -d ' ' | tr ',' '.' | head -1)
      info "Fassung: ${_ver:-unbekannt}"
    fi

    # Signaturen: rein dateibasiert, brauchen kein Werkzeug.
    rezept_signaturen "$_app" "$_rz" "$REZ_PFAD" "$REZ_KURZ"
    # Abgleich gegen bekannte Schwachstellen. Steht hier und nicht unten, weil
    # er rein dateibasiert arbeitet: Fassungen kommen aus Kopfzeilen, der
    # Bestand liegt offline im Rezept. Eine Instanz, deren Werkzeug fehlt,
    # bekommt so trotzdem eine Aussage zur Angreifbarkeit.
    #
    # lib/rezepte.sh nennt rezept_version seit der ersten Fassung als Haken,
    # aufgerufen wurde er nie — ein Haken, den kein Rezept nutzen konnte.
    declare -F rezept_version >/dev/null && rezept_version
    # Kampagnenspezifisches ebenso.
    declare -F rezept_sonder >/dev/null && rezept_sonder

    # Alles Weitere braucht das Werkzeug der Anwendung. Der Rahmen zieht die
    # Probe, damit kein Rezept sie vergessen kann.
    if [[ -n "$_werkzeug" ]]; then
      REZ_PHP=$(command -v php 2>/dev/null || ls /opt/plesk/php/*/bin/php 2>/dev/null | sort -V | tail -1)
      _own=$(datei_meta "$REZ_PFAD" eigner); _own="${_own%%:*}"
      # Zwei Arten von Werkzeug: mitgeliefert (occ liegt IN der Installation)
      # oder extern (wp-cli liegt im PATH). Ohne die Unterscheidung suchte der
      # Rahmen 'wp' im Webspace des Kunden und fand nichts.
      if [[ "$(rezept_feld "$_rz" werkzeug_extern)" == "ja" ]]; then
        REZ_WERKZEUG="$(command -v "$_werkzeug" 2>/dev/null || true)"
      else
        REZ_WERKZEUG="${REZ_PFAD}/${_werkzeug}"
        [[ -f "$REZ_WERKZEUG" ]] || REZ_WERKZEUG=""
      fi
      if [[ -z "$_own" || "$_own" == "?" || -z "$REZ_PHP" || -z "$REZ_WERKZEUG" ]]; then
        befund_melden "$_app" erkennung unklar \
          "${REZ_KURZ}: ${_werkzeug} nicht ausführbar (Werkzeug, PHP oder Eigentümer fehlt) — Instanz nur dateibasiert geprüft" "$REZ_PFAD" web
        continue
      fi
      # shellcheck disable=SC2086
      OCC() { als_eigentuemer "$_own" "$REZ_PHP" -d memory_limit=1024M "$REZ_WERKZEUG" "$@" 2>/dev/null; }
      # shellcheck disable=SC2086
      rezept_werkzeug_bereit "$_app" "$REZ_KURZ" als_eigentuemer "$_own" "$REZ_PHP" -d memory_limit=1024M "$REZ_WERKZEUG" $_probe || continue
    fi

    declare -F rezept_kern   >/dev/null && rezept_kern
    declare -F rezept_konfig >/dev/null && rezept_konfig
    declare -F rezept_db     >/dev/null && rezept_db
  done <<< "$_inst"

  declare -F rezept_verdikt >/dev/null && rezept_verdikt
  # Haken zurueckziehen, damit sie nicht ins naechste Rezept durchschlagen.
  unset -f rezept_version rezept_kern rezept_konfig rezept_db rezept_sonder rezept_verdikt 2>/dev/null || true
done

[[ "$_rz_gelaufen" -eq 0 ]] && info "Keine der bekannten Anwendungen im Prüfumfang gefunden"
fi
