# @nummer:  12c
# @titel:   Nextcloud-Härtungsstand
# @frage:   Ist die Nextcloud so eingerichtet, dass ein Einbruch schwer und ein Zugang widerrufbar ist?
# @kosten:  gering — occ und ein HTTP-Abruf, etwa 15 s je Installation
# @ebene:   website
#
# Abschnitt 12b fragt: ist diese Instanz uebernommen? Dieser hier fragt: wie
# leicht waere es? Er gilt fuer JEDE Nextcloud, unabhaengig von einer Kampagne,
# und er aendert nichts — er misst nur. Die Gegenstuecke zum Aendern liegen im
# lizenzpflichtigen Teil (lib/haerten_nextcloud.sh).
#
# Der Abschnitt pruefen vier Dinge, die in dieser Reihenfolge ueber den Schaden
# entscheiden:
#
#   1. Ist das Datenverzeichnis ueber den Browser erreichbar? Dann sind alle
#      Dateien aller Nutzer oeffentlich, ohne dass irgendetwas kompromittiert
#      sein muesste. Das wird hier nicht abgeleitet, sondern abgerufen.
#   2. Wie viele App-Passwoerter bestehen? Sie sind der einzige Zugang, den ein
#      Passwortwechsel NICHT schliesst. Wer nach einem Vorfall nur Passwoerter
#      neu setzt, laesst genau diese offen.
#   3. Wie viele Konten haben Administrationsrechte?
#   4. Steht die Grundkonfiguration so, dass Zugriffe ueberhaupt nachvollziehbar
#      sind (Protokollstufe, HTTPS-Erzwingung, vertrauenswuerdige Domains)?

h1 "12c. NEXTCLOUD-HÄRTUNGSSTAND"

# Sicherungskopien sind vollstaendige Nextcloud-Baeume mit occ und version.php
# und damit von einer laufenden Instanz nicht zu unterscheiden — ausser am Pfad.
# Der eingebaute Updater legt sie unter updater-<id>/backups/ ab. Ohne diesen
# Filter meldet der Abschnitt jede Sicherung als eigene Installation und
# vervielfacht damit jeden Befund; gemessen am 07.08.2026 auf k42: drei
# vermeintliche Instanzen, alle drei Kopien derselben.
NCH_KOPIE='/updater-[a-z0-9]+/backups/|/[a-z0-9_-]*backups?/|/\.?(quarantaene|quarantine|old|bak)/'

NCH_INSTALLS=""; NCH_KOPIEN=0
while IFS= read -r _occ; do
  _d="$(dirname "$_occ")"
  [[ -f "${_d}/version.php" && -d "${_d}/apps" ]] || continue
  if printf '%s' "$_d" | grep -qE "$NCH_KOPIE"; then
    NCH_KOPIEN=$((NCH_KOPIEN + 1)); continue
  fi
  NCH_INSTALLS+="${_d}"$'\n'
done < <(find "${SCAN_PATHS[@]}" -maxdepth 6 -name occ -type f 2>/dev/null | nf_strip_self)
NCH_INSTALLS=$(printf '%s\n' "$NCH_INSTALLS" | grep -vE '^$' | sort -u || true)
[[ "$NCH_KOPIEN" -gt 0 ]] && info "${NCH_KOPIEN} Sicherungskopie(n) übersprungen — sie werden nicht ausgeliefert und sind kein eigener Härtungsgegenstand"

if [[ -z "$NCH_INSTALLS" ]]; then
  ok "Keine Nextcloud-Installation im Prüfumfang"
else

_php_bin=$(command -v php 2>/dev/null || ls /opt/plesk/php/*/bin/php 2>/dev/null | sort -V | tail -1)

while IFS= read -r NCDIR; do
  [[ -n "$NCDIR" ]] || continue
  _kurz="${NCDIR#"$VHOSTS_DIR"/}"
  h2 "12c.1 ${_kurz}"

  _own=$(stat -c %U "$NCDIR" 2>/dev/null || echo "")
  if [[ -z "$_own" || -z "$_php_bin" ]]; then
    info "${_kurz}: occ nicht ausführbar — Härtungsstand nicht messbar"
    continue
  fi
  # occ immer als Eigentuemer. Als root erzeugt es Cache-Dateien, die der
  # Instanz danach gehoeren muessten und es nicht tun.
  _occ() { sudo -u "$_own" "$_php_bin" -d memory_limit=1024M "${NCDIR}/occ" "$@" 2>/dev/null; }

  # occ antwortet nicht immer mit dem gefragten Wert. Passt die PHP-Fassung
  # nicht zur Nextcloud-Fassung, gibt es statt eines Werts eine HTML-Meldung
  # ("This version of Nextcloud requires at least PHP 8.2<br/>…") — und zwar
  # auf STDOUT und mit Rueckgabewert 0. Ohne diese Sperre landet dieser Satz
  # als Datenverzeichnis, als loglevel und als Protokoll im Kundenbericht.
  # Gemessen am 07.08.2026 auf k42.
  _probe=$(_occ status --output=json || true)
  if ! printf '%s' "$_probe" | python3 -c "import json,sys;json.load(sys.stdin)" 2>/dev/null; then
    _grund=$(printf '%s' "$_probe" | sed 's/<br\/*>/ /g' | tr -d '\n' | cut -c1-160)
    warn "${_kurz}: occ liefert keine verwertbare Antwort — Härtungsstand NICHT gemessen${_grund:+ (${_grund})}"
    NC_HAERTUNG+="${_kurz}: Härtungsstand nicht messbar (occ nicht lauffähig)"$'\n'
    continue
  fi

  # ── 1. Datenverzeichnis ─────────────────────────────────────
  _data=$(_occ config:system:get datadirectory | tr -d '\r' || true)
  if [[ -z "$_data" ]]; then
    info "${_kurz}: datadirectory nicht auslesbar"
  elif [[ "$_data" == "${NCDIR}"* ]]; then
    # Innerhalb des Webroots. Ob das wirklich ausliefert, wird gemessen, nicht
    # vermutet: eine .htaccess kann greifen — oder eben nicht.
    _rel="${_data#"${NCDIR}"/}"
    _url=""
    _dom=$(_occ config:system:get trusted_domains 0 | tr -d '\r' || true)
    [[ -n "$_dom" ]] && _url="https://${_dom}/${_rel}/.ocdata"
    if [[ -n "$_url" ]]; then
      _code=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 12 "$_url" 2>/dev/null || echo "000")
      if [[ "$_code" == "200" ]]; then
        crit "${_kurz}: Datenverzeichnis ist über das Netz abrufbar (HTTP 200 auf ${_url}) — sämtliche Nutzerdateien sind öffentlich" web
        NC_HAERTUNG+="${_kurz}: Datenverzeichnis öffentlich abrufbar (HTTP 200)"$'\n'
      elif [[ "$_code" == "000" ]]; then
        warn "${_kurz}: Datenverzeichnis liegt im Webroot (${_data}); Abruf nicht möglich — Schutz unbelegt"
        NC_HAERTUNG+="${_kurz}: Datenverzeichnis im Webroot, Schutz nicht messbar"$'\n'
      else
        warn "${_kurz}: Datenverzeichnis liegt im Webroot (${_data}), wird aber gesperrt (HTTP ${_code}) — der Schutz hängt an einer einzigen .htaccess"
        NC_HAERTUNG+="${_kurz}: Datenverzeichnis im Webroot, nur durch .htaccess geschützt"$'\n'
      fi
    else
      warn "${_kurz}: Datenverzeichnis liegt im Webroot (${_data})"
      NC_HAERTUNG+="${_kurz}: Datenverzeichnis im Webroot"$'\n'
    fi
  else
    ok "${_kurz}: Datenverzeichnis außerhalb des Webroots (${_data})"
  fi

  # ── 2. App-Passwörter ───────────────────────────────────────
  # Der Zugang, den kein Passwortwechsel schliesst. Die Zahl allein ist kein
  # Befund — sie wird zum Befund, sobald ein Vorfall vorliegt.
  _tok=$(_occ user:list --output=json \
         | python3 -c "import json,sys;print('\n'.join(json.load(sys.stdin)))" 2>/dev/null || true)
  if [[ -n "$_tok" ]]; then
    _n_user=$(printf '%s\n' "$_tok" | grep -c . || true)
    _n_adm=$(_occ group:list --output=json \
             | python3 -c "import json,sys;print(len(json.load(sys.stdin).get('admin',[])))" 2>/dev/null || echo "?")
    info "${_kurz}: ${_n_user} Konten, davon ${_n_adm} mit Administrationsrechten"
    if [[ "$_n_adm" =~ ^[0-9]+$ && "$_n_adm" -gt 2 ]]; then
      warn "${_kurz}: ${_n_adm} Administratorkonten — jedes davon ist ein vollwertiger Zugang"
      NC_HAERTUNG+="${_kurz}: ${_n_adm} Administratorkonten"$'\n'
    fi
    info "${_kurz}: App-Passwörter überleben jeden Passwortwechsel. Nach einem Vorfall müssen sie eigens widerrufen werden (occ user:auth-tokens:delete <konto> --all)."
  fi

  # ── 3. Zwei-Faktor ──────────────────────────────────────────
  # twofactor_backupcodes ist ab Werk aktiv und ist KEIN zweiter Faktor: es
  # erzeugt nur Notfallcodes fuer den Fall, dass ein echter zweiter Faktor
  # eingerichtet ist. Wird die App mitgezaehlt, meldet der Abschnitt bei jeder
  # unveraenderten Nextcloud "Zwei-Faktor verfuegbar" — eine Entwarnung, die
  # nichts deckt. Gemessen am 07.08.2026: genau dieser Fall.
  _2fa=$(_occ app:list --output=json \
         | python3 -c "
import json,sys
d=json.load(sys.stdin).get('enabled',{})
print(','.join(k for k in d if k.startswith('twofactor_') and k != 'twofactor_backupcodes'))" 2>/dev/null || true)
  if [[ -n "$_2fa" ]]; then
    ok "${_kurz}: zweiter Faktor verfügbar (${_2fa})"
  else
    warn "${_kurz}: kein zweiter Faktor eingerichtet — ein erbeutetes Passwort genügt für den vollen Zugang (twofactor_backupcodes zählt nicht, das sind nur Notfallcodes)"
    NC_HAERTUNG+="${_kurz}: kein zweiter Faktor eingerichtet"$'\n'
  fi

  # ── 4. Grundkonfiguration ───────────────────────────────────
  # Wenige Werte, die nach einem Vorfall die Aufklaerung tragen — oder eben nicht.
  _loglvl=$(_occ config:system:get loglevel | tr -d '\r' || echo "")
  if [[ "$_loglvl" =~ ^[3-4]$ ]]; then
    warn "${_kurz}: loglevel steht auf ${_loglvl} (nur Fehler) — Anmeldungen und Zugriffe werden nicht protokolliert, ein Vorfall ist später nicht rekonstruierbar"
    NC_HAERTUNG+="${_kurz}: loglevel ${_loglvl} — zu grob für Nachvollziehbarkeit"$'\n'
  else
    ok "${_kurz}: loglevel ${_loglvl:-Vorgabe}"
  fi

  _proto=$(_occ config:system:get overwriteprotocol | tr -d '\r' || echo "")
  [[ "$_proto" == "https" ]] && ok "${_kurz}: overwriteprotocol https" \
    || info "${_kurz}: overwriteprotocol nicht auf https (${_proto:-nicht gesetzt}) — hinter einem Proxy führt das zu Mixed-Content und abbrechenden Clients"

  _td=$(_occ config:system:get trusted_domains | tr -d '\r' | grep -vE '^$' || true)
  _td_n=$(printf '%s\n' "$_td" | grep -c . || true)
  if [[ "$_td_n" -gt 3 ]]; then
    warn "${_kurz}: ${_td_n} vertrauenswürdige Domains eingetragen — jede erlaubt den Betrieb der Instanz unter dieser Adresse"
    code "$_td"
    NC_HAERTUNG+="${_kurz}: ${_td_n} trusted_domains"$'\n'
  else
    ok "${_kurz}: ${_td_n} vertrauenswürdige Domain(s)"
  fi

  # ── 5. Rechte auf der Konfiguration ─────────────────────────
  _cfg_r=$(stat -c '%a' "${NCDIR}/config/config.php" 2>/dev/null || echo "")
  if [[ -n "$_cfg_r" && ! "$_cfg_r" =~ ^(600|640|660)$ ]]; then
    warn "${_kurz}: config/config.php hat Rechte ${_cfg_r} — sie enthält Datenbankzugang und Instanz-Salt"
    NC_HAERTUNG+="${_kurz}: config.php mit Rechten ${_cfg_r}"$'\n'
  elif [[ -n "$_cfg_r" ]]; then
    ok "${_kurz}: config/config.php Rechte ${_cfg_r}"
  fi

  # ── 6. Fassung ──────────────────────────────────────────────
  # Keine Online-Abfrage: der Abschnitt soll auch ohne Netz laufen. Die Fassung
  # wird genannt, die Bewertung bleibt beim Betreiber.
  _ncv=$(_occ status --output=json \
         | python3 -c "import json,sys;print(json.load(sys.stdin).get('versionstring','?'))" 2>/dev/null || echo "?")
  info "${_kurz}: Nextcloud ${_ncv} — Stand gegen die Herstellerangabe abgleichen"

done <<< "$NCH_INSTALLS"

if [[ -z "$NC_HAERTUNG" ]]; then
  ok "Keine Härtungslücken gefunden"
else
  info "Die Härtungsbefunde sind Schwachstellen, keine Einbruchsbelege. Sie sagen, wie leicht ein Zugriff wäre — nicht, dass er stattgefunden hat."
fi
fi
