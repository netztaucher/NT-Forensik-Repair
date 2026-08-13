# shellcheck shell=bash
# NT-Forensik — Abschnitt 13e: Infektions-Ursachensuche
#
# @nummer:  13e
# @titel:   Zeitachse, Ausbreitungsweg und Reichweite der Quellen
# @frage:   Wann begann es, wie breitete es sich aus, und wie weit reicht der Beleg?
# @kosten:  gering — kein Baumdurchlauf, nur stat() auf bereits belastete Dateien
# @ebene:   website
#
# ------------------------------------------------------------
# WARUM DIESER ABSCHNITT IN DIE UNTERSUCHUNG GEHOERT UND NICHT IN DIE BEREINIGUNG
#
# `mv` zerstoert die ctime. Die Bereinigung nimmt Dateien in Quarantaene — laeuft
# sie zuerst, ist die Kausalkette weg, und zwar unwiederbringlich. Die ctime ist
# der einzige Zeitstempel, den ein Angreifer ohne Schreibrechte am Datentraeger
# nicht faelschen kann; im Anlassfall vom 12.08.2026 ruhte die gesamte
# Ursachenanalyse auf ihr, weil die mtime bei 59.472 Dateien gefaelscht war.
#
# Zweiter Grund: die Bereinigung ist lizenzpflichtig und liegt verschluesselt im
# Paket. Eine forensische Ursachenanalyse gehoert in den freien, nachvollziehbaren
# Teil — sonst kann ein Kunde den Befund nicht pruefen.
#
# ------------------------------------------------------------
# WARUM NACH 13d
#
# 13e liest die Listen, die 13d bereits entlastet hat. Eine Zeitachse aus
# unveraenderten Kern-Dateien waere keine Chronologie eines Angriffs, sondern
# eine des letzten WordPress-Updates.
#
# ------------------------------------------------------------
# WAS DIESER ABSCHNITT NICHT BEHAUPTEN DARF
#
# "Aeltester Nachweis" ist nicht "Infektionsbeginn". Im Anlassfall lag der
# aelteste harte Beleg (24.07. 04:22:05, mtime der vergifteten robots.txt) VOR
# jedem verfuegbaren Zugriffsprotokoll — die Web-Logs reichten nur bis zum
# 4. August, und Google hatte die Doorway-Seiten schon im Index, bevor sie
# beginnen. Abschnitt 13e.4 weist die Reichweite seiner Quellen deshalb
# ausdruecklich aus. Ohne das wird aus einer Protokollgrenze ein Datum, auf das
# sich jemand verlaesst.
# ============================================================

h2 "13e Infektions-Ursachensuche"

# ── Zeitangaben portabel ─────────────────────────────────────
# GNU und BSD teilen sich keine einzige dieser Formen. `date -d` ist GNU-only
# und wurde in diesem Werkzeug schon einmal zur stillen Fehlerquelle (awk
# systime()); hier steht der Fallback von Anfang an.
_u_epoche_str() {   # Sekunden → "YYYY-MM-DD HH:MM:SS"
  date -d "@$1" '+%Y-%m-%d %H:%M:%S' 2>/dev/null \
    || date -r "$1" '+%Y-%m-%d %H:%M:%S' 2>/dev/null \
    || printf '%s' "$1"
}
_u_apache_epoche() { # "24/Jul/2026:04:22:05" → Sekunden, oder leer
  local _s="$1"
  date -d "$(printf '%s' "$_s" | tr '/:' '  ' | awk '{print $1" "$2" "$3" "$4":"$5":"$6}')" +%s 2>/dev/null \
    || date -j -f '%d/%b/%Y:%H:%M:%S' "$_s" +%s 2>/dev/null \
    || true
}
_u_dauer() {        # Sekunden → lesbare Spanne
  local _s="$1"
  if   [[ "$_s" -lt 60    ]]; then printf '%s s' "$_s"
  elif [[ "$_s" -lt 3600  ]]; then printf '%s min' "$(( _s / 60 ))"
  elif [[ "$_s" -lt 86400 ]]; then printf '%s h %s min' "$(( _s / 3600 ))" "$(( (_s % 3600) / 60 ))"
  else printf '%s Tage %s h' "$(( _s / 86400 ))" "$(( (_s % 86400) / 3600 ))"
  fi
}

# ── Welche Dateien auf die Achse gehoeren ────────────────────
# Nur BELASTENDE Listen. Die Sichtungsstufen (REVIEW_DETAIL, MED_DETAIL) bleiben
# draussen: eine Chronologie aus Verdachtsfaellen datiert einen Angriff auf den
# Tag, an dem irgendein Framework installiert wurde.
#
# Die Listen haben unterschiedliche Formen (Bloecke "=== pfad ===", nackte
# Pfade, Pfad plus Text). _u_pfade nimmt nur, was es sicher erkennt, und prueft
# jeden Treffer gegen das Dateisystem. Was es nicht erkennt, faellt weg — und
# genau deshalb steht unten die Zahl der eingesammelten Pfade im Bericht: ein
# Sammler, der stillschweigend nichts findet, sieht aus wie ein sauberer Server.
_u_pfade() {
  local _l _p
  while IFS= read -r _l; do
    if [[ "$_l" == "=== "*" ===" ]]; then
      _p="${_l#=== }"; _p="${_p% ===}"
    elif [[ "$_l" == /* ]]; then
      _p="${_l%%$'\t'*}"          # Pfad<TAB>Rest
      _p="${_p%%[[:space:]]*}"    # Pfad Rest
      _p="${_p%:}"
    else
      continue
    fi
    [[ -f "$_p" ]] && printf '%s\n' "$_p"
  done
}

U_KANDIDATEN=$(
  printf '%s\n' \
    "${DROPPER_DETAIL:-}" "${WEBSHELL_NAMEN:-}" "${CORE_SNE:-}" \
    "${CORE_INJECT_HITS:-}" "${DISGUISED_PAYLOADS:-}" "${SIGNATUR_TREFFER:-}" \
    "${NC_MALWARE:-}" "${JOOMLA_MALWARE:-}" "${ZEITANKER:-}" \
  | _u_pfade | LC_ALL=C sort -u
)
U_ANZAHL=0
[[ -n "$U_KANDIDATEN" ]] && U_ANZAHL=$(printf '%s\n' "$U_KANDIDATEN" | grep -c . || echo 0)

# ============================================================
h2 "13e.1 Zeitachse der belasteten Dateien"
# Dieselben Daten, die 7.14 als Spurenverwischung deutet, ergeben nach ctime
# sortiert die AUSBREITUNGSCHRONOLOGIE: welche Seite zuerst, wie schnell danach
# die naechste. Im Anlassfall trennte das die beiden Wellen sauber — 8 Seiten in
# 3 Stunden, dann 14 Tage Pause, dann 15 Seiten in 13 Minuten — und zeigte, dass
# der erste Schreibvorgang 19 Tage vor dem vermuteten Datum lag.

U_ACHSE=""
U_TAB=""
if [[ "$U_ANZAHL" -gt 0 ]]; then
  while IFS= read -r _p; do
    [[ -n "$_p" ]] || continue
    _c=$(datei_epoche "$_p" ctime 2>/dev/null || echo 0)
    _m=$(datei_epoche "$_p" mtime 2>/dev/null || echo 0)
    [[ "${_c:-0}" -gt 0 ]] || continue
    U_TAB+="${_c}"$'\t'"${_m:-0}"$'\t'"${_p}"$'\n'
  done <<< "$U_KANDIDATEN"
  U_TAB=$(printf '%s' "$U_TAB" | LC_ALL=C sort -n)
fi

if [[ -z "$U_TAB" ]]; then
  ok "Keine belasteten Dateien — keine Zeitachse zu bilden"
else
  U_ZEILEN=$(printf '%s\n' "$U_TAB" | grep -c . || echo 0)
  _u_vorher=0
  _u_n=0
  U_WELLEN=1
  U_ERST=""; U_LETZT=""
  while IFS=$'\t' read -r _c _m _p; do
    [[ -n "$_p" ]] || continue
    _u_n=$(( _u_n + 1 ))
    [[ -z "$U_ERST" ]] && U_ERST="$_c"
    U_LETZT="$_c"
    # Wellentrennung: eine Pause oberhalb der Schwelle bekommt eine eigene Zeile
    # mit der Spanne. Das ist der Unterschied zwischen "23 Dateien" und "zwei
    # Vorgaengen im Abstand von 14 Tagen".
    if [[ "$_u_vorher" -gt 0 && $(( _c - _u_vorher )) -ge "${URSACHE_WELLE_SEK:-3600}" ]]; then
      U_WELLEN=$(( U_WELLEN + 1 ))
      [[ "$_u_n" -le "${URSACHE_ACHSE_MAX:-60}" ]] && \
        U_ACHSE+="    ── Pause: $(_u_dauer $(( _c - _u_vorher ))) ──"$'\n'
    fi
    _u_vorher="$_c"
    [[ "$_u_n" -le "${URSACHE_ACHSE_MAX:-60}" ]] || continue
    U_ACHSE+="$(_u_epoche_str "$_c")  ${_p}"$'\n'
  done <<< "$U_TAB"

  # Kein stilles Abschneiden. Was ueber die Grenze faellt, wird benannt.
  if [[ "$U_ZEILEN" -gt "${URSACHE_ACHSE_MAX:-60}" ]]; then
    U_ACHSE+="    … $(( U_ZEILEN - ${URSACHE_ACHSE_MAX:-60} )) weitere Eintraege — vollstaendig im Beleg"$'\n'
  fi

  info "Aeltester Schreibvorgang: $(_u_epoche_str "$U_ERST") — juengster: $(_u_epoche_str "$U_LETZT")"
  info "${U_ZEILEN} belastete Datei(en), verteilt auf ${U_WELLEN} Vorgang/Vorgaenge (Trennung ab $(_u_dauer "${URSACHE_WELLE_SEK:-3600}") Pause)"
  code "$U_ACHSE"
  # Der Beleg traegt IMMER alles, unabhaengig von URSACHE_ACHSE_MAX.
  evidence "ursache_zeitachse" "$(
    while IFS=$'\t' read -r _c _m _p; do
      [[ -n "$_p" ]] || continue
      printf 'ctime %s | mtime %s | %s\n' \
        "$(_u_epoche_str "$_c")" "$(_u_epoche_str "${_m:-0}")" "$_p"
    done <<< "$U_TAB"
  )" kunde
fi

# ============================================================
h2 "13e.2 ctime gegen mtime — beide Richtungen"
# Abschnitt 7.3 kennt nur EINE Deutung: "mtime aelter als ctime → Rueckdatierung
# moeglich". Der Anlassfall brauchte die andere:
#
#   robots.txt     mtime 24.07. 04:22:05   ctime identisch
#                  → Angreifer, seither unberuehrt → BELASTBARER ZEITPUNKT
#   wp-config.php  mtime 24.07. 04:22:01   ctime 07.08. 13:38:49
#                  → Inode spaeter geaendert; `cp -p` nahm die alte mtime mit
#                  → EIGENE Gegenmassnahme, kein Angreiferzugriff
#
# Ohne diese Unterscheidung haette die eigene Rotation wie ein zweiter Einbruch
# ausgesehen. Und umgekehrt: ein Lauf auf web43 meldete "439 Tage
# Rueckdatierung" an einer unveraenderten Kern-Datei — ein Artefakt der
# Wiederherstellung.
U_DEUTUNG=""
U_ANKER=0; U_INODE=0; U_ZUKUNFT=0
if [[ -n "$U_TAB" ]]; then
  while IFS=$'\t' read -r _c _m _p; do
    [[ -n "$_p" && "${_m:-0}" -gt 0 ]] || continue
    _d=$(( _c - _m ))
    if   [[ "$_d" -lt -2 ]]; then
      # mtime liegt HINTER der ctime. Normal unmoeglich: jedes Setzen der mtime
      # zieht die ctime mit. Also wurde die mtime in die Zukunft gesetzt.
      U_ZUKUNFT=$(( U_ZUKUNFT + 1 ))
      U_DEUTUNG+="ZUKUNFT   $(_u_epoche_str "$_m")  mtime liegt $(_u_dauer $(( -_d ))) NACH der ctime — vorwaerts datiert   ${_p}"$'\n'
    elif [[ "$_d" -le 2 ]]; then
      U_ANKER=$(( U_ANKER + 1 ))
      U_DEUTUNG+="ANKER     $(_u_epoche_str "$_m")  seit dem Schreiben unberuehrt — belastbarer Zeitpunkt              ${_p}"$'\n'
    elif [[ "$_d" -ge "${ZEITSTEMPEL_ZUSATZ_SEK:-2592000}" ]]; then
      U_INODE=$(( U_INODE + 1 ))
      U_DEUTUNG+="INODE     $(_u_epoche_str "$_m")  Inode $(_u_dauer "$_d") spaeter geaendert — mtime stammt nicht von diesem Vorgang   ${_p}"$'\n'
    fi
  done <<< "$U_TAB"
fi

if [[ -z "$U_DEUTUNG" ]]; then
  info "Keine Datei mit auswertbarem Zeitstempelverhaeltnis"
else
  info "${U_ANKER} Anker (belastbarer Zeitpunkt), ${U_INODE} mit spaeter geaenderter Inode, ${U_ZUKUNFT} vorwaerts datiert"
  # Ein vorwaerts datierter Zeitstempel ist kein Nebenbefund: er ist der
  # Versuch, eine Datei aus jeder nach Datum sortierten Liste herauszuhalten.
  [[ "$U_ZUKUNFT" -gt 0 ]] && \
    warn "${U_ZUKUNFT} belastete Datei(en) tragen eine in die Zukunft gesetzte mtime — jede nach Datum sortierte Sichtung uebersieht sie" web
  code "$U_DEUTUNG"
  evidence "ursache_zeitstempel_deutung" "$U_DEUTUNG" kunde
fi

# ============================================================
h2 "13e.3 Reichweite: geteilter Systemnutzer"
# Liegen mehrere vhosts unter demselben Systembenutzer, erreicht EINE Shell sie
# alle — ohne HTTP, ueber das Dateisystem. Im Anlassfall erklaerte das, warum
# zwischen dem 404 und dem 200 einer Doorway-Seite kein schreibender Aufruf
# steht: die Datei kam nicht ueber das Netz.
#
# Das ist bei Plesk KEINE Fehlkonfiguration — ein Abo hat einen Benutzer, dem
# alle seine vhosts gehoeren. Der Befund ist deshalb nicht "geteilter Benutzer",
# sondern die REICHWEITE: welche weiteren vhosts ein Fund miterfasst. Genau das
# bestimmt den Umfang der Bereinigung, und genau das wurde im Anlassfall von
# Hand ermittelt.
#
# WIE WEIT DER LAUF UEBERHAUPT SEHEN DARF
#
# scope_vhost_dirs liefert bei --path GENAU EINEN Pfad. Die Frage "teilt dieser
# vhost seinen Benutzer mit einem anderen?" ist dann nicht mit Nein zu
# beantworten, sondern gar nicht — es gibt keinen zweiten Kandidaten im Blick.
# Eine gruene Zeile waere hier keine Entwarnung, sondern ein Ausfall, der wie
# ein Ergebnis aussieht. Genau diese Verwechslung hat dieses Werkzeug schon
# siebenmal gekostet; sie steht deshalb VOR der Messung.
U_REICHWEITE=""
U_SICHTFELD=$(scope_vhost_dirs | grep -c . || echo 0)
if [[ -n "$U_TAB" ]]; then
  # Systemnutzer der belasteten Dateien einsammeln.
  U_BETROFFEN=$(
    while IFS=$'\t' read -r _c _m _p; do
      [[ -n "$_p" ]] || continue
      _o=$(datei_meta "$_p" eigner 2>/dev/null || true)
      [[ -n "$_o" && "$_o" != "?" ]] && printf '%s\n' "${_o%%:*}"
    done <<< "$U_TAB" | LC_ALL=C sort -u
  )
  while IFS= read -r _nutzer; do
    [[ -n "$_nutzer" ]] || continue
    _liste=$(
      while IFS= read -r _vd; do
        [[ -d "$_vd" ]] || continue
        _vo=$(datei_meta "$_vd" eigner 2>/dev/null || true)
        [[ "${_vo%%:*}" == "$_nutzer" ]] && printf '%s\n' "$_vd"
      done < <(scope_vhost_dirs)
    )
    _n=$(printf '%s\n' "$_liste" | grep -c . || echo 0)
    [[ "$_n" -gt 1 ]] || continue
    U_REICHWEITE+="Systemnutzer ${_nutzer} — eine Shell hier erreicht ${_n} vhost(s):"$'\n'
    U_REICHWEITE+=$(printf '%s\n' "$_liste" | sed 's/^/    /')$'\n'
  done <<< "$U_BETROFFEN"
fi

if [[ -z "$U_REICHWEITE" ]]; then
  if [[ -z "$U_TAB" ]]; then
    ok "Keine belasteten Dateien — keine Reichweite zu bestimmen"
  elif [[ "$U_SICHTFELD" -lt 2 ]]; then
    unklar "Dieser Lauf sieht nur ${U_SICHTFELD} vhost-Verzeichnis(se) — ob der Systemnutzer weitere besitzt, ist hier nicht feststellbar. Mit --global messbar"
  else
    ok "Kein belasteter vhost teilt seinen Systemnutzer mit einem der ${U_SICHTFELD} geprüften"
  fi
else
  warn "Belastete Dateien liegen unter Systemnutzern, denen weitere vhosts gehoeren — der Bereinigungsumfang ist groesser als die Fundliste" web
  code "$U_REICHWEITE"
  evidence "ursache_reichweite_systemnutzer" "$U_REICHWEITE" kunde
fi

# ============================================================
h2 "13e.4 Reichweite der Quellen"
# DER WICHTIGSTE ABSCHNITT, UND DER, DER AM LEICHTESTEN WEGGELASSEN WIRD.
#
# Der Anlassfall endete mit einer offenen Frage: der Weg vom 24. Juli lag VOR
# jedem verfuegbaren Zugriffsprotokoll. Die Web-Logs reichten bis zum 4. August;
# Google hatte die Doorway-Seiten schon davor im Index. "Aeltester Nachweis" ist
# damit nicht "Infektionsbeginn" — und wer das nicht dazuschreibt, macht aus
# einer Protokollgrenze ein Datum, auf das sich jemand verlaesst.
#
# Bewusst wird hier KEINE automatische Zahl fuer den "Infektionsbeginn"
# erzeugt. Der Abschnitt sagt, wie weit die Quellen reichen, und ueberlaesst den
# Schluss dem Pruefer.
U_QUELLEN=""
if [[ -n "$U_TAB" ]]; then
  # Nur die vhosts, in denen tatsaechlich etwas liegt. Ein Protokollfenster ueber
  # 475 vhosts zu bestimmen waere teuer und ohne Aussage.
  #
  # Der vhost wird vom Fund aus nach OBEN gesucht, nicht ueber scope_vhost_dirs.
  # Der Unterschied ist nicht kosmetisch: bei --path liefert scope_vhost_dirs
  # genau die Scan-Wurzel, und die Suche landete dann bei <wurzel>/logs — einem
  # Verzeichnis, das es in keinem Plesk-Layout gibt. Der Abschnitt meldete
  # daraufhin dauerhaft "kein Protokoll", ohne je eines gesucht zu haben.
  #
  # Plesk legt logs/ NEBEN httpdocs/, also im vhost-Verzeichnis. Genau danach
  # wird gesucht: vom Fund aus aufwaerts, hoechstens sechs Ebenen — tiefer
  # verschachtelt liegt kein vhost, und ohne Grenze liefe die Suche bis /.
  U_VHOSTS=$(
    while IFS=$'\t' read -r _c _m _p; do
      [[ -n "$_p" ]] || continue
      _d=$(dirname "$_p"); _i=0
      while [[ "$_i" -lt 6 && "$_d" != "/" && -n "$_d" ]]; do
        [[ -d "${_d}/logs" ]] && { printf '%s\n' "$_d"; break; }
        _d=$(dirname "$_d"); _i=$(( _i + 1 ))
      done
    done <<< "$U_TAB" | LC_ALL=C sort -u | head -n "${URSACHE_LOGS_MAX:-20}"
  )
  while IFS= read -r _vd; do
    [[ -d "${_vd}/logs" ]] || continue
    _erst=""; _gz=0
    for _lf in "${_vd}"/logs/*access*; do
      [[ -f "$_lf" ]] || continue
      case "$_lf" in *.gz|*.bz2|*.xz) _gz=$(( _gz + 1 )); continue ;; esac
      _z=$(head -1 "$_lf" 2>/dev/null | grep -oE '\[[0-9]{2}/[A-Za-z]{3}/[0-9]{4}:[0-9:]{8}' | tr -d '[' || true)
      [[ -n "$_z" ]] || continue
      _e=$(_u_apache_epoche "$_z")
      [[ -n "$_e" ]] || continue
      [[ -z "$_erst" || "$_e" -lt "$_erst" ]] && _erst="$_e"
    done
    [[ -n "$_erst" || "$_gz" -gt 0 ]] || continue
    U_QUELLEN+="${_vd}"$'\n'
    [[ -n "$_erst" ]] && U_QUELLEN+="    Zugriffsprotokoll reicht zurueck bis $(_u_epoche_str "$_erst")"$'\n'
    [[ "$_gz" -gt 0 ]] && U_QUELLEN+="    ${_gz} aeltere(s) Protokoll(e) liegen komprimiert vor — nicht ausgewertet"$'\n'
    # Der eigentliche Satz: liegt der aelteste Beleg VOR dem Protokollfenster,
    # kann der Weg nicht aus den Logs kommen.
    if [[ -n "$_erst" && "$U_ERST" -lt "$_erst" ]]; then
      U_QUELLEN+="    ⚠ Der aelteste Beleg ($(_u_epoche_str "$U_ERST")) liegt $(_u_dauer $(( _erst - U_ERST ))) VOR dem Protokollfenster — der Einstiegsweg ist hier nicht mehr nachweisbar"$'\n'
    fi
  done <<< "$U_VHOSTS"
fi

info "Aeltester Nachweis ist nicht Infektionsbeginn: er ist die aelteste ueberlebende Spur. Aeltere Vorgaenge koennen ueberschrieben, rotiert oder nie protokolliert worden sein."
if [[ -n "$U_QUELLEN" ]]; then
  code "$U_QUELLEN"
  evidence "ursache_quellenlage" "$U_QUELLEN" kunde
  printf '%s' "$U_QUELLEN" | grep -q '⚠' && \
    unklar "Der aelteste Beleg liegt vor dem verfuegbaren Protokollfenster — der Einstiegsweg laesst sich aus den vorhandenen Quellen nicht bestimmen"
elif [[ -n "$U_TAB" ]]; then
  unklar "Kein auswertbares Zugriffsprotokoll neben den belasteten vhosts — die Reichweite der Quellen ist unbestimmt"
fi
