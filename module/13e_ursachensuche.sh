# shellcheck shell=bash
# NT-Forensik — Abschnitt 13e: Infektions-Ursachensuche
#
# @nummer:  13e
# @titel:   Zeitachse, Ausbreitungsweg und Reichweite der Quellen
# @frage:   Wann begann es, wie breitete es sich aus, und wie weit reicht der Beleg?
# @kosten:  mittel — stat() auf belastete Dateien, ein flacher find nach Plugins/Themes
#           und EIN grep -F je Zugriffsprotokoll der belasteten vhosts (auch .gz, #135)
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

# Alle Belege dieses Abschnitts gehen an den Kunden: sie handeln von SEINEN
# Dateien und SEINEM vhost. 13e.3 nennt zwar weitere vhosts desselben
# Systemnutzers — aber genau die gehoeren demselben Abo, sind also nicht fremd.
BELEG_STUFE=kunde

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

# Die Autologin-Plugins aus dem WordPress-Rezept (#134) gehoeren dazu: ihre
# Zeilen beginnen mit dem Installationspfad (ein Verzeichnis, das _u_pfade
# verwirft), die ausloesende Datei steht im dritten Feld. Ohne diese Zeile sah
# 13e.5 am 21.10.2026 den UpdraftCentral-Request zur Anlage von hero-hub nur
# als "Plugin-Anlage, beauftragt?" statt als belegten Einstiegsweg.
U_KANDIDATEN=$(
  printf '%s\n' \
    "${DROPPER_DETAIL:-}" "${WEBSHELL_NAMEN:-}" "${CORE_SNE:-}" \
    "${CORE_INJECT_HITS:-}" "${DISGUISED_PAYLOADS:-}" "${SIGNATUR_TREFFER:-}" \
    "${NC_MALWARE:-}" "${JOOMLA_MALWARE:-}" "${ZEITANKER:-}" \
    "$(printf '%s' "${WP_AUTOLOGIN_PLUGINS:-}" | awk -F'\t' 'NF>=3{print $3}')" \
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
  U_ERST_ROH=$(printf '%s\n' "$U_TAB" | head -1 | cut -f1)
  U_LETZT=$(printf '%s\n' "$U_TAB" | tail -1 | cut -f1)

  # ── Bloecke bilden und einordnen (#65) ─────────────────────────────────
  #
  # Am 13.08.2026 standen ueber 200 Dateien vom 19.02.2026 innerhalb von
  # 41 Sekunden am Anfang der Achse — eine Wiederherstellung, kein
  # Angriffsbeginn. `aeltester_nachweis` nannte trotzdem dieses Datum, und
  # 13e.4 baute darauf sein "173 Tage vor dem Protokollfenster".
  #
  # 7.14 erkennt diese Signatur seit Langem, misst dafuer aber die MTIME.
  # Nach einer Wiederherstellung ist gerade die mtime die alte, verstreute —
  # gehaeuft ist die CTIME. Fuer 7.14 war der Vorgang deshalb unsichtbar.
  #
  # Die Einordnung uebernimmt awk, weil sie zwei Durchgaenge je Block braucht:
  # die Groesse steht erst fest, wenn der Block zu Ende ist.
  #
  # KEIN STILLES WEGFILTERN. Der Block verschwindet nicht, er bekommt EINE
  # Zeile statt 200 — mit Anzahl, Spanne und dem Anteil, der die Einordnung
  # traegt. Ein Angreifer, der 59.472 Dateien in einer Sekunde anfasst, erzeugt
  # dieselbe Haeufung; das war der Anlassfall von 7.14.
  _u_bloecke=$(printf '%s\n' "$U_TAB" | awk -F'\t' \
      -v luecke="${URSACHE_WELLE_SEK:-3600}" \
      -v zusatz="${ZEITSTEMPEL_ZUSATZ_SEK:-2592000}" \
      -v min="${URSACHE_MASSE_MIN:-50}" \
      -v fenster="${URSACHE_MASSE_FENSTER_SEK:-1800}" '
    function schliessen(   i, spanne, art) {
      if (n == 0) return
      spanne = letzt - erst
      # Die Mehrheitsregel ist die eigentliche Bedingung: viele Dateien, die
      # ihre alte mtime behalten haben, sind kopiert worden. Frisch
      # geschriebene Dateien (mtime == ctime) sind es nicht — dann bleibt der
      # Block auf der Achse stehen, Datei fuer Datei.
      art = (n >= min && spanne <= fenster && inode * 2 > n) ? "MASSE" : "NORMAL"
      printf "BLOCK\t%s\t%d\t%d\t%d\t%d\n", art, erst, spanne, n, inode
      if (art != "MASSE") for (i = 1; i <= n; i++) printf "ZEILE\t%s\n", puffer[i]
      for (i = 1; i <= n; i++) delete puffer[i]
      n = 0; inode = 0
    }
    { if (vorher > 0 && $1 - vorher >= luecke) { schliessen(); printf "PAUSE\t%d\n", $1 - vorher }
      vorher = $1
      if (n == 0) erst = $1
      letzt = $1
      puffer[++n] = $0
      if ($2 > 0 && $1 - $2 >= zusatz) inode++ }
    END { schliessen() }')

  _u_n=0
  U_WELLEN=0; U_MASSEN=0
  U_ERST=""
  while IFS=$'\t' read -r _art _a _b _c _d _e; do
    case "$_art" in
      PAUSE)
        [[ "$_u_n" -le "${URSACHE_ACHSE_MAX:-60}" ]] && \
          U_ACHSE+="    ── Pause: $(_u_dauer "$_a") ──"$'\n'
        ;;
      BLOCK)
        # _a=art _b=erste ctime _c=spanne _d=anzahl _e=davon INODE
        if [[ "$_a" == "MASSE" ]]; then
          U_MASSEN=$(( U_MASSEN + 1 ))
          _u_n=$(( _u_n + 1 ))
          [[ "$_u_n" -le "${URSACHE_ACHSE_MAX:-60}" ]] && \
            U_ACHSE+="$(_u_epoche_str "$_b")  ▓ MASSENVORGANG: ${_d} Dateien in $(_u_dauer "$_c"), ${_e} davon mit erhaltener alter mtime — Wiederherstellung oder Migration. Das sagt, WIE geschrieben wurde, nicht WAS: eine Wiederherstellung kann Schadcode mitbringen"$'\n'
        else
          U_WELLEN=$(( U_WELLEN + 1 ))
        fi
        ;;
      ZEILE)
        # _a=ctime _b=mtime _c=pfad
        _u_n=$(( _u_n + 1 ))
        [[ -z "$U_ERST" ]] && U_ERST="$_a"
        [[ "$_u_n" -le "${URSACHE_ACHSE_MAX:-60}" ]] || continue
        U_ACHSE+="$(_u_epoche_str "$_a")  ${_c}"$'\n'
        ;;
    esac
  done <<< "$_u_bloecke"
  # Besteht die Achse NUR aus Massenvorgaengen, gibt es keinen einzelnen
  # Schreibvorgang, auf den man datieren koennte. Dann bleibt der rohe Wert —
  # aber die Aussage darueber steht unten.
  [[ -z "$U_ERST" ]] && U_ERST="$U_ERST_ROH"

  # Kein stilles Abschneiden. Was ueber die Grenze faellt, wird benannt.
  if [[ "$U_ZEILEN" -gt "${URSACHE_ACHSE_MAX:-60}" ]]; then
    U_ACHSE+="    … $(( U_ZEILEN - ${URSACHE_ACHSE_MAX:-60} )) weitere Eintraege — vollstaendig im Beleg"$'\n'
  fi

  info "Aeltester einzelner Schreibvorgang: $(_u_epoche_str "$U_ERST") — juengster: $(_u_epoche_str "$U_LETZT")"
  info "${U_ZEILEN} belastete Datei(en), verteilt auf ${U_WELLEN} Vorgang/Vorgaenge (Trennung ab $(_u_dauer "${URSACHE_WELLE_SEK:-3600}") Pause)"
  # Der rohe aelteste Wert bleibt sichtbar. Sonst waere die Korrektur selbst
  # eine stille Aenderung: wer die Zahl mit einem frueheren Lauf vergleicht,
  # muss sehen, dass sie eine andere Frage beantwortet.
  if [[ "$U_MASSEN" -gt 0 ]]; then
    info "${U_MASSEN} Massenvorgang/-vorgaenge herausgehalten. Aeltester Zeitstempel insgesamt: $(_u_epoche_str "$U_ERST_ROH") — er gehoert zu einem davon und datiert keinen Angriff."
  fi
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
#
# WELCHE PROTOKOLLE ZAEHLEN (#135)
#
# Bis zum 21.10.2026 las dieser Abschnitt nur <vhost>/logs/*access* und davon
# nur die unkomprimierten. Auf web68/cletus begann das Fenster damit am
# 07.01.2026, obwohl zwei .gz-Rotationen weiter zurueckreichten — und Plesk
# schreibt die Protokolle zusaetzlicher Domains nach
# /var/www/vhosts/system/<domain>/logs/, nicht in den vhost. Gesucht wird
# deshalb an allen drei Stellen, und jede Datei nur einmal: system/<d>/logs
# und <vhost>/logs/<d>/ sind bei Plesk dieselbe Datei, doppelt gelesen stuende
# jeder Request zweimal im Beleg.
U_QUELLEN=""
U_FENSTER=""    # vhost<TAB>Epoche der aeltesten Protokollzeile
U_VOR=0         # belastete Dateien, deren ctime VOR dem Protokollfenster liegt
U_IM=0          # ... und solche im Fenster — nur fuer sie kann 13e.5 etwas finden
U_VHOSTS=""

_u_logdateien() {   # <vhost-verzeichnis> → Zugriffsprotokolle, je Datei eine Zeile
  local _vd="$1" _sys="${VHOSTS_DIR:-/var/www/vhosts}/system" _d _f _k _gesehen=""
  {
    printf '%s\n' "${_vd}/logs" "${_sys}/$(basename "$_vd")/logs"
    for _d in "${_vd}"/logs/*/; do [[ -d "$_d" ]] && printf '%s\n' "${_d%/}"; done
    # Zusatzdomains, deren DocumentRoot in diesem vhost liegt. Ihr Name steht
    # nirgends im vhost-Verzeichnis — nur in der Webserver-Konfiguration.
    if [[ -d "$_sys" ]]; then
      grep -lsF -- "${_vd}/" "${_sys}"/*/conf/httpd.conf "${_sys}"/*/conf/nginx.conf 2>/dev/null \
        | while IFS= read -r _f; do printf '%s\n' "$(dirname "$(dirname "$_f")")/logs"; done
    fi
  } | while IFS= read -r _d; do
    [[ -d "$_d" ]] || continue
    for _f in "$_d"/*access*; do
      [[ -f "$_f" ]] || continue
      _k=$(stat -c '%d:%i' "$_f" 2>/dev/null || stat -f '%d:%i' "$_f" 2>/dev/null || printf '%s' "$_f")
      case " ${_gesehen} " in *" ${_k} "*) continue ;; esac
      _gesehen+=" ${_k}"
      printf '%s\n' "$_f"
    done
  done
}

_u_lesen() {        # <protokoll> → Klartext, gleich ob rotiert und gepackt
  case "$1" in
    *.gz)  gzip  -dc -- "$1" 2>/dev/null ;;
    *.bz2) bzip2 -dc -- "$1" 2>/dev/null ;;
    *.xz)  xz    -dc -- "$1" 2>/dev/null ;;
    *)     cat       -- "$1" 2>/dev/null ;;
  esac
}

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
    [[ -n "$_vd" && -d "${_vd}/logs" ]] || continue
    _erst=""; _n=0; _kompr=0; _unl=0
    while IFS= read -r _lf; do
      [[ -n "$_lf" ]] || continue
      _n=$(( _n + 1 ))
      case "$_lf" in *.gz|*.bz2|*.xz) _kompr=$(( _kompr + 1 )) ;; esac
      _z=$(_u_lesen "$_lf" | head -1 | grep -oE '\[[0-9]{2}/[A-Za-z]{3}/[0-9]{4}:[0-9:]{8}' | tr -d '[' || true)
      if [[ -z "$_z" ]]; then
        # Leer ist bei Plesk normal (access_log einer reinen SSL-Seite). Nicht
        # entpackbar ist es nicht — dann fehlt ein Stueck Fenster.
        case "$_lf" in *.gz|*.bz2|*.xz) [[ -s "$_lf" ]] && _unl=$(( _unl + 1 )) ;; esac
        continue
      fi
      _e=$(_u_apache_epoche "$_z")
      [[ -n "$_e" ]] || continue
      [[ -z "$_erst" || "$_e" -lt "$_erst" ]] && _erst="$_e"
    done < <(_u_logdateien "$_vd")
    [[ "$_n" -gt 0 ]] || continue
    U_QUELLEN+="${_vd}"$'\n'
    U_QUELLEN+="    ${_n} Zugriffsprotokoll(e) gelesen, davon ${_kompr} komprimiert"$'\n'
    [[ "$_unl" -gt 0 ]] && U_QUELLEN+="    ${_unl} komprimierte(s) Protokoll(e) nicht entpackbar — nicht ausgewertet, das Fenster kann weiter zurueckreichen"$'\n'
    [[ -n "$_erst" ]] || continue
    U_QUELLEN+="    Zugriffsprotokoll reicht zurueck bis $(_u_epoche_str "$_erst")"$'\n'
    U_FENSTER+="${_vd}"$'\t'"${_erst}"$'\n'
    # Der eigentliche Satz — aber je DATEI, nicht ueber den aeltesten Beleg.
    #
    # Bis #135 entschied allein der aelteste Beleg: lag er vor dem Fenster,
    # hiess es "Einstiegsweg nicht nachweisbar". Auf web68 waren das 26
    # Core-fremde Altdateien von 2013 mit ctime 2024 — und eine Datei vom
    # 15.10.2026 mitten im Fenster, gegen die nie ein Protokoll gehalten wurde.
    # Eine alte Datei sagt nichts ueber den Weg einer neuen.
    _vor=0; _ges=0
    while IFS=$'\t' read -r _c _m _p; do
      [[ -n "$_p" && "$_p" == "${_vd}/"* ]] || continue
      _ges=$(( _ges + 1 ))
      [[ "$_c" -lt "$_erst" ]] && _vor=$(( _vor + 1 ))
    done <<< "$U_TAB"
    U_VOR=$(( U_VOR + _vor )); U_IM=$(( U_IM + _ges - _vor ))
    if [[ "$_vor" -gt 0 && "$_vor" -eq "$_ges" ]]; then
      U_QUELLEN+="    ⚠ Der aelteste Beleg ($(_u_epoche_str "$U_ERST")) liegt $(_u_dauer $(( _erst > U_ERST ? _erst - U_ERST : 0 ))) VOR dem Protokollfenster — der Einstiegsweg ist hier nicht mehr nachweisbar"$'\n'
    elif [[ "$_vor" -gt 0 ]]; then
      U_QUELLEN+="    ⚠ ${_vor} von ${_ges} belasteten Datei(en) liegen VOR dem Protokollfenster — fuer sie ist der Einstiegsweg hier nicht mehr nachweisbar; die uebrigen $(( _ges - _vor )) prueft 13e.5"$'\n'
    fi
  done <<< "$U_VHOSTS"
fi

info "Aeltester Nachweis ist nicht Infektionsbeginn: er ist die aelteste ueberlebende Spur. Aeltere Vorgaenge koennen ueberschrieben, rotiert oder nie protokolliert worden sein."
if [[ -n "$U_QUELLEN" ]]; then
  code "$U_QUELLEN"
  evidence "ursache_quellenlage" "$U_QUELLEN" kunde
elif [[ -n "$U_TAB" ]]; then
  unklar "Kein auswertbares Zugriffsprotokoll neben den belasteten vhosts — die Reichweite der Quellen ist unbestimmt"
fi

# ============================================================
h2 "13e.5 Einstiegsweg im Zugriffsprotokoll"
# ANLASS (#135)
#
# 21.10.2026, Abo web68 auf cletus: das Schad-Plugin wp-content/plugins/
# hero-hub/ entstand am 19.10. um 08:40:51. Im access_ssl_log steht in
# DERSELBEN Sekunde:
#
#   43.250.53.42 - - [19/Oct/2026:08:40:51 +0200] "POST / HTTP/1.1" 200 7084
#                "-" "WordPress/6.4; class-udrpc.php"
#
# class-udrpc.php ist die RPC-Klasse von UpdraftCentral, der Fernsteuerung
# von UpdraftPlus. Der Einstiegsweg stand also im Protokoll — der Bericht
# sagte trotzdem "nicht bestimmbar", weil niemand die Anlagezeit gegen das
# Protokoll gehalten hat. Ein Mensch fand die Zeile in zwei Minuten.
#
# WAS HIER GEPRUEFT WIRD
#
# Fuer die juengsten belasteten Zeitpunkte (Anlage = birth, sonst ctime) und
# fuer frisch angelegte Plugins/Themes im Protokollfenster werden alle
# Requests im Fenster ±2 s gezogen. Zwei Sekunden, weil der Upgrader das
# Archiv erst entpackt und dann kopiert: der Request beginnt vor der Datei,
# und Apache schreibt die Zeile erst bei Ende der Antwort.
#
# WAS DARAUS GESCHLOSSEN WIRD — UND WAS NICHT
#
# Gleichzeitigkeit allein ist kein Beweis. Auf einer gut besuchten Seite
# fallen in jede Sekunde ein paar GETs. Ein Befund entsteht deshalb nur, wenn
# der Request eine KENNUNG traegt, die Dateien schreiben kann: eine
# Fernsteuerung, ein Upload, eine Installation, ein Datei-Editor. XML-RPC und
# wp-login.php werden genannt, aber nur als Warnung — beide werden auf vielen
# Seiten im Sekundentakt beschossen, und ein Zufallstreffer waere sonst ein
# kritischer Befund mit falscher Adresse in der IOC-Liste.
#
# Die Uhrzeit wird in der LOKALEN Zeitzone des Servers gesucht — so schreibt
# Apache sie. Laeuft der Lauf mit einer anderen TZ als der Webserver, findet
# dieser Abschnitt nichts; der Beleg nennt deshalb die gesuchten Zeitpunkte.
#
# Tabelle: Klasse|Kanal|Muster. Das Muster ist ein ERE, wird gegen die ganze
# Protokollzeile in Kleinbuchstaben geprueft, und die ERSTE passende Zeile der
# Tabelle gewinnt — Spezifisches steht deshalb oben. Klassen:
#   fern     Fernsteuerung eines Verwaltungsdienstes        → crit
#   upload   Archiv-Upload ueber wp-admin                   → crit
#   install  Installation ueber wp-admin oder REST          → crit
#   editor   Datei-Editor in wp-admin                       → crit
#   schwach  Weg, der auch ohne Zusammenhang staendig auftritt → warn
# Neue Kennungen gehoeren HIER hinein, nicht in eine Sonderabfrage.
U_KANAELE='fern|UpdraftCentral (Fernsteuerung über UpdraftPlus)|class-udrpc\.php|udrpc_message
fern|ManageWP (Fernsteuerung über ManageWP Worker)|managewp|[?&]mwp_|mwprpc
fern|MainWP (Fernsteuerung über MainWP Child)|mainwpsignature|mainwp
fern|InfiniteWP (Fernsteuerung über IWP Client)|iwp_action|infinitewp
fern|WPMU DEV Hub (Fernsteuerung über WPMU DEV Dashboard)|wpmudev|wdp-un
fern|BlogVault/MalCare (Fernsteuerung)|bvplugname|blogvault|malcare
upload|Plugin-Upload über wp-admin|update\.php\?action=upload-plugin
upload|Theme-Upload über wp-admin|update\.php\?action=upload-theme
install|Plugin-/Theme-Installation über wp-admin|plugin-install\.php|theme-install\.php|update\.php\?action=install-(plugin|theme)|admin-ajax\.php[^ ]*install-(plugin|theme)
install|Plugin-Installation über die REST-API|/wp-json/wp/v2/plugins|rest_route=/?wp/v2/plugins
editor|Datei-Editor in wp-admin|plugin-editor\.php|theme-editor\.php
schwach|XML-RPC (xmlrpc.php)|xmlrpc\.php
schwach|Anmeldung über wp-login.php (POST)|"post [^"]*wp-login\.php'

U_EINSTIEG=""     # Kanal<TAB>Zeit<TAB>IP<TAB>Datei — je belegtem Einstiegsweg, fuer Abschnitt 14
U_EINSTIEG_N=0

_u_geburt() {       # <pfad> → Anlagezeit in Sekunden, 0 wenn nicht messbar
  # Erst die FAEHIGKEIT pruefen, dann fragen: GNU-`stat -f` ist die
  # Dateisystem-Abfrage, und %B liefert dort die Blockgroesse — eine Zahl, die
  # wie eine Zeit aussieht. ext4 ohne grosse Inodes meldet 0 oder "-".
  local _w=""
  if stat -c %W "$1" >/dev/null 2>&1; then
    _w=$(stat -c %W "$1" 2>/dev/null)
  else
    _w=$(stat -f %B "$1" 2>/dev/null)
  fi
  if [[ "$_w" =~ ^[0-9]+$ && "$_w" -gt 0 ]]; then printf '%s' "$_w"; else printf '0'; fi
}
_u_apache_str() {   # Sekunden → "19/Oct/2026:08:40:51" in lokaler Zeit, wie Apache schreibt
  LC_ALL=C date -d "@$1" '+%d/%b/%Y:%H:%M:%S' 2>/dev/null \
    || LC_ALL=C date -r "$1" '+%d/%b/%Y:%H:%M:%S' 2>/dev/null
}
# Zeitpunkte einer Datei: Anlage und letzter Schreibvorgang, wenn sie mehr als
# zwei Sekunden auseinanderliegen. Eine nachtraeglich injizierte Datei hat eine
# alte Anlage und eine frische ctime — der Weg gehoert zur ctime.
_u_zeitpunkte() {   # <art> <ctime> <pfad> → t<TAB>art<TAB>wie<TAB>pfad
  local _b
  _b=$(_u_geburt "$3")
  if [[ "$_b" -gt 0 ]]; then
    printf '%s\t%s\tAnlage\t%s\n' "$_b" "$1" "$3"
    [[ $(( $2 - _b )) -gt 2 ]] && printf '%s\t%s\tSchreibvorgang\t%s\n' "$2" "$1" "$3"
  else
    printf '%s\t%s\tSchreibvorgang\t%s\n' "$2" "$1" "$3"
  fi
  return 0
}

U_KORR=""         # alle Treffer im Fenster, Rohform fuer Beleg und Befunde
U_GESUCHT=0       # Zeitpunkte, gegen die ein Protokoll gehalten wurde
if [[ -n "$U_FENSTER" ]]; then
  while IFS=$'\t' read -r _vd _ab; do
    [[ -n "$_vd" ]] || continue
    # Kandidaten dieses vhosts: belastete Dateien und frisch angelegte
    # Plugins/Themes/MU-Plugins. Die zweite Gruppe, weil am Anlassfall
    # hero-hub/ in KEINER Fundliste stand — das Schad-Plugin war sauber genug
    # geschrieben, um durch jede Signatur zu fallen. Seine Anlage war trotzdem
    # die auffaelligste Zeile im Protokoll.
    _k=$(
      while IFS=$'\t' read -r _c _m _p; do
        [[ -n "$_p" && "$_p" == "${_vd}/"* ]] || continue
        _u_zeitpunkte belastet "$_c" "$_p"
      done <<< "$U_TAB"
      while IFS= read -r _p; do
        [[ -n "$_p" ]] || continue
        _c=$(datei_epoche "$_p" ctime 2>/dev/null || echo 0)
        [[ "${_c:-0}" -gt 0 ]] || continue
        _u_zeitpunkte anlage "$_c" "$_p"
      done < <(find "$_vd" -maxdepth 5 \( -path '*/wp-content/plugins/*' -o -path '*/wp-content/themes/*' \
                 -o -path '*/wp-content/mu-plugins/*' \) -prune -print 2>/dev/null)
    )
    # Je Sekunde EIN Kandidat (belastet vor anlage), nur im Fenster, und je Art
    # die juengsten URSACHE_EINSTIEG_MAX. Ein Plugin mit 300 Dateien ist EINE
    # Anlage, nicht 300.
    _k=$(printf '%s\n' "$_k" | awk -F'\t' -v ab="$_ab" '
          $1 ~ /^[0-9]+$/ && $1 >= ab {
            if (!($1 in art) || (art[$1] == "anlage" && $2 == "belastet")) {
              art[$1] = $2; wie[$1] = $3; pfad[$1] = $4; n[$1] = 0 }
            if (art[$1] == $2) n[$1]++ }
          END { for (t in art) printf "%s\t%s\t%s\t%s\t%d\n", t, art[t], wie[t], pfad[t], n[t] }' \
        | LC_ALL=C sort -t $'\t' -k1,1nr \
        | awk -F'\t' -v max="${URSACHE_EINSTIEG_MAX:-20}" '++z[$2] <= max')
    [[ -n "$_k" ]] || continue
    # Je Kandidat fuenf Sekunden; die Zuordnung Sekunde → Kandidat traegt awk.
    _karte=$(
      while IFS=$'\t' read -r _t _art _wie _p _anz; do
        for _d in -2 -1 0 1 2; do
          _s=$(_u_apache_str $(( _t + _d )))
          [[ -n "$_s" ]] && printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$_s" "$_d" "$_t" "$_art" "$_wie" "$_p" "$_anz"
        done
      done <<< "$_k"
    )
    [[ -n "$_karte" ]] || continue
    U_GESUCHT=$(( U_GESUCHT + $(printf '%s\n' "$_k" | grep -c .) ))
    _muster=$(printf '%s\n' "$_karte" | cut -f1 | LC_ALL=C sort -u | sed 's/^/[/')
    U_KORR+=$(
      while IFS= read -r _lf; do
        [[ -n "$_lf" ]] || continue
        _u_lesen "$_lf" | grep -F -f <(printf '%s\n' "$_muster") 2>/dev/null \
          | awk -v q="$_lf" '{ print q "\t" $0 }'
      done < <(_u_logdateien "$_vd") \
      | awk -F'\t' '
          FNR == 1 { f++ }
          f == 1 { i = index($0, "|"); kl = substr($0, 1, i - 1); r = substr($0, i + 1)
                   i = index(r, "|"); K++; KL[K] = kl; KA[K] = substr(r, 1, i - 1); RE[K] = substr(r, i + 1)
                   next }
          # Erst pruefen, dann lesen: schon das Lesen von M[s] legt den
          # Eintrag an, und "s in M" waere danach immer wahr.
          f == 2 { s = $1; r = substr($0, length(s) + 2)
                   if (s in M) M[s] = M[s] "\n" r; else M[s] = r
                   next }
          {
            lf = $1; zeile = substr($0, length(lf) + 2)
            if (!match(zeile, /\[[0-9][0-9]\/[A-Za-z][A-Za-z][A-Za-z]\/[0-9][0-9][0-9][0-9]:[0-9][0-9]:[0-9][0-9]:[0-9][0-9]/)) next
            s = substr(zeile, RSTART + 1, RLENGTH - 1)
            if (!(s in M)) next
            klein = tolower(zeile); kl = "-"; ka = "-"
            for (i = 1; i <= K; i++) if (klein ~ RE[i]) { kl = KL[i]; ka = KA[i]; break }
            post = (zeile ~ /"POST /) ? 1 : 0
            split(zeile, w, " ")
            n = split(M[s], L, "\n")
            for (j = 1; j <= n; j++)
              print L[j] "\t" post "\t" kl "\t" ka "\t" w[1] "\t" lf "\t" zeile
          }' <(printf '%s\n' "$U_KANAELE") <(printf '%s\n' "$_karte") -
    )$'\n'
  done <<< "$U_FENSTER"
fi
# U_KORR: d t art wie pfad anzahl post klasse kanal ip protokoll zeile
U_KORR=$(printf '%s\n' "$U_KORR" | grep . | LC_ALL=C sort -t $'\t' -k2,2nr -k1,1n || true)

# Der Satzteil zwischen Request und Datei. "in derselben Sekunde wie" verlangt
# den Nominativ, "2 s vor" den Dativ — deshalb EINE Funktion fuer beides.
_u_bezug() {        # <d> <wie> <pfad> <anzahl> → "in derselben Sekunde wie die Anlage von …"
  local _x
  if [[ "$1" -eq 0 ]]; then
    _x="in derselben Sekunde wie "
    if [[ "$2" == "Anlage" ]]; then _x+="die Anlage von $3"; else _x+="der Schreibvorgang an $3"; fi
  else
    if [[ "$1" -lt 0 ]]; then _x="$(( -$1 )) s vor "; else _x="$1 s nach "; fi
    if [[ "$2" == "Anlage" ]]; then _x+="der Anlage von $3"; else _x+="dem Schreibvorgang an $3"; fi
  fi
  [[ "${4:-1}" -gt 1 ]] && _x+=" (und $(( $4 - 1 )) weitere Datei(en) derselben Sekunde)"
  printf '%s' "$_x"
}

if [[ "$U_GESUCHT" -gt 0 ]]; then
  info "${U_GESUCHT} Zeitpunkt(e) gegen das Zugriffsprotokoll gehalten (Fenster ±2 s): die juengsten belasteten Dateien und frisch angelegte Plugins/Themes"
fi

if [[ -n "$U_KORR" ]]; then
  # Beleg: ALLE Requests im Fenster, nicht nur die mit Kennung. Ein POST ohne
  # bekannte Kennung ist genau die Zeile, nach der ein Mensch als naechstes
  # sucht — und die Tabelle oben waechst aus solchen Zeilen.
  _beleg=$(printf '%s\n' "$U_KORR" | awk -F'\t' '
    { key = $2 "\t" $5
      if (key != vorher) {
        if (vorher != "" && z > 40) printf "    … %d weitere Zeile(n)\n", z - 40
        printf "\n── %s %s (%s): %s%s\n", $4, $2, $3, $5, ($6 > 1 ? " (+" ($6 - 1) " weitere derselben Sekunde)" : "")
        vorher = key; z = 0 }
      if (++z > 40) next
      mark = ($7 == 1) ? "▶ POST " : "       "
      kan  = ($9 != "-") ? "[" $9 "] " : ""
      printf "  %s%+ds  %s%s   ← %s\n", mark, $1, kan, $12, $11 }
    END { if (z > 40) printf "    … %d weitere Zeile(n)\n", z - 40 }')
  # Kopfzeilen tragen die Epoche — awk kann sie nicht portabel formatieren.
  while IFS= read -r _t; do
    [[ -n "$_t" ]] && _beleg=${_beleg//" ${_t} ("/" $(_u_epoche_str "$_t") ("}
  done < <(printf '%s\n' "$U_KORR" | cut -f2 | LC_ALL=C sort -u)
  evidence "ursache_einstieg_requests" "Requests im Fenster ±2 s um die geprueften Zeitpunkte (±Ns = Abstand zur Datei; ▶ = POST; [Kanal] = bekannte Kennung)
${_beleg}" kunde

  # ── Belegter Einstiegsweg: belastete Datei + schreibfaehige Kennung ──
  # Fernsteuerungen schreiben nur per POST — die Nutzlast steht im Rumpf. Ein
  # GET auf /wp-content/plugins/mainwp-child/… ist ein Browser, der ein Bild
  # laedt, und bleibt im Beleg. Die wp-admin-Wege dagegen gehen auch per GET:
  # update.php?action=install-plugin ist ein Link mit Nonce.
  _stark=$(printf '%s\n' "$U_KORR" | awk -F'\t' '$3 == "belastet" && (($8 == "fern" && $7 == 1) || $8 ~ /^(upload|install|editor)$/)')
  if [[ -n "$_stark" ]]; then
    _n_meld=0
    while IFS=$'\t' read -r _d _t _art _wie _p _anz _post _kl _ka _ip _lf _zeile; do
      [[ -n "$_ka" ]] || continue
      U_EINSTIEG_N=$(( U_EINSTIEG_N + 1 ))
      U_EINSTIEG+="${_ka}"$'\t'"$(_u_epoche_str $(( _t + _d )))"$'\t'"${_ip}"$'\t'"${_p}"$'\n'
      _n_meld=$(( _n_meld + 1 ))
      [[ "$_n_meld" -le 5 ]] || continue
      crit "Einstiegsweg: ${_ka} — Request $(_u_epoche_str $(( _t + _d ))) von ${_ip} $(_u_bezug "$_d" "$_wie" "$_p" "$_anz")" web
    done < <(printf '%s\n' "$_stark" | awk -F'\t' '!g[$9 "\t" $10]++')
    [[ "$_n_meld" -gt 5 ]] && info "… $(( _n_meld - 5 )) weitere Kanal/Adresse-Paar(e) — vollstaendig im Beleg"
    code "$(printf '%s\n' "$_stark" | cut -f12 | LC_ALL=C sort -u | head -20)"
    # In die IOC-Liste, im Format von Abschnitt 4 ("  Anzahl IP"). Nur die
    # Adressen mit schreibfaehiger Kennung: eine Adresse, die zufaellig in
    # derselben Sekunde ein Bild lud, gehoert in keine Sperrliste.
    _ips=$(printf '%s\n' "$_stark" | cut -f10 | grep -E '^[0-9a-fA-F.:]+$' | LC_ALL=C sort | uniq -c | LC_ALL=C sort -rn || true)
    [[ -n "$_ips" ]] && ATTACK_IPS_UNIQ="${ATTACK_IPS_UNIQ:-}"$'\n'"$_ips"
    # Gekuerzte Adressen (#142). 13e liest auch die gepackten Rotationen, die
    # Plesk mit "Anonymize IPs during log rotation" auf /24 schreibt — Abschnitt
    # 4 sieht nur die aktuellen Dateien und meldet die Kuerzung dann nicht.
    # Anlass k42/web345 am 21.10.2026: Einstiegsweg belegt, Adresse 43.250.53.0.
    _anon=$(printf '%s\n' "$_stark" | cut -f10 | grep -E '^([0-9]{1,3}\.){3}0$' | LC_ALL=C sort -u | paste -sd, - | sed 's/,/, /g' || true)
    if [[ -n "$_anon" ]]; then
      LOGS_ANONYMISIERT=1
      unklar "Einstiegsweg-Adresse nur als /24 (${_anon}) — Zugriffsprotokoll bei der Rotation anonymisiert; als Einzel-IP gesperrt wirkt sie nicht" web
    fi
  fi

  # ── Zeitgleich, aber mit Kennung, die auch ohne Zusammenhang auftritt ──
  _schwach=$(printf '%s\n' "$U_KORR" | awk -F'\t' '$3 == "belastet" && $8 == "schwach"' | awk -F'\t' '!g[$9 "\t" $10]++' | head -3)
  while IFS=$'\t' read -r _d _t _art _wie _p _anz _post _kl _ka _ip _lf _zeile; do
    [[ -n "$_ka" ]] || continue
    warn "Zeitgleich: ${_ka} von ${_ip} ($(_u_epoche_str $(( _t + _d ))), $(_u_bezug "$_d" "$_wie" "$_p" "$_anz")) — als Einstiegsweg zu prüfen; dieser Weg wird auf vielen Seiten im Sekundentakt beschossen, die Gleichzeitigkeit allein belegt ihn nicht" web
  done <<< "$_schwach"

  # ── Frisch angelegte Plugins/Themes mit Kennung ──
  # Keine Fundliste hat sie belastet, also kein crit und keine IOC-Adresse:
  # ManageWP und UpdraftCentral sind bei Agenturen Alltag. Die Frage an den
  # Betreiber ist, ob diese Anlage beauftragt war — auf web68 war sie es nicht.
  _anl=$(printf '%s\n' "$U_KORR" | awk -F'\t' '$3 == "anlage" && $8 != "-"' | awk -F'\t' '!g[$2 "\t" $9 "\t" $10]++')
  if [[ -n "$_anl" ]]; then
    _n_anl=$(printf '%s\n' "$_anl" | cut -f2,5 | LC_ALL=C sort -u | grep -c .)
    warn "${_n_anl} Plugin-/Theme-Anlage(n) im Protokollfenster fallen sekundengenau auf einen Request mit Fernsteuerungs-, Upload- oder Installationskennung — prüfen, ob sie beauftragt waren" web
    code "$(while IFS=$'\t' read -r _d _t _art _wie _p _anz _post _kl _ka _ip _lf _zeile; do
              printf '%s  %s  %s  — %s\n' "$(_u_epoche_str $(( _t + _d )))" "$_ip" "$_ka" "$(_u_bezug "$_d" "$_wie" "$_p" "$_anz")"
            done <<< "$_anl")"
  fi
fi

# ── Aussage zum Einstiegsweg ──
# Der "nicht bestimmbar"-Satz gilt nur noch fuer die Dateien, auf die er
# zutrifft. Steht ein belegter Weg da, waere er fuer die ganze Liste falsch.
if [[ -z "$U_TAB" || -z "$U_QUELLEN" ]]; then
  : # 13e.1 bzw. 13e.4 haben das bereits gesagt
elif [[ "$U_EINSTIEG_N" -gt 0 ]]; then
  [[ "$U_VOR" -gt 0 ]] && \
    unklar "${U_VOR} belastete Datei(en) liegen vor dem Protokollfenster — fuer sie laesst sich der Einstiegsweg aus den vorhandenen Quellen nicht bestimmen; er muss nicht derselbe sein"
elif [[ "$U_IM" -eq 0 && "$U_VOR" -gt 0 ]]; then
  unklar "Der aelteste Beleg liegt vor dem verfuegbaren Protokollfenster — der Einstiegsweg laesst sich aus den vorhandenen Quellen nicht bestimmen"
elif [[ "$U_IM" -gt 0 ]]; then
  _rest=""
  [[ "$U_VOR" -gt 0 ]] && _rest=" (${U_VOR} weitere Datei(en) liegen vor dem Protokollfenster)"
  unklar "Kein Request mit Fernsteuerungs-, Upload- oder Installationskennung im Fenster ±2 s um die belasteten Dateien im Protokollfenster — der Einstiegsweg laesst sich aus den vorhandenen Quellen nicht bestimmen${_rest}"
fi

# ============================================================
h2 "13e.6 Einstieg über Anmeldedaten"
# Der fuenfte Punkt aus #48, und der einzige, dessen Wert im NEGATIVBEFUND
# liegt: laesst sich eine erfolgreiche Anmeldung im Zeitfenster der belasteten
# Dateien ausschliessen, engt das den Einstieg auf die Anwendungsebene ein.
# Im Anlassfall war genau das die Aussage -- kein Einbruch ueber Anmeldedaten,
# beide Angreifernetze tauchen im auth.log nicht auf.
#
# WARUM DAS EIN EIGENER ABSCHNITT IST UND NICHT TEIL VON 3.2
#
# Abschnitt 3.2 zaehlt FEHLVERSUCHE ueber den ganzen Bestand. Hier geht es um
# die andere Richtung und um ein Fenster: gab es im Zeitraum der belasteten
# Dateien eine ERFOLGREICHE Anmeldung? Ohne das Fenster ist die Antwort
# wertlos -- auf einem Server mit taeglicher Wartung ist "es gab erfolgreiche
# Anmeldungen" immer wahr.
#
# WAS DIESER ABSCHNITT NICHT SAGT
#
# "Keine erfolgreiche Anmeldung gefunden" heisst nicht "niemand hat sich
# angemeldet". Es heisst: nicht in diesem Protokoll, in diesem Fenster.
# auth.log rotiert, komprimierte Teile wertet dieser Abschnitt nicht aus, und
# ein Angreifer mit Rootrechten kann Zeilen entfernen. Deshalb wird die
# Reichweite des Protokolls mit ausgewiesen -- dieselbe Regel wie in 13e.4.
U_AUTH=""
U_AUTHLOG=""
# Pruefstand-Naht wie NT_DB_ATTRAPPE und NT_WF_ATTRAPPE: der Pruefbaum hat kein
# /var/log. Ohne diese Naht waere von diesem Abschnitt nur der Ausfallzweig
# gedeckt -- und ein Abschnitt, von dem nur der Ausfall geprueft ist, ist
# ungeprueft.
for _al in "${NT_AUTHLOG_ATTRAPPE:-}" /var/log/auth.log /var/log/secure; do
  [[ -n "$_al" && -r "$_al" ]] && U_AUTHLOG="$_al" && break
done

if [[ -z "$U_TAB" ]]; then
  : # ohne belastete Dateien gibt es kein Fenster — 13e.1 hat das gesagt
elif [[ -z "$U_AUTHLOG" ]]; then
  # KEIN "kein Einstieg ueber Anmeldedaten". Nicht lesbar ist nicht geprueft.
  unklar "Kein lesbares Anmeldeprotokoll (/var/log/auth.log oder /var/log/secure) — ein Einstieg über Anmeldedaten ist damit WEDER belegt NOCH ausgeschlossen"
else
  # Das Fenster: vom aeltesten Schreibvorgang bis zum juengsten, mit einem Tag
  # Vorlauf. Der Vorlauf ist Absicht -- wer sich anmeldet, schreibt nicht in
  # derselben Sekunde.
  _fenster_von=$(( U_ERST - 86400 ))
  _fenster_bis="$U_LETZT"
  # SYSLOG-ZEITSTEMPEL TRAGEN KEIN JAHR -- UND `date -d` GIBT ES AUF macOS NICHT.
  #
  # Der erste Entwurf filterte mit `date -d "$stempel" +%s`. Auf dem
  # Arbeitsplatz schlug das bei JEDER Zeile fehl, alle landeten als
  # "unlesbar" in der Ablage, und der Abschnitt meldete "keine erfolgreiche
  # Anmeldung im Zeitfenster" -- eine Entwarnung aus einer Auswertung, die nie
  # stattgefunden hat. Die Gegenprobe im Pruefbaum hat es sofort gezeigt.
  # Dieselbe Falle wie beim nackten `timeout` in #70.
  #
  # Deshalb python3: es ist ohnehin Voraussetzung, und die Jahresfrage wird
  # dort ausdruecklich entschieden statt dem Zufall ueberlassen. Ein
  # Zeitstempel ohne Jahr wird auf das Jahr gelegt, in dem er in der
  # Vergangenheit liegt -- ein Protokoll ueber den Jahreswechsel hinweg haette
  # sonst Zeilen, die in der Zukunft stehen.
  if ! werkzeug_da python3; then
    unklar "python3 fehlt — das Anmeldeprotokoll ist nicht auswertbar; ein Einstieg über Anmeldedaten ist WEDER belegt NOCH ausgeschlossen"
    return 0 2>/dev/null || U_AUTHLOG=""
  fi
  _auswertung=$(U_LOG="$U_AUTHLOG" U_VON="$_fenster_von" U_BIS="$_fenster_bis" python3 - <<'PY'
import os, re, sys, time, datetime

log = os.environ["U_LOG"]
von = int(os.environ["U_VON"]); bis = int(os.environ["U_BIS"])
# NUR ECHTE FERNANMELDUNGEN.
#
# Der erste Entwurf nahm auch "session opened for user" mit. Das ist eine
# PAM-Sitzung -- jeder Cronjob oeffnet eine. Gemessen am 04.09.2026 auf einer
# echten Instanz: 50 Treffer im Fenster, davon 47 genau solche Sitzungen und
# nur 3 tatsaechliche Anmeldungen, alle von EINER Adresse. Ein Befund, der
# auf jedem gewarteten Server 50 Zeilen wirft, wird nach dem zweiten Mal
# ueberblaettert -- und dann ist auch die eine echte Zeile weg.
muster = re.compile(r"Accepted (password|publickey|keyboard-interactive)")
stempel = re.compile(r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})")
monate = {m: i + 1 for i, m in enumerate(
    ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"])}
jetzt = datetime.datetime.now()

def epoche(zeile):
    t = stempel.match(zeile)
    if not t:
        return None
    mon, tag, std, minu, sek = t.groups()
    if mon not in monate:
        return None
    for jahr in (jetzt.year, jetzt.year - 1):
        try:
            d = datetime.datetime(jahr, monate[mon], int(tag),
                                  int(std), int(minu), int(sek))
        except ValueError:
            continue
        if d <= jetzt + datetime.timedelta(days=1):
            return int(time.mktime(d.timetuple()))
    return None

treffer = []; unlesbar = 0; erste = None
try:
    with open(log, encoding="utf-8", errors="replace") as fh:
        for zeile in fh:
            e = epoche(zeile)
            if e is None:
                if zeile.strip():
                    unlesbar += 1
                continue
            if erste is None:
                erste = e
            if muster.search(zeile) and von <= e <= bis:
                treffer.append(zeile.rstrip("\n"))
except OSError:
    print("FEHLER"); sys.exit(0)

print("REICHT\t%s" % (erste if erste is not None else ""))
print("UNLESBAR\t%d" % unlesbar)
# Die ANZAHL getrennt von der Liste. Die Liste ist gedeckelt -- sonst stehen
# auf einem gewarteten Server hundert Zeilen im Beleg. Der erste Entwurf
# zaehlte die ausgegebenen Zeilen und meldete deshalb bei jeder groesseren
# Zahl genau den Deckel: "50 Anmeldungen", egal ob es 50 oder 500 waren.
print("ANZAHL\t%d" % len(treffer))
print("ADRESSEN\t%d" % len({m.group(1) for m in
                            (re.search(r"from ([0-9a-fA-F.:]+)", z) for z in treffer) if m}))
for z in treffer[-50:]:
    print("TREFFER\t%s" % z)
PY
)
  if printf '%s' "$_auswertung" | grep -q '^FEHLER'; then
    unklar "Anmeldeprotokoll ${U_AUTHLOG} nicht lesbar — ein Einstieg über Anmeldedaten ist WEDER belegt NOCH ausgeschlossen"
    _auswertung=""
  fi
  _treffer=$(printf '%s\n' "$_auswertung" | sed -n 's/^TREFFER\t//p')
  _unlesbar=$(printf '%s\n' "$_auswertung" | sed -n 's/^UNLESBAR\t//p' | head -1)
  _unlesbar="${_unlesbar:-0}"
  _reicht_e=$(printf '%s\n' "$_auswertung" | sed -n 's/^REICHT\t//p' | head -1)
  _n_treffer=$(printf '%s\n' "$_auswertung" | sed -n 's/^ANZAHL\t//p' | head -1)
  _n_treffer="${_n_treffer:-0}"
  _n_adr_roh=$(printf '%s\n' "$_auswertung" | sed -n 's/^ADRESSEN\t//p' | head -1)

  U_AUTH="Protokoll: ${U_AUTHLOG}"$'\n'
  [[ -n "$_reicht_e" ]] && U_AUTH+="Reicht zurueck bis: $(_u_epoche_str "$_reicht_e")"$'\n'
  U_AUTH+="Fenster: $(_u_epoche_str "$_fenster_von") bis $(_u_epoche_str "$_fenster_bis")"$'\n'
  [[ "$_unlesbar" -gt 0 ]] && U_AUTH+="${_unlesbar} Zeile(n) mit unlesbarem Zeitstempel — nicht bewertet"$'\n'
  [[ "$_n_treffer" -gt 50 ]] && U_AUTH+="Liste auf die letzten 50 von ${_n_treffer} gekuerzt"$'\n'
  U_AUTH+=$'\n'"${_treffer:-(keine erfolgreiche Anmeldung im Fenster)}"

  if [[ "$_n_treffer" -gt 0 ]]; then
    # Die Zahl der ADRESSEN entscheidet, ob sich das Hinsehen lohnt: 3
    # Anmeldungen von einer Adresse sind Wartung, 3 von drei Adressen sind
    # eine Frage.
    _n_adr="${_n_adr_roh:-?}"
    warn "${_n_treffer} erfolgreiche Anmeldung(en) von ${_n_adr:-?} Adresse(n) im Zeitfenster der belasteten Dateien — als Einstiegsweg zu prüfen"
    code "$(printf '%s\n' "$_treffer" | head -20)"
    evidence "ursache_anmeldungen" "$U_AUTH" kunde
  elif [[ -n "$_reicht_e" && "$_reicht_e" -gt "$_fenster_von" ]]; then
    # Das Protokoll beginnt NACH dem Fensteranfang: der Zeitraum ist gar nicht
    # abgedeckt. Ein "keine Anmeldung gefunden" waere hier eine Entwarnung aus
    # einer Suche, die den fraglichen Zeitraum nie gesehen hat.
    #
    # Hat 13e.5 den Weg aber im Zugriffsprotokoll belegt, ist diese Luecke
    # keine offene Frage mehr, sondern eine Randnotiz. Auf web68 stand sonst
    # neben "Einstiegsweg: UpdraftCentral" ein zweites ⚪, das den Leser
    # fragen liess, welche der beiden Aussagen gilt (#135).
    if [[ "${U_EINSTIEG_N:-0}" -gt 0 ]]; then
      info "Anmeldeprotokoll beginnt erst $(_u_epoche_str "$_reicht_e") und deckt den Zeitraum der belasteten Dateien nicht ab — der Einstiegsweg ist in 13e.5 über das Zugriffsprotokoll belegt; ein zusätzlicher Einstieg über Anmeldedaten ist damit weder belegt noch ausgeschlossen"
    else
      unklar "Anmeldeprotokoll beginnt erst $(_u_epoche_str "$_reicht_e") und deckt den Zeitraum der belasteten Dateien nicht ab — ein Einstieg über Anmeldedaten ist NICHT ausgeschlossen"
    fi
    evidence "ursache_anmeldungen" "$U_AUTH" kunde
  else
    ok "Keine erfolgreiche Anmeldung im Zeitfenster der belasteten Dateien (${U_AUTHLOG}, ab $(_u_epoche_str "$_reicht_e")) — der Einstieg lag damit nicht bei Anmeldedaten, soweit dieses Protokoll reicht"
    evidence "ursache_anmeldungen" "$U_AUTH" kunde
  fi
fi
