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

# ============================================================
h2 "13e.5 Einstieg über Anmeldedaten"
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
muster = re.compile(r"Accepted (password|publickey|keyboard-interactive)|session opened for user")
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
  _n_treffer=$(printf '%s' "$_treffer" | grep -c . || true); _n_treffer="${_n_treffer:-0}"

  U_AUTH="Protokoll: ${U_AUTHLOG}"$'\n'
  [[ -n "$_reicht_e" ]] && U_AUTH+="Reicht zurueck bis: $(_u_epoche_str "$_reicht_e")"$'\n'
  U_AUTH+="Fenster: $(_u_epoche_str "$_fenster_von") bis $(_u_epoche_str "$_fenster_bis")"$'\n'
  [[ "$_unlesbar" -gt 0 ]] && U_AUTH+="${_unlesbar} Zeile(n) mit unlesbarem Zeitstempel — nicht bewertet"$'\n'
  U_AUTH+=$'\n'"${_treffer:-(keine erfolgreiche Anmeldung im Fenster)}"

  if [[ "$_n_treffer" -gt 0 ]]; then
    warn "${_n_treffer} erfolgreiche Anmeldung(en) im Zeitfenster der belasteten Dateien — als Einstiegsweg zu prüfen"
    code "$(printf '%s\n' "$_treffer" | head -20)"
    evidence "ursache_anmeldungen" "$U_AUTH" kunde
  elif [[ -n "$_reicht_e" && "$_reicht_e" -gt "$_fenster_von" ]]; then
    # Das Protokoll beginnt NACH dem Fensteranfang: der Zeitraum ist gar nicht
    # abgedeckt. Ein "keine Anmeldung gefunden" waere hier eine Entwarnung aus
    # einer Suche, die den fraglichen Zeitraum nie gesehen hat.
    unklar "Anmeldeprotokoll beginnt erst $(_u_epoche_str "$_reicht_e") und deckt den Zeitraum der belasteten Dateien nicht ab — ein Einstieg über Anmeldedaten ist NICHT ausgeschlossen"
    evidence "ursache_anmeldungen" "$U_AUTH" kunde
  else
    ok "Keine erfolgreiche Anmeldung im Zeitfenster der belasteten Dateien (${U_AUTHLOG}, ab $(_u_epoche_str "$_reicht_e")) — der Einstieg lag damit nicht bei Anmeldedaten, soweit dieses Protokoll reicht"
    evidence "ursache_anmeldungen" "$U_AUTH" kunde
  fi
fi
