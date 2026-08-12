# shellcheck shell=bash
# ============================================================
# NT-Forensik — Ausgabe- und Beleg-Funktionen
# ------------------------------------------------------------
# Die Primitiven, auf denen jeder Pruefabschnitt aufsetzt: Ueberschriften,
# Befundzeilen mit Schweregrad, Codebloecke, Beweissicherung, Maskierung fuer
# Kundenberichte und der protokollierte Netzabruf.
# 
# Der zweite Parameter 'web' bei warn/crit ist tragend: nur so markierte
# Befunde erscheinen im Kundenbericht.
# ============================================================

# ── Hilfsfunktionen ──────────────────────────────────────────
h1()  { echo -e "\n${BOLD}${BLU}══════════════════════════════════════════${NC}"; \
        echo -e "${BOLD}${BLU}  $1${NC}"; \
        echo -e "${BOLD}${BLU}══════════════════════════════════════════${NC}"; \
        echo -e "\n## $1\n" >> "$REPORT_FILE"; }

h2()  { echo -e "\n${CYN}▶ $1${NC}"; echo -e "\n### $1\n" >> "$REPORT_FILE"; }

ok()  { echo -e "  ${GRN}✓${NC} $1"; echo "- ✅ $1" >> "$REPORT_FILE"; N_OK=$((N_OK+1)); }
# $2="web" markiert einen WEBSITE-Befund (gehört in den Kundenbericht). Ohne $2
# ist es ein Server-/Root-/Infrastruktur-Befund — der bleibt Technik-/Betreiber-
# Sache und taucht NICHT im Kundenbericht auf (v3.8 Scope-Trennung).
warn(){ echo -e "  ${YLW}⚠${NC}  $1"; echo "- ⚠️  **$1**" >> "$REPORT_FILE"; \
        N_WARN=$((N_WARN+1)); WARN_LIST+="- $1"$'\n'; \
        [[ "${2:-}" == web ]] && CUST_WARN_LIST+="- $1"$'\n'; return 0; }
crit(){ echo -e "  ${RED}✗${NC}  ${BOLD}$1${NC}"; echo "- 🔴 **KRITISCH: $1**" >> "$REPORT_FILE"; \
        N_CRIT=$((N_CRIT+1)); CRIT_LIST+="- $1"$'\n'; \
        [[ "${2:-}" == web ]] && CUST_CRIT_LIST+="- $1"$'\n'; return 0; }
info(){ echo -e "  ${NC}·  $1"; echo "  $1" >> "$REPORT_FILE"; }
code(){ echo -e "\n\`\`\`\n$1\n\`\`\`\n" >> "$REPORT_FILE"; }

# ── Vierter Zustand: die Pruefung hat keine Aussage geliefert ─
#
# Bis v3.10 gab es drei Zustaende. Eine gescheiterte Messung fiel dabei
# regelmaessig auf ok() zurueck: 'wp core verify-checksums' scheitert, die
# Ausgabe ist leer, leer heisst "nichts gefunden", und der Bericht bescheinigt
# einen unveraenderten Kern, der nie geprueft wurde. Dasselbe Muster bei
# 'occ integrity:check-core', 'aide --check', 'last' und dem Imunify-Parser.
#
# Ein Lauf, in dem JEDE Messung scheitert, endete damit auf 🟢 UNAUFFAELLIG mit
# dem Satz "keine Hinweise auf eine Kompromittierung gefunden". Fuer ein
# Forensikwerkzeug ist das der teuerste denkbare Fehler — er wird als
# Entwarnung ausgeliefert.
#
# unklar() sagt, was ok() nicht sagen kann: hier steht kein Ergebnis. Der
# Zaehler ist getrennt, weil ein solcher Befund weder eine bestandene Pruefung
# (ok) noch eine Auffaelligkeit (warn) ist. Er blockiert die gruene Ampel —
# siehe module/14_berichte.sh.
unklar(){ echo -e "  ${CYN}⚪${NC} $1"; echo "- ⚪ **Nicht messbar: $1**" >> "$REPORT_FILE"; \
        N_UNKNOWN=$((N_UNKNOWN+1)); UNKNOWN_LIST+="- $1"$'\n'; \
        [[ "${2:-}" == web ]] && CUST_UNKNOWN_LIST+="- $1"$'\n'; return 0; }

# Existenzpruefung fuer externe Werkzeuge. Bewusst eine eigene Funktion und
# nicht ueberall 'command -v' inline: so ist an der Aufrufstelle sichtbar, dass
# ein fehlendes Werkzeug ein eigener Zustand ist und kein Nullergebnis.
werkzeug_da(){ command -v "$1" >/dev/null 2>&1; }

# Einen Befehl als Eigentuemer einer Installation ausfuehren.
#
#   als_eigentuemer <benutzer> <befehl…>
#
# Im Betrieb laeuft das Werkzeug als root, und der Rechtewechsel ist noetig:
# wp-cli und occ verweigern die Arbeit oder legen Dateien mit falschem
# Eigentuemer an, wenn sie als root laufen.
#
# Sind wir aber ohnehin schon dieser Benutzer, ist 'sudo -u ich' nicht nur
# ueberfluessig, sondern schaedlich: auf einer Maschine ohne NOPASSWD fragt es
# nach einem Passwort und bleibt stehen. Genau daran waere der Pruefstand
# haengengeblieben, sobald er ein Werkzeug im Baum findet.
als_eigentuemer() {
  local wer="$1"; shift
  if [[ -z "$wer" || "$wer" == "$(id -un)" ]]; then
    "$@"
  else
    sudo -u "$wer" "$@"
  fi
}

# ── Scope-Pruefung (v3.13) ───────────────────────────────────
#
# Liegt ein Pfad innerhalb des geprueften Umfangs? Das entscheidet, ob ein
# Befund in die Kundenspur darf.
#
# Bis v3.12 war der Datenschutz ein NACHTRAEGLICHES Netz: der Befund landete im
# Kundenbericht, und die Maskierung machte fremde Kennungen hinterher
# unkenntlich. Das setzt voraus, dass die Maskierung laeuft und greift. Am
# 07.08.2026 lief sie nicht — ihr Fehlschlag wurde als "(nichts zu maskieren)"
# gemeldet, und der unmaskierte Bericht ging raus.
#
# Ein Riegel ist besser als ein Netz: was gar nicht erst hineinkommt, muss
# nicht unkenntlich gemacht werden.
#
# Kanonisiert wird ueber 'cd … && pwd -P' — das loest Symlinks und '..' auf und
# funktioniert ohne 'realpath -m' (GNU-only). Existiert das Ziel nicht mehr,
# wird das uebergeordnete Verzeichnis kanonisiert und der Name angehaengt.
kanonisch() {   # kanonisch <pfad>
  local p="$1" d b
  [[ -n "$p" ]] || return 1
  if [[ -d "$p" ]]; then
    (cd "$p" 2>/dev/null && pwd -P) || printf '%s' "$p"
  else
    d="$(dirname "$p")"; b="$(basename "$p")"
    if [[ -d "$d" ]]; then
      printf '%s/%s' "$(cd "$d" 2>/dev/null && pwd -P || printf '%s' "$d")" "$b"
    else
      printf '%s' "$p"
    fi
  fi
}

im_scope() {   # im_scope <pfad> — 0 = innerhalb, 1 = ausserhalb, 2 = unbestimmbar
  local p="$1" kp s ks
  [[ -n "$p" ]] || return 2
  # Im Betreiberlauf ueber alle vhosts gibt es kein "ausserhalb".
  [[ "${SCOPE_MODE:-global}" == "global" ]] && return 0
  [[ ${#SCAN_PATHS[@]} -gt 0 ]] || return 2
  kp="$(kanonisch "$p")"
  for s in "${SCAN_PATHS[@]}"; do
    [[ -n "$s" ]] || continue
    ks="$(kanonisch "$s")"; ks="${ks%/}"
    [[ "$kp" == "$ks" || "$kp" == "$ks"/* ]] && return 0
  done
  return 1
}

# ── Befundschema (v3.12) ─────────────────────────────────────
#
# Bis hierher hatte jede Anwendung ihre eigenen Variablen: JOOMLA_MALWARE,
# NC_HTACCESS_MAL, WPDB_FLAGS und rund zwanzig weitere. lib/befunde.sh musste
# sie deklarieren, module/14_berichte/50_findings_json.sh sie einzeln
# verdrahten. Ein neuer Scanner kostete damit Aenderungen an drei Stellen im
# Kern — und genau das macht eine Rezept-Schnittstelle wertlos, bei der ein
# neues Rezept nichts als ein Verzeichnis sein soll.
#
#   befund_melden <app> <kategorie> <schwere> "<text>" <pfad|-> [web]
#
#     app        frei. 'wordpress', 'joomla', 'nextcloud', 'typo3', 'shopware'
#     kategorie  FEST. Der Bericht sortiert und ueberschreibt danach; eine
#                unbekannte Kategorie ist ein Fehler, kein stiller Einsortierer.
#     schwere    crit | warn | ok | unklar — leitet an den jeweiligen Helfer
#                weiter, die Zaehlung bleibt also unveraendert.
#     pfad       Pfad des Befunds, oder '-' wenn keiner. PFLICHTSTELLE, damit
#                die Position von 'web' eindeutig bleibt. Der Pfad ist der
#                eigentliche Gewinn: er macht den Datenschutz-Riegel exakt,
#                statt Prosa nach pfadartigen Token durchsuchen zu muessen.
#     web        wie bisher bei crit/warn: nur so markierte Befunde erscheinen
#                im Kundenbericht.
#
# Bewusst als Parameter und nicht als gesetzte Variable: eine Globale, die vor
# dem Aufruf gesetzt und danach geleert werden muss, laesst genau einen
# vergessenen Aufraeumschritt genuegen, damit ein fremder Befund im
# Kundenbericht landet. An dieser Stelle ist das der teuerste denkbare Fehler.
#
# Ablageform ist eine Zeile mit Tabulatoren, kein verschachteltes Array: bash
# 3.2 auf dem Arbeitsplatz kennt keine assoziativen Arrays mit Struktur, und
# das ist dieselbe Fassung, die schon 'source <(...)' still scheitern liess.
BEFUND_KATEGORIEN="erkennung version kern konfig datenbank schadcode logs haertung verdikt"

befund_melden() {   # befund_melden <app> <kategorie> <schwere> <text> <pfad|-> [web]
  local app="$1" kat="$2" schwere="$3" text="$4" pfad="${5:--}" kanal="${6:-}"
  [[ "$pfad" == "-" ]] && pfad=""

  case " ${BEFUND_KATEGORIEN} " in
    *" ${kat} "*) : ;;
    *) # Kein stilles Einsortieren: eine unbekannte Kategorie waere im Bericht
       # unsichtbar, und der Befund ginge verloren.
       warn "Programmfehler: unbekannte Befund-Kategorie '${kat}' (App ${app}) — Befund trotzdem gemeldet"
       kat="schadcode" ;;
  esac

  # Tabulatoren im Text wuerden die Ablageform zerlegen. Sie kommen vor:
  # alles, was aus 'mysql -N' stammt, ist tabgetrennt.
  local sauber="${text//$'\t'/ }"
  BEFUNDE+="${app}"$'\t'"${kat}"$'\t'"${schwere}"$'\t'"${sauber}"$'\t'"${pfad}"$'\n'

  # ── Der Riegel ─────────────────────────────────────────────
  # Ein Befund darf nur dann in die Kundenspur, wenn sein Pfad nachweislich im
  # Pruefumfang liegt. Liegt er ausserhalb, bleibt der Befund vollstaendig in
  # der Betreiberspur und wird zusaetzlich in KANAL_VERWEIGERT vermerkt — so
  # bleibt sichtbar, DASS etwas zurueckgehalten wurde. Stilles Weglassen waere
  # eine zweite Unehrlichkeit.
  if [[ "$kanal" == "web" && -n "$pfad" ]]; then
    if ! im_scope "$pfad"; then
      case $? in
        1) KANAL_VERWEIGERT+="${app}"$'\t'"${pfad}"$'\t'"${sauber}"$'\n'
           kanal="" ;;
        2) # Unbestimmbar ist nicht dasselbe wie ausserhalb. Im Zweifel bleibt
           # der Befund beim Betreiber: ein fehlender Kundenbefund ist
           # aergerlich, ein fremder Kundenbefund ist ein Datenschutzverstoss.
           KANAL_VERWEIGERT+="${app}"$'\t'"${pfad}"$'\t'"[Scope unbestimmbar] ${sauber}"$'\n'
           kanal="" ;;
      esac
    fi
  fi

  # Weiterleiten an den bestehenden Helfer. Die Zaehler, die Kundenspur und
  # die Ampel bleiben damit unveraendert — dieser Umbau aendert die ABLAGE,
  # nicht das Verhalten.
  case "$schwere" in
    crit)   crit   "$text" "$kanal" ;;
    warn)   warn   "$text" "$kanal" ;;
    unklar) unklar "$text" "$kanal" ;;
    ok)     ok     "$text" ;;
    *)      warn "Programmfehler: unbekannte Schwere '${schwere}' — als Warnung gemeldet: ${text}" ;;
  esac
}

# Verdikt je Anwendung. Ersetzt WPDB_VERDICT/JOOMLA_VERDICT/RELAY_VERDICT und
# schliesst zugleich eine Luecke: Abschnitt 12b hatte gar keins, obwohl
# findings.json fuer die anderen ein {flags,text}-Paar liefert.
verdikt_melden() {   # verdikt_melden <app> <flags> <text>
  VERDIKTE+="${1}"$'\t'"${2}"$'\t'"${3//$'\t'/ }"$'\n'
}

# Dateimetadaten portabel. GNU-stat kennt -c, BSD-stat -f — der Zielserver ist
# Linux, der Pruefstand des Entwicklers ist macOS. Ohne Verzweigung liefert
# 'stat -c' dort still einen Fehler, und die Angabe fehlt einfach. Genau so
# standen mtime, ctime, Eigentuemer und Rechte im ersten Entwurf von
# Abschnitt 16 leer im Beleg, ohne dass es auffiel.
#
#   datei_meta <datei> mtime|ctime|crtime|eigner|rechte|groesse
#
# Warum ctime getrennt von mtime: wer eine Datei zurueckdatiert, faelscht die
# mtime. Die ctime laesst sich ohne Schreibrechte am Datentraeger nicht
# faelschen und verraet den Eingriff.
#
# Warum crtime zusaetzlich zu beiden: die ctime verraet zwar den Eingriff, aber
# nicht, wann die Datei entstand — und sie wandert bei jedem chown und jeder
# Ruecksicherung mit. Die Anlegezeit tut das nicht. Im Anlassfall setzte der
# Angreifer die mtime von 59.472 Dateien auf einen einzigen gefaelschten Wert;
# die Chronologie liess sich danach ausschliesslich ueber die crtime
# rekonstruieren. Sie ist nicht ueberall zu haben: ext4 fuehrt sie, meldet sie
# aber nur bei ausreichend grossem Inode, und `stat -c %w` gibt dann "-" aus.
datei_meta() {
  local f="$1" was="$2" w
  if stat -c %y "$f" >/dev/null 2>&1; then      # GNU
    case "$was" in
      mtime)   stat -c %y "$f" | cut -d. -f1 ;;
      ctime)   stat -c %z "$f" | cut -d. -f1 ;;
      crtime)  w=$(stat -c %w "$f" 2>/dev/null || true)
               if [[ -z "$w" || "$w" == "-" ]]; then
                 echo "nicht verfügbar"
               else
                 echo "${w%%.*}"
               fi ;;
      eigner)  stat -c '%U:%G' "$f" ;;
      rechte)  stat -c %a "$f" ;;
      groesse) stat -c %s "$f" ;;
    esac
  elif stat -f %Sm "$f" >/dev/null 2>&1; then   # BSD
    case "$was" in
      mtime)   stat -f '%Sm' -t '%Y-%m-%d %H:%M:%S' "$f" ;;
      ctime)   stat -f '%Sc' -t '%Y-%m-%d %H:%M:%S' "$f" ;;
      crtime)  stat -f '%SB' -t '%Y-%m-%d %H:%M:%S' "$f" 2>/dev/null || echo "nicht verfügbar" ;;
      eigner)  stat -f '%Su:%Sg' "$f" ;;
      rechte)  stat -f '%OLp' "$f" ;;
      groesse) stat -f '%z' "$f" ;;
    esac
  else
    echo "?"
  fi
}

# Rohe Sekundenwerte fuer Rechnungen. Getrennt von datei_meta, weil dort
# formatierte Zeichenketten herauskommen — mit denen laesst sich nicht rechnen.
#   datei_epoche <datei> mtime|ctime   → Sekunden seit 1970, oder 0
datei_epoche() {
  local f="$1" was="$2"
  case "$was" in
    mtime) stat -c %Y "$f" 2>/dev/null || stat -f %m "$f" 2>/dev/null || echo 0 ;;
    ctime) stat -c %Z "$f" 2>/dev/null || stat -f %c "$f" 2>/dev/null || echo 0 ;;
  esac
}

# ── Maskierung für Kundenberichte (v3.5) ─────────────────────
# Kundenberichte gehen an Dritte und müssen DSGVO-datensparsam sein: fremde
# E-Mail-Adressen (etwa WP-Admin-Konten) werden pseudonymisiert. Angreifer-IPs
# bleiben im Klartext — sie sind für den Betroffenen zum Sperren nötig und
# fallen unter berechtigtes Interesse. Technik-/BSI-/DSGVO-Berichte (interne
# bzw. Behördendokumente) bleiben unmaskiert. stdin → stdout.
mask_email(){ sed -E 's/([A-Za-z0-9])[A-Za-z0-9._%+-]*(@[A-Za-z0-9.-]+\.[A-Za-z]{2,})/\1***\2/g'; }

# Beleg sichern: schreibt Rohdaten nummeriert nach belege/
# evidence "label" "inhalt"  → belege/NN_label.txt
# Steckbrief einer belasteten Datei: woran sie erkannt wurde, wie sie aussieht,
# und die Fundstelle im Klartext.
#
# Ein Befund ohne Fundstelle laesst Fehlalarm und Treffer nicht unterscheiden.
# Am 06.08.2026 meldete ein Lauf drei "boesartige Plugins" — der Beleg enthielt
# ausschliesslich Dateipfade. Zwei davon gehoerten zur legitimen elFinder-
# Bibliothek eines echten Plugins, und niemand konnte das am Beleg erkennen;
# die Bewertung blieb offen, bis jemand die Dateien selbst aufmachte. Genau
# diese Arbeit soll der Beleg abnehmen.
#
# Warum drei Zeitstempel statt einer: die mtime allein sagt nur, was der
# letzte Schreiber hinterlassen wollte. `touch -r nachbar.php shell.php` setzt
# sie auf einen unauffaelligen Wert, und der Beleg behauptet danach ein
# Alter, das die Datei nie hatte. ctime und crtime widersprechen dem — die
# eine, weil sie sich ohne Schreibrechte am Datentraeger nicht faelschen
# laesst, die andere, weil `touch` sie gar nicht erst anfasst.
datei_steckbrief() {   # datei_steckbrief <kriterium> <regex> <datei>
  local krit="$1" re="$2" f="$3" mtime="" ctime="" crtime=""
  mtime=$(stat -c '%y' "$f" 2>/dev/null || stat -f '%Sm' "$f" 2>/dev/null || echo "unbekannt")
  ctime=$(datei_meta "$f" ctime 2>/dev/null || echo "unbekannt")
  crtime=$(datei_meta "$f" crtime 2>/dev/null || echo "unbekannt")
  printf '── %s\n' "$f"
  printf '   Kriterium : %s\n' "$krit"
  printf '   Groesse   : %s Bytes\n' "$(wc -c < "$f" 2>/dev/null | tr -d ' ')"
  printf '   Geaendert : %s   (mtime)\n' "${mtime%%.*}"
  printf '   Metadaten : %s   (ctime)\n' "${ctime:-unbekannt}"
  printf '   Angelegt  : %s   (crtime)\n' "${crtime:-nicht verfügbar}"

  # Rueckdatierung: mtime deutlich aelter als die letzte Metadatenaenderung.
  local _mt _ct
  _mt=$(datei_epoche "$f" mtime); _ct=$(datei_epoche "$f" ctime)
  if [[ "${_ct:-0}" -gt 0 && "${_mt:-0}" -gt 0 ]] \
     && (( _ct - _mt > ${ZEITSTEMPEL_ZUSATZ_SEK:-2592000} )); then
    printf '   ! Rueckdatierung: mtime liegt %s Tage vor der letzten Metadatenaenderung\n' \
      "$(( (_ct - _mt) / 86400 ))"
  fi

  # Nachbarvergleich: `touch -r` uebernimmt die mtime einer anderen Datei
  # sekundengenau. Zwei Dateien im selben Verzeichnis, die auf dieselbe
  # Sekunde geschrieben wurden, entstehen bei normaler Arbeit praktisch nicht
  # — bei einer Auslieferung entstehen sie in derselben Sekunde ALLE, nicht
  # genau zu zweit. Gemeldet wird deshalb nur der enge Fall: hoechstens fuenf
  # Partner. Darueber ist es eine Entpackung und kein Hinweis.
  #
  # Verglichen wird ueber stat, nicht ueber `find -newermt`: dessen
  # @Sekunden-Form ist GNU-eigen und scheitert auf BSD stumm — die Pruefung
  # haette auf dem Entwicklungsrechner nie etwas gemeldet, ohne das zu sagen.
  local _dir _partner="" _anz=0 _n _nm
  _dir=$(dirname "$f")
  if [[ "${_mt:-0}" -gt 0 ]]; then
    while IFS= read -r _n; do
      [[ "$_n" == "$f" ]] && continue
      _nm=$(datei_epoche "$_n" mtime)
      [[ "${_nm:-0}" == "${_mt}" ]] || continue
      _partner+="$_n"$'\n'
      _anz=$((_anz+1))
      [[ "$_anz" -gt 5 ]] && break
    done < <(find "$_dir" -maxdepth 1 -type f 2>/dev/null | head -500)
  fi
  if [[ "$_anz" -ge 1 && "$_anz" -le 5 ]]; then
    printf '   ! Gleiche mtime wie %s Datei(en) im selben Verzeichnis — moeglich per touch -r uebernommen:\n' "$_anz"
    printf '%s' "$_partner" | sed 's/^/       /'
  fi

  printf '   SHA256    : %s\n' "$(sha256sum "$f" 2>/dev/null | awk '{print $1}')"
  printf '   Fundstelle (Zeile: Treffer im Kontext):\n'
  local treffer
  treffer=$(grep -nEio ".{0,60}(${re}).{0,60}" "$f" 2>/dev/null | head -5)
  if [[ -n "$treffer" ]]; then
    printf '%s\n' "$treffer" | sed 's/^/     /'
  else
    printf '     (Treffer nicht reproduzierbar — Datei seit dem Scan veraendert?)\n'
  fi
  printf '\n'
}

# ── Belege (v3.12 mit Einstufung) ────────────────────────────
#
#   evidence <bezeichner> <inhalt> [stufe]
#
# `stufe` entscheidet, ob ein Beleg in eine Kundenuebergabe darf:
#
#   kunde      betrifft den geprueften Webauftritt — darf uebergeben werden
#   server     serverweit — nur maskiert und nur, wenn der Befund es braucht
#   betreiber  rein intern — geht nie mit
#
# Warum das noetig wurde: beim Zusammenstellen eines Kundenpakets ging
# `03_admin_changelog.txt` mit, der Betreiber-Changelog. Darin stehen
# SSL-Arbeiten am Server-Host und interne Betriebsnotizen; mit dem geprueften
# Kunden hat die Datei nichts zu tun. Von 45 Belegen nannten 26 den geprueften
# Kunden ueberhaupt nicht (#1).
#
# Ohne dritten Parameter gilt ${BELEG_STUFE}, das der Runner VOR JEDEM MODUL
# auf `betreiber` zuruecksetzt. Das ist die sichere Richtung: ein Beleg, der
# faelschlich beim Betreiber bleibt, ist aergerlich; ein Beleg, der
# faelschlich mitgeht, ist ein Datenschutzverstoss. Ein Modul, das seine
# Belege einstufen will, setzt BELEG_STUFE einmal am Kopf; einzelne Aufrufe
# ueberschreiben das mit dem dritten Parameter.
# ── Datei-Inventar mit Inode und allen Zeitstempeln (#25) ────
#
#   datei_inventar <zieldatei> <pfad...>
#
# WOZU
#
# Zeitstempel liegen im Inode. Wird eine Datei verschoben, quarantaenisiert
# oder geloescht, sind sie weg — und mit ihnen die Antwort auf die Frage, die
# nach einem Vorfall zaehlt: seit wann liegt das Ding dort. Daran haengt, ab
# wann Daten als abgeflossen gelten muessen, und damit der Inhalt der
# DSGVO-Meldung.
#
# WAS DIESE DATEI BEWEIST — UND WAS NICHT
#
# Sie BEWAHRT nichts. Sie haelt eine Beobachtung fest: zum Zeitpunkt T, auf
# Host H, mit Fassung V wurden diese Werte gesehen. Was vorher war, sagt sie
# nicht. Das ist keine Schwaeche, solange es dransteht — mit dem SHA256SUMS
# des Laufs versiegelt ist es eine bezeugte Beobachtung.
#
# DER EIGENTLICHE PUNKT: dev UND inode
#
# Abgeschriebene Zeitstempel beweisen nichts, die kann jeder schreiben.
# Tragend wird das Inventar durch die Geraetenummer und den Inode: nach der
# Quarantaene wird die verschobene Datei erneut gestattet, und stimmen beide
# ueberein, ist bewiesen, dass es DASSELBE Dateiobjekt ist. Die
# aufgezeichnete crtime gilt dann weiter, obwohl die ctime durch das
# Verschieben zerstoert wurde. Stimmen sie nicht ueberein (Kopie ueber eine
# Dateisystemgrenze, tar-Archiv), zeigt der Datensatz den Bruch, statt ihn zu
# verdecken. Aus einem Abschrieb wird damit ein Kettenglied.
#
# WARUM GEBUENDELT
#
# Ein `stat`-Aufruf je Datei waeren bei 100.000 Dateien 100.000 Prozessstarts.
# GNU-find kann alles in einem Durchgang (`-printf`, mit `%B@` auch die
# Anlegezeit), BSD-stat nimmt beliebig viele Dateien auf einmal entgegen.
# Geprueft wird die FAEHIGKEIT, nicht die Plattform: auf dieser Maschine
# steht `bfs` im Pfad, das -printf kann, waehrend /usr/bin/find es nicht kann.
#
# ZEITEN ALS EPOCHENSEKUNDEN
#
# Ein forensischer Datensatz soll keine Zeitzonen-Mehrdeutigkeit tragen.
# Fehlt die Anlegezeit (ext4 fuehrt sie, meldet sie aber nur bei ausreichend
# grossem Inode), steht dort "-" und keine 0 — eine 0 liest sich wie 1970,
# nicht wie "nicht messbar".
#
# WELCHER ZEITSTEMPEL WAS TAUGT — GEMESSEN, NICHT ANGENOMMEN
#
#   mtime   mit `touch` beliebig setzbar. Der Wert, den ein Angreifer faelscht.
#   ctime   von KEINEM touch setzbar; der Kern setzt sie bei jeder
#           Inode-Aenderung auf jetzt. Damit ist "mtime deutlich aelter als
#           ctime" das eigentliche Signal fuer Rueckdatierung.
#           ABER: das Verschieben in die Quarantaene ist selbst eine
#           Inode-Aenderung — danach ist sie ueberschrieben. Genau deshalb
#           gibt es dieses Inventar.
#   crtime  ueberlebt `touch` auf ext4. Auf APFS NICHT: dort haelt der Kern
#           crtime <= mtime, und ein `touch -t 2020` zieht die Anlegezeit mit
#           in die Vergangenheit. Nachgemessen am 12.08.2026:
#               vorher            mtime=1786510340  crtime=1786510340
#               touch -t 2020     mtime=1577833200  crtime=1577833200
#               touch -t 2030     mtime=1893452400  crtime=1577833200
#           Rueckdatierung faelscht dort also beide, Vordatierung nur eine.
#           Der Zielserver ist Linux, dort traegt crtime — aber die Aussage
#           "crtime laesst sich nicht verstellen" gilt nicht ueberall, und
#           ein Beleg soll nicht mehr behaupten, als er halten kann.
datei_inventar() {   # <zieldatei> <pfad...>
  local ziel="$1"; shift
  [[ "$#" -gt 0 ]] || return 0

  {
    echo "# NT-Forensik — Datei-Inventar"
    echo "# Erhoben: $(date -u +"%Y-%m-%dT%H:%M:%SZ") (UTC)"
    echo "# Host: $(hostname -f 2>/dev/null || hostname)"
    echo "# Tool: wp_plesk_forensik.sh v${TOOL_VERSION}"
    echo "#"
    echo "# Diese Datei haelt fest, was zum Zeitpunkt oben zu sehen war — nicht,"
    echo "# was vorher war. dev und inode erlauben es, eine spaeter verschobene"
    echo "# Datei als dieselbe wiederzuerkennen; stimmen sie nach einer"
    echo "# Bereinigung nicht mehr, wurde kopiert statt verschoben und die"
    echo "# Anlegezeit ist verloren."
    echo "#"
    echo "# Zeiten in Sekunden seit 1970-01-01 UTC. '-' heisst nicht messbar."
    echo "#"
    printf '# dev\tinode\tmodus\teigner\tgruppe\tgroesse\tmtime\tctime\tcrtime\tpfad\n'
  } > "$ziel"

  # Zwei Wege, dasselbe Feldlayout. Der Pfad steht bewusst in der LETZTEN
  # Spalte — er ist die einzige, die einen Tabulator enthalten koennte.
  #
  # Geprueft wird die FAEHIGKEIT, nicht die Plattform. Auf dem Arbeitsplatz
  # steht `bfs` im Pfad, das -printf beherrscht, waehrend /usr/bin/find es
  # nicht kann; eine Abfrage auf `uname` haette dort den falschen Zweig
  # gewaehlt.
  # NT_INVENTAR_BSD=1 erzwingt den BSD-Zweig. Ohne diesen Schalter wuerde er
  # NIRGENDS laufen: auf dem Arbeitsplatz steht `bfs` im Pfad und in der CI
  # GNU-find, beide koennen -printf. Ein Zweig, den kein Pruefstand erreicht,
  # ist unbelegter Code — und dieser hier liefe ausgerechnet auf der Plattform,
  # auf der niemand nachsieht.
  if [[ "${NT_INVENTAR_BSD:-0}" != "1" ]] && find "$1" -maxdepth 0 -printf '' 2>/dev/null; then
    find "$@" -type f \
         -printf '%D\t%i\t%m\t%u\t%g\t%s\t%T@\t%C@\t%B@\t%p\n' 2>/dev/null \
      | awk -F'\t' 'BEGIN { OFS = "\t" }
          {
            # Bruchteile abschneiden. GNU liefert "1786509287.9950781560";
            # die Nanosekunden sagen nichts, was die Sekunde nicht sagt, und
            # sie machen die Datei um ein Fuenftel groesser.
            #
            # Fehlt die Anlegezeit, liefert GNU-find ein leeres Feld oder 0.
            # Beides wird zu "-": eine 0 liest sich wie 1970, ein leeres Feld
            # wie "kein Befund" — gemeint ist "nicht messbar".
            for (i = 7; i <= 9; i++) {
              sub(/\..*/, "", $i)
              if ($i == "" || $i == "0") $i = "-"
            }
            print
          }' >> "$ziel"
  else
    # BSD-stat nimmt beliebig viele Dateien auf einmal entgegen; %t ist dort
    # der Tabulator, %OLp die Rechte in Oktal und %N der Dateiname.
    find "$@" -type f -print0 2>/dev/null \
      | xargs -0 stat -f '%d%t%i%t%OLp%t%Su%t%Sg%t%z%t%m%t%c%t%B%t%N' 2>/dev/null \
      >> "$ziel"
  fi

  # Die Zahl gehoert genannt. Ein Inventar, dessen Umfang niemand kennt, ist
  # keines — und ein leeres faellt sonst gar nicht auf.
  grep -vc '^#' "$ziel" 2>/dev/null || echo 0
}

evidence() {
  EVIDENCE_IDX=$((EVIDENCE_IDX+1))
  # %03d, nicht %02d: bei 103 Aufrufstellen sortiert `10_` vor `9_`, und die
  # Reihenfolge im Ordner haette der Reihenfolge im Bericht widersprochen.
  local num; num=$(printf "%03d" "$EVIDENCE_IDX")
  local stufe="${3:-${BELEG_STUFE:-betreiber}}"
  case "$stufe" in
    kunde|server|betreiber) : ;;
    *) warn "Programmfehler: unbekannte Belegstufe '${stufe}' bei '$1' — als betreiber behandelt"
       stufe="betreiber" ;;
  esac
  local file="${BELEGE_DIR}/${num}_$1.txt"
  {
    echo "# Beleg ${num} — $1"
    echo "# Stufe: ${stufe}"
    echo "# Erhoben: $(date -u +"%Y-%m-%dT%H:%M:%SZ") (UTC) / $(date)"
    echo "# Host: $(hostname -f 2>/dev/null || hostname)"
    echo "# Tool: wp_plesk_forensik.sh v${TOOL_VERSION}"
    echo "# ------------------------------------------------------------"
    echo "$2"
  } > "$file"
  # Maschinenlesbares Verzeichnis. Die Kopfzeile im Beleg ist fuer Menschen;
  # wer ein Paket schnuert, soll nicht 113 Dateien aufmachen muessen.
  printf '%s\t%s\t%s\t%s\n' "$num" "$stufe" "$1" "${num}_$1.txt" \
    >> "${BELEGE_DIR}/00_verzeichnis.tsv"
  echo "  Beleg: belege/${num}_$1.txt" >> "$REPORT_FILE"
}

# ── Netzabruf mit Protokoll (v3.8, nur mit --online) ─────────
# NT-Forensik behauptet an mehreren Stellen, read-only und rein lokal zu
# arbeiten. Sobald --online gesetzt ist, stimmt der zweite Teil nicht mehr —
# und das muss belegbar im Bericht stehen, nicht nur im Kopf des Prüfers.
# Jeder Abruf wird mit URL, HTTP-Code, Größe und SHA256 protokolliert.
#
# -L ist zwingend: Release-Downloads antworten mit 302 auf einen
# Auslieferungsdienst. Ohne Folgen der Weiterleitung landet nur die
# 302-Antwort in der Zieldatei und der Abruf scheitert stumm.
# Das Zeitlimit muss ein vollständiges Programmpaket zulassen (rund 30 MB).
# nf_fetch <url> <zieldatei>  → 0 bei HTTP 200
nf_fetch() {
  local url="$1" dest="$2" code sz sum
  code=$(curl -fsSL --max-time 300 --retry 1 -o "$dest" -w '%{http_code}' "$url" 2>/dev/null || echo "000")
  sz=$(stat -c%s "$dest" 2>/dev/null || echo 0)
  sum=$(sha256sum "$dest" 2>/dev/null | awk '{print $1}')
  ONLINE_FETCHES+="$(date -u +"%Y-%m-%dT%H:%M:%SZ")  ${url}  HTTP=${code}  ${sz}B  SHA256=${sum:-–}"$'\n'
  [[ "$code" == "200" ]]
}

# Sichere grep-Zählung (kein set -e Abbruch, immer eine Zahl)
count_grep() {
  local n
  n=$(grep -cE "$1" "$2" 2>/dev/null) || true
  echo "${n:-0}"
}
count_grep_i() {
  local n
  n=$(grep -icE "$1" "$2" 2>/dev/null) || true
  echo "${n:-0}"
}

# ── Modul-Metadaten und Auswahl ──────────────────────────────
# Jedes Modul beschreibt sich im eigenen Kopf (@nummer/@titel/@frage/
# @kosten/@ebene). Es gibt bewusst keine zentrale Liste — die würde
# auseinanderlaufen, sobald jemand ein Modul hinzufügt oder umbenennt.
modul_feld() {   # modul_feld <datei> <feldname>
  sed -n "s/^# @${2}:[[:space:]]*//p" "$1" 2>/dev/null | head -1
}

# Gehört dieser Abschnitt in den Lauf?
#   modul_gewaehlt <nummer> <ebene>
# --nur gewinnt gegen --ohne. Abschnitt 14 (Berichte) läuft immer mit,
# ausser er wird ausdrücklich per --ohne 14 abgewählt: ein Lauf ohne
# Bericht und ohne findings.json ist praktisch nie gewollt.
modul_gewaehlt() {
  local nr="$1" ebene="${2:-}"
  case ",${MODUL_OHNE}," in *",${nr},"*) return 1 ;; esac
  if [[ -n "$MODUL_NUR" ]]; then
    [[ "$nr" == "14" ]] && return 0
    case "$MODUL_NUR" in
      ebene:*) [[ "$ebene" == "${MODUL_NUR#ebene:}" ]] && return 0 || return 1 ;;
    esac
    case ",${MODUL_NUR}," in *",${nr},"*) return 0 ;; *) return 1 ;; esac
  fi
  return 0
}

# ── Fremdkunden aus dem Bericht halten ──────────────────────────────────────
# Ein Bericht ueber EINEN Kunden darf keine Daten anderer Kunden enthalten.
# Auf einem Shared-Host mit 482 vhosts standen in einem Lauf ueber ein einzelnes
# Abo 112 fremde Kennungen: Domainnamen, Systembenutzer, deren Cronjobs und
# SSH-Schluessel. Das ist nicht nur unsauber, es ist eine Weitergabe
# personenbezogener Daten an einen Dritten.
#
# Geloescht wird nicht, sondern pseudonymisiert: aus jeder fremden Kennung wird
# stabil derselbe Platzhalter. Damit bleibt erkennbar, dass zwei Zeilen denselben
# Nachbarn betreffen — was fuer die Bewertung eines serverweiten Musters noetig
# ist —, ohne dass jemand erfaehrt, WER dieser Nachbar ist.
#
# Die serverweiten Abschnitte behalten damit ihren Sinn: "27 shell-faehige
# Benutzer" bleibt eine belastbare Aussage ueber den Server, ohne 27 Kundennamen.
# nf_fremdkunden_maskieren <datei> [pruefen]
#
# Mit 'pruefen' als zweitem Argument wird NICHTS geschrieben — die Funktion
# meldet nur, welche fremden Kennungen sie finden wuerde, und gibt 1 zurueck,
# wenn es welche gibt. Das ist die Endpruefung vor der Auslieferung, und sie
# nutzt bewusst DIESELBE Erkennung wie die Maskierung selbst.
#
# Der erste Entwurf hatte dafuer eine eigene, engere Pruefung: sie kannte nur
# vhost-Pfade und webNN-Kennungen. Die Maskierung erkennt zusaetzlich blanke
# Domains und Mailadressen — und genau so eine blanke URL stand im Testlauf im
# Kundenbericht, waehrend die Endpruefung "sauber" meldete. Ein Riegel, der
# enger greift als das Netz dahinter, ist keiner.
nf_fremdkunden_maskieren() {   # nf_fremdkunden_maskieren <datei> [pruefen]
  local datei="$1" NF_MODUS="${2:-schreiben}"
  [[ -r "$datei" ]] || return 0
  [[ "$SCOPE_MODE" == "global" ]] && return 0   # Betreiberbericht darf alles
  local eigene; eigene=$(printf '%s\n' "${SCAN_PATHS[@]:-}" | sed "s|.*/||" | grep -v '^$' | paste -sd'|' -)
  [[ -n "${ABO_USER:-}" ]] && eigene="${eigene}|${ABO_USER}"
  [[ -n "${DOMAIN:-}"   ]] && eigene="${eigene}|${DOMAIN}"
  eigene="${eigene#|}"; eigene="${eigene%|}"
  # Ohne Eigenliste waere ALLES fremd — auch die Domain des geprueften Kunden.
  # Ein Bericht, in dem der eigene Kunde als "<anderer Kunde 1>" steht, ist
  # wertlos, und der Fehler faellt erst beim Lesen auf. Lieber gar nicht
  # maskieren als falsch: dann bleibt der Bericht wenigstens erkennbar roh.
  if [[ -z "$eigene" ]]; then
    echo "  Maskierung uebersprungen: kein eigener Bezug bestimmbar (SCAN_PATHS/DOMAIN leer)." >&2
    return 1
  fi
  EIGENE_RE="$eigene" NF_MODUS="$NF_MODUS" python3 - "$datei" <<'PY'
import os, re, sys
p = sys.argv[1]
eigen = re.compile(r'^(' + os.environ.get("EIGENE_RE", "___nichts___") + r')$')
txt = open(p, encoding="utf-8", errors="replace").read()
zuordnung, zaehler = {}, [0]
def platzhalter(name):
    if name not in zuordnung:
        zaehler[0] += 1
        zuordnung[name] = "<anderer Kunde %d>" % zaehler[0]
    return zuordnung[name]
def ersetze_vhost(m):
    name = m.group(1)
    return m.group(0) if eigen.match(name) else "/var/www/vhosts/" + platzhalter(name)
txt = re.sub(r'/var/www/vhosts/([^/\s"\'\)\],]+)', ersetze_vhost, txt)
def ersetze_user(m):
    name = m.group(0)
    return name if eigen.match(name) else platzhalter(name)
# Plesk leitet auch Mail- und FTP-Konten vom Systembenutzer ab: an die
# Abo-Kennung haengt ein Suffix (webNN -> webNNpN). Ein Wortende nach der
# Ziffer laesst diese Konten stehen — auf einem echten Server blieb so eine
# Mailadresse der Form "webNNpN@..." im maskierten Beleg zurueck.
txt = re.sub(r'\bweb\d+[a-z0-9_]*', ersetze_user, txt)

# Fremde Kunden stehen nicht nur als vhost-Pfad im Bericht, sondern auch als
# blanke Domain und als Mailadresse — in einem Beleg waren es 226 Domainnamen
# ohne jeden Pfad davor. Eine Maskierung, die nur Pfade kennt, laesst die
# Kundenliste des Servers unveraendert stehen.
#
# Umgekehrte Logik: alles was wie eine Domain aussieht wird maskiert, AUSSER
# den eigenen und einer Liste technischer Domains. Eine Positivliste ist hier
# richtig — bei einer Negativliste faellt jeder neue Kunde durchs Raster, und
# das faellt niemandem auf.
TECHNISCH = re.compile(r'\.(?:arpa|local|localdomain|invalid|test|example)$|^(?:'
    r'wordpress\.(?:org|com)|w\.org|php\.net|debian\.org|ubuntu\.com|canonical\.com|'
    r'plesk\.com|cloudlinux\.com|imunify360\.com|imunify\.com|letsencrypt\.org|'
    r'googleapis\.com|google\.com|gstatic\.com|github\.com|githubusercontent\.com|'
    r'schema\.org|gravatar\.com|jquery\.com|unpkg\.com|jsdelivr\.net|'
    r'mysql\.com|oracle\.com|apache\.org|nginx\.org|openssl\.org|python\.org|'
    r'kernel\.org|systemd\.io|freedesktop\.org|npmjs\.com|packagist\.org'
    r')$', re.I)

def _domain_frei(d):
    dl = d.lower()
    return bool(eigen.match(dl)) or bool(TECHNISCH.search(dl)) or dl.endswith(tuple(
        '.' + e for e in (os.environ.get("EIGENE_RE","").split('|')) if e))

def ersetze_mail(m):
    lokal, dom = m.group(1), m.group(2)
    if _domain_frei(dom):
        return m.group(0)
    return platzhalter(dom.lower()).replace("Kunde", "Adresse")
txt = re.sub(r'\b([A-Za-z0-9._%+-]+)@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b', ersetze_mail, txt)

def ersetze_domain(m):
    d = m.group(0)
    return d if _domain_frei(d) else platzhalter(d.lower())
txt = re.sub(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+'
             r'(?:de|com|net|org|eu|info|shop|online|io|dev|at|ch|nl|fr|it|es|uk|live|xyz|top|site|club)\b',
             ersetze_domain, txt)
# Pruefmodus: nichts schreiben, nur melden, was gefunden wurde.
if os.environ.get("NF_MODUS") == "pruefen":
    if zuordnung:
        print("\n".join(sorted(zuordnung)))
    sys.exit(1 if zuordnung else 0)

if zuordnung:
    txt += ("\n\n---\n\n> **Hinweis zum Datenschutz.** Dieser Server beherbergt weitere Kunden. "
            "Wo serverweite Prüfungen deren Domains oder Systemkonten berührten, stehen "
            "Platzhalter (`<anderer Kunde N>`); derselbe Nachbar trägt dabei immer dieselbe "
            "Nummer, sodass Zusammenhänge erkennbar bleiben. Betroffen waren %d fremde "
            "Kennungen. Die unmaskierte Fassung verbleibt beim Betreiber.\n" % len(zuordnung))
open(p, "w", encoding="utf-8").write(txt)
print("  %d fremde Kennungen maskiert" % len(zuordnung))
PY
}