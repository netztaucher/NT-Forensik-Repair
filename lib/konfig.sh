# shellcheck shell=bash
# ============================================================
# NT-Forensik — Konfiguration, Argumente, Ablage
# ------------------------------------------------------------
# Pfadkonstanten, Version, Argumentauswertung, Laufordner, Root-Pruefung,
# Selbst-Installation. Dazu die aus Pruefabschnitten hochgezogenen Werte
# SCAN_PATH, PLESK_MYSQL_PW — sie werden von mehreren Abschnitten gebraucht
# und muessen unabhaengig davon bereitstehen, welche Abschnitte laufen.
# 
# Wird vom Runner als erstes eingebunden. Setzt keine Ausgabe ab.
# ============================================================

# ── Farben ──────────────────────────────────────────────────
RED='\033[0;31m'; YLW='\033[0;33m'; GRN='\033[0;32m'
BLU='\033[0;34m'; CYN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

# Markenblau fürs Banner. Das reine #003366 wäre auf dunklem Terminal
# praktisch unlesbar — gemessener Kontrast 1,67:1 gegen Schwarz. #0073E6 hat
# denselben Farbton (210°) und dieselbe Sättigung, nur mehr Helligkeit, und
# ist die einzige Stufe dieser Reihe, die gegen Schwarz UND gegen Weiss über
# 4,5:1 kommt (4,59 bzw. 4,57). Truecolor beherrscht nicht jedes Terminal;
# ohne Nachweis bleibt es beim gewöhnlichen Blau statt bei kaputten Escapes.
case "${COLORTERM:-}" in
  truecolor|24bit) NT_BLAU='\033[38;2;0;115;230m' ;;
  *)               NT_BLAU="$BLU" ;;
esac

# ── Feste Infrastruktur-Pfade (netztaucher Plesk-Standard) ──
# Ueberschreibbar ausschliesslich fuer den Pruefstand (werkzeuge/goldmuster.sh
# und die CI). Ein echter Lauf setzt diese Variablen nicht — er findet die
# Vorgaben vor, die dem Plesk-Standard entsprechen. Der Grund fuer die
# Ueberschreibbarkeit: ohne sie laesst sich das Werkzeug nur auf einem echten
# Produktivsystem ausfuehren, und genau das hat dazu gefuehrt, dass Fehler
# regelmaessig erst dort auffielen statt in einem Testlauf.
BASE_DIR="${NT_BASE_DIR:-/root/wartungsscripte}"
FORENSIK_BASE="${BASE_DIR}/forensik"
VHOSTS_DIR="${NT_VHOSTS_DIR:-/var/www/vhosts}"
PLESK_LOG_DIR="/var/log/plesk"
PLESK_PANEL_LOG="${PLESK_LOG_DIR}/panel.log"

# ── Konfiguration ────────────────────────────────────────────
TOOL_VERSION="3.14.0"
DAYS_BACK=30   # Analysezeitraum in Tagen

# ── Argumente & Scope (v3.5) ─────────────────────────────────
# Drei Betriebsarten. Die Server-/Rootebene (Abschnitte 3,5,6,8,9,13) läuft
# in ALLEN Modi mit — der Scope steuert nur den Dateisystem-Scan (Abschnitt 7)
# und, welche Berichte für wen erzeugt werden (siehe Abschnitt 14).
#   --domain <d>  ein Kunde         (= bisheriges Positionsargument)
#   --path <p>    beliebiger Pfad   (Unterordner, Nicht-Plesk-Webspace)
#   --global      alle vhosts       → Betreiberbericht + je-vhost Kundenberichte
# Ohne Argument = --global (rückwärtskompatibel: leeres DOMAIN scannte schon
# immer alle vhosts). Ein blankes Positionsargument bleibt = --domain.
DOMAIN=""
SCOPE_MODE="global"      # global | domain | path | abo
SCAN_PATH_ARG=""         # nur bei --path
ABO_USER=""              # nur bei --webNN / --abo: der Plesk-Systembenutzer
ABO_MIT_SERVER=0         # --mit-server: serverweite Abschnitte trotz Abo-Scope
SCAN_PATHS=()            # ALLE zu prüfenden Wurzeln. Ein Plesk-Abo besitzt oft
                         # mehrere vhost-Verzeichnisse (Hauptdomain, Subdomains,
                         # System-Domain) — ein einzelner Pfad würde sie
                         # übersehen. SCAN_PATH bleibt der erste davon, damit
                         # alles Bestehende unverändert weiterläuft.
WANT_YARA=0              # 7.11 nur auf Wunsch (teuer auf großen Webspaces)
WANT_ONLINE=0            # --online: Joomla-Prüfsummen/Schwachstellenliste nachladen
SCOPE_GESETZT=0          # wurde ein Scope ausdrücklich angegeben? (steuert das Menü)
WANT_MENUE=-1            # -1 = automatisch, 0 = nie, 1 = erzwungen
MODUL_NUR=""             # --nur:  Komma-Liste von Abschnittsnummern
MODUL_OHNE=""            # --ohne: Komma-Liste von Abschnittsnummern
NUR_ROOT=0               # --nur-root: nur die Root-Frage, kompakte Aussage
REZEPT_NUR=""            # --nur-rezept: Komma-Liste von Rezeptnamen
REZEPT_OHNE=""           # --nowordpress u. a.: Komma-Liste abgewaehlter Rezepte
REZEPT_KOPIEN=0          # vom Rahmen je Rezept gesetzt

# Banner. Steht hier und nicht im Runner, weil --help es ebenfalls ausgibt und
# die Hilfe erscheint, lange bevor der Runner den Banner-Punkt erreicht.
# Die Fassung kommt aus TOOL_VERSION — sie war frueher dreimal fest verdrahtet
# und stand nach der Modularisierung dauerhaft auf einem alten Stand.
banner_zeigen() {
  # Kein BOLD: die Blockzeichen sind ohnehin flächig, und Fettschrift
  # verschiebt in manchen Terminals die Farbe in eine hellere Palette —
  # womit der gemessene Kontrast nicht mehr der wäre, den man gewählt hat.
  echo -e "${NT_BLAU}"
  cat <<EOF
███████  ██████  ██████  ███████ ███    ██ ███████ ██ ██   ██
██      ██    ██ ██   ██ ██      ████   ██ ██      ██ ██  ██
█████   ██    ██ ██████  █████   ██ ██  ██ ███████ ██ █████
██      ██    ██ ██   ██ ██      ██  ██ ██      ██ ██ ██  ██
██       ██████  ██   ██ ███████ ██   ████ ███████ ██ ██   ██
  WP-PLESK-FORENSIK v${TOOL_VERSION} — netztaucher | digital
EOF
  echo -e "${NC}"
}

usage() {
  banner_zeigen
  cat <<USAGE
wp_plesk_forensik.sh v${TOOL_VERSION} — read-only WordPress/Plesk-Forensik

Verwendung:
  sudo bash $0 [SCOPE] [Optionen]
  sudo bash $0 kunde.tld                 # Kurzform für --domain kunde.tld

Scope (eines):
  --webNN                 EIN Plesk-Abo (NN = Nummer des Plesk-Systembenutzers).
                          Erfasst ALLE vhost-
                          Verzeichnisse dieses Abos (Hauptdomain, Subdomains,
                          System-Domain) und lässt die serverweiten Abschnitte
                          weg — sonst stünden fremde Kunden im Bericht.
                          Mit --mit-server kommen sie dazu.
  --abo <benutzer>        Wie --webNN, für Abos ohne webNN-Namen
  --domain <domain.tld>   Einen Kunden prüfen; Kundenbericht nur mit dessen Daten
  --path   <pfad>         Beliebigen Pfad/Webspace prüfen. ACHTUNG: begrenzt nur
                          die Abschnitte, die den Pfad auswerten (7, 11, 12);
                          die serverweiten laufen weiter über den ganzen Server.
                          Für "nur dieser Kunde" ist --webNN das richtige.
  --global                Alle vhosts (Standard): Betreiberbericht + je vhost
                          ein eigener, gefilterter Kundenbericht

Abschnittsauswahl:
  --nur <n[,n…]>          Nur diese Prüfabschnitte (z. B. --nur 12)
  --ohne <n[,n…]>         Alle ausser diesen (z. B. --ohne 2,10)
  --nur-joomla            Kurzform für --nur 12
  --nur-rezept <app>      Nur dieses Prüfrezept (z. B. --nur-rezept nextcloud).
                          Verfügbare Rezepte: siehe Verzeichnis rezepte/
  --nur-nextcloud         Kurzform für --nur-rezept nextcloud
  --nur-root              Nur die Root- und Eskalationsprüfung. Beantwortet die
                          eine serverweite Frage, die der Kunde braucht — ist
                          jemand über den Webspace hinausgekommen? — und legt
                          die Antwort als root_aussage.md ab, ohne Daten
                          anderer Kunden. Läuft in Minuten statt Stunden.
  --nojoomla              Joomla-Prüfung weglassen (= --ohne 12)
  --nowordpress           WordPress-Rezept weglassen
  --nur-website           Nur die Abschnitte, die den Webauftritt prüfen
                          (überspringt die serverweiten — deutlich schneller)
  --mit-server            Bei --webNN die serverweiten Abschnitte mitprüfen

Optionen:
  --yara                  YARA-Signaturscan (7.11) aktivieren (langsam auf
                          großen Webspaces; ohne Flag übersprungen)
  --online                Prüfdaten bei Bedarf aus dem Netz nachladen: Joomla-
                          Prüfsummen und Schwachstellenliste sowie die Plugin-
                          Prüfsummen von wordpress.org (ein Abruf je Plugin,
                          auf grossen Servern spürbar).
                          OHNE dieses Flag arbeitet der Lauf rein offline aus
                          dem mitgelieferten Datenbestand; die Plugin-Integrität
                          bleibt dann ungeprüft und wird als solche ausgewiesen.
                          Der Schwachstellen-Abgleich braucht das Flag NICHT —
                          er arbeitet aus dem ausgelieferten Datenbestand.
                          Jeder Abruf wird im Bericht und als Beleg ausgewiesen.
  --kein-menue            Startmenü unterdrücken (für Cronjobs und Skripte)
  --menue                 Startmenü erzwingen
  -h, --help              Diese Hilfe

Ohne Scope-Argument startet das Menü. Wird ein Scope angegeben, läuft die
Prüfung direkt durch — bestehende Aufrufe und Skripte bleiben unverändert.

Die Server-/Rootebene wird mitgeprüft — ausser bei --webNN, wo sie bewusst
entfällt, damit keine fremden Kunden im Bericht stehen; mit --mit-server
kommt sie dazu. In Kundenberichten werden Rootbefunde nur allgemein
(betroffen/nicht betroffen) genannt und IP-Adressen/E-Mails maskiert.

Der Berichtskopf weist immer aus, welche Abschnitte NICHT gelaufen sind —
ein Teillauf darf sich nicht wie ein vollständiges Ergebnis lesen.
USAGE
}

# Argumente kommen aus NT_ARGV (vom Runner gesichert), nicht aus $@:
# diese Datei wird per 'source' aus einer Funktion eingebunden, dort ist $@
# die Argumentliste der Funktion.
set -- "${NT_ARGV[@]:-}"
[[ $# -eq 1 && -z "$1" ]] && shift    # leeres Element bei leerem NT_ARGV

while [[ $# -gt 0 ]]; do
  case "$1" in
    --domain) SCOPE_MODE="domain"; DOMAIN="${2:-}"; SCOPE_GESETZT=1; shift 2 ;;
    --path)   SCOPE_MODE="path";   SCAN_PATH_ARG="${2:-}"; SCOPE_GESETZT=1; shift 2 ;;
    --global) SCOPE_MODE="global"; SCOPE_GESETZT=1; shift ;;
    # Ein Plesk-Abo als Ganzes. --webNN ist die Kurzform, die dem entspricht,
    # was in Plesk und im Gespraech tatsaechlich gesagt wird ("prüf mal das Abo").
    # --abo <name> deckt Systembenutzer ab, die nicht webNN heissen.
    --web[0-9]*) SCOPE_MODE="abo"; ABO_USER="${1#--}"; SCOPE_GESETZT=1; shift ;;
    --abo)       SCOPE_MODE="abo"; ABO_USER="${2:-}";  SCOPE_GESETZT=1; shift 2 ;;
    --mit-server)  ABO_MIT_SERVER=1; shift ;;
    --yara)   WANT_YARA=1; shift ;;
    --online) WANT_ONLINE=1; shift ;;
    --nur)    MODUL_NUR="${2:-}";  shift 2 ;;
    --ohne)   MODUL_OHNE="${2:-}"; shift 2 ;;
    --nur-joomla)  MODUL_NUR="12" ; shift ;;
    # Nextcloud getrennt ansprechbar: 12b sucht nach Uebernahme, 12c misst den
    # Haertungsstand. Beides ist einzeln waehlbar (--nur 12b / --nur 12c);
    # dieser Schalter nimmt beide, weil sie in der Praxis zusammen gefragt sind.
    # Rezepte werden ueber ihren Namen gewaehlt, nicht ueber Abschnittsnummern.
    # Ein neues Rezept ist damit sofort ansprechbar, ohne dass hier etwas
    # nachgetragen werden muss.
    --nur-rezept)    MODUL_NUR="12r"; REZEPT_NUR="${2:-}"; shift 2 ;;
    --nur-nextcloud) MODUL_NUR="12r"; REZEPT_NUR="nextcloud"; shift ;;
    # Die Root-Frage getrennt beantworten. Sie ist die einzige serverweite
    # Aussage, die der Kunde wirklich braucht — "ist jemand ueber meinen
    # Webspace hinausgekommen?" —, und sie laesst sich ohne die uebrigen
    # serverweiten Abschnitte beantworten. Damit muss nicht mehr --mit-server
    # laufen, das Benutzerlisten, Cronjobs und Domains fremder Kunden in den
    # Bericht zieht, nur damit am Ende eine Zeile Verdikt darin steht.
    --nur-root)    MODUL_NUR="13"; NUR_ROOT=1; SCOPE_GESETZT=1; shift ;;
    --nur-website) MODUL_NUR="ebene:website"; shift ;;
    # Abwaehlen einzelner CMS, ohne Abschnittsnummern nachschlagen zu muessen.
    --nojoomla|--ohne-joomla)       MODUL_OHNE="${MODUL_OHNE:+${MODUL_OHNE},}12"; shift ;;
    --nowordpress|--ohne-wordpress) REZEPT_OHNE="${REZEPT_OHNE:+${REZEPT_OHNE},}wordpress"; shift ;;
    --kein-menue)  WANT_MENUE=0; shift ;;
    --menue)       WANT_MENUE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    --) shift; break ;;
    -*) echo "Unbekannte Option: $1" >&2; usage >&2; exit 2 ;;
    *)  # Positionsargument = Domain (Rückwärtskompatibilität)
        SCOPE_MODE="domain"; DOMAIN="$1"; SCOPE_GESETZT=1; shift ;;
  esac
done

# Plausibilität
if [[ "$SCOPE_MODE" == "domain" && -z "$DOMAIN" ]]; then
  echo "Fehler: --domain ohne Domain-Angabe." >&2; usage >&2; exit 2
fi
if [[ "$SCOPE_MODE" == "path" && -z "$SCAN_PATH_ARG" ]]; then
  echo "Fehler: --path ohne Pfad-Angabe." >&2; usage >&2; exit 2
fi

# ── Prüfumfang ableiten ──────────────────────────────────────
# Als Funktion, weil das Startmenü den Umfang nachträglich ändern kann.
# Der Runner ruft sie auf, nachdem das Menü durch ist.

# Wo liegt der Dokumentenstamm dieser Domain wirklich?
#
# ${VHOSTS_DIR}/<domain> ist die Plesk-Vorgabe, aber nur die Vorgabe. Wer eine
# Domain in ein anderes Abo legt, bekommt dort ein leeres Geruest — anon_ftp,
# cgi-bin, error_docs und ein httpdocs ohne Inhalt —, waehrend die Installation
# unter dem Abo der Hauptdomain liegt. Auf einem geprueften Host traf das 29
# Domains: /var/www/vhosts/tdl.therapeut.digital/httpdocs war leer, die
# Installation lag unter /var/www/vhosts/<abo>/tdl.therapeut.digital.
#
# Das Geruest zu pruefen liefert "keine Installation im Pruefumfang" und einen
# Bericht ohne Befunde. Das ist keine Entwarnung, sieht aber genauso aus.
# Deshalb fragen wir Plesk statt zu raten.
plesk_www_root() {   # plesk_www_root <domain>  ->  Pfad oder leer
  command -v plesk >/dev/null 2>&1 || return 0
  plesk db -Ne "SELECT h.www_root FROM domains d JOIN hosting h ON h.dom_id = d.id WHERE d.name = '${1//\'/}' LIMIT 1" 2>/dev/null | head -1
}

# Aus dem Dokumentenstamm den zu pruefenden Ordner ableiten.
# Standard-Layout .../<domain>/httpdocs -> eine Ebene hoeher, damit logs/ und
# conf/ im Umfang bleiben (bisheriges Verhalten). Jedes andere Layout -> genau
# der gemeldete Pfad. Nicht der Elternordner: der waere bei abweichendem Layout
# das ganze Abo mit allen fremden Domains darin.
scan_pfad_aus_www_root() {   # scan_pfad_aus_www_root <www_root>
  local wr="$1"
  [[ -n "$wr" ]] || return 1
  if [[ "$(basename "$wr")" == "httpdocs" ]]; then printf '%s\n' "$(dirname "$wr")"
  else                                             printf '%s\n' "$wr"; fi
}

scan_path_bestimmen() {
  local _wr _plesk_pfad
  case "$SCOPE_MODE" in
    path)   SCAN_PATH="$SCAN_PATH_ARG"; SCAN_PATHS=("$SCAN_PATH") ;;
    domain)
            SCAN_PATH="${VHOSTS_DIR}/${DOMAIN}"
            _wr="$(plesk_www_root "$DOMAIN")"
            _plesk_pfad="$(scan_pfad_aus_www_root "$_wr")"
            if [[ -n "$_plesk_pfad" && "$_plesk_pfad" != "$SCAN_PATH" ]]; then
              echo -e "${YLW}Hinweis:${NC} ${DOMAIN} liegt laut Plesk nicht unter ${SCAN_PATH}." >&2
              echo    "         Dokumentenstamm: ${_wr}" >&2
              echo    "         Geprüft wird:    ${_plesk_pfad}" >&2
              SCAN_PATH="$_plesk_pfad"
            fi
            SCAN_PATHS=("$SCAN_PATH") ;;
    abo)    abo_pfade_bestimmen ;;
    *)      SCAN_PATH="$VHOSTS_DIR"; SCAN_PATHS=("$SCAN_PATH") ;;   # global
  esac
  # Fallback: gesetzte Domain ohne existierenden vhost -> serverweit statt ins Leere
  # Eine --domain ohne existierendes vhost-Verzeichnis eskalierte hier
  # STILLSCHWEIGEND auf serverweit: aus "pruefe diesen einen Kunden" wurde
  # "pruefe alle", ohne dass es jemand erfuhr — auf einem Host mit 482 vhosts
  # der denkbar groesste Datenschutzunfall. Ein Tippfehler in der Domain
  # genuegte.
  if [[ "$SCOPE_MODE" == "domain" && ! -d "$SCAN_PATH" ]]; then
    echo -e "${RED}Fehler:${NC} Für --domain ${DOMAIN} gibt es kein Verzeichnis unter ${SCAN_PATH}." >&2
    echo    "        Tippfehler? Verfügbare Verzeichnisse:" >&2
    ls -1d "${VHOSTS_DIR}"/*/ 2>/dev/null | sed "s|${VHOSTS_DIR}/||;s|/$||" | head -20 | sed 's/^/          /' >&2
    echo    "        Für einen serverweiten Lauf ausdrücklich --global angeben." >&2
    exit 2
  fi

  # Ein vhost-Geruest ohne Inhalt ist kein Pruefumfang. Wer hier weiterlaeuft,
  # bekommt einen Bericht ohne Befunde und haelt ihn fuer eine Entwarnung.
  if [[ "$SCOPE_MODE" == "domain" ]] \
     && [[ -d "${SCAN_PATH}/httpdocs" ]] \
     && [[ -z "$(ls -A "${SCAN_PATH}/httpdocs" 2>/dev/null)" ]]; then
    echo -e "${RED}Fehler:${NC} ${SCAN_PATH}/httpdocs ist leer — dort liegt keine Installation." >&2
    echo    "        Das ist ein Plesk-Geruest, kein Webauftritt. Ein Lauf darauf" >&2
    echo    "        meldet null Befunde und sieht wie eine Entwarnung aus." >&2
    if command -v plesk >/dev/null 2>&1; then
      echo  "        Plesk nennt als Dokumentenstamm: $(plesk_www_root "$DOMAIN")" >&2
    fi
    echo    "        Mit --path auf den tatsächlichen Pfad prüfen." >&2
    exit 2
  fi
}

# ── Abschnittsauswahl gegen die tatsaechlich vorhandenen Module pruefen ──────
#
# --nur nimmt jede Zahl entgegen. Steht dort eine Nummer, die es nicht gibt,
# laeuft nur Abschnitt 14 (Berichte, laeuft immer mit) und der Bericht meldet
# "0 kritisch" — bei counts durchweg 0 und leerem Belegordner. Das ist die
# gefaehrlichste Ausgabe des Werkzeugs: sie sieht aus wie ein Ergebnis.
#
# Der konkrete Anlass: --nur 11. Abschnitt 11 war einmal die WordPress-
# Datenbankpruefung und ist heute ein Rezept (12r). Die Nummer steht weiterhin
# in Anleitungen und stand bis zu diesem Commit auch im eigenen Startmenue.
modul_auswahl_pruefen() {
  [[ -n "${MODUL_NUR}${MODUL_OHNE}" ]] || return 0
  case "$MODUL_NUR" in ebene:*) return 0 ;; esac

  local bekannt="" f nr eintrag unbekannt=""
  for f in "${SELF_DIR}"/module/*.sh; do
    [[ -f "$f" ]] || continue
    nr="$(sed -n 's/^# @nummer:[[:space:]]*//p' "$f" 2>/dev/null | head -1)"
    [[ -n "$nr" ]] && bekannt="${bekannt}${nr},"
  done
  [[ -n "$bekannt" ]] || return 0   # keine Modulkoepfe lesbar -> nicht im Weg stehen

  for eintrag in ${MODUL_NUR//,/ } ${MODUL_OHNE//,/ }; do
    [[ -n "$eintrag" ]] || continue
    case ",${bekannt}" in *",${eintrag},"*) continue ;; esac
    unbekannt="${unbekannt}${eintrag} "
  done
  [[ -n "$unbekannt" ]] || return 0

  echo -e "${RED}Fehler:${NC} unbekannte Abschnittsnummer(n): ${unbekannt% }" >&2
  echo    "        Vorhanden: ${bekannt%,}" >&2
  case " $unbekannt " in
    *" 11 "*)
      echo "" >&2
      echo -e "        ${BOLD}Abschnitt 11 gibt es nicht mehr.${NC}" >&2
      echo    "        Die WordPress-Prüfung ist ein Rezept:  --nur-rezept wordpress" >&2
      echo    "        Für Joomla:                            --nur-joomla" >&2
      echo    "        Für Nextcloud:                         --nur-nextcloud" >&2
      ;;
  esac
  echo "" >&2
  echo "        Ein Lauf mit unbekannter Nummer prüft nichts und meldet 0 Befunde." >&2
  exit 2
}

# Welche vhost-Verzeichnisse dieser Lauf ansehen darf — eine Zeile je Pfad.
#
# Mehrere Abschnitte haben das frueher selbst entschieden, und zwar falsch:
# sie verzweigten allein ueber $DOMAIN und fielen sonst auf ${VHOSTS_DIR}/*
# zurueck. Damit war jeder Lauf ohne --domain serverweit, auch mit --path.
# Auf einem Produktivsystem zog Abschnitt 11 so 57 fremde Installationen in einen Bericht, der
# ein einzelnes Abo pruefen sollte. Die Entscheidung gehoert an EINE Stelle.
scope_vhost_dirs() {
  local d
  if [[ "$SCOPE_MODE" == "global" ]]; then
    for d in "${VHOSTS_DIR}"/*/; do [[ -d "$d" ]] && printf '%s\n' "${d%/}"; done
  else
    printf '%s\n' "${SCAN_PATHS[@]}"
  fi
}

# Alle vhost-Verzeichnisse eines Plesk-Abos einsammeln.
# Der Systembenutzer ist die verlässliche Klammer: Plesk legt für ein Abo einen
# Benutzer (webNN) an, dem sämtliche vhost-Verzeichnisse gehören — Hauptdomain,
# eigenständige Subdomains und die System-Domain webNN.<server>. Nur das
# Home-Verzeichnis zu nehmen würde die Hauptdomain übersehen: auf einem real
# geprüften Abo gehörten dem Benutzer drei Verzeichnisse — Hauptdomain,
# eine Subdomain und die System-Domain —, und die eigentliche Website lag
# NICHT im Home-Verzeichnis.
abo_pfade_bestimmen() {
  if ! id -u "$ABO_USER" >/dev/null 2>&1; then
    echo "Fehler: Systembenutzer '${ABO_USER}' existiert nicht." >&2
    echo "        Plesk-Abos heissen üblicherweise webNN — siehe 'getent passwd | grep vhosts'." >&2
    exit 2
  fi
  local _uid _d
  _uid="$(id -u "$ABO_USER")"
  SCAN_PATHS=()
  for _d in "${VHOSTS_DIR}"/*/; do
    [[ -d "$_d" ]] || continue
    if [[ "$(stat -c %u "$_d" 2>/dev/null || stat -f %u "$_d" 2>/dev/null)" == "$_uid" ]]; then
      SCAN_PATHS+=("${_d%/}")
    fi
  done
  if [[ ${#SCAN_PATHS[@]} -eq 0 ]]; then
    echo "Fehler: Zu '${ABO_USER}' gehört kein Verzeichnis unter ${VHOSTS_DIR}." >&2
    exit 2
  fi
  SCAN_PATH="${SCAN_PATHS[0]}"
  # Ein Abo-Lauf meint den Kunden, nicht den Server. Die serverweiten Abschnitte
  # (Benutzer, Cronjobs, Netzdienste, andere Domains) werten den Scope gar nicht
  # aus und zögen bei 482 vhosts alles Fremde in den Bericht — genau der Grund,
  # aus dem dieser Schalter entstanden ist. Wer beides will, nimmt --mit-server.
  if [[ "$ABO_MIT_SERVER" != "1" && -z "$MODUL_NUR" ]]; then
    MODUL_NUR="ebene:website"
  fi
}

# ── Ablage einrichten ────────────────────────────────────────
# Ebenfalls als Funktion: der Laufordner trägt Host und geprüfte Domain im
# Namen, und die stehen erst nach dem Menü fest.
#
# Namensschema: <datum>_<host>_<scope>, z.B. 2026-09-01_12-50-23_k42_server.
# Datum deutsch lesbar (Jahr-Monat-Tag_Std-Min-Sek), bleibt ISO-sortierbar.
# host: NT_HOST (im Wrapper gesetzt, z.B. k42) sonst der kurze Hostname —
#       damit ein zentral gesammelter Lauf bei mehreren Servern zuzuordnen ist.
# scope: server (kompletter Serverlauf), die Domain (einzel-vhost),
#        abo-<webNN> (Plesk-Abo) oder path (Pfad-Scan ohne ableitbare Domain).
ablage_einrichten() {
  TIMESTAMP=$(date +%Y-%m-%d_%H-%M-%S)
  HOST_SLUG="$(printf '%s' "${NT_HOST:-$(hostname -s)}" | tr -c 'A-Za-z0-9._-' '-')"
  case "$SCOPE_MODE" in
    global) SCOPE_LABEL="server" ;;
    domain) SCOPE_LABEL="$DOMAIN" ;;
    abo)    SCOPE_LABEL="abo-${ABO_USER}" ;;
    path)
      # Pfad-Scan: heisst die letzte Pfadkomponente wie eine Domain
      # (kunde.example, sub.kunde.example), ist sie der Scope -- nur dann sagt
      # der Ordnername, WAS geprueft wurde. Sonst bleibt 'path' (httpdocs, tmp).
      _pb="$(basename "${SCAN_PATH_ARG:-}")"
      if [[ -n "$DOMAIN" ]]; then SCOPE_LABEL="$DOMAIN"
      # Gross-/Kleinschreibung zulassen: Plesk-Subdomains wie
      # praxen/Rq1PoseC7K8wGA.therapeut.digital sind gemischt geschrieben.
      elif [[ "$_pb" =~ ^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$ ]]; then SCOPE_LABEL="$_pb"
      else SCOPE_LABEL="path"; fi
      unset _pb ;;
    *)      SCOPE_LABEL="${DOMAIN:-${SCOPE_MODE}}" ;;
  esac
  SCOPE_LABEL="$(printf '%s' "$SCOPE_LABEL" | tr -c 'A-Za-z0-9._-' '-')"
  RUN_LABEL="${TIMESTAMP}_${HOST_SLUG}_${SCOPE_LABEL}"
  RUN_DIR="${FORENSIK_BASE}/${RUN_LABEL}"

  # ── Zwei Spuren (v3.11) ──────────────────────────────────────
  # Die Zuordnung eines Dokuments entscheidet, wer es sehen darf — und das
  # gehoert in die Ablage, nicht in die Erinnerung des Bearbeiters. Bisher lag
  # alles nebeneinander in einem Ordner, und wer den weitergab, gab auch den
  # Technik-Bericht mit fremden vhosts und die unmaskierten Rohbelege mit.
  #
  # kunde/      geht an den Auftraggeber. Enthaelt nur, was ihn betrifft.
  # betreiber/  bleibt beim Dienstleister. Behoerden-Entwuerfe liegen hier,
  #             weil sie die vollstaendigen Befunde brauchen und der Kunde
  #             sie nicht selbst versendet.
  KUNDE_DIR="${RUN_DIR}/kunde"
  BETREIBER_DIR="${RUN_DIR}/betreiber"

  BELEGE_DIR="${BETREIBER_DIR}/belege"
  REPORT_FILE="${BETREIBER_DIR}/technik_bericht.md"
  BSI_FILE="${BETREIBER_DIR}/bsi_meldung.md"
  DSGVO_FILE="${BETREIBER_DIR}/dsgvo_meldung.md"
  RUN_LOG="${BETREIBER_DIR}/lauf.log"

  KUNDE_FILE="${KUNDE_DIR}/kundenbericht.md"

  LOG_ARCHIVE="${BELEGE_DIR}/logs_sicherung.tar.gz"

  # ── Root-Check ───────────────────────────────────────────────
  # NT_TESTLAUF=1 hebt ihn auf — aber nur zusammen mit NT_BASE_DIR, damit ein
  # Testlauf nie in die Ablage eines echten Laufs schreiben kann. Und er sagt
  # es in jedem erzeugten Dokument: ein Bericht aus einem Testlauf darf mit
  # einem echten nicht verwechselbar sein, sonst ist der Pruefstand selbst
  # eine Fehlerquelle.
  if [[ "${NT_TESTLAUF:-}" == "1" && -n "${NT_BASE_DIR:-}" ]]; then
    TESTLAUF=1
    echo -e "${YLW}TESTLAUF${NC} — ohne Root-Rechte, Ablage unter ${BASE_DIR}."
    echo -e "${YLW}        ${NC}  Serverweite Abschnitte liefern hier keine belastbaren Ergebnisse."
  else
    TESTLAUF=0
    if [[ $EUID -ne 0 ]]; then
      echo -e "${RED}Fehler: Skript muss als root ausgeführt werden.${NC}"
      echo "  sudo bash $0 [domain.tld]"
      exit 1
    fi
  fi

  # ── Basis-Verzeichnisse anlegen ──────────────────────────────
  mkdir -p "$BASE_DIR" "$FORENSIK_BASE" "$KUNDE_DIR" "$BELEGE_DIR"
  chmod 700 "$BASE_DIR" "$FORENSIK_BASE" "$RUN_DIR" "$KUNDE_DIR" "$BETREIBER_DIR" "$BELEGE_DIR"

  # Eine Datei, die sagt, was der jeweilige Ordner ist. Der Ordnername allein
  # traegt die Aussage nicht weit genug: wer das Archiv entpackt und
  # weiterleitet, hat den Zusammenhang oft nicht mehr vor Augen.
  cat > "${KUNDE_DIR}/00_LIESMICH.txt" <<'KUNDE_HINWEIS'
Diese Unterlagen sind fuer den Auftraggeber bestimmt und duerfen
weitergegeben werden.

Sie enthalten ausschliesslich Angaben zum geprueften Webauftritt. Daten
anderer Kunden desselben Servers sind nicht enthalten.

Der Ordner betreiber/ daneben ist NICHT zur Weitergabe bestimmt.
KUNDE_HINWEIS

  cat > "${BETREIBER_DIR}/00_LIESMICH.txt" <<'BETREIBER_HINWEIS'
NICHT WEITERGEBEN.

Dieser Ordner ist fuer den Dienstleister bestimmt. Er enthaelt:

  technik_bericht.md   vollstaendige Befunde, auch serverweite
  bsi_meldung.md       Entwurf, nicht geprueft
  dsgvo_meldung.md     Entwurf, eigener Meldeweg (nicht ueber das BSI)
  findings.json        maschinenlesbar, Eingabe fuer die Bereinigung
  belege/              Rohbelege, BEWUSST unmaskiert (Beweismittel)
  lauf.log             Protokoll des Laufs

Auf einem Server mit mehreren Kunden koennen hier Pfade, Domains und
Kennungen anderer Kunden stehen. Weitergabe an den Auftraggeber waere ein
Datenschutzverstoss. Was an ihn geht, liegt in kunde/.
BETREIBER_HINWEIS

  # ── Keine Selbst-Installation mehr (Ablage-Konvention) ──────
  # Bis hierher kopierte sich der Runner bei jedem Lauf samt signaturen/,
  # reportgen/, daten/, lib/, module/, rezepte/ nach ${BASE_DIR} und suchte den
  # Code anschließend DORT. Folge: BASE_DIR trug Code und Laufdaten zugleich,
  # der Wrapper musste BASE_DIR auf den git-Klon zeigen, und ein Symlink
  # flickte den Rest — "das war Glück, kein Entwurf".
  #
  # Jetzt: Code wird ausschließlich über SELF_DIR gefunden (Module Zeile 245
  # im Runner, signaturen/ lib/ daten/ reportgen/ in den Modulen ebenso). Der
  # git-Checkout IST die installierte Kopie; Rollout = git pull. BASE_DIR ist
  # damit reine Datenablage (forensik/, repair/, quarantaene/) und darf auf
  # /root/wartungsscripte stehen, ohne dass Code hineinwandert.
  # Volle Konvention: Toolset docs/ablage-konvention.md.

  # Alles zusätzlich in lauf.log protokollieren
  exec > >(tee -a "$RUN_LOG") 2>&1

}


# Plesk-Admin-Zugang für die Datenbankprüfungen. Früher in Abschnitt 11;
# die Joomla-Prüfung in Abschnitt 12 fällt ebenfalls darauf zurück.
PLESK_MYSQL_PW=""
[[ -f /etc/psa/.psa.shadow ]] && PLESK_MYSQL_PW=$(cat /etc/psa/.psa.shadow 2>/dev/null || true)

# Webshell-Signatur. Früher in Abschnitt 7; Abschnitt 12 nutzt sie bewusst
# mit — eine Signatur, eine Pflegestelle.
# Case-insensitive angewendet (-i), damit mixed-case-Evasion wie 'EvaL',
# 'evAl', 'EVaL' erkannt wird. Erfasst u.a.:
#  - Variable-Variable-Superglobal:  ${$a.$b.$c}  → rekonstruiert _COOKIE/_POST
#  - eval/assert(base64_decode|gzinflate|gzuncompress|str_rot13|$_...)
#  - preg_replace mit /e-Modifier, create_function-Dropper
# move_uploaded_file($_FILES) bewusst NICHT — matcht legitime Upload-Handler.
# phpunit/sebastian ausgeschlossen (legitimes eval in Testframeworks).
#
# ── Nachtrag August 2026: zwei Shells entkamen diesem Muster ────────────────
#
# 1. Adjazenz-Zwang. Der Ausdruck verlangte den Dekodierer DIREKT hinter eval.
#    Eine Shell nutzte eine Variablenfunktion und entkam:
#        $decode = 'base64' . '_decode';  eval($decode($payload));
#    Neu deshalb: eval auf eine Variable schlechthin.
#
# 2. Packer. Eine zweite Shell entkam auch dieser Erweiterung, weil nach eval(
#    ein String-Literal steht und die Variable erst nach der Verkettung folgt:
#        $F = "\142\141\163\x65…";     // = base64_decode, als Escape-Folge
#        @eval("?>" . $F("PD9waHAg…"));
#    "base64_decode" steht im Klartext nirgends, Superglobale fehlen, die
#    laengste Zeile hat 97 Zeichen. Drei Muster fangen die Klasse: ein eval,
#    das den PHP-Modus neu oeffnet; acht oder mehr Escapes am Stueck; der
#    Encoder-Banner.
#
# eval("?> …) trifft auch Twig — dessen Template-Uebersetzer arbeitet genau so.
# Hingenommen: Twigs Environment.php ist gross und landet ueber
# DROPPER_MAX_BYTES in der Sichtungsstufe, nicht im kritischen Befund.
PATTERN_REGEX='\$\{\s*\$[a-zA-Z0-9_]+(\s*\.\s*\$[a-zA-Z0-9_]+)+\s*\}|eval\s*\(\s*(base64_decode|gzinflate|gzuncompress|str_rot13)|eval\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER)|eval\s*\(\s*\$|eval\s*\(\s*['"'"'"]\s*\?>|\$_(GET|POST|REQUEST|COOKIE|SERVER)\s*\[[^]]*\]\s*\(|(\\x[0-9a-fA-F]{2}|\\[0-7]{3}){8,}|PHP[[:space:]]*Encoder|assert\s*\(\s*\$_|create_function\s*\(\s*['"'"'"][^'"'"'"]*['"'"'"]\s*,\s*\$|preg_replace\s*\(\s*['"'"'"].*/e[imsuxADSUXJ]*['"'"'"]|\bFilesMan\b|c99sh|r57shell|b374k|IndoXploit'

# Zweite Stufe: einzeln unauffaellig, in Summe aussagekraeftig. Diese
# Funktionen kommen in echtem Anwendungscode vor — ein Messlauf ergab 358
# Treffer auf 25.000 Dateien. Sie taugen deshalb NICHT als kritischer Befund
# und werden in Abschnitt 7.3 nur auf kleine Dateien angewandt: ein
# Filemanager-Shell mit unverschleiertem shell_exec ist klein, ein Framework
# mit denselben Aufrufen ist es nicht.
#
# Der Anlass: eine Filemanager-Shell nutzte shell_exec voellig offen. Die
# exec-Familie fehlte in PATTERN_REGEX vollstaendig, die Shell blieb unsichtbar.
# ── Namen, die in einer .htaccess-Freigabeliste stehen DUERFEN ──────────────
#
# Gemessen am echten Befall vom 12./13.08.2026: 29 .htaccess gaben je denselben
# Satz WordPress-Kerndateien frei — das ist legitime Haertung (Zugriff auf
# alles sperren, die Einstiegspunkte wieder oeffnen). Eine dreissigste Datei
# stand daneben und passte in kein Schema:
#
#   58x filefuns.php      <- die Verbreiter-Shell
#   47x index.php
#   29x xmlrpc.php, wp-login.php, wp-load.php, wp-cron.php, …
#
# Der Angreifer MUSS seinen Dateinamen dort eintragen, sonst sperrt seine
# eigene Haertung ihn aus. Genau das macht die Liste zum Verraeter — und zwar
# unabhaengig von Groesse, Endung und Verschleierung. filefuns.php ist 5579 B
# und rutschte deshalb an der Groessenschwelle von Abschnitt 7.3 vorbei.
#
# Die bekannten Plugin-Endpunkte stammen aus derselben Messung: 68 der 97
# Freigabelisten waren legitime Haertung fuer webp-realizer.php, matomo.php
# und gm_dynamic.css.php.
HTACCESS_NAMEN_OK="${HTACCESS_NAMEN_OK:-^(index|xmlrpc|wp-activate|wp-blog-header|wp-comments-post|wp-config|wp-config-sample|wp-cron|wp-links-opml|wp-load|wp-login|wp-mail|wp-settings|wp-signup|wp-trackback|admin-ajax|admin-post|wp-admin/admin-ajax|webp-realizer|matomo|gm_dynamic\\.css)\\.php$}"

PATTERN_REGEX_MED='\b(shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(|\bsystem\s*\(|\bgoto\s+[A-Za-z0-9_]{3,}\s*;|chr\s*\(\s*[0-9]+\s*\)\s*\.\s*chr\s*\(|HTTP_USER_AGENT.*\b(Googlebot|bingbot|crawler|curl)\b|(md5|sha1|password_verify)\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)'

# Schwelle: Dropper sind fast reine Obfuskation → klein. Legitime
# Framework-Nutzung (phpseclib, eGroupware) steckt in großen Dateien.
DROPPER_MAX_BYTES=3000

# ── Zeitstempel-Abstand: zwei Schwellen, absichtlich verschieden ─────────────
# Beide messen dasselbe — wie weit die mtime hinter der ctime zurückliegt —,
# aber sie tragen unterschiedlich viel Last, und deshalb dürfen sie nicht
# denselben Wert haben.
#
# ZUSATZ (30 Tage, Abschnitt 7.3 und datei_steckbrief): steht immer an einer
# Datei, die bereits aus anderem Grund auffällt. Er muss nichts allein
# beweisen, nur einen vorhandenen Verdacht schärfen — also darf er
# empfindlich sein.
#
# ALLEIN (90 Tage, Abschnitt 8.7): erhebt einen eigenen kritischen Befund über
# Systemverzeichnisse. Was hier ausschlägt, steht ohne Stütze im Bericht. Ein
# Messlauf mit der 30-Tage-Schwelle als alleinigem Befund lieferte 62.373
# Dateien — jedes rekursive chown und jede Rücksicherung löst ihn baumweit
# aus. Abschnitt 8.7 nimmt zusätzlich paketverwaltete Dateien aus, bei denen
# der Abstand normales dpkg-Verhalten ist.
ZEITSTEMPEL_ZUSATZ_SEK=2592000     # 30 Tage
ZEITSTEMPEL_ALLEIN_SEK=7776000     # 90 Tage

# ── Zerlegte Funktionsnamen (7.16) ───────────────────────────
# Drei oder mehr einzeln gequotete Zeichen, per Punkt verkettet:
#   $o="f"."o"."p"."e"."n";
# Zur Laufzeit ein gewoehnlicher Funktionsname, fuer jede Signatur ueber
# Funktionsnamen unsichtbar. Legitimer Code tut das nicht — gemessen auf
# 6,4 Mio Pfaden: 5 Treffer, 0 Fehlalarme.
# Bewusst ERE und nicht PCRE: dieser Abschnitt soll auch dort laufen, wo
# grep kein -P kann (#67).
#
# KEIN ${VAR:-...} HIER. Das Muster enthaelt {3,} — bash liest dessen
# schliessende Klammer als Ende der Ersetzung, und die Variable bleibt LEER.
# Ein leeres Muster gibt `grep -lE ""` jede Datei zurueck: aus einem Befund
# ohne legitimen Fall waeren schlagartig alle PHP-Dateien des Servers
# geworden. Beim Bauen genau so passiert.
if [[ -z "${ZERLEGT_REGEX:-}" ]]; then
  _zq="[\"']"                       # ein Anfuehrungszeichen, beide Sorten
  ZERLEGT_REGEX="(${_zq}[A-Za-z]${_zq}\\.){3,}"
  unset _zq
fi

# ── Erzeugter Code unter uploads/ (7.2) ──────────────────────
# Am 14.08.2026 stammten 236 von 282 Treffern des Abschnitts von drei
# Erzeugern: WPML-Twig-Cache (162), TCPDF-Schriftmetriken (66) und der
# Einstellungsdatei von All-In-One-Security (8).
#
# Erkannt wird das FORMAT, nicht der Ort. Eine Pfadregel haette dieselben
# Dateien beseitigt und drei beschreibbare Verzeichnisse geschaffen, in denen
# eine Shell unsichtbar liegt.
#
# ALS VARIABLE UND NICHT DIREKT IM [[ =~ ]]: bash 3.2 (macOS) und bash 5
# (Server) behandeln ein maskiertes Anfuehrungszeichen im Regex-Literal
# unterschiedlich. Direkt geschrieben griff das Muster auf dem Server und
# schwieg auf dem Arbeitsplatz — ein Prüfstand, der lokal gruen ist und die
# Regel nie erreicht.
_uq="'"
# Zwei Schreibweisen im selben Verzeichnis: $type='core' und $type = 'cidfont0'
UPLOAD_FONT_REGEX="[\$]type[[:space:]]*=[[:space:]]*${_uq}(TrueType[A-Za-z]*|Type1|core|cidfont0)${_uq}"
# Unicode-nach-CID-Umsetzungstabelle: reine Array-Zuweisung, kein Aufruf.
UPLOAD_CID_REGEX="[\$]cidinfo\[.uni2cid.\][[:space:]]*=[[:space:]]*array\("
unset _uq

# ── Fremdbibliotheken (13d, #46) ─────────────────────────────
# Verzeichnisse, deren Inhalt nicht vom Betreiber stammt, sondern von einem
# Abhaengigkeitsverwalter. Fuer sie gibt es keinen Pruefsummensatz (#30) —
# gemessen sind 156 von 292 Treffern der kritischen Stufe genau dort.
# Als ERE, wird in 13d dynamisch an awk gegeben.
#
# 3rdparty/ und libraries/ kamen am 14.08.2026 dazu, nachdem 16 Dateien in der
# Quarantaeneliste standen, die dort nicht hingehoerten — TCPDF-Schriftpfade
# und Joomla-Bibliotheken. Beide Namen sind aelter als composer und deshalb
# genauso wenig Betreibercode wie vendor/; Joomla legt seine Fremdbestandteile
# unter libraries/ ab, TCPDF und PHPMailer unter 3rdparty/.
#
# Die Liste ist nach Messung gewachsen und wird weiter wachsen. Das ist kein
# Mangel, sondern die Bauart: sie spricht nicht frei, sie verschiebt die
# Beweislast. Wer unter einem dieser Pfade ablegt und per .htaccess freigibt,
# wird weiterhin von 7.6b gefasst.
VENDOR_PFADE="${VENDOR_PFADE:-/vendor/|/vendor-prefixed/|/node_modules/|/3rdparty/|/libraries/}"

# ── Persistenz in der Datenbank (#47) ────────────────────────
# Ab welcher Groesse eine Option in die Sichtungs-Rangfolge kommt (e3).
# GERATEN, nicht gemessen — 256 KiB liegt deutlich ueber dem, was Widgets und
# Einstellungen brauchen, aber Page-Builder-CSS und Transients erreichen das
# auch legitim. Deshalb haengt an diesem Wert KEIN Befund, nur eine info-Zeile
# mit Beleg. Erst messen, dann einstufen — dieselbe Regel wie bei 7.15.
WP_OPTION_GROSS_BYTES="${WP_OPTION_GROSS_BYTES:-262144}"

# ── Ursachensuche (Abschnitt 13e, #48) ───────────────────────
#
# WELLE: ab welcher Pause zwischen zwei Schreibvorgaengen 13e sie als getrennte
# Vorgaenge ausweist. Im Anlassfall lagen zwischen den beiden Wellen 14 Tage,
# INNERHALB der zweiten 13 Minuten fuer 15 Seiten. Eine Stunde trennt das
# sauber und schneidet keine Welle auf. Der Wert steuert nur die DARSTELLUNG —
# kein Befund haengt an ihm, und die Achse im Beleg ist immer vollstaendig.
#
# Aus der Umgebung uebersteuerbar, wie die uebrigen Pruefstand-Nahtstellen
# (NT_DATEN_DIR, NT_WF_ATTRAPPE). Der Pruefstand kann echte Wellenabstaende
# nicht bauen — dafuer braeuchte er Luecken in der ctime, und genau die laesst
# sich nicht setzen. Er baut deshalb Abstaende von einer Sekunde und senkt die
# Schwelle. Vertretbar, weil an diesem Wert kein Befund haengt.
URSACHE_WELLE_SEK="${URSACHE_WELLE_SEK:-3600}"
# Wie viele Zeilen die Zeitachse IM BERICHT hoechstens zeigt. Auf 475 vhosts
# blieben nach der Entlastung 251 Dateien; eine Achse darueber liest niemand.
# Was ueber die Grenze faellt, wird gezaehlt und benannt — der Beleg traegt
# ohnehin alles. Ein stilles Abschneiden waere dieselbe Luege wie eine stille
# Entlastung.
URSACHE_ACHSE_MAX="${URSACHE_ACHSE_MAX:-60}"
# ── Massenvorgang gegen Angreiferschreibvorgang (13e.1, #65) ─
#
# Am 13.08.2026 stand am Anfang der Zeitachse ein Block von ueber 200 Dateien
# innerhalb von 41 Sekunden, alle vom 19.02.2026 — eine Wiederherstellung oder
# Migration. `ursache.aeltester_nachweis` nannte deshalb dieses Datum, und
# 13e.4 baute darauf sein "173 Tage vor dem Protokollfenster".
#
# DAS UNTERSCHEIDENDE MERKMAL IST NICHT DIE MENGE, SONDERN DAS
# ZEITSTEMPELVERHAELTNIS. Ein Angreifer, der hundert Shells in einer Minute
# ablegt, erzeugt dieselbe Haeufung — aber seine Dateien sind ANKER
# (mtime == ctime, frisch geschrieben). Eine Wiederherstellung mit `cp -p`
# erzeugt INODE (alte mtime, neue ctime). Deshalb ist die Mehrheitsregel unten
# die eigentliche Bedingung; Menge und Zeitfenster grenzen nur ein.
URSACHE_MASSE_MIN="${URSACHE_MASSE_MIN:-50}"          # ab wievielen Dateien
URSACHE_MASSE_FENSTER_SEK="${URSACHE_MASSE_FENSTER_SEK:-1800}"  # in welcher Spanne
# Wie viele vhosts 13e.4 auf ihr Protokollfenster ansieht. Der Test ist ein
# `head -1` je Logdatei; auf allen 475 vhosts waere er sinnlos teuer, und
# Aussagekraft hat er nur dort, wo tatsaechlich etwas liegt.
URSACHE_LOGS_MAX="${URSACHE_LOGS_MAX:-20}"

# ── Injektion in grosse Dateien (7.15) ───────────────────────
#
# Die Zweistufigkeit oben trennt nach GROESSE: klein plus Muster ist kritisch,
# gross plus Muster geht in die Sichtung. Das traegt für Dropper — und ist
# blind für den umgekehrten Fall, eine Injektion IN eine grosse, legitime
# Datei. Eine kommerzielle Plugin-Datei hat 50–400 kB; für sie gibt es keine
# amtliche Prüfsumme, an der sich das prüfen liesse.
#
# lib/injektion_pruefen.py misst deshalb nicht die Datei, sondern die
# Verteilung darin. Diese Werte steuern es; das Programm liest sie aus der
# Umgebung und hat dieselben Vorgaben noch einmal, damit es allein lauffähig
# bleibt (baumscan.sh bindet konfig.sh bewusst nicht ein).
#
# ALLE VIER SIND GERATEN. Sie stammen aus den Fällen im Selbsttest, nicht aus
# einer Messung an einem echten Server — die hängt an der Abnahme (#9). Bis
# dahin meldet 7.15 `info` und keinen Befund. Ein Filter, dessen Schwellen
# niemand gemessen hat, wird sonst die nächste Geräuschquelle; genau so ist
# der fremde Regelsatz mit 359 Treffern unbrauchbar geworden.
export INJEKTION_GROSS_AB=3000       # darunter ist 7.3 zuständig
export INJEKTION_ZEILE_MAX=2000      # längste Zeile, ab der es auffällt
export INJEKTION_RANDLAGE_PCT=5      # Rand der Datei in Prozent
export INJEKTION_PUNKTE_MIN=3        # ab wann eine Datei genannt wird