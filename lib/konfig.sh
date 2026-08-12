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
TOOL_VERSION="3.13.0"
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
scan_path_bestimmen() {
  case "$SCOPE_MODE" in
    path)   SCAN_PATH="$SCAN_PATH_ARG"; SCAN_PATHS=("$SCAN_PATH") ;;
    domain) SCAN_PATH="${VHOSTS_DIR}/${DOMAIN}"; SCAN_PATHS=("$SCAN_PATH") ;;
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
    echo -e "${RED}Fehler:${NC} Für --domain ${DOMAIN} gibt es kein Verzeichnis unter ${VHOSTS_DIR}." >&2
    echo    "        Tippfehler? Verfügbare Verzeichnisse:" >&2
    ls -1d "${VHOSTS_DIR}"/*/ 2>/dev/null | sed "s|${VHOSTS_DIR}/||;s|/$||" | head -20 | sed 's/^/          /' >&2
    echo    "        Für einen serverweiten Lauf ausdrücklich --global angeben." >&2
    exit 2
  fi
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
# Ebenfalls als Funktion: der Laufordner trägt die geprüfte Domain im
# Namen, und die steht erst nach dem Menü fest.
ablage_einrichten() {
  TIMESTAMP=$(date +%Y%m%d_%H%M%S)
  RUN_LABEL="${TIMESTAMP}_${DOMAIN:-${SCOPE_MODE}}"
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

  # ── Selbst-Installation nach /root/wartungsscripte ──────────
  # SELF_PATH und SELF_DIR setzt der Runner, bevor er diese Datei einbindet —
  # er braucht sie schon, um sie überhaupt zu finden.
  INSTALLED_PATH="${BASE_DIR}/wp_plesk_forensik.sh"
  if [[ "$SELF_PATH" != "$INSTALLED_PATH" ]]; then
    cp -f "$SELF_PATH" "$INSTALLED_PATH"
    chmod 700 "$INSTALLED_PATH"
  fi
  # Beigelegte Hilfsdateien (YARA-Signaturen, PDF-Generator, Joomla-Datenbestand)
  # neben das Skript mitziehen — so findet der Lauf sie unter ${BASE_DIR}, egal
  # von wo gestartet wurde.
  #
  # Auffrischen bei JEDEM Lauf, nicht nur beim ersten (v3.8): der frühere
  # '! -e'-Guard hat einen einmal installierten Host dauerhaft auf dem Erststand
  # eingefroren. Bei Signaturen war das ärgerlich; beim versionierten Joomla-
  # Datenbestand (Prüfsummen, Schwachstellenliste) wäre es ein Fehler — der Lauf
  # würde stumm gegen einen jahrealten Stand prüfen und "unauffällig" melden.
  #
  # lib/ und module/ gehören zwingend dazu: ohne sie ist die installierte Kopie
  # unter ${BASE_DIR} nicht lauffähig, weil der Runner nur noch einbindet.
  #
  # rezepte/ ebenso, seit die anwendungsspezifische Prüfung dort liegt (v3.13).
  # Fehlte es, war der Ausfall lautlos: der Rahmen findet kein Rezept, meldet
  # das als Hinweis und läuft mit Rückgabewert 0 weiter. Im Prüfbaum gemessen
  # sind das 4 kritische Befunde und 2 Warnungen weniger — und, schlimmer, die
  # Zahl der nicht messbaren Prüfungen fällt von 4 auf 0. Der Bericht liest
  # sich dadurch VOLLSTÄNDIGER als der Lauf war.
  _srcdir="$SELF_DIR"
  if [[ "$_srcdir" != "$BASE_DIR" ]]; then   # sonst kopiert sich die installierte Kopie selbst
    for _aux in signaturen reportgen daten lib module rezepte; do
      if [[ -d "$_srcdir/$_aux" ]]; then
        mkdir -p "${BASE_DIR}/$_aux"
        # '/.' kopiert den INHALT — ohne den entsteht ${BASE_DIR}/daten/daten
        cp -rf "$_srcdir/$_aux/." "${BASE_DIR}/$_aux/" 2>/dev/null || true
      fi
    done
  fi

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