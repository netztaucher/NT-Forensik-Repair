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

# ── Feste Infrastruktur-Pfade (netztaucher Plesk-Standard) ──
BASE_DIR="/root/wartungsscripte"
FORENSIK_BASE="${BASE_DIR}/forensik"
VHOSTS_DIR="/var/www/vhosts"
PLESK_LOG_DIR="/var/log/plesk"
PLESK_PANEL_LOG="${PLESK_LOG_DIR}/panel.log"

# ── Konfiguration ────────────────────────────────────────────
TOOL_VERSION="3.9.0"
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
SCOPE_MODE="global"      # global | domain | path
SCAN_PATH_ARG=""         # nur bei --path
WANT_YARA=0              # 7.11 nur auf Wunsch (teuer auf großen Webspaces)
WANT_ONLINE=0            # --online: Joomla-Prüfsummen/Schwachstellenliste nachladen
SCOPE_GESETZT=0          # wurde ein Scope ausdrücklich angegeben? (steuert das Menü)
WANT_MENUE=-1            # -1 = automatisch, 0 = nie, 1 = erzwungen
MODUL_NUR=""             # --nur:  Komma-Liste von Abschnittsnummern
MODUL_OHNE=""            # --ohne: Komma-Liste von Abschnittsnummern

usage() {
  cat <<USAGE
wp_plesk_forensik.sh v${TOOL_VERSION} — read-only WordPress/Plesk-Forensik

Verwendung:
  sudo bash $0 [SCOPE] [Optionen]
  sudo bash $0 kunde.tld                 # Kurzform für --domain kunde.tld

Scope (eines):
  --domain <domain.tld>   Einen Kunden prüfen; Kundenbericht nur mit dessen Daten
  --path   <pfad>         Beliebigen Pfad/Webspace prüfen
  --global                Alle vhosts (Standard): Betreiberbericht + je vhost
                          ein eigener, gefilterter Kundenbericht

Abschnittsauswahl:
  --nur <n[,n…]>          Nur diese Prüfabschnitte (z. B. --nur 12)
  --ohne <n[,n…]>         Alle ausser diesen (z. B. --ohne 2,10)
  --nur-joomla            Kurzform für --nur 12
  --nur-website           Nur die Abschnitte, die den Webauftritt prüfen
                          (überspringt die serverweiten — deutlich schneller)

Optionen:
  --yara                  YARA-Signaturscan (7.11) aktivieren (langsam auf
                          großen Webspaces; ohne Flag übersprungen)
  --online                Joomla-Prüfsummen und Schwachstellenliste bei Bedarf
                          aus dem Netz nachladen. OHNE dieses Flag arbeitet der
                          Lauf rein offline aus dem mitgelieferten Datenbestand.
                          Jeder Abruf wird im Bericht und als Beleg ausgewiesen.
  --kein-menue            Startmenü unterdrücken (für Cronjobs und Skripte)
  --menue                 Startmenü erzwingen
  -h, --help              Diese Hilfe

Ohne Scope-Argument startet das Menü. Wird ein Scope angegeben, läuft die
Prüfung direkt durch — bestehende Aufrufe und Skripte bleiben unverändert.

Die Server-/Rootebene wird in jedem Modus mitgeprüft, sofern nicht abgewählt.
In Kundenberichten werden Rootbefunde nur allgemein (betroffen/nicht
betroffen) genannt und IP-Adressen/E-Mails maskiert.

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
    --yara)   WANT_YARA=1; shift ;;
    --online) WANT_ONLINE=1; shift ;;
    --nur)    MODUL_NUR="${2:-}";  shift 2 ;;
    --ohne)   MODUL_OHNE="${2:-}"; shift 2 ;;
    --nur-joomla)  MODUL_NUR="12" ; shift ;;
    --nur-website) MODUL_NUR="ebene:website"; shift ;;
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
    path)   SCAN_PATH="$SCAN_PATH_ARG" ;;
    domain) SCAN_PATH="${VHOSTS_DIR}/${DOMAIN}" ;;
    *)      SCAN_PATH="$VHOSTS_DIR" ;;   # global
  esac
  # Fallback: gesetzte Domain ohne existierenden vhost -> serverweit statt ins Leere
  [[ "$SCOPE_MODE" == "domain" && ! -d "$SCAN_PATH" ]] && SCAN_PATH="$VHOSTS_DIR"
}

# ── Ablage einrichten ────────────────────────────────────────
# Ebenfalls als Funktion: der Laufordner trägt die geprüfte Domain im
# Namen, und die steht erst nach dem Menü fest.
ablage_einrichten() {
  TIMESTAMP=$(date +%Y%m%d_%H%M%S)
  RUN_LABEL="${TIMESTAMP}_${DOMAIN:-${SCOPE_MODE}}"
  RUN_DIR="${FORENSIK_BASE}/${RUN_LABEL}"
  BELEGE_DIR="${RUN_DIR}/belege"
  REPORT_FILE="${RUN_DIR}/technik_bericht.md"
  KUNDE_FILE="${RUN_DIR}/kundenbericht.md"
  BSI_FILE="${RUN_DIR}/bsi_meldung.md"
  DSGVO_FILE="${RUN_DIR}/dsgvo_meldung.md"
  RUN_LOG="${RUN_DIR}/lauf.log"
  LOG_ARCHIVE="${BELEGE_DIR}/logs_sicherung.tar.gz"

  # ── Root-Check ───────────────────────────────────────────────
  if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}Fehler: Skript muss als root ausgeführt werden.${NC}"
    echo "  sudo bash $0 [domain.tld]"
    exit 1
  fi

  # ── Basis-Verzeichnisse anlegen ──────────────────────────────
  mkdir -p "$BASE_DIR" "$FORENSIK_BASE" "$BELEGE_DIR"
  chmod 700 "$BASE_DIR" "$FORENSIK_BASE" "$RUN_DIR" "$BELEGE_DIR"

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
  _srcdir="$SELF_DIR"
  if [[ "$_srcdir" != "$BASE_DIR" ]]; then   # sonst kopiert sich die installierte Kopie selbst
    for _aux in signaturen reportgen daten lib module; do
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
PATTERN_REGEX='\$\{\s*\$[a-zA-Z0-9_]+(\s*\.\s*\$[a-zA-Z0-9_]+)+\s*\}|eval\s*\(\s*(base64_decode|gzinflate|gzuncompress|str_rot13)|eval\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER)|assert\s*\(\s*\$_|create_function\s*\(\s*['"'"'"][^'"'"'"]*['"'"'"]\s*,\s*\$|preg_replace\s*\(\s*['"'"'"].*/e[imsuxADSUXJ]*['"'"'"]|\bFilesMan\b|c99sh|r57shell|b374k'

# Schwelle: Dropper sind fast reine Obfuskation → klein. Legitime
# Framework-Nutzung (phpseclib, eGroupware) steckt in großen Dateien.
DROPPER_MAX_BYTES=3000
