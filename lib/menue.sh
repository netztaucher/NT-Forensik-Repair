# ============================================================
# NT-Forensik — Startmenü
# ------------------------------------------------------------
# Erklärender Einstieg für den Fall, dass jemand das Werkzeug ohne
# Scope-Argument aufruft. Zeigt, was jeder Abschnitt beantwortet und was er
# kostet, und stellt am Ende den gleichwertigen Befehl zum Kopieren bereit.
#
# WICHTIG — das Menü darf bestehende Abläufe nicht brechen:
#   * Mit Scope-Argument (--domain/--path/--global) laeuft die Pruefung immer
#     direkt durch. Ein Aufruf wie
#         ssh root@server "bash …sh --domain kunde.tld"
#     hat kein Terminal; ein Menue wuerde ihn zerstoeren.
#   * Ohne Terminal und ohne Scope gibt es KEINE Rueckfrage, sondern die
#     Uebersicht und einen klaren Abbruch mit Code 2. Ein Cronjob, der auf
#     eine Menueeingabe wartet, haengt sonst unbemerkt fuer immer.
# ============================================================

# Soll das Menü überhaupt erscheinen?
menue_faellig() {
  [[ "${WANT_MENUE}" == "0" ]] && return 1     # --kein-menue
  [[ "${WANT_MENUE}" == "1" ]] && return 0     # --menue erzwingt
  [[ "${SCOPE_GESETZT}" == "1" ]] && return 1  # Scope = eindeutige Anweisung
  return 0
}

# Abschnittsübersicht — auch der Abbruchpfad ohne Terminal nutzt sie.
menue_uebersicht() {
  local datei nr titel frage kosten ebene aktuelle=""
  printf '\n%b%s%b\n' "$BOLD" "  Prüfabschnitte" "$NC"
  for ebene in system website bericht; do
    case "$ebene" in
      system)  printf '\n  %bServer-Ebene%b — betrifft den ganzen Server\n' "$BOLD" "$NC" ;;
      website) printf '\n  %bWebsite-Ebene%b — betrifft den geprüften Webauftritt\n' "$BOLD" "$NC" ;;
      bericht) printf '\n  %bAuswertung%b\n' "$BOLD" "$NC" ;;
    esac
    for datei in "${SELF_DIR}"/module/*.sh; do
      [[ "$(modul_feld "$datei" ebene)" == "$ebene" ]] || continue
      nr=$(modul_feld "$datei" nummer)
      titel=$(modul_feld "$datei" titel)
      frage=$(modul_feld "$datei" frage)
      kosten=$(modul_feld "$datei" kosten)
      printf '   %b%2s%b  %-32s %s\n' "$CYN" "$nr" "$NC" "$titel" "$frage"
      case "$kosten" in
        HOCH*) printf '        %b Aufwand: %s%b\n' "$YLW" "$kosten" "$NC" ;;
        *)     printf '        Aufwand: %s\n' "$kosten" ;;
      esac
    done
  done
  printf '\n'
}

# Kein Terminal und kein Scope: erklären und beenden, nicht warten.
menue_ohne_terminal() {
  printf '\n%bNT-Forensik v%s%b\n' "$BOLD" "$TOOL_VERSION" "$NC"
  printf 'Kein Prüfumfang angegeben und keine Eingabe möglich (kein Terminal).\n'
  menue_uebersicht
  cat <<HINWEIS
  Bitte den Prüfumfang angeben, zum Beispiel:

    bash $0 --domain kunde.tld                 eine Domain, alle Abschnitte
    bash $0 --domain kunde.tld --nur-joomla    nur die Joomla-Prüfung
    bash $0 --global --kein-menue              serverweit (für Cronjobs)

HINWEIS
  exit 2
}

# Eine Zeile einlesen, mit Vorgabewert bei leerer Eingabe.
_frage() {   # _frage <text> <vorgabe> <zielvariable>
  local eingabe
  printf '  %s [%s]: ' "$1" "$2" >&2
  IFS= read -r eingabe || eingabe=""
  printf -v "$3" '%s' "${eingabe:-$2}"
}

menue_starten() {
  printf '\n%b' "$BOLD"
  cat <<'KOPF'
  ┌──────────────────────────────────────────────┐
  │  NT-Forensik — read-only Analyse             │
  └──────────────────────────────────────────────┘
KOPF
  printf '%b' "$NC"
  cat <<'EINLEITUNG'
  Das Werkzeug verändert nichts. Es liest, wertet aus und schreibt seine
  Berichte ausschliesslich nach /root/wartungsscripte/.

EINLEITUNG

  menue_uebersicht

  printf '  %bWas soll geprüft werden?%b\n' "$BOLD" "$NC"
  printf '   1  Eine Domain\n'
  printf '   2  Ein beliebiger Pfad\n'
  printf '   3  Alle Domains des Servers\n'
  local wahl ziel
  _frage "Auswahl" "1" wahl
  case "$wahl" in
    2) _frage "Pfad" "/var/www/vhosts" ziel; SCOPE_MODE="path"; SCAN_PATH_ARG="$ziel" ;;
    3) SCOPE_MODE="global" ;;
    *) _frage "Domain" "" ziel
       [[ -n "$ziel" ]] || { echo "  Ohne Domain kein Lauf — abgebrochen." >&2; exit 2; }
       SCOPE_MODE="domain"; DOMAIN="$ziel" ;;
  esac

  printf '\n  %bWelche Abschnitte?%b\n' "$BOLD" "$NC"
  printf '   1  Vollprüfung — alles\n'
  printf '   2  Nur Website — überspringt die serverweiten Abschnitte, deutlich schneller\n'
  printf '   3  Nur CMS — WordPress und Joomla, für "ist diese Seite übernommen?"\n'
  printf '   4  Eigene Auswahl\n'
  local umfang liste
  _frage "Auswahl" "1" umfang
  case "$umfang" in
    2) MODUL_NUR="ebene:website" ;;
    3) MODUL_NUR="11,12" ;;
    4) _frage "Abschnittsnummern, kommagetrennt" "12" liste; MODUL_NUR="$liste" ;;
    *) MODUL_NUR="" ;;
  esac

  local jn
  printf '\n'
  _frage "YARA-Signaturscan mitlaufen lassen? (langsam) j/n" "n" jn
  [[ "$jn" =~ ^[jJyY] ]] && WANT_YARA=1
  _frage "Fehlende Joomla-Prüfsummen aus dem Netz nachladen? j/n" "n" jn
  [[ "$jn" =~ ^[jJyY] ]] && WANT_ONLINE=1

  # Gleichwertigen Befehl zusammenbauen — der Nutzer soll den Lauf beim
  # nächsten Mal direkt und skriptfähig starten können.
  MENUE_BEFEHL="bash $0"
  case "$SCOPE_MODE" in
    domain) MENUE_BEFEHL+=" --domain ${DOMAIN}" ;;
    path)   MENUE_BEFEHL+=" --path ${SCAN_PATH_ARG}" ;;
    global) MENUE_BEFEHL+=" --global" ;;
  esac
  case "$MODUL_NUR" in
    "")               : ;;
    ebene:website)    MENUE_BEFEHL+=" --nur-website" ;;
    12)               MENUE_BEFEHL+=" --nur-joomla" ;;
    *)                MENUE_BEFEHL+=" --nur ${MODUL_NUR}" ;;
  esac
  [[ "$WANT_YARA"   == "1" ]] && MENUE_BEFEHL+=" --yara"
  [[ "$WANT_ONLINE" == "1" ]] && MENUE_BEFEHL+=" --online"

  printf '\n  %bZusammenfassung%b\n' "$BOLD" "$NC"
  printf '    Umfang:     %s\n' "${DOMAIN:-${SCAN_PATH_ARG:-alle Domains}}"
  printf '    Abschnitte: %s\n' "$(case "$MODUL_NUR" in "") echo "alle";; ebene:website) echo "nur Website-Ebene";; *) echo "$MODUL_NUR";; esac)"
  printf '    Befehl:     %s\n\n' "$MENUE_BEFEHL"
  _frage "Starten? j/n" "j" jn
  [[ "$jn" =~ ^[jJyY] ]] || { echo "  Abgebrochen." >&2; exit 0; }
  printf '\n'
}
