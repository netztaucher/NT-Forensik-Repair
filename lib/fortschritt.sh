# shellcheck shell=bash
# NT-Forensik — Fortschrittsspur
#
# Ein Lauf ueber 475 vhosts dauert knapp drei Stunden. Bis v3.14 gab es keine
# Moeglichkeit zu sehen, WO er gerade steht — der Betreiber sah eine wachsende
# Protokolldatei und sonst nichts. Der Stand liess sich nur von Hand
# rekonstruieren: Prozess suchen, Belege zaehlen, im Protokoll die letzte
# Abschnittszeile finden.
#
# Diese Datei schreibt die Spur, werkzeuge/lauf-status.sh liest sie.
#
# ------------------------------------------------------------
# WARUM KEIN PROZENTWERT
#
# Die Abschnitte sind voellig ungleich lang. Im Messlauf vom 12.08.2026:
#
#   Abschnitt 1–7    (Dateisystem)        ~17 min
#   Abschnitt 8.7    (gsocket-Inhalt)     ~51 min
#   Abschnitt 12r    (Rezepte, --online)  ~90 min
#   Abschnitt 13–14  (Berichte)            ~4 min
#
# "Abschnitt 8 von 14" hiesse dort 57 % und waere nach der Zeit 12 %. Ein
# Prozentwert ueber Abschnitte gezaehlt ist eine Zahl, die nichts bedeutet.
#
# Stattdessen: wo, seit wann — und wie lange derselbe Abschnitt im VORIGEN
# Lauf gedauert hat. Das ist eine Messung. Gibt es keinen Vorlauf, sagt die
# Anzeige das, statt eine Zahl zu erfinden.
# ------------------------------------------------------------

# Ablageort: eine Punktdatei im Laufordner, wie die Pruefsummenlisten. Sie ist
# Arbeitsmaterial, kein Beleg — sie wandert in kein Archiv und in keinen
# Bericht.
FORTSCHRITT_DATEI="${FORTSCHRITT_DATEI:-}"

fortschritt_beginn() {   # fortschritt_beginn — einmal, sobald RUN_DIR steht
  [[ -n "${RUN_DIR:-}" ]] || return 0
  FORTSCHRITT_DATEI="${RUN_DIR}/.fortschritt.tsv"
  # Kopfzeile mit dem Umfang: eine Restschaetzung ist nur gueltig, wenn der
  # Vorlauf denselben Umfang hatte. Ein --nur-website-Lauf ist kein Massstab
  # fuer einen globalen.
  printf '#start\t%s\t%s\t%s\n' "$(date +%s)" "${SCOPE_MODE:-?}" "${ABO_USER:-${DOMAIN:-}}" \
    > "$FORTSCHRITT_DATEI" 2>/dev/null || FORTSCHRITT_DATEI=""
}

fortschritt_abschnitt() {   # fortschritt_abschnitt <nummer> <titel>
  [[ -n "$FORTSCHRITT_DATEI" ]] || return 0
  printf 'abschnitt\t%s\t%s\t%s\n' "$(date +%s)" "${1:-?}" "${2:-}" \
    >> "$FORTSCHRITT_DATEI" 2>/dev/null || true
}

# Unterschritt fuer die langen Schleifen. Bei 12r ist "Installation 87 von 214"
# die einzige Angabe, die waehrend anderthalb Stunden etwas aussagt.
fortschritt_unterschritt() {   # fortschritt_unterschritt <i> <n> <text>
  [[ -n "$FORTSCHRITT_DATEI" ]] || return 0
  printf 'unterschritt\t%s\t%s\t%s\t%s\n' "$(date +%s)" "${1:-0}" "${2:-0}" "${3:-}" \
    >> "$FORTSCHRITT_DATEI" 2>/dev/null || true
}

# ── Die langen Pipelines sichtbar machen ─────────────────────
#
# Die teuersten Abschnitte sind KEINE Schleifen: 8.7 (gsocket) und 7.15
# (Injektionsmass) sind je EIN `find | xargs`-Aufruf. Im Messlauf steckten
# darin 51 bzw. mehrere Minuten, in denen bash nichts sieht und das Protokoll
# stillsteht — der Lauf sah aus wie ein Haenger, und ich habe von Hand
# nachgewiesen, dass er arbeitet.
#
# Der Strom der Pfade laeuft aber durch die Pipe. Dieser Filter reicht ihn
# unveraendert weiter und schreibt nebenbei mit, wo er gerade ist:
#
#   find … | fortschritt_strom "8.7 gsocket" | xargs grep …
#
# Alle 200 Zeilen eine Schreiboperation auf eine kleine Datei — gegenueber
# einem Inhaltsscan ueber 475 vhosts ist das nicht messbar.
#
# WAS DAMIT NICHT GEHT: `grep -r` ueber ein Wurzelverzeichnis. Dort laeuft
# grep den Baum selbst ab, es gibt keinen Strom zum Abgreifen. Abschnitt 7.3
# bleibt deshalb eine Blackbox — das umzubauen hiesse, die Suche selbst zu
# aendern, und das waere ein hoher Preis fuer eine Anzeige.
fortschritt_strom() {   # fortschritt_strom <was> [jede_n_zeilen]
  local was="${1:-}" n="${2:-200}"
  if [[ -z "$FORTSCHRITT_DATEI" ]]; then cat; return 0; fi
  # KEIN systime(): das ist eine GNU-Erweiterung, und BSD-awk (macOS) bricht
  # damit ab — "calling undefined function systime". Die Pipeline haette dann
  # WENIGER Treffer geliefert statt einen Fehler zu melden. Genau die Fehlerart,
  # gegen die dieses Werkzeug gebaut ist.
  #
  # Die Zeit steht ohnehin schon in der Datei: ihre eigene mtime ist der
  # Zeitpunkt der letzten Schreiboperation. werkzeuge/lauf-status.sh liest sie
  # von dort.
  awk -v datei="${FORTSCHRITT_DATEI}.aktuell" -v was="$was" -v n="$n" '
    { print }
    NR % n == 0 {
      # Ueberschreiben, nicht anhaengen: interessant ist der Stand, nicht die
      # Geschichte. Die Datei bleibt damit ein paar hundert Byte gross.
      printf "%s\t%d\t%s\n", was, NR, $0 > datei
      close(datei)
    }
    END {
      printf "%s\t%d\t%s\n", was, NR, "— durch —" > datei
      close(datei)
    }'
}

fortschritt_ende() {
  [[ -n "$FORTSCHRITT_DATEI" ]] || return 0
  printf '#ende\t%s\n' "$(date +%s)" >> "$FORTSCHRITT_DATEI" 2>/dev/null || true
}
