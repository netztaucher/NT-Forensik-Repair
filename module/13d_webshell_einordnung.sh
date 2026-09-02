# shellcheck shell=bash
# NT-Forensik — Abschnitt 13d: Einordnung der Mustertreffer aus 7.3
#
# @nummer:  13d
# @titel:   Mustertreffer einordnen, gegen amtliche Pruefsummen entlasten
# @frage:   Welche der gefundenen Dateien sind wirklich ein Befund?
# @kosten:  gering — kein Baumdurchlauf, nur Listenabgleich
# @ebene:   website
#
# ------------------------------------------------------------
# WARUM DAS URTEIL HIER STEHT UND NICHT IN 7.3
#
# Abschnitt 7.3 durchsucht den Baum nach Webshell-Mustern. Der Durchlauf ist
# teuer und gehoert nach vorn. Das URTEIL gehoert nach hinten, weil die
# Entlastung erst in 12r entsteht: `wp core verify-checksums` fuer den Kern und
# die Pruefsummen von wordpress.org fuer Plugins.
#
# Bis v3.14 urteilte 7.3 sofort. Am 12.08.2026 meldete es deshalb auf einem
# gesunden Kundensystem eine UNVERAENDERTE Kern-Datei als Webshell:
#
#   🔴 KRITISCH: Webshells/Dropper gefunden: 1 Datei(en) < 3000 B
#   ✅ WordPress-Core unveraendert (verify-checksums)
#
# Beides im selben Bericht. Die Datei war
# wp-includes/class-wp-simplepie-sanitize-kses.php; ihre Zeile 42 ist ein
# SimplePie-preg_match mit der HTML-Whitespace-Zeichenklasse aus der
# WHATWG-Spezifikation. Ein KRITISCH loest im Bericht die volle
# Sofortmassnahmen-Liste aus — alle Passwoerter rotieren, SSH-Root abschalten.
#
# Dieselbe Ueberlegung hatte 7.12 zu 13c gemacht. Sie war fuer 7.3 nie gezogen
# worden.
#
# ------------------------------------------------------------
# KEIN STILLES WEGFILTERN
#
# Was entlastet wird, wird GEZAEHLT und ausgewiesen. Ein Befund, der lautlos
# verschwindet, ist die naechste stille Entwarnung — und die ist schlimmer als
# ein Fehlalarm, weil sie nach Pruefung aussieht.
#
# Und keine Entlastung ohne durchgefuehrte Pruefung: die Listen entstehen nur
# bei nachweislich gelaufenem verify-checksums (rezept_kern). Faellt das
# Werkzeug aus, bleiben sie leer, und dann entlastet hier nichts.
# ------------------------------------------------------------

h2 "13d Einordnung der Mustertreffer aus 7.3"

BELEG_STUFE=kunde

# Lief die Suche gar nicht, gibt es nichts einzuordnen — und vor allem nichts
# zu entwarnen. Abschnitt 7.3 hat den Ausfall bereits als ⚪ gemeldet; ein
# "keine Dropper gefunden" daneben waere ein Bericht, der sich selbst
# widerspricht.
if [[ "${NF_OHNE_PCRE:-0}" == "1" ]]; then
  info "Keine Einordnung möglich — die Mustersuche in 7.3 ist nicht gelaufen"
  return 0 2>/dev/null || true
fi

_WL="${PRUEFSUMMEN_WHITELIST:-${RUN_DIR}/.pruefsummen_bestaetigt.txt}"
_WL_KERN="${PRUEFSUMMEN_KERN_WHITELIST:-${RUN_DIR}/.pruefsummen_kern.txt}"
# Gegenprobe: dieselbe Naht wie in 13c. Werden beide Listen geleert, MUSS die
# Entlastung ausbleiben und der Vergleich ausschlagen — sonst waere nicht
# belegt, dass der Filter ueberhaupt greift.
if [[ "${NT_PRUEFSTAND_OHNE_PMF_WHITELIST:-0}" == "1" ]]; then
  _WL="/nicht/vorhanden"; _WL_KERN="/nicht/vorhanden"
fi
# Die Abweichungen aus verify-checksums duerfen NICHT freigegeben werden,
# obwohl sie unter wp-admin/ und wp-includes/ liegen. Sie sind der Grund,
# warum dort ueberhaupt jemand hinsieht.
_AUSN=$(printf '%s\n%s\n' "${CORE_INJECTED:-}" "${CORE_SNE:-}" | grep -v '^$' || true)

# ── Einen Block aus 7.3 aufteilen ────────────────────────────────────────
# Eingabe ist das Format aus 7.3: je Datei ein Absatz, der mit "=== <pfad> ==="
# beginnt. Zurueck kommen zwei Bloecke — was bleibt und was entlastet wurde.
_einordnen() {   # _einordnen <blob>; setzt _REST, _WEG, _N_REST, _N_WEG
  _REST=""; _WEG=""; _N_REST=0; _N_WEG=0
  [[ -n "${1:-}" ]] || return 0
  local roh="${BELEGE_DIR}/.einordnung_roh"
  printf '%s' "$1" > "$roh"
  # ZWEI DATEIEN, KEIN TRENNER IM DATENSTROM.
  #
  # Der erste Entwurf schrieb beide Bloecke hintereinander, getrennt durch
  # eine Zeile mit 0x1e, und schnitt sie mit `sed -n '1,/^\x1e$/p'` wieder
  # auseinander. Das ist falsch: bei einem Bereich `1,/re/` prueft sed das
  # Endmuster erst AB ZEILE 2. Lag der Trenner auf Zeile 1 — also wenn ALLE
  # Treffer entlastet wurden — endete der Bereich nie, und beide Haelften
  # enthielten alles. Auf dem echten System stand dieselbe Datei daraufhin
  # zugleich unter "kritisch" und unter "entlastet".
  #
  # Der Pruefbaum sah es nicht, weil dort immer etwas uebrig blieb.
  NT_LIB="${SELF_DIR}/lib" PMF_WL="$_WL" PMF_WL_KERN="$_WL_KERN" \
  PMF_AUSNAHMEN="$_AUSN" \
  python3 - "$roh" "${roh}.rest" "${roh}.weg" <<'PY'
import os, sys
sys.path.insert(0, os.environ["NT_LIB"])
from pruefsummen_filter import freigabe_bauen

frei = freigabe_bauen(os.environ.get("PMF_WL", ""),
                      os.environ.get("PMF_WL_KERN", ""),
                      os.environ.get("PMF_AUSNAHMEN", ""))

text = open(sys.argv[1], encoding="utf-8", errors="replace").read()
rest, weg = [], []
block, pfad = [], None
def ablegen():
    if pfad is None:
        return
    (weg if frei(pfad) else rest).append("".join(block))
for zeile in text.splitlines(keepends=True):
    if zeile.startswith("=== ") and zeile.rstrip("\n").endswith(" ==="):
        ablegen()
        pfad = zeile.strip()[4:-4]
        block = [zeile]
    elif pfad is not None:
        block.append(zeile)
ablegen()
open(sys.argv[2], "w", encoding="utf-8").write("".join(rest))
open(sys.argv[3], "w", encoding="utf-8").write("".join(weg))
PY
  _REST=$(cat "${roh}.rest" 2>/dev/null || true)
  _WEG=$(cat  "${roh}.weg"  2>/dev/null || true)
  # Gezaehlt wird auf der DATEI, nicht auf der Variablen: eine leere Variable
  # ergibt bei `printf '%s\n'` eine Leerzeile, und die zaehlt grep zwar nicht
  # als Treffer, aber der Unterschied zwischen "leer" und "eine Leerzeile"
  # hat hier schon einmal Zahlen verfaelscht.
  _N_REST=$(grep -c '^=== ' "${roh}.rest" 2>/dev/null || true); _N_REST="${_N_REST:-0}"
  _N_WEG=$(grep -c  '^=== ' "${roh}.weg"  2>/dev/null || true); _N_WEG="${_N_WEG:-0}"
  rm -f "$roh" "${roh}.rest" "${roh}.weg"
}

# ── Fremdbibliotheken aus der kritischen Stufe nehmen (#46) ──────────────
#
# Gemessen am Lauf 20260813_150137_global: von 292 Eintraegen in Stufe 1 lagen
# 156 unter vendor/, vendor-prefixed/ oder node_modules/ — 53 %. Die sechs
# haeufigsten Namen allein waren 153 Dateien, saemtlich legitimer
# Bibliothekscode:
#
#   Flate.php 61 (setasign/fpdi)   PhpEvaluator.php 32 (dompdf)
#   Hash.php  21 (Nextcloud)       Gzip.php         14
#   zip.lib.php 13 (PhpMyAdmin)    DetachedRuleset.php 12 (Less.php)
#
# Das ist nicht nur Rauschen. NT-Repair zieht seine Quarantaene-Kandidaten aus
# genau dieser Liste (nt_repair.sh:373-383) — eine Bereinigung haette
# PDF-Erzeugung, Nextcloud und Less-Kompilierung serverweit verschoben.
#
# WARUM DAS KEINE ENTLASTUNG IST
# Eine Shell KANN unter vendor/ liegen. Die Regel spricht nicht frei, sie
# verschiebt die Beweislast: aus "kritisch, sofort handeln" wird "sichten".
# Wer dort etwas ablegt und es per .htaccess freigibt, wird weiterhin von
# Abschnitt 7.6b gefasst — der Weg, der die 29 echten Hintertueren fand.
#
# Fuer diese Dateien gibt es keinen Pruefsummensatz (#30); bis den jemand
# beschafft, ist die Herkunft aus einem Abhaengigkeitsverzeichnis das
# einzige Merkmal, das zur Verfuegung steht.
_vendor_trennen() {   # <blob>; setzt _V_REST, _V_VENDOR, _N_V_REST, _N_VENDOR
  _V_REST=""; _V_VENDOR=""; _N_V_REST=0; _N_VENDOR=0
  [[ -n "${1:-}" ]] || return 0
  local roh="${BELEGE_DIR}/.vendor_roh"
  printf '%s' "$1" > "$roh"
  : > "${roh}.rest"; : > "${roh}.vendor"
  # Zwei Dateien statt eines Trenners im Datenstrom — derselbe Grund wie oben.
  awk -v re="${VENDOR_PFADE:-/vendor/|/vendor-prefixed/|/node_modules/}" \
      -v a="${roh}.rest" -v b="${roh}.vendor" '
    /^=== .* ===$/ { p = substr($0, 5, length($0) - 8); ziel = (p ~ re) ? b : a }
    ziel != "" { print > ziel }
  ' "$roh"
  _V_REST=$(cat "${roh}.rest"   2>/dev/null || true)
  _V_VENDOR=$(cat "${roh}.vendor" 2>/dev/null || true)
  _N_V_REST=$(grep -c '^=== ' "${roh}.rest"   2>/dev/null || true); _N_V_REST="${_N_V_REST:-0}"
  _N_VENDOR=$(grep -c '^=== ' "${roh}.vendor" 2>/dev/null || true); _N_VENDOR="${_N_VENDOR:-0}"
  rm -f "$roh" "${roh}.rest" "${roh}.vendor"
}

# Ein Satz, der die Entlastung benennt — oder gar nichts, wenn keine stattfand.
_entlastet_satz() {   # _entlastet_satz <anzahl>
  [[ "${1:-0}" -gt 0 ]] && printf ' (%s gegen amtliche Prüfsummen entlastet)' "$1"
}

# ── Stufe 1: kleine Dateien mit Obfuskation ──────────────────────────────
_einordnen "${DROPPER_DETAIL:-}"
_D_REST="$_REST"; _D_WEG="$_WEG"; _D_N="$_N_REST"; _D_NW="$_N_WEG"
# Erst entlasten, dann Fremdbibliotheken abschichten. Die Reihenfolge ist
# bedeutsam: was eine amtliche Pruefsumme bestaetigt, ist erledigt und muss
# gar nicht erst nach seiner Herkunft gefragt werden.
_vendor_trennen "$_D_REST"
_D_REST="$_V_REST"; _D_N="$_N_V_REST"
WEBSHELL_DROPPER_VENDOR="$_V_VENDOR"
WEBSHELL_VENDOR="${_N_VENDOR:-0}"
if [[ "${_N_VENDOR:-0}" -gt 0 ]]; then
  warn "${_N_VENDOR} Mustertreffer liegen in Abhängigkeitsverzeichnissen (vendor/, node_modules/) — zur Sichtung, nicht zur Quarantäne. Für sie gibt es keinen Prüfsummensatz" web
  evidence "webshell_vendor_sichtung" "$_V_VENDOR" kunde
fi
if [[ "${_D_N:-0}" -gt 0 ]]; then
  crit "Webshells/Dropper gefunden: ${_D_N} Datei(en) < ${DROPPER_MAX_BYTES} B mit Obfuskation$(_entlastet_satz "$_D_NW")" web
  DROPPER_CLUSTER=$(printf '%s\n' "$_D_REST" | grep "^=== " \
    | sed 's|=== /var/www/vhosts/||;s| ===||' | cut -d/ -f1 | LC_ALL=C sort | uniq -c | sort -rn || true)
  info "Betroffene Domains (Dropper-Cluster):"
  code "$DROPPER_CLUSTER"
  echo -e "\n**Dropper-Details:**\n\`\`\`\n${_D_REST}\n\`\`\`" >> "$REPORT_FILE"
  evidence "webshell_dropper_kritisch" "$_D_REST" kunde
elif [[ "${_D_NW:-0}" -gt 0 ]]; then
  ok "Keine kleinen Obfuskations-Dropper — ${_D_NW} Mustertreffer waren gegen amtliche Prüfsummen bestätigte Dateien"
else
  ok "Keine kleinen Obfuskations-Dropper gefunden"
fi
# Was entlastet wurde, bleibt belegt. Sonst liesse sich spaeter nicht
# nachvollziehen, WAS der Filter herausgenommen hat.
[[ "${_D_NW:-0}" -gt 0 ]] && evidence "webshell_dropper_entlastet" "$_D_WEG"

# ── DIE ENTLASTUNG MUSS IN findings.json ANKOMMEN ───────────────────────
#
# Abschnitt 14 baut actionable.webshell_dropper aus DROPPER_DETAIL, und aus
# dieser Liste holt sich die Bereinigung ihre Quarantaene-Kandidaten.
#
# Bis hierher wirkte die Entlastung NUR im Bericht: dort stand "398 Datei(en)
# (396 entlastet)", waehrend findings.json unveraendert alle 398 fuehrte —
# darunter unveraenderte WordPress-Kern-Dateien. Die Bereinigung haette sie in
# Quarantaene genommen und damit Installationen zerlegt, die nichts hatten.
#
# Ein Bericht, der entlastet, und eine Schnittstelle, die es nicht tut, sind
# schlimmer als gar keine Entlastung: der Betreiber liest die Entwarnung und
# das Werkzeug handelt trotzdem.
#
# 13d laeuft vor 14, deshalb genuegt das Zurueckschreiben hier. Die
# entlasteten Eintraege sind im Beleg oben festgehalten, sie gehen nicht
# verloren.
DROPPER_DETAIL="$_D_REST"

# ── UND DIE ZAEHLER MUESSEN MIT (#64) ───────────────────────────────────
#
# Die Liste zurueckzuschreiben allein genuegt nicht. WEBSHELL_COUNT stammt aus
# 7.3 und stand damit weiterhin auf dem Stand VOR der Entlastung. Gemessen am
# Lauf 20260813_150137_global: metrics.webshell_count nannte 398, waehrend
# actionable.webshell_dropper 292 Eintraege hatte — 36 % Abweichung in
# derselben Datei.
#
# Und der Zaehler bleibt nicht in findings.json. Er steht im KUNDENBERICHT
# ("398 Schadcode-Dateien im Webverzeichnis gefunden") und in der Tabelle der
# BSI-Meldung. Dort waren 106 Dateien mitgezaehlt, die gegen amtliche
# Pruefsummen als unveraendert bestaetigt sind.
#
# Der rohe Wert geht nicht verloren, er bekommt einen eigenen Namen. Eine
# Entlastung, die nur die Zahl kleiner macht, ohne zu sagen wieviel, waere
# dieselbe Undurchsichtigkeit von der anderen Seite.
WEBSHELL_COUNT_ROH="${WEBSHELL_COUNT:-0}"
WEBSHELL_COUNT="${_D_N:-0}"
WEBSHELL_ENTLASTET="${_D_NW:-0}"

# ── Stufe 2: groessere Dateien, Sichtung ─────────────────────────────────
_einordnen "${REVIEW_DETAIL:-}"
REVIEW_DETAIL="$_REST"
WEBSHELL_REVIEW_ROH="${WEBSHELL_REVIEW:-0}"
WEBSHELL_REVIEW="${_N_REST:-0}"
WEBSHELL_REVIEW_ENTLASTET="${_N_WEG:-0}"
if [[ "${_N_REST:-0}" -gt 0 ]]; then
  warn "Obfuskations-Muster in ${_N_REST} größeren Datei(en) — manuell prüfen (oft legitime Frameworks)$(_entlastet_satz "$_N_WEG")" web
  evidence "webshell_review_gross" "$_REST" kunde
fi

# ── Gefaehrliche Funktionen in kleinen Dateien ───────────────────────────
_einordnen "${MED_DETAIL:-}"
MED_DETAIL="$_REST"
MED_COUNT_ROH="${MED_COUNT:-0}"
MED_COUNT="${_N_REST:-0}"
MED_ENTLASTET="${_N_WEG:-0}"
if [[ "${_N_REST:-0}" -gt 0 ]]; then
  warn "Gefährliche Funktionen (exec-Familie, Bot-Ausblendung, Login-Gate) in ${_N_REST} kleinen Datei(en) — sichten$(_entlastet_satz "$_N_WEG")" web
  code "$(printf '%s\n' "$_REST" | grep '^=== ' | sed 's|=== ||;s| ===||' | awk 'NR<=20')"
  evidence "gefaehrliche_funktionen_klein" "$_REST" kunde
else
  ok "Keine gefährlichen Funktionen in kleinen PHP-Dateien"
fi
