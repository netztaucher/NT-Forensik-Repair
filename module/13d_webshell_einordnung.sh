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
  local ergebnis
  ergebnis=$(
    NT_LIB="${BASE_DIR}/lib" PMF_WL="$_WL" PMF_WL_KERN="$_WL_KERN" \
    PMF_AUSNAHMEN="$_AUSN" python3 - "$roh" <<'PY'
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
# Zwei Bloecke, getrennt durch eine Zeile, die im Inhalt nicht vorkommen kann.
sys.stdout.write("".join(rest))
sys.stdout.write("\x1e\n")
sys.stdout.write("".join(weg))
PY
  )
  _REST=$(printf '%s' "$ergebnis" | sed -n '1,/^\x1e$/p' | sed '$d')
  _WEG=$(printf  '%s' "$ergebnis" | sed -n '/^\x1e$/,$p' | sed '1d')
  _N_REST=$(printf '%s\n' "$_REST" | grep -c '^=== ' || true)
  _N_WEG=$(printf  '%s\n' "$_WEG"  | grep -c '^=== ' || true)
  rm -f "$roh"
}

# Ein Satz, der die Entlastung benennt — oder gar nichts, wenn keine stattfand.
_entlastet_satz() {   # _entlastet_satz <anzahl>
  [[ "${1:-0}" -gt 0 ]] && printf ' (%s gegen amtliche Prüfsummen entlastet)' "$1"
}

# ── Stufe 1: kleine Dateien mit Obfuskation ──────────────────────────────
_einordnen "${DROPPER_DETAIL:-}"
_D_REST="$_REST"; _D_WEG="$_WEG"; _D_N="$_N_REST"; _D_NW="$_N_WEG"
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

# ── Stufe 2: groessere Dateien, Sichtung ─────────────────────────────────
_einordnen "${REVIEW_DETAIL:-}"
if [[ "${_N_REST:-0}" -gt 0 ]]; then
  warn "Obfuskations-Muster in ${_N_REST} größeren Datei(en) — manuell prüfen (oft legitime Frameworks)$(_entlastet_satz "$_N_WEG")" web
  evidence "webshell_review_gross" "$_REST" kunde
fi

# ── Gefaehrliche Funktionen in kleinen Dateien ───────────────────────────
_einordnen "${MED_DETAIL:-}"
if [[ "${_N_REST:-0}" -gt 0 ]]; then
  warn "Gefährliche Funktionen (exec-Familie, Bot-Ausblendung, Login-Gate) in ${_N_REST} kleinen Datei(en) — sichten$(_entlastet_satz "$_N_WEG")" web
  code "$(printf '%s\n' "$_REST" | grep '^=== ' | sed 's|=== ||;s| ===||' | awk 'NR<=20')"
  evidence "gefaehrliche_funktionen_klein" "$_REST" kunde
else
  ok "Keine gefährlichen Funktionen in kleinen PHP-Dateien"
fi
