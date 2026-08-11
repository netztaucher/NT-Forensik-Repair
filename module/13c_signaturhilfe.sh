# shellcheck shell=bash
# NT-Forensik — Abschnitt 13c: Fremder YARA-Regelsatz (php-malware-finder)
#
# @nummer:  13c
# @titel:   Fremder YARA-Regelsatz als Suchhilfsmittel
# @frage:   Welche PHP-Dateien sollte ein Prüfer sich zuerst ansehen?
# @kosten:  gering — ein gebündelter yara-Lauf, im Messlauf 8 s für 25.860 Dateien
# @ebene:   website
#
# ------------------------------------------------------------
# WARUM DIESER ABSCHNITT DIE NUMMER 13c TRÄGT UND NICHT MEHR 7.12
#
# Er filtert seine Trefferliste gegen die Dateien, die als unverändert
# gegenüber dem Original bestätigt wurden — Kern über `wp core
# verify-checksums`, Plugins über die Prüfsummen von wordpress.org. Beides
# entsteht im WordPress-Rezept, also in Abschnitt 12r. Als 7.12 lief dieser
# Abschnitt DAVOR und hatte die Liste noch nicht.
#
# 13c läuft nach 12r und 13b, aber vor 14 (den Berichten). Ein Prüfabschnitt
# mit höherer Nummer als 14 erscheint zwar auf der Konsole, aber in keinem
# Dokument und in keiner Zählung.
#
# ------------------------------------------------------------
# WAS DER FILTER LEISTET — UND WAS NICHT
#
# Messlauf über einen realen Webspace, 25.860 PHP-Dateien: 359 Dateien mit
# Treffern, und der enthaltene gepackte Webshell stand mit drei Regeln auf
# Platz 11. Über ihm der WordPress-Kern, pclzip, UpdraftPlus und Wordfence
# selbst.
#
# Ursache ist die Whitelist des Regelsatzes: sie arbeitet mit SHA1-Hashes
# konkreter Kerndateien (629 Stück für WordPress) auf dem Stand von 2023. Auf
# einer aktuellen Installation passt kein einziger davon. Das Projekt hinter
# dem Regelsatz ruht seit Oktober 2023 — das Problem wächst mit jedem
# WordPress-Release und löst sich nicht von selbst.
#
# Die tote Hash-Whitelist wird deshalb durch eine LEBENDE ersetzt, die bei
# jedem Lauf neu entsteht. Eine Datei, die Byte für Byte dem Original
# entspricht, kann kein untergeschobener Schadcode sein.
#
# Nicht abgedeckt, und das gehört gesagt:
#   - kommerzielle Plugins ohne öffentliche Prüfsummen. Im Messlauf waren das
#     genau die lautesten Fundorte: UpdraftPlus, WP All Import Pro, Wordfence.
#   - Themes. Für theme-checksums liefert wordpress.org HTTP 404.
#   - Installationen ohne wp-cli (Kern) bzw. ohne --online (Plugins).
#
# Eine Halbierung ist realistisch, eine Lösung ist es nicht.
#
# ------------------------------------------------------------
# KEINE STILLE FILTERUNG
#
# Die Zahl der unterdrückten Treffer steht im Befundtext und im Beleg, und der
# Beleg führt sie namentlich auf. In einem Forensikwerkzeug ist ein Filter,
# dessen Wirkung man nicht nachrechnen kann, schlimmer als kein Filter: er
# erzeugt Vertrauen, das sich nicht prüfen lässt.

h1 "13c. FREMDER YARA-REGELSATZ (SUCHHILFSMITTEL)"

# Belegstufe dieses Abschnitts (#1). Der Regelsatz läuft über den Webbaum des
# geprüften Auftritts.
BELEG_STUFE=kunde

# Bewusst ein EIGENER yara-Aufruf, nicht per include in alle.yar:
#
#   1. php.yar bringt `import "hash"` mit. Fehlt das Modul im yara-Build,
#      scheitert die Übersetzung — und mit ihr die gesamte Sammlung. Genau
#      davor warnt der Kopf von signaturen/alle.yar. Ein eigener Aufruf darf
#      folgenlos fehlschlagen.
#   2. Der Regelsatz steht unter LGPL-3.0, dieses Repository unter MIT. Er wird
#      deshalb nicht mitgeliefert, sondern vor Ort geholt
#      (werkzeuge/signaturen-fremd-holen.sh) und liegt in einem Verzeichnis,
#      das nicht im Repository steht.
#
# Anders als 7.11 läuft dieser Scan gebündelt statt Datei für Datei. Bei
# 25.000 PHP-Dateien spart das einen Prozessstart je Datei.
#
# Der Weg dahin führt über --scan-list, NICHT über mehrere Dateiargumente:
# yara nimmt genau ein Ziel entgegen und deutet ein zweites Argument als
# Regeldatei. Ein Bündelaufruf per xargs meldete deshalb im Test 25.860
# Dateien in einer Sekunde ohne einen einzigen Treffer — er hatte gar nicht
# gescannt, sondern nur Übersetzungsfehler erzeugt, die in /dev/null liefen.
FREMD_YAR="${BASE_DIR}/signaturen/fremd/php.yar"

# Prüfstand-Naht: NT_PMF_ATTRAPPE nennt eine Datei mit vorgefertigter
# yara-Ausgabe ("<regel> <pfad>" je Zeile). Ohne sie wäre dieser Abschnitt vom
# Prüfstand nicht erreichbar — der Prüfbaum hat weder yara noch den fremden
# Regelsatz, und ein Filter, der nie gemessen wird, ist eine Behauptung.
PMF_OUT=""
PMF_QUELLE=""
if [[ -n "${NT_PMF_ATTRAPPE:-}" && -r "${NT_PMF_ATTRAPPE}" ]]; then
    PMF_OUT=$(cat "${NT_PMF_ATTRAPPE}")
    PMF_QUELLE="Prüfstand-Attrappe"
    PMF_ALTER=0
elif [[ "$WANT_YARA" != "1" ]]; then
    : # 7.11 hat den Hinweis bereits ausgegeben
elif ! command -v yara &>/dev/null; then
    : # dito
elif [[ ! -f "$FREMD_YAR" ]]; then
    info "php-malware-finder nicht vorhanden — mit werkzeuge/signaturen-fremd-holen.sh holen"
else
    PMF_ALTER=$(( ( $(date +%s) - $(stat -c %Y "$FREMD_YAR" 2>/dev/null || echo 0) ) / 86400 ))
    # Dateiliste bewusst NICHT nach /tmp: Abschnitt 7.8 prüft dort auf
    # ausführbare Dateien, und ein Werkzeug soll den eigenen Prüfgegenstand
    # nicht verändern.
    PMF_LISTE="${BELEGE_DIR}/.pmf_dateiliste"
    find "${SCAN_PATHS[@]}" -type f -size -3M \
        \( -name "*.php" -o -name "*.phtml" -o -name "*.inc" \) 2>/dev/null \
      | nf_strip_self > "$PMF_LISTE"
    PMF_OUT=$(yara -w -p 4 --scan-list "$FREMD_YAR" "$PMF_LISTE" 2>/dev/null || true)
    rm -f "$PMF_LISTE"
    PMF_QUELLE="php.yar"
fi

if [[ -n "$PMF_OUT" ]]; then
    # ── Die lebende Whitelist ────────────────────────────────
    PMF_WL="${PRUEFSUMMEN_WHITELIST:-${RUN_DIR}/.pruefsummen_bestaetigt.txt}"
    PMF_WL_KERN="${PRUEFSUMMEN_KERN_WHITELIST:-${RUN_DIR}/.pruefsummen_kern.txt}"
    # Gegenprobe: NT_PRUEFSTAND_OHNE_PMF_WHITELIST=1 leert beide Listen. Der
    # Vergleich MUSS dann ausschlagen — sonst erreicht der Prüfstand den Filter
    # gar nicht, und die ganze Rangfolge oben wäre unbelegt.
    if [[ "${NT_PRUEFSTAND_OHNE_PMF_WHITELIST:-0}" == "1" ]]; then
      PMF_WL="/nicht/vorhanden"; PMF_WL_KERN="/nicht/vorhanden"
    fi
    # Die Abweichungen aus verify-checksums dürfen NICHT freigegeben werden,
    # obwohl sie unter wp-admin/ und wp-includes/ liegen. Sie sind der Grund,
    # warum dort überhaupt jemand hinsieht.
    PMF_AUSNAHMEN=$(printf '%s\n%s\n' "${CORE_INJECTED:-}" "${CORE_SNE:-}" | grep -v '^$' || true)

    # Die Trefferliste geht ueber eine DATEI an python, nicht ueber stdin:
    # ein Here-Doc liefert bereits das Skript, und ein zweites Umlenken auf
    # stdin ueberschreibt es. Der erste Entwurf tat genau das — python las
    # die Trefferliste als Programm.
    PMF_ROH="${BELEGE_DIR}/.pmf_roh"
    printf '%s\n' "$PMF_OUT" > "$PMF_ROH"
    PMF_GEFILTERT=$(
      PMF_WL="$PMF_WL" PMF_WL_KERN="$PMF_WL_KERN" PMF_AUSNAHMEN="$PMF_AUSNAHMEN" \
      python3 - "$PMF_ROH" <<'PY'
import os, sys

def zeilen(pfad):
    try:
        with open(pfad, encoding="utf-8", errors="replace") as fh:
            return {z.strip() for z in fh if z.strip()}
    except OSError:
        return set()

bestaetigt = zeilen(os.environ.get("PMF_WL", ""))
kerne      = zeilen(os.environ.get("PMF_WL_KERN", ""))
ausnahmen  = {z.strip() for z in os.environ.get("PMF_AUSNAHMEN", "").splitlines() if z.strip()}

# Der Kern ist als VERZEICHNIS bestaetigt, nicht Datei fuer Datei:
# verify-checksums nennt ausschliesslich die Abweichungen. Alles unter
# wp-admin/ und wp-includes/ einer geprueften Instanz, das nicht selbst als
# Abweichung gemeldet wurde, ist damit bestaetigt.
kern_praefixe = tuple(
    os.path.join(k, teil) + os.sep
    for k in kerne for teil in ("wp-admin", "wp-includes")
)

def freigegeben(pfad):
    if pfad in ausnahmen:
        return False
    if pfad in bestaetigt:
        return True
    return pfad.startswith(kern_praefixe)

for zeile in open(sys.argv[1], encoding="utf-8", errors="replace").read().splitlines():
    # yara schreibt "<regelname> <pfad>". Der Pfad kann Leerzeichen enthalten,
    # der Regelname nicht — deshalb genau einmal aufteilen.
    teile = zeile.split(" ", 1)
    if len(teile) != 2:
        continue
    regel, pfad = teile[0], teile[1].strip()
    print("%s\t%s\t%s" % ("WEG" if freigegeben(pfad) else "BLEIBT", regel, pfad))
PY
    )
    rm -f "$PMF_ROH"

    PMF_UNTERDRUECKT=$(printf '%s\n' "$PMF_GEFILTERT" | awk -F'\t' '$1=="WEG"{print $3}' | LC_ALL=C sort -u)
    PMF_REST=$(printf '%s\n' "$PMF_GEFILTERT" | awk -F'\t' '$1=="BLEIBT"{print $2" "$3}')
    PMF_N_WEG=$(printf '%s\n' "$PMF_UNTERDRUECKT" | grep -c . || true)

    if [[ -n "$PMF_REST" ]]; then
        PMF_ANZ=$(printf '%s\n' "$PMF_REST" | awk '{$1=""; print}' | LC_ALL=C sort -u | grep -c . || true)
        # Nach Anzahl ausgelöster Regeln absteigend — als schwache Hilfe, nicht
        # als Trennschärfe. Zweiter Schlüssel ist der Pfad: ohne ihn entscheidet
        # bei Gleichstand die Reihenfolge, in der awk seine Schlüssel ausgibt,
        # und zwei Läufe über denselben Baum lieferten verschiedene Listen.
        PMF_RANG=$(printf '%s\n' "$PMF_REST" \
                   | awk '{r=$1; $1=""; sub(/^ /,""); regeln[$0]=regeln[$0]" "r; n[$0]++}
                          END {for (f in n) printf "%d\t%s\t%s\n", n[f], f, regeln[f]}' \
                   | LC_ALL=C sort -k1,1nr -k2,2 \
                   | awk -F'\t' '{printf "%d Regel(n): %s —%s\n", $1, $2, $3}')
        # Absichtlich warn, nicht crit: die Regeln zielen auf Obfuskierungs- und
        # Funktionsmuster, nicht auf konkrete Schädlinge. Sie treffen deshalb
        # auch legitimen Verschleierungs- und Bibliothekscode. Jeder Treffer
        # gehört gesichtet, keiner ist für sich ein Befund.
        warn "php-malware-finder: $PMF_ANZ Datei(en) mit Treffern — nach Regelanzahl sortiert, jeder Treffer gehört gesichtet (${PMF_N_WEG} als unverändert bestätigte Datei(en) herausgefiltert)" web
        code "$(printf '%s\n' "$PMF_RANG" | head -40)"
        # Der Beleg führt BEIDE Listen. Wer den Filter nicht nachrechnen kann,
        # muss ihm glauben — und das ist genau das, was ein Beleg verhindern soll.
        evidence "php_malware_finder_treffer" "VERBLIEBEN (nach Regelanzahl):
${PMF_RANG}

HERAUSGEFILTERT (${PMF_N_WEG} Datei(en), gegen wordpress.org als unverändert bestätigt):
${PMF_UNTERDRUECKT}" kunde
    else
        ok "php-malware-finder: keine Treffer nach dem Prüfsummenfilter (${PMF_N_WEG} als unverändert bestätigte Datei(en) herausgefiltert)"
    fi

    # Ein Filter, der ALLES wegnimmt, ist kaputt — nicht gut. Das gehört
    # gesagt, solange jemand hinsieht.
    if [[ "${PMF_N_WEG:-0}" -gt 0 && -z "$PMF_REST" ]]; then
        info "Alle Treffer stammten aus bestätigt unveränderten Dateien. Plausibel bei einer sauberen Installation — bei einem Verdachtsfall zweimal hinsehen."
    fi
    [[ -n "$PMF_QUELLE" ]] && info "Quelle: ${PMF_QUELLE}, Regelstand ${PMF_ALTER:-?} Tage alt — der Regelsatz wird vom Projekt kaum noch gepflegt"
elif [[ -n "$PMF_QUELLE" ]]; then
    ok "php-malware-finder: keine Treffer"
    info "Regelstand: ${PMF_ALTER:-?} Tage alt — der Regelsatz wird vom Projekt kaum noch gepflegt"
fi
