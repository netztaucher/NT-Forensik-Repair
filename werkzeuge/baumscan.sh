#!/usr/bin/env bash
# =============================================================================
# baumscan.sh — Schadcode-Suche über einen Server-Verzeichnisbaum (read-only)
# =============================================================================
# Mehrschichtiger Scan für Webspaces (WordPress/Joomla/Nextcloud/beliebig).
# Verändert am Prüfziel NICHTS — schreibt ausschliesslich nach $BASE.
#
# Nutzung:  baumscan.sh <SCOPE-Pfad> [<vergleichs-run-dir>]
#
# Schichten:
#   1  Inventur           ein find -> TSV (Größe, mtime, ctime, Owner, Mode)
#   2  Magic-Byte         .php-Datei mit Bild-Header (Bild-getarnte Shell)
#   2b PHP-in-Medien      echtes PNG/JPG/Font/PDF mit <?php im Inhalt   [NEU]
#   3  Heuristik          gestaffelte Muster HIGH/MED, Shell-Namen      [NEU]
#   4  Timestomping       mtime ≪ ctime + Massen-touch-Cluster          [NEU]
#   5  .htaccess          Angreifer-Whitelists, PHP-Freigabe in uploads [NEU]
#   6  ImunifyAV          eigener Signaturlauf, auf Ergebnis gewartet   [NEU]
#   7  Bewertung          Score je Datei, BEFUND nach Verdacht sortiert [NEU]
#   8  Diff               neue Funde gegenüber einem Vorlauf
#
# Warum diese Schichten: bei einem realen Vorfall im August 2026 fand der Signaturscanner alle
# vier Backdoors, die erste Fassung dieses Skripts nur eine — und die ungerankt
# auf Platz 126 einer Fundliste. Die Lücken waren: Adjazenz-Zwang im Muster
# (eval($decode(...)) wurde nicht erkannt), fehlende exec-Familie, einseitiger
# Magic-Byte-Test und fehlende Priorisierung. Schichten 2b, 3, 4, 5 und 7
# schliessen genau diese Lücken.
#
# Abhängigkeiten: bash, find, awk, grep -P, sed, sort, xargs, stat
# Optional:       imunify-antivirus, ionice
# =============================================================================

set -uo pipefail

# =============================================================================
# Betriebsart "qualifizieren" — Treffer auflösen
# =============================================================================
# Ein TREFFER ist kein Urteil, sondern eine offene Frage. Diese Betriebsart
# sammelt die Fakten, mit denen sie sich beantworten lässt.
#
#   baumscan.sh qualifizieren <lauf-verzeichnis> [--online]
#
# Nach SAUBER führt weiterhin genau ein Weg: eine amtliche Prüfsumme. Alles
# andere kann einen Treffer nur ERKLÄREN. Ein erklärter, aber unbeweisbarer
# Treffer wird KEIN mit protokolliertem Grund — nicht SAUBER.
if [ "${1:-}" = "qualifizieren" ]; then
  shift
  QRUN="${1:?Lauf-Verzeichnis nötig}"; shift || true
  [ "${1:-}" = "--online" ] && BAUMSCAN_ONLINE=1
  [ -s "$QRUN/urteile.tsv" ] || { echo "Keine urteile.tsv in $QRUN"; exit 2; }

  # Diese Betriebsart läuft VOR dem Konfigurationsteil und muss ihre Werkzeuge
  # selbst setzen. Ohne das war $NICE hier unbelegt; mit `set -u` brach die
  # Pipeline still ab, der Hash-Index entstand nie, und alle 607 Treffer
  # blieben "offen" — ein Fehlschlag, der wie ein Ergebnis aussah.
  NICE="ionice -c3 nice -n19"
  command -v ionice >/dev/null 2>&1 || NICE="nice -n19"

  KORPUS="${BAUMSCAN_KORPUS:-/var/www/vhosts}"
  QOUT="$QRUN/QUALIFIZIERUNG.txt"
  QTSV="$QRUN/qualifizierung.tsv"
  ENTSCHEID="$QRUN/entscheidungen.tsv"
  [ -f "$ENTSCHEID" ] || printf '# Pfad\tUrteil\tKennung\tDatum\tBegründung\n' > "$ENTSCHEID"

  awk -F'\t' '$1=="TREFFER" {print $3}' "$QRUN/urteile.tsv" > "$QRUN/.treffer_pfade"
  ANZ=$(wc -l < "$QRUN/.treffer_pfade")
  echo "[$(date +%H:%M:%S)] $ANZ Treffer zu qualifizieren"

  # ── Verbreitungsindex: EIN Durchlauf über den Korpus ─────────────────────
  # 607 Treffer einzeln serverweit zu suchen hiesse 607 Durchläufe. Statt
  # dessen einmal alle Dateinamen der Treffer einsammeln und den Korpus ein
  # einziges Mal durchgehen.
  echo "[$(date +%H:%M:%S)] Verbreitungsindex über $KORPUS..."
  awk -F/ '{print $NF}' "$QRUN/.treffer_pfade" | sort -u > "$QRUN/.treffer_namen"
  find "$KORPUS" -type f -size -3M -printf '%f\t%s\t%p\n' 2>/dev/null \
    | awk -F'\t' 'NR==FNR {gesucht[$0]=1; next} ($1 in gesucht)' \
        "$QRUN/.treffer_namen" - > "$QRUN/.korpus_index" 2>/dev/null
  echo "[$(date +%H:%M:%S)]   $(wc -l < "$QRUN/.korpus_index") Kandidaten im Korpus"

  # Den Korpus EINMAL hashen, nicht je Treffer. Der erste Entwurf hashte bis zu
  # 80 Kandidaten pro Treffer — bei 607 Treffern waren das zehntausende
  # Aufrufe, und der Lauf war nach zehn Minuten nicht durch.
  echo "[$(date +%H:%M:%S)] Korpus hashen..."
  cut -f3 "$QRUN/.korpus_index" | tr '\n' '\0' \
    | $NICE xargs -0 -r -P4 -n100 sha256sum 2>/dev/null > "$QRUN/.korpus_hashes"
  echo "[$(date +%H:%M:%S)]   $(wc -l < "$QRUN/.korpus_hashes") Hashes"

  # Zugriffslogs EINMAL auspacken. Je Treffer zu zgreppen hiesse, dieselben
  # komprimierten Logs hundertfach zu entpacken.
  echo "[$(date +%H:%M:%S)] Zugriffslogs sammeln..."
  : > "$QRUN/.logs_text"
  cut -f3 "$QRUN/.treffer_pfade" 2>/dev/null >/dev/null
  sed 's|\(/var/www/vhosts/[^/]*\).*|\1|' "$QRUN/.treffer_pfade" | sort -u | while read -r vr; do
    [ -d "$vr/logs" ] || continue
    zcat -f "$vr"/logs/*access* 2>/dev/null >> "$QRUN/.logs_text"
  done
  echo "[$(date +%H:%M:%S)]   $(wc -l < "$QRUN/.logs_text") Logzeilen"

  : > "$QTSV"
  {
    echo "==============================================================="
    echo " Qualifizierung der Treffer — Entscheidungsvorlage"
    echo " Lauf:   $QRUN"
    echo " Datum:  $(date -Is)"
    echo "==============================================================="
    echo
    echo "Jeder Block ist eine offene Frage, kein Urteil. Nach SAUBER führt"
    echo "nur die amtliche Prüfsumme. Entscheidungen gehören nach"
    echo "entscheidungen.tsv — mit Kennung und Begründung."
    echo
  } > "$QOUT"

  while IFS= read -r f; do
    [ -f "$f" ] || continue
    name=$(basename "$f")
    groesse=$(stat -c%s "$f" 2>/dev/null || echo 0)
    hash=$(sha256sum "$f" 2>/dev/null | cut -d' ' -f1)
    grund=$(awk -F'\t' -v p="$f" '$3==p {print $2}' "$QRUN/urteile.tsv" | head -1)

    # 1. Verbreitung — gleicher Inhalt auf wie vielen Installationen?
    # Nachschlagen im vorbereiteten Hash-Index, nicht neu hashen.
    installationen=$(awk -v h="$hash" -v selbst="$f" -v k="$KORPUS" '
        $1==h && $2!=selbst {
          pfad = $2
          sub("^" k "/", "", pfad)
          sub("/.*", "", pfad)
          gesehen[pfad] = 1
        }
        END { n=0; for (i in gesehen) n++; print n }
      ' "$QRUN/.korpus_hashes")

    # 2. Amtliche Prüfsumme — gehört die Datei überhaupt zum Lieferumfang?
    pruefsumme="keine Referenz"
    case "$f" in
      */wp-content/plugins/*)
        pslug=$(echo "$f" | sed 's|.*/wp-content/plugins/\([^/]*\)/.*|\1|')
        pj=$(ls "$QRUN"/.plugin_"${pslug}"_*.json 2>/dev/null | head -1)
        if [ -n "$pj" ] && [ -s "$pj" ] && command -v python3 >/dev/null 2>&1; then
          prel=$(echo "$f" | sed "s|.*/wp-content/plugins/${pslug}/||")
          pruefsumme=$(python3 - "$pj" "$prel" "$f" <<'PY' 2>/dev/null
import hashlib, json, sys
try:
    daten = json.load(open(sys.argv[1]))
except Exception:
    print("Satz unlesbar"); raise SystemExit
dateien = daten.get("files") or {}
rel = sys.argv[2]
if rel not in dateien:
    print("NICHT IM LIEFERUMFANG — Datei wurde hinzugefügt")
    raise SystemExit
erwartet = dateien[rel].get("md5")
if isinstance(erwartet, list):
    erwartet = erwartet[0] if erwartet else None
try:
    ist = hashlib.md5(open(sys.argv[3], "rb").read()).hexdigest()
except OSError:
    print("nicht lesbar"); raise SystemExit
print("stimmt" if ist == erwartet else "WEICHT AB — Datei wurde verändert")
PY
)
        else
          pruefsumme="kein Satz verfügbar (kommerziell, Eigenbau oder Version unbekannt)"
        fi
        ;;
    esac

    # 3. Zeitliche Einordnung — mit dem Bestand entstanden oder einzeln?
    crt=$(stat -c %w "$f" 2>/dev/null); [ -z "$crt" ] || [ "$crt" = "-" ] && crt="nicht verfügbar"
    nachbarn_crt=$(find "$(dirname "$f")" -maxdepth 1 -type f -printf '%p\n' 2>/dev/null \
      | head -40 | while read -r n; do stat -c %w "$n" 2>/dev/null | cut -c1-10; done \
      | sort | uniq -c | sort -rn | head -1)

    # 4. Nachbarschaft — wie stehen die Geschwister da?
    dir=$(dirname "$f")
    n_sauber=$(awk -F'\t' -v d="$dir/" '$1=="SAUBER" && index($3,d)==1 {n++} END{print n+0}' "$QRUN/urteile.tsv")
    n_gesamt=$(awk -F'\t' -v d="$dir/" 'index($3,d)==1 {n++} END{print n+0}' "$QRUN/urteile.tsv")

    # 5. Zugriffsspur — wurde die Datei je angefordert?
    if [ -s "$QRUN/.logs_text" ]; then
      treffer_log=$(grep -acF -- "$name" "$QRUN/.logs_text" 2>/dev/null || true)
      treffer_log=${treffer_log:-0}
      if [ "$treffer_log" -gt 0 ]; then
        logspur="$treffer_log Zugriff(e) in den vorhandenen Logs — ANSEHEN"
      else
        logspur="kein Zugriff in den vorhandenen Logs (Aufbewahrung beachten)"
      fi
    else
      logspur="keine Logs vorhanden"
    fi

    # 6. Vorschlag — ausdrücklich nur ein Vorschlag
    if echo "$pruefsumme" | grep -q "^stimmt"; then
      vorschlag="SAUBER (amtliche Prüfsumme)"
    elif echo "$pruefsumme" | grep -qE "NICHT IM LIEFERUMFANG|WEICHT AB"; then
      vorschlag="BEFALLEN prüfen — Datei passt nicht zum Lieferumfang"
    elif [ "$installationen" -ge 5 ]; then
      vorschlag="KEIN mit Grund: Fremdcode, auf $installationen Installationen identisch"
    else
      vorschlag="offen — bleibt TREFFER"
    fi

    printf '%s\t%s\t%s\t%s\t%s\n' "$f" "$grund" "$pruefsumme" "$installationen" "$vorschlag" >> "$QTSV"
    {
      echo "---------------------------------------------------------------"
      echo "$f"
      echo "  angeschlagen:  $grund"
      echo "  Prüfsumme:     $pruefsumme"
      echo "  Verbreitung:   identischer Inhalt auf $installationen weiteren Installation(en)"
      echo "  angelegt:      $crt"
      echo "  Nachbarschaft: $n_sauber von $n_gesamt Dateien im Verzeichnis amtlich bestätigt"
      echo "  Zugriffsspur:  $logspur"
      echo "  VORSCHLAG:     $vorschlag"
    } >> "$QOUT"
  done < "$QRUN/.treffer_pfade"

  rm -f "$QRUN/.verbreitung_tmp"
  {
    echo
    echo "==============================================================="
    echo " Zusammenfassung der Vorschläge"
    echo "==============================================================="
    cut -f5 "$QTSV" | sed 's/ —.*//; s/ (.*//' | sort | uniq -c | sort -rn
    echo
    echo "Kein Vorschlag ändert von sich aus ein Urteil. Wer entscheidet,"
    echo "trägt es in entscheidungen.tsv ein:"
    echo "  <Pfad>  <Urteil>  <Kennung>  <Datum>  <Begründung>"
  } >> "$QOUT"

  echo "[$(date +%H:%M:%S)] FERTIG."
  sed -n '1,12p' "$QOUT"
  echo "..."
  tail -12 "$QOUT"
  echo
  echo "Entscheidungsvorlage: $QOUT"
  exit 0
fi

if [ "${1:-}" = "--online" ]; then BAUMSCAN_ONLINE=1; shift; fi
SCOPE="${1:?Scope-Pfad nötig (z. B. /var/www/vhosts/beispiel.de)}"
PREV="${2:-}"

BASE="${BAUMSCAN_BASE:-/root/wartungsscripte/baumscan}"
TS="$(date +%Y%m%d_%H%M%S)"
SLUG="$(basename "$SCOPE")"
RUN="$BASE/${TS}_${SLUG}"

# Vom Scan ausgenommen (Backups blähen den Lauf auf, ohne Erkenntnis zu bringen)
EXCL="${BAUMSCAN_EXCL:-$SCOPE/wordpress-backups}"

# Bekannte Fehlalarme: SHA256 je Zeile, Rest der Zeile ist Kommentar.
FP_LIST="${BAUMSCAN_FP_LIST:-$BASE/fp-hashes.txt}"

MAX_PHP_SIZE=3145728      # 3 MB — größere PHP-Dateien sind praktisch nie Shells
MAX_MEDIA_SIZE=20971520   # 20 MB — Obergrenze für den Inhaltsscan von Medien
CLUSTER_MIN=500           # ab so vielen Dateien mit identischer mtime: Verdacht
TIMESTOMP_GAP=2592000     # 30 Tage: mtime so viel älter als ctime = verdächtig
IMUNIFY_TIMEOUT=${BAUMSCAN_IMUNIFY_TIMEOUT:-900}  # Wartezeit auf den eigenen Signaturlauf
NICE="ionice -c3 nice -n19"
command -v ionice >/dev/null 2>&1 || NICE="nice -n19"

mkdir -p "$RUN" && chmod 700 "$RUN"
echo "$RUN" > "$BASE/CURRENT"

log() { echo "[$(date +%H:%M:%S)] $*"; }

# Ein Fund: Kategorie, Punkte, Pfad  ->  wird in Schicht 7 aggregiert
RAW="$RUN/findings_raw.tsv"
: > "$RAW"
fund() { printf '%s\t%s\t%s\n' "$1" "$2" "$3" >> "$RAW"; }

# -----------------------------------------------------------------------------
# 0  Manifest
# -----------------------------------------------------------------------------
{
  echo "NT-Baumscan $(date -Is)"
  echo "Scope:    $SCOPE"
  echo "Excl:     $EXCL"
  echo "Host:     $(hostname)"
  echo "imunify:  $(imunify-antivirus version 2>/dev/null || echo 'nicht vorhanden')"
  echo "FP-Liste: $([ -f "$FP_LIST" ] && wc -l < "$FP_LIST" || echo 0) Einträge"
} > "$RUN/00_manifest.txt"

# -----------------------------------------------------------------------------
# 1  Inventur — Größe, mtime, ctime, Owner, Mode, Pfad
# -----------------------------------------------------------------------------
log "Inventur..."
INV="$RUN/01_inventur.tsv"
$NICE find "$SCOPE" -path "$EXCL" -prune -o -type f \
  -printf '%s\t%T@\t%C@\t%u\t%m\t%p\n' > "$INV" 2>/dev/null
log "  $(wc -l < "$INV") Dateien"

# PHP-Kandidaten (Endung ODER später per Inhalt gefunden)
awk -F'\t' -v max="$MAX_PHP_SIZE" \
  '$1+0<max && tolower($6) ~ /\.(php|php[0-9]|phtml|phps|inc|module|install)$/ {print $6}' \
  "$INV" > "$RUN/01d_php_kandidaten.txt"

# PHP in Upload-/Cache-Verzeichnissen (dort gehört fast nie PHP hin)
awk -F'\t' '$6 ~ /\/(uploads|files|media|cache|tmp|assets)\/.*\.(php|php[0-9]|phtml)$/ {print $6}' "$INV" \
  | grep -vE '/(index|charmap)\.php$' > "$RUN/01b_php_in_uploads.txt"

while read -r f; do
  [ -n "$f" ] && fund "PHP_IN_UPLOADS" 20 "$f"
done < "$RUN/01b_php_in_uploads.txt"

# -----------------------------------------------------------------------------
# 2  Magic-Byte — .php-Datei, die als Bild getarnt ist
# -----------------------------------------------------------------------------
log "Magic-Byte (PHP mit Bild-Header)..."
magic_one() {
  m=$(head -c8 "$1" 2>/dev/null | tr -d '\0')
  case "$m" in
    GIF8*|*PNG*|$'\xff\xd8'*|BM*|RIFF*) echo "$1" ;;
  esac
}
export -f magic_one
tr '\n' '\0' < "$RUN/01d_php_kandidaten.txt" \
  | $NICE xargs -0 -r -P4 -n50 bash -c 'for f; do magic_one "$f"; done' _ \
  > "$RUN/02_magic_php_als_bild.txt" 2>/dev/null

while read -r f; do
  [ -n "$f" ] && fund "MAGIC_PHP_ALS_BILD" 60 "$f"
done < "$RUN/02_magic_php_als_bild.txt"

# -----------------------------------------------------------------------------
# 2b  PHP-in-Medien — der umgekehrte Fall: echtes Bild, PHP im Inhalt   [NEU]
# -----------------------------------------------------------------------------
# Genau so kam ein realer Dropper herein: gültiges PNG, PHP im tEXt-Chunk. Jeder Betrachter
# zeigt das Bild, jeder Endungs-Filter winkt es durch.
log "PHP-Marker in Medien-/Asset-Dateien..."
# Nur der vollständige Öffner <?php. Kurzformen wie <?= sind zwei bis drei
# Bytes und treten in JPEG-/PNG-Binärdaten rein zufällig auf — ein Lauf mit
# ihnen erzeugte 5.323 Fehlalarme auf einem einzigen Webspace.
PHP_MARK='<\?php'

awk -F'\t' -v max="$MAX_MEDIA_SIZE" \
  '$1+0<max && tolower($6) ~ /\.(png|jpe?g|gif|webp|bmp|ico|svg|tiff?|woff2?|ttf|otf|eot|mp[34]|wav|avi|mov|pdf|dat|bin)$/ {print $6}' \
  "$INV" > "$RUN/02b_medien_kandidaten.txt"

tr '\n' '\0' < "$RUN/02b_medien_kandidaten.txt" \
  | $NICE xargs -0 -r -P4 -n200 grep -laP "$PHP_MARK" 2>/dev/null \
  > "$RUN/02b_php_in_medien.txt"

while read -r f; do
  [ -n "$f" ] && fund "PHP_IN_MEDIENDATEI" 55 "$f"
done < "$RUN/02b_php_in_medien.txt"

# Text-Assets separat und schwächer gewichtet — dort kommt <?php auch legitim vor
awk -F'\t' -v max="$MAX_MEDIA_SIZE" \
  '$1+0<max && tolower($6) ~ /\.(css|js|json|xml|txt|md|log|po|mo|sql|htaccess)$/ {print $6}' \
  "$INV" > "$RUN/02b_text_kandidaten.txt"

tr '\n' '\0' < "$RUN/02b_text_kandidaten.txt" \
  | $NICE xargs -0 -r -P4 -n200 grep -laP '<\?php[\s(]' 2>/dev/null \
  > "$RUN/02b_php_in_textassets.txt"

while read -r f; do
  [ -n "$f" ] && fund "PHP_IN_TEXTASSET" 20 "$f"
done < "$RUN/02b_php_in_textassets.txt"

# Medien-Dateien ohne Endung sind ebenfalls einen Blick wert
awk -F'\t' -v max="$MAX_MEDIA_SIZE" \
  '$1+0<max && $6 !~ /\/[^\/]*\.[A-Za-z0-9]+$/ {print $6}' "$INV" \
  > "$RUN/02b_ohne_endung.txt"
tr '\n' '\0' < "$RUN/02b_ohne_endung.txt" \
  | $NICE xargs -0 -r -P4 -n200 grep -laP "$PHP_MARK" 2>/dev/null \
  >> "$RUN/02b_php_in_medien.txt"

# -----------------------------------------------------------------------------
# 3  Heuristik — gestaffelte Muster                                    [NEU]
# -----------------------------------------------------------------------------
# HIGH: Konstrukte, die in gepflegtem Anwendungscode praktisch nicht vorkommen.
# Wichtig: kein Adjazenz-Zwang. `eval($decode($x))` über eine Variablenfunktion
# umgeht jedes Muster, das eval direkt neben base64_decode erwartet.
log "Heuristik HIGH..."
PR_HIGH='eval\s*\(\s*\$'                                             # eval auf Variable/Variablenfunktion
PR_HIGH+='|eval\s*\(\s*(base64_decode|gzinflate|gzuncompress|str_rot13|strrev|gzdecode|convert_uudecode)'
PR_HIGH+='|assert\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER)'
PR_HIGH+='|preg_replace\s*\(\s*(["\x27])[^"\x27]*/[a-zA-Z]*e[a-zA-Z]*\1'   # /e-Modifikator
PR_HIGH+='|create_function\s*\('
PR_HIGH+='|\$\{\s*\$[a-zA-Z0-9_]+(\s*\.\s*\$[a-zA-Z0-9_]+)+\s*\}'    # Variablen-Variable aus Fragmenten
PR_HIGH+='|\$_(GET|POST|REQUEST|COOKIE|SERVER)\s*\[[^]]*\]\s*\('     # Aufruf direkt aus Superglobal
PR_HIGH+='|(system|passthru|shell_exec|popen|proc_open|pcntl_exec)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)'
PR_HIGH+='|\bFilesMan\b|c99sh|r57shell|b374k|IndoXploit|WSO\s*[0-9]|AlfaTeam|priv8|N4ST4R|Cyber\s*Sec'
# Gepackte Shells (Encoder-Bauart). Ein Prüfsatzlauf zeigte, dass ein 45-KB-
# Webshell durch alle bisherigen Muster fiel: er ruft eval nicht auf einer
# Variablen auf, sondern auf einer Verkettung — eval("?>".$fn(...)) — und
# schreibt den Funktionsnamen als Escape-Folge, sodass "base64_decode" nirgends
# im Klartext steht. Superglobals fehlen, die längste Zeile hat 97 Zeichen.
PR_HIGH+='|eval\s*\(\s*["\x27]\s*\?>'                                # eval, das PHP-Modus neu öffnet
PR_HIGH+='|(\\\\x[0-9a-fA-F]{2}|\\\\[0-7]{3}){8,}'                   # als Escape-Folge getarnter Bezeichner
PR_HIGH+='|PHP[[:space:]]*Encoder|miladworkshop|Encoding[[:space:]]+by'

tr '\n' '\0' < "$RUN/01d_php_kandidaten.txt" \
  | $NICE xargs -0 -r -P4 -n200 grep -lPi "$PR_HIGH" 2>/dev/null \
  > "$RUN/03_heuristik_high.txt"

while read -r f; do
  [ -n "$f" ] && fund "HEURISTIK_HIGH" 40 "$f"
done < "$RUN/03_heuristik_high.txt"

# Packer getrennt erfassen — nicht wegen der Punkte, sondern wegen des Urteils.
# HEURISTIK_HIGH allein ist NICHT beweiskräftig: eval("?> …) trifft auch Twig,
# create_function() steht in phpseclib und in altem Theme-Code. Diese Treffer
# gehören gesichtet.
# Ausschliesslich der Banner eines Obfuskators. Nichts sonst.
#
# Der erste Entwurf nahm auch lange Escape-Folgen auf ("acht oder mehr \xNN am
# Stück, das schreibt niemand freiwillig"). Der Lauf gegen einen bereinigten
# Baum widerlegte das sofort: 12 Dateien wurden BEFALLEN gemeldet, darunter
# phpseclib RSA.php und Blowfish.php sowie HTMLPurifier. Krypto-Bibliotheken
# bestehen aus genau solchen Folgen — S-Boxen, OID-Bytes, Testvektoren:
#     \x2a\x86\x48\x86\xf7\x0d\x01\x05\x03
# 59 dieser Dateien trugen zugleich eine gültige amtliche Prüfsumme. Der
# Widerspruchszähler hat die Regel überführt, bevor sie in einen Kundenbericht
# geraten konnte. Die Escape-Folge steht deshalb weiter in PR_HIGH und führt
# zu TREFFER — dort gehört sie hin.
#
# Der Banner dagegen trennt scharf: serverweit über 74 Installationen tragen
# Nur SELBSTBESCHREIBUNGEN einer kodierten Datei, keine blossen Nennungen.
#
# Der bare Produktname taugt nicht: "ionCube" steht in Composers
# DiagnoseCommand, weil der den Loader prüft, und in easy-wp-smtp. "obfuscated
# by" steht in siebzehn Kopien von broken-link-checker. Beides sind Erwähnungen,
# keine kodierten Dateien. Gesucht ist die Zeile, mit der ein Obfuskator seine
# eigene Ausgabe stempelt.
PR_PACKER='miladworkshop|PHP Encoding by|PHP Encoder Version|Encoded by (ionCube|Zend Guard|SourceGuardian)'
tr '\n' '\0' < "$RUN/01d_php_kandidaten.txt" \
  | $NICE xargs -0 -r -P4 -n200 grep -lPi "$PR_PACKER" 2>/dev/null \
  > "$RUN/03d_packer.txt"

while read -r f; do
  [ -n "$f" ] && fund "PACKER_SIGNATUR" 60 "$f"
done < "$RUN/03d_packer.txt"

# MED: einzeln unauffällig, in Summe aussagekräftig. Eine reale Filemanager-Shell nutzte
# shell_exec ohne jede Verschleierung — das fehlte im Muster komplett.
log "Heuristik MED..."
PR_MED='\b(shell_exec|passthru|popen|proc_open|pcntl_exec|system|exec)\s*\('
PR_MED+='|base64_decode|gzinflate|gzuncompress|str_rot13'
PR_MED+='|\bgoto\s+[A-Za-z0-9_]{3,}\s*;'                             # goto-Obfuskierung
PR_MED+='|chr\s*\(\s*[0-9]+\s*\)\s*\.\s*chr\s*\('                    # chr-Ketten
PR_MED+='|(move_uploaded_file|file_put_contents)\s*\(\s*\$_'
PR_MED+='|(md5|password_verify|hash)\s*\(\s*\$_POST'                 # Login-Gate einer Shell
PR_MED+='|HTTP_USER_AGENT.*\b(Googlebot|bingbot|crawler|curl)\b'     # Bot-Ausblendung

tr '\n' '\0' < "$RUN/01d_php_kandidaten.txt" \
  | $NICE xargs -0 -r -P4 -n200 grep -lPi "$PR_MED" 2>/dev/null \
  > "$RUN/03_heuristik_med.txt"

while read -r f; do
  [ -n "$f" ] && fund "HEURISTIK_MED" 15 "$f"
done < "$RUN/03_heuristik_med.txt"

# Sehr lange Zeilen: typisch für minifizierten/obfuskierten Shell-Code
log "Zeilenlängen..."
tr '\n' '\0' < "$RUN/01d_php_kandidaten.txt" \
  | $NICE xargs -0 -r -P4 -n100 awk 'length($0)>2000 {print FILENAME; nextfile}' 2>/dev/null \
  | sort -u > "$RUN/03b_lange_zeilen.txt"

while read -r f; do
  [ -n "$f" ] && fund "SEHR_LANGE_ZEILE" 10 "$f"
done < "$RUN/03b_lange_zeilen.txt"

# Base64-Blöcke über mehrere Zeilen. Packer brechen ihre Nutzlast um, damit
# keine einzelne Zeile auffällt — die Zeilenlängenprüfung läuft dann ins Leere.
# Fünf aufeinanderfolgende Zeilen aus reinem Base64-Alphabet sind in
# Anwendungscode praktisch ausgeschlossen.
log "Base64-Blöcke..."
tr '\n' '\0' < "$RUN/01d_php_kandidaten.txt" \
  | $NICE xargs -0 -r -P4 -n100 awk '
      FNR==1 { lauf=0; zert=0 }
      # Zertifikate und Schluessel sind ebenfalls lange Base64-Bloecke. Ihre
      # DER-Kodierung beginnt mit MII — Wordfence etwa legt seine
      # Root-Zertifikate so ab. Ab dieser Kopfzeile wird der GESAMTE folgende
      # Block uebersprungen; nur die Kopfzeile auszunehmen genuegt nicht, weil
      # die Folgezeilen beliebiges Base64 sind und weiter ausloesen wuerden.
      /^MI[A-Za-z0-9+\/=]{58,}$/ { zert=1; lauf=0; next }
      /^[A-Za-z0-9+\/=]{60,}$/ {
        if (zert) next
        lauf++; if (lauf>=5) { print FILENAME; lauf=-9999; nextfile }
        next
      }
      { lauf=0; zert=0 }' 2>/dev/null \
  | sort -u > "$RUN/03c_base64_bloecke.txt"

while read -r f; do
  [ -n "$f" ] && fund "BASE64_BLOCK" 35 "$f"
done < "$RUN/03c_base64_bloecke.txt"

# -----------------------------------------------------------------------------
# 4  Timestomping                                                      [NEU]
# -----------------------------------------------------------------------------
# Angreifer datieren mtime zurück, damit neue Dateien alt aussehen. Die ctime
# lässt sich per touch nicht setzen — die Lücke zwischen beiden verrät es.
#
# ACHTUNG, hart erkauft: mtime ≪ ctime ist als EIGENSTÄNDIGER Fund wertlos.
# Jedes rekursive chown, jede Rücksicherung und jede Rechtekorrektur setzt die
# ctime des gesamten Baums neu, während die mtime alt bleibt. Ein Testlauf
# meldete so 62.373 Dateien. Der Wert entsteht erst als MODIFIKATOR: er hebt
# eine Datei, die aus anderem Grund auffällt. Deshalb wird hier nur die Liste
# erzeugt; die Punktevergabe erfolgt in Schicht 7 gegen die Primärfunde.
log "Timestomping..."
awk -F'\t' -v gap="$TIMESTOMP_GAP" '
  $3+0 - $2+0 > gap && tolower($6) ~ /\.(php|php[0-9]|phtml|inc|png|jpe?g|gif|ico|svg)$/ {
    printf "%s\t%s\t%s\t%s\n", strftime("%Y-%m-%d %H:%M:%S",$2), strftime("%Y-%m-%d %H:%M:%S",$3),
           int(($3-$2)/86400), $6
  }' "$INV" | sort -k4 > "$RUN/04_timestomping.txt"
awk -F'\t' '{print $4}' "$RUN/04_timestomping.txt" | sort -u > "$RUN/.timestomp_pfade"

# Massen-touch: viele Dateien mit exakt identischer mtime über mehrere
# Verzeichnisse. In einem realen Fall waren es 59.472 Dateien in einer einzigen Sekunde.
awk -F'\t' '{print int($2)}' "$INV" | sort | uniq -c | sort -rn \
  | awk -v min="$CLUSTER_MIN" '$1>=min {print $1"\t"strftime("%Y-%m-%d %H:%M:%S",$2)"\t"$2}' \
  > "$RUN/04b_mtime_cluster.txt"

# -----------------------------------------------------------------------------
# 5  .htaccess-Anomalien                                               [NEU]
# -----------------------------------------------------------------------------
# In einem realen Fall lag neben jeder Shell eine .htaccess, die genau
# diese eine Datei freigab — ein sehr verlässlicher Marker.
log ".htaccess-Anomalien..."
: > "$RUN/05_htaccess_anomalien.txt"
awk -F'\t' '$6 ~ /\/\.htaccess$/ {print $6}' "$INV" | while read -r h; do
  [ -f "$h" ] || continue
  if grep -qPzi '(?s)<FilesMatch[^>]*\.php[^>]*>.*?Allow\s+from\s+all' "$h" 2>/dev/null; then
    echo -e "FREIGABE_EINZELDATEI\t$h" >> "$RUN/05_htaccess_anomalien.txt"
    fund "HTACCESS_SHELL_FREIGABE" 50 "$h"
  fi
  if echo "$h" | grep -qE '/(uploads|files|media|cache)/' \
     && grep -qPi '(AddType\s+application/x-httpd-php|php_flag\s+engine\s+on|SetHandler\s+.*php)' "$h" 2>/dev/null; then
    echo -e "PHP_FREIGABE_IN_UPLOADS\t$h" >> "$RUN/05_htaccess_anomalien.txt"
    fund "HTACCESS_PHP_IN_UPLOADS" 50 "$h"
  fi
done

# -----------------------------------------------------------------------------
# 6  ImunifyAV — eigenen Lauf einreihen und dessen Ergebnis abholen
# -----------------------------------------------------------------------------
# Frühere Fassung stiess den Scan an und las danach `malware malicious list` —
# also die HISTORIE aller je gefundenen Dateien, nicht das Ergebnis des eigenen
# Laufs. Zwei Fehler in einem: das Ergebnis kam zu früh (der Scan lief noch),
# und es enthielt längst entfernte Dateien. Auf einem bereinigten Webspace
# standen dadurch vier Geisterdateien auf den Plätzen 1 bis 4 der Rangliste.
#
# Richtig ist: Lauf einreihen, auf seinen Abschluss warten, Funde über
# --by-scan-id abholen. Nur diese Funde stammen aus diesem Scan.
: > "$RUN/06_imunify_bestand.txt"
: > "$RUN/06_imunify_bereits_entfernt.txt"

if ! command -v imunify-antivirus >/dev/null 2>&1; then
  log "ImunifyAV nicht vorhanden — Schicht übersprungen"
elif ! command -v python3 >/dev/null 2>&1; then
  log "python3 fehlt — ImunifyAV-Schicht übersprungen (JSON nicht auswertbar)"
else
  START_TS=$(date +%s)
  log "ImunifyAV: Lauf einreihen..."
  imunify-antivirus malware on-demand queue put "$SCOPE" \
    --ignore-mask "$EXCL/*" --intensity low --json > "$RUN/06_scan_start.json" 2>&1

  # Auf den eigenen Lauf warten. Erkennungsmerkmal: gleicher Pfad, nicht vor
  # dem eigenen Startzeitpunkt begonnen, abgeschlossen.
  SCANID=""
  WARTE=0
  while [ "$WARTE" -lt "$IMUNIFY_TIMEOUT" ]; do
    SCANID=$(imunify-antivirus malware on-demand list --json 2>/dev/null | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(0)
pfad, ab = sys.argv[1], int(sys.argv[2])
treffer = [
    i for i in d.get("items", [])
    if i.get("path") == pfad
    and (i.get("created") or 0) >= ab - 5
    and i.get("completed")
]
if treffer:
    print(sorted(treffer, key=lambda i: i["created"])[-1]["scanid"])
' "$SCOPE" "$START_TS" 2>/dev/null)
    [ -n "$SCANID" ] && break
    sleep 10
    WARTE=$((WARTE + 10))
  done

  if [ -z "$SCANID" ]; then
    log "  ImunifyAV: kein Ergebnis binnen ${IMUNIFY_TIMEOUT}s — Schicht unvollständig"
    echo "ZEITUEBERSCHREITUNG nach ${IMUNIFY_TIMEOUT}s" > "$RUN/06_imunify_status.txt"
  else
    log "  ImunifyAV: Lauf $SCANID nach ${WARTE}s abgeschlossen"
    echo "scanid=$SCANID dauer=${WARTE}s" > "$RUN/06_imunify_status.txt"
    imunify-antivirus malware malicious list --by-scan-id "$SCANID" \
      --by-status found --limit 1000 --json 2>/dev/null \
      | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(0)
for i in d.get("items", []):
    f = i.get("file") or i.get("path")
    if f:
        print(f)
' 2>/dev/null | sort -u > "$RUN/06_imunify_funde.txt"

    while read -r f; do
      [ -n "$f" ] || continue
      # Existenzprüfung bleibt: zwischen Scan und Auswertung kann bereinigt
      # worden sein, und ImunifyAV meldet auch Pfade in Quarantäne.
      if [ -e "$f" ]; then
        echo "$f" >> "$RUN/06_imunify_bestand.txt"
        fund "IMUNIFY_SIGNATUR" 70 "$f"
      else
        echo "$f" >> "$RUN/06_imunify_bereits_entfernt.txt"
      fi
    done < "$RUN/06_imunify_funde.txt"
    log "  ImunifyAV: $(wc -l < "$RUN/06_imunify_bestand.txt") aktive Funde"
  fi
fi

# -----------------------------------------------------------------------------
# 7  Bewertung und Rangfolge                                           [NEU]
# -----------------------------------------------------------------------------
# Ohne Rangfolge ertrinkt der echte Fund in Cache-Rauschen: Ein echter Fund stand beim
# Ersteinsatz auf Platz 126 einer alphabetischen Liste und wurde übersehen.
log "Bewertung..."

# Bekannte Fehlalarme herausnehmen (SHA256-Allowlist)
if [ -s "$FP_LIST" ]; then
  awk '{print $1}' "$FP_LIST" | grep -E '^[0-9a-f]{64}$' | sort -u > "$RUN/.fp_hashes"
  awk -F'\t' '{print $3}' "$RAW" | sort -u | while read -r f; do
    [ -f "$f" ] || continue
    h=$(sha256sum "$f" 2>/dev/null | cut -d' ' -f1)
    grep -qx "$h" "$RUN/.fp_hashes" 2>/dev/null && echo "$f"
  done > "$RUN/07_fehlalarme_gefiltert.txt"
  if [ -s "$RUN/07_fehlalarme_gefiltert.txt" ]; then
    grep -vFf "$RUN/07_fehlalarme_gefiltert.txt" "$RAW" > "$RAW.tmp" && mv "$RAW.tmp" "$RAW"
  fi
else
  : > "$RUN/07_fehlalarme_gefiltert.txt"
fi

# Doppelte Meldungen derselben Kategorie für dieselbe Datei zählen einmal.
sort -u "$RAW" -o "$RAW"

# Timestomping als Modifikator: +25 nur für Dateien, die ohnehin auffallen.
if [ -s "$RUN/.timestomp_pfade" ]; then
  awk -F'\t' 'NR==FNR {prim[$3]=1; next} ($0 in prim) {print "TIMESTOMP_VERDACHT\t25\t"$0}' \
    "$RAW" "$RUN/.timestomp_pfade" >> "$RAW"
fi

# Mitglied eines Massen-touch-Clusters: +10, ebenfalls nur als Modifikator.
if [ -s "$RUN/04b_mtime_cluster.txt" ]; then
  cut -f3 "$RUN/04b_mtime_cluster.txt" | sort -u > "$RUN/.cluster_zeiten"
  awk -F'\t' 'NR==FNR {z[$1]=1; next} (int($2) in z) {print $6}' \
    "$RUN/.cluster_zeiten" "$INV" | sort -u > "$RUN/.cluster_pfade"
  awk -F'\t' 'NR==FNR {prim[$3]=1; next} ($0 in prim) {print "MTIME_CLUSTER\t10\t"$0}' \
    "$RAW" "$RUN/.cluster_pfade" >> "$RAW"
fi

sort -u "$RAW" -o "$RAW"
sort -t"$(printf '\t')" -k3,3 "$RAW" | awk -F'\t' '
  { score[$3]+=$2; cats[$3] = ($3 in cats ? cats[$3]"," $1 : $1) }
  END { for (p in score) printf "%d\t%s\t%s\n", score[p], cats[p], p }
' | sort -rn > "$RUN/findings.tsv"

stufe() {
  if   [ "$1" -ge 70 ]; then echo "KRITISCH"
  elif [ "$1" -ge 40 ]; then echo "HOCH"
  elif [ "$1" -ge 20 ]; then echo "PRUEFEN"
  else                       echo "HINWEIS"; fi
}

# -----------------------------------------------------------------------------
# 7b  Urteil je Datei — für JEDE Datei im Baum                          [NEU]
# -----------------------------------------------------------------------------
# Bisher bekamen nur Dateien MIT Fund eine Aussage. Bei einem realen Lauf waren
# das 870 von 101.735 — für 100.865 Dateien stand nichts da, und im Bericht
# las sich das wie Entwarnung. Das ist die gefährlichste Sorte Bericht.
#
# Vier Urteile, und nur eines davon ist eine Unbedenklichkeitsaussage:
#
#   SAUBER    Amtliche Prüfsumme stimmt. Das ist die EINZIGE Quelle für dieses
#             Urteil. Keine Heuristik, keine Verbreitung, kein Bauchgefühl.
#   KEIN      Nichts angeschlagen — und keine Referenz vorhanden, um es zu
#             bestätigen. Der ehrliche Normalfall für Uploads, eigene Themes,
#             Konfigurationen, kommerzielle Erweiterungen.
#   TREFFER   Etwas hat angeschlagen, mit Auslegungsspielraum. Gehört gesichtet.
#   BEFALLEN  Beweis, der nicht vernünftig bestreitbar ist.
#
# Rangfolge: BEFALLEN > SAUBER > TREFFER > KEIN. Ein Widerspruch (amtliche
# Prüfsumme stimmt UND Signaturtreffer) wird gesondert ausgewiesen statt
# stillschweigend aufgelöst — er bedeutet entweder Fehlalarm des Scanners oder
# einen Angriff auf die Lieferkette. Beides gehört vor Augen.
log "Urteile je Datei..."

URTEILE="$RUN/urteile.tsv"
: > "$URTEILE"
: > "$RUN/.sauber_pfade"
: > "$RUN/09_pruefsummen_quellen.txt"

# ── Amtliche Prüfsummen ────────────────────────────────────────────────────
# Ohne Netz gibt es kein SAUBER. Das ist kein Mangel des Werkzeugs, sondern die
# Wahrheit: ohne Referenz lässt sich Unbedenklichkeit nicht behaupten.
if [ "${BAUMSCAN_ONLINE:-0}" = "1" ] && command -v curl >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1; then
  # WordPress-Kern
  while read -r vfile; do
    [ -n "$vfile" ] || continue
    wproot=$(dirname "$(dirname "$vfile")")
    wpver=$(sed -n "s/^\$wp_version = '\([^']*\)'.*/\1/p" "$vfile" 2>/dev/null | head -1)
    [ -n "$wpver" ] || continue
    kern_json="$RUN/.kern_${wpver}.json"
    if [ ! -s "$kern_json" ]; then
      curl -fsSL --max-time 30 \
        "${BAUMSCAN_KERN_BASIS:-https://api.wordpress.org/core/checksums/1.0/}?version=${wpver}&locale=en_US" \
        -o "$kern_json" 2>/dev/null || true
    fi
    [ -s "$kern_json" ] || continue
    echo "WP-Kern $wpver -> $wproot" >> "$RUN/09_pruefsummen_quellen.txt"
    python3 - "$kern_json" "$wproot" <<'PY' >> "$RUN/.sauber_pfade" 2>/dev/null
import hashlib, json, os, sys
try:
    daten = json.load(open(sys.argv[1]))
except Exception:
    sys.exit(0)
wurzel = sys.argv[2]
for rel, md5 in (daten.get("checksums") or {}).items():
    pfad = os.path.join(wurzel, rel)
    try:
        with open(pfad, "rb") as fh:
            if hashlib.md5(fh.read()).hexdigest() == md5:
                print(pfad)
    except OSError:
        pass
PY
  done < <(find "$SCOPE" -path "$EXCL" -prune -o -type f -name version.php -path "*/wp-includes/*" -print 2>/dev/null)

  # Plugins aus dem wordpress.org-Verzeichnis
  while read -r pdir; do
    [ -d "$pdir" ] || continue
    slug=$(basename "$pdir")
    # Version NUR aus der Hauptdatei des Plugins lesen — der einzigen mit
    # "Plugin Name:" im Kopf. Der erste Entwurf nahm die erste "Version:"-Zeile
    # aus IRGENDEINER php-Datei des Verzeichnisses und erwischte damit die
    # Kopfzeile einer mitgelieferten Bibliothek. Folge: falsche Version,
    # Prüfsummensatz nicht gefunden, 80 Treffer in einem Plugin, das sehr wohl
    # einen Satz hat.
    phaupt=$(grep -rlE "^[[:space:]]*\*?[[:space:]]*Plugin Name:" "$pdir" --include="*.php" \
             --exclude-dir=vendor --exclude-dir=lib --exclude-dir=libraries 2>/dev/null \
             | awk '{print length"\t"$0}' | sort -n | head -1 | cut -f2)
    [ -n "$phaupt" ] || phaupt="$pdir/$slug.php"
    pver=$(grep -m1 -iE "^[[:space:]]*\*?[[:space:]]*Version:[[:space:]]*[0-9]" "$phaupt" 2>/dev/null \
           | sed 's/.*[Vv]ersion:[[:space:]]*//' | tr -d '\r' | awk '{print $1}')
    [ -n "$pver" ] || continue
    pj="$RUN/.plugin_${slug}_${pver}.json"
    if [ ! -s "$pj" ]; then
      # Quelle umlenkbar — der Pruefstand zeigt sie auf eine lokale Datei
      # (curl kann file://). Ohne das haenge jeder Test am Netz und an der
      # Frage, ob wordpress.org gerade eine bestimmte Fassung noch fuehrt.
      curl -fsSL --max-time 20 \
        "${BAUMSCAN_PRUEFSUMMEN_BASIS:-https://downloads.wordpress.org/plugin-checksums}/${slug}/${pver}.json" \
        -o "$pj" 2>/dev/null || true
    fi
    [ -s "$pj" ] || continue
    echo "Plugin $slug $pver" >> "$RUN/09_pruefsummen_quellen.txt"
    python3 - "$pj" "$pdir" <<'PY' >> "$RUN/.sauber_pfade" 2>/dev/null
import hashlib, json, os, sys
try:
    daten = json.load(open(sys.argv[1]))
except Exception:
    sys.exit(0)
wurzel = sys.argv[2]
for rel, eintrag in (daten.get("files") or {}).items():
    erwartet = eintrag.get("md5")
    if isinstance(erwartet, list):
        erwartet = erwartet[0] if erwartet else None
    if not erwartet:
        continue
    pfad = os.path.join(wurzel, rel)
    try:
        with open(pfad, "rb") as fh:
            if hashlib.md5(fh.read()).hexdigest() == erwartet:
                print(pfad)
    except OSError:
        pass
PY
  done < <(find "$SCOPE" -path "$EXCL" -prune -o -type d -path "*/wp-content/plugins/*" -maxdepth 6 -print 2>/dev/null \
           | awk -F'/wp-content/plugins/' 'NF>1 {split($2,t,"/"); print $1"/wp-content/plugins/"t[1]}' | sort -u)
  sort -u "$RUN/.sauber_pfade" -o "$RUN/.sauber_pfade"
  log "  amtlich bestätigt: $(wc -l < "$RUN/.sauber_pfade") Dateien aus $(wc -l < "$RUN/09_pruefsummen_quellen.txt") Quelle(n)"
else
  log "  ohne Netz oder ohne python3/curl — kein SAUBER möglich, alles unbestätigt"
fi

# ── Kategorien den Urteilen zuordnen ───────────────────────────────────────
# BEFALLEN nur für Belege ohne vernünftigen Auslegungsspielraum.
BEFALLEN_KAT='IMUNIFY_SIGNATUR|PHP_IN_MEDIENDATEI|MAGIC_PHP_ALS_BILD|HTACCESS_SHELL_FREIGABE|HTACCESS_PHP_IN_UPLOADS|PACKER_SIGNATUR'

awk -F'\t' -v befmuster="$BEFALLEN_KAT" '
  # 1. Durchgang: amtlich bestätigte Pfade
  FILENAME ~ /\.sauber_pfade$/ { sauber[$0] = 1; next }
  # 2. Durchgang: bewertete Funde (score, kategorien, pfad)
  FILENAME ~ /findings\.tsv$/  { kat[$3] = $2; next }
  # 3. Durchgang: die Inventur — sie bestimmt, WELCHE Dateien beurteilt werden
  {
    pfad = $6
    k = (pfad in kat) ? kat[pfad] : ""
    istbef = (k != "" && k ~ befmuster)
    istsauber = (pfad in sauber)
    if (istbef && istsauber) {
      printf "WIDERSPRUCH\tamtliche Prüfsumme stimmt UND %s\t%s\n", k, pfad
    } else if (istbef) {
      printf "BEFALLEN\t%s\t%s\n", k, pfad
    } else if (istsauber) {
      printf "SAUBER\tamtliche Prüfsumme stimmt\t%s\n", pfad
    } else if (k != "") {
      printf "TREFFER\t%s\t%s\n", k, pfad
    } else {
      printf "KEIN\tkeine Referenz vorhanden, nichts angeschlagen\t%s\n", pfad
    }
  }
' "$RUN/.sauber_pfade" "$RUN/findings.tsv" "$INV" > "$URTEILE"

U_BEFALLEN=$(grep -c "^BEFALLEN" "$URTEILE" 2>/dev/null || true); U_BEFALLEN=${U_BEFALLEN:-0}
U_TREFFER=$(grep -c '^TREFFER'  "$URTEILE" 2>/dev/null || echo 0)
U_SAUBER=$(grep -c '^SAUBER'    "$URTEILE" 2>/dev/null || echo 0)
U_KEIN=$(grep -c '^KEIN'        "$URTEILE" 2>/dev/null || echo 0)
U_WIDER=$(grep -c "^WIDERSPRUCH" "$URTEILE" 2>/dev/null || true); U_WIDER=${U_WIDER:-0}

CRIT="$RUN/BEFUND.txt"
{
  echo "==============================================================="
  echo " NT-Baumscan — Befund"
  echo " Scope: $SCOPE"
  echo " Lauf:  $(date -Is)"
  echo "==============================================================="
  echo
  echo "---------------------------------------------------------------"
  echo " URTEIL JE DATEI — jede Datei im Baum, nicht nur die Treffer"
  echo "---------------------------------------------------------------"
  printf "  %-10s %8d   %s\n" "BEFALLEN" "$U_BEFALLEN" "Beweis, nicht vernünftig bestreitbar"
  printf "  %-10s %8d   %s\n" "TREFFER"  "$U_TREFFER"  "angeschlagen, gehört gesichtet"
  printf "  %-10s %8d   %s\n" "SAUBER"   "$U_SAUBER"   "amtliche Prüfsumme stimmt"
  printf "  %-10s %8d   %s\n" "KEIN"     "$U_KEIN"     "nichts gefunden — und nicht bestätigbar"
  [ "$U_WIDER" -gt 0 ] && printf "  %-10s %8d   %s\n" "WIDERSPRUCH" "$U_WIDER" "Prüfsumme stimmt UND Signaturtreffer — klären"
  echo
  echo "  KEIN ist keine Entwarnung. Es heisst: nichts angeschlagen, und es gibt"
  echo "  keine Referenz, an der sich Unbedenklichkeit belegen liesse."
  if [ "$U_SAUBER" -eq 0 ]; then
    echo "  SAUBER ist 0 — ohne --online gibt es keine amtlichen Prüfsummen."
  fi
  echo
  echo "Vollständige Liste: urteile.tsv (ein Urteil je Datei)"
  echo
  echo "Dateien gesamt:        $(wc -l < "$INV")"
  echo "PHP-Kandidaten:        $(wc -l < "$RUN/01d_php_kandidaten.txt")"
  echo "Bewertete Funde:       $(wc -l < "$RUN/findings.tsv")"
  echo "Als Fehlalarm gefiltert: $(wc -l < "$RUN/07_fehlalarme_gefiltert.txt")"
  echo
  echo "---------------------------------------------------------------"
  echo " RANGLISTE — höchster Verdacht zuerst"
  echo "---------------------------------------------------------------"
  printf "%-9s %-6s %-45s %s\n" "STUFE" "PKT" "KATEGORIEN" "PFAD"
  while IFS=$'\t' read -r score cats path; do
    printf "%-9s %-6s %-45s %s\n" "$(stufe "$score")" "$score" "${cats:0:45}" "$path"
  done < "$RUN/findings.tsv"

  echo
  echo "---------------------------------------------------------------"
  echo " ECHTE ANLEGEZEIT der Top-Funde (crtime schlägt gefälschte mtime)"
  echo "---------------------------------------------------------------"
  head -40 "$RUN/findings.tsv" | cut -f3 | while read -r f; do
    [ -e "$f" ] || continue
    b=$(stat -c '%w' "$f" 2>/dev/null); m=$(stat -c '%y' "$f" 2>/dev/null)
    printf "  angelegt %-32s mtime %-32s %s\n" "${b:0:19}" "${m:0:19}" "$f"
  done

  if [ -s "$RUN/04b_mtime_cluster.txt" ]; then
    echo
    echo "---------------------------------------------------------------"
    echo " MASSEN-ZEITSTEMPEL — Hinweis auf flächiges Timestomping"
    echo "---------------------------------------------------------------"
    echo " Viele Dateien mit exakt identischer mtime. Wenn deren crtime davon"
    echo " abweicht, wurden die Zeitstempel nachträglich gesetzt."
    awk -F'\t' '{printf "  %8d Dateien  mtime %s\n", $1, $2}' "$RUN/04b_mtime_cluster.txt"
  fi

  if [ -s "$RUN/05_htaccess_anomalien.txt" ]; then
    echo
    echo "---------------------------------------------------------------"
    echo " .htaccess-ANOMALIEN"
    echo "---------------------------------------------------------------"
    sed 's/^/  /' "$RUN/05_htaccess_anomalien.txt"
  fi

  echo
  echo "---------------------------------------------------------------"
  echo " ROHDATEN je Schicht"
  echo "---------------------------------------------------------------"
  for f in 01b_php_in_uploads 02_magic_php_als_bild 02b_php_in_medien \
           02b_php_in_textassets 03_heuristik_high 03_heuristik_med \
           03b_lange_zeilen 04_timestomping 06_imunify_bestand; do
    [ -f "$RUN/$f.txt" ] && printf "  %-28s %6d Zeilen\n" "$f.txt" "$(wc -l < "$RUN/$f.txt")"
  done
} > "$CRIT"

# -----------------------------------------------------------------------------
# 8  Diff gegen einen Vorlauf — nur NEUE Funde sind ein Alarm
# -----------------------------------------------------------------------------
if [ -n "$PREV" ] && [ -d "$PREV" ]; then
  NEU="$RUN/RESCAN_NEUE_FUNDE.txt"
  {
    echo "Neue bewertete Funde gegenüber $PREV:"
    comm -13 <(cut -f3 "$PREV/findings.tsv" 2>/dev/null | sort) \
             <(cut -f3 "$RUN/findings.tsv" | sort)
  } > "$NEU"
  if [ "$(grep -cv '^Neue bewertete' "$NEU")" -gt 0 ]; then
    cp "$NEU" "$RUN/RESCAN_ALARM"
    echo "!!! RESCAN-ALARM: neue verdächtige Dateien — siehe $NEU"
  fi
fi

sha256sum "$RUN"/*.txt "$RUN"/*.tsv 2>/dev/null > "$RUN/SHA256SUMS"
chmod -R go-rwx "$RUN"

log "FERTIG."
echo
sed -n '1,40p' "$CRIT"
echo
echo "Vollständiger Befund: $CRIT"
echo "$RUN"
