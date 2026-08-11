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
#   6  ImunifyAV          Signaturscan (asynchron, falls vorhanden)
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

tr '\n' '\0' < "$RUN/01d_php_kandidaten.txt" \
  | $NICE xargs -0 -r -P4 -n200 grep -lPi "$PR_HIGH" 2>/dev/null \
  > "$RUN/03_heuristik_high.txt"

while read -r f; do
  [ -n "$f" ] && fund "HEURISTIK_HIGH" 40 "$f"
done < "$RUN/03_heuristik_high.txt"

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
# 6  ImunifyAV — Signaturscan asynchron anstossen
# -----------------------------------------------------------------------------
if command -v imunify-antivirus >/dev/null 2>&1; then
  log "ImunifyAV-Scan starten..."
  imunify-antivirus malware on-demand start --path "$SCOPE" \
    --ignore-mask "$EXCL/*" --intensity low --json > "$RUN/06_scan_start.json" 2>&1
  # Die Fundliste ist eine HISTORIE. Bereits entfernte Dateien stehen weiter
  # darin. Ohne Existenzprüfung führt ein sauberer Webspace die Rangliste mit
  # Geistern an — im Test standen vier längst quarantänisierte Dateien auf den
  # Plätzen 1 bis 4.
  imunify-antivirus malware malicious list --limit 500 --json 2>/dev/null \
    | grep -oE '"file": "[^"]+"' | sed 's/"file": "//;s/"$//' \
    | grep -F "$SCOPE" | sort -u > "$RUN/06_imunify_historie.txt" 2>/dev/null
  : > "$RUN/06_imunify_bestand.txt"
  : > "$RUN/06_imunify_bereits_entfernt.txt"
  while read -r f; do
    [ -n "$f" ] || continue
    if [ -e "$f" ]; then
      echo "$f" >> "$RUN/06_imunify_bestand.txt"
      fund "IMUNIFY_SIGNATUR" 70 "$f"
    else
      echo "$f" >> "$RUN/06_imunify_bereits_entfernt.txt"
    fi
  done < "$RUN/06_imunify_historie.txt"
else
  log "ImunifyAV nicht vorhanden — Schicht übersprungen"
  : > "$RUN/06_imunify_bestand.txt"
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

CRIT="$RUN/BEFUND.txt"
{
  echo "==============================================================="
  echo " NT-Baumscan — Befund"
  echo " Scope: $SCOPE"
  echo " Lauf:  $(date -Is)"
  echo "==============================================================="
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
