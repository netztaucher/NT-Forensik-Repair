# shellcheck shell=bash
# NT-Forensik — Abschnitt 7: Dateisystem-Scan
#
# @nummer:  7
# @titel:   Dateisystem-Scan
# @frage:   Liegt Schadcode im Webverzeichnis?
# @kosten:  mittel bis hoch — durchsucht den gesamten Prüfumfang
# @ebene:   website
#
# Wird vom Runner eingebunden, nicht einzeln ausgefuehrt.
# Vorgabewerte der hier gefuellten Variablen: lib/befunde.sh

# Belegstufe dieses Abschnitts (#1). Vorgabe `server`, weil dieser Abschnitt beides prueft: den Webbaum des
# Kunden UND /tmp, /root, /etc. Die Belege aus dem Webbaum sind unten
# einzeln als `kunde` gekennzeichnet.
BELEG_STUFE=server

h1 "7. DATEISYSTEM-SCAN"
# ============================================================


h2 "7.1 Kürzlich veränderte PHP-Dateien (letzte ${DAYS_BACK} Tage)"
echo -e "  ${YLW}Durchsuche Webspace (kann dauern...)${NC}"

# Die Sortierung braucht einen zweiten Schluessel. Feld 8 aus `find -ls` ist
# der Monat, und Dateien desselben Monats sind damit gleichrangig — welche
# von ihnen die Abschneidung bei 50 ueberlebt, entschied bis hierher der
# Zufall. Zwei Laeufe ueber denselben unveraenderten Baum lieferten
# verschiedene Listen. Ein Beleg, der sich zwischen zwei Laeufen ohne Anlass
# aendert, ist als Beweismittel wertlos. Der Pfad in Feld 11 ist eindeutig
# und macht die Ordnung vollstaendig; LC_ALL=C haelt sie ueber Sprachraeume
# hinweg gleich.
RECENT_PHP=$(find "${SCAN_PATHS[@]}" -name "*.php" -mtime -"$DAYS_BACK" -ls 2>/dev/null \
  | LC_ALL=C sort -k8 -r -k11 | head -50 || true)
if [[ -n "$RECENT_PHP" ]]; then
  info "Kürzlich veränderte .php-Dateien:"
  code "$(echo "$RECENT_PHP" | head -30)"
  evidence "veraenderte_php_dateien" "$RECENT_PHP" kunde
else
  ok "Keine kürzlich veränderten PHP-Dateien gefunden"
fi

h2 "7.2 PHP-Dateien in Upload-Verzeichnissen"
PHP_IN_UPLOADS_RAW=$(find "${SCAN_PATHS[@]}" \
  \( -path "*/uploads/*.php" -o -path "*/uploads/*.phtml" -o -path "*/uploads/*.php5" \) \
  2>/dev/null || true)

# Bekannte Guard-/Plugin-Dateien herausfiltern (Avia, LayerSlider, BackWPup,
# Borlabs etc. legen legitime index.php/Cache-PHP in uploads/ ab)
PHP_IN_UPLOADS=""
GUARD_COUNT=0
if [[ -n "$PHP_IN_UPLOADS_RAW" ]]; then
  while IFS= read -r f; do
    [[ -f "$f" ]] || continue
    # Groesse portabel ueber datei_meta. Vorher stand hier `stat -c%s` mit dem
    # Rueckfallwert 999999 — und `stat -c` ist GNU. Auf BSD schlug der Aufruf
    # fehl, jede Datei galt als 999999 Bytes gross, und damit war JEDE
    # groessenabhaengige Waechterregel dieses Filters wirkungslos: die
    # 200-Byte-Regel, die 2000-Byte-ABSPATH-Regel und die neue Pruefung auf
    # die leere Datei. Aufgefallen ist es erst, als der Pruefstand eine leere
    # index.php als "extrem verdaechtig" meldete.
    fsize=$(datei_meta "$f" groesse 2>/dev/null || echo 999999)
    [[ "$fsize" =~ ^[0-9]+$ ]] || fsize=999999
    # Leere Datei. Der haeufigste Waechter ueberhaupt und der teuerste blinde
    # Fleck: die Inhaltspruefung darunter verlangt einen Treffer, und eine
    # leere Datei liefert keinen. Ein Messlauf ueber 68 Installationen meldete
    # so 274 leere index.php als "extrem verdaechtig". Eine Datei ohne ein
    # einziges Byte kann nichts ausfuehren — sie muss vor der Inhaltspruefung
    # ausscheiden, nicht in ihr.
    if [[ "$fsize" -eq 0 ]]; then
      GUARD_COUNT=$((GUARD_COUNT+1)); continue
    fi
    # Guard-Files: winzig + typischer Inhalt
    if [[ "$fsize" -lt 200 ]] && head -c 200 "$f" 2>/dev/null \
       | grep -qiE "silence is golden|browsing the directory is not allowed|^<\?php[[:space:]]*$"; then
      GUARD_COUNT=$((GUARD_COUNT+1)); continue
    fi
    # Bekannte legitime Plugin-Pfade in uploads/ (Avia/Enfold-Iconfonts,
    # BackWPup, Borlabs, WP-Hide-Config, index.php-Guards in Backup-Ordnern)
    case "$f" in
      */uploads/borlabs-cookie/*|*/uploads/backwpup*/index.php|*/uploads/backup/*/index.php|*/uploads/backup/index.php)
        GUARD_COUNT=$((GUARD_COUNT+1)); continue ;;
      */avia_fonts/*charmap*.php|*/avia_icon_fonts/*charmap*.php)
        GUARD_COUNT=$((GUARD_COUNT+1)); continue ;;
      */uploads/wph/environment.php)   # WP Hide plugin config, ABSPATH-guarded
        GUARD_COUNT=$((GUARD_COUNT+1)); continue ;;
      # Weitere Plugins, die eigene Ablagen unter uploads/ anlegen und darin
      # Waechter setzen. Aus demselben Messlauf wie die leeren Dateien oben.
      #
      # Bewusst nur index.php, nicht der ganze Teilbaum: forminator/, cache/
      # und wc-logs/ sind beschreibbare Ablagen und damit genau die Orte, an
      # denen eine Shell abgelegt wird. Ein Muster */uploads/cache/* haette
      # den Fehlalarm beseitigt und zugleich eine blinde Stelle geschaffen.
      */uploads/forminator/*/index.php|*/uploads/forminator/index.php)
        GUARD_COUNT=$((GUARD_COUNT+1)); continue ;;
      */uploads/wpforms/*/index.php|*/uploads/wpforms/index.php)
        GUARD_COUNT=$((GUARD_COUNT+1)); continue ;;
      */uploads/updraft/*/index.php|*/uploads/updraft/index.php)
        GUARD_COUNT=$((GUARD_COUNT+1)); continue ;;
      */uploads/wc-*/index.php|*/uploads/cache/index.php)
        GUARD_COUNT=$((GUARD_COUNT+1)); continue ;;
    esac
    # Generischer ABSPATH-Guard (WP-Plugin-Konvention: exit wenn direkt aufgerufen)
    if [[ "$fsize" -lt 2000 ]] && head -c 120 "$f" 2>/dev/null | grep -q "ABSPATH"; then
      GUARD_COUNT=$((GUARD_COUNT+1)); continue
    fi
    PHP_IN_UPLOADS+="$f"$'\n'
  done <<< "$PHP_IN_UPLOADS_RAW"
fi

if [[ -n "$PHP_IN_UPLOADS" ]]; then
  # Die Zahl der gefilterten Waechter gehoert AUCH hierher. Sie stand bisher
  # nur in der Entwarnungszeile — also genau dann nicht im Bericht, wenn es
  # etwas zu bewerten gab. Wer zwoelf Funde liest, muss erkennen koennen, dass
  # daneben 274 Dateien als unbedenklich ausgeschieden wurden.
  crit "PHP-Dateien in Upload-Verzeichnissen (nach Guard-Filter, extrem verdächtig; ${GUARD_COUNT} Guard-/Plugin-Dateien gefiltert)" web
  code "$PHP_IN_UPLOADS"
  UPLOAD_HASHES=$(echo "$PHP_IN_UPLOADS" | xargs -r sha256sum 2>/dev/null || true)
  evidence "php_in_uploads_mit_hashes" "GEFILTERT (verdächtig):
$PHP_IN_UPLOADS

SHA256:
$UPLOAD_HASHES

ALLE FUNDE (inkl. ${GUARD_COUNT} Guard-/Plugin-Dateien, zur Nachvollziehbarkeit):
$PHP_IN_UPLOADS_RAW" kunde
else
  ok "Keine verdächtigen PHP-Dateien in Upload-Verzeichnissen (${GUARD_COUNT} legitime Guard-/Plugin-Dateien gefiltert)"
  [[ -n "$PHP_IN_UPLOADS_RAW" ]] && evidence "php_in_uploads_nur_guards" "$PHP_IN_UPLOADS_RAW" kunde
fi

h2 "7.3 Webshell-Muster (Inhalt) — zweistufig"
echo -e "  ${YLW}Scanne auf Webshell-Signaturen (inkl. obfuskierte Cookie-Backdoors)...${NC}"


WEBSHELL_HITS=$(grep -rlPi "$PATTERN_REGEX" "${SCAN_PATHS[@]}" --include="*.php" \
  --exclude-dir=phpunit --exclude-dir=sebastian --exclude-dir=mockery 2>/dev/null || true)

DROPPER_CLUSTER=""
WEBSHELL_COUNT=0        # Tier 1: kritische Dropper
WEBSHELL_REVIEW=0       # Tier 2: große Dateien, manuell prüfen
DROPPER_DETAIL=""
REVIEW_DETAIL=""
if [[ -n "$WEBSHELL_HITS" ]]; then
  while IFS= read -r f; do
    [[ -f "$f" ]] || continue
    fsize=$(stat -c%s "$f" 2>/dev/null || echo 0)
    fhash=$(sha256sum "$f" 2>/dev/null | awk '{print $1}' || true)
    fmtime=$(stat -c %y "$f" 2>/dev/null || true)
    # Anlegezeit (crtime) mitführen. Sie übersteht `touch`, mtime und ctime
    # nicht. Im Anlassfall setzte der Angreifer die mtime von 59.472 Dateien
    # auf einen einzigen gefälschten Wert; die Chronologie liess sich danach
    # ausschliesslich über die crtime rekonstruieren.
    fcrtime=$(stat -c %w "$f" 2>/dev/null || true)
    [[ -z "$fcrtime" || "$fcrtime" == "-" ]] && fcrtime="nicht verfügbar"
    # Zeitstempel-Manipulation: mtime deutlich älter als ctime. Als alleiniger
    # Befund wertlos — jedes rekursive chown und jede Rücksicherung löst es
    # baumweit aus (Messlauf: 62.373 Dateien). Hier steht es als ZUSATZ an
    # einer Datei, die bereits aus anderem Grund auffällt. Nur so trägt es.
    fzeit=""
    _mt=$(stat -c %Y "$f" 2>/dev/null || echo 0)
    _ct=$(stat -c %Z "$f" 2>/dev/null || echo 0)
    if [[ "$_ct" -gt 0 && $(( _ct - _mt )) -gt "${ZEITSTEMPEL_ZUSATZ_SEK:-2592000}" ]]; then
      fzeit="ZEITSTEMPEL: mtime ist $(( (_ct - _mt) / 86400 )) Tage älter als die letzte Metadatenänderung — Rückdatierung möglich"$'\n'
    fi
    preview=$(grep -noPi "$PATTERN_REGEX" "$f" 2>/dev/null | head -2 | cut -c1-160 || true)
    entry="=== $f ===
Größe: ${fsize} B | mtime: ${fmtime} | SHA256: ${fhash}
Angelegt (crtime): ${fcrtime}
${fzeit}Treffer: ${preview}
"
    if [[ "$fsize" -lt "$DROPPER_MAX_BYTES" ]]; then
      WEBSHELL_COUNT=$((WEBSHELL_COUNT+1))
      DROPPER_DETAIL+="$entry"$'\n'
    else
      WEBSHELL_REVIEW=$((WEBSHELL_REVIEW+1))
      REVIEW_DETAIL+="$entry"$'\n'
    fi
  done <<< "$WEBSHELL_HITS"
fi

if [[ "$WEBSHELL_COUNT" -gt 0 ]]; then
  crit "Webshells/Dropper gefunden: ${WEBSHELL_COUNT} Datei(en) < ${DROPPER_MAX_BYTES} B mit Obfuskation" web
  DROPPER_CLUSTER=$(echo "$DROPPER_DETAIL" | grep "^=== " | sed 's|=== /var/www/vhosts/||;s| ===||' | cut -d/ -f1 | sort | uniq -c | sort -rn || true)
  info "Betroffene Domains (Dropper-Cluster):"
  code "$DROPPER_CLUSTER"
  echo -e "\n**Dropper-Details:**\n\`\`\`\n$DROPPER_DETAIL\n\`\`\`" >> "$REPORT_FILE"
  evidence "webshell_dropper_kritisch" "$DROPPER_DETAIL" kunde
else
  ok "Keine kleinen Obfuskations-Dropper gefunden"
fi

if [[ "$WEBSHELL_REVIEW" -gt 0 ]]; then
  warn "Obfuskations-Muster in ${WEBSHELL_REVIEW} größeren Datei(en) — manuell prüfen (oft legitime Frameworks)" web
  evidence "webshell_review_gross" "$REVIEW_DETAIL" kunde
fi

# ── Zweite Stufe: gefährliche Funktionen in kleinen Dateien ─────────────────
# PATTERN_REGEX_MED trifft Funktionen, die auch legitim vorkommen — ein
# Messlauf ergab 358 Treffer auf 25.000 Dateien. Als kritischer Befund taugt
# das nicht. Die Grössenschwelle macht es brauchbar: eine Filemanager-Shell
# mit unverschleiertem shell_exec ist klein, ein Framework mit denselben
# Aufrufen ist es nicht. Dateien, die bereits Stufe 1 ausgelöst haben, bleiben
# hier aussen vor — sie sind gemeldet.
MED_DETAIL=""
MED_COUNT=0
while IFS= read -r f; do
  [[ -f "$f" ]] || continue
  [[ -n "$WEBSHELL_HITS" ]] && grep -qxF "$f" <<< "$WEBSHELL_HITS" && continue
  fsize=$(stat -c%s "$f" 2>/dev/null || echo 0)
  [[ "$fsize" -lt "$DROPPER_MAX_BYTES" ]] || continue
  MED_COUNT=$((MED_COUNT+1))
  MED_DETAIL+="=== $f ===
Größe: ${fsize} B | mtime: $(stat -c %y "$f" 2>/dev/null) | SHA256: $(sha256sum "$f" 2>/dev/null | awk '{print $1}')
Angelegt (crtime): $(stat -c %w "$f" 2>/dev/null)
Treffer: $(grep -noPi "$PATTERN_REGEX_MED" "$f" 2>/dev/null | head -2 | cut -c1-160)
"$'\n'
done < <(grep -rlPi "$PATTERN_REGEX_MED" "${SCAN_PATHS[@]}" --include="*.php" \
           --exclude-dir=phpunit --exclude-dir=sebastian --exclude-dir=mockery 2>/dev/null | sort || true)

if [[ "$MED_COUNT" -gt 0 ]]; then
  warn "Gefährliche Funktionen (exec-Familie, Bot-Ausblendung, Login-Gate) in ${MED_COUNT} kleinen Datei(en) — sichten" web
  code "$(echo "$MED_DETAIL" | grep '^=== ' | sed 's|=== ||;s| ===||' | head -20)"
  evidence "gefaehrliche_funktionen_klein" "$MED_DETAIL" kunde
else
  ok "Keine gefährlichen Funktionen in kleinen PHP-Dateien"
fi

h2 "7.4 Versteckte Dateien und Verzeichnisse im Webspace"
HIDDEN=$(find "${SCAN_PATHS[@]}" -name ".*" -not -name ".htaccess" -not -name ".well-known" \
  -not -name ".git*" -not -name ".user.ini" 2>/dev/null | head -20 || true)
if [[ -n "$HIDDEN" ]]; then
  warn "Versteckte Dateien/Verzeichnisse gefunden — manuell prüfen" web
  code "$HIDDEN"
  evidence "versteckte_dateien" "$HIDDEN" kunde
else
  ok "Keine auffälligen versteckten Dateien"
fi

h2 "7.5 Verdächtige Dateinamen (namensbasiert, geringe Konfidenz → Warnung)"
# Namensbasiert = viele False Positives (Plugin-Klassen wie class.u.shell.php,
# class-wp-optimize-bypass.php; Cache-Hashes mit 'c99'). Daher WARN, nicht CRIT,
# und aggressive Ausschlüsse: Core, vendor, Template-Caches, Twig, Elementor-Assets.
# whole-name-Match (kein Substring in Pfad) via -iname am Basenamen.
SUSP_NAMES=$(find "${SCAN_PATHS[@]}" -type f \
  \( -iname "*.php" -o -iname "*.phtml" -o -iname "*.php5" -o -iname "*.pl" \
     -o -iname "*.py" -o -iname "*.sh" -o -iname "*.cgi" \) \
  \( -iname "*shell*" -o -iname "*exploit*" -o -iname "*hack*" \
     -o -iname "*r57*" -o -iname "*c99*" \
     -o -iname "*bypass*" -o -iname "*backdoor*" \) \
  -not -path "*/wp-includes/*" -not -path "*/wp-admin/*" \
  -not -path "*/vendor/*" -not -path "*/node_modules/*" \
  -not -path "*/cache/*" -not -path "*/templates_c/*" -not -path "*/var/cache/*" \
  -not -path "*/twig/*" -not -path "*/wp-content/plugins/*" \
  2>/dev/null || true)
if [[ -n "$SUSP_NAMES" ]]; then
  warn "Dateinamen mit verdächtigen Schlüsselwörtern (manuell gegen Inhalt prüfen)" web
  code "$(echo "$SUSP_NAMES" | xargs -r ls -la 2>/dev/null)"
  evidence "verdaechtige_dateinamen" "$(echo "$SUSP_NAMES" | xargs -r ls -la 2>/dev/null)" kunde
else
  ok "Keine verdächtigen Dateinamen (außerhalb Core/vendor/cache/plugins)"
fi

h2 "7.6 .htaccess-Dateien prüfen"
HTACCESS_REDIRECTS=$(find "${SCAN_PATHS[@]}" -name ".htaccess" 2>/dev/null \
  -exec grep -lE "RewriteRule.*http|Redirect.*http" {} \; || true)
if [[ -n "$HTACCESS_REDIRECTS" ]]; then
  warn ".htaccess mit externen Weiterleitungen gefunden" web
  code "$HTACCESS_REDIRECTS"
  HT_CONTENT=""
  while IFS= read -r f; do
    HT_CONTENT+="=== $f ==="$'\n'"$(cat "$f" 2>/dev/null)"$'\n'
    code "$(cat "$f" 2>/dev/null)"
  done <<< "$HTACCESS_REDIRECTS"
  evidence "htaccess_weiterleitungen" "$HT_CONTENT" kunde
else
  ok "Keine externen Weiterleitungen in .htaccess gefunden"
fi

# ── Freigabe genau einer PHP-Datei ──────────────────────────────────────────
# Ein sehr verlässlicher Marker. Im Anlassfall lag neben jeder Shell eine
# .htaccess, die PHP im Verzeichnis sperrte und genau die eigene Datei wieder
# freigab — der Angreifer sperrte damit Mitbewerber aus:
#
#     <FilesMatch "^(newpath.php|extra-buttons.php|index.php)$">
#         Order allow,deny
#         Allow from all
#     </FilesMatch>
#
# Legitime Software tut das praktisch nie: sie sperrt Verzeichnisse pauschal
# oder gibt sie pauschal frei, nicht einzelne PHP-Dateien namentlich.
#
# Bewusst mit awk statt `grep -Pz`: die Suche über Zeilengrenzen braucht dort
# PCRE und die Null-Trennung. Auf dem Entwicklungsrechner lief ein grep ohne
# PCRE-Unterstützung und wies -P schlicht zurück — die Prüfung blieb stumm und
# meldete "keine Freigabe gefunden", obwohl eine danebenlag. Ein Werkzeug, das
# auf fremden Servern mit unbekannten Werkzeugständen läuft, darf sich darauf
# nicht verlassen. awk gibt es überall und kann Zustand über Zeilen halten.
HT_WHITELIST=""
while IFS= read -r h; do
  [[ -f "$h" ]] || continue
  if awk '
      { z = tolower($0) }
      z ~ /<files(match)?[^>]*\.php[^>]*>/ { drin = 1; next }
      z ~ /<\/files(match)?>/              { drin = 0; next }
      drin && z ~ /allow[ \t]+from[ \t]+all/ { gefunden = 1 }
      END { exit(gefunden ? 0 : 1) }
    ' "$h" 2>/dev/null; then
    HT_WHITELIST+="=== $h ==="$'\n'"$(cat "$h" 2>/dev/null)"$'\n\n'
  fi
done < <(find "${SCAN_PATHS[@]}" -name ".htaccess" 2>/dev/null | nf_strip_self)

if [[ -n "$HT_WHITELIST" ]]; then
  HT_WL_ANZ=$(grep -c '^=== ' <<< "$HT_WHITELIST" || echo 0)
  crit ".htaccess gibt gezielt einzelne PHP-Datei(en) frei — typisch für abgesicherte Webshells (${HT_WL_ANZ})" web
  code "$HT_WHITELIST"
  evidence "htaccess_einzelfreigabe_php" "$HT_WHITELIST" kunde
else
  ok "Keine .htaccess mit gezielter Freigabe einzelner PHP-Dateien"
fi

h2 "7.7 SUID/SGID-Dateien in Webspace und tmp-Verzeichnissen"
SUID_FILES=$(find "${SCAN_PATHS[@]}" /tmp /var/tmp /dev/shm -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null || true)
if [[ -n "$SUID_FILES" ]]; then
  crit "SUID/SGID-Dateien in Webspace/tmp — Privilege-Escalation-Verdacht" web
  code "$(echo "$SUID_FILES" | xargs -r ls -la 2>/dev/null)"
  evidence "suid_dateien" "$(echo "$SUID_FILES" | xargs -r ls -la 2>/dev/null)"
else
  ok "Keine SUID/SGID-Dateien in Webspace oder tmp"
fi

h2 "7.8 Ausführbare Dateien in tmp-Verzeichnissen"
# Entpackte AppImage-Pakete in systemd-private-Verzeichnissen sind auf einem
# Plesk-Server der Normalfall: Collabora Office und andere Dienste entpacken
# sich bei jedem Start dorthin. Auf einem echten Kundensystem stellten sie 20
# von 23 Funden — und weil die Liste bei 20 abgeschnitten wurde, verdraengten
# sie alles andere. Das Bereinigungswerkzeug haette diese Dateien in Quarantaene
# verschoben und damit einen laufenden Dienst zerlegt, waehrend der echte
# Schadcode unangetastet blieb.
#
# Ausgeblendet wird nur der Entpack-Baum selbst, nicht das Verzeichnis darueber:
# ein Angreifer, der den Dienst uebernimmt, legt seine Dateien nicht in einen
# bei jedem Neustart neu erzeugten Ordner.
# Collabora Office (Plesk/Nextcloud) legt bei jedem Start zwei Baeume unter
# /tmp an: das entpackte AppImage und ein "systemplate" mit den dynamischen
# Ladern. Beides sind Laufzeit-Artefakte, die bei jedem Neustart neu entstehen
# — ein Angreifer legt dort nichts ab, was ueberleben soll. Auf einem echten
# Kundensystem stellten sie erst 20, nach der ersten Fassung dieses Filters
# noch 4 von 7 Quarantaene-Kandidaten. Ein Bereinigungslauf haette Collaboras
# ld-linux mitgenommen und den Dienst zerlegt.
TMP_LEGITIM='/appimage_extracted_[0-9a-f]+/|/coolwsd\.[A-Za-z0-9]+/systemplate/'
TMP_ALLE=$(find /tmp /var/tmp /dev/shm -type f \( -perm -u+x -o -name "*.sh" -o -name "*.php" -o -name "*.py" -o -name "*.pl" \) 2>/dev/null | nf_strip_self || true)
TMP_N_ALLE=$(printf '%s\n' "$TMP_ALLE" | grep -c . || true)
TMP_EXECS=$(printf '%s\n' "$TMP_ALLE" | grep -vE "$TMP_LEGITIM" || true)
TMP_N_ZEIG=$(printf '%s\n' "$TMP_EXECS" | grep -c . || true)
TMP_N_AUS=$(( TMP_N_ALLE - TMP_N_ZEIG ))
# Keine stille Deckelung: was nicht gezeigt wird, wird beziffert.
TMP_KAPPUNG=""
if [[ "$TMP_N_ZEIG" -gt 60 ]]; then
  TMP_KAPPUNG="Anzeige auf 60 von ${TMP_N_ZEIG} Dateien begrenzt — vollstaendige Liste im Beleg."
  TMP_EXECS=$(printf '%s\n' "$TMP_EXECS" | head -60)
fi
if [[ -n "$TMP_EXECS" ]]; then
  warn "Ausführbare Dateien/Skripte in tmp-Verzeichnissen — prüfen (${TMP_N_ZEIG})"
  [[ "$TMP_N_AUS" -gt 0 ]] && info "${TMP_N_AUS} weitere aus entpackten AppImage-Paketen (systemd-private) ausgeblendet — bei Plesk der Normalfall"
  [[ -n "$TMP_KAPPUNG" ]] && info "$TMP_KAPPUNG"
  code "$(echo "$TMP_EXECS" | xargs -r ls -la 2>/dev/null)"
  evidence "tmp_executables" "Gefunden gesamt: ${TMP_N_ALLE}
Davon als AppImage-Entpackung ausgeblendet: ${TMP_N_AUS}
Bewertet: ${TMP_N_ZEIG}
${TMP_KAPPUNG}

$(printf '%s\n' "$TMP_ALLE" | grep -vE "$TMP_LEGITIM" | xargs -r ls -la 2>/dev/null)

$(printf '%s\n' "$TMP_ALLE" | grep -vE "$TMP_LEGITIM" | xargs -r sha256sum 2>/dev/null)"
else
  ok "Keine ausführbaren Dateien in tmp-Verzeichnissen$([[ "$TMP_N_AUS" -gt 0 ]] && echo " (${TMP_N_AUS} AppImage-Dateien ausgeblendet)")"
fi

h2 "7.9 Immutable-Flags im Webspace (chattr +i — Malware-Selbstschutz)"
IMMUTABLE=$(find "${SCAN_PATHS[@]}" -maxdepth 6 -type f -name "*.php" 2>/dev/null | head -8000 \
  | xargs -r lsattr 2>/dev/null | awk '$1 ~ /i/ {print}' || true)
if [[ -n "$IMMUTABLE" ]]; then
  crit "PHP-Dateien mit Immutable-Flag — Malware schützt sich so vor Löschung" web
  code "$IMMUTABLE"
  evidence "immutable_dateien" "$IMMUTABLE" kunde
else
  ok "Keine Immutable-Flags auf PHP-Dateien (Stichprobe max. 8000 Dateien)"
fi

h2 "7.10 Als Schlüssel-/Konfigdatei getarnte Binaries"
# Konkreter Anlass: eine gs-netcat-Binary lag als ~/.ssh/id_rsa auf dem
# System. Eine Datei mit diesem Namen prüft niemand auf ihren Dateityp.
# Erkennung über das ELF-Magic (7f 45 4c 46), nicht über den Namen.
# Scope: System-Verzeichnisse (Schlüssel-/Konfig-Ablageorte) plus der
# geprüfte Webspace ${SCAN_PATH} — NICHT alle vhosts. Auf Shared-Hosts
# mit hunderten vhosts explodiert ein $VHOSTS_DIR-Scan (Plesk-Statistik/
# webalizer allein liefern Zehntausende .png/.log-Treffer). Der serverweite
# Voll-Scan bleibt dem Global-Modus (ab v3.5) vorbehalten. Die Endungsliste
# ist bewusst auf Schlüssel-/Zertifikat-/Konfig-Namen begrenzt; eine als
# Bild/Log getarnte ELF fängt ohnehin der inhaltsbasierte Signaturscan 8.7
# (grep -rla) und, falls vorhanden, YARA (7.11) — beide lesen den Inhalt,
# nicht den Namen.
MASQ_FOUND=""
while IFS= read -r f; do
    [[ -f "$f" ]] || continue
    magic=$(head -c4 "$f" 2>/dev/null | od -An -tx1 2>/dev/null | tr -d ' \n')
    if [[ "$magic" == "7f454c46" ]]; then
        MASQ_FOUND+="$(ls -la --time-style=long-iso "$f" 2>/dev/null)  SHA256: $(sha256sum "$f" 2>/dev/null | awk '{print $1}')"$'\n'
        MASQ_BINARIES+="$f"$'\n'
    fi
done < <(find /root /home /etc "${SCAN_PATHS[@]}" /tmp /var/tmp /dev/shm -xdev -type f \
    \( -name 'id_*' -o -name '*.pem' -o -name '*.key' -o -name '*.crt' \
       -o -name 'authorized_keys*' -o -name 'known_hosts' -o -name '*.conf' \) 2>/dev/null | nf_strip_self)

if [[ -n "$MASQ_FOUND" ]]; then
    crit "Ausführbare Binary als Schlüssel-/Konfigdatei getarnt"
    code "$MASQ_FOUND"
    evidence "getarnte_binaries" "$MASQ_FOUND"
else
    ok "Keine als Schlüssel-/Konfigdatei getarnten Binaries"
fi

h2 "7.11 YARA-Signaturscan (optional)"
# Nutzt signaturen/gsocket-backdoors.yar, falls yara installiert ist.
# Die Regel ELF_Masquerading_As_KeyFile braucht die externe Variable
# 'filename' — ohne sie würde sie auf jede ELF-Datei anschlagen.
# Sammel-Regeldatei bevorzugen (bindet gsocket + Joomla + künftige ein).
# Rückfall auf die einzelne Datei hält Hosts lauffähig, die noch einen alten
# signaturen/-Stand tragen.
YARA_RULES_FILE="${BASE_DIR}/signaturen/alle.yar"
[[ -f "$YARA_RULES_FILE" ]] || YARA_RULES_FILE="${BASE_DIR}/signaturen/gsocket-backdoors.yar"
if [[ "$WANT_YARA" != "1" ]]; then
    info "YARA-Scan nicht aktiviert — mit --yara einschalten (auf großen Webspaces langsam)"
elif command -v yara &>/dev/null && [[ -f "$YARA_RULES_FILE" ]]; then
    YARA_DETAIL=""
    while IFS= read -r f; do
        [[ -f "$f" ]] || continue
        bn=$(basename "$f")
        yout=$(yara -w -d filename="$bn" "$YARA_RULES_FILE" "$f" 2>/dev/null || true)
        if [[ -n "$yout" ]]; then
            rules=$(echo "$yout" | awk '{print $1}' | sort -u | tr '\n' ' ')
            YARA_DETAIL+="$f — Regeln: $rules"$'\n'
            YARA_HITS+="$f"$'\n'
        fi
    done < <(find /tmp /var/tmp /dev/shm /root /home /usr/local/bin /usr/local/sbin /opt "${SCAN_PATHS[@]}" \
                -xdev -type f -size -30M 2>/dev/null | nf_strip_self)
    if [[ -n "$YARA_DETAIL" ]]; then
        crit "YARA-Signaturtreffer im Dateisystem"
        code "$YARA_DETAIL"
        evidence "yara_treffer" "$YARA_DETAIL"
    else
        ok "Keine YARA-Signaturtreffer"
    fi
elif ! command -v yara &>/dev/null; then
    info "yara nicht installiert — Signaturscan übersprungen (apt install yara)"
else
    info "Keine Regeldatei unter $YARA_RULES_FILE — Signaturscan übersprungen"
fi

h2 "7.12 Fremder YARA-Regelsatz (php-malware-finder, optional)"
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
if [[ "$WANT_YARA" != "1" ]]; then
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
    if [[ -n "$PMF_OUT" ]]; then
        PMF_ANZ=$(echo "$PMF_OUT" | awk '{print $2}' | sort -u | wc -l)
        # Nach Anzahl ausgelöster Regeln absteigend — als schwache Hilfe, nicht
        # als Trennschärfe. Messlauf über 25.860 PHP-Dateien: 359 betroffene
        # Dateien, und der enthaltene gepackte Webshell landete mit drei Regeln
        # auf Platz 11. Über ihm standen WordPress-Kern, pclzip, UpdraftPlus und
        # Wordfence selbst, alle mit drei bis vier Regeln.
        #
        # Ursache ist die Whitelist des Regelsatzes: sie arbeitet mit SHA1-Hashes
        # konkreter Kerndateien (629 Stück für WordPress) aus dem Stand von 2023.
        # Auf einer aktuellen Installation passt kein einziger davon, also greift
        # sie nicht, und der Kern selbst schlägt an.
        #
        # Konsequenz: dieser Abschnitt ist ein Suchhilfsmittel für den Prüfer,
        # kein Detektor. Er gehört gelesen, nicht geglaubt.
        PMF_RANG=$(echo "$PMF_OUT" | awk '{r=$1; $1=""; sub(/^ /,""); regeln[$0]=regeln[$0]" "r; n[$0]++}
                     END {for (f in n) printf "%d\t%s\t%s\n", n[f], f, regeln[f]}' \
                   | sort -rn | awk -F'\t' '{printf "%d Regel(n): %s —%s\n", $1, $2, $3}')
        # Absichtlich warn, nicht crit: die Regeln zielen auf Obfuskierungs- und
        # Funktionsmuster, nicht auf konkrete Schädlinge. Sie treffen deshalb
        # auch legitimen Verschleierungs- und Bibliothekscode. Jeder Treffer
        # gehört gesichtet, keiner ist für sich ein Befund.
        warn "php-malware-finder: $PMF_ANZ Datei(en) mit Treffern — nach Regelanzahl sortiert, jeder Treffer gehört gesichtet" web
        code "$(echo "$PMF_RANG" | head -40)"
        evidence "php_malware_finder_treffer" "$PMF_RANG" kunde
    else
        ok "php-malware-finder: keine Treffer"
    fi
    info "Regelstand: $PMF_ALTER Tage alt — der Regelsatz wird vom Projekt kaum noch gepflegt"
fi

h2 "7.13 PHP-Code in Medien- und Asset-Dateien"
# Der Gegenpol zu 7.10: dort ein Binary, das sich als Schlüsseldatei ausgibt,
# hier PHP-Code, der in einer echten Mediendatei sitzt.
#
# Anlassfall: ein gültiges PNG, 512×512, das sich in jedem Bildbetrachter
# normal öffnet — mit PHP im tEXt-Chunk, das Schadcode von aussen nachlud. Es
# lag neun Tage unentdeckt. Weder der Signaturscanner noch die Heuristik noch
# ein fremder YARA-Regelsatz meldeten es, und zwar aus demselben Grund: die
# Nutzlast war völlig unverschleiert.
#
#   <?php $u = "https://…/de.php"; $c = curl_init(); …
#
# Kein eval, kein Base64, keine Superglobals. Auf Token-Ebene harmloser Code.
# Bösartig ist nicht der Code, sondern der Behälter. Deshalb prüft dieser
# Abschnitt nicht, WAS das PHP tut, sondern nur, DASS es dort steht.
#
# Gesucht wird ausschliesslich der vollständige Öffner "<?php". Die Kurzformen
# "<?=" und "<?" sind zwei bis drei Bytes und treten in Binärdaten zufällig
# auf — ein Versuch damit erzeugte 5.323 Fehlalarme auf einem einzigen Webspace.
MEDIA_HITS=$(find "${SCAN_PATHS[@]}" -type f -size -20M \
    \( -iname "*.png" -o -iname "*.jpg" -o -iname "*.jpeg" -o -iname "*.gif" \
       -o -iname "*.webp" -o -iname "*.bmp" -o -iname "*.ico" -o -iname "*.svg" \
       -o -iname "*.tif" -o -iname "*.tiff" -o -iname "*.woff" -o -iname "*.woff2" \
       -o -iname "*.ttf" -o -iname "*.otf" -o -iname "*.eot" -o -iname "*.pdf" \
       -o -iname "*.mp3" -o -iname "*.mp4" -o -iname "*.wav" \) 2>/dev/null \
  | nf_strip_self \
  | tr '\n' '\0' \
  | xargs -0 -r -P4 -n200 grep -laF '<?php' 2>/dev/null | sort -u || true)

if [[ -n "$MEDIA_HITS" ]]; then
    MEDIA_ANZ=$(echo "$MEDIA_HITS" | grep -c . || echo 0)
    crit "PHP-Code in $MEDIA_ANZ Mediendatei(en) — in einem echten Bild gehört kein PHP" web
    MEDIA_DETAIL=""
    while IFS= read -r mf; do
        [[ -f "$mf" ]] || continue
        MEDIA_DETAIL+="$mf"$'\n'
        MEDIA_DETAIL+="    Typ:      $(file -b "$mf" 2>/dev/null | cut -c1-70)"$'\n'
        MEDIA_DETAIL+="    Angelegt: $(stat -c %w "$mf" 2>/dev/null || echo '?')"$'\n'
        MEDIA_DETAIL+="    SHA256:   $(sha256sum "$mf" 2>/dev/null | cut -d' ' -f1)"$'\n'
        MEDIA_DETAIL+="    Nutzlast: $(grep -aoP '<\?php.{0,120}' "$mf" 2>/dev/null | head -1 | tr -d '\000')"$'\n\n'
        DISGUISED_PAYLOADS+="$mf"$'\n'
    done <<< "$MEDIA_HITS"
    code "$MEDIA_DETAIL"
    evidence "php_in_mediendateien" "$MEDIA_DETAIL" kunde
else
    ok "Kein PHP-Code in Medien- oder Asset-Dateien"
fi

h2 "7.14 Massenhaft gleiche Zeitstempel (Spurenverwischung)"
# Der Gegenpol zur Einzelbetrachtung in 7.3: dort die Rückdatierung EINER
# auffälligen Datei, hier die flächige Manipulation.
#
# Im Anlassfall setzte der Angreifer die mtime von 59.472 Dateien in einer
# einzigen Sekunde auf denselben gefälschten Wert. Danach war jede Aussage der
# Form "diese Datei ist neu" wertlos — und genau das war der Zweck.
#
# Bewusst als Hinweis, nicht als Befund: dieselbe Signatur entsteht auch bei
# einer Rücksicherung, einer Migration oder einem Auspacken mit erhaltenen
# Zeitstempeln. Was der Prüfer daraus macht, hängt davon ab, ob für den
# Zeitpunkt eine Erklärung existiert. Die Frage zu stellen ist der Wert.
# Kein `| head` am Ende der Kette. `head` schliesst die Pipe, sobald es genug
# hat; das vorgelagerte `sort` bekommt EPIPE und schreibt
#   sort: write failed: 'standard output': Broken pipe
# nach stderr. Ob es dazu kommt, haengt davon ab, ob die Ausgabe noch in den
# Pipe-Puffer passt — also vom Zufall. Genau so ist die Zeile in der CI
# aufgetaucht: die aufgenommene Referenz trug sie, der Vergleichslauf nicht.
# Ein Pruefstand, der bei gleichem Programmstand mal so und mal so ausschlaegt,
# ist keiner. awk begrenzt deshalb selbst und liest die Eingabe bis zum Ende.
ZEIT_CLUSTER=$(find "${SCAN_PATHS[@]}" -type f -printf '%T@\n' 2>/dev/null \
  | cut -d. -f1 | LC_ALL=C sort | uniq -c | LC_ALL=C sort -rn \
  | awk -v min="${ZEITCLUSTER_MIN:-500}" '$1>=min && ++n<=5 {print $1"\t"$2}')

if [[ -n "$ZEIT_CLUSTER" ]]; then
  ZC_DETAIL=""
  while IFS=$'\t' read -r anzahl epoche; do
    [[ -n "$epoche" ]] || continue
    ZC_DETAIL+="$anzahl Dateien tragen exakt $(date -d "@$epoche" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "$epoche")"$'\n'
    # Gegenprobe über die Anlegezeit: stimmt sie mit der mtime überein, ist es
    # ein echter Massenvorgang (Auspacken, Kopie). Weicht sie ab, wurde die
    # mtime nachträglich gesetzt — das ist der Unterschied zwischen Migration
    # und Verschleierung.
    # Dieselbe Sache: `sort | head -1` bricht sort mitten im Schreiben ab.
    # Hier wird die ganze Liste geholt und die erste Zeile in der Shell
    # abgeschnitten. LC_ALL=C, damit die Stichprobe nicht davon abhaengt,
    # welche Sprachumgebung gerade gesetzt ist — sie steht im Beleg.
    beispiel=$(find "${SCAN_PATHS[@]}" -type f -newermt "@$((epoche-1))" ! -newermt "@$((epoche+1))" 2>/dev/null | LC_ALL=C sort)
    beispiel="${beispiel%%$'\n'*}"
    if [[ -n "$beispiel" ]]; then
      bcr=$(stat -c %w "$beispiel" 2>/dev/null || true)
      ZC_DETAIL+="    Stichprobe: $beispiel"$'\n'"    angelegt:   ${bcr:-nicht verfügbar}"$'\n'
    fi
  done <<< "$ZEIT_CLUSTER"
  info "Auffällig viele Dateien mit identischem Zeitstempel — Ursache klären"
  code "$ZC_DETAIL"
  evidence "zeitstempel_cluster" "$ZC_DETAIL" kunde
else
  ok "Keine auffälligen Zeitstempel-Häufungen"
fi

# ============================================================