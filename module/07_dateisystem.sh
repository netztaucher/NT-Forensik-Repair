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

h1 "7. DATEISYSTEM-SCAN"
# ============================================================


h2 "7.1 Kürzlich veränderte PHP-Dateien (letzte ${DAYS_BACK} Tage)"
echo -e "  ${YLW}Durchsuche Webspace (kann dauern...)${NC}"

RECENT_PHP=$(find "${SCAN_PATHS[@]}" -name "*.php" -mtime -"$DAYS_BACK" -ls 2>/dev/null \
  | sort -k8 -r | head -50 || true)
if [[ -n "$RECENT_PHP" ]]; then
  info "Kürzlich veränderte .php-Dateien:"
  code "$(echo "$RECENT_PHP" | head -30)"
  evidence "veraenderte_php_dateien" "$RECENT_PHP"
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
    fsize=$(stat -c%s "$f" 2>/dev/null || echo 999999)
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
    esac
    # Generischer ABSPATH-Guard (WP-Plugin-Konvention: exit wenn direkt aufgerufen)
    if [[ "$fsize" -lt 2000 ]] && head -c 120 "$f" 2>/dev/null | grep -q "ABSPATH"; then
      GUARD_COUNT=$((GUARD_COUNT+1)); continue
    fi
    PHP_IN_UPLOADS+="$f"$'\n'
  done <<< "$PHP_IN_UPLOADS_RAW"
fi

if [[ -n "$PHP_IN_UPLOADS" ]]; then
  crit "PHP-Dateien in Upload-Verzeichnissen (nach Guard-Filter, extrem verdächtig)" web
  code "$PHP_IN_UPLOADS"
  UPLOAD_HASHES=$(echo "$PHP_IN_UPLOADS" | xargs -r sha256sum 2>/dev/null || true)
  evidence "php_in_uploads_mit_hashes" "GEFILTERT (verdächtig):
$PHP_IN_UPLOADS

SHA256:
$UPLOAD_HASHES

ALLE FUNDE (inkl. ${GUARD_COUNT} Guard-/Plugin-Dateien, zur Nachvollziehbarkeit):
$PHP_IN_UPLOADS_RAW"
else
  ok "Keine verdächtigen PHP-Dateien in Upload-Verzeichnissen (${GUARD_COUNT} legitime Guard-/Plugin-Dateien gefiltert)"
  [[ -n "$PHP_IN_UPLOADS_RAW" ]] && evidence "php_in_uploads_nur_guards" "$PHP_IN_UPLOADS_RAW"
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
    preview=$(grep -noPi "$PATTERN_REGEX" "$f" 2>/dev/null | head -2 | cut -c1-160 || true)
    entry="=== $f ===
Größe: ${fsize} B | mtime: ${fmtime} | SHA256: ${fhash}
Treffer: ${preview}
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
  evidence "webshell_dropper_kritisch" "$DROPPER_DETAIL"
else
  ok "Keine kleinen Obfuskations-Dropper gefunden"
fi

if [[ "$WEBSHELL_REVIEW" -gt 0 ]]; then
  warn "Obfuskations-Muster in ${WEBSHELL_REVIEW} größeren Datei(en) — manuell prüfen (oft legitime Frameworks)" web
  evidence "webshell_review_gross" "$REVIEW_DETAIL"
fi

h2 "7.4 Versteckte Dateien und Verzeichnisse im Webspace"
HIDDEN=$(find "${SCAN_PATHS[@]}" -name ".*" -not -name ".htaccess" -not -name ".well-known" \
  -not -name ".git*" -not -name ".user.ini" 2>/dev/null | head -20 || true)
if [[ -n "$HIDDEN" ]]; then
  warn "Versteckte Dateien/Verzeichnisse gefunden — manuell prüfen" web
  code "$HIDDEN"
  evidence "versteckte_dateien" "$HIDDEN"
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
  evidence "verdaechtige_dateinamen" "$(echo "$SUSP_NAMES" | xargs -r ls -la 2>/dev/null)"
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
  evidence "htaccess_weiterleitungen" "$HT_CONTENT"
else
  ok "Keine externen Weiterleitungen in .htaccess gefunden"
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
  evidence "immutable_dateien" "$IMMUTABLE"
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
FREMD_YAR="${BASE_DIR}/signaturen/fremd/php.yar"
if [[ "$WANT_YARA" != "1" ]]; then
    : # 7.11 hat den Hinweis bereits ausgegeben
elif ! command -v yara &>/dev/null; then
    : # dito
elif [[ ! -f "$FREMD_YAR" ]]; then
    info "php-malware-finder nicht vorhanden — mit werkzeuge/signaturen-fremd-holen.sh holen"
else
    PMF_ALTER=$(( ( $(date +%s) - $(stat -c %Y "$FREMD_YAR" 2>/dev/null || echo 0) ) / 86400 ))
    PMF_OUT=$(find "${SCAN_PATHS[@]}" -type f -size -3M \
                \( -name "*.php" -o -name "*.phtml" -o -name "*.inc" \) 2>/dev/null \
              | nf_strip_self \
              | tr '\n' '\0' \
              | xargs -0 -r -P4 -n200 yara -w "$FREMD_YAR" 2>/dev/null || true)
    if [[ -n "$PMF_OUT" ]]; then
        PMF_ANZ=$(echo "$PMF_OUT" | awk '{print $2}' | sort -u | wc -l)
        # Absichtlich warn, nicht crit: die Regeln zielen auf Obfuskierungs- und
        # Funktionsmuster, nicht auf konkrete Schädlinge. Sie treffen deshalb
        # auch legitimen Verschleierungs- und Bibliothekscode. Jeder Treffer
        # gehört gesichtet, keiner ist für sich ein Befund.
        warn "php-malware-finder: $PMF_ANZ Datei(en) mit Treffern — jeder Treffer gehört gesichtet"
        code "$(echo "$PMF_OUT" | awk '{r=$1; $1=""; sub(/^ /,""); print $0" — Regel: "r}' | sort -u | head -40)"
        evidence "php_malware_finder_treffer" "$PMF_OUT"
    else
        ok "php-malware-finder: keine Treffer"
    fi
    info "Regelstand: $PMF_ALTER Tage alt — der Regelsatz wird vom Projekt kaum noch gepflegt"
fi

# ============================================================