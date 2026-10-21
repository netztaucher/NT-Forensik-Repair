# shellcheck shell=bash
# ============================================================
# NT-Forensik — Signaturen und Selbstausschluss
# ------------------------------------------------------------
# Erkennungsmuster, die von mehreren Abschnitten benutzt werden, sowie der
# Selbstausschluss: NT-Forensik legt Berichte unter BASE_DIR ab, und da die
# Berichte die Suchbegriffe im Klartext enthalten, wuerde sich das Werkzeug
# ab dem zweiten Lauf selbst als Backdoor melden.
# ============================================================

# Signaturfamilie THC gsocket / gs-netcat. Trifft auch bei Umbenennung,
# da die Strings im Binary verbleiben (auch bei stripped).
GS_SIG_REGEX='GSRN|gs\.thc\.org|GS_connect|GSOCKET_ARGS|GSOCKET_SECRET|gs-netcat|4_gs-netcat\.c|GS_daemonize|gs_watchdog|GSOCKET_SOCKS|GS_gen_secret'
# Vom gsocket-Installer verwendete Tarnnamen
GS_DISGUISE_REGEX='gs-dbus|gs-bd|dbus-run-session\.sh'

# ── WordPress-Administratoren: Namens- und Adressmuster ─────────────────────
# Bis v3.9.0 wurde ein Admin nur dann gemeldet, wenn er JÜNGER als DAYS_BACK war.
# Ein Konto "adminbackup <adminbackup@wordpress.org>" vom Juni 2025 rutschte
# damit im August 2026 durch, und der Bericht meldete ausdrücklich "keine
# kürzlich angelegten Admins" — eine Entwarnung genau dort, wo ein Lehrbuch-IOC
# stand. Alter allein ist kein Kriterium: ein Angreifer, der lange unentdeckt
# bleibt, wird dadurch nicht harmloser, sondern gefährlicher.
#
# Zwei Stufen, weil die Trennschärfe verschieden ist.

# Stufe 1 — Adressen, die es bei echten Menschen nicht gibt.
# wordpress.org vergibt keine Postfächer; eine Adresse dort ist frei erfunden.
# Wegwerfdienste stehen nie hinter einem gewollten Administratorkonto.
WP_ADMIN_MAIL_CRIT='@wordpress\.org$|@example\.(com|org|net)$|@(mailinator|guerrillamail|yopmail|10minutemail|tempmail|sharklasers|maildrop|trashmail|getnada)\.'

# Stufe 1 — Anmeldenamen, die praktisch ausschliesslich von Angreifern stammen.
# Bewusst eng gehalten: "admin" allein ist auf alten Installationen normal und
# steht deshalb NICHT hier. Ein Fehlalarm auf dieser Stufe kostet Vertrauen.
WP_ADMIN_LOGIN_CRIT='^(admin_?backup|backup_?admin|wp_?-?support|wp_?-?service|wpservice|wp_?maintenance|contentadmin|admin_?wp|wp_?updates?)$'

# Stufe 2 — auffällig, aber erklärbar. Nur Hinweis, keine Wertung.
# Durchnummerierte Konten entstehen auch, wenn eine Agentur mehrere Zugänge
# anlegt; lange Ziffernketten sprechen dagegen für automatisierte Erzeugung.
WP_ADMIN_LOGIN_WARN='^(admin|administrator|user|test|demo|support|root)[0-9]{1,4}$|^[a-z]{1,3}[0-9]{5,}$'
# Freemail-Adressen gehören hier ausdrücklich NICHT hinein: gmx.de, web.de und
# gmail.com sind bei deutschen Website-Betreibern der Normalfall. Eine Regel,
# die bei der Mehrheit der legitimen Kunden anschlägt, trainiert nur das
# Wegklicken — und wird dann auch beim echten Fund weggeklickt.
WP_ADMIN_MAIL_WARN='@wordpress\.com$'

# WICHTIG — Selbstausschluss: NT-Forensik legt seine Berichte und Belege unter
# ${BASE_DIR} (/root/wartungsscripte) ab. Da /root mitgescannt wird und die
# Berichte die Suchbegriffe im Klartext enthalten, würde sich das Skript ab dem
# zweiten Lauf selbst als Backdoor melden. Alle Scans dieses Abschnitts filtern
# daher konsequent gegen BEIDE eigenen Orte: ${BASE_DIR} (Laufdaten, Berichte,
# Quarantäne) und ${SELF_DIR} (Code, signaturen/*.yar). Seit der Code nicht
# mehr nach BASE_DIR kopiert wird, reicht BASE_DIR allein nicht — von einem
# Checkout außerhalb von BASE_DIR meldete das Werkzeug sonst seine eigenen
# YARA-Regeln als Treffer.
nf_strip_self() { grep -vF -e "${BASE_DIR}/" -e "${SELF_DIR}/" || true; }

# Eigene Prozesskette (Skript + Eltern), damit der Lauf sich nicht selbst meldet
NF_SELF_PIDS=" $$ ${PPID:-0} "
_nf_p=${PPID:-0}
for _nf_i in 1 2 3 4 5; do
    [[ -r "/proc/$_nf_p/status" ]] || break
    _nf_p=$(awk '/^PPid:/{print $2}' "/proc/$_nf_p/status" 2>/dev/null)
    [[ -z "$_nf_p" || "$_nf_p" == "0" ]] && break
    NF_SELF_PIDS+="$_nf_p "
done
nf_is_self() { [[ " $NF_SELF_PIDS " == *" $1 "* ]]; }

# ── Ternär-Kette aus Hex-Literalen (#144) ───────────────────────────────────
#
# 21.10.2026, web68 auf cletus: wp-content/plugins/german.php.bak, 48 993 B,
# EINE Zeile, die mit einer Kette wie dieser beginnt:
#
#     <?php (0x4eF1)?0xBf9C0:(0x21afd)?0xC3:(0x0Be)?0xFf9cD:…
#
# Jede Bedingung ist ein konstantes Hex-Literal, das Ergebnis steht also
# vorher fest — die Kette rechnet nichts, sie verschleiert nur. Kein Mensch
# und kein Codegenerator fuer legitimen PHP-Code schreibt zwanzig solcher
# Glieder hintereinander. Imunify meldete die Datei als Malware; keines der
# Muster in PATTERN_REGEX (lib/konfig.sh) traf sie.
#
# Genau zwanzig Glieder, nicht "zwanzig oder mehr": fuer die Entscheidung
# reicht der Anfang, und die Vorschau in 7.3 bleibt kurz statt die ganze
# 48-kB-Zeile auszugeben. Leerraum zwischen den Teilen ist zugelassen — eine
# Kette, die ein Formatierer umbrochen hat, ist dieselbe Kette.
#
# Weil das Muster nur in Verschleierung vorkommt, wertet 7.3 es UNABHAENGIG
# von der Groesse als Stufe 1. Die Groessenschwelle DROPPER_MAX_BYTES trennt
# Dropper von Frameworks, die dieselben Funktionen legitim benutzen — fuer
# eine Hex-Ternaer-Kette gibt es diesen legitimen Fall nicht.
HEX_TERNAER_REGEX='(\(\s*0x[0-9a-f]+\s*\)\s*\?\s*0x[0-9a-f]+\s*:\s*){20}'

# ── Suchraum der Mustersuche: PHP ist nicht nur, was .php heisst (#144) ─────
#
# Dieselbe Datei wie oben fiel schon vor dem Muster durch: 7.3 suchte mit
# `--include="*.php"`, und german.php.bak heisst nicht so. Sie stand im
# Inventar (belege/00_dateien.tsv) und sonst nirgends.
#
# Ein Webserver fuehrt .php.bak nicht aus — aber `include`/`require` fragt
# nicht nach der Endung. Ein einziges include "german.php.bak" in einer
# harmlosen Datei, und der Code laeuft. Merkregel aus frueheren Faellen:
# Schadcode nach Dateikopf und Groesse suchen, nicht nach Endung.
#
# Die Endung erweitert NUR den Suchraum. Ob eine Datei ein Befund wird,
# entscheiden allein die Muster: eine Editor-Sicherung upgrade.php~ ohne
# Schadmuster bleibt unsichtbar, wie ihr Original.
PHP_SUCHRAUM_INCLUDE=(--include='*.php' --include='*.php.*' --include='*.php~'
                      --include='*.phtml' --include='*.php[3-8]' --include='*.phar'
                      --include='*.inc' --include='*.phps')
# Dieselbe Menge als ERE fuer awk (Pfad kleingeschrieben). Was hierauf passt,
# deckt der grep oben bereits ab und wird bei der Kopfsuche uebersprungen.
PHP_SUCHRAUM_ERE='\.(php|phtml|php[3-8]|phar|inc|phps|php~)$|\.php\.[^/]*$'
# Endungen, deren Kopf NICHT gelesen wird: Medien und Schriften sind Sache von
# 7.13 (dort ohne Kopfbedingung, auch PHP mitten im Bild), Archive und .mo
# sind binaer und koennen nicht mit "<?php" beginnen, kosten aber das Lesen.
PHP_KOPF_OHNE_ERE='\.(png|jpe?g|gif|webp|bmp|ico|svg|tiff?|woff2?|ttf|otf|eot|pdf|mp3|mp4|wav|avi|mov|wmv|mpe?g|m4v|mkv|webm|flv|ogg|oga|ogv|aac|flac|m4a|wma|zip|gz|tgz|bz2|xz|7z|rar|tar|mo)$'
# Verzeichnisse ohne Kopfsuche: Seiten-Caches (zehntausende erzeugte Dateien)
# und Abhaengigkeiten, dazu die Testframeworks, die 7.3 ohnehin auslaesst.
PHP_KOPF_OHNE_DIR_ERE='/(cache|node_modules|\.git|phpunit|sebastian|mockery)/'
# Obergrenze fuer die Kopfsuche in KiB. Ein Dropper ist klein; die Grenze haelt
# Datenbank-Abzuege und Logs heraus, deren Kopf zu lesen nichts kostet, deren
# Mustersuche aber sehr wohl.
PHP_KOPF_MAX_KIB="${PHP_KOPF_MAX_KIB:-2048}"
