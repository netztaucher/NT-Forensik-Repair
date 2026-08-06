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
# daher konsequent gegen ${BASE_DIR}.
nf_strip_self() { grep -vF "${BASE_DIR}/" || true; }

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
