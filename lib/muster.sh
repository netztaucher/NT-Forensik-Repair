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
