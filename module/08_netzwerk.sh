# NT-Forensik — Abschnitt 8: Netzwerk & Dienste
#
# @nummer:  8
# @titel:   Netzwerk & Dienste
# @frage:   Läuft ein Fernzugriff, ein Miner oder ein getarnter Prozess?
# @kosten:  mittel
# @ebene:   system
#
# Wird vom Runner eingebunden, nicht einzeln ausgefuehrt.
# Vorgabewerte der hier gefuellten Variablen: lib/befunde.sh

h1 "8. NETZWERK & DIENSTE"
# ============================================================

h2 "8.1 Offene Ports und lauschende Dienste"
OPEN_PORTS=$(ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null || echo "ss/netstat nicht verfügbar")
code "$OPEN_PORTS"
evidence "offene_ports" "$OPEN_PORTS"

UNEXPECTED=$(ss -tlnp 2>/dev/null | grep -vE ":22 |:80 |:443 |:8443 |:8880 |:21 |:25 |:465 |:587 |:110 |:143 |:993 |:995 |:3306 |:5432 |:53 |:106 |:990 " \
  | grep LISTEN || true)
if [[ -n "$UNEXPECTED" ]]; then
  warn "Unerwartete lauschende Ports — manuell verifizieren"
  code "$UNEXPECTED"
fi

h2 "8.2 Prozess-Forensik"
evidence "prozessliste_voll" "$(ps auxf 2>/dev/null || true)"

# 8.2a Top-CPU/RAM (Krypto-Miner, Spam-Bots)
TOP_CPU=$(ps aux --sort=-%cpu 2>/dev/null | head -8 || true)
info "Top-Prozesse nach CPU:"
code "$TOP_CPU"
MINER_PROCS=$(ps aux 2>/dev/null | grep -iE "xmrig|minerd|kinsing|kdevtmpfsi|cryptonight|stratum\+tcp" | grep -v grep || true)
if [[ -n "$MINER_PROCS" ]]; then
  crit "Krypto-Miner-Prozess erkannt!"
  code "$MINER_PROCS"
  evidence "miner_prozesse" "$MINER_PROCS"
else
  ok "Keine bekannten Miner-Prozessnamen"
fi

# 8.2b Prozesse mit gelöschtem Binary
# Nur kritisch, wenn das gelöschte Ziel NICHT ein Standard-Systempfad ist.
# Nach apt/dpkg-Upgrades laufen Alt-Prozesse legitim mit "(deleted)" auf
# /usr/bin/python3.10 etc. — das ist KEINE Malware.
DELETED_ALL=$(ls -l /proc/[0-9]*/exe 2>/dev/null | grep "(deleted)" || true)
DELETED_SUSPECT=""
DELETED_BENIGN=0
if [[ -n "$DELETED_ALL" ]]; then
  while IFS= read -r line; do
    tgt=$(echo "$line" | sed -n 's/.*-> \(.*\) (deleted)/\1/p')
    case "$tgt" in
      /usr/bin/*|/usr/sbin/*|/bin/*|/sbin/*|/lib/*|/lib64/*|/usr/lib/*|/usr/lib64/*|/opt/plesk/*|/usr/local/*)
        DELETED_BENIGN=$((DELETED_BENIGN+1)) ;;   # Upgrade-Rest, gutartig
      *)
        DELETED_SUSPECT+="$line"$'\n' ;;          # /tmp, /dev/shm, memfd, Webspace, unlink
    esac
  done <<< "$DELETED_ALL"
fi
if [[ -n "$DELETED_SUSPECT" ]]; then
  crit "Prozess(e) mit gelöschtem Binary auf Nicht-Systempfad — typisch für Malware"
  code "$DELETED_SUSPECT"
  evidence "prozesse_geloeschte_binaries" "$DELETED_SUSPECT"
else
  ok "Keine verdächtigen gelöschten Binaries (${DELETED_BENIGN} gutartige Upgrade-Reste ignoriert)"
fi

# 8.2c Prozesse, die aus /tmp, /dev/shm, /var/tmp oder dem Webspace laufen
PROCS_BAD_PATH=""
for pid in /proc/[0-9]*; do
  exe=$(readlink "$pid/exe" 2>/dev/null) || continue
  case "$exe" in
    /tmp/*|/var/tmp/*|/dev/shm/*|${VHOSTS_DIR}/*)
      PROCS_BAD_PATH+="PID $(basename "$pid"): $exe — $(tr '\0' ' ' < "$pid/cmdline" 2>/dev/null | head -c 200)"$'\n' ;;
  esac
done
if [[ -n "$PROCS_BAD_PATH" ]]; then
  crit "Prozesse laufen aus tmp-/Webspace-Verzeichnissen!"
  code "$PROCS_BAD_PATH"
  evidence "prozesse_verdaechtige_pfade" "$PROCS_BAD_PATH"
else
  ok "Keine Prozesse aus /tmp, /dev/shm oder Webspace"
fi

# 8.2d Reverse-Shell-Muster in Prozess-Kommandozeilen
REVSHELL=$(ps auxww 2>/dev/null \
  | grep -E "bash -i|nc -e|nc -c|/dev/tcp/|python.{0,40}socket\.socket|perl.{0,40}Socket|php -r.{0,40}fsockopen|socat.{0,20}exec" \
  | grep -vE "grep|wp_plesk_forensik" || true)
if [[ -n "$REVSHELL" ]]; then
  crit "Reverse-Shell-Muster in laufenden Prozessen!"
  code "$REVSHELL"
  evidence "reverse_shell_prozesse" "$REVSHELL"
else
  ok "Keine Reverse-Shell-Muster in Prozessliste"
fi

# 8.2e Langlaufende Prozesse der Web-User (psacln/psaserv/www-data)
WEBUSER_PROCS=$(ps -eo user,pid,etime,pcpu,cmd --sort=-etime 2>/dev/null \
  | awk '$1 ~ /^(psacln|psaserv|www-data)/ || $1 ~ /^web[0-9]/' \
  | grep -vE "php-fpm|apache|nginx" | head -15 || true)
if [[ -n "$WEBUSER_PROCS" ]]; then
  warn "Web-User haben eigene (Nicht-PHP-FPM-)Prozesse — prüfen"
  code "$WEBUSER_PROCS"
  evidence "webuser_prozesse" "$WEBUSER_PROCS"
else
  ok "Keine auffälligen Web-User-Prozesse"
fi

h2 "8.3 Aktive Netzwerkverbindungen"
ACTIVE_CONNS=$(ss -tnp 2>/dev/null | grep ESTAB | head -25 || true)
code "$ACTIVE_CONNS"
evidence "aktive_verbindungen" "$ACTIVE_CONNS"

h2 "8.4 DNS-Records prüfen"
if [[ -n "$DOMAIN" ]] && command -v dig &>/dev/null; then
  DNS_INFO="A-Record:   $(dig +short A "$DOMAIN" 2>/dev/null | tr '\n' ' ')
MX-Record:  $(dig +short MX "$DOMAIN" 2>/dev/null | tr '\n' ' ')
NS-Record:  $(dig +short NS "$DOMAIN" 2>/dev/null | tr '\n' ' ')
TXT-Record: $(dig +short TXT "$DOMAIN" 2>/dev/null | head -5 | tr '\n' ' ')"
  code "$DNS_INFO"
  evidence "dns_records" "$DNS_INFO"
  info "Bitte manuell verifizieren, ob diese Records korrekt sind"
elif [[ -n "$DOMAIN" ]]; then
  warn "dig nicht verfügbar — DNS manuell prüfen"
fi

h2 "8.5 Mailqueue (Spam-Versand-Indikator)"
if command -v postqueue &>/dev/null; then
  QUEUE_COUNT=$(postqueue -p 2>/dev/null | tail -1 | grep -oE "[0-9]+ Request" | grep -oE "[0-9]+" || echo "0")
  QUEUE_COUNT=${QUEUE_COUNT:-0}
  info "Mails in Postfix-Queue: $QUEUE_COUNT"
  if [[ "$QUEUE_COUNT" -gt 100 ]]; then
    crit "Mailqueue ungewöhnlich voll ($QUEUE_COUNT) — Spam-Versand möglich!"
    evidence "mailqueue" "$(postqueue -p 2>/dev/null | head -60)"
  elif [[ "$QUEUE_COUNT" -gt 20 ]]; then
    warn "Mailqueue erhöht ($QUEUE_COUNT) — beobachten"
    evidence "mailqueue" "$(postqueue -p 2>/dev/null | head -60)"
  else
    ok "Mailqueue unauffällig ($QUEUE_COUNT)"
  fi
else
  info "postqueue nicht verfügbar — Mailqueue manuell prüfen"
fi

h2 "8.6 Paketintegrität Kern-Binaries (dpkg -V)"
if command -v dpkg &>/dev/null; then
  # '5' an Position 3 = MD5-Mismatch gegen Paketdatenbank; Binaries in bin/sbin
  PKG_MODIFIED=$(dpkg -V bash coreutils openssh-server openssh-client curl wget cron 2>/dev/null \
    | grep -E "^..5" | grep -E "/(s?bin)/" || true)
  if [[ -n "$PKG_MODIFIED" ]]; then
    crit "System-Binaries weichen von Paketdatenbank ab — Manipulations-Verdacht!"
    code "$PKG_MODIFIED"
    evidence "manipulierte_binaries" "$PKG_MODIFIED
$(echo "$PKG_MODIFIED" | awk '{print $NF}' | xargs -r sha256sum 2>/dev/null)"
  else
    ok "Kern-Binaries (bash, ssh, curl, wget, cron) stimmen mit Paketdatenbank überein"
  fi
  # debsums ergänzt dpkg -V: prüft die md5-Summen der installierten Paketdateien
  # gegen die bei der Installation gespeicherten. Bewusst auf dieselbe kritische
  # Paketmenge begrenzt — debsums liest Dateiinhalte, über ALLE Pakete wäre es
  # (wie 7.11/8.7) zu teuer. Fund fließt in PKG_MODIFIED → Root-Verdikt (11.5).
  if command -v debsums &>/dev/null; then
    DEBSUMS_BAD=$(debsums -c bash coreutils openssh-server openssh-client curl wget cron 2>/dev/null || true)
    if [[ -n "$DEBSUMS_BAD" ]]; then
      crit "debsums: veränderte Paketdateien in Kern-Paketen — Manipulations-Verdacht"
      code "$DEBSUMS_BAD"
      evidence "debsums_changed" "$DEBSUMS_BAD
$(printf '%s\n' "$DEBSUMS_BAD" | xargs -r sha256sum 2>/dev/null)"
      PKG_MODIFIED+=$'\n'"$DEBSUMS_BAD"
    else
      ok "debsums: Kern-Paketdateien unverändert (md5 gegen Installationsstand)"
    fi
  else
    info "debsums nicht installiert — ergänzende md5-Paketprüfung übersprungen (apt install debsums)"
  fi
fi

h2 "8.7 Relay-Backdoors (THC gsocket / gs-netcat)"
# gsocket öffnet KEINEN Port. Beide Seiten verbinden sich ausgehend über
# TLS/443 zu einem Relay (GSRN) und finden sich über ein gemeinsames
# Geheimnis. Abschnitt 8.1 (LISTEN-Ports) ist dagegen blind — deshalb
# hier eigens Datei-, Prozess- und Verbindungsebene.
# Scope wie 7.10/7.11: System-Dirs voll, vhost-Teil nur ${SCAN_PATH} (der
# serverweite Voll-Scan über alle vhosts bleibt dem Global-Modus ab v3.5
# vorbehalten — über hunderte vhosts liest der Scan jede Datei und ist auf
# Shared-Hosts nicht tragbar).
# Umsetzung als find | grep statt grep -r: die Größengrenze -size -30M
# überspringt Backup-Archive und Quarantäne-Dumps (auf Produktions-Root
# schnell dutzende GB), die der Regex sonst byteweise durchkämmt. Die gesuchte
# gs-netcat-Binary ist ~2,8 MB und bleibt damit erfasst. nf_strip_self prunt
# den eigenen Ablageordner ${BASE_DIR} VOR dem Lesen. grep -a (ohne -I!) ist
# Absicht: -I würde Binärdateien überspringen und genau die ELF-Backdoor
# nie lesen.
GS_FILE_HITS=$(find /tmp /var/tmp /dev/shm /root /home /usr/local/bin /usr/local/sbin /opt "$SCAN_PATH" \
    -xdev -type f -size -30M 2>/dev/null | nf_strip_self \
    | xargs -r -d '\n' grep -la -E "$GS_SIG_REGEX" 2>/dev/null \
    | grep -vF "$INSTALLED_PATH" || true)
if [[ -n "$GS_FILE_HITS" ]]; then
    # Differenzierung nach Dateityp — ohne sie erzeugt jede Dokumentation und
    # jede Signaturdatei, die die Begriffe nennt, einen Fehlalarm:
    #   ELF-Binary   → das Werkzeug selbst liegt auf dem System (kritisch)
    #   Skript/Text  → Installer, Konfiguration oder nur eine Erwähnung (Review)
    GS_ELF=""; GS_TEXT=""
    while IFS= read -r f; do
        [[ -f "$f" ]] || continue
        line="$(ls -la --time-style=long-iso "$f" 2>/dev/null)  SHA256: $(sha256sum "$f" 2>/dev/null | awk '{print $1}')"
        magic=$(head -c4 "$f" 2>/dev/null | od -An -tx1 2>/dev/null | tr -d ' \n')
        if [[ "$magic" == "7f454c46" ]]; then
            GS_ELF+="$line"$'\n'
            GSOCKET_HITS+="$f"$'\n'
        else
            GS_TEXT+="$line"$'\n'
        fi
    done <<< "$GS_FILE_HITS"

    if [[ -n "$GS_ELF" ]]; then
        crit "gs-netcat-Binary auf dem System gefunden — interaktive Relay-Backdoor"
        code "$GS_ELF"
        evidence "gsocket_binaries" "$GS_ELF"
    fi
    if [[ -n "$GS_TEXT" ]]; then
        warn "gsocket-Begriffe in Nicht-Binärdateien (Installer, Konfig oder bloße Erwähnung) — manuell einordnen"
        code "$GS_TEXT"
        evidence "gsocket_textfunde" "$GS_TEXT"
    fi
else
    ok "Keine gsocket-Signaturen im Dateisystem"
fi

GS_PROC_HITS=$(ps -eo pid,ppid,user,etime,args 2>/dev/null \
    | grep -iE "$GS_SIG_REGEX|$GS_DISGUISE_REGEX" \
    | grep -vE "grep|wp_plesk_forensik" || true)
if [[ -n "$GS_PROC_HITS" ]]; then
    crit "gsocket-typischer Prozess läuft"
    code "$GS_PROC_HITS"
    evidence "gsocket_prozesse" "$GS_PROC_HITS"
    GSOCKET_HITS+="(Prozess) $(echo "$GS_PROC_HITS" | head -1)"$'\n'
else
    ok "Kein gsocket-typischer Prozessname"
fi

h2 "8.8 Fileless-Prozesse (memfd — Binary nur im RAM)"
# memfd_create() führt ein Binary aus, das nie auf der Platte landet.
# Kein Dateiscanner der Welt findet das; nur /proc verrät es.
# Abschnitt 8.2b sieht solche Prozesse zwar als "(deleted)", benennt
# aber die Ursache nicht — und die ist für die Bewertung entscheidend.
MEMFD_DETAIL=""
for pid in /proc/[0-9]*; do
    nf_is_self "$(basename "$pid")" && continue
    exe=$(readlink "$pid/exe" 2>/dev/null) || continue
    case "$exe" in
        *memfd:*)
            p=$(basename "$pid")
            MEMFD_DETAIL+="PID $p — $exe
  comm:    $(cat "$pid/comm" 2>/dev/null)
  cmdline: $(tr '\0' ' ' < "$pid/cmdline" 2>/dev/null | head -c 200)
  user:    $(stat -c %U "$pid" 2>/dev/null)
  ppid:    $(awk '/^PPid:/{print $2}' "$pid/status" 2>/dev/null)
"
            FILELESS_PROCS+="PID $p: $exe"$'\n' ;;
    esac
done
if [[ -n "$MEMFD_DETAIL" ]]; then
    crit "Prozess(e) laufen ausschließlich aus dem Arbeitsspeicher (memfd) — fileless Malware"
    code "$MEMFD_DETAIL"
    evidence "fileless_memfd_prozesse" "$MEMFD_DETAIL"
else
    ok "Keine memfd-Prozesse (keine fileless Ausführung)"
fi

h2 "8.9 Als Kernel-Thread getarnte Prozesse"
# Echte Kernel-Threads haben eckige Klammern im Namen, PPID 2 (kthreadd)
# UND kein /proc/PID/exe. Ein User-Prozess, der sich [kworker/…] nennt,
# verrät sich über genau diese beiden Merkmale.
# Die Tarnung kann über comm (prctl PR_SET_NAME) ODER über argv[0]
# (exec -a, in `ps` sichtbar) laufen — beide sind gratis fälschbar, daher
# werden beide geprüft. comm allein würde eine reine argv[0]-Tarnung
# übersehen, obwohl sie in der Prozessliste wie ein Kernel-Thread aussieht.
KTHREAD_DETAIL=""
for pid in /proc/[0-9]*; do
    nf_is_self "$(basename "$pid")" && continue
    comm=$(cat "$pid/comm" 2>/dev/null) || continue
    argv0=$(tr '\0' '\n' < "$pid/cmdline" 2>/dev/null | head -1)
    # kthread-typisch tarnt sich, wenn comm ODER argv[0] mit '[' beginnt
    if [[ "$comm" == \[* || "$argv0" == \[* ]]; then
        ppid=$(awk '/^PPid:/{print $2}' "$pid/status" 2>/dev/null)
        exe=$(readlink "$pid/exe" 2>/dev/null)
        # Beweis: echte Kernel-Threads haben KEIN exe und PPID 2. Ein Treffer
        # mit vorhandenem exe oder fremder PPID ist damit belastbar (crit).
        if [[ -n "$exe" ]] || { [[ -n "$ppid" ]] && [[ "$ppid" != "2" ]] && [[ "$ppid" != "0" ]]; }; then
            p=$(basename "$pid")
            [[ "$comm" == \[* ]] && vektor="comm='$comm'" || vektor="argv[0]='$argv0'"
            KTHREAD_DETAIL+="PID $p gibt sich als Kernel-Thread aus ($vektor)
  comm: $comm
  argv[0]: ${argv0:-<leer>}
  exe:  ${exe:-<keins>}
  ppid: ${ppid:-?} (echte Kernel-Threads: 2)
  user: $(stat -c %U "$pid" 2>/dev/null)
"
            KTHREAD_FAKES+="PID $p: ${comm}${argv0:+ / $argv0}"$'\n'
        fi
    fi
done
if [[ -n "$KTHREAD_DETAIL" ]]; then
    crit "Prozess(e) tarnen sich als Kernel-Thread"
    code "$KTHREAD_DETAIL"
    evidence "kernel_thread_tarnung" "$KTHREAD_DETAIL"
else
    ok "Keine als Kernel-Thread getarnten Prozesse"
fi

h2 "8.10 Verwaiste Interpreter ohne Terminal"
# Eine Shell mit PPID 1 und ohne kontrollierendes TTY hat keinen
# Benutzer am anderen Ende — das ist das Profil einer abgesetzten
# Reverse-Shell, die den Elternprozess überlebt hat.
ORPHAN_DETAIL=""
for pid in /proc/[0-9]*; do
    nf_is_self "$(basename "$pid")" && continue
    comm=$(cat "$pid/comm" 2>/dev/null) || continue
    case "$comm" in
        sh|bash|dash|zsh|ksh|perl|python|python3|ruby|php|nc|ncat|socat)
            ppid=$(awk '/^PPid:/{print $2}' "$pid/status" 2>/dev/null)
            tty=$(awk '{print $7}' "$pid/stat" 2>/dev/null)
            if [[ "$ppid" == "1" ]] && [[ "${tty:-0}" == "0" ]]; then
                p=$(basename "$pid")
                ORPHAN_DETAIL+="PID $p ($comm) — PPID 1, kein TTY
  cmdline: $(tr '\0' ' ' < "$pid/cmdline" 2>/dev/null | head -c 200)
  user:    $(stat -c %U "$pid" 2>/dev/null)
  cwd:     $(readlink "$pid/cwd" 2>/dev/null)
"
                ORPHAN_SHELLS+="PID $p: $comm"$'\n'
            fi ;;
    esac
done
if [[ -n "$ORPHAN_DETAIL" ]]; then
    warn "Verwaiste Shell(s)/Interpreter ohne Terminal — mit laufenden Diensten abgleichen"
    code "$ORPHAN_DETAIL"
    evidence "verwaiste_interpreter" "$ORPHAN_DETAIL"
else
    ok "Keine verwaisten Interpreter ohne TTY"
fi

h2 "8.11 Prozess-Umgebung auf Backdoor-Marker"
# GSOCKET_*/GS_ARGS verrät gsocket auch dann, wenn das Binary umbenannt
# wurde. LD_PRELOAD in einem einzelnen Prozess ist Hooking ohne Eintrag
# in /etc/ld.so.preload. HISTFILE=/dev/null ist Spurenvermeidung.
ENV_DETAIL=""
for pid in /proc/[0-9]*; do
    [[ -r "$pid/environ" ]] || continue
    if grep -aqE "GSOCKET_|GS_ARGS=|LD_PRELOAD=|HISTFILE=/dev/null|HISTSIZE=0" "$pid/environ" 2>/dev/null; then
        p=$(basename "$pid")
        nf_is_self "$p" && continue
        ENV_DETAIL+="PID $p ($(cat "$pid/comm" 2>/dev/null)) — $(tr '\0' ' ' < "$pid/cmdline" 2>/dev/null | head -c 120)
$(tr '\0' '\n' < "$pid/environ" 2>/dev/null | grep -aE "GSOCKET_|GS_ARGS=|LD_PRELOAD=|HISTFILE=|HISTSIZE=" | sed 's/^/  /')
"
    fi
done
if [[ -n "$ENV_DETAIL" ]]; then
    crit "Prozess(e) mit Backdoor-typischen Umgebungsvariablen"
    code "$ENV_DETAIL"
    evidence "prozess_umgebung_marker" "$ENV_DETAIL"
else
    ok "Keine Backdoor-Marker in Prozess-Umgebungen"
fi

h2 "8.12 Ausgehende Verbindungen (Relay-Erkennung)"
# Der eigentliche Kanal einer Relay-Backdoor. Ausgehend auf 443 sieht
# wie normales HTTPS aus — auffällig wird es durch den Prozess, der die
# Verbindung hält. Bekannte Web-/Update-/Monitoring-Clients sind
# ausgenommen; alles andere auf 443/7350 ist erklärungsbedürftig.
#
# WICHTIG — nur der PEER-Port zählt: Auf einem Webserver hat jede eingehende
# HTTPS-Verbindung lokal Port 443. Ein simples grep ':443 ' trifft dieses
# lokale Feld und meldet dann jeden Besucher als Relay-Verdacht — auf einem
# Produktions-Plesk sind das dutzende Fehlalarme pro Lauf (gemessen: 76
# eingehende vs. 2 echte ausgehende). Eine Relay-Backdoor verbindet sich
# AUSGEHEND, d. h. der ENTFERNTE Port ist 443/7350. Wir werten deshalb
# ausschließlich das Peer-Feld ($5 in `ss`: Netid Recv-Q Send-Q Local Peer
# Process) aus.
if command -v ss &>/dev/null; then
    ESTAB=$(ss -tunp state established 2>/dev/null || true)
    evidence "verbindungen_etabliert" "$ESTAB"

    RELAY_SUSPECT=$(echo "$ESTAB" \
        | awk 'NR>1 { n=split($5,a,":"); pp=a[n]; if (pp=="443" || pp=="7350") print }' \
        | grep -viE 'users:\(\("(nginx|apache2?|httpd|curl|wget|php-fpm[0-9.]*|php|node|containerd|dockerd|packagekitd?|snapd|unattended-upgr|apt|apt-get|aptd|systemd-resolve|chronyd?|ntpd|fail2ban-server|certbot|git|ssh|sshd|tailscaled|sw-engine|psa|plesk|mysqld|postfix|dovecot|python3?)"' || true)
    if [[ -n "$RELAY_SUSPECT" ]]; then
        crit "Ausgehende TLS-Verbindung durch untypischen Prozess — Relay-Backdoor-Verdacht"
        code "$RELAY_SUSPECT"
        evidence "relay_verdaechtige_verbindungen" "$RELAY_SUSPECT"
        RELAY_CONNECTIONS+="$RELAY_SUSPECT"$'\n'
    else
        ok "Keine untypischen ausgehenden 443/7350-Verbindungen"
    fi

    TOR_CONN=$(echo "$ESTAB" \
        | awk 'NR>1 { n=split($5,a,":"); pp=a[n]; if (pp=="9001"||pp=="9030"||pp=="9050"||pp=="9150") print }' || true)
    if [[ -n "$TOR_CONN" ]]; then
        warn "TOR-typische Verbindung(en) — gsocket kann optional über TOR routen"
        code "$TOR_CONN"
        evidence "tor_verbindungen" "$TOR_CONN"
    else
        ok "Keine TOR-typischen Verbindungen"
    fi
else
    warn "'ss' nicht verfügbar — ausgehende Verbindungen nicht prüfbar"
fi

h2 "8.13 Kürzlich veränderte Systemdateien & Zeitstempel-Manipulation (referenzlos)"
# Ohne Baseline: in Verzeichnissen, die im Normalbetrieb STABIL sind (kein Paket
# schreibt dort), ist eine kürzlich geänderte/neue Datei erklärungsbedürftig.
# ctime (Inode-Änderungszeit) lässt sich mit `touch -d` NICHT zurückdatieren —
# das setzt nur mtime/atime. Ein Angreifer, der mtime fälscht, verrät sich über
# die Diskrepanz. Nur stat-Traversierung (kein Dateiinhalt) → schnell.
INTEG_DIRS=(/usr/local/bin /usr/local/sbin /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/systemd/system /etc/init.d)
RECENT_SYS=""; TIMESTOMP=""
_have_dpkg=0; command -v dpkg &>/dev/null && _have_dpkg=1
while IFS= read -r f; do
    [[ -f "$f" ]] || continue
    ct=$(stat -c %Z "$f" 2>/dev/null); mt=$(stat -c %Y "$f" 2>/dev/null)
    [[ -z "$ct" || -z "$mt" ]] && continue
    # Paketverwaltete Dateien ausschließen: deren mtime ist das (alte) Build-Datum,
    # die ctime das (neue) Installations-/Update-Datum — das ist KEIN Timestomping,
    # sondern normales Paketverhalten. Inhaltsmanipulation solcher Dateien fängt
    # 8.6 (dpkg -V/debsums). Nur NICHT-paketierte Dateien sind hier belastbar.
    if [[ "$_have_dpkg" == 1 ]] && dpkg -S "$f" &>/dev/null; then continue; fi
    line="$(stat -c 'ctime %z | mtime %y | %n' "$f" 2>/dev/null)"
    if (( ct - mt > 7776000 )); then
        # Inode kürzlich geändert, mtime aber künstlich >90 Tage davor: Timestomping.
        TIMESTOMP+="$line"$'\n'
    else
        RECENT_SYS+="$line"$'\n'
    fi
done < <(find "${INTEG_DIRS[@]}" -xdev -type f -ctime -"${DAYS_BACK}" -not -path "${BASE_DIR}/*" 2>/dev/null | head -300)

if [[ -n "$TIMESTOMP" ]]; then
    crit "Zeitstempel-Manipulation (Timestomping): Datei(en) mit künstlich zurückdatiertem mtime"
    code "$TIMESTOMP"
    evidence "timestomp" "$TIMESTOMP"
fi
if [[ -n "$RECENT_SYS" ]]; then
    warn "Kürzlich veränderte Dateien in normalerweise stabilen Systemverzeichnissen — gegen Wartungsfenster/Paket-Updates abgleichen"
    code "$(printf '%s' "$RECENT_SYS" | head -60)"
    evidence "recent_system_changes" "$RECENT_SYS"
elif [[ -z "$TIMESTOMP" ]]; then
    ok "Keine kürzlich veränderten Dateien in stabilen Systemverzeichnissen (${DAYS_BACK} Tage)"
fi

h2 "8.14 AIDE-Integritätsabgleich (dauerhafte FIM, falls eingerichtet)"
# AIDE ist eine echte Baseline-Datenbank — nur aussagekräftig, wenn sie VOR
# einer Kompromittierung erstellt wurde. Das Skript NUTZT eine vorhandene DB
# (read-only), erstellt/aktualisiert sie aber NICHT. Config-Vorlage:
# haertung/aide-forensik.conf. `aide --check` liest Inhalte und kann dauern —
# läuft daher nur, wenn AIDE bereits eingerichtet ist (bewusste Entscheidung).
if command -v aide &>/dev/null; then
    AIDE_DB=$(ls /var/lib/aide/aide.db /var/lib/aide/aide.db.gz 2>/dev/null | head -1 || true)
    if [[ -n "$AIDE_DB" ]]; then
        AIDE_OUT=$(aide --check 2>/dev/null | grep -E '^(Added|Removed|Changed|Total|Number)' | head -40 || true)
        if echo "$AIDE_OUT" | grep -qE '(Added|Removed|Changed).*entries:[[:space:]]*[1-9]'; then
            crit "AIDE meldet Abweichungen zur Integritäts-Baseline"
            code "$AIDE_OUT"
            evidence "aide_check" "$AIDE_OUT"
        else
            ok "AIDE-Abgleich ohne Abweichungen zur Baseline"
        fi
    else
        info "AIDE installiert, aber keine Baseline-DB — mit 'aide --init' anlegen (Vorlage: haertung/aide-forensik.conf)"
    fi
else
    info "AIDE nicht installiert — dauerhafte Datei-Integritätsüberwachung nicht aktiv (Härtung: haertung/aide-forensik.conf)"
fi

h2 "8.15 Imunify-Malware-Datenbank (autoritativer Scanner, read-only)"
# Plesk/Imunify betreibt einen eigenen signaturbasierten Malware-Scanner mit
# gepflegter Datenbank und Cloud-Heuristik. Statt diese Erkennung nachzubauen,
# LESEN wir ihr Ergebnis (Status "found" = erkannt, noch nicht bereinigt).
# Es wird KEIN Scan ausgelöst — nur die bestehende DB abgefragt (read-only).
# Scope-aware: bei --domain/--path nur Treffer unterhalb ${SCAN_PATH}.
IMU_BIN=""
for _c in imunify-antivirus imunify360-agent; do command -v "$_c" &>/dev/null && { IMU_BIN="$_c"; break; }; done
if [[ -n "$IMU_BIN" ]] && command -v python3 &>/dev/null; then
    # --limit hoch: die Standardausgabe liefert nur 50 Einträge; ohne dies
    # würde der Scope-Filter (und die Zählung) auf Servern mit vielen Treffern
    # unvollständig bleiben.
    IMU_JSON=$("$IMU_BIN" malware malicious list --json --by-status found --limit 100000 2>/dev/null || true)
    IMU_REPORT=$(SCOPE_PATH="$SCAN_PATH" VHOSTS="$VHOSTS_DIR" python3 -c '
import sys, os, json, re
try: d = json.loads(sys.stdin.read())
except Exception: sys.exit(0)
items = d.get("items", []) if isinstance(d, dict) else (d if isinstance(d, list) else [])
sp = os.environ.get("SCOPE_PATH", ""); vh = os.environ.get("VHOSTS", "/var/www/vhosts")
glob = (sp == vh or not sp)
# Quarantäne-/Backup-Pfade sind bereits eingedämmt, nicht live.
qpat = re.compile(r"/(schadcode|quarant\w*|backup|_?bak|altkopie|sicherung)(/|_|\.)", re.I)
def keep(i):
    f = str(i.get("file", ""))
    if not (glob or f.startswith(sp)): return False
    if qpat.search(f): return False            # eingedämmt/Backup, kein Live-Fund
    if not os.path.isfile(f): return False     # Imunify-DB veraltet: Datei existiert nicht mehr
    return True
sel = [i for i in items if keep(i)]
print("COUNT=%d" % len(sel))
for i in sel[:60]:
    print("%s  [%s]  %s" % (i.get("file"), i.get("type",""), str(i.get("hash",""))[:16]))
' <<<"$IMU_JSON")
    IMU_COUNT=$(printf '%s\n' "$IMU_REPORT" | sed -n 's/^COUNT=//p')
    IMU_LIST=$(printf '%s\n' "$IMU_REPORT" | grep -v '^COUNT=' || true)
    if [[ "${IMU_COUNT:-0}" -gt 0 ]]; then
        crit "Imunify meldet ${IMU_COUNT} nicht bereinigte Malware-Datei(en) im Prüf-Scope" web
        code "$IMU_LIST"
        evidence "imunify_malware" "Scanner: $IMU_BIN, Status=found, Scope=$SCAN_PATH
$IMU_LIST"
        IMUNIFY_HITS="$IMU_LIST"
    else
        ok "Imunify: keine offenen Malware-Treffer im Prüf-Scope (Status found)"
    fi
elif [[ -n "$IMU_BIN" ]]; then
    info "Imunify vorhanden ($IMU_BIN), aber python3 fehlt — DB nicht ausgewertet"
else
    info "Imunify-CLI nicht gefunden — autoritative Scanner-DB nicht abgefragt"
fi

# ============================================================
