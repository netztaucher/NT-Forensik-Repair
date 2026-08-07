# shellcheck shell=bash
# NT-Forensik — Abschnitt 6: Cronjobs & Persistenz
#
# @nummer:  6
# @titel:   Cronjobs & Persistenz
# @frage:   Hat sich etwas eingerichtet, das den Neustart überlebt?
# @kosten:  gering
# @ebene:   system
#
# Wird vom Runner eingebunden, nicht einzeln ausgefuehrt.
# Vorgabewerte der hier gefuellten Variablen: lib/befunde.sh

h1 "6. CRONJOBS & PERSISTENZ"
# ============================================================

h2 "6.1 Root-Crontab"
# 'crontab -l' liefert Rueckgabewert 1 sowohl bei "keine Crontab vorhanden"
# als auch bei "Zugriff verweigert" oder fehlendem cron. Der Unterschied
# entscheidet, ob hier nichts steht oder ob nichts gelesen werden konnte.
ROOT_CRON=$(crontab -l 2>&1); _cron_rc=$?
if [[ $_cron_rc -ne 0 ]] && ! printf '%s' "$ROOT_CRON" | grep -qiE 'no crontab for'; then
  unklar "Root-Crontab nicht lesbar — Persistenz ueber cron nicht geprueft ($(printf '%s' "$ROOT_CRON" | tr -d '\n' | cut -c1-80))"
  ROOT_CRON=""
elif [[ $_cron_rc -ne 0 ]]; then
  ROOT_CRON="(keine Crontab fuer root)"
fi
code "$ROOT_CRON"

h2 "6.2 System-Cronjobs"
SYSTEM_CRONS=$(ls -la /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/ /etc/cron.weekly/ 2>/dev/null || true)
code "$SYSTEM_CRONS"

SUSP_CRON=$(find /etc/cron* /var/spool/cron -type f 2>/dev/null \
  | xargs grep -lE "curl|wget|bash.*http|base64|nc -" 2>/dev/null || true)
if [[ -n "$SUSP_CRON" ]]; then
  crit "Verdächtige Cronjobs gefunden"
  code "$SUSP_CRON"
  CRON_CONTENT=""
  while IFS= read -r cf; do
    CRON_CONTENT+="=== $cf ==="$'\n'"$(cat "$cf" 2>/dev/null)"$'\n'
    code "$(cat "$cf" 2>/dev/null)"
  done <<< "$SUSP_CRON"
  evidence "verdaechtige_cronjobs" "$CRON_CONTENT"
else
  ok "Keine offensichtlich verdächtigen Cronjobs"
fi

h2 "6.3 Alle Benutzer-Crontabs"
ALL_USER_CRONS=""
for user in $(cut -f1 -d: /etc/passwd); do
  UCRON=$(crontab -u "$user" -l 2>/dev/null || true)
  if [[ -n "$UCRON" && "$UCRON" != *"no crontab"* ]]; then
    info "Crontab für $user:"
    code "$UCRON"
    ALL_USER_CRONS+="=== $user ==="$'\n'"$UCRON"$'\n'
  fi
done
[[ -n "$ALL_USER_CRONS" ]] && evidence "benutzer_crontabs" "$ALL_USER_CRONS"

h2 "6.4 Systemd-Timer prüfen"
if command -v systemctl &>/dev/null; then
  TIMERS=$(systemctl list-timers --all 2>/dev/null | head -25 || true)
  code "$TIMERS"
  evidence "systemd_timer" "$(systemctl list-timers --all 2>/dev/null || true)"
fi

h2 "6.5 at-Jobs"
if command -v atq &>/dev/null; then
  AT_JOBS=$(atq 2>/dev/null || true)
  if [[ -n "$AT_JOBS" ]]; then
    warn "at-Jobs vorhanden — Inhalte prüfen (atq/at -c <id>)"
    code "$AT_JOBS"
    AT_DETAIL=""
    while IFS= read -r line; do
      jid=$(echo "$line" | awk '{print $1}')
      AT_DETAIL+="=== Job $jid ==="$'\n'"$(at -c "$jid" 2>/dev/null | tail -20)"$'\n'
    done <<< "$AT_JOBS"
    evidence "at_jobs" "$AT_JOBS
$AT_DETAIL"
  else
    ok "Keine at-Jobs"
  fi
else
  info "atd nicht installiert"
fi

h2 "6.6 Fremde/kürzlich geänderte systemd-Units"
if [[ -d /etc/systemd/system ]]; then
  # Units außerhalb der Paketverwaltung — beliebter Persistenz-Ort
  CUSTOM_UNITS=$(find /etc/systemd/system -maxdepth 2 -name "*.service" -type f 2>/dev/null || true)
  RECENT_UNITS=$(find /etc/systemd/system /usr/lib/systemd/system -name "*.service" -mtime -"$DAYS_BACK" -type f 2>/dev/null || true)
  code "Eigene Units in /etc/systemd/system:
$CUSTOM_UNITS"
  if [[ -n "$RECENT_UNITS" ]]; then
    warn "systemd-Units in den letzten ${DAYS_BACK} Tagen geändert/angelegt — prüfen"
    code "$RECENT_UNITS"
    UNIT_CONTENT=""
    while IFS= read -r u; do
      UNIT_CONTENT+="=== $u ($(stat -c %y "$u" 2>/dev/null)) ==="$'\n'"$(cat "$u" 2>/dev/null)"$'\n\n'
    done <<< "$RECENT_UNITS"
    evidence "neue_systemd_units" "$UNIT_CONTENT"
  else
    ok "Keine kürzlich geänderten systemd-Units"
  fi
  # ExecStart mit Download-Mustern
  SUSP_UNITS=$(grep -lE "ExecStart=.*(curl|wget|base64|/tmp/|/dev/shm/)" /etc/systemd/system/*.service 2>/dev/null || true)
  if [[ -n "$SUSP_UNITS" ]]; then
    crit "systemd-Units mit verdächtigem ExecStart (curl/wget/tmp)"
    code "$SUSP_UNITS"
    evidence "verdaechtige_systemd_units" "$(grep -E "ExecStart" $SUSP_UNITS 2>/dev/null || true)"
  fi
fi

h2 "6.7 Weitere Persistenz-Orte (rc.local, ld.so.preload, profile.d)"
PERSIST_REPORT=""
if [[ -s /etc/rc.local ]]; then
  RC_LOCAL=$(grep -vE "^#|^$" /etc/rc.local 2>/dev/null || true)
  if [[ -n "$RC_LOCAL" ]]; then
    warn "/etc/rc.local enthält aktive Befehle — prüfen"
    code "$RC_LOCAL"
    PERSIST_REPORT+="=== /etc/rc.local ==="$'\n'"$RC_LOCAL"$'\n'
  fi
else
  ok "/etc/rc.local leer oder nicht vorhanden"
fi
if [[ -s /etc/ld.so.preload ]]; then
  crit "/etc/ld.so.preload ist NICHT leer — klassischer Userland-Rootkit-Ort!"
  code "$(cat /etc/ld.so.preload 2>/dev/null)"
  PERSIST_REPORT+="=== /etc/ld.so.preload ==="$'\n'"$(cat /etc/ld.so.preload 2>/dev/null)"$'\n'
else
  ok "/etc/ld.so.preload leer — kein Preload-Hijack"
fi
RECENT_PROFILED=$(find /etc/profile.d /etc/bash_completion.d -type f -mtime -"$DAYS_BACK" 2>/dev/null || true)
if [[ -n "$RECENT_PROFILED" ]]; then
  warn "Kürzlich geänderte Shell-Hooks in profile.d/bash_completion.d"
  code "$RECENT_PROFILED"
  PERSIST_REPORT+="=== profile.d (neu) ==="$'\n'"$RECENT_PROFILED"$'\n'
else
  ok "Keine kürzlich geänderten Shell-Hooks"
fi
[[ -n "$PERSIST_REPORT" ]] && evidence "persistenz_orte" "$PERSIST_REPORT"

h2 "6.8 Kernel-Module"
LSMOD_OUT=$(lsmod 2>/dev/null | head -40 || true)
code "$LSMOD_OUT"
evidence "kernel_module" "$(lsmod 2>/dev/null || true)"

h2 "6.9 Weniger bekannte Persistenz-Orte (udev, PAM, APT, linger)"
# Diese vier Orte überleben eine Bereinigung, die sich auf Cron und
# systemd beschränkt — und werden genau deshalb gern genutzt.
EXOTIC_PERSIST=""

# udev: RUN+= führt Code aus, sobald ein passendes Gerät auftaucht
UDEV_HITS=$(grep -rnasE 'RUN\+?=.*(sh|bash|python|perl|/tmp/|/dev/shm/)' /etc/udev/rules.d/ 2>/dev/null || true)
if [[ -n "$UDEV_HITS" ]]; then
    crit "udev-Regel führt Code aus — Persistenz über Geräte-Events"
    code "$UDEV_HITS"
    EXOTIC_PERSIST+="=== udev ==="$'\n'"$UDEV_HITS"$'\n'
else
    ok "Keine udev-Regeln mit Code-Ausführung"
fi

# PAM: pam_exec.so hängt sich in jeden Login ein
PAM_HITS=$(grep -rnasE 'pam_exec\.so|/tmp/|/dev/shm/' /etc/pam.d/ 2>/dev/null || true)
if [[ -n "$PAM_HITS" ]]; then
    crit "PAM-Konfiguration ruft externes Programm auf — Login-Hook"
    code "$PAM_HITS"
    EXOTIC_PERSIST+="=== PAM ==="$'\n'"$PAM_HITS"$'\n'
else
    ok "Keine auffälligen PAM-Einträge"
fi

# APT: Pre-/Post-Invoke läuft bei jedem apt-Aufruf als root
APT_HITS=$(grep -rnasE '(Pre-Invoke|Post-Invoke).*(curl|wget|/tmp/|/dev/shm/|base64)' /etc/apt/apt.conf.d/ 2>/dev/null || true)
if [[ -n "$APT_HITS" ]]; then
    crit "APT-Hook lädt/führt Code aus — läuft bei jedem apt-Lauf als root"
    code "$APT_HITS"
    EXOTIC_PERSIST+="=== APT ==="$'\n'"$APT_HITS"$'\n'
else
    ok "Keine auffälligen APT-Hooks"
fi

# systemd linger: User-Services laufen ohne Login weiter
if [[ -d /var/lib/systemd/linger ]]; then
    LINGER_USERS=$(ls -A /var/lib/systemd/linger 2>/dev/null || true)
    if [[ -n "$LINGER_USERS" ]]; then
        warn "Benutzer mit aktivem 'linger' — deren systemd-User-Services laufen auch ohne Login: $(echo "$LINGER_USERS" | tr '\n' ' ')"
        USER_UNITS=$(find /home /root -maxdepth 5 -type d -path '*/.config/systemd/user' 2>/dev/null \
            | while read -r d; do ls -la "$d" 2>/dev/null | sed "s|^|[$d] |"; done || true)
        code "$LINGER_USERS

$USER_UNITS"
        EXOTIC_PERSIST+="=== linger ==="$'\n'"$LINGER_USERS"$'\n'"$USER_UNITS"$'\n'
    else
        ok "Kein Benutzer mit aktivem linger"
    fi
fi

[[ -n "$EXOTIC_PERSIST" ]] && evidence "persistenz_exotisch" "$EXOTIC_PERSIST"

# ============================================================