# NT-Forensik — Runbook (manuelle Einzelschritte)

Kopierbare Befehle für die **manuelle Ad-hoc-Analyse** einzelner Prüfpunkte — spiegelt die 13 Abschnitte von `wp_plesk_forensik.sh` (v3.0) wider.

> Für den kompletten automatisierten Lauf: `bash /root/wartungsscripte/wp_plesk_forensik.sh <domain>`.
> Dieses Runbook ist für gezieltes Nachfassen einzelner Punkte gedacht.
> Alle Schritte sind **read-only** — keine Lösch- oder Schreiboperationen im Webspace.

Ergänzend: [Handbuch](handbuch.md) · [Erkennungs-Referenz](erkennung.md) · [Incident-Response-Playbook](incident-response.md)

---

## 🗂️ Feste Ablage-Konvention

Alles unter **`/root/wartungsscripte/`** — Skript und Belege getrennt vom Webspace:

```
/root/wartungsscripte/
├── wp_plesk_forensik.sh
└── forensik/<YYYYMMDD_HHMMSS>_<domain>/
    ├── belege/  (Rohdaten, SHA256-versiegelt, Chain-of-Custody)
    ├── kundenbericht.md · bsi_meldung.md · dsgvo_meldung.md · technik_bericht.md
    └── lauf.log
```

## ⚙️ Konfiguration (einmalig anpassen)

```bash
export DOMAIN="kundendomain.tld"
export RUN_DIR="/root/wartungsscripte/forensik/$(date +%Y%m%d_%H%M%S)_${DOMAIN}"
export BELEGE_DIR="$RUN_DIR/belege"
export SCAN_PATH="/var/www/vhosts/$DOMAIN"
export DAYS_BACK=30
mkdir -p "$BELEGE_DIR"; chmod 700 /root/wartungsscripte "$RUN_DIR"
echo "Lauf-Verzeichnis: $RUN_DIR"
```

---

## SCHRITT 0 — Logs sofort sichern

> **Höchste Priorität.** Erst sichern, dann analysieren.

```bash
tar czf "$BELEGE_DIR/logs_sicherung.tar.gz" \
  /var/log/auth.log* /var/log/secure* /var/log/plesk/ \
  /var/log/proftpd/ /var/log/vsftpd.log /var/log/fail2ban.log \
  /var/log/modsec_audit.log /var/log/maillog \
  "/var/www/vhosts/system/$DOMAIN/logs/" "/var/www/vhosts/$DOMAIN/logs/" \
  2>/dev/null || echo "Einige Pfade fehlen — OK"
ls -lh "$BELEGE_DIR/logs_sicherung.tar.gz"
```

---

## SCHRITT 1 — System-Übersicht

```bash
cat /etc/os-release | grep -E "^(NAME|VERSION)="; uname -a; uptime
plesk version 2>/dev/null | head -3
php -v 2>/dev/null | head -1
plesk bin php_handler --list 2>/dev/null
apache2 -v 2>/dev/null || nginx -v 2>&1
```

### 1.6 Abgleich mit Admin-Änderungsprotokoll

```bash
# Dokumentierte Systemänderungen — erklärt gutartige Funde
cat /root/changelog.md 2>/dev/null || echo "Kein /root/changelog.md — Änderungen nicht dokumentiert"
```

---

## SCHRITT 2 — Zugriffs-Analyse

```bash
# SSH-Logins
last -n 50
last | grep "^root"

# Fehlversuche + Top-Brute-Force-IPs
grep -hE "Failed password|Invalid user|authentication failure" /var/log/auth.log* /var/log/secure* 2>/dev/null | wc -l
grep -hE "Failed password|Invalid user" /var/log/auth.log* /var/log/secure* 2>/dev/null \
  | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | sort | uniq -c | sort -rn | head -15

# Erfolgreiche SSH-Logins (wer kam rein?)
grep -h "Accepted" /var/log/auth.log* /var/log/secure* 2>/dev/null | tail -20

# Plesk-Panel-Logins
grep -i "login\|auth\|session" /var/log/plesk/panel.log 2>/dev/null | tail -30

# FTP
tail -50 /var/log/proftpd/proftpd.log 2>/dev/null || tail -50 /var/log/vsftpd.log 2>/dev/null
```

---

## SCHRITT 3 — Web-Traffic-Analyse

> Plesk-Logs liegen unter `/var/www/vhosts/system/<domain>/logs/`.

```bash
LOGDIR=/var/www/vhosts/system/$DOMAIN/logs
LOG="$LOGDIR/access_log"; [ -f "$LOG" ] || LOG="/var/www/vhosts/$DOMAIN/logs/access_log"

# Scanner-Signaturen
grep -icE "sqlmap|nikto|havij|acunetix|nessus|masscan|nuclei" "$LOG"

# Webshell-typische POSTs
grep -E "POST.*(wp-content/uploads|xmlrpc)" "$LOG" | tail -20

# wp-login Brute-Force (Top-IPs)
grep -E "POST.*wp-login\.php" "$LOG" | awk '{print $1}' | sort | uniq -c | sort -rn | head -10

# Top-IPs gesamt
awk '{print $1}' "$LOG" | sort | uniq -c | sort -rn | head -20

# Alle rotierten + gz-Logs einbeziehen (Namen der gefundenen Backdoors einsetzen)
{ cat $LOGDIR/access_log $LOGDIR/*.processed 2>/dev/null; zcat $LOGDIR/*.gz 2>/dev/null; } \
  | grep -aE "verdaechtige-datei\.php" | awk '{print $1}' | sort | uniq -c | sort -rn
```

---

## SCHRITT 4 — Benutzer & Rechte

```bash
# Shell-fähige Benutzer
grep -vE "nologin|false|sync|halt|shutdown" /etc/passwd | awk -F: '{print $1, "UID="$3, "Shell="$7}'
# UID-0 (root-Äquivalenz)
awk -F: '($3==0){print "⚠️  UID-0:", $1}' /etc/passwd
# Sudo
grep -vE "^#|^$" /etc/sudoers 2>/dev/null; ls -la /etc/sudoers.d/ 2>/dev/null
# authorized_keys (root + Web-User) + kürzlich geändert
find /home /root /var/www/vhosts -maxdepth 4 -name authorized_keys 2>/dev/null \
  | while read f; do echo "=== $f ($(stat -c %y "$f" 2>/dev/null|cut -d. -f1)) ==="; cat "$f"; done
find /home /root /var/www/vhosts -maxdepth 4 -name authorized_keys -mtime -$DAYS_BACK 2>/dev/null
```

---

## SCHRITT 5 — Cronjobs & Persistenz

```bash
# Crontabs
crontab -l 2>/dev/null
for u in $(cut -f1 -d: /etc/passwd); do c=$(crontab -u "$u" -l 2>/dev/null); [ -n "$c" ] && echo "--- $u ---" && echo "$c"; done
# Verdächtige Cron-Inhalte
find /etc/cron* /var/spool/cron -type f 2>/dev/null | xargs grep -lE "curl|wget|bash.*http|base64|nc -" 2>/dev/null
# systemd-Timer + kürzlich geänderte/verdächtige Units
systemctl list-timers --all 2>/dev/null | head -25
find /etc/systemd/system /usr/lib/systemd/system -name "*.service" -mtime -$DAYS_BACK 2>/dev/null
grep -lE "ExecStart=.*(curl|wget|base64|/tmp/|/dev/shm/)" /etc/systemd/system/*.service 2>/dev/null
# at-Jobs
atq 2>/dev/null
# Weitere Persistenz-Orte
grep -vE "^#|^$" /etc/rc.local 2>/dev/null
[ -s /etc/ld.so.preload ] && echo "⚠️  ld.so.preload NICHT leer:" && cat /etc/ld.so.preload || echo "✓ ld.so.preload leer"
find /etc/profile.d /etc/bash_completion.d -type f -mtime -$DAYS_BACK 2>/dev/null
```

---

## SCHRITT 6 — Dateisystem-Scan

```bash
# Kürzlich veränderte PHP-Dateien
find "$SCAN_PATH" -name "*.php" -mtime -$DAYS_BACK -ls 2>/dev/null | sort -k8 -r | head -30

# PHP in Upload-Verzeichnissen (Guard-Files ausklammern)
find "$SCAN_PATH" \( -path "*/uploads/*.php" -o -path "*/uploads/*.phtml" \) 2>/dev/null \
  | grep -vE "/(borlabs-cookie|backwpup|avia_fonts|avia_icon_fonts)/"
```

### 6.3 Webshell-Erkennung (v3.0-Signatur — obfuskierte Cookie-Backdoors)

> Case-insensitive, erfasst Variable-Variable-Superglobale und mixed-case `EvaL`.

```bash
REGEX='\$\{\s*\$[a-zA-Z0-9_]+(\s*\.\s*\$[a-zA-Z0-9_]+)+\s*\}|eval\s*\(\s*(base64_decode|gzinflate|gzuncompress|str_rot13)|eval\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER)|assert\s*\(\s*\$_|preg_replace\s*\(\s*['"'"'"].*/e[imsuxADSUXJ]*['"'"'"]|\bFilesMan\b|c99sh|r57shell|b374k'

# Trefferliste (phpunit/sebastian/mockery ausgeschlossen)
grep -rlPi "$REGEX" "$SCAN_PATH" --include="*.php" \
  --exclude-dir=phpunit --exclude-dir=sebastian --exclude-dir=mockery 2>/dev/null

# Zweistufig: Dropper (< 3000 B) = kritisch, größer = Review
for f in $(grep -rlPi "$REGEX" "$SCAN_PATH" --include="*.php" --exclude-dir=phpunit --exclude-dir=sebastian 2>/dev/null); do
  s=$(stat -c%s "$f"); [ "$s" -lt 3000 ] && echo "🔴 DROPPER  $s B  $f" || echo "⚠️  review  $s B  $f"
done | sort
```

### 6.7–6.9 SUID, tmp-Executables, Immutable-Flags

```bash
# SUID/SGID in Webspace + tmp (Privilege-Escalation-Verdacht)
find "$SCAN_PATH" /tmp /var/tmp /dev/shm -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | xargs -r ls -la
# Ausführbare Skripte in tmp
find /tmp /var/tmp /dev/shm -type f \( -name "*.sh" -o -name "*.php" -o -name "*.py" -o -perm -u+x \) 2>/dev/null | head -20
# Immutable-PHP (chattr +i = Malware-Selbstschutz)
find "$SCAN_PATH" -name "*.php" 2>/dev/null | head -8000 | xargs -r lsattr 2>/dev/null | awk '$1 ~ /i/'
# .htaccess mit externen Weiterleitungen
find "$SCAN_PATH" -name ".htaccess" 2>/dev/null | xargs grep -lE "RewriteRule.*http|Redirect.*http" 2>/dev/null
```

---

## SCHRITT 7 — Netzwerk & Dienste

```bash
# Offene Ports
ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null

# Prozess-Forensik
ps aux --sort=-%cpu | head -8                                         # Top-CPU (Miner?)
ps aux | grep -iE "xmrig|kinsing|kdevtmpfsi|stratum\+tcp" | grep -v grep
ls -l /proc/[0-9]*/exe 2>/dev/null | grep "(deleted)" | grep -vE "/usr/|/lib/|/opt/plesk"  # gelöschte Binaries (Nicht-Systempfad)
ps auxww | grep -E "bash -i|nc -e|/dev/tcp/|python.*socket|php -r.*fsockopen" | grep -v grep  # Reverse-Shells
for p in /proc/[0-9]*; do e=$(readlink "$p/exe" 2>/dev/null); case "$e" in /tmp/*|/dev/shm/*|/var/tmp/*|/var/www/*) echo "$p -> $e";; esac; done

# Aktive Verbindungen
ss -tnp 2>/dev/null | grep ESTAB | head -20

# DNS
dig +short A "$DOMAIN"; dig +short MX "$DOMAIN"; dig +short NS "$DOMAIN"

# Mailqueue (Spam-Versand-Indikator)
postqueue -p 2>/dev/null | tail -1

# Binär-Integrität (Rootkit-Indikator)
dpkg -V bash coreutils openssh-server curl wget cron 2>/dev/null | grep -E "^..5" | grep -E "/(s?bin)/"
```

---

## SCHRITT 8 — Sicherheitsdienste

```bash
fail2ban-client status 2>/dev/null
fail2ban-client status 2>/dev/null | grep "Jail list" | sed 's/.*Jail list://;s/,/\n/g' \
  | xargs -I{} fail2ban-client status {} 2>/dev/null
grep -E "^SecRuleEngine" /etc/apache2/mods-enabled/security2.conf /etc/nginx/modsec/modsecurity.conf 2>/dev/null
ufw status verbose 2>/dev/null || firewall-cmd --list-all 2>/dev/null || iptables -L -n 2>/dev/null | head -20
```

---

## SCHRITT 9 — Andere Domains auf dem Server

```bash
ls /var/www/vhosts/ | grep -vE "^(system|chroot)$"
for d in /var/www/vhosts/*/; do
  b=$(basename "$d"); log="/var/www/vhosts/system/$b/logs/access_log"; [ -f "$log" ] || continue
  s=$(grep -icE "sqlmap|nikto|havij" "$log" 2>/dev/null)
  sh=$(grep -cE "POST.*(wp-content/uploads|eval|base64)" "$log" 2>/dev/null)
  [ "$s" -gt 0 -o "$sh" -gt 0 ] && echo "⚠️  $b — Scanner:$s Shell-POSTs:$sh"
done
```

---

## SCHRITT 10 — WordPress-Datenbank-Prüfung

> Nutzt Plesk-Admin-MySQL-Zugang (Passwort in `/etc/psa/.psa.shadow`).

```bash
PW=$(cat /etc/psa/.psa.shadow)
# WP-Configs finden
find /var/www/vhosts/$DOMAIN -maxdepth 4 -name wp-config.php 2>/dev/null
# Für jede: DB + Prefix auslesen
CFG=/var/www/vhosts/$DOMAIN/httpdocs/wp-config.php
DB=$(grep -oP "define\(\s*['\"]DB_NAME['\"]\s*,\s*['\"]\K[^'\"]*" "$CFG")
PFX=$(grep -oP '\$table_prefix\s*=\s*['"'"'"]\K[^'"'"'"]*' "$CFG")

# Administrator-Konten
MYSQL_PWD="$PW" mysql -u admin -N -e "USE \`$DB\`;
 SELECT u.user_login,u.user_email,u.user_registered FROM ${PFX}users u
 JOIN ${PFX}usermeta m ON u.ID=m.user_id
 WHERE m.meta_key='${PFX}capabilities' AND m.meta_value LIKE '%administrator%';"

# Kürzlich angelegte Admins (< 30 Tage = hochverdächtig)
MYSQL_PWD="$PW" mysql -u admin -N -e "USE \`$DB\`;
 SELECT u.user_login,u.user_registered FROM ${PFX}users u
 JOIN ${PFX}usermeta m ON u.ID=m.user_id
 WHERE m.meta_key='${PFX}capabilities' AND m.meta_value LIKE '%administrator%'
 AND u.user_registered > DATE_SUB(NOW(), INTERVAL 30 DAY);"

# Verdächtige Optionen + siteurl/home
MYSQL_PWD="$PW" mysql -u admin -N -e "USE \`$DB\`;
 SELECT option_name FROM ${PFX}options
 WHERE option_value LIKE '%base64_decode%' OR option_value LIKE '%eval(%'
    OR option_name LIKE '%auto_prepend%';
 SELECT option_name,option_value FROM ${PFX}options WHERE option_name IN ('siteurl','home');"
```

---

## SCHRITT 11 — Root- & Eskalations-Prüfung

```bash
# Erfolgreiche Root-Logins (IP + Auth-Methode)
grep -hE "Accepted (password|publickey) for root" /var/log/auth.log* /var/log/secure* 2>/dev/null
grep -hc "Accepted password for root" /var/log/auth.log* 2>/dev/null    # Passwort-Login = Härtungslücke

# /root/.ssh/authorized_keys — Fingerprints + mtime
stat -c %y /root/.ssh/authorized_keys 2>/dev/null
while read l; do [ -z "$l" ] && continue; echo "$l" | ssh-keygen -lf /dev/stdin 2>/dev/null; done < /root/.ssh/authorized_keys

# Web-User-Keys serverweit — Fremd-Keys vs. Plesk-eigene (plesk-ssh-terminal)
find /var/www/vhosts -maxdepth 3 -name authorized_keys 2>/dev/null | while read f; do
  u=$(echo "$f"|cut -d/ -f5); while read l; do [ -z "$l" ] && continue
    fp=$(echo "$l"|ssh-keygen -lf /dev/stdin 2>/dev/null); echo "$u : $fp"; done < "$f"
done | grep -v "plesk-ssh-terminal" && echo "↑ Fremd-Keys prüfen" || echo "✓ nur Plesk-Keys"

# Privilege-Escalation (sudo/su durch Nicht-Root)
grep -hE "sudo:.*(www-data|psacln|web[0-9])" /var/log/auth.log* 2>/dev/null

# Angreifer-IP gegen Root-Logins abgleichen (IP aus Schritt 3 einsetzen)
grep -h "203.0.113.66" /var/log/auth.log* 2>/dev/null | wc -l   # 0 = nie am SSH
```

**Root-Verdikt:** Keine Angreifer-IP unter Root-Logins + keine Fremd-Keys + keine Eskalation + `dpkg -V` sauber ⇒ Vorfall auf Web-User-Ebene begrenzt.

---

## SCHRITT 12 — Berichte & Belege (Routine)

> Empfohlen: das Skript erzeugt alle drei Berichte + versiegelte Belege automatisch.

```bash
bash /root/wartungsscripte/wp_plesk_forensik.sh "$DOMAIN"

# Belege manuell versiegeln (bei Einzelschritt-Analyse)
cd "$BELEGE_DIR" && sha256sum ./* > SHA256SUMS
cd "$RUN_DIR" && tar czf "/root/wartungsscripte/forensik/$(basename "$RUN_DIR").tar.gz" -C .. "$(basename "$RUN_DIR")"
```

Erzeugte Artefakte: `kundenbericht.md`, `bsi_meldung.md`, `dsgvo_meldung.md`, `technik_bericht.md`, `belege/` (SHA256SUMS).

### BSI-Meldewege & Fristen

| Weg | Wann |
|---|---|
| **mip.bsi.bund.de** | Meldepflichtige (KRITIS / NIS2, §32 BSIG) |
| freiwillig (bsi.bund.de) | alle anderen |
| **ZAC** der Landespolizei | Straftatverdacht (Strafanzeige) |
| **Datenschutz-Aufsichtsbehörde** | personenbezogene Daten → **DSGVO Art. 33, 72 h** |

NIS2/BSIG: Erstmeldung ≤ 24 h, Folge ≤ 72 h, Abschluss ≤ 1 Monat.

---

## SCHRITT 13 — Quarantäne & Härtung (nach der Analyse)

> **Erst nach Beweissicherung.** Verschieben statt löschen — siehe [Incident-Response-Playbook](incident-response.md).

```bash
# SSH-Härtung prüfen (erst Key-Login testen, dann Passwort aus!)
grep -E "PermitRootLogin|PasswordAuthentication|PubkeyAuthentication" /etc/ssh/sshd_config
# Fail2ban
systemctl status fail2ban 2>/dev/null
# PHP disable_functions
php -i 2>/dev/null | grep "disable_functions"
```

**Sofort:** Passwörter rotieren (WP, Plesk, FTP, SSH, DB) · WP-Salts neu · Angreifer-IP sperren · genutzte Plugins deaktivieren.
**Kurzfristig:** WP aus sauberem Backup neu · Fail2ban + ModSecurity · SSH Key-only.
**Mittelfristig:** `disable_functions` härten · AIDE/Tripwire · automatische Malware-Scans · `/root/changelog.md` pflegen.

---

*netztaucher | digital — Runbook zu wp_plesk_forensik.sh v3.0. Nur für autorisiertes Personal auf eigenen/betreuten Systemen.*
