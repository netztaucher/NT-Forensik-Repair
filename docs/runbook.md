# 🔍 WP-Plesk Forensik Runbook — v2.0
**netztaucher | digital** — Incident Response nach WordPress-Kompromittierung

> **Verwendung in Warp:** Jeder Codeblock ist ein ausführbarer Schritt.  
> Variablen oben anpassen, dann Block für Block ausführen.  
> Alle Schritte sind **read-only** — keine Lösch- oder Schreiboperationen.

---

## 🗂️ Feste Ablage-Konvention (netztaucher-Standard)

Alles liegt unter **`/root/wartungsscripte`** — Skripte UND forensische Belege:

```
/root/wartungsscripte/
├── wp_plesk_forensik.sh                  ← Skript (installiert sich selbst hierhin)
└── forensik/
    ├── <YYYYMMDD_HHMMSS>_<domain>/       ← EIN Ordner PRO LAUF
    │   ├── belege/                       ← nummerierte Rohdaten, SHA256-versiegelt
    │   │   ├── 00_manifest.txt           ← Chain-of-Custody
    │   │   ├── NN_*.txt
    │   │   ├── logs_sicherung.tar.gz
    │   │   └── SHA256SUMS
    │   ├── technik_bericht.md            ← vollständiger Technik-Bericht
    │   ├── kundenbericht.md              ← lesbare Zusammenfassung für den Kunden
    │   ├── bsi_meldung.md                ← BSI-Meldung (Best Practice, vorausgefüllt)
    │   └── lauf.log                      ← Ausführungsprotokoll
    └── <YYYYMMDD_HHMMSS>_<domain>.tar.gz ← Übergabe-Archiv des Laufs
```

**Routine pro Lauf (automatisch durch das Skript):**
1. Logs sichern → `belege/logs_sicherung.tar.gz`
2. Alle Analysen fahren, jede Erkenntnis als nummerierter Beleg
3. `technik_bericht.md` + `kundenbericht.md` + `bsi_meldung.md` erzeugen
4. Belege mit `SHA256SUMS` versiegeln, Übergabe-Archiv packen

## ⚡ Schnellstart (empfohlen)

```bash
# Skript auf den Server bringen und ausführen — legt /root/wartungsscripte selbst an
scp wp_plesk_forensik.sh root@SERVER:/root/
ssh root@SERVER "bash /root/wp_plesk_forensik.sh kundendomain.tld"

# Folgende Läufe direkt aus der festen Ablage:
ssh root@SERVER "bash /root/wartungsscripte/wp_plesk_forensik.sh kundendomain.tld"
```

---

## ⚙️ Konfiguration für manuelle Schritte (einmalig anpassen)

```bash
export DOMAIN="kundendomain.tld"
export RUN_DIR="/root/wartungsscripte/forensik/$(date +%Y%m%d_%H%M%S)_${DOMAIN}"
export REPORT_DIR="$RUN_DIR"                 # Alias für die Blöcke unten
export BELEGE_DIR="$RUN_DIR/belege"
export SCAN_PATH="/var/www/vhosts/$DOMAIN"
export DAYS_BACK=30

mkdir -p "$BELEGE_DIR"
chmod 700 /root/wartungsscripte "$RUN_DIR"
echo "Lauf-Verzeichnis: $RUN_DIR"
```

---

## 📦 SCHRITT 0 — Logs sofort sichern

> **Höchste Priorität.** Logs werden regelmäßig rotiert. Erst sichern, dann alles andere.

```bash
tar czf "$BELEGE_DIR/logs_sicherung.tar.gz" \
  /var/log/auth.log* \
  /var/log/secure* \
  /var/log/plesk/ \
  /var/log/proftpd/ \
  /var/log/vsftpd.log \
  /var/log/fail2ban.log \
  /var/log/modsec_audit.log \
  /var/log/maillog \
  "/var/www/vhosts/$DOMAIN/logs/" \
  2>/dev/null || echo "Einige Pfade nicht vorhanden — OK"

ls -lh "$BELEGE_DIR/logs_sicherung.tar.gz"
```

---

## 🖥️ SCHRITT 1 — System-Übersicht

### 1.1 OS, Kernel, Uptime

```bash
echo "=== OS ===" && cat /etc/os-release | grep -E "^(NAME|VERSION)="
echo "=== Kernel ===" && uname -a
echo "=== Uptime ===" && uptime
echo "=== Last Reboot ===" && last reboot | head -5
```

### 1.2 Plesk-Version

```bash
plesk version 2>/dev/null || echo "Plesk nicht im PATH"
```

### 1.3 PHP-Versionen

```bash
php -v 2>/dev/null | head -1
plesk bin php_handler --list 2>/dev/null || echo "Plesk php_handler nicht verfügbar"
```

### 1.4 Webserver-Version

```bash
apache2 -v 2>/dev/null || nginx -v 2>&1 || echo "Kein bekannter Webserver im PATH"
```

---

## 👤 SCHRITT 2 — Login-Analyse

### 2.1 SSH-Logins (letzte 50)

```bash
last -n 50
```

### 2.2 Root-Logins herausfiltern

```bash
last | grep "^root"
```

### 2.3 Fehlgeschlagene SSH-Versuche

```bash
grep -E "Failed password|Invalid user|authentication failure" \
  /var/log/auth.log /var/log/secure 2>/dev/null | wc -l
```

### 2.4 Top-IPs bei SSH-Brute-Force

```bash
grep "Failed password\|Invalid user" /var/log/auth.log /var/log/secure 2>/dev/null \
  | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' \
  | sort | uniq -c | sort -rn | head -15
```

### 2.5 Erfolgreiche SSH-Logins (wer kam rein?)

```bash
grep "Accepted" /var/log/auth.log /var/log/secure 2>/dev/null | tail -20
```

### 2.6 Plesk Panel-Logins

```bash
grep -i "login\|auth\|session" /var/log/plesk/panel.log 2>/dev/null | tail -30 \
  || echo "Panel-Log nicht gefunden — manuell: Plesk → Tools & Einstellungen → Aktionsprotokoll"
```

### 2.7 FTP-Zugriffe

```bash
# ProFTPD
tail -50 /var/log/proftpd/proftpd.log 2>/dev/null \
  || tail -50 /var/log/vsftpd.log 2>/dev/null \
  || echo "Kein FTP-Log gefunden"
```

### 2.8 Top-IPs aus FTP-Logs

```bash
awk '{print $NF}' /var/log/proftpd/proftpd.log 2>/dev/null \
  | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' \
  | sort | uniq -c | sort -rn | head -10
```

---

## 🌐 SCHRITT 3 — Web-Traffic Analyse

### 3.1 SQLMap / bekannte Scanner im Access-Log

```bash
grep -icE "sqlmap|nikto|havij|acunetix|nessus|masscan|nuclei" \
  "$SCAN_PATH/logs/access_log" 2>/dev/null && \
  grep -iE "sqlmap|nikto|havij" "$SCAN_PATH/logs/access_log" 2>/dev/null | head -20
```

### 3.2 Verdächtige POST-Requests (Webshell-Upload)

```bash
grep -E "POST.*(wp-content/uploads|xmlrpc)" \
  "$SCAN_PATH/logs/access_log" 2>/dev/null | wc -l

grep -E "POST.*wp-content/uploads" \
  "$SCAN_PATH/logs/access_log" 2>/dev/null | tail -20
```

### 3.3 wp-login Brute-Force

```bash
grep -cE "POST.*wp-login\.php" "$SCAN_PATH/logs/access_log" 2>/dev/null \
  && grep "POST.*wp-login" "$SCAN_PATH/logs/access_log" 2>/dev/null \
  | awk '{print $1}' | sort | uniq -c | sort -rn | head -10
```

### 3.4 Top-IPs gesamt

```bash
awk '{print $1}' "$SCAN_PATH/logs/access_log" 2>/dev/null \
  | sort | uniq -c | sort -rn | head -20
```

### 3.5 Redirects (Weiterleitung auf fremde Domains)

```bash
grep -E " 30[1-8] " "$SCAN_PATH/logs/access_log" 2>/dev/null | tail -20
```

### 3.6 Requests im Tatzeitraum (3–7 Tage vor Entdeckung)

```bash
# Datum anpassen: [DD/MMM/YYYY] Format
grep -E "0[3-7]/Jul/2025" "$SCAN_PATH/logs/access_log" 2>/dev/null \
  | grep "POST" | head -30
```

---

## 👥 SCHRITT 4 — Benutzer & Rechte

### 4.1 Shell-fähige Benutzer

```bash
grep -vE "nologin|false|sync|halt|shutdown" /etc/passwd \
  | awk -F: '{print $1, "UID="$3, "Shell="$7}'
```

### 4.2 Benutzer mit Root-Äquivalenz (UID 0)

```bash
awk -F: '($3==0){print "⚠️  UID-0:", $1}' /etc/passwd
```

### 4.3 Sudo-Berechtigungen

```bash
cat /etc/sudoers 2>/dev/null | grep -v "^#\|^$"
ls -la /etc/sudoers.d/ 2>/dev/null
```

### 4.4 FTP-Benutzer (Plesk)

```bash
/usr/local/psa/bin/ftpuser --list 2>/dev/null \
  || echo "Manuell prüfen: Plesk → Websites & Domains → FTP-Zugang"
```

### 4.5 Authorized SSH-Keys (alle Benutzer)

```bash
find /home /root /var/www -name "authorized_keys" 2>/dev/null \
  | while read f; do echo "=== $f ==="; cat "$f" 2>/dev/null; done
```

---

## ⏰ SCHRITT 5 — Cronjobs & Persistenz

### 5.1 Root-Crontab

```bash
crontab -l 2>/dev/null || echo "(leer)"
```

### 5.2 System-Cron-Verzeichnisse

```bash
ls -la /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/ /etc/cron.weekly/ 2>/dev/null
```

### 5.3 Verdächtige Cronjobs (curl/wget/base64)

```bash
find /etc/cron* /var/spool/cron -type f 2>/dev/null \
  | xargs grep -lE "curl|wget|bash.*http|base64|nc -" 2>/dev/null \
  || echo "✓ Keine verdächtigen Cronjobs gefunden"
```

### 5.4 Alle Benutzer-Crontabs

```bash
for user in $(cut -f1 -d: /etc/passwd); do
  cron=$(crontab -u "$user" -l 2>/dev/null) || continue
  [[ -n "$cron" ]] && echo "--- $user ---" && echo "$cron"
done
```

### 5.5 Systemd-Timer

```bash
systemctl list-timers --all 2>/dev/null | head -25
```

---

## 📁 SCHRITT 6 — Dateisystem-Scan

### 6.1 Kürzlich veränderte PHP-Dateien (letzte 30 Tage)

```bash
find "$SCAN_PATH" -name "*.php" -mtime -$DAYS_BACK -ls 2>/dev/null \
  | sort -k8 -r | head -30
```

### 6.2 PHP in Upload-Verzeichnissen (kritisch!)

```bash
find "$SCAN_PATH" \
  \( -path "*/uploads/*.php" -o -path "*/uploads/*.phtml" -o -path "*/uploads/*.php5" \) \
  2>/dev/null \
  && echo "⚠️  PHP in Uploads gefunden!" \
  || echo "✓ Keine PHP-Dateien in Uploads"
```

### 6.3 Webshell-Signaturen im Code

```bash
grep -rlP \
  "eval\(base64_decode|eval\(gzinflate|system\(\\\$_|exec\(\\\$_|passthru\(\\\$_|assert\(\\\$_" \
  "$SCAN_PATH" --include="*.php" 2>/dev/null \
  || echo "✓ Keine Webshell-Muster gefunden"
```

### 6.4 Backdoor-typische Dateinamen

```bash
find "$SCAN_PATH" -type f \
  \( -iname "*shell*" -o -iname "*exploit*" -o -iname "*hack*" \
     -o -iname "*r57*" -o -iname "*c99*" -o -iname "*backdoor*" \
     -o -iname "*bypass*" \) \
  2>/dev/null \
  || echo "✓ Keine verdächtigen Dateinamen"
```

### 6.5 .htaccess mit externen Weiterleitungen

```bash
find "$SCAN_PATH" -name ".htaccess" 2>/dev/null \
  | xargs grep -lE "RewriteRule.*http|Redirect.*http" 2>/dev/null \
  || echo "✓ Keine externen .htaccess-Weiterleitungen"
```

### 6.6 Verdächtige Dateirechte (world-writable)

```bash
find "$SCAN_PATH" -type f -perm -o+w 2>/dev/null \
  | grep -v ".git" | head -20 \
  || echo "✓ Keine world-writable Dateien"
```

---

## 🌍 SCHRITT 7 — Netzwerk & Dienste

### 7.1 Offene Ports

```bash
ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null
```

### 7.2 Unerwartete lauschende Ports

```bash
ss -tlnp 2>/dev/null \
  | grep -vE ":22 |:80 |:443 |:8443 |:21 |:25 |:110 |:143 |:993 |:995 |:3306 |:53 " \
  | grep LISTEN
```

### 7.3 Aktive ausgehende Verbindungen

```bash
ss -tnp 2>/dev/null | grep ESTABLISHED
```

### 7.4 DNS-Records prüfen

```bash
dig +short A "$DOMAIN" && echo "---"
dig +short MX "$DOMAIN" && echo "---"
dig +short NS "$DOMAIN" && echo "---"
dig +short TXT "$DOMAIN" | head -5
```

---

## 🛡️ SCHRITT 8 — Sicherheitsdienste

### 8.1 Fail2ban Status

```bash
fail2ban-client status 2>/dev/null || echo "⚠️  Fail2ban nicht aktiv/installiert"
```

### 8.2 Fail2ban — alle Jails

```bash
fail2ban-client status 2>/dev/null \
  | grep "Jail list" \
  | sed 's/.*Jail list://;s/,/\n/g' \
  | xargs -I{} fail2ban-client status {} 2>/dev/null
```

### 8.3 ModSecurity

```bash
grep -E "^SecRuleEngine" \
  /etc/apache2/mods-enabled/security2.conf \
  /etc/nginx/modsec/modsecurity.conf 2>/dev/null \
  || echo "⚠️  ModSecurity-Konfig nicht gefunden"

wc -l /var/log/modsec_audit.log 2>/dev/null && echo "Einträge im Audit-Log"
```

### 8.4 Firewall-Status

```bash
ufw status verbose 2>/dev/null \
  || firewall-cmd --list-all 2>/dev/null \
  || iptables -L -n 2>/dev/null | head -20 \
  || echo "⚠️  Kein Firewall-Tool gefunden"
```

---

## 🏘️ SCHRITT 9 — Andere Domains auf dem Server

### 9.1 Alle Domains auflisten

```bash
ls /var/www/vhosts/ 2>/dev/null | head -50
```

### 9.2 Scanner-Aktivität bei allen Domains

```bash
for domain_dir in /var/www/vhosts/*/; do
  d=$(basename "$domain_dir")
  log="$domain_dir/logs/access_log"
  [[ ! -f "$log" ]] && continue
  scanners=$(grep -icE "sqlmap|nikto|havij" "$log" 2>/dev/null || echo 0)
  shells=$(grep -cE "POST.*wp-content/uploads" "$log" 2>/dev/null || echo 0)
  [[ "$scanners" -gt 0 || "$shells" -gt 0 ]] && \
    echo "⚠️  $d — Scanner: $scanners, Shell-POSTs: $shells"
done
echo "--- Scan abgeschlossen ---"
```

---

## 📊 SCHRITT 10 — Berichte & Belege (Routine pro Lauf)

> **Empfohlen:** Das Skript erzeugt alle drei Berichte + versiegelte Belege automatisch.
> Die manuellen Schritte oben sind für Ad-hoc-Prüfungen einzelner Punkte gedacht.

```bash
bash /root/wartungsscripte/wp_plesk_forensik.sh "$DOMAIN"
```

Erzeugt pro Lauf automatisch:

| Artefakt | Inhalt |
|---|---|
| `kundenbericht.md` | Lesbare Zusammenfassung mit Ampel-Bewertung — direkt an den Kunden gebbar |
| `bsi_meldung.md` | BSI-Meldung nach Best Practice (BSIG/NIS2-Struktur), Kennzahlen + IOCs vorausgefüllt, `[AUSFÜLLEN]`-Platzhalter für den Rest |
| `technik_bericht.md` | Vollständiger technischer Bericht mit allen Prüfpunkten |
| `belege/` | Nummerierte Rohdaten, Chain-of-Custody-Manifest, `SHA256SUMS` |
| `<lauf>.tar.gz` | Übergabe-Archiv des kompletten Laufs |

### Belege manuell versiegeln (falls Schritte einzeln ausgeführt wurden)

```bash
cd "$BELEGE_DIR" && sha256sum ./* > SHA256SUMS
cd "$RUN_DIR" && tar czf "/root/wartungsscripte/forensik/$(basename "$RUN_DIR").tar.gz" -C .. "$(basename "$RUN_DIR")"
```

### Optional: Berichte als HTML exportieren (falls pandoc installiert)

```bash
pandoc "$RUN_DIR/kundenbericht.md" -o "$RUN_DIR/kundenbericht.html" 2>/dev/null \
  && echo "HTML: $RUN_DIR/kundenbericht.html" \
  || echo "pandoc nicht installiert — apt install pandoc"
```

### Archiv vom Server holen

```bash
scp "root@SERVER:/root/wartungsscripte/forensik/$(basename "$RUN_DIR").tar.gz" .
```

### BSI-Meldung — Meldewege & Fristen

| Weg | Wann |
|---|---|
| **BSI Melde- und Informationsportal** — https://mip.bsi.bund.de | Meldepflichtige (KRITIS / NIS2, §32 BSIG) |
| **Freiwillige Meldung** — bsi.bund.de → "Cyber-Sicherheitsvorfall melden" | Alle anderen Unternehmen |
| **ZAC der Landespolizei** (Strafanzeige) | Bei Straftatverdacht — parallel empfohlen |
| **Datenschutz-Aufsichtsbehörde** (DSGVO Art. 33) | Personenbezogene Daten betroffen → **72 h!** Separater Meldeweg |

Fristen NIS2/BSIG: Erstmeldung ≤ 24 h, Folgemeldung ≤ 72 h, Abschlussbericht ≤ 1 Monat.

---

## ✅ Checkliste Sofortmaßnahmen

```bash
cat <<'CHECKLIST'
┌─────────────────────────────────────────────────────────────────────┐
│  SOFORTMASSNAHMEN NACH DEM FORENSIK-SCAN                           │
├──────────────────────────────────────────────────────────┬──────────┤
│ Maßnahme                                                 │ Priorität│
├──────────────────────────────────────────────────────────┼──────────┤
│ Alle Passwörter rotieren (Plesk, FTP, SSH, DB, WP)       │ 🔴 SOFORT│
│ SSH Root-Login deaktivieren (PermitRootLogin no)          │ 🔴 SOFORT│
│ SSH auf Key-only (PasswordAuthentication no)              │ 🔴 SOFORT│
│ Google Search Console: unbekannte Inhaber entfernen       │ 🔴 SOFORT│
│ Fail2ban aktivieren (ssh, ftp, plesk-panel)               │ 🟠 KURZ  │
│ ModSecurity + OWASP CRS aktivieren                        │ 🟠 KURZ  │
│ PHP disable_functions härten (exec, shell_exec, system)   │ 🟠 KURZ  │
│ Maldet/ClamAV vollständiger Scan                          │ 🟠 KURZ  │
│ WP-Neuinstallation aus sauberem Backup                    │ 🟡 MITTEL│
│ WP-Admin mit HTTP-Auth schützen                           │ 🟡 MITTEL│
│ Automatische Malware-Scans einrichten                     │ 🟡 MITTEL│
│ AIDE/Tripwire für File-Integrity-Monitoring               │ 🟡 MITTEL│
└──────────────────────────────────────────────────────────┴──────────┘
CHECKLIST
```

---

## 🩹 SCHRITT 11 — Härtung (nach der Analyse)

### SSH absichern

```bash
# ACHTUNG: Erst SSH-Key einrichten, dann PasswordAuthentication deaktivieren!
# Nicht einfach so ausführen — erst Key-Login testen!
echo "Aktuelle SSH-Config:"
grep -E "PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|Port" /etc/ssh/sshd_config
```

### Fail2ban für Plesk einrichten

```bash
# Status prüfen
systemctl status fail2ban 2>/dev/null

# Plesk-spezifische Jail-Config anzeigen (falls vorhanden)
cat /etc/fail2ban/jail.d/plesk.conf 2>/dev/null \
  || echo "Plesk Jail nicht konfiguriert"
```

### PHP disable_functions prüfen

```bash
php -i 2>/dev/null | grep "disable_functions"
```

---

*netztaucher | digital — wp_plesk_forensik_runbook.md v2.0*  
*Nur für den Einsatz durch autorisiertes Personal auf eigenen/betreuten Systemen.*
