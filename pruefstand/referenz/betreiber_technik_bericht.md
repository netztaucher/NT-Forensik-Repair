# Forensik-Bericht (Technik): WordPress/Plesk Sicherheitsvorfall

| | |
|---|---|
| **Lauf-ID** | <LAUF-ID> |
| **Domain** | Alle Domains |
| **Analysiert am** | <UMGEBUNG> |
| **Server** | <UMGEBUNG> |
| **Erstellt durch** | wp_plesk_forensik.sh <FASSUNG> |
| **Belege** | <PRUEFSTAND>/ablage/forensik/<LAUF-ID>/betreiber/belege |

---

> **Hinweis:** Dieser Bericht ist maschinell erstellt und ersetzt keine manuelle Prüfung durch einen Sicherheitsexperten.

---
> ⚠️ **TESTLAUF — kein Befund dieses Berichts ist belastbar.**
> Erzeugt ohne Root-Rechte gegen einen synthetischen Verzeichnisbaum
> (`werkzeuge/goldmuster.sh`). Die serverweiten Abschnitte hatten keinen
> Zugriff auf ihre Quellen. Dieses Dokument dient ausschliesslich dem
> Vergleich zweier Programmstaende und darf niemandem vorgelegt werden.

---

## 4. WEB-TRAFFIC ANALYSE


### 4.1 Access-Logs auf Angriffsmuster prüfen


## 7. DATEISYSTEM-SCAN


### 7.1 Kürzlich veränderte PHP-Dateien (letzte 30 Tage)

  Kürzlich veränderte .php-Dateien:

```
<INODE> -rw-r--r-- <EIGNER> 131 <MTIME> <PRUEFSTAND>/vhosts/kunde-zwei.example/backups/updater-abc123/nextcloud-28.0.1.2-1700000000/config/config.php
<INODE> -rw-r--r-- <EIGNER> 131 <MTIME> <PRUEFSTAND>/vhosts/kunde-zwei.example/cloud.kunde-zwei.example/config/config.php
<INODE> -rw-r--r-- <EIGNER> 16 <MTIME> <PRUEFSTAND>/vhosts/kunde-zwei.example/backups/updater-abc123/nextcloud-28.0.1.2-1700000000/config/config/index.php
<INODE> -rw-r--r-- <EIGNER> 16 <MTIME> <PRUEFSTAND>/vhosts/kunde-zwei.example/cloud.kunde-zwei.example/config/config/index.php
<INODE> -rw-r--r-- <EIGNER> 169 <MTIME> <PRUEFSTAND>/vhosts/kunde-drei.example/httpdocs/wp-config.php
<INODE> -rw-r--r-- <EIGNER> 169 <MTIME> <PRUEFSTAND>/vhosts/kunde-eins.example/backup/httpdocs/wp-config.php
<INODE> -rw-r--r-- <EIGNER> 169 <MTIME> <PRUEFSTAND>/vhosts/kunde-eins.example/httpdocs/wp-config.php
<INODE> -rw-r--r-- <EIGNER> 169 <MTIME> <PRUEFSTAND>/vhosts/kunde-zwei.example/httpdocs/wp-config.php
<INODE> -rw-r--r-- <EIGNER> 17 <MTIME> <PRUEFSTAND>/vhosts/kunde-eins.example/httpdocs/index.php
<INODE> -rw-r--r-- <EIGNER> 17 <MTIME> <PRUEFSTAND>/vhosts/kunde-zwei.example/backups/updater-abc123/nextcloud-28.0.1.2-1700000000/filefuns.php
<INODE> -rw-r--r-- <EIGNER> 17 <MTIME> <PRUEFSTAND>/vhosts/kunde-zwei.example/cloud.kunde-zwei.example/filefuns.php
<INODE> -rw-r--r-- <EIGNER> 230 <MTIME> <PRUEFSTAND>/vhosts/kunde-zwei.example/joomla.kunde-zwei.example/configuration.php
<INODE> -rw-r--r-- <EIGNER> 34 <MTIME> <PRUEFSTAND>/vhosts/kunde-zwei.example/joomla.kunde-zwei.example/libraries/src/Version.php
<INODE> -rw-r--r-- <EIGNER> 37 <MTIME> <PRUEFSTAND>/vhosts/kunde-zwei.example/backups/updater-abc123/nextcloud-28.0.1.2-1700000000/version.php
<INODE> -rw-r--r-- <EIGNER> 37 <MTIME> <PRUEFSTAND>/vhosts/kunde-zwei.example/cloud.kunde-zwei.example/version.php
<INODE> -rw-r--r-- <EIGNER> 42 <MTIME> <PRUEFSTAND>/vhosts/kunde-zwei.example/httpdocs/wp-content/mu-plugins/cache.php
<INODE> -rw-r--r-- <EIGNER> 43 <MTIME> <PRUEFSTAND>/vhosts/kunde-zwei.example/httpdocs/wp-content/uploads/2026/03/bild.php
```

  Beleg: belege/01_veraenderte_php_dateien.txt

### 7.2 PHP-Dateien in Upload-Verzeichnissen

- 🔴 **KRITISCH: PHP-Dateien in Upload-Verzeichnissen (nach Guard-Filter, extrem verdächtig)**

```
<PRUEFSTAND>/vhosts/kunde-zwei.example/httpdocs/wp-content/uploads/2026/03/bild.php

```

  Beleg: belege/02_php_in_uploads_mit_hashes.txt

### 7.3 Webshell-Muster (Inhalt) — zweistufig

- ✅ Keine kleinen Obfuskations-Dropper gefunden

### 7.4 Versteckte Dateien und Verzeichnisse im Webspace

- ✅ Keine auffälligen versteckten Dateien

### 7.5 Verdächtige Dateinamen (namensbasiert, geringe Konfidenz → Warnung)

- ✅ Keine verdächtigen Dateinamen (außerhalb Core/vendor/cache/plugins)

### 7.6 .htaccess-Dateien prüfen

- ⚠️  **.htaccess mit externen Weiterleitungen gefunden**

```
<PRUEFSTAND>/vhosts/kunde-zwei.example/httpdocs/.htaccess
```


```
# BEGIN WordPress
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteBase /
RewriteRule ^index\.php$ - [L]
RewriteRule . /index.php [L]
</IfModule>
# END WordPress

# BEGIN YOAST REDIRECTS
Redirect 301 /alte-seite /neue-seite
# END YOAST REDIRECTS

Redirect 301 /shop https://shop.kunde-zwei.example/
Header always set Strict-Transport-Security "max-age=31536000"
AddType application/font-woff2 .woff2
<Files "wp-config.php">
  Require all denied
</Files>

# Angreiferzeilen darunter
AddType application/x-httpd-php .jpg
php_value auto_prepend_file /var/www/vhosts/<anderer Kunde 1>/httpdocs/wp-content/uploads/2026/03/bild.php
```

  Beleg: belege/03_htaccess_weiterleitungen.txt

### 7.7 SUID/SGID-Dateien in Webspace und tmp-Verzeichnissen

- ✅ Keine SUID/SGID-Dateien in Webspace oder tmp

### 7.8 Ausführbare Dateien in tmp-Verzeichnissen

- ✅ Keine ausführbaren Dateien in tmp-Verzeichnissen

### 7.9 Immutable-Flags im Webspace (chattr +i — Malware-Selbstschutz)

- ✅ Keine Immutable-Flags auf PHP-Dateien (Stichprobe max. 8000 Dateien)

### 7.10 Als Schlüssel-/Konfigdatei getarnte Binaries

- ✅ Keine als Schlüssel-/Konfigdatei getarnten Binaries

### 7.11 YARA-Signaturscan (optional)

  YARA-Scan nicht aktiviert — mit --yara einschalten (auf großen Webspaces langsam)

## 11. WORDPRESS-DATENBANK-PRÜFUNG


### 11.1 Gefundene WordPress-Installationen

  WordPress-Installationen: 4

```
<PRUEFSTAND>/vhosts/kunde-zwei.example/httpdocs/wp-config.php
<PRUEFSTAND>/vhosts/kunde-eins.example/httpdocs/wp-config.php
<PRUEFSTAND>/vhosts/kunde-eins.example/backup/httpdocs/wp-config.php
<PRUEFSTAND>/vhosts/kunde-drei.example/httpdocs/wp-config.php
```

- ⚪ **Nicht messbar: grep ohne PCRE-Unterstützung (-P) — Zugangsdaten aus wp-config.php nicht lesbar, keine Datenbank-Prüfung möglich**

### 11.9 WordPress-DB-Verdikt

- ✅ WP-DB-VERDIKT: unauffällig

🟢 **Keine Angreifer-Spuren in den WordPress-Datenbanken** (keine neuen Admins, keine manipulierten Optionen).


### 11.10 WP Toolkit — Instanz-Status (Plesk-eigene Bewertung, read-only)

  WP Toolkit / python3 nicht verfügbar — Plesk-Instanzbewertung nicht abgefragt

## 12. JOOMLA-PRÜFUNG


### 12.1 Gefundene Joomla-Installationen

  Joomla-Installationen: 1

```
<PRUEFSTAND>/vhosts/kunde-zwei.example/joomla.kunde-zwei.example/configuration.php
```

  Joomla-Datenbestand: Stand 2026-08-05 (0 Tage alt)

#### kunde-zwei.example/joomla.kunde-zwei.example  (Prefix: `jos_`)

- ⚠️  **kunde-zwei.example/joomla.kunde-zwei.example: Joomla-Version nicht bestimmbar (weder joomla.xml noch Version.php lesbar)**
- ⚠️  **kunde-zwei.example/joomla.kunde-zwei.example: Standard-Tabellenpräfix jos_ (macht SQL-Injection-Angriffe zielgenau ohne Vorab-Erkundung)**
  kunde-zwei.example/joomla.kunde-zwei.example: kein Datenbankname bzw. kein gültiges Präfix — Datenbank-Prüfung übersprungen

### 12.7 Abgleich mit bekannten Schwachstellen — kunde-zwei.example/joomla.kunde-zwei.example


### 12.8 Joomla-typische Schaddateien — kunde-zwei.example/joomla.kunde-zwei.example

- ✅ kunde-zwei.example/joomla.kunde-zwei.example: keine Joomla-typischen Schaddateien gefunden

### 12.10 Joomla-Verdikt

- ✅ JOOMLA-VERDIKT: unauffällig

🟢 **Keine Angreifer-Spuren in den Joomla-Installationen** — Version schlüssig, Konfiguration ohne kritische Schwächen, kein Hinweis auf einen Datenabfluss über die Programmschnittstelle.


## 12b. NEXTCLOUD-PRÜFUNG

- ⚠️  **1 Nextcloud-Sicherungskopie(n) nicht geprüft — sie werden nicht ausgeliefert, würden Schadcode beim Zurückspielen aber wiederherstellen**
  Nextcloud-Installationen: 1

```
<PRUEFSTAND>/vhosts/kunde-zwei.example/cloud.kunde-zwei.example
```


### 12b.1 kunde-zwei.example/cloud.kunde-zwei.example

  Fassung: 28.0.1.2
- 🔴 **KRITISCH: kunde-zwei.example/cloud.kunde-zwei.example: Root-.htaccess trägt Angreifer-Merkmale (Freigabeliste mit fremden Dateinamen)**

```
1:Order allow,deny
2:<Files "filefuns.php">
```

  Beleg: belege/04_nextcloud_htaccess_kunde-zwei_example_cloud_kunde-zwei_example.txt
- 🔴 **KRITISCH: kunde-zwei.example/cloud.kunde-zwei.example: bekannte Schaddateien der Nextcloud-Kampagne gefunden**

```
<PRUEFSTAND>/vhosts/kunde-zwei.example/cloud.kunde-zwei.example/filefuns.php
```

- 🔴 **KRITISCH: kunde-zwei.example/cloud.kunde-zwei.example: verschachtelte Verzeichnisse (z. B. config/config) — typisch für diese Kampagne**

```
<PRUEFSTAND>/vhosts/kunde-zwei.example/cloud.kunde-zwei.example/config/config
```

- ⚪ **Nicht messbar: kunde-zwei.example/cloud.kunde-zwei.example: Eigentümer oder PHP nicht ermittelbar — Kern-Integrität nicht geprüft**

## 12c. NEXTCLOUD-HÄRTUNGSSTAND

  1 Sicherungskopie(n) übersprungen — sie werden nicht ausgeliefert und sind kein eigener Härtungsgegenstand

### 12c.1 kunde-zwei.example/cloud.kunde-zwei.example

- ⚪ **Nicht messbar: kunde-zwei.example/cloud.kunde-zwei.example: occ nicht ausführbar — Härtungsstand nicht messbar**
  Für die messbaren Instanzen keine Härtungslücken. Für die übrigen liegt kein Ergebnis vor — das ist keine Entwarnung.

## 13b. .HTACCESS — SICHERUNG UND EINORDNUNG


### 13b.1 Sicherung

- ✅ 5 von 5 .htaccess-Dateien gesichert (belege/htaccess/)

### 13b.2 Einordnung der Direktiven

- ✅ kunde-eins.example/httpdocs/.htaccess (wordpress): 2 eigene Direktive(n), nichts Fremdes
- 🔴 **KRITISCH: kunde-zwei.example/backups/updater-abc123/nextcloud-28.0.1.2-1700000000/.htaccess (nextcloud): 3 Angreifer-Direktive(n) in der .htaccess**

```
Order allow,deny                                      Apache-2.2-Zugriffssyntax in einer Nextcloud — dort nie vom Kern erzeugt
<Files "filefuns.php">                                Dateiname aus bekannter Schadcode-Kampagne
<Files filefuns.php> … Allow from all                 Sperre fuer alles, Freigabe fuer genau diese eine PHP-Datei
```

  Beleg: belege/05_htaccess_fremd_kunde-zwei_example_backups_updater-abc123_nextcloud-28_0_1_2-1700000000__htaccess.txt
- 🔴 **KRITISCH: kunde-zwei.example/cloud.kunde-zwei.example/.htaccess (nextcloud): 3 Angreifer-Direktive(n) in der .htaccess**

```
Order allow,deny                                      Apache-2.2-Zugriffssyntax in einer Nextcloud — dort nie vom Kern erzeugt
<Files "filefuns.php">                                Dateiname aus bekannter Schadcode-Kampagne
<Files filefuns.php> … Allow from all                 Sperre fuer alles, Freigabe fuer genau diese eine PHP-Datei
```

  Beleg: belege/06_htaccess_fremd_kunde-zwei_example_cloud_kunde-zwei_example__htaccess.txt
- 🔴 **KRITISCH: kunde-zwei.example/httpdocs/.htaccess (wordpress): 2 Angreifer-Direktive(n) in der .htaccess**

```
AddType application/x-httpd-php .jpg                  PHP-Ausfuehrung fuer eine Nicht-PHP-Endung
php_value auto_prepend_file /var/www/vhosts/<anderer Kunde 2>  auto_prepend_file auf eine Datei im Webspace
```

  Beleg: belege/07_htaccess_fremd_kunde-zwei_example_httpdocs__htaccess.txt
- 🔴 **KRITISCH: kunde-zwei.example/httpdocs/wp-content/uploads/.htaccess (unbekannt): 1 Angreifer-Direktive(n) in der .htaccess**

```
<Files bild.php> … Allow from all                     Freigabe fuer eine PHP-Datei in einem Verzeichnis, in das keine gehoert
```

  Beleg: belege/08_htaccess_fremd_kunde-zwei_example_httpdocs_wp-content_uploads__htaccess.txt
  Beleg: belege/09_htaccess_einordnung.txt

### 13b.3 Wirksamkeit

- 🔴 **KRITISCH: Kein Apache-Prozess, aber nginx läuft — .htaccess-Dateien werden NICHT ausgewertet und schützen nichts**

## 14. ZUSAMMENFASSUNG


### 14.1 Befund-Statistik

| Kategorie | Anzahl |
|---|---|
| 🔴 Kritische Befunde | 9 |
| ⚠️ Warnungen | 4 |
| ✅ Unauffällige Prüfungen | 12 |
| ⚪ Nicht messbar | 3 |

> **3 Prüfung(en) haben keine Aussage geliefert.** Ihr Ergebnis ist weder
> ein Befund noch eine Entwarnung — der jeweilige Bereich ist ungeprüft:
>
> - grep ohne PCRE-Unterstützung (-P) — Zugangsdaten aus wp-config.php nicht lesbar, keine Datenbank-Prüfung möglich
> - kunde-zwei.example/cloud.kunde-zwei.example: Eigentümer oder PHP nicht ermittelbar — Kern-Integrität nicht geprüft
> - kunde-zwei.example/cloud.kunde-zwei.example: occ nicht ausführbar — Härtungsstand nicht messbar

### 14.2 Empfohlene Sofortmaßnahmen

| Priorität | Maßnahme | Status |
|---|---|---|
| 🔴 Sofort | Alle Passwörter rotieren (Plesk, FTP, SSH, DB) | ☐ |
| 🔴 Sofort | SSH Root-Login deaktivieren (`PermitRootLogin no`) | ☐ |
| 🔴 Sofort | SSH auf Key-only (`PasswordAuthentication no`) | ☐ |
| 🔴 Sofort | Google Search Console: alle unbekannten Inhaber entfernen | ☐ |
| 🟠 Kurzfristig | Fail2ban aktivieren (ssh, ftp, plesk-panel) | ☐ |
| 🟠 Kurzfristig | ModSecurity mit OWASP CRS aktivieren | ☐ |
| 🟠 Kurzfristig | PHP `disable_functions` härten | ☐ |
| 🟠 Kurzfristig | Maldet/ClamAV vollständigen Scan laufen lassen | ☐ |
| 🟡 Mittelfristig | WordPress-Neuinstallation aus sauberem Backup | ☐ |
| 🟡 Mittelfristig | WP-Admin mit HTTP-Auth absichern | ☐ |
| 🟡 Mittelfristig | Automatische Malware-Scans einrichten | ☐ |
| 🟡 Mittelfristig | Intrusion Detection System (AIDE/Tripwire) | ☐ |

---
*Bericht erstellt am: <ZEIT>*
*Tool: wp_plesk_forensik.sh <FASSUNG> — netztaucher | digital*
  findings.json geschrieben: <PRUEFSTAND>/ablage/forensik/<LAUF-ID>/betreiber/findings.json


---

> **Hinweis zum Datenschutz.** Dieser Server beherbergt weitere Kunden. Wo serverweite Prüfungen deren Domains oder Systemkonten berührten, stehen Platzhalter (`<anderer Kunde N>`); derselbe Nachbar trägt dabei immer dieselbe Nummer, sodass Zusammenhänge erkennbar bleiben. Betroffen waren 2 fremde Kennungen. Die unmaskierte Fassung verbleibt beim Betreiber.
  PDF übersprungen (pandoc/weasyprint/reportgen nicht verfügbar).

> **Eingeschränkter Lauf.** Die folgenden Prüfabschnitte wurden auf ausdrückliche Auswahl hin NICHT ausgeführt. Ihre Ergebnisse fehlen in diesem Bericht — das ist keine Entwarnung für diese Bereiche:
>
> - 1. System-Übersicht
> - 2. Logs sichern
> - 3. Zugriffs-Analyse
> - 5. Benutzer & Rechte
> - 6. Cronjobs & Persistenz
> - 8. Netzwerk & Dienste
> - 9. Sicherheits-Dienste
> - 10. Andere Domains
> - 13. Root- & Eskalations-Prüfung

