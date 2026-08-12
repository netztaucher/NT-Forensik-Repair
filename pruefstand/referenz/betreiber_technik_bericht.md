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


### 7.0 Datei-Inventar (Inode und Zeitstempel sichern)

  Inventar: 617 Datei(en) erfasst, davon 617 mit Anlegezeit (belege/00_dateien.tsv)

### 7.1 Kürzlich veränderte PHP-Dateien (letzte 30 Tage)

  Kürzlich veränderte .php-Dateien:

```
<INODE> -rw-r--r-- <EIGNER> 0 <MTIME> <PRUEFSTAND>/vhosts/kunde-zwei.example/httpdocs/wp-content/uploads/index.php
<INODE> -rw-r--r-- <EIGNER> 12 <MTIME> <PRUEFSTAND>/vhosts/kunde-zwei.example/httpdocs/wp-content/uploads/cache/index.php
<INODE> -rw-r--r-- <EIGNER> 12 <MTIME> <PRUEFSTAND>/vhosts/kunde-zwei.example/httpdocs/wp-content/uploads/forminator/index.php
<INODE> -rw-r--r-- <EIGNER> 17 <MTIME> <PRUEFSTAND>/vhosts/kunde-zwei.example/httpdocs/wp-load.php
<INODE> -rw-r--r-- <EIGNER> 202 <MTIME> <PRUEFSTAND>/vhosts/kunde-zwei.example/httpdocs/wp-content/uploads/2026/03/hilfe.php
<INODE> -rw-r--r-- <EIGNER> 230 <MTIME> <PRUEFSTAND>/vhosts/kunde-zwei.example/joomla.kunde-zwei.example/configuration.php
<INODE> -rw-r--r-- <EIGNER> 29 <MTIME> <PRUEFSTAND>/vhosts/kunde-zwei.example/httpdocs/wp-includes/version.php
<INODE> -rw-r--r-- <EIGNER> 33469 <MTIME> <PRUEFSTAND>/vhosts/kunde-zwei.example/httpdocs/wp-content/plugins/pruefstand-kev/gross-sauber.php
<INODE> -rw-r--r-- <EIGNER> 33477 <MTIME> <PRUEFSTAND>/vhosts/kunde-zwei.example/httpdocs/wp-content/plugins/pruefstand-kopflos/gross-sauber.php
<INODE> -rw-r--r-- <EIGNER> 33988 <MTIME> <PRUEFSTAND>/vhosts/kunde-zwei.example/httpdocs/wp-content/plugins/pruefstand-kev/gross-injiziert.php
<INODE> -rw-r--r-- <EIGNER> 33996 <MTIME> <PRUEFSTAND>/vhosts/kunde-zwei.example/httpdocs/wp-content/plugins/pruefstand-kopflos/gross-injiziert.php
<INODE> -rw-r--r-- <EIGNER> 34 <MTIME> <PRUEFSTAND>/vhosts/kunde-zwei.example/joomla.kunde-zwei.example/libraries/src/Version.php
<INODE> -rw-r--r-- <EIGNER> 43 <MTIME> <PRUEFSTAND>/vhosts/kunde-zwei.example/httpdocs/wp-content/uploads/2026/03/bild.php
<INODE> -rw-r--r-- <EIGNER> 53 <MTIME> <PRUEFSTAND>/vhosts/kunde-zwei.example/httpdocs/wp-content/plugins/pruefstand-alt/lib/b.php
<INODE> -rw-r--r-- <EIGNER> 53 <MTIME> <PRUEFSTAND>/vhosts/kunde-zwei.example/httpdocs/wp-content/plugins/pruefstand-alt/lib/c.php
<INODE> -rw-r--r-- <EIGNER> 53 <MTIME> <PRUEFSTAND>/vhosts/kunde-zwei.example/httpdocs/wp-content/plugins/pruefstand-alt/lib/d.php
<INODE> -rw-r--r-- <EIGNER> 53 <MTIME> <PRUEFSTAND>/vhosts/kunde-zwei.example/httpdocs/wp-content/plugins/pruefstand-alt/lib/e.php
<INODE> -rw-r--r-- <EIGNER> 53 <MTIME> <PRUEFSTAND>/vhosts/kunde-zwei.example/httpdocs/wp-content/plugins/pruefstand-kev/lib/a.php
<INODE> -rw-r--r-- <EIGNER> 53 <MTIME> <PRUEFSTAND>/vhosts/kunde-zwei.example/httpdocs/wp-content/plugins/pruefstand-kev/lib/b.php
<INODE> -rw-r--r-- <EIGNER> 53 <MTIME> <PRUEFSTAND>/vhosts/kunde-zwei.example/httpdocs/wp-content/plugins/pruefstand-kev/lib/c.php
<INODE> -rw-r--r-- <EIGNER> 53 <MTIME> <PRUEFSTAND>/vhosts/kunde-zwei.example/httpdocs/wp-content/plugins/pruefstand-kev/lib/d.php
<INODE> -rw-r--r-- <EIGNER> 53 <MTIME> <PRUEFSTAND>/vhosts/kunde-zwei.example/httpdocs/wp-content/plugins/pruefstand-kev/lib/e.php
<INODE> -rw-r--r-- <EIGNER> 57 <MTIME> <PRUEFSTAND>/vhosts/kunde-zwei.example/httpdocs/wp-content/plugins/pruefstand-kopflos/lib/a.php
<INODE> -rw-r--r-- <EIGNER> 57 <MTIME> <PRUEFSTAND>/vhosts/kunde-zwei.example/httpdocs/wp-content/plugins/pruefstand-kopflos/lib/b.php
<INODE> -rw-r--r-- <EIGNER> 57 <MTIME> <PRUEFSTAND>/vhosts/kunde-zwei.example/httpdocs/wp-content/plugins/pruefstand-kopflos/lib/c.php
<INODE> -rw-r--r-- <EIGNER> 57 <MTIME> <PRUEFSTAND>/vhosts/kunde-zwei.example/httpdocs/wp-content/plugins/pruefstand-kopflos/lib/d.php
<INODE> -rw-r--r-- <EIGNER> 57 <MTIME> <PRUEFSTAND>/vhosts/kunde-zwei.example/httpdocs/wp-content/plugins/pruefstand-kopflos/lib/e.php
<INODE> -rw-r--r-- <EIGNER> 73 <MTIME> <PRUEFSTAND>/vhosts/kunde-zwei.example/httpdocs/wp-content/plugins/pruefstand-kopflos/pruefstand-kopflos.php
<INODE> -rw-r--r-- <EIGNER> 82 <MTIME> <PRUEFSTAND>/vhosts/kunde-zwei.example/httpdocs/wp-content/plugins/pruefstand-kev/pruefstand-kev.php
<INODE> -rw-r--r-- <EIGNER> 84 <MTIME> <PRUEFSTAND>/vhosts/kunde-zwei.example/httpdocs/wp-content/plugins/pruefstand-alt/pruefstand-alt.php
```

  Beleg: belege/001_veraenderte_php_dateien.txt

### 7.2 PHP-Dateien in Upload-Verzeichnissen

- 🔴 **KRITISCH: PHP-Dateien in Upload-Verzeichnissen (nach Guard-Filter, extrem verdächtig; 3 Guard-/Plugin-Dateien gefiltert)**

```
<PRUEFSTAND>/vhosts/kunde-zwei.example/httpdocs/wp-content/uploads/2026/03/bild.php
<PRUEFSTAND>/vhosts/kunde-zwei.example/httpdocs/wp-content/uploads/2026/03/hilfe.php

```

  Beleg: belege/002_php_in_uploads_mit_hashes.txt

### 7.3 Webshell-Muster (Inhalt) — zweistufig

- ✅ Keine kleinen Obfuskations-Dropper gefunden
- ✅ Keine gefährlichen Funktionen in kleinen PHP-Dateien

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

  Beleg: belege/003_htaccess_weiterleitungen.txt
- 🔴 **KRITISCH: .htaccess gibt gezielt einzelne PHP-Datei(en) frei — typisch für abgesicherte Webshells (3)**

```
=== <PRUEFSTAND>/vhosts/kunde-zwei.example/httpdocs/wp-content/uploads/.htaccess ===
Order allow,deny
<Files "bild.php">
  Allow from all
</Files>

=== <PRUEFSTAND>/vhosts/kunde-zwei.example/cloud.kunde-zwei.example/.htaccess ===
Order allow,deny
<Files "filefuns.php">
  Allow from all
</Files>

=== <PRUEFSTAND>/vhosts/kunde-zwei.example/backups/updater-abc123/nextcloud-28.0.1.2-1700000000/.htaccess ===
Order allow,deny
<Files "filefuns.php">
  Allow from all
</Files>


```

  Beleg: belege/004_htaccess_einzelfreigabe_php.txt

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

### 7.13 PHP-Code in Medien- und Asset-Dateien

- 🔴 **KRITISCH: PHP-Code in 2 Mediendatei(en) — in einem echten Bild gehört kein PHP**

```
<PRUEFSTAND>/vhosts/kunde-zwei.example/httpdocs/wp-content/plugins/beispiel-plugin/assets/banner.png
    Typ:      data
    Angelegt: ?
    SHA256:   <SHA256>
    Nutzlast: 

<PRUEFSTAND>/vhosts/kunde-zwei.example/httpdocs/wp-content/uploads/2026/03/logo.png
    Typ:      data
    Angelegt: ?
    SHA256:   <SHA256>
    Nutzlast: 


```

  Beleg: belege/005_php_in_mediendateien.txt

### 7.14 Massenhaft gleiche Zeitstempel (Spurenverwischung)

- ✅ Keine auffälligen Zeitstempel-Häufungen

### 7.15 Injektion in grosse Dateien (ohne Referenz)

  7 grosse Datei(en) mit auffälliger Verteilung — nach Punkten sortiert, Einordnung offen

```
<PRUEFSTAND>/vhosts/kunde-drei.example/httpdocs/wp-content/plugins/pruefstand-aktuell/gross-injiziert.php	4	DICHTE=120,RANDLAGE
<PRUEFSTAND>/vhosts/kunde-drei.example/httpdocs/wp-content/plugins/pruefstand-alt/gross-injiziert.php	4	DICHTE=120,RANDLAGE
<PRUEFSTAND>/vhosts/kunde-drei.example/httpdocs/wp-content/plugins/pruefstand-kev/gross-injiziert.php	4	DICHTE=120,RANDLAGE
<PRUEFSTAND>/vhosts/kunde-zwei.example/httpdocs/wp-content/plugins/pruefstand-aktuell/gross-injiziert.php	4	DICHTE=120,RANDLAGE
<PRUEFSTAND>/vhosts/kunde-zwei.example/httpdocs/wp-content/plugins/pruefstand-alt/gross-injiziert.php	4	DICHTE=120,RANDLAGE
<PRUEFSTAND>/vhosts/kunde-zwei.example/httpdocs/wp-content/plugins/pruefstand-kev/gross-injiziert.php	4	DICHTE=120,RANDLAGE
<PRUEFSTAND>/vhosts/kunde-zwei.example/httpdocs/wp-content/plugins/pruefstand-kopflos/gross-injiziert.php	4	DICHTE=120,RANDLAGE
```

  Beleg: belege/006_injektion_grosse_dateien.txt

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


## 12r. ANWENDUNGS-PRÜFREZEPTE


### 12r.1 Nextcloud

  Installationen: 1

```
<PRUEFSTAND>/vhosts/kunde-zwei.example/cloud.kunde-zwei.example
```

- ⚠️  **Nextcloud: 1 Sicherungskopie(n) nicht geprüft — sie werden nicht ausgeliefert, würden Schadcode beim Zurückspielen aber wiederherstellen**

### 12r.1.x kunde-zwei.example/cloud.kunde-zwei.example

  Fassung: 28.0.1.2
- 🔴 **KRITISCH: kunde-zwei.example/cloud.kunde-zwei.example: bekannte Schaddatei der Nextcloud-Kampagne (filefuns.php)**

```
<PRUEFSTAND>/vhosts/kunde-zwei.example/cloud.kunde-zwei.example/filefuns.php
```

- 🔴 **KRITISCH: kunde-zwei.example/cloud.kunde-zwei.example: Root-.htaccess trägt Angreifer-Merkmale (Freigabeliste mit fremden Dateinamen)**

```
1:Order allow,deny
2:<Files "filefuns.php">
```

  Beleg: belege/007_nextcloud_htaccess_kunde-zwei_example_cloud_kunde-zwei_example.txt
- 🔴 **KRITISCH: kunde-zwei.example/cloud.kunde-zwei.example: verschachtelte Verzeichnisse (z. B. config/config) — typisch für diese Kampagne**

```
<PRUEFSTAND>/vhosts/kunde-zwei.example/cloud.kunde-zwei.example/config/config
```

- ⚪ **Nicht messbar: kunde-zwei.example/cloud.kunde-zwei.example: Werkzeug antwortet nicht verwertbar — nicht geprüft**

### 12r.2 WordPress

  Installationen: 3

```
<PRUEFSTAND>/vhosts/kunde-drei.example/httpdocs
<PRUEFSTAND>/vhosts/kunde-eins.example/httpdocs
<PRUEFSTAND>/vhosts/kunde-zwei.example/httpdocs
```


### 12r.2.x kunde-drei.example/httpdocs

- ⚪ **Nicht messbar: kunde-drei.example/httpdocs: 1 Bestandteil(e) ohne lesbare Fassung — für sie ist keine Aussage zur Angreifbarkeit möglich**
  Beleg: belege/008_wp_version_nicht_bewertbar_kunde-drei_example_httpdocs.txt
- ✅ kunde-drei.example/httpdocs: keine bekannte Schwachstelle im vorliegenden Datenbestand (Stand <STAND>)
- ✅ kunde-drei.example/httpdocs: keine Doorway-.htaccess-Signatur
- ✅ kunde-drei.example/httpdocs: keine @include base64_decode()-Injektion
- ✅ kunde-drei.example/httpdocs: 2 Plugin(s) gegen wordpress.org geprüft — keine veränderte Codedatei
- ⚪ **Nicht messbar: kunde-drei.example/httpdocs: 1 Plugin(s) ohne Prüfsummensatz und alle Themes — Unversehrtheit nicht feststellbar (Premium, Fork, Eigenbau; für Themes veröffentlicht wordpress.org keine Prüfsummen)**
  Beleg: belege/009_wp_ohne_pruefsummen_kunde-drei_example_httpdocs.txt
- ✅ kunde-drei.example/httpdocs: WordPress-Core unverändert (verify-checksums)
  kunde-drei.example/httpdocs: kein Wordfence in dieser Installation — keine Zweitmeinung verfügbar

### 12r.2.x kunde-eins.example/httpdocs

- ✅ kunde-eins.example/httpdocs: keine Doorway-.htaccess-Signatur
- ✅ kunde-eins.example/httpdocs: keine @include base64_decode()-Injektion
- ✅ kunde-eins.example/httpdocs: WordPress-Core unverändert (verify-checksums)
  kunde-eins.example/httpdocs: kein Wordfence in dieser Installation — keine Zweitmeinung verfügbar

### 12r.2.x kunde-zwei.example/httpdocs

- ⚠️  **kunde-zwei.example/httpdocs: core wordpress 6.4.1 ist von einer bekannten Schwachstelle betroffen ([6.0 … 6.4.1]) CVE-2026-90004 — behoben in 6.4.2.**
- ⚠️  **kunde-zwei.example/httpdocs: plugin pruefstand-alt 2.0.3 ist von einer bekannten Schwachstelle betroffen ([2.0 … 2.4.1]) CVE-2026-90002 — behoben in 2.5.**
- 🔴 **KRITISCH: kunde-zwei.example/httpdocs: plugin pruefstand-kev 1.2 ist von einer bekannten Schwachstelle betroffen ((* … 2.0)) CVE-2026-90001 — behoben in 2.0. Diese Lücke wird nachweislich aktiv ausgenutzt — sofort handeln.**
- ⚠️  **kunde-zwei.example/httpdocs: theme pruefstand-thema 0.9 ist von einer bekannten Schwachstelle betroffen ((* … 1.0)) CVE-2026-90005 — behoben in 1.0.**
- ⚠️  **kunde-zwei.example/httpdocs: Bibliothek (in einem Plugin) pruefstand/bibliothek 1.2.0 ist von einer bekannten Schwachstelle betroffen ([1.0.0 … 1.4.0)) CVE-2026-90006 — behoben in 1.4.0.**
- ⚪ **Nicht messbar: kunde-zwei.example/httpdocs: 3 Bestandteil(e) ohne lesbare Fassung — für sie ist keine Aussage zur Angreifbarkeit möglich**
  Beleg: belege/010_wp_version_nicht_bewertbar_kunde-zwei_example_httpdocs.txt
  Beleg: belege/011_wp_schwachstellen_kunde-zwei_example_httpdocs.txt
- ✅ kunde-zwei.example/httpdocs: keine Doorway-.htaccess-Signatur
- 🔴 **KRITISCH: kunde-zwei.example/httpdocs: 1 Datei(en) mit @include base64_decode() — getarnte Payload-Nachladung**

```
<PRUEFSTAND>/vhosts/kunde-zwei.example/httpdocs/wp-content/mu-plugins/cache.php
```

  Beleg: belege/012_wp_include_injektion_kunde-zwei_example_httpdocs.txt
- ⚠️  **kunde-zwei.example/httpdocs: 1 mu-Plugin(s) — laufen ohne Aktivierung und erscheinen in keiner Pluginliste**

```
<PRUEFSTAND>/vhosts/kunde-zwei.example/httpdocs/wp-content/mu-plugins/cache.php
```

- 🔴 **KRITISCH: kunde-zwei.example/httpdocs: 8 veränderte Plugin-Codedatei(en) gegenüber wordpress.org — Plugin neu installieren, Dateien vorher sichern**

```
<PRUEFSTAND>/vhosts/kunde-zwei.example/httpdocs/wp-content/plugins/pruefstand-aktuell/gross-injiziert.php
<PRUEFSTAND>/vhosts/kunde-zwei.example/httpdocs/wp-content/plugins/pruefstand-aktuell/gross-sauber.php
<PRUEFSTAND>/vhosts/kunde-zwei.example/httpdocs/wp-content/plugins/pruefstand-aktuell/pruefstand-aktuell.php
<PRUEFSTAND>/vhosts/kunde-zwei.example/httpdocs/wp-content/plugins/pruefstand-aktuell/lib/b.php
<PRUEFSTAND>/vhosts/kunde-zwei.example/httpdocs/wp-content/plugins/pruefstand-aktuell/lib/c.php
<PRUEFSTAND>/vhosts/kunde-zwei.example/httpdocs/wp-content/plugins/pruefstand-aktuell/lib/a.php
<PRUEFSTAND>/vhosts/kunde-zwei.example/httpdocs/wp-content/plugins/pruefstand-aktuell/lib/d.php
<PRUEFSTAND>/vhosts/kunde-zwei.example/httpdocs/wp-content/plugins/pruefstand-aktuell/lib/e.php
```

  Beleg: belege/013_wp_plugin_veraendert_kunde-zwei_example_httpdocs.txt
- ⚪ **Nicht messbar: kunde-zwei.example/httpdocs: 2 Plugin(s) ohne Prüfsummensatz und alle Themes — Unversehrtheit nicht feststellbar (Premium, Fork, Eigenbau; für Themes veröffentlicht wordpress.org keine Prüfsummen)**
  Beleg: belege/014_wp_ohne_pruefsummen_kunde-zwei_example_httpdocs.txt
- 🔴 **KRITISCH: kunde-zwei.example/httpdocs: 1 veränderte Core-Datei(en) — Injektion oder Manipulation**

```
<PRUEFSTAND>/vhosts/kunde-zwei.example/httpdocs/wp-includes/load.php
```

  Beleg: belege/015_wp_core_veraendert_kunde-zwei_example_httpdocs.txt
- ⚠️  **kunde-zwei.example/httpdocs: 1 Core-fremde Datei(en) in wp-admin/wp-includes — prüfen**
  Beleg: belege/016_wp_core_fremd_kunde-zwei_example_httpdocs.txt
- ⚠️  **kunde-zwei.example/httpdocs: Wordfence-Scan ist <TAGE> Tage alt — was danach abgelegt wurde, steht in diesem Bestand nicht**
  kunde-zwei.example/httpdocs: Wordfence mit freiem Schlüssel — der Signaturbestand ist kleiner und läuft dem kostenpflichtigen um 30 Tage hinterher
- ⚠️  **kunde-zwei.example/httpdocs: Wordfence führt 1 Plugin(s) als verwundbar**

```
The Plugin "pruefstand-kev" has a known security vulnerability
```

- ⚠️  **kunde-zwei.example/httpdocs: Wordfence führt 1 Theme(s) als verwundbar**

```
The Theme "pruefstand-thema" has a known security vulnerability
```

- ⚠️  **kunde-zwei.example/httpdocs: Wordfence hat Pfade vom Scan ausgenommen — ein unauffälliger Wordfence-Bericht ist für diese Bereiche KEINE Entwarnung**

```
Scan skipped 99 paths outside the WordPress installation
```

  Beleg: belege/017_wordfence_uebersprungen_kunde-zwei_example_httpdocs.txt
- ⚠️  **kunde-zwei.example/httpdocs: Wordfence meldet 1 Datei(en) als verändert gegenüber dem Original — Integritätsabweichung, kein Signaturtreffer**

```
Modified plugin file: wp-content/plugins/pruefstand-aktuell/pruefstand-aktuell.php
```

  kunde-zwei.example/httpdocs: Wordfence führt 1 Plugin(s) als aufgegeben (kein Hersteller-Support mehr)

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

  Beleg: belege/018_htaccess_fremd_kunde-zwei_example_backups_updater-abc123_nextcloud-28_0_1_2-1700000000__htaccess.txt
- 🔴 **KRITISCH: kunde-zwei.example/cloud.kunde-zwei.example/.htaccess (nextcloud): 3 Angreifer-Direktive(n) in der .htaccess**

```
Order allow,deny                                      Apache-2.2-Zugriffssyntax in einer Nextcloud — dort nie vom Kern erzeugt
<Files "filefuns.php">                                Dateiname aus bekannter Schadcode-Kampagne
<Files filefuns.php> … Allow from all                 Sperre fuer alles, Freigabe fuer genau diese eine PHP-Datei
```

  Beleg: belege/019_htaccess_fremd_kunde-zwei_example_cloud_kunde-zwei_example__htaccess.txt
- 🔴 **KRITISCH: kunde-zwei.example/httpdocs/.htaccess (wordpress): 2 Angreifer-Direktive(n) in der .htaccess**

```
AddType application/x-httpd-php .jpg                  PHP-Ausfuehrung fuer eine Nicht-PHP-Endung
php_value auto_prepend_file /var/www/vhosts/<anderer Kunde 2>  auto_prepend_file auf eine Datei im Webspace
```

  Beleg: belege/020_htaccess_fremd_kunde-zwei_example_httpdocs__htaccess.txt
- 🔴 **KRITISCH: kunde-zwei.example/httpdocs/wp-content/uploads/.htaccess (unbekannt): 1 Angreifer-Direktive(n) in der .htaccess**

```
<Files bild.php> … Allow from all                     Freigabe fuer eine PHP-Datei in einem Verzeichnis, in das keine gehoert
```

  Beleg: belege/021_htaccess_fremd_kunde-zwei_example_httpdocs_wp-content_uploads__htaccess.txt
  Beleg: belege/022_htaccess_einordnung.txt

### 13b.3 Wirksamkeit

- 🔴 **KRITISCH: Kein Apache-Prozess, aber nginx läuft — .htaccess-Dateien werden NICHT ausgewertet und schützen nichts**

## 13c. FREMDER YARA-REGELSATZ (SUCHHILFSMITTEL)

- ⚠️  **php-malware-finder: 4 Datei(en) mit Treffern — nach Regelanzahl sortiert, jeder Treffer gehört gesichtet (9 als unverändert bestätigte Datei(en) herausgefiltert)**

```
3 Regel(n): <PRUEFSTAND>/vhosts/kunde-zwei.example/httpdocs/wp-content/uploads/2026/03/bild.php — ObfuscatedPhp DodgyStrings SuspiciousEncoding
3 Regel(n): <PRUEFSTAND>/vhosts/kunde-zwei.example/httpdocs/wp-content/uploads/2026/03/hilfe.php — ObfuscatedPhp DodgyStrings SuspiciousEncoding
3 Regel(n): <PRUEFSTAND>/vhosts/kunde-zwei.example/httpdocs/wp-includes/load.php — ObfuscatedPhp DodgyStrings HexEncoding
2 Regel(n): <PRUEFSTAND>/vhosts/kunde-zwei.example/httpdocs/wp-content/plugins/pruefstand-aktuell/pruefstand-aktuell.php — ObfuscatedPhp DodgyStrings
```

  Beleg: belege/023_php_malware_finder_treffer.txt
  Quelle: Prüfstand-Attrappe, Regelstand 0 Tage alt — der Regelsatz wird vom Projekt kaum noch gepflegt

## 14. ZUSAMMENFASSUNG

  Fundstellen-Details: <PRUEFSTAND>/ablage/forensik/<LAUF-ID>/kunde/befunde_details.md (20 Fund(e), 7 Familien, 1 zu prüfen)

### 14.1 Befund-Statistik

| Kategorie | Anzahl |
|---|---|
| 🔴 Kritische Befunde | 15 |
| ⚠️ Warnungen | 16 |
| ✅ Unauffällige Prüfungen | 22 |
| ⚪ Nicht messbar | 5 |

> **5 Prüfung(en) haben keine Aussage geliefert.** Ihr Ergebnis ist weder
> ein Befund noch eine Entwarnung — der jeweilige Bereich ist ungeprüft:
>
> - kunde-zwei.example/cloud.kunde-zwei.example: Werkzeug antwortet nicht verwertbar — nicht geprüft
> - kunde-drei.example/httpdocs: 1 Bestandteil(e) ohne lesbare Fassung — für sie ist keine Aussage zur Angreifbarkeit möglich
> - kunde-drei.example/httpdocs: 1 Plugin(s) ohne Prüfsummensatz und alle Themes — Unversehrtheit nicht feststellbar (Premium, Fork, Eigenbau; für Themes veröffentlicht wordpress.org keine Prüfsummen)
> - kunde-zwei.example/httpdocs: 3 Bestandteil(e) ohne lesbare Fassung — für sie ist keine Aussage zur Angreifbarkeit möglich
> - kunde-zwei.example/httpdocs: 2 Plugin(s) ohne Prüfsummensatz und alle Themes — Unversehrtheit nicht feststellbar (Premium, Fork, Eigenbau; für Themes veröffentlicht wordpress.org keine Prüfsummen)

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
- ✅ Kundenspur enthält keine fremden Kennungen
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

