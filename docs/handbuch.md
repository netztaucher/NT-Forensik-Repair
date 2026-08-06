# NT-Forensik — Handbuch

Vollständiges Benutzerhandbuch zu `wp_plesk_forensik.sh`.

> Ergänzende Dokumente: [Erkennungs-Referenz](erkennung.md) · [Incident-Response-Playbook](incident-response.md) · [Runbook (manuelle Einzelschritte)](runbook.md)

---

## Inhalt

1. [Für wen ist das Tool](#1-für-wen-ist-das-tool)
2. [Voraussetzungen](#2-voraussetzungen)
3. [Installation & Schnellstart](#3-installation--schnellstart)
4. [Ablage-Konzept](#4-ablage-konzept)
5. [Die 14 Prüfabschnitte](#5-die-14-prüfabschnitte)
6. [Die vier Berichte](#6-die-vier-berichte)
7. [Beweissicherung (Chain-of-Custody)](#7-beweissicherung-chain-of-custody)
8. [Verdikte richtig lesen](#8-verdikte-richtig-lesen)
9. [Typischer Ablauf eines Einsatzes](#9-typischer-ablauf-eines-einsatzes)
10. [Troubleshooting](#10-troubleshooting)
11. [FAQ](#11-faq)
12. [Rechtliches](#12-rechtliches)

---

## 1. Für wen ist das Tool

`wp_plesk_forensik.sh` ist ein **read-only Analyse-Skript** für Administratoren und Dienstleister, die einen **Plesk-Server nach einem (vermuteten) WordPress-Einbruch** untersuchen müssen. Es ersetzt keinen Malware-Cleaner und keinen Virenscanner — es **sichert Beweise, erkennt Angriffsspuren und erstellt die Dokumentation**, die Kunde, BSI und ggf. Datenschutzbehörde brauchen.

**Grundprinzip:** Das Skript verändert den Webspace nicht. Es liest, wertet aus und schreibt ausschließlich nach `/root/wartungsscripte/`. Das Entfernen von Schadcode ist ein bewusst getrennter, manueller Schritt **nach** der Beweissicherung.

## 2. Voraussetzungen

| | |
|---|---|
| Plattform | Plesk-Server (getestet: Plesk Obsidian auf Ubuntu 22.04) |
| Rechte | `root` |
| Pflicht | `bash`, Standard-GNU-Coreutils |
| Optional | `dig` (DNS), `fail2ban-client`, `dpkg` (Binärintegrität), `mysql` + Plesk-Admin-Zugang (WordPress-DB-Prüfung), `ssh-keygen` (Key-Fingerprints) |

Fehlt ein optionales Werkzeug, überspringt das Skript den betroffenen Punkt mit einem Hinweis — der Lauf bricht nie ab.

## 3. Installation & Schnellstart

```bash
# 1. Werkzeug auf den Server bringen — das GANZE Verzeichnis, nicht nur das
#    Skript: ohne lib/ und module/ bricht der Lauf mit Code 3 ab.
ssh root@SERVER "git clone --depth 1 https://github.com/netztaucher/NT-Forensik-Repair.git /root/nt-forensik"
# ohne git auf dem Zielsystem:
#   rsync -a --exclude laeufe --exclude .git ./ root@SERVER:/root/nt-forensik/

# 2. Für eine bestimmte Domain ausführen
ssh root@SERVER "bash /root/nt-forensik/wp_plesk_forensik.sh kundendomain.tld"

# 3. Oder: alle Domains des Servers prüfen
ssh root@SERVER "bash /root/nt-forensik/wp_plesk_forensik.sh --global --kein-menue"
```

Beim ersten Lauf **installiert sich das Skript selbst** nach `/root/wartungsscripte/wp_plesk_forensik.sh`. Folgende Läufe startest du von dort:

```bash
ssh root@SERVER "bash /root/wartungsscripte/wp_plesk_forensik.sh kundendomain.tld"
```

**Domain-Argument oder nicht?**
- **Mit Domain**: schnell, fokussiert auf einen Vhost (Dateisystem-Scan + DB-Prüfung auf diese Domain begrenzt).
- **Ohne Domain**: prüft alle Vhosts. Länger (der Webshell-Scan läuft über `/var/www/vhosts` komplett), aber deckt server-weite Mitbetroffenheit auf.

## 4. Ablage-Konzept

Alles liegt unter **`/root/wartungsscripte/`** — getrennt vom Webspace, damit Belege nicht mit kompromittierten Daten vermischt werden:

```
/root/wartungsscripte/
├── wp_plesk_forensik.sh                       # installiert sich selbst hierhin
└── forensik/
    ├── <YYYYMMDD_HHMMSS>_<domain>/            # EIN Ordner PRO LAUF
    │   ├── belege/                            # nummerierte Rohdaten
    │   │   ├── 00_manifest.txt                # Chain-of-Custody
    │   │   ├── NN_*.txt                       # je ein Beleg pro Fund
    │   │   ├── logs_sicherung.tar.gz          # Voll-Backup aller Logs
    │   │   └── SHA256SUMS                     # Versiegelung
    │   ├── kundenbericht.md
    │   ├── bsi_meldung.md
    │   ├── dsgvo_meldung.md
    │   ├── technik_bericht.md
    │   └── lauf.log                           # komplettes Ausführungsprotokoll
    └── <YYYYMMDD_HHMMSS>_<domain>.tar.gz      # Übergabe-Archiv des Laufs
```

Jeder Lauf ist in sich abgeschlossen und wird durch das Übergabe-Archiv transportierbar.

## 5. Die 14 Prüfabschnitte

### 1 — System-Übersicht
OS, Kernel, Plesk-Version, PHP-Handler, Webserver, Uptime. **§1.6** liest `/root/changelog.md` (dokumentierte Systemänderungen) und stellt es zum Abgleich bereit: Ein Fund, der dort erklärt ist, ist meist gutartige Wartung — fehlt der Eintrag, ist er erklärungsbedürftig.

### 2 — Logs sichern
**Erste Amtshandlung.** Voll-Backup aller relevanten Logs (auth, secure, Plesk, FTP, fail2ban, modsec, Maillog, Vhost-Logs) nach `belege/logs_sicherung.tar.gz`, bevor Rotation Beweise vernichtet.

### 3 — Zugriffs-Analyse
SSH-Logins (letzte 50), fehlgeschlagene Versuche + Top-Brute-Force-IPs, erfolgreiche Authentifizierungen, Plesk-Panel-Logins, FTP-Zugriffe.

### 4 — Web-Traffic-Analyse
Pro Vhost-Access-Log: Scanner-Signaturen (sqlmap, nikto, …), Webshell-typische POST-Requests, wp-login- und xmlrpc-Brute-Force, Top-IPs, HTTP-Fehlerquoten. Konsolidiert auffällige Angreifer-IPs als IOCs.

### 5 — Benutzer & Rechte
Shell-fähige Benutzer, UID-0-Konten, `sudo`-Rechte, alle `authorized_keys` (inkl. kürzlich geänderter), Plesk-FTP-Benutzer.

### 6 — Cron & Persistenz
Root- und Benutzer-Crontabs, System-Cronjobs, **verdächtige Cron-Inhalte** (curl/wget/base64/nc), systemd-Timer, **at-Jobs**, **fremde/neue systemd-Units** (mit Download-`ExecStart`), **`rc.local`**, **`/etc/ld.so.preload`** (Userland-Rootkit-Ort), **`profile.d`-Hooks**, Kernel-Module.

### 7 — Dateisystem-Scan
Kürzlich veränderte PHP-Dateien, **PHP in Upload-Verzeichnissen** (Guard-gefiltert), **Webshell-Muster (zweistufig)** → siehe [Erkennungs-Referenz](erkennung.md), versteckte Dateien, verdächtige Dateinamen, `.htaccess`-Redirects, **SUID/SGID in Webspace/tmp**, **ausführbare Dateien in tmp**, **Immutable-Flags** (`chattr +i`).

### 8 — Netzwerk & Dienste
Offene Ports (unerwartete markiert), **Prozess-Forensik** (Miner, gelöschte Binaries auf Nicht-Systempfaden, Herkunft aus tmp/Webspace, Reverse-Shell-Muster, Web-User-Prozesse), aktive Verbindungen, DNS-Records, **Mailqueue** (Spam-Indikator), **`dpkg -V`-Binärintegrität** (Rootkit-Indikator).

### 9 — Sicherheitsdienste
Fail2ban-Status + Jails, ModSecurity-Konfiguration + Audit-Log, Firewall (ufw/firewalld/iptables).

### 10 — Andere Domains
Alle Plesk-Domains + server-weite Scanner-/Webshell-Übersicht (Tabelle) — zeigt Mitbetroffenheit.

### 11 — WordPress-Datenbank-Prüfung
Findet WP-Installs, liest DB-Zugang aus `wp-config.php`, prüft read-only: Administrator-Konten, **kürzlich angelegte Admins** (Persistenz-Indikator), `siteurl`/`home` (Redirect-Hijack), **verdächtige Optionen** (`base64`/`eval`/`auto_prepend`), aktive Plugins (flaggt Datei-Manager). Endet mit **WP-DB-Verdikt** 🟢/🔴.

### 12 — Joomla-Prüfung
Findet Joomla-Installationen über `class JConfig` in der `configuration.php` (der Dateiname allein ist zu unscharf) und prüft read-only:

- **12.2 Version & Wartungsende** — aus `joomla.xml` und `libraries/src/Version.php`. Widersprechen sich die Quellen, ist das selbst ein Befund (Manipulation oder abgebrochene Migration). Joomla 3 **und** 4 erhalten keine Sicherheitspatches mehr.
- **12.3 Härtung** — `debug`, `error_reporting`, Standard-Sicherheitsschlüssel, `force_ssl`, Standard-Tabellenpräfix, offene CORS-Freigabe, geteilte Sitzungen. Dazu eine Strukturprüfung: steht in der `configuration.php` ausführbarer Code, wurde sie als Hintertür umgebaut.
- **12.4 Ungeschützter API-Zugriff** — CVE-2023-23752 gibt die Datenbank-Zugangsdaten im Klartext an jeden Aufrufer heraus. Liegt die Version im Lückenbereich, wird zusätzlich im Zugriffsprotokoll nach erfolgreichen Abrufen gesucht; nur ein Antwortcode 200 belegt den Abfluss, 401 ist legitime Überwachung.
- **12.5 Kern-Integrität** — Prüfsummen-Vergleich aller Dateien des Programmkerns gegen die offizielle Fassung. Meldet veränderte Dateien, kernfremde Dateien in reinen Joomla-Verzeichnissen und fehlende Dateien. Reine Änderungen an Zeilenenden oder Leerzeichen (typisch nach einer Übertragung per FTP) werden erkannt, aber nicht gewertet. Rund 9800 Dateien in etwa 4 Sekunden.
- **12.6 Datenbank** — aktive System-Plugins (laufen bei jedem Seitenaufruf, noch vor jeder Rechteprüfung), Super-User über die tatsächliche Rechtetabelle statt der Standardgruppe, Verwaltungsrechte an offene Gruppen, Angriffsmuster in der Sitzungstabelle, **Injektionen in den Vorlagen-Einstellungen**, verschleierte Modulinhalte, dauerhafte Anmelde-Token.
- **12.8 Schaddateien** — als Bild getarnte PHP-Dateien, PHP in Medien- und Zwischenspeicher-Ordnern, Filterumgehung über gemischte Schreibweise der Endung, Code vor der Zugriffssperre, verbliebenes Installationsverzeichnis, automatisch vorgeschaltete PHP-Datei, Sicherungsarchive im Webverzeichnis.
- **12.9 Protokolle** — bekannte Joomla-Angriffswege. Der Wortlaut trennt Versuch und Erfolg: kritisch wird der Befund nur zusammen mit einem Dateifund.

Endet mit **Joomla-Verdikt** 🟢/🔴.

### 13 — Root- & Eskalations-Prüfung
Zentrale Frage: **Root übernommen oder auf Web-User-Ebene begrenzt?** Prüft erfolgreiche Root-Logins (IP + Auth-Methode, flaggt Passwort-Login), `/root/.ssh/authorized_keys`, Web-User-Keys server-weit (Fremd- vs. Plesk-Keys), sudo/su-Eskalation, Binärintegrität. Gleicht bekannte Web-Angreifer-IPs gegen Root-Logins ab. Endet mit **Root-Verdikt** 🟢/🔴.

### 14 — Zusammenfassung
Befund-Statistik + Maßnahmenplan (Sofort/Kurz-/Mittelfristig).

## 6. Die vier Berichte

| Bericht | Zielgruppe | Inhalt |
|---|---|---|
| **`kundenbericht.md`** | Kunde (Laie) | Ampel-Einstufung mit Konsequenz, Sofortmaßnahmen mit **24h/72h-Fristen**, verständliche Technik-Zusammenfassung, maschinell vorbefüllter Angriffshergang, Root-/DB-Reichweite, DSGVO-/BSI-Hinweise |
| **`bsi_meldung.md`** | BSI | BSIG/NIS2-Struktur, vorausgefüllte Kennzahlen & IOCs, Reichweite/Root-Verdikt, Meldewege & Fristen. `[AUSFÜLLEN]`-Felder für Kontakt/Einstufung |
| **`dsgvo_meldung.md`** | Datenschutz-Aufsichtsbehörde | Art. 33 DSGVO — **eigener Meldeweg**. Meldepflicht-Einschätzung (🔴/🟠/🟢), Pflichtinhalte Art. 33 Abs. 3 (Art der Verletzung, Betroffene/Datensätze, Folgen, Maßnahmen), betroffene Datenquellen vorbefüllt |
| **`technik_bericht.md`** | Techniker | Alle Prüfpunkte im Detail, mit Belegverweisen |

Der Kundenbericht füllt sich vollständig aus den Lauf-Daten — **keine nackten Platzhalter**. In BSI- und DSGVO-Meldung bleiben bewusst Formularfelder offen, die das Tool nicht kennen kann (Kontakt/Einstufung bzw. Datenkategorien, Zahl der Betroffenen — das weiß nur der/die Verantwortliche).

> **Wichtig:** BSI-Meldung und DSGVO-Meldung sind **getrennte Meldewege an verschiedene Stellen** (BSI-Portal vs. Datenschutz-Aufsichtsbehörde des Bundeslandes). Nicht verwechseln.

Zusätzlich schreibt jeder Lauf **`findings.json`** — einen maschinenlesbaren Export aller Befunde (Verdikte, Zähler, Metriken, actionable Pfade/IPs). Kein Bericht für Menschen, sondern die Schnittstelle für nachgelagerte Werkzeuge (Remediation). Ebenfalls SHA256-versiegelt.

## 7. Beweissicherung (Chain-of-Custody)

- Jeder Fund wird als nummerierter Beleg `belege/NN_<name>.txt` mit Kopf (Zeitpunkt UTC+lokal, Host, Tool-Version) abgelegt.
- `belege/00_manifest.txt` dokumentiert Lauf-ID, Server, Ausführenden, Start/Ende.
- Am Ende werden **alle Belege und Berichte per `SHA256SUMS` versiegelt**.
- Verdächtige Dateien (Webshells, Uploads) werden **sofort gehasht**, damit ihre Integrität später belegbar ist.
- Das Übergabe-Archiv `<lauf>.tar.gz` bündelt den kompletten Lauf revisionssicher.

> Für gerichtsverwertbare Beweise: Archiv unverändert sichern, Hashes separat notieren, Übergabekette dokumentieren.

## 8. Verdikte richtig lesen

**Gesamt-Ampel (Kundenbericht):**
- 🔴 **Kritisch** — mindestens ein kritischer Befund (z. B. Webshell-Dropper). Kompromittierung belegt.
- 🟡 **Auffällig** — nur Warnungen. Schwächen/Angriffsversuche, kein belegter Einbruch.
- 🟢 **Unauffällig** — keine Indikatoren in diesem Lauf (Momentaufnahme, kein Freibrief).

**Root-Verdikt (§13):**
- 🟢 = Angriff nach Beweislage auf Web-User-Ebene begrenzt → Bereinigung der Website genügt.
- 🔴 = Root-Kompromittierung nicht ausgeschlossen → Server als kompromittiert behandeln, Neuaufsetzen erwägen.

**WP-DB-Verdikt (§11):**
- 🟢 = keine fremden Admins/Optionen in den WordPress-Datenbanken.
- 🔴 = Auffälligkeiten → fremde Admins/Optionen prüfen und bereinigen.

Ein 🟢-Root-Verdikt bei gleichzeitig 🔴-Gesamtampel ist der häufige, wichtige Fall: **echter Website-Einbruch, aber der Server-Kern und die anderen Domains sind sauber.**

## 9. Typischer Ablauf eines Einsatzes

Siehe [Incident-Response-Playbook](incident-response.md) für Details. Kurzform:

1. **Lauf starten** → Logs gesichert, Berichte + Belege erzeugt.
2. **Berichte lesen** → Ampel, Root-/DB-Verdikt, Dropper-Cluster.
3. **Zugriffslogs manuell auswerten** → Angreifer-IP, Einfallstor, Zeitachse (Rohdaten in `belege/`).
4. **Schadcode quarantänisieren** (verschieben, nicht löschen; Hash-Log) — **nach** Beweissicherung.
5. **Berichte finalisieren** (Angriffshergang, ergriffene Maßnahmen ergänzen).
6. **Melden** (DSGVO Art. 33 / BSI) falls einschlägig.
7. **Bereinigen & härten** (Passwörter, sauberes Backup, SSH-Key-only, Fail2ban, ModSecurity).

## 10. Troubleshooting

| Symptom | Ursache / Lösung |
|---|---|
| „Skript muss als root ausgeführt werden" | Mit `sudo`/als root starten. |
| WP-DB-Prüfung: „keine DB-Verbindung" | Plesk-Admin-MySQL nicht verfügbar oder abweichende `wp-config.php`-Zugänge. Prüfen, ob `mysql` installiert ist und `/etc/psa/.psa.shadow` lesbar. |
| Lauf dauert sehr lange | Ohne Domain-Argument wird der komplette Webspace gescannt. Für Einzeldomain die Domain angeben. |
| Kein `access_log` gefunden | Plesk legt Logs unter `/var/www/vhosts/system/<domain>/logs/` ab; das Skript deckt beide Pfade ab. Bei Abweichung Log-Pfad prüfen. |
| Webshell-Treffer wirken wie False Positives | §7.3 trennt Dropper (klein) von Framework-`eval` (groß, „Review"). Große Treffer sind meist legitime Bibliotheken — siehe [Erkennungs-Referenz](erkennung.md). |
| `dig`/`fail2ban`/`dpkg` fehlt | Punkt wird übersprungen; optionales Paket nachinstallieren für Vollabdeckung. |

## 11. FAQ

**Verändert das Skript meine Website?**
Nein. Read-only bzgl. Webspace; schreibt nur nach `/root/wartungsscripte/`. Quarantäne/Löschung von Schadcode sind separate, manuelle Schritte.

**Kann ich es wiederholt laufen lassen?**
Ja. Jeder Lauf erzeugt einen eigenen Zeitstempel-Ordner; nichts wird überschrieben.

**Findet es jede Webshell?**
Nein — kein Tool tut das. Es ist stark bei obfuskierten Cookie-Backdoors und gängigen Mustern. Ein sauberer Lauf ist kein Unbedenklichkeitsbeweis.

**Warum bleiben in der BSI-Meldung Platzhalter?**
Kontakt- und Einstufungsfelder (KRITIS/NIS2) sind organisatorisch und können nicht automatisch ermittelt werden.

**Ist es nur für WordPress?**
Der Fokus liegt auf WordPress/Plesk, aber Zugriffs-, Prozess-, Persistenz-, Netzwerk- und Root-Prüfungen sind CMS-unabhängig nutzbar.

## 12. Rechtliches

- **Nur auf eigenen oder ausdrücklich betreuten Systemen einsetzen.** Forensik auf fremden Systemen ohne Auftrag ist strafbar.
- Bei Betroffenheit personenbezogener Daten: **DSGVO Art. 33** — Meldung an die Aufsichtsbehörde binnen **72 Stunden**.
- Die erzeugte `bsi_meldung.md` ist ein **Entwurf** und ersetzt keine Rechtsberatung.
- Lizenz: MIT (siehe `LICENSE`).

---
*netztaucher | digital*
