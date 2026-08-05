<p align="center">
  <a href="https://netztaucher.com/wordpress">
    <img src="assets/banner.png" alt="NT Forensik — WordPress & Rootserver · Digitale Spurensuche. Klare Analyse. Sichere Lösung." width="100%">
  </a>
</p>

<p align="center">
  <b><a href="https://netztaucher.com/wordpress">WordPress-Betreuung &amp; Sicherheit durch netztaucher</a></b>
  &nbsp;·&nbsp; <a href="https://github.com/netztaucher/NT-Forensik/releases">Releases</a>
  &nbsp;·&nbsp; <a href="docs/handbuch.md">Handbuch</a>
</p>

<p align="center">
  <a href="https://github.com/netztaucher/NT-Forensik/releases"><img src="https://img.shields.io/github/v/release/netztaucher/NT-Forensik?label=Release" alt="Release"></a>
  <img src="https://img.shields.io/badge/Modus-read--only-brightgreen" alt="read-only">
  <img src="https://img.shields.io/badge/Plesk-Obsidian%20%7C%20Ubuntu%2022.04-informational" alt="Plesk">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT"></a>
</p>

# NT-Forensik

**Forensische Incident-Response für WordPress/Plesk-Server — ein einzelnes, read-only Bash-Skript.**

> 🔒 **Read-only by design.** Das Skript **verändert den Webspace nicht** — es liest, wertet aus und schreibt ausschließlich nach `/root/wartungsscripte/`. Beweise bleiben unangetastet; das Entfernen von Schadcode ist ein bewusst getrennter, manueller Schritt **nach** der Sicherung.

`wp_plesk_forensik.sh` untersucht einen kompromittierten (oder verdächtigen) Plesk-Server systematisch auf Angriffsspuren und erzeugt pro Lauf vier fertige Dokumente:

- **`kundenbericht.md`** — verständlicher Bericht für den Kunden (Ampel-Bewertung, Sofortmaßnahmen mit Fristen, Angriffshergang).
- **`bsi_meldung.md`** — vorausgefüllter Entwurf für die BSI-Meldung (BSIG/NIS2-Struktur) inkl. Kennzahlen und IOCs.
- **`dsgvo_meldung.md`** — vorausgefüllter Entwurf für die Datenschutz-Meldung nach **Art. 33 DSGVO** (eigener Meldeweg an die Aufsichtsbehörde) mit Meldepflicht-Einschätzung und den Pflichtinhalten des Art. 33 Abs. 3.
- **`technik_bericht.md`** — vollständiger technischer Bericht über alle Prüfpunkte.
- **`findings.json`** — maschinenlesbarer Export aller Befunde (Verdikte, IOCs, actionable Pfade) für nachgelagerte Werkzeuge.

Alle Rohdaten werden als nummerierte, SHA256-versiegelte Belege abgelegt (Chain-of-Custody).

> Entwickelt von **netztaucher | digital** für den Einsatz auf eigenen und betreuten Systemen.

---

## 🛡️ WordPress-Betreuung durch netztaucher

NT-Forensik entsteht aus der täglichen Praxis unserer **WordPress-Wartung und -Absicherung**. Sie betreiben WordPress und wollen Einbrüche wie die hier dokumentierten gar nicht erst erleben — oder brauchen im Ernstfall schnelle, saubere Incident-Response?

**→ [netztaucher.com/wordpress](https://netztaucher.com/wordpress)** — Wartung, Härtung, Monitoring und Notfall-Forensik aus einer Hand.

---

## Warum

Nach einem WordPress-Einbruch ist die erste Stunde entscheidend: Logs rotieren, Beweise verschwinden, und der Kunde braucht eine klare Aussage. Übliche Malware-Scanner übersehen moderne, obfuskierte Backdoors (z. B. Cookie-getriggerte `eval`-Dropper mit gemischter Groß-/Kleinschreibung). NT-Forensik ist genau darauf ausgelegt: **sichern, erkennen, dokumentieren — in einem Durchlauf, ohne das System zu verändern.**

## Funktionsumfang

Der Lauf gliedert sich in 14 Abschnitte:

| # | Abschnitt | Prüft u. a. |
|---|---|---|
| 1 | System-Übersicht | OS, Plesk, PHP, Webserver; Abgleich mit `/root/changelog.md` |
| 2 | Logs sichern | Voll-Backup aller relevanten Logs (erste Amtshandlung) |
| 3 | Zugriffs-Analyse | SSH-Logins, Brute-Force-IPs, Plesk-Panel, FTP |
| 4 | Web-Traffic | Scanner-Signaturen, Webshell-POSTs, wp-login-Brute-Force |
| 5 | Benutzer & Rechte | Shell-User, UID-0, sudo, SSH-Keys, **SSH-Login-Hooks, forced commands** |
| 6 | Cron & Persistenz | Crontabs, systemd-Timer/Units, at-Jobs, rc.local, `ld.so.preload`, **udev/PAM/APT/linger** |
| 7 | Dateisystem | Webshells (2-stufig), PHP in Uploads, SUID, Immutable-Flags, `.htaccess`-Redirects, **getarnte ELF-Binaries, YARA-Scan** |
| 8 | Netzwerk & Dienste | Offene Ports, Prozess-Forensik, **Relay-Backdoors (gsocket), fileless/memfd, Kernel-Thread-Tarnung, ausgehende Verbindungen**, Mailqueue, `dpkg -V`/`debsums`-Integrität, **ctime/Timestomp, AIDE, Imunify-DB** |
| 9 | Sicherheitsdienste | Fail2ban, ModSecurity, Firewall |
| 10 | Andere Domains | Server-weite Betroffenheit |
| 11 | **WordPress-Datenbank** | Fremde Admins, manipulierte Optionen, aktive Plugins, **WP-Toolkit-Infektionsstatus** |
| 12 | **Joomla-Prüfung** | Version & Wartungsende, Härtung der `configuration.php`, ungeschützter API-Zugriff, **Kern-Integrität (Prüfsummen)**, **Datenbank-Persistenz (System-Plugins, Super-User, Vorlagen-Injektionen)**, Abgleich mit bekannten Schwachstellen, Joomla-typische Schaddateien, Angriffsspuren in den Protokollen |
| 13 | **Root-/Eskalations-Prüfung** | Root-Logins, Fremd-Keys, Privilege-Escalation → Root-Verdikt |
| 14 | Zusammenfassung | Befund-Statistik, Maßnahmenplan |

### Erkennungs-Highlights

- **Obfuskierte Cookie-Backdoors**: erkennt Variable-Variable-Superglobale (`${$a.$b.$c}` → `_COOKIE`) und mixed-case `EvaL(base64_decode(...))` — eine gängige Evasion, die Signaturscanner umgehen.
- **Zweistufige Webshell-Bewertung**: kleine Obfuskations-Dropper (kritisch) vs. große Framework-Dateien mit legitimem `eval` (Review) — trennt echte Funde vom Rauschen per Dateigröße.
- **False-Positive-Filter**: Theme-Iconfonts, WP-Guard-Dateien, Upgrade-Reste gelöschter Binaries, Plesk-eigene SSH-Keys.
- **Root-Verdikt**: konsolidiert Login-, Key-, sudo- und Binärintegritätsdaten zu einer klaren Aussage „auf Web-User-Ebene begrenzt" vs. „Root nicht ausgeschlossen".
- **Portlose Relay-Backdoors**: erkennt THC gsocket / gs-netcat, das über ein öffentliches Relay ausgehend auf 443 arbeitet und daher weder von Portscans noch von rkhunter/chkrootkit gefunden wird.
- **Fileless-Ausführung**: Prozesse, deren Binary via `memfd_create()` nur im RAM existiert — für jeden Dateiscanner unsichtbar.
- **Tarnungs-Erkennung**: ELF-Binaries mit harmlosem Dateinamen (der reale Anlass war eine gs-netcat-Binary namens `~/.ssh/id_rsa`) und Prozesse, die sich als Kernel-Thread ausgeben.
- **Zeitstempel-Manipulation (Timestomping)**: referenzlos über die ctime/mtime-Diskrepanz — ein Angreifer, der das Änderungsdatum zurücksetzt, verrät sich über die Inode-Änderungszeit.
- **Autoritative Scanner-Taps**: liest read-only die Ergebnisse der ohnehin vorhandenen Plesk-Werkzeuge — **Imunify-Malware-DB** und **WP-Toolkit-Infektionsstatus** — statt eigene Signaturen nachzubauen (löst keinen Scan aus).
- **Befund-Einordnung**: ordnet Funde grob einer Familie samt Geschäftsmodell zu, listet Fundstellen mit Pfaden relativ zum Kundenverzeichnis in `befunde_details.md` und zeigt eine Grobstatistik auf dem PDF-Deckblatt.
- **Joomla-Datenbank-Persistenz**: prüft die Stellen, an denen sich ein Angreifer in Joomla einnistet, ohne eine einzige Datei anzufassen — aktive System-Plugins (laufen bei jedem Seitenaufruf, noch vor jeder Rechteprüfung), Super-User über die tatsächliche Rechtetabelle statt der Standardgruppe, und **Injektionen in den Vorlagen-Einstellungen**. Letztere sind der Grund, warum ein reiner Dateiscan bei der Helix3-Kampagne (2026) eine verunstaltete Seite als sauber meldet: die Nutzlast liegt ausschließlich in der Datenbank und überlebt jede Wiederherstellung der Dateien.
- **Kern-Integrität für Joomla**: Joomla veröffentlicht — anders als WordPress — keine Prüfsummen je Datei. NT-Forensik erzeugt sie deshalb selbst aus den offiziellen Paketen und vergleicht rund 9800 Dateien in etwa vier Sekunden. Der Vergleich läuft zweistufig: passt der Hash nicht, wird ein zweiter über den auf Leerzeichen normalisierten Inhalt gerechnet. Damit fallen Änderungen an Zeilenenden oder Leerzeichen heraus — der klassische Fehlalarm nach einer Übertragung per FTP oder einer Bearbeitung unter Windows.
- **Als Bild getarnte Hintertüren**: eine Datei, die der Webserver als PHP ausführt, aber mit einer Bild-Kennung beginnt — das Muster der JCE- und Medien-Uploadlücken. Dafür gibt es keinen legitimen Fall, die Regel ist praktisch fehlalarmfrei.
- **Wartungsende als Befund**: Joomla 3 und 4 erhalten beide keine Sicherheitspatches mehr (seit 08/2023 bzw. 10/2025). Advisories aus 2026 nennen weiterhin 3.x als betroffen, ohne dass ein Fix existiert — solche Installationen sind nicht „veraltet", sondern dauerhaft angreifbar.

## Verwendung

```bash
# Auf den Server bringen (Skript + optionale Hilfsordner signaturen/ reportgen/)
scp wp_plesk_forensik.sh root@SERVER:/root/
scp -r signaturen reportgen root@SERVER:/root/     # optional: YARA + PDF-Generator

# Einen Kunden prüfen (Kundenbericht enthält nur dessen Daten, maskiert)
ssh root@SERVER "bash /root/wp_plesk_forensik.sh --domain kundendomain.tld"

# Beliebigen Pfad prüfen
ssh root@SERVER "bash /root/wp_plesk_forensik.sh --path /var/www/vhosts/kunde/httpdocs/shop"

# Alle Domains (Betreiber-Triage; erzeugt einen serverweiten Betreiberbericht,
# NICHT für die Weitergabe an einzelne Kunden)
ssh root@SERVER "bash /root/wp_plesk_forensik.sh --global"

# YARA-Signaturscan zusätzlich (langsam auf großen Webspaces)
ssh root@SERVER "bash /root/wp_plesk_forensik.sh --domain kunde.tld --yara"

# Hilfe
ssh root@SERVER "bash /root/wp_plesk_forensik.sh --help"
```

Für die Joomla-Prüfung muss der Datenbestand mit auf den Server:

```bash
scp -r wp_plesk_forensik.sh signaturen daten reportgen root@SERVER:/root/
```

Der Lauf arbeitet standardmäßig **rein offline** — er baut keine Verbindung nach außen auf. `--online` erlaubt dem Lauf, Vergleichsdaten nachzuladen; jeder Abruf wird mit URL, Antwortcode und Prüfsumme im Technikbericht, als Beleg und in `findings.json` ausgewiesen, damit im Nachhinein nachvollziehbar bleibt, dass der Lauf das Netz berührt hat.

> Ein blankes Positionsargument (`… wp_plesk_forensik.sh kunde.tld`) bleibt als
> `--domain kunde.tld` erhalten (rückwärtskompatibel). Die **Server-/Rootebene
> wird in jedem Modus mitgeprüft**; in Kundenberichten werden Rootbefunde nur
> allgemein genannt und IP-Adressen/E-Mails maskiert.

Das Skript installiert sich beim ersten Lauf nach `/root/wartungsscripte/` und legt pro Lauf einen Ordner an:

```
/root/wartungsscripte/forensik/<YYYYMMDD_HHMMSS>_<scope>/
├── belege/                 # nummerierte Rohdaten, SHA256-versiegelt, Chain-of-Custody
├── kundenbericht.md        # laienlesbar; im --global-Modus Betreiberbericht
├── befunde_details.md      # Fundstellen relativ zum Kundenverzeichnis + Familie (nur bei Funden)
├── zusammenfassung.md      # KPI-Kurzfassung (Teil 2 des PDF)
├── abschlussbericht.pdf    # gebrandetes PDF (nur wenn pandoc+weasyprint da)
├── bsi_meldung.md
├── dsgvo_meldung.md
├── technik_bericht.md
├── findings.json
└── lauf.log
```

### Voraussetzungen

- Plesk-Server (getestet: Plesk Obsidian auf Ubuntu 22.04), Bash, Root-Rechte.
- Optional: `dig`, `fail2ban-client`, `dpkg`, MySQL-Zugang (für die WordPress-DB-Prüfung; nutzt Plesk-Admin-Zugang automatisch).
- Read-only: das Skript verändert den Webspace **nicht**.

## Beispielberichte

Im Ordner [`examples/`](examples/) liegen vollständige Beispielberichte eines **fiktiven** Vorfalls (alle Domains, IP-Adressen, Hashes und Namen sind erfunden — RFC-5737-Dokumentations-IPs, `example`-Domains):

- [`examples/kundenbericht.md`](examples/kundenbericht.md)
- [`examples/bsi_meldung.md`](examples/bsi_meldung.md)
- [`examples/dsgvo_meldung.md`](examples/dsgvo_meldung.md)
- [`examples/technik_bericht_auszug.md`](examples/technik_bericht_auszug.md)
- [`examples/findings.json`](examples/findings.json)

## Dokumentation

- **[`docs/handbuch.md`](docs/handbuch.md)** — vollständiges Benutzerhandbuch: Installation, alle 14 Prüfabschnitte, Berichte, Verdikte lesen, Troubleshooting, FAQ.
- **[`docs/erkennung.md`](docs/erkennung.md)** — Erkennungs-Referenz: Signaturen, zweistufige Webshell-Bewertung, False-Positive-Filter, Root-Verdikt, Grenzen.
- **[`docs/joomla-pruefung.md`](docs/joomla-pruefung.md)** — Joomla-Prüfung im Detail: die zehn Prüfschritte, Datenbestand, Offline-/Online-Betrieb, Fehlalarm-Vermeidung, Pflege.
- **[`docs/relay-backdoors.md`](docs/relay-backdoors.md)** — Relay-Backdoors (gsocket), Prozess-Introspektion und warum Signatur-Rootkitscanner diese Klasse verfehlen.
- **[`docs/incident-response.md`](docs/incident-response.md)** — Incident-Response-Playbook: 7 Phasen von der Beweissicherung bis zur Härtung.
- **[`docs/runbook.md`](docs/runbook.md)** — Runbook für die manuelle Ad-hoc-Analyse einzelner Prüfpunkte.

## Sicherheit & Recht

- **Nur auf eigenen oder ausdrücklich betreuten Systemen einsetzen.** Forensik auf fremden Systemen ohne Auftrag ist strafbar.
- Das Skript ist **read-only** bzgl. des Webspace; es schreibt ausschließlich in `/root/wartungsscripte/` (root-only, `chmod 700`).
- **Zwei getrennte Meldewege:** die BSI-Meldung (`bsi_meldung.md`, BSIG/NIS2 — seit 06.12.2025 in Kraft: Frühwarnung ≤ 24 h, Folgemeldung ≤ 72 h, Abschluss ≤ 1 Monat) und die DSGVO-Meldung (`dsgvo_meldung.md`, **Art. 33** an die Datenschutz-Aufsichtsbehörde, ≤ 72 h). Nicht verwechseln.
- Alle erzeugten Meldungen sind **Entwürfe** und ersetzen keine Rechtsberatung.

## Lizenz

MIT — siehe [LICENSE](LICENSE).

---
*netztaucher | digital*
