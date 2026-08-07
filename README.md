<p align="center">
  <a href="https://netztaucher.com/wordpress">
    <img src="assets/banner.png" alt="NT Forensik — WordPress & Rootserver · Digitale Spurensuche. Klare Analyse. Sichere Lösung." width="100%">
  </a>
</p>

<p align="center">
  <b><a href="https://netztaucher.com/wordpress">WordPress-Betreuung &amp; Sicherheit durch netztaucher</a></b>
  &nbsp;·&nbsp; <a href="https://github.com/netztaucher/NT-Forensik-Repair/releases">Releases</a>
  &nbsp;·&nbsp; <a href="docs/handbuch.md">Handbuch</a>
</p>

<p align="center">
  <a href="https://github.com/netztaucher/NT-Forensik-Repair/releases"><img src="https://img.shields.io/github/v/release/netztaucher/NT-Forensik-Repair?label=Release" alt="Release"></a>
  <img src="https://img.shields.io/badge/Modus-read--only-brightgreen" alt="read-only">
  <img src="https://img.shields.io/badge/Plesk-Obsidian%20%7C%20Ubuntu%2022.04-informational" alt="Plesk">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT"></a>
</p>

# NT-Forensik-Repair

**Forensische Incident-Response für WordPress/Joomla/Nextcloud auf Plesk-Servern — Analyse und Bereinigung, strikt getrennt.**

| | | |
|---|---|---|
| **`wp_plesk_forensik.sh`** | Analyse — was ist passiert? | frei, quelloffen, ohne Netz lauffähig |
| **`nt_repair.sh`** | Bereinigung — was tun wir dagegen? | [lizenzgebunden](docs/lizenz.md) |

> 🔒 **Read-only by design.** Die Analyse **verändert den Webspace nicht** — sie liest, wertet aus und schreibt ausschließlich nach `/root/wartungsscripte/`. Beweise bleiben unangetastet. Das Entfernen von Schadcode ist ein bewusst getrennter Schritt **nach** der Sicherung; dafür gibt es [`nt_repair.sh`](#bereinigung--nt_repairsh), das ohne ausdrückliches Go pro Aktion nichts ändert und nie löscht, sondern verschiebt.

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

Der Lauf gliedert sich in 15 Abschnitte:

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
| 12b | **Nextcloud-Prüfung** | Manipulierte Root-`.htaccess` (WordPress-Freigabeliste), bekannte Schaddateien der Kampagne, verschachtelte Verzeichnisse (`config/config`), aufgeblähte `index.php`, **Kern-Integrität über `occ integrity:check-core`** |
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

**Das Werkzeug besteht aus mehr als einer Datei.** Seit v3.9.0 liegen die
Prüfabschnitte in `module/` und die gemeinsamen Funktionen in `lib/`; fehlt
einer der beiden Ordner, bricht der Lauf mit Code 3 ab. Es gehört also das
ganze Verzeichnis auf den Server, nicht das Skript allein.

```bash
# Auf den Server bringen — am einfachsten direkt klonen
ssh root@SERVER "git clone --depth 1 https://github.com/netztaucher/NT-Forensik-Repair.git /root/nt-forensik"

# ohne git auf dem Zielsystem: das ganze Verzeichnis übertragen
rsync -a --exclude laeufe --exclude .git ./ root@SERVER:/root/nt-forensik/
```

| Ordner | wofür | nötig |
|---|---|---|
| `lib/`, `module/` | Runner und Prüfabschnitte | **immer** |
| `daten/` | Joomla-Prüfsummen und Schwachstellenlisten (3 MB) | für Abschnitt 12 |
| `signaturen/` | YARA-Regeln | nur mit `--yara` |
| `reportgen/` | PDF-Erzeugung | nur für den PDF-Bericht |

```bash
# Ein Plesk-Abo als Ganzes — alle Verzeichnisse dieses Kunden, sonst nichts
ssh root@SERVER "bash /root/nt-forensik/wp_plesk_forensik.sh --web43"

# Einen Kunden prüfen (Kundenbericht enthält nur dessen Daten, maskiert)
ssh root@SERVER "bash /root/nt-forensik/wp_plesk_forensik.sh --domain kundendomain.tld"

# Beliebigen Pfad prüfen
ssh root@SERVER "bash /root/nt-forensik/wp_plesk_forensik.sh --path /var/www/vhosts/kunde/httpdocs/shop"

# Alle Domains (Betreiber-Triage; erzeugt einen serverweiten Betreiberbericht,
# NICHT für die Weitergabe an einzelne Kunden)
ssh root@SERVER "bash /root/nt-forensik/wp_plesk_forensik.sh --global"

# Nur die Root-Frage: ist jemand über den Webspace hinausgekommen?
#   Beantwortet die eine serverweite Frage, die der Kunde braucht — ohne
#   Benutzerlisten, Cronjobs und Domains anderer Kunden in den Bericht zu ziehen.
ssh root@SERVER "bash /root/nt-forensik/wp_plesk_forensik.sh --nur-root --kein-menue"

# Nur die Joomla-Prüfung — spart Log-Archiv und serverweiten Dateiscan
ssh root@SERVER "bash /root/nt-forensik/wp_plesk_forensik.sh --domain kunde.tld --nur-joomla"

# Nur die WordPress-Seite: Web-Traffic, Dateisystem-Scan, WP-Datenbank
ssh root@SERVER "bash /root/nt-forensik/wp_plesk_forensik.sh --domain kunde.tld --nur 4,7,11"

# YARA-Signaturscan zusätzlich (langsam auf großen Webspaces)
ssh root@SERVER "bash /root/nt-forensik/wp_plesk_forensik.sh --domain kunde.tld --yara"

# Hilfe
ssh root@SERVER "bash /root/nt-forensik/wp_plesk_forensik.sh --help"
```

**Ohne Scope-Argument startet ein Menü**, das die Abschnitte erklärt und am
Ende den passenden Befehl zum Kopieren ausgibt. Aufrufe mit `--domain`,
`--path` oder `--global` laufen immer direkt durch; für Cronjobs zusätzlich
`--kein-menue`.

Abschnitte lassen sich gezielt wählen: `--nur 12`, `--ohne 2,10`,
`--nur-website`. Der Bericht weist dann aus, was **nicht** geprüft wurde —
ein Teillauf darf sich nicht wie ein vollständiges Ergebnis lesen.

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
- **[`docs/architektur.md`](docs/architektur.md)** — Aufbau: Runner, `lib/`, `module/`, das Modul-Interface, wie man einen Prüfabschnitt hinzufügt, und wie belegt wird, dass ein Umbau nichts verändert hat.
- **[`docs/joomla-pruefung.md`](docs/joomla-pruefung.md)** — Joomla-Prüfung im Detail: die zehn Prüfschritte, Datenbestand, Offline-/Online-Betrieb, Fehlalarm-Vermeidung, Pflege.
- **[`docs/relay-backdoors.md`](docs/relay-backdoors.md)** — Relay-Backdoors (gsocket), Prozess-Introspektion und warum Signatur-Rootkitscanner diese Klasse verfehlen.
- **[`docs/incident-response.md`](docs/incident-response.md)** — Incident-Response-Playbook: 7 Phasen von der Beweissicherung bis zur Härtung.
- **[`docs/runbook.md`](docs/runbook.md)** — Runbook für die manuelle Ad-hoc-Analyse einzelner Prüfpunkte.
- **[`docs/findings-schnittstelle.md`](docs/findings-schnittstelle.md)** — `findings.json` als Vertrag: welche Feldpfade NT-Repair liest und was bei Schema-Änderungen zu tun ist.
- **[`docs/lizenz.md`](docs/lizenz.md)** — Lizenz für den Bereinigungsteil: für wen, welcher Umfang, Einrichtung, Ausfallreserve, Nutzungsbedingungen.
- **[`docs/lizenzierung-technik.md`](docs/lizenzierung-technik.md)** — das Schutzmodell dahinter: wie die Bindung funktioniert, wo ihre Grenzen liegen, wie eine Fassung ausgeliefert wird.

## Bereinigung — `nt_repair.sh`

Die Analyse beantwortet, **was passiert ist**. Für den Schritt danach — Quarantäne,
IOC-Sperren, Zugangsdaten, Bericht und Kundenanschreiben — liegt `nt_repair.sh`
daneben. Es liest die `findings.json` des Forensik-Laufs und arbeitet sie ab; ohne
ausdrückliches Go pro Aktion ändert es nichts, und gelöscht wird nie, nur verschoben.

```bash
# Plan aus einem Forensik-Lauf, ohne Änderung
bash nt_repair.sh --from /root/wartungsscripte/forensik/<LAUF>

# Ausführen, mit Einzelbestätigung je Aktionsgruppe
bash nt_repair.sh --from /root/wartungsscripte/forensik/<LAUF> --apply
```

### Was die Bereinigung kann

| | |
|---|---|
| **Quarantäne** | verschiebt, löscht nie. SHA-256 vor jedem Eingriff, jede Datei rückholbar. Liest alle Befundlisten der Forensik — auch die von Imunify, YARA und der Plugin-Signaturprüfung |
| **IOC-Sperren** | iptables, idempotent, persistiert |
| **Zugangsdaten** | Systemkonto, WordPress-Konten, Datenbank und Plesk-Abo. Datenbank über `plesk bin database`, damit Plesk und MySQL synchron bleiben; `wp-config.php` über `wp config set`. Passwörter gehen nie über die Kommandozeile, jedes Ergebnis landet in 1Password und wird zurückgelesen |
| **Berichte** | Kundenbericht, BSI-Abschlussmeldung, DSGVO-Nachmeldung, Statusmail als `.eml` |

**Manipulierte Original-Dateien werden nicht verschoben.** Eine injizierte `wp-includes`-Datei
zu entfernen legt die Seite lahm — richtig ist, den Kern neu einzuspielen. Solche Funde werden
benannt und protokolliert, statt still zu verschwinden.

**Jede Datei, die das Werkzeug ändert, bekommt einen Kommentarblock**: wann, durch welche Fassung,
aus welchem Anlass, was und warum — mit Verweis auf das Protokoll und die Quelle des Werkzeugs.
Eine unerklärte Änderung an einer Datei, die nach einem Vorfall angefasst wurde, ist sonst selbst
ein Befund.

### Werkzeugspezifische Bereinigung

Was ein Fund bedeutet, hängt davon ab, wo er liegt. Die Bereinigung unterscheidet:

- **WordPress** — Plugin vollständig deinstallieren statt nur Dateien entfernen (Eintrag in
  `active_plugins`, Verzeichnisrest, Datenbank-Reste), Sicherheitsschlüssel erneuern, alle
  Sitzungen beenden, Administratorkonten prüfen und entfernen
- **Joomla** — System-Plugins und Vorlagen-Parameter in der Datenbank, wo die Nutzlast auch
  ohne eine einzige Datei überlebt
- **Datenbank-Werkzeuge** (Adminer, phpMyAdmin im Webroot) — als Datenzugriff eingestuft, nicht
  als Sachschaden. Für die DSGVO-Bewertung ist das der Unterschied

### Erkannte Schwachstellen

Die Forensik ordnet gefundenen Erweiterungen bekannte Schwachstellen zu — aus einer gepflegten
Liste, nicht aus einer Vermutung. Der Bericht sagt dazu ausdrücklich: er nennt den Weg, der bei
dieser Erweiterung **bekannt** ist, nicht den, der benutzt wurde. Belegen ließe sich das nur
über die Zugriffsprotokolle des Zeitraums.

Für Joomla kommt der Abgleich aus dem mitgelieferten Datenbestand: **214 CVE-Bereiche** und
**199 zugeordnete verwundbare Erweiterungen**, dazu Prüfsummen von 11 Kernfassungen. Für
WordPress-Plugins pflegt die Bereinigung eine eigene Zuordnung (`daten/plugin-cve.tsv`).

Ausdrücklich als Befund gilt auch **Wartungsende**: Joomla 3 und 4 bekommen keine
Sicherheitspatches mehr, Advisories aus 2026 nennen 3.x weiterhin als betroffen. Solche
Installationen sind nicht „veraltet", sondern dauerhaft angreifbar.

### Lizenz

Der Bereinigungsteil ist **kostenpflichtig**. Der Lader `nt_repair.sh` bleibt offen lesbar — er
enthält kein Geheimnis. Der Inhalt liegt verschlüsselt in `paket/`; den Schlüssel liefert der
Lizenzserver bei jedem Lauf, gebunden an den Arbeitsplatz, der die Bereinigung führt.

Das ist bewusst so gebaut: eine Prüfung, die nur „gültig" zurückgibt, ließe sich aus dem offenen
Lader herauspatchen. **Einen Schlüssel, den man nicht hat, nicht.** Ist der Lizenzserver nicht
erreichbar, greift eine Ausfallreserve von sieben Tagen, an denselben Arbeitsplatz gebunden.

**Die Analyse ist davon unberührt.** `wp_plesk_forensik.sh` läuft vollständig — ohne Lizenz, ohne
Netz, mit offenem Quelltext. Im Vorfall ist die Analyse der dringende Teil; Bereinigen kann warten,
bis wieder Netz da ist.

Umfang und Bedingungen: [`docs/lizenz.md`](docs/lizenz.md). Was die Verschlüsselung leistet
und was nicht, steht ungeschönt in [`docs/lizenzierung-technik.md`](docs/lizenzierung-technik.md) — gegen den Ausführenden schützt sie nicht, und
eine Doku, die etwas anderes behauptet, wäre eine Falle für den, der ihr glaubt.

## Sicherheit & Recht

- **Nur auf eigenen oder ausdrücklich betreuten Systemen einsetzen.** Forensik auf fremden Systemen ohne Auftrag ist strafbar.
- Das Skript ist **read-only** bzgl. des Webspace; es schreibt ausschließlich in `/root/wartungsscripte/` (root-only, `chmod 700`).
- **Zwei getrennte Meldewege:** die BSI-Meldung (`bsi_meldung.md`, BSIG/NIS2 — seit 06.12.2025 in Kraft: Frühwarnung ≤ 24 h, Folgemeldung ≤ 72 h, Abschluss ≤ 1 Monat) und die DSGVO-Meldung (`dsgvo_meldung.md`, **Art. 33** an die Datenschutz-Aufsichtsbehörde, ≤ 72 h). Nicht verwechseln.
- Alle erzeugten Meldungen sind **Entwürfe** und ersetzen keine Rechtsberatung.

## Lizenz

MIT — siehe [LICENSE](LICENSE). **Ausgenommen** ist `paket/` (der verschlüsselte
Inhalt von `nt_repair.sh`): proprietär, kostenpflichtig, siehe
[`paket/LICENSE`](paket/LICENSE). Der Lader `nt_repair.sh` selbst steht unter MIT —
er enthält nichts Geheimes und soll nachlesbar sein.

---
*netztaucher | digital*
