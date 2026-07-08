# NT-Forensik

**Forensische Incident-Response für WordPress/Plesk-Server — ein einzelnes, read-only Bash-Skript.**

`wp_plesk_forensik.sh` untersucht einen kompromittierten (oder verdächtigen) Plesk-Server systematisch auf Angriffsspuren und erzeugt pro Lauf drei fertige Dokumente:

- **`kundenbericht.md`** — verständlicher Bericht für den Kunden (Ampel-Bewertung, Sofortmaßnahmen mit Fristen, Angriffshergang).
- **`bsi_meldung.md`** — vorausgefüllter Entwurf für die BSI-Meldung (BSIG/NIS2-Struktur) inkl. Kennzahlen und IOCs.
- **`technik_bericht.md`** — vollständiger technischer Bericht über alle Prüfpunkte.

Alle Rohdaten werden als nummerierte, SHA256-versiegelte Belege abgelegt (Chain-of-Custody).

> Entwickelt von **netztaucher | digital** für den Einsatz auf eigenen und betreuten Systemen.

---

## Warum

Nach einem WordPress-Einbruch ist die erste Stunde entscheidend: Logs rotieren, Beweise verschwinden, und der Kunde braucht eine klare Aussage. Übliche Malware-Scanner übersehen moderne, obfuskierte Backdoors (z. B. Cookie-getriggerte `eval`-Dropper mit gemischter Groß-/Kleinschreibung). NT-Forensik ist genau darauf ausgelegt: **sichern, erkennen, dokumentieren — in einem Durchlauf, ohne das System zu verändern.**

## Funktionsumfang

Der Lauf gliedert sich in 13 Abschnitte:

| # | Abschnitt | Prüft u. a. |
|---|---|---|
| 1 | System-Übersicht | OS, Plesk, PHP, Webserver; Abgleich mit `/root/changelog.md` |
| 2 | Logs sichern | Voll-Backup aller relevanten Logs (erste Amtshandlung) |
| 3 | Zugriffs-Analyse | SSH-Logins, Brute-Force-IPs, Plesk-Panel, FTP |
| 4 | Web-Traffic | Scanner-Signaturen, Webshell-POSTs, wp-login-Brute-Force |
| 5 | Benutzer & Rechte | Shell-User, UID-0, sudo, SSH-Keys |
| 6 | Cron & Persistenz | Crontabs, systemd-Timer/Units, at-Jobs, rc.local, `ld.so.preload` |
| 7 | Dateisystem | Webshells (2-stufig), PHP in Uploads, SUID, Immutable-Flags, `.htaccess`-Redirects |
| 8 | Netzwerk & Dienste | Offene Ports, Prozess-Forensik, Mailqueue, `dpkg -V`-Integrität |
| 9 | Sicherheitsdienste | Fail2ban, ModSecurity, Firewall |
| 10 | Andere Domains | Server-weite Betroffenheit |
| 11 | **WordPress-Datenbank** | Fremde Admins, manipulierte Optionen, aktive Plugins |
| 12 | **Root-/Eskalations-Prüfung** | Root-Logins, Fremd-Keys, Privilege-Escalation → Root-Verdikt |
| 13 | Zusammenfassung | Befund-Statistik, Maßnahmenplan |

### Erkennungs-Highlights

- **Obfuskierte Cookie-Backdoors**: erkennt Variable-Variable-Superglobale (`${$a.$b.$c}` → `_COOKIE`) und mixed-case `EvaL(base64_decode(...))` — eine gängige Evasion, die Signaturscanner umgehen.
- **Zweistufige Webshell-Bewertung**: kleine Obfuskations-Dropper (kritisch) vs. große Framework-Dateien mit legitimem `eval` (Review) — trennt echte Funde vom Rauschen per Dateigröße.
- **False-Positive-Filter**: Theme-Iconfonts, WP-Guard-Dateien, Upgrade-Reste gelöschter Binaries, Plesk-eigene SSH-Keys.
- **Root-Verdikt**: konsolidiert Login-, Key-, sudo- und Binärintegritätsdaten zu einer klaren Aussage „auf Web-User-Ebene begrenzt" vs. „Root nicht ausgeschlossen".

## Verwendung

```bash
# Auf den Server bringen und ausführen (legt /root/wartungsscripte selbst an)
scp wp_plesk_forensik.sh root@SERVER:/root/
ssh root@SERVER "bash /root/wp_plesk_forensik.sh kundendomain.tld"

# Ohne Domain-Argument → alle Domains des Servers
ssh root@SERVER "bash /root/wp_plesk_forensik.sh"
```

Das Skript installiert sich beim ersten Lauf nach `/root/wartungsscripte/` und legt pro Lauf einen Ordner an:

```
/root/wartungsscripte/forensik/<YYYYMMDD_HHMMSS>_<domain>/
├── belege/                 # nummerierte Rohdaten, SHA256-versiegelt, Chain-of-Custody
├── kundenbericht.md
├── bsi_meldung.md
├── technik_bericht.md
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
- [`examples/technik_bericht_auszug.md`](examples/technik_bericht_auszug.md)

## Dokumentation

- [`docs/runbook.md`](docs/runbook.md) — Schritt-für-Schritt-Runbook für die manuelle Ad-hoc-Analyse einzelner Prüfpunkte.

## Sicherheit & Recht

- **Nur auf eigenen oder ausdrücklich betreuten Systemen einsetzen.** Forensik auf fremden Systemen ohne Auftrag ist strafbar.
- Das Skript ist **read-only** bzgl. des Webspace; es schreibt ausschließlich in `/root/wartungsscripte/`.
- Bei Betroffenheit personenbezogener Daten: **DSGVO Art. 33** (72-Stunden-Meldefrist) beachten. Die erzeugte `bsi_meldung.md` ist ein Entwurf und ersetzt keine Rechtsberatung.

## Lizenz

MIT — siehe [LICENSE](LICENSE).

---
*netztaucher | digital*
