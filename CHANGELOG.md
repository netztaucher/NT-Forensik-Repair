# Changelog

Alle nennenswerten Änderungen an `wp_plesk_forensik.sh`.

## [3.1.0] — 2026-07-08

### Neu
- **DSGVO-Meldung (`dsgvo_meldung.md`)** als eigener, vierter Bericht pro Lauf. Struktur nach **Art. 33 DSGVO** mit den Pflichtinhalten des Art. 33 Abs. 3 (lit. a–d), maschineller **Meldepflicht-Einschätzung** (🔴/🟠/🟢 aus Befundlage + WordPress-Betroffenheit), vorbefüllten betroffenen Datenquellen und klarer Abgrenzung zum BSI-Meldeweg. In SHA256-Versiegelung und Berichts-Index aufgenommen.

### Geändert
- Kundenbericht verweist getrennt auf DSGVO- und BSI-Meldung (unterschiedliche Meldewege).

## [3.0.0] — 2026-07-08

Erste vollständig dokumentierte, gebrandete Release.

### Neu
- **Handbuch, Erkennungs-Referenz und Incident-Response-Playbook** unter `docs/`.
- **netztaucher-Branding**: Hero-Banner im README, Logo, verlinkte WordPress-Leistung ([netztaucher.com/wordpress](https://netztaucher.com/wordpress)).
- **WordPress-Leistungs-Hinweis im Kundenbericht-Footer** — jeder erzeugte Kundenbericht verweist auf die netztaucher WordPress-Betreuung.

### Enthält alle Erkennungs- und Berichtsfunktionen aus 2.9.0 (siehe unten).

## [2.9.0] — 2026-07-08

Erste öffentliche Veröffentlichung.

### Erkennung
- **Obfuskierte Cookie-Backdoors**: Variable-Variable-Superglobale (`${$a.$b.$c}`) und mixed-case `EvaL(base64_decode(...))` werden case-insensitive erkannt — schließt eine gängige Evasion-Lücke, an der reine Signaturscanner scheitern.
- **Zweistufige Webshell-Bewertung**: kleine Obfuskations-Dropper (kritisch) vs. große Framework-Dateien mit legitimem `eval` (Review), getrennt per Dateigröße.
- **Prozess-Forensik**: gelöschte Binaries (nur Nicht-Systempfade), Krypto-Miner, Herkunft aus `/tmp`/`/dev/shm`/Webspace, Reverse-Shell-Muster in Kommandozeilen.
- **Persistenz**: at-Jobs, fremde/neue systemd-Units, `rc.local`, `ld.so.preload`, `profile.d`-Hooks, Kernel-Module.
- **Dateisystem**: SUID/SGID in Webspace/tmp, Immutable-Flags (`chattr +i`), ausführbare Dateien in tmp.
- **System**: `dpkg -V`-Binärintegrität (Rootkit-Indikator), Postfix-Mailqueue (Spam-Versand).

### Neue Abschnitte
- **§11 WordPress-Datenbank-Prüfung**: fremde/kürzlich angelegte Admin-Konten, manipulierte Optionen (`siteurl`/`home`, `auto_prepend`, `base64`/`eval`), aktive Plugins. Read-only, nutzt Plesk-Admin-MySQL-Zugang.
- **§12 Root- & Eskalations-Prüfung**: Root-Login-IPs + Auth-Methode, `/root/.ssh/authorized_keys`, Web-User-Keys (Fremd- vs. Plesk-Keys), sudo/su-Eskalation, konsolidiertes Root-Verdikt.
- **§1.6 Changelog-Abgleich**: liest `/root/changelog.md` (dokumentierte Systemänderungen) und gleicht Befunde dagegen ab.

### Berichte
- Kundenbericht komplett überarbeitet: Ampel-Einstufung mit Konsequenz-Text, Sofortmaßnahmen-Tabelle mit Fristen (24 h / 72 h), technische Kurzfassung, DSGVO-/BSI-Hinweise.
- Abschnitt „Angriffshergang" füllt sich maschinell aus den Lauf-Daten (auffällige IPs, Einfallstor-Hypothesen, Zeitraum, Aktivität) — keine nackten Platzhalter mehr.
- BSI-Meldung mit vorausgefüllten Kennzahlen, IOCs und Reichweite-/Root-Verdikt.

### Robustheit
- Collector-Ausführung ohne `set -e`/`pipefail` (liefert immer vollständige Berichte, auch bei Einzelfehlern).
- False-Positive-Filter: Theme-Iconfonts, WP-Guard-Dateien, Upgrade-Reste gelöschter Binaries, Plesk-eigene SSH-Keys, Framework-`eval`.
- Chain-of-Custody: nummerierte Belege, SHA256-Versiegelung, Übergabe-Archiv pro Lauf.
