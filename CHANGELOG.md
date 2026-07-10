# Changelog

Alle nennenswerten Änderungen an `wp_plesk_forensik.sh`.

## [3.3.0] — 2026-07-10

### Neu — Detektion der Doorway-/Persistenz-Familie
Lehre aus einem realen Plesk-WordPress-Kundenvorfall (2026-07): Der Signatur-Webshell-Scan meldete `0`
Treffer, während der Server massiv kompromittiert war (RCE-Backdoor + SEO-Spam-
Doorway „open_cache_ruzhu" + selbst-versteckende Admin-Persistenz). Neue Prüfungen
in §11 (laufen auch **ohne** DB-Verbindung):

- **WordPress-Kern-Integrität** via `wp core verify-checksums` (wenn wp-cli vorhanden):
  erkennt injizierte Core-Dateien („doesn't verify") und Core-fremde Dateien
  („should not exist" — Doorways, getarnte Payloads, Attacker-Backups `*.orig`).
- **Doorway-`.htaccess`-Signatur** (`FilesMatch` erlaubt nur `index.php|cache.php`) —
  deckt die rekursiv verschachtelte `cache.php`-Injector-Familie über den ganzen
  Webspace auf, unabhängig von Datei-Endung/Obfuskation.
- **Bootstrap-Injektion** `@include base64_decode()` in `*.php` (Core-Persistenz, die
  bei jedem Request getarnte Payloads `.ttf/.png/.gif/.css` nachlädt).
- **wp-cli-DB-Fallback**: schlägt der direkte `mysql`-Zugang fehl, wird die DB über
  `wp db query` (als Datei-Eigentümer) geprüft — verhindert das stille Überspringen
  der DB-Prüfung (im Vorfall wurden so 4 Angreifer-Admins zunächst übersehen).
- **File-Manager-Webshells + manipulierte .htaccess** (Lehre aus 403-Prüfung, 3. Schicht):
  Erkennung von TinyFileManager/elFinder/FilesMan/H3K/b374k/WSO in Plugin-Ordnern (CRIT)
  sowie von `.htaccess`, die alle `.php` per `FilesMatch`-Whitelist sperren und nur
  Webshell-Namen (`adminfuns.php`, `classsmtps.php`, `postnews.php` …) zulassen — das
  blockiert legitime `wp-admin`-Seiten (**403**) und tarnt zugleich die Webshells.
  Neue findings.json-Felder `filemanager`/`tampered_htaccess`.
- **Bewertung ALLER Plugins + mu-Plugins** (nicht nur der aktiven): Filesystem-Scan über
  `wp-content/plugins/` **und** `wp-content/mu-plugins/` auf Fake-Signatur
  (`Author: WordPress` + `wordpress.org/plugins/`) und Backdoor-Hooks
  (`pre_user_query`, `create_admin`, `ensure_plugin_active`, `eval(base64_decode($_POST/GET/REQUEST))`).
  Bösartige Plugins deaktivieren/verstecken sich selbst und stehen **nicht** in
  `active_plugins`; mu-Plugins laufen ohne Aktivierung immer. Neue findings.json-Felder
  `suspicious_plugins`, `mu_plugins` + Metrik `suspicious_plugins`.

### Geändert
- **`wpconf_get()` überspringt auskommentierte Zeilen** (`// # * /*`). Vorher griff
  `head -1` fälschlich einen alten, auskommentierten `define('DB_NAME', …)`-Wert
  (Migrations-Rest) → Prüfung landete auf der falschen/nicht existenten Datenbank.
- Admin-Enumeration nutzt die Roh-`capabilities`-Meta (`administrator";b:1`). **Hinweis:**
  `wp user list --role=administrator` ist **nicht** verlässlich — Malware kann via
  `pre_user_query` Admins vor UI und wp-cli verstecken (im Vorfall real beobachtet).

### findings.json
- Neue `actionable`-Felder: `injected_core`, `core_should_not_exist`, `doorway_dirs`,
  `core_include_injection`, `disguised_payloads`, `rogue_wp_admins`.
- Neue `metrics`: `injected_core_files`, `doorway_dirs`, `core_include_injections`,
  `rogue_wp_admins`.

## [3.2.0] — 2026-07-08

### Neu
- **Maschinenlesbarer Export `findings.json`** pro Lauf. Enthält `run_id`, Verdikte (root/wpdb), Zähler, Metriken und die actionable Befunde (Webshell-Dropper, PHP-in-Uploads, SUID, tmp-Executables, Immutable, verdächtige Cron/systemd, Persistenz, Prozesse, WP-Configs, Fremd-SSH-Keys, IOC-IPs). Kein `jq`-Zwang (reines Bash-JSON), in SHA256-Versiegelung + Übergabe-Archiv aufgenommen. Dient als sauberer Vertrag für nachgelagerte Remediation-/Repair-Werkzeuge.

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
