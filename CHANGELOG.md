# Changelog

Alle nennenswerten Änderungen an `wp_plesk_forensik.sh`.

## [3.7.0] — 2026-08-05

### Neu — Mail-Kontext in findings.json
- `findings.json` (schema **1.3**) enthält bei Funden einen Block
  **`malware_summary`**: `total`, `affected_area` (grob: Shop-/Joomla-/WordPress-/
  Webbereich, aus den Fundpfaden), `finding_summary` (laienverständliche
  Formulierung aus dominanter Familie + Anzahl, Singular/Plural), `timeframe`
  (Zeitbezug aus der neuesten Datei-mtime, z. B. „erst in diesem Sommer"),
  `newest` und `families{}`. Ohne Funde: `"malware_summary": null`.
- Zweck: der Anschreiben-Generator (Kunden-E-Mail) füllt Bereich, Fund und
  Zeitbezug automatisch aus dem Lauf, statt sie manuell zu setzen.

## [3.6.0] — 2026-08-05

### Neu — System-Integrität (referenzlos & baseline)
- **§8.6 debsums** ergänzt `dpkg -V`: md5-Abgleich der Kern-Paketdateien gegen den
  Installationsstand (auf dieselbe kritische Paketmenge begrenzt, fließt in den
  Root-Verdikt). Übersprungen, wenn `debsums` fehlt.
- **§8.13 Kürzlich veränderte Systemdateien & Timestomping** (referenzlos, ohne
  Baseline): meldet neue/geänderte Dateien in normalerweise stabilen Systemdirs
  (`/usr/local/bin`, cron-, systemd-Unit-Dirs …) und erkennt **Zeitstempel-
  Manipulation** — Inode kürzlich geändert (ctime), mtime aber künstlich
  zurückdatiert. Nur `stat`-Traversierung, daher schnell.
- **§8.14 AIDE-Abgleich**: nutzt eine vorhandene AIDE-Baseline read-only
  (`aide --check`) und meldet Abweichungen. Erstellt/aktualisiert die DB **nicht**.
  Vorlage: `haertung/aide-forensik.conf`.

### Neu — Autoritative Scanner-Taps (read-only)
Statt eigene Erkennung nachzubauen, werden die Ergebnisse der auf Plesk ohnehin
vorhandenen, spezialisierten Scanner **gelesen** (kein Scan wird ausgelöst):
- **§8.15 Imunify-Malware-Datenbank** (`imunify-antivirus`/`imunify360-agent`):
  offene Treffer (Status „found") im Prüf-Scope. Signatur-Familie wird
  ausgewertet.
- **§11.10 WP Toolkit** (`plesk ext wp-toolkit --list`): meldet vom WP Toolkit
  als **infiziert** markierte WordPress-Instanzen. Beide Taps sind scope-aware.

### Neu — Befund-Klassifikation, Detaildatei & PDF-Deckblatt-Card
- Schadcode-Funde werden grob einer **Familie** (Defacement, Backdoor/Webshell,
  SEO-Spam/Doorway, Phishing, Cryptominer …) samt **Geschäftsmodell** zugeordnet.
- Neue Datei **`befunde_details.md`** listet alle Fundstellen mit Pfaden
  **relativ zum Kundenverzeichnis** (nie absolut); Kunden- und Technik-Bericht
  verweisen darauf. Details bewusst nicht im laienlesbaren Kundenbericht.
- Das **PDF-Deckblatt (Seite 1)** trägt eine **Grobstatistik-Card**: Fundstellen
  gesamt + je Familie eine Kachel.
- `findings.json` → schema **1.2**: neue Schlüssel `timestomp`,
  `recent_system_changes`, `imunify_malware`, `wptk_infected`.

### Geändert
- **`--yara`** entkoppelt: der YARA-Scan lief bereits ab v3.5 nur auf Wunsch.

## [3.5.0] — 2026-08-05

### Neu — Scope-Steuerung, DSGVO-Datensparsamkeit, PDF-Abschlussbericht
- **Scope-Schalter** `--domain <d>` / `--path <p>` / `--global` (plus `--yara`,
  `-h/--help`). Das bisherige Positionsargument bleibt als `--domain` erhalten.
  Die Server-/Rootebene wird in **jedem** Modus mitgeprüft; der Scope steuert nur
  den Dateisystem-Scan und die Berichtserzeugung.
- **Kundenbericht ohne Root-Details**: §4 nennt die Serverebene nur noch generisch
  (betroffen / nicht betroffen). Der vollständige Root-Verdikt inkl. IPs,
  Indikatorzahl und „Server-neu-aufsetzen"-Empfehlung bleibt Technik- und
  BSI-Bericht vorbehalten.
- **DSGVO-Datensparsamkeit**: fremde E-Mail-Adressen (z. B. WP-Admin-Konten)
  werden in Kundenberichten pseudonymisiert (`a***@domain`). Angreifer-IPs
  bleiben zum Sperren im Klartext (berechtigtes Interesse). Technik-/BSI-/
  DSGVO-Berichte (interne bzw. Behördendokumente) bleiben unmaskiert.
- **PDF-Abschlussbericht** im netztaucher-Layout (`abschlussbericht.pdf`):
  Teil 1 = Kundenbericht, Teil 2 = KPI-Zusammenfassung (`zusammenfassung.md`).
  Pipeline pandoc → weasyprint über `reportgen/`. Fehlt eine Abhängigkeit, wird
  das PDF übersprungen — die Markdown-Berichte bleiben vollständig und maßgeblich.
- **`--yara`-Flag**: der YARA-Scan (7.11) läuft nur noch auf Wunsch (auf großen
  Webspaces teuer), statt automatisch bei installiertem `yara`.

### Behoben
- **Cross-Mandanten-Leck geschlossen**: Ein `--global`-Lauf erzeugte zuvor einen
  „Kundenbericht", der bei leerem Domain-Argument die Befunde (und ggf.
  personenbezogenen Daten) **aller** Kunden mischte. Der Global-Lauf ist jetzt
  klar als **Betreiberbericht** gekennzeichnet und nicht zur Weitergabe an
  einzelne Kunden bestimmt; kundenspezifische, maskierte Berichte entstehen über
  `--domain`.

## [3.4.0] — 2026-08-05

### Neu — Relay-Backdoors & Prozess-Introspektion
Lehre aus einem realen Fund: eine als `~/.ssh/id_rsa` getarnte gs-netcat-Binary
(THC gsocket) — eine 2,8 MB große, statisch gelinkte, gestrippte ELF-Datei. Diese
Backdoor-Klasse öffnet **keinen Port** (beide Seiten verbinden sich ausgehend über
TLS/443 zu einem Relay) und war für v3.3 unsichtbar. Auch rkhunter/chkrootkit finden
sie nicht: kein Rootkit, keine trojanisierten Binaries, kein offener Port. Die neuen
Prüfungen setzen deshalb auf **strukturelle** Merkmale statt auf Namen.

- **§8.7 Relay-Backdoors (gsocket/gs-netcat)** — Signaturscan auf Datei- und
  Prozessebene, ELF und Text getrennt bewertet (Binary = kritisch, Textfund = Review).
- **§8.8 Fileless (memfd)** — Prozesse, deren Binary via `memfd_create()` nur im RAM
  existiert und nie auf der Platte lag.
- **§8.9 Kernel-Thread-Tarnung** — User-Prozesse, die sich `[kworker/…]` nennen,
  enttarnt über PPID ≠ 2 und vorhandenes `/proc/PID/exe`. Prüft comm **und** argv[0].
- **§8.10 Verwaiste Interpreter** — Shells mit PPID 1 ohne kontrollierendes TTY.
- **§8.11 Prozess-Umgebung** — `GSOCKET_*`, `GS_ARGS`, `LD_PRELOAD`,
  `HISTFILE=/dev/null` in `/proc/PID/environ`.
- **§8.12 Ausgehende Verbindungen** — Relay-typische Verbindungen mit **Peer-Port**
  443/7350 außerhalb der Prozess-Whitelist, TOR-Ports.
- **§7.10 Getarnte Binaries** — ELF-Magic-Prüfung für Dateien mit Schlüssel-/Konfig-Namen
  (`id_rsa`, `*.pem`, `*.key`, `*.crt`, `authorized_keys`, `*.conf`).
- **§7.11 YARA-Signaturscan** über `signaturen/gsocket-backdoors.yar` (optional, wird
  ohne installiertes `yara` übersprungen).
- **§5.6 SSH-Login-Hooks** (`~/.ssh/rc`, `/etc/ssh/sshrc` — laufen bei jedem Login,
  stehen in keinem Cron) und **§5.7** `authorized_keys` mit erzwungenem `command="…"`.
- **§6.9 Exotische Persistenz** — udev `RUN+=`, PAM `pam_exec.so`, APT `Pre-/Post-Invoke`,
  systemd `linger`.
- **`RELAY_VERDICT`** — konsolidiertes Verdikt analog zum Root-Verdikt, in Technik-,
  Kunden- und BSI-Bericht sowie `findings.json` (`verdicts.relay`, schema 1.1).
- **`signaturen/gsocket-backdoors.yar`** — YARA-Regelsatz (4 gsocket-Regeln + Reverse-Shell-/Webshell-Muster).
- **`haertung/audit-backdoor.rules`** — auditd-Regelsatz für laufende Verhaltensüberwachung
  nach dem Vorfall.
- **`docs/relay-backdoors.md`** — Erkennungs-Dokumentation inkl. Begründung, warum
  rkhunter und chkrootkit diese Backdoor-Klasse nicht finden.

### Behoben / gehärtet (im Test auf echtem Plesk aufgefallen)
- **Signaturscans nutzen `grep -a`/`grep -rla` ohne `-I`.** Das `-I`-Flag überspringt
  Binärdateien und hätte genau die gesuchten ELF-Backdoors ausgeschlossen.
- **Selbstausschluss** (`nf_strip_self`): alle neuen Scans filtern gegen `${BASE_DIR}`,
  sonst meldet der Lauf ab dem zweiten Mal die eigenen Berichte als Fund.
- **Laufzeit auf Shared-Hosts**: §7.10/§7.11/§8.7 scopen den vhost-Teil auf `SCAN_PATH`
  (statt aller vhosts) und begrenzen den Inhaltsscan auf Dateien `< 30 MB` — sonst
  liest der Regex auf Produktions-Servern zig GB Backups/Quarantäne byteweise durch.
- **§8.12 wertet nur den Peer-Port aus.** Ein Webserver hat bei jeder **eingehenden**
  HTTPS-Verbindung lokal Port 443; die erste Fassung meldete diese als ausgehenden
  Relay-Verdacht (auf echtem Plesk gemessen: 76 eingehende vs. 2 echte ausgehende).

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
