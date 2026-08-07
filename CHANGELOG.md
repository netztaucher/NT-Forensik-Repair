# Changelog

Alle nennenswerten Änderungen an `wp_plesk_forensik.sh`.

## [unveröffentlicht]

### Neu — Der Prüfbaum trägt Plugins
Bis hierher hatte keine der drei Installationen im Prüfbaum ein Plugin. Der
Trefferpfad des Schwachstellenabgleichs war damit nicht erreichbar: der
Prüfstand sah ausschliesslich den Fall „nichts zu vergleichen".

Kunde 2 bekommt verwundbare Fassungen (eine mit belegter Ausnutzung, eine ohne,
ein betroffenes Theme, ein Plugin ohne lesbaren Kopf), Kunde 3 als Gegenprobe
die behobenen. Dazu ein eigener, winziger Datenbestand, den `goldmuster.sh` bei
jedem Bau erzeugt — mit tagesaktuellem Stand, weil ein fester Stand nach
`WP_DATEN_MAX_TAGE` veraltet wäre und der Prüfstand dann ohne jede
Codeänderung ausschlüge.

Alle Kennungen und CVE-Nummern im Fixture sind **frei erfunden**. Ein Prüfbaum
darf keine Tatsachenbehauptung über ein echtes Plugin enthalten.

Eine zweite Gegenprobe in der CI erklärt den Bestand für veraltet und erwartet,
dass der Vergleich das bemerkt — sonst wüsste niemand, ob der Baum den
Trefferpfad überhaupt erreicht.

`WP_DATEN_DIR` erlaubt einen Datenbestand ausserhalb der Installation. Der
Prüfstand braucht das; im Betrieb ist es brauchbar, wenn mehrere Installationen
sich einen gepflegten Bestand teilen.

### Neu — Der Haken `rezept_version` wird aufgerufen
`lib/rezepte.sh` nennt ihn seit der ersten Fassung als Haken, `module/12r_rezepte.sh`
rief ihn nie auf und zog ihn auch im `unset -f` nicht zurück. Ein Rezept konnte
ihn also deklarieren, ohne dass je etwas passierte. Der Haken läuft jetzt vor
`rezept_sonder` — dateibasiert, ohne Werkzeug der Anwendung.

### Neu — WordPress: Plugin-Integrität gegen wordpress.org
`rezept_kern` prüft nicht mehr nur den Kern. Die Dateien installierter Plugins
werden gegen `downloads.wordpress.org/plugin-checksums/<slug>/<version>.json`
abgeglichen (md5 **und** sha256 je Datei). Das findet **veränderte** Dateien
statt veralteter Fassungen — für eine Forensik die stärkere Aussage, und der
Kern ist selten das Einfallstor: die Nutzlast liegt fast immer im Plugin-Ordner.

Nur mit `--online`, ein Abruf je Plugin, protokolliert über `nf_fetch`.

Vier Befundklassen: veränderte `.php`/`.js` sind 🔴, veränderte Nicht-Codedateien
und fehlende Dateien ⚠️, zusätzliche PHP-Dateien vorerst nur ein Beleg.

Bewusst **nicht** über `wp plugin verify-checksums` — das Kommando zählt die
Plugins über die WordPress-Laufzeit auf, und genau darüber nimmt sich ein
manipuliertes Plugin per `all_plugins`-Filter selbst aus der Prüfung. Ausserdem
deckt es weder mu-Plugins noch Themes ab.

Plugins ohne Prüfsummensatz (Premium, Fork, Eigenbau) und Themes, für die
wordpress.org grundsätzlich keine Prüfsummen veröffentlicht, werden zu **einem**
⚪ zusammengefasst.

### Neu — WordPress: Abgleich gegen bekannte Schwachstellen
Das Rezept nutzt den Haken und gleicht Kern, Plugins und Themes gegen den
Datenbestand unter `rezepte/wordpress/daten/` ab. **Offline** — kein `--online`
nötig, geprüft wird gegen das, was ausgeliefert wurde.

Die Fassungen kommen aus Kopfzeilen im Dateisystem, nicht aus der Datenbank und
nicht über wp-cli: ein manipuliertes Plugin nimmt sich über den
`all_plugins`-Filter selbst aus jeder Laufzeitliste, und der Abgleich soll auch
dort etwas sagen, wo wp-cli fehlt. Der Kern kommt aus `wp-includes/version.php`,
Themes aus `style.css`.

Bewertung: ein Treffer mit KEV-Kennzeichen ist 🔴 mit dem ausdrücklichen Hinweis
auf die belegte Ausnutzung, sonst ⚠️. Bestandteile ohne lesbare Fassung werden zu
**einem** ⚪ zusammengefasst — je Stück würde das die Kundenampel auf fast jeder
Seite dauerhaft blockieren.

**Ein veralteter Datenbestand ist gefährlicher als gar keiner**: er liefert ein
ruhiges Ergebnis, das nach Prüfung aussieht. Über 30 Tage (`WP_DATEN_MAX_TAGE`)
meldet das Rezept deshalb ⚪ und vergleicht nicht. Fehlt der Bestand ganz, ist es
ein Hinweis — dann wurde nichts versucht, dieselbe Linie wie beim abgeschalteten
YARA-Scan.

### Neu — Schwachstellen-Datenbestand und Vergleicher für WordPress
Das Gegenstück zu `daten/joomla/` entsteht: `rezepte/wordpress/daten/` mit
`werkzeuge/wordpress-daten-update.sh` als Pflegewerkzeug und
`lib/wp_schwachstellen.py` als Vergleicher.

Der Unterbau; das Scharfschalten geschieht im WordPress-Rezept (siehe oben).

**Eigener Versionsvergleich statt `j_vernum`.** Das Joomla-Verfahren presst
`a.b.c` in eine Zahl `aabbbccc`. Für Joomla trägt das; für WordPress-Plugins
nicht, weil dort vierstellige Fassungen (`1.2.3.4`) und Vorabkennungen
(`2.0-beta1`, `3.1-RC2`) verbreitet sind — `j_vernum` liefert dafür `0` und
überspringt den Vergleich. Bei Joomla ist das die richtige Vorsicht, bei
WordPress wären es massenhaft Nicht-Bewertungen.

Umgesetzt ist die Semantik von PHPs `version_compare`, also die Ordnung, die
WordPress selbst benutzt: `1.0-dev < 1.0a1 < 1.0b1 < 1.0RC1 < 1.0 < 1.0pl1`.
Geprüft wird sie nicht gegen eine handgeschriebene Erwartungstabelle, sondern
gegen die echte PHP-Funktion — `werkzeuge/version_compare_gegentest.sh`
vergleicht 30.000 Fassungspaare, und die CI führt das bei jeder Änderung aus.

**Intervalle mit einzeln offenen Grenzen.** `>= 2.0 und <= 2.4.1` und
`>= 2.0 und < 2.4.1` unterscheiden sich genau um die Fassung, in der die Lücke
behoben wurde; auf „kleiner als" verkürzen lässt sich das nicht.

**Drei Zustände.** `BETROFFEN`, `SAUBER`, `UNBEWERTBAR`. Eine unlesbare Version
darf nicht als „nicht betroffen" durchgehen, und ein fehlender Eintrag heißt
„keine bekannte Schwachstelle im vorliegenden Bestand", nicht „sicher".

### Neu — `rezepte/wordpress/daten/`
Enthält vorerst nur `kev/kev-wordpress.tsv`: die sechs WordPress-Einträge aus
dem KEV-Katalog der CISA (gemeinfrei). Sie tragen die einzige Aussage, die eine
Priorisierung wirklich rechtfertigt — diese Lücke wird nachweislich ausgenutzt.
Gegenstück zur Spalte `kev` in `daten/joomla/cve/joomla-ext-kritisch.tsv`.

Die Schwachstellentabellen unter `vuln/` sind noch nicht erzeugt: der
Wordfence-Feed verlangt seit v3 einen Schlüssel. `QUELLEN.md` führt die
Lizenz-Ampel aller geprüften Quellen und die Punkte, die vor der ersten
Auslieferung eines Wordfence-Bestandes zu erledigen sind.

Nicht verwendet: WPScan (Speichern und Cachen vertraglich untersagt),
Patchstack (kein offener Zugang), wpvulnerability.net (Lizenz der Daten nicht
erklärt, keine Bulk-Schnittstelle), GitHub Advisory Database (lizenzrechtlich
sauber, aber ohne verwertbare WordPress-Abdeckung).

## [3.9.0] — 2026-08-06

### ⚠️ Breaking — Aufruf ohne Argument
Bisher bedeutete ein Aufruf ohne Argument implizit `--global`. Jetzt startet
er das **Startmenü**. Ohne Terminal (Cronjob, `ssh` ohne `-t`) bricht der Lauf
mit Code 2 und einer Erklärung ab, statt auf eine Eingabe zu warten.

**Cronjobs und Skripte ohne Scope-Argument müssen angepasst werden:**

```diff
- bash /root/wartungsscripte/wp_plesk_forensik.sh
+ bash /root/wartungsscripte/wp_plesk_forensik.sh --global --kein-menue
```

Aufrufe **mit** Scope-Argument (`--domain`, `--path`, `--global`) laufen
unverändert direkt durch — sie sind eine eindeutige Anweisung, dort erscheint
nie ein Menü. Der dokumentierte SSH-Einzeiler bleibt gültig.

### Neu — Modularer Aufbau
Aus einer Datei mit 4412 Zeilen wurden ein Runner (114 Zeilen), fünf
`lib/`-Dateien und 14 Module unter `module/`, eines je Prüfabschnitt.

Anlass war doppelt: auf einem Server mit 482 Vhosts hing eine reine
Joomla-Prüfung minutenlang im Log-Archiv von Abschnitt 2, und während der
Joomla-Entwicklung musste jeder Testlauf den Abschnitt erst per `awk` aus dem
Skript herausschneiden.

Der Schnitt war mechanisch — Zeilen verschoben, keine Logik umgeschrieben.
Nur so ließ er sich per Ausgabevergleich belegen. `lib/befunde.sh` macht den
Vertrag zwischen den Modulen sichtbar, der vorher schon bestand: jede
Ergebnisvariable mit neutralem Vorgabewert, damit ein übersprungener
Abschnitt den Bericht unter `set -u` nicht abstürzen lässt.

Aufbau und Erweiterung: [`docs/architektur.md`](docs/architektur.md).

### Neu — Abschnittsauswahl

```
--nur 12              nur dieser Abschnitt
--nur 7,11,12         mehrere
--ohne 2,10           alle ausser diesen
--nur-joomla          Kurzform für --nur 12
--nur-website         nur die Abschnitte, die den Webauftritt prüfen
```

Abschnitt 14 läuft immer mit, ausser er wird per `--ohne 14` abgewählt.

**Ein Teillauf weist sich als solcher aus.** Der Technikbericht bekommt einen
Kasten mit den nicht ausgeführten Abschnitten und dem Hinweis, dass deren
Fehlen keine Entwarnung ist; `findings.json` führt `run.vollstaendig`,
`run.module_gelaufen` und `run.module_uebersprungen`. Berichte gehen an Kunden
und ans BSI — eine Teilprüfung, die sich wie ein vollständiges Ergebnis liest,
wäre schlimmer als gar keine.

### Neu — Startmenü
Erklärt die Abschnitte gruppiert nach Ebene mit Frage und Aufwand, fragt
Umfang und Auswahl ab und gibt am Ende den gleichwertigen Befehl aus. Module
beschreiben sich dafür im eigenen Kopf (`@nummer`, `@titel`, `@frage`,
`@kosten`, `@ebene`) — eine zentrale Liste würde auseinanderlaufen.

`--kein-menue` unterdrückt es, `--menue` erzwingt es.

### Behoben — Werte, die nur in einem Abschnitt existierten
`SCAN_PATH`, `PLESK_MYSQL_PW`, `PATTERN_REGEX` und `DROPPER_MAX_BYTES` wurden
mitten in einem Prüfabschnitt gesetzt und von anderen gelesen. Sie stehen
jetzt in `lib/konfig.sh` bzw. `lib/muster.sh`. Ohne das hätte jedes
Überspringen dieser Abschnitte die folgenden mit `unbound variable` abgebrochen.

Ebenso fehlten `ROOT_CUSTOMER_HINT` und `MALWARE_TOTAL` als Vorgabewerte —
der Kundenbericht liest beide ungeschützt.

### Behoben — Argumente kamen nicht an
`source` aus einer Funktion heraus setzt `$@` auf die Argumente der Funktion,
nicht des Skripts. Nach dem Schnitt kam damit keine einzige Option in
`lib/konfig.sh` an; `--help` löste die Root-Prüfung aus statt die Hilfe zu
zeigen. Der Runner sichert die Kommandozeile jetzt in `NT_ARGV`, bevor er
irgendetwas einbindet.

## [3.8.0] — 2026-08-05

### Neu — Abschnitt 12: Joomla-Prüfung

Joomla kam im Werkzeug bisher nur als Pfad-Heuristik für das Kunden-Anschreiben
vor. Eine Joomla-Site bekam faktisch denselben Bericht wie ein statisches
Verzeichnis — obwohl seit Juni 2026 eine Welle von Massenausnutzungen gegen
Joomla-Erweiterungen läuft (drei Joomla-Einträge im KEV-Katalog der CISA, zwei
davon aus 2026) und **Joomla 3 und 4 beide keine Sicherheitspatches mehr
erhalten**.

- **12.1 Erkennung** über `class JConfig`; der Dateiname `configuration.php`
  allein ist zu unscharf. Backup-/Altkopien werden übersprungen.
- **12.2 Version & Wartungsende** aus mehreren unabhängigen Quellen.
  Widersprechen sie sich, ist das selbst ein Befund.
- **12.3 Härtung** der `configuration.php`, inkl. Strukturprüfung auf
  ausführbaren Code (Muster der Rusty-Joomla-Hintertür) und auf
  Sicherungskopien im Webverzeichnis.
- **12.4 Ungeschützter API-Zugriff** (CVE-2023-23752) mit Gegenprobe im
  Zugriffsprotokoll.
- **12.5 Kern-Integrität**: Prüfsummen-Vergleich des Programmkerns — das
  Gegenstück zu `wp core verify-checksums`, das es für Joomla bisher nirgends
  gab. Joomla veröffentlicht keine Prüfsummen je Datei; sie werden deshalb aus
  den offiziellen Paketen selbst erzeugt. Rund 9800 Dateien in etwa vier
  Sekunden. Zweistufig: passt der Hash nicht, entscheidet ein zweiter über den
  auf Leerzeichen normalisierten Inhalt — damit fallen reine Änderungen an
  Zeilenenden heraus, der klassische Fehlalarm nach FTP-Übertragung.
- **12.7 Abgleich mit bekannten Schwachstellen**: Kern gegen die Meldungen des
  Joomla-Sicherheitsteams, Erweiterungen gegen die Liste verwundbarer
  Erweiterungen und eine handgepflegte Tabelle der Fälle mit belegter
  Massenausnutzung.
- **12.6 Datenbank**: aktive System-Plugins (laufen vor jeder Rechteprüfung),
  Super-User über die tatsächliche Rechtetabelle statt der Standardgruppe,
  Rechtevergabe an offene Gruppen, Deserialisierungs-Spuren in der
  Sitzungstabelle, **Injektionen in den Vorlagen-Einstellungen**, verschleierte
  Modulinhalte, dauerhafte Anmelde-Token.
- **12.8 Schaddateien**: als Bild getarnte PHP-Dateien, PHP in Medien- und
  Zwischenspeicher-Ordnern, Filterumgehung über gemischte Schreibweise,
  Code vor der Zugriffssperre, verbliebenes Installationsverzeichnis,
  ungeschützter jDownloads-Uploader, `auto_prepend_file`, Sicherungsarchive.
- **12.9 Protokolle**: bekannte Joomla-Angriffswege. Versuch und Erfolg werden
  getrennt — kritisch nur zusammen mit einem Dateifund.
- **12.10 Joomla-Verdikt**, angeschlossen an Kundenbericht, BSI-Meldung,
  `findings.json` und PDF-Zusammenfassung.

Die Vorlagen-Prüfung ist der Grund, warum ein reiner Dateiscan bei der
Helix3-Kampagne versagt: die Nutzlast liegt ausschließlich in der Datenbank
und überlebt jede Wiederherstellung der Dateien.

### Neu — Signaturen & Optionen
- `signaturen/joomla-malware.yar` als Eigenimplementierung; kein Regelwerk aus
  GPL-Quellen übernommen (das Repository steht unter MIT).
- `signaturen/alle.yar` bindet die Regelsätze per `include` ein. Rückfall auf
  die Einzeldatei hält Installationen mit altem Signaturstand lauffähig.
- `--online` erlaubt dem Lauf, Vergleichsdaten nachzuladen. Ohne das Flag
  arbeitet er rein offline. Jeder Abruf wird mit URL, Antwortcode und
  Prüfsumme im Bericht, als Beleg und in `findings.json` ausgewiesen.

### Neu — Datenbestand und Pflegewerkzeug
`werkzeuge/joomla-daten-update.sh` erzeugt den Bestand unter `daten/joomla/`
(Kern-Prüfsummen, Schwachstellenlisten). Läuft auf der Entwicklungsmaschine
oder in der CI, **nie** auf einem Kundenserver, und wird deshalb nicht mit
ausgeliefert. Der Bestand umfasst elf Joomla-Fassungen in 3 MB: die
Prüfsummen liegen je Zweig statt je Fassung, weil gemessen 93 % der Dateien
über die Patch-Releases eines Zweigs identisch sind.

### Behoben — `nf_fetch` folgte keiner Weiterleitung
Der Netzabruf verwendete `curl` ohne `-L`. Release-Downloads antworten mit
302 auf einen Auslieferungsdienst; ohne Folgen der Weiterleitung landete nur
die 302-Antwort in der Zieldatei und der Abruf scheiterte stumm. Zudem war
das Zeitlimit von 25 Sekunden für ein 30-MB-Paket zu knapp.

### Behoben — `findings.json` wurde bei echten Funden unlesbar
`json_arr`/`json_str` maskierten keine Steuerzeichen. Tabulatoren stecken in
jeder Zeile, die aus `mysql -N` stammt — unter anderem in `ROGUE_ADMINS`.
Die Datei wurde damit ausgerechnet dann ungültig, **wenn ein echter Fund
vorlag**, und der Anschreiben-Generator konnte sie nicht mehr lesen. Unbemerkt
geblieben, weil die Beispieldatei nur leere Listen enthält.

### Behoben — Hilfsdateien wurden nie aufgefrischt
Die Selbst-Installation kopierte `signaturen/` und `reportgen/` nur, wenn das
Ziel **noch nicht existierte**. Ein einmal installierter Host blieb dauerhaft
auf dem Erststand und hätte neue Signaturen nie erhalten.

### Behoben — Abschnittsnummern
Die Unterabschnitte der Root-Prüfung hießen 11.1–11.6 innerhalb von
Abschnitt 12. Mit dem neuen Joomla-Abschnitt rücken Root-Prüfung auf 13 und
Zusammenfassung auf 14; alle Querverweise wurden mitgezogen.

### Geändert
- `MAIL_AREA`: die frühere Joomla-Regex traf schon bei einem blanken
  `/administrator` und damit auch bei Nicht-Joomla. Jetzt ist der volle
  Joomla-Pfadkontext nötig. WordPress steht vor Shop (WooCommerce liegt immer
  unter `wp-content`), und Joomla-Shops werden über die verbreiteten
  Shop-Komponenten erkannt statt Joomla pauschal als Shop zu behandeln.
- `findings.json`: **Schema 1.4** — neu `verdicts.joomla`, ein Block
  `data_sources` (Stand des Datenbestands, Online-Modus, Netzabrufe) und
  `joomla_*`-Felder unter `metrics` und `actionable`. Rückwärtskompatibel,
  `mailgen.py` liest weiterhin unverändert.

### Geprüft
Gegen echte Joomla-Pakete (3.10.12, 4.4.14, 5.4.7) und ein unverändertes
Joomla-Schema auf MySQL 8.0: eine saubere Installation bleibt vollständig
still, alle Angriffsmuster werden erkannt. Zwei dabei gefundene Fehler in der
neuen Prüfung wurden vor der Auslieferung behoben — ein Feldversatz durch
leere Datenbankspalten und ein Fehlalarm, der alle Kern-System-Plugins einer
Neuinstallation als Hintertür meldete.

## [3.7.1] — 2026-08-05

### Behoben — Scope-Trennung Kundenbericht
- Der **Kundenbericht** zeigte bisher ALLE Befunde inkl. Server-/Root-/
  Infrastruktur-Ebene (Cronjobs, Rechteausweitung, Root-Verdikt, andere
  Benutzer, Ports, systemd, `/root/.ssh` …). Das gehört dort nicht hin und
  leakte interne Serverdetails an den Kunden.
- `crit`/`warn` kennen jetzt einen **`web`-Scope** (`crit "…" web`): nur so
  markierte **Website-Befunde** (Webshells, WordPress-DB/Core/Plugins, Doorway,
  Imunify-/WP-Toolkit-Treffer, Webspace-Auffälligkeiten, Traffic der Domain)
  landen im Kundenbericht. Server-/Root-Befunde bleiben Technik-/BSI-/
  Betreiberbericht vorbehalten.
- SSH-Brute-Force-Zeile aus der Kunden-Kurzfassung entfernt (Server-Ebene).

### Behoben — Root-Fehlalarm durch Self-Kontamination
- §11.4 Privilege-Escalation ankert jetzt auf die **Caller-Position**
  (`sudo: webNN :` = Web-User ruft sudo auf). Die alte Regex traf auch das
  TARGET-Feld (`USER=webNN`) und meldete damit **root→Web-User**-Aufrufe als
  Eskalation — u.a. NT-Forensiks eigenes `sudo -u webNN wp core verify-checksums`
  (§11) und jeden Plesk-internen root→User-sudo. Folge war ein
  „Root-Kompromittierung möglich" auf **sauberen** Servern. Jetzt nur noch echte
  Web-User→root-Eskalation.

### Behoben — Imunify-Tap überzeichnet
- §8.15 zählt einen Imunify-Treffer nur, wenn die Datei **noch auf der Platte
  existiert**. Imunifys DB behält Status „found" auch für längst gelöschte
  Dateien → sonst Malware-Fehlalarm für nicht mehr vorhandene Funde.
- Quarantäne-/Backup-Pfade (`schadcode/`, `quarantine`, `backup`, `*_bak`,
  `altkopie`, `sicherung`) werden ausgeschlossen — die sind bereits eingedämmt,
  kein Live-Befund.

### Behoben — Kunden-Ampel nach Website-Scope
- Die Einstufung des Kundenberichts (🔴/🟡/🟢) richtet sich jetzt nach den
  **Website-Befunden** (+ echte Malware), nicht mehr nach dem Gesamt-`N_CRIT`.
  Server-/Root-Befunde allein machen den Kundenbericht nicht mehr „KRITISCH".

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
