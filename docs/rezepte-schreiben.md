# Ein Prüfrezept schreiben

Ein Rezept beschreibt, wie eine Anwendung geprüft wird. Es ist ein Verzeichnis
unter `rezepte/` — mehr braucht es nicht. Gefunden wird per Glob, es gibt kein
Zentralregister, das gepflegt werden müsste.

```
rezepte/<app>/
├── rezept.conf      Pflicht — die Deklaration
├── rezept.sh        optional — Haken für das, was nur diese Anwendung kann
├── signaturen.tsv   optional — muster ⇥ schwere ⇥ was_es_ist
└── daten/           optional — Offline-Bestand (Prüfsummen, CVE-Listen)
```

## Warum es das gibt

Bis v3.12 hatte jede Anwendung ihren eigenen Prüfabschnitt. Vier Abschnitte für
WordPress, Joomla und Nextcloud — und vier Auslegungen desselben Vertrags:

| Schritt | Die vier Abschnitte taten |
|---|---|
| Sicherungskopien filtern | 12 meldete `info`, 12b `warn`, 12c `info`, 11 filterte gar nicht |
| Selbstausschluss | 11 fehlte er |
| Werkzeug-Probe vor der Messung | nur 12c hatte sie |
| Verdikt | 12b hatte keins |

Keine dieser Abweichungen war beabsichtigt. Der Rahmen macht daraus **eine**
Auslegung, und zwar die strengste — und ein Rezept kann sie nicht überspringen.

## Was der Rahmen leistet

Diese Schritte muss ein Rezept **nicht** schreiben. Sie passieren immer:

- Installationen finden (Marker + Bestätigungsdatei + Selbstausschluss)
- Sicherungskopien herausfiltern und als Warnung ausweisen
- Leerfall, Zählung, Auflistung
- **Werkzeug-Probe vor der Messung** — antwortet das Werkzeug nicht verwertbar,
  wird `unklar` gemeldet statt eine leere Ausgabe als „nichts gefunden" zu lesen
- Signaturen aus `signaturen.tsv` anwenden
- Verdikt einsammeln

## `rezept.conf`

Eine **Datendatei, kein Skript.** Sie wird gelesen, nicht ausgeführt — ein
Rezept aus fremder Hand darf nichts mit Root-Rechten tun können.

```ini
name          = Nextcloud
ebene         = website

marker        = occ            # was gesucht wird
marker_tiefe  = 6
bestaetigung  = version.php, apps/    # muss zusätzlich existieren; '/' = Verzeichnis

kopien_regex  = /updater-[a-z0-9]+/backups/|/[a-z0-9_-]*backups?/
legitim_regex = /lib/composer/composer/     # Falsch-Positiv-Ausnahmen INNERHALB einer gesunden Instanz

werkzeug            = occ
werkzeug_probe      = status --output=json
werkzeug_probe_form = json     # json | version | text

version_datei = version.php
version_regex = \$OC_Version *= *array *\( *[0-9,\ ]+
```

**Marker allein genügt nie.** `occ` liegt auch in Sicherungskopien und in
Dokumentation; erst zusammen mit `version.php` und `apps/` ist es eine
Installation. WordPress hatte bisher keine Bestätigung — `wp-config.php` ist
unscharf genug, dass es durchging, aber es brach das Muster.

**`werkzeug_probe_form` ist wichtiger, als es aussieht.** `occ` antwortet bei
unpassender PHP-Fassung mit einer HTML-Meldung auf STDOUT und Rückgabewert 0.
`json` verlangt deshalb gültiges JSON, nicht bloß irgendeine Ausgabe.

## `rezept.sh` — die Haken

Nur das, was der Rahmen nicht kann. Jeder Haken ist optional.

| Haken | Wofür |
|---|---|
| `rezept_kern` | Kern-Integrität (`occ integrity:check-core`, `wp core verify-checksums`) |
| `rezept_konfig` | Konfigurations- und Härtungsprüfungen |
| `rezept_db` | Datenbankprüfungen |
| `rezept_sonder` | alles Übrige, etwa kampagnenspezifische Merkmale |
| `rezept_verdikt` | **Pflicht in der Praxis** — ohne Verdikt fehlt die Aussage |

Aufgerufen wird je Installation mit:

| Variable | Inhalt |
|---|---|
| `$REZ_PFAD` | absoluter Pfad der Installation |
| `$REZ_KURZ` | Pfad relativ zu `$VHOSTS_DIR`, für Meldungen |
| `$OCC` | Funktion, die das Werkzeug als Eigentümer ausführt |

**Die Präfixe sind kein Zierrat.** Die erste Fassung nannte die Variable schlicht
`NC` — und `NC` ist im Werkzeug die Farb-Reset-Sequenz. Jede Ausgabe klebte am
Pfad und war unlesbar. Derselbe Fehler war zuvor schon einmal in den
Nextcloud-Abschnitten passiert.

## Befunde melden

Ausschließlich über `befund_melden`. Nicht über `crit`/`warn` direkt — sonst
fehlt der Pfad, und ohne Pfad greift der Datenschutz-Riegel nicht.

```bash
befund_melden <app> <kategorie> <schwere> "<text>" <pfad|-> [web]
verdikt_melden <app> <flags> "<text>"
```

**Kategorien** (fest): `erkennung version kern konfig datenbank schadcode logs
haertung verdikt`
**Schwere**: `crit` `warn` `ok` `unklar`

`web` markiert einen Befund für den Kundenbericht. Ob er dort ankommt,
entscheidet der Riegel anhand des **Pfades**: liegt er außerhalb des
Prüfumfangs, bleibt der Befund beim Betreiber und wird als zurückgehalten
ausgewiesen.

**`unklar` ist kein Verlegenheitswert.** Wenn eine Messung nicht durchgeführt
werden konnte, ist das weder ein Befund noch eine Entwarnung — und es blockiert
die grüne Ampel im Kundenbericht. Ein unberechtigtes `unklar` ist dabei genauso
schädlich wie ein falsches `ok`.

## Muster gegen echte Daten halten

Bevor ein Muster in `signaturen.tsv` oder in einen Haken kommt: gegen einen
echten Bestand prüfen, nicht gegen die Vorstellung davon.

Beim `.htaccess`-Abschnitt fielen so drei geplante „harte Angriffsmerkmale"
durch — gemessen an 412 echten Dateien:

| Geplant | Realität |
|---|---|
| `AddType` | 173 Vorkommen, **ausnahmslos legitim** (MIME-Typen für Schriften, Video) |
| `Order allow,deny` | 29 Dateien, normale Apache-2.2-Syntax |
| `auto_prepend_file` | kommt vor — **und ist Wordfence**, eine Schutzsoftware |

Ohne die Messung hätte das Werkzeug die Schutzsoftware als Hintertür gemeldet.

## Aufrufen

```bash
--nur-rezept <app>      # nur dieses Rezept
--nur-nextcloud         # Kurzform
--nur 12r               # alle Rezepte
```
