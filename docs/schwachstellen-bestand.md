# Der Schwachstellen-Datenbestand

Wie er entsteht, warum er im Repository liegt, was zu tun ist, wenn der
Zeitplan rot wird.

---

## Wozu er da ist

Abschnitt 12 gleicht die gefundenen WordPress-Fassungen — Kern, Plugins,
Themes, dazu Composer-Abhängigkeiten — gegen bekannte Schwachstellen ab. Ohne
Datenbestand meldete jeder Lauf bis August 2026:

```
Kein Datenbestand vorhanden — Abgleich übersprungen
```

Der Abgleich war gebaut, geprüft und lief gegen nichts. Das war der größte
einzelne Funktionsausfall des Werkzeugs.

## Was drin steht

| Datei | Inhalt |
|---|---|
| `rezepte/wordpress/daten/vuln/wp-core.tsv` | Kern-Schwachstellen |
| `rezepte/wordpress/daten/vuln/wp-plugins.tsv` | Plugin-Schwachstellen |
| `rezepte/wordpress/daten/vuln/wp-themes.tsv` | Theme-Schwachstellen |
| `rezepte/wordpress/daten/vuln/composer/` | GHSA/OSV für Packagist-Pakete |
| `rezepte/wordpress/daten/kev/kev-wordpress.tsv` | CISA-Katalog, aktiv ausgenutzt |

Je Zeile: `slug`, `von`, `von_inkl`, `bis`, `bis_inkl`, `behoben`, `cve`,
`cvss`, `kev`, `quelle`.

**Übernommen werden ausschließlich Tatsachen.** Der Feed bringt zusätzlich
`description`, `remediation`, `researchers`, eine CWE-Beschreibung und den
Titel mit — alles formulierte Texte, und die trägt dieses Repository nicht.
Derselbe Grundsatz wie beim Joomla-Bestand. Er ist hier zusätzlich praktisch:
weniger fremder Text heißt weniger Lizenzfläche. Aus 150 MB Feed werden so
7 MB Tabellen.

Größenordnung beim ersten Aufbau (2026-08-12): 38.456 Datensätze, davon 93 %
mit CVE-Nummer, 72 % vom Hersteller behoben — **28 % ohne verfügbaren Fix.**
Der Zuwachs beschleunigt sich: 4.892 neue Datensätze 2023, 8.317 in 2024,
10.831 in 2025.

## Warum er mit im Repository liegt

Drei Gründe, alle bindend:

1. **Die Auslieferung *ist* der Clone.** Das Werkzeug kommt per
   `git clone --depth 1` auf den Kundenserver (siehe README). Was hier nicht
   liegt, ist dort nicht da.
2. **Der Server kann nicht selbst holen.** Der Wordfence-Schlüssel darf
   ausdrücklich weder ins Repository noch auf einen Kundenserver. Es gibt
   keinen Weg, den Bestand zur Laufzeit nachzuladen.
3. **Belegzweck.** Ein Befund muss später einem *bestimmten* Datenstand
   zuzuordnen sein — dafür sind `VERSION` und `MANIFEST.sha256` da. Für einen
   Bericht an einen Kunden oder ans BSI ist das keine Nebensache.

Der flache Clone überträgt keinen Verlauf. Der Zuwachs je Aufbau belastet nur
die Arbeitskopie des Betreibers, nie den Kundenserver.

---

## Die 30-Tage-Marke

`WP_DATEN_MAX_TAGE` steht auf **30** (`lib/konfig.sh`). Ist der Bestand älter,
meldet das Rezept einen Befund und **bricht den Abgleich ab**
(`rezepte/wordpress/rezept.sh:160`):

```
Schwachstellen-Datenbestand ist N Tage alt — Ergebnis nicht belastbar,
Bestand erneuern
```

Das ist Absicht. Ein Abgleich gegen veraltete Daten liefert stille
Entwarnungen, und die sind schlimmer als gar kein Abgleich: der Bericht sieht
geprüft aus. Aus derselben Überlegung gilt eine Tabelle aus nur Kopfzeilen
nicht als Bestand — käme sie durch, wäre jedes Plugin `SAUBER`.

**Daraus folgt die Taktung.** Der Zeitplan läuft wöchentlich, nicht monatlich:
vier Puffer bis zur Marke. Fällt ein Lauf aus, bleibt Zeit für den nächsten.

---

## Der Zeitplan

`.github/workflows/schwachstellen-bestand.yml`, montags 04:17 UTC, dazu
`workflow_dispatch` für den Griff von Hand.

Ablauf:

1. Prüfen, ob das Secret hinterlegt ist
2. `werkzeuge/wordpress-daten-update.sh --wordfence`
3. Prüfen, dass alle drei Tabellen Datenzeilen führen
4. `werkzeuge/lizenz-pruefstand.sh`
5. `python3 lib/wp_schwachstellen.py --selbsttest`
6. Pull Request öffnen, mit den Abdeckungszahlen im Text

### Warum die Prüfstände im erzeugenden Lauf stehen

Ein Pull Request, den der `GITHUB_TOKEN` öffnet, löst per GitHub-Regel **keine
weiteren Workflows aus**. Stünden die Prüfungen nur in `pruefung.yml`, käme ein
vollständig ungeprüftes Datenpaket zum Zusammenführen — und es sähe geprüft
aus, weil ja ein PR mit Checks-Bereich da wäre. Deshalb laufen sie vorher.

### Warum ein PR und kein Direktpush

Ein 7-MB-Datenwechsel gehört gesehen. Vor allem gehören die Abdeckungszahlen
gesehen: **sackt die Zahl der verschiedenen Slugs gegenüber dem Vorlauf
deutlich ab, ist das ein Vorfall bei der Quelle und kein Update.** Zeilen
allein sagen wenig — 40.000 Einträge auf 300 Slugs decken etwas ganz anderes ab
als 40.000 auf 16.000.

### Warum kein Githook

Wurde erwogen und verworfen:

- `.git/hooks/` wird von git nicht versioniert und nicht geklont — der Hook
  fehlte auf jeder anderen Maschine
- Hooks hängen an Commit oder Push. Der Bestand veraltet mit der Zeit, nicht
  mit Commits. Ein 150-MB-Abruf je Commit liefe sofort in HTTP 429
- der Schlüssel läge auf einer Arbeitsplatte statt an einer Stelle mit
  Zugriffskontrolle

---

## Der Schlüssel

Kostenlos, aber Registrierung nötig. Die Datenbank selbst ist frei, auch für
kommerzielle Nutzung.

1. Konto auf `wordfence.com`
2. Dashboard → **Integrations** → Token erzeugen
3. Im Repository unter **Settings → Secrets and variables → Actions** als
   `WORDFENCE_API_KEY` hinterlegen

Von Hand auf der Entwicklungsmaschine:

```bash
export WORDFENCE_API_KEY='…'
bash werkzeuge/wordpress-daten-update.sh --wordfence
```

**Der Schlüssel gelangt weder ins Repository noch auf einen Kundenserver.**
Deshalb läuft der Zeitplan ausschließlich über `schedule` und
`workflow_dispatch` — beides im Zusammenhang des Hauptrepositories, Fork-PRs
sehen das Secret nie. `pull_request_target` darf in diesem Workflow **nie**
auftauchen: es liefe mit Secrets im Zusammenhang des Zielrepositories und
machte den Schlüssel für jeden Fork erreichbar.

---

## Lizenz: warum `LICENSE` erzeugt wird

Die Bedingungen gestatten die Weitergabe ausdrücklich, verlangen dafür aber je
Kopie drei Dinge. Alle drei entstehen maschinell:

| Auflage | erfüllt durch |
|---|---|
| Verweis auf den Datensatz | Spalte `quelle` jeder Zeile, aus dem Feld `references` |
| Copyright-Vermerk | `LICENSE`, aus dem Feld `copyrights` des Feeds |
| Lizenztext im Wortlaut | `LICENSE`, ebendaher |

Der Feed führt je Datensatz ein Feld `copyrights` mit Vermerk und Lizenztext
**im Wortlaut** — für Defiant durchgängig, für MITRE bei allen Sätzen mit
CVE-Bezug. `lizenz_schreiben()` leitet `LICENSE` daraus ab.

Das ersetzt eine Sperre durch eine Bauart. §5c der Bedingungen behält eine
einseitige Änderung vor; bisher hing es an Sorgfalt, dass der eingetragene Text
zu dem Bestand passt, mit dem er ausgeliefert wird. Jetzt stammen beide
zwangsläufig aus **demselben Abruf**.

Der ursprünglich geplante Weg — Text von der Bedingungsseite holen — wäre
ohnehin nicht gangbar: sie beantwortet Skriptzugriffe mit HTTP 202 und leerem
Rumpf.

### MITRE-Anzeigepflicht: entschieden

Die Frage stand als Voraussetzung vor der ersten Auslieferung. Sie ist aus dem
Wortlaut im Feed beantwortet: beide Lizenztexte binden die Weitergabe wortgleich
an *reproduce … in any such copy*. Keiner verlangt eine Nennung gegenüber dem
Endnutzer oder in der Trefferausgabe; MITRE verlangt nicht einmal den Hyperlink,
den Defiant fordert.

**Eine Beilage genügt.** `LICENSE` und `NOTICE` reisen mit dem Bestand und sind
die Kopie, in der die Vermerke stehen. Das Autorenfeld aus Issue #13 ist für
diese Quelle keine Voraussetzung. Für DRL-lizenzierte Regelwerke bleibt die
Lage unverändert.

---

## Wenn der Lauf rot wird

### Rückgabewert 2 — Abbruch am Lizenz-Gate

**Nicht wiederholen. Das ist kein Aussetzer.** Zwei mögliche Ursachen:

**a) Der Abzug führt zwei verschiedene Lizenzfassungen.** Genau der Zustand, in
dem eine Änderung der Bedingungen gerade anläuft — Wordfence stellt um, und im
selben Abzug stehen alte und neue Sätze nebeneinander. Ein Bestand mit zwei
Fassungen lässt sich nicht mit einer ausliefern.

Zu tun: den Abzug aufheben, beide Fassungen vergleichen, prüfen ob die neue
Fassung die Weitergabe noch deckt. Erst danach entscheiden.

**b) Das Feld `copyrights` fehlt.** Dann hat sich das Feedformat geändert. Der
Normalisierer ist gegen die dokumentierte Struktur gebaut; fällt ein Feld weg,
fallen wahrscheinlich mehr weg.

In beiden Fällen wird **kein Bestand geschrieben**. Der alte bleibt liegen und
altert weiter auf die 30-Tage-Marke zu — es besteht also Frist, aber keine
Eile von Minuten.

### HTTP 429

Zu häufig abgerufen. Der Feed kennt keinen Teilabruf, jeder Lauf holt den
vollen Bestand. Ein zweiter Abruf innerhalb weniger Minuten wird abgewiesen.

Beim Zeitplan praktisch ausgeschlossen. Tritt es bei Handläufen auf: den
150-MB-Abzug aufheben und mit `--aus-datei` weiterarbeiten statt neu zu holen.

### HTTP 401

Schlüssel abgelehnt — zurückgezogen, abgelaufen oder falsch hinterlegt. Unter
Integrations neu erzeugen und das Secret ersetzen.

### „keine Datenzeilen"

Der Aufbau lief durch, aber eine Tabelle ist leer. Das darf nicht ins
Repository: ohne Datenzeilen käme jedes Plugin als `SAUBER` zurück — eine
stille Entwarnung, und die sieht nach Prüfung aus. Der Lauf bricht ab, der alte
Bestand bleibt.

---

## Von Hand arbeiten

```bash
export WORDFENCE_API_KEY='…'
bash werkzeuge/wordpress-daten-update.sh --wordfence
```

Am Normalisierer arbeiten, ohne die Ratenbegrenzung zu reizen — Abzug einmal
holen, dann beliebig oft daraus aufbauen:

```bash
curl -H "Authorization: Bearer $WORDFENCE_API_KEY" \
     -o /tmp/wf-roh.json \
     https://www.wordfence.com/api/intelligence/v3/vulnerabilities/production
```

```bash
bash werkzeuge/wordpress-daten-update.sh --aus-datei /tmp/wf-roh.json
```

CISA-Katalog getrennt erneuern — gemeinfrei, kein Schlüssel, kein Gate:

```bash
bash werkzeuge/wordpress-daten-update.sh --kev
```

Prüfen, was entstanden ist:

```bash
bash werkzeuge/lizenz-pruefstand.sh
```

---

## Verwandtes

- `rezepte/wordpress/daten/QUELLEN.md` — Herkunft je Datei, Lizenz-Ampel aller
  geprüften Quellen, warum WPScan und wpvulnerability.net ausgeschieden sind
- `rezepte/wordpress/daten/NOTICE` — Lizenzlage je Datei
- `rezepte/wordpress/daten/LICENSE` — erzeugt, nicht von Hand pflegen
- `docs/erkennung.md` — was der Abgleich leistet und wo seine Grenzen liegen

---

*netztaucher | digital*
