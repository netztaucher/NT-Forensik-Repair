# Changelog

Alle nennenswerten Änderungen an `wp_plesk_forensik.sh`.

## [unveröffentlicht]

### Behoben — bei jeder vierten Schwachstelle stand die falsche Angabe im Bericht

Gefunden vom **ersten Lauf gegen eine echte Installation** (#9), in den ersten
drei Sekunden. Im Bericht stand:

```
core wordpress 7.0.3 ... ([* … *]) https://www.wordfence.com/... — behoben in CVE-2017-14990.
```

Soll wäre `([6.0 … 6.4.1]) CVE-2026-90004 — behoben in 6.4.2`. Die Quell-URL
stand an der Stelle der CVE-Nummer, die CVE-Nummer hinter „behoben in".

**Die Ursache:** Tab ist in bash ein IFS-Whitespace-Zeichen. Auch wenn `IFS`
nur auf Tab steht, gilt eine *Folge* von Tabs als **ein** Trenner — leere
Mittelfelder verschwinden, und alles dahinter rutscht nach links. Betroffen war
jeder Datensatz ohne behobene Fassung: **11.732 von 45.121, also 26 %.**

Umgestellt auf Unit Separator (0x1f), der kein Whitespace ist.

**Dieselbe Ursache im Joomla-Pfad**, und dort schlimmer: `vel.tsv` hat in
**allen 199 Zeilen** ein leeres Mittelfeld, `joomla-ext-kritisch.tsv` in 16 von
17. Drei Leseschleifen umgestellt (`12_joomla.sh`, Kern-CVE, kritische
Erweiterungen, VEL).

Die vier SQL-Leseschleifen bleiben unverändert — sie sind seit jeher durch
`IF(…,'-',…)` in der Abfrage abgesichert, mit einem Kommentar, der genau diese
Falle beschreibt. Das Wissen war da; es war nur nicht auf die Stellen
angewendet, die aus **Dateien** lesen.

### Behoben — der Prüfbaum hatte die Lücke nicht, die die echten Daten haben

Warum 46 Selbsttestfälle und ein deckungsgleiches Goldmuster nichts sahen:
**jede Fixture-Zeile führte in jedem Feld einen Wert.** Der Fall „betroffen,
aber ohne Fix" kam schlicht nicht vor — obwohl er in den echten Daten gut jeden
vierten Datensatz betrifft.

Neu: `pruefstand-ohne-fix`, eine Zeile mit **zwei leeren Mittelfeldern**
(`behoben` und `kev`). Vor dem Aufnehmen der Referenz gegen den zurückgedrehten
Fix geprüft — sie erzeugt dann exakt den Produktionsfehler.

Das ist die eigentliche Lehre aus diesem Fund: eine Fixture, die nur
vollständige Datensätze kennt, prüft die halbe Wirklichkeit.

## [unveröffentlicht]

### Behoben — die Werkzeug-Probe lief ohne Pfad und schaltete die halbe Prüfung ab

Der schwerste Fund des ersten Laufs gegen ein echtes System (#9).

`module/12r_rezepte.sh` prüft vor jeder wp-cli-Nutzung, ob das Werkzeug
antwortet. Diese Probe rief `wp core version` **ohne `--path`** auf. wp-cli
sucht dann ab dem Arbeitsverzeichnis — dem Laufordner — und antwortet:

```
Error: This does not seem to be a WordPress installation.
```

Die Probe **konnte** nicht gelingen. Ihr Fehlschlag führte zu `continue`, und
damit fielen auf **jeder echten WordPress-Installation** aus:

- `wp core verify-checksums` — die Kern-Integritätsprüfung
- `rezept_konfig` und `rezept_db`
- die Kern-Whitelist `.pruefsummen_kern.txt`, mit der Abschnitt 13c bestätigt
  unveränderte Dateien entlastet

Im Bericht stand dafür eine Zeile: „Werkzeug antwortet nicht verwertbar".

**Was das gekostet hat**, zeigt die Gegenprobe im Prüfbaum: ohne den Pfad
verschwinden bei der befallenen Installation der Befund „1 veränderte
Core-Datei(en) — Injektion oder Manipulation", die Core-fremden Dateien und
sämtliche Wordfence-Auswertungen. Ein manipulierter Kern wäre unentdeckt
geblieben.

Auf dem gemessenen System stand stattdessen ein 🔴 „Webshell/Dropper" auf
`wp-includes/class-wp-simplepie-sanitize-kses.php` — einer unveränderten
Core-Datei. `wp core verify-checksums` von Hand: *„WordPress installation
verifies against checksums."*

Neuer Rezept-Schlüssel `werkzeug_pfad_arg`, für WordPress `--path=%s`.
Nextcloud braucht ihn nicht: `occ` liegt in der Installation, deshalb fiel es
dort nie auf.

### Behoben — der Befund konnte seinen eigenen Grund nicht nennen

`rezept_werkzeug_bereit` verwarf stderr mit `2>/dev/null`. Die Formprüfung
liest stdout, und bei einem Fehler ist stdout leer — weggeworfen wurde also
ausgerechnet der Satz, der die Ursache benennt. Der Befund lautete
„nicht verwertbar", ohne Klammer, ohne Grund.

stderr wird jetzt getrennt aufgefangen und ergänzt den Befund, wenn stdout
nichts hergibt. Ein Aufruf, nicht zwei — die Probe läuft je Instanz, und auf
einem Host mit 68 davon zählt das.

### Behoben — die Attrappe hatte den Fehler ausdrücklich umgangen

Im Prüfbaum stand wörtlich:

```php
# Die Probe laeuft OHNE --path, deshalb hier ein fester Wert.
```

Der Defekt war beim Bau der Attrappe **bemerkt** — und umgangen statt behoben.
Echtes wp-cli kann ohne Pfad nicht antworten; die Attrappe konnte es.

Sie verhält sich jetzt wie das Original: ohne `--path` ein Fehler auf stderr
und Rückgabewert 1. Fällt der Pfad wieder weg, schlägt der Prüfbaum aus.

Das ist der vierte Fund dieser Art an einem Tag — nach #38, #39 und #40. Die
drei anderen waren Lücken in den Fixtures. Dieser hier war keine Lücke,
sondern eine Anpassung an den Defekt.

## [unveröffentlicht]

### Geändert — der Prüfbaum kennt jetzt die Formen des echten Systems

An einem Tag fanden zwei Läufe gegen **eine** echte Installation fünf Fehler,
die 46 Selbsttestfälle, ein deckungsgleiches Goldmuster und vier Prüfstände
nicht sehen konnten. Vier hatten dieselbe Ursache: der Prüfbaum kannte eine
Form nicht, die es in der Wirklichkeit gibt.

Statt weiter einzeln nachzurüsten, wenn wieder etwas auffällt, sind die Formen
des gemessenen Systems jetzt erhoben und gegen den Prüfbaum gehalten. Die
Liste steht im Baumbauer selbst, damit sie beim nächsten Fund fortgeschrieben
wird statt neu erhoben.

**Neu im Baum**, beide direkt vom echten System abgenommen:

- `pruefstand-daten` — Verzeichnis unter `plugins/` **ohne jede PHP-Datei**,
  nur eine `version.json`. Vorbild: `chronosly-addons`.
- `pruefstand-vorlagen` — PHP **nur in Unterordnern**, kein Kopf, und der
  Inhalt ist reines JSON auf einer Riesenzeile. Vorbild:
  `chronosly-templates/dad7/default.php`.

Der Prüfbaum kannte bisher nur `pruefstand-kopflos`: PHP **oben**, ohne Kopf.
Die beiden echten Formen fehlten — und deshalb blieb unbemerkt, dass
`_wp_bestand` jedes Verzeichnis unter `plugins/` als Plugin zählt. Der
Referenzlauf zeigt es jetzt: „3 Bestandteil(e) ohne lesbare Fassung" wird zu
**5**, „2 Plugin(s) ohne Prüfsummensatz" zu **4**.

**Die Referenz hält damit vorerst das falsche Verhalten fest.** Das ist
Absicht und im Baumbauer vermerkt: sobald #39 behoben ist, zeigt der
Referenzvergleich genau, was sich ändert. Ohne die Fixture wäre die Reparatur
unbelegbar.

Nebenbei liefert `pruefstand-vorlagen` §7.15 das Rauschmaterial, das ihm
fehlte — lange Zeile, hohe Dichte, kein Schadcode.

### Dokumentiert — was der Prüfbaum grundsätzlich nicht leisten kann

Ein Rauschmaß. Auf dem echten System listete §7.15 **235 Dateien** über der
Schwelle, 222 davon mit genau 3 Punkten — also exakt auf
`INJEKTION_PUNKTE_MIN`. Im Prüfbaum sind es eine Handvoll.

Er kann prüfen, **dass** der Detektor trennt. Wo die Schwelle liegen muss,
kann nur eine Messung an einem echten Server sagen. Das gehört so
festgehalten, damit niemand die Schwellen aus dem Prüfbaum ableitet.

Drei Formen bleiben bewusst offen, jeweils mit Issue: fehlende
Prüfsummendatei und veränderte Nicht-Codedatei (#40), unveränderte Core-Datei
mit Mustertreffer (#42). Sie gehören mit der jeweiligen Reparatur dazu — eine
Fixture für #42 würde sonst den Fehlalarm als Sollwert einfrieren.

## [unveröffentlicht]

### Behoben — die Webshell-Mustersuche lief auf macOS nie und meldete Entwarnung

Der schwerste Einzelfund. `PATTERN_REGEX` ist ein PCRE; BSD-grep (macOS)
kennt `-P` nicht und bricht mit „invalid option -- P" ab. Das
`2>/dev/null || true` fing es weg: die Trefferliste blieb leer, und Abschnitt
7.3 meldete **„Keine kleinen Obfuskations-Dropper gefunden"** — eine
Entwarnung aus einer Suche, die nie gelaufen ist.

Auf den Kundenservern (Linux, GNU grep) lief sie. Aber die
**Goldmuster-Referenz entsteht auf einem macOS-Arbeitsplatz** — sie schrieb
„keine Funde" fest, und §7.3 war damit lokal vollständig ungeprüft. Genau
deshalb fiel auch nicht auf, dass der Prüfbaum den kritischen Pfad gar nicht
erreichte.

Jetzt eine Probe davor. Fehlt PCRE, gibt es einen ⚪-Befund mit dem Satz
„Das ist KEINE Entwarnung" — und Abschnitt 13d schweigt, statt daneben
„keine Dropper gefunden" zu schreiben.

Derselbe Fehler wie bei der Werkzeug-Probe in 12r: ein Ausfall, der aussieht
wie ein Ergebnis.

### Behoben — §7.3 urteilte, bevor die Prüfsummen-Entlastung existierte (#42)

Am 12.08.2026 meldete das Werkzeug auf einem **gesunden** Kundensystem
`wp-includes/class-wp-simplepie-sanitize-kses.php` als Webshell. Zeile 42 ist
ein SimplePie-`preg_match` mit der HTML-Whitespace-Zeichenklasse aus der
WHATWG-Spezifikation. Zwei Zeilen darüber stand im selben Bericht
„WordPress-Core unverändert (verify-checksums)".

Ein 🔴 löst die volle Sofortmaßnahmen-Liste aus — alle Passwörter rotieren,
SSH-Root abschalten.

**Ursache:** die Listen der gegen amtliche Prüfsummen bestätigten Dateien
entstehen in 12r. §7.3 läuft in Modul 07, davor.

**Neu: Abschnitt 13d.** Der teure Baumdurchlauf bleibt in 7.3, das Urteil
wandert dorthin, wo die Entlastung vorliegt — dieselbe Überlegung, die
seinerzeit 7.12 zu 13c gemacht hat, für 7.3 aber nie gezogen worden war.

Betroffen sind alle drei Stufen: kritische Dropper, Sichtungsstufe und
gefährliche Funktionen in kleinen Dateien.

**Kein stilles Wegfiltern.** Was entlastet wird, steht in der Meldung
(„2 Datei(en) … (1 gegen amtliche Prüfsummen entlastet)") und in einem
eigenen Beleg. Ein Befund, der lautlos verschwindet, ist die nächste stille
Entwarnung.

Die Entscheidung selbst steht jetzt in `lib/pruefsummen_filter.py` mit
eigenem Selbsttest (9 Fälle) und wird von 13c **und** 13d genutzt. Zwei
Kopien wären die nächste Gelegenheit zum Auseinanderlaufen — genau daran
entstand dieser Fehlalarm.

### Hinzugefügt — das Abnahmekriterium im Prüfbaum

Zwei kleine Dateien mit acht Hex-Escapes, der Machart der echten Kern-Datei
nachgebaut:

- unter dem **geprüften** Kern von Kunde 3 → **muss entlastet werden**
- ausserhalb jedes Kerns bei Kunde 2 → **muss 🔴 bleiben**

Auf Linux verifiziert, weil §7.3 auf macOS nicht läuft:

```
🔴 KRITISCH: Webshells/Dropper gefunden: 2 Datei(en) < 3000 B mit Obfuskation
             (1 gegen amtliche Prüfsummen entlastet)
```

Fällt die erste nicht weg, greift die Entlastung nicht. Fällt die zweite weg,
entlastet der Filter zu viel — und das wäre die stille Entwarnung, gegen die
der ganze Abschnitt gebaut ist.

## [unveröffentlicht]

### Behoben — 13d zählte doppelt, wenn ALLE Treffer entlastet wurden

Fehler in der Reparatur von #42, gefunden beim Bestätigungslauf auf dem echten
System. Der Bericht meldete:

```
🔴 KRITISCH: 1 Datei(en) < 3000 B mit Obfuskation (1 gegen amtliche Prüfsummen entlastet)
```

Bei **einem** Treffer. Dieselbe Datei stand zugleich im Beleg „kritisch" und im
Beleg „entlastet".

**Ursache:** der erste Entwurf schrieb beide Blöcke hintereinander in einen
Datenstrom, getrennt durch eine Zeile mit `0x1e`, und schnitt sie mit
`sed -n '1,/^\x1e$/p'` wieder auseinander. Ein sed-Bereich `1,/re/` prüft sein
Endmuster aber erst **ab Zeile 2**. Lag der Trenner auf Zeile 1 — also genau
dann, wenn die Restliste leer ist — endete der Bereich nie, und beide Hälften
enthielten alles.

Jetzt schreibt das Python zwei Dateien. Kein Trenner im Datenstrom, keine
Bereichsangabe, keine Escaping-Frage.

**Warum der Prüfbaum es nicht sah:** bei Kunde 2 und 3 blieb immer etwas übrig.
Die Lage „alles entlastet, Restliste leer" kam nicht vor. Neu ist deshalb
Kunde 1 mit genau einem Mustertreffer, der entlastet wird.

Damit sind es drei Lagen statt zwei: nichts entlastet, teilweise entlastet,
alles entlastet. Der halbvolle Fall allein übersieht den leeren.

## [unveröffentlicht]

### Behoben — §7.13 war an Videoformaten blind: 17 von 32 Nutzlasten gefunden

Gemessen an einem **echten Befall** auf einem Server mit 475 vhosts
(12.08.2026, parallele Vorfallsuntersuchung). Dort lagen 32 als Mediendateien
getarnte Hintertüren. Dieser Abschnitt fand **17**.

Die fehlenden 15: `.avi` (7), `.mov` (5), `.wmv` (4), `.mpg`, `.mpeg`. Die
Endungsliste kannte von den Bewegtbildformaten **nur `.mp4`**. Wer seine Shell
`video.avi` nennt, war unsichtbar.

Aufgenommen sind jetzt zusätzlich `.avi .mov .wmv .mpg .mpeg .m4v .mkv .webm
.flv .ogg .oga .ogv .aac .flac .m4a .wma`.

**Bewusst nicht aufgenommen: `.js` und `.css`.** Dieselbe Messung fand dort 39
bzw. 30 Dateien mit `<?php` — durchweg legitime, von PHP erzeugte Templates.
Sie aufzunehmen hätte 69 Fehlalarme erzeugt und den Abschnitt entwertet.

Der Prüfbaum kannte die Lücke ebenfalls nicht — er hatte nur `.png`. Neu sind
eine `.avi` und eine `.mov`, beide ohne Verdachtsmerkmal im Code: geprüft wird
der Behälter, nicht was das PHP tut. Die Referenz geht damit von 2 auf 4
erkannte Mediendateien.

### Behoben — FastCGI galt als verdächtiger Prozess

§8.2e meldete „Web-User haben eigene (Nicht-PHP-FPM-)Prozesse — prüfen". Der
Filter kannte nur `php-fpm`. Auf einem Server mit 475 vhosts laufen aber
regelmäßig Seiten im FastCGI-Modus, und deren Prozesse heißen `php-cgi`:

```
web72   /opt/plesk/php/8.3/bin/php-cgi -c .../nightworks-berlin.de/etc/php.ini
```

Bei der Messung war **jeder einzelne Treffer** dieses Abschnitts ein solcher
`php-cgi`. Ein Befund, der auf einer verbreiteten Betriebsart immer anschlägt,
wird beim nächsten Mal überlesen — und dann fällt auch der echte nicht mehr
auf.

## [unveröffentlicht]

### Behoben — zwei Hinweise erzeugten auf JEDER WordPress-Installation eine Warnung

Gemessen am Lauf über 475 vhosts. Auf jeder einzelnen Installation standen:

```
⚠ core wordpress 6.9.6 ist von einer bekannten Schwachstelle betroffen ([* … *]) CVE-2017-14990.
⚠ core wordpress 6.9.6 ist von einer bekannten Schwachstelle betroffen ([* … *]) CVE-2022-3590.
```

Bereich `*` bis `*`, keine behobene Fassung — **eine Warnung ohne jede
Abhilfe, dauerhaft, auf allen Seiten.** Rund tausend Zeilen, die niemand
abarbeiten kann.

Der Feed markiert beide selbst als `informational: true`: *„WordPress Core –
All Known Versions"*. Wordfence stuft sie also gar nicht als Schwachstelle
ein — der Normalisierer übernahm sie trotzdem.

Dieselbe Fehlerart wie beim FastCGI-Fehlalarm: was immer anschlägt, wird
überlesen — und dann fällt der echte Befund auch nicht mehr auf.

`informational`-Datensätze werden jetzt beim Aufbau übergangen. **Kein stilles
Wegfiltern:** die Zahl steht im Aufbauprotokoll (`Nicht uebernommen:
informational=121`).

Die 308 Plugin- und 148 Theme-Einträge ohne behobene Fassung bleiben
unberührt — das sind echte Lücken in aufgegebenen Erweiterungen, und sie
melden nur, wenn die Erweiterung installiert ist.

### Hinzugefügt — Angreifer-Konten sind jetzt handlungsfähig an die Bereinigung übergeben

`actionable.rogue_wp_admins` trug bisher nur Benutzername, E-Mail und Datum.
Die Kopfzeile mit der Installation wird beim Bauen der Liste herausgefiltert —
**welche Installation gemeint war, stand nicht drin.** Auf einem Server mit 475
vhosts ist ein Benutzername ohne Pfad nicht handlungsfähig, sondern gefährlich:
derselbe Name existiert dort vielfach.

Genau daran scheiterte die Bereinigung. Die Aktionsart `rogue_admin_removed`
ist im Berichtsgenerator und in der Statusmail vorgesehen, wurde aber **nie
erzeugt** — ihr fehlten die Daten.

Neu, additiv neben den bestehenden Listen:

```json
"rogue_wp_admins_detail":   [{"pfad":"…","benutzer":"…","email":"…","angelegt":"…"}],
"suspect_wp_admins_detail": [{"pfad":"…","benutzer":"…","email":"…","angelegt":""}]
```

Belegt und Verdacht bleiben getrennt — die Trennung stammt aus dem Rezept und
ist dort begründet: *„das ist ein Verdacht, kein Beleg — eine automatische
Bereinigung darf diese Konten nie anfassen."* Der Verdacht bekommt die
strukturierte Fassung trotzdem, damit er im Bericht **namentlich und der
richtigen Installation zugeordnet** auftaucht.

### Behoben — die WordPress-Datenbankprüfung fiel auf macOS spurlos aus

Beim Bauen des Prüfbaums für die Konten aufgefallen. `rezept_db` stieg bei
fehlgeschlagenem Zugang mit einem nackten `|| return 0` aus: **kein Befund,
keine Zeile, nichts.** Eine Installation ohne Datenbankprüfung sah im Bericht
aus wie eine mit unauffälligem Ergebnis.

Der Grund ist derselbe wie bei §7.3 und der Werkzeug-Probe: `rezept_konf_wert`
liest die Werte aus `wp-config.php` mit `grep -oP`, und BSD-grep kennt kein
`-P`. Auf einem macOS-Arbeitsplatz lieferte der Griff nach `DB_NAME` deshalb
immer leer — **die Datenbankprüfung lief dort nie.** Auch nicht im Prüfbaum,
dessen Referenz von genau dort stammt.

Jetzt ein Befund mit dem Grund im Klartext und dem Satz „Das ist KEINE
Entwarnung."

### Geändert — die wp-cli-Attrappe beantwortet Datenbankabfragen

Sie fiel bei allem außer `core version` und `core verify-checksums` still auf
`exit(0)` ohne Ausgabe. Der Prüfbaum fand damit **nie** einen Angreifer-Admin,
und der ganze Weg von der Erkennung über `findings.json` bis zur Bereinigung
war ungeprüft.

Kunde 2 liefert jetzt zwei belegte Konten (`wp_backup`, `svc_updater`) und
einen Verdachtsfall (`wpadmin`); Kunde 3 bleibt als Gegenprobe leer.

Auf Linux verifiziert — auf macOS ist die Datenbankprüfung mangels PCRE nicht
ausführbar.

## [unveröffentlicht]

### Hinzugefügt — vergiftete robots.txt findet den Doorway-Generator in der Datenbank (#47)

Der Generator der SEO-Spam-Kampagne sitzt in der **Datenbank**, nicht auf der
Platte. Ein reiner Dateiscan meldet die Kampagne als sauber — und genau das tat
dieses Werkzeug beim Befall vom 12.08.2026 auf 23 Seiten.

Was der Angreifer aber anfassen **muss**, ist die `robots.txt`; Google findet
die Doorway-Seiten sonst nicht. Dort stand:

```
Sitemap: https://…/index.php/sitemap.xml
```

**Was hier ausdrücklich KEIN Befund ist:** WordPress liefert seit 5.5 selbst
eine virtuelle Sitemap unter `/wp-sitemap.xml`, Yoast unter
`/sitemap_index.xml`. „Sitemap ohne Datei" ist der **Normalfall**. Wer darauf
anschlägt, meldet jede gepflegte Seite.

Das Merkmal ist der Pfad **durch `index.php`**: die PATHINFO-Form benutzt kein
verbreitetes Plugin. Sie ist der Weg, eine beliebige Adresse von PHP
beantworten zu lassen, ohne Rewrite-Regeln — und damit ohne Spur im
Dateisystem.

Die mtime der Datei wird als **Zeitanker** mitgeführt. Sie überlebt, weil
niemand `robots.txt` ansieht: im Vorfall war sie zwei Wochen älter als das
älteste Zugriffsprotokoll und datierte den Einbruch 19 Tage zurück.

Prüfbaum, beide Richtungen: Kunde 2 trägt die Kampagnen-Fassung (🔴 mit Beleg),
Kunde 3 eine völlig normale mit der WordPress-Sitemap (kein Befund, nur der
Zeitanker). Die Gegenprobe ist hier der eigentliche Test — eine Regel, die auf
`/wp-sitemap.xml` anspricht, wäre wertlos.

## [3.14.0] — 2026-08-12

Eine Fassung mit einem Thema: **der Schwachstellenabgleich läuft nicht mehr
gegen nichts.**

Er war seit Fassung 3.9 gebaut, geprüft und mit Selbsttests hinterlegt. Nur
meldete jeder Lauf „Kein Datenbestand vorhanden — Abgleich übersprungen". Das
war der größte einzelne Funktionsausfall des Werkzeugs, und er sah nicht wie
einer aus: die Zeile stand unauffällig zwischen den anderen.

Jetzt liegen 45.121 Zeilen auf 18.062 verschiedene Slugs im Repository, und ein
Zeitplan hält sie unter der 30-Tage-Marke, ab der das Werkzeug den eigenen
Abgleich als nicht belastbar meldet.

Nebenher hat sich eine seit Wochen offene Rechtsfrage aufgelöst — nicht durch
Auslegung, sondern weil der Lizenztext im Feed selbst mitkommt und dort
wörtlich steht, was verlangt wird.

### Hinzugefügt — der Schwachstellenabgleich hat einen Datenbestand (#7, #8)

Bis heute meldete jeder Lauf „Kein Datenbestand vorhanden — Abgleich
übersprungen". Das war der größte einzelne Funktionsausfall des Werkzeugs: der
Abgleich war gebaut, geprüft und lief gegen nichts.

Jetzt liegen **45.121 Zeilen auf 18.062 verschiedene Slugs** in
`rezepte/wordpress/daten/vuln/`. Der erste echte Abruf war zugleich der erste
Formattest — von 38.456 Datensätzen wurde **kein einziger verworfen**.

### Behoben — das Manifest bestätigte seine eigene Lieferung nicht

`MANIFEST.sha256` führte einen veralteten Hash für `NOTICE`: die Datei war
**nach** dem Erzeugen des Manifests noch bearbeitet worden. `shasum -c` schlug
damit auf `main` fehl.

Das Manifest ist der Beleg dafür, gegen welchen Datenstand ein Befund
entstanden ist — für einen Bericht an einen Kunden oder ans BSI ist das keine
Nebensache. Eines, das seine eigene Lieferung nicht bestätigt, belegt nichts,
und es fällt niemandem auf, solange es niemand nachrechnet.

Gefunden hat es der neue Zeitplan bei seinem ersten echten Lauf, an der
einzigen Stelle, an der jemand nachrechnete. Der Lizenz-Prüfstand rechnet es
jetzt bei jedem Lauf nach — genannt zu sein genügt nicht.

### Hinzugefügt — der Bestand erneuert sich selbst, wöchentlich

`.github/workflows/schwachstellen-bestand.yml`, montags, dazu von Hand über
`workflow_dispatch`.

Die Taktung ist keine Geschmacksfrage. `WP_DATEN_MAX_TAGE` steht auf **30** —
danach meldet das Rezept den eigenen Abgleich als „nicht belastbar" und bricht
ihn ab (`rezept.sh:160`). Wöchentlich hält vier Puffer bis zur Marke; fällt ein
Lauf aus, bleibt Zeit für den nächsten.

Ein Githook wäre das falsche Werkzeug gewesen: `.git/hooks/` wird nicht
versioniert und nicht geklont, hängt am falschen Auslöser — der Bestand
veraltet mit der Zeit, nicht mit Commits — und der Schlüssel läge auf einer
Arbeitsplatte statt an einer Stelle mit Zugriffskontrolle.

Der Lauf öffnet einen **PR**, keinen Direktpush. Die Abdeckungszahlen stehen im
PR-Text: sackt die Zahl der verschiedenen Slugs gegenüber dem Vorlauf ab, ist
das ein Vorfall bei der Quelle und kein Update.

Die Prüfstände laufen **im erzeugenden Lauf**, nicht erst im PR. Ein PR aus dem
`GITHUB_TOKEN` löst per GitHub-Regel keine weiteren Workflows aus — sonst käme
ein ungeprüftes Datenpaket zum Zusammenführen, und es sähe geprüft aus.

Kein Fremd-Action: der Lauf trägt einen Schlüssel und hat `contents: write`,
jede weitere Action wäre eine zusätzliche Stelle, der beides anvertraut werden
müsste. Der PR entsteht mit `gh`. Ausgelöst wird nur über `schedule` und
`workflow_dispatch`, damit Fork-PRs das Secret nie sehen.

Dazu `docs/schwachstellen-bestand.md` — was im Bestand steht, warum er
mitgeliefert wird, und was Rückgabewert 2 bedeutet (nicht wiederholen: es ist
der §5c-Fall).

### Geändert — LICENSE wird aus dem Feed abgeleitet statt von Hand gepflegt

Der Feed führt je Datensatz ein Feld `copyrights` mit Copyright-Vermerk und
Lizenztext **im Wortlaut**, für Defiant durchgängig und für MITRE bei allen
Sätzen mit CVE-Bezug. `lizenz_schreiben()` leitet `LICENSE` daraus ab.

Das ersetzt eine Sperre durch eine Bauart. §5c der Bedingungen behält eine
einseitige Änderung vor; bisher hing es an Sorgfalt, dass der eingetragene Text
zu dem Bestand passt, mit dem er ausgeliefert wird. Jetzt stammen beide
zwangsläufig aus **demselben Abruf**. Der geplante Weg — Text von der Webseite
holen — wäre ohnehin nicht gangbar gewesen: sie beantwortet Skriptzugriffe mit
HTTP 202 und leerem Rumpf.

Weichen die Sätze eines Abzugs im Lizenztext voneinander ab, bricht der Aufbau
ab und schreibt nichts. Das ist genau der Zustand, in dem eine Änderung der
Bedingungen anläuft — er darf nicht mit der erstbesten Fassung geglättet
werden.

`LICENSE` und `NOTICE` stehen jetzt mit im `MANIFEST.sha256`. Ein Manifest, das
die Daten sichert und den Lizenztext ausspart, sichert die Lieferung nur halb.

### Entschieden — die MITRE-Anzeigepflicht verlangt keine Nennung in der Ausgabe

Die Frage war seit der Recherche offen und stand als Voraussetzung vor der
ersten Auslieferung. Sie ist aus dem Wortlaut im Feed beantwortet: beide
Lizenztexte binden die Weitergabe an *reproduce … in any such copy*, keiner
verlangt eine Nennung gegenüber dem Endnutzer. **Eine Beilage genügt** —
`LICENSE` und `NOTICE` reisen mit dem Bestand.

Damit ist das Autorenfeld aus #13 für diese Quelle keine Voraussetzung. Für
DRL-lizenzierte Regelwerke bleibt die Lage unverändert.

### Geändert — der Lizenz-Prüfstand prüft die neuen Sollwerte

Er prüfte bis hierher eine Welt, die es nicht mehr gibt: „Gate zu, keine
Daten". Umgedreht statt abgeschwächt — der eingecheckte Bestand **muss** jetzt
vorliegen und Datenzeilen führen, `LICENSE` **muss** öffnen und beide
Rechteinhaber führen. Dazu vier neue Gegenproben um `lizenz_schreiben()`:
Lizenztext wörtlich übernommen, zwei Fassungen brechen ab, fehlendes
`copyrights` bricht ab, und nach einem Abbruch liegt **kein** Bestand.

Dafür hat `wordpress-daten-update.sh` die Naht `NT_DATEN_DIR` bekommen — ohne
sie ließe sich „schreibt bei fehlender Lizenz nichts" nur prüfen, indem man das
echte Verzeichnis beschreibt.

### Geändert — der Bereinigungsteil springt von 0.5.3 auf 0.7.0

`paket/repair-0.7.0.enc` ersetzt `repair-0.5.3.enc`; `PAKET_VERSION` und
`PAKET_SHA256` im Lader zeigen darauf. Die alte Fassung bleibt im Verzeichnis
liegen — ein Rückfall ist damit ein Zweizeiler und kein Wiederherstellen aus
der Historie.

Was der neue Stand mitbringt (NT-Repair 0.6.0 und 0.7.0):

- Die Berichte behaupten keine Wirksamkeit mehr ohne Kontrolllauf. Bis 0.5.3
  setzten sie die Fundzahl der **Untersuchung** als „verbleibende
  Schadcode-Dateien" ein und schrieben „technisch verifiziert" darüber — in
  einer Meldung an eine Datenschutz-Aufsichtsbehörde.
- Die Fundzahl kommt aus `metrics.schadcode_gesamt` statt aus
  `metrics.webshell_count`, das nur Dropper-Signaturen kennt.
- `actionable.signatur_treffer` und `actionable.plugin_veraendert` werden
  gelesen.
- Die Quarantäne hält `dev`, `inode` und alle drei Zeitstempel **vor** dem
  Verschieben fest und gleicht sie gegen `belege/00_dateien.tsv` ab.
- Auswahl je Datei statt alles-oder-nichts.
- `--apply` verlangt eine Haltung zum Kontrolllauf.

**ACHTUNG, Reihenfolge:** der Lader fragt den Lizenzserver nach genau dieser
Fassung. Ist der Schlüssel zu 0.7.0 dort noch nicht eingetragen, scheitert
**jeder** Kundenlauf mit „Lizenzserver kennt Fassung 0.7.0 nicht". Diese
Änderung darf erst zusammenlaufen, wenn der Schlüssel steht.

### Behoben — leere Schwachstellen-Tabellen galten als Datenbestand

Nach einem Testlauf lagen drei `vuln/*.tsv` mit **nur Kopfzeilen** im
Repository. Sie sahen aus wie ein Bestand, enthielten aber nichts — und
`rezept_version` prüfte auf die Existenz der **Dateien**, nicht auf
Datenzeilen. Der Abgleich wäre also gegen nichts gelaufen und hätte jedes
Plugin als `SAUBER` gemeldet: „keine bekannte Schwachstelle im vorliegenden
Bestand".

Das ist der gefährlichste Zustand von allen, weil er nach Prüfung aussieht.
Ohne die Dateien sagt das Werkzeug ehrlich „Kein Datenbestand vorhanden —
Abgleich übersprungen".

Geprüft wird jetzt auf Datenzeilen. Die drei leeren Tabellen sind entfernt;
der Prüfstand hält beide Richtungen fest und prüft zusätzlich, dass gar keine
`vuln/*.tsv` im Repository liegen, solange das Lizenz-Gate zu ist — eine leere
Tabelle dort wäre ein Widerspruch in sich.

### Behoben — `grep -c … || echo 0` schrieb doppelte Nullen nach VERSION

Derselbe Fehler, den dieses Repository an drei anderen Stellen ausdrücklich
dokumentiert: `grep -c` gibt bei null Treffern bereits eine `0` aus **und**
endet ungleich 0, der Rückfall hängt eine zweite an. In `VERSION` stand
daraufhin `0\n0 Zeile(n)`.

### Neu — das Lizenz-Gate ist eine Sperre, kein Häkchen (#8)

Sobald ein Wordfence-Bestand im öffentlichen Repository liegt, ist er
**ausgeliefert** — und die Auflagen gelten ab diesem Augenblick, nicht ab dem
nächsten Release. Die Weitergabe ist nur gedeckt, wenn Copyright-Vermerk und
Lizenztext je Kopie beiliegen; der Verweis je Zeile in der Spalte `quelle`
genügt der Auflage nicht.

Als Punkt auf einer Merkliste hielte das genau bis zu dem Tag, an dem es eilig
ist. `werkzeuge/wordpress-daten-update.sh` bricht deshalb mit Rückgabewert 2
ab, solange `rezepte/wordpress/daten/LICENSE` ein Gerüst ist — bei
`--wordfence`, `--alles` **und** `--aus-datei`. Ein gespeicherter Feed ist
derselbe Bestand.

`--kev` hängt bewusst **nicht** am Gate: der CISA-Katalog ist ein Werk einer
US-Behörde, gemeinfrei, ohne Auflagen. Ein Gate davor würde den einzigen heute
pflegbaren Teil blockieren. Auch das ist geprüft.

`LICENSE` liegt als Gerüst bei und sagt selbst, was wohin gehört — samt der
Begründung, warum der Lizenztext **zum Zeitpunkt des Bezugs** geholt und nicht
aus einer älteren Fassung übernommen wird: §5c behält eine einseitige Änderung
der Bedingungen vor.

### Neu — Abdeckung wird bei jedem Bestandsaufbau gezählt

„Wie viele Datensätze, wie viele verschiedene Slugs?" stand als einmalige
Aufgabe im Issue. Zeilen allein sagen wenig — 40.000 Einträge auf 300 Slugs
decken etwas anderes ab als 40.000 auf 12.000. Die Zahl wird jetzt bei jedem
Lauf neu erhoben und steht in `VERSION`.

### Offen — die MITRE-Anzeigepflicht

Nicht entschieden, und das bleibt so, bis jemand es entscheidet. Die Frage ist
in `LICENSE` und `NOTICE` mit ihrer **Konsequenz** hinterlegt:

| Auslegung | Folge |
|---|---|
| Beilage genügt | `LICENSE` und `NOTICE` reichen |
| Nennung in der Trefferausgabe | es braucht das Autorenfeld aus #13 — dann ist das kein Nebenschauplatz mehr, sondern Voraussetzung |

### Neu — Abschnitt 7.15: Injektion in grosse Dateien, ohne Referenz

Der blinde Fleck der Zweistufigkeit aus 7.3, ausdrücklich benannt. Sie trennt
nach **Grösse**: klein plus Muster ist kritisch, gross plus Muster geht in die
Sichtung. Das trägt für Dropper — ein Dropper ist fast nur Obfuskation und
deshalb winzig.

Blind ist die Regel für den umgekehrten Fall: eine **Injektion in eine grosse,
legitime Datei**. Eine kommerzielle Plugin-Datei hat 50–400 kB. Wird dort Code
eingeschleust, landet sie bestenfalls in der Sichtung, zusammen mit jeder
Krypto-Bibliothek des Servers. Ohne Mustertreffer sagt das Werkzeug gar
nichts — und prüfen lässt es sich nicht, weil für kommerzielle Plugins niemand
Prüfsummen veröffentlicht.

`lib/injektion_pruefen.py` misst deshalb nicht die Datei, sondern die
**Verteilung darin**. Ein 300-Byte-Fremdkörper in 400 kB verschwindet in jedem
Durchschnitt über die ganze Datei, aber nicht in diesen vier Massen:

| Merkmal | |
|---|---|
| `ANHANG` | Code hinter dem letzten schliessenden Tag |
| `LANGZEILE` | eine Nutzlast ist meist *eine* enorme Zeile |
| `DICHTE` | kodierte Zeichen im dichtesten 512-Byte-Fenster, nicht im Mittel |
| `RANDLAGE` | der Fund liegt am äussersten Rand der Datei |

**Bewusst `info` und kein Befund.** Die Schwellen stammen aus den Fällen des
Selbsttests, nicht aus einer Messung an einem echten Server — die hängt an der
Abnahme (#9). Erst messen, dann einstufen; dasselbe Vorgehen wie bei #11. Ein
Filter mit geratenen Schwellen als Warnung auszuliefern wäre die nächste
Geräuschquelle, und genau so ist der fremde Regelsatz mit 359 Treffern
unbrauchbar geworden.

Beim Bauen verworfen: ein Merkmal für „mehr als ein `<?php`". Gemessen an einer
Template-Datei mit **401 Öffnern** — Themes und View-Dateien wechseln ständig
zwischen PHP und HTML, das ist ihre Bauform. Das Merkmal hätte auf jeder von
ihnen Druck erzeugt und trug nichts, was `DICHTE` und `RANDLAGE` nicht schon
tragen.

Der Selbsttest prüft **beide Richtungen**: drei Fälle müssen melden, drei
müssen schweigen (unauffällige grosse Datei, legitimes `eval` mitten in einer
Klasse, Template mit 401 Öffnern). Ein Mass, das nur „findet den Schadcode"
prüft, wäre durch „meldet immer" zu bestehen. Der Prüfbaum trägt je Plugin
eine injizierte und eine saubere Datei **gleicher Grösse und gleicher
Machart** — die saubere ist der eigentliche Test.

### Dokumentiert — die Lücke bei kommerziellen Plugins

`docs/erkennung.md` §8 nennt sie jetzt ausdrücklich, mit dem Rechercheergebnis,
warum es keine Fremdquelle gibt. Bisher stand das nur im Quelltext von
`module/13c_signaturhilfe.sh`.

## [3.13.0] — 2026-08-12

Eine Fassung mit einem einzigen Thema: **die Zeitstempel überleben die
Bereinigung.**

Sie liegen im Inode. Wird eine Datei verschoben, quarantänisiert oder
gelöscht, sind sie weg — und mit ihnen die Antwort auf die Frage, die nach
einem Vorfall zählt: seit wann liegt das Ding dort. Daran hängt, ab wann Daten
als abgeflossen gelten müssen, und damit der Inhalt der DSGVO-Meldung.

Bis hierher hielt das Werkzeug die Zeitstempel nur für die Handvoll Dateien
fest, für die ohnehin ein Beleg entstand. Für alles andere gab es keine
Aufzeichnung — auch nicht für die Nachbardateien, ohne die sich später nicht
mehr sagen lässt, was in derselben Sekunde sonst noch angefasst wurde.

Der Gegenpart liegt in NT-Repair (#16 dort): dort muss nach dem Verschieben
über `dev`+`inode` nachgewiesen werden, dass es dieselbe Datei ist. Erst dann
ist die Kette geschlossen.


### Neu — Datei-Inventar mit Inode und allen Zeitstempeln (#25)

Zeitstempel liegen im Inode. Wird eine Datei verschoben, quarantänisiert oder
gelöscht, sind sie weg — und mit ihnen die Antwort auf die Frage, die nach
einem Vorfall zählt: **seit wann liegt das Ding dort.** Daran hängt, ab wann
Daten als abgeflossen gelten müssen, und damit der Inhalt der DSGVO-Meldung.

Abschnitt **7.0** erhebt deshalb vor allen Prüfungen ein Inventar über den
gesamten Prüfumfang und legt es als `belege/00_dateien.tsv` ab, mitversiegelt
vom bestehenden `SHA256SUMS`:

```
dev  inode  modus  eigner  gruppe  groesse  mtime  ctime  crtime  pfad
```

**Der eigentliche Punkt sind `dev` und `inode`.** Abgeschriebene Zeitstempel
beweisen nichts — die kann jeder schreiben. Nach der Quarantäne wird die
verschobene Datei erneut `stat`-et: stimmen Gerätenummer und Inode überein,
ist bewiesen, dass es dasselbe Dateiobjekt ist, und die aufgezeichneten Werte
gelten weiter. Stimmen sie nicht überein — Kopie über eine Dateisystemgrenze,
tar-Archiv —, zeigt der Datensatz den Bruch, statt ihn zu verdecken. Aus einem
Abschrieb wird damit ein **Kettenglied**. Gegenstück: netztaucher/NT-Repair#16.

Das Inventar erfasst **alles**, nicht nur die Funde. Die Frage nach einem
Vorfall lautet fast immer „was hat sich sonst noch in derselben Sekunde
geändert?", und die ist nur beantwortbar, wenn auch das Unauffällige
aufgezeichnet wurde. 100.000 Zeilen sind rund 12 MB — nichts neben dem
Log-Archiv.

Erhoben wird gebündelt: `find -printf` unter GNU, `xargs stat -f` unter BSD.
Ein `stat`-Aufruf je Datei wären bei 100.000 Dateien 100.000 Prozessstarts.
Geprüft wird dabei die **Fähigkeit**, nicht die Plattform — auf dem
Arbeitsplatz steht `bfs` im Pfad, das `-printf` beherrscht, während
`/usr/bin/find` es nicht kann.

Was das Inventar **nicht** ist: eine Bewahrung. Es hält eine Beobachtung fest —
„zum Zeitpunkt T, auf Host H, mit Fassung V wurden diese Werte gesehen". Was
vorher war, sagt es nicht. Das steht im Kopf der Datei.

### Prüfstand — beide Erhebungswege, nicht nur der gerade laufende

`datei_inventar` hat zwei Wege: GNU-`find -printf` und gebündeltes BSD-`stat`.
Der BSD-Zweig wäre **nirgends** gelaufen — auf dem Arbeitsplatz steht `bfs` im
PATH, in der CI GNU-`find`, beide können `-printf`. Ein Zweig, den kein
Prüfstand erreicht, ist unbelegter Code, und dieser hier liefe ausgerechnet auf
der Plattform, auf der niemand nachsieht.

`NT_INVENTAR_BSD=1` erzwingt ihn. Der Prüfstand nutzt das, wo BSD-`stat`
wirklich vorhanden ist, und prüft zusätzlich, dass **beide Wege denselben
Inode nennen** — sonst messen sie verschiedene Dinge und niemand wüsste,
welcher stimmt. Wo BSD-`stat` fehlt (Linux, CI), wird das ausgesprochen statt
still übersprungen: eine ausgelassene Prüfung, die niemand erwähnt, sieht aus
wie eine bestandene.

### Gemessen — `crtime` ist nur auf ext4 fälschungssicher

Die Aussage „die Anlegezeit lässt sich mit `touch` nicht verstellen" gilt
nicht überall. Auf APFS hält der Kern `crtime <= mtime`, und eine
**Rückdatierung zieht die Anlegezeit mit**:

```
vorher          mtime=1786510340  crtime=1786510340
touch -t 2020   mtime=1577833200  crtime=1577833200   ← beide gefälscht
touch -t 2030   mtime=1893452400  crtime=1577833200   ← nur die mtime
```

Der Zielserver ist Linux, dort trägt `crtime`. Aber der verlässliche
Anhaltspunkt für eine Rückdatierung ist auf **jeder** Plattform die `ctime`:
sie ist von keinem `touch` setzbar, der Kern setzt sie bei jeder
Inode-Änderung. Genau sie überschreibt das Verschieben in die Quarantäne —
weshalb es dieses Inventar überhaupt gibt. Die Messung steht im Quelltext,
nicht nur hier.

## [3.12.0] — 2026-08-11

Diese Fassung räumt hinter einem Umbau auf, den niemand als unfertig erkannt
hatte. Beim Umzug der WordPress- und Nextcloud-Prüfungen nach `rezepte/` waren
zwölf Befundvariablen stehengeblieben, die seither niemand mehr füllte —
`findings.json` gab sie weiter aus, als leere Listen. Eine leere Liste liest
sich wie „nichts gefunden". Der Reparaturteil bekam seither keine
Quarantäne-Kandidaten mehr, und zwei Zähler standen dauerhaft auf 0, während
derselbe Bericht die Funde namentlich auflistete.

Der zweite Schwerpunkt ist die **Trennung zwischen Betreiber und Kunde**: jeder
Beleg trägt jetzt eine Einstufung, und aus einem Lauf lässt sich ein
übergabefähiges Paket schnüren, statt es von Hand zu sortieren.

Der dritte ist **weniger Rauschen**: der fremde YARA-Regelsatz filtert seine
Trefferliste gegen Dateien, die als unverändert gegenüber dem Original
bestätigt sind. Im Prüfstand rückt der eingebaute Schadcode damit von hinten
auf Platz 1.

Was diese Fassung nicht kann, steht bei den einzelnen Einträgen. Die Fassung
selbst erzwingt übrigens **keine neue Prüfstand-Referenz mehr** — die
Normalisierung erfasst die Bannerzeile jetzt mit; bis v3.11 tat sie es nicht,
und jede Neuaufnahme nach einem Versionssprung übernahm stillschweigend jede
echte Abweichung mit, die im selben Sprung entstanden war.


### Neu — Composer-Abhängigkeiten der Plugins gegen GHSA prüfen (#14)

Der Schwachstellenabgleich erfasste Kern, Plugins und Themes — **nicht** die
Bibliotheken, die ein Plugin in `wp-content/plugins/*/vendor/` mitbringt. Dort
steckt regelmässig fremder Code mit eigenen Lücken: Guzzle, PHPMailer,
Monolog.

Für **Packagist** ist die GitHub Advisory Database vollständig und maschinell
auswertbar — anders als für WordPress-Plugins, wo die Advisories kein
OSV-Ökosystem tragen und es damit nichts zu vergleichen gibt. Die Lizenzlage
ist die beste aller geprüften Quellen: CC-BY 4.0, die Attribution erfüllt der
Verweis je Datensatz.

`lib/wp_schwachstellen.py` liest jetzt **OSV-JSON** direkt, ohne Umweg über
eine TSV-Zwischenstufe — die wäre eine weitere Stelle, an der sich ein Fehler
versteckt. `lib/composer_bestand.py` liest die installierten Pakete aus
`vendor/composer/installed.json` (nicht aus `composer.lock`: die sagt, was
installiert werden *soll*, nicht was liegt).

Die Intervall-Semantik ist die Stelle, an der ein Fehler am teuersten wäre:
`introduced` ist **einschliesslich**, `fixed` **ausschliesslich**. Wer das
verwechselt, meldet die behobene Fassung als verwundbar oder lässt die erste
betroffene durchgehen — beides sieht im Bericht plausibel aus. Sieben neue
Selbsttestfälle decken beide Grenzen, den offenen Bereich ohne `fixed` und die
Abgrenzung gegen fremde Ökosysteme ab.

Entwicklungsstände (`dev-main`) gehen als **UNBEWERTBAR** durch, nicht als
sauber.

**Ohne Datenbestand wird gar nicht erst erhoben.** Sonst käme jedes Paket als
⚪ zurück — auf einer echten Installation schnell hundert je Instanz, und der
vierte Zustand würde zu Rauschen. Der Bestand kommt über
`wordpress-daten-update.sh --composer <verzeichnis>`; das Vorfiltern des 3,5 GB
grossen Bulk-Repositorys gehört in die CI, nicht auf eine Entwicklungsmaschine.

### Neu — Wordfence-Bestand der geprüften Installation auslesen (#17)

Läuft auf einer Installation Wordfence, liegt dort ein vollständiger
Scan-Datenbestand in der Datenbank. NT-Forensik las davon nichts.

Ausgewertet werden `wfissues` und `wfconfig`. Der wertvollste Befund ist
**nicht** die Schwachstellenmeldung, sondern `skippedPaths`: bei einem Vorfall
im August 2026 hatte Wordfence 99 Pfade gar nicht gescannt, weil „Dateien
ausserhalb der WordPress-Installation scannen" standardmässig aus ist — und
genau dort lagen zwei der Shells. Wer den Wordfence-Bericht des Kunden als
Entwarnung liest, liest ihn falsch, und das steht im Bestand ausdrücklich
drin.

`knownfile` wird als **Integritätsabweichung** gemeldet, nicht als
Signaturtreffer. Die Verwechslung ist bei der Auswertung des echten Bestands
passiert und hätte beinahe legitimen Plugin-Code als Schadcode in den
Kundenbericht gebracht.

Das Alter des letzten Scans wird bewertet — ein Bestand von vor drei Wochen
sagt nichts über heute — und ein freier Schlüssel vermerkt.

**Reichweite, ehrlich:** auf einem Server mit 68 WordPress-Installationen
hatten 5 Wordfence-Tabellen. Das sind 7 %. Eine Zweitmeinung, wo vorhanden —
keine Primärquelle.

`apiKey` wird ausdrücklich **nicht** gelesen; die Abfragen nennen ihre Felder
einzeln statt `SELECT *`. Read-only wie der Rest, kein Installieren, kein
Wordfence-CLI.

Der Prüfbaum hat keine Datenbank; die Naht `NT_WF_ATTRAPPE` speist einen
vorgefertigten Bestand ein — mit je einer Zeile pro Befundart, damit die
Zuordnung nicht verrutscht, und nur für **eine** der drei Installationen,
damit auch der häufige Fall ohne Wordfence geübt wird.

### Geändert — 7.12 heisst jetzt 13c und filtert gegen lebende Prüfsummen (#18)

Der fremde Regelsatz (php-malware-finder) lieferte im Messlauf über 25.860
PHP-Dateien **359 Treffer** — und der enthaltene gepackte Webshell stand mit
drei Regeln auf **Platz 11**. Über ihm der WordPress-Kern, pclzip, UpdraftPlus
und Wordfence selbst.

Ursache ist die Whitelist des Regelsatzes: SHA1-Hashes konkreter Kerndateien,
629 Stück für WordPress, auf dem Stand von 2023. Auf einer aktuellen
Installation passt kein einziger. Das Projekt ruht seit Oktober 2023, das
Problem wächst mit jedem WordPress-Release.

An ihre Stelle tritt eine **lebende** Whitelist, die bei jedem Lauf neu
entsteht: `wp core verify-checksums` bestätigt den Kern, die Prüfsummen von
wordpress.org bestätigen die Plugins. Eine Datei, die Byte für Byte dem
Original entspricht, kann kein untergeschobener Schadcode sein.

Dafür musste der Abschnitt umziehen: als 7.12 lief er **vor** dem
WordPress-Rezept und hatte die Bestätigungen noch nicht. Er liegt jetzt als
`module/13c_signaturhilfe.sh` und läuft nach 12r, aber vor den Berichten.

**Keine stille Filterung.** Die Zahl der unterdrückten Treffer steht im
Befundtext, und der Beleg führt beide Listen — die verbliebenen und die
herausgefilterten — namentlich auf. Ein Filter, dessen Wirkung man nicht
nachrechnen kann, ist in einem Forensikwerkzeug schlimmer als kein Filter.

Ausdrücklich **nicht** freigegeben werden die Dateien aus `CORE_INJECTED` und
`CORE_SNE`, obwohl sie unter `wp-admin/` und `wp-includes/` liegen. Sie sind
der Grund, warum dort überhaupt jemand hinsieht.

Nicht abgedeckt und ehrlich zu benennen: kommerzielle Plugins ohne öffentliche
Prüfsummen (im Messlauf genau die lautesten Fundorte), Themes, und
Installationen ohne wp-cli.

Nachgewiesen: der Prüfbaum trägt eine vorgefertigte yara-Ausgabe
(`NT_PMF_ATTRAPPE`) mit neun bestätigt unveränderten Bibliotheks- und
Kerndateien über dem Schadcode. Eine eigene CI-Stufe prüft das
Abnahmekriterium aus dem Issue: der Schadcode muss unter den ersten fünf
stehen (er steht auf **Platz 1**) und der Filter muss etwas — aber nicht
alles — herausgenommen haben. Dazu die Gegenprobe
`NT_PRUEFSTAND_OHNE_PMF_WHITELIST=1`.

### Neu — `werkzeuge/kundenpaket.sh` (#4)

Schnürt aus einem Lauf ein übergabefähiges Paket:
`01_Kundenunterlagen` · `02_Meldungen` · `03_Technik` · `04_Belege` ·
`05_Bereinigung`. Belege der Stufe `kunde` gehen maskiert mit und werden
lückenlos neu nummeriert; `server` nur mit `--mit-server`, `betreiber` nie.

Immer draussen, ohne Schalter: `findings.json` (Maschinendatei),
das Log-Archiv (im Anlassfall 527 MB Zugriffe aller Domains des Servers) und
die BSI-Meldung (Meldeweg des Betreibers). Die DSGVO-Meldung geht mit — sie
ist die Pflicht des Kunden als Verantwortlichem, nicht die des Betreibers.

Weil die Belege maskiert und neu nummeriert werden, stimmen die Prüfsummen des
Laufs nicht mehr. Das Paket bekommt deshalb ein **eigenes** SHA256SUMS und ein
LIESMICH, das den Unterschied benennt und auf das Originalsiegel beim
Betreiber verweist — sonst sieht eine gewollte Änderung wie ein gebrochenes
Siegel aus. `04_Belege/00_verzeichnis.tsv` nennt zu jedem Beleg seine
ursprüngliche Nummer.

Ein Betreiberlauf (`scope_mode=global`) wird abgelehnt: es gäbe niemanden,
gegen den maskiert werden könnte. Dafür trägt `findings.json` ab v3.12 den
Prüfumfang (`run.scope_mode`, `run.abo_user`, `run.scan_paths`).

`werkzeuge/kundenpaket-pruefstand.sh` prüft elf Soll-Werte, darunter die
Gegenprobe zu `--mit-server`: ein Werkzeug, das grundsätzlich nichts
übernimmt, würde die Sperren sonst genauso „bestehen".

### Behoben — der Kundenbericht nannte Betreiber-Dokumente „Ihre Unterlagen"

Abschnitt 8 führte `technik_bericht.md`, `bsi_meldung.md`, `dsgvo_meldung.md`
und `belege/` auf. Alle vier liegen in `betreiber/` und sind laut
`lib/konfig.sh` ausdrücklich **nicht** zur Weitergabe bestimmt. Der Bericht
nennt jetzt, was tatsächlich im Paket liegt — und sagt, was nicht darin ist
und warum.

### Neu — Belege tragen eine Einstufung (#1)

`evidence` nimmt einen dritten Parameter: `kunde`, `server` oder `betreiber`.

| Stufe | Bedeutung |
|---|---|
| `kunde` | betrifft den geprüften Webauftritt — darf übergeben werden |
| `server` | serverweit — nur maskiert und nur, wenn der Befund es braucht |
| `betreiber` | rein intern — geht nie mit |

Anlass: beim Zusammenstellen eines Kundenpakets ging `03_admin_changelog.txt`
mit — der Betreiber-Changelog mit SSL-Arbeiten am Server-Host und internen
Betriebsnotizen. Von 45 Belegen nannten 26 den geprüften Kunden überhaupt
nicht.

Statt 113 Aufrufe einzeln zu ändern, setzt jeder Abschnitt seine Stufe einmal
am Kopf; einzelne Aufrufe überschreiben sie. Der Runner setzt `BELEG_STUFE`
**vor jedem Modul** auf `betreiber` zurück — ohne das erbte ein Abschnitt ohne
eigene Angabe die Einstufung des vorherigen, und zwar unsichtbar.

Zwei CI-Stufen halten das offen: jedes Modul, das Belege erhebt, muss seine
Stufe benennen, und ein Abschnitt der Ebene `system` darf nichts als `kunde`
einstufen. Der Prüfstand läuft mit `--nur-website` und erreicht diese
Abschnitte nicht — die Einstufung wäre sonst von keinem Vergleich gedeckt.

Dazu `belege/00_verzeichnis.tsv` (Nummer, Stufe, Bezeichner, Datei) und eine
Zusammenfassung im Manifest. Die Nummerierung ist auf `%03d` umgestellt: bei
über hundert Belegen sortierte `10_` vor `9_`.

Die Belege im Laufordner bleiben **unmaskiert** — sie sind Beweismittel des
Betreibers. Maskiert wird beim Schnüren des Kundenpakets (#4).

### Behoben — `sort: write failed: Broken pipe` mitten im Bericht

`… | sort | head -5` schliesst die Pipe, sobald `head` genug hat; `sort`
bekommt EPIPE und schreibt eine Fehlermeldung nach stderr — **nicht immer,
sondern je nachdem, ob die Ausgabe noch in den Pipe-Puffer passt**. In der CI
trug die aufgenommene Referenz die Zeile, der Vergleichslauf desselben Standes
nicht. Ein Prüfstand, der bei gleichem Programmstand mal so und mal so
ausschlägt, taugt nichts; und in einem forensischen Beleg hat eine
Interpreter-Meldung ohnehin nichts verloren.

Betroffen waren sechs Stellen (7.14, 3.x, 4.x, `baumscan.sh`). `awk` begrenzt
jetzt selbst und liest die Eingabe zu Ende. Bei der Gelegenheit `LC_ALL=C` vor
jedes beteiligte `sort` — dieselbe Falle wie in 7.1.

### Behoben — die Befund-Einordnung lief bei `--nur-website` überhaupt nicht (#3)

Der Block, der jedem Fund eine Familie und ein Geschäftsmodell zuordnet und
`befunde_details.md` schreibt, stand am Ende von Abschnitt 13. Abschnitt 13
trägt die Ebene `system` und läuft bei `--nur-website` nicht — also entstand
ausgerechnet im häufigsten Fall, der Prüfung eines einzelnen Kundenauftritts,
gar keine Detaildatei. Der Kundenbericht verwies trotzdem darauf.

Der Block liegt jetzt als `module/14_berichte/05_einordnung.sh` bei den
Berichten. Er liest nur Befundvariablen und schreibt nur Berichtstext; dort
gehört er hin.

### Behoben — der einzige bash-4-Code im Werkzeug

Dieselbe Einordnung benutzte vier assoziative Arrays (`declare -A`, ab bash 4).
Aufgefallen ist das nie, weil der Block auf dem Entwicklungsrechner (macOS,
bash 3.2) nie lief — siehe oben. Beim Verschieben brach der erste Lauf sofort
mit `declare: -A: invalid option` ab; auf einem Zielsystem mit bash 3.2 hätte
derselbe Fehler mitten im Bericht gestanden. Ersetzt durch tabgetrennte Listen
und `awk`. Eine CI-Stufe hält die Sprachgrenze offen.

### Behoben — Fundlisten, die seit dem Rezept-Umzug leer blieben (#3, #2)

Beim Umzug der WordPress- und Nextcloud-Prüfungen von `module/11_wordpress.sh`
und `module/12b_nextcloud.sh` nach `rezepte/` blieben zwölf Befundvariablen
stehen, wurden aber von niemandem mehr gefüllt: `CORE_INJECTED`, `CORE_SNE`,
`DOORWAY_DIRS`, `CORE_INJECT_HITS`, `MU_PLUGINS`, `TAMPERED_HTACCESS`,
`ROGUE_ADMINS`, `SUSPECT_ADMINS`, `NC_MALWARE`, `NC_HTACCESS_MAL`,
`NC_NESTED`, `NC_INTEGRITY`.

Sichtbar wurde das nirgends. `findings.json` gab die Schlüssel weiter aus, nur
eben als leere Listen — und eine leere Liste liest sich wie „nichts gefunden".
Der Reparaturteil bekam keine Quarantäne-Kandidaten mehr, und
`metrics.rogue_wp_admins` stand dauerhaft auf 0, auch wenn derselbe Bericht die
Angreifer-Konten namentlich auflistete. Die Rezepte füllen sie wieder.

Zwei Listen kamen neu hinzu, weil es ihre Quelle vorher gar nicht gab:
`SIGNATUR_TREFFER` (Treffer aus `signaturen.tsv` — bis hierher stand nur der
**erste** je Muster irgendwo maschinenlesbar) und `PLUGIN_VERAENDERT`. Beide
auch in `findings.json` unter `actionable`.

### Behoben — `metrics.wp_installs` war immer 0

`WP_COUNT` wurde nirgends mehr zugewiesen. `module/14_berichte/40_dsgvo.sh`
entscheidet anhand desselben Werts, ob ein WordPress-Absatz in die Meldung
gehört — die Bedingung war damit dauerhaft falsch. Der Rezept-Rahmen zählt
jetzt wieder.

### Neu — `metrics.schadcode_gesamt` und ein zweiter Rang (#2)

`metrics.webshell_count` erfasst nur klassische Dropper-Signaturen aus
Abschnitt 7. Ein Bericht, der daraus „0 Schadcode-Dateien" ableitet, während
zehn Dateien in Quarantäne liegen, beschädigt jede andere Zahl darin.
`schadcode_gesamt` zählt alle dateibasierten Fundstellen, quellenübergreifend
und **ohne Doppelzählung** — dieselbe Datei steht regelmässig in mehreren
Listen. `webshell_count` bleibt unverändert bestehen.

Getrennt davon `zu_pruefen_gesamt`: kernfremde Dateien, mu-Plugins,
Ausführbares in `/tmp`. Deren Quelle meldet selbst nur `warn`. Sie stehen mit
eigener Überschrift in `befunde_details.md`, zählen aber nicht als Schadcode —
wer sie mitzählt, baut die Übertreibung ein, die #2 in der Gegenrichtung
beklagt.

Die BSI-Meldung führt beide Zahlen. Der Kundenbericht sagt „**N**
Schadcode-Fundstelle(n)", wo bisher die Entwarnung „Keine akuten technischen
Kompromittierungs-Indikatoren" stand — die erschien nämlich immer, sobald die
technische Kurzfassung leer blieb, auch eine Zeile über einer Tabelle mit
dreizehn Fundstellen.

### Geändert — Plugin-Prüfsummen hängen nicht mehr an wp-cli (#10)

`_wp_plugin_integritaet` wurde aus `rezept_kern` nach `rezept_sonder`
verschoben. `rezept_kern` läuft erst nach der Werkzeug-Probe des Rahmens, also
nur mit lauffähigem wp-cli — gebraucht wird wp-cli hier aber nirgends: die
Bestandsliste kommt aus `version.php` und den Plugin-Kopfzeilen, verglichen
wird mit `python3`. Eine Instanz ohne wp-cli verlor damit ausgerechnet die
Prüfung, die den Plugin-Ordner abdeckt.

Preis: die Befunde stehen im Bericht nicht mehr neben der Kern-Integrität. Die
Kategorie in `befund_melden` bleibt `kern`, nur die Reihenfolge ändert sich.

Nachgewiesen in der CI: ein Lauf mit `NT_PRUEFSTAND_OHNE_WPCLI=1` muss die
Prüfsummen-Aussage trotzdem in der Konsole zeigen. Gegen den alten Stand
gemessen — dort erscheint sie nicht.

### Behoben — der Wächter-Filter in 7.2 war auf BSD vollständig wirkungslos

Die Dateigrösse wurde mit `stat -c%s` gelesen, und `stat -c` ist GNU. Auf BSD
schlug der Aufruf fehl, der Rückfallwert `999999` griff, und damit galt **jede**
Datei als zu gross: die 200-Byte-Regel, die 2000-Byte-ABSPATH-Regel und die
neue Prüfung auf die leere Datei liefen alle ins Leere. Auf dem Zielsystem
(Linux) hat der Filter gearbeitet — auf dem Entwicklungsrechner nie, und
niemand konnte das sehen, weil ein wirkungsloser Filter einfach mehr Funde
meldet und nicht etwa einen Fehler. Jetzt über `datei_meta`, das beide
`stat`-Familien kennt.

### Behoben — 274 leere `index.php` als „extrem verdächtig" (#6)

Der Wächter-Test verlangte eine kleine Datei **und** einen Inhaltstreffer. Eine
leere Datei liefert keinen Treffer und rutschte durch. Über 68 Installationen
gemessen waren das 274 Fehlalarme. Leere Dateien scheiden jetzt vor der
Inhaltsprüfung aus; dazu Pfadmuster für Forminator, WPForms, UpdraftPlus,
WooCommerce und `uploads/cache`.

Bewusst **nur** deren `index.php`, nicht der ganze Teilbaum: das sind
beschreibbare Ablagen und damit genau die Orte, an denen eine Shell landet. Ein
Muster `*/uploads/cache/*` hätte den Fehlalarm beseitigt und zugleich eine
blinde Stelle geschaffen.

Die Zahl der gefilterten Wächter steht jetzt auch im **Trefferzweig** — bisher
erschien sie nur in der Entwarnungszeile, also genau dann nicht, wenn es etwas
zu bewerten gab. Neu in `findings.json`:
`metrics.uploads_guards_gefiltert` (additiv, kein Schema-Bump).

### Behoben — 7.1 lieferte bei zwei Läufen verschiedene Listen

`sort -k8 -r` sortiert nach dem Monatsnamen aus `find -ls`. Dateien desselben
Monats sind damit gleichrangig, und welche von ihnen die Abschneidung bei 50
überlebt, entschied der Zufall. Ein Beleg, der sich zwischen zwei Läufen ohne
Anlass ändert, ist als Beweismittel wertlos. Der Pfad ist jetzt zweiter
Schlüssel, `LC_ALL=C` hält die Ordnung über Sprachräume hinweg gleich.

### Neu — ctime und crtime in den Belegen (#5)

`datei_steckbrief()` führte nur die mtime. Die sagt aber nur, was der letzte
Schreiber hinterlassen wollte: `touch -r nachbar.php shell.php` setzt sie auf
einen unauffälligen Wert, und der Beleg behauptet danach ein Alter, das die
Datei nie hatte. Jetzt stehen alle drei Zeitstempel darin, dazu zwei Hinweise:

- **Rückdatierung** — mtime liegt mehr als 30 Tage vor der letzten
  Metadatenänderung.
- **Übernommene mtime** — sekundengleich mit höchstens fünf Nachbardateien.
  Die obere Schranke ist tragend: eine Entpackung schreibt viele Dateien in
  dieselbe Sekunde, das ist normal und darf nicht gemeldet werden.

`datei_meta()` kennt jetzt `crtime`; neu ist `datei_epoche()` für Rechnungen.
Die beiden Zeitstempel-Schwellen heissen jetzt `ZEITSTEMPEL_ZUSATZ_SEK` (30
Tage) und `ZEITSTEMPEL_ALLEIN_SEK` (90 Tage) und stehen mit Begründung in
`lib/konfig.sh`. Sie sind absichtlich verschieden: der Zusatz stützt einen
vorhandenen Verdacht und darf empfindlich sein, der alleinstehende Befund in
8.7 trägt sich selbst.

**Nicht enthalten**: die Quarantäne-Protokollierung aus #5. Sie liegt in
NT-Repair.

### Behoben — zwei kritische Website-Befunde erreichten den Kunden nie

7.12 (php-malware-finder) und 7.13 (PHP in Mediendateien) meldeten ohne das
`web`-Flag. Beide bewerten die Website-Ebene, einer davon kritisch — und beide
blieben damit im Betreiberbericht stehen. 7.10, 7.11 und der YARA-Treffer
behalten bewusst kein `web`: sie scannen serverweit.

### Neu — `werkzeuge/kern-pruefstand.sh`

Die Referenz unter `pruefstand/referenz/` hält von den Belegen nur die
**Dateinamen** fest, nicht deren Inhalt. Der Inhalt eines Belegs ist aber das,
was am Ende getragen werden soll, und war von keinem Vergleich gedeckt: man
konnte jede Zeile darin ändern, ohne dass ein Prüfstand ausschlug. Der neue
Prüfstand prüft die Zeitstempel-Auswertung gegen Soll-Werte, jeweils mit
Gegenprobe — zu jedem „wird gemeldet" gehört ein Fall, der nicht gemeldet
werden darf.

### Behoben — zwei Punkte am Goldmuster

- Die Banner-Kopfzeile `WP-PLESK-FORENSIK v…` fehlte in der
  Normalisierungsliste. Folge: nach jedem Versionssprung schlug der Vergleich
  aus, wurde die Referenz neu aufgenommen — und die Neuaufnahme übernahm
  stillschweigend jede echte Abweichung mit, die im selben Sprung entstand.
- Der Lauf setzt jetzt `LC_ALL=C`. Die Zeitstempel-Regel erkennt die englische
  Form von `date`; auf einem deutsch eingestellten Rechner schlug der Vergleich
  sonst bei jedem Lauf aus und war damit wertlos.

## [3.11.0] — 2026-08-11

Anlass war ein realer Vorfall: fünf Schadobjekte in einem Webspace, von denen
der Signaturscanner vier fand und die eigene Heuristik eines. Das Nachspiel hat
mehr über das Werkzeug verraten als über den Angreifer.

Für v3.10.0 gibt es keinen eigenen Abschnitt — die Fassung wurde ohne einen
getaggt. Ihre Änderungen stehen weiter unten, ab „Rezept-Schnittstelle".

### Neu — Urteil je Datei statt Fundliste

Bisher bekamen nur Dateien **mit** Fund eine Aussage. Bei einem Lauf über einen
echten Webspace waren das 870 von 101.735. Für 100.865 Dateien stand nichts da,
und im Bericht las sich das wie Entwarnung. Dazu die Verwechslung im Wort:
`ok()` bedeutet „diese Prüfung hat nichts gefunden", nicht „diese Datei ist
sauber" — der Bericht schrieb trotzdem ✅.

`werkzeuge/baumscan.sh` fällt jetzt für **jede** Datei der Inventur ein Urteil:

| Urteil | Bedeutung | Quelle |
|---|---|---|
| `SAUBER` | positiv bestätigt | amtliche Prüfsumme — die einzige Quelle |
| `KEIN` | nichts angeschlagen, **nicht bestätigbar** | der ehrliche Normalfall |
| `TREFFER` | angeschlagen, Auslegung nötig | Heuristik mit Spielraum |
| `BEFALLEN` | Beweis, nicht vernünftig bestreitbar | Signatur, PHP im Bild, Packer-Banner, `.htaccess`-Einzelfreigabe |

Rangfolge `BEFALLEN` > `SAUBER` > `TREFFER` > `KEIN`. Trifft beides zugleich zu,
wird das als `WIDERSPRUCH` ausgewiesen statt stillschweigend aufgelöst: es
bedeutet Fehlalarm oder einen Angriff auf die Lieferkette.

Gemessen an 101.737 Dateien: 80.770 `KEIN`, 20.360 `SAUBER`, 606 `TREFFER`.
20.360 Dateien sind damit positiv bestätigt — vorher gab es diese Aussage für
keine einzige.

**Der Widerspruchszähler hat sich sofort bewährt.** Ein erster Entwurf wertete
lange Escape-Folgen als Packer-Beweis. Der Lauf gegen einen **bereinigten** Baum
meldete daraufhin zwölf `BEFALLEN` — phpseclib `RSA.php`, `Blowfish.php`,
HTMLPurifier. Krypto-Bibliotheken bestehen aus solchen Folgen: S-Boxen,
OID-Bytes, Testvektoren. 59 dieser Dateien trugen zugleich eine gültige amtliche
Prüfsumme. Die Regel war widerlegt, bevor sie in einen Kundenbericht geraten
konnte.

### Neu — Betriebsart `qualifizieren`

```
baumscan.sh qualifizieren <lauf-verzeichnis> [--online]
```

Ein `TREFFER` ist kein Urteil, sondern eine offene Frage. Die Betriebsart
sammelt je Treffer Verbreitung im Korpus, amtliche Prüfsumme, Anlegezeit,
Nachbarschaft und Zugriffsspur — und **ändert von sich aus kein Urteil**.
Entscheidungen gehören nach `entscheidungen.tsv`, mit Kennung, Datum und
Begründung. Eine blosse Hash-Allowlist ist nach einem halben Jahr eine Liste
unbegründeter Ausnahmen.

Der Verbreitungsabgleich trägt: dieselbe Bibliotheksdatei liegt auf bis zu 26
unabhängigen Installationen identisch vor, der echte Schadcode auf keiner.

An 606 Treffern liessen sich 19 über die Verbreitung auflösen, 3 lagen
überhaupt in einem Plugin mit amtlichem Satz. Das ist keine Schwäche des
Verfahrens, sondern ein Befund: die Treffer konzentrieren sich fast vollständig
in kommerziellen Erweiterungen, für die es keine öffentliche Referenz gibt.

### Neu — Abschnitt 7.13: PHP-Code in Medien- und Asset-Dateien

Der Gegenpol zu 7.10. Dort ein Binary, das sich als Schlüsseldatei ausgibt, hier
PHP in einer echten Mediendatei.

Der Anlassfall war ein gültiges PNG, 512×512, das sich in jedem Bildbetrachter
normal öffnet — mit PHP im tEXt-Chunk, das Schadcode nachlud. Es lag neun Tage
unentdeckt. Gemeldet hat es niemand: der Signaturscanner nicht, die Heuristik
nicht, und auch kein fremder YARA-Regelsatz, obwohl einer davon eine Regel genau
dafür mitbringt. Der Grund ist bei allen derselbe — die Nutzlast war völlig
unverschleiert. Kein `eval`, kein Base64, keine Superglobale. Auf Token-Ebene
harmloser Code.

Bösartig ist nicht der Code, sondern der Behälter. Der Abschnitt prüft deshalb
nicht, **was** das PHP tut, sondern nur, **dass** es dort steht.

Dabei fiel auf: `DISGUISED_PAYLOADS` war in `lib/befunde.sh` deklariert, wurde
von `module/13_root.sh` und `50_findings_json.sh` ausgewertet — und von keinem
Abschnitt befüllt. Die Kategorie „Getarnte Payload" stand im Bericht und konnte
strukturell nie etwas melden.

### Neu — Abschnitt 7.14: massenhaft gleiche Zeitstempel

Im Anlassfall trugen 59.472 Dateien dieselbe gefälschte `mtime`. Danach war jede
Aussage der Form „diese Datei ist neu" wertlos — genau das war der Zweck.

Bewusst als Hinweis, nicht als Befund: dieselbe Signatur entsteht auch bei einer
Rücksicherung oder Migration. Mit Gegenprobe über die Anlegezeit einer
Stichprobe — sie unterscheidet Migration von Verschleierung.

### Neu — Abschnitt 7.12: fremder YARA-Regelsatz (optional)

Bindet php-malware-finder als **Suchhilfsmittel** ein, nicht als Detektor. Der
Regelsatz wird nicht mitgeliefert, sondern mit
`werkzeuge/signaturen-fremd-holen.sh` vor Ort geholt: er steht unter LGPL-3.0,
dieses Repository unter MIT.

Ehrliche Einordnung, gemessen: 359 betroffene Dateien bei 25.860 PHP-Dateien,
und der enthaltene gepackte Webshell landete auf Platz 11. Über ihm standen
WordPress-Kern, `pclzip`, UpdraftPlus und Wordfence. Ursache sind die
mitgelieferten Whitelists — sie arbeiten mit SHA1-Hashes konkreter Dateien,
allein 629 für WordPress, auf dem Stand von 2023. Auf einer aktuellen
Installation passt kein einziger davon.

### Neu — Musterstufen erweitert

`PATTERN_REGEX` verlangte den Dekodierer **direkt** hinter `eval`. Zwei reale
Shells entkamen: eine über eine Variablenfunktion, eine über einen PHP-Encoder,
der den Funktionsnamen als Escape-Folge schreibt und `eval("?>" . $F(…))`
aufruft. Neu erfasst werden `eval` auf eine Variable, `eval` das den PHP-Modus
neu öffnet, Escape-Folgen, Encoder-Banner und der Aufruf direkt aus einer
Superglobalen.

Dazu `PATTERN_REGEX_MED` als zweite, schwächer gewichtete Stufe: exec-Familie,
`goto`-Obfuskierung, `chr`-Ketten, Bot-Ausblendung nach User-Agent. Diese
Funktionen kommen legitim vor — ein Messlauf ergab 358 Treffer auf 25.000
Dateien. Abschnitt 7.3 wendet sie deshalb nur auf Dateien unter
`DROPPER_MAX_BYTES` an. Anlass war eine Filemanager-Shell mit unverschleiertem
`shell_exec`, die vollständig unsichtbar blieb.

### Neu — Abschnitt 7.6 erkennt Freigaben einzelner PHP-Dateien

Im Anlassfall lag neben jeder Shell eine `.htaccess`, die PHP im Verzeichnis
sperrte und genau die eigene Datei freigab — der Angreifer sperrte damit
Mitbewerber aus. Legitime Software tut das praktisch nie.

Umgesetzt mit `awk` statt `grep -Pz`: auf dem Entwicklungsrechner läuft ein
`grep` ohne PCRE, das `-P` schlicht zurückweist. Die Prüfung blieb stumm und
meldete „keine Freigabe gefunden", obwohl eine danebenlag. Ein Werkzeug, das auf
fremden Servern mit unbekannten Werkzeugständen läuft, darf sich darauf nicht
verlassen.

### Neu — Anlegezeit (crtime) in den Befunden

`touch` kann `mtime` und `atime` setzen, die Anlegezeit nicht. Im Anlassfall war
sie das einzige Mittel, die Chronologie zu rekonstruieren; `mtime` und `ctime`
waren beide unbrauchbar. Abschnitt 7.3 führt sie jetzt je Fund mit.

Die Rückdatierung selbst steht als **Zusatz** an einer ohnehin auffälligen
Datei. Als eigener Befund wäre sie wertlos: jedes rekursive `chown` und jede
Rücksicherung löst sie baumweit aus, ein Messlauf meldete damit 62.373 Dateien.

### Neu — `werkzeuge/baumscan.sh`

Eigenständiges Schnellwerkzeug für die erste Sichtung eines Verzeichnisbaums.
Read-only, Laufzeit Sekunden statt Minuten, weil eine einzige Inventur als TSV
alle weiteren Schichten speist. Acht Schichten, eigene Bewertung, Diff gegen
einen Vorlauf.

Die ImunifyAV-Schicht reiht einen **eigenen** Lauf ein und holt dessen Ergebnis
über `--by-scan-id`. Die frühere Fassung las stattdessen `malware malicious
list` — die Historie aller je gefundenen Dateien, und das auch noch, während der
Scan noch lief. Auf einem bereinigten Webspace standen dadurch vier
Geisterdateien auf den Plätzen 1 bis 4.

### Neu — `werkzeuge/baumscan-pruefstand.sh`

Prüft die Urteile gegen **Soll-Werte** statt gegen einen Referenzlauf. Bei einem
Urteil ist die richtige Antwort vorher bekannt; ein Referenzvergleich meldet nur,
dass sich etwas geändert hat, hier soll er melden, dass etwas falsch ist.

Neun Dateien mit vorab feststehendem Urteil, dazu zwei Zusicherungen: jede Datei
bekommt ein Urteil, und `SAUBER` stammt ausschliesslich aus amtlichen
Prüfsummen. Drei Gegenproben in der CI, alle schlagen an.

Der Prüfbaum von `goldmuster.sh` trägt drei neue, **isolierende** Proben. Die
vorhandene PNG-Probe taugte als Nachweis nicht: sie nutzt `system($_GET[…])` und
schlägt auch bei den Musterprüfungen an — man hätte 7.13 entfernen können, ohne
dass der Prüfstand es merkt.

### Behoben — der yara-Aufruf scannte nie

`yara` nimmt genau **ein** Ziel entgegen und deutet ein zweites Argument als
Regeldatei. Ein Bündelaufruf per `xargs` meldete 25.860 Dateien in einer Sekunde
ohne einen Treffer — er hatte nicht gescannt, sondern Übersetzungsfehler
erzeugt, die in `/dev/null` liefen. Ein stiller Totalausfall, der wie ein
sauberer Befund aussieht. Richtig ist `--scan-list`: 25.860 Dateien in 8
Sekunden.

Im selben Zug fiel auf, dass `werkzeuge/signaturen-fremd-holen.sh` den Regelsatz
unvollständig holte. `whitelist.yar` bindet acht weitere Dateien ein; fehlt eine,
verweigert yara die Übersetzung des **gesamten** Satzes — und ein nicht
übersetzter Regelsatz meldet nichts, auch bei echtem Schadcode nicht. Die
Übersetzungsprüfung gibt jetzt einen Fehlercode zurück, statt es nur anzuzeigen.

## [3.10.0 und früher — Rezept-Schnittstelle, WordPress-Rezept, Prüfstand]

### Behoben — Abschnitt 13b machte die Prüfstand-Referenz maschinenabhängig
13b.3 entscheidet über `pgrep`, ob Apache oder nginx läuft. Der Befund „Kein
Apache-Prozess, aber nginx läuft" hing damit am Zustand der Maschine, auf der
die Referenz aufgenommen wurde — und fehlte auf jeder anderen. Ein **fehlender
kritischer Befund** ist die teuerste Falschmeldung eines Prüfstands: sie sieht
aus wie eine Regression und ist keine.

Die CI merkt es nicht, weil sie ihre Referenz je Lauf selbst aufnimmt und auf
dem Runner keiner der Dienste läuft.

`NT_WEBSERVER=apache|nginx|keiner` hält den Zustand fest, nach dem Muster von
`NT_BASE_DIR`/`NT_VHOSTS_DIR`. Der Prüfstand setzt `nginx` — der Zweig, der den
kritischen Befund erzeugt, gehört geübt, nicht der, der schweigt.

`docs/architektur.md` führt 13b jetzt in der Liste der Abschnitte, die den
Live-Systemzustand lesen, mit der Regel: wer so einen Abschnitt schreibt,
braucht eine Überschreibung für den Prüfstand.

### Behoben — die Prüfstand-Referenz galt nur am Tag ihrer Aufnahme
Die ok-Zeile des Schwachstellenabgleichs nennt den Datenstand, und der
Prüfstand erzeugt seinen Bestand bei jedem Bau mit dem Datum von **heute**
(sonst wäre er nach 30 Tagen „veraltet" und das Rezept vergliche nicht mehr).
Die eingecheckte Referenz stimmte damit genau an dem Tag, an dem sie
aufgenommen wurde, und schlug ab dem nächsten Morgen aus.

Die CI merkt das nie — sie nimmt ihre Referenz je Lauf selbst auf. Betroffen
war nur der lokale Vergleich vor dem Commit, also genau der Schritt, der
Regressionen fangen soll. Und eine Abweichung, die jeden Morgen von selbst
auftaucht, verführt dazu, die Referenz einfach neu aufzunehmen — bis niemand
mehr hinsieht.

`goldmuster.sh` normalisiert den Datenstand jetzt wie die übrigen
Zeitangaben. Der Wert bleibt im echten Bericht stehen, wo er hingehört.

### Behoben — `grep -c` mit `|| echo 0` ergab „0\n0"
`rezept_kern` zählte die Meldungen von `verify-checksums` mit
`grep -c … || echo 0`. `grep -c` gibt bei null Treffern aber **bereits** eine 0
aus und endet trotzdem ungleich 0 — der Rückfall hängte eine zweite an. Der
folgende Vergleich brach mit `[[: 0 0: syntax error in expression` ab, und die
Kern-Integrität wurde für saubere Installationen nie ausgewertet.

Derselbe Fehler steckte in `nf_fetch` (`HTTP=404000`) und ist dort schon
behoben.

### Behoben — der Prüfstand nahm Fehlermeldungen als erwartete Ausgabe
Der Vergleich prüft auf Gleichheit. Eine Fehlermeldung, die in beiden Läufen
steht, gilt ihm deshalb als unverändert — und genau so ist der Syntaxfehler
oben in die eingecheckte Referenz gewandert und dort unbemerkt geblieben.

`goldmuster.sh` prüft die Konsolenausgabe jetzt unabhängig vom Vergleich auf
Meldungen des Interpreters (`syntax error`, `unbound variable`,
`command not found`, `: line N:`) und bricht ab, statt sie aufzunehmen.

### Neu — wp-cli-Attrappe im Prüfbaum
Ohne ein `wp` im PATH bricht der Rahmen nach der Werkzeug-Probe ab, und
`rezept_kern` läuft nie — Kern-Integrität und Plugin-Prüfsummen waren vom
Prüfstand nicht erreichbar. Beides sind Prüfungen, die im Vorfall zählen.

Die Attrappe ist ein PHP-Programm, weil echtes wp-cli eines ist und der Rahmen
`php <datei>` aufruft. Sie beantwortet genau zwei Fragen und leitet ihre
Antwort aus dem Pfad ab; wp-cli bildet sie nicht nach. Geprüft wird der Weg
durch das Rezept, nicht ob wp-cli funktioniert.

Dazu `WP_PRUEFSUMMEN_BASIS`: zeigt die Variable auf ein Verzeichnis statt auf
wordpress.org, wird nachgeschlagen statt abgerufen — und das `--online`-Tor
entfällt, weil es wegen des Netzzugriffs besteht. Der Prüfstand erzeugt seine
Prüfsummen aus dem Baum, mit genau einer gewollten Abweichung.

Drei Gegenproben in der CI schalten je eine Quelle ab und erwarten, dass der
Vergleich es bemerkt. Ohne sie behauptete der Prüfstand Abdeckung, die es
nicht gibt.

### Behoben — `sudo -u` auf sich selbst
Der Rahmen führte das Werkzeug immer per `sudo -u <eigentümer>` aus, auch wenn
der Lauf schon diesem Benutzer gehört. Als root ist der Rechtewechsel nötig;
als der Benutzer selbst ist er überflüssig und auf einer Maschine ohne
NOPASSWD fragt er nach einem Passwort und bleibt stehen. `als_eigentuemer` in
`lib/kern.sh` überspringt ihn in diesem Fall.

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
