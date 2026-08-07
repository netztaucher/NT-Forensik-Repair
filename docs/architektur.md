# NT-Forensik — Aufbau

Wie das Werkzeug intern aufgebaut ist und wie man es erweitert. Für Entwickler; wer es nur benutzt, ist im [Handbuch](handbuch.md) besser aufgehoben.

---

## Warum überhaupt Module

Bis v3.8 war alles eine Datei mit 4412 Zeilen. Zwei Dinge haben das zum Problem gemacht:

**Der Lauf war nicht steuerbar.** Auf einem Server mit 482 Vhosts hing eine reine Joomla-Prüfung minutenlang im Log-Archiv von Abschnitt 2 — es gab keine Möglichkeit, Abschnitte abzuwählen.

**Abschnitte waren einzeln nicht testbar.** Während der Joomla-Entwicklung musste jeder Testlauf den Abschnitt erst per `awk` aus dem Skript herausschneiden und mit nachgebauten Ausgabefunktionen einbinden. In einem Werkzeug, das als root auf Kundensystemen läuft, ist schlechte Testbarkeit kein Komfortproblem.

Der Schnitt war billiger als die Zeilenzahl vermuten lässt, weil die Kopplung **sternförmig** ist: von 117 abschnittsübergreifend gelesenen Variablen kamen 33 aus der Konfiguration und 79 flossen in den Bericht. Echte Abhängigkeiten zwischen zwei Prüfabschnitten gab es nur fünf, und drei davon sind beim Schnitt aufgelöst worden.

---

## Verzeichnisse

```
wp_plesk_forensik.sh   Runner — Einstiegspunkt, bindet ein und orchestriert
lib/
  konfig.sh            Pfade, Version, Argumente, Prüfumfang, Ablage, Selbst-Installation
  befunde.sh           Vorgabewerte aller Befund-Variablen — das Modul-Interface
  muster.sh            Signaturen, die mehrere Abschnitte nutzen; Selbstausschluss
  kern.sh              Ausgabe, Beweissicherung, Modul-Metadaten und Auswahl
  menue.sh             Startmenü
module/
  01_system.sh … 14_berichte.sh     ein Modul je Prüfabschnitt
signaturen/            YARA-Regeln
daten/                 Joomla-Prüfsummen und Schwachstellenlisten
reportgen/             PDF-Erzeugung
werkzeuge/             Pflegeskripte — laufen NIE auf einem Kundenserver
```

Module sind **keine** Funktionsbibliotheken, sondern schlichte Skripte, die der Runner der Reihe nach einbindet. Variablen bleiben global. Das war Absicht: der Schnitt sollte Zeilen verschieben, nicht Logik umschreiben — nur so ließ er sich per Ausgabevergleich beweisen.

---

## Ablauf eines Laufs

1. Runner bestimmt sein eigenes Verzeichnis und sichert die Aufrufargumente in `NT_ARGV`
2. `lib/konfig.sh` wertet die Argumente aus (Prüfumfang, Auswahl, Optionen)
3. `lib/befunde.sh`, `lib/muster.sh`, `lib/kern.sh`, `lib/menue.sh` werden eingebunden
4. Startmenü, falls kein Prüfumfang angegeben wurde
5. `scan_path_bestimmen` und `ablage_einrichten` — erst jetzt, weil das Menü Umfang und Domain geändert haben kann und der Laufordner die Domain im Namen trägt
6. Banner, Chain-of-Custody-Manifest, Berichtskopf
7. Module der Reihe nach, sofern ausgewählt

**Reihenfolge ist bedeutsam:** Abschnitt 13 fasst die Dateifunde der vorherigen Abschnitte zu Schadcode-Familien zusammen, Abschnitt 14 schreibt daraus die Berichte.

> **Falle beim Einbinden:** `source` aus einer Funktion heraus setzt `$@` auf die Argumente der *Funktion*, nicht des Skripts. Deshalb sichert der Runner die Kommandozeile in `NT_ARGV`, bevor er irgendetwas lädt, und `lib/konfig.sh` liest daraus. Ohne das kommt kein einziges Argument an — der Fehler äusserte sich darin, dass `--help` die Root-Prüfung auslöste statt die Hilfe zu zeigen.

---

## Das Modul-Interface: `lib/befunde.sh`

Jede Variable, die ein Modul füllt und ein späteres liest, steht dort mit einem neutralen Vorgabewert. Das ist der gesamte Vertrag zwischen den Modulen.

```bash
JOOMLA_MALWARE=""        # Joomla-typische Schaddateien
JOOMLA_FLAGS=0           # Zähler harter Kompromittierungsindikatoren
JOOMLA_VERDICT="⚪ …"     # Verdikt, falls der Abschnitt nicht lief
```

Der Zweck ist Skip-Sicherheit: Das Skript läuft unter `set -u`. Ein übersprungener Abschnitt hinterlässt seinen Vorgabewert, und der Berichtsteil liest ihn, ohne dass der Lauf abbricht.

**Wer einen neuen Befund einführt, trägt ihn hier ein.** Vergisst man es, bricht der Lauf ab, sobald der Abschnitt einmal übersprungen wird — nicht sofort, sondern irgendwann bei einem Teillauf. Das ist die unangenehmste Fehlerklasse in diesem Aufbau.

Zwei Variablen sind noch echte Abhängigkeiten zwischen Abschnitten: `ATTACK_IPS_UNIQ` (§4 und §12 → §13) und `PKG_MODIFIED` (§8 → §13). Beide sind `${VAR:-}`-abgesichert und degradieren sauber.

---

## Ein Modul hinzufügen

1. Datei unter `module/` anlegen. Die Nummer im Dateinamen bestimmt die Reihenfolge — der Runner iteriert alphabetisch über `module/*.sh`.
2. Kopf setzen. Das Menü und die Auswahl lesen daraus; eine zentrale Liste gibt es bewusst nicht, die würde auseinanderlaufen.

```bash
# NT-Forensik — Abschnitt 15: Beispiel
#
# @nummer:  15
# @titel:   Beispiel-Prüfung
# @frage:   Welche Frage beantwortet dieser Abschnitt?
# @kosten:  gering
# @ebene:   website
```

`@ebene` ist `system`, `website` oder `bericht` und steuert die Gruppierung im Menü sowie `--nur-website`. `@kosten` beginnt mit `HOCH`, wenn der Abschnitt spürbar Zeit kostet — das Menü hebt solche Einträge hervor. Diese Angabe hat im Vorfall auf einem Produktivsystem gefehlt.

3. Ergebnisvariablen in `lib/befunde.sh` mit Vorgabewert eintragen.
4. Ausgabe über die Primitiven aus `lib/kern.sh`: `h2`, `ok`, `info`, `warn`, `crit`, `code`, `evidence`.

**Der zweite Parameter `web` ist tragend:** `crit "…" web` markiert einen Befund als Website-Befund. Nur so markierte Befunde erscheinen im Kundenbericht und zählen in dessen Ampel. Ohne ihn bleibt der Befund Technik- und Betreibersache — richtig für Server- und Root-Ebene, falsch für alles, was den Kunden betrifft.

**Vier Zustände, nicht drei.** `ok` heißt geprüft und in Ordnung, `warn`/`crit` heißen etwas gefunden — und `unklar` heißt: die Prüfung hat kein Ergebnis geliefert. Wer eine Messung schreibt, deren Werkzeug fehlen oder scheitern kann, muss diesen Fall abfangen. Die Regel dazu: **vor der Messung eine Probe, deren Antwort sich prüfen lässt.**

```bash
if ! werkzeug_da occ; then
  unklar "$site: occ nicht vorhanden — Kern-Integrität nicht geprüft" web
else
  probe=$(occ status --output=json 2>/dev/null || true)
  if ! printf '%s' "$probe" | python3 -c 'import json,sys;json.load(sys.stdin)' 2>/dev/null; then
    unklar "$site: occ antwortet nicht verwertbar — Kern-Integrität nicht geprüft" web
  else
    …hier messen…
  fi
fi
```

Ohne diese Trennung landet ein Fehlschlag bei `ok`, weil eine leere Ausgabe wie „nichts gefunden" aussieht. `N_UNKNOWN > 0` blockiert die grüne Ampel im Kundenbericht — ein unberechtigtes `unklar` ist deshalb genauso schädlich wie ein falsches `ok`.

## Ein Modul aufteilen

Wird ein Abschnitt zu groß, um ihn noch chirurgisch zu ändern, bekommt er ein
gleichnamiges Verzeichnis:

```
module/
├── 14_berichte.sh          Metadatenkopf + h1, sonst nichts
└── 14_berichte/            wird nach dem Hauptmodul geladen
    ├── 10_statistik.sh
    ├── 20_kundenbericht.sh
    └── …
```

Der Runner lädt `module/NN_name/*.sh` in Glob-Reihenfolge direkt nach
`module/NN_name.sh` (`modul_teile_laden`). Die Metadaten bleiben am Hauptmodul,
`modul_gewaehlt` entscheidet **einmal für die ganze Gruppe** — `--nur 14` und
`--ohne 12` verhalten sich unverändert. Ein Unterabschnitt ist kein eigener
Abschnitt, sondern ein Stück desselben, und teilt sich dessen Variablen.

Die Nummernpräfixe der Teile bestimmen die Reihenfolge und sind bedeutsam,
wo Teile aufeinander aufbauen: bei §14 bildet `20_kundenbericht.sh` die Ampel,
die `60_pdf.sh` braucht, und `90_ausliefern.sh` maskiert und packt, muss also
zuletzt laufen.

---

## Auswahl und Teilläufe

`modul_gewaehlt` in `lib/kern.sh` entscheidet. `--nur` gewinnt gegen `--ohne`. Abschnitt 14 läuft immer mit, ausser er wird ausdrücklich per `--ohne 14` abgewählt — ein Lauf ohne Bericht und ohne `findings.json` ist praktisch nie gewollt.

**Ein Teillauf weist sich als solcher aus.** Der Technikbericht bekommt einen Kasten mit den nicht ausgeführten Abschnitten und dem ausdrücklichen Hinweis, dass deren Fehlen keine Entwarnung ist. `findings.json` führt `run.vollstaendig`, `run.module_gelaufen` und `run.module_uebersprungen`.

Das ist kein Schönheitsmerkmal: Berichte gehen an Kunden und ans BSI. Eine Teilprüfung, die sich wie ein vollständiges Ergebnis liest, ist schlimmer als gar keine Prüfung.

---

## Auslieferung

Die Selbst-Installation kopiert bei jedem Lauf `signaturen`, `reportgen`, `daten`, `lib` und `module` nach `/root/wartungsscripte/`. `lib` und `module` sind dabei zwingend — ohne sie ist die installierte Kopie nicht lauffähig, weil der Runner nur noch einbindet.

Der Runner lädt alles relativ zum eigenen Verzeichnis (`SELF_DIR`). Damit läuft das Werkzeug aus dem Repository genauso wie aus der installierten Kopie. Fehlt eine Datei, bricht er mit klarer Meldung und Code 3 ab, statt still zu scheitern.

---

## Wie geprüft wird, dass ein Umbau nichts verändert hat

Ein byte-genauer Vergleich des Technikberichts ist **nicht möglich**: die Abschnitte 1, 3, 5, 6, 8 und 9 lesen den Live-Systemzustand (Uptime, Load, Auth-Log, systemd-Timer). Zwei Läufe derselben Fassung unterscheiden sich dort zwangsläufig.

Verglichen wird deshalb, was das Werkzeug **aussagt**, nicht was das System gerade meldet:

| Invariante | Warum |
|---|---|
| `findings.json` vollständig | der maschinenlesbare Vertrag — alle Zähler, Verdikte, Fundpfade |
| Kunden-, BSI-, DSGVO-Bericht vollständig | enthalten keinen Live-Zustand |
| Abschnittsstruktur des Technikberichts | alle Überschriften |
| Befundzeilen | jedes ✅ / ⚠️ / 🔴 |

Zwei Fallstricke, beide real eingetreten:

- **Zeitstempel in Listenausgaben.** `ls -l /proc/*/exe` trägt in jeder Zeile eine Uhrzeit. Ohne Normalisierung sieht jeder Lauf anders aus, obwohl der Inhalt gleich ist.
- **Das Werkzeug sieht sich selbst.** Läuft der Test aus `/tmp`, meldet Abschnitt 8 den eigenen Prozess als „Prozess aus tmp-Verzeichnis" — mal ja, mal nein, je nach Zeitpunkt. Der Prüfaufbau gehört deshalb nach `/root`.

Vor jedem Vergleich zweier Fassungen gehört ein **Selbsttest**: zweimal dieselbe Fassung laufen lassen. Weichen die Ergebnisse ab, ist der Vergleich wertlos und die Normalisierung unvollständig.

---
*netztaucher | digital*
