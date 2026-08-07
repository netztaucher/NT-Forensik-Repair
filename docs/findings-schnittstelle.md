# findings.json — die Schnittstelle zu NT-Repair

`findings.json` ist nicht nur Ausgabe, sondern **Vertrag**. NT-Repair liest die Datei
und leitet daraus ab, was bereinigt wird. Eine Umbenennung oder ein entfernter Pfad
bricht dort etwas, ohne dass in diesem Repo ein Test fehlschlägt.

Geschrieben von [`module/14_berichte/50_findings_json.sh`](../module/14_berichte/50_findings_json.sh)
in `emit_findings_json()`.

**Ablageort ab v3.11:** `<LAUF>/betreiber/findings.json` — nicht mehr flach im Laufordner.
Die Datei enthält absolute Pfade und wird bewusst **nicht** maskiert, weil der
Reparaturteil die echten Pfade braucht. Sie gehört damit in die Betreiberspur und
nicht in die Kundenübergabe.
Aktuelle Fassung: **schema_version 1.7**.

## Was sich in 1.6 und 1.7 geändert hat

Alles additiv — bestehende Leser brechen nicht.

| Feld | Seit | Bedeutung |
|---|---|---|
| `actionable.htaccess_fremd` | 1.6 | `.htaccess`-Dateien mit Angreifer-Direktiven |
| `htaccess_unwirksam` | 1.6 | Grund, warum `.htaccess` gar nicht ausgewertet wird (leer = wird ausgewertet) |
| `befunde` | 1.7 | Befunde nach Anwendung und Kategorie, **mit Pfad** |
| `verdikte` | 1.7 | Verdikt je Anwendung, `{flags, text}` |

### `befunde` — das generische Schema

```json
"befunde": {
  "nextcloud": {
    "haertung": [
      {"schwere": "unklar",
       "text": "…: occ nicht ausführbar — Härtungsstand nicht messbar",
       "pfad": "/var/www/vhosts/…/cloud.example"}
    ]
  }
}
```

Die **Kategorien sind fest**: `erkennung version kern konfig datenbank schadcode
logs haertung verdikt`. Die **Anwendungen sind frei** — ein neuer Scanner für
TYPO3 oder Shopware taucht hier auf, ohne dass am Kern etwas geändert wird.

`schwere` ist `crit`, `warn` oder `unklar`. **`ok` steht bewusst nicht drin:**
unauffällige Einzelbefunde sind der Normalfall und würden die Datei um ein
Vielfaches aufblähen; ihre Zahl steht in `counts.ok`.

**`pfad` ist der eigentliche Zweck.** Er erlaubt es, einen Befund exakt einem
Verzeichnis zuzuordnen — Grundlage sowohl für die Bereinigung als auch für den
Datenschutz-Riegel, der entscheidet, ob ein Befund in die Kundenspur darf.

### Migration

Die anwendungsspezifischen Listen unter `actionable` (`nextcloud_malware`,
`joomla_*`, `wp_configs` …) bleiben vorerst **parallel** bestehen und werden je
Modul abgelöst, sobald es ohnehin angefasst wird. Ein Leser sollte neu
geschriebenen Code gegen `befunde` bauen; `actionable` bleibt lesbar, bis die
Migration abgeschlossen ist.

## Was sich in 1.5 geändert hat

Zwei neue Felder, beide **additiv** — bestehende Leser brechen nicht.

| Feld | Typ | Bedeutung |
|---|---|---|
| `counts.unknown` | Zahl | Prüfungen, die kein Ergebnis geliefert haben |
| `run.nicht_messbar` | Liste | welche das waren, im Klartext |

**Warum das für den Reparaturteil zählt:** bis 1.4 war eine gescheiterte Messung
von einem sauberen Befund nicht zu unterscheiden. Scheiterte `wp core
verify-checksums`, war die Ausgabe leer, leer galt als „nichts gefunden", und der
Bericht bescheinigte einen unveränderten Kern, der nie geprüft wurde. Ein Lauf, in
dem *jede* Messung scheiterte, endete auf 🟢 UNAUFFÄLLIG.

Ein Leser darf einer Entwarnung deshalb nur trauen, wenn `counts.unknown == 0` ist:

```bash
if [[ "$(jq '.counts.unknown' findings.json)" -gt 0 ]]; then
  echo "Teilergebnis — nicht als Entwarnung behandeln:"
  jq -r '.run.nicht_messbar[]' findings.json
fi
```

`run.nicht_messbar` und `run.module_uebersprungen` sind nicht dasselbe:
Übersprungen wurden ganze Abschnitte **auf Anweisung** (`--nur`/`--ohne`), nicht
messbar sind Einzelprüfungen, die laufen **sollten** und nichts lieferten.

## Wer liest was

Drei Programme in NT-Repair greifen zu. Die folgenden Pfade sind belegt — sie stehen
so im Quelltext und dürfen nicht ohne Anpassung dort wegfallen.

### `nt_repair.sh` — die Bereinigung selbst

| Pfad | Verwendung |
|---|---|
| `run_id` | Verknüpfung des Repair-Laufs mit dem Forensik-Lauf |
| `host` | Zielserver, wenn `--host` fehlt |
| `domain` | Kundendomain im Protokoll |
| `verdicts.root.flags` | Schweregrad — steuert das zweistufige Freigabemodell |
| `actionable.webshell_dropper` | Quarantäne-Kandidaten |
| `actionable.php_in_uploads` | Quarantäne-Kandidaten |
| `actionable.suid` | Quarantäne-Kandidaten |
| `actionable.tmp_executables` | Quarantäne-Kandidaten |
| `actionable.immutable` | Quarantäne-Kandidaten |
| `actionable.ioc_ips.attacker` | IP-Sperren |
| `actionable.ioc_ips.ssh_bruteforce` | IP-Sperren |

### `lib/gen_report.sh` — die drei Berichte

`verdicts.root.flags`, `verdicts.root.text`, `verdicts.wpdb.text`,
`metrics.webshell_count`, `metrics.injected_core_files`, `metrics.doorway_dirs`,
`metrics.rogue_wp_admins`

### `lib/statusmail.py` — die Statusmail nach der Reparatur

`domain`, `verdicts.root`, `metrics` — und aus dem **Kontrolllauf**
(zweites findings.json, nach der Bereinigung erhoben): `counts`,
`run.vollstaendig`, `run.module_uebersprungen`.

Die letzten beiden entscheiden, ob die Mail Entwarnung geben darf. Ein Teillauf
(`--nur`, `--ohne`, `--nur-joomla`) setzt `run.vollstaendig` auf `false`, und die
Mail sagt das dann ausdrücklich. Fällt das Feld weg, liest sich ein Teillauf
stillschweigend wie ein vollständiger Freispruch — der Fehlerfall, der zählt.

## Regeln für Änderungen

- **Feld hinzufügen** — unkritisch, kein Schema-Bump nötig. Beide Seiten lesen
  defensiv (`.get(...) or {}` bzw. `|| echo ""`).
- **Feld umbenennen oder entfernen** — Schema-Bump **und** Anpassung in NT-Repair,
  im selben Zug. Die Tabelle oben ist die Prüfliste.
- **Typ ändern** (Zahl → Zeichenkette, Objekt → Feld) — dasselbe. `verdicts.*.flags`
  wird auf beiden Seiten als Zahl verglichen.

Gegenprobe nach jeder Änderung an `emit_findings_json()`:

```bash
python3 -m json.tool < /root/wartungsscripte/forensik/<LAUF>/betreiber/findings.json > /dev/null
```

Ungültiges JSON fällt sonst erst bei NT-Repair auf — und dort still, weil die
Lesefunktionen Fehler abfangen und leer zurückgeben. Genau das ist in v3.8 passiert:
Tabulatoren aus `mysql -N` machten die Datei ungültig, und zwar ausgerechnet dann,
wenn es echte Funde gab.
