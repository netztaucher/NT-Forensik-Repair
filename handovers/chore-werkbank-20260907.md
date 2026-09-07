```json
{
  "format": 2,
  "project": "NT-Forensik-Repair",
  "branch": "chore/werkbank-20260907",
  "sessions": [
    {
      "session_id": "e69f06cf-6280-405c-baa7-6813521762cc",
      "machine": "imac",
      "started": "2026-09-07T06:40:00Z",
      "updated": "2026-09-07T07:25:00Z",
      "topic": "Werkbank eingerichtet — Registry-Einträge für wordpress und NT-Forensik-Repair, Serena-Ursache gefunden, Umzug hierher",
      "status": "final",
      "muninn_id": "01M1XBWBDRVEAAK9WQF6XBHA8C",
      "muninn_available": true,
      "handover_from": "01KZNBFP5X9GP3DVN4Q96Y48FY"
    }
  ]
}
```

<!-- STOP -->

## Warum dieser Record hier liegt

Die Session begann als `/kontext` in einem Worktree des Repos `netztaucher/wordpress`
und endete hier. Der Worktree hieß `nt-repair-forensik-tests` — gemeint war dieses
Repo, angelegt war er im falschen. Drei Viertel der Arbeit fielen in NT-Brain und
`netztaucher/wordpress` an; abgelegt ist der Record dort, wo weitergearbeitet wird.

## Was zuerst zu tun ist

1. **Branch umbenennen.** `chore/werkbank-20260907` ist ein Platzhalter — die Aufgabe
   war beim Anlegen noch nicht genannt.
   ```
   git branch -m chore/<slug>
   ```
2. **Serena-MCP neu starten.** `~/.serena/serena_config.yml` ist repariert, wirkt aber
   erst nach Neustart. Bis dahin keine `get_diagnostics_for_file` — die HARD RULE
   „GitNexus → Serena → GitNexus" ist nur halb erfüllbar.
3. **Alten Worktree entfernen.**
   ```
   git -C /Volumes/daten/Dropbox/_dev/WordPress worktree remove .claude/worktrees/nt-repair-forensik-tests-6e0c52
   ```
   Sauber, 0 unpushed Commits, kein Stash. Kein `--force` nötig.

## Was über dieses Repo zu wissen ist

**Die Prüfstände liegen nicht in `pruefstand/`.** Das Verzeichnis enthält nur
`referenz/`. Die 15 Prüfstände sind Skripte in `werkzeuge/`:

| Art | Dateien |
|---|---|
| `*-pruefstand.sh` | kern, baumscan, lizenz, inventar, kundenpaket, auswahl, bericht, schnittstelle |
| `*_selbsttest.sh` | doorway, zeilenenden, zerlegte, hub_sso, injektion_einordnung, haertung, lizenzschluessel, zweitquelle |
| Gegentest | `version_compare_gegentest.sh` |

CI: `.github/workflows/pruefung.yml` und `schwachstellen-bestand.yml`.

**`netztaucher/NT-Forensik` existiert nicht mehr** — GitHub liefert 404. Die Org hat
nur noch dieses Repo (Analyse quelloffen, Bereinigung lizenzgebunden) und
`NT-Repair` (privater Bereinigungs-Orchestrator auf Basis von `findings.json`).
Der GitNexus-Index führt `NT-Forensik` aber weiter mit Stand 2026-08-06, 50 Dateien.
Wer über den Index dorthin sucht, landet auf einem Repo, das es nicht gibt.
**Diese Karteileiche ist noch nicht beseitigt.**

## Was diese Session geliefert hat

Alles gemerged.

| PR | Inhalt |
|---|---|
| [nt-brain#686](https://github.com/netztaucher/nt-brain/pull/686) `791f2d93` | Registry-Eintrag `WordPress` → `netztaucher/wordpress`, `repo_id R_kgDOSmcmiQ` |
| [nt-brain#687](https://github.com/netztaucher/nt-brain/pull/687) `c62d66a5` | Registry-Eintrag `NT-Forensik-Repair`, `repo_id R_kgDOTz-Cyg` |
| [wordpress#7](https://github.com/netztaucher/wordpress/pull/7) `c112078a1` | 10 Sync-Konfliktkopien aus Git, Ignore-Regeln, `handovers/`, HANDOVER.md geprüft |

Vor beiden Registry-Einträgen lief `/kontext` in den „kein Match"-Stopp aus §0.

## Drei Handgriffe, die sich wiederholen werden

**Ein Registry-Eintrag genügt.** `core/bin/generate-tool-configs.py` erzeugt daraus
automatisch `.serena/project.yml` im Ziel-Repo *und* den Eintrag in
`core/bin/gitnexus-analyze-all.sh`. Kein Handklonen, keine zweite Pflegestelle.

**Vor JSON-Edits an `registry.json` den Round-Trip prüfen.** Erst testen, ob
`json.dumps(d, indent=2, ensure_ascii=False) + "\n"` das Original byte-genau
reproduziert. Tut es das nicht, formatiert der Edit die ganze Datei um und der Diff
wird unlesbar.

**Dirty fremder Arbeitsbaum: Blob-Hashes statt Bauchgefühl.** NT-Brain `main` hing
6 Commits zurück und trug uncommitteten WIP einer parallelen infra-Session. Gebaut
wurde deshalb in einem eigenen Worktree von `origin/main`. Beim Nachziehen zeigte
der Vergleich `git hash-object <f>` gegen `git rev-parse origin/main:<f>`, dass 4
der 5 schmutzigen Dateien byte-identisch waren — gefahrlos verwerfbar.
`core/steering/workflows/wissen.md` blieb stehen: 13 echte Zeilen, und `origin/main`
fasst die Datei ohnehin nicht an.

## Weitere offene Punkte

- **`NT-WP-Templates/.venv`** hängt mit 1069 Dateien im Index von
  `netztaucher/wordpress`. Ein komplettes virtualenv in Git — eigener PR, eigene
  Entscheidung.
- **Fremder WIP in NT-Brain**: 13 Zeilen in `core/steering/workflows/wissen.md` plus
  untracktes `projects/infra/` warten weiter auf einen Commit der infra-Session.
