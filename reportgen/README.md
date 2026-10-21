# reportgen — Kundenpaket im Designsystem NT Docs

Erzeugt aus einem Forensik-Lauf die drei Kundendokumente nach dem Standard vom
21.10.2026 (#149, Playbook [Phase 5](../docs/incident-response.md#kundenpaket--standard-seit-21102026)):

| Datei | Inhalt |
|---|---|
| `NT-Sicherheitsbericht_<Kunde>_<Datum>.pdf` | Seite 1 Ergebnis (Kopfband, drei Statuskarten, Das Wichtigste, Kunde/Ansprechpartner, Was Sie jetzt tun sollten), Teil 1 Kundenbericht (Sie) in sechs Kapiteln, Teil 2 Protokoll in nummerierten Abschnitten bis „Offene Punkte“ |
| `NT-Dokumentation_DSGVO-Art33_<Kunde>_<Datum>.pdf` | 2 Seiten: Ergebnis, Prüfliste, Verantwortlicher/Auftragsverarbeiter, Einordnung mit Frist; Angaben nach Art. 33 Abs. 3, Abwägung, Unterschriftsfeld |
| `NT-Einordnung_BSI-Meldung_<Kunde>_<Datum>.pdf` | 2 Seiten: KRITIS, NIS2 (Schwellen mit Stand), freiwillig; alle Angaben für eine freiwillige Meldung |

## Aufruf

```bash
reportgen/kundenpaket.py --lauf <lauf-ordner> --ziel <ordner> \
    [--fall fall.json] [--pruefung <ordner>] [--entwurf fall.entwurf.json]
```

Der Forensik-Lauf ruft das selbst auf (`module/14_berichte/60_pdf.sh`): PDFs nach
`kunde/`, Seitenbilder und Prüfbericht nach `betreiber/kundenpaket_pruefung/`, die
zusammengeführte Fall-Datei nach `betreiber/kundenpaket_fall.entwurf.json`. Eine
Fall-Datei für den Lauf: `NT_KUNDENFALL=<datei>`. Prüfstand-Läufe (`NT_TESTLAUF=1`)
bauen kein PDF, ausser mit `NT_KUNDENPAKET_IM_TESTLAUF=1`.

Rückgabe: 0 regelgerecht und ohne Interna, 1 Aufruf-/Lauffehler, 2 Satz- oder
Regelfehler, 3 Interna-Wächter schlägt an. Bei 2 und 3 liegen die PDFs zur Ansicht vor,
nicht zur Auslieferung.

## Inhalt: Lauf und Fall-Datei

1. **Aus dem Lauf** (`betreiber/findings.json`, `betreiber/kundenpaket_funde.tsv`):
   Websites, Funde mit Pfad ab der Dokumentenwurzel und SHA-256, Angreifer-Adressen,
   Einstiegsweg, Zeitachse, Zahl der Prüfungen ohne Ergebnis. Nur was im Prüfumfang
   (`run.scan_paths`) liegt — andere Kunden des Servers kommen nicht vor. Ein
   Betreiberlauf (`scope_mode=global`) wird abgelehnt.
2. **Aus der Fall-Datei** (`--fall`): Kunde, Erzählung, Bereinigung (`"bereinigt": true`),
   Aufgaben mit Frist, Meldepflicht, DSGVO- und BSI-Angaben, Mail. Jeder Schlüssel
   überschreibt den Wert aus dem Lauf (Objekte rekursiv, Listen ganz). Muster:
   [`pruefstand/kundenpaket/fall.json`](../pruefstand/kundenpaket/fall.json).
   Text darf `**fett**` und `` `mono` `` (Hashes, IPs, Pfade) enthalten.

## Satz und Prüfung (`ntdocs_satz.py`)

- Feste A4-Seiten (`div.nt-page`), nur Klassen aus `ntdocs/components/bundle.css`.
- **Gemessen statt geschätzt:** jeder Baustein wird einmal gesetzt und gemessen, dann
  auf Seiten verteilt. Tabellen und Listen brechen zwischen Zeilen um (Kopf wird
  wiederholt, nie eine einzelne Zeile allein), Abschnitte laufen über Folgeseiten.
- **Geprüft wird das fertige PDF:** Seitenzahl wie geplant, Inhalt ≥ 8 mm über der
  Fusszeile, Titel einzeilig, „Seite x von y“ automatisch, DSGVO/BSI genau 2 Seiten,
  Sprachregeln (kein ß, keine Gedankenstriche, keine geraden Anführungszeichen, keine
  Emoji). Läuft eine Seite über, wird sie gekürzt und neu gesetzt.
- Seitenbilder (`pdftoppm`) je Seite unter `--pruefung/seiten/` — **ansehen muss sie ein
  Mensch**, bevor das Paket rausgeht.
- Danach `werkzeuge/interna-waechter.sh` über alle drei PDFs (#150).

Bekannte Fallen (gemessen, #149): `Nummernliste` setzt in WeasyPrint die Ziffer über den
Text — Abläufe stehen deshalb als Tabelle. `Anlagenkopf` erzwingt einen Seitenumbruch —
Teil 2 nutzt `Seitenkopf`/`nt-pagehead is-linie`. `.nt-gap` und `nt-state` in
Tabellenzellen sind ab NT Docs v30 behoben; die Kopie unter `ntdocs/` ist neuer.

## NT Docs

`ntdocs/` ist eine Kopie des Designsystems (Tokens, Komponenten, Schriften, Logos,
Icons), Herkunft und Prüfsummen in [`ntdocs/QUELLE.md`](ntdocs/QUELLE.md). Geändert wird
im Designsystem, nicht hier; danach die Kopie neu holen.

## Voraussetzungen

- **WeasyPrint** im venv (PEP 668), dazu `pdftoppm`/`pdftotext` (poppler):
  ```bash
  python3 -m venv ~/.venvs/weasyprint
  ~/.venvs/weasyprint/bin/pip install weasyprint
  brew install pango poppler        # macOS; Debian: apt install poppler-utils
  ```
  Gefunden wird das Python über `$NT_WEASYPRINT_PY`, sonst den Interpreter hinter
  `$WEASYPRINT` bzw. `weasyprint` im PATH, sonst `~/.venvs/weasyprint/bin/python`.

## Prüfstand

```bash
werkzeuge/kundenpaket-pruefstand.sh
```

Echter Lauf über den Goldmuster-Baum plus Fixture: drei PDFs, Seitenzahlen, Seitenbilder,
fremder Kunde bleibt draussen, Interna grün und rot (eingeschleuster Issue-Verweis),
Anschreiben, Übergabepaket. Braucht WeasyPrint und poppler. Die CI installiert beides
(venv mit `weasyprint==70.0`, `poppler-utils`) im Job „Zwei Läufe“ und lässt den Prüfstand dort
laufen; den Wächter allein prüft zusätzlich `werkzeuge/interna_waechter_selbsttest.sh`.

---

## Altlayout: `nt_report_pdf.sh`

Der frühere Generator für Abschlussberichte im alten netztaucher-Design (Navy-Deckblatt,
Markdown über pandoc). **Vom Forensik-Lauf nicht mehr benutzt** (bis 21.10.2026 als
`kunde/abschlussbericht.pdf`); er bleibt für Berichte stehen, die noch darauf aufbauen.

### Pipeline

```
Markdown  ──pandoc──▶  HTML-Fragmente  ──build_report_html.py──▶  gebrandetes HTML  ──weasyprint──▶  PDF
```

Der Seiten-Footer wird über **weasyprint `@page`-Randboxen** (running elements) gesetzt — sitzt zuverlässig am unteren Seitenrand (Chrome `position:fixed` war dafür ungeeignet).

### Voraussetzungen

- **pandoc**
- **weasyprint** (venv empfohlen wegen PEP 668):
  ```bash
  python3 -m venv ~/.venvs/weasyprint
  ~/.venvs/weasyprint/bin/pip install weasyprint
  # macOS: pango/cairo via Homebrew
  brew install pango gdk-pixbuf
  export WEASYPRINT=~/.venvs/weasyprint/bin/weasyprint
  export DYLD_FALLBACK_LIBRARY_PATH=/opt/homebrew/lib   # macOS
  ```
  `nt_report_pdf.sh` findet weasyprint über `$WEASYPRINT` oder PATH.

### Verwendung

```bash
./nt_report_pdf.sh \
  --teil1 kundenbericht.md \
  --teil2 protokoll.md \
  --title 'Sicherheitsvorfall\nUntersuchung & Bereinigung' \
  --domain 'kunde.de' \
  --subtitle 'Server srv.tld — Abschlussbericht · 08.07.2026' \
  --meta 'Forensik-Lauf=<id>' --meta 'Repair-Lauf=<id>' --meta 'Einstufung=Bereinigt' \
  --intro 'Kurzer Einleitungssatz für das Deckblatt.' \
  --out NT-Sicherheitsbericht.pdf
```

**Argumente:** `--teil1` (Pflicht, Markdown), `--teil2` (optional), `--out`, `--title` (`\n` = Umbruch), `--domain`, `--subtitle`, `--meta Label=Value` (wiederholbar → Deckblatt-Zeile), `--intro`, `--eyebrow`, `--teil1-label`, `--teil2-label`, `--kontakt-tel`, `--kontakt-mail`.

### Markdown-Hinweise

- Normale Markdown-Tabellen, Überschriften, Listen, Blockquotes (→ orange Callout-Box).
- **KPI-Kacheln** im Teil 2: Fenced Div `::: kpigrid` mit einer Liste (jeder Punkt „**Zahl** Label"):
  ```
  ::: kpigrid
  - **40** Domains geprüft
  - **11** Schaddateien
  :::
  ```

### Dateien

- `nt_report_pdf.sh` — CLI-Wrapper (pandoc → build → weasyprint)
- `build_report_html.py` — baut das gebrandete HTML (CSS/Deckblatt/Footer)
- `assets/nt-logo.svg` — Taucher-Logo (Footer + Cover)

---
*netztaucher | digital — proprietär. Vorlage für Abschlussberichte.*
