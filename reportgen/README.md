# NT-Repair — Report-Generator (gebrandetes PDF)

Erzeugt Abschlussberichte im **netztaucher-Design** als PDF: full-bleed Navy-Deckblatt, Orange-Akzent (#ff8800), oranger Titel-Unterstrich, „Bei Fragen"-Block, Seiten-Footer (Logo · Kontakt · VERTRAULICH). Teil 1 (Kundenbericht) + optional Teil 2 (Forensik-Protokoll).

## Pipeline

```
Markdown  ──pandoc──▶  HTML-Fragmente  ──build_report_html.py──▶  gebrandetes HTML  ──weasyprint──▶  PDF
```

Der Seiten-Footer wird über **weasyprint `@page`-Randboxen** (running elements) gesetzt — sitzt zuverlässig am unteren Seitenrand (Chrome `position:fixed` war dafür ungeeignet).

## Voraussetzungen

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

## Verwendung

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

## Markdown-Hinweise

- Normale Markdown-Tabellen, Überschriften, Listen, Blockquotes (→ orange Callout-Box).
- **KPI-Kacheln** im Teil 2: Fenced Div `::: kpigrid` mit einer Liste (jeder Punkt „**Zahl** Label"):
  ```
  ::: kpigrid
  - **40** Domains geprüft
  - **11** Schaddateien
  :::
  ```

## Dateien

- `nt_report_pdf.sh` — CLI-Wrapper (pandoc → build → weasyprint)
- `build_report_html.py` — baut das gebrandete HTML (CSS/Deckblatt/Footer)
- `assets/nt-logo.svg` — Taucher-Logo (Footer + Cover)

---
*netztaucher | digital — proprietär. Vorlage für Abschlussberichte.*
