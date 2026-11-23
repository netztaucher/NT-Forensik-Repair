# reportgen — Kundenpaket im Berichtslayout NT Dokumente

Erzeugt aus einem Forensik-Lauf die drei Kundendokumente nach dem Standard vom
21.10.2026 (#149, Playbook [Phase 5](../docs/incident-response.md#kundenpaket--standard-seit-21102026)),
seit 23.11.2026 im **Berichtslayout** des Designsystems NT Dokumente (Komponente Bericht,
freigegeben von Marco; das frühere Layout mit Kopfband und Statuskarten ist abgelöst, #160):

| Datei | Inhalt |
|---|---|
| `NT-Sicherheitsbericht_<Kunde>_<Datum>.pdf` | Briefkopf, Vermerk, Adress-Cards (Auftraggeber, Ersteller mit Vorgangsnummer und Kenntnis), Überschrift und Lead; 1 Zusammenfassung, 2 Bewertung, 3 Ablauf, 4 Ergriffene Massnahmen, 5 Erforderliche nächste Schritte (Kasten „Vordringlich“), 6 Meldepflichten, Unterschrift; Anhang „Technisches Protokoll“ auf eigener Seite |
| `NT-Dokumentation_DSGVO-Art33_<Kunde>_<Datum>.pdf` | genau 2 Seiten: Verantwortliche/Auftragsverarbeiter, Ergebnis, 1 Zeitpunkte, 2 Angaben nach Art. 33 Abs. 3 a bis d mit Ausfüllfeldern, 3 Prüfung, 4 Abwägung, 5 Entscheidung mit Unterschrift |
| `NT-Einordnung_BSI-Meldung_<Kunde>_<Datum>.pdf` | genau 2 Seiten: Ergebnis, 1 Einordnung (KRITIS, NIS2, freiwillig), 2 Angaben für eine freiwillige Meldung, 3 Indikatoren (IOC), Meldeweg |

Jede Seite trägt den Geschäftsfuss (Anschrift, Handelsregister, Kontakt, „Vertraulich“,
„Seite x von y“).

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
Regelfehler, 3 Interna-Wächter schlägt an, 4 Entwurf (Protokoll ungeprüft, siehe unten).
Bei 2, 3 und 4 liegen die PDFs zur Ansicht vor, nicht zur Auslieferung.

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

So landen die Felder im Layout:

| Feld | Stelle |
|---|---|
| `kunde.name`, `zeilen`, `rolle`, `email` | Adress-Card Auftraggeber (DSGVO: Verantwortliche) |
| `ansprechpartner` (`name`, `funktion`, `firma`, `telefon`, `email`) | Adress-Card Ersteller, Unterschrift |
| `vorgang` | Vorgangsnummer (sonst `SV-<Datum>-01`) |
| `bericht.titel` bzw. `bericht.ueberschrift` | Überschrift; `bericht.lede` der Lead darunter |
| `bericht.kicker` bzw. `bericht.untertitel` | Untertitel im Briefkopf (Teil nach „·“, dazu „Stand …“) |
| `bericht.vermerk`, `dsgvo.vermerk`, `bsi.vermerk` | Vertraulichkeitsvermerk unter der Haarlinie |
| `bericht.kurz` (`absaetze`, `hinweis`, `nach`) | 1 Zusammenfassung, `hinweis` als Kasten |
| `bericht.bewertung`, `ablauf`, `erledigt` | 2 Bewertung, 3 Ablauf, 4 Ergriffene Massnahmen |
| `bericht.jetzt`, `aufgaben`, `aufgaben_hinweis` | 5 Nächste Schritte |
| `bericht.meldepflichten` | 6 Meldepflichten |
| `bericht.protokoll.abschnitte` (`titel`, `meta`, `absaetze`, `tabelle`, `checks`, `fussnote`) | Anhang A.1, A.2, … |
| `dsgvo.titel`/`ergebnis`, `art`, `personen`, `personen_text`, `massnahmen`, `pruefliste`, `abwaegung`, `einordnung` | DSGVO-Dokument; optional `zeitpunkte`, `beginn`, `zahl`, `kontakt`, `folgen` |
| `bsi.titel`/`ergebnis`, `status`, `gruende`, `angaben`, `auswirkung`, `massnahmen`, `merkmale`/`iocs`, `hinweis` | BSI-Dokument |

Gelesen, aber im Berichtslayout nicht mehr gedruckt: `bericht.meta`, `bericht.status`,
`bericht.wichtigste`, `bericht.protokoll.kacheln`, `dsgvo.status`.

### Protokoll prüfen, nicht übernehmen (Entwurf-Sperre)

Ohne Fall-Datei kommt der Anhang aus dem, was der Lauf einordnet, Fehlalarme
eingeschlossen (Vorfall vom 23.11.2026: ein gewöhnliches PDF als Schadcode, das bekannte
Einfallstor als „nicht belegt“). Darum gilt der Anhang nur als geprüft, wenn die Fall-Datei

- `bericht.protokoll` mit dem geprüften Protokoll liefert, oder
- `"protokoll_geprueft": true` unter `bericht` setzt (die Liste aus dem Lauf stimmt).

Sonst sind alle drei Dokumente ein **Entwurf**: Vermerk „Entwurf · … · nicht zur
Auslieferung“, roter Kasten „Automatisch, ungeprüft“ im Anhang, Rückgabe 4.
`werkzeuge/kundenpaket.sh` erkennt den Vermerk und baut kein Paket.

## Satz und Prüfung (`bericht_satz.py`)

- WeasyPrint setzt im Fluss: Abschnitte brechen frei um, Tabellenköpfe wiederholen sich,
  Kästen, Adress-Cards und Unterschrift bleiben zusammen, der Anhang beginnt auf einer
  eigenen Seite. Der Geschäftsfuss ist ein laufendes Element im Seitenrand, „Seite x von
  y“ zählt WeasyPrint.
- **Geprüft wird das gesetzte Dokument:** Geschäftsfuss auf jeder Seite, nichts ragt über
  den rechten Satzspiegel (lange Hashes, Pfade), DSGVO und BSI genau 2 Seiten,
  Sprachregeln (kein ß, keine Gedankenstriche, keine geraden Anführungszeichen, keine
  Emoji).
- Seitenbilder (`pdftoppm`) je Seite unter `--pruefung/seiten/` — **ansehen muss sie ein
  Mensch**, bevor das Paket rausgeht.
- Danach `werkzeuge/interna-waechter.sh` über alle drei PDFs (#150).

## Layout (`bericht/`)

`bericht/bericht.css` setzt die Komponente Bericht aus dem Designsystem NT Dokumente für
WeasyPrint um, dazu Schriften und Logo. Herkunft, Abweichungen und Prüfsummen in
[`bericht/QUELLE.md`](bericht/QUELLE.md). Geändert wird im Designsystem, danach hier
nachziehen und den Prüfstand laufen lassen.

## Voraussetzungen

- **WeasyPrint** im venv (PEP 668), dazu `pdftoppm`/`pdftotext` (poppler):
  ```bash
  python3 -m venv ~/.venvs/weasyprint
  ~/.venvs/weasyprint/bin/pip install weasyprint
  brew install pango poppler        # macOS; Debian: apt install poppler-utils
  ```
  Gefunden wird das Python über `$NT_WEASYPRINT_PY`, sonst den Interpreter hinter
  `$WEASYPRINT` bzw. `weasyprint` im PATH, sonst `~/.venvs/weasyprint/bin/python`.
  Die Schriften liegen im Repo, nichts wird nachgeladen.

## Prüfstand

```bash
werkzeuge/kundenpaket-pruefstand.sh
```

Echter Lauf über den Goldmuster-Baum plus Fixture: drei PDFs, Seitenzahlen, Geschäftsfuss,
Seitenbilder, fremder Kunde bleibt draussen, Interna grün und rot (eingeschleuster
Issue-Verweis), Entwurf-Sperre (Rückgabe 4, kein Paket), Anschreiben, Übergabepaket.
Braucht WeasyPrint und poppler. Die CI installiert beides (venv mit `weasyprint==70.0`,
`poppler-utils`) im Job „Zwei Läufe“ und lässt den Prüfstand dort laufen; den Wächter
allein prüft zusätzlich `werkzeuge/interna_waechter_selbsttest.sh`.

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
