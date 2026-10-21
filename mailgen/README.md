# mailgen — Kunden-Anschreiben

Zwei Werkzeuge für zwei Anlässe:

| Werkzeug | Anlass |
|---|---|
| `anschreiben.py` | **Abschluss eines Vorfalls** (Standard vom 21.10.2026, #151): kurzes HTML-Anschreiben zum Kundenpaket, Apple-Mail-Entwurf in einem Schritt |
| `mailgen.py` | **Erstkontakt** bei einem Fund: dringliches Anschreiben mit Angebot (Forensik → Bereinigung) |

## anschreiben.py — Abschluss eines Vorfalls

```bash
mailgen/anschreiben.py --fall fall.json --ziel <ordner> \
    --anhang NT-Sicherheitsbericht_….pdf --anhang NT-Dokumentation_DSGVO-Art33_….pdf \
    --anhang NT-Einordnung_BSI-Meldung_….pdf \
    --bildschirmfoto https://kunde.tld [--bild vorhanden.png] [--apple-mail]
```

- **Kurz:** rund 150 Wörter (Prüfung schlägt über 190 an). Anrede, Ergebnis, Ursache in
  einem Satz, ein Kasten „Bitte heute“ mit höchstens drei Punkten, „Meldepflicht“ in
  zwei bis drei Sätzen, Gruss, Adresszeile.
- **Sprache:** Sie-Form, normale Gross-/Kleinschreibung (Abweichung von der
  Brandvoice-Kleinschreibung, Entscheidung Marco für Sie-Kunden mit Vorfall), kein ß,
  keine Gedankenstriche.
- **Layout:** Tabellen und Inline-Stile, Farben aus NT Docs (Kasten `#fff1e0`, Label
  `#a85400`/`#003366`), kein Kopf, kein Logo. Text-Alternative mit gleichem Inhalt.
- **Inhalt** aus dem Abschnitt `mail` der Fall-Datei (`an`, `betreff`, `anrede`,
  `ergebnis`, `ursache`, `bitte_heute`, `meldepflicht`, `gruss`); was fehlt, wird aus
  Bericht und DSGVO-Abschnitt abgeleitet. Fragen, die den Kunden nicht betreffen oder
  geklärt sind, gehören in den Bericht, nicht in die Mail.
- **Bildschirmfotos** der laufenden Startseiten: `--bildschirmfoto <url>` nimmt sie mit
  Chrome headless in 1440×1000 auf. Der Satz „… laufen wieder, wie die zwei
  Bildschirmfotos von heute im Anhang zeigen“ passt sich der Zahl an.
- **Ergebnis:** `anschreiben.html`, `anschreiben.txt`, `anschreiben.eml` (Archiv, Ansicht)
  und `anschreiben_entwurf.applescript`. Danach prüft `werkzeuge/interna-waechter.sh`
  die Mail.

### Apple-Mail-Entwurf (gemessen 21.10.2026)

- Der Entwurf entsteht nur über `make new outgoing message` + `set html content` +
  **alle Anhänge im selben Skriptlauf**, dann genau ein `save`. Jedes weitere Speichern
  per Skript behält nur die Anhänge dieses Laufs. `--apple-mail` führt genau dieses
  Skript aus, und nur, wenn die Prüfung grün ist; gesendet wird nie.
- Eine `.eml` mit `X-Unsent: 1` öffnet Mail nur als Ansicht, nicht als Entwurf.
- „Erneut senden“ per UI ist für Agenten gesperrt (der Auto-Modus wertet es als Senden).
- Mail verkleinert angehängte PNG auf 1280 px Breite.
- Prüfen über die Quelle des gespeicherten Entwurfs: Anhänge per sha256 gegen den Ordner.

## mailgen.py — Erstkontakt

Erzeugt aus einem NT-Forensik-Lauf eine versandfertige **`.eml`** (Apple-Mail-
Format): dringliches, freundliches Kundenanschreiben zum Sicherheitsvorfall,
mit beiden Banner-Grafiken inline und den beiden Arbeitsschritten (Forensik →
Bereinigung).

## Verwendung

```bash
python3 mailgen.py kunde.json      # Config aus JSON
python3 mailgen.py                 # eingebautes Beispiel
```

Ergebnis: `anschreiben_<domain>.eml` (in Apple Mail per Doppelklick öffnen,
prüfen, senden) + `anschreiben_<domain>.preview.html` zum Ansehen.

## Config

```json
{
  "findings": "…/forensik/<lauf>/findings.json",
  "domain": "echte-kundendomain.de",
  "recipients": [{"name": "Herr/Frau Nachname", "email": "kunde@domain.de"}]
}
```

- **`findings`** (optional): Pfad zu einer `findings.json` (Tool ab v3.7,
  schema ≥ 1.3). Daraus werden **`affected_area`**, **`finding_summary`**,
  **`timeframe`** und **`has_shop`** automatisch aus `malware_summary` befüllt.
- **`domain`**: echte Kundendomain (die `findings.json` kennt nur den internen
  vhost-Namen) — überschreibt den Wert aus dem Lauf.
- **`recipients`**: Empfänger (To-Header).

Felder lassen sich in der Config auch **manuell** setzen (überschreibt die
Auto-Befüllung): `affected_area`, `finding_summary`, `timeframe`, `has_shop`.

## Variable vs. fixer Text

Variabel: Domain, Empfänger, Bereich, Fund, Zeitbezug (Letztere drei aus dem
Lauf). Fix: die beiden Schritte, Banner, 199-€-Block, Signatur/Impressum.

## Abhängigkeiten

Nur Python-Standardbibliothek. Der Ordner `assets/` (forensik.png, repair.png)
muss neben `mailgen.py` liegen.
