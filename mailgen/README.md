# mailgen — Kunden-Anschreiben aus dem Forensik-Lauf

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
