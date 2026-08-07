# Meldung einer Verletzung des Schutzes personenbezogener Daten (Art. 33 DSGVO)

> **Eigener Meldeweg — nicht mit der BSI-Meldung verwechseln.** Diese Meldung geht
> an die zuständige **Datenschutz-Aufsichtsbehörde** des Bundeslandes, nicht ans BSI.
> Entwurf — vom **Verantwortlichen** zu prüfen und mit `[AUSFÜLLEN]` zu ergänzen.

## Meldepflicht — Einschätzung

🟠 **Meldepflicht prüfen.** Es liegt ein kritischer Befund vor. Ob personenbezogene Daten betroffen sind, muss der/die Verantwortliche bewerten (Art. 33 Abs. 1: Meldung, außer die Verletzung führt voraussichtlich zu keinem Risiko).

| | |
|---|---|
| **Frist** | unverzüglich, **≤ 72 Stunden** ab Kenntnis (Art. 33 Abs. 1) |
| **Bei Überschreitung** | Begründung der Verzögerung beifügen (Art. 33 Abs. 1 S. 2) |
| **Ausnahme** | keine Meldung, wenn die Verletzung **voraussichtlich zu keinem Risiko** für die Rechte und Freiheiten natürlicher Personen führt |
| **Empfänger** | Datenschutz-Aufsichtsbehörde des Bundeslandes des Verantwortlichen |
| **Betroffene benachrichtigen?** | bei **hohem Risiko** zusätzlich Art. 34 (unverzüglich an die Betroffenen) |

## 1. Verantwortlicher (meldende Stelle i. S. d. DSGVO)

| Feld | Angabe |
|---|---|
| Verantwortlicher (Unternehmen) | [AUSFÜLLEN — Betreiber der Website, nicht der Dienstleister] |
| Anschrift | [AUSFÜLLEN] |
| Datenschutzbeauftragter (Name) | [AUSFÜLLEN] |
| DSB Kontakt (E-Mail/Telefon) | [AUSFÜLLEN] |
| Technische Unterstützung | netztaucher | digital |

> **Pflichtangabe Art. 33 Abs. 3 lit. b:** Name und Kontaktdaten des DSB oder einer sonstigen Anlaufstelle.

## 2. Art der Verletzung (Art. 33 Abs. 3 lit. a)

**Sachverhalt (technisch belegt):** Kompromittierung der Website auf dem Server imac. Auffälligkeiten mit möglichem unbefugtem Zugriff.

- **Art:** ☑ Vertraulichkeitsverletzung (unbefugter Zugriff)  ☐ Integritätsverletzung  ☐ Verfügbarkeitsverletzung — [prüfen]
- **Zeitraum:** [AUSFÜLLEN — aus Analyse: Datei-Zeitstempel / Log-Auswertung, siehe technik_bericht.md]

## 3. Betroffene Personen und Datensätze (Art. 33 Abs. 3 lit. a)

> Muss der/die Verantwortliche bewerten — die Forensik liefert nur die betroffenen Systeme.

| Feld | Angabe |
|---|---|
| Kategorien betroffener Personen | [AUSFÜLLEN — z. B. Kunden, Newsletter-Abonnenten, Kontaktanfragen] |
| Ungefähre Zahl betroffener Personen | [AUSFÜLLEN] |
| Kategorien betroffener Daten | [AUSFÜLLEN — z. B. Name, E-Mail, Anschrift, Bestell-/Zahlungsdaten] |
| Ungefähre Zahl betroffener Datensätze | [AUSFÜLLEN] |
| Besondere Kategorien (Art. 9)? | [AUSFÜLLEN — Gesundheit, etc.? i. d. R. nein] |

**Betroffene Datenquellen auf dem Server (aus der Analyse):**
- kunde-zwei.example/httpdocs
- kunde-eins.example/httpdocs
- kunde-eins.example/backup/httpdocs
- kunde-drei.example/httpdocs
- 

## 4. Wahrscheinliche Folgen (Art. 33 Abs. 3 lit. c)

[AUSFÜLLEN — z. B. Risiko von Identitätsdiebstahl, Spam/Phishing gegen Betroffene, Missbrauch von Zugangsdaten. Einschätzung des Risikogrades: gering / mittel / hoch.]

## 5. Ergriffene und vorgeschlagene Maßnahmen (Art. 33 Abs. 3 lit. d)

**Bereits ergriffen (technisch):**
- Forensische Sicherung und Dokumentation (revisionssicher, SHA256), Lauf-ID `<LAUF-ID>`.

- [AUSFÜLLEN — z. B. Passwörter rotiert, Hintertüren entfernt, Domain offline]

**Vorgeschlagen:**
- Rotation aller Zugangsdaten, WordPress-Neuaufbau aus sauberem Backup, Härtung.
- [AUSFÜLLEN — Maßnahmen zur Minderung nachteiliger Folgen für Betroffene]

## 6. Dokumentation (Art. 33 Abs. 5)

Auch wenn keine Meldung erfolgt, ist die Verletzung intern zu dokumentieren. Diese
Analyse (Lauf `<LAUF-ID>`, Belege mit Prüfsummen) erfüllt die technische
Dokumentationsgrundlage. Rechtliche Bewertung und Entscheidung obliegen dem/der Verantwortlichen.

## 7. Anlagen

| Anlage | Pfad |
|---|---|
| Technischer Forensik-Bericht | `technik_bericht.md` |
| BSI-Meldung (separater Meldeweg) | `bsi_meldung.md` |
| Beweismittel inkl. Prüfsummen | `belege/` (SHA256SUMS) |

---
*Entwurf maschinell erstellt am <ZEIT> — wp_plesk_forensik.sh <FASSUNG>, netztaucher | digital.*
*Struktur nach Art. 33 DS-GVO. Ersetzt keine Rechtsberatung — vor Versand durch den Verantwortlichen/DSB prüfen.*
