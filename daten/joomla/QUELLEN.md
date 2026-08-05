# Datenherkunft und Lizenzen — Joomla-Datenbestand

NT-Forensik steht unter **MIT** und ist öffentlich. Eine GPL-lizenzierte Datei
im Repository wäre eine Lizenzkollision. Diese Tabelle ist der Nachweis, woher
jede Datei stammt und warum sie hier liegen darf.

**Grundsatz:** Übernommen werden nur **Tatsachen** — Name, Version, Status,
CVE-Nummer, Verweis. Kein Beschreibungstext aus fremden Quellen. Tatsachen
sind nicht urheberrechtlich geschützt, formulierter Fließtext schon.

| Datei | Quelle | Lizenz der Quelle | Was übernommen wurde | Stand |
|---|---|---|---|---|
| `vel/vel.tsv` | Liste verwundbarer Erweiterungen, `extensions.joomla.org` (`option=com_vel&format=json`) | **GNU/GPL**, laut Anbieter ausdrücklich auch in kommerziellen Erweiterungen nutzbar | Elementname, Typ, Ordner, Paketname, korrigierte Fassung, Status, CVE-Nummer, Verweis-URL. **Kein** `description`-Text. | 2026-08-05 |
| `vel/alias.tsv` | eigene Zuordnungstabelle | — | vollständig selbst erstellt | Handpflege |
| `vel/VERIFY` | Prüfsumme desselben Feeds | wie oben | reine Prüfsumme | 2026-08-05 |
| `cve/joomla-core.tsv` | Sicherheitszentrum des Joomla Security Strike Team (`developer.joomla.org`) | keine ausdrückliche Angabe | Versionsbereiche, CVE-Nummer, Schwere, Angriffsart. Beschreibungstexte werden **nicht** übernommen. | 2026-08-05 |
| `cve/joomla-ext-kritisch.tsv` | Herstellerwarnungen, Katalog bekannt ausgenutzter Schwachstellen der CISA, öffentliche Vorfallsberichte | Tatsachen aus mehreren Quellen | Elementname, Versionsbereich, CVE, Fassung mit Behebung. Der Hinweistext ist **eigenformuliert**. | Handpflege |
| `../../signaturen/joomla-malware.yar` | Eigenimplementierung nach öffentlich dokumentierten Angriffsmustern | — | **kein** Regelwerk aus fremden Quellen übernommen, weder Wortlaut noch Struktur | Handpflege |

## Bewusst nicht verwendet

| Quelle | Grund |
|---|---|
| Fertige Prüfsummen-Sammlungen Dritter | Für die Daten selbst ist keine Lizenz angegeben. Prüfsummen werden stattdessen aus den offiziellen Joomla-Paketen selbst erzeugt — eindeutig und von jedem nachrechenbar. |
| Wortlisten aus GPL-lizenzierten Scannern (joomscan, JoomlaScan, CMSmap) | GPL ist ansteckend; das Repository steht unter MIT. Benötigte Tatsachen wurden in ein eigenes Schema neu erhoben. |
| JAMSS (Joomla-Anti-Malware-Scan-Script) | GPL-3.0. Nur als Ideengeber gelesen — kein Ausdruck im Wortlaut übernommen. |
| droopescan-Versionsdaten | AGPL-3.0 (netzwerkwirksames Copyleft), und ohne Abdeckung für Joomla 4/5/6. |
| Regelwerke unter DRL 1.1 (z. B. signature-base) | Kommerziell zulässig, verlangt aber die Nennung des Urhebers **in der Trefferausgabe**. Der Scan gibt derzeit nur Regelnamen aus; bis das umgestellt ist, wird nichts davon übernommen. |
| Datenbank für Schwachstellen der NVD über die Joomla-Produktkennung | Messbar unbrauchbar als Kriterium: die Abfrage liefert hunderte Treffer, darunter Komponenten-Lücken von 2006 und Altlasten aus Mambo. |

## Aktualisierung

```bash
bash werkzeuge/joomla-daten-update.sh --alles
```

Läuft auf der Entwicklungsmaschine oder in der CI, **nie** auf einem
Kundenserver — das Werkzeug wird deshalb auch nicht mit ausgeliefert.

Vor dem Vollabruf der Erweiterungsliste wird deren Prüfsumme verglichen; ist
sie unverändert, entfällt der Abruf. Klartext-Namen ohne Zuordnung hängt das
Werkzeug als auskommentierte Aufgabenzeilen an `vel/alias.tsv` an, statt sie
stillschweigend zu verwerfen.
