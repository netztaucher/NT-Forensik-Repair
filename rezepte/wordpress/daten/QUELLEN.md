# Datenherkunft und Lizenzen — WordPress-Datenbestand

NT-Forensik steht unter **MIT** und ist öffentlich. Diese Tabelle ist der
Nachweis, woher jede Datei stammt und warum sie hier liegen darf. Gegenstück zu
[`daten/joomla/QUELLEN.md`](../joomla/QUELLEN.md), und derselbe Grundsatz gilt:

> Übernommen werden nur **Tatsachen** — Name, Kennung, Version, Status,
> CVE-Nummer, CVSS-Wert, Verweis. Kein Beschreibungstext aus fremden Quellen.
> Tatsachen sind nicht urheberrechtlich geschützt, formulierter Fließtext schon.

Bei WordPress kommt ein zweiter Grund dazu: die einzige inhaltlich vollständige
Quelle erlaubt die Weitergabe zwar ausdrücklich, aber unter Auflagen. Je weniger
fremder Text im Bestand liegt, desto kleiner ist die Fläche, auf die sich diese
Auflagen erstrecken.

---

## Was heute im Repository liegt

| Datei | Quelle | Lizenz der Quelle | Was übernommen wurde | Stand |
|---|---|---|---|---|
| `kev/kev-wordpress.tsv` | Katalog bekannt ausgenutzter Schwachstellen der CISA (`cisa.gov`) | Werk einer US-Behörde, **gemeinfrei** | CVE-Nummer, Hersteller, Produkt, Aufnahmedatum, Ransomware-Kennzeichen. **Kein** `shortDescription`, **kein** `requiredAction` — das sind formulierte Texte. | 2026-08-07 |

Mehr nicht. Die Schwachstellentabellen unter `vuln/` sind **noch nicht erzeugt**
— siehe unten.

---

## Lizenz-Ampel der geprüften Quellen

Stand der Prüfung: **2026-08-06/07**. Alle Bewertungen sind Lesarten öffentlicher
Vertragstexte, keine Rechtsberatung.

| Quelle | abfragen | spiegeln | mitliefern | Ampel |
|---|---|---|---|---|
| **CISA KEV** | ✅ | ✅ | ✅ | 🟢 gemeinfrei |
| **wordpress.org Prüfsummen** | ✅ | ✅ | (zu groß) | 🟢 offizielle Infrastruktur, reine Tatsachen |
| **Wordfence Intelligence** | ✅ | ✅ | ✅ | 🟢 **unter Auflagen** |
| **GitHub Advisory Database** | ✅ | ✅ | ✅ | 🟢 CC-BY 4.0 — aber praktisch ohne WP-Abdeckung |
| **NVD / CVE über CPE** | ✅ | ✅ | ✅ | 🟡 frei, als Prädikat aber unbrauchbar |
| **wpvulnerability.net** | ✅ | ❓ | ❌ | 🟡 Lizenz der Daten nicht erklärt |
| **Patchstack** | 🟡 | ❌ | ❌ | 🔴 kein offener Zugang |
| **WPScan (Automattic)** | ❌ | ❌ | ❌ | 🔴 vertraglich ausgeschlossen |

### Wordfence Intelligence — grün, aber mit Bedingungen

Die Nutzungsbedingungen (§3a, Stand 26.01.2026) gewähren eine „perpetual,
worldwide, non-exclusive, no-charge, royalty-free, irrevocable license to
reproduce, prepare derivative works of, publicly display, publicly perform,
sublicense, and distribute the Service", und §1 zählt Datenbank und
Schwachstelleninformationen ausdrücklich zum *Service*. Weitergabe ist damit vom
Wortlaut gedeckt — anders als bei allen anderen kommerziellen Quellen.

Die Auflagen sind allerdings nicht trivial:

1. **Bezug nur mit Konto und Bearer-Schlüssel**, der nicht weitergegeben oder
   unterlizenziert werden darf. Der Schlüssel wird deshalb aus der Umgebung
   gelesen (`WORDFENCE_API_KEY`) und gelangt weder ins Repository noch auf einen
   Kundenserver. Nur das Ergebnis wird ausgeliefert.
2. **Attribution je Kopie**: Copyright-Vermerk, Lizenztext und ein Hyperlink auf
   den jeweiligen Datensatz. Der Hyperlink steht in der Spalte `quelle` jeder
   Zeile; Copyright-Vermerk und Lizenztext fehlen noch (siehe unten).
3. **Die Daten werden dadurch nicht MIT-lizenziert.** Das Repository wird
   gemischt lizenziert.
4. **`irrevocable` schützt nur bereits bezogene Kopien.** Widerruf des
   Schlüssels ist jederzeit „in Company's sole discretion" vorbehalten (§2c),
   einseitige Änderung der Bedingungen ebenso (§5c). Die Ampel ist eine
   Momentaufnahme und gehört vor jedem Release neu geprüft.

### Warum nicht die anderen

| Quelle | Grund |
|---|---|
| **WPScan** | Die Nutzungsbedingungen untersagen „storing or downloading (in any fashion or for any length of time) any data relating to the Services … vulnerability data" und die Nutzung „to create any similar or competing service and/or product". Beides trifft dieses Vorhaben unmittelbar. |
| **Patchstack** | Kein offener Bulk-Zugang. Der Standard-Tarif wird Neukunden nicht mehr angeboten, der erweiterte nur unter Individualvertrag. Die Bedingungen behalten „all right, title, and interest" an den Daten vor. |
| **wpvulnerability.net** | Technisch reizvoll: ohne Schlüssel abrufbar, mit ausdrücklicher Intervall-Semantik (`min_operator`/`max_operator`). Die Lizenzseite sagt aber nur, man arbeite „usually … with EUPL v1.2" — das ist keine Lizenzgewährung für die Daten. Dazu ist der Bestand nach eigener Angabe aus fremden öffentlichen Quellen aggregiert, deren Lizenzlage damit unbekannt einfließt, und es gibt keinen Bulk-Endpunkt. Als mitgelieferter Bestand nicht vertretbar; als Abfragequelle zur Laufzeit denkbar. |
| **GitHub Advisory Database** | Lizenzrechtlich die sauberste Quelle (CC-BY 4.0, Attribution per Link genügt). Nur: WordPress-Plugins sind dort keinem OSV-Ökosystem zugeordnet und tragen deshalb keine `affected`-Angaben — es gibt nichts zu vergleichen. Bleibt sinnvoll für Composer-Abhängigkeiten in `wp-content/plugins/*/vendor/`, das ist ein eigener Prüfschritt. |
| **NVD über CPE** | Dieselbe Erfahrung wie bei Joomla: die CPE-Abdeckung für WP-Plugins ist lückenhaft und die Treffermenge verrauscht. Als Prädikat unbrauchbar, allenfalls zur Anreicherung. |

**Das heißt: es gibt genau eine tragfähige Primärquelle.** Das ist ein
Klumpenrisiko und steht hier, damit es nicht in Vergessenheit gerät.

---

## Format der Schwachstellentabellen

`vuln/wp-plugins.tsv`, `vuln/wp-themes.tsv`, `vuln/wp-core.tsv` — je Zeile ein
Versionsbereich, tabulatorgetrennt:

```
slug  von  von_inkl  bis  bis_inkl  behoben  cve  cvss  kev  quelle
```

- `slug` — der Bezeichner aus dem wordpress.org-Verzeichnis. Beim Kern
  `wordpress`.
- `von` / `bis` — Grenzen des betroffenen Bereichs. `*` heißt „offen".
- `von_inkl` / `bis_inkl` — `1` oder `0`. Die Grenzen sind **einzeln** offen
  oder geschlossen; das lässt sich nicht auf „kleiner als" verkürzen, weil
  `>= 2.0 und <= 2.4.1` und `>= 2.0 und < 2.4.1` sich genau um die Fassung
  unterscheiden, in der die Lücke behoben wurde.
- `kev` — `ja`, wenn die CVE-Nummer im KEV-Katalog steht.
- `quelle` — Verweis auf den Datensatz. Erfüllt zugleich die Attributionsauflage.

Die Semantik entspricht dem OSV-Schema (`affected[].ranges[].events` mit
`introduced` / `fixed` / `last_affected`), das inzwischen die Ökosystemkennung
`WordPress:Core|:Plugin|:Theme` mit dem wordpress.org-Slug als `name` führt.
Übernommen ist die **Semantik**, nicht das Format: TSV ist in Bash ohne
Fremdwerkzeug lesbar, klein und diff-freundlich — wie bei Joomla.

Der Dienst osv.dev ist **keine** Quelle: eine Abfrage mit
`"ecosystem":"WordPress:Plugin"` beantwortet er mit
`{"code":3,"message":"invalid ecosystem"}` (geprüft 2026-08-06). Das Schema
kennt WordPress, der Dienst noch nicht.

---

## Aktualisierung

```bash
export WORDFENCE_API_KEY='…'          # nur auf der Entwicklungsmaschine
bash werkzeuge/wordpress-daten-update.sh --alles
```

Läuft auf der Entwicklungsmaschine oder in der CI, **nie** auf einem
Kundenserver — das Werkzeug wird deshalb auch nicht mit ausgeliefert.

Der Wordfence-Feed kennt **keinen Teilabruf**: beide Endpunkte liefern immer den
ganzen Bestand und nehmen keine Parameter. Ein Delta entsteht nur lokal. Auf
`ETag`/`If-Modified-Since` lässt sich nicht bauen — beides ist nicht
dokumentiert, und die Antwort führt keine entsprechenden Kopfzeilen.

`VERSION` und `MANIFEST.sha256` halten fest, welcher Stand vorliegt. Das ist
keine Kür: ein Befund gegen einen Schwachstellenbestand ist nur so viel wert,
wie sich der Bestand später nachweisen lässt.

---

## Offen vor der ersten Auslieferung

Diese Punkte sind **erledigt, bevor der erste Wordfence-Bestand eingecheckt
wird** — nicht danach:

1. **`rezepte/wordpress/daten/LICENSE` anlegen** mit dem Copyright-Vermerk von Defiant
   und dem Lizenztext. Die Bedingungen verlangen beides je Kopie; der Verweis je
   Zeile allein genügt nicht.
2. **MITRE-Anzeigepflicht klären.** Wordfence nennt für CVE-Anteile eine
   Anzeigepflicht gegenüber dem Endnutzer. Ob das eine Pflicht zur Nennung **in
   der Trefferausgabe** ist — dann derselbe Konflikt wie bei DRL 1.1, der hier
   bereits zum Ausschluss von Regelwerken geführt hat — oder nur eine
   Beilagepflicht, ist ungeklärt.
3. **Feedformat gegenprüfen.** Der Normalisierer in
   `werkzeuge/wordpress-daten-update.sh` ist gegen die dokumentierte Struktur
   gebaut und gegen einen nachgebauten Feed getestet, **nicht gegen den echten**
   — dafür fehlte der Schlüssel. Der erste echte Lauf ist gleichzeitig der erste
   Formattest. Er weist aus, wie viele Datensätze nicht übernommen wurden; steht
   dort eine große Zahl, stimmt die Annahme über das Format nicht.
4. **Abdeckung auszählen.** Wie viele Datensätze hat der Feed, wie viele
   verschiedene Slugs? Ohne diese Zahl lässt sich nicht beurteilen, ob die
   Abhängigkeit von einer einzigen Quelle tragbar ist.

---
*netztaucher | digital*
