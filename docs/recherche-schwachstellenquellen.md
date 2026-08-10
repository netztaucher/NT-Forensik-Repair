# Schwachstellenquellen und fremde Regelwerke — Recherchestand

**Stand der Prüfung: 6./7. August 2026.** Alle Bewertungen sind Lesarten
öffentlicher Vertragstexte zu diesem Datum, keine Rechtsberatung. Lizenzen
ändern sich; ein Recherchestand ohne Datum ist nach einem Jahr eine Behauptung.

Dieses Dokument beantwortet die Frage, die vor jeder neuen Datenquelle und vor
jedem übernommenen Regelwerk steht: **was handelt man sich damit ein?** Das
Werkzeug ist öffentlich und steht unter MIT. Eine Quelle, die Weitergabe
untersagt oder Copyleft mitbringt, ist damit unbrauchbar — unabhängig davon,
wie gut ihre Daten sind.

Was tatsächlich ausgeliefert wird, steht in
[`rezepte/wordpress/daten/QUELLEN.md`](../rezepte/wordpress/daten/QUELLEN.md).
Dieses Dokument ist die Vorarbeit dazu und geht darüber hinaus: es bewertet auch
Quellen, die **nicht** verwendet werden, und die Regelwerke fremder Scanner.

---

## Was seit der Recherche daraus geworden ist

| Ergebnis | Umgesetzt in |
|---|---|
| Datenbestand + Versionsvergleicher | [`lib/wp_schwachstellen.py`](../lib/wp_schwachstellen.py), [`werkzeuge/wordpress-daten-update.sh`](../werkzeuge/wordpress-daten-update.sh) |
| Abgleich im Prüflauf | Haken `rezept_version` in [`rezepte/wordpress/rezept.sh`](../rezepte/wordpress/rezept.sh) |
| Plugin-Prüfsummen gegen wordpress.org | Haken `rezept_kern`, ebenda |
| Lizenz-Nachweis des ausgelieferten Bestands | [`rezepte/wordpress/daten/QUELLEN.md`](../rezepte/wordpress/daten/QUELLEN.md) |

Offen ist der erste echte Abruf des Wordfence-Feeds — er braucht einen
Schlüssel und ist zugleich der erste Formattest des Normalisierers.

---

## Teil 1 — Datenquellen für WordPress-Schwachstellen

Die Frage je Quelle: darf ein **MIT-lizenziertes, kommerziell eingesetztes**
Werkzeug die Daten (a) abfragen, (b) lokal spiegeln, (c) im Repository
mitliefern?

| Quelle | a | b | c | Ampel |
|---|---|---|---|---|
| **Wordfence Intelligence** | ✅ | ✅ | ✅ | 🟢 **unter Auflagen** |
| **CISA KEV** | ✅ | ✅ | ✅ | 🟢 gemeinfrei |
| **wordpress.org Prüfsummen** | ✅ | ✅ | (zu groß) | 🟢 |
| **GitHub Advisory Database** | ✅ | ✅ | ✅ | 🟢 — aber ohne WP-Abdeckung |
| **NVD / CVE über CPE** | ✅ | ✅ | ✅ | 🟡 frei, als Prädikat unbrauchbar |
| **wpvulnerability.net** | ✅ | ❓ | ❌ | 🟡 Datenlizenz nicht erklärt |
| **Patchstack** | 🟡 | ❌ | ❌ | 🔴 kein offener Zugang |
| **WPScan (Automattic)** | ❌ | ❌ | ❌ | 🔴 vertraglich ausgeschlossen |

### Wordfence Intelligence — die einzige tragfähige Primärquelle

Die Nutzungsbedingungen (§3a, Fassung vom 26.01.2026) gewähren eine
„perpetual, worldwide, non-exclusive, no-charge, royalty-free, irrevocable
license to reproduce, prepare derivative works of, publicly display, publicly
perform, sublicense, and distribute the Service", und §1 zählt Datenbank und
Schwachstelleninformationen ausdrücklich zum *Service*. Weitergabe ist damit vom
Wortlaut gedeckt — als einzige der kommerziellen Quellen.

Die Auflagen stehen mit ihren Konsequenzen in
[`QUELLEN.md`](../rezepte/wordpress/daten/QUELLEN.md): Kontopflicht und
Bearer-Schlüssel (der nie auf einen Kundenserver gelangt), Attribution je Kopie,
und ein Bezugsrecht, das jederzeit widerrufbar ist. `irrevocable` schützt nur
bereits bezogene Kopien.

**Das ist ein Klumpenrisiko.** Fällt Wordfence weg, gibt es nach heutigem Stand
keinen Ersatz, der Weitergabe erlaubt.

### Warum die anderen ausscheiden

**WPScan** — die Nutzungsbedingungen untersagen „storing or downloading (in any
fashion or for any length of time) any data relating to the Services …
vulnerability data" und die Nutzung „to create any similar or competing service
and/or product". Beides trifft dieses Vorhaben unmittelbar. Auch reines Abfragen
wäre für ein kommerziell eingesetztes Werkzeug nur mit Enterprise-Vertrag
zulässig.

**Patchstack** — kein offener Bulk-Zugang. Der Standard-Tarif wird Neukunden
nicht mehr angeboten, der erweiterte nur unter Individualvertrag. Die
Bedingungen behalten „all right, title, and interest" an den Daten vor.
Inhaltlich wäre die Quelle gut: sie führt `patched_in_ranges`, `is_exploited`
und `patch_priority`, also genau die Semantik, die ein Versionsabgleich braucht.

**wpvulnerability.net** — technisch reizvoll: ohne Schlüssel abrufbar, mit
expliziter Intervall-Semantik (`min_operator`/`max_operator`). Die Lizenzseite
sagt aber nur, man arbeite *„usually … with EUPL v1.2"*. Das ist eine Aussage
über die Gewohnheit der Betreiber, keine Lizenzgewährung für die Daten. Dazu ist
der Bestand nach eigener Angabe aus fremden öffentlichen Quellen aggregiert,
deren Lizenzlage damit unbekannt einfließt, und es gibt keinen Bulk-Endpunkt.
Als mitgelieferter Bestand nicht vertretbar; als Abfragequelle zur Laufzeit
denkbar, falls jemand das Klumpenrisiko oben verkleinern will.

**GitHub Advisory Database** — lizenzrechtlich die sauberste Quelle (CC-BY 4.0,
die Attribution lässt sich durch einen Link erfüllen). Nur: WordPress-Plugins
sind dort keinem OSV-Ökosystem zugeordnet und tragen deshalb keine
`affected`-Angaben. Es gibt schlicht nichts zu vergleichen. Bleibt sinnvoll für
Composer-Abhängigkeiten in `wp-content/plugins/*/vendor/` — ein eigener
Prüfschritt, noch nicht gebaut.

**NVD über CPE** — dieselbe Erfahrung wie bei Joomla: die CPE-Abdeckung für
WP-Plugins ist lückenhaft und die Treffermenge verrauscht. Als Prädikat
unbrauchbar, allenfalls zur Anreicherung um CVSS-Werte.

### Zwei technische Randbefunde

**Themes lassen sich nicht auf Unversehrtheit prüfen.** wordpress.org
veröffentlicht Prüfsummen nur für Plugins;
`downloads.wordpress.org/theme-checksums/…` antwortet mit HTTP 404 (geprüft
06.08.2026). Das Rezept meldet Themes deshalb als *nicht messbar* statt sie zu
übergehen.

**Das OSV-Schema kennt WordPress, der Dienst osv.dev nicht.** Das Schema
definiert kanonisch `WordPress:Core|:Plugin|:Theme` mit dem wordpress.org-Slug
als `name`. Eine Abfrage an `api.osv.dev` mit diesem Ökosystem wird mit
`{"code":3,"message":"invalid ecosystem"}` beantwortet. Übernommen ist deshalb
die **Semantik** des Schemas, nicht der Dienst als Quelle.

---

## Teil 2 — Fremde Regelwerke als Testeinspeisung

Die zweite Frage der Recherche war, ob sich zusätzliche Prüfungen über ein
etabliertes Regelformat einspeisen lassen, statt ein Eigenformat zu erfinden.
Ergebnis: **weitgehend nein**, und die Gründe sind lizenzrechtlich, nicht
technisch.

| Regelwerk | Lizenz | Ampel |
|---|---|---|
| **YARA** (eigene Regeln) | — | 🟢 bereits im Einsatz, `signaturen/` |
| **Nuclei-Templates** | MIT | 🟢 mitlieferbar, aber Laufzeit fehlt |
| **SigmaHQ-Regeln** | DRL 1.1 | 🔴 siehe unten |
| **Semgrep Registry** | Semgrep Rules License v1.0 | 🔴 |
| **ClamAV** | GPLv2 (libclamav) | 🔴 als Bibliothek, 🟡 als Fremdprozess |
| **OVAL/SCAP, OpenVAS NASL** | — | ⚪ nicht bewertet |

### SigmaHQ und die DRL 1.1 — woran es genau scheitert

Die Detection Rule License 1.1 ist **nicht** grundsätzlich unvereinbar: sie
erlaubt kommerzielle Nutzung, Verkauf, Änderung und Weitergabe, und zwar
kostenfrei. Sie scheitert an einer einzelnen Klausel.

Die DRL verlangt Urhebernennung **in der Trefferausgabe**: eine Meldung, die auf
einem Regel-Match beruht, muss die Autorenkennung der Regel mitführen. Bei
Weitergabe müssen zusätzlich das `author`-Feld, ein Verweis auf das Regelset und
der Lizenztext erhalten bleiben.

Für dieses Werkzeug heißt das konkret: jeder Befund, der aus einer
DRL-lizenzierten Regel entsteht, müsste den Regelautor bis in `findings.json`
und in den Kundenbericht durchreichen. Das ist kein Formatierungsdetail,
sondern eine Änderung am Ausgabevertrag gegenüber NT-Repair — und in einem
Bericht, der an Kunden und ans BSI geht, eine Fremdkennung, die dort
erklärungsbedürftig ist.

**Machbar wäre es.** Es setzt voraus, dass das Befundschema ein Autorenfeld je
Regel führt und die Berichte es ausgeben. Solange das nicht existiert, ist die
Klausel nicht erfüllbar, und ein Regelwerk unter DRL darf nicht übernommen
werden. Dieselbe Überlegung hat schon dazu geführt, dass die `signature-base`
für Joomla nicht verwendet wurde (siehe `QUELLEN.md`, „Bewusst nicht
verwendet").

### Die übrigen

**Semgrep Registry** — seit dem 13.12.2024 unter einer proprietären Eigenlizenz.
Nutzung nur für „eigene interne Geschäftszwecke", nicht unterlizenzierbar,
Weitergabe untersagt, Bereitstellung „als Dienst für andere" ebenfalls. Das
trifft sowohl das öffentliche Repository als auch den Bereinigungsteil als
Dienstleistung. Die Engine ist LGPL-2.1 und getrennt zu bewerten.

**Nuclei-Templates** — MIT, also mitlieferbar, ohne Pflicht zur Urhebernennung
in der Trefferausgabe. Scheitert an der Praxis: `nuclei` ist auf einem
Plesk-Kundenserver nicht installiert, und die WordPress-Templates prüfen
überwiegend über HTTP von außen, was zum lokalen read-only-Ansatz nicht passt.
Als Ideengeber brauchbar, als Laufzeitformat nicht. **Vorsicht** beim Projekt
`nuclei-wordfence-cve` (über 8.000 aus Wordfence-Daten erzeugte Templates): das
sind abgeleitete Wordfence-Daten, dort gilt zusätzlich deren Attribution, nicht
nur MIT.

**ClamAV** — libclamav steht unter GPLv2, und die Pflicht erstreckt sich auf
jede linkende Software. Eine Einbindung als Bibliothek scheidet aus; ein loser
Aufruf des separaten `clamscan`-Prozesses wäre vertretbar. Die Lizenz der
Signaturdatenbanken selbst ist nicht erklärt — nicht mitliefern. Das
**CVD-Format** (512-Byte-Kopf mit Signatur und MD5, `cl_cvdverify()`) ist
allerdings ein brauchbares Vorbild, falls jemals signierte Regelpakete gebraucht
werden.

**OVAL/SCAP und OpenVAS NASL** wurden nicht bewertet. Beide brauchen
schwergewichtige Laufzeiten und sind für ein Bash-Werkzeug auf Kundenservern
voraussichtlich unpraktikabel.

### Was daraus folgt

Die Testeinspeisung läuft nicht über fremde Regelwerke, sondern über zwei
eigene, bereits vorhandene Wege:

1. **Der Datenkanal** — eine Zeile in `rezepte/wordpress/daten/vuln/*.tsv` ist
   ein zusätzlicher Test. Kein Code, kein Review-Aufwand.
2. **Der Signaturkanal** — `signaturen/*.yar` und `signaturen.tsv` je Rezept.

Beides deckt den weit überwiegenden Teil dessen ab, wofür man sonst ein fremdes
Regelformat übernehmen würde.

---

## Was vor einer Erweiterung zu prüfen ist

1. **Ampeln neu bewerten.** Alle Angaben oben sind vom 6./7.08.2026. Die
   Wordfence-Bedingungen sind laut §5c einseitig änderbar, das Bezugsrecht laut
   §2c jederzeit widerrufbar.
2. **Bei jeder neuen Quelle: nur Tatsachen übernehmen.** Name, Kennung,
   Version, Status, CVE, CVSS, Verweis — keine Beschreibungstexte. Das hält die
   lizenzbehaftete Fläche klein und ist bei Joomla wie bei WordPress derselbe
   Grundsatz.
3. **Abdeckung auszählen, nicht schätzen.** Für keine der Quellen ist bisher
   belegt, welchen Anteil der aktiven wordpress.org-Plugins sie erfasst.

---
*netztaucher | digital*
