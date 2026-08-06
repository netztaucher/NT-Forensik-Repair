# NT-Forensik — Joomla-Prüfung (Abschnitt 12)

Vollständige Referenz zur Joomla-Prüfung in `wp_plesk_forensik.sh` ab v3.8.0.

> Ergänzend: [Handbuch](handbuch.md) · [Erkennungs-Referenz](erkennung.md) · [Incident-Response](incident-response.md)

---

## Inhalt

1. [Warum eine eigene Prüfung](#1-warum-eine-eigene-prüfung)
2. [Schnellstart](#2-schnellstart)
3. [Die zehn Prüfschritte](#3-die-zehn-prüfschritte)
4. [Datenbestand](#4-datenbestand)
5. [Offline und `--online`](#5-offline-und---online)
6. [Befunde richtig lesen](#6-befunde-richtig-lesen)
7. [Fehlalarm-Vermeidung](#7-fehlalarm-vermeidung)
8. [Pflege](#8-pflege)
9. [Grenzen](#9-grenzen)

---

## 1. Warum eine eigene Prüfung

Der allgemeine Dateisystem-Scan (Abschnitt 7) findet Webshells. Er findet drei Dinge **nicht**, die bei Joomla den Regelfall darstellen:

**Angreifbarkeit ohne Schadcode.** Joomla 3 erhält seit August 2023 keine Sicherheitspatches mehr, die kostenpflichtige Verlängerung lief im Februar 2025 aus. Joomla 4 ist seit dem 14.10.2025 ebenfalls am Ende, 4.4.14 war der letzte Stand. Sicherheitsmeldungen aus 2026 nennen weiterhin 3.x als betroffen, ohne dass auf irgendeinem Kanal eine Korrektur existiert. Eine solche Installation ist nicht „veraltet", sondern dauerhaft angreifbar — auch wenn kein einziges Schadcode-Muster zu finden ist.

**Persistenz ohne Datei.** Eine Zeile in `#__extensions` mit `folder='system'` lädt bei jedem Seitenaufruf Code — noch vor dem Routing und vor jeder Rechteprüfung. Es braucht dafür keinen Menüpunkt, keine URL, keine Anmeldung.

**Nutzlast ausschließlich in der Datenbank.** Die Helix3-Kampagne (Juli 2026) schreibt ihren Schadcode in die Vorlagen-Einstellungen (`#__template_styles.params`), die das Template direkt in die Seite ausgibt. Ein reiner Dateiscanner meldet eine verunstaltete Seite als sauber — und eine Wiederherstellung aller Dateien beseitigt nichts.

Dazu kommt die Lage: Seit Juni 2026 läuft eine Welle von Massenausnutzungen gegen Joomla-Erweiterungen. Drei Joomla-Einträge stehen im Katalog bekannt ausgenutzter Schwachstellen der US-Behörde CISA, zwei davon aus 2026.

---

## 2. Schnellstart

```bash
# Skript und Datenbestand auf den Server bringen
scp -r wp_plesk_forensik.sh lib module signaturen daten reportgen root@SERVER:/root/

# Eine Domain prüfen
ssh root@SERVER "bash /root/wp_plesk_forensik.sh --domain kunde.tld"
```

Beim ersten Lauf installiert sich das Skript nach `/root/wartungsscripte/` und zieht `signaturen/`, `daten/` und `reportgen/` mit. Ab v3.8.0 werden diese Ordner bei **jedem** Lauf aufgefrischt — vorher blieb ein einmal installierter Host dauerhaft auf dem Erststand.

Weitere Betriebsarten:

```bash
# Beliebiges Verzeichnis (Nicht-Plesk, Unterordner)
bash /root/wartungsscripte/wp_plesk_forensik.sh --path /var/www/vhosts/kunde.tld/httpdocs

# Alle Vhosts des Servers
bash /root/wartungsscripte/wp_plesk_forensik.sh --global

# Zusätzlich Signaturscan und Nachladen fehlender Prüfsummen
bash /root/wartungsscripte/wp_plesk_forensik.sh --domain kunde.tld --yara --online
```

**Voraussetzungen:** `root`, `bash`, GNU-Coreutils, `python3`. Optional `mysql` (Datenbankprüfung), `yara` (Signaturscan). Fehlt etwas, überspringt der Lauf den Punkt mit Hinweis und bricht nie ab.

**Der Lauf verändert nichts.** Er liest, wertet aus und schreibt ausschließlich nach `/root/wartungsscripte/`.

---

## 3. Die zehn Prüfschritte

### 12.1 Erkennung

Sucht `configuration.php` und verlangt darin `class JConfig` — der Dateiname allein ist zu unscharf, fast jedes PHP-Projekt hat eine. Backup- und Quarantänekopien werden über einen Pfadfilter ausgeschlossen und separat gezählt, sonst erzeugt jede Altkopie eigene Befunde.

Gibt zusätzlich den Stand des mitgelieferten Datenbestands aus und warnt ab 180 Tagen Alter. Ein stiller Lauf gegen einen jahrealten Bestand wäre die gefährlichste Form von „unauffällig".

### 12.2 Version und Wartungsende

Vier unabhängige Quellen:

| Quelle | Gilt für |
|---|---|
| `administrator/manifests/files/joomla.xml` → `<version>` | alle |
| `libraries/src/Version.php` → `MAJOR_/MINOR_/PATCH_VERSION` | 3.8+ / 4 / 5 / 6 |
| `libraries/cms/version/version.php` → `RELEASE` + `DEV_LEVEL` | nur 3.0–3.7 (in 3.8.0 gelöscht) |
| `#__extensions` mit `type='file' AND element='joomla'` | Datenbank-Gegenprobe |

Zwei Fallstricke, beide gegen echte Pakete geprüft: Das `version="3.6"`-**Attribut** am `<extension>`-Tag ist die Manifest-Schemaversion, nicht die CMS-Version. Und `type='file'` in der Datenbankabfrage ist Pflicht — es gibt auch eine `type='library'`-Zeile mit demselben `element`.

**Widersprüchliche Quellen sind selbst ein Befund:** unterschiedliche Haupt-/Nebenversion → 🔴 (Manipulation oder abgebrochene Migration), nur unterschiedlicher Patchstand → ⚠️ (unvollständiges Update oder Restore).

Bewertung der Zweige:

| Zweig | Sicherheitspatches bis | Endstand | Einstufung |
|---|---|---|---|
| 1.x / 2.5 | lange vorbei | — | 🔴 |
| 3.10 | 2023-08 (Verlängerung bis 2025-02) | 3.10.12 | 🔴 |
| 4.4 | **2025-10-14** | **4.4.14** | 🔴 |
| 5.4 | 2027-10 | 5.4.7 | Patchstand prüfen |
| 6.1 | 2029-10 | 6.1.2 | Patchstand prüfen |

### 12.3 Konfigurations-Härtung

Liest `configuration.php`. Beide Schreibweisen werden behandelt: Joomla 3 schreibt gequotete Strings (`'0'`), Joomla 4+ native Werte (`false`) — ein Vergleich nur gegen `'1'` würde `$debug = true` stumm übersehen.

Geprüft werden `error_reporting`, `debug`, Standard-Sicherheitsschlüssel, `force_ssl`, Standard-Tabellenpräfix, offene CORS-Freigabe, geteilte Sitzungen, abgeschaltete Sitzungs-Metadaten und `behind_loadbalancer` ohne echten Proxy (macht alle IP-Protokolle als Beweis wertlos).

**Strukturprüfung:** Die Datei darf nichts als die `JConfig`-Klasse mit Zuweisungen enthalten. Jedes `eval`, `assert`, `base64_decode`, `$_POST` darin → 🔴. Das ist die exakte Form der Rusty-Joomla-Hintertür. Ebenso werden Sicherungskopien (`configuration.php.bak` und Varianten) gemeldet — sie enthalten die Datenbank-Zugangsdaten im Klartext und sind je nach Serverkonfiguration per Browser abrufbar.

### 12.4 Ungeschützter API-Zugriff

**CVE-2023-23752** (Joomla 4.0.0–4.2.7): der Endpunkt `/api/index.php/v1/config/application?public=true` liefert die komplette Konfiguration inklusive Datenbank-Zugangsdaten im Klartext an jeden unauthentifizierten Aufrufer. Steht seit Januar 2024 im KEV-Katalog der CISA.

Liegt die Version im Bereich → 🔴 mit der Auflage, die Zugangsdaten als abgeflossen zu behandeln. Zusätzlich Gegenprobe im Zugriffsprotokoll des betroffenen Vhosts: **nur Antwortcode 200** auf genau diesem Endpunkt belegt einen Abfluss. Überwachungswerkzeuge rufen `/api/index.php/v1/` regelmäßig legitim ab und erhalten 401.

**CVE-2026-23899** (4.0.0–5.4.3, 6.0.0–6.0.3) ist der Nachfolger derselben Klasse, benötigt aber einen gültigen Zugriffsschlüssel → eine Stufe niedriger.

### 12.5 Kern-Integrität

Das Gegenstück zu `wp core verify-checksums`, das es für Joomla nirgends gibt: Joomla veröffentlicht keine Prüfsummen je Datei. NT-Forensik erzeugt sie deshalb selbst aus den offiziellen Paketen.

Gemeldet werden **veränderte** Kerndateien (🔴), **kernfremde** Dateien (🔴) und **fehlende** Dateien (⚠️). Rund 9800 Dateien in etwa vier Sekunden.

**Zweistufiger Vergleich.** Passt der Hash nicht, entscheidet ein zweiter über den auf einfache Leerzeichen normalisierten Inhalt. Stimmt der, war es nur eine Änderung an Zeilenenden, Tabs oder angehängten Leerzeichen — typisch nach einer Übertragung per FTP oder einer Bearbeitung unter Windows. Solche Fälle werden gezählt und ausgewiesen, aber **nicht gewertet**.

**Kernfremde Dateien** nur in Verzeichnissen, die ausschließlich Joomla-Programmcode enthalten dürfen: `includes/`, `administrator/includes/`, `libraries/src/`, `libraries/vendor/`, `api/`, `cli/`, `layouts/`. In `components/`, `modules/`, `plugins/`, `templates/`, `language/` und `media/` liegen legitim Dritt-Erweiterungen.

Nie verglichen wird, was der Betreiber selbst pflegt: `configuration.php`, `.htaccess`, `web.config`, `.user.ini`, `robots.txt`, `cache/`, `tmp/`, `logs/`, `images/`.

Fehlt die Fassung im Bestand, sagt der Lauf das offen und prüft **nicht** stillschweigend gegen etwas Ähnliches.

### 12.6 Datenbank

Zugang über den Plesk-Admin-Zugang, sonst über die Zugangsdaten aus `configuration.php`. Nur lesende Abfragen. Die Dateiprüfungen laufen **vorher** und liefern auch dann ein Ergebnis, wenn die Verbindung scheitert.

| Prüfung | 🔴 bei |
|---|---|
| **(a) System-Plugins** | fehlendem Verzeichnis, Schadcode im Plugin-Ordner, oder fehlendem Installationspaket während alle anderen eines haben |
| **(b) Super-User** | freigeschaltet **und** nicht gesperrt **und** nie angemeldet **und** frisch angelegt — alle vier zugleich. Zusätzlich MD5- oder Leerpasswort auf aktiven Konten |
| **(c) Rechtetabelle** | Verwaltungsrechte an „Öffentlich"/„Registriert" |
| **(d) Sitzungen** | bekannte Deserialisierungs-Ketten (`JDatabaseDriverMysqli`, `JSimplepieFactory`, `disconnectHandlers`) |
| **(e) Vorlagen-Parameter** | Skriptcode in `#__template_styles.params` |
| **(f) Module** | Verschleierung **und** Versteckmerkmal zugleich |
| **(g) Anmelde-Token** | Einträge vorhanden, obwohl „Angemeldet bleiben" abgeschaltet ist (⚠️) |

Zu (a): `PluginHelper::importPlugin('system')` läuft im Bootstrap vor Routing und vor jeder Rechteprüfung. Eine aktive Zeile lädt `plugins/system/<element>/` bei **jedem** Aufruf der Seite. Deshalb ist das die bevorzugte Stelle für dauerhaften Zugriff — die Astroid-Kampagne nutzte `plg_system_blpayload`.

Zu (b): Super-User werden **nicht** über die Standardgruppe 8 bestimmt, sondern über die Rechtetabelle des Wurzel-Assets samt Untergruppen. Joomla erlaubt weitere Gruppen mit Verwaltungsrecht, und Kindgruppen erben es.

Zu (e): siehe Abschnitt 1 — das ist die Prüfung, die einen reinen Dateiscan schlägt.

### 12.7 Abgleich mit bekannten Schwachstellen

**Kern** gegen die Meldungen des Joomla Security Strike Team: 214 Versionsbereiche aus 140 Meldungen, zurück bis 2017. Ab hoher Schwere 🔴, sonst ⚠️. Ältere Lücken betreffen nur Joomla bis 3.7 — solche Installationen meldet 12.2 ohnehin bereits als kritisch ungepatcht.

Bewusst **nicht** über die NVD: eine Abfrage nach der Joomla-Produktkennung liefert dort hunderte Treffer, darunter Komponenten-Lücken von 2006 und Mambo-Altlasten. Als Kriterium messbar unbrauchbar.

**Erweiterungen** gegen zwei Quellen:

- eine handgepflegte Tabelle der Fälle mit belegter Massenausnutzung (JCE, SP Page Builder, Page Builder CK, Helix3, iCagenda, Balbooa Forms, jDownloads, RSFiles! u. a.). Nötig, weil die aktuelle Welle neuer ist als der offizielle Feed und mehrere Fälle dort nicht stehen. Einträge im KEV-Katalog erhalten schärferen Wortlaut.
- die offizielle Liste verwundbarer Erweiterungen. Ein Eintrag **ohne verfügbare Korrektur** → 🔴 mit der Empfehlung zu deinstallieren; das ist der wertvollste Teil dieser Quelle.

Die Zuordnung läuft ausschließlich über exakte Elementnamen mit einer handgepflegten Übersetzungstabelle. **Wichtig:** `#__extensions` führt Komponenten, Module und Pakete mit Präfix (`com_`, `mod_`, `pkg_`), Plugins und Templates aber **ohne** — dort steht der blanke Name, bei Plugins zusammen mit dem Ordner. Die Tabellen sind auf genau diese Form gebracht.

Aktive Webservice-Bausteine werden als Kontext ausgewiesen: sie vergrößern die Angriffsfläche mehrerer Kern-Schwachstellen aus 2026 erheblich.

### 12.8 Joomla-typische Schaddateien

Stärkste Regel, praktisch fehlalarmfrei: **Bild-Kennung in den ersten vier Bytes einer Datei, die der Webserver als PHP ausführt.** Genau so sehen die über die JCE- und Medien-Uploadlücken abgelegten Hintertüren aus — die Bild-Kennung bringt sie an der Upload-Prüfung vorbei. Einen legitimen Fall dafür gibt es nicht.

Weiter: PHP in `images/`, `tmp/`, `cache/`, `media/` (Schutzdateien gefiltert), gemischte Schreibweise der Endung (`.pHp`), ausführbarer Code **vor** der `_JEXEC`-Zugriffssperre in den Einstiegsdateien, verbliebenes `installation/`-Verzeichnis, ungeschützter jDownloads-Uploader (CVE-2026-61900), `auto_prepend_file`, Sicherungsarchive außerhalb des Backup-Ordners.

### 12.9 Protokolle

Bekannte Joomla-Angriffswege: JCE-Bot, `icagenda-batch`, `task=profiles.import`, `task=asset.uploadCustomIcon`, `com_ajax&plugin=helix3`, Registrierungs-Bursts.

**Versuch ist nicht Erfolg.** Ein Protokolleintrag belegt, dass jemand einen bekannten Weg ausprobiert hat — auf einem öffentlich erreichbaren Server Alltag. Der Befund ist deshalb ⚠️ und zählt **nicht** ins Verdikt. 🔴 wird er nur zusammen mit einem Dateifund an derselben Installation.

### 12.10 Verdikt

`JOOMLA_FLAGS` zählt **nur harte Kompromittierungsindikatoren** — nicht Härtungsbefunde aus 12.3 und nicht Schwachstellen aus 12.7. Sonst stünde bei jeder Site mit einem veralteten Modul 🔴 im Kundenbericht.

Das Verdikt geht in Kundenbericht, BSI-Meldung, `findings.json` und die PDF-Zusammenfassung.

---

## 4. Datenbestand

```
daten/joomla/
├── VERSION                       Stand des Bestands
├── QUELLEN.md                    Herkunft und Lizenz jeder Datei
├── coresums/
│   ├── 3.10.tsv.gz               Kern-Prüfsummen je Zweig
│   ├── 4.4.tsv.gz
│   ├── 5.4.tsv.gz
│   ├── 6.1.tsv.gz
│   ├── index.tsv                 welcher Zweig deckt welche Fassungen ab
│   └── ausnahmen.tsv             freigegebene Abweichungen
├── cve/
│   ├── joomla-core.tsv           214 Versionsbereiche
│   └── joomla-ext-kritisch.tsv   belegte Massenausnutzung (handgepflegt)
└── vel/
    ├── vel.tsv                   verwundbare Erweiterungen
    ├── alias.tsv                 Klartext-Name → Elementname
    └── VERIFY                    Prüfsumme des Feeds
```

**3 MB für elf Joomla-Fassungen.** Die Prüfsummen liegen je Zweig statt je Fassung: gemessen sind 93 % der Dateien über die Patch-Releases eines Zweigs identisch. Drei Fassungen kombiniert kosten 860 KB statt 2408 KB einzeln.

Herkunft und Lizenz jeder Datei stehen in [`daten/joomla/QUELLEN.md`](../daten/joomla/QUELLEN.md). Grundsatz: übernommen werden nur Tatsachen (Name, Version, Status, CVE-Nummer), kein Beschreibungstext aus fremden Quellen — das Repository steht unter MIT.

---

## 5. Offline und `--online`

Der Lauf arbeitet **standardmäßig rein offline** und baut keine Verbindung nach außen auf.

`--online` erlaubt zwei Nachladungen:

1. die aktuelle Liste verwundbarer Erweiterungen (vorher wird die Prüfsumme verglichen; unverändert → kein Abruf)
2. für eine Fassung ohne lokalen Prüfsummen-Satz das offizielle Joomla-Paket dieser Fassung (rund 30 MB)

Geladen wird nach `${RUN_DIR}/.online/` — **nie** in den mitgelieferten Bestand, damit der Lauf reproduzierbar bleibt.

**Jeder Abruf wird protokolliert** mit URL, Antwortcode, Größe und Prüfsumme des Ergebnisses. Das erscheint in Abschnitt 12.11 des Technikberichts, als eigener Beleg und in `findings.json` unter `data_sources.network_fetches`. Ein Lauf, der das Netz berührt hat, darf nicht behaupten, rein lokal gewesen zu sein.

---

## 6. Befunde richtig lesen

**Das Verdikt beantwortet eine Frage:** Gibt es Spuren eines Angreifers? Nicht: Ist die Installation gepflegt?

Ein 🟢-Verdikt bei gleichzeitig mehreren ⚠️ aus 12.3 und 12.7 ist der Normalfall bei einer vernachlässigten, aber nicht übernommenen Seite. Das ist eine belastbare Aussage — sie trennt „muss aktualisiert werden" von „muss bereinigt werden".

**Was 🔴 auslöst:** widersprüchliche Versionsangaben, Wartungsende, Standard-Sicherheitsschlüssel, ausführbarer Code in der Konfiguration, belegter Zugangsdaten-Abfluss, veränderte oder kernfremde Kerndateien, Persistenz in der Datenbank, Injektionen in Vorlagen oder Modulen, Joomla-typische Schaddateien, Erweiterung mit aktiv ausgenutzter Lücke.

**Nach einem 🔴 im Bereich Zugangsdaten** (12.4) gilt: Datenbank-Passwort, Joomla-Sicherheitsschlüssel und alle Super-User-Passwörter wechseln, `#__user_keys` leeren. Ein Passwortwechsel allein reicht nicht — ein Anmelde-Token authentifiziert ohne Passwort und ohne zweiten Faktor.

---

## 7. Fehlalarm-Vermeidung

Grundsatz des Werkzeugs: *lieber gezielt whitelisten als Signaturen aufweichen.* Die wichtigsten Stellen:

| Prüfung | Ohne Gegenmaßnahme | Gegenmaßnahme |
|---|---|---|
| `tmp_path`/`log_path` | Joomlas Werkseinstellung liegt unter dem Webverzeichnis → Befund auf **100 %** aller Installationen | zusätzlich muss der Schutz per `.htaccess` fehlen |
| Leeres `manifest_cache` | Joomlas `base.sql` liefert Kern-Erweiterungen mit leerem Feld → **alle 18** Kern-System-Plugins einer Neuinstallation gemeldet | Indikator gilt nur relativ zur selben Installation |
| Aktive System-Plugins | 20–40 sind auf einer gepflegten Seite normal | rohe Bedingung ist kein Befund |
| Kern-Prüfsummen | CRLF nach FTP-Übertragung | zweiter Hash über normalisierten Inhalt |
| Kernfremde Dateien | Dritt-Erweiterungen | nur reine Kern-Verzeichnisse |
| `<script>` in Modulen | „Eigenes HTML" ist genau dafür da | Verschleierungs- **und** Versteckmerkmal nötig |
| Zuordnung Erweiterung | 60 % des Feeds tragen Klartext-Titel | nur exakte Treffer, kein unscharfer Abgleich |
| API-Abruf im Protokoll | Überwachung ruft legitim ab (401) | nur Antwortcode 200 zählt |

---

## 8. Pflege

```bash
bash werkzeuge/joomla-daten-update.sh --alles       # alles
bash werkzeuge/joomla-daten-update.sh --vel         # nur Erweiterungsliste
bash werkzeuge/joomla-daten-update.sh --cve         # nur Kern-Schwachstellen
bash werkzeuge/joomla-daten-update.sh --coresums    # nur Prüfsummen
bash werkzeuge/joomla-daten-update.sh --coresums 5.4.8 6.1.3   # gezielte Fassungen
```

Läuft auf der Entwicklungsmaschine oder in der CI, **nie** auf einem Kundenserver — deshalb liegt es unter `werkzeuge/` und wird nicht mit ausgeliefert.

Erscheint eine neue Joomla-Fassung, `--coresums <fassung>` nachziehen. Bis dahin deckt `--online` sie ab.

Klartext-Namen ohne Zuordnung hängt das Werkzeug als auskommentierte Aufgabenzeilen an `vel/alias.tsv` an, statt sie stillschweigend zu verwerfen. Elf Namen bleiben derzeit bewusst offen; die Gründe stehen im Kopf der Datei.

---

## 9. Grenzen

- **Keine Garantie auf Vollständigkeit.** Neue Verschleierungsvarianten können der Signatur entgehen.
- **Der Prüfsummen-Vergleich deckt nur den Kern.** Eine veränderte Datei in einer Dritt-Erweiterung fällt nicht auf — dafür gibt es keine Referenz.
- **Elf Feed-Einträge sind nicht zugeordnet** und werden beim Abgleich übersprungen.
- **Die Datenbankprüfung braucht eine Verbindung.** Scheitert sie, fehlen die Persistenz-Prüfungen; die Dateiprüfungen laufen trotzdem, und der Bericht sagt es.
- **Protokolle reichen begrenzt zurück.** Ein Abfluss vor dem Rotationsfenster ist nicht mehr nachweisbar — die Abwesenheit eines Protokolleintrags ist deshalb kein Freispruch.
- **Kern-Schwachstellen erst ab 2017.** Ältere betreffen nur Joomla bis 3.7, das ohnehin als kritisch ungepatcht gemeldet wird.

Das Werkzeug **beschleunigt und dokumentiert** die Forensik. Die Bewertung bleibt beim geschulten Auge.

---
*netztaucher | digital*
