# Sicherheitsvorfall — Bericht


| | |
|---|---|
| **Einstufung** | 🔴 KRITISCH |
| **Erstellt durch** | netztaucher \| digital |
| **Datum** | <ZEIT> |
| **Geprüfter Server** | imac |
| **Prüfungs-ID** | <LAUF-ID> |
| **Befunde** | 🔴 18 kritisch · ⚠️ 26 auffällig · ⚪ 13 nicht messbar |

---

## 1. Das Wichtigste in einem Satz

**Ihr System wurde nachweislich kompromittiert.** Es liegen konkrete, technisch belegte Hinweise auf einen erfolgreichen Angriff vor. Ein Angreifer hatte oder hat Zugriff auf Ihren Webauftritt. **Es besteht akuter Handlungsbedarf** — bitte arbeiten Sie die Sofortmaßnahmen unten noch heute ab.

**Warum das dringend ist:** Solange die Zugänge des Angreifers gültig sind, kann er jederzeit zurückkehren, weitere Hintertüren legen, Daten (auch Kundendaten) abgreifen, Spam über Ihre Domain versenden oder Ihre Seite für Betrug/Schadsoftware missbrauchen. Jede Stunde zählt.

## 2. ⏱️ Sofortmaßnahmen — bitte noch heute

| # | Maßnahme | Frist |
|---|---|---|
| 1 | **Alle Passwörter ändern**: WordPress-Admin, Hosting-/Plesk-Panel, FTP/SFTP, SSH, Datenbank. Nicht nur eines — alle. | sofort (< 24 h) |
| 2 | **Alle aktiven Sitzungen beenden** (WordPress-Sicherheitsschlüssel/Salts neu erzeugen), damit gestohlene Logins ungültig werden. | sofort (< 24 h) |
| 3 | **Verwundbare Zugänge/Plugins abschalten**, über die der Angriff lief (siehe Abschnitt 4). | sofort (< 24 h) |
| 4 | **Angreifer-IP-Adressen sperren** (siehe Abschnitt 4). | sofort (< 24 h) |
| 5 | **Prüfen, ob personenbezogene Daten betroffen sind** — falls ja, greift die 72-Stunden-Meldepflicht (siehe Abschnitt 6). | < 72 h |

> Diese Schritte stoppen den akuten Zugriff. Die vollständige Bereinigung (Abschnitt 5) folgt danach.

## 3. Was wir technisch gefunden haben

- **30 Schadcode-Fundstelle(n)** in Ihrem Webauftritt. Was jede einzelne ist und wozu sie dient, steht in der Einordnung unten und vollständig in `befunde_details.md`.
- 1 weitere Fundstelle(n) sind noch einzuordnen — sie sind kein belegter Schadcode, aber auch nicht abgehakt. Liste in `befunde_details.md`.

**Schadcode-Einordnung — 30 Fundstelle(n):**

| Art | Anzahl | Was damit bezweckt wird |
|---|---|---|
| Getarnte Payload | 9 | Nachladbarer Schadcode in Nicht-PHP-Datei |
| Verändertes Plugin | 8 | Fremder Code in einem legitimen Plugin — nachträglich eingebaute Hintertür |
| Code-Injection | 4 | Schadcode in legitime Dateien eingeschleust |
| Manipulierte .htaccess | 4 | Zugriffsregeln zugunsten des Angreifers — hält seine Dateien erreichbar und sperrt Mitbewerber aus |
| PHP im Upload-Verzeichnis | 3 | Ausführbarer Code dort, wo nur Dateien liegen sollen — der klassische Weg einer hochgeladenen Shell |
| Bekannte Schaddatei | 1 | Nach Namensmuster erkanntes Angriffswerkzeug (Dateimanager, Uploader, Shell) |
| Tarnstruktur | 1 | Angelegte Verzeichnisse, die echte nachahmen — Ablage für Nutzlasten |

> Die vollständige Liste der betroffenen Dateien — mit Pfaden **relativ zu Ihrem
> Verzeichnis** — liegt in der Datei `befunde_details.md` bei Ihren Unterlagen.

**Kritische Einzelbefunde:**

- PHP-Dateien in Upload-Verzeichnissen (nach Guard-Filter, extrem verdächtig; 6 Guard-/Plugin-Dateien gefiltert)
- .htaccess gibt gezielt einzelne PHP-Datei(en) frei — typisch für abgesicherte Webshells (4)
- 2 Datei(en) sind in einer .htaccess namentlich freigegeben, gehören aber zu keinem bekannten Einstiegspunkt — und liegen dort. Für dieses Muster gibt es keinen legitimen Fall
- PHP-Code in 9 Mediendatei(en) — in einem echten Bild gehört kein PHP
- 1 Datei(en) setzen Funktionsnamen aus Einzelzeichen zusammen — für dieses Muster gibt es keinen legitimen Fall
- kunde-zwei.example/cloud.kunde-zwei.example: bekannte Schaddatei der Nextcloud-Kampagne (filefuns.php)
- kunde-zwei.example/cloud.kunde-zwei.example: Root-.htaccess trägt Angreifer-Merkmale (Freigabeliste mit fremden Dateinamen)
- kunde-zwei.example/cloud.kunde-zwei.example: verschachtelte Verzeichnisse (z. B. config/config) — typisch für diese Kampagne
- kunde-zwei.example/httpdocs: plugin pruefstand-kev 1.2 ist von einer bekannten Schwachstelle betroffen ((* … 2.0)) CVE-2026-90001 — behoben in 2.0. Diese Lücke wird nachweislich aktiv ausgenutzt — sofort handeln.
- kunde-zwei.example/httpdocs: 1 Datei(en) mit @include base64_decode() — getarnte Payload-Nachladung
- kunde-zwei.example/httpdocs: 8 veränderte Plugin-Codedatei(en) gegenüber wordpress.org — Plugin neu installieren, Dateien vorher sichern
- kunde-zwei.example/httpdocs: 1 abweichende Datei(en) im Core-Update-Staging (Fassung 7.1) — dort hat niemand etwas zu suchen außer dem Updater
- kunde-zwei.example/httpdocs: 1 veränderte Core-Datei(en) — Injektion oder Manipulation
- kunde-zwei.example/backups/updater-abc123/nextcloud-28.0.1.2-1700000000/.htaccess (nextcloud): 3 Angreifer-Direktive(n) in der .htaccess
- kunde-zwei.example/cloud.kunde-zwei.example/.htaccess (nextcloud): 3 Angreifer-Direktive(n) in der .htaccess
- kunde-zwei.example/httpdocs/.htaccess (wordpress): 2 Angreifer-Direktive(n) in der .htaccess
- kunde-zwei.example/httpdocs/wp-content/uploads/.htaccess (unbekannt): 1 Angreifer-Direktive(n) in der .htaccess
- Kein Apache-Prozess, aber nginx läuft — .htaccess-Dateien werden NICHT ausgewertet und schützen nichts
**Auffälligkeiten (zeitnah beheben):**

- 3 PHP-Datei(en) in Upload-Verzeichnissen sind erzeugter Code bekannten Formats — nicht in Quarantäne, aber zu sichten
- .htaccess mit externen Weiterleitungen gefunden
- kunde-zwei.example/joomla.kunde-zwei.example: Joomla-Version nicht bestimmbar (weder joomla.xml noch Version.php lesbar)
- kunde-zwei.example/joomla.kunde-zwei.example: Standard-Tabellenpräfix jos_ (macht SQL-Injection-Angriffe zielgenau ohne Vorab-Erkundung)
- kunde-drei.example/httpdocs: 3 Core-Datei(en) für den Eigentümer schreibgeschützt (in einem Vorgang gesetzt am <ZEIT>) — Core-Updates scheitern daran, still; Ursache klären (Härtung von Hand oder Schutz eingeschleusten Codes vor dem nächsten Update)
- kunde-drei.example/httpdocs: 1 Härtungspunkt(e) in wp-config.php offen
- kunde-eins.example/httpdocs: 2 Härtungspunkt(e) in wp-config.php offen
- kunde-vier.example/httpdocs: 2 Härtungspunkt(e) in wp-config.php offen
- kunde-zwei.example/httpdocs: 2 Verzeichnis(se) unter plugins/ mit PHP-Dateien, aber ohne Plugin-Kopf — kein Plugin; kann eine Angreifer-Ablage sein, sichten
- kunde-zwei.example/httpdocs: core wordpress 6.4.1 ist von einer bekannten Schwachstelle betroffen ([6.0 … 6.4.1]) CVE-2026-90004 — behoben in 6.4.2.
- kunde-zwei.example/httpdocs: plugin pruefstand-alt 2.0.3 ist von einer bekannten Schwachstelle betroffen ([2.0 … 2.4.1]) CVE-2026-90002 — behoben in 2.5.
- kunde-zwei.example/httpdocs: plugin pruefstand-ohne-fix 1.0 ist von einer bekannten Schwachstelle betroffen ([* … *]) CVE-2026-90007.
- kunde-zwei.example/httpdocs: theme pruefstand-thema 0.9 ist von einer bekannten Schwachstelle betroffen ((* … 1.0)) CVE-2026-90005 — behoben in 1.0.
- kunde-zwei.example/httpdocs: Bibliothek (in einem Plugin) pruefstand/bibliothek 1.2.0 ist von einer bekannten Schwachstelle betroffen ([1.0.0 … 1.4.0)) CVE-2026-90006 — behoben in 1.4.0.
- kunde-zwei.example/httpdocs: 1 mu-Plugin(s) — laufen ohne Aktivierung und erscheinen in keiner Pluginliste
- kunde-zwei.example/httpdocs: 1 Core-Datei(en) stammen aus Fassung 7.1 (liegengebliebenes Update-Staging) — das Update ist abgebrochen, der Kern gemischt; Update abschließen
- kunde-zwei.example/httpdocs: 1 Core-fremde Datei(en) in wp-admin/wp-includes — prüfen
- kunde-zwei.example/httpdocs: 2 Härtungspunkt(e) in wp-config.php offen
- kunde-zwei.example/httpdocs: Wordfence-Scan ist <TAGE> Tage alt — was danach abgelegt wurde, steht in diesem Bestand nicht
- kunde-zwei.example/httpdocs: Wordfence führt 1 Plugin(s) als verwundbar
- kunde-zwei.example/httpdocs: Wordfence führt 1 Theme(s) als verwundbar
- kunde-zwei.example/httpdocs: Wordfence hat Pfade vom Scan ausgenommen — ein unauffälliger Wordfence-Bericht ist für diese Bereiche KEINE Entwarnung
- kunde-zwei.example/httpdocs: Wordfence meldet 1 Datei(en) als verändert gegenüber dem Original — Integritätsabweichung, kein Signaturtreffer
- kunde-zwei.example/httpdocs: active_plugins führt Einträge ohne Datei auf der Platte — Leiche oder Tarnung, sichten
- php-malware-finder: 4 Datei(en) mit Treffern — nach Regelanzahl sortiert, jeder Treffer gehört gesichtet (9 als unverändert bestätigte Datei(en) herausgefiltert)
- 1 belastete Datei(en) tragen eine in die Zukunft gesetzte mtime — jede nach Datum sortierte Sichtung uebersieht sie

## 4. Reichweite des Angriffs — war nur Ihre Website oder der ganze Server betroffen?

Die Reichweite auf Serverebene wurde in diesem Lauf nicht geprüft.

> **Was das bedeutet:** „Serverebene" (Root) ist die Administratorebene des
> gesamten Servers, auf dem neben Ihrer auch andere Websites liegen. Blieb ein
> Angreifer darunter (nur auf Ebene Ihrer Website), ist der Schaden auf Ihren
> Webauftritt begrenzt. Die technische Detailbewertung der Serverebene liegt beim
> Serverbetreiber; sie ist nicht Teil dieses Kundenberichts.

**WordPress-Datenbank:** ⚪ Keine WordPress-Installation im Scan-Pfad gefunden — keine Datenbank-Prüfung durchgeführt.

**Joomla:** 🟢 **Keine Angreifer-Spuren in den Joomla-Installationen** — Version schlüssig, Konfiguration ohne kritische Schwächen, kein Hinweis auf einen Datenabfluss über die Programmschnittstelle.
**Fernzugriff / Relay-Backdoor:** ⚪ Relay-Backdoor-Prüfung nicht durchgeführt.

## 5. Angriffshergang & Angreifer

> *Die folgenden Angaben sind maschinell aus den Protokollen dieses Laufs abgeleitet.
> Die endgültige Zuordnung (konkreter Angreifer-Login, exaktes Einfallstor) bestätigen
> wir bei der manuellen Auswertung; alle Rohdaten liegen revisionssicher in `belege/`.*

**Auffällige IP-Adressen:**

In den vorliegenden Protokollen wurden keine eindeutig auffälligen IP-Adressen automatisch isoliert (ggf. Log-Reichweite zu kurz).

**Wahrscheinliches Einfallstor (aus der Befundlage):**

  - Kein eindeutiger Vektor aus den Automatik-Daten ableitbar — manuelle Log-Auswertung erforderlich.

**Zeitliche Einordnung:** Analysezeitraum dieses Laufs: letzte 30 Tage. Der genaue Zugriffszeitraum ergibt sich aus der manuellen Log-Auswertung und den Datei-Zeitstempeln (siehe `belege/`).

**Beobachtete Angreifer-Aktivität:** Aus den Automatik-Daten keine konkrete Angreifer-Aktion belegt — bei der manuellen Auswertung zu prüfen.



## 6. Bereinigung & dauerhafte Absicherung

**Bereits von uns durchgeführt:**

- Vollständige forensische Sicherung aller Protokolle und Beweise (revisionssicher, mit Prüfsummen) — Lauf-ID `<LAUF-ID>`.
- Vollständiger Scan von Dateisystem, Prozessen, Persistenz-Mechanismen und Datenbanken.


**Als Nächstes nötig:**

1. Gefundene Schadcode-Dateien entfernen (aus Quarantäne, nach Beweissicherung).
2. Betroffenes WordPress **aus einem nachweislich sauberen Backup** (vor dem Einbruch) neu aufsetzen — ein reines "Überschreiben" reicht bei Hintertüren nicht.
3. Alle Plugins/Themes aktualisieren, ungenutzte entfernen.
4. Server härten: SSH auf Schlüssel-Login umstellen, Fail2ban/ModSecurity aktivieren, PHP-Funktionen einschränken.
5. Datei-Integritäts-Überwachung und automatische Malware-Scans einrichten.

## 7. Rechtliche Pflichten (bitte beachten)

> **Datenschutz (DSGVO Art. 33):** Wenn bei diesem Vorfall personenbezogene Daten
> betroffen sein **könnten** (Kundendaten, Bestellungen, E-Mail-Adressen in der
> Website-Datenbank), müssen Sie das der zuständigen Datenschutz-Aufsichtsbehörde
> **innerhalb von 72 Stunden nach Bekanntwerden** melden. Die Frist läuft bereits.
> Ein vorbereiteter Entwurf liegt in `dsgvo_meldung.md`.

> **Meldung an das BSI:** Eine vorbereitete Meldung liegt in `bsi_meldung.md`
> (**eigener Meldeweg**, getrennt von der Datenschutzmeldung). Ob eine Pflicht besteht,
> hängt von Ihrer Einstufung ab — im Zweifel ist eine freiwillige Meldung sinnvoll.

Wir unterstützen Sie bei allen Meldungen — sprechen Sie uns umgehend an.

## 8. Ihre Unterlagen zu diesem Vorfall

| Dokument | Zweck |
|---|---|
| `kundenbericht.md` | Dieses Dokument |
| `befunde_details.md` | Vollständige Fundstellen-Liste (Pfade relativ zu Ihrem Verzeichnis, Familie, Signatur) |
| `root_aussage.md` | Aussage dazu, ob der Vorfall über Ihren Webauftritt hinausreicht |
| `02_Meldungen/` | Entwurf Ihrer DSGVO-Meldung (Art. 33) — von Ihnen zu prüfen und abzusenden |
| `04_Belege/` | Die Rohbelege zu den Befunden, maskiert und mit eigenen SHA256-Prüfsummen |

> **Was Sie hier NICHT finden — und warum.** Der vollständige Technik-Bericht,
> die BSI-Meldung und die unmaskierten Rohbelege liegen beim Betreiber Ihres
> Servers. Sie enthalten serverweite Angaben und, auf einem Server mit mehreren
> Kunden, Pfade und Kennungen anderer Kunden. Was davon Sie betrifft, steht
> vollständig in diesem Bericht. Den Technik-Bericht können Sie bei Bedarf
> anfordern; er wird dann maskiert beigelegt.



---

### Über netztaucher | digital

Diese Analyse stammt aus unserer laufenden **WordPress-Betreuung und -Absicherung**.
Wir übernehmen Wartung, Härtung, Monitoring und Notfall-Forensik für WordPress- und
Rootserver — damit Vorfälle wie dieser gar nicht erst entstehen oder im Ernstfall
sauber und dokumentiert behoben werden.

**→ https://<anderer Kunde 1>/wordpress**

---
*netztaucher | digital — maschinell erstellt (wp_plesk_forensik.sh <FASSUNG>) und dokumentiert den Zustand zum Prüfzeitpunkt. Der Angriffshergang (Abschnitt 5/6) wird nach manueller Auswertung ergänzt.*


---

> **Hinweis zum Datenschutz.** Dieser Server beherbergt weitere Kunden. Wo serverweite Prüfungen deren Domains oder Systemkonten berührten, stehen Platzhalter (`<anderer Kunde N>`); derselbe Nachbar trägt dabei immer dieselbe Nummer, sodass Zusammenhänge erkennbar bleiben. Betroffen waren 1 fremde Kennungen. Die unmaskierte Fassung verbleibt beim Betreiber.
