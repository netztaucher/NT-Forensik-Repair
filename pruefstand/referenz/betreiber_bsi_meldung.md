# Meldung eines IT-Sicherheitsvorfalls an das BSI

> **Entwurf — vor Versand prüfen und Platzhalter `[AUSFÜLLEN]` ergänzen.**
>
> **Meldewege:**
> - Meldepflichtige Unternehmen (KRITIS / NIS2 / §32 BSIG): **BSI Melde- und Informationsportal** — https://<anderer Kunde 2>
> - Freiwillige Meldung (alle Unternehmen): https://<anderer Kunde 3> → "Cyber-Sicherheitsvorfall melden" bzw. E-Mail an <anderer Adresse 1>
> - Bei Straftatverdacht zusätzlich: **ZAC** (Zentrale Ansprechstelle Cybercrime) der Landespolizei — Strafanzeige empfohlen
>
> **Fristen (NIS2/BSIG):** Erstmeldung ≤ 24 h nach Kenntnis, Folgemeldung ≤ 72 h, Abschlussbericht ≤ 1 Monat.
> **DSGVO Art. 33:** Bei Betroffenheit personenbezogener Daten Meldung an die Datenschutz-Aufsichtsbehörde ≤ 72 h (separater Meldeweg!).

---

## 1. Meldende Stelle

| Feld | Angabe |
|---|---|
| Unternehmen (Dienstleister) | netztaucher \| digital |
| Ansprechpartner | [AUSFÜLLEN] |
| E-Mail | [AUSFÜLLEN] |
| Telefon (Rückfragen) | [AUSFÜLLEN] |
| Meldung erfolgt | ☐ im eigenen Namen  ☐ im Auftrag des betroffenen Unternehmens |

## 2. Betroffenes Unternehmen / Einrichtung

| Feld | Angabe |
|---|---|
| Unternehmen | [AUSFÜLLEN — Kunde] |
| Branche / Sektor | [AUSFÜLLEN] |
| Betroffene Domain(s) | [AUSFÜLLEN] |
| Betroffener Server | imac () |
| Einstufung | ☐ KRITIS  ☐ NIS2 besonders wichtige Einrichtung  ☐ NIS2 wichtige Einrichtung  ☐ nicht meldepflichtig (freiwillige Meldung) |

## 3. Zeitliche Einordnung

| Feld | Angabe |
|---|---|
| Feststellung des Vorfalls | [AUSFÜLLEN — Datum/Uhrzeit der Entdeckung] |
| Vermuteter Beginn | [AUSFÜLLEN — Analysezeitraum ab ca. [AUSFÜLLEN]] |
| Forensische Analyse | <ZEIT> (Lauf-ID: <LAUF-ID>) |
| Vorfall andauernd? | ☐ ja  ☐ nein  ☐ unklar |

## 4. Art des Vorfalls

☐ Kompromittierung Webserver/CMS (WordPress)
☐ Webshell / Hintertür auf System
☐ Defacement / SEO-Spam / Malware-Verteilung
☐ Brute-Force-Angriff auf Zugänge
☐ Datenabfluss (vermutet/bestätigt)
☐ Sonstiges: [AUSFÜLLEN]

## 5. Automatisiert erhobene Kennzahlen (dieser Forensik-Lauf)

| Indikator | Wert |
|---|---|
| Kritische Befunde | 18 |
| Warnungen | 21 |
| Fehlgeschlagene SSH-Login-Versuche | 0 |
| Scanner-Aktivität in Web-Logs (Treffer) | 0 |
| Verdächtige POST-Requests (Webshell-Muster) | 0 |
| Webshell-Verdachtsdateien im Dateisystem | 0 |
| Schadcode-Fundstellen gesamt (alle Quellen) | 22 |
| Davon noch einzuordnen | 1 |
| Domains auf dem Server (Mitbetroffenheit möglich) | 0 |

### Kritische Einzelbefunde

- PHP-Dateien in Upload-Verzeichnissen (nach Guard-Filter, extrem verdächtig; 4 Guard-/Plugin-Dateien gefiltert)
- .htaccess gibt gezielt einzelne PHP-Datei(en) frei — typisch für abgesicherte Webshells (4)
- 2 Datei(en) sind in einer .htaccess namentlich freigegeben, gehören aber zu keinem bekannten Einstiegspunkt — und liegen dort. Für dieses Muster gibt es keinen legitimen Fall
- PHP-Code in 4 Mediendatei(en) — in einem echten Bild gehört kein PHP
- kunde-zwei.example/cloud.kunde-zwei.example: bekannte Schaddatei der Nextcloud-Kampagne (filefuns.php)
- kunde-zwei.example/cloud.kunde-zwei.example: Root-.htaccess trägt Angreifer-Merkmale (Freigabeliste mit fremden Dateinamen)
- kunde-zwei.example/cloud.kunde-zwei.example: verschachtelte Verzeichnisse (z. B. config/config) — typisch für diese Kampagne
- kunde-zwei.example/httpdocs: plugin pruefstand-kev 1.2 ist von einer bekannten Schwachstelle betroffen ((* … 2.0)) CVE-2026-90001 — behoben in 2.0. Diese Lücke wird nachweislich aktiv ausgenutzt — sofort handeln.
- kunde-zwei.example/httpdocs: robots.txt verweist auf eine Sitemap über index.php/ — Kennzeichen eines Doorway-Generators IN der Datenbank; ein Dateiscan findet ihn nicht (robots.txt vom <ZEIT>)
- kunde-zwei.example/httpdocs: 1 Datei(en) mit @include base64_decode() — getarnte Payload-Nachladung
- kunde-zwei.example/httpdocs: 8 veränderte Plugin-Codedatei(en) gegenüber wordpress.org — Plugin neu installieren, Dateien vorher sichern
- kunde-zwei.example/httpdocs: 1 veränderte Core-Datei(en) — Injektion oder Manipulation
- kunde-zwei.example/httpdocs: PHP-Code in wp_options — Optionen tragen Daten, keinen Code; hier legt ein Generator seinen Lader ab
- kunde-zwei.example/backups/updater-abc123/nextcloud-28.0.1.2-1700000000/.htaccess (nextcloud): 3 Angreifer-Direktive(n) in der .htaccess
- kunde-zwei.example/cloud.kunde-zwei.example/.htaccess (nextcloud): 3 Angreifer-Direktive(n) in der .htaccess
- kunde-zwei.example/httpdocs/.htaccess (wordpress): 2 Angreifer-Direktive(n) in der .htaccess
- kunde-zwei.example/httpdocs/wp-content/uploads/.htaccess (unbekannt): 1 Angreifer-Direktive(n) in der .htaccess
- Kein Apache-Prozess, aber nginx läuft — .htaccess-Dateien werden NICHT ausgewertet und schützen nichts

## 6. Indikatoren (IOCs)

### Auffällige IP-Adressen (aus Angriffsmustern konsolidiert)

```
Keine konsolidierten Angreifer-IPs in diesem Lauf.
```

### Top-IPs SSH-Brute-Force

```
Keine.
```

Datei-Hashes verdächtiger Dateien: siehe `belege/` (SHA256SUMS und Einzelbelege).

## 7. Auswirkungen

### Reichweite / Root-Kompromittierung (automatisiert bewertet)

⚪ Root-Prüfung nicht durchgeführt.


### Relay-Backdoor / ausgehender Fernzugriff (automatisiert bewertet)

⚪ Relay-Backdoor-Prüfung nicht durchgeführt.

| Frage | Antwort |
|---|---|
| Server-Root kompromittiert? | Nach Beweislage nein (auf Web-User-Ebene begrenzt) |
| Relay-Backdoor / Fernzugriffskanal? | kein Hinweis (kein Ausschluss bei inaktivem Kanal) |
| WordPress-Datenbank | unauffällig (keine fremden Admins/Optionen) |
| Joomla-Installation | unauffällig |
| Verfügbarkeit beeinträchtigt? | [AUSFÜLLEN] |
| Integrität von Daten/Systemen verletzt? | [AUSFÜLLEN] |
| Vertraulichkeit verletzt (Datenabfluss)? | [AUSFÜLLEN] |
| Personenbezogene Daten betroffen? | [AUSFÜLLEN — falls ja: DSGVO Art. 33 beachten!] |
| Auswirkung auf Dritte/Kunden? | [AUSFÜLLEN] |

## 8. Vermuteter Angriffsvektor

Basierend auf der forensischen Analyse (in absteigender Wahrscheinlichkeit):

1. [AUSFÜLLEN — z. B. kompromittiertes/veraltetes WordPress-Plugin]
2. [AUSFÜLLEN — z. B. wp-admin Brute-Force mit anschließendem Plugin-Upload]
3. [AUSFÜLLEN — z. B. kompromittierte FTP/SSH-Zugangsdaten]

## 9. Bereits ergriffene Maßnahmen

- Forensische Sicherung aller relevanten Logs (revisionssicher, SHA256-gehasht): <PRUEFSTAND>/ablage/forensik/<LAUF-ID>`
- [AUSFÜLLEN — z. B. Passwörter rotiert, Webshell entfernt/quarantänisiert, Domain offline genommen]

## 10. Geplante Maßnahmen

- [AUSFÜLLEN — z. B. Neuaufsetzen aus sauberem Backup, Härtung SSH/PHP, Fail2ban, ModSecurity+OWASP CRS]

## 11. Anlagen

| Anlage | Pfad |
|---|---|
| Technischer Forensik-Bericht | `technik_bericht.md` |
| Beweismittel inkl. Prüfsummen | `belege/` (SHA256SUMS) |
| Log-Vollsicherung | `belege/logs_sicherung.tar.gz` |

---
*Entwurf maschinell erstellt am <ZEIT> — wp_plesk_forensik.sh <FASSUNG>, netztaucher | digital.*
*Struktur orientiert an den Meldevorgaben des BSI (Erst-/Folgemeldung nach BSIG/NIS2) — vor Versand fachlich prüfen.*


---

> **Hinweis zum Datenschutz.** Dieser Server beherbergt weitere Kunden. Wo serverweite Prüfungen deren Domains oder Systemkonten berührten, stehen Platzhalter (`<anderer Kunde N>`); derselbe Nachbar trägt dabei immer dieselbe Nummer, sodass Zusammenhänge erkennbar bleiben. Betroffen waren 3 fremde Kennungen. Die unmaskierte Fassung verbleibt beim Betreiber.
