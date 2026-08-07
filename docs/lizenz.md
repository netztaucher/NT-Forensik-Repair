# NT-Repair — Lizenz

Die **Analyse** (`wp_plesk_forensik.sh`) ist frei und quelloffen. Sie läuft ohne Lizenz,
ohne Netz und ohne Anmeldung, mit einsehbarem Quelltext. Daran ändert sich nichts.

Die **Bereinigung** (`nt_repair.sh`) ist kostenpflichtig.

---

## Für wen

Für **Agenturen, Hoster und IT-Dienstleister**, die Sicherheitsvorfälle auf Servern ihrer
Kunden bearbeiten.

NT-Repair läuft nicht auf dem betroffenen Server, sondern auf Ihrem Arbeitsplatz und greift
per SSH zu. Das ist Absicht: der entschlüsselte Code liegt nie auf einem System, das gerade
als kompromittiert gilt, und das Bereinigungsprotokoll entsteht außerhalb — Beweissicherung
gehört nicht auf den Tatort.

Für Websitebetreiber, die nur die eigene Seite bereinigen wollen, ist das Werkzeug nicht
gedacht: es setzt Root-Zugriff auf den Server voraus.

## Was Sie bekommen

| | |
|---|---|
| **Quarantäne** | verschiebt, löscht nie. SHA-256 vor jedem Eingriff, jede Datei rückholbar |
| **IOC-Sperren** | Angreiferadressen serverseitig blockieren, idempotent und dauerhaft |
| **Zugangsdaten** | Systemkonto, WordPress, Datenbank und Plesk — mit Ablage in 1Password und Rückleseprobe |
| **Berichte** | Kundenbericht, BSI-Abschlussmeldung, DSGVO-Nachmeldung |
| **Statusmail** | versandfertige `.eml` an den Kunden, aus dem Protokoll abgeleitet |

Dazu die Regeln, die im Werkzeug fest verdrahtet sind: kein ändernder Schritt ohne
dokumentierten Kontrolllauf **und** ausdrückliche Freigabe je Aktionsgruppe. Nie löschen,
nur verschieben. Jede geänderte Datei bekommt einen Kommentarblock, der sagt, wer sie wann
und warum angefasst hat.

## Umfang der Lizenz

**Eine Lizenz gilt für einen Arbeitsplatz** — den Rechner, von dem aus Sie Bereinigungen
durchführen. Wie viele Kunden, Server und Vorfälle Sie damit bearbeiten, ist nicht begrenzt.

Beim ersten Start ohne hinterlegten Schlüssel nennt das Werkzeug die Kennung Ihres
Arbeitsplatzes. Diese Kennung schalten wir frei; danach ist die Lizenz an diesen Rechner
gebunden.

**Rechnerwechsel** ist jederzeit möglich — neue Kennung mitteilen, wir schalten um. Ein
Aufpreis entsteht dabei nicht; die Lizenz wandert mit, sie vervielfältigt sich nicht.

**Zweiter Arbeitsplatz** (Notebook neben Arbeitsplatzrechner, zweiter Mitarbeiter) benötigt
eine eigene Lizenz.

## Bezug und Preis

> **[AUSFÜLLEN]** — Preismodell, Laufzeit und Kündigungsfrist. Diese Angaben gehören vor der
> Veröffentlichung ergänzt; sie stehen bewusst nicht im Quelltext.

Anfragen: **kontakt@netztaucher.com** · [netztaucher.com](https://netztaucher.com)

## Einrichtung

Nach der Freischaltung hinterlegen Sie den Schlüssel einmalig:

```bash
mkdir -p ~/.nt-repair && chmod 700 ~/.nt-repair
printf 'NT-XXXX-XXXX-XXXX\n' > ~/.nt-repair/lizenz.key
chmod 600 ~/.nt-repair/lizenz.key
```

Das war alles. Jeder Lauf prüft die Lizenz selbst.

## Wenn der Lizenzserver ausfällt

Das Werkzeug fragt bei jedem Lauf zuerst den Lizenzserver. Ist er nicht erreichbar, arbeitet
es bis zu **sieben Tage** aus einer Ausfallreserve weiter.

Der Grund ist praktisch: in einem Vorfall arbeitet man auch mal aus einem Hotel-WLAN oder über
einen Mobilfunk-Hotspot. Ein Werkzeug, das dann streikt, ist im entscheidenden Moment nutzlos.

Die Reserve ist an Ihren Arbeitsplatz gebunden — auf einen anderen Rechner kopiert ist sie
wertlos. Nach sieben Tagen ohne Verbindung endet sie.

**Die Analyse ist davon nie betroffen.** Sie läuft immer, auch ohne Netz und ohne Lizenz.

## Was wir nicht sehen

Der Lizenzserver erfährt bei jeder Prüfung: Ihren Lizenzschlüssel, die Kennung Ihres
Arbeitsplatzes, die verwendete Programmfassung und den Zeitpunkt.

**Nicht** übermittelt werden: welchen Server Sie bearbeiten, welche Domain, welche Funde es
gab, welche Dateien Sie entfernen. Das Werkzeug sendet keine Befunddaten — weder an uns noch
sonst wohin. Ihre Kundendaten bleiben bei Ihnen.

## Nutzungsbedingungen

Erlaubt ist die Ausführung über den mitgelieferten Lader mit einem gültigen, auf Ihren
Arbeitsplatz ausgestellten Schlüssel — für beliebig viele eigene und betreute Systeme.

Nicht erlaubt: das Entschlüsseln des Pakets ohne gültige Lizenz, das Umgehen oder Nachbilden
der Lizenzprüfung, Weitergabe oder Weiterverkauf des entschlüsselten Inhalts, Bearbeitung
oder Ableitung von Werken daraus.

Die Verschlüsselung ist eine wirksame technische Schutzmaßnahme im Sinne des § 95a UrhG.

Der vollständige Wortlaut liegt in [`../paket/LICENSE`](../paket/LICENSE).

## Haftung

NT-Repair verändert Produktivsysteme. Es tut das nur nach ausdrücklicher Freigabe, es
protokolliert jeden Schritt, und es verschiebt statt zu löschen — aber die Verantwortung für
den Einsatz liegt beim Anwender.

Erzeugte BSI- und DSGVO-Meldungen sind **Entwürfe**. Sie ersetzen keine Rechtsberatung, und
die Meldeentscheidung trifft der Verantwortliche.

---

Wie der Schutz technisch funktioniert und wo seine Grenzen liegen, steht in
[`lizenzierung-technik.md`](lizenzierung-technik.md).
