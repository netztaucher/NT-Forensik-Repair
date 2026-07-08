# Sicherheitsvorfall — Bericht für beispiel-shop.example

> **Beispielbericht mit fiktiven Daten.** Alle Domains, IP-Adressen, Hashes und
> Namen sind erfunden (RFC-5737-Dokumentations-IPs, `example`-Domains). Erzeugt mit
> `wp_plesk_forensik.sh` zur Veranschaulichung des Ausgabeformats.

| | |
|---|---|
| **Einstufung** | 🔴 KRITISCH |
| **Erstellt durch** | netztaucher \| digital |
| **Datum** | 08.07.2026 |
| **Betroffene Domain** | beispiel-shop.example |
| **Server** | srv-web01.hoster.example |
| **Prüfungs-ID** | 20260708_090000_server |
| **Befunde** | 🔴 1 kritisch · ⚠️ 12 auffällig · ✅ 230 geprüft |

---

## 1. Das Wichtigste in einem Satz

**Ihre Website wurde nachweislich kompromittiert.** Ein Angreifer hat über einen längeren Zeitraum **17 versteckte Hintertüren** in Ihrem Webauftritt platziert und hatte zuletzt **aktiven Zugriff** auf Ihren WordPress-Administrationsbereich.

**Warum das dringend ist:** Solange die Zugangsdaten des Angreifers gültig sind, kann er jederzeit zurückkehren, neue Hintertüren legen, Kundendaten abgreifen, über Ihre Domain Spam versenden oder Ihre Seite für Betrug missbrauchen. Wir haben die akute Gefahr eingedämmt (Abschnitt 6), aber **die Zugänge müssen jetzt von Ihnen geändert werden** — sonst kommt der Angreifer sofort zurück.

## 2. ⏱️ Sofortmaßnahmen — bitte noch heute

| # | Maßnahme | Frist |
|---|---|---|
| 1 | **Alle Passwörter ändern**: WordPress-Admin, Plesk-Panel, FTP/SFTP, SSH, Datenbank. Ausnahmslos alle. | sofort (< 24 h) |
| 2 | **Alle WordPress-Sitzungen ungültig machen** (Sicherheitsschlüssel / „Salts" in `wp-config.php` neu erzeugen). | sofort (< 24 h) |
| 3 | **Verwundbares Datei-Manager-Plugin deaktivieren/aktualisieren** — über es lief der Angriff (Abschnitt 5). | sofort (< 24 h) |
| 4 | **Angreifer-IP `203.0.113.66` sperren** (server- und WordPress-seitig). | sofort (< 24 h) |
| 5 | **Prüfen, ob Kundendaten betroffen sind** — falls ja, läuft die 72-Stunden-DSGVO-Frist (Abschnitt 7). | < 72 h |

## 3. Was wir technisch gefunden haben

**17 Hintertüren („Webshells") auf beispiel-shop.example.** Das sind winzige, getarnte PHP-Skripte (190–280 Byte), über die der Angreifer per Fernzugriff beliebige Befehle auf Ihrem Server ausführen kann. Sie tragen harmlose Namen und liegen in unauffälligen Ordnern:

```
httpdocs/img/social-icon.php        httpdocs/css/theme-cache.php
httpdocs/img/banner/promo-2.php     httpdocs/cgi-bin/mime-helper.php
httpdocs/js/lib-loader.php          ...
```

**Technische Funktionsweise:** Jede Datei rekonstruiert per Trick den Befehl
`eval(base64_decode($_COOKIE['<Schlüssel>']))`. Der Schadcode wird also nicht in der URL,
sondern in einem **Cookie** übergeben — dadurch taucht er in normalen Zugriffsprotokollen
nicht auf und entgeht den meisten Virenscannern. Genau diese Tarnung (gemischte Groß-/
Kleinschreibung `EvaL`, zerstückelte Variablennamen) ist der Grund, warum die Dateien
lange unentdeckt blieben.

**Zeitraum der Platzierung (aus den Datei-Zeitstempeln):**

| Erste Hintertür | Letzte Hintertür | Dauer |
|---|---|---|
| 12.02.2024 | 03.01.2025 | **~11 Monate durchgehender Zugriff** |

## 4. Reichweite — hatte der Angreifer Server-Vollzugriff (Root)?

🟢 **Nein. Der Angriff blieb auf Website-Ebene begrenzt — der Server-Administratorzugang (Root) wurde nicht übernommen.**

| Prüfung | Ergebnis |
|---|---|
| Angreifer-IP `203.0.113.66` in den SSH-Server-Protokollen | **0 Treffer** — nie am Systemzugang |
| Rechte der 17 Hintertüren | nur Website-Benutzer, **nicht Root** |
| Fremde SSH-Schlüssel (Root oder andere Websites) | keine |
| Rechteausweitung (sudo/su) durch Website-Benutzer | keine |
| Unversehrtheit der System-Programme (Rootkit-Test) | bestanden |

**WordPress-Datenbank:** 🟢 Keine Angreifer-Spuren (keine fremden Admin-Konten, keine manipulierten Optionen).

## 5. Angriffshergang & Angreifer

| | |
|---|---|
| **Angreifer-IP** | `203.0.113.66` (kein gültiger Reverse-DNS-Eintrag) |
| **Aktive Sitzung** | 06.07.2026, 20:10 – 22:40 Uhr — ~2.900 Anfragen |
| **Zugriffsart** | Eingeloggter WordPress-Administrator (gestohlene/erratene Zugangsdaten) |

**So ist der Angreifer vorgegangen:**

1. Anmeldung im WordPress-Adminbereich mit gültigen Zugangsdaten.
2. Nutzung eines **Datei-Manager-Plugins** als Werkzeug, um Dateien abzulegen.
3. **Direkter Aufruf mehrerer Hintertüren** mit Server-Antwort „200 OK" — die Hintertüren waren aktiv.

**Ergänzend — Rateangriffe auf den SSH-Serverzugang** (über 28.000 Fehlversuche). Auffälligste IPs zum Sperren:

```
192.0.2.10    192.0.2.55    198.51.100.7
198.51.100.23 203.0.113.9   203.0.113.140
```

## 6. Bereinigung & dauerhafte Absicherung

**Bereits von uns durchgeführt:**

- Vollständige forensische Sicherung aller Protokolle und Beweise (revisionssicher, mit Prüfsummen).
- Alle 17 Hintertüren in schreibgeschützte Quarantäne verschoben; Live-Webverzeichnis danach nachweislich frei.

**Als Nächstes nötig:**

1. Passwörter & Sitzungen wie in Abschnitt 2 — zuerst.
2. WordPress-Datenbank auf fremde Admin-Konten prüfen.
3. WordPress aus sauberem Backup (vor 02/2024) neu aufsetzen.
4. Plugins aktualisieren, Datei-Manager-Plugins entfernen.
5. Server härten: SSH-Key-only, Fail2ban, ModSecurity, automatische Malware-Scans.

## 7. Rechtliche Pflichten (bitte umgehend prüfen)

> **Datenschutz (DSGVO Art. 33):** Bei möglicher Betroffenheit personenbezogener Daten
> Meldung an die Datenschutz-Aufsichtsbehörde **innerhalb von 72 Stunden**.

> **BSI-Meldung:** Eine vorbereitete Meldung liegt bei (`bsi_meldung.md`).

## 8. Ihre Unterlagen zu diesem Vorfall

| Dokument | Zweck |
|---|---|
| `kundenbericht.md` | Dieses Dokument |
| `bsi_meldung.md` | Vorbereitete BSI-Meldung |
| `technik_bericht.md` | Vollständiger technischer Bericht |
| `belege/` | Rohdaten & Beweismittel, SHA256-versiegelt |

---

### Über netztaucher | digital

Diese Analyse stammt aus unserer laufenden **WordPress-Betreuung und -Absicherung**.
Wir übernehmen Wartung, Härtung, Monitoring und Notfall-Forensik für WordPress- und
Rootserver.

**→ https://netztaucher.com/wordpress**

---
*netztaucher | digital — maschinell erstellt (wp_plesk_forensik.sh). Beispielbericht mit fiktiven Daten.*
