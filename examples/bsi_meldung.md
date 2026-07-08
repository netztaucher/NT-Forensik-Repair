# Meldung eines IT-Sicherheitsvorfalls an das BSI

> **Beispiel mit fiktiven Daten.** Alle Angaben sind erfunden (RFC-5737-IPs,
> `example`-Domains). Entwurf — vor Versand prüfen und `[AUSFÜLLEN]`-Felder ergänzen.
>
> **Meldewege:**
> - Meldepflichtige (KRITIS / NIS2 / §32 BSIG): **BSI Melde- und Informationsportal** — https://mip.bsi.bund.de
> - Freiwillige Meldung: https://www.bsi.bund.de → „Cyber-Sicherheitsvorfall melden"
> - Bei Straftatverdacht zusätzlich: **ZAC** der Landespolizei — Strafanzeige empfohlen
>
> **Fristen (NIS2/BSIG):** Erstmeldung ≤ 24 h, Folgemeldung ≤ 72 h, Abschlussbericht ≤ 1 Monat.
> **DSGVO Art. 33:** Bei personenbezogenen Daten Meldung an die Aufsichtsbehörde ≤ 72 h (separat!).

---

## 1. Meldende Stelle

| Feld | Angabe |
|---|---|
| Unternehmen (Dienstleister) | netztaucher \| digital |
| Ansprechpartner | [AUSFÜLLEN] |
| E-Mail | [AUSFÜLLEN] |
| Telefon | [AUSFÜLLEN] |
| Meldung erfolgt | ☐ im eigenen Namen  ☑ im Auftrag des betroffenen Unternehmens |

## 2. Betroffenes Unternehmen / Einrichtung

| Feld | Angabe |
|---|---|
| Unternehmen | [AUSFÜLLEN — Betreiber beispiel-shop.example] |
| Branche / Sektor | Handel (Onlineshop) |
| Betroffene Domain | beispiel-shop.example |
| Betroffener Server | srv-web01.hoster.example |
| Plattform | Plesk Obsidian, Ubuntu 22.04, WordPress |
| Einstufung | ☐ KRITIS  ☐ NIS2  ☑ nicht meldepflichtig (freiwillige Meldung) |

## 3. Zeitliche Einordnung

| Feld | Angabe |
|---|---|
| Feststellung des Vorfalls | 08.07.2026 (forensische Analyse) |
| Nachgewiesener Angreifer-Zugriff | 06.07.2026, 20:10–22:40 Uhr |
| Vermuteter Beginn | 12.02.2024 (Zeitstempel der ersten Hintertür) |
| Vorfall andauernd? | ☑ ja (Zugänge bei Feststellung noch nicht rotiert) |

## 4. Art des Vorfalls

☑ Kompromittierung Webserver/CMS (WordPress)
☑ Webshell / Hintertür (17 Stück)
☑ Missbrauch legitimer Admin-Funktionen / verwundbarer Plugins

## 5. Sachverhalt

Auf beispiel-shop.example wurden **17 obfuskierte PHP-Hintertüren („Cookie-Backdoors")**
festgestellt. Jede Datei führt in einem HTTP-Cookie übergebenen Code aus
(`eval(base64_decode($_COOKIE[...]))`), verschleiert durch Variable-Variablen und
gemischte Groß-/Kleinschreibung. Die Dateien sind 190–280 Byte groß, tragen
unauffällige Namen und liegen verstreut in `img/`, `css/`, `js/`, `cgi-bin/`.
Die Zeitstempel belegen kontinuierliche Platzierung über ~11 Monate
(12.02.2024 – 03.01.2025). Protokolle zeigen für den 06.07.2026 eine Angreifer-Sitzung
(~2.900 Anfragen) als eingeloggter WordPress-Admin über ein Datei-Manager-Plugin.

## 6. Automatisiert erhobene Kennzahlen

| Indikator | Wert |
|---|---|
| Hintertüren / Webshells (bestätigt) | 17 |
| Zeitraum der Platzierung | 12.02.2024 – 03.01.2025 |
| Fehlgeschlagene SSH-Login-Versuche | 28.400 |
| Domains auf dem Server | 38 |

## 7. Indikatoren (IOCs)

### Angreifer-IP (Web / WordPress-Admin)

```
203.0.113.66    — aktive Admin-Sitzung 06.07.2026, kein Reverse-DNS
```

### Auffälligste IPs SSH-Brute-Force

```
192.0.2.10    192.0.2.55    198.51.100.7
198.51.100.23 203.0.113.9   203.0.113.140
```

### Datei-Indikatoren (Auszug)

```
img/social-icon.php   css/theme-cache.php   js/lib-loader.php
cgi-bin/mime-helper.php   img/banner/promo-2.php
```

Code-Signatur: `${$a.$b.$c}` (Variable-Variable → `_COOKIE`) + mixed-case
`EvaL(base64_decode(...))`. SHA256-Prüfsummen: siehe `belege/` (fiktiv im Beispiel).

## 8. Reichweite / Root-Kompromittierung

🟢 **Keine Hinweise auf Root-Kompromittierung — Vorfall auf Web-User-Ebene begrenzt.**

| Prüfung | Ergebnis |
|---|---|
| Server-Root kompromittiert? | Nein (nach Beweislage) |
| Angreifer-IP in SSH-Auth-Logs | 0 Treffer |
| Fremde SSH-Keys (root + Web-User) | keine |
| Privilege-Escalation | keine |
| Binär-Integrität (`dpkg -V`) | unverändert → kein Rootkit |

## 9. Vermuteter Angriffsvektor

1. Kompromittierte WordPress-Administrator-Zugangsdaten (wahrscheinlichste Ursache).
2. Missbrauch eines Datei-Manager-Plugins zum Ablegen der Hintertüren.
3. Persistenz über verteilte, getarnte Backdoors.

## 10. Bereits ergriffene Maßnahmen

- Forensische Vollsicherung (revisionssicher, SHA256).
- Auswertung der Zugriffsprotokolle → Angreifer-IP, Vektor, Zeitachse.
- Alle 17 Hintertüren in schreibgeschützte Quarantäne verschoben.

## 11. Geplante Maßnahmen

- Rotation aller Zugangsdaten, Invalidierung aller Sitzungen.
- Prüfung der WordPress-DB, Neuaufsetzen aus sauberem Backup.
- Server-Härtung (SSH-Key-only, Fail2ban, ModSecurity), IOC-IP-Sperren.

## 12. Anlagen

| Anlage | Pfad |
|---|---|
| Technischer Forensik-Bericht | `technik_bericht.md` |
| Kundenbericht | `kundenbericht.md` |
| Beweismittel inkl. Prüfsummen | `belege/` |

---
*Beispiel mit fiktiven Daten — netztaucher | digital (wp_plesk_forensik.sh). Struktur nach BSI-Meldevorgaben; vor Versand fachlich prüfen.*
