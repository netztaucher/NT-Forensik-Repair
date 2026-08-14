# Fundstellen-Details

> Pfade **relativ zum Kundenverzeichnis** (nicht der absolute Serverpfad).
> Erzeugt: <ZEIT> · Prüfung `<LAUF-ID>` · 28 Fundstelle(n), 1 zu prüfen.

| Familie | Anzahl | Geschäftsmodell |
|---|---|---|
| Getarnte Payload | 9 | Nachladbarer Schadcode in Nicht-PHP-Datei |
| Verändertes Plugin | 8 | Fremder Code in einem legitimen Plugin — nachträglich eingebaute Hintertür |
| Manipulierte .htaccess | 4 | Zugriffsregeln zugunsten des Angreifers — hält seine Dateien erreichbar und sperrt Mitbewerber aus |
| PHP im Upload-Verzeichnis | 3 | Ausführbarer Code dort, wo nur Dateien liegen sollen — der klassische Weg einer hochgeladenen Shell |
| Code-Injection | 2 | Schadcode in legitime Dateien eingeschleust |
| Bekannte Schaddatei | 1 | Nach Namensmuster erkanntes Angriffswerkzeug (Dateimanager, Uploader, Shell) |
| Tarnstruktur | 1 | Angelegte Verzeichnisse, die echte nachahmen — Ablage für Nutzlasten |

## Getarnte Payload (9) — Nachladbarer Schadcode in Nicht-PHP-Datei

- `kunde-zwei.example/httpdocs/wp-content/plugins/beispiel-plugin/assets/banner.png`
- `kunde-zwei.example/httpdocs/wp-content/uploads/2026/03/clip.avi`
- `kunde-zwei.example/httpdocs/wp-content/uploads/2026/03/clip.mov`
- `kunde-zwei.example/httpdocs/wp-content/uploads/2026/03/logo.png`
- `kunde-zwei.example/httpdocs/wp-content/uploads/2026/03/wiederherstellung/bild1.png`
- `kunde-zwei.example/httpdocs/wp-content/uploads/2026/03/wiederherstellung/bild2.png`
- `kunde-zwei.example/httpdocs/wp-content/uploads/2026/03/wiederherstellung/bild3.png`
- `kunde-zwei.example/httpdocs/wp-content/uploads/2026/03/wiederherstellung/bild4.png`
- `kunde-zwei.example/httpdocs/wp-content/uploads/2026/03/wiederherstellung/bild5.png`

## Verändertes Plugin (8) — Fremder Code in einem legitimen Plugin — nachträglich eingebaute Hintertür

- `kunde-zwei.example/httpdocs/wp-content/plugins/pruefstand-aktuell/gross-injiziert.php`
- `kunde-zwei.example/httpdocs/wp-content/plugins/pruefstand-aktuell/gross-sauber.php`
- `kunde-zwei.example/httpdocs/wp-content/plugins/pruefstand-aktuell/pruefstand-aktuell.php`
- `kunde-zwei.example/httpdocs/wp-content/plugins/pruefstand-aktuell/lib/b.php`
- `kunde-zwei.example/httpdocs/wp-content/plugins/pruefstand-aktuell/lib/c.php`
- `kunde-zwei.example/httpdocs/wp-content/plugins/pruefstand-aktuell/lib/a.php`
- `kunde-zwei.example/httpdocs/wp-content/plugins/pruefstand-aktuell/lib/d.php`
- `kunde-zwei.example/httpdocs/wp-content/plugins/pruefstand-aktuell/lib/e.php`

## Manipulierte .htaccess (4) — Zugriffsregeln zugunsten des Angreifers — hält seine Dateien erreichbar und sperrt Mitbewerber aus

- `kunde-zwei.example/backups/updater-abc123/nextcloud-28.0.1.2-1700000000/.htaccess`
- `kunde-zwei.example/cloud.kunde-zwei.example/.htaccess`
- `kunde-zwei.example/httpdocs/.htaccess`
- `kunde-zwei.example/httpdocs/wp-content/uploads/.htaccess`

## PHP im Upload-Verzeichnis (3) — Ausführbarer Code dort, wo nur Dateien liegen sollen — der klassische Weg einer hochgeladenen Shell

- `kunde-zwei.example/httpdocs/wp-content/uploads/cache/wpml/twig/3e/getarnt.php`
- `kunde-zwei.example/httpdocs/wp-content/uploads/2026/03/bild.php`
- `kunde-zwei.example/httpdocs/wp-content/uploads/2026/03/hilfe.php`

## Code-Injection (2) — Schadcode in legitime Dateien eingeschleust

- `kunde-zwei.example/httpdocs/wp-content/mu-plugins/cache.php`
- `kunde-zwei.example/httpdocs/wp-includes/load.php`

## Bekannte Schaddatei (1) — Nach Namensmuster erkanntes Angriffswerkzeug (Dateimanager, Uploader, Shell)

- `kunde-zwei.example/cloud.kunde-zwei.example/filefuns.php`

## Tarnstruktur (1) — Angelegte Verzeichnisse, die echte nachahmen — Ablage für Nutzlasten

- `kunde-zwei.example/cloud.kunde-zwei.example/config/config`

---

# Zu prüfen — Einordnung offen (1)

> Diese Fundstellen sind **kein belegter Schadcode** und zählen nicht in die
> Zahl oben. Ihre Quelle meldet sie als prüfenswert, nicht als bestätigt:
> eine kernfremde Datei ist oft eine Update-Altlast, ein mu-Plugin meistens
> gewollt. Ungeprüft bleiben sollten sie trotzdem nicht.

## Kernfremde Datei (1) — Datei im Programmkern, die dort nicht hingehört — Hintertür oder Update-Altlast

- `kunde-zwei.example/httpdocs/wp-admin/mu.php`

