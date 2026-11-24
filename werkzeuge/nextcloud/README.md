# Nextcloud-Werkzeuge für den Vorfall

Werkzeuge für Phase 7 des [Incident-Response-Playbooks](../../docs/incident-response.md#phase-7--bereinigen--härten),
wenn die kompromittierte Anwendung eine Nextcloud auf Plesk ist. Die WordPress-Aktuatoren aus
`infra/ops/secret-rotation/` greifen dort nicht. Entstanden aus den Einmal-Skripten eines Vorfalls
vom 23./24.11.2026 (Miner über `richdocumentscode/proxy.php`), verallgemeinert in #162.

Jedes Skript macht ohne `--ausfuehren` nur einen **Trockenlauf** und ändert nichts. `--help` zeigt
den Kopfkommentar mit allen Schaltern. Die Server-Skripte laufen als root auf dem Plesk-Server,
`occ` als Systembenutzer des Abos (`--abo`).

| Skript | Wo | Zweck |
|---|---|---|
| [`nc-stufenupdate.sh`](nc-stufenupdate.sh) | Server | Update aus einer EOL-Version, eine Hauptversion je Stufe; je Stufe Sicherung (DB + httpdocs), Prüfung, Rückweg. Entfernt das Einfallstor (`--app-entfernen`), verschiebt Fremdeinträge (`cgi-bin`), stellt PHP um (`--php-wechsel 28:8.3`). |
| [`nc-folgelauf.sh`](nc-folgelauf.sh) | Server | `inventur` (Geheimnisse nach Namen), `db` (DB-Passwort, Kill-Proof `ERROR 1045`), `abmelden` (alle Geräte und Sitzungen, ab NC 28) |
| [`nc-rotation-mac.sh`](nc-rotation-mac.sh) | Arbeitsplatz | Treiber: Wert erzeugen → **zuerst 1Password** → per stdin über ssh an den Server-Teil. Teile `abo`, `postfach`, `nutzer`, `pleskadmin`, `mailapp`. Gescheitert = Eintrag `VERWORFEN …` |
| [`nc-rotation-server.sh`](nc-rotation-server.sh) | Server / Mailserver | Server-Teil des Treibers; je Modus Setzen, Prüfen, Kill-Proof |
| [`nc-abschluss.sh`](nc-abschluss.sh) | Server | `cron` (Hintergrundjobs über `/etc/cron.d`, Abo bleibt in `cron.deny`), `appupdate` (mit Sicherung und Rückweg), `quarantaene` (Kopien alter Geheimnisse mit `shred -u` löschen) |
| [`op-sammel-item.sh`](op-sammel-item.sh) | Arbeitsplatz | Übergabe-Item für den Kunden: alle Items eines Tresors in einem, `--ausschluss` für Betreiber-Zugänge, `--erwartet` als Anzahl-Sperre, Fingerabdruck vorher = nachher |
| [`lib.sh`](lib.sh) | — | gemeinsame Helfer |
| [`nextcloud_selbsttest.sh`](nextcloud_selbsttest.sh) | CI | Selbsttest mit Attrappen, ohne Netz und root |

## Reihenfolge im Vorfall

```bash
# Server, als root (Skripte aus dem Repo-Stand auf den Server kopieren)
bash nc-stufenupdate.sh --domain <domain> --abo <abo> --app-entfernen richdocumentscode            # Trockenlauf
bash nc-stufenupdate.sh --domain <domain> --abo <abo> --app-entfernen richdocumentscode --ausfuehren
bash nc-folgelauf.sh inventur --domain <domain> --abo <abo>
bash nc-folgelauf.sh db       --domain <domain> --abo <abo> --ausfuehren
bash nc-folgelauf.sh abmelden --domain <domain> --abo <abo> --ausfuehren

# Arbeitsplatz: alle übrigen Zugänge, Werte zuerst in 1Password
bash nc-rotation-mac.sh --server <ssh-ziel> --mailserver <ssh-ziel> --postfach <smtp-konto> \
     --domain <domain> --abo <abo> --tresor <tresor> --tag <vorfall-tag>            # Trockenlauf
bash nc-rotation-mac.sh … --ausfuehren

# Übergabe: nur Kundenzugänge (Konten, Postfach); Plesk-Admin, Systembenutzer, DB bleiben beim Betreiber
env -u OP_SERVICE_ACCOUNT_TOKEN bash op-sammel-item.sh --tresor <tresor> --ausschluss '<regex>' --erwartet <n> --ausfuehren

# Abschluss, Server
bash nc-abschluss.sh cron        --domain <domain> --abo <abo> --ausfuehren
bash nc-abschluss.sh appupdate   --domain <domain> --abo <abo> --ausfuehren   # wenn cron.php bricht
bash nc-abschluss.sh quarantaene --domain <domain> --abo <abo> --ausfuehren   # erst nach der Rotation
```

`--ip <ip>` lässt die Prüfungen per `curl --resolve` direkt den Server treffen (an CDN oder DNS vorbei).
Ablagen: `--arbeit` (Vorgabe `/root/nc-ir/<domain>`, Sicherungen und Lauf-Log) und `--quarantaene`
(Vorgabe `/root/quarantaene/nc-<domain>`). Jede Massnahme steht in `/root/changelog.md`.

## Regeln, die die Skripte einhalten

- **Werte nie als Argument, nie in einer Ausgabe.** Plesk über `PSA_PASSWORD` und `-passwd ""`,
  Nextcloud über `OC_PASS` mit `--password-from-env`, MySQL über `MYSQL_PWD` mit `--no-defaults`,
  curl über `-K -`. Belege nur als sha256-12. Der Selbsttest prüft das für jeden Lauf.
- **Rotiert ist, was den alten Wert ablehnt** (Lex Clavis). Wo der alte Wert unbekannt ist
  (Plesk-Admin, Systembenutzer), steht im changelog, was belegt ist — beim Plesk-Admin
  „nicht feststellbar“, nie „bestanden“.
- **Schema-Änderungen nur mit Sicherung und Rückweg** (Lex Mutatio): jede Update-Stufe, jedes App-Update.
- `--abo` muss der Systembenutzer sein und `--domain` die Hauptdomain des Abos, sonst lehnt
  `plesk bin subscription` ab und es ändert sich nichts.

## Grenzen

- Die verallgemeinerte Fassung ist mit Attrappen getestet, ein Lauf gegen eine echte Instanz steht
  aus (#165). Bis dahin `# Rueckweg: nein` in den Kopfzeilen.
- Nur MySQL/MariaDB. `secret` und `passwordsalt` der Nextcloud werden nicht rotiert (zerstört
  verschlüsselte Daten); was mit `secret` verschlüsselt ist (Mail-App-Konten), wird stattdessen neu gesetzt.
- Ausgehende Sperren (Plesk-Firewall) gehören nicht hierher: siehe Playbook, Phase 7, Abschluss,
  und die Absicherung durch infra `ops/input-spruenge`.
