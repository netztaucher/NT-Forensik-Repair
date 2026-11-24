# NT-Forensik — Incident-Response-Playbook

Schritt-für-Schritt-Ablauf für einen echten Vorfall — von der Meldung bis zur Härtung. `wp_plesk_forensik.sh` deckt die Phasen **Sichern**, **Analysieren** und **Dokumentieren** ab; die übrigen Schritte sind manuell.

> Reihenfolge ist wichtig: **erst sichern, dann anfassen.** Wer zuerst aufräumt, vernichtet Beweise und verliert die Ursache.

---

## Phase 0 — Vor dem ersten Befehl

- **Nicht überstürzt löschen oder neu aufsetzen.** Beweise zuerst.
- **Zugang notieren:** Wie wurde der Vorfall entdeckt? Wann? Durch wen?
- **Scope klären:** ein Vhost oder der ganze Server? Im Zweifel: ganzer Server.
- **Uhr stellen:** alle folgenden Zeiten in einer Zeitzone dokumentieren.

## Phase 1 — Sichern & Analysieren (automatisiert)

```bash
ssh root@SERVER "git clone --depth 1 https://github.com/netztaucher/NT-Forensik-Repair.git /root/nt-forensik"
ssh root@SERVER "bash /root/nt-forensik/wp_plesk_forensik.sh betroffene-domain.tld"
```

Der Lauf:
- sichert **sofort alle Logs** (bevor Rotation zuschlägt),
- erzeugt `kundenbericht.md`, `bsi_meldung.md`, `technik_bericht.md`,
- legt SHA256-versiegelte Belege an und packt **zwei** Archive:
  `<LAUF>_kunde.tar.gz` (weitergabefähig) und `<LAUF>_betreiber.tar.gz` (nicht weitergeben).

> **Frischer Vorfall: Roh-Protokolle vor der nächsten Plesk-Rotation sichern.**
> Plesk rotiert die vhost-Protokolle einmal täglich (auf web68/cletus um 06:43). Ist
> „Anonymize IPs during log rotation“ eingeschaltet (*Tools & Settings › Server Settings*),
> trägt die Rotation nur noch das /24 — aus `43.250.53.42` wurde am 21.10.2026 `43.250.53.0`,
> die volle Adresse stand danach nirgends mehr (#142). Die Einstellung gilt **serverweit**;
> ein Schalter je Abo ist nicht belegt, und Plesk bietet dafür keine CLI. Deshalb vor der
> nächsten Rotation, auch wenn Abschnitt 2 (Log-Archiv) übersprungen wird:
>
> ```bash
> D=betroffene-domain.tld
> tar czf /root/roh-logs_${D}_$(date +%Y%m%d-%H%M).tar.gz -C /var/www/vhosts/system/$D logs
> ```
>
> Abschnitt 4 meldet gekürzte Protokolle je Datei (Beleg `zugriffsprotokolle_anonymisiert`)
> und ⚪ *„IOC-Adressen nur als /24“*, sobald eine IOC-Adresse daraus stammt; in
> `findings.json` steht dann `metrics.logs_anonymisiert: 1`. Solche Adressen nicht als
> Einzel-IP sperren und nicht als Einzel-IP melden.

**Ergebnis sichten:**
```bash
ssh root@SERVER "cat /root/wartungsscripte/forensik/<LAUF>/kunde/kundenbericht.md"
```
Achte auf: Gesamt-Ampel, **Dropper-Cluster** (welche Domain?), **Root-Verdikt**, **WP-DB-Verdikt**.

## Phase 2 — Manuelle Log-Auswertung (Angreifer bestimmen)

Die Rohdaten liegen in `belege/`. Ziel: **Angreifer-IP, Einfallstor, Zeitachse**.

```bash
# Wer hat die gefundenen Backdoors aufgerufen?  (Namen aus dem Dropper-Cluster einsetzen)
D=betroffene-domain.tld
LOGDIR=/var/www/vhosts/system/$D/logs
{ cat $LOGDIR/access_log $LOGDIR/*.processed; zcat $LOGDIR/*.gz; } 2>/dev/null \
  | grep -aE "backdoor1\.php|backdoor2\.php" \
  | awk '{print $1}' | sort | uniq -c | sort -rn

# Was hat diese IP sonst getan?  (Admin-Login? Datei-Manager? Plugin-Exploit?)
grep -a "<ANGREIFER-IP>" $LOGDIR/access_log \
  | grep -aoE '"(GET|POST) [^ ]+' | sort | uniq -c | sort -rn | head -30
```

Typische Muster: eingeloggter `wp-admin`, Datei-Manager-Plugin (`admin-ajax.php?action=...file...`), verwundbare Plugin-Endpunkte (`?dir=`, `?file=`).

> Cookie-Backdoors übergeben ihren Payload im **Cookie-Header** — der wird nicht geloggt. Die Log-Spur zeigt Aufrufe (GET/POST) und Antwortcodes, nicht den Payload.

## Phase 3 — Root-Frage klären

Der Root-Verdikt (§12) beantwortet die wichtigste Frage:

- 🟢 **auf Web-User-Ebene begrenzt** → nur die betroffene Website bereinigen/neu aufsetzen.
- 🔴 **Root nicht ausgeschlossen** → **gesamten Server** als kompromittiert behandeln.

Gegenprüfen: Taucht die Angreifer-IP in den SSH-Auth-Logs auf? Gibt es fremde SSH-Keys? Wenn beides nein und `dpkg -V` sauber → der Server-Kern ist mit hoher Wahrscheinlichkeit intakt.

## Phase 4 — Schadcode quarantänisieren (nicht löschen!)

Erst **nach** Beweissicherung. Verschieben statt löschen, Hashes protokollieren, schreibgeschützt ablegen:

```bash
RUN=/root/wartungsscripte/forensik/<LAUF>
QDIR=$RUN/quarantaene; mkdir -p "$QDIR"
DOC=/var/www/vhosts/$D/httpdocs

# Vorher hashen
for f in pfad/zu/backdoor1.php pfad/zu/backdoor2.php; do
  sha256sum "$DOC/$f" >> "$RUN/belege/quarantaene_hashes.txt"
done
# Verschieben unter Pfaderhalt + schreibschützen
for f in pfad/zu/backdoor1.php pfad/zu/backdoor2.php; do
  mkdir -p "$QDIR/$(dirname "$f")"
  mv "$DOC/$f" "$QDIR/$f" && chmod 400 "$QDIR/$f"
done
```

Danach erneut scannen und bestätigen, dass **0 Backdoors** im Live-Verzeichnis verbleiben.

## Phase 5 — Berichte finalisieren

Im `kundenbericht.md`/`bsi_meldung.md` ergänzen (die maschinellen Teile stehen schon):
- Abschnitt „Angriffshergang" um die bestätigte Angreifer-IP + Vektor,
- „Bereits durchgeführt" um Quarantäne/Offline-Nahme,
- BSI-Formularfelder (Kontakt, Einstufung).

**Ursache auch beim Hersteller suchen.** Kam der Einstieg über eine Fernwartung oder ein
Premium-Plugin (UpdraftCentral, ManageWP, MainWP, WPMU-Dashboard), zuerst die
Sicherheitsmeldungen des Herstellers prüfen. Im Vorfall vom 21.10.2026 stammte der
Schlüssel aus einem Einbruch bei TeamUpdraft — belegt durch das `updraftcentral_client_log`
(Sondierung unter erfundener Kennung, danach ein gültig signierter Befehl).

Belege nach Änderungen neu versiegeln:
```bash
cd "$RUN/belege" && sha256sum ./* > SHA256SUMS
```

### Kundenpaket — Standard seit 21.10.2026

Was an den Kunden geht, folgt diesem Standard. Das Werkzeug erzeugt ihn (#149, #150, #151).
Layout seit 23.11.2026: **Berichtslayout** des Designsystems NT Dokumente (Komponente Bericht),
freigegeben von Marco, nachdem das frühere Layout mit Kopfband, Statuskarten und halbleeren
Kapitelseiten als nicht seriös abgelehnt wurde (#160).

| Teil | Form |
|---|---|
| Sicherheitsbericht | Briefkopf (Logo, Dokumenttitel rechts), Haarlinie, Vertraulichkeitsvermerk, Adress-Cards Auftraggeber/Ersteller mit Vorgangsnummer; Abschnitte 1 Zusammenfassung, 2 Bewertung, 3 Ablauf, 4 Ergriffene Massnahmen, 5 Nächste Schritte, 6 Meldepflichten, Unterschrift; Anhang „Technisches Protokoll" auf eigener Seite |
| Dokumentation Art. 33 DSGVO | 2 Seiten, Zeitpunkte, Angaben nach Abs. 3 a bis d mit Ausfüllfeldern, Prüfung, Abwägung, Entscheidung mit Unterschrift der Verantwortlichen |
| Einordnung BSI-Meldung | 2 Seiten, Einordnung KRITIS/NIS2/freiwillig, Angaben für eine freiwillige Meldung, Indikatoren (IOC) |
| Geschäftsfuss | auf jeder Seite: Anschrift, Handelsregister, Kontakt, „Vertraulich", „Seite x von y" |
| Bildschirmfotos | Startseiten nach der Bereinigung (Chrome headless, 1440×1000) |
| Anschreiben | kurze HTML-Mail (~150 Wörter, ein Kasten „Bitte heute", Meldepflicht in 2–3 Sätzen), normale Gross-/Kleinschreibung, kein Kopf, kein Logo |

**Keine Interna im Kundenpaket:** keine Issue-Nummern, Werkzeugnamen oder -stände,
Serverpfade, Ablagen (1Password, Register), internen Servernamen, keine Daten anderer
Kunden, keine Admin-Benutzernamen, kein unerklärter Fachjargon (Liste in #150).
Beweise zum Vorfall (Hashes, Angreifer-IPs, Zeitstempel, Pfade im Kunden-Webspace) bleiben.

**Vor der Auslieferung jede Seite als Bild prüfen.** Umbrüche, Abstände und fluchtende
Tabellenzeilen sind nur im Bild sichtbar. Danach `pdftotext` gegen die Interna-Liste.

**Das Protokoll (Anhang) wird geprüft, nicht übernommen.** Ohne Fall-Datei übernimmt der
Anhang, was der Lauf einordnet, Fehlalarme eingeschlossen (Vorfall vom 23.11.2026: ein
gewöhnliches PDF als Schadcode, das bekannte Einfallstor als „nicht belegt"). Das Werkzeug
setzt die Dokumente dann als **Entwurf** (Vermerk „nicht zur Auslieferung", roter Kasten im
Anhang, Rückgabe 4), und `werkzeuge/kundenpaket.sh` nimmt sie nicht ins Paket. Freigeben:
in der Fall-Datei `bericht.protokoll` mit dem geprüften Protokoll liefern oder, wenn die
Liste aus dem Lauf stimmt, `"protokoll_geprueft": true` unter `bericht` setzen.

So entsteht das Paket:

```bash
# 1. Der Lauf hat einen Entwurf aus seinen Funden gebaut (kunde/NT-*.pdf) und die
#    Vorlage betreiber/kundenpaket_fall.entwurf.json geschrieben. Kunde, Erzählung,
#    Bereinigung, Aufgaben, Meldepflicht und das geprüfte Protokoll dort eintragen
#    (Muster: pruefstand/kundenpaket/fall.json), dann neu setzen:
reportgen/kundenpaket.py --lauf "$RUN" --fall fall.json --ziel "$RUN/kunde" \
    --pruefung "$RUN/betreiber/kundenpaket_pruefung"
# 2. Jede Seite ansehen: $RUN/betreiber/kundenpaket_pruefung/seiten/*.png
# 3. Anschreiben mit Bildschirmfotos der Startseiten, Entwurf in Apple Mail:
mailgen/anschreiben.py --fall fall.json --ziel "$RUN/betreiber/mail" \
    --anhang "$RUN"/kunde/NT-*.pdf --bildschirmfoto https://kunde.tld --apple-mail
# 4. Übergabepaket mit Belegen (prüft die PDFs erneut gegen die Interna-Liste):
werkzeuge/kundenpaket.sh "$RUN"
```

`reportgen/kundenpaket.py` setzt im Fluss (WeasyPrint), prüft jede Seite auf
Geschäftsfuss und Überlauf über den rechten Satzspiegel, DSGVO und BSI auf genau 2 Seiten
und alle Texte auf die Sprachregeln, und legt die Seitenbilder beim Betreiber ab. Ansehen
muss sie trotzdem ein Mensch. Der Wächter `werkzeuge/interna-waechter.sh` liest die Sperrliste
`werkzeuge/interna-sperrliste.txt`; Namen anderer Kunden desselben Servers lassen sich
über `NT_INTERNA_EXTRA=<datei>` ergänzen.

## Phase 6 — Melden (falls einschlägig)

| Meldeweg | Wann | Frist |
|---|---|---|
| **Datenschutz-Aufsichtsbehörde** (DSGVO Art. 33) | personenbezogene Daten betroffen/möglich | **72 h** ab Kenntnis |
| **BSI-Meldeportal** (mip.bsi.bund.de) | KRITIS / NIS2 / §32 BSIG | Erst ≤ 24 h, Folge ≤ 72 h |
| **BSI freiwillig** | alle anderen (Allianz für Cybersicherheit) | jederzeit sinnvoll |
| **ZAC der Landespolizei** | Straftatverdacht | Strafanzeige empfohlen |

**Meldepflicht belegen statt schätzen.** Für Art. 33 zählen, was der Angreifer *tatsächlich*
tun konnte und was in der Instanz liegt:
- ausgeführte Befehle der Fernwartung (Client-Log) und Antworten > 10 MB im Zugriffsprotokoll,
- Personenbezug zählen: Benutzer, Kommentare mit E-Mail, Formular-/Newsletter-/Bestell-/Quizdaten.

Bleibt es bei „kein Abruf, nur Admin-Konten", ist das Risiko voraussichtlich keines: keine
Meldung, aber Dokumentation nach Abs. 5 (unterschrieben beim Verantwortlichen). NIS2 gilt
seit 06.12.2025 für mittlere Unternehmen (≥ 50 Beschäftigte oder > 10 Mio. € Umsatz und
Bilanzsumme) in den gelisteten Sektoren; Stand und Quelle im Dokument nennen. Keine
Rechtsberatung — die Entscheidung trifft der Verantwortliche.

## Phase 7 — Bereinigen & Härten

**Sofort:**
- Alle Passwörter rotieren (WordPress, Plesk, FTP, SSH, DB) — **nur über die Aktuatoren**
  in `infra/ops/secret-rotation/` (`rotate-plesk-wp-db.sh`, `rotate-plesk-ftp.sh`,
  `set-wp-user-password.sh`), mit Kill-Proof: rotiert ist erst, was den alten Wert ablehnt.
- Fernwartungs-Schlüssel widerrufen und von aussen prüfen (UpdraftCentral: RPC-POST mit
  alter Kennung muss die normale Startseite liefern, nicht eine leere Antwort).
- Im Kunden-Webspace gespeicherte Fremd-Zugangsdaten entfernen (z. B. updraftplus.com-Login
  in `updraftplus-addons_options`).
- Zusätzliche FTP-Unterkonten und ungenutzte `.ssh/id_rsa` prüfen; unbekannte sperren bzw. in Quarantäne.
- Alle WP-Sitzungen invalidieren (Salts in `wp-config.php` neu).
- `WP_DEBUG` abschalten, wenn es an ist (vorher `wp-config.php` sichern).
- Angreifer-IP + Brute-Force-IPs sperren — anonymisierte `.0`-Adressen nie als Einzel-IP.
- Verwundbare/genutzte Plugins deaktivieren/aktualisieren.

**Kurzfristig:**
- WordPress **aus sauberem Backup vor der Erstinfektion** neu aufsetzen (nicht nur „drüberbügeln").
- WP-DB auf fremde Admins/Optionen prüfen (der §11-Verdikt hilft).
- Fail2ban + ModSecurity (OWASP CRS) aktivieren.

**Nextcloud-Fall (gemessen 23.11.2026):** die WordPress-Aktuatoren greifen hier nicht.
Bis die Skripte im Repo liegen (#162), gilt dieses Vorgehen:
- **Werte nie als Argument.** Plesk: `PSA_PASSWORD="$NEU" plesk bin subscription|mail -u <x> -passwd ""`,
  Plesk-Admin genauso mit `plesk bin admin --set-admin-password -passwd ""`.
  Nextcloud: `OC_PASS` + `occ user:resetpassword --password-from-env <uid>`, unter `runuser`
  nur mit `--whitelist-environment=OC_PASS`. curl liest Zugangsdaten mit `-K -` von stdin.
- **Reihenfolge:** Wert auf dem Mac erzeugen, zuerst in 1Password ablegen, dann per stdin über
  ssh an das Server-Skript. Scheitert das Setzen, bekommt der Eintrag das Präfix `VERWORFEN`.
- **Kill-Proof je Klasse:** DB `ERROR 1045` mit altem Wert · Systembenutzer shadow-Hash vorher/nachher ·
  Postfach IMAP mit altem Wert vorher ok, nachher abgelehnt (sonst alten Wert zurücksetzen) ·
  Nextcloud-Konto neuer Hash + WebDAV `PROPFIND` 207 · App-Geheimnis zurücklesen (`hash_equals`).
  Beim Plesk-Admin ist der alte Wert nicht prüfbar: als „nicht feststellbar" dokumentieren, nicht als bestanden.
- **Abmelden:** `occ user:auth-tokens:*` gibt es erst ab NC 28; auf älteren Ständen nach dem Update.
- **SMTP-Postfach der Nextcloud** steht lesbar in `config.php`. Es mitrotieren, `mail_smtppassword`
  mit Sicherung anpassen und prüfen, ob die Mail-App dasselbe Postfach nutzt.
- **Kern-API NC 35:** `\OC::$server->getCrypto()` gibt es nicht mehr, stattdessen
  `\OCP\Server::get(\OCP\Security\ICrypto::class)`. PHP gegen den Kern erst lesend testen.
- **Update aus EOL:** eine Hauptversion je Stufe, vor jeder Stufe Sicherung httpdocs + DB.
  Nach einem Rollback blockiert `data/updater-<id>/.step` den Updater (meldet Erfolg in 1 s
  ohne Wirkung): vor jedem Lauf beiseitelegen. „Kein Update" gilt nur bei `No update available`,
  sonst `version.php` vorher/nachher vergleichen. Abschluss: `update:check`, `app:update --showonly`,
  `integrity:check-core`.
- **Übergabe an den Kunden:** ein eigenes 1Password-Item nur mit Kundenzugängen (Konten, Postfach).
  DB, Systembenutzer und Plesk-Admin bleiben beim Betreiber. Der Bericht sagt, welche Daten
  rotiert wurden und dass sie als Export aus dem Passwortmanager kommen, nie per Mail.

**Mittelfristig:**
- SSH auf Key-only (`PermitRootLogin prohibit-password`, `PasswordAuthentication no`).
- PHP `disable_functions` härten.
- Automatische Malware-Scans + Datei-Integritäts-Überwachung (AIDE/Tripwire).
- `/root/changelog.md` pflegen — dokumentierte Änderungen erleichtern den nächsten Forensik-Lauf (§1.6-Abgleich).

## Merksätze

1. **Erst sichern, dann anfassen.**
2. **Verschieben, nicht löschen** — Beweise.
3. **Passwörter zuerst** — solange Zugänge gültig sind, ist jede Reinigung sinnlos.
4. **Sauberes Backup** schlägt Nachbereinigung.
5. **Dokumentieren** — der Kunde, das BSI und ggf. das Gericht brauchen die Kette.
6. **Rotiert ist, was den alten Wert ablehnt** — „der neue funktioniert" reicht nicht.
7. **Kundenpaket ohne Interna** — und jede Seite einmal als Bild ansehen.
8. **Wirkung belegen, nicht Erfolgsmeldung glauben** — Versionsdatei, Hash oder Ablehnung des alten Werts.

---
*netztaucher | digital*
