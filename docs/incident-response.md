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
- legt SHA256-versiegelte Belege + Übergabe-Archiv an.

**Ergebnis sichten:**
```bash
ssh root@SERVER "cat /root/wartungsscripte/forensik/<LAUF>/kundenbericht.md"
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

Belege nach Änderungen neu versiegeln:
```bash
cd "$RUN/belege" && sha256sum ./* > SHA256SUMS
```

## Phase 6 — Melden (falls einschlägig)

| Meldeweg | Wann | Frist |
|---|---|---|
| **Datenschutz-Aufsichtsbehörde** (DSGVO Art. 33) | personenbezogene Daten betroffen/möglich | **72 h** ab Kenntnis |
| **BSI-Meldeportal** (mip.bsi.bund.de) | KRITIS / NIS2 / §32 BSIG | Erst ≤ 24 h, Folge ≤ 72 h |
| **BSI freiwillig** | alle anderen | jederzeit sinnvoll |
| **ZAC der Landespolizei** | Straftatverdacht | Strafanzeige empfohlen |

## Phase 7 — Bereinigen & Härten

**Sofort:**
- Alle Passwörter rotieren (WordPress, Plesk, FTP, SSH, DB).
- Alle WP-Sitzungen invalidieren (Salts in `wp-config.php` neu).
- Angreifer-IP + Brute-Force-IPs sperren.
- Verwundbare/genutzte Plugins deaktivieren/aktualisieren.

**Kurzfristig:**
- WordPress **aus sauberem Backup vor der Erstinfektion** neu aufsetzen (nicht nur „drüberbügeln").
- WP-DB auf fremde Admins/Optionen prüfen (der §11-Verdikt hilft).
- Fail2ban + ModSecurity (OWASP CRS) aktivieren.

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

---
*netztaucher | digital*
