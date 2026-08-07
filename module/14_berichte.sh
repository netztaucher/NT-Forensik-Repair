# NT-Forensik — Abschnitt 14: Zusammenfassung & Berichte
#
# @nummer:  14
# @titel:   Zusammenfassung & Berichte
# @frage:   Erzeugt Technik-, Kunden-, BSI- und DSGVO-Bericht sowie findings.json
# @kosten:  gering
# @ebene:   bericht
#
# Wird vom Runner eingebunden, nicht einzeln ausgefuehrt.
# Vorgabewerte der hier gefuellten Variablen: lib/befunde.sh

h1 "14. ZUSAMMENFASSUNG"
# ============================================================

cat >> "$REPORT_FILE" <<SUMMARY

### 14.1 Befund-Statistik

| Kategorie | Anzahl |
|---|---|
| 🔴 Kritische Befunde | ${N_CRIT} |
| ⚠️ Warnungen | ${N_WARN} |
| ✅ Unauffällige Prüfungen | ${N_OK} |

### 14.2 Empfohlene Sofortmaßnahmen

| Priorität | Maßnahme | Status |
|---|---|---|
| 🔴 Sofort | Alle Passwörter rotieren (Plesk, FTP, SSH, DB) | ☐ |
| 🔴 Sofort | SSH Root-Login deaktivieren (\`PermitRootLogin no\`) | ☐ |
| 🔴 Sofort | SSH auf Key-only (\`PasswordAuthentication no\`) | ☐ |
| 🔴 Sofort | Google Search Console: alle unbekannten Inhaber entfernen | ☐ |
| 🟠 Kurzfristig | Fail2ban aktivieren (ssh, ftp, plesk-panel) | ☐ |
| 🟠 Kurzfristig | ModSecurity mit OWASP CRS aktivieren | ☐ |
| 🟠 Kurzfristig | PHP \`disable_functions\` härten | ☐ |
| 🟠 Kurzfristig | Maldet/ClamAV vollständigen Scan laufen lassen | ☐ |
| 🟡 Mittelfristig | WordPress-Neuinstallation aus sauberem Backup | ☐ |
| 🟡 Mittelfristig | WP-Admin mit HTTP-Auth absichern | ☐ |
| 🟡 Mittelfristig | Automatische Malware-Scans einrichten | ☐ |
| 🟡 Mittelfristig | Intrusion Detection System (AIDE/Tripwire) | ☐ |

---
*Bericht erstellt am: $(date)*
*Tool: wp_plesk_forensik.sh v${TOOL_VERSION} — netztaucher | digital*
SUMMARY

# ============================================================
# KUNDENBERICHT (lesbar, ohne Fachjargon-Overload)
# ============================================================

# Ampel nach KUNDEN-Scope (v3.7.1): nur Website-Befunde bestimmen die Einstufung
# des Kundenberichts — Server-/Root-Befunde (in N_CRIT enthalten) gehören dem
# Betreiber, nicht dem Kunden. Sonst steht 🔴 KRITISCH im Kundenbericht, obwohl
# an SEINER Website nichts Kritisches ist.
N_CUST_CRIT=$(printf '%s' "$CUST_CRIT_LIST" | grep -c . || true)
N_CUST_WARN=$(printf '%s' "$CUST_WARN_LIST" | grep -c . || true)
if [[ "${N_CUST_CRIT:-0}" -gt 0 || "${MALWARE_TOTAL:-0}" -gt 0 ]]; then
  AMPEL="🔴 KRITISCH"
  AMPEL_TEXT="**Ihr System wurde nachweislich kompromittiert.** Es liegen konkrete, technisch belegte Hinweise auf einen erfolgreichen Angriff vor. Ein Angreifer hatte oder hat Zugriff auf Ihren Webauftritt. **Es besteht akuter Handlungsbedarf** — bitte arbeiten Sie die Sofortmaßnahmen unten noch heute ab."
  DRINGLICHKEIT="**Warum das dringend ist:** Solange die Zugänge des Angreifers gültig sind, kann er jederzeit zurückkehren, weitere Hintertüren legen, Daten (auch Kundendaten) abgreifen, Spam über Ihre Domain versenden oder Ihre Seite für Betrug/Schadsoftware missbrauchen. Jede Stunde zählt."
elif [[ "${N_CUST_WARN:-0}" -gt 0 ]]; then
  AMPEL="🟡 AUFFÄLLIG"
  AMPEL_TEXT="Es wurden Auffälligkeiten gefunden, die auf Sicherheitsschwächen oder Angriffsversuche hindeuten. Ein erfolgreicher Einbruch ist nicht belegt, die Punkte sollten aber zeitnah geprüft und behoben werden."
  DRINGLICHKEIT="**Warum das wichtig ist:** Die gefundenen Schwachstellen sind typische Einfallstore. Werden sie nicht geschlossen, ist ein erfolgreicher Angriff nur eine Frage der Zeit."
else
  AMPEL="🟢 UNAUFFÄLLIG"
  AMPEL_TEXT="Bei dieser Prüfung wurden keine Hinweise auf eine Kompromittierung gefunden. Das ist eine Momentaufnahme und ersetzt keine laufende Absicherung."
  DRINGLICHKEIT=""
fi

# Technische Kurzfassung der Kernbefunde (maschinell aus dem Lauf)
TECH_SUMMARY=""
if [[ "${WEBSHELL_COUNT:-0}" -gt 0 ]]; then
  TECH_SUMMARY+="- **${WEBSHELL_COUNT} Schadcode-Dateien (Hintertüren / \"Webshells\")** im Webverzeichnis gefunden. Das sind versteckte PHP-Skripte, über die ein Angreifer beliebige Befehle auf Ihrem Server ausführen kann — meist als harmlose Bilder oder Systemdateien getarnt."$'\n'
  if [[ -n "${DROPPER_CLUSTER:-}" ]]; then
    TECH_SUMMARY+="  Betroffene Domain(s):"$'\n'"$(echo "$DROPPER_CLUSTER" | sed 's/^/    - /')"$'\n'
  fi
fi
if [[ "${WEBSHELL_REVIEW:-0}" -gt 0 ]]; then
  TECH_SUMMARY+="- ${WEBSHELL_REVIEW} weitere Datei(en) mit auffälligen Code-Mustern (überwiegend veraltete, aber gefährliche Programmbibliotheken) — manuelle Prüfung nötig."$'\n'
fi
# Joomla-Befunde in die Kunden-Kurzfassung heben — sonst schweigt sie, wenn
# Joomla das einzige CMS des Kunden ist (v3.8).
if [[ "${JOOMLA_FLAGS:-0}" -gt 0 ]]; then
  TECH_SUMMARY+="- **Joomla-Befunde (${JOOMLA_FLAGS})** — Ihre Joomla-Installation weist Auffälligkeiten auf: veralteter Programmstand, unsichere Konfiguration oder ein nachweisbarer Zugriff auf Ihre Zugangsdaten. Einzelheiten in Abschnitt 4."$'\n'
fi

# SSH-Brute-Force ist ein SERVER-Befund (Betreiber-Ebene) und gehört nicht in
# den Kundenbericht — bleibt im Technik-/BSI-Bericht. (v3.8 Scope-Trennung)
[[ -z "$TECH_SUMMARY" ]] && TECH_SUMMARY="- Keine akuten technischen Kompromittierungs-Indikatoren an Ihrer Website in diesem Lauf."

# Angriffshergang aus Lauf-Daten maschinell vorbefüllen (keine nackten Platzhalter).
# Was der Lauf NICHT automatisch weiß (konkreter Angreifer-Login, Einfallstor),
# bleibt als klar markierte, kurze Ergänzungszeile — kein leeres [AUSFÜLLEN].
AUTO_IPS="${ATTACK_IPS_UNIQ:-}"
[[ -z "$AUTO_IPS" ]] && AUTO_IPS="${TOP_FAIL_IPS:-}"

if [[ -n "$AUTO_IPS" ]]; then
  ANGRIFF_IPS="Maschinell aus den Protokollen ermittelte auffällige IP-Adressen (Anzahl = Requests/Treffer):
\`\`\`
$(echo "$AUTO_IPS" | head -10)
\`\`\`
_Die konkrete Angreifer-IP wird bei der manuellen Log-Auswertung bestätigt._"
else
  ANGRIFF_IPS="In den vorliegenden Protokollen wurden keine eindeutig auffälligen IP-Adressen automatisch isoliert (ggf. Log-Reichweite zu kurz)."
fi

# Einfallstor-Hypothesen aus Befundlage
ANGRIFF_VEKTOR=""
[[ "${WEBSHELL_COUNT:-0}" -gt 0 ]] && ANGRIFF_VEKTOR+="  - Abgelegte Hintertüren (${WEBSHELL_COUNT}) deuten auf Datei-Upload über ein verwundbares Plugin/Theme oder gestohlene Zugangsdaten."$'\n'
[[ "${WPLOGIN_TOTAL:-0}" -gt 20 ]] && ANGRIFF_VEKTOR+="  - Auffällige wp-login-Aktivität → WordPress-Login als möglicher Einstieg."$'\n'
[[ "${SSH_FAILED_COUNT:-0}" -gt 1000 ]] && ANGRIFF_VEKTOR+="  - ${SSH_FAILED_COUNT} SSH-Rateangriffe → Passwort-Brute-Force auf den Serverzugang."$'\n'
[[ -z "$ANGRIFF_VEKTOR" ]] && ANGRIFF_VEKTOR="  - Kein eindeutiger Vektor aus den Automatik-Daten ableitbar — manuelle Log-Auswertung erforderlich."$'\n'

ANGRIFF_ZEIT="Analysezeitraum dieses Laufs: letzte ${DAYS_BACK} Tage. Der genaue Zugriffszeitraum ergibt sich aus der manuellen Log-Auswertung und den Datei-Zeitstempeln (siehe \`belege/\`)."

if [[ "${WEBSHELL_COUNT:-0}" -gt 0 || "${TOTAL_SHELL_POSTS:-0}" -gt 0 ]]; then
  ANGRIFF_TAT="Ablage von Schadcode/Hintertüren im Webauftritt${DROPPER_CLUSTER:+ (betroffen: $(echo "$DROPPER_CLUSTER" | awk '{print $2}' | tr '\n' ' '))}. Umfang der weiteren Aktivität (Datenzugriff, Änderungen) wird bei der Detailauswertung bestimmt."
else
  ANGRIFF_TAT="Aus den Automatik-Daten keine konkrete Angreifer-Aktion belegt — bei der manuellen Auswertung zu prüfen."
fi

# Befundlisten für den Kundenbericht DSGVO-datensparsam pseudonymisieren
# (fremde E-Mail-Adressen). Angreifer-IPs bleiben zum Sperren im Klartext.
# Kundenbericht zeigt NUR Website-Befunde (via crit/warn "…" web) — Server-/
# Root-/Infrastruktur-Befunde bleiben Technik-/Betreiber-Sache (v3.8).
KUNDE_CRIT_LIST=$(printf '%s' "$CUST_CRIT_LIST" | mask_email)
KUNDE_WARN_LIST=$(printf '%s' "$CUST_WARN_LIST" | mask_email)

# Scope-Warnung (v3.5): Im Global-Modus umfasst der Bericht ALLE Domains und
# darf nicht als Einzelkunden-Bericht verschickt werden — sonst sähe Kunde A die
# Befunde (und ggf. personenbezogenen Daten) von Kunde B. Kundenspezifische,
# maskierte Berichte entstehen über einen Lauf mit --domain <kunde.tld>.
if [[ "$SCOPE_MODE" == "global" ]]; then
  KUNDE_TITEL="Serverweiter Befundbericht (Betreiber)"
  SCOPE_BANNER="> ⚠️ **Serverweiter Betreiberbericht — nicht für die Weitergabe an einzelne Kunden.**
> Dieser Lauf (\`--global\`) umfasst **alle Domains** des Servers; die folgenden
> Befunde können mehrere Kunden betreffen. Für einen kundenspezifischen Bericht
> (nur dessen Daten, personenbezogene Angaben maskiert, ohne Root-Details) den
> Lauf mit \`--domain <kunde.tld>\` wiederholen.
"
else
  KUNDE_TITEL="Sicherheitsvorfall — Bericht${DOMAIN:+ für ${DOMAIN}}"
  SCOPE_BANNER=""
fi

cat > "$KUNDE_FILE" <<KUNDE
# ${KUNDE_TITEL}

${SCOPE_BANNER}
| | |
|---|---|
| **Einstufung** | ${AMPEL} |
| **Erstellt durch** | netztaucher \| digital |
| **Datum** | $(date +"%d.%m.%Y, %H:%M Uhr") |
| **Geprüfter Server** | $(hostname -f 2>/dev/null || hostname) |
| **Prüfungs-ID** | ${RUN_LABEL} |
| **Befunde** | 🔴 ${N_CRIT} kritisch · ⚠️ ${N_WARN} auffällig · ✅ ${N_OK} geprüft |

---

## 1. Das Wichtigste in einem Satz

${AMPEL_TEXT}

${DRINGLICHKEIT}

$(if [[ "$N_CRIT" -gt 0 ]]; then
echo "## 2. ⏱️ Sofortmaßnahmen — bitte noch heute

| # | Maßnahme | Frist |
|---|---|---|
| 1 | **Alle Passwörter ändern**: WordPress-Admin, Hosting-/Plesk-Panel, FTP/SFTP, SSH, Datenbank. Nicht nur eines — alle. | sofort (< 24 h) |
| 2 | **Alle aktiven Sitzungen beenden** (WordPress-Sicherheitsschlüssel/Salts neu erzeugen), damit gestohlene Logins ungültig werden. | sofort (< 24 h) |
| 3 | **Verwundbare Zugänge/Plugins abschalten**, über die der Angriff lief (siehe Abschnitt 4). | sofort (< 24 h) |
| 4 | **Angreifer-IP-Adressen sperren** (siehe Abschnitt 4). | sofort (< 24 h) |
| 5 | **Prüfen, ob personenbezogene Daten betroffen sind** — falls ja, greift die 72-Stunden-Meldepflicht (siehe Abschnitt 6). | < 72 h |

> Diese Schritte stoppen den akuten Zugriff. Die vollständige Bereinigung (Abschnitt 5) folgt danach."
fi)

## 3. Was wir technisch gefunden haben

${TECH_SUMMARY}

$(if [[ "${MALWARE_TOTAL:-0}" -gt 0 ]]; then
echo "**Schadcode-Einordnung — ${MALWARE_TOTAL} Fundstelle(n):**

| Art | Anzahl | Was damit bezweckt wird |
|---|---|---|
${MALWARE_FAMILY_ROWS}
> Die vollständige Liste der betroffenen Dateien — mit Pfaden **relativ zu Ihrem
> Verzeichnis** — liegt in der Datei \`befunde_details.md\` bei Ihren Unterlagen."
fi)

$(if [[ -n "$KUNDE_CRIT_LIST" ]]; then
echo "**Kritische Einzelbefunde:**

$KUNDE_CRIT_LIST"
fi)
$(if [[ -n "$KUNDE_WARN_LIST" ]]; then
echo "**Auffälligkeiten (zeitnah beheben):**

$KUNDE_WARN_LIST"
fi)

## 4. Reichweite des Angriffs — war nur Ihre Website oder der ganze Server betroffen?

${ROOT_CUSTOMER_HINT}

> **Was das bedeutet:** „Serverebene" (Root) ist die Administratorebene des
> gesamten Servers, auf dem neben Ihrer auch andere Websites liegen. Blieb ein
> Angreifer darunter (nur auf Ebene Ihrer Website), ist der Schaden auf Ihren
> Webauftritt begrenzt. Die technische Detailbewertung der Serverebene liegt beim
> Serverbetreiber; sie ist nicht Teil dieses Kundenberichts.

**WordPress-Datenbank:** ${WPDB_VERDICT}
$(if [[ "${JOOMLA_COUNT:-0}" -gt 0 ]]; then printf '\n**Joomla:** %s\n' "${JOOMLA_VERDICT}"; fi)
**Fernzugriff / Relay-Backdoor:** ${RELAY_VERDICT}

## 5. Angriffshergang & Angreifer

> *Die folgenden Angaben sind maschinell aus den Protokollen dieses Laufs abgeleitet.
> Die endgültige Zuordnung (konkreter Angreifer-Login, exaktes Einfallstor) bestätigen
> wir bei der manuellen Auswertung; alle Rohdaten liegen revisionssicher in \`belege/\`.*

**Auffällige IP-Adressen:**

${ANGRIFF_IPS}

**Wahrscheinliches Einfallstor (aus der Befundlage):**

${ANGRIFF_VEKTOR}
**Zeitliche Einordnung:** ${ANGRIFF_ZEIT}

**Beobachtete Angreifer-Aktivität:** ${ANGRIFF_TAT}

$(if [[ -n "${TOP_FAIL_IPS:-}" ]]; then
echo "**Auffälligste angreifende IP-Adressen (SSH-Rateangriff) — zum Sperren:**

\`\`\`
$TOP_FAIL_IPS
\`\`\`"
fi)

## 6. Bereinigung & dauerhafte Absicherung

**Bereits von uns durchgeführt:**

- Vollständige forensische Sicherung aller Protokolle und Beweise (revisionssicher, mit Prüfsummen) — Lauf-ID \`${RUN_LABEL}\`.
$(if [[ "${WEBSHELL_COUNT:-0}" -gt 0 ]]; then echo "- Systematische Erfassung aller ${WEBSHELL_COUNT} Schadcode-Fundstellen inkl. Prüfsummen (Grundlage für die Quarantäne)."; else echo "- Vollständiger Scan von Dateisystem, Prozessen, Persistenz-Mechanismen und Datenbanken."; fi)
$(if [[ "${WEBSHELL_COUNT:-0}" -gt 0 ]]; then echo "- _Weitere bereits durchgeführte Sofortmaßnahmen (z. B. Quarantäne der Fundstellen, Domain offline) trägt netztaucher hier fallbezogen ein._"; fi)

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
> Ein vorbereiteter Entwurf liegt in \`dsgvo_meldung.md\`.

> **Meldung an das BSI:** Eine vorbereitete Meldung liegt in \`bsi_meldung.md\`
> (**eigener Meldeweg**, getrennt von der Datenschutzmeldung). Ob eine Pflicht besteht,
> hängt von Ihrer Einstufung ab — im Zweifel ist eine freiwillige Meldung sinnvoll.

Wir unterstützen Sie bei allen Meldungen — sprechen Sie uns umgehend an.

## 8. Ihre Unterlagen zu diesem Vorfall

| Dokument | Zweck |
|---|---|
| \`kundenbericht.md\` | Dieses Dokument |$(if [[ "${MALWARE_TOTAL:-0}" -gt 0 ]]; then printf '\n| `befunde_details.md` | Vollständige Fundstellen-Liste (Pfade relativ zu Ihrem Verzeichnis, Familie, Signatur) |'; fi)
| \`technik_bericht.md\` | Vollständiger technischer Bericht (alle Prüfpunkte, inkl. Root-Prüfung §13) |
| \`bsi_meldung.md\` | Vorbereitete BSI-Meldung (BSIG/NIS2) |
| \`dsgvo_meldung.md\` | Vorbereitete DSGVO-Meldung (Art. 33, eigener Meldeweg an die Datenschutzbehörde) |
| \`belege/\` | Alle Rohdaten & Beweismittel, mit SHA256-Prüfsummen versiegelt |

$(if [[ -f /root/changelog.md ]]; then echo "> **Abgleich mit Wartungsdokumentation:** Die Befunde wurden gegen das
> Admin-Änderungsprotokoll (\`/root/changelog.md\`) abgeglichen; dort dokumentierte
> Systemänderungen sind als reguläre Wartung eingeordnet."; fi)

---

### Über netztaucher | digital

Diese Analyse stammt aus unserer laufenden **WordPress-Betreuung und -Absicherung**.
Wir übernehmen Wartung, Härtung, Monitoring und Notfall-Forensik für WordPress- und
Rootserver — damit Vorfälle wie dieser gar nicht erst entstehen oder im Ernstfall
sauber und dokumentiert behoben werden.

**→ https://netztaucher.com/wordpress**

---
*netztaucher | digital — maschinell erstellt (wp_plesk_forensik.sh v${TOOL_VERSION}) und dokumentiert den Zustand zum Prüfzeitpunkt. Der Angriffshergang (Abschnitt 5/6) wird nach manueller Auswertung ergänzt.*
KUNDE

# ============================================================
# BSI-MELDUNG (Best Practice, vorausgefüllt)
# ============================================================

FIRST_SEEN=$(date -d "-${DAYS_BACK} days" +"%d.%m.%Y" 2>/dev/null || echo "[AUSFÜLLEN]")

cat > "$BSI_FILE" <<BSI
# Meldung eines IT-Sicherheitsvorfalls an das BSI

> **Entwurf — vor Versand prüfen und Platzhalter \`[AUSFÜLLEN]\` ergänzen.**
>
> **Meldewege:**
> - Meldepflichtige Unternehmen (KRITIS / NIS2 / §32 BSIG): **BSI Melde- und Informationsportal** — https://mip.bsi.bund.de
> - Freiwillige Meldung (alle Unternehmen): https://www.bsi.bund.de → "Cyber-Sicherheitsvorfall melden" bzw. E-Mail an meldestelle@bsi.bund.de
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
| Betroffene Domain(s) | ${DOMAIN:-[AUSFÜLLEN]} |
| Betroffener Server | $(hostname -f 2>/dev/null || hostname) ($(hostname -I 2>/dev/null | awk '{print $1}' || echo "IP: [AUSFÜLLEN]")) |
| Einstufung | ☐ KRITIS  ☐ NIS2 besonders wichtige Einrichtung  ☐ NIS2 wichtige Einrichtung  ☐ nicht meldepflichtig (freiwillige Meldung) |

## 3. Zeitliche Einordnung

| Feld | Angabe |
|---|---|
| Feststellung des Vorfalls | [AUSFÜLLEN — Datum/Uhrzeit der Entdeckung] |
| Vermuteter Beginn | [AUSFÜLLEN — Analysezeitraum ab ca. ${FIRST_SEEN}] |
| Forensische Analyse | $(date +"%d.%m.%Y %H:%M") (Lauf-ID: ${RUN_LABEL}) |
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
| Kritische Befunde | ${N_CRIT} |
| Warnungen | ${N_WARN} |
| Fehlgeschlagene SSH-Login-Versuche | ${SSH_FAILED_COUNT:-0} |
| Scanner-Aktivität in Web-Logs (Treffer) | ${TOTAL_SCANNER_HITS:-0} |
| Verdächtige POST-Requests (Webshell-Muster) | ${TOTAL_SHELL_POSTS:-0} |
| Webshell-Verdachtsdateien im Dateisystem | ${WEBSHELL_COUNT:-0} |
| Domains auf dem Server (Mitbetroffenheit möglich) | ${DOMAIN_COUNT:-0} |

$(if [[ -n "$CRIT_LIST" ]]; then
echo "### Kritische Einzelbefunde

$CRIT_LIST"
fi)

## 6. Indikatoren (IOCs)

### Auffällige IP-Adressen (aus Angriffsmustern konsolidiert)

\`\`\`
${ATTACK_IPS_UNIQ:-Keine konsolidierten Angreifer-IPs in diesem Lauf.}
\`\`\`

### Top-IPs SSH-Brute-Force

\`\`\`
${TOP_FAIL_IPS:-Keine.}
\`\`\`

Datei-Hashes verdächtiger Dateien: siehe \`belege/\` (SHA256SUMS und Einzelbelege).

## 7. Auswirkungen

### Reichweite / Root-Kompromittierung (automatisiert bewertet)

${ROOT_VERDICT}
$(if [[ -n "${ROOT_NOTES:-}" ]]; then echo; echo "$ROOT_NOTES"; fi)

### Relay-Backdoor / ausgehender Fernzugriff (automatisiert bewertet)

${RELAY_VERDICT}

| Frage | Antwort |
|---|---|
| Server-Root kompromittiert? | $(if [[ "${ROOT_FLAGS:-0}" -eq 0 ]]; then echo "Nach Beweislage nein (auf Web-User-Ebene begrenzt)"; else echo "NICHT ausgeschlossen — ${ROOT_FLAGS} Indikator(en), siehe Technik-Bericht §13"; fi) |
| Relay-Backdoor / Fernzugriffskanal? | $(if [[ "${RELAY_FLAGS:-0}" -eq 0 ]]; then echo "kein Hinweis (kein Ausschluss bei inaktivem Kanal)"; else echo "Verdacht/Nachweis — ${RELAY_FLAGS} Punkt(e), siehe Technik-Bericht §8.7–8.12"; fi) |
| WordPress-Datenbank | $(if [[ "${WPDB_FLAGS:-0}" -eq 0 ]]; then echo "unauffällig (keine fremden Admins/Optionen)"; else echo "AUFFÄLLIG — ${WPDB_FLAGS} Befund(e), siehe Technik-Bericht §11"; fi) |
| Joomla-Installation | $(if [[ "${JOOMLA_COUNT:-0}" -eq 0 ]]; then echo "keine im Prüf-Scope"; elif [[ "${JOOMLA_FLAGS:-0}" -eq 0 ]]; then echo "unauffällig"; else echo "AUFFÄLLIG — ${JOOMLA_FLAGS} Befund(e), siehe Technik-Bericht §12"; fi) |
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

- Forensische Sicherung aller relevanten Logs (revisionssicher, SHA256-gehasht): \`${RUN_DIR}\`
- [AUSFÜLLEN — z. B. Passwörter rotiert, Webshell entfernt/quarantänisiert, Domain offline genommen]

## 10. Geplante Maßnahmen

- [AUSFÜLLEN — z. B. Neuaufsetzen aus sauberem Backup, Härtung SSH/PHP, Fail2ban, ModSecurity+OWASP CRS]

## 11. Anlagen

| Anlage | Pfad |
|---|---|
| Technischer Forensik-Bericht | \`technik_bericht.md\` |
| Beweismittel inkl. Prüfsummen | \`belege/\` (SHA256SUMS) |
| Log-Vollsicherung | \`belege/logs_sicherung.tar.gz\` |

---
*Entwurf maschinell erstellt am $(date) — wp_plesk_forensik.sh v${TOOL_VERSION}, netztaucher | digital.*
*Struktur orientiert an den Meldevorgaben des BSI (Erst-/Folgemeldung nach BSIG/NIS2) — vor Versand fachlich prüfen.*
BSI

# ============================================================
# DSGVO-MELDUNG (Art. 33 DSGVO — eigener Meldeweg, NICHT BSI!)
# ============================================================
# Personenbezogene Daten liegen auf fast jeder WordPress-Seite (Kommentare,
# Kontaktformulare, Bestellungen). Bei einem Einbruch ist eine Betroffenheit
# meist nicht auszuschließen → Art. 33 prüfen.

# Einschätzung zur Meldepflicht (maschinell, ersetzt keine Rechtsprüfung)
if [[ "${WEBSHELL_COUNT:-0}" -gt 0 && "${WP_COUNT:-0}" -gt 0 ]]; then
  DSGVO_HINWEIS="🔴 **Meldung wahrscheinlich erforderlich.** Es liegt eine bestätigte Kompromittierung vor und es sind WordPress-Installationen (mit typischerweise personenbezogenen Daten) betroffen. Eine Betroffenheit personenbezogener Daten ist **nicht auszuschließen** — die 72-Stunden-Frist des Art. 33 DSGVO läuft ab Kenntnis."
elif [[ "${N_CRIT:-0}" -gt 0 ]]; then
  DSGVO_HINWEIS="🟠 **Meldepflicht prüfen.** Es liegt ein kritischer Befund vor. Ob personenbezogene Daten betroffen sind, muss der/die Verantwortliche bewerten (Art. 33 Abs. 1: Meldung, außer die Verletzung führt voraussichtlich zu keinem Risiko)."
else
  DSGVO_HINWEIS="🟢 **Nach aktueller Befundlage kein akuter Meldeanlass** aus dieser Analyse. Die Bewertung der Meldepflicht obliegt dem/der Verantwortlichen."
fi

# Betroffene WordPress-Datenbanken (potenzielle Datenquellen) für die Meldung
DSGVO_DBS="${WP_CONFIGS:-}"
[[ -n "$DSGVO_DBS" ]] && DSGVO_DBS=$(echo "$DSGVO_DBS" | sed "s|${VHOSTS_DIR}/||;s|/wp-config.php||" | sed 's/^/- /')

cat > "$DSGVO_FILE" <<DSGVO
# Meldung einer Verletzung des Schutzes personenbezogener Daten (Art. 33 DSGVO)

> **Eigener Meldeweg — nicht mit der BSI-Meldung verwechseln.** Diese Meldung geht
> an die zuständige **Datenschutz-Aufsichtsbehörde** des Bundeslandes, nicht ans BSI.
> Entwurf — vom **Verantwortlichen** zu prüfen und mit \`[AUSFÜLLEN]\` zu ergänzen.

## Meldepflicht — Einschätzung

${DSGVO_HINWEIS}

| | |
|---|---|
| **Frist** | unverzüglich, **≤ 72 Stunden** ab Kenntnis (Art. 33 Abs. 1) |
| **Bei Überschreitung** | Begründung der Verzögerung beifügen (Art. 33 Abs. 1 S. 2) |
| **Ausnahme** | keine Meldung, wenn die Verletzung **voraussichtlich zu keinem Risiko** für die Rechte und Freiheiten natürlicher Personen führt |
| **Empfänger** | Datenschutz-Aufsichtsbehörde des Bundeslandes des Verantwortlichen |
| **Betroffene benachrichtigen?** | bei **hohem Risiko** zusätzlich Art. 34 (unverzüglich an die Betroffenen) |

## 1. Verantwortlicher (meldende Stelle i. S. d. DSGVO)

| Feld | Angabe |
|---|---|
| Verantwortlicher (Unternehmen) | [AUSFÜLLEN — Betreiber der Website, nicht der Dienstleister] |
| Anschrift | [AUSFÜLLEN] |
| Datenschutzbeauftragter (Name) | [AUSFÜLLEN] |
| DSB Kontakt (E-Mail/Telefon) | [AUSFÜLLEN] |
| Technische Unterstützung | netztaucher | digital |

> **Pflichtangabe Art. 33 Abs. 3 lit. b:** Name und Kontaktdaten des DSB oder einer sonstigen Anlaufstelle.

## 2. Art der Verletzung (Art. 33 Abs. 3 lit. a)

**Sachverhalt (technisch belegt):** Kompromittierung der Website${DOMAIN:+ ${DOMAIN}} auf dem Server $(hostname -f 2>/dev/null || hostname). $(if [[ "${WEBSHELL_COUNT:-0}" -gt 0 ]]; then echo "${WEBSHELL_COUNT} Hintertür(en) im Webverzeichnis; unbefugter Zugriff auf das System belegt."; else echo "Auffälligkeiten mit möglichem unbefugtem Zugriff."; fi)

- **Art:** ☑ Vertraulichkeitsverletzung (unbefugter Zugriff)  ☐ Integritätsverletzung  ☐ Verfügbarkeitsverletzung — [prüfen]
- **Zeitraum:** [AUSFÜLLEN — aus Analyse: Datei-Zeitstempel / Log-Auswertung, siehe technik_bericht.md]

## 3. Betroffene Personen und Datensätze (Art. 33 Abs. 3 lit. a)

> Muss der/die Verantwortliche bewerten — die Forensik liefert nur die betroffenen Systeme.

| Feld | Angabe |
|---|---|
| Kategorien betroffener Personen | [AUSFÜLLEN — z. B. Kunden, Newsletter-Abonnenten, Kontaktanfragen] |
| Ungefähre Zahl betroffener Personen | [AUSFÜLLEN] |
| Kategorien betroffener Daten | [AUSFÜLLEN — z. B. Name, E-Mail, Anschrift, Bestell-/Zahlungsdaten] |
| Ungefähre Zahl betroffener Datensätze | [AUSFÜLLEN] |
| Besondere Kategorien (Art. 9)? | [AUSFÜLLEN — Gesundheit, etc.? i. d. R. nein] |

**Betroffene Datenquellen auf dem Server (aus der Analyse):**
$(if [[ -n "$DSGVO_DBS" ]]; then echo "$DSGVO_DBS"; else echo "- Keine WordPress-Datenbank im Scan-Pfad gefunden — Datenquellen manuell bestimmen."; fi)

## 4. Wahrscheinliche Folgen (Art. 33 Abs. 3 lit. c)

[AUSFÜLLEN — z. B. Risiko von Identitätsdiebstahl, Spam/Phishing gegen Betroffene, Missbrauch von Zugangsdaten. Einschätzung des Risikogrades: gering / mittel / hoch.]

## 5. Ergriffene und vorgeschlagene Maßnahmen (Art. 33 Abs. 3 lit. d)

**Bereits ergriffen (technisch):**
- Forensische Sicherung und Dokumentation (revisionssicher, SHA256), Lauf-ID \`${RUN_LABEL}\`.
$(if [[ "${WEBSHELL_COUNT:-0}" -gt 0 ]]; then echo "- Erfassung aller ${WEBSHELL_COUNT} Schadcode-Fundstellen (Grundlage für Bereinigung/Quarantäne)."; fi)
- [AUSFÜLLEN — z. B. Passwörter rotiert, Hintertüren entfernt, Domain offline]

**Vorgeschlagen:**
- Rotation aller Zugangsdaten, WordPress-Neuaufbau aus sauberem Backup, Härtung.
- [AUSFÜLLEN — Maßnahmen zur Minderung nachteiliger Folgen für Betroffene]

## 6. Dokumentation (Art. 33 Abs. 5)

Auch wenn keine Meldung erfolgt, ist die Verletzung intern zu dokumentieren. Diese
Analyse (Lauf \`${RUN_LABEL}\`, Belege mit Prüfsummen) erfüllt die technische
Dokumentationsgrundlage. Rechtliche Bewertung und Entscheidung obliegen dem/der Verantwortlichen.

## 7. Anlagen

| Anlage | Pfad |
|---|---|
| Technischer Forensik-Bericht | \`technik_bericht.md\` |
| BSI-Meldung (separater Meldeweg) | \`bsi_meldung.md\` |
| Beweismittel inkl. Prüfsummen | \`belege/\` (SHA256SUMS) |

---
*Entwurf maschinell erstellt am $(date) — wp_plesk_forensik.sh v${TOOL_VERSION}, netztaucher | digital.*
*Struktur nach Art. 33 DS-GVO. Ersetzt keine Rechtsberatung — vor Versand durch den Verantwortlichen/DSB prüfen.*
DSGVO

# ============================================================
# BELEGE VERSIEGELN: SHA256 über alles
# ============================================================

# ── Maschinenlesbarer Export für das Repair-Tool (findings.json) ──
# Kein jq-Zwang; JSON von Hand aus vorhandenen Variablen/Belegen gebaut.
FINDINGS_FILE="${RUN_DIR}/findings.json"

# JSON-Maskierung. Steuerzeichen MÜSSEN maskiert werden, sonst ist die Datei
# ungültig (v3.8): Tabulatoren stecken in praktisch jeder Zeile, die aus
# `mysql -N` stammt (ROGUE_ADMINS, Joomla-DB-Abfragen) — vorher erzeugte genau
# der Fall, auf den es ankommt (ein echter Fund), unlesbares findings.json und
# damit einen stillen Ausfall des Anschreiben-Generators.
# Reihenfolge ist zwingend: erst Backslash, dann Anführungszeichen, dann
# Steuerzeichen — sonst werden die selbst eingefügten Backslashes nochmals
# maskiert. Das abschließende tr entfernt die restlichen, nicht darstellbaren
# Steuerzeichen (ohne \t und \r, die oben bereits behandelt sind).
json_esc() { sed 's/\\/\\\\/g; s/"/\\"/g; s/\t/\\t/g; s/\r/\\r/g' | tr -d '\000-\010\013\014\016-\037'; }
json_str() {   # einzeiliger String → JSON-escaped (ohne Anführungszeichen)
  printf '%s' "$1" | tr '\n' ' ' | json_esc
}
json_arr() {   # stdin: ein Item pro Zeile → JSON-Array von Strings
  local first=1 out="[" line esc
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    esc=$(printf '%s' "$line" | json_esc)
    if [ "$first" -eq 1 ]; then out="${out}\"${esc}\""; first=0; else out="${out},\"${esc}\""; fi
  done
  printf '%s]' "$out"
}

emit_findings_json() {
  local ws php suid tmpx immu cron sysd persist procs wpc fkeys aips bips suspadm
  local corei coresne doorw coreinj disg rogue
  corei=$(printf '%s\n' "${CORE_INJECTED:-}"      | json_arr)
  coresne=$(printf '%s\n' "${CORE_SNE:-}"         | json_arr)
  doorw=$(printf '%s\n' "${DOORWAY_DIRS:-}"       | json_arr)
  coreinj=$(printf '%s\n' "${CORE_INJECT_HITS:-}" | json_arr)
  disg=$(printf '%s\n' "${DISGUISED_PAYLOADS:-}"  | json_arr)
  rogue=$(printf '%s\n' "${ROGUE_ADMINS:-}"       | grep -vE '^=== |^$' | json_arr)
  suspadm=$(printf '%s\n' "${SUSPECT_ADMINS:-}"   | grep -vE '^=== |^$' | json_arr)
  local suspp muplug tamphta
  suspp=$(printf '%s\n' "${SUSP_PLUGINS:-}"       | json_arr)
  muplug=$(printf '%s\n' "${MU_PLUGINS:-}"        | json_arr)
  tamphta=$(printf '%s\n' "${TAMPERED_HTACCESS:-}" | json_arr)
  local n_corei n_doorw n_coreinj n_rogue
  n_corei=$(printf '%s\n'   "${CORE_INJECTED:-}"     | grep -c . 2>/dev/null)
  n_doorw=$(printf '%s\n'   "${DOORWAY_DIRS:-}"      | grep -c . 2>/dev/null)
  n_coreinj=$(printf '%s\n' "${CORE_INJECT_HITS:-}"  | grep -c . 2>/dev/null)
  n_rogue=$(printf '%s\n'   "${ROGUE_ADMINS:-}"      | grep -vE '^=== |^$' | grep -c . 2>/dev/null)
  local n_suspp; n_suspp=$(printf '%s\n' "${SUSP_PLUGINS:-}" | grep -c . 2>/dev/null)
  ws=$(echo "${DROPPER_DETAIL:-}"      | grep '^=== ' | sed 's/^=== //; s/ ===$//' | json_arr)
  php=$(printf '%s\n' "${PHP_IN_UPLOADS:-}"    | json_arr)
  suid=$(printf '%s\n' "${SUID_FILES:-}"       | json_arr)
  tmpx=$(printf '%s\n' "${TMP_EXECS:-}"        | json_arr)
  immu=$(printf '%s\n' "${IMMUTABLE:-}"        | json_arr)
  cron=$(printf '%s\n' "${SUSP_CRON:-}"        | json_arr)
  sysd=$(printf '%s\n' "${SUSP_UNITS:-}"       | json_arr)
  persist=$(printf '%s\n' "${PERSIST_REPORT:-}" | grep '^=== ' | sed 's/^=== //; s/ ===$//' | json_arr)
  procs=$(printf '%s\n%s\n%s\n' "${MINER_PROCS:-}" "${DELETED_SUSPECT:-}" "${REVSHELL:-}" | json_arr)
  wpc=$(printf '%s\n' "${WP_CONFIGS:-}"        | json_arr)
  fkeys=$(printf '%s\n' "${FOREIGN_KEYS:-}"    | json_arr)
  aips=$(printf '%s\n' "${ATTACK_IPS_UNIQ:-}"  | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | json_arr)
  bips=$(printf '%s\n' "${TOP_FAIL_IPS:-}"     | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | json_arr)
  # v3.4 Relay-Backdoors — Prozess-/Datei-Introspektion (Abschnitte 5.6/5.7, 6.9, 7.10/7.11, 8.7–8.12)
  local gsock masq fless kthr orph sshh relc yhit
  gsock=$(printf '%s\n' "${GSOCKET_HITS:-}"     | json_arr)
  masq=$(printf '%s\n'  "${MASQ_BINARIES:-}"    | json_arr)
  fless=$(printf '%s\n' "${FILELESS_PROCS:-}"   | json_arr)
  kthr=$(printf '%s\n'  "${KTHREAD_FAKES:-}"    | json_arr)
  orph=$(printf '%s\n'  "${ORPHAN_SHELLS:-}"    | json_arr)
  sshh=$(printf '%s\n'  "${SSH_LOGIN_HOOKS:-}"  | json_arr)
  relc=$(printf '%s\n'  "${RELAY_CONNECTIONS:-}" | json_arr)
  yhit=$(printf '%s\n'  "${YARA_HITS:-}"        | json_arr)
  # v3.6 System-Integrität & Scanner-Taps
  local tstomp recsys imuh wptk malsum
  # Mail-Kontext für den Anschreiben-Generator (null, wenn keine Funde)
  if [[ "${MALWARE_TOTAL:-0}" -gt 0 ]]; then
    malsum="{ \"total\": ${MALWARE_TOTAL}, \"affected_area\": \"$(json_str "${MAIL_AREA:-}")\", \"finding_summary\": \"$(json_str "${MAIL_FINDING:-}")\", \"timeframe\": \"$(json_str "${MAIL_TIMEFRAME:-}")\", \"newest\": \"${MAIL_NEWEST:-}\", \"families\": ${MAIL_FAMILIES_JSON} }"
  else
    malsum="null"
  fi
  tstomp=$(printf '%s\n' "${TIMESTOMP:-}"       | json_arr)
  recsys=$(printf '%s\n' "${RECENT_SYS:-}"      | json_arr)
  imuh=$(printf '%s\n'   "${IMUNIFY_HITS:-}"    | json_arr)
  wptk=$(printf '%s\n'   "${WPTK_INFECTED:-}"   | json_arr)
  # v3.8 Joomla-Prüfung + Netz-Transparenz
  local jcfg jver jcweak jlog jcmod jcunk jsysp jsuper jsess jmodc jtpl jukeys jvuln jmal onlinef
  jcfg=$(printf   '%s\n' "${JOOMLA_CONFIGS:-}"       | json_arr)
  jver=$(printf   '%s\n' "${JOOMLA_VERSIONS:-}"      | json_arr)
  jcweak=$(printf '%s\n' "${JOOMLA_CONFIG_WEAK:-}"   | grep -vE '^=== |^$' | json_arr)
  jlog=$(printf   '%s\n' "${JOOMLA_LOG_IOC:-}"       | json_arr)
  jcmod=$(printf  '%s\n' "${JOOMLA_CORE_MODIFIED:-}" | json_arr)
  jcunk=$(printf  '%s\n' "${JOOMLA_CORE_UNKNOWN:-}"  | json_arr)
  jsysp=$(printf  '%s\n' "${JOOMLA_SYS_PLUGINS:-}"   | json_arr)
  jsuper=$(printf '%s\n' "${JOOMLA_ROGUE_SUPER:-}"   | grep -vE '^=== |^$' | json_arr)
  jsess=$(printf  '%s\n' "${JOOMLA_SESSION_HITS:-}"  | json_arr)
  jmodc=$(printf  '%s\n' "${JOOMLA_MOD_CUSTOM:-}"    | json_arr)
  jtpl=$(printf   '%s\n' "${JOOMLA_TPL_PARAMS:-}"    | json_arr)
  jukeys=$(printf '%s\n' "${JOOMLA_USER_KEYS:-}"     | json_arr)
  jvuln=$(printf  '%s\n' "${JOOMLA_VULN_EXT:-}"      | json_arr)
  jmal=$(printf   '%s\n' "${JOOMLA_MALWARE:-}"       | json_arr)
  onlinef=$(printf '%s\n' "${ONLINE_FETCHES:-}"      | json_arr)
  # Welche Abschnitte liefen, welche nicht — damit ein Teillauf maschinell
  # als solcher erkennbar ist und nicht als vollständiges Ergebnis gilt.
  local modgel moduebr
  modgel=$(printf '%s\n' ${MODULE_GELAUFEN:-} | json_arr)
  moduebr=$(printf '%s\n' "${MODULE_UEBERSPRUNGEN:-}" | json_arr)
  local n_jcmod n_jvuln n_jsuper
  n_jcmod=$(printf  '%s\n' "${JOOMLA_CORE_MODIFIED:-}" | grep -c . 2>/dev/null)
  n_jvuln=$(printf  '%s\n' "${JOOMLA_VULN_EXT:-}"      | grep -c . 2>/dev/null)
  n_jsuper=$(printf '%s\n' "${JOOMLA_ROGUE_SUPER:-}"   | grep -vE '^=== |^$' | grep -c . 2>/dev/null)

  cat > "$FINDINGS_FILE" <<JSON
{
  "schema_version": "1.4",
  "tool": "wp_plesk_forensik.sh",
  "tool_version": "${TOOL_VERSION}",
  "run_id": "$(json_str "$RUN_LABEL")",
  "host": "$(json_str "$(hostname -f 2>/dev/null || hostname)")",
  "domain": "$(json_str "${DOMAIN:-}")",
  "generated_utc": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "run": {
    "vollstaendig": $(if [[ -z "${MODULE_UEBERSPRUNGEN:-}" ]]; then echo true; else echo false; fi),
    "module_gelaufen": ${modgel:-[]},
    "module_uebersprungen": ${moduebr:-[]}
  },
  "counts": { "crit": ${N_CRIT:-0}, "warn": ${N_WARN:-0}, "ok": ${N_OK:-0} },
  "verdicts": {
    "root": { "flags": ${ROOT_FLAGS:-0}, "text": "$(json_str "${ROOT_VERDICT:-}")" },
    "wpdb": { "flags": ${WPDB_FLAGS:-0}, "text": "$(json_str "${WPDB_VERDICT:-}")" },
    "joomla": { "flags": ${JOOMLA_FLAGS:-0}, "text": "$(json_str "${JOOMLA_VERDICT:-}")" },
    "relay": { "flags": ${RELAY_FLAGS:-0}, "text": "$(json_str "${RELAY_VERDICT:-}")" }
  },
  "data_sources": {
    "joomla_snapshot": "$(json_str "${J_DATA_STAMP:-}")",
    "joomla_snapshot_age_days": ${JOOMLA_DATA_AGE:-0},
    "online_mode": $(if [[ "${WANT_ONLINE:-0}" == "1" ]]; then echo true; else echo false; fi),
    "network_fetches": ${onlinef:-[]}
  },
  "metrics": {
    "webshell_count": ${WEBSHELL_COUNT:-0},
    "webshell_review": ${WEBSHELL_REVIEW:-0},
    "injected_core_files": ${n_corei:-0},
    "doorway_dirs": ${n_doorw:-0},
    "core_include_injections": ${n_coreinj:-0},
    "rogue_wp_admins": ${n_rogue:-0},
    "suspicious_plugins": ${n_suspp:-0},
    "ssh_failed": ${SSH_FAILED_COUNT:-0},
    "wp_installs": ${WP_COUNT:-0},
    "joomla_installs": ${JOOMLA_COUNT:-0},
    "joomla_core_modified": ${n_jcmod:-0},
    "joomla_vulnerable_extensions": ${n_jvuln:-0},
    "joomla_rogue_superusers": ${n_jsuper:-0},
    "domains": ${DOMAIN_COUNT:-0}
  },
  "actionable": {
    "webshell_dropper": ${ws:-[]},
    "injected_core": ${corei:-[]},
    "core_should_not_exist": ${coresne:-[]},
    "doorway_dirs": ${doorw:-[]},
    "core_include_injection": ${coreinj:-[]},
    "disguised_payloads": ${disg:-[]},
    "rogue_wp_admins": ${rogue:-[]},
    "suspect_wp_admins": ${suspadm:-[]},
    "suspicious_plugins": ${suspp:-[]},
    "mu_plugins": ${muplug:-[]},
    "tampered_htaccess": ${tamphta:-[]},
    "php_in_uploads": ${php:-[]},
    "suid": ${suid:-[]},
    "tmp_executables": ${tmpx:-[]},
    "immutable": ${immu:-[]},
    "cron_suspect": ${cron:-[]},
    "systemd_suspect": ${sysd:-[]},
    "persistence": ${persist:-[]},
    "proc_malicious": ${procs:-[]},
    "wp_configs": ${wpc:-[]},
    "foreign_ssh_keys": ${fkeys:-[]},
    "ioc_ips": { "attacker": ${aips:-[]}, "ssh_bruteforce": ${bips:-[]} },
    "gsocket_hits": ${gsock:-[]},
    "masq_binaries": ${masq:-[]},
    "fileless_procs": ${fless:-[]},
    "kthread_fakes": ${kthr:-[]},
    "orphan_shells": ${orph:-[]},
    "ssh_login_hooks": ${sshh:-[]},
    "relay_connections": ${relc:-[]},
    "yara_hits": ${yhit:-[]},
    "timestomp": ${tstomp:-[]},
    "recent_system_changes": ${recsys:-[]},
    "imunify_malware": ${imuh:-[]},
    "wptk_infected": ${wptk:-[]},
    "joomla_configs": ${jcfg:-[]},
    "joomla_versions": ${jver:-[]},
    "joomla_config_weak": ${jcweak:-[]},
    "joomla_log_ioc": ${jlog:-[]},
    "joomla_core_modified": ${jcmod:-[]},
    "joomla_core_unknown": ${jcunk:-[]},
    "joomla_system_plugins": ${jsysp:-[]},
    "joomla_rogue_superusers": ${jsuper:-[]},
    "joomla_session_payloads": ${jsess:-[]},
    "joomla_mod_custom": ${jmodc:-[]},
    "joomla_template_params": ${jtpl:-[]},
    "joomla_user_keys": ${jukeys:-[]},
    "joomla_vulnerable_extensions": ${jvuln:-[]},
    "joomla_malware": ${jmal:-[]}
  },
  "malware_summary": ${malsum}
}
JSON
  echo "  findings.json geschrieben: $FINDINGS_FILE" >> "$REPORT_FILE"
}
emit_findings_json

# ── PDF-Abschlussbericht (v3.5, optional/degradierend) ───────
# Teil 1 = Kundenbericht (laienlesbar, maskiert), Teil 2 = KPI-Zusammenfassung.
# reportgen/ muss neben dem Skript oder unter ${BASE_DIR} liegen. Fehlt
# pandoc/weasyprint/reportgen, wird das PDF übersprungen — die Markdown-Berichte
# bleiben vollständig und maßgeblich (Read-only-Versprechen, kein harter Fehler).
PDF_FILE="${RUN_DIR}/abschlussbericht.pdf"
REPORTGEN_DIR=""
for _d in "$(dirname "$SELF_PATH")/reportgen" "${BASE_DIR}/reportgen"; do
  [[ -x "$_d/nt_report_pdf.sh" ]] && { REPORTGEN_DIR="$_d"; break; }
done
_wp="${WEASYPRINT:-$(command -v weasyprint 2>/dev/null || true)}"
if [[ -n "$REPORTGEN_DIR" ]] && command -v pandoc >/dev/null 2>&1 && [[ -n "$_wp" ]]; then
  ZUSAMMEN_FILE="${RUN_DIR}/zusammenfassung.md"
  {
    echo "::: kpigrid"
    echo "- **${N_CRIT}** kritische Befunde"
    echo "- **${N_WARN}** Auffälligkeiten"
    echo "- **${N_OK}** geprüfte Punkte"
    echo "- **$(ls -1 "$BELEGE_DIR" 2>/dev/null | grep -vc SHA256SUMS)** Belege (SHA256)"
    echo ":::"
    echo
    echo "## Bewertung im Überblick"
    echo
    echo "**Reichweite (Serverebene):** ${ROOT_CUSTOMER_HINT}"
    echo
    echo "**Fernzugriff / Relay-Backdoor:** ${RELAY_VERDICT}"
    echo
    echo "**WordPress-Datenbank:** ${WPDB_VERDICT}"
    if [[ "${JOOMLA_COUNT:-0}" -gt 0 ]]; then
      echo
      echo "**Joomla:** ${JOOMLA_VERDICT}"
    fi
  } > "$ZUSAMMEN_FILE"
  _dom="${DOMAIN:-$(hostname -f 2>/dev/null || hostname)}"
  # Grobstatistik der Schadcode-Familien fürs Deckblatt (Seite 1)
  COVER_STATS=""
  if [[ "${MALWARE_TOTAL:-0}" -gt 0 ]]; then
    COVER_STATS=$(for fam in "${!FAM_COUNT[@]}"; do echo "${FAM_COUNT[$fam]}|$fam"; done \
      | sort -rn | while IFS='|' read -r n f; do printf '%s:%s;' "$f" "$n"; done)
  fi
  if WEASYPRINT="$_wp" bash "$REPORTGEN_DIR/nt_report_pdf.sh" \
       --teil1 "$KUNDE_FILE" --teil2 "$ZUSAMMEN_FILE" \
       --title "Sicherheitsvorfall\nForensische Untersuchung" \
       --eyebrow "netztaucher | digital — Forensik" \
       --domain "$_dom" \
       --subtitle "Prüfung ${RUN_LABEL} · $(date +%d.%m.%Y)" \
       --teil2-label "Teil 2 — Zusammenfassung der Aktion" \
       --meta "Einstufung=${AMPEL}" --meta "Prüfungs-ID=${RUN_LABEL}" \
       ${COVER_STATS:+--cover-stats "$COVER_STATS"} \
       --out "$PDF_FILE" >/dev/null 2>&1; then
    echo "  PDF-Abschlussbericht: $PDF_FILE" >> "$REPORT_FILE"
  else
    echo "  PDF-Erzeugung fehlgeschlagen — Markdown-Berichte bleiben maßgeblich." >> "$REPORT_FILE"
    PDF_FILE=""
  fi
else
  echo "  PDF übersprungen (pandoc/weasyprint/reportgen nicht verfügbar)." >> "$REPORT_FILE"
  PDF_FILE=""
fi

(
  cd "$BELEGE_DIR"
  # Manifest abschließen
  {
    echo ""
    echo "Ende (UTC):     $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    echo "Belege gesamt:  $(ls -1 | grep -vc "SHA256SUMS" || true)"
  } >> 00_manifest.txt
  sha256sum ./* 2>/dev/null | grep -v "SHA256SUMS" > SHA256SUMS || true
)
# ── Kompakte Root-Aussage (--nur-root) ──────────────────────
# Ein eigenes, kurzes Dokument statt eines Berichts mit 14 Abschnitten. Es
# enthaelt genau das, was der Kunde zu dieser Frage bekommen darf: die
# Antwort, den Zeitpunkt, den Pruefumfang — und keine Indikatorenzahl, keine
# IP, keinen Pfad. Die Einzelheiten sind Sache des Betreibers und stehen im
# Beleg root_verdikt.
if [[ "${NUR_ROOT:-0}" == "1" ]]; then
  cat > "${RUN_DIR}/root_aussage.md" <<AUSSAGE
# Prüfung der Serverebene — Ergebnis

| | |
|---|---|
| **Geprüfter Bereich** | ${DOMAIN:-${ABO_USER:-Webspace}} |
| **Geprüft am** | $(date '+%d.%m.%Y um %H:%M Uhr') |
| **Lauf-Kennung** | ${RUN_LABEL} |
| **Werkzeug** | wp_plesk_forensik.sh v${TOOL_VERSION} |

## Die Frage

Ist ein Angreifer über Ihren Webspace hinaus auf die Verwaltungsebene des
Servers gelangt? Davon hängt ab, ob eine Bereinigung Ihrer Website ausreicht
oder ob der Server selbst neu aufgesetzt werden muss.

## Die Antwort

$(if [[ "${ROOT_FLAGS:-0}" -eq 0 ]]; then
echo "**Nein — keine Hinweise auf einen erweiterten Zugriff.**"
echo ""
echo "Geprüft wurden: erfolgreiche Anmeldungen auf Verwaltungsebene und ihre Herkunft,"
echo "hinterlegte Zugangsschlüssel, Möglichkeiten zur Rechteausweitung durch Webbenutzer"
echo "sowie die Unversehrtheit der Systemprogramme. Keine dieser Prüfungen hat"
echo "angeschlagen."
echo ""
echo "Ein etwaiger Vorfall ist nach dieser Beweislage auf Ihr Hosting-Konto begrenzt."
echo "Eine Bereinigung der Website ist damit ausreichend; der Server muss nicht neu"
echo "aufgesetzt werden."
else
echo "**Ein erweiterter Zugriff ist nicht auszuschließen.**"
echo ""
echo "Mindestens eine der Prüfungen auf Verwaltungsebene hat angeschlagen. Die"
echo "Einzelheiten liegen beim Betreiber und werden dort bewertet; sie enthalten"
echo "Daten, die nicht in ein Kundendokument gehören."
echo ""
echo "**Für Sie bedeutet das:** eine Bereinigung der Website allein genügt möglicherweise"
echo "nicht. Der Betreiber entscheidet über das weitere Vorgehen und meldet sich dazu."
fi)

## Grenzen dieser Aussage

Sie beschreibt den Zustand zum oben genannten Zeitpunkt. Sie sagt nichts darüber
aus, ob Ihre Website selbst Schadcode enthält — das ist Gegenstand der
Website-Prüfung und eines eigenen Berichts.

---

*netztaucher | digital*
AUSSAGE
  echo -e "\n${BOLD}Root-Aussage:${NC}   ${RUN_DIR}/root_aussage.md"
fi

# ── Fremdkunden aus den weiterzugebenden Dokumenten halten ───
# Vor dem Hashen, damit die Pruefsummen zur ausgelieferten Fassung passen.
# Ein Bericht ueber EINEN Kunden darf keine Daten anderer Kunden enthalten;
# auf einem Shared-Host mit 482 vhosts standen in einem Lauf ueber ein
# einzelnes Abo 112 fremde Kennungen in 17 Abschnitten.
#
# Die Belege unter belege/ bleiben bewusst UNMASKIERT: sie sind Beweismittel
# und gehoeren dem Betreiber, nicht in eine Kundenuebergabe. Wer das Paket
# weitergibt, gibt die Berichte weiter, nicht die Rohbelege.
if [[ "$SCOPE_MODE" != "global" ]]; then
  echo -e "\n${BOLD}Datenschutz${NC}"
  for _dok in technik_bericht.md kundenbericht.md befunde_details.md root_aussage.md lauf.log; do
    [[ -f "${RUN_DIR}/${_dok}" ]] || continue
    printf '  %-24s' "$_dok"
    nf_fremdkunden_maskieren "${RUN_DIR}/${_dok}" || echo "  (nichts zu maskieren)"
  done
fi

# Berichte + findings.json ebenfalls hashen
(
  cd "$RUN_DIR"
  sha256sum technik_bericht.md kundenbericht.md bsi_meldung.md dsgvo_meldung.md findings.json 2>/dev/null >> "${BELEGE_DIR}/SHA256SUMS" || true
  [[ -f befunde_details.md ]] && sha256sum befunde_details.md 2>/dev/null >> "${BELEGE_DIR}/SHA256SUMS" || true
  [[ -n "$PDF_FILE" && -f "$PDF_FILE" ]] && sha256sum "$(basename "$PDF_FILE")" zusammenfassung.md 2>/dev/null >> "${BELEGE_DIR}/SHA256SUMS" || true
)

# Übergabe-Archiv des kompletten Laufs
RUN_ARCHIVE="${FORENSIK_BASE}/${RUN_LABEL}.tar.gz"
tar czf "$RUN_ARCHIVE" -C "$FORENSIK_BASE" "$RUN_LABEL" 2>/dev/null || true

# ============================================================
# ABSCHLUSSMELDUNG
# ============================================================

echo ""
echo -e "${BOLD}${GRN}══════════════════════════════════════════${NC}"
echo -e "${BOLD}${GRN}  ANALYSE ABGESCHLOSSEN — Lauf ${RUN_LABEL}${NC}"
echo -e "${BOLD}${GRN}══════════════════════════════════════════${NC}"
echo ""
echo -e "${BOLD}Befunde:${NC}       🔴 ${N_CRIT} kritisch, ⚠️ ${N_WARN} Warnungen, ✅ ${N_OK} ok"
echo ""
echo -e "${BOLD}Lauf-Ordner:${NC}     ${RUN_DIR}"
echo -e "${BOLD}Kundenbericht:${NC}   ${KUNDE_FILE}"
echo -e "${BOLD}BSI-Meldung:${NC}     ${BSI_FILE}"
echo -e "${BOLD}DSGVO-Meldung:${NC}   ${DSGVO_FILE}"
echo -e "${BOLD}Technik-Bericht:${NC} ${REPORT_FILE}"
[[ -n "${PDF_FILE:-}" && -f "${PDF_FILE:-}" ]] && echo -e "${BOLD}PDF-Bericht:${NC}     ${PDF_FILE}"
echo -e "${BOLD}findings.json:${NC}   ${FINDINGS_FILE} (maschinenlesbar, für NT-Repair)"
echo -e "${BOLD}Belege:${NC}          ${BELEGE_DIR} (SHA256-versiegelt)"
echo -e "${BOLD}Übergabe-Archiv:${NC} ${RUN_ARCHIVE}"
echo ""
echo -e "${YLW}Nächste Schritte:${NC}"
echo -e "  1. Kundenbericht prüfen:   cat ${KUNDE_FILE}"
echo -e "  2. BSI-Meldung ergänzen:   [AUSFÜLLEN]-Felder in ${BSI_FILE}"
echo -e "  3. DSGVO-Meldung prüfen:   [AUSFÜLLEN]-Felder in ${DSGVO_FILE} (eigener Meldeweg!)"
echo -e "  4. Archiv lokal sichern:   scp root@$(hostname -f 2>/dev/null || hostname):${RUN_ARCHIVE} ."
echo -e "  5. Alle 🔴-Maßnahmen sofort umsetzen"
echo ""
