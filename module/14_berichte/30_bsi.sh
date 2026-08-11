# shellcheck shell=bash
# NT-Forensik — Abschnitt 14, Teil: BSI-Meldung (Entwurf)
#
# Unterabschnitt von module/14_berichte.sh. Wird vom Runner nach dem
# Hauptmodul geladen (siehe modul_teile_laden in wp_plesk_forensik.sh) und
# teilt sich dessen Variablen. Nicht einzeln ausfuehrbar.

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
| Schadcode-Fundstellen gesamt (alle Quellen) | ${MALWARE_TOTAL:-0} |
| Davon noch einzuordnen | ${PRUEF_TOTAL:-0} |
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
