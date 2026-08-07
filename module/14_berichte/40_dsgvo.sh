# shellcheck shell=bash
# NT-Forensik — Abschnitt 14, Teil: DSGVO-Meldung nach Art. 33 (Entwurf, eigener Meldeweg)
#
# Unterabschnitt von module/14_berichte.sh. Wird vom Runner nach dem
# Hauptmodul geladen (siehe modul_teile_laden in wp_plesk_forensik.sh) und
# teilt sich dessen Variablen. Nicht einzeln ausfuehrbar.

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
# WP_CONFIGS ist im Global-Modus die Liste ALLER WordPress-Installationen des
# Servers. Ungefiltert stuenden damit die Domains unbeteiligter Kunden als
# "betroffene Datenquellen" in einem Dokument, das an eine Aufsichtsbehoerde
# geht. Gefiltert wird ueber denselben Scope-Test wie der Kundenkanal.
DSGVO_DBS=""
while IFS= read -r _wc; do
  [[ -n "$_wc" ]] || continue
  im_scope "$_wc" && DSGVO_DBS+="${_wc}"$'\n'
done <<< "${WP_CONFIGS:-}"
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
