# shellcheck shell=bash
# NT-Forensik — Abschnitt 14, Teil: Ampel und Kundenbericht
#
# Unterabschnitt von module/14_berichte.sh. Wird vom Runner nach dem
# Hauptmodul geladen (siehe modul_teile_laden in wp_plesk_forensik.sh) und
# teilt sich dessen Variablen. Nicht einzeln ausfuehrbar.

# ============================================================
# KUNDENBERICHT (lesbar, ohne Fachjargon-Overload)
# ============================================================

# Ampel nach KUNDEN-Scope (v3.7.1): nur Website-Befunde bestimmen die Einstufung
# des Kundenberichts — Server-/Root-Befunde (in N_CRIT enthalten) gehören dem
# Betreiber, nicht dem Kunden. Sonst steht 🔴 KRITISCH im Kundenbericht, obwohl
# an SEINER Website nichts Kritisches ist.
N_CUST_CRIT=$(printf '%s' "$CUST_CRIT_LIST" | grep -c . || true)
N_CUST_WARN=$(printf '%s' "$CUST_WARN_LIST" | grep -c . || true)
N_CUST_UNKNOWN=$(printf '%s' "$CUST_UNKNOWN_LIST" | grep -c . || true)

# Nicht messbare Pruefungen blockieren die gruene Ampel (v3.11). Vorher konnte
# ein Lauf, in dem jede einzelne Messung scheiterte, auf 🟢 UNAUFFAELLIG enden
# mit dem Satz "keine Hinweise auf eine Kompromittierung gefunden" — die
# Abwesenheit eines Befunds wurde als Abwesenheit eines Problems ausgegeben.
# Gruen bedeutet ab jetzt: geprueft UND nichts gefunden.
UNKLAR_HINWEIS=""
if [[ "${N_CUST_UNKNOWN:-0}" -gt 0 ]]; then
  UNKLAR_HINWEIS=$(printf '\n\n**%s Prüfung(en) konnten nicht durchgeführt werden.** Für diese Bereiche liegt kein Ergebnis vor — weder ein Befund noch eine Entwarnung. Was dort nicht geprüft werden konnte, steht im Technik-Bericht.' "${N_CUST_UNKNOWN}")
fi

if [[ "${N_CUST_CRIT:-0}" -gt 0 || "${MALWARE_TOTAL:-0}" -gt 0 ]]; then
  AMPEL="🔴 KRITISCH"
  AMPEL_TEXT="**Ihr System wurde nachweislich kompromittiert.** Es liegen konkrete, technisch belegte Hinweise auf einen erfolgreichen Angriff vor. Ein Angreifer hatte oder hat Zugriff auf Ihren Webauftritt. **Es besteht akuter Handlungsbedarf** — bitte arbeiten Sie die Sofortmaßnahmen unten noch heute ab."
  DRINGLICHKEIT="**Warum das dringend ist:** Solange die Zugänge des Angreifers gültig sind, kann er jederzeit zurückkehren, weitere Hintertüren legen, Daten (auch Kundendaten) abgreifen, Spam über Ihre Domain versenden oder Ihre Seite für Betrug/Schadsoftware missbrauchen. Jede Stunde zählt."
elif [[ "${N_CUST_WARN:-0}" -gt 0 ]]; then
  AMPEL="🟡 AUFFÄLLIG"
  AMPEL_TEXT="Es wurden Auffälligkeiten gefunden, die auf Sicherheitsschwächen oder Angriffsversuche hindeuten. Ein erfolgreicher Einbruch ist nicht belegt, die Punkte sollten aber zeitnah geprüft und behoben werden.${UNKLAR_HINWEIS}"
  DRINGLICHKEIT="**Warum das wichtig ist:** Die gefundenen Schwachstellen sind typische Einfallstore. Werden sie nicht geschlossen, ist ein erfolgreicher Angriff nur eine Frage der Zeit."
elif [[ "${N_CUST_UNKNOWN:-0}" -gt 0 ]]; then
  AMPEL="🟡 UNVOLLSTÄNDIG"
  AMPEL_TEXT="In den Bereichen, die geprüft werden konnten, wurden keine Hinweise auf eine Kompromittierung gefunden. **Ein Teil der Prüfungen konnte jedoch nicht durchgeführt werden.** Dieses Ergebnis ist deshalb keine Entwarnung: für die betroffenen Bereiche liegt schlicht kein Ergebnis vor.${UNKLAR_HINWEIS}"
  DRINGLICHKEIT="**Was jetzt zu tun ist:** Die Ursache der nicht durchführbaren Prüfungen klären und den Lauf wiederholen. Erst dann lässt sich sagen, ob Ihr System unauffällig ist."
else
  AMPEL="🟢 UNAUFFÄLLIG"
  AMPEL_TEXT="Alle vorgesehenen Prüfungen konnten durchgeführt werden, und keine davon ergab einen Hinweis auf eine Kompromittierung. Das ist eine Momentaufnahme und ersetzt keine laufende Absicherung."
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
# Die Kurzfassung kennt nur eine Handvoll Quellen (Webshell-Zähler, Joomla,
# SSH). Bleibt sie leer, stand hier bisher ausnahmslos die Entwarnung — auch
# dann, wenn die Einordnung darunter dreizehn Fundstellen auflistete. Genau der
# Widerspruch aus #2, nur eine Ebene höher: eine Entwarnung, die eine Zeile
# später widerlegt wird, beschädigt jede andere Aussage im Dokument.
if [[ -z "$TECH_SUMMARY" ]]; then
  if [[ "${MALWARE_TOTAL:-0}" -gt 0 ]]; then
    TECH_SUMMARY="- **${MALWARE_TOTAL} Schadcode-Fundstelle(n)** in Ihrem Webauftritt. Was jede einzelne ist und wozu sie dient, steht in der Einordnung unten und vollständig in \`befunde_details.md\`."
  else
    TECH_SUMMARY="- Keine akuten technischen Kompromittierungs-Indikatoren an Ihrer Website in diesem Lauf."
  fi
fi
# Der zweite Rang gehört ebenfalls genannt — sonst liest sich ein Lauf, der
# ausschliesslich Prüfenswertes fand, wie ein glatter Freispruch.
[[ "${PRUEF_TOTAL:-0}" -gt 0 ]] && \
  TECH_SUMMARY+=$'\n'"- ${PRUEF_TOTAL} weitere Fundstelle(n) sind noch einzuordnen — sie sind kein belegter Schadcode, aber auch nicht abgehakt. Liste in \`befunde_details.md\`."

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
| **Befunde** | 🔴 ${N_CUST_CRIT} kritisch · ⚠️ ${N_CUST_WARN} auffällig · ⚪ ${N_CUST_UNKNOWN} nicht messbar |

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
| \`kundenbericht.md\` | Dieses Dokument |$(if [[ "${MALWARE_TOTAL:-0}" -gt 0 || "${PRUEF_TOTAL:-0}" -gt 0 ]]; then printf '\n| `befunde_details.md` | Vollständige Fundstellen-Liste (Pfade relativ zu Ihrem Verzeichnis, Familie, Signatur) |'; fi)
| \`root_aussage.md\` | Aussage dazu, ob der Vorfall über Ihren Webauftritt hinausreicht |
| \`02_Meldungen/\` | Entwurf Ihrer DSGVO-Meldung (Art. 33) — von Ihnen zu prüfen und abzusenden |
| \`04_Belege/\` | Die Rohbelege zu den Befunden, maskiert und mit eigenen SHA256-Prüfsummen |

> **Was Sie hier NICHT finden — und warum.** Der vollständige Technik-Bericht,
> die BSI-Meldung und die unmaskierten Rohbelege liegen beim Betreiber Ihres
> Servers. Sie enthalten serverweite Angaben und, auf einem Server mit mehreren
> Kunden, Pfade und Kennungen anderer Kunden. Was davon Sie betrifft, steht
> vollständig in diesem Bericht. Den Technik-Bericht können Sie bei Bedarf
> anfordern; er wird dann maskiert beigelegt.

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
