# shellcheck shell=bash
# NT-Forensik — Abschnitt 14, Teil: Anhang §14.1/14.2 an den Technik-Bericht
#
# Unterabschnitt von module/14_berichte.sh. Wird vom Runner nach dem
# Hauptmodul geladen (siehe modul_teile_laden in wp_plesk_forensik.sh) und
# teilt sich dessen Variablen. Nicht einzeln ausfuehrbar.


cat >> "$REPORT_FILE" <<SUMMARY

### 14.1 Befund-Statistik

| Kategorie | Anzahl |
|---|---|
| 🔴 Kritische Befunde | ${N_CRIT} |
| ⚠️ Warnungen | ${N_WARN} |
| ✅ Unauffällige Prüfungen | ${N_OK} |
| ⚪ Nicht messbar | ${N_UNKNOWN} |

$(if [[ "${N_UNKNOWN:-0}" -gt 0 ]]; then
  printf '> **%s Prüfung(en) haben keine Aussage geliefert.** Ihr Ergebnis ist weder\n' "${N_UNKNOWN}"
  printf '> ein Befund noch eine Entwarnung — der jeweilige Bereich ist ungeprüft:\n>\n'
  printf '%s' "$UNKNOWN_LIST" | while IFS= read -r _z; do [[ -n "$_z" ]] && printf '> %s\n' "$_z"; done
fi)

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
