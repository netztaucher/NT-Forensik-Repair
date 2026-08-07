# shellcheck shell=bash
# NT-Forensik — Abschnitt 14, Teil: Kompakte Root-Aussage fuer --nur-root
#
# Steht bewusst VOR der Maskierung (55): das Dokument geht an den Kunden,
# und was nach der Maskierung entsteht, wird nicht mehr maskiert.
# Unterabschnitt von module/14_berichte.sh. Wird vom Runner nach dem
# Hauptmodul geladen (siehe modul_teile_laden in wp_plesk_forensik.sh) und
# teilt sich dessen Variablen. Nicht einzeln ausfuehrbar.

# ── Kompakte Root-Aussage (--nur-root) ──────────────────────
# Ein eigenes, kurzes Dokument statt eines Berichts mit 14 Abschnitten. Es
# enthaelt genau das, was der Kunde zu dieser Frage bekommen darf: die
# Antwort, den Zeitpunkt, den Pruefumfang — und keine Indikatorenzahl, keine
# IP, keinen Pfad. Die Einzelheiten sind Sache des Betreibers und stehen im
# Beleg root_verdikt.
if [[ "${NUR_ROOT:-0}" == "1" ]]; then
  cat > "${KUNDE_DIR}/root_aussage.md" <<AUSSAGE
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
  echo -e "\n${BOLD}Root-Aussage:${NC}   ${KUNDE_DIR}/root_aussage.md"
fi
