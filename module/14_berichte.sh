# shellcheck shell=bash
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

# ── Belegt die Fassungsangabe diesen Lauf? (#55) ─────────────
#
# Der Runner hat Inhalt und Commit vor dem ersten `source` festgehalten. Hier,
# unmittelbar vor den Berichten, wird beides erneut erhoben. Weicht es ab,
# stammen die Abschnitte dieses Laufs aus verschiedenen Fassungen — und die
# Fassungsangabe in findings.json, im Technikbericht und in den Behoerden-
# Entwuerfen belegt ihn nicht.
#
# KEIN ABBRUCH. Ein Vorfallslauf ueber drei Stunden darf daran nicht
# scheitern; er muss es nur SAGEN. ⚪ und nicht ⚠️, weil nichts am geprueften
# System auffaellig ist — die Messung selbst ist es, die nicht mehr fuer sich
# einstehen kann.
if declare -F programmstand_hash >/dev/null; then
  PROGRAMMSTAND_VORHER="${PROGRAMMSTAND_COMMIT_START:-}"
  PROGRAMMSTAND_NACHHER="$(programmstand_commit)"
  _ps_jetzt="$(programmstand_hash)"
  # EIN LEERER HASH IST KEINE UEBEREINSTIMMUNG.
  #
  # Faellt die Prüfsummenrechnung aus — kein md5sum, kein md5, `find` ohne
  # Leserecht —, liefern beide Seiten dieselbe leere Zeichenkette, und der
  # Vergleich meldete "unveraendert". Ein Ausfall, der aussieht wie ein
  # Ergebnis: genau die Bauart, gegen die dieses Werkzeug gebaut ist, und in
  # diesem Fall stuende die falsche Entwarnung in einem Behoerdenentwurf.
  if [[ -z "$_ps_jetzt" || -z "${PROGRAMMSTAND_HASH_START:-}" ]]; then
    PROGRAMMSTAND_STABIL=0
    unklar "Programmstand nicht feststellbar (Prüfsummenwerkzeug fehlt oder Dateien nicht lesbar) — ob die Abschnitte dieses Laufs aus derselben Fassung stammen, ist damit offen. Das ist KEINE Entwarnung."
  elif [[ "$_ps_jetzt" != "$PROGRAMMSTAND_HASH_START" ]]; then
    PROGRAMMSTAND_STABIL=0
    _ps_wechsel=""
    [[ -n "$PROGRAMMSTAND_VORHER" && "$PROGRAMMSTAND_VORHER" != "$PROGRAMMSTAND_NACHHER" ]] \
      && _ps_wechsel=" (${PROGRAMMSTAND_VORHER} → ${PROGRAMMSTAND_NACHHER})"
    unklar "Der Programmstand hat sich während des Laufs geändert${_ps_wechsel} — die Fassungsangabe ${TOOL_VERSION} belegt diesen Lauf nicht. Die Abschnitte stammen aus verschiedenen Fassungen; für einen belastbaren Beleg den Lauf auf einem festen Stand wiederholen."
  else
    ok "Programmstand über den ganzen Lauf unverändert — die Fassungsangabe belegt diesen Lauf"
  fi
fi

# Der Rest dieses Abschnitts liegt in module/14_berichte/ — eine Datei je
# erzeugtem Dokument. Die Aufteilung ist noetig, weil hier vorher 1.011 Zeilen
# standen, die sieben verschiedene Dokumente erzeugten; in einer Datei dieser
# Groesse laesst sich nichts mehr chirurgisch aendern.
#
# Die Teile werden vom Runner in Glob-Reihenfolge nachgeladen und teilen sich
# alle Variablen dieses Abschnitts. Reihenfolge ist bedeutsam:
#   10 Statistik      haengt an den Technik-Bericht an
#   20 Kundenbericht  bildet die Ampel, die 60 fuer das PDF braucht
#   30 BSI, 40 DSGVO  Behoerden-Entwuerfe
#   50 findings.json  Schnittstelle zum Reparaturteil
#   60 PDF            baut auf dem Kundenbericht aus 20 auf
#   70 Belege         versiegelt, was 10-60 erzeugt haben
#   80 Root-Aussage   nur bei --nur-root
#   90 Ausliefern     maskiert, packt, meldet ab — muss zuletzt laufen
