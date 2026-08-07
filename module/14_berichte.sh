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
