#!/usr/bin/env bash
# ============================================================
# NT-Forensik — Selbsttest der zweiten Schwachstellenquelle (#12)
# ------------------------------------------------------------
#   werkzeuge/zweitquelle_selbsttest.sh
#
# WOZU
#
# Wordfence ist heute die einzige Quelle, deren Daten weitergegeben werden
# dürfen. Fällt sie weg, gibt es keinen Ersatz. wpvulnerability.net wird
# deshalb zur Laufzeit befragt — nicht gespiegelt, nicht mitgeliefert.
#
# Geprüft wird die ABBILDUNG der fremden Intervall-Semantik auf das eigene
# Modell, ohne Netz: die Operatoren sind an 656 echten Antworten gemessen
# (min: None|ge, max: lt|le|eq, unfixed: 0|1), und ein falsch ausgelegtes
# Intervall meldet entweder eine geschlossene Lücke oder schweigt zu einer
# offenen. Beides sieht im Bericht plausibel aus.
#
# In beide Richtungen: die betroffene Fassung muss melden, die behobene darf
# nicht.
# ============================================================
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
fail=0

python3 - <<'PY' || fail=1
import sys
sys.path.insert(0, "lib")
import wp_schwachstellen as ws

fehler = 0

def pruefe(roh, version, soll, was):
    global fehler
    eintraege = ws._wpv_umsetzen("testplugin", [roh])
    daten = {"plugin": {"testplugin": eintraege}} if eintraege else {"plugin": {}}
    betroffen = any(z[0] == "BETROFFEN"
                    for z in ws.pruefen(daten, "plugin", "testplugin", version))
    ist = "BETROFFEN" if betroffen else "SAUBER"
    if ist == soll:
        print("  OK     %-46s -> %s" % (was, ist))
    else:
        print("  FEHLER %-46s -> %s (erwartet %s)" % (was, ist, soll))
        fehler += 1

def op(mn=None, mno=None, mx=None, mxo=None, unfixed="0", cve="CVE-2026-0001"):
    return {"operator": {"min_version": mn, "min_operator": mno,
                         "max_version": mx, "max_operator": mxo,
                         "unfixed": unfixed},
            "impact": {"cvss": {"score": "9.8"}},
            "source": [{"id": cve, "name": cve, "link": "https://www.cve.org/x"}]}

print("=== Abbildung der Intervall-Semantik")
# max_operator 'lt' — der haeufigste Fall (3564 von 3685 gemessenen)
pruefe(op(mx="5.3.2", mxo="lt"), "5.3.1", "BETROFFEN", "lt: Fassung darunter")
pruefe(op(mx="5.3.2", mxo="lt"), "5.3.2", "SAUBER",    "lt: die behobene Fassung selbst")
# 'le' — 118 Faelle
pruefe(op(mx="2.0",   mxo="le"), "2.0",   "BETROFFEN", "le: obere Grenze eingeschlossen")
pruefe(op(mx="2.0",   mxo="le"), "2.0.1", "SAUBER",    "le: eine Fassung darueber")
# 'eq' — 3 Faelle
pruefe(op(mx="1.4.3", mxo="eq"), "1.4.3", "BETROFFEN", "eq: genau diese Fassung")
pruefe(op(mx="1.4.3", mxo="eq"), "1.4.2", "SAUBER",    "eq: eine andere Fassung")
# min_operator 'ge' — 25 Faelle
pruefe(op(mn="3.0", mno="ge", mx="3.5", mxo="lt"), "3.2", "BETROFFEN", "ge/lt: mitten im Bereich")
pruefe(op(mn="3.0", mno="ge", mx="3.5", mxo="lt"), "2.9", "SAUBER",    "ge/lt: unterhalb des Bereichs")

print("=== Was NICHT geraten wird")
# Ein unbekannter Operator darf nicht ausgelegt werden.
if ws._wpv_umsetzen("x", [op(mx="1.0", mxo="zwischen")]) == []:
    print("  OK     unbekannter Operator wird übersprungen")
else:
    print("  FEHLER unbekannter Operator wurde ausgelegt"); fehler += 1
# unfixed=1: es gibt keine behobene Fassung -> Feld leer, nicht die Grenze.
e = ws._wpv_umsetzen("x", [op(mx="9.9", mxo="lt", unfixed="1")])[0]
if e["behoben"] == "":
    print("  OK     unfixed=1 -> keine behobene Fassung ausgewiesen")
else:
    print("  FEHLER unfixed=1 -> '%s' als behoben ausgewiesen" % e["behoben"]); fehler += 1
# KEV fuehrt diese Quelle nicht — das Feld entscheidet ueber crit statt warn.
if e["kev"] == "":
    print("  OK     KEV bleibt leer (die Quelle führt es nicht)")
else:
    print("  FEHLER KEV wurde geraten"); fehler += 1

print("=== Ausfall ist keine Entwarnung")
# None (nicht geantwortet) und [] (gefuehrt, nichts bekannt) sind verschieden.
daten = {"plugin": {}}
protokoll = {}
ws.zweitquelle_dazu(daten, [("plugin", "")], protokoll)
if protokoll.get("abgefragt", -1) == 0:
    print("  OK     leere Kennung wird nicht abgefragt")
else:
    print("  FEHLER leere Kennung wurde abgefragt"); fehler += 1

sys.exit(1 if fehler else 0)
PY

[[ $fail -eq 0 ]] && echo "=> ALLE BESTANDEN" || echo "=> FEHLGESCHLAGEN"
exit $fail
