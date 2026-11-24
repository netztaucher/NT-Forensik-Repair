#!/usr/bin/env bash
# =============================================================================
# op-sammel-item.sh — Items eines 1Password-Tresors zu EINEM Übergabe-Item zusammenfassen
# =============================================================================
# Test:     ja - werkzeuge/nextcloud/nextcloud_selbsttest.sh (Attrappe für op, CI) · NT-Forensik-Repair#162
# Rueckweg: ja - neues Item löschen (op item delete <id>), Quellen bleiben unberührt; im Vorfall 23.11.2026 nicht nötig, Quellen danach unverändert · NT-Forensik-Repair#162
#
#   op-sammel-item.sh --tresor <id|name> [--titel "<titel>"] [--tag <tag>]...
#                     [--ausschluss <regex>] [--erwartet <anzahl>] [--ausfuehren]
#
# Ein Abschnitt je Quell-Item (Titel = Item-Titel) mit Adresse, Benutzer, Passwort, Notiz und
# allen weiteren Feldern. Werte laufen nur durch Pipes (op item get -> python -> op item create).
# Ausgabe: Quell-Titel, Feldanzahl, Fingerabdruck (sha256-12) aller Werte vorher und nachher.
#
#   --ausschluss  Regex auf den Titel: diese Items bleiben draussen (z. B. Plesk-Admin, Systembenutzer,
#                 DB — die bleiben beim Betreiber, das Übergabe-Item bekommt nur Kundenzugänge)
#   --erwartet    Anzahl der übrigen Items; weicht sie ab, wird nichts angelegt
#
# Ohne --ausfuehren: Trockenlauf — zählt und bildet den Fingerabdruck, legt nichts an.
# Mit der EIGENEN Anmeldung starten, nicht mit dem Dienstkonto:
#   env -u OP_SERVICE_ACCOUNT_TOKEN bash op-sammel-item.sh --tresor <id> ...
#
# Rückgabe: 0 ok · 2 Dienstkonto aktiv · 3 Tresor leer · 4 Anzahl ungleich --erwartet ·
#           5 Fingerabdruck oder Feldanzahl des neuen Items weicht ab
# =============================================================================
set -euo pipefail
V=""; T="Zugangsdaten (Übergabe $(date +%F))"; TAGS="sammel-item"; AUS='^$'; ERW=""; LOS=0
while [ $# -gt 0 ]; do
  case "$1" in
    --ausfuehren) LOS=1; shift; continue;;
    -h|--help) sed -n '2,/^set /{/^#/p;}' "$0" | sed -E 's/^# ?//'; exit 0;;
  esac
  [ $# -ge 2 ] || { echo "ABBRUCH: Wert fehlt für $1" >&2; exit 1; }
  case "$1" in
    --tresor) V=$2;; --titel) T=$2;; --tag) TAGS="$TAGS,$2";;
    --ausschluss) AUS=$2;; --erwartet) ERW=$2;;
    *) echo "ABBRUCH: unbekannter Schalter $1" >&2; exit 1;;
  esac; shift 2
done
[ -n "$V" ] || { echo "ABBRUCH: --tresor fehlt" >&2; exit 1; }
[ -z "${OP_SERVICE_ACCOUNT_TOKEN:-}" ] || { echo "ABBRUCH: Dienstkonto aktiv, mit env -u OP_SERVICE_ACCOUNT_TOKEN starten"; exit 2; }
[ "$LOS" = 1 ] || echo "TROCKENLAUF (mit --ausfuehren wird das Item angelegt)"
op vault get "$V" --format json | python3 -c 'import json,sys; d=json.load(sys.stdin); print("Tresor:", d["name"], "·", d.get("items","?"), "Items")'
IDS=$(op item list --vault "$V" --format json | AUS="$AUS" python3 -c 'import json,os,re,sys
r=re.compile(os.environ["AUS"])
for i in json.load(sys.stdin):
    if r.search(i["title"]): print("  ausgelassen:", i["title"], file=sys.stderr)
    else: print(i["id"])')
[ -n "$IDS" ] || { echo "ABBRUCH: keine Items"; exit 3; }
N=$(printf '%s\n' "$IDS" | grep -c .); echo "Items im Sammel-Item: $N"
[ -z "$ERW" ] || [ "$N" = "$ERW" ] || { echo "ABBRUCH: $N Items statt erwartet $ERW, nichts angelegt"; exit 4; }

FPD=$(mktemp); trap 'rm -f "$FPD"' EXIT
# Alle Items als JSON-Zeilen in die Pipe; python baut das Sammel-Item; nur der Fingerabdruck landet in $FPD
baue(){
  for id in $IDS; do op item get "$id" --vault "$V" --format json | tr -d '\n'; echo; done | FPD="$FPD" python3 -c '
import json, os, sys, hashlib
title, tags = sys.argv[1], sys.argv[2].split(","); secs = []; fields = []; vals = []
for k, line in enumerate(sys.stdin):
    if not line.strip(): continue
    it = json.loads(line); sid = "s%02d" % k
    secs.append({"id": sid, "label": it.get("title", "Item %d" % k)})
    print("  Quelle:", it.get("title"), "·", it.get("category"), file=sys.stderr)
    for u in it.get("urls") or []:
        if u.get("href"):
            fields.append({"id": "%s_url%d" % (sid, len(fields)), "type": "URL", "label": "Adresse", "value": u["href"], "section": {"id": sid}}); vals.append(u["href"])
    for f in it.get("fields") or []:
        v = f.get("value")
        if v in (None, ""): continue
        lab = f.get("label") or f.get("id")
        if f.get("purpose") == "NOTES" or f.get("id") == "notesPlain": lab = "Notiz"
        t = f.get("type", "STRING")
        if t == "OTP": t = "CONCEALED"
        if t not in ("STRING", "CONCEALED", "URL", "EMAIL", "PHONE", "DATE", "MONTH_YEAR"): t = "STRING"
        fields.append({"id": "%s_f%d" % (sid, len(fields)), "type": t, "label": lab, "value": v, "section": {"id": sid}}); vals.append(v)
fp = hashlib.sha256("\x00".join(sorted(vals)).encode()).hexdigest()[:12]
open(os.environ["FPD"], "w").write("%d %s\n" % (len(fields), fp))
print("  Abschnitte %d · Felder %d · Fingerabdruck Werte %s" % (len(secs), len(fields), fp), file=sys.stderr)
print(json.dumps({"title": title, "category": "SECURE_NOTE", "tags": tags, "sections": secs, "fields": fields}))
' "$T" "$TAGS"
}
if [ "$LOS" != 1 ]; then baue >/dev/null; echo "TROCKENLAUF: nichts angelegt."; exit 0; fi
NEU=$(baue | op item create --vault "$V" --format json | python3 -c '
import json, sys, hashlib
d = json.load(sys.stdin); v = [f["value"] for f in d.get("fields", []) if f.get("section") and f.get("value") not in (None, "")]
print(d["id"], len(v), hashlib.sha256("\x00".join(sorted(v)).encode()).hexdigest()[:12])')
read -r ID NF NFP <<< "$NEU"; read -r QF QFP < "$FPD"
echo "Neu angelegt: $ID · Felder $NF · Fingerabdruck $NFP (Quelle: Felder $QF · $QFP)"
[ "$NF" = "$QF" ] && [ "$NFP" = "$QFP" ] || { echo "FEHLER: neues Item weicht von den Quellen ab — prüfen, ggf. op item delete $ID"; exit 5; }
echo "Gegenprobe bestanden: Feldanzahl und Fingerabdruck gleich."
