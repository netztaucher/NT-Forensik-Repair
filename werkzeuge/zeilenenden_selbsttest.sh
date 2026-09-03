#!/usr/bin/env bash
# ============================================================
# NT-Forensik — Selbsttest der Zeilenenden-Gegenprobe (#84)
# ------------------------------------------------------------
#   werkzeuge/zeilenenden_selbsttest.sh [rezept.sh]
#
# WOZU
#
# Am 31.08.2026 meldete der Plugin-Prüfsummenvergleich 108 "veränderte
# Codedateien" — kritisch, mit der vollen Sofortmaßnahmen-Liste. Von 47
# Dateien eines Plugins waren 46 nach `tr -d '\r'` byteweise identisch: das
# amtliche Archiv trug CRLF, die Installation war auf LF normalisiert worden.
#
# Der Test hält beide Richtungen fest UND die Gegenprobe: eine Datei mit
# echter Änderung muss weiterhin MOD ergeben. Ein Filter, der nur "meldet
# nicht mehr" prüft, wäre durch "meldet nie" zu bestehen — und das ist der
# Fehler, der hier weh tut.
#
# Läuft ohne WordPress und ohne Netz: der Prüfsummensatz wird aus den
# Testdateien selbst erzeugt.
# ============================================================
set -uo pipefail
REZEPT="${1:-$(cd "$(dirname "$0")/.." && pwd)/rezepte/wordpress/rezept.sh}"
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
fail=0

# Den Python-Vergleicher aus dem Rezept lösen (er lebt dort als Heredoc).
sed -n '/^import hashlib, json, os, sys$/,/^PY$/p' "$REZEPT" | sed '$d' > "$TMP/vergleich.py"
[[ -s "$TMP/vergleich.py" ]] || { echo "FEHLER: Vergleicher nicht aus $REZEPT lösbar"; exit 1; }

PDIR="$TMP/plugins/testplugin"; mkdir -p "$PDIR"
# Vorlage mit LF; das "amtliche" Archiv bekommt CRLF (die gemessene Richtung).
printf '<?php\nfunction a() {\n  return 1;\n}\n'            > "$TMP/original-lf.php"
printf '<?php\r\nfunction a() {\r\n  return 1;\r\n}\r\n'     > "$TMP/original-crlf.php"
printf '<?php\nfunction a() {\n  return 1;\n}\n// eval($_GET[0]);\n' > "$TMP/veraendert.php"

sha() { python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$1"; }

# Fall 1: Archiv CRLF, Installation LF        -> ZEILENENDEN
# Fall 2: Archiv LF,   Installation CRLF      -> ZEILENENDEN (Gegenrichtung)
# Fall 3: Archiv LF,   Installation verändert -> MOD
cp "$TMP/original-lf.php"   "$PDIR/a.php"
cp "$TMP/original-crlf.php" "$PDIR/b.php"
cp "$TMP/veraendert.php"    "$PDIR/c.php"
cat > "$TMP/soll.json" <<JSON
{"files": {
  "a.php": {"sha256": "$(sha "$TMP/original-crlf.php")"},
  "b.php": {"sha256": "$(sha "$TMP/original-lf.php")"},
  "c.php": {"sha256": "$(sha "$TMP/original-lf.php")"}
}}
JSON
printf 'testplugin\t1.0\t%s\t%s\n' "$PDIR" "$TMP/soll.json" > "$TMP/liste"

AUS=$(python3 "$TMP/vergleich.py" "$TMP/liste" 2>&1)

pruefe() {   # <datei> <erwartete-art> <beschreibung>
  local art; art=$(printf '%s\n' "$AUS" | awk -F'\t' -v d="$1" '$4 ~ d"$" {print $1; exit}')
  if [[ "$art" == "$2" ]]; then printf '  OK     %-44s -> %s\n' "$3" "$art"
  else printf '  FEHLER %-44s -> %s (erwartet %s)\n' "$3" "${art:-nichts}" "$2"; fail=1; fi
}

echo "=== Zeilenenden-Gegenprobe"
pruefe "a.php" ZEILENENDEN "Archiv CRLF, Installation LF"
pruefe "b.php" ZEILENENDEN "Archiv LF, Installation CRLF"
pruefe "c.php" MOD         "echte Änderung bleibt Befund"

# Die als ZEILENENDEN erkannten Dateien müssen mit ABSOLUTEM Pfad erscheinen —
# die Zeile speist die Prüfsummen-Whitelist, ein relativer Pfad entliese dort nichts.
if printf '%s\n' "$AUS" | awk -F'\t' '$1=="ZEILENENDEN"{print $4}' | grep -qv '^/'; then
  echo "  FEHLER Whitelist-Pfad ist nicht absolut"; fail=1
else
  echo "  OK     ZEILENENDEN-Zeilen tragen absolute Pfade"
fi

[[ $fail -eq 0 ]] && echo "=> ALLE BESTANDEN" || echo "=> FEHLGESCHLAGEN"
exit $fail
