#!/usr/bin/env bash
# ============================================================
# NT-Forensik — Selbsttest der Lizenzschlüssel-Formprüfung (#83)
# ------------------------------------------------------------
#   werkzeuge/lizenzschluessel_selbsttest.sh [nt_repair.sh]
#
# WOZU
#
# Am 31.08.2026 stand in ~/.nt-repair/lizenz.key eine versehentlich
# hineinkopierte Befehlszeile mit einem Anführungszeichen darin. Der
# Anfragekörper wurde durch Zeichenkettenverkettung gebaut, das
# Anführungszeichen zerlegte das JSON, und der Lizenzserver antwortete
# „Invalid JSON body." — eine Meldung, die auf den SERVER zeigt, während die
# Ursache in einer LOKALEN DATEI lag. Das hat zwei Messungen am falschen Ende
# gekostet.
#
# Geprüft wird in BEIDE Richtungen. Eine Formprüfung, die alles abweist, wäre
# durch „weist immer ab" zu bestehen — und sie würde einen gültigen Schlüssel
# blockieren, also das Werkzeug unbrauchbar machen.
#
# Läuft ohne Netz: der Lader bricht vor dem ersten Aufruf ab, und genau das
# ist der Prüfgegenstand.
# ============================================================
set -uo pipefail
LADER="${1:-$(cd "$(dirname "$0")/.." && pwd)/nt_repair.sh}"
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/.nt-repair"
fail=0

pruefe() {   # <inhalt> <soll: ABGEFANGEN|DURCH> <beschreibung>
  printf '%s\n' "$1" > "$TMP/.nt-repair/lizenz.key"
  local aus; aus=$(HOME="$TMP" bash "$LADER" --findings /dev/null 2>&1)
  local ist="DURCH"
  grep -qE 'enthaelt keinen Lizenzschluessel|Kein Lizenzschluessel gefunden' <<<"$aus" && ist="ABGEFANGEN"
  if [[ "$ist" == "$2" ]]; then printf '  OK     %-44s -> %s\n' "$3" "$ist"
  else printf '  FEHLER %-44s -> %s (erwartet %s)\n' "$3" "$ist" "$2"; fail=1; fi
  # Der Inhalt darf NIE in der Ausgabe stehen: eine Fehlermeldung, die einen
  # Schlüssel in ein Protokoll oder einen Screenshot schreibt, ist ein
  # eigener Fehler.
  if [[ -n "$1" ]] && grep -qF "$1" <<<"$aus"; then
    printf '  FEHLER %-44s -> Schlüsselinhalt steht in der Ausgabe\n' "$3"; fail=1
  fi
}

echo "=== Formprüfung des Lizenzschlüssels"
pruefe 'curl -X POST "https://beispiel/api" -d "{}"' ABGEFANGEN "hineinkopierte Befehlszeile (der Anlassfall)"
pruefe ''                                            ABGEFANGEN "leere Datei"
pruefe 'NT-A1B2-C3D4'                                ABGEFANGEN "zu kurz"
pruefe 'NT-A1B2-C3D4-E5F6X'                          ABGEFANGEN "ein Zeichen zu viel"
pruefe 'NT-A1B2-C3D4-E5F6'                           DURCH      "gültige Form"
pruefe 'nt-a1b2-c3d4-e5f6'                           DURCH      "gültige Form, klein geschrieben"

echo "=== Der Anfragekörper ist gültiges JSON"
# Der Anlassfall entstand daran, dass der Körper durch Verkettung gebaut
# wurde. Hier wird derselbe Aufbau nachgerechnet, den der Lader benutzt.
KOERPER=$(python3 -c 'import json,sys; print(json.dumps({"key":sys.argv[1],"domain":sys.argv[2],"product":"nt-repair","nonce":sys.argv[3],"version":sys.argv[4]}))' \
          'NT-"A1B2"-C3D4-E5F6' 'ABC123' 'deadbeef' '0.8.3' 2>/dev/null)
if python3 -c 'import json,sys; d=json.loads(sys.argv[1]); sys.exit(0 if d["key"]=="NT-\"A1B2\"-C3D4-E5F6" else 1)' "$KOERPER" 2>/dev/null; then
  echo "  OK     Anführungszeichen im Schlüssel zerlegen das JSON nicht"
else
  echo "  FEHLER Anführungszeichen im Schlüssel zerlegen den Anfragekörper"; fail=1
fi

echo "=== curl verwirft seine Fehlerausgabe nicht mehr"
if grep -q 'curl .*2>/dev/null' "$LADER"; then
  echo "  FEHLER curl schreibt weiterhin nach /dev/null"; fail=1
else
  echo "  OK     kein 2>/dev/null an einem curl-Aufruf"
fi

[[ $fail -eq 0 ]] && echo "=> ALLE BESTANDEN" || echo "=> FEHLGESCHLAGEN"
exit $fail
