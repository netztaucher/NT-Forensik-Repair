#!/usr/bin/env bash
# ============================================================
# NT-Forensik — öffentlichen Stand für das Verteil-Repo zusammenstellen (#126)
# ------------------------------------------------------------
#   werkzeuge/verteilung-bauen.sh <ref> <zielordner>
#
# Test:     ja - werkzeuge/verteilung_selbsttest.sh, läuft in pruefung.yml · NT-Forensik-Repair#126
# Rueckweg: entfällt - schreibt nur in einen neuen, leeren Zielordner
#
# WOZU
#
# Kunden installieren per anonymem `git clone`. Damit das Quell-Repo privat
# werden kann, holen sie den Stand künftig aus dem öffentlichen Verteil-Repo
# netztaucher/NT-Forensik. Dieses Skript legt fest, WAS dort ankommt.
#
# Was verteilt wird, steht in verteilung/umfang.txt, was nie verteilt wird, in
# verteilung/privat.txt. Jeder Eintrag der obersten Ebene muss in genau einer
# der beiden Listen stehen, sonst bricht das Skript ab. Ein neuer Ordner (etwa
# der Quelltext der Bereinigung) gelangt so nie aus Versehen hinaus: er ist
# privat, bis ihn jemand ausdrücklich in umfang.txt einträgt.
#
# Der Stand kommt per `git archive` aus dem angegebenen Ref, nicht aus dem
# Arbeitsverzeichnis. Nicht eingecheckte Dateien können also nicht mitgehen.
#
# Rückgabe: 0 gebaut · 2 Aufruf falsch · 3 Listen passen nicht zum Stand
# ============================================================
set -uo pipefail

QUELLE="${VERTEIL_QUELLE:-$(cd "$(dirname "$0")/.." && pwd)}"
REF="${1:-}"; ZIEL="${2:-}"

abbruch() { echo "verteilung-bauen: $2" >&2; exit "$1"; }

[[ -n "$REF" && -n "$ZIEL" ]] || abbruch 2 "Aufruf: verteilung-bauen.sh <ref> <zielordner>"
git -C "$QUELLE" rev-parse --verify -q "${REF}^{commit}" >/dev/null \
  || abbruch 2 "Ref nicht gefunden: $REF"
if [[ -e "$ZIEL" ]]; then
  [[ -d "$ZIEL" && -z "$(ls -A "$ZIEL")" ]] || abbruch 2 "Ziel ist nicht leer: $ZIEL"
fi

liste() {  # liste <datei> — Einträge ohne Kommentare und Leerzeilen
  [[ -r "$1" ]] || abbruch 3 "Liste fehlt: $1"
  sed -e 's/#.*//' -e 's/[[:space:]]*$//' -e 's/^[[:space:]]*//' "$1" | awk 'NF'
}

UMFANG="$(liste "$QUELLE/verteilung/umfang.txt")"
PRIVAT="$(liste "$QUELLE/verteilung/privat.txt")"
OBEN="$(git -C "$QUELLE" ls-tree --name-only "$REF")"

drin() { grep -qxF -- "$1" <<<"$2"; }

fehler=0
while IFS= read -r e; do
  [[ -n "$e" ]] || continue
  u=0; p=0
  drin "$e" "$UMFANG" && u=1
  drin "$e" "$PRIVAT" && p=1
  if (( u + p == 0 )); then
    echo "  nicht eingestuft: $e  (in verteilung/umfang.txt oder privat.txt eintragen)" >&2; fehler=1
  elif (( u + p == 2 )); then
    echo "  doppelt eingestuft: $e  (steht in umfang.txt UND privat.txt)" >&2; fehler=1
  fi
done <<<"$OBEN"
while IFS= read -r e; do
  [[ -n "$e" ]] || continue
  drin "$e" "$OBEN" || { echo "  umfang.txt nennt, was es nicht gibt: $e" >&2; fehler=1; }
done <<<"$UMFANG"
(( fehler == 0 )) || abbruch 3 "Listen passen nicht zum Stand $REF — nichts gebaut."

mkdir -p "$ZIEL"
EINTRAEGE=()   # ohne mapfile: das gibt es erst ab bash 4 (macOS hat 3.2)
while IFS= read -r e; do EINTRAEGE+=("$e"); done <<<"$UMFANG"
git -C "$QUELLE" archive --format=tar "$REF" -- "${EINTRAEGE[@]}" | tar -x -C "$ZIEL" \
  || abbruch 3 "git archive fehlgeschlagen."

# Zweite Sicherung: kein privater Eintrag im Ergebnis, egal wie er hineinkam.
while IFS= read -r e; do
  [[ -n "$e" ]] || continue
  [[ -e "$ZIEL/$e" ]] && abbruch 3 "privater Eintrag im Ergebnis: $e"
done <<<"$PRIVAT"

SHA="$(git -C "$QUELLE" rev-parse "${REF}^{commit}")"
VERSION="$(sed -n 's/^TOOL_VERSION="\(.*\)"/\1/p' "$ZIEL/lib/konfig.sh" 2>/dev/null | head -1)"
printf 'version=%s\nquelle_commit=%s\n' "${VERSION:-unbekannt}" "$SHA" > "$ZIEL/VERTEILSTAND"

echo "Stand ${VERSION:-unbekannt} (${SHA:0:12}) gebaut: $(find "$ZIEL" -type f | wc -l | tr -d ' ') Dateien in $ZIEL"
