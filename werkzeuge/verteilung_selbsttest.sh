#!/usr/bin/env bash
# ============================================================
# NT-Forensik — Selbsttest: Verteilung ins öffentliche Verteil-Repo (#126)
# ------------------------------------------------------------
#   werkzeuge/verteilung_selbsttest.sh
#
# Test:     ja - dieses Skript, Spiel-Repos und lokales Bare-Repo, kein Netz · NT-Forensik-Repair#126
# Rueckweg: entfällt - schreibt nur in ein Wegwerfverzeichnis
#
# WOZU
#
# Das Verteil-Repo ist öffentlich, das Quell-Repo soll privat werden. Der
# Fehler, der hier zählt, ist ein privater Ordner, der hinausgeht. Geprüft
# wird deshalb in BEIDE Richtungen:
#   1. echter Stand: Werkzeug ist vollständig und startet, Privates fehlt
#   2. Spiel-Repo: ein nicht eingestufter Ordner bricht ab (Code 3),
#      ebenso ein doppelt eingestufter und ein verwaister Eintrag
#   3. Aufruf: nicht leeres Ziel und fehlender Ref brechen ab (Code 2)
#   4. Schieben: erster Lauf in ein leeres Bare-Repo legt main an, zweiter
#      Lauf ohne Änderung erzeugt keinen Commit, ein Tag wird angelegt und
#      danach nicht verschoben
# ============================================================
set -uo pipefail
WURZEL="$(cd "$(dirname "$0")/.." && pwd)"
BAUEN="$WURZEL/werkzeuge/verteilung-bauen.sh"
SCHIEBEN="$WURZEL/werkzeuge/verteilung-schieben.sh"
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
FEHLER=0
ok()   { echo "  ✓ $1"; }
fehl() { echo "  ✗ $1"; FEHLER=$((FEHLER+1)); }
soll() {  # soll <erwarteter rc> <text> <befehl...>
  local rc_soll="$1" text="$2"; shift 2
  "$@" >"$TMP/out" 2>&1; local rc=$?
  if [[ "$rc" == "$rc_soll" ]]; then ok "$text (rc=$rc)"; else fehl "$text: rc=$rc, erwartet $rc_soll"; sed 's/^/      /' "$TMP/out"; fi
}
export GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@t GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@t
# Lokale Commit-Hooks (etwa eine Sperre gegen Commits auf main) gelten nicht für Spiel-Repos.
export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=core.hooksPath GIT_CONFIG_VALUE_0=/dev/null

echo "1. Echter Stand (HEAD)"
D="$TMP/echt"
soll 0 "baut" bash "$BAUEN" HEAD "$D"
for p in wp_plesk_forensik.sh nt_repair.sh lib/konfig.sh module paket LICENSE .gitignore VERTEILSTAND; do
  [[ -e "$D/$p" ]] && ok "enthält $p" || fehl "fehlt: $p"
done
for p in .github handovers verteilung; do
  [[ -e "$D/$p" ]] && fehl "Privates im Stand: $p" || ok "ohne $p"
done
ls "$D"/paket/*.enc >/dev/null 2>&1 && ok "verschlüsseltes Paket dabei" || fehl "kein Paket unter paket/"
grep -qx "quelle_commit=$(git -C "$WURZEL" rev-parse HEAD)" "$D/VERTEILSTAND" && ok "VERTEILSTAND nennt den Quell-Commit" || fehl "VERTEILSTAND falsch"
bash "$D/wp_plesk_forensik.sh" --help >"$TMP/hilfe" 2>&1   # erst Datei: grep -q unter pipefail
if grep -q "WP-PLESK-FORENSIK" "$TMP/hilfe"; then ok "Forensik startet aus dem Stand"; else fehl "Forensik startet nicht aus dem Stand"; fi
bash -n "$D/nt_repair.sh" && ok "Lader syntaktisch ok" || fehl "Lader: Syntaxfehler"

echo "2. Spiel-Repo: Einstufung"
S="$TMP/spiel"; mkdir -p "$S/werkzeuge" "$S/verteilung" "$S/lib" "$S/intern"
cp "$BAUEN" "$S/werkzeuge/"
echo 'TOOL_VERSION="9.9.9"' > "$S/lib/konfig.sh"; echo geheim > "$S/intern/x"
printf 'lib\nwerkzeuge\n' > "$S/verteilung/umfang.txt"
printf 'verteilung\nintern\n' > "$S/verteilung/privat.txt"
git -C "$S" init -q && git -C "$S" add -A && git -C "$S" commit -qm a
soll 0 "eingestuft: baut" env VERTEIL_QUELLE="$S" bash "$BAUEN" HEAD "$TMP/s1"
[[ -e "$TMP/s1/intern" ]] && fehl "privater Ordner intern/ ging mit" || ok "intern/ blieb draußen"
grep -q 'version=9.9.9' "$TMP/s1/VERTEILSTAND" && ok "Version aus lib/konfig.sh" || fehl "Version nicht gelesen"

mkdir -p "$S/repair"; echo quelltext > "$S/repair/kern.sh"; git -C "$S" add -A; git -C "$S" commit -qm b
soll 3 "neuer Ordner repair/ ohne Einstufung bricht ab" env VERTEIL_QUELLE="$S" bash "$BAUEN" HEAD "$TMP/s2"
[[ -e "$TMP/s2/repair" ]] && fehl "repair/ trotz Abbruch geschrieben" || ok "nichts von repair/ geschrieben"

printf 'repair\n' >> "$S/verteilung/privat.txt"; printf 'repair\n' >> "$S/verteilung/umfang.txt"
soll 3 "doppelt eingestuft bricht ab" env VERTEIL_QUELLE="$S" bash "$BAUEN" HEAD "$TMP/s3"
printf 'lib\nwerkzeuge\ngibtsnicht\n' > "$S/verteilung/umfang.txt"; printf 'verteilung\nintern\nrepair\n' > "$S/verteilung/privat.txt"
soll 3 "verwaister Eintrag in umfang.txt bricht ab" env VERTEIL_QUELLE="$S" bash "$BAUEN" HEAD "$TMP/s4"

echo "3. Aufruf"
mkdir -p "$TMP/voll"; echo x > "$TMP/voll/x"
soll 2 "nicht leeres Ziel" bash "$BAUEN" HEAD "$TMP/voll"
soll 2 "unbekannter Ref" bash "$BAUEN" gibt-es-nicht "$TMP/s5"
soll 2 "ohne Argumente" bash "$BAUEN"

echo "4. Schieben ins Bare-Repo"
B="$TMP/verteil.git"; git init -q --bare "$B"
soll 0 "erster Lauf in leeres Repo" bash "$SCHIEBEN" "$D" "$B" v0.0.1
[[ "$(git -C "$B" rev-list --count main 2>/dev/null)" == 1 ]] && ok "main mit einem Commit" || fehl "main fehlt oder falsch"
git -C "$B" rev-parse -q --verify refs/tags/v0.0.1 >/dev/null && ok "Tag v0.0.1 angelegt" || fehl "Tag fehlt"
git -C "$B" cat-file -e main:wp_plesk_forensik.sh 2>/dev/null && ok "Werkzeug im Verteil-Repo" || fehl "Werkzeug fehlt im Verteil-Repo"
git -C "$B" cat-file -e main:.github 2>/dev/null && fehl ".github im Verteil-Repo" || ok "kein .github im Verteil-Repo"
soll 0 "zweiter Lauf, gleicher Stand" bash "$SCHIEBEN" "$D" "$B"
[[ "$(git -C "$B" rev-list --count main)" == 1 ]] && ok "kein leerer Commit" || fehl "unveränderter Stand erzeugte einen Commit"
alt="$(git -C "$B" rev-parse -q --verify refs/tags/v0.0.1)"
echo neu >> "$D/README.md"
soll 0 "geänderter Stand, vorhandenes Tag" bash "$SCHIEBEN" "$D" "$B" v0.0.1
[[ "$(git -C "$B" rev-list --count main)" == 2 ]] && ok "neuer Commit vorwärts" || fehl "kein neuer Commit"
[[ -n "$alt" && "$(git -C "$B" rev-parse refs/tags/v0.0.1)" == "$alt" ]] && ok "Tag nicht verschoben" || fehl "Tag wurde verschoben"
soll 2 "Ordner ohne VERTEILSTAND" bash "$SCHIEBEN" "$TMP/voll" "$B"

echo
if (( FEHLER == 0 )); then echo "Verteilung: alles bestanden."; exit 0; fi
echo "Verteilung: $FEHLER Fehlschläge."; exit 1
