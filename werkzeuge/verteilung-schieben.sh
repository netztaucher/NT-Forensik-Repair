#!/usr/bin/env bash
# ============================================================
# NT-Forensik — gebauten Stand ins Verteil-Repo schreiben (#126)
# ------------------------------------------------------------
#   werkzeuge/verteilung-schieben.sh <standordner> <ziel-git-url> [tag]
#
# Test:     ja - werkzeuge/verteilung_selbsttest.sh gegen ein lokales Bare-Repo, läuft in pruefung.yml · NT-Forensik-Repair#126
# Rueckweg: ja - jeder Stand ist ein eigener Commit im Verteil-Repo; zurück mit `git revert` dort oder durch erneuten Lauf auf einem älteren Ref · NT-Forensik-Repair#126
#
# WOZU
#
# Nimmt den Ordner aus werkzeuge/verteilung-bauen.sh und macht daraus genau
# einen Commit auf `main` des Verteil-Repos (netztaucher/NT-Forensik). Kunden
# installieren mit `git clone` und aktualisieren mit `git pull --ff-only`;
# deshalb wird nur vorwärts geschrieben, nie mit --force.
#
# Unveränderter Stand erzeugt keinen Commit. Ein Tag wird nur angelegt, wenn
# es ihn im Verteil-Repo noch nicht gibt; ein vorhandenes Tag wird nie
# verschoben.
#
# Zugang: der Aufrufer setzt GIT_SSH_COMMAND (Deploy-Key). Dieses Skript liest
# und druckt keinen Schlüssel.
#
# Rückgabe: 0 geschrieben oder unverändert · 2 Aufruf falsch · 3 git scheiterte
# ============================================================
set -uo pipefail

STAND="${1:-}"; URL="${2:-}"; TAG="${3:-}"
abbruch() { echo "verteilung-schieben: $2" >&2; exit "$1"; }

[[ -n "$STAND" && -n "$URL" ]] || abbruch 2 "Aufruf: verteilung-schieben.sh <standordner> <ziel-git-url> [tag]"
[[ -r "$STAND/VERTEILSTAND" ]] || abbruch 2 "Kein gebauter Stand (VERTEILSTAND fehlt): $STAND"

ARBEIT="$(mktemp -d)"; trap 'rm -rf "$ARBEIT"' EXIT
W="$ARBEIT/repo"

git clone -q --branch main "$URL" "$W" 2>/dev/null || {
  # Leeres Verteil-Repo: es gibt noch keinen Zweig main.
  git clone -q "$URL" "$W" || abbruch 3 "Klonen fehlgeschlagen: $URL"
  git -C "$W" rev-parse -q --verify HEAD >/dev/null && abbruch 3 "Verteil-Repo hat Inhalt, aber keinen Zweig main."
  git -C "$W" checkout -q -b main
}

# Inhalt ersetzen, .git behalten. Ohne rsync, das nicht überall da ist.
find "$W" -mindepth 1 -maxdepth 1 ! -name .git -exec rm -rf {} +
cp -a "$STAND/." "$W/"

version="$(sed -n 's/^version=//p' "$STAND/VERTEILSTAND")"
quelle="$(sed -n 's/^quelle_commit=//p' "$STAND/VERTEILSTAND")"

git -C "$W" add -A
if git -C "$W" diff --cached --quiet; then
  echo "Verteil-Repo unverändert (Stand $version)."
else
  git -C "$W" -c core.hooksPath=/dev/null -c user.name="netztaucher Verteilung" \
              -c user.email="41898282+github-actions[bot]@users.noreply.github.com" \
      commit -q -m "Stand $version (${quelle:0:12})" || abbruch 3 "Commit fehlgeschlagen."
  echo "Neuer Stand $version (${quelle:0:12})."
fi

if [[ -n "$TAG" ]]; then
  if git -C "$W" ls-remote --exit-code --tags origin "refs/tags/$TAG" >/dev/null 2>&1; then
    echo "Tag $TAG gibt es im Verteil-Repo schon — bleibt, wie es ist."
    TAG=""
  else
    git -C "$W" tag -a "$TAG" -m "NT-Forensik $TAG" || abbruch 3 "Tag fehlgeschlagen."
  fi
fi

git -C "$W" push -q origin main || abbruch 3 "Push nach main fehlgeschlagen (nur vorwärts, kein --force)."
[[ -z "$TAG" ]] || git -C "$W" push -q origin "refs/tags/$TAG" || abbruch 3 "Push des Tags $TAG fehlgeschlagen."
echo "Verteil-Repo auf $(git -C "$W" rev-parse --short HEAD)${TAG:+, Tag $TAG}."
