#!/usr/bin/env bash
# ============================================================
# NT-Forensik — Selbsttest der Doorway-Einstufung aus robots.txt (#86)
# ------------------------------------------------------------
#   werkzeuge/doorway_selbsttest.sh
#
# WOZU
#
# Die robots.txt-Zeile „Sitemap: …/index.php/sitemap.xml" galt als Beweis für
# einen Doorway-Generator in der Datenbank. Sie ist keiner: index.php/… ist
# die PATHINFO-Permalinkform, die WordPress selbst beantwortet. Am 01.09.2026
# waren 6 von 8 crit-Befunden eines Laufs dieser Fehlalarm.
#
# Geprüft wird die Einstufung in BEIDE Richtungen. Ein Filter, der nur
# „meldet nicht mehr crit" prüft, wäre durch „meldet nie" zu bestehen — ein
# echter Doorway (tausende URLs, Spam-Muster) muss weiterhin crit ergeben.
#
# Der Test ruft nichts ab: die Sitemap-Antworten liegen als Dateien vor, die
# Einstufung wird auf denselben Kennzahlen nachgerechnet, die der Detektor
# bildet (Core-Marker, <loc>-Zahl, Spam-Treffer).
# ============================================================
set -uo pipefail
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
fail=0
SCHWELLE=500

# Die Einstufung des Detektors, gleiche Reihenfolge wie im Rezept.
urteil() {   # <kern> <n_url> <spam>
  local kern="$1" n="$2" spam="$3"
  if [[ "$spam" -gt 0 || "$n" -gt "$SCHWELLE" ]]; then echo crit
  elif [[ "$kern" -eq 1 ]]; then echo info
  else echo unklar; fi
}
kennzahlen() {   # <datei> -> "<kern> <n_url> <spam>"
  local f="$1" kern=0 n s
  grep -qE 'wp-sitemap-(posts|taxonomies|users)' "$f" && kern=1
  n=$(grep -c '<loc>' "$f" 2>/dev/null) || true
  s=$(grep -ciE 'viagra|cialis|casino|payday|escort|replica-watch|porn' "$f" 2>/dev/null) || true
  echo "$kern ${n:-0} ${s:-0}"
}
pruefe() {   # <datei> <erwartet> <beschreibung>
  local k; k=$(kennzahlen "$1"); local got; got=$(urteil $k)
  if [[ "$got" == "$2" ]]; then printf '  OK     %-46s -> %-6s (%s)\n' "$3" "$got" "$k"
  else printf '  FEHLER %-46s -> %s statt %s (%s)\n' "$3" "$got" "$2" "$k"; fail=1; fi
}

# 1) WordPress-Core-Sitemap-Index — der gemessene Normalfall
cat > "$TMP/core.xml" <<'XML'
<?xml version="1.0"?><sitemapindex>
<sitemap><loc>https://beispiel.example/wp-sitemap-posts-post-1.xml</loc></sitemap>
<sitemap><loc>https://beispiel.example/wp-sitemap-taxonomies-category-1.xml</loc></sitemap>
<sitemap><loc>https://beispiel.example/wp-sitemap-users-1.xml</loc></sitemap>
</sitemapindex>
XML
# 2) Echter Doorway: viele URLs
{ echo '<?xml version="1.0"?><urlset>'
  for i in $(seq 1 600); do echo "<url><loc>https://beispiel.example/seite-$i/</loc></url>"; done
  echo '</urlset>'; } > "$TMP/doorway_viele.xml"
# 3) Echter Doorway: wenige URLs, aber Spam
cat > "$TMP/doorway_spam.xml" <<'XML'
<?xml version="1.0"?><urlset>
<url><loc>https://beispiel.example/cheap-viagra-online/</loc></url>
<url><loc>https://beispiel.example/best-casino-bonus/</loc></url>
</urlset>
XML
# 4) Tote Route (404-HTML) — weder Core noch Doorway
printf '<!DOCTYPE html><html><body>Nicht gefunden</body></html>\n' > "$TMP/tot.html"

echo "=== Doorway-Einstufung aus der Sitemap-Antwort"
pruefe "$TMP/core.xml"          info   "Core-Sitemap (wp-sitemap-*) entlastet"
pruefe "$TMP/doorway_viele.xml" crit   "600 URLs ueber der Schwelle"
pruefe "$TMP/doorway_spam.xml"  crit   "wenige URLs, aber Spam-Muster"
pruefe "$TMP/tot.html"          unklar "tote Route bleibt unentschieden"

# Ohne Abruf (kein --online) gibt es keine Kennzahlen: das muss 'unklar' sein
# und darf nie crit werden.
got=$(urteil 0 0 0)
if [[ "$got" == "unklar" ]]; then echo "  OK     ohne --online kein Urteil                  -> unklar"
else echo "  FEHLER ohne --online -> $got"; fail=1; fi

[[ $fail -eq 0 ]] && echo "=> ALLE BESTANDEN" || echo "=> FEHLGESCHLAGEN"
exit $fail
