#!/usr/bin/env bash
# ============================================================
# NT-Forensik — Selbsttest: Bot-Sperrliste ist keine Cloaking-Weiche (#137)
# ------------------------------------------------------------
#   werkzeuge/htaccess_sperrliste_selbsttest.sh [13b_htaccess.sh]
#
# Test:     ja - dieser Selbsttest, Attrappen statt Server · NT-Forensik-Repair#137
# Rueckweg: entfällt - liest nur
#
# WOZU
#
# Abschnitt 13b meldete am 21.10.2026 eine echte WordPress-.htaccess als
# KRITISCH mit "3 Angreifer-Direktive(n)": bingbot, YANDEX und YandexBot in
# einer klassischen Bad-Bot-Sperrliste, die mit 'RewriteRule ^.* - [F,L]'
# endet. Das ist Abwehr — die Suchmaschine bekommt nichts, nicht etwas anderes.
#
# Geprueft wird in BEIDE Richtungen. Ein Filter, der nur "Sperrliste entlastet"
# prueft, waere durch "entlastet jede Suchmaschinen-Bedingung" zu bestehen —
# und dann bliebe genau die Weiche drin, fuer die die Regel gebaut wurde.
#
# Laeuft ohne Server, ohne WordPress und ohne Netz: der Abschnitt wird
# vollstaendig eingebunden, der Rahmen (crit/warn/evidence …) sind Attrappen.
# Die Anlassdatei selbst ist Kundenmaterial und liegt NICHT im Repo; der Fall
# unten bildet ihren Aufbau nach (Kennungen, Reihenfolge, Abschlussregel).
# ============================================================
# Attrappen und Rahmenvariablen werden erst vom eingebundenen Abschnitt benutzt —
# die statische Pruefung sieht das nicht.
# shellcheck disable=SC2034,SC2329
set -uo pipefail
MODUL="${1:-$(cd "$(dirname "$0")/.." && pwd)/module/13b_htaccess.sh}"
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
fail=0

# --- Attrappen des Rahmens -------------------------------------------------
PROTO=""
h1()   { :; }
h2()   { :; }
ok()   { PROTO+="OK|$1"$'\n'; }
info() { PROTO+="INFO|$1"$'\n'; }
warn() { PROTO+="WARN|$1"$'\n'; }
crit() { PROTO+="CRIT|$1"$'\n'; }
unklar() { PROTO+="UNKLAR|$1"$'\n'; }
code() { PROTO+="CODE|$1"$'\n'; }
evidence() { :; }
fortschritt_unterschritt() { :; }
datei_meta() { echo "-"; }
datei_steckbrief() { :; }
nf_strip_self() { cat; }
export NT_WEBSERVER=keiner

lauf() {   # <name> -> PROTO; Datei liegt in $TMP/<name>/.htaccess
  PROTO=""; HTACCESS_FREMD=""; HTACCESS_UNWIRKSAM=""
  VHOSTS_DIR="$TMP"; BELEGE_DIR="$TMP/belege.$1"; SCAN_PATHS=("$TMP/$1")
  # shellcheck source=/dev/null
  source "$MODUL"
}

fall() {   # <name> -> legt WordPress-Verzeichnis an, .htaccess von stdin
  mkdir -p "$TMP/$1"; printf '<?php\n' > "$TMP/$1/wp-config.php"
  cat > "$TMP/$1/.htaccess"
}

pruefe() {   # <name> <soll: CRIT|WARN|KEIN> <muster-im-protokoll|-> <beschreibung>
  local ist="KEIN"
  lauf "$1"
  if   grep -q '^CRIT|' <<< "$PROTO"; then ist="CRIT"
  elif grep -q '^WARN|' <<< "$PROTO"; then ist="WARN"
  fi
  if [[ "$ist" == "$2" ]] && { [[ "$3" == "-" ]] || grep -qF -- "$3" <<< "$PROTO"; }; then
    printf '  OK     %-52s -> %s\n' "$4" "$ist"
  else
    printf '  FEHLER %-52s -> %s (erwartet %s, Muster "%s")\n' "$4" "$ist" "$2" "$3"
    printf '%s' "$PROTO" | sed 's/^/           /' | head -12; fail=1
  fi
}

# --- Faelle -----------------------------------------------------------------
# 1. Anlass: Bad-Bot-Liste mit bingbot/YANDEX in der Mitte bzw. am Ende, eine
#    Abschlussregel mit Ziel '-' und [F,L], davor der WordPress-Block.
fall anlass <<'H'
# BEGIN WordPress
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteBase /
RewriteRule ^index\.php$ - [L]
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule . /index.php [L]
</IfModule>
# END WordPress
RewriteEngine On
RewriteCond %{HTTP_USER_AGENT} ^aipbot [OR]
RewriteCond %{HTTP_USER_AGENT} .*bingbot/.* [OR]
RewriteCond %{HTTP_USER_AGENT} .*Ahrefs/.* [OR]
RewriteCond %{HTTP_USER_AGENT} HTTrack [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^YANDEX [OR]
RewriteCond %{HTTP_USER_AGENT} ^YandexBot [OR]
RewriteCond %{HTTP_USER_AGENT} ^Zeus
RewriteRule ^.* - [F,L]
H

# 2. Dieselbe Sperre in Apache-2.4-Schreibweise R=403 und mit [G].
fall sperre_r403 <<'H'
RewriteCond %{HTTP_USER_AGENT} googlebot [NC]
RewriteRule ^privat/ - [R=403,L]
RewriteCond %{HTTP_USER_AGENT} slurp [NC]
RewriteRule .* - [G]
H

# 3. Echte Weiche: Suchmaschine bekommt eine PHP-Datei des Angreifers.
fall weiche_php <<'H'
RewriteEngine On
RewriteCond %{HTTP_USER_AGENT} (googlebot|bingbot) [NC]
RewriteRule ^(.*)$ /wp-content/uploads/2020/x.php?p=$1 [L]
H

# 4. Echte Weiche: Umleitung 302 auf eine fremde Domain.
fall weiche_r302 <<'H'
RewriteCond %{HTTP_USER_AGENT} Googlebot [NC,OR]
RewriteCond %{HTTP_USER_AGENT} YandexBot [NC]
RewriteRule ^(.*)$ https://spam.example.net/$1 [R=302,L]
H

# 5. Echte Weiche: Proxy auf fremden Inhalt.
fall weiche_proxy <<'H'
RewriteCond %{HTTP_USER_AGENT} bingbot [NC]
RewriteRule ^shop/(.*)$ http://doorway.example.org/$1 [P,L]
H

# 6. Weiche und Sperre in derselben Datei: die Sperre darf die Weiche nicht
#    mitentlasten — jede Bedingung mit IHRER Regel.
fall gemischt <<'H'
RewriteCond %{HTTP_USER_AGENT} ^YandexBot [OR]
RewriteCond %{HTTP_USER_AGENT} ^Baiduspider
RewriteRule ^.* - [F,L]
RewriteCond %{HTTP_USER_AGENT} googlebot [NC]
RewriteRule ^(.*)$ /cache/seo.php [L]
H

# 7. Verneinte Kennung vor einer Sperre: alle AUSSER Google ausgesperrt —
#    die Rueckseite der Weiche, nicht entlasten.
fall verneint <<'H'
RewriteCond %{HTTP_USER_AGENT} !googlebot [NC]
RewriteRule ^angebot/ - [F]
H

# 8. Mehrdeutig: Kennung vor einer internen Umschreibung ohne PHP-Ziel.
fall mehrdeutig <<'H'
RewriteCond %{HTTP_USER_AGENT} bingbot [NC]
RewriteRule ^(.*)$ /bot-seiten/$1 [L]
H

# 9. Kennung ohne jede nachfolgende Regel.
fall ohne_regel <<'H'
RewriteCond %{HTTP_USER_AGENT} duckduckbot [NC]
H

echo "=== Sperrliste wird entlastet"
pruefe anlass       KEIN "Sperrliste (Zugriff verweigert)" "Anlass #137: Bad-Bot-Liste mit [F,L]"
pruefe sperre_r403  KEIN "Sperrliste (Zugriff verweigert)" "Sperre mit R=403 bzw. [G]"

echo "=== Echte Weiche bleibt kritisch"
pruefe weiche_php   CRIT "PHP-Ziel"     "UA-Weiche auf fremde PHP-Datei"
pruefe weiche_r302  CRIT "fremde URL"   "UA-Bedingung + [R=302] auf fremde Domain"
pruefe weiche_proxy CRIT "Proxy [P]"    "UA-Bedingung + [P] auf fremden Inhalt"
pruefe gemischt     CRIT "PHP-Ziel"     "Sperre und Weiche in einer Datei"

echo "=== Mehrdeutiges nicht still ok"
pruefe verneint     WARN "verneinte"    "verneinte Kennung vor einer Sperre"
pruefe mehrdeutig   WARN "weder Sperre" "interne Umschreibung ohne PHP-Ziel"
pruefe ohne_regel   WARN "ohne nachfolgende" "Kennung ohne RewriteRule"

echo "=== Zaehlung im Anlassfall"
# Genau drei Suchmaschinen-Kennungen stehen in der Liste, alle drei muessen als
# Sperre vermerkt sein — keine darf als fremd mitlaufen.
lauf anlass
if grep -qF "3 Suchmaschinen-Kennung(en) in einer Bot-Sperrliste" <<< "$PROTO" \
   && ! grep -q "Angreifer-Direktive" <<< "$PROTO"; then
  echo "  OK     3 Kennungen als Sperre vermerkt, keine Angreifer-Direktive"
else
  echo "  FEHLER Zaehlung im Anlassfall:"; printf '%s' "$PROTO" | sed 's/^/           /'; fail=1
fi
# Im gemischten Fall darf die Sperre nicht als Angreifer-Direktive mitzaehlen.
lauf gemischt
if grep -qF "1 Angreifer-Direktive(n)" <<< "$PROTO"; then
  echo "  OK     gemischt: genau 1 Angreifer-Direktive (die Weiche)"
else
  echo "  FEHLER gemischt:"; printf '%s' "$PROTO" | sed 's/^/           /'; fail=1
fi

[[ $fail -eq 0 ]] && echo "=> ALLE BESTANDEN" || echo "=> FEHLGESCHLAGEN"
exit $fail
