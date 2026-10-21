#!/usr/bin/env bash
# ============================================================
# NT-Forensik — Selbsttest Suchraum und Hex-Ternaer-Kette in 7.3 (#144)
# ------------------------------------------------------------
#   werkzeuge/php_endung_selbsttest.sh [07_dateisystem.sh] [13d_webshell_einordnung.sh]
#
# Test:     ja - dieser Selbsttest selbst, Wegwerfbaum ohne Server · NT-Forensik-Repair#144
# Rueckweg: entfällt - liest nur
#
# WOZU
#
# 21.10.2026, web68 auf cletus: wp-content/plugins/german.php.bak, 48 993 B,
# eine Zeile Hex-Ternaer-Verschleierung ("<?php (0x4eF1)?0xBf9C0:…"). Imunify
# meldete sie, NT-Forensik fuehrte sie nur im Inventar: 7.3 las nur *.php,
# und keines der Muster kannte die Kette.
#
# Geprueft wird in beide Richtungen:
#   - .php.bak mit Hex-Ternaer-Kette (groesser als DROPPER_MAX_BYTES) -> Stufe 1
#     mit Vermerk "per include ausführbar", in 13d kritisch
#   - Datei ohne PHP-Endung, aber mit <?php-Kopf und Kette -> ebenso
#   - .php~ und .php.bak OHNE Schadmuster -> nirgends (die Endung erweitert
#     nur den Suchraum, sie belastet nicht)
#   - .jpg mit <?php-Kopf -> wie bisher nur 7.13, nicht doppelt in 7.3
#   - legitime .php -> nirgends; kleiner .php-Dropper -> Stufe 1 ohne Vermerk
#   - grosse .php mit gewoehnlichem Muster -> weiterhin Stufe 2 (Groessenregel
#     unveraendert)
#   - Kopfsuche unter cache/ -> ausgelassen
#
# Die Proben sind SYNTHETISCH: dieselbe Struktur wie der Fund, nicht der Fund.
# Echte Malware gehoert nicht ins Repo.
#
# Geprueft wird der ECHTE Code: die Abschnitte 7.3 und 7.13 werden aus dem
# Modul geschnitten und mit Attrappen des Rahmens ausgefuehrt, 13d ganz. Der
# Kopfteil laeuft dreimal — mit Inventar, ohne Inventar (find) und mit
# erzwungenem awk-Weg —, damit kein Zweig unbelegt bleibt.
#
# VORAUSSETZUNGEN, UND WAS OHNE SIE PASSIERT
#
# Teil A (7.3/7.13) braucht ein grep mit -P und GNU-stat; Teil B (13d) braucht
# python3. Fehlt etwas, wird der Teil NICHT als bestanden gezaehlt: der Test
# endet dann mit 2 ("nicht vollstaendig geprueft"), nie mit 0. Eine Pruefung,
# die nicht lief, ist keine bestandene. In der CI (Linux) laufen beide.
# ============================================================
set -uo pipefail
WURZEL="$(cd "$(dirname "$0")/.." && pwd)"
MODUL="${1:-${WURZEL}/module/07_dateisystem.sh}"
MODUL13D="${2:-${WURZEL}/module/13d_webshell_einordnung.sh}"
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
fail=0; unvollstaendig=0

soll() {   # <beschreibung> <bedingung als Ausdruck>
  if eval "$2"; then printf '  OK     %s\n' "$1"
  else printf '  FEHLER %s\n         (%s)\n' "$1" "$2"; fail=1; fi
}

# ── Wegwerfbaum ──────────────────────────────────────────────
V="$TMP/vhosts/web68.example/httpdocs"
mkdir -p "$V/wp-content/plugins" "$V/wp-admin/includes" "$V/wp-content/uploads/2026/10" \
         "$V/wp-content/cache/seite" "$V/wp-content/languages"

# Hex-Ternaer-Kette wie im Fund, aber synthetisch: 300 Glieder, damit die
# Datei ueber DROPPER_MAX_BYTES (3000 B) liegt — genau dort fiel sie bisher
# in die Sichtung statt in Stufe 1.
kette() { local i; printf '<?php '; for ((i = 0; i < 300; i++)); do printf '(0xAB)?0xCD:'; done; printf '0;\n'; }
BAK="$V/wp-content/plugins/german.php.bak"
kette > "$BAK"
touch -t 201302270000 "$BAK" 2>/dev/null || true
KOPF="$V/wp-content/languages/german.txt"          # keine PHP-Endung, PHP-Kopf
kette > "$KOPF"
CACHE="$V/wp-content/cache/seite/eintrag.txt"       # Kopfsuche laesst cache/ aus
kette > "$CACHE"

# Editor-Sicherungen legitimer Dateien: duerfen nirgends auftauchen.
TILDE="$V/wp-admin/includes/upgrade.php~"
cat > "$TILDE" <<'PHP'
<?php
/**
 * WordPress Upgrade API — Editor-Sicherung, unveraendert.
 */
function wp_install_defaults( $user_id ) {
	global $wpdb, $wp_rewrite, $table_prefix;
	$cat_name = __( 'Uncategorized' );
	return update_option( 'default_category', 1 );
}
PHP
BAK_LEGIT="$V/wp-content/plugins/hallo.php.bak"
printf '<?php\n/* Plugin Name: Hallo */\nfunction hallo() { echo "Hallo"; }\n' > "$BAK_LEGIT"
TXT_LEGIT="$V/wp-content/languages/notiz.txt"
printf '<?php\n// Konfigurationsnotiz, harmlos\n$farbe = "blau";\n' > "$TXT_LEGIT"

# Bild mit PHP-Kopf: Sache von 7.13, nicht von 7.3.
JPG="$V/wp-content/uploads/2026/10/bild.jpg"
printf '<?php eval($_POST["x"]); ?>\n' > "$JPG"

# Legitime .php und ein kleiner, gewoehnlicher Dropper.
LEGIT="$V/index.php"
printf "<?php\ndefine( 'WP_USE_THEMES', true );\nrequire __DIR__ . '/wp-blog-header.php';\n" > "$LEGIT"
DROP="$V/wp-content/uploads/2026/10/x.php"
printf '<?php eval(base64_decode($_POST["c"])); ?>\n' > "$DROP"
# Grosse .php mit gewoehnlichem Muster: bleibt Stufe 2.
GROSS="$V/wp-content/plugins/gross.php"
{ printf '<?php\n'; for ((i = 0; i < 200; i++)); do printf '// Fuelltext fuer die Groessenschwelle\n'; done
  printf 'eval($code);\n'; } > "$GROSS"

# Minimales Inventar im Format von datei_inventar (lib/kern.sh): Groesse in
# Spalte 6, Pfad in Spalte 10.
INV="$TMP/00_dateien.tsv"
{ printf '# dev\tinode\tmodus\teigner\tgruppe\tgroesse\tmtime\tctime\tcrtime\tpfad\n'
  find "$TMP/vhosts" -type f | LC_ALL=C sort | while IFS= read -r f; do
    printf '1\t1\t644\tu\tg\t%s\t0\t0\t-\t%s\n' "$(wc -c < "$f" | tr -d ' ')" "$f"
  done; } > "$INV"

# ── Teil A: 7.3 und 7.13 ausfuehren ─────────────────────────
PCRE_GREP=""
for _g in grep ggrep ugrep; do
  if command -v "$_g" >/dev/null 2>&1 && echo x | "$_g" -qP x 2>/dev/null; then PCRE_GREP="$_g"; break; fi
done
GNU_STAT=0; stat -c%s "$LEGIT" >/dev/null 2>&1 && GNU_STAT=1

# Abschnitte aus dem Modul schneiden: von der Ueberschrift bis vor die naechste.
abschnitt() { sed -n "/^h2 \"$1 /,/^h2 \"$2 /p" "$MODUL" | sed '$d'; }
abschnitt '7\.3' '7\.4'   > "$TMP/a73.sh"
abschnitt '7\.13' '7\.14' > "$TMP/a713.sh"

laufA() {   # <mit_inventar 0|1> <ohne_python 0|1>
  rm -f "$TMP/ergA"
  # SC2034: die Variablen liest der per `source` eingebundene Code.
  # shellcheck disable=SC2034
  (
    SCAN_PATHS=("$TMP/vhosts"); BASE_DIR="$TMP/basis"; SELF_DIR="$WURZEL"
    NF_GREP="$PCRE_GREP"; YLW=""; NC=""; DISGUISED_PAYLOADS=""
    [[ "$1" == "1" ]] && INVENTAR_DATEI="$INV" || INVENTAR_DATEI=""
    NT_KOPF_OHNE_PYTHON="$2"
    eval "$(grep -E '^(PATTERN_REGEX|PATTERN_REGEX_MED|DROPPER_MAX_BYTES)=' "${WURZEL}/lib/konfig.sh")"
    # shellcheck source=/dev/null
    source "${WURZEL}/lib/muster.sh"
    CRIT=""
    h2() { :; }; info() { :; }; ok() { :; }; code() { :; }; evidence() { :; }; warn() { :; }
    crit() { CRIT+="$1"$'\n'; }
    befund_melden() { CRIT+="UNKLAR: $4"$'\n'; }
    # shellcheck source=/dev/null
    source "$TMP/a73.sh"
    # shellcheck source=/dev/null
    source "$TMP/a713.sh"
    {
      printf 'HITS<<\n%s\n>>\n' "${WEBSHELL_HITS:-}"
      printf 'DROPPER<<\n%s\n>>\n' "${DROPPER_DETAIL:-}"
      printf 'REVIEW<<\n%s\n>>\n' "${REVIEW_DETAIL:-}"
      printf 'MED<<\n%s\n>>\n' "${MED_DETAIL:-}"
      printf 'KOPF<<\n%s\n>>\n' "${PHP_KOPF_DATEIEN:-}"
      printf 'MEDIA<<\n%s\n>>\n' "${DISGUISED_PAYLOADS:-}"
      printf 'CRIT<<\n%s\n>>\n' "$CRIT"
    } > "$TMP/ergA"
  )
}
teil() { awk -v k="$1" '$0 == k"<<" {an=1; next} an && $0 == ">>" {exit} an {print}' "$TMP/ergA"; }
# Den Absatz einer Datei aus einem Detailblock holen.
absatz() { awk -v p="=== $2 ===" '$0 == p {an=1; print; next} an && /^=== / {exit} an {print}' <<< "$(teil "$1")"; }
drin() { teil "$1" | grep -qxF "=== $2 ===" ; }
gelistet() { teil "$1" | grep -qxF "$2"; }

if [[ -z "$PCRE_GREP" || "$GNU_STAT" != "1" ]]; then
  echo "=== Teil A (7.3/7.13) NICHT GEPRUEFT: grep mit -P ${PCRE_GREP:-fehlt}, GNU-stat $([[ $GNU_STAT == 1 ]] && echo da || echo fehlt)"
  unvollstaendig=1
else
  for variante in "1 0:mit Inventar" "0 0:ohne Inventar (find)" "1 1:awk-Weg statt python3"; do
    args="${variante%%:*}"; name="${variante#*:}"
    # shellcheck disable=SC2086
    laufA $args
    echo "=== Teil A, ${name}"
    soll ".php.bak mit Hex-Kette in Stufe 1"            'drin DROPPER "$BAK"'
    soll ".php.bak: Vermerk Hex-Ternär-Kette"           '[[ "$(absatz DROPPER "$BAK")" == *"HEX-TERNÄR-KETTE"* ]]'
    soll ".php.bak: Vermerk per include ausführbar"     '[[ "$(absatz DROPPER "$BAK")" == *"ENDUNG: .php.bak statt .php — per include ausführbar"* ]]'
    soll ".php.bak: Datei groesser als 3000 B"          '[[ $(wc -c < "$BAK") -gt 3000 ]]'
    soll ".php.bak nicht zusaetzlich in Stufe 2"        '! drin REVIEW "$BAK"'
    soll "PHP-Kopf ohne Endung erkannt"                 'gelistet KOPF "$KOPF"'
    soll ".txt mit PHP-Kopf und Kette in Stufe 1"       'drin DROPPER "$KOPF"'
    soll ".txt: Vermerk per include ausführbar"         '[[ "$(absatz DROPPER "$KOPF")" == *"ENDUNG: .txt statt .php — per include ausführbar"* ]]'
    soll "cache/ von der Kopfsuche ausgelassen"         '! gelistet KOPF "$CACHE" && ! gelistet HITS "$CACHE"'
    soll ".php~ ohne Schadmuster: kein Treffer"         '! gelistet HITS "$TILDE" && ! drin MED "$TILDE"'
    soll ".php.bak ohne Schadmuster: kein Treffer"      '! gelistet HITS "$BAK_LEGIT" && ! drin MED "$BAK_LEGIT"'
    soll ".txt mit Kopf ohne Schadmuster: kein Treffer" '! gelistet HITS "$TXT_LEGIT"'
    soll ".jpg mit PHP-Kopf: nicht in 7.3"              '! gelistet HITS "$JPG" && ! gelistet KOPF "$JPG"'
    soll ".jpg mit PHP-Kopf: wie bisher 7.13"           'gelistet MEDIA "$JPG" && [[ "$(teil CRIT)" == *"PHP-Code in 1 Mediendatei"* ]]'
    soll "legitime .php: kein Treffer"                  '! gelistet HITS "$LEGIT"'
    soll "kleiner .php-Dropper weiter in Stufe 1"       'drin DROPPER "$DROP"'
    soll ".php-Dropper: kein Endungsvermerk"            '[[ "$(absatz DROPPER "$DROP")" != *"ENDUNG:"* ]]'
    soll "grosse .php mit eval(\$: weiter Stufe 2"      'drin REVIEW "$GROSS" && ! drin DROPPER "$GROSS"'
  done
  absatz DROPPER "$BAK" > "$TMP/bak_absatz"
fi

# ── Teil C: Kopfsuche allein, python3- gegen awk-Weg ────────
#
# Braucht weder PCRE noch GNU-stat und laeuft deshalb auch auf dem
# Arbeitsplatz. Beide Wege muessen dieselbe Menge liefern — sonst haengt das
# Ergebnis davon ab, ob auf dem Server python3 liegt.
eval "$(sed -n '/^_php_kopf_kandidaten()/,/^}/p; /^_php_kopf_pruefen()/,/^}/p' "$TMP/a73.sh")"
if ! declare -F _php_kopf_pruefen >/dev/null; then
  echo "=== Teil C, Kopfsuche"
  soll "Kopfsuche im Modul vorhanden" 'false'
else
  # shellcheck disable=SC2034
  kopf() {   # <mit_inventar 0|1> <ohne_python 0|1>
    ( SCAN_PATHS=("$TMP/vhosts"); BASE_DIR="$TMP/basis"; SELF_DIR="$WURZEL"
      [[ "$1" == "1" ]] && INVENTAR_DATEI="$INV" || INVENTAR_DATEI=""
      NT_KOPF_OHNE_PYTHON="$2"
      # shellcheck source=/dev/null
      source "${WURZEL}/lib/muster.sh"
      _php_kopf_kandidaten | tr '\n' '\0' | _php_kopf_pruefen | LC_ALL=C sort -u )
  }
  # shellcheck disable=SC2034  # gelesen in den soll-Ausdruecken (eval)
  ERW=$(printf '%s\n' "$KOPF" "$TXT_LEGIT" | LC_ALL=C sort)
  echo "=== Teil C, Kopfsuche"
  if command -v python3 >/dev/null 2>&1; then
    soll "python3-Weg, mit Inventar"  '[[ "$(kopf 1 0)" == "$ERW" ]]'
    soll "python3-Weg, ohne Inventar" '[[ "$(kopf 0 0)" == "$ERW" ]]'
  else
    echo "  (python3-Weg nicht geprueft: python3 fehlt)"; unvollstaendig=1
  fi
  soll "awk-Weg, mit Inventar"        '[[ "$(kopf 1 1)" == "$ERW" ]]'
  soll "awk-Weg, ohne Inventar"       '[[ "$(kopf 0 1)" == "$ERW" ]]'
fi

# ── Teil B: 13d ordnet die Kette als kritisch ein ───────────
if ! command -v python3 >/dev/null 2>&1; then
  echo "=== Teil B (13d) NICHT GEPRUEFT: python3 fehlt"
  unvollstaendig=1
else
  # Aus Teil A, wenn er lief; sonst ein Absatz im Format von 7.3 mit den
  # Vermerken, die 7.3 schreibt (Wortlaut oben in Teil A belegt).
  if [[ -s "$TMP/bak_absatz" ]]; then
    D="$(cat "$TMP/bak_absatz")"$'\n'
  else
    D="=== $BAK ===
Größe: 3609 B | mtime: 2013-02-27 00:00:00 | SHA256: 0
Angelegt (crtime): nicht verfügbar
OBFUSKATION: HEX-TERNÄR-KETTE — konstante Bedingungen aus Hex-Literalen, kein legitimer Code; Stufe 1 unabhängig von der Größe
ENDUNG: .php.bak statt .php — per include ausführbar
Treffer: 1:<?php (0xAB)?0xCD:(0xAB)?0xCD:
"$'\n'
  fi
  mkdir -p "$TMP/run/belege"
  # shellcheck disable=SC2034
  (
    RUN_DIR="$TMP/run"; BELEGE_DIR="$TMP/run/belege"; SELF_DIR="$WURZEL"
    REPORT_FILE="$TMP/run/bericht.md"; : > "$REPORT_FILE"
    DROPPER_MAX_BYTES=3000; WANT_ONLINE=1; NF_OHNE_INJEKTIONSMASS=1
    DROPPER_DETAIL="$D"; WEBSHELL_COUNT=1
    CRIT=""
    h2() { :; }; code() { :; }; warn() { :; }; ok() { :; }; info() { :; }; evidence() { :; }
    crit() { CRIT+="$1"$'\n'; }
    # shellcheck source=/dev/null
    source "$MODUL13D"
    printf '%s' "$CRIT" > "$TMP/critB"
    printf '%s\n' "${DROPPER_DETAIL:-}" | grep '^=== ' > "$TMP/actionB" || true
  )
  echo "=== Teil B, 13d"
  soll "crit fuer die .php.bak"                     '[[ "$(cat "$TMP/critB")" == *"gefunden: 1 Datei(en)"* ]]'
  soll "Wortlaut nennt die Hex-Ternär-Kette"        '[[ "$(cat "$TMP/critB")" == *"Hex-Ternär-Kette in jeder Größe, davon 1"* ]]'
  soll "kein falsches \"< 3000 B\" vor der Zahl"    '[[ "$(cat "$TMP/critB")" != *"1 Datei(en) < 3000 B"* ]]'
  soll "in actionable (Bereinigungsliste)"          'grep -qF "$BAK" "$TMP/actionB"'
fi

if [[ $fail -ne 0 ]]; then echo "=> FEHLGESCHLAGEN"; exit 1; fi
if [[ $unvollstaendig -ne 0 ]]; then echo "=> NICHT VOLLSTAENDIG GEPRUEFT (keine Fehler in den gelaufenen Teilen)"; exit 2; fi
echo "=> ALLE BESTANDEN"
exit 0
