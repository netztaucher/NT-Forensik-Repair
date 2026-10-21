#!/usr/bin/env bash
# ============================================================
# NT-Forensik — Selbsttest der Fernzugangs-Befunde im WordPress-Rezept
# ------------------------------------------------------------
#   werkzeuge/wp_fernzugang_selbsttest.sh [rezept.sh]
#
# Test:     ja - dieses Skript selbst, ohne Server: Attrappen fuer Rahmen und Datenbank (NT_DB_ATTRAPPE) · NT-Forensik-Repair#134 #138 #139
# Rueckweg: entfällt - liest nur
#
# WOZU
#
# Fall vom 21.10.2026 (web68, web345): Einstieg ueber einen vergessenen
# UpdraftCentral-Schluessel, danach ein Autologin-Plugin (hero-hub/,
# hero-binder-1d4/), dazu verwaiste Administratorrechte in usermeta. Der Lauf
# auf main sah keine der drei Spuren. Dieser Test haelt die drei neuen
# Pruefungen an genau diesen Lagen fest:
#
#   _wp_autologin_plugins        (#134)  Anlass-Plugin -> crit + actionable;
#                                        legitimes wp_set_auth_cookie -> kein crit
#   _wp_db_persistenz e4         (#138)  verwaiste Rechte -> warn; keine -> ok
#   _wp_haertung_updraftcentral  (#139)  Schluessel -> warn; mit RPC-Logzeile
#                                        -> crit; das Schluesselmaterial steht
#                                        in KEINER Ausgabe und keiner Variable
#
# Die Plugin-Vorlage ist dem echten Fund nachgebaut, Token und Kennwort sind
# Platzhalter — die echten Werte gehoeren nicht ins Repository.
# ============================================================
set -uo pipefail
REZEPT="${1:-$(cd "$(dirname "$0")/.." && pwd)/rezepte/wordpress/rezept.sh}"
SELF_DIR="$(cd "$(dirname "$REZEPT")/../.." && pwd)"
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
fail=0

# --- Attrappen des Rahmens -------------------------------------------------
# Alles, was der Rahmen in Bericht, Konsole oder Beleg schreiben wuerde, landet
# in EINER Datei. Daran wird am Ende geprueft, dass kein Geheimnis darin steht.
AUSGABE="$TMP/ausgabe.txt"; : > "$AUSGABE"
ALLES="$TMP/alles.txt";     : > "$ALLES"
befund_melden() { printf 'BEFUND\t%s\t%s\t%s\t%s\n' "$2" "$3" "$4" "${5:-}" >> "$AUSGABE"; }
evidence()      { printf 'BELEG\t%s\n%s\n' "$1" "$2" >> "$AUSGABE"; }
code()          { printf 'CODE\n%s\n' "$1" >> "$AUSGABE"; }
info()          { printf 'INFO\t%s\n' "$1" >> "$AUSGABE"; }
werkzeug_da()   { command -v "$1" >/dev/null 2>&1; }
datei_meta()    { if stat -c %y "$1" >/dev/null 2>&1; then stat -c %y "$1" | cut -d. -f1; else stat -f '%Sm' -t '%Y-%m-%d %H:%M:%S' "$1" 2>/dev/null; fi; }
nf_fetch()      { return 1; }
RUN_DIR="$TMP"; DAYS_BACK=30; REZ_PFX="wp_"; WANT_ONLINE=0
VHOSTS_DIR="$TMP/vhosts"

eval "$(sed -n '/^datei_epoche()/,/^}/p' "${SELF_DIR}/lib/kern.sh")"
for f in _db_da _db_sql _wp_im_verzeichnis _wp_logdir _wp_log_lesen _wp_log_tage _wp_autologin_plugins \
         _wp_udc_lesen _wp_haertung_updraftcentral _wp_db_persistenz; do
  eval "$(sed -n "/^${f}()/,/^}\$/p" "$REZEPT")"
  declare -F "$f" >/dev/null || { echo "FEHLER: ${f} nicht im Rezept gefunden"; exit 1; }
done

neu() {   # frische Instanz unter vhosts/<domain>/httpdocs, Logs unter system/<domain>/logs
  REZ_KURZ="$1"; REZ_PFAD="${VHOSTS_DIR}/$1/httpdocs"
  mkdir -p "$REZ_PFAD/wp-content/plugins" "${VHOSTS_DIR}/system/$1/logs"
  printf '<?php\n' > "$REZ_PFAD/wp-config.php"
  WP_AUTOLOGIN_PLUGINS=""; WP_ORPHAN_CAPS=""; WP_UDC_SCHLUESSEL=""; WP_PLUGIN_LEICHEN=""; WP_OPT_CODE=""
  cat "$AUSGABE" >> "$ALLES"; : > "$AUSGABE"
  unset PRUEFSUMMEN_WHITELIST NT_DB_ATTRAPPE
}

ergebnis() {   # <name> <ok|FEHLER> [hinweis]
  if [[ "$2" == ok ]]; then printf '  OK     %s\n' "$1"; else printf '  FEHLER %s  %s\n' "$1" "${3:-}"; fail=1; fi
}
hat_befund() {   # <name> <schwere> <textmuster>
  if grep -E "^BEFUND	[a-z]+	$2	" "$AUSGABE" | grep -qF -- "$3"; then ergebnis "$1 -> $2" ok
  else ergebnis "$1 -> $2" FEHLER "$(grep '^BEFUND' "$AUSGABE" | cut -f3,4 | head -3 | tr '\n' '|' | cut -c1-200)"; fi
}
kein_befund() {   # <name> <schwere>
  if grep -qE "^BEFUND	[a-z]+	$2	" "$AUSGABE"; then ergebnis "$1 -> kein $2" FEHLER "$(grep -E "^BEFUND	[a-z]+	$2	" "$AUSGABE" | head -1 | cut -c1-160)"
  else ergebnis "$1 -> kein $2" ok; fi
}
enthaelt() {   # <name> <text> <muster>
  if [[ "$2" == *"$3"* ]]; then ergebnis "$1" ok; else ergebnis "$1" FEHLER "erwartet: $3 — ist: ${2:0:160}"; fi
}

# Anlass-Plugin, nachgebaut (Struktur wie hero-hub.php, Werte ersetzt).
anlass_plugin() {   # <datei>
  cat > "$1" <<'PHP'
<?php
/**
 * Hero Hub
 *
 * @wordpress-plugin
 * Plugin Name:       Hero Hub
 * Description:       Small maintenance toolkit: keeps option storage tidy.
 * Version:           2.8.1
 * Author:            QuietPress Labs
 */
if ( ! defined( 'ABSPATH' ) ) { exit; }
define( 'HEROHUB_TOKEN', 'PLATZHALTER-TOKEN-0000' );
define( 'HEROHUB_FIELD', '_platzhalter' );
define( 'HEROHUB_SVC_LOGIN', 'svc-platzhalter' );
define( 'HEROHUB_SVC_PASS', 'PLATZHALTER-PASS-0000' );
final class HeroHub {
	private function __construct() {
		add_action( 'init', array( $this, 'handle_sync' ), 1 );
	}
	public function handle_sync() {
		if ( isset( $_GET[ self::FIELD ] ) && hash_equals( self::TOKEN, (string) $_GET[ self::FIELD ] ) ) {
			$user = get_user_by( 'login', self::SVC_LOGIN );
			if ( ! $user ) {
				$uid = wp_insert_user( array(
					'user_login' => self::SVC_LOGIN,
					'user_pass' => self::SVC_PASS,
					'role' => 'editor',
				) );
				if ( is_wp_error( $uid ) ) return;
				$u = new WP_User( $uid );
				$u->add_cap( 'manage_options' );
				$u->add_cap( 'install_plugins' );
				$user = get_user_by( 'id', $uid );
			}
			wp_set_current_user( $user->ID, $user->user_login );
			wp_set_auth_cookie( $user->ID, true, is_ssl() );
			wp_safe_redirect( admin_url( 'index.php' ) );
			exit;
		}
	}
}
PHP
}

# ============================================================
echo "=== #134 _wp_autologin_plugins"

neu anlass.example
mkdir -p "$REZ_PFAD/wp-content/plugins/hero-hub/assets"
anlass_plugin "$REZ_PFAD/wp-content/plugins/hero-hub/hero-hub.php"
printf '/* placeholder */  \n' > "$REZ_PFAD/wp-content/plugins/hero-hub/assets/public.js"
for _i in 1 2 3; do
  printf '[21-Oct-2026 08:4%s:00 UTC] PHP Fatal error:  Uncaught Error: Undefined constant HeroHub::FIELD in %s/wp-content/plugins/hero-hub/hero-hub.php:21\n' \
    "$_i" "$REZ_PFAD" >> "${VHOSTS_DIR}/system/anlass.example/logs/error_log"
done
_wp_autologin_plugins
hat_befund  "Anlass-Plugin hero-hub" crit "Autologin-Hintertür"
enthaelt    "actionable nennt den Plugin-Ordner" "$WP_AUTOLOGIN_PLUGINS" "$REZ_PFAD/wp-content/plugins/hero-hub"$'\t'
enthaelt    "Beleg zaehlt die Fatal-Flut im error_log" "$(cat "$AUSGABE")" "3 Fatal-Zeile(n)"
enthaelt    "Beleg nennt die Rechtevergabe" "$(cat "$AUSGABE")" "add_cap(manage_options)"
enthaelt    "Beleg: Ordner im Untersuchungszeitraum" "$(cat "$AUSGABE")" "IM Untersuchungszeitraum"
if grep -qE 'PLATZHALTER-(TOKEN|PASS)' "$AUSGABE"; then ergebnis "Token/Kennwort nicht im Beleg" FEHLER
else ergebnis "Token/Kennwort nicht im Beleg" ok; fi

neu mu.example
mkdir -p "$REZ_PFAD/wp-content/mu-plugins"
anlass_plugin "$REZ_PFAD/wp-content/mu-plugins/maint.php"
_wp_autologin_plugins
hat_befund  "dieselbe Vorlage als mu-Plugin" crit "Autologin-Hintertür"
enthaelt    "actionable nennt die mu-Datei" "$WP_AUTOLOGIN_PLUGINS" "mu-plugins/maint.php"

neu legitim.example
mkdir -p "$REZ_PFAD/wp-content/plugins/eigene-anmeldung"
cat > "$REZ_PFAD/wp-content/plugins/eigene-anmeldung/eigene-anmeldung.php" <<'PHP'
<?php
/* Plugin Name: Eigene Anmeldung */
add_action( 'wp_login', function ( $login, $user ) {
	// Sitzung nach erfolgreicher Anmeldung verlaengern — kein Konto, keine Anfrage.
	wp_set_auth_cookie( $user->ID, true );
}, 10, 2 );
PHP
_wp_autologin_plugins
kein_befund "wp_set_auth_cookie ohne Benutzeranlage und Eingabe" crit
hat_befund  "wp_set_auth_cookie ohne Benutzeranlage und Eingabe" ok "kein Plugin mit Autologin-Muster"
enthaelt    "actionable bleibt leer" "${WP_AUTOLOGIN_PLUGINS:-LEER}" "LEER"

neu sammel.example
mkdir -p "$REZ_PFAD/wp-content/plugins/shop"
{ printf '<?php\n/* Plugin Name: Shop */\nfunction shop_neuer_kunde() {\n  $mail = sanitize_email( $_POST["email"] );\n  return wp_insert_user( array( "user_email" => $mail ) );\n}\n'
  for _i in $(seq 1 120); do printf '// Fuellzeile %s\n' "$_i"; done
  printf 'function shop_anmelde_cookie( $id ) {\n  wp_set_auth_cookie( $id, true );\n}\n'; } \
  > "$REZ_PFAD/wp-content/plugins/shop/shop-user-functions.php"
_wp_autologin_plugins
kein_befund "Sammeldatei: Merkmale weit auseinander (WooCommerce-Lage)" crit

neu entlastet.example
mkdir -p "$REZ_PFAD/wp-content/plugins/social-login"
anlass_plugin "$REZ_PFAD/wp-content/plugins/social-login/social-login.php"
PRUEFSUMMEN_WHITELIST="$TMP/whitelist.txt"
printf '%s\n' "$REZ_PFAD/wp-content/plugins/social-login/social-login.php" > "$PRUEFSUMMEN_WHITELIST"
_wp_autologin_plugins
kein_befund "amtlich bestätigte Datei mit Muster" crit
enthaelt    "als Herstellercode vermerkt" "$(cat "$AUSGABE")" "gegen die amtlichen Prüfsummen bestätigt"
enthaelt    "nicht in actionable" "${WP_AUTOLOGIN_PLUGINS:-LEER}" "LEER"

# ============================================================
echo "=== #138 verwaiste Administratorrechte (_wp_db_persistenz e4)"

neu verwaist.example
NT_DB_ATTRAPPE="$TMP/db_verwaist"; mkdir -p "$NT_DB_ATTRAPPE"
printf '5\twp_capabilities\ta:1:{s:13:"administrator";b:1;}\t10\n' > "$NT_DB_ATTRAPPE/verwaiste_rechte.tsv"
printf '9\twp_2_capabilities\ta:2:{s:6:"editor";b:1;s:14:"manage_options";b:1;}\tNULL\n' >> "$NT_DB_ATTRAPPE/verwaiste_rechte.tsv"
_wp_db_persistenz
hat_befund  "user_id 5 administrator ohne Benutzerzeile" warn "verwaiste Administratorrecht"
enthaelt    "actionable: user_id 5 mit Rechten" "$WP_ORPHAN_CAPS" "$REZ_PFAD"$'\t5\twp_capabilities\tadministrator'
enthaelt    "actionable: Multisite-Schluessel" "$WP_ORPHAN_CAPS" $'\t9\twp_2_capabilities\teditor,manage_options'
enthaelt    "Beleg nennt user_level" "$(cat "$AUSGABE")" $'5\twp_capabilities\tadministrator\t10'

neu sauber.example
NT_DB_ATTRAPPE="$TMP/db_sauber"; mkdir -p "$NT_DB_ATTRAPPE"; : > "$NT_DB_ATTRAPPE/verwaiste_rechte.tsv"
_wp_db_persistenz
hat_befund  "keine verwaisten Rechte" ok "keine verwaisten Administratorrechte"
enthaelt    "actionable bleibt leer" "${WP_ORPHAN_CAPS:-LEER}" "LEER"

# ============================================================
echo "=== #139 _wp_haertung_updraftcentral"

# Testoption wie aus `mysql -N`: PHP-serialisiert, Zeilenumbrueche im
# Schluessel als \n maskiert. Erzeugt ohne Shell-Variable, damit die
# Variablenpruefung am Ende nichts findet, was der Test selbst abgelegt hat.
python3 - "$TMP/db_udc" "$TMP/db_udc_multi" "$TMP/db_udc_kaputt" <<'PY'
import os, sys
def s(b): return b's:%d:"%s";' % (len(b), b)
key = b"-----BEGIN RSA PRIVATE KEY-----\nGEHEIM-NICHT-AUSGEBEN\n-----END RSA PRIVATE KEY-----"
eintrag = (b"a:4:{" + s(b"name") + s(b"UpdraftCentral Remote Control") + s(b"key") + s(key)
           + s(b"created") + b"i:1625097600;" + s(b"extra_info")
           + b"a:1:{" + s(b"mothership") + s(b"https://zentrale.example") + b"}}")
wert = b"a:1:{" + s(b"7a3f9c2e1b") + eintrag + b"}"
esc = wert.replace(b"\\", b"\\\\").replace(b"\n", b"\\n").replace(b"\t", b"\\t")
for d in sys.argv[1:]:
    os.makedirs(d, exist_ok=True)
open(os.path.join(sys.argv[1], "udc_optionen.tsv"), "wb").write(esc + b"\n")
open(os.path.join(sys.argv[2], "udc_sitemeta.tsv"), "wb").write(esc + b"\n")
open(os.path.join(sys.argv[3], "udc_optionen.tsv"), "wb").write(esc[: len(esc) // 2] + b"\n")
PY

neu ohne-udc.example
NT_DB_ATTRAPPE="$TMP/db_leer"; mkdir -p "$NT_DB_ATTRAPPE"
_wp_haertung_updraftcentral
hat_befund  "kein Schlüssel" ok "kein UpdraftCentral-Schlüssel"

neu udc.example
NT_DB_ATTRAPPE="$TMP/db_udc"
_wp_haertung_updraftcentral
hat_befund  "Schlüssel ohne RPC-Nutzung" warn "Fernsteuerung möglich"
enthaelt    "actionable: id, Name, Datum" "$WP_UDC_SCHLUESSEL" "$REZ_PFAD"$'\t7a3f9c2e1b\tUpdraftCentral Remote Control\t2021-07-01 00:00 UTC'
enthaelt    "Beleg: keine RPC-Zeile" "$(cat "$AUSGABE")" "keine in ${VHOSTS_DIR}/system/udc.example/logs"

neu rpc.example
NT_DB_ATTRAPPE="$TMP/db_udc"
_heute=$(LC_ALL=C date '+%d/%b/%Y:%H:%M:%S %z')
_alt=$(LC_ALL=C date -d '@1600000000' '+%d/%b/%Y:%H:%M:%S %z' 2>/dev/null || LC_ALL=C date -r 1600000000 '+%d/%b/%Y:%H:%M:%S %z')
{ printf '203.0.113.7 - - [%s] "POST / HTTP/1.1" 200 7084 "-" "WordPress/6.4; class-udrpc.php"\n' "$_heute"
  printf '198.51.100.9 - - [%s] "POST / HTTP/1.1" 200 7084 "-" "WordPress/6.4; class-udrpc.php"\n' "$_alt"
  printf '192.0.2.1 - - [%s] "GET / HTTP/1.1" 200 1000 "-" "Mozilla/5.0"\n' "$_heute"; } \
  > "${VHOSTS_DIR}/system/rpc.example/logs/access_ssl_log"
_wp_haertung_updraftcentral
hat_befund  "Schlüssel + udrpc-Logzeile im Zeitraum" crit "203.0.113.7"
if grep '^BEFUND' "$AUSGABE" | grep -qF '198.51.100.9'; then ergebnis "Logzeile ausserhalb des Zeitraums zaehlt nicht" FEHLER
else ergebnis "Logzeile ausserhalb des Zeitraums zaehlt nicht" ok; fi

# Anlass 21.10.2026: Plesk hatte um 06:43 rotiert, die RPC-Aufrufe lagen nur
# noch gepackt vor. Eine Pruefung, die .gz uebergeht, meldet dann warn statt crit.
neu gz-rpc.example
NT_DB_ATTRAPPE="$TMP/db_udc"
: > "${VHOSTS_DIR}/system/gz-rpc.example/logs/access_ssl_log"
printf '203.0.113.8 - - [%s] "POST / HTTP/1.1" 200 7084 "-" "WordPress/6.4; class-udrpc.php"\n' "$_heute" \
  | gzip -c > "${VHOSTS_DIR}/system/gz-rpc.example/logs/access_ssl_log.processed.1.gz"
_wp_haertung_updraftcentral
hat_befund  "udrpc-Zeile nur im rotierten .gz" crit "203.0.113.8"

neu alt-rpc.example
NT_DB_ATTRAPPE="$TMP/db_udc"
printf '198.51.100.9 - - [%s] "POST / HTTP/1.1" 200 7084 "-" "WordPress/6.4; class-udrpc.php"\n' "$_alt" \
  > "${VHOSTS_DIR}/system/alt-rpc.example/logs/access_ssl_log"
_wp_haertung_updraftcentral
hat_befund  "nur alte udrpc-Zeile" warn "Fernsteuerung möglich"

neu multi.example
NT_DB_ATTRAPPE="$TMP/db_udc_multi"
_wp_haertung_updraftcentral
hat_befund  "Multisite: Schlüssel in sitemeta" warn "Fernsteuerung möglich"

neu kaputt.example
NT_DB_ATTRAPPE="$TMP/db_udc_kaputt"
_wp_haertung_updraftcentral
hat_befund  "abgeschnittene Option" unklar "nicht lesbar"

neu ohnelog.example
rm -rf "${VHOSTS_DIR}/system/ohnelog.example"
NT_DB_ATTRAPPE="$TMP/db_udc"
_wp_haertung_updraftcentral
hat_befund  "ohne Protokollverzeichnis" warn "RPC-Nutzung nicht geprüft"

# ============================================================
echo "=== Schlüsselmaterial"
neu ende.example
declare -p > "$TMP/variablen.txt" 2>/dev/null
if grep -qF 'GEHEIM-NICHT-AUSGEBEN' "$ALLES"; then ergebnis "nicht in Befund, Beleg, Code, Hinweis" FEHLER
else ergebnis "nicht in Befund, Beleg, Code, Hinweis" ok; fi
if grep -qF 'GEHEIM-NICHT-AUSGEBEN' "$TMP/variablen.txt"; then ergebnis "nicht in einer Shell-Variable" FEHLER
else ergebnis "nicht in einer Shell-Variable" ok; fi
# Gegenprobe: die Attrappe enthaelt den Wert wirklich — sonst prueften die
# beiden Zeilen oben gegen nichts.
if grep -qF 'GEHEIM-NICHT-AUSGEBEN' "$TMP/db_udc/udc_optionen.tsv"; then ergebnis "Gegenprobe: Attrappe traegt den Wert" ok
else ergebnis "Gegenprobe: Attrappe traegt den Wert" FEHLER; fi

[[ $fail -eq 0 ]] && echo "=> ALLE BESTANDEN" || echo "=> FEHLGESCHLAGEN"
exit $fail
