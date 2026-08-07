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
    (r'\S*?[/.]nt-goldmuster/lauf',                '<PRUEFSTAND>'),
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
  local d
  for d in technik_bericht.md kundenbericht.md bsi_meldung.md dsgvo_meldung.md findings.json; do
    [[ -f "${lauf}/${d}" ]] && normalisieren "${lauf}/${d}" > "${ZIEL}/${d}"
  done
  normalisieren "${ABLAGE}/konsole.txt" > "${ZIEL}/konsole.txt"
  cp "${ABLAGE}/rueckgabewert.txt" "${ZIEL}/" 2>/dev/null || true
  # Die Belegdateinamen sind Teil des Verhaltens, ihr Inhalt nicht.
  ls -1 "${lauf}/belege" 2>/dev/null | sort > "${ZIEL}/belege_dateiliste.txt" || true
}

# ── Hauptteil ────────────────────────────────────────────────
echo -e "${BOLD}NT-Forensik · Goldmuster${NC}"
echo -e "  Programmstand: $(cd "$SELF_DIR" && git rev-parse --short HEAD 2>/dev/null || echo '?')"

BAUM="${ARBEIT}/vhosts"; ABLAGE="${ARBEIT}/ablage"
mkdir -p "$ABLAGE"
baum_bauen "$BAUM"
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
