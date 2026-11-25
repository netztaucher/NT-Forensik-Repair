#!/usr/bin/env bash
# =============================================================================
# kundenpaket-pruefstand.sh — prüft, was werkzeuge/kundenpaket.sh zurückhält
# =============================================================================
# Warum ein eigener Prüfstand:
#
# goldmuster.sh vergleicht den LAUF. Das Paket entsteht danach und aus einem
# anderen Werkzeug; kein bestehender Vergleich fasst es an. Und der Prüfbaum
# läuft mit --nur-website — er erzeugt deshalb ausschliesslich Belege der Stufe
# `kunde`. Ein Fehler in der Aussortierung von `server` und `betreiber` wäre
# damit unsichtbar, und zwar genau in der Richtung, die weh tut: zuviel geht
# mit.
#
# Hier stehen Soll-Werte. Bei "darf dieser Beleg mitgehen" ist die richtige
# Antwort vorher bekannt.
#
# Der Lauf wird ECHT erzeugt (goldmuster-Baum, ein Durchlauf des Werkzeugs) und
# anschliessend um je einen künstlichen `server`- und `betreiber`-Beleg
# ergänzt. Ein rein synthetischer Laufordner würde nur prüfen, ob das
# Paketwerkzeug sein eigenes Dateiformat versteht.
#
# Nutzung:  werkzeuge/kundenpaket-pruefstand.sh
# Rückgabe: 0 wenn alle Soll-Werte erreicht wurden, sonst 1
# =============================================================================
set -uo pipefail

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/.." && pwd)"
ARBEIT="${KUNDENPAKET_PRUEFSTAND_DIR:-${TMPDIR:-/tmp}/nt-kundenpaket-pruefstand}"
RED='\033[0;31m'; GRN='\033[0;32m'; NC='\033[0m'
FEHLER=0
pok()   { echo -e "  ${GRN}✓${NC} $1"; }
pfehl() { echo -e "  ${RED}✗${NC} $1"; FEHLER=$((FEHLER+1)); }

rm -rf "$ARBEIT"; mkdir -p "$ARBEIT"
echo "Kundenpaket-Prüfstand"
echo "  Arbeit: $ARBEIT"
echo

# ── Einen echten Lauf erzeugen ──────────────────────────────────────────────
NT_GOLDMUSTER_DIR="${ARBEIT}/gm" bash "${SELF_DIR}/werkzeuge/goldmuster.sh" baum >/dev/null 2>&1
BAUM="${ARBEIT}/gm/lauf/vhosts"
[[ -d "${BAUM}/kunde-zwei.example" ]] || { echo "Prüfbaum nicht entstanden."; exit 1; }

NT_TESTLAUF=1 \
NT_BASE_DIR="${ARBEIT}/ablage" \
NT_VHOSTS_DIR="$BAUM" \
WP_DATEN_DIR="${ARBEIT}/gm/lauf/wpdaten" \
WP_PRUEFSUMMEN_BASIS="${ARBEIT}/gm/lauf/wpsummen" \
NT_WEBSERVER=nginx \
PATH="${ARBEIT}/gm/lauf/bin:$PATH" \
LC_ALL=C LANG=C \
  bash "${SELF_DIR}/wp_plesk_forensik.sh" \
       --path "${BAUM}/kunde-zwei.example" --nur-website --kein-menue \
       >"${ARBEIT}/lauf.log" 2>&1

LAUF=$(find "${ARBEIT}/ablage/forensik" -maxdepth 1 -type d -name '2*' 2>/dev/null | head -1)
[[ -n "$LAUF" ]] || { echo "Kein Laufordner entstanden — siehe ${ARBEIT}/lauf.log"; exit 1; }
BELEGE="${LAUF}/betreiber/belege"
VERZ="${BELEGE}/00_verzeichnis.tsv"
[[ -s "$VERZ" ]] || { pfehl "Der Lauf hat kein 00_verzeichnis.tsv geschrieben (#1)"; exit 1; }
pok "Lauf steht, $(grep -c . "$VERZ") eingestufte(r) Beleg(e)"

# ── Zwei Belege ergänzen, die NICHT mitgehen dürfen ─────────────────────────
# Inhalte mit eindeutigen Marken, damit sich im Paket nachweisen lässt, dass
# nicht nur die Datei fehlt, sondern auch ihr Inhalt nirgends auftaucht.
printf 'MARKE_BETREIBER_GEHEIM\nSSL-Arbeiten am Server-Host\n' > "${BELEGE}/900_admin_changelog.txt"
printf 'MARKE_SERVERWEIT\n22/tcp offen\n'                       > "${BELEGE}/901_offene_ports.txt"
{
  printf '900\tbetreiber\tadmin_changelog\t900_admin_changelog.txt\n'
  printf '901\tserver\toffene_ports\t901_offene_ports.txt\n'
} >> "$VERZ"

# Ein fremder Kunde in einem `kunde`-Beleg. Die Maskierung muss ihn ersetzen —
# sonst wandert er mit in die Übergabe.
ERSTER=$(awk -F'\t' '$2=="kunde"{print $4; exit}' "$VERZ")
[[ -n "$ERSTER" ]] || { pfehl "kein kunde-Beleg im Lauf — Probe nicht durchführbar"; exit 1; }
printf '\n/var/www/vhosts/fremder-kunde.example/httpdocs/geheim.php\n' >> "${BELEGE}/${ERSTER}"

# ── Paket ohne Schalter ─────────────────────────────────────────────────────
P1="${ARBEIT}/paket_ohne"
bash "${SELF_DIR}/werkzeuge/kundenpaket.sh" "$LAUF" "$P1" >"${ARBEIT}/paket_ohne.log" 2>&1
if [[ ! -d "$P1" ]]; then
  pfehl "kein Paket entstanden — siehe ${ARBEIT}/paket_ohne.log"
  exit 1
fi

enthalten() { grep -rqF "$1" "$2" 2>/dev/null; }

if enthalten MARKE_BETREIBER_GEHEIM "$P1"; then
  pfehl "Der Betreiber-Beleg ist im Paket — genau der Fall aus #1"
else
  pok "Betreiber-Beleg bleibt draussen"
fi
if enthalten MARKE_SERVERWEIT "$P1"; then
  pfehl "Ein serverweiter Beleg geht ohne --mit-server mit"
else
  pok "serverweiter Beleg bleibt ohne --mit-server draussen"
fi
if enthalten fremder-kunde.example "$P1"; then
  pfehl "Ein fremder Kunde steht unmaskiert im Paket"
else
  pok "fremder Kunde ist maskiert"
fi
if [[ -e "${P1}/betreiber" ]] || find "$P1" -name 'findings.json' | grep -q .; then
  pfehl "findings.json oder die Betreiberspur liegt im Paket"
else
  pok "findings.json und Betreiberspur bleiben draussen"
fi

# Lückenlose Nummerierung: 001..N ohne Loch. Nach dem Aussortieren klaffen
# sonst Lücken, und eine Belegliste mit Löchern liest sich, als fehle etwas.
NUMMERN=$(find "${P1}/04_Belege" -name '[0-9][0-9][0-9]_*.txt' -exec basename {} \; 2>/dev/null \
          | cut -c1-3 | LC_ALL=C sort)
ANZ=$(printf '%s\n' "$NUMMERN" | grep -c . || true)
SOLL=$(seq -f '%03g' 1 "${ANZ:-0}" 2>/dev/null | LC_ALL=C sort)
if [[ "$ANZ" -gt 0 && "$NUMMERN" == "$SOLL" ]]; then
  pok "Belege lückenlos von 001 bis $(printf '%03d' "$ANZ")"
else
  pfehl "Belegnummern haben Lücken oder fehlen ganz (${ANZ} Datei(en))"
fi

# Das Siegel muss über die MASKIERTE Fassung stimmen. Ein Paket, dessen eigene
# Prüfsummen nicht aufgehen, ist als Beweismittel wertlos.
if ( cd "$P1" && sha256sum -c SHA256SUMS >/dev/null 2>&1 ); then
  pok "SHA256SUMS des Pakets geht auf"
else
  pfehl "SHA256SUMS des Pakets geht NICHT auf"
fi
if grep -q "SHA256" "${P1}/00_LIESMICH.txt" 2>/dev/null; then
  pok "LIESMICH erklärt, warum das Siegel abweicht"
else
  pfehl "LIESMICH sagt nicht, warum das Siegel vom Original abweicht"
fi

# ── Paket mit --mit-server ──────────────────────────────────────────────────
# Gegenprobe zur Sperre oben: der Schalter muss auch wirklich etwas bewirken.
# Ohne diese Probe wäre ein Werkzeug, das grundsätzlich nichts übernimmt,
# genauso "bestanden".
P2="${ARBEIT}/paket_mit_server"
bash "${SELF_DIR}/werkzeuge/kundenpaket.sh" "$LAUF" "$P2" --mit-server >/dev/null 2>&1
if enthalten MARKE_SERVERWEIT "$P2"; then
  pok "--mit-server nimmt den serverweiten Beleg auf"
else
  pfehl "--mit-server bewirkt nichts — die Sperre oben belegt dann gar nichts"
fi
if enthalten MARKE_BETREIBER_GEHEIM "$P2"; then
  pfehl "--mit-server zieht auch Betreiber-Belege mit — die Stufe trennt nicht"
else
  pok "--mit-server lässt Betreiber-Belege weiterhin draussen"
fi

# ── Betreiberlauf muss abgelehnt werden ─────────────────────────────────────
# Bei scope_mode=global gibt es keinen einzelnen Kunden, gegen den maskiert
# werden könnte — das Werkzeug darf dann kein Paket bauen, statt eines ohne
# Maskierung zu liefern.
LAUF_G="${ARBEIT}/lauf_global"
cp -R "$LAUF" "$LAUF_G"
python3 - "${LAUF_G}/betreiber/findings.json" <<'PY'
import json, sys
p = sys.argv[1]
d = json.load(open(p, encoding="utf-8"))
d.setdefault("run", {})["scope_mode"] = "global"
json.dump(d, open(p, "w", encoding="utf-8"))
PY
if bash "${SELF_DIR}/werkzeuge/kundenpaket.sh" "$LAUF_G" "${ARBEIT}/paket_global" >/dev/null 2>&1; then
  pfehl "Ein Betreiberlauf (scope_mode=global) wurde zu einem Kundenpaket verarbeitet"
else
  pok "Betreiberlauf wird abgelehnt"
fi

echo
if [[ "$FEHLER" -eq 0 ]]; then
  echo -e "${GRN}Alle Soll-Werte erreicht.${NC}"
  exit 0
fi
echo -e "${RED}${FEHLER} Abweichung(en).${NC}"
exit 1
