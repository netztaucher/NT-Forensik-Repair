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
# Seit dem Standard vom 21.10.2026 (#149, #150, #151) prüft er ausserdem die
# Kundendokumente selbst: aus dem echten Lauf und der anonymen Fixture
# pruefstand/kundenpaket/fall.json entstehen Sicherheitsbericht, DSGVO- und
# BSI-Dokument (NT Docs, WeasyPrint) und das Anschreiben. Geprüft werden
# Seitenzahl, Überlauf, Seitenbilder, fremde Kunden, die Interna-Sperrliste in
# beide Richtungen (grün ohne, rot mit eingeschleustem Issue-Verweis) und die
# Mail (Wortzahl, Anhänge).
#
# Braucht ein Python mit WeasyPrint (reportgen/README.md): $NT_WEASYPRINT_PY,
# sonst der Interpreter hinter $WEASYPRINT, sonst ~/.venvs/weasyprint.
#
# Nutzung:  werkzeuge/kundenpaket-pruefstand.sh
# Rückgabe: 0 wenn alle Soll-Werte erreicht wurden, sonst 1
#
# Test:     ja - ist selbst der Prüfstand (Soll-Werte, Gegenproben je Sperre) · NT-Forensik-Repair#1, #149
# Rueckweg: entfällt - schreibt nur in den Arbeitsordner (KUNDENPAKET_PRUEFSTAND_DIR)
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

# ── Kundendokumente (NT Docs) aus Lauf und Fixture ──────────────────────────
WPY="${NT_WEASYPRINT_PY:-}"
if [[ -z "$WPY" ]]; then
  _wp="${WEASYPRINT:-$(command -v weasyprint 2>/dev/null || true)}"
  [[ -n "$_wp" && "$_wp" != */* ]] && _wp="$(command -v "$_wp" 2>/dev/null || true)"
  [[ -n "$_wp" && -f "$_wp" ]] && WPY="$(head -1 "$_wp" | sed -n 's/^#![[:space:]]*//p' | awk '{print $1}')"
fi
[[ -z "$WPY" && -x "${HOME}/.venvs/weasyprint/bin/python" ]] && WPY="${HOME}/.venvs/weasyprint/bin/python"
if [[ -z "$WPY" ]] || ! "$WPY" -c 'import weasyprint' >/dev/null 2>&1; then
  pfehl "Kein Python mit WeasyPrint — die Kundendokumente sind NICHT geprüft (reportgen/README.md)"
  exit 1
fi
FALL="${SELF_DIR}/pruefstand/kundenpaket/fall.json"
KP="${ARBEIT}/kp_pruefung"

# Ein fremder Kunde in findings.json und in der Fundliste. Das Werkzeug darf
# nur Pfade aus dem Prüfumfang aufnehmen — sonst stünde er im Bericht.
python3 - "${LAUF}/betreiber/findings.json" "${LAUF}/betreiber/kundenpaket_funde.tsv" <<'PY'
import json, sys
p = sys.argv[1]
d = json.load(open(p, encoding="utf-8"))
d.setdefault("actionable", {}).setdefault("disguised_payloads", []).append(
    "/var/www/vhosts/fremder-kunde.example/httpdocs/wp-content/uploads/fremd.png")
json.dump(d, open(p, "w", encoding="utf-8"))
with open(sys.argv[2], "a", encoding="utf-8") as f:
    f.write("Getarnte Payload\t/var/www/vhosts/fremder-kunde.example/httpdocs/wp-content/uploads/fremd.png\t\n")
PY

"$WPY" "${SELF_DIR}/reportgen/kundenpaket.py" --lauf "$LAUF" --ziel "${LAUF}/kunde" --fall "$FALL" \
       --pruefung "$KP" --entwurf "${ARBEIT}/fall.entwurf.json" >"${ARBEIT}/kundenpaket_py.log" 2>&1
KP_RC=$?
if [[ "$KP_RC" -eq 0 ]]; then
  pok "Kundendokumente gesetzt, regelgerecht und ohne Interna"
else
  pfehl "reportgen/kundenpaket.py endet mit ${KP_RC} — siehe ${ARBEIT}/kundenpaket_py.log"
fi
BER=$(find "${LAUF}/kunde" -maxdepth 1 -name 'NT-Sicherheitsbericht_*.pdf' | head -1)
DSG=$(find "${LAUF}/kunde" -maxdepth 1 -name 'NT-Dokumentation_DSGVO-Art33_*.pdf' | head -1)
BSI=$(find "${LAUF}/kunde" -maxdepth 1 -name 'NT-Einordnung_BSI-Meldung_*.pdf' | head -1)
if [[ -s "$BER" && -s "$DSG" && -s "$BSI" ]]; then
  pok "drei PDFs: $(basename "$BER"), $(basename "$DSG"), $(basename "$BSI")"
else
  pfehl "nicht alle drei Kunden-PDFs entstanden"
fi

seiten() { pdfinfo "$1" 2>/dev/null | awk '/^Pages:/{print $2}'; }
for paar in "${DSG}:2" "${BSI}:2"; do
  f="${paar%:*}"; soll="${paar##*:}"
  [[ -f "$f" ]] || continue
  if [[ "$(seiten "$f")" == "$soll" ]]; then pok "$(basename "$f"): ${soll} Seiten"
  else pfehl "$(basename "$f"): $(seiten "$f") Seiten statt ${soll}"; fi
done
# Seitenzahl in der Fusszeile = Seiten des PDFs, und jede Seite liegt als Bild vor
for f in "$BER" "$DSG" "$BSI"; do
  [[ -f "$f" ]] || continue
  n=$(seiten "$f")
  fuss=$(pdftotext -enc UTF-8 "$f" - 2>/dev/null | grep -oE 'Seite [0-9]+ von [0-9]+' | awk '{print $4}' | sort -u | tr '\n' ' ')
  bilder=$(find "${KP}/seiten" -name "$(basename "$f" .pdf)-*.png" 2>/dev/null | grep -c .)
  if [[ "$fuss" == "${n} " && "$bilder" == "$n" ]]; then
    pok "$(basename "$f" .pdf): ${n} Seiten, Fusszeile (Seite x von ${n}), ${bilder} Seitenbilder"
  else
    pfehl "$(basename "$f" .pdf): ${n} Seiten, Fusszeile (Seite x von ${fuss}), ${bilder} Seitenbilder"
  fi
done
if python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); sys.exit(any(x["fehler"] or x["regelverstoesse"] for x in d["dokumente"]))' "${KP}/pruefung.json" 2>/dev/null; then
  pok "kein Überlauf, ≥ 8 mm über der Fusszeile, Titel einzeilig, Sprachregeln eingehalten"
else
  pfehl "Satzprüfung meldet Fehler — ${KP}/pruefung.json"
fi
if pdftotext -enc UTF-8 "$BER" - 2>/dev/null | grep -q 'fremder-kunde'; then
  pfehl "Ein fremder Kunde steht im Sicherheitsbericht"
else
  pok "fremder Kunde aus findings.json steht nicht im Sicherheitsbericht"
fi
# Die Fundliste (Abschnitt Schadcode) muss die Funde des Laufs tragen, nicht
# nur die Zeitachse. Gegenprobe zu einem Lauf, der eine leere Liste lieferte.
if pdftotext -enc UTF-8 "$BER" - 2>/dev/null | grep -qE '[0-9]+ Funde? im Webspace\. Pfade ab der Dokumentenwurzel'; then
  pok "Funde aus dem Prüfumfang stehen mit Pfad im Webspace im Bericht"
else
  pfehl "Funde aus dem Lauf fehlen im Bericht"
fi

# Gegenprobe Interna: ein Issue-Verweis in der Fall-Datei muss auffallen.
python3 - "$FALL" "${ARBEIT}/fall_interna.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
d["bericht"]["jetzt"] += " Siehe infra#1062."
json.dump(d, open(sys.argv[2], "w", encoding="utf-8"), ensure_ascii=False)
PY
"$WPY" "${SELF_DIR}/reportgen/kundenpaket.py" --lauf "$LAUF" --ziel "${ARBEIT}/kunde_interna" \
       --fall "${ARBEIT}/fall_interna.json" >"${ARBEIT}/kundenpaket_interna.log" 2>&1
IRC=$?
if [[ "$IRC" -eq 3 ]] && grep -q 'infra#1062' "${ARBEIT}/kundenpaket_interna.log"; then
  pok "Interna-Wächter schlägt bei eingeschleustem Issue-Verweis an"
else
  pfehl "Interna-Wächter schweigt zum eingeschleusten Issue-Verweis (rc ${IRC})"
fi

# Anschreiben: kurz, drei Punkte, alle Anhänge, ohne Interna
pdftoppm -r 60 -png -f 1 -l 1 "$BER" "${ARBEIT}/Screenshot_kunde-zwei.example" >/dev/null 2>&1
FOTO=$(find "$ARBEIT" -maxdepth 1 -name 'Screenshot_kunde-zwei.example*.png' | head -1)
python3 "${SELF_DIR}/mailgen/anschreiben.py" --fall "${ARBEIT}/fall.entwurf.json" --ziel "${ARBEIT}/mail" \
        --anhang "$BER" --anhang "$DSG" --anhang "$BSI" --bild "$FOTO" >"${ARBEIT}/anschreiben.log" 2>&1
MRC=$?
ANH=$(python3 -c 'import email,sys; m=email.message_from_bytes(open(sys.argv[1],"rb").read()); print(sum(1 for p in m.walk() if p.get_filename()))' "${ARBEIT}/mail/anschreiben.eml" 2>/dev/null)
if [[ "$MRC" -eq 0 && "$ANH" == "4" && -s "${ARBEIT}/mail/anschreiben.txt" && -s "${ARBEIT}/mail/anschreiben_entwurf.applescript" ]]; then
  pok "Anschreiben: $(grep -oE '[0-9]+ Wörter' "${ARBEIT}/anschreiben.log"), HTML + Text, 4 Anhänge, ohne Interna"
else
  pfehl "Anschreiben nicht regelgerecht (rc ${MRC}, ${ANH:-0} Anhänge) — ${ARBEIT}/anschreiben.log"
fi

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
if [[ -f "${P1}/01_Kundenunterlagen/$(basename "$BER")" && -f "${P1}/02_Meldungen/$(basename "$DSG")" \
      && -f "${P1}/02_Meldungen/$(basename "$BSI")" ]] && ! find "${P1}/01_Kundenunterlagen" "${P1}/02_Meldungen" -name '*.md' | grep -q .; then
  pok "Paket: Sicherheitsbericht in 01, DSGVO und BSI in 02, keine Markdown-Rohfassung"
else
  pfehl "Paket enthält nicht die NT-Docs-PDFs an ihrem Platz (oder Rohfassungen)"
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

# ── Paket aus einem Lauf mit Interna im PDF wird abgelehnt ──────────────────
LAUF_I="${ARBEIT}/lauf_interna"
cp -R "$LAUF" "$LAUF_I"
rm -f "${LAUF_I}"/kunde/NT-*.pdf
cp "${ARBEIT}"/kunde_interna/NT-*.pdf "${LAUF_I}/kunde/" 2>/dev/null
if bash "${SELF_DIR}/werkzeuge/kundenpaket.sh" "$LAUF_I" "${ARBEIT}/paket_interna" >"${ARBEIT}/paket_interna.log" 2>&1; then
  pfehl "Ein Lauf mit Interna in den Kunden-PDFs wurde zu einem Paket verarbeitet"
elif [[ -e "${ARBEIT}/paket_interna" ]]; then
  pfehl "kundenpaket.sh lehnt ab, hinterlässt aber ein Paket"
else
  pok "kundenpaket.sh lehnt Kunden-PDFs mit Interna ab, kein Paket entsteht"
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
