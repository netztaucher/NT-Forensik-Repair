#!/usr/bin/env bash
# ============================================================
# NT-Forensik — WordPress-Datenbestand aktualisieren
# ------------------------------------------------------------
# Laeuft auf der Entwicklungsmaschine oder in der CI, NIEMALS auf einem
# Kundenserver. Deshalb liegt das Skript unter werkzeuge/ und wird von der
# Selbst-Installation bewusst nicht mit ausgeliefert.
#
# Schreibt ausschliesslich nach rezepte/wordpress/daten/ — der Bestand gehoert
# zum Rezept, damit ein Rezept weiterhin ein Verzeichnis ist und sonst nichts.
#
#   wordpress-daten-update.sh --wordfence    Schwachstellen (BRAUCHT SCHLUESSEL)
#   wordpress-daten-update.sh --kev          aktiv ausgenutzte Luecken (CISA)
#   wordpress-daten-update.sh --alles
#   wordpress-daten-update.sh --aus-datei <feed.json>   gespeicherten Feed einlesen
#
# ------------------------------------------------------------
# DER SCHLUESSEL VERLAESST DIESE MASCHINE NICHT
#
# Der Wordfence-Feed verlangt seit v3 einen Bearer-Schluessel, und die
# Nutzungsbedingungen untersagen ausdruecklich, ihn weiterzugeben oder
# unterzulizenzieren. Er wird deshalb aus der Umgebung gelesen
# (WORDFENCE_API_KEY) und steht weder im Repository noch im erzeugten
# Datenbestand. Auf einen Kundenserver gelangt nur das Ergebnis.
#
# ------------------------------------------------------------
# ES WERDEN NUR TATSACHEN UEBERNOMMEN
#
# Aus dem Feed kommen Name, Kennung, Versionsbereich, behobene Fassung,
# CVE-Nummer, CVSS-Wert und der Verweis auf den Datensatz. NICHT uebernommen
# werden description, remediation, researchers und cwe-Beschreibung — das sind
# formulierte Texte, und die traegt dieses Repository nicht.
#
# Derselbe Grundsatz wie bei daten/joomla/QUELLEN.md. Er ist hier zusaetzlich
# praktisch: weniger fremder Text heisst weniger Lizenzflaeche.
#
# Die Attributionsauflage von Defiant bleibt davon unberuehrt: jeder Datensatz
# fuehrt seinen Verweis in der Spalte 'quelle' mit. VOR der ersten Auslieferung
# eines Wordfence-Bestandes muss zusaetzlich rezepte/wordpress/daten/LICENSE mit dem
# Lizenztext angelegt werden — siehe rezepte/wordpress/daten/QUELLEN.md, Abschnitt
# 'Offen vor der ersten Auslieferung'.
# ============================================================
set -uo pipefail

HIER="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DATEN="${HIER}/rezepte/wordpress/daten"

WF_BASIS="https://www.wordfence.com/api/intelligence/v3/vulnerabilities"
KEV_URL="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

meldung() { printf '  %s\n' "$*"; }
fehler()  { printf 'FEHLER: %s\n' "$*" >&2; }

mkdir -p "${DATEN}/vuln" "${DATEN}/kev"

# ── Wordfence ───────────────────────────────────────────────
# Es gibt zwei Feeds. Genommen wird 'production': 'scanner' fuehrt weder CVE
# noch CVSS, und beides sind Tatsachen, die der Bericht braucht — eine
# CVE-Nummer ist die einzige quellenneutrale Kennung, ueber die sich ein Befund
# spaeter nachschlagen laesst. Die Beschreibungstexte, die 'production'
# zusaetzlich mitbringt, werden beim Normalisieren verworfen.
#
# Der Feed kennt keinen Teilabruf: beide Endpunkte liefern immer den ganzen
# Bestand und nehmen keine Parameter. Ein Delta gibt es also nur lokal.
wordfence_holen() {
    local ziel="$1"
    if [[ -z "${WORDFENCE_API_KEY:-}" ]]; then
        fehler "WORDFENCE_API_KEY ist nicht gesetzt."
        fehler "Schluessel unter wordfence.com → Integrations anlegen und setzen:"
        fehler "    export WORDFENCE_API_KEY='…'"
        fehler "Der Schluessel darf nicht ins Repository und nicht auf einen Kundenserver."
        return 1
    fi
    meldung "Feed abrufen (voller Bestand, kein Teilabruf moeglich) …"
    local code
    code=$(curl -sS -o "$ziel" -w '%{http_code}' --max-time 300 \
                -H "Authorization: Bearer ${WORDFENCE_API_KEY}" \
                "${WF_BASIS}/production" 2>/dev/null) || true
    case "${code:-000}" in
        200) meldung "HTTP 200, $(wc -c < "$ziel" | tr -d ' ') Bytes" ;;
        401) fehler "HTTP 401 — Schluessel abgelehnt."; return 1 ;;
        429) fehler "HTTP 429 — zu haeufig abgerufen. Spaeter erneut."; return 1 ;;
        410) fehler "HTTP 410 — Endpunkt abgeschaltet. Doku pruefen."; return 1 ;;
        *)   fehler "HTTP ${code} — Abruf fehlgeschlagen."; return 1 ;;
    esac
}

wordfence_normalisieren() {
    local roh="$1"
    python3 - "$roh" "${DATEN}/vuln" <<'PY'
import json, os, sys

roh, ziel = sys.argv[1], sys.argv[2]
try:
    with open(roh, encoding="utf-8", errors="replace") as fh:
        daten = json.load(fh)
except Exception as e:
    print("  FEHLER: Feed nicht lesbar (%s)" % e)
    sys.exit(1)

if not isinstance(daten, dict):
    print("  FEHLER: Wurzelelement ist kein Objekt — Feedformat geaendert?")
    sys.exit(1)

zeilen = {"core": [], "plugin": [], "theme": []}
# Kein stilles Verwerfen: was nicht verwertbar ist, wird gezaehlt und am Ende
# ausgewiesen. Ein Bestand, der klaglos 8000 Datensaetze schluckt und 300
# davon wegwirft, sieht vollstaendig aus und ist es nicht.
verworfen = {"ohne_software": 0, "ohne_slug": 0, "unbekannter_typ": 0,
             "ohne_bereich": 0}

def text(wert):
    return "" if wert is None else str(wert).replace("\t", " ").strip()

for uuid, satz in daten.items():
    if not isinstance(satz, dict):
        continue
    cve = text(satz.get("cve"))
    cvss = satz.get("cvss") or {}
    punkte = text(cvss.get("score") if isinstance(cvss, dict) else cvss)
    # Der Verweis auf den Datensatz ist Pflicht: die Lizenz von Defiant
    # verlangt ihn je Kopie. Fehlt er, wird er aus der Kennung gebaut.
    quelle = text(satz.get("references", [""])[0] if isinstance(satz.get("references"), list) and satz.get("references") else "")
    if not quelle:
        quelle = "https://www.wordfence.com/threat-intel/vulnerabilities/id/%s" % uuid

    programme = satz.get("software")
    if not isinstance(programme, list) or not programme:
        verworfen["ohne_software"] += 1
        continue

    for prog in programme:
        if not isinstance(prog, dict):
            continue
        typ = text(prog.get("type")).lower()
        if typ == "core":
            slug = "wordpress"
        else:
            slug = text(prog.get("slug"))
        if typ not in zeilen:
            verworfen["unbekannter_typ"] += 1
            continue
        if not slug:
            verworfen["ohne_slug"] += 1
            continue

        behoben = ""
        gepatcht = prog.get("patched_versions")
        if isinstance(gepatcht, list) and gepatcht:
            behoben = text(gepatcht[0])

        bereiche = prog.get("affected_versions")
        if not isinstance(bereiche, dict) or not bereiche:
            verworfen["ohne_bereich"] += 1
            continue

        for _bezeichnung, b in bereiche.items():
            if not isinstance(b, dict):
                continue
            # '*' heisst 'jede Fassung'. Leere Grenzen werden ebenso
            # behandelt; lib/wp_schwachstellen.py kennt beide Schreibweisen.
            von = text(b.get("from_version")) or "*"
            bis = text(b.get("to_version")) or "*"
            zeilen[typ].append("\t".join([
                slug, von,
                "1" if b.get("from_inclusive") else "0",
                bis,
                "1" if b.get("to_inclusive") else "0",
                behoben, cve, punkte, "", quelle,
            ]))

dateien = {"core": "wp-core.tsv", "plugin": "wp-plugins.tsv",
           "theme": "wp-themes.tsv"}
for typ, name in dateien.items():
    pfad = os.path.join(ziel, name)
    eindeutig = sorted(set(zeilen[typ]))
    with open(pfad, "w", encoding="utf-8") as fh:
        fh.write("# NT-Forensik — Schwachstellenbereiche %s\n" % typ)
        fh.write("# Quelle: Wordfence Intelligence, Defiant Inc. Siehe ../QUELLEN.md\n")
        fh.write("# slug\tvon\tvon_inkl\tbis\tbis_inkl\tbehoben\tcve\tcvss\tkev\tquelle\n")
        for z in eindeutig:
            fh.write(z + "\n")
    print("  %-16s %6d Zeile(n)" % (name, len(eindeutig)))

gesamt = sum(verworfen.values())
if gesamt:
    print("  Nicht uebernommen: %s" % ", ".join(
        "%s=%d" % (k, v) for k, v in sorted(verworfen.items()) if v))
PY
}

# ── CISA KEV ────────────────────────────────────────────────
# Werk einer US-Behoerde und damit gemeinfrei. Klein, aber es traegt die
# einzige Aussage, die eine Priorisierung wirklich rechtfertigt: diese Luecke
# wird nachweislich ausgenutzt. Das Gegenstueck zur Spalte 'kev' in
# daten/joomla/cve/joomla-ext-kritisch.tsv.
kev_aktualisieren() {
    echo "== Katalog bekannt ausgenutzter Schwachstellen (CISA KEV) =="
    local roh="${DATEN}/kev/.roh.json"
    if ! curl -fsS --max-time 60 -o "$roh" "$KEV_URL"; then
        fehler "KEV-Katalog nicht abrufbar"; return 1
    fi
    python3 - "$roh" "${DATEN}/kev/kev-wordpress.tsv" <<'PY'
import json, sys, pathlib
roh, ziel = sys.argv[1], sys.argv[2]
d = json.loads(pathlib.Path(roh).read_text(encoding="utf-8"))
alle = d.get("vulnerabilities", [])
# Uebernommen werden nur Tatsachen: Kennung, Hersteller, Produkt, Datum,
# Ransomware-Kennzeichen. shortDescription und requiredAction sind
# formulierte Texte und bleiben draussen.
treffer = []
for x in alle:
    heu = " ".join([x.get("vendorProject", ""), x.get("product", ""),
                    x.get("vulnerabilityName", "")]).lower()
    if "wordpress" not in heu:
        continue
    treffer.append("\t".join([
        x.get("cveID", ""), x.get("vendorProject", ""), x.get("product", ""),
        x.get("dateAdded", ""), x.get("knownRansomwareCampaignUse", ""),
    ]))
p = pathlib.Path(ziel)
p.write_text(
    "# NT-Forensik — WordPress-Eintraege aus dem KEV-Katalog der CISA\n"
    "# Quelle: cisa.gov, Werk einer US-Behoerde (gemeinfrei). Siehe ../QUELLEN.md\n"
    "# Katalogfassung: %s\n"
    "# cve\thersteller\tprodukt\taufgenommen\transomware\n" % d.get("catalogVersion", "")
    + "".join(z + "\n" for z in sorted(set(treffer))), encoding="utf-8")
print("  kev-wordpress.tsv %4d Eintrag/Eintraege (von %d im Katalog)"
      % (len(set(treffer)), len(alle)))
PY
    rm -f "$roh"
}

# ── kev-Spalte in die Schwachstellentabellen eintragen ──────
kev_verknuepfen() {
    [[ -f "${DATEN}/kev/kev-wordpress.tsv" ]] || return 0
    python3 - "${DATEN}" <<'PY'
import os, sys
basis = sys.argv[1]
kev = set()
kpfad = os.path.join(basis, "kev", "kev-wordpress.tsv")
if os.path.isfile(kpfad):
    for z in open(kpfad, encoding="utf-8"):
        if z.startswith("#") or not z.strip():
            continue
        kev.add(z.split("\t")[0].strip().upper())
if not kev:
    sys.exit(0)
for name in ("wp-core.tsv", "wp-plugins.tsv", "wp-themes.tsv"):
    pfad = os.path.join(basis, "vuln", name)
    if not os.path.isfile(pfad):
        continue
    aus, n = [], 0
    for z in open(pfad, encoding="utf-8"):
        if z.startswith("#") or not z.strip():
            aus.append(z); continue
        f = z.rstrip("\n").split("\t")
        if len(f) >= 9 and f[6].strip().upper() in kev:
            f[8] = "ja"; n += 1
        aus.append("\t".join(f) + "\n")
    open(pfad, "w", encoding="utf-8").writelines(aus)
    if n:
        print("  %-16s %d Eintrag/Eintraege als aktiv ausgenutzt markiert" % (name, n))
PY
}

# ── Datenstand festhalten ───────────────────────────────────
# Ohne Stand und Pruefsummen laesst sich spaeter nicht belegen, gegen welchen
# Bestand ein Befund entstanden ist. Fuer einen Bericht, der an einen Kunden
# oder ans BSI geht, ist das keine Nebensache.
stand_schreiben() {
    local datum; datum=$(date -u +"%Y-%m-%d")
    {
        printf '%s | erzeugt von werkzeuge/wordpress-daten-update.sh\n' "$datum"
        for f in "${DATEN}"/vuln/*.tsv "${DATEN}"/kev/*.tsv; do
            [[ -f "$f" ]] || continue
            printf '%-28s %6s Zeile(n)\n' "$(basename "$f")" \
                   "$(grep -vc '^#' "$f" 2>/dev/null || echo 0)"
        done
    } > "${DATEN}/VERSION"

    ( cd "$DATEN" && find . -type f \( -name '*.tsv' -o -name VERSION \) \
        | LC_ALL=C sort \
        | while read -r f; do
            if command -v sha256sum >/dev/null 2>&1; then sha256sum "$f";
            else shasum -a 256 "$f"; fi
          done ) > "${DATEN}/MANIFEST.sha256"
    meldung "VERSION und MANIFEST.sha256 geschrieben"
}

AKTION="${1:-}"
case "$AKTION" in
    --wordfence)
        echo "== Wordfence Intelligence =="
        ROH=$(mktemp); trap 'rm -f "$ROH"' EXIT
        wordfence_holen "$ROH" && wordfence_normalisieren "$ROH" && kev_verknuepfen
        stand_schreiben
        ;;
    --aus-datei)
        [[ -n "${2:-}" && -f "${2:-}" ]] || { fehler "Datei angeben"; exit 2; }
        echo "== Wordfence Intelligence (aus Datei ${2}) =="
        wordfence_normalisieren "$2" && kev_verknuepfen
        stand_schreiben
        ;;
    --kev)
        kev_aktualisieren && kev_verknuepfen
        stand_schreiben
        ;;
    --alles)
        kev_aktualisieren
        echo "== Wordfence Intelligence =="
        ROH=$(mktemp); trap 'rm -f "$ROH"' EXIT
        wordfence_holen "$ROH" && wordfence_normalisieren "$ROH"
        kev_verknuepfen
        stand_schreiben
        ;;
    *)
        sed -n '3,20p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
        exit 2
        ;;
esac
