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
#   wordpress-daten-update.sh --composer <verzeichnis>  GHSA/OSV fuer Packagist
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
# Die Attributionsauflage von Defiant bleibt davon unberuehrt. Sie verlangt je
# Kopie drei Dinge, und alle drei entstehen maschinell:
#
#   1. Verweis auf den Datensatz -> Spalte 'quelle' jeder Zeile
#   2. Copyright-Vermerk         -> LICENSE, aus dem Feld 'copyrights' des Feeds
#   3. Lizenztext im Wortlaut    -> LICENSE, ebendaher
#
# Punkt 2 und 3 waren bis v3.13 Handarbeit mit einer Sperre davor. Seit der
# Feed sein Feld 'copyrights' mitliefert, ist das ueberfluessig — siehe
# lizenz_schreiben() weiter unten und QUELLEN.md.
# ============================================================
set -uo pipefail

HIER="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# NT_DATEN_DIR ist die Naht fuer den Pruefstand: er muss pruefen koennen, dass
# bei fehlender Lizenz KEIN Bestand entsteht — und das geht nur, wenn er dabei
# nicht das echte Verzeichnis beschreibt.
DATEN="${NT_DATEN_DIR:-${HIER}/rezepte/wordpress/daten}"

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
# ── Das Lizenz-Gate (#8) ─────────────────────────────────────
#
# Sobald ein Wordfence-Bestand im oeffentlichen Repository liegt, ist er
# AUSGELIEFERT — und die Auflagen gelten ab diesem Augenblick, nicht ab dem
# naechsten Release. Die Weitergabe ist nur gedeckt, wenn Copyright-Vermerk und
# Lizenztext je Kopie beiliegen; der Verweis je Zeile in der Spalte 'quelle'
# genuegt der Auflage nicht.
#
# Als Punkt auf einer Merkliste war das ein Vorsatz. Hier ist es eine Sperre:
# solange rezepte/wordpress/daten/LICENSE ein Geruest ist, wird kein Bestand
# geschrieben. Ein Vorsatz haelt genau bis zu dem Tag, an dem es eilig ist.
lizenz_gate() {
    local lic="${DATEN}/LICENSE"
    if [[ ! -r "$lic" ]]; then
        fehler "${lic} fehlt."
        fehler "Ohne Copyright-Vermerk und Lizenztext ist die Weitergabe nicht gedeckt."
        return 1
    fi
    if grep -q '^PLATZHALTER' "$lic"; then
        fehler "${lic} ist noch ein Geruest — lizenz_schreiben hat nicht gegriffen."
        fehler "Das ist ein Fehler im Ablauf, keine Handarbeit: der Lizenztext"
        fehler "wird seit v3.14 aus dem Feld 'copyrights' des Feeds abgeleitet."
        return 1
    fi
    for marke in 'DATUM EINTRAGEN' 'STAND EINTRAGEN' 'IM WORTLAUT EINSETZEN'; do
        if grep -qF "$marke" "$lic"; then
            fehler "${lic}: '[${marke}]' steht noch drin."
            return 1
        fi
    done
    return 0
}

# ── Lizenztext aus dem Feed ableiten (#8) ────────────────────
#
# Der Feed fuehrt je Datensatz ein Feld 'copyrights' mit Vermerk und Lizenztext
# im Wortlaut — fuer Defiant durchgaengig, fuer MITRE bei allen Saetzen mit
# CVE-Bezug. Damit muss der Text weder abgeschrieben noch von der Webseite
# geholt werden (die blockt Skriptzugriff mit HTTP 202 und leerem Rumpf).
#
# Das loest §5c baulich statt durch Vorsatz: Lizenztext und Bestand stammen
# zwangsläufig aus DEMSELBEN Abruf. Eine einseitige Aenderung der Bedingungen
# kann nicht mehr unbemerkt an einem alten Text vorbeilaufen.
#
# Die Gegenprobe steckt in der Auswertung selbst: weichen die Saetze im
# Lizenztext voneinander ab, wird abgebrochen. Ein Bestand, in dem zwei
# Fassungen nebeneinander stehen, laesst sich nicht mit einer ausliefern.
lizenz_schreiben() {
    local roh="$1"
    python3 - "$roh" "${DATEN}/LICENSE" "$(date -u +%Y-%m-%d)" <<'PY'
import json, sys

roh, ziel, datum = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    with open(roh, encoding="utf-8", errors="replace") as fh:
        daten = json.load(fh)
except Exception as e:
    print("  FEHLER: Feed nicht lesbar (%s)" % e)
    sys.exit(1)

# Je Partei alle vorkommenden Fassungen einsammeln. Nicht die erste nehmen und
# hoffen: genau die Annahme "wird schon ueberall gleich sein" ist die, die
# spaeter niemand mehr nachweisen kann.
parteien = {}
meldungen = set()
for satz in daten.values():
    if not isinstance(satz, dict):
        continue
    c = satz.get("copyrights") or {}
    if not isinstance(c, dict):
        continue
    if isinstance(c.get("message"), str):
        meldungen.add(c["message"])
    for name, eintrag in c.items():
        if not isinstance(eintrag, dict):
            continue
        p = parteien.setdefault(name, {"n": 0, "fassungen": set()})
        p["n"] += 1
        p["fassungen"].add((eintrag.get("notice") or "",
                            eintrag.get("license") or "",
                            eintrag.get("license_url") or ""))

if not parteien:
    print("  FEHLER: Feed fuehrt kein Feld 'copyrights' — Format geaendert?")
    print("  Ohne Lizenztext aus der Quelle wird nichts geschrieben.")
    sys.exit(1)

uneinig = [n for n, p in parteien.items() if len(p["fassungen"]) != 1]
if uneinig:
    for n in uneinig:
        print("  FEHLER: %s fuehrt %d verschiedene Lizenzfassungen im selben "
              "Bestand." % (n, len(parteien[n]["fassungen"])))
    print("  Abbruch: ein Bestand mit zwei Fassungen laesst sich nicht mit")
    print("  einer ausliefern. Die Abweichung gehoert geprueft, nicht geglaettet.")
    sys.exit(1)

gesamt = len(daten)
zeilen = []
schreib = zeilen.append
schreib("Wordfence Intelligence Vulnerability Database — Lizenz und Vermerke")
schreib("=" * 68)
schreib("")
schreib("DIESE DATEI IST ERZEUGT. Sie wird von werkzeuge/wordpress-daten-update.sh")
schreib("bei jedem Bestandsaufbau aus dem Feld 'copyrights' des Feeds neu")
schreib("abgeleitet — nicht von Hand gepflegt und nicht aus einer aelteren")
schreib("Fassung uebernommen.")
schreib("")
schreib("Grund: §5c der Bedingungen behaelt eine einseitige Aenderung vor. Ein")
schreib("Lizenztext, der nicht zu dem Bestand passt, mit dem er ausgeliefert")
schreib("wird, belegt nichts. Weil Text und Daten aus demselben Abruf stammen,")
schreib("kann das hier nicht auseinanderlaufen.")
schreib("")
schreib("  Abgerufen am      : %s" % datum)
schreib("  Datensaetze gesamt: %d" % gesamt)
schreib("")
if meldungen:
    for m in sorted(meldungen):
        schreib("  Hinweis des Feeds : %s" % m)
    schreib("")
schreib("Die Auflage verlangt je Kopie drei Dinge. Alle drei sind erfuellt:")
schreib("")
schreib("  1. Verweis auf den einzelnen Datensatz — Spalte 'quelle' jeder Zeile")
schreib("     in vuln/*.tsv, aus dem Feld 'references' des Feeds.")
schreib("  2. Copyright-Vermerk  — unten, im Wortlaut aus der Quelle.")
schreib("  3. Lizenztext         — unten, im Wortlaut aus der Quelle.")
schreib("")
for name in sorted(parteien):
    notice, lizenz, url = next(iter(parteien[name]["fassungen"]))
    n = parteien[name]["n"]
    schreib("")
    schreib(name)
    schreib("-" * max(len(name), 20))
    schreib("Betrifft %d von %d Datensaetzen (%.1f %%)." % (n, gesamt, 100.0 * n / gesamt))
    schreib("")
    schreib("Copyright-Vermerk im Wortlaut:")
    schreib("")
    schreib("  " + notice)
    schreib("")
    schreib("Lizenztext im Wortlaut:")
    schreib("")
    for absatz in lizenz.split("\n"):
        schreib("  " + absatz if absatz.strip() else "")
    schreib("")
    schreib("  Bedingungen: %s" % url)

schreib("")
schreib("")
schreib("Zur MITRE-Anzeigepflicht — entschieden")
schreib("--------------------------------------")
schreib("")
schreib("Beide Lizenztexte binden die Weitergabe wortgleich an 'reproduce ... in")
schreib("any such copy'. Keiner von beiden verlangt eine Nennung gegenueber dem")
schreib("Endnutzer oder in der Trefferausgabe. Diese Datei reist mit dem Bestand")
schreib("und ist damit die Kopie, in der die Vermerke stehen.")
schreib("")
schreib("Daraus folgt: eine Beilage genuegt. Ein Autorenfeld im Befundschema")
schreib("(Issue #13) ist fuer diese Quelle keine Voraussetzung. Waere es eine,")
schreib("stuende hier der Grund; die Frage war vor der ersten Auslieferung offen")
schreib("und ist am %s aus dem Wortlaut des Feeds beantwortet worden." % datum)

with open(ziel, "w", encoding="utf-8") as fh:
    fh.write("\n".join(zeilen).rstrip() + "\n")

print("  LICENSE erzeugt — %s" % ", ".join(
    "%s (%d Saetze)" % (n, parteien[n]["n"]) for n in sorted(parteien)))
PY
}

# ── Abdeckung auszaehlen (#8) ────────────────────────────────
#
# "Wie viele Datensaetze, wie viele verschiedene Slugs?" — ohne diese Zahl
# laesst sich nicht beurteilen, ob die Abhaengigkeit von einer einzigen Quelle
# tragbar ist. Sie gehoert deshalb nicht in eine einmalige Auswertung, sondern
# bei jedem Bestandsaufbau neu erhoben und in VERSION geschrieben.
abdeckung_zaehlen() {
    local f typ zeilen slugs
    for f in "${DATEN}"/vuln/*.tsv; do
        [[ -r "$f" ]] || continue
        typ="$(basename "$f")"
        # Ohne '|| echo 0', siehe stand_schreiben.
        zeilen=$(grep -cv '^#' "$f" 2>/dev/null)
        slugs=$(grep -v '^#' "$f" 2>/dev/null | cut -f1 | LC_ALL=C sort -u | grep -c .)
        printf '%-33s %6s Zeile(n), %5s verschiedene Slugs\n' "$typ" "$zeilen" "$slugs"
    done
}

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
            # KEIN '|| echo 0': grep -c gibt bei null Treffern bereits eine 0
            # aus UND endet ungleich 0. Der Rueckfall haengte damit eine
            # zweite Null an, und in VERSION stand "0\n0 Zeile(n)". Derselbe
            # Fehler steckte in nf_fetch und in rezept_kern.
            printf '%-28s %6s Zeile(n)\n' "$(basename "$f")" \
                   "$(grep -vc '^#' "$f" 2>/dev/null)"
        done
        # Abdeckung je Tabelle (#8). Zeilen allein sagen wenig — eine Quelle mit
        # 40.000 Eintraegen auf 300 Slugs deckt etwas anderes ab als eine mit
        # 40.000 auf 12.000. Ohne die zweite Zahl laesst sich nicht beurteilen,
        # ob die Abhaengigkeit von einer einzigen Quelle tragbar ist.
        if ls "${DATEN}"/vuln/*.tsv >/dev/null 2>&1; then
            printf '\nAbdeckung\n'
            abdeckung_zaehlen
        fi
    } > "${DATEN}/VERSION"

    # LICENSE und NOTICE gehoeren mit in die Pruefsummen: sie sind der Teil der
    # Lieferung, der die Weitergabe deckt. Ein Manifest, das die Daten sichert
    # und den Lizenztext auslaesst, sichert die Lieferung nur halb.
    ( cd "$DATEN" && find . -type f \
          \( -name '*.tsv' -o -name VERSION -o -name LICENSE -o -name NOTICE \) \
        | LC_ALL=C sort \
        | while read -r f; do
            if command -v sha256sum >/dev/null 2>&1; then sha256sum "$f";
            else shasum -a 256 "$f"; fi
          done ) > "${DATEN}/MANIFEST.sha256"
    meldung "VERSION und MANIFEST.sha256 geschrieben"
}

AKTION="${1:-}"
case "$AKTION" in
    # REIHENFOLGE: erst holen, dann Lizenz aus dem Abzug schreiben, dann das
    # Gate, erst danach normalisieren. Der Lizenztext steckt im Feed — er kann
    # nicht vor dem Abruf vorliegen. Geschuetzt bleibt trotzdem, was zu
    # schuetzen war: wordfence_normalisieren ist der einzige Schritt, der einen
    # Bestand ins Repository schreibt, und er laeuft erst nach dem Gate.
    --wordfence)
        echo "== Wordfence Intelligence =="
        ROH=$(mktemp); trap 'rm -f "$ROH"' EXIT
        wordfence_holen "$ROH"    || exit 1
        lizenz_schreiben "$ROH"   || exit 2
        lizenz_gate               || exit 2
        wordfence_normalisieren "$ROH" && kev_verknuepfen
        stand_schreiben
        ;;
    --aus-datei)
        [[ -n "${2:-}" && -f "${2:-}" ]] || { fehler "Datei angeben"; exit 2; }
        echo "== Wordfence Intelligence (aus Datei ${2}) =="
        lizenz_schreiben "$2"     || exit 2
        lizenz_gate               || exit 2
        wordfence_normalisieren "$2" && kev_verknuepfen
        stand_schreiben
        ;;
    --kev)
        kev_aktualisieren && kev_verknuepfen
        stand_schreiben
        ;;
    --composer)
        # GHSA/OSV fuer Composer-Abhaengigkeiten (#14).
        #
        # WARUM HIER NICHT SELBST GEHOLT WIRD: das Bulk-Repository der GitHub
        # Advisory Database ist rund 3,5 GB und enthaelt jedes Oekosystem. Es
        # auf einer Entwicklungsmaschine zu spiegeln waere Verschwendung, und
        # es je Lauf zu klonen erst recht. Das Vorfiltern gehoert in die CI:
        # ein flacher Klon, die Packagist-Advisories heraus, den Rest weg.
        #
        # Diese Stufe uebernimmt deshalb einen bereits vorgefilterten Bestand
        # aus einem Verzeichnis. Das ist ehrlicher als ein Abruf, der auf jeder
        # Maschine anders lange dauert und gelegentlich scheitert.
        #
        # LIZENZ: CC-BY 4.0 — die beste Lage aller geprueften Quellen. Kein
        # Schluessel, keine Auflagen je Kopie, kein widerrufbares Bezugsrecht.
        # Die Attribution wird durch den Verweis je Datensatz erfuellt; der
        # Vergleicher traegt ihn aus dem Feld `id` in die Spalte `quelle`.
        QUELLE="${2:-}"
        [[ -n "$QUELLE" && -d "$QUELLE" ]] || {
            fehler "Verzeichnis mit vorgefilterten OSV-Advisories angeben"
            echo "  Vorfiltern (in der CI, nicht hier):" >&2
            echo "    git clone --depth 1 https://github.com/github/advisory-database" >&2
            echo "    find advisory-database/advisories/github-reviewed -name '*.json' \\" >&2
            echo "      | xargs grep -l '"ecosystem": *"Packagist"' > packagist.liste" >&2
            exit 2
        }
        echo "== GHSA/OSV (Packagist) aus ${QUELLE} =="
        ZIEL_C="${DATEN}/vuln/composer"
        mkdir -p "$ZIEL_C"
        # Nur Advisories mit Packagist-Bezug. Der Vergleicher wuerde fremde
        # Oekosysteme zwar ignorieren, aber ein Bestand, der zu 95 % aus
        # Unbenutzbarem besteht, kostet bei jedem Lauf Lesezeit.
        _n=0
        while IFS= read -r _f; do
            grep -q '"ecosystem": *"Packagist"' "$_f" 2>/dev/null || continue
            cp "$_f" "${ZIEL_C}/$(basename "$_f")" && _n=$((_n+1))
        done < <(find "$QUELLE" -name '*.json' -type f 2>/dev/null)
        meldung "${_n} Packagist-Advisory(s) uebernommen"
        [[ "$_n" -eq 0 ]] && fehler "Kein einziges — zeigt das Verzeichnis wirklich auf die Advisories?"
        stand_schreiben
        ;;
    --alles)
        lizenz_gate || exit 2
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
