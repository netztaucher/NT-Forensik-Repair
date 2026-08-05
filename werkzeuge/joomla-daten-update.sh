#!/usr/bin/env bash
# ============================================================
# NT-Forensik — Joomla-Datenbestand aktualisieren
# ------------------------------------------------------------
# Läuft auf der Entwicklungsmaschine oder in der CI, NIEMALS auf einem
# Kundenserver. Deshalb liegt das Skript unter werkzeuge/ und wird von der
# Selbst-Installation bewusst nicht mit ausgeliefert.
#
# Schreibt ausschließlich nach daten/joomla/.
#
#   joomla-daten-update.sh --vel        Liste verwundbarer Erweiterungen
#   joomla-daten-update.sh --cve        Kern-Schwachstellen aus dem Sicherheitszentrum
#   joomla-daten-update.sh --coresums [Version ...]   Kern-Prüfsummen
#   joomla-daten-update.sh --alles
#
# Lizenz: der Feed steht unter GNU/GPL und erlaubt ausdrücklich die Nutzung
# in kommerziellen Erweiterungen. Übernommen werden nur Tatsachen (Name,
# Version, Status, CVE-Nummer, Verweis) — KEIN Beschreibungstext, damit im
# MIT-lizenzierten Repository kein fremder Fließtext landet. Siehe QUELLEN.md.
# ============================================================
set -u

HIER="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATEN="${HIER}/../daten/joomla"
VEL_URL="https://extensions.joomla.org/index.php?option=com_vel&format=json"
VEL_VERIFY_URL="${VEL_URL}&task=verify"
JSST_RSS="https://developer.joomla.org/security-centre.feed?type=rss"
JSST_ARCHIV="https://developer.joomla.org/security-centre.html"

RELEASE_URL="https://github.com/joomla/joomla-cms/releases/download"
# Ausgelieferte Fassungen. Zwei je totem Zweig (3.10, 4.4 sind Endstände),
# die letzten drei je gepflegtem Zweig. Alles andere deckt --online ab, das
# das offizielle Paket der tatsächlich gefundenen Fassung nachlädt.
CORESUM_VERSIONEN="3.10.11 3.10.12 4.4.12 4.4.13 4.4.14 5.4.5 5.4.6 5.4.7 6.1.0 6.1.1 6.1.2"

mkdir -p "${DATEN}/vel" "${DATEN}/cve" "${DATEN}/coresums"

meldung() { printf '  %s\n' "$*"; }
fehler()  { printf 'FEHLER: %s\n' "$*" >&2; }

# ── Liste verwundbarer Erweiterungen ────────────────────────
vel_aktualisieren() {
  echo "== Liste verwundbarer Erweiterungen (VEL) =="

  # Erst die Prüfsumme des Feeds holen. Ist sie unverändert, sparen wir uns
  # den Vollabruf — der Feed ist rund 320 KB.
  local neu_hash alt_hash
  neu_hash=$(curl -fsS --max-time 30 "$VEL_VERIFY_URL" 2>/dev/null \
             | python3 -c 'import sys,json; print(json.load(sys.stdin).get("data",""))' 2>/dev/null || true)
  alt_hash=$(cat "${DATEN}/vel/VERIFY" 2>/dev/null || true)
  if [[ -n "$neu_hash" && "$neu_hash" == "$alt_hash" ]]; then
    meldung "unverändert (${neu_hash:0:16}…) — kein Vollabruf nötig"
    return 0
  fi

  local roh="${DATEN}/vel/.roh.json"
  if ! curl -fsS --max-time 60 -o "$roh" "$VEL_URL"; then
    fehler "Feed nicht abrufbar"; return 1
  fi

  python3 - "$roh" "${DATEN}/vel/vel.tsv" "${DATEN}/vel/alias.tsv" <<'PY'
import json, re, sys, pathlib

roh, ziel, alias_datei = sys.argv[1], sys.argv[2], sys.argv[3]
d = json.loads(pathlib.Path(roh).read_text())
data = d.get("data", {})
posten = data.get("items", [])

# Bereits gepflegte Aliase einlesen, damit sie nicht verloren gehen.
alias = {}
ap = pathlib.Path(alias_datei)
if ap.exists():
    for zeile in ap.read_text().splitlines():
        if not zeile.strip() or zeile.startswith("#"):
            continue
        teile = zeile.split("\t")
        if len(teile) >= 2:
            alias[teile[0].strip().lower()] = teile[1].strip()

zeilen, offen = [], []
for p in posten:
    inst = p.get("install_data") or ""
    if isinstance(inst, str) and inst.strip().startswith("{"):
        try:
            inst = json.loads(inst)
        except Exception:
            inst = {}
    if not isinstance(inst, dict):
        inst = {}

    name = (inst.get("name") or "").strip()
    typ = (inst.get("type") or "").strip()
    ordner = (inst.get("folder") or "").strip()
    patch = (p.get("patch_version") or "").strip()
    status = (p.get("statusText") or "").strip()
    cve = (p.get("cve_id") or "").strip()
    verweis = (p.get("link") or p.get("url") or "").strip()
    titel = re.sub(r"\s+", " ", (p.get("title") or "")).strip()

    # Elementname bestimmen. Nur exakte Treffer — bewusst KEINE unscharfe
    # Zuordnung: ein falsch zugeordneter Eintrag erzeugt flottenweit einen
    # falschen kritischen Befund. Lieber ein Eintrag weniger.
    element = ""
    if re.fullmatch(r"(com|mod|plg|pkg|tpl)_[a-z0-9_]+", name.lower()):
        element = name.lower()
    elif name.lower() in alias:
        element = alias[name.lower()]
    elif titel.split(",")[0].strip().lower() in alias:
        element = alias[titel.split(",")[0].strip().lower()]
    else:
        if name:
            offen.append(name)
        continue

    # Nur Tatsachen — kein Beschreibungstext aus dem Feed.
    zeilen.append("\t".join([element, typ, ordner, name, patch, status, cve, verweis]))

zeilen = sorted(set(zeilen))
with open(ziel, "w") as f:
    f.write("# element\ttype\tfolder\tname\tpatch_version\tstatus\tcve\turl\n")
    f.write("\n".join(zeilen) + "\n")

# Nicht zuzuordnende Klartext-Namen sichtbar als Aufgabe anhängen, statt sie
# stillschweigend zu verlieren.
neu = sorted({n for n in offen if n.lower() not in alias})
if neu:
    with open(alias_datei, "a") as f:
        f.write("\n# --- automatisch ergaenzt, bitte Elementnamen eintragen ---\n")
        for n in neu:
            f.write("# %s\t\n" % n)

print("  %d von %d Eintraegen zugeordnet" % (len(zeilen), len(posten)))
print("  %d Klartext-Namen ohne Alias (in alias.tsv als Aufgabe vermerkt)" % len(neu))
PY

  [[ -n "$neu_hash" ]] && printf '%s\n' "$neu_hash" > "${DATEN}/vel/VERIFY"
  rm -f "$roh"
}

# ── Kern-Prüfsummen ─────────────────────────────────────────
# Erzeugt aus den OFFIZIELLEN Joomla-Paketen, nicht aus einer fremden
# Prüfsummen-Sammlung: damit ist die Lizenzfrage eindeutig (Prüfsummen sind
# Tatsachen, das GPL-Paket selbst wird weder verteilt noch abgeleitet) und
# jeder kann den Bestand nachrechnen.
#
# Ein Manifest je ZWEIG statt je Fassung: gemessen sind 93 % der Dateien über
# die Patch-Releases eines Zweigs identisch. Drei Fassungen kombiniert kosten
# 860 KB statt 2408 KB einzeln.
#
# Format (tab-getrennt, gzip):
#   pfad  sha256  sha256_ohne_leerraum  fassungen
# "fassungen" ist "*", wenn die Datei in ALLEN Fassungen des Manifests mit
# genau diesem Hash vorliegt — das trifft auf die grosse Mehrheit zu. Sonst
# eine Komma-Liste. Daraus ergibt sich auch, welche Dateien es in einer
# Fassung ueberhaupt geben muss (fuer die Erkennung fehlender Dateien).
coresums_aktualisieren() {
  echo "== Kern-Prüfsummen =="
  local versionen="${*:-$CORESUM_VERSIONEN}"
  local arbeit; arbeit=$(mktemp -d)
  local v zweig
  # nach Zweig gruppieren
  local zweige=""
  for v in $versionen; do
    zweig=$(printf '%s' "$v" | cut -d. -f1,2)
    case " $zweige " in *" $zweig "*) ;; *) zweige="$zweige $zweig" ;; esac
  done

  for zweig in $zweige; do
    local zv=""
    for v in $versionen; do
      [[ "$(printf '%s' "$v" | cut -d. -f1,2)" == "$zweig" ]] && zv="$zv $v"
    done
    echo "  Zweig ${zweig}:${zv}"
    rm -rf "${arbeit:?}/b"; mkdir -p "${arbeit}/b"
    local geholt=""
    for v in $zv; do
      local url="${RELEASE_URL}/${v}/Joomla_${v}-Stable-Full_Package.tar.gz"
      if ! curl -fsSL --max-time 300 -o "${arbeit}/p.tgz" "$url"; then
        meldung "    ${v}: Paket nicht abrufbar — übersprungen"; continue
      fi
      mkdir -p "${arbeit}/b/${v}"
      if ! tar xzf "${arbeit}/p.tgz" -C "${arbeit}/b/${v}" 2>/dev/null; then
        meldung "    ${v}: Paket nicht entpackbar — übersprungen"
        rm -rf "${arbeit}/b/${v}"; continue
      fi
      rm -f "${arbeit}/p.tgz"
      geholt="$geholt $v"
    done
    [[ -n "$geholt" ]] || { meldung "    keine Fassung verfügbar"; continue; }

    JZWEIG="$zweig" JVERS="$geholt" JWURZEL="${arbeit}/b" JZIEL="${DATEN}/coresums/${zweig}.tsv.gz" \
      python3 <<'PY'
import os, re, gzip, hashlib

zweig  = os.environ["JZWEIG"]
vers   = os.environ["JVERS"].split()
wurzel = os.environ["JWURZEL"]
ziel   = os.environ["JZIEL"]

# Zweiter Hash ueber den auf einfache Leerzeichen normalisierten Inhalt.
# Faengt Zeilenende-Umstellungen (CRLF), Tabs und angehaengte Leerzeichen ab —
# der klassische Fehlalarm nach einer Uebertragung per FTP oder einer
# Bearbeitung unter Windows.
squash = re.compile(rb"[\n\r\t\v\f ]+")

# Nie im Manifest: das Installationsverzeichnis wird nach dem Aufsetzen
# geloescht, und was der Betreiber selbst pflegt, gehoert nicht in einen
# Integritaetsvergleich.
AUS = ("installation",)
AUS_DATEI = {"configuration.php", ".htaccess", "web.config", ".user.ini", "robots.txt"}

def manifest(pfad):
    m = {}
    for wz, verz, dateien in os.walk(pfad):
        verz[:] = [d for d in verz if os.path.relpath(os.path.join(wz, d), pfad) not in AUS]
        for d in dateien:
            vp = os.path.join(wz, d)
            rel = os.path.relpath(vp, pfad)
            if rel in AUS_DATEI:
                continue
            try:
                roh = open(vp, "rb").read()
            except OSError:
                continue
            m[rel] = (hashlib.sha256(roh).hexdigest(),
                      hashlib.sha256(squash.sub(b" ", roh)).hexdigest())
    return m

alle = {}
vorhanden = []
for v in vers:
    p = os.path.join(wurzel, v)
    if not os.path.isdir(p):
        continue
    vorhanden.append(v)
    for rel, hashes in manifest(p).items():
        alle.setdefault((rel, hashes), []).append(v)

zeilen = []
for (rel, (h, hs)), vs in alle.items():
    marke = "*" if len(vs) == len(vorhanden) else ",".join(sorted(vs))
    zeilen.append("\t".join([rel, h, hs, marke]))

kopf = [
    "# NT-Forensik — Kern-Pruefsummen Joomla, Zweig %s" % zweig,
    "# Fassungen: %s" % ",".join(vorhanden),
    "# Erzeugt aus den offiziellen Joomla-Paketen (Verfahren: werkzeuge/joomla-daten-update.sh)",
    "# Spalten: pfad\tsha256\tsha256_ohne_leerraum\tfassungen ('*' = alle oben genannten)",
]
inhalt = ("\n".join(kopf + sorted(zeilen)) + "\n").encode()
with gzip.open(ziel, "wb", 9) as f:
    f.write(inhalt)

gemeinsam = sum(1 for z in zeilen if z.endswith("\t*"))
print("    %d Fassung(en), %d Eintraege (%d gemeinsam), %.0f KB"
      % (len(vorhanden), len(zeilen), gemeinsam, os.path.getsize(ziel) / 1024))
PY
  done

  rm -rf "$arbeit"
  # Index: welcher Zweig deckt welche Fassungen ab
  {
    printf '# zweig\tfassungen\n'
    local f
    for f in "${DATEN}/coresums/"*.tsv.gz; do
      [[ -f "$f" ]] || continue
      printf '%s\t%s\n' "$(basename "$f" .tsv.gz)" \
        "$(gzip -dc "$f" | sed -n 's/^# Fassungen: //p' | head -1)"
    done
  } > "${DATEN}/coresums/index.tsv"
  meldung "Index: $(grep -vc '^#' "${DATEN}/coresums/index.tsv") Zweig(e)"
}

# ── Kern-Schwachstellen aus dem Sicherheitszentrum ──────────
cve_aktualisieren() {
  echo "== Kern-Schwachstellen (Joomla Security Strike Team) =="
  # Bewusst NICHT über die NVD: eine Abfrage nach der Joomla-CPE liefert
  # hunderte Treffer, darunter Komponenten-Lücken von 2006 und Mambo-Altlasten.
  # Nur die Herstellerquelle nennt belastbare Versionsbereiche.
  local tmp="${DATEN}/cve/.roh.xml"
  local seiten="${DATEN}/cve/.archiv"
  mkdir -p "$seiten"
  curl -fsS --max-time 45 -o "$tmp" "$JSST_RSS" || { fehler "RSS nicht abrufbar"; return 1; }
  # Archiv mitnehmen (25 Meldungen je Seite), damit auch ältere Zweige abgedeckt sind
  local i
  for i in $(seq 0 25 425); do
    curl -fsS --max-time 45 -o "${seiten}/s${i}.html" "${JSST_ARCHIV}?start=${i}" 2>/dev/null || true
  done

  python3 - "$tmp" "$seiten" "${DATEN}/cve/joomla-core.tsv" <<'PY'
import re, sys, pathlib, html

rss, archiv, ziel = sys.argv[1], sys.argv[2], sys.argv[3]
roh = pathlib.Path(rss).read_text(errors="replace")
for p in sorted(pathlib.Path(archiv).glob("*.html")):
    roh += p.read_text(errors="replace")
roh = html.unescape(roh)

# Die Angaben stehen als HTML-Liste: <li><strong>Versions: </strong>4.0.0-5.4.6
# Der Wert liegt also HINTER dem schliessenden Tag, nicht direkt hinter dem
# Doppelpunkt. Deshalb erst die Tags entfernen, dann die Felder lesen.
entferne_tags = lambda s: re.sub(r"<[^>]+>", " ", s)

eintraege = {}
# Auf die Meldungskennung teilen, nicht auf <item>: die Archivseiten sind
# reines HTML ohne <item>, und ein gemeinsamer Split wuerde sonst alle
# Archiv-Meldungen zu einem Block verkleben (dann bleibt je Seite nur eine
# einzige CVE uebrig). Die Kennung [JJJJMMTT] steht in beiden Formaten.
bloecke = re.split(r"(?=\[20\d{6}\])", roh)
for block in bloecke:
    txt = entferne_tags(block)
    cve = re.search(r"(CVE-20\d\d-\d{4,7})", txt)
    vers = re.search(r"Versions?\s*:\s*([0-9][0-9a-zA-Z.,\-\s]*?)(?:Exploit|Reported|CVE|$)", txt)
    if not cve or not vers:
        continue
    cid = cve.group(1)
    # Bekannter Tippfehler in einer Meldung: eine CVE-Nummer mit einer Ziffer
    # zu viel. Auf die tatsaechliche Nummer zurechtruecken.
    if cid == "CVE-2026-352212":
        cid = "CVE-2026-35222"
    schwere = re.search(r"Severity\s*:\s*(\w+)", txt)
    typ = re.search(r"Exploit type\s*:\s*([^:]{2,60}?)\s+Reported", txt)

    # "4.0.0-5.4.6, 6.0.0-6.1.1" -> mehrere Bereiche
    for teil in vers.group(1).split(","):
        m = re.match(r"^\s*(\d+\.\d+(?:\.\d+)?)\s*-\s*(\d+\.\d+(?:\.\d+)?)", teil)
        if not m:
            continue
        lo, hi = m.group(1), m.group(2)
        lo = lo if lo.count(".") == 2 else lo + ".0"
        hi = hi if hi.count(".") == 2 else hi + ".999"
        schluessel = (lo, hi, cid)
        if schluessel in eintraege:
            continue
        eintraege[schluessel] = "\t".join([
            lo, hi, cid,
            (schwere.group(1) if schwere else ""),
            re.sub(r"\s+", " ", typ.group(1)).strip() if typ else "",
        ])

zeilen = [eintraege[k] for k in sorted(eintraege)]
with open(ziel, "w") as f:
    f.write("# min_version\tmax_version\tcve\tschwere\ttyp\n")
    f.write("\n".join(zeilen) + "\n")
print("  %d Versionsbereiche aus %d Meldungen" % (len(zeilen), len({k[2] for k in eintraege})))
PY

  rm -rf "$tmp" "$seiten"
}

stand_schreiben() {
  {
    printf '%s | erzeugt von werkzeuge/joomla-daten-update.sh\n' "$(date -u +%F)"
    printf 'vel.tsv           %s Zeilen\n' "$(grep -vc '^#' "${DATEN}/vel/vel.tsv" 2>/dev/null || echo 0)"
    printf 'joomla-core.tsv   %s Zeilen\n' "$(grep -vc '^#' "${DATEN}/cve/joomla-core.tsv" 2>/dev/null || echo 0)"
    printf 'joomla-ext-kritisch.tsv %s Zeilen (handgepflegt)\n' "$(grep -vc '^#' "${DATEN}/cve/joomla-ext-kritisch.tsv" 2>/dev/null || echo 0)"
    printf 'coresums          %s Zweig(e): %s\n' \
      "$(grep -vc '^#' "${DATEN}/coresums/index.tsv" 2>/dev/null || echo 0)" \
      "$(grep -v '^#' "${DATEN}/coresums/index.tsv" 2>/dev/null | cut -f2 | tr '\n' ' ')"
  } > "${DATEN}/VERSION"
  echo "== Stand =="; sed 's/^/  /' "${DATEN}/VERSION"
}

case "${1:-}" in
  --vel)      vel_aktualisieren ;;
  --cve)      cve_aktualisieren ;;
  --coresums) shift; coresums_aktualisieren "$@" ;;
  --alles)    vel_aktualisieren; cve_aktualisieren; coresums_aktualisieren ;;
  *) echo "Verwendung: $0 --vel | --cve | --coresums [Fassung ...] | --alles" >&2; exit 2 ;;
esac
stand_schreiben
