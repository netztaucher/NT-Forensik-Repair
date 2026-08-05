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
#   joomla-daten-update.sh --vel     Liste verwundbarer Erweiterungen
#   joomla-daten-update.sh --cve     Kern-Schwachstellen aus dem Sicherheitszentrum
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

mkdir -p "${DATEN}/vel" "${DATEN}/cve"

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
  } > "${DATEN}/VERSION"
  echo "== Stand =="; sed 's/^/  /' "${DATEN}/VERSION"
}

case "${1:-}" in
  --vel)   vel_aktualisieren ;;
  --cve)   cve_aktualisieren ;;
  --alles) vel_aktualisieren; cve_aktualisieren ;;
  *) echo "Verwendung: $0 --vel | --cve | --alles" >&2; exit 2 ;;
esac
stand_schreiben
