# shellcheck shell=bash
# ============================================================
# NT-Forensik — Ausgabe- und Beleg-Funktionen
# ------------------------------------------------------------
# Die Primitiven, auf denen jeder Pruefabschnitt aufsetzt: Ueberschriften,
# Befundzeilen mit Schweregrad, Codebloecke, Beweissicherung, Maskierung fuer
# Kundenberichte und der protokollierte Netzabruf.
# 
# Der zweite Parameter 'web' bei warn/crit ist tragend: nur so markierte
# Befunde erscheinen im Kundenbericht.
# ============================================================

# ── Hilfsfunktionen ──────────────────────────────────────────
h1()  { echo -e "\n${BOLD}${BLU}══════════════════════════════════════════${NC}"; \
        echo -e "${BOLD}${BLU}  $1${NC}"; \
        echo -e "${BOLD}${BLU}══════════════════════════════════════════${NC}"; \
        echo -e "\n## $1\n" >> "$REPORT_FILE"; }

h2()  { echo -e "\n${CYN}▶ $1${NC}"; echo -e "\n### $1\n" >> "$REPORT_FILE"; }

ok()  { echo -e "  ${GRN}✓${NC} $1"; echo "- ✅ $1" >> "$REPORT_FILE"; N_OK=$((N_OK+1)); }
# $2="web" markiert einen WEBSITE-Befund (gehört in den Kundenbericht). Ohne $2
# ist es ein Server-/Root-/Infrastruktur-Befund — der bleibt Technik-/Betreiber-
# Sache und taucht NICHT im Kundenbericht auf (v3.8 Scope-Trennung).
warn(){ echo -e "  ${YLW}⚠${NC}  $1"; echo "- ⚠️  **$1**" >> "$REPORT_FILE"; \
        N_WARN=$((N_WARN+1)); WARN_LIST+="- $1"$'\n'; \
        [[ "${2:-}" == web ]] && CUST_WARN_LIST+="- $1"$'\n'; return 0; }
crit(){ echo -e "  ${RED}✗${NC}  ${BOLD}$1${NC}"; echo "- 🔴 **KRITISCH: $1**" >> "$REPORT_FILE"; \
        N_CRIT=$((N_CRIT+1)); CRIT_LIST+="- $1"$'\n'; \
        [[ "${2:-}" == web ]] && CUST_CRIT_LIST+="- $1"$'\n'; return 0; }
info(){ echo -e "  ${NC}·  $1"; echo "  $1" >> "$REPORT_FILE"; }
code(){ echo -e "\n\`\`\`\n$1\n\`\`\`\n" >> "$REPORT_FILE"; }

# ── Vierter Zustand: die Pruefung hat keine Aussage geliefert ─
#
# Bis v3.10 gab es drei Zustaende. Eine gescheiterte Messung fiel dabei
# regelmaessig auf ok() zurueck: 'wp core verify-checksums' scheitert, die
# Ausgabe ist leer, leer heisst "nichts gefunden", und der Bericht bescheinigt
# einen unveraenderten Kern, der nie geprueft wurde. Dasselbe Muster bei
# 'occ integrity:check-core', 'aide --check', 'last' und dem Imunify-Parser.
#
# Ein Lauf, in dem JEDE Messung scheitert, endete damit auf 🟢 UNAUFFAELLIG mit
# dem Satz "keine Hinweise auf eine Kompromittierung gefunden". Fuer ein
# Forensikwerkzeug ist das der teuerste denkbare Fehler — er wird als
# Entwarnung ausgeliefert.
#
# unklar() sagt, was ok() nicht sagen kann: hier steht kein Ergebnis. Der
# Zaehler ist getrennt, weil ein solcher Befund weder eine bestandene Pruefung
# (ok) noch eine Auffaelligkeit (warn) ist. Er blockiert die gruene Ampel —
# siehe module/14_berichte.sh.
unklar(){ echo -e "  ${CYN}⚪${NC} $1"; echo "- ⚪ **Nicht messbar: $1**" >> "$REPORT_FILE"; \
        N_UNKNOWN=$((N_UNKNOWN+1)); UNKNOWN_LIST+="- $1"$'\n'; \
        [[ "${2:-}" == web ]] && CUST_UNKNOWN_LIST+="- $1"$'\n'; return 0; }

# Existenzpruefung fuer externe Werkzeuge. Bewusst eine eigene Funktion und
# nicht ueberall 'command -v' inline: so ist an der Aufrufstelle sichtbar, dass
# ein fehlendes Werkzeug ein eigener Zustand ist und kein Nullergebnis.
werkzeug_da(){ command -v "$1" >/dev/null 2>&1; }

# ── Maskierung für Kundenberichte (v3.5) ─────────────────────
# Kundenberichte gehen an Dritte und müssen DSGVO-datensparsam sein: fremde
# E-Mail-Adressen (etwa WP-Admin-Konten) werden pseudonymisiert. Angreifer-IPs
# bleiben im Klartext — sie sind für den Betroffenen zum Sperren nötig und
# fallen unter berechtigtes Interesse. Technik-/BSI-/DSGVO-Berichte (interne
# bzw. Behördendokumente) bleiben unmaskiert. stdin → stdout.
mask_email(){ sed -E 's/([A-Za-z0-9])[A-Za-z0-9._%+-]*(@[A-Za-z0-9.-]+\.[A-Za-z]{2,})/\1***\2/g'; }

# Beleg sichern: schreibt Rohdaten nummeriert nach belege/
# evidence "label" "inhalt"  → belege/NN_label.txt
# Steckbrief einer belasteten Datei: woran sie erkannt wurde, wie sie aussieht,
# und die Fundstelle im Klartext.
#
# Ein Befund ohne Fundstelle laesst Fehlalarm und Treffer nicht unterscheiden.
# Am 06.08.2026 meldete ein Lauf drei "boesartige Plugins" — der Beleg enthielt
# ausschliesslich Dateipfade. Zwei davon gehoerten zur legitimen elFinder-
# Bibliothek eines echten Plugins, und niemand konnte das am Beleg erkennen;
# die Bewertung blieb offen, bis jemand die Dateien selbst aufmachte. Genau
# diese Arbeit soll der Beleg abnehmen.
datei_steckbrief() {   # datei_steckbrief <kriterium> <regex> <datei>
  local krit="$1" re="$2" f="$3" mtime=""
  mtime=$(stat -c '%y' "$f" 2>/dev/null || stat -f '%Sm' "$f" 2>/dev/null || echo "unbekannt")
  printf '── %s\n' "$f"
  printf '   Kriterium : %s\n' "$krit"
  printf '   Groesse   : %s Bytes\n' "$(wc -c < "$f" 2>/dev/null | tr -d ' ')"
  printf '   Geaendert : %s\n' "${mtime%%.*}"
  printf '   SHA256    : %s\n' "$(sha256sum "$f" 2>/dev/null | awk '{print $1}')"
  printf '   Fundstelle (Zeile: Treffer im Kontext):\n'
  local treffer
  treffer=$(grep -nEio ".{0,60}(${re}).{0,60}" "$f" 2>/dev/null | head -5)
  if [[ -n "$treffer" ]]; then
    printf '%s\n' "$treffer" | sed 's/^/     /'
  else
    printf '     (Treffer nicht reproduzierbar — Datei seit dem Scan veraendert?)\n'
  fi
  printf '\n'
}

evidence() {
  EVIDENCE_IDX=$((EVIDENCE_IDX+1))
  local num; num=$(printf "%02d" "$EVIDENCE_IDX")
  local file="${BELEGE_DIR}/${num}_$1.txt"
  {
    echo "# Beleg ${num} — $1"
    echo "# Erhoben: $(date -u +"%Y-%m-%dT%H:%M:%SZ") (UTC) / $(date)"
    echo "# Host: $(hostname -f 2>/dev/null || hostname)"
    echo "# Tool: wp_plesk_forensik.sh v${TOOL_VERSION}"
    echo "# ------------------------------------------------------------"
    echo "$2"
  } > "$file"
  echo "  Beleg: belege/${num}_$1.txt" >> "$REPORT_FILE"
}

# ── Netzabruf mit Protokoll (v3.8, nur mit --online) ─────────
# NT-Forensik behauptet an mehreren Stellen, read-only und rein lokal zu
# arbeiten. Sobald --online gesetzt ist, stimmt der zweite Teil nicht mehr —
# und das muss belegbar im Bericht stehen, nicht nur im Kopf des Prüfers.
# Jeder Abruf wird mit URL, HTTP-Code, Größe und SHA256 protokolliert.
#
# -L ist zwingend: Release-Downloads antworten mit 302 auf einen
# Auslieferungsdienst. Ohne Folgen der Weiterleitung landet nur die
# 302-Antwort in der Zieldatei und der Abruf scheitert stumm.
# Das Zeitlimit muss ein vollständiges Programmpaket zulassen (rund 30 MB).
# nf_fetch <url> <zieldatei>  → 0 bei HTTP 200
nf_fetch() {
  local url="$1" dest="$2" code sz sum
  code=$(curl -fsSL --max-time 300 --retry 1 -o "$dest" -w '%{http_code}' "$url" 2>/dev/null || echo "000")
  sz=$(stat -c%s "$dest" 2>/dev/null || echo 0)
  sum=$(sha256sum "$dest" 2>/dev/null | awk '{print $1}')
  ONLINE_FETCHES+="$(date -u +"%Y-%m-%dT%H:%M:%SZ")  ${url}  HTTP=${code}  ${sz}B  SHA256=${sum:-–}"$'\n'
  [[ "$code" == "200" ]]
}

# Sichere grep-Zählung (kein set -e Abbruch, immer eine Zahl)
count_grep() {
  local n
  n=$(grep -cE "$1" "$2" 2>/dev/null) || true
  echo "${n:-0}"
}
count_grep_i() {
  local n
  n=$(grep -icE "$1" "$2" 2>/dev/null) || true
  echo "${n:-0}"
}

# ── Modul-Metadaten und Auswahl ──────────────────────────────
# Jedes Modul beschreibt sich im eigenen Kopf (@nummer/@titel/@frage/
# @kosten/@ebene). Es gibt bewusst keine zentrale Liste — die würde
# auseinanderlaufen, sobald jemand ein Modul hinzufügt oder umbenennt.
modul_feld() {   # modul_feld <datei> <feldname>
  sed -n "s/^# @${2}:[[:space:]]*//p" "$1" 2>/dev/null | head -1
}

# Gehört dieser Abschnitt in den Lauf?
#   modul_gewaehlt <nummer> <ebene>
# --nur gewinnt gegen --ohne. Abschnitt 14 (Berichte) läuft immer mit,
# ausser er wird ausdrücklich per --ohne 14 abgewählt: ein Lauf ohne
# Bericht und ohne findings.json ist praktisch nie gewollt.
modul_gewaehlt() {
  local nr="$1" ebene="${2:-}"
  case ",${MODUL_OHNE}," in *",${nr},"*) return 1 ;; esac
  if [[ -n "$MODUL_NUR" ]]; then
    [[ "$nr" == "14" ]] && return 0
    case "$MODUL_NUR" in
      ebene:*) [[ "$ebene" == "${MODUL_NUR#ebene:}" ]] && return 0 || return 1 ;;
    esac
    case ",${MODUL_NUR}," in *",${nr},"*) return 0 ;; *) return 1 ;; esac
  fi
  return 0
}

# ── Fremdkunden aus dem Bericht halten ──────────────────────────────────────
# Ein Bericht ueber EINEN Kunden darf keine Daten anderer Kunden enthalten.
# Auf einem Shared-Host mit 482 vhosts standen in einem Lauf ueber ein einzelnes
# Abo 112 fremde Kennungen: Domainnamen, Systembenutzer, deren Cronjobs und
# SSH-Schluessel. Das ist nicht nur unsauber, es ist eine Weitergabe
# personenbezogener Daten an einen Dritten.
#
# Geloescht wird nicht, sondern pseudonymisiert: aus jeder fremden Kennung wird
# stabil derselbe Platzhalter. Damit bleibt erkennbar, dass zwei Zeilen denselben
# Nachbarn betreffen — was fuer die Bewertung eines serverweiten Musters noetig
# ist —, ohne dass jemand erfaehrt, WER dieser Nachbar ist.
#
# Die serverweiten Abschnitte behalten damit ihren Sinn: "27 shell-faehige
# Benutzer" bleibt eine belastbare Aussage ueber den Server, ohne 27 Kundennamen.
nf_fremdkunden_maskieren() {   # nf_fremdkunden_maskieren <datei>
  local datei="$1"
  [[ -r "$datei" ]] || return 0
  [[ "$SCOPE_MODE" == "global" ]] && return 0   # Betreiberbericht darf alles
  local eigene; eigene=$(printf '%s\n' "${SCAN_PATHS[@]:-}" | sed "s|.*/||" | grep -v '^$' | paste -sd'|' -)
  [[ -n "${ABO_USER:-}" ]] && eigene="${eigene}|${ABO_USER}"
  [[ -n "${DOMAIN:-}"   ]] && eigene="${eigene}|${DOMAIN}"
  eigene="${eigene#|}"; eigene="${eigene%|}"
  # Ohne Eigenliste waere ALLES fremd — auch die Domain des geprueften Kunden.
  # Ein Bericht, in dem der eigene Kunde als "<anderer Kunde 1>" steht, ist
  # wertlos, und der Fehler faellt erst beim Lesen auf. Lieber gar nicht
  # maskieren als falsch: dann bleibt der Bericht wenigstens erkennbar roh.
  if [[ -z "$eigene" ]]; then
    echo "  Maskierung uebersprungen: kein eigener Bezug bestimmbar (SCAN_PATHS/DOMAIN leer)." >&2
    return 1
  fi
  EIGENE_RE="$eigene" python3 - "$datei" <<'PY'
import os, re, sys
p = sys.argv[1]
eigen = re.compile(r'^(' + os.environ.get("EIGENE_RE", "___nichts___") + r')$')
txt = open(p, encoding="utf-8", errors="replace").read()
zuordnung, zaehler = {}, [0]
def platzhalter(name):
    if name not in zuordnung:
        zaehler[0] += 1
        zuordnung[name] = "<anderer Kunde %d>" % zaehler[0]
    return zuordnung[name]
def ersetze_vhost(m):
    name = m.group(1)
    return m.group(0) if eigen.match(name) else "/var/www/vhosts/" + platzhalter(name)
txt = re.sub(r'/var/www/vhosts/([^/\s"\'\)\],]+)', ersetze_vhost, txt)
def ersetze_user(m):
    name = m.group(0)
    return name if eigen.match(name) else platzhalter(name)
# Plesk leitet auch Mail- und FTP-Konten vom Systembenutzer ab: an die
# Abo-Kennung haengt ein Suffix (webNN -> webNNpN). Ein Wortende nach der
# Ziffer laesst diese Konten stehen — auf einem echten Server blieb so eine
# Mailadresse der Form "webNNpN@..." im maskierten Beleg zurueck.
txt = re.sub(r'\bweb\d+[a-z0-9_]*', ersetze_user, txt)

# Fremde Kunden stehen nicht nur als vhost-Pfad im Bericht, sondern auch als
# blanke Domain und als Mailadresse — in einem Beleg waren es 226 Domainnamen
# ohne jeden Pfad davor. Eine Maskierung, die nur Pfade kennt, laesst die
# Kundenliste des Servers unveraendert stehen.
#
# Umgekehrte Logik: alles was wie eine Domain aussieht wird maskiert, AUSSER
# den eigenen und einer Liste technischer Domains. Eine Positivliste ist hier
# richtig — bei einer Negativliste faellt jeder neue Kunde durchs Raster, und
# das faellt niemandem auf.
TECHNISCH = re.compile(r'\.(?:arpa|local|localdomain|invalid|test|example)$|^(?:'
    r'wordpress\.(?:org|com)|w\.org|php\.net|debian\.org|ubuntu\.com|canonical\.com|'
    r'plesk\.com|cloudlinux\.com|imunify360\.com|imunify\.com|letsencrypt\.org|'
    r'googleapis\.com|google\.com|gstatic\.com|github\.com|githubusercontent\.com|'
    r'schema\.org|gravatar\.com|jquery\.com|unpkg\.com|jsdelivr\.net|'
    r'mysql\.com|oracle\.com|apache\.org|nginx\.org|openssl\.org|python\.org|'
    r'kernel\.org|systemd\.io|freedesktop\.org|npmjs\.com|packagist\.org'
    r')$', re.I)

def _domain_frei(d):
    dl = d.lower()
    return bool(eigen.match(dl)) or bool(TECHNISCH.search(dl)) or dl.endswith(tuple(
        '.' + e for e in (os.environ.get("EIGENE_RE","").split('|')) if e))

def ersetze_mail(m):
    lokal, dom = m.group(1), m.group(2)
    if _domain_frei(dom):
        return m.group(0)
    return platzhalter(dom.lower()).replace("Kunde", "Adresse")
txt = re.sub(r'\b([A-Za-z0-9._%+-]+)@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b', ersetze_mail, txt)

def ersetze_domain(m):
    d = m.group(0)
    return d if _domain_frei(d) else platzhalter(d.lower())
txt = re.sub(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+'
             r'(?:de|com|net|org|eu|info|shop|online|io|dev|at|ch|nl|fr|it|es|uk|live|xyz|top|site|club)\b',
             ersetze_domain, txt)
if zuordnung:
    txt += ("\n\n---\n\n> **Hinweis zum Datenschutz.** Dieser Server beherbergt weitere Kunden. "
            "Wo serverweite Prüfungen deren Domains oder Systemkonten berührten, stehen "
            "Platzhalter (`<anderer Kunde N>`); derselbe Nachbar trägt dabei immer dieselbe "
            "Nummer, sodass Zusammenhänge erkennbar bleiben. Betroffen waren %d fremde "
            "Kennungen. Die unmaskierte Fassung verbleibt beim Betreiber.\n" % len(zuordnung))
open(p, "w", encoding="utf-8").write(txt)
print("  %d fremde Kennungen maskiert" % len(zuordnung))
PY
}