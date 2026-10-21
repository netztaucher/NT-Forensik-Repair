# shellcheck shell=bash
# NT-Forensik — Abschnitt 13b: .htaccess
#
# @nummer:  13b
# @titel:   .htaccess sichern und einordnen
# @frage:   Was steht in den .htaccess-Dateien, wem gehört es, und wirkt es überhaupt?
# @kosten:  gering — Dateikopie und Textanalyse, wenige Sekunden
# @ebene:   website
#
# Die Nummer 13b ist kein Zufall: Abschnitt 14 schreibt die Berichte. Ein
# Pruefabschnitt mit hoeherer Nummer laeuft danach, und seine Befunde
# erscheinen zwar auf der Konsole, aber in keinem Dokument und in keiner
# Zaehlung. Im ersten Entwurf trug dieser Abschnitt die 16 und war damit
# wirkungslos, ohne dass es auffiel.
#
# Wird vom Runner eingebunden, nicht einzeln ausgefuehrt.
# Vorgabewerte der hier gefuellten Variablen: lib/befunde.sh
#
# ------------------------------------------------------------
# WARUM DIESER ABSCHNITT ZUERST SICHERT
#
# Eine befallene .htaccess wird spaeter ersetzt. Was dabei verlorengeht, sind
# nicht die Angreiferregeln — die sollen weg —, sondern die Regeln des
# Betreibers: Umleitungen, Sicherheitskopfzeilen, Zwischenspeicherung,
# Zugriffssperren. Gemessen auf einem Produktivsystem mit 412 .htaccess-Dateien:
# 501 Redirect- und 39 RedirectPermanent-Anweisungen. Wer die verliert, bricht
# Verlinkungen und Suchmaschinenplatzierungen.
#
# Die Sicherung laesst sich nicht nachholen. Deshalb steht sie vor allem
# anderen, und deshalb werden ALLE Dateien gesichert, nicht nur die
# auffaelligen: 343 KB fuer 412 Dateien: kostenlos. Eine gesunde Nachbardatei
# ist ausserdem der beste Vergleichsmassstab fuer eine kranke.
#
# ------------------------------------------------------------
# DIE VIER EIMER
#
#   kern    vom System erzeugt und identisch regenerierbar. In der Praxis
#           genau EIN Block: '# BEGIN WordPress'. Alles andere nicht.
#   eigen   vom Betreiber oder seinen Erweiterungen. MUSS eine Erneuerung
#           ueberleben.
#   fremd   vom Angreifer.
#   unklar  laesst sich nicht belegen. Kommt zur Handentscheidung, wird NICHT
#           automatisch einsortiert.
#
# Der Unterschied zwischen eigen und fremd ist die eigentliche Schwierigkeit —
# ein RewriteRule kann beides sein. Regel: nichts wird als eigen eingestuft,
# was nicht belegbar harmlos ist, und nichts als fremd, was auch legitim
# vorkommt. Beide Fehlerrichtungen sind teuer: ein uebersehener Angreifer
# bleibt drin, eine falsch als fremd eingestufte Regel wird geloescht.

# Belegstufe dieses Abschnitts (#1). Die .htaccess-Dateien liegen im Webbaum des geprueften Auftritts.
BELEG_STUFE=kunde

h1 "13b. .HTACCESS — SICHERUNG UND EINORDNUNG"

HTA_DIR="${BELEGE_DIR}/htaccess"
HTA_LISTE=$(find "${SCAN_PATHS[@]}" -name .htaccess -type f 2>/dev/null | nf_strip_self | sort || true)
# Der Nenner fuer die Fortschrittsanzeige. Beide Schleifen unten laufen ueber
# dieselbe Liste — auf einem Server mit 475 vhosts sind das ueber 12.000
# Dateien, und beide Durchlaeufe dauern zusammen laenger als der komplette
# Dateisystem-Scan. Ohne Zaehler sieht man Domainnamen vorbeiziehen und weiss
# nicht, ob 200 oder 11.000 abgearbeitet sind.
HTA_N=$(printf '%s\n' "$HTA_LISTE" | grep -c . 2>/dev/null); HTA_N="${HTA_N:-0}"

if [[ -z "$HTA_LISTE" ]]; then
  ok "Keine .htaccess-Datei im Prüfumfang"
else
HTA_ANZAHL=$(printf '%s\n' "$HTA_LISTE" | grep -c . || true)
mkdir -p "$HTA_DIR"

# ── 13b.1 Vollsicherung ───────────────────────────────────────
h2 "13b.1 Sicherung"
{
  echo "# NT-Forensik — Sicherung aller .htaccess-Dateien im Prüfumfang"
  echo "# Erstellt: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  echo "#"
  echo "# Spalten: SHA256 | Groesse | mtime | ctime | Eigentuemer | Rechte | Pfad"
  echo "# Die Kopien liegen als flachgeklopfter Pfad daneben."
  echo "#"
  echo "# mtime und ctime getrennt: wer eine Datei zurueckdatiert, faelscht die"
  echo "# mtime — die ctime bleibt stehen und verraet den Eingriff."
} > "${HTA_DIR}/00_index.txt"

_hta_gesichert=0
_hta_i=0
while IFS= read -r _h; do
  [[ -f "$_h" ]] || continue
  _hta_i=$((_hta_i+1))
  # Jede 200. Datei, nicht jede: der Schreibvorgang selbst soll die Sicherung
  # nicht ausbremsen.
  (( _hta_i % 200 == 0 )) && fortschritt_unterschritt "$_hta_i" "$HTA_N" "13b.1 .htaccess sichern"
  _flach=$(printf '%s' "${_h#"$VHOSTS_DIR"/}" | tr '/' '_')
  cp -p "$_h" "${HTA_DIR}/${_flach}" 2>/dev/null || continue
  printf '%s | %s | %s | %s | %s | %s | %s\n' \
    "$(sha256sum "$_h" 2>/dev/null | awk '{print $1}')" \
    "$(datei_meta "$_h" groesse)" \
    "$(datei_meta "$_h" mtime)" \
    "$(datei_meta "$_h" ctime)" \
    "$(datei_meta "$_h" eigner)" \
    "$(datei_meta "$_h" rechte)" \
    "${_h#"$VHOSTS_DIR"/}" >> "${HTA_DIR}/00_index.txt"
  _hta_gesichert=$((_hta_gesichert + 1))
done <<< "$HTA_LISTE"

if [[ "$_hta_gesichert" -eq "$HTA_ANZAHL" ]]; then
  ok "${_hta_gesichert} von ${HTA_ANZAHL} .htaccess-Dateien gesichert (belege/htaccess/)"
else
  # Eine nicht gesicherte Datei ist bei einer spaeteren Erneuerung unrettbar.
  # Das darf nicht als Nebensatz durchgehen.
  crit "Nur ${_hta_gesichert} von ${HTA_ANZAHL} .htaccess-Dateien gesichert — die übrigen wären bei einer Erneuerung unwiederbringlich" web
fi

# ── 13b.2 Einordnung ──────────────────────────────────────────
h2 "13b.2 Einordnung der Direktiven"

# Zu welchem System gehoert eine .htaccess? Ohne diese Angabe kann niemand
# entscheiden, welche Bloecke legitim sind — eine WordPress-.htaccess sieht
# anders aus als eine Nextcloud-.htaccess, und 'Order allow,deny' ist im einen
# Fall Alltag und im anderen nie legitim.
hta_system() {   # hta_system <verzeichnis>
  local d="$1"
  if   [[ -f "${d}/wp-config.php" || -f "${d}/wp-load.php" ]]; then echo "wordpress"
  elif [[ -f "${d}/configuration.php" ]] && grep -qE 'class[[:space:]]+JConfig' "${d}/configuration.php" 2>/dev/null; then echo "joomla"
  elif [[ -f "${d}/occ" && -f "${d}/version.php" ]]; then echo "nextcloud"
  elif [[ -f "${d}/typo3conf/LocalConfiguration.php" || -d "${d}/typo3" ]]; then echo "typo3"
  else echo "unbekannt"
  fi
}

HTA_BERICHT=""
_hta_j=0
while IFS= read -r _h; do
  [[ -f "$_h" ]] || continue
  _hta_j=$((_hta_j+1))
  (( _hta_j % 200 == 0 )) && fortschritt_unterschritt "$_hta_j" "$HTA_N" "13b.2 Direktiven einordnen"
  _hd="$(dirname "$_h")"
  _sys="$(hta_system "$_hd")"
  _kurz="${_h#"$VHOSTS_DIR"/}"

  # Die Einordnung selbst. Python, weil Blockgrenzen (# BEGIN … # END) und
  # Container (<IfModule> …) mit Zeilenweise-grep nicht sauber zu fassen sind.
  _urteil=$(NT_SYS="$_sys" python3 - "$_h" <<'PY' 2>/dev/null || true
import os, re, sys, json

sys_typ = os.environ.get("NT_SYS", "unbekannt")
zeilen = open(sys.argv[1], encoding="utf-8", errors="replace").read().split("\n")

# ── Regenerierbar ist genau ein Block ────────────────────────
# Gemessen auf einem Produktivsystem: '# BEGIN WordPress' in 100 von 412
# Dateien — daneben aber elf weitere Markerbloecke von Erweiterungen
# (YOAST REDIRECTS, LSCACHE, WP Rocket, EWWWIO, Really Simple Security).
# 'wp rewrite flush' schreibt NUR den WordPress-Block neu. Wer die ganze Datei
# ersetzt, wirft '# BEGIN YOAST REDIRECTS' mit den echten Kundenumleitungen
# weg. Erweiterungsbloecke gehoeren deshalb zu 'eigen', nicht zu 'kern'.
KERN_MARKER = {"WordPress"}

# ── Fremd: eng gefasst, mit Ausnahmen ────────────────────────
# Jede Regel hier wurde gegen 412 echte Dateien geprueft. Was dabei
# durchfiel, steht als Ausnahme daneben — sonst meldet das Werkzeug
# Schutzsoftware als Hintertuer.
SCHUTZ_PLUGINS = re.compile(
    r"wordfence-waf|ithemes-security|sucuri|ninjafirewall|wp-security|aiowps", re.I)
NICHT_PHP_ENDUNG = re.compile(r"\.(jpe?g|png|gif|ico|svg|webp|txt|css|js|woff2?|ttf|eot|pdf)\b", re.I)
DROPPER = re.compile(
    r"filefuns|adminfuns|cjfuns|classsmtps|chtmlfuns|comfunctions|postnews|"
    r"schallfuns|epinyins|siteheads|hplfuns|moddofuns", re.I)
SUCHMASCHINE = re.compile(r"googlebot|bingbot|yandex|slurp|duckduckbot", re.I)

def ist_fremd(z):
    zl = z.strip()
    if DROPPER.search(zl):
        return "Dateiname aus bekannter Schadcode-Kampagne"
    # AddType/AddHandler/SetHandler auf PHP fuer eine Nicht-PHP-Endung.
    # AddType allein ist untauglich als Merkmal: 173 Vorkommen im Bestand,
    # ausnahmslos MIME-Typen fuer Schriften, Video und SVG.
    if re.search(r"^(AddType|AddHandler|SetHandler)\b", zl, re.I) \
       and re.search(r"php|x-httpd", zl, re.I) and NICHT_PHP_ENDUNG.search(zl):
        return "PHP-Ausfuehrung fuer eine Nicht-PHP-Endung"
    # auto_prepend_file ist NICHT automatisch ein Angriff: Wordfence baut seine
    # Firewall genau so. Ohne diese Ausnahme meldet das Werkzeug die
    # Schutzsoftware als Hintertuer.
    if re.search(r"auto_(pre|ap)pend_file", zl, re.I) and not SCHUTZ_PLUGINS.search(zl):
        return "auto_prepend_file auf eine Datei im Webspace"
    # Die Suchmaschinen-Kennung steht hier NICHT mehr: eine RewriteCond sagt
    # allein nichts, erst ihre RewriteRule entscheidet — siehe ua_weiche()
    # weiter unten.
    if re.search(r"^ErrorDocument\b", zl, re.I) and re.search(r"upload.*\.php", zl, re.I):
        return "Fehlerseite auf ein PHP-Skript im Upload-Verzeichnis"
    if re.search(r"base64_decode|eval\s*\(|\\x[0-9a-f]{2}", zl, re.I):
        return "kodierte Zeichenkette in einer Direktive"
    # 'Order allow,deny' ist im Bestand 29-mal legitim (Apache-2.2-Syntax).
    # In einer Nextcloud dagegen erzeugt der Kern das nie.
    if sys_typ == "nextcloud" and re.search(r"^Order\s+allow,deny", zl, re.I):
        return "Apache-2.2-Zugriffssyntax in einer Nextcloud — dort nie vom Kern erzeugt"
    return None

# ── Suchmaschinen-Kennung: die Bedingung allein ist kein Urteil ─
# Bis 21.10.2026 galt jede RewriteCond auf %{HTTP_USER_AGENT} mit bingbot,
# yandex & Co. als Cloaking — Zeile fuer Zeile, ohne Blick auf die Regel. Im
# Anlassfall (#137, eine WordPress-.htaccess von 12/2020) war das eine
# klassische Bad-Bot-Sperrliste: ueber 100 'RewriteCond %{HTTP_USER_AGENT} …
# [OR]', darunter bingbot, YANDEX und YandexBot, und am Ende genau EINE
# 'RewriteRule ^.* - [F,L]'. Gemeldet wurden 3 Angreifer-Direktiven, crit.
#
# Cloaking heisst: die Suchmaschine bekommt etwas ANDERES — eine andere
# Datei, eine fremde Seite, eine Umleitung. Eine Regel mit Ziel '-' und
# [F]/[G] (oder R=403/410) liefert ihr gar nichts, sie sperrt aus. Das ist
# Abwehr, wenn auch gegen die falschen Gaeste.
#
# Apache haengt alle RewriteCond an die NAECHSTE RewriteRule. Genau so wird
# hier ausgewertet: jede Bedingung mit IHRER Regel, nicht mit der Datei.
#   sperre    Ziel '-', Abschluss [F]/[G]/R=403/410  -> eigen, mit Vermerk
#   weiche    Ziel PHP-Datei, absolute URL oder [P]   -> fremd (crit)
#   unklar    alles andere, auch keine Regel gefunden -> warn, Handentscheidung
# Eine VERNEINTE Bedingung ('!googlebot') vor einer Sperre ist ausdruecklich
# nicht entlastet: sie sperrt alle AUSSER der Suchmaschine aus, und das ist
# die Rueckseite derselben Weiche.
SPERR_FLAGGE = re.compile(r"^(f|forbidden|g|gone|r(edirect)?=(403|410))$", re.I)

def regel_zerlegen(z):
    m = re.match(r"^\s*RewriteRule\s+(\S+)\s+(\S+)(?:\s+\[([^\]]*)\])?", z, re.I)
    if not m:
        return None, []
    return m.group(2), [f.strip().lower() for f in (m.group(3) or "").split(",") if f.strip()]

def ua_weiche(bed, regel):
    """-> ("sperre"|"weiche"|"unklar", Begruendung)"""
    if regel is None:
        return "unklar", "Suchmaschinen-Kennung ohne nachfolgende RewriteRule"
    ziel, flaggen = regel_zerlegen(regel)
    if ziel is None:
        return "unklar", "Suchmaschinen-Kennung, RewriteRule nicht lesbar"
    kurz = regel.strip()[:60]
    if any(f in ("p", "proxy") for f in flaggen):
        return "weiche", "Weiche nach Suchmaschinen-Kennung (Cloaking) — Proxy [P]: " + kurz
    if re.match(r"^(https?:)?//", ziel, re.I):
        return "weiche", "Weiche nach Suchmaschinen-Kennung (Cloaking) — fremde URL: " + kurz
    if re.search(r"\.php\d?(\?|$)", ziel, re.I):
        return "weiche", "Weiche nach Suchmaschinen-Kennung (Cloaking) — PHP-Ziel: " + kurz
    sperre = ziel == "-" and any(SPERR_FLAGGE.match(f) for f in flaggen)
    verneint = bool(re.match(r"^\s*RewriteCond\s+\S+\s+!", bed, re.I))
    if sperre and not verneint:
        return "sperre", "Sperrliste (Zugriff verweigert): " + kurz
    if sperre:
        return "unklar", "verneinte Suchmaschinen-Kennung vor einer Sperre — alle ausser der Suchmaschine ausgesperrt"
    return "unklar", "Suchmaschinen-Kennung, Ziel weder Sperre noch eindeutig fremd: " + kurz

# Jede RewriteCond-Zeile -> die RewriteRule, an der sie haengt (Apache-Semantik).
regel_zu = {}
_offen = []
for _i, _roh in enumerate(zeilen):
    _z = _roh.strip()
    if re.match(r"^RewriteCond\b", _z, re.I):
        _offen.append(_i)
    elif re.match(r"^RewriteRule\b", _z, re.I):
        for _k in _offen:
            regel_zu[_k] = _roh
        _offen = []

# ── Eigen: Positivliste ──────────────────────────────────────
EIGEN = re.compile(
    r"^(Redirect|RedirectMatch|RedirectPermanent|RedirectTemp"
    r"|Header|RequestHeader|Expires\w*|AddOutputFilterByType|AddEncoding"
    r"|AddCharset|FileETag|AuthType|AuthName|AuthUserFile|AuthGroupFile"
    r"|Require|Options|IndexIgnore|DirectoryIndex|ErrorDocument"
    r"|SetEnv|SetEnvIf|SetEnvIfNoCase|BrowserMatch|php_value|php_flag"
    r"|AddType|AddHandler|LimitRequestBody|ServerSignature)\b", re.I)
# Zugriffssteuerung, beide Apache-Fassungen.
ZUGRIFF = re.compile(r"^(Order|Allow|Deny|Satisfy)\b", re.I)
# Struktur, traegt selbst keine Aussage.
STRUKTUR = re.compile(r"^(</?IfModule|</?Files|</?FilesMatch|</?Directory|</?Limit|"
                      r"RewriteEngine|RewriteBase|</?IfVersion)", re.I)

# ── Freigabelisten: sperren sieht aus wie schuetzen ──────────
# Eine Regel, die alles verbietet und danach GENAU EINE PHP-Datei freigibt,
# steuert keinen Zugriff — sie schaltet frei. Der Angreifer legt sie, damit
# seine Datei erreichbar bleibt, waehrend der Rest gesperrt wirkt.
# In einem Upload-, Cache- oder Temp-Verzeichnis hat KEINE PHP-Datei etwas
# verloren, dort ist jede Freigabe ein Befund. Anderswo sind wenige
# Einstiegspunkte legitim (Zugriffsschutz per IP auf wp-login.php).
KEIN_PHP_VERZEICHNIS = re.compile(r"/(uploads?|cache|tmp|temp|files|media|assets)(/|$)", re.I)
LEGITIME_EINSTIEGE = {"index.php", "wp-login.php", "admin-ajax.php", "xmlrpc.php",
                      "wp-cron.php", "remote.php", "status.php", "occ"}
pfad = sys.argv[1]
in_upload = bool(KEIN_PHP_VERZEICHNIS.search(os.path.dirname(pfad)))
# Sperrt die Datei ueberhaupt irgendwo? Ohne Sperre ist eine Freigabe
# wirkungslos und damit auch kein Hinweis.
roher_text = "\n".join(zeilen)
sperrt = bool(re.search(r"^\s*(Order\s+allow,deny|Deny\s+from\s+all|Require\s+all\s+denied)",
                        roher_text, re.I | re.M))

erg = {"kern": [], "eigen": [], "fremd": [], "unklar": [], "sperre": [], "weiche_unklar": []}
marker = None
behaelter = None   # aktuell offener <Files …> / <FilesMatch …>
for nr, roh in enumerate(zeilen):
    z = roh.strip()
    if not z:
        continue

    b = re.match(r"^<Files(?:Match)?\s+\"?([^\">]+)\"?\s*>", z, re.I)
    if b:
        behaelter = b.group(1).strip()
    elif re.match(r"^</Files(?:Match)?>", z, re.I):
        behaelter = None
    elif behaelter and re.match(r"^(Allow\s+from\s+all|Require\s+all\s+granted)", z, re.I):
        datei = behaelter.strip("\"'")
        if ".php" in datei.lower() and sperrt and \
           (in_upload or os.path.basename(datei) not in LEGITIME_EINSTIEGE):
            erg["fremd"].append({
                "zeile": "<Files %s> … %s" % (behaelter, z),
                "grund": ("Freigabe fuer eine PHP-Datei in einem Verzeichnis, in das keine gehoert"
                          if in_upload else
                          "Sperre fuer alles, Freigabe fuer genau diese eine PHP-Datei"),
                "block": marker})
            continue
    m = re.match(r"^#\s*BEGIN\s+(.+?)\s*$", z, re.I)
    if m:
        marker = m.group(1)
        continue
    if re.match(r"^#\s*END\b", z, re.I):
        marker = None
        continue
    if z.startswith("#"):
        continue

    grund = ist_fremd(z)
    if grund:
        erg["fremd"].append({"zeile": roh, "grund": grund, "block": marker})
        continue
    if re.search(r"^RewriteCond.*HTTP_USER_AGENT", z, re.I) and SUCHMASCHINE.search(z):
        art, grund = ua_weiche(z, regel_zu.get(nr))
        eintrag = {"zeile": roh, "grund": grund, "block": marker}
        if art == "weiche":
            erg["fremd"].append(eintrag)
        elif art == "sperre":
            # Gehoert dem Betreiber und muss eine Erneuerung ueberleben —
            # der Vermerk steht trotzdem im Beleg, damit niemand ihn fuer
            # eine uebersehene Weiche haelt.
            erg["eigen"].append(eintrag)
            erg["sperre"].append(eintrag)
        else:
            erg["unklar"].append({"zeile": roh, "block": marker})
            erg["weiche_unklar"].append(eintrag)
        continue
    if marker:
        # Innerhalb eines Markerblocks: nur der WordPress-Block ist
        # regenerierbar, alles andere gehoert der Erweiterung und damit
        # dem Betreiber.
        erg["kern" if marker in KERN_MARKER else "eigen"].append(
            {"zeile": roh, "block": marker})
        continue
    if STRUKTUR.match(z):
        continue
    if EIGEN.match(z) or ZUGRIFF.match(z):
        erg["eigen"].append({"zeile": roh, "block": None})
        continue
    # RewriteRule/RewriteCond ausserhalb eines Markerblocks: kann eine
    # Kundenumleitung sein oder eine Angreiferweiche. Nicht entscheidbar,
    # also auch nicht entschieden.
    erg["unklar"].append({"zeile": roh, "block": None})

print(json.dumps({"system": sys_typ,
                  "n_kern": len(erg["kern"]), "n_eigen": len(erg["eigen"]),
                  "n_fremd": len(erg["fremd"]), "n_unklar": len(erg["unklar"]),
                  "n_sperre": len(erg["sperre"]), "n_weiche_unklar": len(erg["weiche_unklar"]),
                  "sperre": erg["sperre"][:20], "weiche_unklar": erg["weiche_unklar"][:20],
                  "fremd": erg["fremd"][:20], "unklar": [u["zeile"] for u in erg["unklar"]][:20]},
                 ensure_ascii=False))
PY
)

  if [[ -z "$_urteil" ]]; then
    unklar "${_kurz}: Einordnung nicht möglich (python3 fehlt oder Datei unlesbar)" web
    continue
  fi

  _nf=$(printf '%s' "$_urteil" | python3 -c 'import json,sys;print(json.load(sys.stdin)["n_fremd"])' 2>/dev/null || echo 0)
  _nu=$(printf '%s' "$_urteil" | python3 -c 'import json,sys;print(json.load(sys.stdin)["n_unklar"])' 2>/dev/null || echo 0)
  _ne=$(printf '%s' "$_urteil" | python3 -c 'import json,sys;print(json.load(sys.stdin)["n_eigen"])' 2>/dev/null || echo 0)
  _ns=$(printf '%s' "$_urteil" | python3 -c 'import json,sys;print(json.load(sys.stdin)["n_sperre"])' 2>/dev/null || echo 0)
  _nw=$(printf '%s' "$_urteil" | python3 -c 'import json,sys;print(json.load(sys.stdin)["n_weiche_unklar"])' 2>/dev/null || echo 0)

  HTA_BERICHT+="${_kurz}"$'\t'"${_sys}"$'\t'"${_nf}"$'\t'"${_nu}"$'\t'"${_ne}"$'\n'

  if [[ "${_nf:-0}" -gt 0 ]]; then
    crit "${_kurz} (${_sys}): ${_nf} Angreifer-Direktive(n) in der .htaccess" web
    code "$(printf '%s' "$_urteil" | python3 -c '
import json,sys
d=json.load(sys.stdin)
for f in d["fremd"]:
    print("%-52s  %s" % (f["zeile"].strip()[:52], f["grund"]))' 2>/dev/null)"
    HTACCESS_FREMD+="${_h}"$'\n'
    evidence "htaccess_fremd_$(echo "$_kurz" | tr '/.' '__')" \
      "$(datei_steckbrief "Angreifer-Direktiven in .htaccess (System: ${_sys})" \
         'AddType|AddHandler|SetHandler|auto_prepend|auto_append|HTTP_USER_AGENT|ErrorDocument' "$_h")"
  elif [[ "${_nw:-0}" -gt 0 ]]; then
    # Eine Suchmaschinen-Kennung, deren Regel weder klar sperrt noch klar
    # umleitet (#137): nicht still unter "nicht zuordenbar" verschwinden
    # lassen — Cloaking ist der Zweck genau dieser Bedingung.
    warn "${_kurz} (${_sys}): ${_nw} Bedingung(en) auf Suchmaschinen-Kennung ohne eindeutiges Ziel — von Hand prüfen" web
    code "$(printf '%s' "$_urteil" | python3 -c '
import json,sys
d=json.load(sys.stdin)
for f in d["weiche_unklar"]:
    print("%-52s  %s" % (f["zeile"].strip()[:52], f["grund"]))' 2>/dev/null)"
  elif [[ "${_nu:-0}" -gt 0 ]]; then
    # Nicht als Befund melden: unentscheidbare Umleitungen sind der Normalfall.
    # Die Zahl gehoert trotzdem in den Bericht, damit bei einer spaeteren
    # Erneuerung niemand glaubt, die Datei liesse sich vollautomatisch ersetzen.
    info "${_kurz} (${_sys}): ${_ne} eigene, ${_nu} nicht zuordenbare Direktive(n) — Handentscheidung bei einer Erneuerung"
  else
    ok "${_kurz} (${_sys}): ${_ne} eigene Direktive(n), nichts Fremdes"
  fi
  # Bot-Sperrliste mit Suchmaschinen-Kennung (#137): kein Befund, aber ein
  # Vermerk im Beleg — wer bingbot in einer .htaccess findet, soll lesen, dass
  # es geprueft und als Sperre erkannt wurde.
  if [[ "${_ns:-0}" -gt 0 ]]; then
    info "${_kurz} (${_sys}): ${_ns} Suchmaschinen-Kennung(en) in einer Bot-Sperrliste — Sperrliste (Zugriff verweigert), kein Cloaking"
    code "$(printf '%s' "$_urteil" | python3 -c '
import json,sys
d=json.load(sys.stdin)
for f in d["sperre"]:
    print("%-52s  %s" % (f["zeile"].strip()[:52], f["grund"]))' 2>/dev/null)"
  fi
done <<< "$HTA_LISTE"

[[ -n "$HTA_BERICHT" ]] && evidence "htaccess_einordnung" \
  "Pfad	System	fremd	unklar	eigen
${HTA_BERICHT}"

# ── 13b.3 Wirkt die Datei überhaupt? ──────────────────────────
# Eine .htaccess, die der Webserver nicht liest, gibt falsche Sicherheit. Bei
# 'AllowOverride None' oder einem reinen nginx-Aufbau ist sie Dekoration — und
# ein Bericht, der "durch .htaccess geschuetzt" schreibt, waere dann falsch.
h2 "13b.3 Wirksamkeit"

# Welcher Webserver laeuft? Ueberschreibbar ausschliesslich fuer den Pruefstand
# ueber NT_WEBSERVER=apache|nginx|keiner — aus demselben Grund wie NT_BASE_DIR
# und NT_VHOSTS_DIR in lib/konfig.sh.
#
# Ohne die Ueberschreibung haengt dieser Abschnitt am Live-Zustand der
# Maschine, und die eingecheckte Pruefstand-Referenz waere je nach laufenden
# Diensten eine andere. Real eingetreten am 08.08.2026: die Referenz wurde
# aufgenommen, waehrend lokal nginx lief, und meldete danach auf jeder Maschine
# ohne nginx einen FEHLENDEN kritischen Befund. Ein fehlender kritischer Befund
# ist die teuerste Falschmeldung, die ein Pruefstand erzeugen kann — sie sieht
# aus wie eine Regression und ist keine.
webserver_lauft() {   # webserver_lauft apache|nginx
  case "${NT_WEBSERVER:-}" in
    apache) [[ "$1" == apache ]]; return ;;
    nginx)  [[ "$1" == nginx  ]]; return ;;
    keiner) return 1 ;;
  esac
  if [[ "$1" == apache ]]; then
    pgrep -x apache2 >/dev/null 2>&1 || pgrep -x httpd >/dev/null 2>&1
  else
    pgrep -x nginx >/dev/null 2>&1
  fi
}

if ! webserver_lauft apache; then
  if webserver_lauft nginx; then
    crit "Kein Apache-Prozess, aber nginx läuft — .htaccess-Dateien werden NICHT ausgewertet und schützen nichts" web
    HTACCESS_UNWIRKSAM="nginx ohne Apache"
  else
    unklar "Weder Apache noch nginx als Prozess gefunden — Wirksamkeit der .htaccess nicht feststellbar"
  fi
else
  _ao=$(grep -rhoiE 'AllowOverride[[:space:]]+[A-Za-z]+' /etc/apache2 /etc/httpd \
        "${VHOSTS_DIR}/system"/*/conf 2>/dev/null | awk '{print tolower($2)}' | sort -u | tr '\n' ' ' || true)
  if [[ -z "$_ao" ]]; then
    unklar "AllowOverride in der Apache-Konfiguration nicht auffindbar — Wirksamkeit der .htaccess nicht belegt"
  elif [[ "$_ao" == "none " ]]; then
    crit "Apache steht durchgängig auf 'AllowOverride None' — .htaccess-Dateien werden ignoriert und schützen nichts" web
    HTACCESS_UNWIRKSAM="AllowOverride None"
  else
    ok "Apache wertet .htaccess aus (AllowOverride: ${_ao% })"
  fi
fi
fi
