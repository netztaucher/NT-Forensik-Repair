#!/usr/bin/env bash
# ============================================================
# NT-Forensik — kundenpaket.sh
#
#   werkzeuge/kundenpaket.sh <lauf-ordner> [ziel] [--mit-server] [--mit-technik]
#                            [--mit-rohfassung]
#
# Test:     ja - werkzeuge/kundenpaket-pruefstand.sh · NT-Forensik-Repair#1, #149, #150
# Rueckweg: entfällt - schreibt nur einen neuen Ordner (kein Überschreiben), der Lauf bleibt unverändert
#
# ------------------------------------------------------------
# WOZU
#
# Das Zusammenstellen eines übergabefähigen Pakets war Handarbeit: Berichte
# einsortieren, Belege maskieren, den Betreiber-Changelog aussortieren, neu
# nummerieren, neu versiegeln, ein LIESMICH schreiben. Jeder dieser Schritte
# ist regelhaft — und jeder einzelne ist eine Gelegenheit, versehentlich etwas
# mitzugeben, das nicht mitgehört. Genau so ging `03_admin_changelog.txt`
# einmal mit: der Betreiber-Changelog mit SSL-Arbeiten am Server-Host.
#
# ------------------------------------------------------------
# WAS MITGEHT — UND WAS NICHT
#
# Grundlage ist die Einstufung aus `belege/00_verzeichnis.tsv` (#1):
#
#   kunde      geht mit, maskiert
#   server     geht NUR mit --mit-server mit, maskiert
#   betreiber  geht nie mit
#
# Immer draussen, ohne Schalter:
#   findings.json   Maschinendatei für die Bereinigung, keine Kundenunterlage
#   lauf.log        Protokoll des Werkzeugs
#   Log-Archiv      im Anlassfall 527 MB Zugriffe ALLER Domains des Servers
#   bsi_meldung.md  Meldeweg des Betreibers, nicht des Kunden
#   Markdown-Rohfassungen (kundenbericht.md, dsgvo_meldung.md, ...) — nur mit
#                   --mit-rohfassung. Kundendokumente sind seit dem Standard
#                   vom 21.10.2026 die PDFs im Designsystem NT Docs (#149).
#
# Vor dem Packen prüft werkzeuge/interna-waechter.sh die Kundendokumente gegen
# die Interna-Sperrliste (#150). Ein Treffer bricht ab — es entsteht kein Paket.
#
# Das Paket ist bewusst KLEINER als das, was der Betreiber hat. Wer mehr
# hineinlegen will, tut das bewusst über einen Schalter — nicht aus Versehen.
#
# ------------------------------------------------------------
# WARUM DAS SIEGEL EIN ANDERES IST
#
# Die Belege werden für das Paket maskiert und neu nummeriert. Damit ändert
# sich ihr Inhalt, und die SHA256-Summen des Laufs passen nicht mehr. Das ist
# kein Mangel, sondern der Zweck — aber es muss dabeistehen, sonst sieht es
# nach einem gebrochenen Siegel aus. Das Paket bekommt deshalb ein eigenes
# SHA256SUMS und ein LIESMICH, das den Unterschied benennt und auf das
# Originalsiegel beim Betreiber verweist.
# ============================================================
set -uo pipefail

RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[0;33m'; CYN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
# Eigene Namen, nicht ok/warn/info: dieses Werkzeug bindet lib/kern.sh ein, und
# die Bibliothek definiert genau diese drei selbst — sie schreiben in
# REPORT_FILE und zaehlen Befunde. Wer sie gleichnamig anlegt, verliert sie
# beim `source` stillschweigend an die Bibliothek und bekommt beim naechsten
# Aufruf "REPORT_FILE: unbound variable".
pok()   { echo -e "  ${GRN}✅${NC} $1"; }
pwarn() { echo -e "  ${YLW}⚠️ ${NC} $1"; }
pfail() { echo -e "  ${RED}❌${NC} $1" >&2; exit 1; }
pinfo() { echo -e "  ${CYN}·${NC}  $1"; }

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/.." && pwd)"

LAUF=""; ZIEL=""; MIT_SERVER=0; MIT_TECHNIK=0; MIT_ROH=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --mit-server)  MIT_SERVER=1; shift ;;
    --mit-technik) MIT_TECHNIK=1; shift ;;
    --mit-rohfassung) MIT_ROH=1; shift ;;
    -h|--help)
      sed -n '3,6p;21,44p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    -*) pfail "Unbekannter Schalter: $1" ;;
    *)  if [[ -z "$LAUF" ]]; then LAUF="$1"; else ZIEL="$1"; fi; shift ;;
  esac
done
[[ -n "$LAUF" ]] || pfail "Kein Lauf-Ordner angegeben. Aufruf: werkzeuge/kundenpaket.sh <lauf-ordner> [ziel]"
LAUF="${LAUF%/}"
[[ -d "$LAUF" ]] || pfail "Kein Verzeichnis: $LAUF"

KUNDE_SRC="${LAUF}/kunde"
BETR_SRC="${LAUF}/betreiber"
BELEGE_SRC="${BETR_SRC}/belege"
FINDINGS="${BETR_SRC}/findings.json"
VERZ="${BELEGE_SRC}/00_verzeichnis.tsv"

[[ -d "$KUNDE_SRC" ]] || pfail "Kein kunde/-Ordner in ${LAUF} — ist das ein Lauf-Ordner?"
# Ein abgebrochener Lauf hat seine Kundendokumente absichtlich geloescht. Aus
# den Resten ein Paket zu bauen waere die Umgehung genau dieser Sperre.
[[ -f "${KUNDE_SRC}/00_ABBRUCH.txt" ]] && \
  pfail "Dieser Lauf wurde bei der Endprüfung abgebrochen (fremde Kennungen in der Kundenspur). Kein Paket."

# ── Kontext für die Maskierung ───────────────────────────────
# Kommt aus findings.json (Feld run.scope_mode/abo_user/scan_paths, ab v3.12).
# Ohne diese Angaben kann nf_fremdkunden_maskieren nicht bestimmen, was "eigen"
# ist; sie verweigert dann die Maskierung, und ein unmaskiertes Paket ist genau
# das, was hier verhindert werden soll. Deshalb Abbruch statt Notlauf.
[[ -f "$FINDINGS" ]] || pfail "findings.json fehlt (${FINDINGS}) — ohne sie ist der Prüfumfang nicht bestimmbar."
eval "$(python3 - "$FINDINGS" <<'PY'
import json, shlex, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
r = d.get("run") or {}
print("SCOPE_MODE=%s" % shlex.quote(r.get("scope_mode") or ""))
print("ABO_USER=%s"   % shlex.quote(r.get("abo_user") or ""))
print("DOMAIN=%s"     % shlex.quote(d.get("domain") or ""))
pfade = r.get("scan_paths") or []
print("SCAN_PATHS=(%s)" % " ".join(shlex.quote(p) for p in pfade))
PY
)"
: "${SCOPE_MODE:=}" "${ABO_USER:=}" "${DOMAIN:=}"
[[ -n "${SCAN_PATHS+x}" ]] || SCAN_PATHS=()

if [[ "$SCOPE_MODE" == "global" ]]; then
  pfail "Betreiberlauf über alle vhosts (scope_mode=global). Ein Kundenpaket setzt EINEN Kunden voraus — sonst gäbe es niemanden, gegen den maskiert werden könnte."
fi
if [[ -z "$SCOPE_MODE" ]]; then
  pfail "findings.json nennt keinen Prüfumfang (run.scope_mode fehlt). Der Lauf stammt aus einer Fassung vor v3.12 — Paket von Hand schnüren oder Lauf wiederholen."
fi

# nf_fremdkunden_maskieren steht in lib/kern.sh. Der Rest der Bibliothek wird
# nicht gebraucht; die Funktion liest nur SCOPE_MODE, SCAN_PATHS, ABO_USER,
# DOMAIN — alles oben gesetzt.
# shellcheck source=/dev/null
BOLD='' BLU='' CYN='' YLW='' \
N_OK=0 N_WARN=0 N_CRIT=0 N_INFO=0 \
  source "${SELF_DIR}/lib/kern.sh" 2>/dev/null || true
declare -F nf_fremdkunden_maskieren >/dev/null || \
  pfail "nf_fremdkunden_maskieren nicht gefunden — lib/kern.sh passt nicht zu diesem Werkzeug."
# Die Bibliothek hat die Farbvariablen fuer ihren eigenen Gebrauch geleert.
RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[0;33m'; CYN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

LAUF_NAME="$(basename "$LAUF")"
ZIEL="${ZIEL:-$(dirname "$LAUF")/${LAUF_NAME}_kundenpaket}"
[[ -e "$ZIEL" ]] && pfail "Ziel existiert bereits: ${ZIEL} — bewusst kein Überschreiben."

# ── Kundendokumente (NT Docs) vorhanden und ohne Interna? ────
KD_PDFS=()
while IFS= read -r _p; do KD_PDFS+=("$_p"); done \
  < <(find "$KUNDE_SRC" -maxdepth 1 -name 'NT-*.pdf' 2>/dev/null | LC_ALL=C sort)
if [[ ${#KD_PDFS[@]} -eq 0 && "$MIT_ROH" -eq 0 ]]; then
  pfail "Keine Kundendokumente (kunde/NT-*.pdf). Erst reportgen/kundenpaket.py --lauf ${LAUF} --ziel ${KUNDE_SRC} [--fall fall.json] ausführen — oder bewusst --mit-rohfassung."
fi
if [[ ${#KD_PDFS[@]} -gt 0 ]]; then
  if ! bash "${SELF_DIR}/werkzeuge/interna-waechter.sh" "${KD_PDFS[@]}"; then
    pfail "Interna in den Kundendokumenten (siehe oben, Sperrliste werkzeuge/interna-sperrliste.txt). Kein Paket."
  fi
fi

echo -e "${BOLD}NT-Forensik · Kundenpaket${NC}"
pinfo "Lauf:  ${LAUF}"
pinfo "Ziel:  ${ZIEL}"
pinfo "Umfang: ${SCOPE_MODE}${ABO_USER:+ (${ABO_USER})}${DOMAIN:+ ${DOMAIN}}"

mkdir -p "${ZIEL}/01_Kundenunterlagen" "${ZIEL}/02_Meldungen" \
         "${ZIEL}/03_Technik" "${ZIEL}/04_Belege" "${ZIEL}/05_Bereinigung"

uebernehmen() {   # <quelle> <zielordner> [neuer name]
  local q="$1" z="$2" n="${3:-$(basename "$1")}"
  [[ -f "$q" ]] || return 1
  cp "$q" "${z}/${n}" || return 1
  # Jede uebernommene Datei wird maskiert — auch die aus kunde/, die es
  # bereits sein sollte. Doppelt maskieren schadet nicht; sich darauf
  # verlassen, dass es schon jemand getan hat, schon.
  nf_fremdkunden_maskieren "${z}/${n}" >/dev/null || {
    pwarn "Maskierung fehlgeschlagen: ${n} — Datei entfernt"
    rm -f "${z}/${n}"; return 1
  }
  return 0
}

# ── 01 Kundenunterlagen ──────────────────────────────────────
N_DOK=0; N_MELD=0
if [[ "$MIT_ROH" -eq 1 ]]; then
  for d in kundenbericht.md befunde_details.md root_aussage.md; do
    uebernehmen "${KUNDE_SRC}/${d}" "${ZIEL}/01_Kundenunterlagen" && N_DOK=$((N_DOK+1))
  done
fi
for p in "${KD_PDFS[@]+"${KD_PDFS[@]}"}"; do
  # PDFs werden NICHT maskiert: reportgen/kundenpaket.py nimmt nur Pfade aus
  # dem Pruefumfang auf, und der Interna-Waechter hat sie oben geprueft. Ein
  # Textersatz im PDF-Binaerstrom wuerde die Datei zerstoeren.
  case "$(basename "$p")" in
    NT-Dokumentation_DSGVO*|NT-Einordnung_BSI*)
      cp "$p" "${ZIEL}/02_Meldungen/" && N_MELD=$((N_MELD+1)) ;;
    *) cp "$p" "${ZIEL}/01_Kundenunterlagen/" && N_DOK=$((N_DOK+1)) ;;
  esac
done
pok "01_Kundenunterlagen: ${N_DOK} Dokument(e)"

# ── 02 Meldungen ─────────────────────────────────────────────
# Die DSGVO-Meldung gehoert dem Kunden: er ist Verantwortlicher fuer die
# personenbezogenen Daten seines Auftritts und hat die Meldepflicht nach
# Art. 33. Die BSI-Meldung bleibt draussen — sie betrifft den Betreiber und
# seinen Meldeweg.
if [[ "$MIT_ROH" -eq 1 ]] && uebernehmen "${BETR_SRC}/dsgvo_meldung.md" "${ZIEL}/02_Meldungen"; then
  N_MELD=$((N_MELD+1))
fi
if [[ "$N_MELD" -gt 0 ]]; then
  pok "02_Meldungen: ${N_MELD} Dokument(e)"
else
  pwarn "02_Meldungen: keine Dokumente zur Meldepflicht im Lauf"
fi
cat > "${ZIEL}/02_Meldungen/LIESMICH.txt" <<'MELD'
MELDEPFLICHT — EINSCHAETZUNG, KEINE RECHTSBERATUNG

Dokumentation Art. 33 DSGVO: unsere Einschaetzung zur Meldepflicht und alle
Angaben nach Art. 33 Abs. 3. Die Entscheidung obliegt IHNEN als
Verantwortlichem fuer die Daten Ihres Webauftritts. Bitte unterschreiben Sie
das Dokument und legen Sie es zu Ihren Datenschutzunterlagen (Art. 33 Abs. 5).
Wer meldet: Frist 72 Stunden ab Kenntnis.

Einordnung BSI-Meldung: ob eine Pflicht nach BSIG/NIS2 besteht, und alle
Angaben fuer eine freiwillige Meldung.
MELD

# ── 03 Technik ───────────────────────────────────────────────
if [[ "$MIT_TECHNIK" -eq 1 ]]; then
  if uebernehmen "${BETR_SRC}/technik_bericht.md" "${ZIEL}/03_Technik"; then
    pok "03_Technik: Technik-Bericht (maskiert, auf ausdrückliche Anforderung)"
  else
    pwarn "03_Technik: kein Technik-Bericht im Lauf"
  fi
else
  cat > "${ZIEL}/03_Technik/LIESMICH.txt" <<'TECH'
DIESER ORDNER IST ABSICHTLICH LEER.

Der vollstaendige Technik-Bericht enthaelt auch serverweite Befunde: offene
Ports, Root-Anmeldungen, Systemdienste. Das betrifft den Server des
Betreibers, nicht Ihren Webauftritt — und es waere fuer Sie weder pruefbar
noch handlungsleitend.

Was Sie betrifft, steht vollstaendig in 01_Kundenunterlagen.

Wenn Sie den Technik-Bericht dennoch brauchen (etwa fuer Ihre Versicherung
oder eine eigene Pruefung), fordern Sie ihn beim Betreiber an. Er wird dann
maskiert beigelegt.
TECH
  pok "03_Technik: bewusst leer (LIESMICH erklärt warum)"
fi

# ── 04 Belege ────────────────────────────────────────────────
# Lueckenlose Neunummerierung: nach dem Aussortieren klaffen Luecken, und eine
# Belegliste mit Loechern liest sich, als fehle etwas.
N_BEL=0; N_RAUS=0; N_SERVER=0
if [[ -f "$VERZ" ]]; then
  : > "${ZIEL}/04_Belege/00_verzeichnis.tsv"
  while IFS=$'\t' read -r nr stufe label datei; do
    [[ -n "${datei:-}" ]] || continue
    case "$stufe" in
      kunde) : ;;
      server)
        if [[ "$MIT_SERVER" -eq 1 ]]; then N_SERVER=$((N_SERVER+1))
        else N_RAUS=$((N_RAUS+1)); continue; fi ;;
      *) N_RAUS=$((N_RAUS+1)); continue ;;
    esac
    [[ -f "${BELEGE_SRC}/${datei}" ]] || { pwarn "Beleg fehlt im Lauf: ${datei}"; continue; }
    N_BEL=$((N_BEL+1))
    neu="$(printf '%03d' "$N_BEL")_${label}.txt"
    if uebernehmen "${BELEGE_SRC}/${datei}" "${ZIEL}/04_Belege" "$neu"; then
      printf '%s\t%s\t%s\t%s\t%s\n' "$(printf '%03d' "$N_BEL")" "$stufe" "$label" "$neu" "$datei" \
        >> "${ZIEL}/04_Belege/00_verzeichnis.tsv"
    else
      N_BEL=$((N_BEL-1))
    fi
  done < "$VERZ"
  pok "04_Belege: ${N_BEL} übernommen (davon ${N_SERVER} serverweit), ${N_RAUS} zurückgehalten"
else
  pwarn "04_Belege: kein 00_verzeichnis.tsv im Lauf — ohne Einstufung wird KEIN Beleg übernommen (#1)."
  cat > "${ZIEL}/04_Belege/LIESMICH.txt" <<'BEL'
KEINE BELEGE IN DIESEM PAKET.

Der Lauf stammt aus einer Fassung vor v3.12 und hat seine Belege nicht
eingestuft. Ohne Einstufung laesst sich nicht entscheiden, welcher Beleg
Ihren Auftritt betrifft und welcher den Server des Betreibers — und im
Zweifel geht keiner mit.
BEL
fi

# ── 05 Bereinigung ───────────────────────────────────────────
# Der Bereinigungsbericht entsteht in NT-Repair, also spaeter und anderswo.
N_REP=0
for r in "${LAUF}"/bereinigung/*.md "${LAUF}"/repair/*.md; do
  [[ -f "$r" ]] || continue
  uebernehmen "$r" "${ZIEL}/05_Bereinigung" && N_REP=$((N_REP+1))
done
if [[ "$N_REP" -eq 0 ]]; then
  cat > "${ZIEL}/05_Bereinigung/LIESMICH.txt" <<'REP'
NOCH KEIN BEREINIGUNGSBERICHT.

Dieses Paket dokumentiert die UNTERSUCHUNG. Die Bereinigung ist ein eigener
Schritt mit eigenem Protokoll (welche Datei wann in Quarantaene ging, welche
Zugaenge erneuert wurden). Er wird hier nachgereicht.

Solange dieser Ordner nur diesen Hinweis enthaelt, gilt: die Befunde aus
01_Kundenunterlagen sind erhoben, aber noch nicht behoben.
REP
  pok "05_Bereinigung: noch offen (LIESMICH erklärt den Stand)"
else
  pok "05_Bereinigung: ${N_REP} Protokoll(e)"
fi

# ── Siegel und LIESMICH ──────────────────────────────────────
(
  cd "$ZIEL" || exit 0
  find . -type f ! -name SHA256SUMS -print0 \
    | LC_ALL=C sort -z \
    | xargs -0 sha256sum 2>/dev/null > SHA256SUMS || true
)

cat > "${ZIEL}/00_LIESMICH.txt" <<LIES
UNTERSUCHUNGSUNTERLAGEN — ${DOMAIN:-Ihr Webauftritt}
Lauf ${LAUF_NAME}
Erstellt: $(date '+%d.%m.%Y, %H:%M Uhr')

  01_Kundenunterlagen  Sicherheitsbericht (PDF)
  02_Meldungen         Dokumentation Art. 33 DSGVO und Einordnung BSI-Meldung (PDF)
  03_Technik           $(if [[ "$MIT_TECHNIK" -eq 1 ]]; then echo "Technik-Bericht, maskiert"; else echo "leer — siehe LIESMICH darin"; fi)
  04_Belege            ${N_BEL} Rohbeleg(e), maskiert und neu nummeriert
  05_Bereinigung       $(if [[ "$N_REP" -eq 0 ]]; then echo "noch offen"; else echo "${N_REP} Protokoll(e)"; fi)

WARUM DAS SIEGEL EIN ANDERES IST ALS BEIM BETREIBER

Die Belege in diesem Paket sind maskiert: Pfade, Kennungen und Domains
anderer Kunden desselben Servers sind durch Platzhalter ersetzt. Damit
weicht ihr Inhalt vom Original ab, und die SHA256-Summen des Laufs passen
nicht mehr. Das ist gewollt — Sie sollen keine Daten Dritter erhalten.

Dieses Paket traegt deshalb ein EIGENES SHA256SUMS ueber die maskierte
Fassung. Die unmaskierten Originale und ihr Siegel liegen beim Betreiber und
koennen im Streitfall herangezogen werden. \`00_verzeichnis.tsv\` in
04_Belege nennt zu jedem Beleg seine urspruengliche Nummer.

WAS NICHT IN DIESEM PAKET IST — UND WARUM

  findings.json      Maschinendatei fuer die Bereinigung, keine Unterlage
  Log-Archiv         enthaelt die Zugriffe ALLER Domains des Servers
  BSI-Meldung        Meldeweg des Betreibers (Ihre Einordnung liegt in 02)
  ${N_RAUS} Beleg(e)  betreffen den Server des Betreibers, nicht Ihren Auftritt

Das Paket ist damit kleiner als der Bestand beim Betreiber. Was Sie
zusaetzlich brauchen, koennen Sie dort anfordern.
LIES

# Das LIESMICH entstand nach dem Siegel — sonst versiegelte es sich selbst.
( cd "$ZIEL" && sha256sum 00_LIESMICH.txt >> SHA256SUMS 2>/dev/null ) || true

echo ""
pok "Paket steht: ${ZIEL}"
pinfo "$(find "$ZIEL" -type f | wc -l | tr -d ' ') Datei(en), $(du -sh "$ZIEL" 2>/dev/null | cut -f1)"
[[ "$N_RAUS" -gt 0 ]] && pinfo "${N_RAUS} Beleg(e) bewusst zurückgehalten — Begründung in 00_LIESMICH.txt"
echo ""
