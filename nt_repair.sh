#!/usr/bin/env bash
# ============================================================
# NT-Repair — Lizenz-Lader
# ------------------------------------------------------------
# Die Bereinigung liegt verschluesselt in paket/repair-<fassung>.enc.
# Dieses Skript holt den Schluessel beim Lizenzserver, entschluesselt das
# Paket in den Arbeitsspeicher und fuehrt es aus. Ohne gueltige Lizenz gibt
# es keinen Schluessel und damit keinen Lauf.
#
# Der Lader selbst ist bewusst offen lesbar. Er enthaelt kein Geheimnis:
# was er tut, kann jeder nachvollziehen, und was er nicht hat, kann auch
# niemand aus ihm herausholen.
#
# Verwendung — unveraendert gegenueber der frueheren Fassung:
#   nt_repair.sh --findings <pfad/findings.json> | --from <lauf-dir>
#                [--host <sshhost>] [--apply] [--kunde "Name"] [--note "..."]
#
# Lizenzschluessel:  Umgebungsvariable NT_REPAIR_LIZENZ
#                    oder ~/.nt-repair/lizenz.key (eine Zeile)
#
# Die Forensik (wp_plesk_forensik.sh) braucht davon nichts. Sie ist frei,
# quelloffen und laeuft ohne Netz und ohne Lizenz vollstaendig durch.
#
# © 2026 netztaucher | digital — der Paketinhalt ist proprietaer.
# ============================================================
set -uo pipefail

# ── Was zu dieser Fassung gehoert ────────────────────────────
# Beide Werte kommen aus werkzeuge/paket-bauen.sh (NT-Repair) und gehoeren
# zusammen. PAKET_SHA256 ist die Pruefsumme des ENTSCHLUESSELTEN Archivs.
PAKET_VERSION="0.8.3"
PAKET_SHA256="faf373d5cdccfa2341d888908de4b3355c95c4e099e65833e8833a8600f68c2e"

LIZENZ_SERVER="${NT_REPAIR_LIZENZ_SERVER:-https://tools.netztaucher.com/licence}"
NACHFRIST_TAGE="${NT_REPAIR_NACHFRIST_TAGE:-7}"

RED='\033[0;31m'; YLW='\033[0;33m'; CYN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
abbruch() { echo -e "\n  ${RED}❌${NC} $1\n" >&2; exit 1; }
hinweis() { echo -e "  ${CYN}·${NC}  $1" >&2; }
warnung() { echo -e "  ${YLW}⚠️ ${NC} $1" >&2; }

SELF_PATH="$(readlink -f "$0" 2>/dev/null || echo "$0")"
SELF_DIR="$(cd "$(dirname "$SELF_PATH")" && pwd)"
PAKET="${SELF_DIR}/paket/repair-${PAKET_VERSION}.enc"
STATE_DIR="${HOME}/.nt-repair"
CACHE="${STATE_DIR}/lizenz.cache"

[[ -r "$PAKET" ]] || abbruch "Paket fehlt: ${PAKET}"
command -v openssl >/dev/null 2>&1 || abbruch "openssl wird benoetigt."
command -v curl    >/dev/null 2>&1 || abbruch "curl wird benoetigt."
command -v python3 >/dev/null 2>&1 || abbruch "python3 wird benoetigt."

# shasum gibt es auf macOS, sha256sum auf den meisten Linux-Systemen.
if command -v shasum >/dev/null 2>&1; then
  sha256() { shasum -a 256 | awk '{print $1}'; }
elif command -v sha256sum >/dev/null 2>&1; then
  sha256() { sha256sum | awk '{print $1}'; }
else
  abbruch "Weder shasum noch sha256sum vorhanden."
fi

# ── Arbeitsplatz-Fingerabdruck ───────────────────────────────
# Tritt an die Stelle der Domain, die der Lizenzserver sonst prueft. NT-Repair
# laeuft vom Arbeitsplatz aus per SSH auf fremde Server — eine eigene Domain
# hat es nicht. Gebunden wird deshalb der Rechner, der die Bereinigung fuehrt.
fingerabdruck() {
  local roh
  case "$(uname -s)" in
    Darwin) roh="$(ioreg -rd1 -c IOPlatformExpertDevice 2>/dev/null \
                   | awk -F'"' '/IOPlatformUUID/{print $4}')" ;;
    *)      roh="$(cat /etc/machine-id 2>/dev/null \
                   || cat /var/lib/dbus/machine-id 2>/dev/null)" ;;
  esac
  [[ -n "${roh:-}" ]] || return 1
  printf 'nt-repair:%s:%s' "$roh" "$(hostname -s 2>/dev/null || hostname)" \
    | sha256 | tr 'a-z' 'A-Z' | cut -c1-32
}

FINGER="$(fingerabdruck)" || abbruch "Rechner-Kennung nicht ermittelbar — Lizenzbindung nicht moeglich."

# ── Lizenzschluessel ─────────────────────────────────────────
LIZENZ="${NT_REPAIR_LIZENZ:-}"
LIZENZ_QUELLE="Umgebungsvariable NT_REPAIR_LIZENZ"
if [[ -z "$LIZENZ" && -r "${STATE_DIR}/lizenz.key" ]]; then
  LIZENZ="$(head -1 "${STATE_DIR}/lizenz.key" | tr -d '[:space:]')"
  LIZENZ_QUELLE="${STATE_DIR}/lizenz.key"
fi

# ── Form pruefen, bevor irgendetwas das Netz erreicht (#83) ──
#
# Bis hierher galt der Dateiinhalt ungeprueft als Schluessel. Am 31.08.2026
# stand in lizenz.key eine versehentlich hineinkopierte Befehlszeile mit
# einem Anfuehrungszeichen darin. Der Koerper der Anfrage wurde durch
# Zeichenkettenverkettung gebaut, das Anfuehrungszeichen zerlegte das JSON,
# und der Lizenzserver antwortete "Invalid JSON body."
#
# Die Meldung nannte den SERVER, die Ursache lag in einer LOKALEN DATEI. Das
# hat zwei Messungen am falschen Ende gekostet: config.php auf dem
# Lizenzserver auf Syntaxfehler geprueft, Fassungsliste ausgelesen,
# Zeitstempel verglichen.
#
# Die Falle entsteht leicht: wer den Schluessel ueber `read -rs` hinterlegt,
# sieht seine Eingabe nicht.
#
# DER INHALT WIRD NIE AUSGEGEBEN. Gemeldet werden Laenge und Herkunft, nicht
# der Wert -- eine Fehlermeldung, die einen Schluessel in ein Protokoll oder
# einen Screenshot schreibt, ist ein eigener Fehler.
# Das Praefix case-unempfindlich: die Form stammt aus dem Hilfetext dieses
# Laders (NT-XXXX-XXXX-XXXX), nicht aus einer gemessenen Serverregel. Wer
# seinen Schluessel klein schreibt, soll hier nicht haengenbleiben --
# ueber Gross- und Kleinschreibung entscheidet der Lizenzserver, nicht
# diese Probe. Sie soll offensichtlich falschen INHALT abfangen (die
# hineinkopierte Befehlszeile), keine Serverregel durchsetzen.
if [[ -n "$LIZENZ" && ! "$LIZENZ" =~ ^[Nn][Tt]-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}$ ]]; then
  cat >&2 <<HILFE

  FEHLER: ${LIZENZ_QUELLE} enthaelt keinen Lizenzschluessel
     (${#LIZENZ} Zeichen, erwartet NT-XXXX-XXXX-XXXX).

  Der Inhalt wird hier bewusst nicht angezeigt. Nachsehen mit:
      cat ${STATE_DIR}/lizenz.key

  Neu hinterlegen:
      printf 'NT-XXXX-XXXX-XXXX\\n' > ${STATE_DIR}/lizenz.key
      chmod 600 ${STATE_DIR}/lizenz.key

  Die Analyse braucht keine Lizenz:
      bash wp_plesk_forensik.sh --domain kunde.tld

HILFE
  exit 1
fi
if [[ -z "$LIZENZ" ]]; then
  cat >&2 <<HILFE

  ${BOLD}NT-Repair ist lizenzpflichtig.${NC}

  Kein Lizenzschluessel gefunden. Hinterlegen mit:

      mkdir -p ~/.nt-repair && chmod 700 ~/.nt-repair
      printf 'NT-XXXX-XXXX-XXXX\n' > ~/.nt-repair/lizenz.key
      chmod 600 ~/.nt-repair/lizenz.key

  oder einmalig ueber die Umgebung:  NT_REPAIR_LIZENZ=NT-XXXX-XXXX-XXXX

  Rechner-Kennung dieses Arbeitsplatzes (fuer die Freischaltung):
      ${FINGER}

  Die Analyse braucht keine Lizenz:
      bash wp_plesk_forensik.sh --domain kunde.tld

HILFE
  exit 1
fi

# ── Schluessel vom Lizenzserver holen ────────────────────────
# Erst fragen, dann erst den Zwischenspeicher. Damit wirkt eine gesperrte
# Lizenz sofort, sobald der Rechner am Netz ist — der Zwischenspeicher ist
# Ausfallreserve, nicht Abkuerzung.
schluessel_vom_server() {
  local nonce antwort koerper fehler
  nonce="$(openssl rand -hex 16)"
  # KEINE ZEICHENKETTENVERKETTUNG FUER JSON (#83). Der Koerper entsteht in
  # demselben python3, das die Antwort auswertet -- es maskiert korrekt. Die
  # Formpruefung oben faengt den Anlassfall schon ab; diese Stelle sorgt
  # dafuer, dass derselbe Bau nicht an anderer Stelle wieder zuschlaegt.
  koerper="$(python3 -c 'import json,sys; print(json.dumps({"key":sys.argv[1],"domain":sys.argv[2],"product":"nt-repair","nonce":sys.argv[3],"version":sys.argv[4]}))' \
              "$LIZENZ" "$FINGER" "$nonce" "$PAKET_VERSION")" || return 2
  # Transportfehler NICHT nach /dev/null (#83). Solange die Ursache offen
  # ist, ist eine verworfene Fehlerausgabe ein selbstgestellter Hinterhalt --
  # das steht als eigene Regel in CLAUDE.md. curl schreibt seinen Grund nach
  # stderr; der wandert in eine Datei und wird im Fehlerfall gezeigt.
  fehler="$(mktemp)"
  antwort="$(curl -sS --max-time 20 -X POST "${LIZENZ_SERVER}/validate" \
      -H 'Content-Type: application/json' \
      --data-binary "$koerper" \
      2>"$fehler")" || {
        [[ -s "$fehler" ]] && printf '  Lizenzserver nicht erreichbar: %s\n' \
          "$(head -2 "$fehler" | tr '\n' ' ')" >&2
        rm -f "$fehler"; return 2; }
  rm -f "$fehler"
  [[ -n "$antwort" ]] || return 2

  python3 - "$antwort" <<'PY'
import json, sys
try:
    d = json.loads(sys.argv[1])
except Exception:
    sys.exit(3)
if not d.get("valid"):
    sys.stderr.write((d.get("message") or "Lizenz abgelehnt.") + "\n")
    sys.exit(4)
k = d.get("payload_key")
if not k:
    sys.stderr.write("Antwort ohne Ausliefer-Schluessel.\n")
    sys.exit(5)
print(k)
PY
}

# ── Ausfallreserve ───────────────────────────────────────────
# Der Schluessel liegt verschluesselt, und zwar mit dem Fingerabdruck dieses
# Rechners. Auf einen anderen Rechner kopiert ist die Datei wertlos.
cache_schreiben() {
  local ct
  ct="$(printf '%s\n' "$1" \
        | openssl enc -aes-256-cbc -pbkdf2 -iter 200000 -salt -a -pass fd:3 3< <(printf %s "$FINGER") 2>/dev/null)" || return 1
  mkdir -p "$STATE_DIR" && chmod 700 "$STATE_DIR"
  { date +%s; printf '%s\n' "$ct"; } > "$CACHE"
  chmod 600 "$CACHE"
}
cache_lesen() {
  [[ -r "$CACHE" ]] || return 1
  local ts alter
  ts="$(head -1 "$CACHE")"
  [[ "$ts" =~ ^[0-9]+$ ]] || return 1
  alter=$(( $(date +%s) - ts ))
  (( alter <= NACHFRIST_TAGE * 86400 )) || return 1
  tail -n +2 "$CACHE" \
    | openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -a -pass fd:3 3< <(printf %s "$FINGER") 2>/dev/null
}

PAYLOAD_KEY="$(schluessel_vom_server)"; RC=$?
case "$RC" in
  0) cache_schreiben "$PAYLOAD_KEY" || warnung "Ausfallreserve nicht schreibbar (${CACHE})." ;;
  2) warnung "Lizenzserver nicht erreichbar — versuche Ausfallreserve."
     PAYLOAD_KEY="$(cache_lesen)" \
       || abbruch "Keine gueltige Ausfallreserve (max. ${NACHFRIST_TAGE} Tage). Ohne Netz kein Repair — die Analyse laeuft weiter."
     hinweis "Ausfallreserve verwendet. Sobald wieder Netz da ist, laeuft die Pruefung normal." ;;
  4) abbruch "Lizenz nicht gueltig fuer diesen Arbeitsplatz (${FINGER})." ;;
  5) abbruch "Lizenzserver kennt Fassung ${PAKET_VERSION} nicht. Neuere Fassung ziehen." ;;
  *) abbruch "Lizenzpruefung fehlgeschlagen (Code ${RC})." ;;
esac
[[ -n "${PAYLOAD_KEY:-}" ]] || abbruch "Kein Ausliefer-Schluessel erhalten."

# ── Paket oeffnen ────────────────────────────────────────────
# Nichts wird ausgepackt. Der Klartext geht ueber /dev/fd direkt in die
# Shell und in python3 — es entsteht keine Datei, die jemand vergessen
# koennte, und kein Aufraeumen, das bei kill -9 ausfaellt.
oeffne() { openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -in "$PAKET" -pass fd:3 3< <(printf %s "$PAYLOAD_KEY") 2>/dev/null; }
entpacke() { oeffne | tar -xzO -f - "$1" 2>/dev/null; }

IST_SHA="$(oeffne | sha256)"
if [[ "$IST_SHA" != "$PAKET_SHA256" ]]; then
  abbruch "Paket passt nicht zum Schluessel — nichts ausgefuehrt.
        erwartet ${PAKET_SHA256}
        erhalten ${IST_SHA}"
fi

# Der Kern ruft seine Hilfsskripte hierueber auf. Weil die Funktion schon
# existiert, wenn kern.sh eingebunden wird, bleibt dessen eigene Definition
# (die auf Dateien unter lib/ zeigen wuerde) unbenutzt.
nt_lib_run() {   # nt_lib_run <pfad-im-paket> [argumente...]
  local rel="$1"; shift
  bash <(entpacke "$rel") "$@"
}

# Der Kern wird ueber eval eingebunden, nicht ueber `source <(...)`.
# Gemessen auf bash 3.2.57 (macOS-Vorgabe): `source` aus einer
# Prozess-Substitution fuehrt dort NICHTS aus und meldet trotzdem Erfolg —
# der Lauf endete lautlos mit Code 0. Das ist die gefaehrlichste Sorte
# Fehler: er sieht aus wie ein erfolgreicher Lauf.
# eval haelt den Klartext ebenfalls nur im Arbeitsspeicher und laesst die
# Aufrufargumente unveraendert stehen — kern.sh sieht dieselbe
# Kommandozeile, die dieses Skript bekommen hat.
KERN="$(entpacke kern.sh)"
[[ -n "$KERN" ]] || abbruch "Kern liess sich nicht aus dem Paket loesen."
eval "$KERN"
