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
PAKET_VERSION="0.5.3"
PAKET_SHA256="b8679d0f2b691109aa9917874e391240f8162a80ad107c38de31f3135474fd9d"

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
if [[ -z "$LIZENZ" && -r "${STATE_DIR}/lizenz.key" ]]; then
  LIZENZ="$(head -1 "${STATE_DIR}/lizenz.key" | tr -d '[:space:]')"
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
  local nonce antwort
  nonce="$(openssl rand -hex 16)"
  antwort="$(curl -sS --max-time 20 -X POST "${LIZENZ_SERVER}/validate" \
      -H 'Content-Type: application/json' \
      -d "{\"key\":\"${LIZENZ}\",\"domain\":\"${FINGER}\",\"product\":\"nt-repair\",\"nonce\":\"${nonce}\",\"version\":\"${PAKET_VERSION}\"}" \
      2>/dev/null)" || return 2   # 2 = Server nicht erreichbar
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
