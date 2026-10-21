#!/usr/bin/env bash
# =============================================================================
# interna_waechter_selbsttest.sh — Sperrliste in beide Richtungen (#150)
# =============================================================================
# Test:     ja - läuft in CI (.github/workflows/pruefung.yml) · NT-Forensik-Repair#150
# Rueckweg: entfällt - schreibt nur in ein temporäres Verzeichnis
#
# Ein Wächter, der nur „meldet Interna“ prüft, wäre durch „meldet immer“ zu
# bestehen. Deshalb zwei Richtungen:
#   - Beweise zum Vorfall (Hashes, IPs, Zeitstempel, Pfade im Webspace,
#     Paragrafen) müssen SCHWEIGEN,
#   - jedes Beispiel aus #150 muss einzeln ANSCHLAGEN.
# Geprüft wird über Text, HTML und E-Mail; PDFs prüft kundenpaket-pruefstand.sh.
# =============================================================================
set -uo pipefail
SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
W="${SELF_DIR}/interna-waechter.sh"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
FEHLER=0
ok()   { echo "  ✓ $1"; }
fehl() { echo "  ✗ $1"; FEHLER=$((FEHLER+1)); }

# ── darf nicht anschlagen ───────────────────────────────────────────────────
cat > "${T}/sauber.txt" <<'TXT'
Erster Zugriff 18.10.2026, 23:33 Uhr von 203.0.113.7 über die Fernsteuerung.
SHA-256 39ef548449d372b45abdd7d6ab3580b19b90c335e88b5b1c9f720850ab059b67
Pfad wp-content/plugins/hero-hub/hero-hub.php im Webspace der Website.
Pflicht nach § 32 BSIG, Art. 33 Abs. 5 DSGVO, Anlagen 1 und 2.
Sicherheitsbericht · Seite 3 von 9 · die netztaucher GmbH
Geprüft: Das alte Passwort wird abgewiesen. Prüfung der Server ohne Befund.
WordPress 6.4.1, UpdraftPlus 2.26.13, Lauf der Untersuchung am 21.10.2026.
TXT
if bash "$W" "${T}/sauber.txt" >"${T}/out" 2>&1; then
  ok "Beweise zum Vorfall bleiben unbeanstandet"
else
  fehl "Fehlalarm auf erlaubte Beweise:"; sed 's/^/      /' "${T}/out"
fi

# ── muss anschlagen (je Zeile eine eigene Datei) ────────────────────────────
while IFS= read -r probe; do
  [[ -n "$probe" ]] || continue
  printf 'Text davor. %s Text danach.\n' "$probe" > "${T}/probe.txt"
  if bash "$W" "${T}/probe.txt" >/dev/null 2>&1; then
    fehl "schweigt zu: ${probe}"
  else
    ok "schlägt an: ${probe}"
  fi
done <<'PROBEN'
siehe infra#1062
erledigt in #140
NT-Repair#34 ist offen
Seite Lücken im Werkzeug
mit NT-Forensik geprüft
Stand e4c5e1c → 8f0b256
Lauf 2026-10-21_08-28-00_abo-web68
Schalter --online gesetzt
Skript bereinigung_hero.sh
nt_repair.sh lief
rotate-plesk-ftp.sh ausgeführt
abgelegt in 1Password
steht im Register
secrets.registry.json
Quarantäne unter /root/wartungsscripte/q
Sicherung in /var/lib/nt-wartung/x
Docroot /var/www/vhosts/web68.example/httpdocs
Protokoll actions.jsonl
siehe RUECKWEG.txt
Server k42
Sprung über k42-sprung@dev
Mail über vca-mail-wrapper
auf homer geprüft
Root-Verdikt unauffällig
Kill-Proof bestanden
nach dem Rotations-Ritual
Fingerabdruck a1b2c3d4e5f6
PROBEN

# ── HTML und E-Mail werden gelesen ──────────────────────────────────────────
printf '<p>Bitte <b>heute</b> lesen.</p><p>Details in infra#77</p>\n' > "${T}/mail.html"
bash "$W" "${T}/mail.html" >/dev/null 2>&1 && fehl "HTML wird nicht gelesen" || ok "HTML: Treffer im Text gefunden"
python3 - "${T}/mail.eml" <<'PY'
import sys
from email.message import EmailMessage
m = EmailMessage(); m["Subject"] = "Abschluss"; m["To"] = "a@example.org"
m.set_content("Guten Tag,\nalles erledigt.")
m.add_alternative("<p>Guten Tag,</p><p>Werkzeug NT-Forensik</p>", subtype="html")
open(sys.argv[1], "wb").write(bytes(m))
PY
bash "$W" "${T}/mail.eml" >/dev/null 2>&1 && fehl "E-Mail: HTML-Teil wird nicht gelesen" || ok "E-Mail: Treffer im HTML-Teil gefunden"

# ── Nicht lesbar ist nicht grün ─────────────────────────────────────────────
bash "$W" "${T}/gibt-es-nicht.pdf" >/dev/null 2>&1; rc=$?
[[ "$rc" -eq 2 ]] && ok "fehlende Datei endet mit 2, nicht mit grün" || fehl "fehlende Datei endet mit ${rc}"

echo
[[ "$FEHLER" -eq 0 ]] && { echo "Interna-Wächter: alle Proben bestanden."; exit 0; }
echo "Interna-Wächter: ${FEHLER} Abweichung(en)."; exit 1
