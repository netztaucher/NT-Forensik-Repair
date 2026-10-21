#!/usr/bin/env bash
# ============================================================
# NT-Forensik — Selbsttest: Fremdkunden-Maskierung lässt Vorlagentext stehen (#148)
# ------------------------------------------------------------
#   werkzeuge/maskierung_selbsttest.sh
#
# Test:     ja - dieses Skript, künstlicher Bericht ohne Server · NT-Forensik-Repair#148
# Rueckweg: entfällt - liest nur
#
# WOZU
#
# Am 21.10.2026 (Vorfall Mattmüller, cletus) stand in der Kundenfassung von
# bsi_meldung.md "https://<anderer Kunde 2>" statt des BSI-Meldeportals, eine
# Mailadresse des BSI als "<anderer Adresse 1>" und der eigene Server als
# "<anderer Kunde 4>". nf_fremdkunden_maskieren (lib/kern.sh) maskiert alles, was
# wie eine Domain aussieht, ausser einer Positivliste; amtliche Adressen und der
# eigene Hostname fehlten darin.
#
# Geprüft wird in BEIDE Richtungen. Ein Test, der nur "BSI bleibt stehen" prüft,
# wäre durch "maskiert gar nichts mehr" zu bestehen:
#   1. Meldewege des BSI, Allianz für Cybersicherheit, Betreiber-Kontakt und der
#      eigene Hostname bleiben wörtlich stehen
#   2. Nachbar als Domain, Mailadresse, vhost-Pfad und webNN wird maskiert,
#      ebenso ein anderer Server derselben Hosting-Domain
#   3. die eigene Domain bleibt stehen
#   4. Prüfmodus: reiner Vorlagentext meldet 0, mit Nachbar 1
# ============================================================
set -uo pipefail
WURZEL="$(cd "$(dirname "$0")/.." && pwd)"
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
fail=0
t_ok()   { printf '  ok   %s\n' "$1"; }
t_nein() { printf '  FEHL %s\n' "$1"; fail=1; }

# shellcheck source=/dev/null
RED='' GRN='' YLW='' BLU='' CYN='' BOLD='' NC='' N_OK=0 N_WARN=0 N_CRIT=0 N_INFO=0
source "${WURZEL}/lib/kern.sh" 2>/dev/null || true
declare -F nf_fremdkunden_maskieren >/dev/null || { echo "nf_fremdkunden_maskieren fehlt in lib/kern.sh"; exit 1; }

SCOPE_MODE=abo
SCAN_PATHS=(/var/www/vhosts/kunde-eins.de)
ABO_USER=web68
DOMAIN=kunde-eins.de
export NF_HOST_FQDN=cletus.kundenserver42.de

echo "Fremdkunden-Maskierung (#148)"

cat > "$TMP/vorlage.md" <<'EOF'
| Betroffener Server | cletus.kundenserver42.de (109.234.218.232) |
BSI Melde- und Informationsportal — https://mip.bsi.bund.de
Freiwillige Meldung über https://www.allianz-fuer-cybersicherheit.de bzw. E-Mail an meldestelle@bsi.bund.de
Informationen: https://www.bsi.bund.de
Kontakt: neuber@netztaucher.com · https://netztaucher.com/wordpress
Eigene Website: https://kunde-eins.de, Pfad /var/www/vhosts/kunde-eins.de/httpdocs, Konto web68
EOF
cp "$TMP/vorlage.md" "$TMP/nur_vorlage.md"

nf_fremdkunden_maskieren "$TMP/vorlage.md" >/dev/null 2>&1
for erwartet in \
    "cletus.kundenserver42.de (109.234.218.232)" \
    "https://mip.bsi.bund.de" \
    "https://www.allianz-fuer-cybersicherheit.de" \
    "meldestelle@bsi.bund.de" \
    "https://www.bsi.bund.de" \
    "neuber@netztaucher.com" \
    "https://netztaucher.com/wordpress" \
    "https://kunde-eins.de" \
    "/var/www/vhosts/kunde-eins.de/httpdocs" \
    "Konto web68"; do
  grep -qF "$erwartet" "$TMP/vorlage.md" && t_ok "bleibt: $erwartet" || t_nein "maskiert: $erwartet"
done
grep -q "anderer" "$TMP/vorlage.md" && t_nein "Vorlagentext bekam Platzhalter: $(grep -o '<anderer [^>]*>' "$TMP/vorlage.md" | sort -u | tr '\n' ' ')" || t_ok "kein Platzhalter im reinen Vorlagentext"

cat > "$TMP/nachbar.md" <<'EOF'
Serverweit gefunden: nachbar-shop.de, Mail info@nachbar-shop.de
Pfad /var/www/vhosts/zweiter-nachbar.de/httpdocs/x.php, Konto web12
Anderer Server derselben Flotte: homer.kundenserver42.de
Meldeweg: https://mip.bsi.bund.de
EOF
nf_fremdkunden_maskieren "$TMP/nachbar.md" >/dev/null 2>&1
for weg in "nachbar-shop.de" "zweiter-nachbar.de" "web12" "homer.kundenserver42.de"; do
  grep -qF "$weg" "$TMP/nachbar.md" && t_nein "nicht maskiert: $weg" || t_ok "maskiert: $weg"
done
grep -qF "https://mip.bsi.bund.de" "$TMP/nachbar.md" && t_ok "Meldeweg neben Nachbarn erhalten" || t_nein "Meldeweg neben Nachbarn maskiert"

if nf_fremdkunden_maskieren "$TMP/nur_vorlage.md" pruefen >/dev/null 2>&1; then
  t_ok "Prüfmodus: Vorlagentext sauber (0)"
else
  t_nein "Prüfmodus meldet Vorlagentext als fremd"
fi
printf 'Nachbar: nachbar-shop.de\n' > "$TMP/pruef_nachbar.md"
if nf_fremdkunden_maskieren "$TMP/pruef_nachbar.md" pruefen >/dev/null 2>&1; then
  t_nein "Prüfmodus übersieht Nachbarn"
else
  t_ok "Prüfmodus: Nachbar erkannt (1)"
fi

[[ $fail -eq 0 ]] && echo "GRÜN" || echo "ROT"
exit $fail
