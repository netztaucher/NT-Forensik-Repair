#!/usr/bin/env bash
# =============================================================================
# signaturen-fremd-holen.sh — fremde YARA-Regelsätze nachladen
# =============================================================================
# Holt Regelsätze Dritter nach signaturen/fremd/. Dieses Verzeichnis steht
# NICHT im Repository und wird nicht mitgeliefert.
#
# Warum nicht mitliefern: php-malware-finder steht unter LGPL-3.0, dieses
# Repository unter MIT. Wer die Regeln weitergibt, übernimmt die Pflichten der
# LGPL — Lizenztext beilegen, Änderungen kenntlich machen, Quelle benennen.
# Diese Pflicht wollen wir dem Anwender nicht unterschieben. Er holt sich die
# Regeln selbst; dieses Werkzeug nimmt ihm nur das Suchen ab.
#
# Nutzung:
#   signaturen-fremd-holen.sh                 alle verfügbaren Regelsätze
#   signaturen-fremd-holen.sh --php-malware-finder
#   signaturen-fremd-holen.sh --pruefen       nur Zustand anzeigen
# =============================================================================

set -euo pipefail

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ZIEL="$BASE_DIR/signaturen/fremd"

PMF_REPO="https://raw.githubusercontent.com/jvoisin/php-malware-finder/master"
PMF_DATEIEN=(data/php.yar data/whitelist.yar LICENSE)

rot()  { printf '\033[31m%s\033[0m\n' "$*"; }
gruen(){ printf '\033[32m%s\033[0m\n' "$*"; }
gelb() { printf '\033[33m%s\033[0m\n' "$*"; }

pruefen() {
    echo "Zielverzeichnis: $ZIEL"
    if [[ ! -d "$ZIEL" ]]; then
        gelb "  nicht vorhanden — noch nichts geholt"
        return
    fi
    for f in "$ZIEL"/*.yar; do
        [[ -f "$f" ]] || continue
        alter=$(( ( $(date +%s) - $(stat -c %Y "$f" 2>/dev/null || stat -f %m "$f") ) / 86400 ))
        printf '  %-20s %6s Bytes   geholt vor %s Tagen\n' \
               "$(basename "$f")" "$(wc -c < "$f")" "$alter"
    done
    if command -v yara >/dev/null 2>&1 && [[ -f "$ZIEL/php.yar" ]]; then
        if yara -w "$ZIEL/php.yar" /dev/null >/dev/null 2>&1; then
            gruen "  yara übersetzt den Regelsatz fehlerfrei"
        else
            rot   "  yara kann den Regelsatz NICHT übersetzen:"
            yara -w "$ZIEL/php.yar" /dev/null 2>&1 | sed 's/^/    /' | head -5
            echo  "    Häufigste Ursache: yara ohne hash-Modul gebaut (php.yar nutzt import \"hash\")."
        fi
    fi
}

holen_pmf() {
    mkdir -p "$ZIEL"
    echo "php-malware-finder wird geholt..."
    for datei in "${PMF_DATEIEN[@]}"; do
        ziel="$ZIEL/$(basename "$datei")"
        if curl -fsSL --max-time 30 "$PMF_REPO/$datei" -o "$ziel.neu"; then
            mv "$ziel.neu" "$ziel"
            printf '  %-16s %s Bytes\n' "$(basename "$datei")" "$(wc -c < "$ziel")"
        else
            rm -f "$ziel.neu"
            rot "  FEHLER beim Holen von $datei"
            return 1
        fi
    done

    # LICENSE unter sprechendem Namen ablegen, damit sie nicht mit einer
    # Lizenz dieses Projekts verwechselt wird.
    [[ -f "$ZIEL/LICENSE" ]] && mv "$ZIEL/LICENSE" "$ZIEL/LICENSE.php-malware-finder"

    cat > "$ZIEL/HERKUNFT.md" <<'TXT'
# Fremde Regelsätze — Herkunft und Lizenz

Dieses Verzeichnis steht **nicht** im Repository und wird **nicht** mitgeliefert.
Es wird von `werkzeuge/signaturen-fremd-holen.sh` befüllt.

## php-malware-finder

- Quelle: https://github.com/jvoisin/php-malware-finder
- Dateien: `php.yar`, `whitelist.yar`
- Lizenz: **LGPL-3.0** — Text in `LICENSE.php-malware-finder`
- Verwendet von: `module/07_dateisystem.sh`, Abschnitt 7.12

### Einordnung

Die Regeln zielen auf **Obfuskierungs- und Funktionsmuster**, nicht auf
konkrete Schädlinge. Das ist ihre Stärke und ihre Schwäche zugleich:

- Sie altern langsamer als Sample-Signaturen, weil Verschleierungstechnik
  langlebiger ist als ein einzelner Schädling.
- Sie erzeugen mehr Fehlalarme, weil legitimer Code dieselben Funktionen nutzt.
  Deshalb meldet Abschnitt 7.12 als **Warnung**, nicht als Befund.

### Pflegezustand

Der letzte inhaltliche Stand der Regeln datiert auf **Februar 2023**, die letzte
Aktivität im Projekt auf Oktober 2023. Der Regelsatz ist damit eine
**Ergänzung**, kein Ersatz für einen gepflegten Signaturbestand. Wer ihn als
alleinige Malware-Erkennung einsetzt, täuscht sich über seine Abdeckung.
TXT

    gruen "Fertig. Ablage: $ZIEL"
    echo
    gelb "Lizenzhinweis: LGPL-3.0. Bei Weitergabe dieses Verzeichnisses gelten"
    gelb "deren Pflichten. Der Regelstand ist von Februar 2023 — siehe HERKUNFT.md."
}

case "${1:---alles}" in
    --pruefen)              pruefen ;;
    --php-malware-finder)   holen_pmf; echo; pruefen ;;
    --alles)                holen_pmf; echo; pruefen ;;
    -h|--hilfe|--help)      sed -n '2,20p' "$0" ;;
    *)                      rot "Unbekannte Option: $1"; sed -n '2,20p' "$0"; exit 2 ;;
esac
