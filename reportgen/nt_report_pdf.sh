#!/usr/bin/env bash
# ============================================================
# NT-Forensik — nt_report_pdf.sh
# Erzeugt einen gebrandeten Abschlussbericht (PDF) im netztaucher-Design:
# full-bleed Navy-Deckblatt, Orange-Akzent, Seiten-Footer (Logo/Kontakt/VERTRAULICH),
# Teil 1 (Kundenbericht) + optional Teil 2 (Forensik-Protokoll).
#
# Pipeline: Markdown --pandoc--> HTML-Fragmente --python--> gebrandetes HTML
#           --weasyprint--> PDF
#
# Verwendung:
#   nt_report_pdf.sh --teil1 kundenbericht.md [--teil2 protokoll.md] \
#     --title "Sicherheitsvorfall\nUntersuchung & Bereinigung" \
#     --domain "kunde.de" --subtitle "Server srv.tld — Abschlussbericht · 08.07.2026" \
#     --meta "Forensik-Lauf=<id>" --meta "Einstufung=Bereinigt" \
#     --out bericht.pdf
#
# Voraussetzungen: pandoc, weasyprint (siehe docs/setup.md — venv empfohlen).
# weasyprint-Pfad über $WEASYPRINT oder PATH. macOS: DYLD_FALLBACK_LIBRARY_PATH=/opt/homebrew/lib
#
# © 2026 netztaucher | digital — proprietär, kostenpflichtig.
# ============================================================
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOGO="${HERE}/assets/nt-logo.svg"

RED='\033[0;31m'; GRN='\033[0;32m'; NC='\033[0m'
fail(){ echo -e "  ${RED}❌${NC} $1"; exit 1; }
ok(){ echo -e "  ${GRN}✅${NC} $1"; }

TEIL1=""; TEIL2=""; OUT="bericht.pdf"; PASS=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --teil1) TEIL1="$2"; shift 2 ;;
    --teil2) TEIL2="$2"; shift 2 ;;
    --out)   OUT="$2"; shift 2 ;;
    --title|--domain|--subtitle|--intro|--eyebrow|--teil1-label|--teil2-label|--kontakt-tel|--kontakt-mail|--cover-stats)
             PASS+=("$1" "$2"); shift 2 ;;
    --meta)  PASS+=("--meta" "$2"); shift 2 ;;
    *) fail "Unbekanntes Argument: $1" ;;
  esac
done
[[ -f "$TEIL1" ]] || fail "--teil1 <markdown> fehlt/nicht gefunden"
command -v pandoc >/dev/null 2>&1 || fail "pandoc nicht installiert"

# weasyprint finden
WP="${WEASYPRINT:-}"
[[ -z "$WP" ]] && WP="$(command -v weasyprint || true)"
[[ -n "$WP" ]] || fail "weasyprint nicht gefunden — \$WEASYPRINT setzen oder installieren (docs/setup.md)"

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
pandoc "$TEIL1" -f markdown -t html -o "$TMP/t1.html"
T2ARG=()
if [[ -n "$TEIL2" && -f "$TEIL2" ]]; then
  pandoc "$TEIL2" -f markdown+fenced_divs -t html -o "$TMP/t2.html"
  T2ARG=(--teil2-html "$TMP/t2.html")
fi

python3 "${HERE}/build_report_html.py" --out "$TMP/final.html" --logo "$LOGO" \
  --teil1-html "$TMP/t1.html" "${T2ARG[@]}" "${PASS[@]}"

export DYLD_FALLBACK_LIBRARY_PATH="${DYLD_FALLBACK_LIBRARY_PATH:-/opt/homebrew/lib}"
"$WP" "$TMP/final.html" "$OUT" 2>&1 | grep -iv 'deprecat' || true
[[ -f "$OUT" ]] && ok "PDF erzeugt: $OUT" || fail "weasyprint lieferte kein PDF"
