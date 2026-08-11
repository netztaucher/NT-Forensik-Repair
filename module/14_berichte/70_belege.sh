# shellcheck shell=bash
# NT-Forensik — Abschnitt 14, Teil: Belege versiegeln: Manifest und SHA256SUMS
#
# Unterabschnitt von module/14_berichte.sh. Wird vom Runner nach dem
# Hauptmodul geladen (siehe modul_teile_laden in wp_plesk_forensik.sh) und
# teilt sich dessen Variablen. Nicht einzeln ausfuehrbar.

# ============================================================
# BELEGE VERSIEGELN: SHA256 über alles
# ============================================================
# Stand vor der Aufteilung faelschlich ueber dem findings.json-Block.

(
  cd "$BELEGE_DIR"
  # Manifest abschließen
  {
    echo ""
    echo "Ende (UTC):     $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    # `00_`-Dateien sind Verwaltung, keine Belege. Bis v3.11 zählte das
    # Manifest sich selbst mit.
    echo "Belege gesamt:  $(ls -1 | grep -vcE 'SHA256SUMS|^00_' || true)"
    # Einstufung nach #1. Wer ein Kundenpaket schnürt, sieht hier auf einen
    # Blick, wieviel davon überhaupt übergeben werden darf.
    if [[ -s 00_verzeichnis.tsv ]]; then
      echo ""
      echo "Einstufung (Einzelheiten in 00_verzeichnis.tsv):"
      awk -F'\t' '{n[$2]++} END{for (s in n) printf "  %-10s %s\n", s, n[s]}' \
        00_verzeichnis.tsv | LC_ALL=C sort
      echo ""
      echo "  kunde      betrifft den geprüften Webauftritt — darf übergeben werden"
      echo "  server     serverweit — nur maskiert und nur, wenn der Befund es braucht"
      echo "  betreiber  rein intern — geht nie mit"
    fi
  } >> 00_manifest.txt
  sha256sum ./* 2>/dev/null | grep -v "SHA256SUMS" > SHA256SUMS || true
)
