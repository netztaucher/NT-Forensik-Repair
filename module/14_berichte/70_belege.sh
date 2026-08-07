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
    echo "Belege gesamt:  $(ls -1 | grep -vc "SHA256SUMS" || true)"
  } >> 00_manifest.txt
  sha256sum ./* 2>/dev/null | grep -v "SHA256SUMS" > SHA256SUMS || true
)
