#!/usr/bin/env bash
# =============================================================================
# lauf-status.sh — wo steht ein laufender Forensik-Lauf?
# =============================================================================
# Ein Lauf über 475 vhosts dauert knapp drei Stunden. Bis v3.14 gab es keine
# Möglichkeit zu sehen, WO er gerade ist: der Betreiber sah eine wachsende
# Protokolldatei und sonst nichts. Der Stand ließ sich nur von Hand
# rekonstruieren — Prozess suchen, Belege zählen, im Protokoll die letzte
# Abschnittszeile finden.
#
# WARUM HIER KEIN PROZENTWERT STEHT
#
# Die Abschnitte sind völlig ungleich lang. Aus dem Messlauf vom 12.08.2026
# (162 Minuten über 475 vhosts):
#
#   Abschnitt 1–7    Dateisystem           ~17 min
#   Abschnitt 8.7    gsocket-Inhaltsscan   ~51 min
#   Abschnitt 12r    Rezepte mit --online  ~90 min
#   Abschnitt 13–14  Berichte               ~4 min
#
# „Abschnitt 8 von 14" hieße dort 57 % und wäre nach der Zeit 12 %. Ein
# Prozentwert über Abschnitte gezählt ist eine Zahl, die nichts bedeutet.
#
# Stattdessen: wo, seit wann — und wie lange derselbe Abschnitt im VORIGEN Lauf
# gedauert hat. Das ist eine Messung. Gibt es keinen vergleichbaren Vorlauf,
# sagt die Anzeige das, statt eine Zahl zu erfinden.
#
# Nutzung:
#   werkzeuge/lauf-status.sh                 neuester Lauf
#   werkzeuge/lauf-status.sh <laufordner>    ein bestimmter
#   werkzeuge/lauf-status.sh --watch         alle 30 s neu
# =============================================================================
set -uo pipefail

BASIS="${FORENSIK_BASE:-/root/wartungsscripte/forensik}"
RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[0;33m'; CYN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

WATCH=0; ZIEL=""
for a in "$@"; do
  case "$a" in
    --watch) WATCH=1 ;;
    -h|--help) sed -n '2,32p' "$0"; exit 0 ;;
    *) ZIEL="$a" ;;
  esac
done

dauer() {   # dauer <sekunden> → "1 h 23 min" / "4 min 12 s"
  local s="${1:-0}"
  if   [[ "$s" -ge 3600 ]]; then printf '%d h %02d min' $((s/3600)) $(((s%3600)/60))
  elif [[ "$s" -ge 60   ]]; then printf '%d min %02d s' $((s/60)) $((s%60))
  else                           printf '%d s' "$s"; fi
}

status_zeigen() {
  local lauf="$ZIEL"
  [[ -n "$lauf" ]] || lauf=$(ls -td "$BASIS"/*_* 2>/dev/null | head -1)
  if [[ -z "$lauf" || ! -d "$lauf" ]]; then
    echo -e "  ${RED}Kein Laufordner unter ${BASIS}${NC}"; return 1
  fi
  local spur="${lauf}/.fortschritt.tsv"

  echo -e "${BOLD}NT-Forensik · Laufstatus${NC}"
  echo -e "  Lauf: $(basename "$lauf")"

  if [[ ! -r "$spur" ]]; then
    # Ältere Läufe haben keine Spur. Dann sagen, was sich ohne sie feststellen
    # lässt — und dazu, dass es eine Schätzung aus Hilfsgrößen ist.
    echo -e "  ${YLW}Keine Fortschrittsspur${NC} (Lauf vor v3.15 oder abgebrochen)."
    echo    "  Ersatzweise aus den Belegen:"
    printf  '    Belege: %s\n' "$(ls "${lauf}/betreiber/belege" 2>/dev/null | grep -c '^[0-9]' || echo 0)"
    return 0
  fi

  local start scope umfang
  start=$(awk -F'\t' '$1=="#start"{print $2; exit}' "$spur")
  scope=$(awk -F'\t' '$1=="#start"{print $3; exit}' "$spur")
  umfang=$(awk -F'\t' '$1=="#start"{print $4; exit}' "$spur")
  local ende; ende=$(awk -F'\t' '$1=="#ende"{print $2; exit}' "$spur")
  local jetzt; jetzt=$(date +%s)
  local bezug="${ende:-$jetzt}"

  printf '  Umfang: %s %s\n' "$scope" "${umfang:-}"
  printf '  Beginn: %s\n' "$(date -d "@$start" '+%H:%M:%S' 2>/dev/null || date -r "$start" '+%H:%M:%S' 2>/dev/null)"
  printf '  Läuft seit: %s\n' "$(dauer $((bezug - start)))"

  if [[ -n "$ende" ]]; then
    echo -e "\n  ${GRN}✅ Abgeschlossen${NC} nach $(dauer $((ende - start)))"
    return 0
  fi

  # Aktueller Abschnitt
  local a_zeit a_nr a_titel
  IFS=$'\t' read -r _ a_zeit a_nr a_titel < <(awk -F'\t' '$1=="abschnitt"' "$spur" | tail -1)
  if [[ -n "${a_nr:-}" ]]; then
    echo -e "\n  ${BOLD}Abschnitt ${a_nr}${NC} — ${a_titel}"
    printf  '    seit %s\n' "$(dauer $((jetzt - a_zeit)))"
  fi

  # Wo steht eine lange Pipeline gerade? Die Zeit kommt aus der mtime der
  # Datei — der Filter schreibt bewusst keinen Zeitstempel hinein, weil awks
  # systime() eine GNU-Erweiterung ist und auf BSD die Pipeline zerlegt hätte.
  if [[ -r "${spur}.aktuell" ]]; then
    local p_was p_n p_pfad p_alter
    IFS=$'\t' read -r p_was p_n p_pfad < "${spur}.aktuell"
    p_alter=$(( jetzt - $(stat -c %Y "${spur}.aktuell" 2>/dev/null || stat -f %m "${spur}.aktuell" 2>/dev/null || echo "$jetzt") ))
    if [[ "$p_alter" -lt 300 ]]; then
      printf '    %s: %s Pfade gelesen\n' "$p_was" "$p_n"
      printf '    zuletzt: %s\n' "$(printf '%s' "$p_pfad" | cut -c1-72)"
    fi
  fi

  # Unterschritt, falls dieser Abschnitt einen führt (12r)
  local u_zeit u_i u_n u_txt
  IFS=$'\t' read -r _ u_zeit u_i u_n u_txt < <(awk -F'\t' '$1=="unterschritt"' "$spur" | tail -1)
  if [[ -n "${u_i:-}" && "${u_zeit:-0}" -ge "${a_zeit:-0}" ]]; then
    printf '    Installation %s von %s — %s\n' "$u_i" "$u_n" "$u_txt"
    # Nur hier ist eine Hochrechnung ehrlich: gleichartige Schritte, gezählt.
    if [[ "${u_i:-0}" -gt 2 && "${u_n:-0}" -gt "${u_i:-0}" ]]; then
      local je=$(( (jetzt - a_zeit) / u_i ))
      printf '    ≈ %s je Installation, noch %s für diesen Abschnitt\n' \
             "$(dauer "$je")" "$(dauer $(( je * (u_n - u_i) )))"
    fi
  fi

  # ── Der Vergleich mit dem Vorlauf ──────────────────────────────────────
  # Nur ein Lauf mit DEMSELBEN Umfang taugt als Massstab. Ein --nur-website-Lauf
  # sagt nichts über einen globalen.
  local vor=""
  local kand
  while IFS= read -r kand; do
    [[ "$kand" == "$lauf" ]] && continue
    [[ -r "${kand}/.fortschritt.tsv" ]] || continue
    awk -F'\t' -v s="$scope" '$1=="#start" && $3==s {gefunden=1} END{exit !gefunden}' \
        "${kand}/.fortschritt.tsv" || continue
    awk -F'\t' '$1=="#ende"{gefunden=1} END{exit !gefunden}' "${kand}/.fortschritt.tsv" || continue
    vor="$kand"; break
  done < <(ls -td "$BASIS"/*_* 2>/dev/null)

  if [[ -z "$vor" ]]; then
    echo -e "\n  ${CYN}Keine Restschätzung${NC} — kein abgeschlossener Vorlauf mit gleichem Umfang."
    echo    "  Die Zahl käme sonst aus einer Annahme, nicht aus einer Messung."
    return 0
  fi

  local vspur="${vor}/.fortschritt.tsv"
  local vstart vende
  vstart=$(awk -F'\t' '$1=="#start"{print $2; exit}' "$vspur")
  vende=$(awk -F'\t' '$1=="#ende"{print $2; exit}' "$vspur")

  echo -e "\n  ${BOLD}Vergleich${NC} mit $(basename "$vor") (${GRN}$(dauer $((vende - vstart)))${NC} gesamt)"

  # Wann begann derselbe Abschnitt dort, und wie lange dauerte er?
  local v_ab_start v_ab_ende
  v_ab_start=$(awk -F'\t' -v n="$a_nr" '$1=="abschnitt" && $3==n {print $2; exit}' "$vspur")
  if [[ -n "$v_ab_start" ]]; then
    v_ab_ende=$(awk -F'\t' -v s="$v_ab_start" \
      '($1=="abschnitt" || $1=="#ende") && $2>s {print $2; exit}' "$vspur")
    v_ab_ende="${v_ab_ende:-$vende}"
    printf '    Abschnitt %s dauerte dort %s\n' "$a_nr" "$(dauer $((v_ab_ende - v_ab_start)))"
    local rest=$(( vende - v_ab_start ))
    local schon=$(( jetzt - a_zeit ))
    local uebrig=$(( rest - schon ))
    if [[ "$uebrig" -gt 0 ]]; then
      echo -e "    ${BOLD}Voraussichtlich noch $(dauer "$uebrig")${NC}, Ende gegen $(date -d "@$((jetzt + uebrig))" '+%H:%M' 2>/dev/null || date -r "$((jetzt + uebrig))" '+%H:%M' 2>/dev/null)"
      echo   "    (aus dem Vorlauf gemessen, nicht geschätzt — ein langsamerer"
      echo   "     Server oder mehr Installationen verschieben es nach hinten)"
    else
      echo -e "    ${YLW}Länger als der Vorlauf an dieser Stelle.${NC}"
    fi
  else
    printf '    Abschnitt %s kam im Vorlauf nicht vor — keine Restschätzung.\n' "$a_nr"
  fi
}

if [[ "$WATCH" -eq 1 ]]; then
  while :; do clear; status_zeigen; echo; echo "  (Strg-C beendet · alle 30 s)"; sleep 30; done
else
  status_zeigen
fi
