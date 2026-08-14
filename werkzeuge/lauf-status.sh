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
  # NUR Verzeichnisse. `ls -td "$BASIS"/*_*` griff auch Dateien — am
  # 13.08.2026 lag eine nohup-Logdatei mit Unterstrich im Namen neben den
  # Laufordnern, war die neueste Fundstelle, und der Status meldete "Kein
  # Laufordner", waehrend der Lauf lief. Ein Werkzeug, das den Zustand
  # anzeigen soll und stattdessen von einer Nachbardatei umfaellt, ist
  # schlimmer als keines: es sieht aus wie "kein Lauf aktiv".
  # Muster [0-9]*_*: Laufordner heissen YYYYMMDD_HHMMSS_<umfang>. Die
  # Namenssortierung ist damit zugleich die Zeitsortierung — und anders als
  # die mtime aendert sich der Name waehrend des Laufs nicht.
  [[ -n "$lauf" ]] || lauf=$(for d in "$BASIS"/[0-9]*_*/; do [[ -d "$d" ]] && printf '%s\n' "${d%/}"; done | LC_ALL=C sort -r | head -1)
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
    # EINE HALB GELESENE ZEILE IST KEINE MESSUNG.
    #
    # Die Datei wird vom laufenden Scan fortlaufend ueberschrieben. Wer genau
    # dazwischen liest, bekommt leere Felder — und die Anzeige druckte dann
    #
    #     :  Pfade gelesen
    #     zuletzt:
    #
    # Zwei Zeilen, die eine Messung behaupten und keine tragen. Am 14.08.2026
    # im laufenden Bestaetigungslauf beobachtet.
    #
    # Kein Sperren, kein Warten, kein Wiederholen: der naechste Aufruf in
    # wenigen Sekunden hat die Zahl ohnehin. Eine Zeile, die nichts weiss,
    # sagt besser nichts.
    if [[ "$p_alter" -lt 300 && -n "${p_was:-}" && -n "${p_n:-}" ]]; then
      printf '    %s: %s Pfade gelesen\n' "$p_was" "$p_n"
      [[ -n "${p_pfad:-}" ]] && printf '    zuletzt: %s\n' "$(printf '%s' "$p_pfad" | cut -c1-72)"
    fi
  fi

  # Unterschritt, falls dieser Abschnitt einen führt (12r)
  local u_zeit u_i u_n u_txt
  IFS=$'\t' read -r _ u_zeit u_i u_n u_txt < <(awk -F'\t' '$1=="unterschritt"' "$spur" | tail -1)
  if [[ -n "${u_i:-}" && "${u_zeit:-0}" -ge "${a_zeit:-0}" ]]; then
    # Bewusst allgemein: 12r zaehlt Installationen, 13b .htaccess-Dateien.
    # Was gezaehlt wird, steht im Text — die Anzeige muss es nicht wissen.
    printf '    %s von %s — %s\n' "$u_i" "$u_n" "$u_txt"
    # Nur hier ist eine Hochrechnung ehrlich: gleichartige Schritte, gezählt.
    #
    # BEZUGSPUNKT IST DER UNTERSCHRITT, NICHT DER ABSCHNITT.
    #
    # Bis hierher stand hier (jetzt - a_zeit) / u_i — die Laufzeit des ganzen
    # Abschnitts gegen einen Zähler, der bei jedem neuen Unterschritt wieder
    # bei null beginnt. Am 13.08.2026 im laufenden Messlauf beobachtet:
    # 13b.1 war nach 26 min durch, 13b.2 zählte 2.200 von 12.158 — die Anzeige
    # rechnete 1958 s / 2200 und meldete "≈ 1 je Sekunde, noch 2 h 49 min".
    # Der Rohverlauf zeigte 200 Schritte je 32 s, also 6,2/s und knapp 27 min.
    # Faktor sechs daneben, und zwar in die pessimistische Richtung.
    #
    # Eine Restschätzung, der man nicht trauen kann, ist schlimmer als keine:
    # dieses Werkzeug weist eine fehlende Schätzung ausdrücklich aus, statt zu
    # raten. Dann darf die vorhandene nicht raten.
    #
    # Gerechnet wird aus der ERSTEN Zeile desselben Unterschritts. Und ohne
    # Zwischenrunden: Rest = offen × verstrichen / erledigt. Eine gerundete
    # Rate von 0 oder 1 verzerrt sonst genau bei den schnellen Schritten.
    local b_zeit b_i
    IFS=$'\t' read -r _ b_zeit b_i _ _ < <(
      awk -F'\t' -v t="$u_txt" '$1=="unterschritt" && $5==t' "$spur" | head -1)
    local u_dt=$(( jetzt - ${b_zeit:-$a_zeit} ))
    local u_di=$(( u_i - ${b_i:-0} ))
    if [[ "$u_di" -gt 2 && "$u_dt" -gt 0 && "${u_n:-0}" -gt "${u_i:-0}" ]]; then
      local rest=$(( (u_n - u_i) * u_dt / u_di ))
      if [[ "$u_dt" -ge "$u_di" ]]; then
        printf '    ≈ %s je Schritt, noch %s für diesen Abschnitt\n' \
               "$(dauer $(( u_dt / u_di )))" "$(dauer "$rest")"
      else
        printf '    ≈ %s je Sekunde, noch %s für diesen Abschnitt\n' \
               "$(( u_di / u_dt ))" "$(dauer "$rest")"
      fi
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
