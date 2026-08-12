# shellcheck shell=bash
# ============================================================
# NT-Forensik — Prüfrezepte: der Rahmen
# ------------------------------------------------------------
# Ein Rezept beschreibt, wie eine Anwendung geprueft wird. Es besteht aus einer
# Deklaration (rezept.conf) und optional einer Datei mit Haken (rezept.sh) fuer
# das, was nur diese Anwendung kann.
#
#   rezepte/<app>/
#     rezept.conf      Pflicht — die Deklaration
#     rezept.sh        optional — Haken: rezept_version, rezept_kern,
#                      rezept_konfig, rezept_db, rezept_sonder
#     signaturen.tsv   optional — muster <TAB> schwere <TAB> was_es_ist
#     daten/           optional — Offline-Bestand (Pruefsummen, CVE)
#
# Gefunden wird per Glob, es gibt kein Zentralregister. Ein neues Rezept ist
# ein Verzeichnis, sonst nichts. Die Lehre stammt aus dem nt-profiler, wo eine
# 57-Zeilen-Registrierungsliste im Kern gepflegt werden musste und ein neues
# Rezept deshalb immer zwei Dateien kostete.
#
# ------------------------------------------------------------
# WAS DER RAHMEN GARANTIERT — UND DAS REZEPT NICHT UEBERSPRINGEN KANN
#
# Diese Schritte waren bisher in jedem CMS-Abschnitt einzeln ausprogrammiert,
# mit Abweichungen, die niemand beabsichtigt hatte:
#
#   Installationen finden      11:60, 12:75/82, 12b:31/36, 12c:38/43
#   Sicherungskopien filtern   12 meldete info, 12b warn, 12c info, 11 gar nicht
#   Selbstausschluss           11 fehlte er
#   Werkzeug-Probe             nur 12c hatte sie
#   Verdikt                    12b hatte keins
#
# Vier Abschnitte, vier Auslegungen desselben Vertrags. Der Rahmen macht daraus
# eine — und zwar die strengste.
# ============================================================

REZEPT_DIR="${SELF_DIR:-.}/rezepte"

# ── Deklaration lesen ────────────────────────────────────────
# Bewusst kein 'source': eine Rezeptdatei aus fremder Hand wuerde damit mit
# Root-Rechten ausgefuehrt. rezept.conf ist eine Datendatei, kein Skript, und
# wird als solche gelesen — Schluessel=Wert, alles andere ignoriert.
rezept_feld() {   # rezept_feld <rezeptverzeichnis> <schluessel>
  sed -n "s/^${2}[[:space:]]*=[[:space:]]*//p" "${1}/rezept.conf" 2>/dev/null \
    | head -1 | sed 's/^"//; s/"$//'
}

# ── Installationen finden ────────────────────────────────────
# Marker + Bestaetigung: der Marker findet Kandidaten, die Bestaetigung
# schliesst Sicherungskopien und Fehltreffer aus. WordPress hatte bisher keine
# Bestaetigung — 'wp-config.php' allein ist unscharf genug, dass es durchging,
# aber es brach das Muster.
rezept_installationen() {   # rezept_installationen <rezeptverzeichnis>
  local rz="$1"
  local marker tiefe bestaetigung kopien
  marker="$(rezept_feld "$rz" marker)"
  tiefe="$(rezept_feld "$rz" marker_tiefe)"; tiefe="${tiefe:-5}"
  bestaetigung="$(rezept_feld "$rz" bestaetigung)"
  kopien="$(rezept_feld "$rz" kopien_regex)"

  [[ -n "$marker" ]] || return 0

  local gefunden="" uebersprungen=0 d
  while IFS= read -r treffer; do
    [[ -n "$treffer" ]] || continue
    d="$(dirname "$treffer")"

    # Bestaetigung: kommagetrennte Liste von Pfaden, die zusaetzlich existieren
    # muessen. Ein '/' am Ende verlangt ein Verzeichnis.
    local ok_best=1 b
    IFS=',' read -ra _blist <<< "$bestaetigung"
    for b in "${_blist[@]}"; do
      b="${b// /}"; [[ -n "$b" ]] || continue
      if [[ "$b" == */ ]]; then
        [[ -d "${d}/${b%/}" ]] || { ok_best=0; break; }
      else
        [[ -f "${d}/${b}" ]] || { ok_best=0; break; }
      fi
    done
    [[ "$ok_best" -eq 1 ]] || continue

    # Sicherungskopien. Einheitlich als warn gemeldet — die Begruendung von
    # Abschnitt 12b galt immer schon fuer alle: eine Sicherung mit Schadcode
    # stellt ihn beim Zurueckspielen wieder her.
    if [[ -n "$kopien" ]] && printf '%s' "$d" | grep -qE "$kopien"; then
      uebersprungen=$((uebersprungen + 1)); continue
    fi
    gefunden+="${d}"$'\n'
  done < <(find "${SCAN_PATHS[@]}" -maxdepth "$tiefe" -name "$marker" -type f 2>/dev/null | nf_strip_self)

  # Die Zahl der uebersprungenen Kopien wird als erste Zeile MITGEGEBEN, nicht
  # in eine Variable geschrieben: die Funktion laeuft beim Aufrufer in einer
  # Klammerersetzung, also in einer Subshell, und jede dort gesetzte Variable
  # ist danach wieder weg. Genau daran ist schon einmal die Uebergabe von
  # SCAN_PATHS gescheitert — dort blieb die Eigenliste leer, und die Maskierung
  # erklaerte den eigenen Kunden zum Fremden.
  printf 'KOPIEN=%s\n' "$uebersprungen"
  printf '%s' "$gefunden" | grep -vE '^$' | sort -u || true
}

# ── Konfigurationswert lesen ─────────────────────────────────
# Ein Ausdruck statt zwei fast gleicher Funktionen. wpconf_get und jconf_get
# unterschieden sich nur in der Zielsyntax; der Kommentar in 12_joomla.sh trug
# sogar noch eine veraltete Zeilennummer auf sein Vorbild.
rezept_konf_wert() {   # rezept_konf_wert <datei> <ausdruck-mit-%s> <schluessel>
  local datei="$1" muster="$2" schluessel="$3"
  [[ -r "$datei" ]] || return 1
  # Auskommentierte Zeilen weg: sonst greift head -1 einen alten, deaktivierten
  # Wert — etwa eine Migrations-Altlast — und die Pruefung laeuft auf der
  # falschen Datenbank.
  grep -vE '^[[:space:]]*(//|#|\*|/\*)' "$datei" 2>/dev/null \
    | grep -oP "$(printf "$muster" "$schluessel")" 2>/dev/null | head -1
}

# ── Werkzeug-Probe ───────────────────────────────────────────
# Pflicht, nicht Kuer. Vor v3.11 pruefte nur Abschnitt 12c, ob das Werkzeug
# ueberhaupt antwortet; ueberall sonst galt eine leere Ausgabe als 'nichts
# gefunden' und erzeugte ein ok(). Der Rahmen zieht die Probe selbst, damit
# ein Rezept sie nicht vergessen kann.
rezept_werkzeug_bereit() {   # rezept_werkzeug_bereit <app> <kurzname> <befehl…>
  local app="$1" kurz="$2"; shift 2
  local ausgabe fehlertext
  # DER GRUND GEHOERT IN DEN BEFUND.
  #
  # Bis v3.14 wurde stderr mit 2>/dev/null verworfen. Der Befund lautete dann
  # "Werkzeug antwortet nicht verwertbar — nicht geprüft", ohne Klammer und
  # ohne Grund: die Formpruefung liest stdout, und bei einem Fehler ist stdout
  # leer. Weggeworfen wurde ausgerechnet der Satz, der die Ursache benennt —
  #   Error: This does not seem to be a WordPress installation.
  # — und damit blieb ein Ausfall der halben Pruefung monatelang unerklaert.
  #
  # stderr wird getrennt aufgefangen: die Formpruefung darf es nicht sehen
  # (eine Warnung auf stderr macht eine gute Antwort nicht ungueltig), der
  # Befund dagegen schon. EIN Aufruf, nicht zwei — die Probe laeuft je
  # Instanz, und auf einem Host mit 68 davon zaehlt das.
  local _err; _err=$(mktemp)
  ausgabe=$("$@" 2>"$_err" || true)
  fehlertext=$(cut -c1-400 "$_err" 2>/dev/null); rm -f "$_err"
  local pruefer; pruefer="$(rezept_feld "${REZEPT_DIR}/${app}" werkzeug_probe_form)"
  case "${pruefer:-json}" in
    json)    printf '%s' "$ausgabe" | python3 -c 'import json,sys;json.load(sys.stdin)' 2>/dev/null ;;
    version) [[ "$ausgabe" =~ ^[0-9]+\.[0-9]+ ]] ;;
    *)       [[ -n "$ausgabe" ]] ;;
  esac || {
    local grund
    grund=$(printf '%s' "${ausgabe:-$fehlertext}" \
            | sed 's/<br\/*>/ /g' | tr -d '\n' | cut -c1-160)
    befund_melden "$app" erkennung unklar \
      "${kurz}: Werkzeug antwortet nicht verwertbar — nicht geprüft${grund:+ (${grund})}" "$kurz" web
    return 1
  }
  return 0
}

# ── Signaturen anwenden ──────────────────────────────────────
# signaturen.tsv: muster <TAB> schwere <TAB> was_es_ist
# Die Muster leben beim Rezept, nicht im Kern. Bis v3.12 standen die
# WordPress-Muster in lib/muster.sh (also in der gemeinsamen Bibliothek),
# die Joomla- und Nextcloud-Muster dagegen inline im jeweiligen Abschnitt.
rezept_signaturen() {   # rezept_signaturen <app> <rezeptverzeichnis> <installationspfad> <kurzname>
  local app="$1" rz="$2" pfad="$3" kurz="$4"
  local tsv="${rz}/signaturen.tsv"
  [[ -r "$tsv" ]] || return 0
  local ausnahme; ausnahme="$(rezept_feld "$rz" legitim_regex)"
  local muster schwere was treffer
  while IFS=$'\t' read -r muster schwere was; do
    [[ -n "$muster" && "${muster:0:1}" != "#" ]] || continue
    treffer=$(find "$pfad" -maxdepth 6 -type f -name "$muster" 2>/dev/null \
              | { [[ -n "$ausnahme" ]] && grep -vE "$ausnahme" || cat; } | head -20 || true)
    [[ -n "$treffer" ]] || continue
    befund_melden "$app" schadcode "${schwere:-warn}" \
      "${kurz}: ${was:-bekannte Schaddatei} (${muster})" "$(printf '%s' "$treffer" | head -1)" web
    code "$treffer"
    # Nur der ERSTE Treffer steht im Befund, der Rest bisher ausschliesslich im
    # code-Block des Menschentextes. Damit war ein Signaturtreffer maschinell
    # nicht auswertbar: weder konnte befunde_details.md erklaeren, was die
    # Datei ist, noch bekam der Reparaturteil sie als Quarantaene-Kandidaten.
    # Genau der Fall aus #3 — drei wp-file-manager-Dateien standen in der
    # Quarantaenetabelle, ohne dass irgendwo stand, wozu sie dienen.
    SIGNATUR_TREFFER+="${treffer}"$'\n'
  done < "$tsv"
}

# ── Datenbankzugang ──────────────────────────────────────────
# Ein Satz Funktionen statt zweier fast gleicher. wp_sql und j_sql
# unterschieden sich nur darin, dass Joomla keinen wp-cli-Rueckfall hat; der
# Kommentar in module/12_joomla.sh trug sogar noch eine veraltete Zeilennummer
# auf sein Vorbild — ein Beleg dafuer, dass die Kopie den Bezug zum Original
# schon verloren hatte.
#
# Die Zugangsdaten kommen aus der Konfigurationsdatei der Anwendung. Welche
# Datei und welche Syntax, sagt das Rezept:
#
#   konf_datei   = wp-config.php
#   konf_muster  = define\(\s*['"]%s['"]\s*,\s*['"]\K[^'"]*
#   konf_db_name = DB_NAME
#   praefix_muster = \$table_prefix\s*=\s*['"]\K[^'"]*
rezept_db_zugang() {   # rezept_db_zugang <rezeptverzeichnis> <konfigdatei>
  local rz="$1" cfg="$2" m
  m="$(rezept_feld "$rz" konf_muster)"
  REZ_DB=$(rezept_konf_wert "$cfg" "$m" "$(rezept_feld "$rz" konf_db_name)")
  REZ_DBUSER=$(rezept_konf_wert "$cfg" "$m" "$(rezept_feld "$rz" konf_db_user)")
  REZ_DBPASS=$(rezept_konf_wert "$cfg" "$m" "$(rezept_feld "$rz" konf_db_pass)")
  REZ_DBHOST=$(rezept_konf_wert "$cfg" "$m" "$(rezept_feld "$rz" konf_db_host)")
  REZ_DBHOST="${REZ_DBHOST:-localhost}"

  # Praefix-Haertung. Der Wert wird ROH in SQL-Zeichenketten interpoliert —
  # Abschnitt 11 tat das bis v3.13 ungeprueft, Joomla haertete denselben Wert
  # seit jeher. Derselbe Angriffsweg, einmal abgedeckt und einmal nicht: wer
  # die wp-config.php schreiben kann, bekam damit beliebiges SQL in die
  # Abfragen des Pruefwerkzeugs, das als root laeuft.
  local pm; pm="$(rezept_feld "$rz" praefix_muster)"
  REZ_PFX=""
  if [[ -n "$pm" ]]; then
    REZ_PFX=$(grep -oP "$pm" "$cfg" 2>/dev/null | head -1)
  fi
  REZ_PFX="${REZ_PFX:-$(rezept_feld "$rz" praefix_vorgabe)}"
  if [[ -n "$REZ_PFX" && ! "$REZ_PFX" =~ ^[A-Za-z0-9_]+$ ]]; then
    befund_melden "$(basename "$rz")" datenbank crit \
      "${REZ_KURZ}: Tabellen-Präfix enthält unerwartete Zeichen (${REZ_PFX}) — Datenbankprüfung übersprungen, die Konfigurationsdatei ist möglicherweise manipuliert" "$cfg" web
    return 1
  fi
  [[ -n "$REZ_DB" ]]
}

# SQL ausfuehren. Drei Stufen: Plesk-Admin, Zugangsdaten der Anwendung,
# Werkzeug der Anwendung. Read-only — es werden ausschliesslich SELECTs
# gestellt, das Werkzeug veraendert nie eine Kundendatenbank.
rezept_sql() {   # rezept_sql <abfrage>
  local q="$1"
  if [[ -n "${PLESK_MYSQL_PW:-}" ]]; then
    MYSQL_PWD="$PLESK_MYSQL_PW" mysql -u admin -N -e "USE \`${REZ_DB}\`; $q" 2>/dev/null && return 0
  fi
  MYSQL_PWD="$REZ_DBPASS" mysql -h "${REZ_DBHOST%%:*}" -u "$REZ_DBUSER" -N -e "$q" "$REZ_DB" 2>/dev/null && return 0
  [[ -n "${REZ_CLI_SQL:-}" ]] && $REZ_CLI_SQL "$q" 2>/dev/null
}
