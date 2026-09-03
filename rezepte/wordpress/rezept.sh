# shellcheck shell=bash
# ============================================================
# NT-Forensik — Prüfrezept WordPress: die Haken
# ------------------------------------------------------------
# Nur das, was der Rahmen nicht kann. Finden, Kopienfilter, Selbstausschluss,
# Werkzeug-Probe, Signaturen, Datenbankzugang samt Präfix-Härtung und Verdikt
# macht lib/rezepte.sh.
#
# Ersetzt module/11_wordpress.sh (425 Zeilen). Drei Dinge, die dort fehlten,
# leistet jetzt der Rahmen — nicht dieses Rezept:
#
#   Sicherungskopien filtern   fehlte ganz
#   Selbstausschluss           fehlte
#   Präfix-Härtung             fehlte; Joomla hatte sie seit jeher
#
# Aufgerufen wird je Installation mit $REZ_PFAD, $REZ_KURZ; nach
# rezept_db_zugang zusätzlich $REZ_DB, $REZ_PFX und die Funktion rezept_sql.
# ============================================================

# wp-cli wird als Eigentümer der Installation ausgeführt (Plesk-tauglich).
_wp() {
  local owner; owner=$(datei_meta "${REZ_PFAD}/wp-config.php" eigner)
  owner="${owner%%:*}"; owner="${owner:-root}"
  als_eigentuemer "$owner" "$REZ_PHP" "$REZ_WERKZEUG" "$@" \
       --path="$REZ_PFAD" --skip-plugins --skip-themes 2>/dev/null
}
# Wie _wp, aber OHNE das stderr-Verschlucken. `wp core verify-checksums` schreibt
# seine Abweichungen (Warning:/Error:) auf stderr, nicht auf stdout — mit dem
# 2>/dev/null aus _wp kam bei jeder Installation mit Abweichungen eine LEERE
# Ausgabe zurück. rezept_kern hielt den Kern dann fälschlich für 'nicht geprüft'
# (der äußere 2>&1 lief ins Leere), die Kern-Whitelist blieb leer, und 13c/13d
# meldeten die UNVERÄNDERTE wp-includes/class-wp-simplepie-sanitize-kses.php als
# KRITISCH. Gemessen im k42-Serverlauf 03.09.2026: 19 von 23 Instanzen, deren
# einzige Abweichung ein verändertes wp-config-sample.php (Zeilenenden, #84) oder
# eine echte Core-Abweichung war — beides landete lautlos in /dev/null. #94.
_wp_err() {
  local owner; owner=$(datei_meta "${REZ_PFAD}/wp-config.php" eigner)
  owner="${owner%%:*}"; owner="${owner:-root}"
  als_eigentuemer "$owner" "$REZ_PHP" "$REZ_WERKZEUG" "$@" \
       --path="$REZ_PFAD" --skip-plugins --skip-themes
}
REZ_CLI_SQL="_wp db query --skip-column-names"

# Versionsordnung — ausschliesslich ueber den geprueften Vergleicher in
# lib/wp_schwachstellen.py (version_vergleich, gegen PHPs version_compare mit
# 30000 Faellen gegengetestet, werkzeuge/version_compare_gegentest.sh).
#
# KEINE zweite Umsetzung in Bash. Eine Ordnung, die an einer Stelle abweicht,
# meldet entweder eine Luecke, die geschlossen ist, oder schweigt zu einer, die
# offen ist — beides sieht im Bericht plausibel aus. Dieselbe Ueberlegung steht
# in lib/pruefsummen_filter.py: eine zweite Kopie ist die naechste Gelegenheit
# zum Auseinanderlaufen.
#
#   0 = $1 ist kleiner als $2
#   1 = nicht kleiner
#   2 = nicht entscheidbar (python3 oder die Bibliothek fehlt)
_ver_kleiner() {   # _ver_kleiner <a> <b>
  [[ "$1" == "$2" ]] && return 1
  command -v python3 >/dev/null 2>&1 || return 2
  [[ -r "${SELF_DIR:-.}/lib/wp_schwachstellen.py" ]] || return 2
  python3 - "${SELF_DIR:-.}/lib" "$1" "$2" <<'PY'
import sys
sys.path.insert(0, sys.argv[1])
from wp_schwachstellen import version_vergleich
sys.exit(0 if version_vergleich(sys.argv[2], sys.argv[3]) < 0 else 1)
PY
}

# ── Abgleich gegen bekannte Schwachstellen ───────────────────
# Der Bestand liegt offline unter daten/ dieses Rezepts, der Vergleich in
# lib/wp_schwachstellen.py. Kein Netzzugriff, kein --online: was hier geprueft
# wird, steht im ausgelieferten Datenbestand.
#
# Fassungen kommen aus Kopfzeilen im Dateisystem, NICHT aus der Datenbank und
# nicht ueber wp-cli. Zwei Gruende: ein manipuliertes Plugin nimmt sich ueber
# den all_plugins-Filter selbst aus jeder Laufzeitliste, und der Abgleich soll
# auch dort etwas sagen, wo wp-cli fehlt.
#
# NICHT aus readme.txt: der dortige 'Stable tag' ist die im Verzeichnis als
# stabil markierte Fassung, nicht die installierte.
_wp_kopf_version() {   # $1 = Datei, $2 = Kennzeichen das vorkommen muss
  grep -qiE "^[[:space:]]*\*?[[:space:]]*${2}[[:space:]]*:" "$1" 2>/dev/null || return 1
  sed -nE 's/^[[:space:]]*\*?[[:space:]]*[Vv]ersion[[:space:]]*:[[:space:]]*([^[:space:]]+).*/\1/p' \
      "$1" 2>/dev/null | head -1
}

# Bestandsliste erheben: typ<TAB>slug<TAB>version
_wp_bestand() {
  local d f ver

  # Kern aus wp-includes/version.php. Das ist die Fassung, die laeuft — die
  # Werkzeug-Probe des Rahmens laeuft erst spaeter und koennte fehlen.
  if [[ -f "${REZ_PFAD}/wp-includes/version.php" ]]; then
    ver=$(sed -nE "s/^[[:space:]]*\\\$wp_version[[:space:]]*=[[:space:]]*'([^']+)'.*/\\1/p" \
          "${REZ_PFAD}/wp-includes/version.php" 2>/dev/null | head -1)
    [[ -n "$ver" ]] && printf 'core\twordpress\t%s\n' "$ver"
  fi

  # Was ein Plugin IST, entscheidet der Kopf, nicht das Verzeichnis (#39).
  # Chronosly legt Daten- und Vorlagenordner neben sein Plugin — einer ohne
  # jede PHP-Datei, einer mit PHP nur in Unterordnern (inhaltlich JSON, ohne
  # Kopf). WordPress fuehrt beide in keiner Pluginliste; dieses Werkzeug
  # zaehlte sie als Plugin, und der Bericht wies "2 Plugin(s) ohne
  # Pruefsummensatz" auf einer Installation aus, die KEIN echtes Plugin ohne
  # Pruefsummensatz hatte. 12 % "nicht bewertbar" als Artefakt — die Sorte
  # Zahl, die beim naechsten Mal achselzuckend uebergangen wird.
  #
  # Kriterium: ein 'Plugin Name:'-Kopf irgendwo im Verzeichnis. Der billige
  # Griff (oberste Ebene, wie bisher) zuerst; nur wenn dort kein Kopf liegt,
  # der teure rekursive — er trifft damit nur die Ausnahmen, nicht die 345
  # Dateien eines gepflegten Plugins.
  #
  # Verzeichnisse ohne Kopf gehen als eigene Zeilenart 'keinplugin' in den
  # Strom, mit dem Vermerk, ob PHP darin liegt. NICHT stillschweigend weg:
  # ein kopfloses Verzeichnis mit PHP unter plugins/ kann eine
  # Angreifer-Ablage sein. Der Aufrufer macht daraus einen sichtbaren
  # Hinweis — nur eben ausserhalb der Angreifbarkeitsbilanz. (Nebenwirkungen
  # hier druin waeren verloren: _wp_bestand laeuft in Kommandosubstitution.)
  local kopf v
  for d in "${REZ_PFAD}"/wp-content/plugins/*/; do
    [[ -d "$d" ]] || continue
    d="${d%/}"; ver=""; kopf=""
    for f in "$d"/*.php; do
      [[ -f "$f" ]] || continue
      if v=$(_wp_kopf_version "$f" "Plugin Name"); then
        kopf="${kopf:-$f}"
        # Wie bisher: die erste Datei, die Kopf UND Fassung traegt, gewinnt.
        # Eine mit Kopf ohne Fassung bleibt Rueckfalloption.
        [[ -n "$v" ]] && { ver="$v"; kopf="$f"; break; }
      fi
    done
    if [[ -z "$kopf" ]]; then
      kopf=$(grep -rliE --include='*.php' \
             '^[[:space:]]*\*?[[:space:]]*Plugin Name[[:space:]]*:' "$d" 2>/dev/null | head -1)
      [[ -n "$kopf" ]] && ver=$(_wp_kopf_version "$kopf" "Plugin Name")
    fi
    if [[ -n "$kopf" ]]; then
      printf 'plugin\t%s\t%s\n' "$(basename "$d")" "$ver"
    else
      local _php=""
      [[ -n "$(find "$d" -type f -name '*.php' -print 2>/dev/null | head -1)" ]] && _php="php"
      printf 'keinplugin\t%s\t%s\n' "$(basename "$d")" "$_php"
    fi
  done

  # Themes tragen ihre Fassung in style.css.
  for d in "${REZ_PFAD}"/wp-content/themes/*/; do
    [[ -d "$d" ]] || continue
    d="${d%/}"; ver=""
    [[ -f "$d/style.css" ]] && ver=$(_wp_kopf_version "$d/style.css" "Theme Name")
    printf 'theme\t%s\t%s\n' "$(basename "$d")" "${ver:-}"
  done

  # Composer-Abhaengigkeiten der Plugins (#14). Der Abgleich erfasste bis
  # v3.12 Kern, Plugins und Themes — NICHT die Bibliotheken, die ein Plugin in
  # seinem vendor/ mitbringt. Dort steckt regelmaessig fremder Code mit eigenen
  # Luecken: Guzzle, PHPMailer, Monolog und Aehnliches.
  _wp_composer_bestand
}

# Installierte Composer-Pakete aus vendor/composer/installed.json.
#
# NICHT aus composer.lock: die Lock-Datei sagt, was installiert werden SOLL.
# installed.json sagt, was tatsaechlich liegt — und genau danach wird gefragt.
# Beide Formate kommen vor: bis Composer 1 eine blanke Liste, ab Composer 2 ein
# Objekt mit "packages".
_wp_composer_bestand() {
  werkzeug_da python3 || return 0
  # Ohne Datenbestand gar nicht erst erheben. Sonst kaeme jedes Paket als
  # UNBEWERTBAR zurueck ("kein Datenbestand fuer diesen Typ") — auf einer
  # echten Installation sind das schnell hundert ⚪ je Instanz, und der vierte
  # Zustand wird zu Rauschen, das niemand mehr liest. Genau davor warnt der
  # Kommentar zum Sammel-⚪ weiter unten.
  local basis="${WP_DATEN_DIR:-${REZEPT_DIR}/wordpress/daten}"
  [[ -d "${basis}/vuln/composer" ]] || return 0
  local d
  for d in "${REZ_PFAD}"/wp-content/plugins/*/vendor/composer/installed.json \
           "${REZ_PFAD}"/wp-content/mu-plugins/*/vendor/composer/installed.json; do
    [[ -f "$d" ]] || continue
    python3 "${SELF_DIR:-.}/lib/composer_bestand.py" "$d" 2>/dev/null || true
  done
}

rezept_version() {
  # WP_DATEN_DIR erlaubt einen Bestand ausserhalb der Installation. Gebraucht
  # wird das vom Pruefstand, der einen eigenen, kleinen Bestand einspeist —
  # ohne ihn koennte er den Trefferpfad dieser Pruefung nie ueben, und eine
  # Pruefung ohne Abdeckung ist genau die Sorte, die unbemerkt kaputtgeht.
  # Im Betrieb ebenso brauchbar, wenn mehrere Installationen sich einen
  # gepflegten Bestand teilen sollen.
  local basis="${WP_DATEN_DIR:-${REZEPT_DIR}/wordpress/daten}"
  local vergleicher="${SELF_DIR:-.}/lib/wp_schwachstellen.py"
  local bestand ergebnis n_betroffen n_unbewertbar alter

  if ! werkzeug_da python3; then
    befund_melden wordpress version unklar \
      "${REZ_KURZ}: python3 fehlt — Abgleich gegen bekannte Schwachstellen nicht möglich" "$REZ_PFAD" web
    return 0
  fi
  if [[ ! -r "$vergleicher" ]]; then
    befund_melden wordpress version unklar \
      "${REZ_KURZ}: lib/wp_schwachstellen.py fehlt in der Installation — Abgleich nicht möglich" "$REZ_PFAD" web
    return 0
  fi

  # Kein Datenbestand: Hinweis, kein ⚪. Es wurde nichts gemessen und nichts
  # versucht — derselbe Fall wie ein abgeschalteter YARA-Scan. Ein ⚪ waere
  # hier zwar streng, wuerde aber auf JEDEM Lauf stehen, solange der Bestand
  # nicht erzeugt ist, und damit zu Rauschen. Sobald ein Bestand da ist,
  # entscheidet sein Alter (unten) wieder ueber ⚪.
  # Geprueft wird auf DATENZEILEN, nicht auf Dateien. Eine Tabelle, die nur aus
  # Kopfzeilen besteht, ist kein Bestand — sie sieht aber wie einer aus, und
  # der Vergleich liefe dann gegen nichts: jedes Plugin kaeme als SAUBER
  # zurueck ("keine bekannte Schwachstelle im vorliegenden Bestand"), also als
  # stille Entwarnung. Genau so lagen die Dateien nach einem Testlauf im
  # Repository, bevor es auffiel.
  if ! grep -rhv '^#' "${basis}"/vuln/*.tsv 2>/dev/null | grep -q .; then
    # Einmal je Lauf, nicht je Installation: die Aussage gilt global, und auf
    # einem Server mit vierzig Instanzen waeren vierzig gleiche Zeilen nur
    # Rauschen. Die Variable ueberlebt die Schleife — der Rahmen zieht nur
    # Funktionen zurueck, keine Variablen.
    if [[ -z "${WP_DATEN_GEMELDET:-}" ]]; then
      info "Kein WordPress-Schwachstellen-Datenbestand vorhanden — Abgleich übersprungen (werkzeuge/wordpress-daten-update.sh)"
      WP_DATEN_GEMELDET=1
    fi
    return 0
  fi

  # Ein veralteter Bestand ist gefaehrlicher als gar keiner: er liefert ein
  # ruhiges Ergebnis, das nach Pruefung aussieht. Deshalb ⚪ statt Hinweis.
  if [[ -f "${basis}/VERSION" ]]; then
    local stand; stand=$(sed -nE 's/^([0-9]{4}-[0-9]{2}-[0-9]{2}).*/\1/p' "${basis}/VERSION" | head -1)
    if [[ -n "$stand" ]]; then
      alter=$(( ( $(date -u +%s) - $(date -u -d "$stand" +%s 2>/dev/null \
                    || date -u -j -f %Y-%m-%d "$stand" +%s 2>/dev/null || echo 0) ) / 86400 ))
      if [[ "${alter:-0}" -gt "${WP_DATEN_MAX_TAGE:-30}" ]]; then
        befund_melden wordpress version unklar \
          "${REZ_KURZ}: Schwachstellen-Datenbestand ist ${alter} Tage alt — Ergebnis nicht belastbar, Bestand erneuern" "$REZ_PFAD" web
        return 0
      fi
    fi
  fi

  bestand=$(_wp_bestand)
  [[ -n "$bestand" ]] || return 0

  # Verzeichnisse ohne Plugin-Kopf aus dem Strom nehmen, BEVOR der
  # Vergleicher sie als UNBEWERTBAR in die Bilanz zieht (#39) — und sichtbar
  # melden statt stillschweigend wegzufiltern. Zwei Lagen, zwei Gewichte:
  # ohne jede PHP-Datei ist es ein Datenordner (Hinweis); mit PHP-Dateien,
  # aber ohne Kopf, kann es eine Angreifer-Ablage sein (sichten).
  local keinplugin kp_php kp_ohne
  keinplugin=$(printf '%s\n' "$bestand" | awk -F'\t' '$1=="keinplugin"')
  bestand=$(printf '%s\n' "$bestand" | awk -F'\t' '$1!="keinplugin"')
  if [[ -n "$keinplugin" ]]; then
    kp_php=$(printf '%s\n' "$keinplugin"  | awk -F'\t' '$3=="php"{print $2}')
    kp_ohne=$(printf '%s\n' "$keinplugin" | awk -F'\t' '$3!="php" && NF{print $2}')
    if [[ -n "$kp_php" ]]; then
      befund_melden wordpress version warn \
        "${REZ_KURZ}: $(printf '%s\n' "$kp_php" | grep -c .) Verzeichnis(se) unter plugins/ mit PHP-Dateien, aber ohne Plugin-Kopf — kein Plugin; kann eine Angreifer-Ablage sein, sichten" "$REZ_PFAD" web
      evidence "wp_plugins_ohne_kopf_mit_php_$(echo "$REZ_KURZ" | tr '/.' '__')" \
               "$(printf '%s\n' "$kp_php" | sed "s|^|${REZ_PFAD}/wp-content/plugins/|")"
    fi
    if [[ -n "$kp_ohne" ]]; then
      info "${REZ_KURZ}: $(printf '%s\n' "$kp_ohne" | grep -c .) Verzeichnis(se) unter plugins/ ohne jede PHP-Datei — Datenordner, kein Plugin, nicht in der Angreifbarkeitsbilanz"
      evidence "wp_plugins_datenordner_$(echo "$REZ_KURZ" | tr '/.' '__')" \
               "$(printf '%s\n' "$kp_ohne" | sed "s|^|${REZ_PFAD}/wp-content/plugins/|")"
    fi
  fi
  [[ -n "$bestand" ]] || return 0

  ergebnis=$(printf '%s\n' "$bestand" | python3 "$vergleicher" --daten "$basis" 2>/dev/null || true)
  [[ -n "$ergebnis" ]] || return 0

  # Betroffene einzeln melden — anders als beim ⚪ unten ist hier jeder Fall
  # eine eigene Handlung: dieses Plugin auf diese Fassung bringen.
  # TAB IST IN BASH EIN IFS-WHITESPACE-ZEICHEN.
  #
  # Auch wenn IFS nur auf Tab steht, gilt eine Folge von Tabs als EIN Trenner.
  # Leere Mittelfelder verschwinden damit, und alles dahinter rutscht nach
  # links. Bei einem Datensatz ohne behobene Fassung (26 % des Bestandes) stand
  # deshalb im Bericht die Quell-URL an der Stelle der CVE-Nummer und die
  # CVE-Nummer hinter "behoben in".
  #
  # Der Prüfbaum konnte das nicht sehen: seine Fixture-Zeilen führen in jedem
  # Feld einen Wert. Gefunden hat es der erste Lauf gegen eine echte
  # Installation.
  #
  # Unit Separator (0x1f) ist kein Whitespace — dort bleiben leere Felder
  # erhalten.
  while IFS=$'\x1f' read -r zustand typ slug version bereich behoben cve kev _quelle; do
    [[ "$zustand" == "BETROFFEN" ]] || continue
    # "composer guzzlehttp/guzzle" liest sich fuer einen Kunden wie ein
    # Werkzeugname. Gemeint ist eine Programmbibliothek, die ein Plugin
    # mitbringt — das gehoert so dazustehen.
    local _art="$typ"; [[ "$typ" == "composer" ]] && _art="Bibliothek (in einem Plugin)"
    local satz="${REZ_KURZ}: ${_art} ${slug} ${version} ist von einer bekannten Schwachstelle betroffen (${bereich})"
    [[ -n "$cve" ]]     && satz+=" ${cve}"
    [[ -n "$behoben" ]] && satz+=" — behoben in ${behoben}"
    if [[ "$kev" == "ja" ]]; then
      befund_melden wordpress version crit \
        "${satz}. Diese Lücke wird nachweislich aktiv ausgenutzt — sofort handeln." "$REZ_PFAD" web
    else
      befund_melden wordpress version warn "${satz}." "$REZ_PFAD" web
    fi
  done <<< "${ergebnis//$'\t'/$'\x1f'}"

  n_betroffen=$(printf '%s\n' "$ergebnis" | grep -c '^BETROFFEN' || true)
  n_unbewertbar=$(printf '%s\n' "$ergebnis" | grep -c '^UNBEWERTBAR' || true)

  # Nicht bewertbares zu EINEM ⚪ zusammengefasst. Ein Plugin ohne lesbare
  # Fassung gibt es auf fast jeder Seite; ein ⚪ je Stueck wuerde die
  # Kundenampel dauerhaft blockieren und den vierten Zustand zu Rauschen
  # machen, das niemand mehr liest.
  if [[ "${n_unbewertbar:-0}" -gt 0 ]]; then
    befund_melden wordpress version unklar \
      "${REZ_KURZ}: ${n_unbewertbar} Bestandteil(e) ohne lesbare Fassung — für sie ist keine Aussage zur Angreifbarkeit möglich" "$REZ_PFAD" web
    evidence "wp_version_nicht_bewertbar_$(echo "$REZ_KURZ" | tr '/.' '__')" \
             "$(printf '%s\n' "$ergebnis" | grep '^UNBEWERTBAR')"
  fi

  if [[ "${n_betroffen:-0}" -eq 0 ]]; then
    befund_melden wordpress version ok \
      "${REZ_KURZ}: keine bekannte Schwachstelle im vorliegenden Datenbestand (Stand $(sed -n '1s/ .*//p' "${basis}/VERSION" 2>/dev/null))" "$REZ_PFAD"
  else
    evidence "wp_schwachstellen_$(echo "$REZ_KURZ" | tr '/.' '__')" "$ergebnis"
  fi
}

# ── Plugin-Integrität gegen die Prüfsummen von wordpress.org ─
# Das Gegenstück zu verify-checksums für den Kern, nur für Plugins. Es findet
# VERÄNDERTE Dateien statt veralteter Fassungen — für eine Forensik die
# stärkere Aussage: eine alte Version ist ein Risiko, eine veränderte
# Plugin-Datei ist ein Befund.
#
# Warum nicht `wp plugin verify-checksums`: das Kommando zählt die Plugins über
# die WordPress-Laufzeit auf, und genau darüber nimmt sich ein manipuliertes
# Plugin per all_plugins-Filter selbst aus der Prüfung — derselbe Grund, aus
# dem rezept_version die Fassungen aus Kopfzeilen liest. Ausserdem deckt es
# weder mu-Plugins (checksum-command #27) noch Themes ab und gibt die
# Prüfsummendatei nicht als Beleg heraus.
#
# Nur mit --online: je Plugin ein Abruf. Protokolliert über nf_fetch, damit in
# findings.json steht, gegen welchen Stand geprüft wurde.

# Woher die Prüfsummen kommen. Vorgabe ist wordpress.org; ein lokaler Pfad
# ersetzt den Abruf durch ein Nachschlagen unter <basis>/<slug>/<fassung>.json.
# Der Prüfstand nutzt das — anders liesse sich diese Prüfung nur mit
# Netzzugriff in der CI abdecken, und ein Prüfstand, der von der Erreichbarkeit
# eines fremden Dienstes abhängt, misst irgendwann dessen Ausfälle statt des
# Werkzeugs.
WP_PRUEFSUMMEN_BASIS="${WP_PRUEFSUMMEN_BASIS:-https://downloads.wordpress.org/plugin-checksums}"

_wp_pruefsummen_aus_netz() {
  [[ "$WP_PRUEFSUMMEN_BASIS" == http*://* ]]
}

_wp_pruefsummen_holen() {   # <slug> <fassung> <zieldatei>
  if _wp_pruefsummen_aus_netz; then
    nf_fetch "${WP_PRUEFSUMMEN_BASIS}/$1/$2.json" "$3"
  else
    local quelle="${WP_PRUEFSUMMEN_BASIS}/$1/$2.json"
    [[ -s "$quelle" ]] || return 1
    cp "$quelle" "$3" 2>/dev/null
  fi
}

_wp_plugin_integritaet() {
  local cache liste ergebnis slug ver ziel pdir
  local n_mod n_soft n_extra n_fehlt n_geprueft n_ohne
  # Je Instanz, nicht ueber den ganzen Lauf: der Beleg heisst
  # wp_ohne_pruefsummen_<instanz>, und ein Beleg mit dem Namen einer Instanz
  # darf nicht die Plugins der vorherigen enthalten. Der erste Entwurf liess
  # die Liste mitwachsen — jeder Beleg war dadurch eine Obermenge des
  # vorigen, und die Zuordnung Plugin -> Installation war dahin.
  local OHNE_SATZ=""

  cache="${RUN_DIR}/.online/plugin-checksums"
  mkdir -p "$cache"
  liste=$(mktemp "${RUN_DIR}/.wpint.XXXXXX")
  n_ohne=0

  # Bestandsliste kommt aus rezept_version — dieselbe Erhebung, dieselbe
  # Disziplin bei der Fassung. Themes bleiben aussen vor: für sie
  # veröffentlicht wordpress.org keine Prüfsummen (theme-checksums → HTTP 404,
  # nachgeprüft 06.08.2026).
  while IFS=$'\t' read -r typ slug ver; do
    [[ "$typ" == "plugin" ]] || continue
    pdir="${REZ_PFAD}/wp-content/plugins/${slug}"
    [[ -d "$pdir" ]] || continue
    if [[ -z "$ver" ]]; then
      n_ohne=$((n_ohne+1))
      OHNE_SATZ+="${REZ_KURZ}"$'\t'"${slug}"$'\t'"(keine Fassung lesbar)"$'\n'
      continue
    fi
    ziel="${cache}/${slug}-${ver}.json"
    if [[ ! -s "$ziel" ]] && ! _wp_pruefsummen_holen "$slug" "$ver" "$ziel"; then
      rm -f "$ziel"
      # Kein Prüfsummensatz. Zwei Ursachen, hier nicht unterscheidbar: das
      # Plugin liegt nicht im wordpress.org-Verzeichnis (Premium, Fork,
      # Eigenbau), oder die Fassung ist dort nicht veröffentlicht.
      #
      # Der NAME wird mitgeschrieben, nicht nur gezählt. Die Frage "für welche
      # Plugins brauchen wir Hersteller-Archive" (#30) liess sich sonst nur aus
      # der Erinnerung beantworten — und genau diese Plugins sind die lautesten
      # Fundorte des Rauschfilters in 13c, weil er sie nicht erreicht.
      n_ohne=$((n_ohne+1))
      OHNE_SATZ+="${REZ_KURZ}"$'\t'"${slug}"$'\t'"${ver}"$'\n'
      continue
    fi
    printf '%s\t%s\t%s\t%s\n' "$slug" "$ver" "$pdir" "$ziel" >> "$liste"
  done <<< "$(_wp_bestand)"

  if [[ ! -s "$liste" ]]; then
    rm -f "$liste"
    [[ "$n_ohne" -gt 0 ]] && befund_melden wordpress kern unklar \
      "${REZ_KURZ}: ${n_ohne} Plugin(s) ohne Prüfsummensatz bei wordpress.org — Unversehrtheit nicht feststellbar" "$REZ_PFAD" web
    return 0
  fi

  ergebnis=$(python3 - "$liste" <<'PY' 2>/dev/null || true
import hashlib, json, os, sys

# Als Code gewertete Endungen. Eine Abweichung darin ist eine Codeaenderung am
# ausgelieferten Plugin und damit kritisch; alles andere (readme.txt,
# Uebersetzungen, Stilvorlagen, Bilder) ist eine weiche Abweichung. wp-cli
# zieht dieselbe Grenze ueber seinen --strict-Schalter.
CODE = {".php", ".phtml", ".php5", ".php7", ".inc", ".js", ".mjs"}

def passt(soll, ist_md5, ist_sha):
    # Das Format erlaubt je Datei MEHRERE gueltige Pruefsummen (Whitelist).
    # Ein 1:1-Vergleich wuerde hier Falsch-Positive erzeugen.
    for schluessel, ist in (("md5", ist_md5), ("sha256", ist_sha)):
        wert = soll.get(schluessel)
        if wert is None:
            continue
        kandidaten = wert if isinstance(wert, list) else [wert]
        if any(str(k).lower() == ist for k in kandidaten):
            return True
    return False

for zeile in open(sys.argv[1], encoding="utf-8", errors="replace").read().splitlines():
    teile = zeile.split("\t")
    if len(teile) != 4:
        continue
    slug, ver, pdir, jsondatei = teile
    try:
        with open(jsondatei, encoding="utf-8", errors="replace") as fh:
            soll_dateien = (json.load(fh) or {}).get("files") or {}
    except Exception:
        print("\t".join(["OHNE", slug, ver, "Pruefsummendatei nicht lesbar"]))
        continue
    if not soll_dateien:
        print("\t".join(["OHNE", slug, ver, "Pruefsummendatei ohne Dateiliste"]))
        continue

    gesehen = set()
    for wurzel, _dirs, dateien in os.walk(pdir):
        for name in dateien:
            voll = os.path.join(wurzel, name)
            if os.path.islink(voll):
                continue
            rel = os.path.relpath(voll, pdir)
            gesehen.add(rel)
            soll = soll_dateien.get(rel)
            if soll is None:
                # Nicht im Pruefsummensatz. Nur PHP ist erwaehnenswert — alles
                # andere sind ueberwiegend Zwischenspeicher und Protokolle.
                if os.path.splitext(name)[1].lower() in CODE:
                    print("\t".join(["EXTRA", slug, ver, rel]))
                continue
            try:
                with open(voll, "rb") as fh:
                    roh = fh.read()
            except Exception:
                continue
            if not passt(soll, hashlib.md5(roh).hexdigest(),
                               hashlib.sha256(roh).hexdigest()):
                art = "MOD" if os.path.splitext(name)[1].lower() in CODE else "SOFT"
                print("\t".join([art, slug, ver, rel]))
            else:
                # Bestaetigt unveraendert gegenueber wordpress.org. Bisher fiel
                # dieser Fall stillschweigend durch — gezaehlt wurde nur, was
                # ABWEICHT. Die Bestaetigung ist aber ihrerseits eine Aussage:
                # eine Datei, die Byte fuer Byte dem Original entspricht, kann
                # kein untergeschobener Schadcode sein. Abschnitt 13c filtert
                # damit das Rauschen des fremden Regelsatzes (#18).
                # Nur Code-Endungen: Bilder und Uebersetzungen tauchen in
                # keiner Trefferliste auf, und die Liste bliebe sonst
                # zehnmal so lang.
                if os.path.splitext(name)[1].lower() in CODE:
                    print("\t".join(["UNVERAENDERT", slug, ver, voll]))

    for rel in sorted(set(soll_dateien) - gesehen):
        print("\t".join(["FEHLT", slug, ver, rel]))

    print("\t".join(["GEPRUEFT", slug, ver, str(len(soll_dateien))]))
PY
  )
  rm -f "$liste"

  # Die bestätigt unveränderten Dateien in die Whitelist für Abschnitt 13c
  # (#18). Bewusst in eine DATEI und nicht in eine Variable: auf einem Server
  # mit 68 Installationen sind das leicht 100.000 Zeilen, und eine
  # Shell-Variable dieser Größe wird bei jeder Zuweisung kopiert.
  # Der Ablageort liegt im Laufordner, aber weder in kunde/ noch in betreiber/
  # — er ist Arbeitsmaterial, kein Beleg, und wandert in kein Archiv.
  printf '%s\n' "$ergebnis" | awk -F'\t' '$1=="UNVERAENDERT"{print $4}' \
    >> "${PRUEFSUMMEN_WHITELIST:-${RUN_DIR}/.pruefsummen_bestaetigt.txt}"

  n_geprueft=$(printf '%s\n' "$ergebnis" | grep -c '^GEPRUEFT' || true)
  n_mod=$(printf   '%s\n' "$ergebnis" | grep -c '^MOD'   || true)
  n_soft=$(printf  '%s\n' "$ergebnis" | grep -c '^SOFT'  || true)
  n_extra=$(printf '%s\n' "$ergebnis" | grep -c '^EXTRA' || true)
  n_fehlt=$(printf '%s\n' "$ergebnis" | grep -c '^FEHLT' || true)
  n_ohne=$((n_ohne + $(printf '%s\n' "$ergebnis" | grep -c '^OHNE' || true)))

  local basis="${REZ_PFAD}/wp-content/plugins/"
  if [[ "${n_mod:-0}" -gt 0 ]]; then
    local mods; mods=$(printf '%s\n' "$ergebnis" | awk -F'\t' -v p="$basis" '$1=="MOD"{print p $2 "/" $4}')
    befund_melden wordpress kern crit \
      "${REZ_KURZ}: ${n_mod} veränderte Plugin-Codedatei(en) gegenüber wordpress.org — Plugin neu installieren, Dateien vorher sichern" \
      "$(printf '%s\n' "$mods" | head -1)" web
    code "$(printf '%s\n' "$mods" | head -30)"
    evidence "wp_plugin_veraendert_$(echo "$REZ_KURZ" | tr '/.' '__')" "$mods"
    PLUGIN_VERAENDERT+="$mods"$'\n'
  elif [[ "${n_geprueft:-0}" -gt 0 ]]; then
    befund_melden wordpress kern ok \
      "${REZ_KURZ}: ${n_geprueft} Plugin(s) gegen wordpress.org geprüft — keine veränderte Codedatei" "$REZ_PFAD"
  fi

  # Beide Befunde mit Beleg (#40). Sie standen als nackte Zahl im Bericht —
  # und genau die fehlenden Dateien waren Messpunkt 3 aus #9. Ohne die Pfade
  # laesst sich nicht beurteilen, ob es harmlos ist (entfernte Sprachdateien,
  # abgespeckte Auslieferung) oder ob jemand Dateien geloescht hat. Ein
  # Befund, der eine Handlung fordert, muss liefern, was man dazu braucht.
  if [[ "${n_soft:-0}" -gt 0 ]]; then
    befund_melden wordpress kern warn \
      "${REZ_KURZ}: ${n_soft} veränderte Nicht-Codedatei(en) in Plugins (readme, Übersetzungen, Stilvorlagen) — meist harmlos" "$REZ_PFAD"
    evidence "wp_plugin_nichtcode_veraendert_$(echo "$REZ_KURZ" | tr '/.' '__')" \
             "$(printf '%s\n' "$ergebnis" | awk -F'\t' -v p="$basis" '$1=="SOFT"{print p $2 "/" $4}')"
  fi

  if [[ "${n_fehlt:-0}" -gt 0 ]]; then
    befund_melden wordpress kern warn \
      "${REZ_KURZ}: ${n_fehlt} im Prüfsummensatz geführte Plugin-Datei(en) fehlen auf der Platte" "$REZ_PFAD"
    evidence "wp_plugin_fehlt_$(echo "$REZ_KURZ" | tr '/.' '__')" \
             "$(printf '%s\n' "$ergebnis" | awk -F'\t' -v p="$basis" '$1=="FEHLT"{print p $2 "/" $4}')"
  fi

  # Zusätzliche PHP-Dateien: vorerst nur Beleg. Plugins legen auch legitim PHP
  # an (Zwischenspeicher, index.php-Wachen); erst nach Messung an echten
  # Installationen entscheiden, ob daraus eine Warnung wird.
  if [[ "${n_extra:-0}" -gt 0 ]]; then
    info "${REZ_KURZ}: ${n_extra} PHP-Datei(en) in Plugin-Ordnern ohne Eintrag im Prüfsummensatz — Übersicht im Beleg"
    evidence "wp_plugin_zusatz_php_$(echo "$REZ_KURZ" | tr '/.' '__')" \
             "$(printf '%s\n' "$ergebnis" | awk -F'\t' '$1=="EXTRA"{print $2 "/" $4}')"
  fi

  # Nicht Prüfbares zu EINEM ⚪ — je Plugin würde das die Kundenampel auf fast
  # jeder Seite dauerhaft blockieren. Themes stehen mit drin, weil es für sie
  # überhaupt keine Prüfsummenquelle gibt.
  if [[ "${n_ohne:-0}" -gt 0 ]]; then
    befund_melden wordpress kern unklar \
      "${REZ_KURZ}: ${n_ohne} Plugin(s) ohne Prüfsummensatz und alle Themes — Unversehrtheit nicht feststellbar (Premium, Fork, Eigenbau; für Themes veröffentlicht wordpress.org keine Prüfsummen)" "$REZ_PFAD" web
    # Die Namen in einen Beleg. Ein Sammel-⚪ sagt, WIEVIELE nicht prüfbar
    # sind; für die Frage, welche Hersteller-Archive beschafft werden müssen
    # (#30), braucht es WELCHE. Die Zahl allein hat diese Frage bisher
    # unbeantwortbar gemacht.
    evidence "wp_ohne_pruefsummen_$(echo "$REZ_KURZ" | tr '/.' '__')" \
             "$(printf '%s' "$OHNE_SATZ" | LC_ALL=C sort -u)" kunde
  fi

  # Ausdrücklich 0: die Funktion endet sonst auf dem Rückgabewert des letzten
  # Tests und meldete auf der ERFOLGSBAHN eine 1, wenn nichts unbewertbar war.
  # Heute liest das niemand aus; wer den Aufruf später verkettet, hätte einen
  # Fehler, der nur bei sauberen Installationen auftritt.
  return 0
}

# ── Kern-Integrität und die Doorway-Familie ──────────────────
# Der Signatur-Webshell-Scan übersieht goto-obfuskierte Doorways, als Nicht-PHP
# getarnte Nutzlasten und @include-Injektionen. verify-checksums plus
# Doorway-Signatur decken die Familie auf.
#
# Der Aufruf läuft über _wp_err (nicht _wp): verify-checksums schreibt seine
# Abweichungen auf stderr, das _wp verschluckt hätte. Damit heißt eine LEERE
# Ausgabe hier jetzt wirklich 'wp-cli ist gescheitert' — bei Abweichungen steht
# der Grund in CHK_ROH, bei sauberem Kern die Success-Zeile (#94).
rezept_kern() {
  local CHK cmod csne LISTE CHK_ROH CHK_RC
  # Rückgabewert getrennt festhalten. Bis v3.12 stand hier nur die gefilterte
  # Ausgabe, und der Status der Pipe war der von `grep` — ein gescheitertes
  # verify-checksums war damit von einem sauberen Kern nicht zu unterscheiden.
  # Für den Befund unten machte das keinen Unterschied (beides ergab cmod=0,
  # was hier bewusst als "keine Abweichung" gilt), für die Whitelist in
  # Abschnitt 13c aber sehr wohl: sie darf einen Kern nur dann freigeben, wenn
  # er nachweislich geprüft WURDE.
  CHK_ROH=$(_wp_err core verify-checksums 2>&1); CHK_RC=$?
  CHK=$(printf '%s\n' "$CHK_ROH" | grep "Warning:" || true)
  # KEIN '|| echo 0': grep -c gibt bei null Treffern bereits eine 0 aus UND
  # endet ungleich 0. Der Rueckfall haengte damit eine zweite Null an, cmod
  # wurde "0\n0", und die naechste Zeile brach mit
  #   [[: 0 0: syntax error in expression
  # ab. Genau derselbe Fehler steckte in nf_fetch ("HTTP=404000").
  cmod=$(echo "$CHK" | grep -c "doesn.t verify" 2>/dev/null) || true
  csne=$(echo "$CHK" | grep -c "should not exist" 2>/dev/null) || true

  if [[ "${cmod:-0}" -gt 0 ]]; then
    LISTE=$(echo "$CHK" | grep "doesn.t verify" | sed "s|.*checksum: |${REZ_PFAD}/|")
    befund_melden wordpress kern crit "${REZ_KURZ}: ${cmod} veränderte Core-Datei(en) — Injektion oder Manipulation" "$REZ_PFAD" web
    code "$(echo "$LISTE" | head -30)"
    evidence "wp_core_veraendert_$(echo "$REZ_KURZ" | tr '/.' '__')" "$LISTE"
    CORE_INJECTED+="$LISTE"$'\n'
  elif [[ -z "$CHK_ROH" ]]; then
    # KEINE AUSGABE HEISST NICHT "SAUBER".
    #
    # Ein bestandener Lauf sagt "Success: WordPress installation verifies
    # against checksums.", ein Fehlschlag sagt "Error: …". Beides steht in
    # CHK_ROH, weil 2>&1 umgeleitet wird. Kommt GAR NICHTS zurück, hat das
    # Kommando nicht geantwortet — abgebrochen, ohne Speicher, ohne Netz zum
    # Prüfsummendienst, vom Hoster abgeschossen.
    #
    # Bis hierher fiel dieser Fall in den else-Zweig und ergab die Zeile
    # "WordPress-Core unverändert (verify-checksums)". Auf kundenserver42
    # betraf das 12 von 121 Instanzen: gruener Satz im Kundenbericht, obwohl
    # die Pruefung nie stattgefunden hat.
    #
    # Die zweite Haelfte des Schadens steht weiter unten: ohne Ausgabe gibt es
    # auch keinen Whitelist-Eintrag, und ohne den entlastet 13c die Kern-
    # Dateien dieser Instanz nicht. Der Lauf meldete also gleichzeitig "Kern
    # unveraendert" UND fuehrte Kern-Dateien als Fund. Beides aus derselben
    # Wurzel, und beides sah plausibel aus.
    #
    # `unklar` ist genau fuer diesen Zustand da: die Pruefung lief, lieferte
    # aber keine Aussage. Solange N_UNKNOWN ueber 0 steht, kann die
    # Kundenampel nicht auf gruen springen.
    befund_melden wordpress kern unklar "${REZ_KURZ}: wp core verify-checksums hat nicht geantwortet — der Kern ist WEDER bestätigt NOCH beanstandet (Rückgabewert ${CHK_RC})" "$REZ_PFAD" web
  else
    befund_melden wordpress kern ok "${REZ_KURZ}: WordPress-Core unverändert (verify-checksums)" "$REZ_PFAD"
  fi

  if [[ "${csne:-0}" -gt 0 ]]; then
    LISTE=$(echo "$CHK" | grep "should not exist" | sed "s|.*exist: |${REZ_PFAD}/|")
    befund_melden wordpress kern warn "${REZ_KURZ}: ${csne} Core-fremde Datei(en) in wp-admin/wp-includes — prüfen" "$REZ_PFAD" web
    evidence "wp_core_fremd_$(echo "$REZ_KURZ" | tr '/.' '__')" "$LISTE"
    CORE_SNE+="$LISTE"$'\n'
  fi

  # Kern-Whitelist für Abschnitt 13c (#18). Nicht die einzelnen Dateien —
  # verify-checksums nennt nur die ABWEICHUNGEN, und die Gutfälle einzeln
  # aufzuzählen hiesse, den Kern selbst zu durchlaufen. Stattdessen der
  # Verzeichnispräfix: alles unter wp-admin/ und wp-includes/, das NICHT in
  # CORE_INJECTED oder CORE_SNE steht, ist genau die Menge, die
  # verify-checksums als unverändert bestätigt hat.
  #
  # Bedingung ist der Rückgabewert. Ein Kern, dessen Prüfung gescheitert ist,
  # darf hier nicht auftauchen — sonst würde ein Werkzeugausfall zur
  # Freigabe des Verzeichnisses, in dem eine untergeschobene Datei am
  # wahrscheinlichsten liegt.
  if [[ "$CHK_RC" -eq 0 || "${cmod:-0}" -gt 0 || "${csne:-0}" -gt 0 ]] \
     && [[ -n "$CHK_ROH" ]]; then
    printf '%s\n' "${REZ_PFAD}" \
      >> "${PRUEFSUMMEN_KERN_WHITELIST:-${RUN_DIR}/.pruefsummen_kern.txt}"
  fi
}

# ── Dateibasierte Merkmale ───────────────────────────────────
rezept_sonder() {
  # ── Vergiftete robots.txt (#47) ────────────────────────────
  #
  # Der Doorway-Generator der SEO-Spam-Kampagne sitzt in der DATENBANK, nicht
  # auf der Platte. Ein reiner Dateiscan meldet die Kampagne als sauber — und
  # genau das tat dieses Werkzeug beim Befall vom 12.08.2026 auf 23 Seiten.
  #
  # Was der Angreifer aber anfassen MUSS, ist die robots.txt: Google findet die
  # Doorway-Seiten sonst nicht. Dort stand:
  #
  #   Sitemap: https://…/index.php/sitemap.xml
  #
  # WAS HIER KEIN BEFUND IST — und das ist der wichtige Teil:
  # WordPress liefert seit 5.5 selbst eine VIRTUELLE Sitemap unter
  # /wp-sitemap.xml, Yoast unter /sitemap_index.xml. "Sitemap ohne Datei" ist
  # also der Normalfall. Wer darauf anschlaegt, meldet jede gepflegte Seite.
  #
  # Das Merkmal ist der Pfad DURCH index.php: die PATHINFO-Form
  # 'index.php/…' benutzt kein verbreitetes Plugin. Sie ist der Weg, eine
  # beliebige Adresse von PHP beantworten zu lassen, ohne Rewrite-Regeln zu
  # brauchen — und damit ohne Spur im Dateisystem.
  #
  # Die mtime der Datei ist nebenbei der ZEITANKER: sie ueberlebt, weil
  # niemand robots.txt ansieht. Im Vorfall war sie zwei Wochen aelter als das
  # aelteste Zugriffsprotokoll und datierte den Einbruch 19 Tage zurueck.
  if [[ -f "${REZ_PFAD}/robots.txt" ]]; then
    local _sm _mt
    _sm=$(grep -iE '^[[:space:]]*Sitemap:' "${REZ_PFAD}/robots.txt" 2>/dev/null || true)
    _mt=$(datei_meta "${REZ_PFAD}/robots.txt" mtime 2>/dev/null || true)
    if printf '%s' "$_sm" | grep -qE 'index\.php/'; then
      befund_melden wordpress schadcode crit \
        "${REZ_KURZ}: robots.txt verweist auf eine Sitemap über index.php/ — Kennzeichen eines Doorway-Generators IN der Datenbank; ein Dateiscan findet ihn nicht${_mt:+ (robots.txt vom ${_mt})}" \
        "${REZ_PFAD}/robots.txt" web
      code "$_sm"
      evidence "wp_robots_doorway_$(echo "$REZ_KURZ" | tr '/.' '__')" \
               "${REZ_PFAD}/robots.txt   mtime: ${_mt:-?}"$'\n'"$_sm" kunde
      # Auf die Zeitachse in 13e. Diese Datei ist haeufig der aelteste Beleg,
      # den es ueberhaupt noch gibt — sie ueberlebt, weil niemand sie ansieht.
      ZEITANKER+="${REZ_PFAD}/robots.txt"$'\n'
    elif [[ -n "$_sm" ]]; then
      # Kein Verdacht — nur der Zeitanker. Eine gegenstaendliche robots.txt in
      # einer WordPress-Wurzel ist verbreitet und voellig legitim.
      info "${REZ_KURZ}: robots.txt vorhanden${_mt:+, zuletzt geändert ${_mt}} — als Zeitanker vermerkt"
    fi
  fi

  # Doorway-.htaccess: eine FilesMatch-Regel, die nur index.php und cache.php
  # zulässt. Kleine Datei, eindeutige Signatur.
  local DW
  DW=$(find "$REZ_PFAD" -name ".htaccess" -size -400c 2>/dev/null \
       | while read -r hf; do grep -qF "(index.php|cache.php)" "$hf" 2>/dev/null && dirname "$hf"; done || true)
  if [[ -n "$DW" ]]; then
    befund_melden wordpress schadcode crit "${REZ_KURZ}: $(echo "$DW" | grep -c .) Doorway-Verzeichnis(se) (cache.php/index.php-Signatur)" "$(echo "$DW" | head -1)" web
    code "$(echo "$DW" | head -30)"
    DOORWAY_DIRS+="$DW"$'\n'
  else
    befund_melden wordpress schadcode ok "${REZ_KURZ}: keine Doorway-.htaccess-Signatur" "$REZ_PFAD"
  fi

  # Bootstrap-Injektion: @include base64_decode() lädt die Nutzlast bei jedem
  # Seitenaufruf nach, ohne dass im Code etwas Auffälliges steht.
  local CI
  CI=$(grep -rlF "include base64_decode" "$REZ_PFAD" --include="*.php" 2>/dev/null | head -40 || true)
  if [[ -n "$CI" ]]; then
    befund_melden wordpress schadcode crit "${REZ_KURZ}: $(echo "$CI" | grep -c .) Datei(en) mit @include base64_decode() — getarnte Payload-Nachladung" "$(echo "$CI" | head -1)" web
    code "$(echo "$CI" | head -20)"
    evidence "wp_include_injektion_$(echo "$REZ_KURZ" | tr '/.' '__')" "$CI"
    CORE_INJECT_HITS+="$CI"$'\n'
  else
    befund_melden wordpress schadcode ok "${REZ_KURZ}: keine @include base64_decode()-Injektion" "$REZ_PFAD"
  fi

  # mu-Plugins laufen IMMER, ohne Aktivierung und ohne in der Pluginliste zu
  # erscheinen. Bösartige Plugins deaktivieren oder verstecken sich selbst und
  # tauchen deshalb nicht in active_plugins auf — geprüft wird das Dateisystem.
  local MU
  MU=$(find "${REZ_PFAD}/wp-content/mu-plugins" -maxdepth 1 -name '*.php' 2>/dev/null | head -20 || true)
  if [[ -n "$MU" ]]; then
    befund_melden wordpress schadcode warn "${REZ_KURZ}: $(echo "$MU" | grep -c .) mu-Plugin(s) — laufen ohne Aktivierung und erscheinen in keiner Pluginliste" "$(echo "$MU" | head -1)" web
    code "$MU"
    MU_PLUGINS+="$MU"$'\n'
  fi

  # Manipulierte .htaccess mit Freigabeliste. Abschnitt 13b prüft das
  # gründlicher und für jede Anwendung; hier bleibt der schnelle Namensabgleich,
  # weil er ohne Einordnung auskommt.
  local BAD
  BAD=$(find "$REZ_PFAD" -name ".htaccess" 2>/dev/null | while read -r hf; do
          grep -qE "adminfuns|chtmlfuns|classsmtps|comfunctions|postnews|schallfuns|epinyins|siteheads|hplfuns|moddofuns" "$hf" 2>/dev/null && echo "$hf"; done || true)
  if [[ -n "$BAD" ]]; then
    befund_melden wordpress schadcode crit "${REZ_KURZ}: manipulierte .htaccess (Freigabeliste mit Webshell-Namen)" "$(echo "$BAD" | head -1)" web
    code "$(echo "$BAD" | sed "s|${REZ_PFAD}/||")"
    TAMPERED_HTACCESS+="$BAD"$'\n'
  fi

  # Plugin-Prüfsummen gegen wordpress.org. verify-checksums deckt nur den Kern
  # ab, und der ist selten das Einfallstor — die Nutzlast liegt fast immer im
  # Plugin-Ordner.
  #
  # Der Aufruf stand bis v3.11 in rezept_kern, und rezept_kern läuft erst NACH
  # der Werkzeug-Probe des Rahmens (module/12r_rezepte.sh:104-125), also nur
  # mit lauffähigem wp-cli. Gebraucht wird wp-cli hier nirgends: die
  # Bestandsliste kommt aus _wp_bestand (liest version.php und die
  # Plugin-Kopfzeilen), verglichen wird mit python3 gegen abgerufene
  # JSON-Sätze. Eine Instanz ohne wp-cli verlor damit eine Prüfung, die dort
  # möglich gewesen wäre — und zwar ausgerechnet die, die den Plugin-Ordner
  # abdeckt.
  #
  # Preis der Verschiebung: die Befunde stehen im Bericht nicht mehr neben der
  # Kern-Integrität. Die Kategorie in befund_melden bleibt bewusst `kern`,
  # damit die Einordnung erhalten bleibt; nur die Reihenfolge ändert sich.
  #
  # Das --online-Tor besteht wegen des Netzzugriffs. Zeigt WP_PRUEFSUMMEN_BASIS
  # auf ein Verzeichnis, wird nichts abgerufen — dann wäre das Tor eine Hürde
  # ohne Grund.
  if _wp_pruefsummen_aus_netz && [[ "${WANT_ONLINE:-0}" != "1" ]]; then
    info "${REZ_KURZ}: Plugin-Integrität nicht geprüft — die Prüfsummen von wordpress.org brauchen --online"
  elif ! werkzeug_da python3; then
    befund_melden wordpress kern unklar "${REZ_KURZ}: python3 fehlt — Plugin-Integrität nicht prüfbar" "$REZ_PFAD" web
  else
    _wp_plugin_integritaet
  fi
}

# ── Konfiguration: exponierter Fernzugang ────────────────────
#
# WARUM DAS NICHT DER SCHWACHSTELLEN-ABGLEICH ERLEDIGT
#
# Der Abgleich in rezept_version kennt nur, was im Datenbestand steht. Beim
# Einbruch vom 28.08.2026 (fortbildungszentrum-halfmann.de) war der Weg hinein
# CVE-2026-76581 im WPMU DEV Dashboard: veroeffentlicht am 27.08., der Bestand
# stammte vom 12.08. Eine Instanz auf 5.0.1 galt dem Abgleich deshalb als
# sauber — betroffen war sie trotzdem.
#
# Die Konfiguration dagegen ist ohne Bestand messbar: ist der Hub-Fernzugang
# ueberhaupt scharf? Erst SSO + Admin-Mapping machen aus der Luecke eine offene
# Tuer. Das gilt fuer die naechste Luecke derselben Familie genauso, ohne dass
# jemand einen Datenbestand nachziehen muss.
#
# Der Angriff im Log: admin-ajax.php?action=wdpsso_step1 (302) gefolgt von
# wdpsso_step2&outgoing_hmac=… (302), danach Plugin-Upload als Administrator.
# Der SSO-Login erzeugt KEIN wp_login-Ereignis — Anmeldeprotokolle zeigen ihn
# nicht.
rezept_konfig() {
  local PLUG="${REZ_PFAD}/wp-content/plugins/wpmudev-updates"
  local HAUPT="${PLUG}/update-notifications.php"
  [[ -d "$PLUG" ]] || return 0            # Dashboard nicht installiert
  local kurz="${REZ_KURZ}"

  # ── Version aus dem Plugin-Kopf ────────────────────────────
  local ver=""
  [[ -r "$HAUPT" ]] && ver=$(grep -m1 -E '^\s*\*?\s*Version:' "$HAUPT" 2>/dev/null \
                             | grep -oE '[0-9]+(\.[0-9]+)*' | head -1)

  # ── Ist SSO hart abgeschaltet? ─────────────────────────────
  # Die Konstante wirkt in beiden Schritten vor jeder Pruefung; sie sticht die
  # Option. Ohne diese Abfrage meldete die Pruefung eine gehaertete Instanz als
  # offen.
  local konstante=0
  grep -qE "define\(\s*['\"]WPMUDEV_DISABLE_SSO['\"]\s*,\s*true" \
       "${REZ_PFAD}/wp-config.php" 2>/dev/null && konstante=1

  # ── Optionen: SSO-Zustand und ob die Site verbunden ist ────
  # Vom Schluessel wird ausschliesslich die LAENGE gelesen. Der Wert ist ein
  # Zugangsgeheimnis und hat in Befund, Beleg und Logzeile nichts zu suchen.
  local sso keylen
  sso=$(_db_sql wpmudev_sso \
        "SELECT option_value FROM ${REZ_PFX}options WHERE option_name='wdp_un_sso';" 2>/dev/null | head -1)
  keylen=$(_db_sql wpmudev_key \
        "SELECT LENGTH(option_value) FROM ${REZ_PFX}options WHERE option_name='wpmudev_apikey';" 2>/dev/null | head -1)
  keylen="${keylen//[^0-9]/}"; keylen="${keylen:-0}"

  # enabled";b:1 = an, b:0 = aus. Fehlt der Schluessel ganz (Dashboard 4.11.x),
  # heisst das NICHT 'aus': die am 01.09. erneut uebernommene Instanz trug
  # userid ohne enabled. Ein fehlender Schalter wird deshalb als scharf
  # gewertet, sobald ein Benutzer gemappt ist.
  local sso_an=0 sso_user=""
  if [[ -n "$sso" ]]; then
    sso_user=$(printf '%s' "$sso" | grep -oE '"userid";i:[0-9]+' | grep -oE '[0-9]+$')
    if printf '%s' "$sso" | grep -q '"enabled";b:1'; then sso_an=1
    elif printf '%s' "$sso" | grep -q '"enabled";b:0'; then sso_an=0
    elif [[ -n "$sso_user" ]]; then sso_an=1
    fi
  fi

  # ── Urteil ────────────────────────────────────────────────
  local lage="Dashboard ${ver:-unbekannt}, SSO $([[ $sso_an -eq 1 ]] && echo scharf || echo aus)${sso_user:+ (Benutzer ${sso_user})}, Site $([[ ${keylen:-0} -gt 0 ]] && echo verbunden || echo unverbunden)"
  local haertung="Härtung: define('WPMUDEV_DISABLE_SSO', true) in wp-config.php und Dashboard ≥ 5.0.2"

  if [[ "$konstante" -eq 1 ]]; then
    befund_melden wordpress konfig ok \
      "${kurz}: Hub-SSO per WPMUDEV_DISABLE_SSO hart abgeschaltet (${lage})" "$REZ_PFAD"
    return 0
  fi

  if [[ -z "$ver" ]]; then
    befund_melden wordpress konfig unklar \
      "${kurz}: WPMU DEV Dashboard vorhanden, Version nicht lesbar — Hub-SSO nicht bewertbar. ${haertung}" "$REZ_PFAD" web
    return 0
  fi

  # Einmal ordnen, dann entscheiden — und den dritten Zustand ehrlich
  # behandeln: ohne python3 ist die Reihenfolge nicht bestimmbar, und geraten
  # wird hier nicht.
  local vor502 ueber500
  _ver_kleiner "$ver" "5.0.2"; vor502=$?
  if [[ "$vor502" -eq 2 ]]; then
    befund_melden wordpress konfig unklar \
      "${kurz}: Versionsordnung nicht verfügbar (python3 oder lib/wp_schwachstellen.py fehlt) — Hub-SSO nicht bewertbar. ${lage}. ${haertung}" "$REZ_PFAD" web
    return 0
  fi
  _ver_kleiner "5.0.0" "$ver"; ueber500=$?

  if [[ "$vor502" -eq 0 ]] && [[ "$sso_an" -eq 1 ]]; then
    befund_melden wordpress konfig crit \
      "${kurz}: Hub-SSO scharf bei Dashboard ${ver} — unangemeldete Übernahme als Administrator möglich (CVE-2026-76581, behoben in 5.0.2). ${lage}. ${haertung}" "$REZ_PFAD" web
  elif [[ "$ueber500" -ne 0 ]] && [[ "${keylen:-0}" -eq 0 ]]; then
    befund_melden wordpress konfig crit \
      "${kurz}: Dashboard ${ver} unverbunden mit leerem Schlüssel — WDP-AUTH-Signaturen fälschbar (CVE-2026-15459, behoben in 5.0.1). ${lage}. ${haertung}" "$REZ_PFAD" web
  elif [[ "$vor502" -eq 0 ]]; then
    befund_melden wordpress konfig warn \
      "${kurz}: Dashboard ${ver} veraltet (CVE-2026-76581 bis 5.0.1) — SSO derzeit aus, die Tür geht mit einem Optionsschalter wieder auf. ${lage}" "$REZ_PFAD" web
  elif [[ "$sso_an" -eq 1 ]]; then
    befund_melden wordpress haertung warn \
      "${kurz}: Hub-SSO scharf (Dashboard ${ver}) — ein Fernzugang, der einen Administrator ohne Anmeldung einloggt und kein wp_login-Ereignis hinterlässt. ${haertung}" "$REZ_PFAD" web
  else
    befund_melden wordpress konfig ok "${kurz}: Hub-SSO nicht scharf (${lage})" "$REZ_PFAD"
  fi

  evidence "wp_hub_sso_$(echo "$kurz" | tr '/.' '__')" \
    "Instanz:   ${REZ_PFAD}
Dashboard: ${ver:-unbekannt}
SSO:       $([[ $sso_an -eq 1 ]] && echo scharf || echo aus)${sso_user:+ , Benutzer ${sso_user}}
Konstante: $([[ $konstante -eq 1 ]] && echo 'WPMUDEV_DISABLE_SSO gesetzt' || echo 'nicht gesetzt')
Schlüssel: $([[ ${keylen:-0} -gt 0 ]] && echo "gesetzt (${keylen} Zeichen, Wert nicht protokolliert)" || echo 'leer')"
}

# ── Datenbank ────────────────────────────────────────────────
# Read-only, ausschließlich SELECT. Der Rahmen hat den Zugang aufgebaut und
# das Präfix gehärtet — ohne diese Härtung ging der Wert aus wp-config.php roh
# in die Abfragen, und wer die Datei schreiben kann, bekam damit beliebiges SQL
# in ein Werkzeug, das als root läuft.
rezept_db() {
  # Prüfstand-Naht (#17). Der Wordfence-Zweig liest ausschliesslich aus der
  # Datenbank, und der Prüfbaum hat keine — ohne diesen Vorgriff wäre er von
  # keinem Vergleich gedeckt. Mit gesetzter Attrappe läuft er hier, ohne sie
  # weiter unten am regulären Platz; das Flag verhindert einen doppelten Lauf
  # auf einem System, das beides hat.
  WF_GELAUFEN=0
  if [[ -n "${NT_WF_ATTRAPPE:-}" ]]; then _wp_wordfence; WF_GELAUFEN=1; fi
  # Dieselbe Naht für den Persistenz-Zweig (#47), aus demselben Grund: eine
  # Auswertung, die der Prüfstand nie misst, verrutscht unbemerkt.
  DBP_GELAUFEN=0
  if [[ -n "${NT_DB_ATTRAPPE:-}" ]]; then _wp_db_persistenz; DBP_GELAUFEN=1; fi

  if ! werkzeug_da mysql && [[ -z "${REZ_WERKZEUG:-}" ]]; then
    befund_melden wordpress datenbank unklar "${REZ_KURZ}: weder mysql-Client noch wp-cli vorhanden — Datenbank nicht geprüft" "$REZ_PFAD" web
    return 0
  fi
  # EIN STILLER AUSSTIEG IST HIER FALSCH.
  #
  # Bis v3.14 stand hier nur `|| return 0`. Schlug der Zugang fehl, verschwand
  # die gesamte Datenbankpruefung SPURLOS — kein Befund, keine Zeile, nichts.
  # Im Bericht sah eine Installation ohne DB-Pruefung genauso aus wie eine mit
  # unauffaelligem Ergebnis.
  #
  # Der haeufigste Grund ist keine kaputte Konfiguration, sondern ein fehlendes
  # PCRE: rezept_konf_wert liest die Werte mit `grep -oP`, und BSD-grep kennt
  # kein -P. Auf einem macOS-Arbeitsplatz lieferte der Griff nach DB_NAME
  # deshalb immer leer — und damit lief die Datenbankpruefung dort NIE. Auch
  # nicht im Pruefbaum, dessen Referenz von genau dort stammt.
  if ! rezept_db_zugang "${REZEPT_DIR}/wordpress" "${REZ_PFAD}/wp-config.php"; then
    local _grund="Zugangsdaten nicht lesbar"
    echo 'x' | grep -qP 'x' 2>/dev/null || _grund="grep beherrscht kein -P (PCRE) — die Werte aus wp-config.php sind damit nicht lesbar"
    befund_melden wordpress datenbank unklar \
      "${REZ_KURZ}: Datenbank nicht geprüft (${_grund}). Das ist KEINE Entwarnung." "${REZ_PFAD}/wp-config.php" web
    return 0
  fi
  if ! rezept_sql "SELECT 1;" >/dev/null 2>&1; then
    befund_melden wordpress datenbank warn "${REZ_KURZ}: keine DB-Verbindung (Zugang prüfen) — Datenbankabfragen übersprungen" "${REZ_PFAD}/wp-config.php" web
    return 0
  fi

  # a) Kürzlich angelegte Administratoren. Der eindeutigste Einzelbefund: ein
  # Admin, der erst nach dem Vorfall entstand, ist praktisch nie legitim.
  #
  # MIT EINER AUSNAHME, DIE DIE REGEL BIS ZUM 14.08.2026 NICHT KANNTE.
  #
  # Sie prüfte nur das Alter des KONTOS, nicht das der INSTALLATION. Eine
  # Seite, die nach dem Vorfall angelegt wurde, kann aber gar keinen "nach der
  # Kompromittierung hinzugefügten" Administrator haben — ihr erster Benutzer
  # IST der Installateur.
  #
  # Auf einem Plesk-Host traf das zweimal zu: `moorth` (info@agentur.example) war
  # auf beiden gemeldeten Installationen der Benutzer mit der niedrigsten
  # Anlagezeit, auf einer davon entstand der älteste Beitrag zwei Stunden NACH
  # dem Konto. Eine Agentur, die Kundenseiten aufsetzt.
  #
  # Der Schaden wäre nicht der Fehlalarm gewesen, sondern die Bereinigung:
  # Schritt 4 des Reparaturablaufs deaktiviert Konten aus dieser Liste
  # (Sitzungen, Rolle, Passwort). Auf zwei laufenden Kundenseiten hätte das
  # den EINZIGEN Administrator ausgesperrt.
  #
  # `aeltere` zählt Benutzer, die vor dem Kandidaten angelegt wurden. Ist die
  # Zahl 0, hat er die Installation eröffnet. Bewusst KEIN stilles Wegfiltern:
  # solche Konten kommen in einen eigenen Topf mit eigener Zahl, denn ein
  # Angreifer, der zuerst alle anderen Benutzer löscht, sähe genauso aus.
  local NEU ALLE
  ALLE=$(rezept_sql "SELECT u.user_login, u.user_email, u.user_registered,
           (SELECT COUNT(*) FROM ${REZ_PFX}users u2
             WHERE u2.user_registered < u.user_registered
                OR (u2.user_registered = u.user_registered AND u2.ID < u.ID)) AS aeltere
         FROM ${REZ_PFX}users u
         JOIN ${REZ_PFX}usermeta m ON u.ID=m.user_id
         WHERE m.meta_key='${REZ_PFX}capabilities' AND m.meta_value LIKE '%administrator%'
         AND u.user_registered > DATE_SUB(NOW(), INTERVAL ${DAYS_BACK} DAY);")
  NEU=""
  local GRUENDER="" _z _ae
  while IFS= read -r _z; do
    [[ -n "$_z" ]] || continue
    _ae="${_z##*$'\t'}"                      # letzte Spalte: Anzahl aelterer
    [[ "$_ae" =~ ^[0-9]+$ ]] || _ae=1        # unlesbar -> wie bisher behandeln
    if [[ "$_ae" -eq 0 ]]; then
      GRUENDER+="${_z%$'\t'*}"$'\n'
    else
      NEU+="${_z%$'\t'*}"$'\n'
    fi
  done <<< "$ALLE"
  NEU="${NEU%$'\n'}"; GRUENDER="${GRUENDER%$'\n'}"

  if [[ -n "$GRUENDER" ]]; then
    # Das Alter der Installation gehoert in den Beleg. Ohne es steht da eine
    # Behauptung; mit ihm kann der Leser die Einordnung nachpruefen.
    local _alt
    _alt=$(rezept_sql "SELECT MIN(post_date) FROM ${REZ_PFX}posts;" 2>/dev/null | head -1)
    # `warn`, nicht `ok`. befund_melden kennt ohnehin nur crit|warn|unklar|ok —
    # der erste Entwurf schrieb `info` und erzeugte damit die Zeile
    #   "Programmfehler: unbekannte Schwere 'info' — als Warnung gemeldet"
    # in einem echten Lauf. Aufgefallen erst auf dem Server.
    #
    # Und `warn` ist auch inhaltlich richtig: das Konto ist ERKLAERT, nicht
    # freigesprochen. Ein Angreifer, der zuerst alle anderen Benutzer loescht,
    # saehe genauso aus. Die Einstufung nimmt es aus der Bereinigung, nicht aus
    # dem Bericht.
    befund_melden wordpress datenbank warn \
      "${REZ_KURZ}: Administrator-Konto(en) ohne älteren Benutzer — hat die Installation eröffnet, kein nachträglich hinzugefügtes Konto. Kein Bereinigungsziel, aber zu sichten" "$REZ_PFAD"
    code "$GRUENDER"
    evidence "wp_gruender_admins_$(echo "$REZ_KURZ" | tr '/.' '__')" \
      "Kein Benutzer dieser Installation ist aelter als die genannten Konten.
Aeltester Beitrag der Installation: ${_alt:-unbekannt}

${GRUENDER}"
    while IFS= read -r _z; do
      [[ -n "$_z" ]] && GRUENDER_ADMINS+="${REZ_PFAD}"$'\t'"${_z}"$'\n'
    done <<< "$GRUENDER"
  fi

  if [[ -n "$NEU" ]]; then
    befund_melden wordpress datenbank crit "${REZ_KURZ}: kürzlich angelegte(s) Administrator-Konto(en) — Angreifer-Verdacht" "$REZ_PFAD" web
    code "$NEU"
    evidence "wp_neue_admins_$(echo "$REZ_KURZ" | tr '/.' '__')" "$NEU"
    # Mit Kopfzeile je Instanz — findings.json filtert sie beim Zaehlen wieder
    # heraus (`grep -vE '^=== |^$'`), braucht sie aber, um die Konten der
    # richtigen Installation zuzuordnen. Ohne diese Zuweisung stand
    # metrics.rogue_wp_admins dauerhaft auf 0, waehrend derselbe Bericht die
    # Konten namentlich auffuehrte (#2).
    ROGUE_ADMINS+="=== ${REZ_KURZ} ==="$'\n'"$NEU"$'\n'
    # Dieselben Konten noch einmal, mit vollem Pfad je Zeile — das ist die
    # Fassung, mit der die Bereinigung arbeiten kann (siehe lib/befunde.sh).
    while IFS= read -r _z; do
      [[ -n "$_z" ]] || continue
      ROGUE_ADMINS_DETAIL+="${REZ_PFAD}"$'\t'"${_z}"$'\n'
    done <<< "$NEU"
  elif [[ -z "$GRUENDER" ]]; then
    befund_melden wordpress datenbank ok "${REZ_KURZ}: keine kürzlich angelegten Administratoren" "$REZ_PFAD"
  fi

  # b) Admins mit angreifertypischem Namen oder Adresse. Bewusst getrennt vom
  # Befund oben: das ist ein Verdacht, kein Beleg — eine automatische
  # Bereinigung darf diese Konten nie anfassen.
  local VERDACHT
  VERDACHT=$(rezept_sql "SELECT u.user_login, u.user_email FROM ${REZ_PFX}users u
              JOIN ${REZ_PFX}usermeta m ON u.ID=m.user_id
              WHERE m.meta_key='${REZ_PFX}capabilities' AND m.meta_value LIKE '%administrator%'
              AND (u.user_login REGEXP '${WP_ADMIN_LOGIN_CRIT:-^(wpadmin|admin[0-9]+)$}'
                OR u.user_email REGEXP '${WP_ADMIN_MAIL_CRIT:-@(mail\\\\.ru|yandex)}');")
  if [[ -n "$VERDACHT" ]]; then
    befund_melden wordpress datenbank warn "${REZ_KURZ}: Administrator mit angreifertypischem Namen oder Adresse — Verdacht, kein Beleg" "$REZ_PFAD" web
    code "$VERDACHT"
    SUSPECT_ADMINS+="=== ${REZ_KURZ} ==="$'\n'"$VERDACHT"$'\n'
    # Auch der Verdacht bekommt die handlungsfaehige Fassung — nicht, damit
    # etwas damit geschieht, sondern damit er im Bericht NAMENTLICH und der
    # richtigen Installation zugeordnet auftaucht. Ein Verdacht, den niemand
    # zuordnen kann, ist auf 475 vhosts wertlos.
    #
    # Die Bereinigung darf diese Konten nicht deaktivieren; sie notiert sie.
    while IFS= read -r _z; do
      [[ -n "$_z" ]] || continue
      SUSPECT_ADMINS_DETAIL+="${REZ_PFAD}"$'\t'"${_z}"$'\n'
    done <<< "$VERDACHT"
  fi

  # c) Manipulierte Optionen. siteurl/home weisen auf einen Redirect-Hijack,
  # auto_prepend_file auf eine dauerhaft nachgeladene Nutzlast.
  local OPT
  OPT=$(rezept_sql "SELECT option_name, LEFT(option_value,120) FROM ${REZ_PFX}options
         WHERE option_name IN ('siteurl','home')
            OR option_value LIKE '%auto_prepend_file%'
            OR option_value LIKE '%base64_decode%';")
  [[ -n "$OPT" ]] && { info "${REZ_KURZ}: Optionen (siteurl/home und Auffälligkeiten):"; code "$OPT"; }

  # d) Wordfence-Bestand auslesen, falls vorhanden (#17).
  [[ "${WF_GELAUFEN:-0}" -eq 1 ]] || _wp_wordfence

  # e) Persistenz in der Datenbank (#47).
  [[ "${DBP_GELAUFEN:-0}" -eq 1 ]] || _wp_db_persistenz
}

# ── Persistenz in der Datenbank (#47) ────────────────────────
# Der Anlassfall: ein Doorway-Generator sass in der Installation, nicht auf
# der Platte. robots.txt zeigte auf 'index.php/sitemap.xml' — einen virtuellen
# Pfad, den WordPress beantwortet. Google hatte die erzeugten Seiten im Index,
# bevor das Protokollfenster beginnt. Ein reiner Dateiscan meldete die
# Kampagne als sauber.
#
# Dieser Zweig sucht den GENERATOR statt nur seine Ausgabe. Drei Fragen:
#
#   e1) Steht in active_plugins ein Eintrag, zu dem es KEINE Datei gibt?
#       WordPress raeumt solche Eintraege beim Aufruf der Plugin-Seite selbst
#       weg (validate_active_plugins) — ein Eintrag, der sich haelt, heisst
#       also: entweder sieht niemand auf diese Seite, oder etwas verhindert
#       das Wegraeumen. Leiche oder Tarnung; beides gehoert gesichtet.
#   e2) Steht PHP in den Optionen? Ein '<?php' oder ein auto_prepend_file in
#       wp_options hat keinen legitimen Fall — Optionen tragen Daten, keinen
#       Code. Das ist der Ort, an dem ein Generator seinen Lader ablegt.
#   e3) Welche Optionen sind auffaellig gross? Vorlagen und Wortlisten einer
#       Doorway-Kampagne muessen irgendwo liegen, und wp_options ist der
#       uebliche Ort. BEWUSST nur info + Beleg: die Schwelle ist geraten, und
#       legitime Optionen werden gross (Transients, Page-Builder-CSS). Erst
#       messen, dann einstufen — dieselbe Regel wie bei 7.15.
#
# Die Bereinigung fasst NICHTS davon an. Das ist eine offene Entscheidung
# (#47): eine falsch entfernte Option macht eine Seite unbrauchbar, und anders
# als bei einer Datei sieht man es nicht sofort. Bis dahin: erkennen und
# ausweisen.
_db_sql() {   # _db_sql <kennung> <abfrage>
  # Pruefstand-Naht wie _wf_sql: NT_DB_ATTRAPPE nennt ein Verzeichnis mit je
  # einer Datei <kennung>.tsv. Der Pruefbaum hat keine Datenbank.
  if [[ -n "${NT_DB_ATTRAPPE:-}" ]]; then
    if [[ -r "${NT_DB_ATTRAPPE}/nur" ]] \
       && ! grep -qF "$(cat "${NT_DB_ATTRAPPE}/nur")" <<<"${REZ_KURZ}"; then
      return 0
    fi
    [[ -r "${NT_DB_ATTRAPPE}/$1.tsv" ]] && cat "${NT_DB_ATTRAPPE}/$1.tsv"
    return 0
  fi
  rezept_sql "$2"
}

_wp_db_persistenz() {
  # Mit gesetzter Attrappe laeuft dieser Zweig fuer JEDE Instanz des
  # Pruefbaums — aber nur eine hat Daten. Ohne dieses Gate bekaemen die
  # anderen "kein PHP-Code in wp_options" als gruene Zeile, obwohl nichts
  # gemessen wurde. Eine Entwarnung ohne Messung ist eine stille Entwarnung;
  # die Instanzen ausserhalb der Attrappe sagen deshalb GAR nichts.
  if [[ -n "${NT_DB_ATTRAPPE:-}" ]]; then
    if [[ -r "${NT_DB_ATTRAPPE}/nur" ]] \
       && ! grep -qF "$(cat "${NT_DB_ATTRAPPE}/nur")" <<<"${REZ_KURZ}"; then
      return 0
    fi
  fi

  # e1) active_plugins gegen die Platte.
  local AKTIV LEICHEN="" PLUGDIR="${REZ_PFAD}/wp-content/plugins"
  AKTIV=$(_db_sql aktive_plugins "SELECT option_value FROM ${REZ_PFX:-}options WHERE option_name='active_plugins';")
  # OHNE plugins-VERZEICHNIS GIBT ES KEINEN ABGLEICH.
  #
  # Der Test lautet `[[ -f "${PLUGDIR}/${_e}" ]]`. Fehlt PLUGDIR, scheitert er
  # fuer JEDEN Eintrag — und die Regel meldet die vollstaendige Plugin-Liste
  # als Leichen. Ein maximaler Befund aus einem fehlenden Verzeichnis, und er
  # sieht aus wie das schlimmste denkbare Ergebnis statt wie ein Ausfall.
  #
  # Auf kundenserver42 waren 18 der 37 gemeldeten Eintraege genau das: jemand
  # hatte plugins/ nach plugins-old bzw. plugins_old umbenannt — die uebliche
  # Handbewegung, um eine Seite zur Fehlersuche plugin-frei zu starten.
  #
  # Wie bei verify-checksums (#65) ist der richtige Zustand `unklar`, nicht
  # `warn` und nicht `ok`: die Frage ist offen, nicht beantwortet. Der Hinweis
  # nennt den wahrscheinlichen Grund, damit niemand das Verzeichnis sucht, das
  # unter anderem Namen daneben liegt.
  local E1_MOEGLICH=1
  if [[ -n "$AKTIV" ]] && [[ ! -d "$PLUGDIR" ]]; then
    local _umbenannt="" _k
    for _k in "${PLUGDIR}-old" "${PLUGDIR}_old" "${PLUGDIR}.bak" "${PLUGDIR}-alt"; do
      [[ -d "$_k" ]] && _umbenannt="${_umbenannt}${_umbenannt:+, }$(basename "$_k")"
    done
    befund_melden wordpress datenbank unklar \
      "${REZ_KURZ}: wp-content/plugins fehlt — der Abgleich von active_plugins gegen die Platte ist nicht möglich${_umbenannt:+ (daneben liegt: ${_umbenannt})}" \
      "$REZ_PFAD" web
    E1_MOEGLICH=0
  fi
  if [[ -n "$AKTIV" && "$E1_MOEGLICH" -eq 1 ]]; then
    # PHP-serialisiert: a:2:{i:0;s:19:"akismet/akismet.php";…}. Gebraucht
    # werden nur die Pfadliterale; die Laengenangaben interessieren nicht.
    local _e
    while IFS= read -r _e; do
      [[ -n "$_e" ]] || continue
      [[ -f "${REZ_PFAD}/wp-content/plugins/${_e}" ]] || LEICHEN+="${_e}"$'\n'
    done < <(printf '%s' "$AKTIV" | grep -oE '"[^"]+\.php"' | tr -d '"')
  fi
  if [[ -n "$LEICHEN" ]]; then
    befund_melden wordpress datenbank warn \
      "${REZ_KURZ}: active_plugins führt Einträge ohne Datei auf der Platte — Leiche oder Tarnung, sichten" "$REZ_PFAD" web
    code "$LEICHEN"
    evidence "wp_db_plugin_leichen_$(echo "$REZ_KURZ" | tr '/.' '__')" "$LEICHEN" kunde
    while IFS= read -r _e; do
      [[ -n "$_e" ]] && WP_PLUGIN_LEICHEN+="${REZ_PFAD}"$'\t'"${_e}"$'\n'
    done <<< "$LEICHEN"
  elif [[ -n "$AKTIV" && "$E1_MOEGLICH" -eq 1 ]]; then
    befund_melden wordpress datenbank ok "${REZ_KURZ}: alle Einträge in active_plugins liegen auf der Platte" "$REZ_PFAD"
  elif [[ "$E1_MOEGLICH" -eq 0 ]]; then
    : # das ⚪ oben ist die Aussage; eine zweite Zeile wäre nur Rauschen
  else
    # Leer heisst hier zweierlei — keine aktiven Plugins ODER Abfrage ohne
    # Ergebnis. Beides ist keine gepruefte Aussage, also keine gruene Zeile.
    info "${REZ_KURZ}: active_plugins leer oder nicht lesbar — Abgleich gegen die Platte entfällt"
  fi

  # e2) PHP in den Optionen — ZURUECKGESTUFT AUF info.
  #
  # Die Regel wurde als `crit` ausgeliefert und am 13.08.2026 zum ersten Mal
  # gegen 121 echte Installationen gehalten: 12 Treffer, davon 0 echte.
  #
  #   6x  simplehooks-settings    ein Plugin, dessen ZWECK das Ablegen von
  #                               PHP-Schnipseln in Hooks ist
  #   1x  wf_sn_vu_vulns          Wordfence-Schwachstellenbestand; enthaelt
  #                               base64_decode( als BESCHREIBUNG von Schadmustern
  #   2x  sm_main_show_1          Slider-Markup
  #   3x  Theme- und Export-Optionen
  #
  # Ein Wert, der PHP enthaelt, ist in wp_options nicht die Ausnahme. Solange
  # die Regel nicht trennt, darf sie keine Sofortmassnahmen ausloesen — und
  # eine Bereinigung darf ihre Liste erst recht nicht abarbeiten.
  #
  # DER BELEG BELEGTE NICHTS.
  # Gespeichert wurde LEFT(option_value,160); das Muster steckt bei einem
  # serialisierten Wert regelmaessig weiter hinten. In KEINEM der 12 Belege
  # war der Treffer sichtbar — der Befund war aus seinem eigenen Beleg nicht
  # nachpruefbar, derselbe Fehler wie #40. Deshalb liefert die Abfrage jetzt
  # das getroffene Muster und ein Fenster DARUM statt eines blinden Anfangs.
  local OPTCODE _lok
  _lok="CASE WHEN LOCATE('<?php', option_value) > 0 THEN LOCATE('<?php', option_value)
             WHEN LOCATE('auto_prepend_file', option_value) > 0 THEN LOCATE('auto_prepend_file', option_value)
             ELSE LOCATE('base64_decode(', option_value) END"
  OPTCODE=$(_db_sql optionen_php "SELECT option_name,
               CASE WHEN LOCATE('<?php', option_value) > 0 THEN '<?php'
                    WHEN LOCATE('auto_prepend_file', option_value) > 0 THEN 'auto_prepend_file'
                    ELSE 'base64_decode(' END,
               LENGTH(option_value),
               SUBSTRING(option_value, GREATEST(1, ${_lok} - 60), 160)
             FROM ${REZ_PFX:-}options
             WHERE option_value LIKE '%<?php%'
                OR option_value LIKE '%auto_prepend_file%'
                OR option_value LIKE '%base64_decode(%';")
  if [[ -n "$OPTCODE" ]]; then
    info "${REZ_KURZ}: $(printf '%s\n' "$OPTCODE" | grep -c .) Option(en) mit PHP-Merkmal — KEIN Befund: legitime Plugins legen dort Code ab (gemessen: 12 von 12 Fehlalarmen). Rangfolge für die Sichtung"
    code "$OPTCODE"
    evidence "wp_db_optionen_php_$(echo "$REZ_KURZ" | tr '/.' '__')" "$OPTCODE" kunde
    while IFS= read -r _e; do
      [[ -n "$_e" ]] && WP_OPT_CODE+="${REZ_PFAD}"$'\t'"${_e}"$'\n'
    done <<< "$OPTCODE"
  fi

  # e3) Grosse Optionen — Rangfolge fuer die Sichtung, kein Befund.
  local OPTGROSS
  OPTGROSS=$(_db_sql optionen_gross "SELECT option_name, LENGTH(option_value) FROM ${REZ_PFX:-}options
              WHERE LENGTH(option_value) >= ${WP_OPTION_GROSS_BYTES:-262144}
              ORDER BY LENGTH(option_value) DESC LIMIT 10;")
  if [[ -n "$OPTGROSS" ]]; then
    info "${REZ_KURZ}: auffällig grosse Optionen (>= ${WP_OPTION_GROSS_BYTES:-262144} B) — Rangfolge für die Sichtung, kein Befund:"
    code "$OPTGROSS"
    evidence "wp_db_optionen_gross_$(echo "$REZ_KURZ" | tr '/.' '__')" "$OPTGROSS" kunde
  fi
}

# ── Wordfence: die vorhandene Zweitmeinung (#17) ─────────────
# Läuft auf der geprüften Installation Wordfence, liegt dort ein vollständiger
# Scan-Datenbestand in der Datenbank — Dateihashes, Signaturstatus,
# Schwachstellenmeldungen, übersprungene Pfade. NT-Forensik las davon nichts.
#
# EHRLICHE EINORDNUNG DER REICHWEITE: auf einem Plesk-Server mit 68
# WordPress-Installationen haben 5 Wordfence-Tabellen. Das sind 7 %. Diese
# Schicht ist eine Zweitmeinung, wo vorhanden — keine Primärquelle. Wer auf
# dieser Grundlage Abdeckung behauptet, täuscht sich. Zum Vergleich aus
# demselben Lauf: der serverweite Signaturscanner meldete offene Funde auf 18
# Abos.
#
# Der wertvollste Einzelbefund ist NICHT die Schwachstellenmeldung, sondern
# `skippedPaths`: bei einem Vorfall im August 2026 hatte Wordfence 99 Pfade gar
# nicht gescannt, weil die Option "Dateien ausserhalb der WordPress-
# Installation scannen" standardmässig aus ist — und genau dort lagen zwei der
# Shells. Wer den Wordfence-Bericht des Kunden als Entwarnung liest, liest ihn
# falsch, und das steht im Datenbestand ausdrücklich drin.
#
# NICHT gelesen wird `apiKey` aus wfconfig. Ein fremder Zugangsschlüssel hat
# weder im Bericht noch in den Belegen etwas verloren; die Abfragen unten
# nennen die Felder deshalb einzeln statt mit SELECT *.
#
# Read-only wie der Rest. Kein Installieren, kein Wordfence-CLI.
_wf_sql() {   # _wf_sql <kennung> <abfrage>
  # Prüfstand-Naht: NT_WF_ATTRAPPE nennt ein Verzeichnis mit je einer Datei
  # <kennung>.tsv. Ohne sie wäre dieser Zweig nicht prüfbar — der Prüfbaum hat
  # keine Datenbank, und eine Auswertung, die nie gemessen wird, verrutscht
  # unbemerkt. Genau das ist bei der Auswertung des echten Bestands passiert:
  # ein als "Modified plugin file" gemeldeter Treffer war legitimer
  # Plugin-Code, nur nicht deckungsgleich mit der Fassung auf wordpress.org.
  if [[ -n "${NT_WF_ATTRAPPE:-}" ]]; then
    # Nur fuer die Instanzen, die in `nur` genannt sind. Sonst traege JEDE
    # Installation im Pruefbaum Wordfence, und der haeufigste Fall — die 93 %
    # OHNE — waere nie geuebt.
    if [[ -r "${NT_WF_ATTRAPPE}/nur" ]] \
       && ! grep -qF "$(cat "${NT_WF_ATTRAPPE}/nur")" <<<"${REZ_KURZ}"; then
      return 0
    fi
    [[ -r "${NT_WF_ATTRAPPE}/$1.tsv" ]] && cat "${NT_WF_ATTRAPPE}/$1.tsv"
    return 0
  fi
  rezept_sql "$2"
}

_wp_wordfence() {
  # ${REZ_PFX:-} und nicht ${REZ_PFX}: mit gesetzter Prüfstand-Attrappe läuft
  # dieser Zweig VOR rezept_db_zugang, und unter `set -u` bricht der Lauf sonst
  # mit "REZ_PFX: unbound variable" ab. Im Betrieb ist das Präfix an dieser
  # Stelle immer gesetzt — die Abfrage geht dort an eine echte Datenbank.
  local WF_DA
  WF_DA=$(_wf_sql tabellen "SHOW TABLES LIKE '${REZ_PFX:-}wfconfig';")
  if [[ -z "$WF_DA" ]]; then
    info "${REZ_KURZ}: kein Wordfence in dieser Installation — keine Zweitmeinung verfügbar"
    return 0
  fi

  # ── Betriebszustand des Scanners ─────────────────────────
  local WF_CFG WF_KEY WF_LETZTER WF_ALTER
  WF_CFG=$(_wf_sql konfig "SELECT name, val FROM ${REZ_PFX:-}wfconfig
             WHERE name IN ('keyType','lastScanCompleted','isPaid','scansEnabled_malware');")
  WF_KEY=$(printf '%s\n' "$WF_CFG" | awk -F'\t' '$1=="keyType"{print $2}' | head -1)
  WF_LETZTER=$(printf '%s\n' "$WF_CFG" | awk -F'\t' '$1=="lastScanCompleted"{print $2}' | head -1)

  # Ein Bestand von vor drei Wochen sagt nichts über heute. Das gehört
  # ausgesprochen, bevor irgendjemand die Befunde darunter als aktuell liest.
  if [[ "$WF_LETZTER" =~ ^[0-9]+$ ]]; then
    WF_ALTER=$(( ( $(date +%s) - WF_LETZTER ) / 86400 ))
    if [[ "$WF_ALTER" -gt 14 ]]; then
      befund_melden wordpress logs warn \
        "${REZ_KURZ}: Wordfence-Scan ist ${WF_ALTER} Tage alt — was danach abgelegt wurde, steht in diesem Bestand nicht" "$REZ_PFAD" web
    else
      info "${REZ_KURZ}: Wordfence-Scan ${WF_ALTER} Tage alt"
    fi
  else
    befund_melden wordpress logs unklar \
      "${REZ_KURZ}: Wordfence vorhanden, aber kein abgeschlossener Scan hinterlegt — der Bestand sagt nichts über den Zustand" "$REZ_PFAD" web
  fi
  [[ "$WF_KEY" == "free" ]] && \
    info "${REZ_KURZ}: Wordfence mit freiem Schlüssel — der Signaturbestand ist kleiner und läuft dem kostenpflichtigen um 30 Tage hinterher"

  # ── Die Befunde ──────────────────────────────────────────
  local WF_ISS
  WF_ISS=$(_wf_sql issues "SELECT type, shortMsg FROM ${REZ_PFX:-}wfissues
             WHERE status IN ('new','active');")
  [[ -n "$WF_ISS" ]] || { info "${REZ_KURZ}: Wordfence meldet keine offenen Befunde"; return 0; }

  _wf_typ() { printf '%s\n' "$WF_ISS" | awk -F'\t' -v t="$1" '$1==t' ; }
  local _n

  # Schwachstellen: eine gepflegte Aussage, die wir sonst selbst herleiten
  # müssten. Sie ergänzt den eigenen Abgleich, ersetzt ihn nicht.
  _n=$(_wf_typ wfPluginVulnerable | grep -c . || true)
  if [[ "${_n:-0}" -gt 0 ]]; then
    befund_melden wordpress version warn \
      "${REZ_KURZ}: Wordfence führt ${_n} Plugin(s) als verwundbar" "$REZ_PFAD" web
    code "$(_wf_typ wfPluginVulnerable | cut -f2)"
  fi
  _n=$(_wf_typ wfThemeVulnerable | grep -c . || true)
  if [[ "${_n:-0}" -gt 0 ]]; then
    befund_melden wordpress version warn \
      "${REZ_KURZ}: Wordfence führt ${_n} Theme(s) als verwundbar" "$REZ_PFAD" web
    code "$(_wf_typ wfThemeVulnerable | cut -f2)"
  fi

  # DER Befund dieses Abschnitts. Kategorie `logs`, nicht `schadcode`: es ist
  # keine Aussage über Schadcode, sondern über die Reichweite einer Prüfung.
  _n=$(_wf_typ skippedPaths | grep -c . || true)
  if [[ "${_n:-0}" -gt 0 ]]; then
    befund_melden wordpress logs warn \
      "${REZ_KURZ}: Wordfence hat Pfade vom Scan ausgenommen — ein unauffälliger Wordfence-Bericht ist für diese Bereiche KEINE Entwarnung" "$REZ_PFAD" web
    code "$(_wf_typ skippedPaths | cut -f2)"
    evidence "wordfence_uebersprungen_$(echo "$REZ_KURZ" | tr '/.' '__')" \
             "$(_wf_typ skippedPaths | cut -f2)"
  fi

  # knownfile ist eine INTEGRITÄTSABWEICHUNG, kein Signaturtreffer. Die
  # Verwechslung ist bei der Auswertung des echten Bestands passiert und hätte
  # beinahe legitimen Plugin-Code als Schadcode in den Kundenbericht gebracht.
  _n=$(_wf_typ knownfile | grep -c . || true)
  if [[ "${_n:-0}" -gt 0 ]]; then
    befund_melden wordpress kern warn \
      "${REZ_KURZ}: Wordfence meldet ${_n} Datei(en) als verändert gegenüber dem Original — Integritätsabweichung, kein Signaturtreffer" "$REZ_PFAD" web
    code "$(_wf_typ knownfile | cut -f2)"
  fi

  _n=$(_wf_typ wfPluginAbandoned | grep -c . || true)
  [[ "${_n:-0}" -gt 0 ]] && \
    info "${REZ_KURZ}: Wordfence führt ${_n} Plugin(s) als aufgegeben (kein Hersteller-Support mehr)"

  unset -f _wf_typ
}

# ── Verdikt ──────────────────────────────────────────────────
rezept_verdikt() {
  local n; n=$(printf '%s' "${BEFUNDE:-}" | grep -c $'^wordpress\t.*\tcrit\t' || true)
  if [[ "${n:-0}" -gt 0 ]]; then
    verdikt_melden wordpress "$n" "🔴 ${n} kritische WordPress-Befunde — Kompromittierung belegt oder dringend abzuklären."
  elif printf '%s' "${UNKNOWN_LIST:-}" | grep -q 'wordpress\|WordPress\|Datenbank nicht geprüft'; then
    verdikt_melden wordpress 0 "⚪ WordPress teilweise nicht prüfbar — kein Befund, aber auch keine Entwarnung."
  else
    verdikt_melden wordpress 0 "🟢 Keine Angreifer-Spuren in den WordPress-Installationen."
  fi
}
