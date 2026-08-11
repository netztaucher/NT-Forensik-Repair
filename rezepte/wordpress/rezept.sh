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
REZ_CLI_SQL="_wp db query --skip-column-names"

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

  for d in "${REZ_PFAD}"/wp-content/plugins/*/; do
    [[ -d "$d" ]] || continue
    d="${d%/}"; ver=""
    for f in "$d"/*.php; do
      [[ -f "$f" ]] || continue
      ver=$(_wp_kopf_version "$f" "Plugin Name") && [[ -n "$ver" ]] && break
      ver=""
    done
    printf 'plugin\t%s\t%s\n' "$(basename "$d")" "$ver"
  done

  # Themes tragen ihre Fassung in style.css.
  for d in "${REZ_PFAD}"/wp-content/themes/*/; do
    [[ -d "$d" ]] || continue
    d="${d%/}"; ver=""
    [[ -f "$d/style.css" ]] && ver=$(_wp_kopf_version "$d/style.css" "Theme Name")
    printf 'theme\t%s\t%s\n' "$(basename "$d")" "${ver:-}"
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
  if ! ls "${basis}"/vuln/*.tsv >/dev/null 2>&1; then
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
  ergebnis=$(printf '%s\n' "$bestand" | python3 "$vergleicher" --daten "$basis" 2>/dev/null || true)
  [[ -n "$ergebnis" ]] || return 0

  # Betroffene einzeln melden — anders als beim ⚪ unten ist hier jeder Fall
  # eine eigene Handlung: dieses Plugin auf diese Fassung bringen.
  while IFS=$'\t' read -r zustand typ slug version bereich behoben cve kev _quelle; do
    [[ "$zustand" == "BETROFFEN" ]] || continue
    local satz="${REZ_KURZ}: ${typ} ${slug} ${version} ist von einer bekannten Schwachstelle betroffen (${bereich})"
    [[ -n "$cve" ]]     && satz+=" ${cve}"
    [[ -n "$behoben" ]] && satz+=" — behoben in ${behoben}"
    if [[ "$kev" == "ja" ]]; then
      befund_melden wordpress version crit \
        "${satz}. Diese Lücke wird nachweislich aktiv ausgenutzt — sofort handeln." "$REZ_PFAD" web
    else
      befund_melden wordpress version warn "${satz}." "$REZ_PFAD" web
    fi
  done <<< "$ergebnis"

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
      n_ohne=$((n_ohne+1)); continue
    fi
    ziel="${cache}/${slug}-${ver}.json"
    if [[ ! -s "$ziel" ]] && ! _wp_pruefsummen_holen "$slug" "$ver" "$ziel"; then
      rm -f "$ziel"
      # Kein Prüfsummensatz. Zwei Ursachen, hier nicht unterscheidbar: das
      # Plugin liegt nicht im wordpress.org-Verzeichnis (Premium, Fork,
      # Eigenbau), oder die Fassung ist dort nicht veröffentlicht.
      n_ohne=$((n_ohne+1)); continue
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

  [[ "${n_soft:-0}" -gt 0 ]] && befund_melden wordpress kern warn \
    "${REZ_KURZ}: ${n_soft} veränderte Nicht-Codedatei(en) in Plugins (readme, Übersetzungen, Stilvorlagen) — meist harmlos" "$REZ_PFAD"

  [[ "${n_fehlt:-0}" -gt 0 ]] && befund_melden wordpress kern warn \
    "${REZ_KURZ}: ${n_fehlt} im Prüfsummensatz geführte Plugin-Datei(en) fehlen auf der Platte" "$REZ_PFAD"

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
  [[ "${n_ohne:-0}" -gt 0 ]] && befund_melden wordpress kern unklar \
    "${REZ_KURZ}: ${n_ohne} Plugin(s) ohne Prüfsummensatz und alle Themes — Unversehrtheit nicht feststellbar (Premium, Fork, Eigenbau; für Themes veröffentlicht wordpress.org keine Prüfsummen)" "$REZ_PFAD" web

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
# Die Werkzeug-Probe hat der Rahmen gezogen; eine leere Ausgabe heißt hier
# wirklich 'keine Abweichung' und nicht 'wp-cli ist gescheitert'.
rezept_kern() {
  local CHK cmod csne LISTE CHK_ROH CHK_RC
  # Rückgabewert getrennt festhalten. Bis v3.12 stand hier nur die gefilterte
  # Ausgabe, und der Status der Pipe war der von `grep` — ein gescheitertes
  # verify-checksums war damit von einem sauberen Kern nicht zu unterscheiden.
  # Für den Befund unten machte das keinen Unterschied (beides ergab cmod=0,
  # was hier bewusst als "keine Abweichung" gilt), für die Whitelist in
  # Abschnitt 13c aber sehr wohl: sie darf einen Kern nur dann freigeben, wenn
  # er nachweislich geprüft WURDE.
  CHK_ROH=$(_wp core verify-checksums 2>&1); CHK_RC=$?
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

# ── Datenbank ────────────────────────────────────────────────
# Read-only, ausschließlich SELECT. Der Rahmen hat den Zugang aufgebaut und
# das Präfix gehärtet — ohne diese Härtung ging der Wert aus wp-config.php roh
# in die Abfragen, und wer die Datei schreiben kann, bekam damit beliebiges SQL
# in ein Werkzeug, das als root läuft.
rezept_db() {
  if ! werkzeug_da mysql && [[ -z "${REZ_WERKZEUG:-}" ]]; then
    befund_melden wordpress datenbank unklar "${REZ_KURZ}: weder mysql-Client noch wp-cli vorhanden — Datenbank nicht geprüft" "$REZ_PFAD" web
    return 0
  fi
  rezept_db_zugang "${REZEPT_DIR}/wordpress" "${REZ_PFAD}/wp-config.php" || return 0
  if ! rezept_sql "SELECT 1;" >/dev/null 2>&1; then
    befund_melden wordpress datenbank warn "${REZ_KURZ}: keine DB-Verbindung (Zugang prüfen) — Datenbankabfragen übersprungen" "${REZ_PFAD}/wp-config.php" web
    return 0
  fi

  # a) Kürzlich angelegte Administratoren. Der eindeutigste Einzelbefund: ein
  # Admin, der erst nach dem Vorfall entstand, ist praktisch nie legitim.
  local NEU
  NEU=$(rezept_sql "SELECT u.user_login, u.user_email, u.user_registered FROM ${REZ_PFX}users u
         JOIN ${REZ_PFX}usermeta m ON u.ID=m.user_id
         WHERE m.meta_key='${REZ_PFX}capabilities' AND m.meta_value LIKE '%administrator%'
         AND u.user_registered > DATE_SUB(NOW(), INTERVAL ${DAYS_BACK} DAY);")
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
  else
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
  fi

  # c) Manipulierte Optionen. siteurl/home weisen auf einen Redirect-Hijack,
  # auto_prepend_file auf eine dauerhaft nachgeladene Nutzlast.
  local OPT
  OPT=$(rezept_sql "SELECT option_name, LEFT(option_value,120) FROM ${REZ_PFX}options
         WHERE option_name IN ('siteurl','home')
            OR option_value LIKE '%auto_prepend_file%'
            OR option_value LIKE '%base64_decode%';")
  [[ -n "$OPT" ]] && { info "${REZ_KURZ}: Optionen (siteurl/home und Auffälligkeiten):"; code "$OPT"; }
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
