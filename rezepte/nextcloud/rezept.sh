# shellcheck shell=bash
# ============================================================
# NT-Forensik — Prüfrezept Nextcloud: die Haken
# ------------------------------------------------------------
# Nur das, was der Rahmen nicht kann. Finden, Kopienfilter, Leerfall,
# Werkzeug-Probe, Signaturen und Verdikt macht lib/rezepte.sh.
#
# Diese Datei fasst zusammen, was bis v3.12 in module/12b_nextcloud.sh
# (Übernahme) und module/12c_nextcloud_haertung.sh (Härtungsstand) stand. Die
# beiden waren zu rund 95 % wortgleich: Findeverfahren, Kopienfilter,
# Leerfall-Behandlung und PHP-Suche standen doppelt, mit Abweichungen, die
# niemand beabsichtigt hatte — 12b meldete Sicherungskopien als warn, 12c als
# info, obwohl die Begründung dieselbe war.
#
# Aufgerufen wird je Installation mit:
#   $REZ_PFAD   absoluter Pfad der Installation
#   $REZ_KURZ   Pfad relativ zu $VHOSTS_DIR (für Meldungen)
#   $OCC        Funktion, die occ als Eigentümer ausführt
#
# Die Namen tragen bewusst ein Präfix. Die erste Fassung nannte die Variable
# schlicht NC — und NC ist im Werkzeug die Farb-Reset-Sequenz. Jede Ausgabe
# klebte am Pfad und war unlesbar. Derselbe Fehler war am 07.08.2026 schon
# einmal in den Nextcloud-Abschnitten passiert.
# ============================================================

# ── Kern-Integrität ──────────────────────────────────────────
# Das Gegenstück zu 'wp core verify-checksums'. Es findet Dateien, die im Kern
# nichts zu suchen haben — genau die Klasse, die Signaturscanner übersieht,
# weil an ihr nichts auffällig aussieht.
#
# Die Werkzeug-Probe hat der Rahmen bereits gezogen; hier ist occ nachweislich
# ansprechbar. Eine leere Ausgabe heißt deshalb wirklich 'keine Abweichung'.
rezept_kern() {
  local _int
  _int=$($OCC integrity:check-core 2>/dev/null | head -40 || true)
  if [[ -z "$_int" ]]; then
    befund_melden nextcloud kern ok "${REZ_KURZ}: occ integrity:check-core meldet keine Abweichung" "$REZ_PFAD"
  else
    befund_melden nextcloud kern crit "${REZ_KURZ}: occ integrity:check-core meldet Abweichungen im Kern" "$REZ_PFAD" web
    code "$(printf '%s\n' "$_int" | head -20)"
    evidence "nextcloud_integritaet_$(echo "$REZ_KURZ" | tr '/.' '__')" "$_int"
    # findings.json liest daraus NUR die Kopfzeilen (grep '^=== ') und macht
    # daraus die Liste betroffener Instanzen — nicht den occ-Text selbst.
    NC_INTEGRITY+="=== ${REZ_KURZ} ==="$'\n'"$_int"$'\n'
  fi
}

# ── Konfiguration und Härtung ────────────────────────────────
rezept_konfig() {
  # Datenverzeichnis. Liegt es im Webroot, ist der einzige Schutz eine
  # .htaccess — und die ist das erste, was ein Angreifer ersetzt. Ob sie
  # wirklich sperrt, wird abgerufen und nicht vermutet.
  local _data _dom _url _code _rel
  _data=$($OCC config:system:get datadirectory | tr -d '\r' || true)
  if [[ -z "$_data" ]]; then
    befund_melden nextcloud konfig unklar "${REZ_KURZ}: datadirectory nicht auslesbar — Lage des Datenverzeichnisses nicht geprüft" "$REZ_PFAD" web
  elif [[ "$_data" == "${REZ_PFAD}"* ]]; then
    _rel="${_data#"${REZ_PFAD}"/}"
    _dom=$($OCC config:system:get trusted_domains 0 | tr -d '\r' || true)
    if [[ -n "$_dom" ]]; then
      _url="https://${_dom}/${_rel}/.ocdata"
      _code=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 12 "$_url" 2>/dev/null || echo "000")
      case "$_code" in
        200) befund_melden nextcloud konfig crit "${REZ_KURZ}: Datenverzeichnis ist über das Netz abrufbar (HTTP 200) — sämtliche Nutzerdateien sind öffentlich" "$_data" web ;;
        000) befund_melden nextcloud konfig unklar "${REZ_KURZ}: Datenverzeichnis liegt im Webroot; Abruf nicht möglich — Schutz unbelegt" "$_data" web ;;
        *)   befund_melden nextcloud konfig warn "${REZ_KURZ}: Datenverzeichnis liegt im Webroot, wird aber gesperrt (HTTP ${_code}) — der Schutz hängt an einer einzigen .htaccess" "$_data" web ;;
      esac
    else
      befund_melden nextcloud konfig warn "${REZ_KURZ}: Datenverzeichnis liegt im Webroot (${_data})" "$_data" web
    fi
  else
    befund_melden nextcloud konfig ok "${REZ_KURZ}: Datenverzeichnis außerhalb des Webroots" "$_data"
  fi

  # Administratorkonten. Jedes ist ein vollwertiger Zugang.
  local _n_adm
  _n_adm=$($OCC group:list --output=json \
           | python3 -c "import json,sys;print(len(json.load(sys.stdin).get('admin',[])))" 2>/dev/null || echo "?")
  if [[ "$_n_adm" =~ ^[0-9]+$ && "$_n_adm" -gt 2 ]]; then
    befund_melden nextcloud konfig warn "${REZ_KURZ}: ${_n_adm} Administratorkonten — jedes davon ist ein vollwertiger Zugang" "$REZ_PFAD" web
  fi
  info "${REZ_KURZ}: App-Passwörter überleben jeden Passwortwechsel. Nach einem Vorfall müssen sie eigens widerrufen werden (occ user:auth-tokens:delete <konto> --all)."

  # Zweiter Faktor. twofactor_backupcodes ist ab Werk aktiv und KEIN zweiter
  # Faktor — es erzeugt nur Notfallcodes für den Fall, dass einer besteht.
  # Mitgezählt meldete die Prüfung bei jeder unveränderten Nextcloud
  # 'Zwei-Faktor verfügbar', eine Entwarnung, die nichts deckt.
  local _2fa
  _2fa=$($OCC app:list --output=json | python3 -c "
import json,sys
d=json.load(sys.stdin).get('enabled',{})
print(','.join(k for k in d if k.startswith('twofactor_') and k != 'twofactor_backupcodes'))" 2>/dev/null || true)
  if [[ -n "$_2fa" ]]; then
    befund_melden nextcloud konfig ok "${REZ_KURZ}: zweiter Faktor verfügbar (${_2fa})" "$REZ_PFAD"
  else
    befund_melden nextcloud konfig warn "${REZ_KURZ}: kein zweiter Faktor eingerichtet — ein erbeutetes Passwort genügt für den vollen Zugang (twofactor_backupcodes zählt nicht, das sind nur Notfallcodes)" "$REZ_PFAD" web
  fi

  # Protokollstufe. Bei 3/4 werden Anmeldungen nicht protokolliert — ein
  # späterer Vorfall ist dann nicht mehr rekonstruierbar.
  local _loglvl
  _loglvl=$($OCC config:system:get loglevel | tr -d '\r' || echo "")
  if [[ "$_loglvl" =~ ^[3-4]$ ]]; then
    befund_melden nextcloud logs warn "${REZ_KURZ}: loglevel steht auf ${_loglvl} (nur Fehler) — Anmeldungen und Zugriffe werden nicht protokolliert, ein Vorfall ist später nicht rekonstruierbar" "$REZ_PFAD" web
  else
    befund_melden nextcloud logs ok "${REZ_KURZ}: loglevel ${_loglvl:-Vorgabe}" "$REZ_PFAD"
  fi

  # Vertrauenswürdige Domains. Jeder Eintrag erlaubt den Betrieb unter dieser
  # Adresse — ein fremder darunter ist ein Übernahmeweg.
  local _td _td_n
  _td=$($OCC config:system:get trusted_domains | tr -d '\r' | grep -vE '^$' || true)
  _td_n=$(printf '%s\n' "$_td" | grep -c . || true)
  if [[ "$_td_n" -gt 3 ]]; then
    befund_melden nextcloud konfig warn "${REZ_KURZ}: ${_td_n} vertrauenswürdige Domains eingetragen — jede erlaubt den Betrieb der Instanz unter dieser Adresse" "$REZ_PFAD" web
    code "$_td"
  else
    befund_melden nextcloud konfig ok "${REZ_KURZ}: ${_td_n} vertrauenswürdige Domain(s)" "$REZ_PFAD"
  fi

  # Rechte auf der Konfiguration: sie enthält Datenbankzugang und Instanz-Salt.
  local _cfg_r
  _cfg_r=$(datei_meta "${REZ_PFAD}/config/config.php" rechte)
  if [[ -n "$_cfg_r" && "$_cfg_r" != "?" && ! "$_cfg_r" =~ ^(600|640|660)$ ]]; then
    befund_melden nextcloud konfig warn "${REZ_KURZ}: config/config.php hat Rechte ${_cfg_r} — sie enthält Datenbankzugang und Instanz-Salt" "${REZ_PFAD}/config/config.php" web
  elif [[ -n "$_cfg_r" && "$_cfg_r" != "?" ]]; then
    befund_melden nextcloud konfig ok "${REZ_KURZ}: config/config.php Rechte ${_cfg_r}" "${REZ_PFAD}/config/config.php"
  fi
}

# ── Kampagnenspezifisches ────────────────────────────────────
# Der Angriff arbeitete WordPress-artig: eine Root-.htaccess, die PHP pauschal
# sperrt und genau die eigenen Dateien freigibt, dazu verschachtelte
# Verzeichnisse mit je einer index.php. Eine so präparierte Nextcloud fällt im
# Betrieb nur dadurch auf, dass Clients keine Verbindung mehr bekommen — im
# Apache-Log steht dann AH01797, was wie ein Rechteproblem aussieht.
rezept_sonder() {
  # Root-.htaccess. Das aussagekräftigste Einzelmerkmal: eine echte
  # Nextcloud-.htaccess enthält Rewrites für remote.php und .well-known.
  local _ht="${REZ_PFAD}/.htaccess" _mal
  if [[ -r "$_ht" ]]; then
    _mal=$(grep -nEi 'filefuns|adminfuns|cjfuns|classsmtps|wp-login\.php|Order allow,deny' "$_ht" 2>/dev/null | head -6 || true)
    if [[ -n "$_mal" ]]; then
      befund_melden nextcloud schadcode crit "${REZ_KURZ}: Root-.htaccess trägt Angreifer-Merkmale (Freigabeliste mit fremden Dateinamen)" "$_ht" web
      code "$_mal"
      NC_HTACCESS_MAL+="${_ht}"$'\n'
      evidence "nextcloud_htaccess_$(echo "$REZ_KURZ" | tr '/.' '__')" \
        "$(datei_steckbrief 'Root-.htaccess mit WordPress-Freigabeliste — bei Nextcloud nie legitim' \
           'filefuns|adminfuns|cjfuns|classsmtps|wp-login\.php|Order allow,deny' "$_ht")"
    elif ! grep -qE 'remote\.php|well-known' "$_ht" 2>/dev/null; then
      befund_melden nextcloud schadcode warn "${REZ_KURZ}: Root-.htaccess ohne Nextcloud-Rewrites (remote.php / .well-known) — vermutlich ersetzt" "$_ht" web
    else
      befund_melden nextcloud schadcode ok "${REZ_KURZ}: Root-.htaccess sieht nach Nextcloud aus" "$_ht"
    fi
  else
    befund_melden nextcloud schadcode warn "${REZ_KURZ}: keine Root-.htaccess vorhanden — Zugriffsschutz und Rewrites fehlen" "$REZ_PFAD" web
  fi

  # Verschachtelte Verzeichnisse (config/config, data/data). In einer gesunden
  # Instanz gibt es das nicht; die Ausnahmeliste aus rezept.conf fängt die
  # Fälle ab, in denen es doch normal ist.
  local _legit _nest="" _n _t
  _legit="$(rezept_feld "${REZEPT_DIR}/nextcloud" legitim_regex)"
  for _n in config data images ocs dist core apps; do
    _t=$(find "$REZ_PFAD" -maxdepth 4 -type d -path "*/${_n}/${_n}" 2>/dev/null | grep -vE "$_legit" || true)
    [[ -n "$_t" ]] && _nest+="$_t"$'\n'
  done
  _nest=$(printf '%s\n' "$_nest" | grep -vE '^$' || true)
  if [[ -n "$_nest" ]]; then
    befund_melden nextcloud schadcode crit "${REZ_KURZ}: verschachtelte Verzeichnisse (z. B. config/config) — typisch für diese Kampagne" "$(printf '%s' "$_nest" | head -1)" web
    code "$_nest"
    NC_NESTED+="$_nest"$'\n'
  else
    befund_melden nextcloud schadcode ok "${REZ_KURZ}: keine verschachtelten Verzeichnisse" "$REZ_PFAD"
  fi

  # Aufgeblähte index.php. Die echte ist rund 3,7 KB; die präparierte war
  # 50 KB groß und enthielt goto-Sprünge und hexkodierte Zeichenketten.
  if [[ -f "${REZ_PFAD}/index.php" ]]; then
    local _sz; _sz=$(wc -c < "${REZ_PFAD}/index.php" | tr -d ' ')
    if [[ "$_sz" -gt 20000 ]]; then
      befund_melden nextcloud schadcode crit "${REZ_KURZ}: index.php ist ${_sz} Bytes groß (Nextcloud liefert rund 3.700)" "${REZ_PFAD}/index.php" web
      NC_MALWARE+="${REZ_PFAD}/index.php"$'\n'
      evidence "nextcloud_index_$(echo "$REZ_KURZ" | tr '/.' '__')" \
        "$(datei_steckbrief 'index.php um ein Vielfaches zu gross — Nextcloud liefert rund 3.700 Bytes' \
           'goto |\\x[0-9a-f]{2}|eval|base64_decode' "${REZ_PFAD}/index.php")"
    else
      befund_melden nextcloud schadcode ok "${REZ_KURZ}: index.php unauffällig (${_sz} Bytes)" "${REZ_PFAD}/index.php"
    fi
  fi
}

# ── Verdikt ──────────────────────────────────────────────────
# Pflicht im Rezeptvertrag. Abschnitt 12b hatte bis v3.12 gar keins, obwohl
# findings.json für WordPress und Joomla ein {flags,text}-Paar liefert — der
# offensichtlichste Kandidat für einen Vertragsbestandteil.
rezept_verdikt() {
  local n; n=$(printf '%s' "${BEFUNDE:-}" | grep -c $'^nextcloud\t.*\tcrit\t' || true)
  if [[ "${n:-0}" -gt 0 ]]; then
    verdikt_melden nextcloud "$n" "🔴 ${n} kritische Nextcloud-Befunde — Übernahme belegt oder dringend abzuklären."
  elif printf '%s' "${UNKNOWN_LIST:-}" | grep -q 'nicht geprüft\|nicht messbar'; then
    verdikt_melden nextcloud 0 "⚪ Nextcloud teilweise nicht prüfbar — kein Befund, aber auch keine Entwarnung."
  else
    verdikt_melden nextcloud 0 "🟢 Keine Hinweise auf eine übernommene Nextcloud."
  fi
}
