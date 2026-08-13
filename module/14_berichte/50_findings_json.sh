# shellcheck shell=bash
# NT-Forensik — Abschnitt 14, Teil: findings.json — die Schnittstelle zum Reparaturteil
#
# Unterabschnitt von module/14_berichte.sh. Wird vom Runner nach dem
# Hauptmodul geladen (siehe modul_teile_laden in wp_plesk_forensik.sh) und
# teilt sich dessen Variablen. Nicht einzeln ausfuehrbar.

# ── Maschinenlesbarer Export für das Repair-Tool (findings.json) ──
# Kein jq-Zwang; JSON von Hand aus vorhandenen Variablen/Belegen gebaut.
FINDINGS_FILE="${BETREIBER_DIR}/findings.json"

# JSON-Maskierung. Steuerzeichen MÜSSEN maskiert werden, sonst ist die Datei
# ungültig (v3.8): Tabulatoren stecken in praktisch jeder Zeile, die aus
# `mysql -N` stammt (ROGUE_ADMINS, Joomla-DB-Abfragen) — vorher erzeugte genau
# der Fall, auf den es ankommt (ein echter Fund), unlesbares findings.json und
# damit einen stillen Ausfall des Anschreiben-Generators.
# Reihenfolge ist zwingend: erst Backslash, dann Anführungszeichen, dann
# Steuerzeichen — sonst werden die selbst eingefügten Backslashes nochmals
# maskiert. Das abschließende tr entfernt die restlichen, nicht darstellbaren
# Steuerzeichen (ohne \t und \r, die oben bereits behandelt sind).
json_esc() { sed 's/\\/\\\\/g; s/"/\\"/g; s/\t/\\t/g; s/\r/\\r/g' | tr -d '\000-\010\013\014\016-\037'; }
json_str() {   # einzeiliger String → JSON-escaped (ohne Anführungszeichen)
  printf '%s' "$1" | tr '\n' ' ' | json_esc
}
json_arr() {   # stdin: ein Item pro Zeile → JSON-Array von Strings
  local first=1 out="[" line esc
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    esc=$(printf '%s' "$line" | json_esc)
    if [ "$first" -eq 1 ]; then out="${out}\"${esc}\""; first=0; else out="${out},\"${esc}\""; fi
  done
  printf '%s]' "$out"
}

# stdin: <pfad>\t<benutzer>\t<email>\t<angelegt> → JSON-Array von Objekten
#
# Warum Objekte und nicht wieder Strings: die Bereinigung muss `wp --path=…`
# aufrufen koennen. Ein Benutzername ohne Installation ist auf einem Server
# mit 475 vhosts nicht handlungsfaehig, sondern gefaehrlich — derselbe Name
# existiert dort vielfach. Genau daran scheiterte rogue_admin_removed.
#
# Fehlende Felder bleiben leer statt zu verrutschen: gelesen wird nach
# Spaltennummer, nicht nach Anzahl.
json_admin_arr() {
  local first=1 out="[" line pfad ben mail wann
  while IFS=$'\t' read -r pfad ben mail wann; do
    [ -z "${pfad}${ben}" ] && continue
    [ "$first" -eq 1 ] && first=0 || out="${out},"
    out="${out}{\"pfad\":\"$(printf '%s' "${pfad:-}" | json_esc)\""
    out="${out},\"benutzer\":\"$(printf '%s' "${ben:-}" | json_esc)\""
    out="${out},\"email\":\"$(printf '%s' "${mail:-}" | json_esc)\""
    out="${out},\"angelegt\":\"$(printf '%s' "${wann:-}" | json_esc)\"}"
  done
  printf '%s]' "$out"
}

# stdin: <pfad>\t<eintrag> → JSON-Array von Objekten (Persistenz-Zweig, #47)
#
# Objekte statt Strings aus demselben Grund wie bei json_admin_arr: ein
# Eintrag ohne Installationspfad ist auf einem Server mit 475 vhosts nicht
# zuzuordnen. Die Bereinigung liest diese Listen bewusst NICHT.
json_db_arr() {
  local first=1 out="[" pfad eintrag
  while IFS=$'\t' read -r pfad eintrag; do
    [ -z "${pfad}${eintrag}" ] && continue
    [ "$first" -eq 1 ] && first=0 || out="${out},"
    out="${out}{\"pfad\":\"$(printf '%s' "${pfad:-}" | json_esc)\""
    out="${out},\"eintrag\":\"$(printf '%s' "${eintrag:-}" | json_esc)\"}"
  done
  printf '%s]' "$out"
}

# stdin: <ctime>\t<mtime>\t<pfad> → JSON-Array von Objekten (Abschnitt 13e)
#
# Rohe Sekunden, keine formatierten Zeitangaben. Wer die Achse
# weiterverarbeitet, will rechnen koennen; die lesbare Fassung steht im Bericht
# und im Beleg. Beide Zeitstempel wandern mit: erst ihr VERHAELTNIS trennt den
# Angreifer von der eigenen Gegenmassnahme.
json_zeitachse_arr() {
  local first=1 out="[" ct mt pfad
  while IFS=$'\t' read -r ct mt pfad; do
    [ -z "$pfad" ] && continue
    [ "$first" -eq 1 ] && first=0 || out="${out},"
    out="${out}{\"pfad\":\"$(printf '%s' "$pfad" | json_esc)\""
    out="${out},\"ctime\":${ct:-0},\"mtime\":${mt:-0}}"
  done
  printf '%s]' "$out"
}

emit_findings_json() {
  local ws php suid tmpx immu cron sysd persist procs wpc fkeys aips bips suspadm nchta ncmal ncnest ncint
  local corei coresne doorw coreinj disg rogue rogued suspadmd uzeit dbleichen dboptcode
  dbleichen=$(printf '%s\n' "${WP_PLUGIN_LEICHEN:-}" | json_db_arr)
  dboptcode=$(printf '%s\n' "${WP_OPT_CODE:-}"       | json_db_arr)
  # Zeitachse aus 13e. Leer, wenn 13e nichts belastet fand oder uebersprungen
  # wurde — dann bleibt das Array leer, nicht das Feld weg.
  uzeit=$(printf '%s\n' "${U_TAB:-}" | json_zeitachse_arr)
  corei=$(printf '%s\n' "${CORE_INJECTED:-}"      | json_arr)
  coresne=$(printf '%s\n' "${CORE_SNE:-}"         | json_arr)
  doorw=$(printf '%s\n' "${DOORWAY_DIRS:-}"       | json_arr)
  coreinj=$(printf '%s\n' "${CORE_INJECT_HITS:-}" | json_arr)
  disg=$(printf '%s\n' "${DISGUISED_PAYLOADS:-}"  | json_arr)
  rogue=$(printf '%s\n' "${ROGUE_ADMINS:-}"       | grep -vE '^=== |^$' | json_arr)
  suspadm=$(printf '%s\n' "${SUSPECT_ADMINS:-}"   | grep -vE '^=== |^$' | json_arr)
  # Die handlungsfaehige Fassung: je Eintrag ein Objekt MIT Installationspfad.
  # Die beiden flachen Listen daruber bleiben unveraendert — sie zaehlen und
  # werden vom Berichtsgenerator gelesen. Neu ist additiv, siehe
  # docs/findings-schnittstelle.md.
  rogued=$(printf '%s\n'   "${ROGUE_ADMINS_DETAIL:-}"   | json_admin_arr)
  suspadmd=$(printf '%s\n' "${SUSPECT_ADMINS_DETAIL:-}" | json_admin_arr)
  # v3.12 (#3): zwei Quellen, die es vorher gar nicht als Liste gab. Die
  # Signaturtreffer standen bis hierher ausschliesslich im Menschentext, und
  # zwar nur der erste je Muster — der Reparaturteil bekam sie nie zu sehen,
  # obwohl genau sie im Vorfall in der Quarantaenetabelle landeten.
  # Der Pruefumfang, maschinenlesbar. werkzeuge/kundenpaket.sh braucht ihn, um
  # dieselbe Maskierung anzuwenden wie der Lauf — ohne SCOPE_MODE, ABO_USER und
  # SCAN_PATHS kann nf_fremdkunden_maskieren nicht entscheiden, was "eigen" ist,
  # und maskiert dann lieber gar nicht. Ein Paketwerkzeug, das diese Angabe
  # raten muesste, wuerde entweder den eigenen Kunden unkenntlich machen oder
  # fremde stehen lassen.
  local scanp; scanp=$(printf '%s\n' "${SCAN_PATHS[@]:-}" | json_arr)
  local sigtr plugmod
  sigtr=$(printf '%s\n'   "${SIGNATUR_TREFFER:-}"  | json_arr)
  plugmod=$(printf '%s\n' "${PLUGIN_VERAENDERT:-}" | json_arr)
  local suspp muplug tamphta
  suspp=$(printf '%s\n' "${SUSP_PLUGINS:-}"       | json_arr)
  muplug=$(printf '%s\n' "${MU_PLUGINS:-}"        | json_arr)
  tamphta=$(printf '%s\n' "${TAMPERED_HTACCESS:-}" | json_arr)
  # Nextcloud (Abschnitte 12b/12c). Ohne diese Zuweisungen greift unten
  # ausnahmslos der Vorgabewert [] — die Schluessel stuenden dann auch bei
  # echten Funden leer in der findings.json, und NT-Repair saehe nichts.
  nchta=$(printf '%s\n'  "${NC_HTACCESS_MAL:-}" | json_arr)
  ncmal=$(printf '%s\n'  "${NC_MALWARE:-}"      | json_arr)
  ncnest=$(printf '%s\n' "${NC_NESTED:-}"       | json_arr)
  ncint=$(printf '%s\n'  "${NC_INTEGRITY:-}"    | grep '^=== ' | sed 's/^=== //; s/ ===$//' | json_arr)
  local nchard; nchard=$(printf '%s\n' "${NC_HAERTUNG:-}" | json_arr)
  # Abschnitt 16. htaccess_fremd nennt die Dateien mit Angreifer-Direktiven;
  # htaccess_unwirksam sagt, ob .htaccess ueberhaupt ausgewertet wird — ohne
  # das koennte der Reparaturteil eine Datei saeubern, die niemand liest.
  # ── Generisches Befundschema (v3.12) ───────────────────────
  # Gruppiert nach Anwendung und Kategorie. Der Bericht kennt die Kategorien,
  # nicht die Anwendungsnamen — genau das macht einen neuen Scanner kernfrei.
  local befgen verdgen
  befgen=$(printf '%s' "${BEFUNDE:-}" | python3 -c '
import json, sys
raus = {}
for z in sys.stdin.read().split("\n"):
    if not z.strip():
        continue
    teil = z.split("\t")
    if len(teil) < 5:
        continue
    app, kat, schwere, text, pfad = teil[0], teil[1], teil[2], teil[3], teil[4]
    # Unauffaellige Einzelbefunde nicht mitschleppen: sie sind der Normalfall
    # und blaehen die Datei um ein Vielfaches auf, ohne dass ein Leser damit
    # etwas anfaengt. Die Zahl steht in counts.ok.
    if schwere == "ok":
        continue
    raus.setdefault(app, {}).setdefault(kat, []).append(
        {"schwere": schwere, "text": text, "pfad": pfad})
print(json.dumps(raus, ensure_ascii=False))' 2>/dev/null || echo '{}')
  verdgen=$(printf '%s' "${VERDIKTE:-}" | python3 -c '
import json, sys
raus = {}
for z in sys.stdin.read().split("\n"):
    if not z.strip():
        continue
    teil = z.split("\t")
    if len(teil) < 3:
        continue
    raus[teil[0]] = {"flags": int(teil[1]) if teil[1].isdigit() else 0, "text": teil[2]}
print(json.dumps(raus, ensure_ascii=False))' 2>/dev/null || echo '{}')

  local htafremd htaunw
  htafremd=$(printf '%s\n' "${HTACCESS_FREMD:-}" | json_arr)
  htaunw=$(json_str "${HTACCESS_UNWIRKSAM:-}")
  local n_corei n_doorw n_coreinj n_rogue
  n_corei=$(printf '%s\n'   "${CORE_INJECTED:-}"     | grep -c . 2>/dev/null)
  n_doorw=$(printf '%s\n'   "${DOORWAY_DIRS:-}"      | grep -c . 2>/dev/null)
  n_coreinj=$(printf '%s\n' "${CORE_INJECT_HITS:-}"  | grep -c . 2>/dev/null)
  n_rogue=$(printf '%s\n'   "${ROGUE_ADMINS:-}"      | grep -vE '^=== |^$' | grep -c . 2>/dev/null)
  local n_suspp; n_suspp=$(printf '%s\n' "${SUSP_PLUGINS:-}" | grep -c . 2>/dev/null)
  ws=$(echo "${DROPPER_DETAIL:-}"      | grep '^=== ' | sed 's/^=== //; s/ ===$//' | json_arr)
  # Abschnitt 7.6b: namentlich freigegeben, kein bekannter Einstiegspunkt, und
  # vorhanden. Eigener Schluessel statt in webshell_dropper hineingemischt —
  # die Herkunft eines Quarantaenekandidaten muss ablesbar bleiben.
  local wsn; wsn=$(printf '%s\n' "${WEBSHELL_NAMEN:-}" | json_arr)
  php=$(printf '%s\n' "${PHP_IN_UPLOADS:-}"    | json_arr)
  suid=$(printf '%s\n' "${SUID_FILES:-}"       | json_arr)
  tmpx=$(printf '%s\n' "${TMP_EXECS:-}"        | json_arr)
  immu=$(printf '%s\n' "${IMMUTABLE:-}"        | json_arr)
  cron=$(printf '%s\n' "${SUSP_CRON:-}"        | json_arr)
  sysd=$(printf '%s\n' "${SUSP_UNITS:-}"       | json_arr)
  persist=$(printf '%s\n' "${PERSIST_REPORT:-}" | grep '^=== ' | sed 's/^=== //; s/ ===$//' | json_arr)
  procs=$(printf '%s\n%s\n%s\n' "${MINER_PROCS:-}" "${DELETED_SUSPECT:-}" "${REVSHELL:-}" | json_arr)
  wpc=$(printf '%s\n' "${WP_CONFIGS:-}"        | json_arr)
  fkeys=$(printf '%s\n' "${FOREIGN_KEYS:-}"    | json_arr)
  aips=$(printf '%s\n' "${ATTACK_IPS_UNIQ:-}"  | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | json_arr)
  bips=$(printf '%s\n' "${TOP_FAIL_IPS:-}"     | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | json_arr)
  # v3.4 Relay-Backdoors — Prozess-/Datei-Introspektion (Abschnitte 5.6/5.7, 6.9, 7.10/7.11, 8.7–8.12)
  local gsock masq fless kthr orph sshh relc yhit
  gsock=$(printf '%s\n' "${GSOCKET_HITS:-}"     | json_arr)
  masq=$(printf '%s\n'  "${MASQ_BINARIES:-}"    | json_arr)
  fless=$(printf '%s\n' "${FILELESS_PROCS:-}"   | json_arr)
  kthr=$(printf '%s\n'  "${KTHREAD_FAKES:-}"    | json_arr)
  orph=$(printf '%s\n'  "${ORPHAN_SHELLS:-}"    | json_arr)
  sshh=$(printf '%s\n'  "${SSH_LOGIN_HOOKS:-}"  | json_arr)
  relc=$(printf '%s\n'  "${RELAY_CONNECTIONS:-}" | json_arr)
  yhit=$(printf '%s\n'  "${YARA_HITS:-}"        | json_arr)
  # v3.6 System-Integrität & Scanner-Taps
  local tstomp recsys imuh wptk malsum
  # Mail-Kontext für den Anschreiben-Generator (null, wenn keine Funde)
  if [[ "${MALWARE_TOTAL:-0}" -gt 0 ]]; then
    malsum="{ \"total\": ${MALWARE_TOTAL}, \"affected_area\": \"$(json_str "${MAIL_AREA:-}")\", \"finding_summary\": \"$(json_str "${MAIL_FINDING:-}")\", \"timeframe\": \"$(json_str "${MAIL_TIMEFRAME:-}")\", \"newest\": \"${MAIL_NEWEST:-}\", \"families\": ${MAIL_FAMILIES_JSON} }"
  else
    malsum="null"
  fi
  tstomp=$(printf '%s\n' "${TIMESTOMP:-}"       | json_arr)
  recsys=$(printf '%s\n' "${RECENT_SYS:-}"      | json_arr)
  imuh=$(printf '%s\n'   "${IMUNIFY_HITS:-}"    | json_arr)
  wptk=$(printf '%s\n'   "${WPTK_INFECTED:-}"   | json_arr)
  # v3.8 Joomla-Prüfung + Netz-Transparenz
  local jcfg jver jcweak jlog jcmod jcunk jsysp jsuper jsess jmodc jtpl jukeys jvuln jmal onlinef
  jcfg=$(printf   '%s\n' "${JOOMLA_CONFIGS:-}"       | json_arr)
  jver=$(printf   '%s\n' "${JOOMLA_VERSIONS:-}"      | json_arr)
  jcweak=$(printf '%s\n' "${JOOMLA_CONFIG_WEAK:-}"   | grep -vE '^=== |^$' | json_arr)
  jlog=$(printf   '%s\n' "${JOOMLA_LOG_IOC:-}"       | json_arr)
  jcmod=$(printf  '%s\n' "${JOOMLA_CORE_MODIFIED:-}" | json_arr)
  jcunk=$(printf  '%s\n' "${JOOMLA_CORE_UNKNOWN:-}"  | json_arr)
  jsysp=$(printf  '%s\n' "${JOOMLA_SYS_PLUGINS:-}"   | json_arr)
  jsuper=$(printf '%s\n' "${JOOMLA_ROGUE_SUPER:-}"   | grep -vE '^=== |^$' | json_arr)
  jsess=$(printf  '%s\n' "${JOOMLA_SESSION_HITS:-}"  | json_arr)
  jmodc=$(printf  '%s\n' "${JOOMLA_MOD_CUSTOM:-}"    | json_arr)
  jtpl=$(printf   '%s\n' "${JOOMLA_TPL_PARAMS:-}"    | json_arr)
  jukeys=$(printf '%s\n' "${JOOMLA_USER_KEYS:-}"     | json_arr)
  jvuln=$(printf  '%s\n' "${JOOMLA_VULN_EXT:-}"      | json_arr)
  jmal=$(printf   '%s\n' "${JOOMLA_MALWARE:-}"       | json_arr)
  onlinef=$(printf '%s\n' "${ONLINE_FETCHES:-}"      | json_arr)
  # Welche Abschnitte liefen, welche nicht — damit ein Teillauf maschinell
  # als solcher erkennbar ist und nicht als vollständiges Ergebnis gilt.
  local modgel moduebr
  modgel=$(printf '%s\n' ${MODULE_GELAUFEN:-} | json_arr)
  moduebr=$(printf '%s\n' "${MODULE_UEBERSPRUNGEN:-}" | json_arr)
  # Nicht messbare Einzelpruefungen. 'module_uebersprungen' nennt ganze
  # Abschnitte, die auf Anweisung nicht liefen; das hier nennt Pruefungen, die
  # laufen SOLLTEN und kein Ergebnis lieferten. NT-Repair darf einer Entwarnung
  # nicht trauen, solange diese Liste nicht leer ist.
  local unmess; unmess=$(printf '%s\n' "${UNKNOWN_LIST:-}" | sed 's/^- //' | json_arr)
  local n_jcmod n_jvuln n_jsuper
  n_jcmod=$(printf  '%s\n' "${JOOMLA_CORE_MODIFIED:-}" | grep -c . 2>/dev/null)
  n_jvuln=$(printf  '%s\n' "${JOOMLA_VULN_EXT:-}"      | grep -c . 2>/dev/null)
  n_jsuper=$(printf '%s\n' "${JOOMLA_ROGUE_SUPER:-}"   | grep -vE '^=== |^$' | grep -c . 2>/dev/null)

  cat > "$FINDINGS_FILE" <<JSON
{
  "schema_version": "1.7",
  "tool": "wp_plesk_forensik.sh",
  "tool_version": "${TOOL_VERSION}",
  "run_id": "$(json_str "$RUN_LABEL")",
  "host": "$(json_str "$(hostname -f 2>/dev/null || hostname)")",
  "domain": "$(json_str "${DOMAIN:-}")",
  "generated_utc": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "run": {
    "vollstaendig": $(if [[ -z "${MODULE_UEBERSPRUNGEN:-}" ]]; then echo true; else echo false; fi),
    "module_gelaufen": ${modgel:-[]},
    "module_uebersprungen": ${moduebr:-[]},
    "nicht_messbar": ${unmess:-[]},
    "scope_mode": "$(json_str "${SCOPE_MODE:-}")",
    "abo_user": "$(json_str "${ABO_USER:-}")",
    "scan_paths": ${scanp:-[]}
  },
  "htaccess_unwirksam": "${htaunw}",
  "befunde": ${befgen:-{\}},
  "verdikte": ${verdgen:-{\}},
  "counts": { "crit": ${N_CRIT:-0}, "warn": ${N_WARN:-0}, "ok": ${N_OK:-0}, "unknown": ${N_UNKNOWN:-0} },
  "verdicts": {
    "root": { "flags": ${ROOT_FLAGS:-0}, "text": "$(json_str "${ROOT_VERDICT:-}")" },
    "wpdb": { "flags": ${WPDB_FLAGS:-0}, "text": "$(json_str "${WPDB_VERDICT:-}")" },
    "joomla": { "flags": ${JOOMLA_FLAGS:-0}, "text": "$(json_str "${JOOMLA_VERDICT:-}")" },
    "relay": { "flags": ${RELAY_FLAGS:-0}, "text": "$(json_str "${RELAY_VERDICT:-}")" }
  },
  "data_sources": {
    "joomla_snapshot": "$(json_str "${J_DATA_STAMP:-}")",
    "joomla_snapshot_age_days": ${JOOMLA_DATA_AGE:-0},
    "online_mode": $(if [[ "${WANT_ONLINE:-0}" == "1" ]]; then echo true; else echo false; fi),
    "network_fetches": ${onlinef:-[]}
  },
  "ursache": {
    "aeltester_nachweis": ${U_ERST:-0},
    "juengster_nachweis": ${U_LETZT:-0},
    "dateien": ${U_ZEILEN:-0},
    "vorgaenge": ${U_WELLEN:-0},
    "zeitanker": ${U_ANKER:-0},
    "inode_spaeter_geaendert": ${U_INODE:-0},
    "vorwaerts_datiert": ${U_ZUKUNFT:-0},
    "zeitachse": ${uzeit:-[]},
    "reichweite_systemnutzer": "$(json_str "${U_REICHWEITE:-}")",
    "quellenlage": "$(json_str "${U_QUELLEN:-}")"
  },
  "metrics": {
    "webshell_count": ${WEBSHELL_COUNT:-0},
    "webshell_review": ${WEBSHELL_REVIEW:-0},
    "uploads_guards_gefiltert": ${GUARD_COUNT:-0},
    "injected_core_files": ${n_corei:-0},
    "doorway_dirs": ${n_doorw:-0},
    "core_include_injections": ${n_coreinj:-0},
    "rogue_wp_admins": ${n_rogue:-0},
    "suspicious_plugins": ${n_suspp:-0},
    "schadcode_gesamt": ${MALWARE_TOTAL:-0},
    "zu_pruefen_gesamt": ${PRUEF_TOTAL:-0},
    "ssh_failed": ${SSH_FAILED_COUNT:-0},
    "wp_installs": ${WP_COUNT:-0},
    "joomla_installs": ${JOOMLA_COUNT:-0},
    "joomla_core_modified": ${n_jcmod:-0},
    "joomla_vulnerable_extensions": ${n_jvuln:-0},
    "joomla_rogue_superusers": ${n_jsuper:-0},
    "domains": ${DOMAIN_COUNT:-0}
  },
  "actionable": {
    "webshell_dropper": ${ws:-[]},
    "htaccess_fremdname": ${wsn:-[]},
    "injected_core": ${corei:-[]},
    "core_should_not_exist": ${coresne:-[]},
    "doorway_dirs": ${doorw:-[]},
    "core_include_injection": ${coreinj:-[]},
    "disguised_payloads": ${disg:-[]},
    "rogue_wp_admins": ${rogue:-[]},
    "suspect_wp_admins": ${suspadm:-[]},
    "rogue_wp_admins_detail": ${rogued:-[]},
    "suspect_wp_admins_detail": ${suspadmd:-[]},
    "wp_db_plugin_leichen": ${dbleichen:-[]},
    "wp_db_optionen_php": ${dboptcode:-[]},
    "nextcloud_htaccess": ${nchta:-[]},
    "nextcloud_malware": ${ncmal:-[]},
    "nextcloud_nested": ${ncnest:-[]},
    "nextcloud_core_modified": ${ncint:-[]},
    "nextcloud_hardening": ${nchard:-[]},
    "htaccess_fremd": ${htafremd:-[]},
    "signatur_treffer": ${sigtr:-[]},
    "plugin_veraendert": ${plugmod:-[]},
    "suspicious_plugins": ${suspp:-[]},
    "mu_plugins": ${muplug:-[]},
    "tampered_htaccess": ${tamphta:-[]},
    "php_in_uploads": ${php:-[]},
    "suid": ${suid:-[]},
    "tmp_executables": ${tmpx:-[]},
    "immutable": ${immu:-[]},
    "cron_suspect": ${cron:-[]},
    "systemd_suspect": ${sysd:-[]},
    "persistence": ${persist:-[]},
    "proc_malicious": ${procs:-[]},
    "wp_configs": ${wpc:-[]},
    "foreign_ssh_keys": ${fkeys:-[]},
    "ioc_ips": { "attacker": ${aips:-[]}, "ssh_bruteforce": ${bips:-[]} },
    "gsocket_hits": ${gsock:-[]},
    "masq_binaries": ${masq:-[]},
    "fileless_procs": ${fless:-[]},
    "kthread_fakes": ${kthr:-[]},
    "orphan_shells": ${orph:-[]},
    "ssh_login_hooks": ${sshh:-[]},
    "relay_connections": ${relc:-[]},
    "yara_hits": ${yhit:-[]},
    "timestomp": ${tstomp:-[]},
    "recent_system_changes": ${recsys:-[]},
    "imunify_malware": ${imuh:-[]},
    "wptk_infected": ${wptk:-[]},
    "joomla_configs": ${jcfg:-[]},
    "joomla_versions": ${jver:-[]},
    "joomla_config_weak": ${jcweak:-[]},
    "joomla_log_ioc": ${jlog:-[]},
    "joomla_core_modified": ${jcmod:-[]},
    "joomla_core_unknown": ${jcunk:-[]},
    "joomla_system_plugins": ${jsysp:-[]},
    "joomla_rogue_superusers": ${jsuper:-[]},
    "joomla_session_payloads": ${jsess:-[]},
    "joomla_mod_custom": ${jmodc:-[]},
    "joomla_template_params": ${jtpl:-[]},
    "joomla_user_keys": ${jukeys:-[]},
    "joomla_vulnerable_extensions": ${jvuln:-[]},
    "joomla_malware": ${jmal:-[]}
  },
  "malware_summary": ${malsum}
}
JSON
  echo "  findings.json geschrieben: $FINDINGS_FILE" >> "$REPORT_FILE"
}
emit_findings_json
