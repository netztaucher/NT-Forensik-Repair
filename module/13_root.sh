# shellcheck shell=bash
# NT-Forensik — Abschnitt 13: Root- & Eskalations-Prüfung
#
# @nummer:  13
# @titel:   Root- & Eskalations-Prüfung
# @frage:   War der Vorfall auf die Website begrenzt oder ist der Server betroffen?
# @kosten:  gering
# @ebene:   system
#
# Wird vom Runner eingebunden, nicht einzeln ausgefuehrt.
# Vorgabewerte der hier gefuellten Variablen: lib/befunde.sh

h1 "13. ROOT- & ESKALATIONS-PRÜFUNG"
# ============================================================
# Zentrale Frage: Hat ein Angreifer Root-Rechte erlangt oder blieb der
# Vorfall auf Web-User-Ebene? Konsolidiert Login-, Key-, sudo- und
# Binär-Integritätsdaten zu einem Root-Verdikt.

ROOT_FLAGS=0          # >0 => Root-Kompromittierung nicht ausgeschlossen
ROOT_NOTES=""

h2 "13.1 Erfolgreiche Root-Logins (IP + Auth-Methode)"
ROOT_LOGIN_LINES=$(grep -hE "Accepted (password|publickey) for root" /var/log/auth.log* /var/log/secure* 2>/dev/null || true)
ROOT_LOGIN_IPS=$(echo "$ROOT_LOGIN_LINES" | grep -oE "from [0-9.]+" | awk '{print $2}' | sort -u || true)
if [[ -n "$ROOT_LOGIN_IPS" ]]; then
  info "Distinct-IPs mit erfolgreichem Root-Login:"
  code "$ROOT_LOGIN_IPS"
  # Root-Login per Passwort = Härtungslücke (Brute-Force-Angriffsfläche)
  ROOT_PW=$(echo "$ROOT_LOGIN_LINES" | grep -c "Accepted password for root" || true)
  if [[ "${ROOT_PW:-0}" -gt 0 ]]; then
    warn "Root-Login per PASSWORT aktiv ($ROOT_PW Anmeldungen) — auf Key-only umstellen (PermitRootLogin prohibit-password)"
    ROOT_NOTES+="- Root-Login per Passwort ist aktiviert (Härtungslücke)."$'\n'
  fi
  evidence "root_logins_erfolgreich" "$ROOT_LOGIN_LINES"
else
  info "Keine erfolgreichen Root-Logins in vorliegenden Auth-Logs (ggf. Log-Reichweite beachten)"
fi

# Abgleich Angreifer-IP (falls aus Web-Analyse bekannt) gegen Root-Logins
if [[ -n "${ATTACK_IPS_UNIQ:-}" ]]; then
  ATTACK_IP_LIST=$(echo "$ATTACK_IPS_UNIQ" | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' || true)
  ROOT_HIT=""
  while IFS= read -r aip; do
    [[ -z "$aip" ]] && continue
    if echo "$ROOT_LOGIN_IPS" | grep -qF "$aip"; then ROOT_HIT+="$aip "; fi
    # Auch: Angreifer-IP je in auth.log (SSH-Kontakt)?
  done <<< "$ATTACK_IP_LIST"
  if [[ -n "$ROOT_HIT" ]]; then
    crit "Angreifer-IP(s) mit Root-Login gefunden: $ROOT_HIT — ROOT KOMPROMITTIERT"
    ROOT_FLAGS=$((ROOT_FLAGS+1))
    ROOT_NOTES+="- Angreifer-IP $ROOT_HIT hat sich erfolgreich als root angemeldet."$'\n'
  else
    ok "Keine Web-Angreifer-IP unter den Root-Login-IPs"
  fi
fi

h2 "13.2 /root/.ssh/authorized_keys (Root-SSH-Schlüssel)"
if [[ -f /root/.ssh/authorized_keys ]]; then
  ROOT_KEYS=$(while read -r l; do [[ -z "$l" ]] && continue; echo "$l" | ssh-keygen -lf /dev/stdin 2>/dev/null || echo "unparsebar: ${l:0:50}"; done < /root/.ssh/authorized_keys)
  RK_MTIME=$(stat -c %y /root/.ssh/authorized_keys 2>/dev/null | cut -d. -f1)
  info "Root-Keys (Fingerprint / Kommentar), Datei geändert: $RK_MTIME"
  code "$ROOT_KEYS"
  evidence "root_authorized_keys" "geändert: $RK_MTIME"$'\n'"$ROOT_KEYS"
  # Kürzlich geändert?
  RK_RECENT=$(find /root/.ssh/authorized_keys -mtime -"$DAYS_BACK" 2>/dev/null || true)
  if [[ -n "$RK_RECENT" ]]; then
    warn "/root/.ssh/authorized_keys in den letzten ${DAYS_BACK} Tagen geändert — Keys gegen bekannte Admin-/Plesk-Keys verifizieren (Plesk-SSH-Terminal schreibt seinen Key beim Öffnen neu)"
    ROOT_NOTES+="- Root-authorized_keys kürzlich geändert ($RK_MTIME) — verifizieren."$'\n'
  fi
else
  info "Keine /root/.ssh/authorized_keys vorhanden"
fi

h2 "13.3 Web-User-SSH-Keys serverweit (Fremd-Key-Persistenz?)"
# Angreifer-Persistenz auf Web-User-Ebene: fremde Keys in vhost-.ssh.
# Plesk-eigene 'plesk-ssh-terminal'-Keys sind gutartig (Panel-Terminal).
WEBUSER_KEYS=""
FOREIGN_KEYS=""
while IFS= read -r f; do
  [[ -f "$f" ]] || continue
  u=$(echo "$f" | cut -d/ -f5)
  while read -r l; do
    [[ -z "$l" ]] && continue
    fp=$(echo "$l" | ssh-keygen -lf /dev/stdin 2>/dev/null || echo "unparsebar ${l:0:40}")
    WEBUSER_KEYS+="$u : $fp"$'\n'
    echo "$fp" | grep -q "plesk-ssh-terminal" || FOREIGN_KEYS+="$u : $fp"$'\n'
  done < "$f" 2>/dev/null
done < <(find "$VHOSTS_DIR" -maxdepth 3 -name authorized_keys 2>/dev/null)
if [[ -n "$WEBUSER_KEYS" ]]; then
  code "$WEBUSER_KEYS"
  evidence "webuser_ssh_keys" "$WEBUSER_KEYS"
fi
if [[ -n "$FOREIGN_KEYS" ]]; then
  crit "Nicht-Plesk-SSH-Keys bei Web-Usern — mögliche Angreifer-Persistenz, verifizieren"
  code "$FOREIGN_KEYS"
  evidence "webuser_fremde_keys" "$FOREIGN_KEYS"
  ROOT_FLAGS=$((ROOT_FLAGS+1))
  ROOT_NOTES+="- Fremde (Nicht-Plesk) SSH-Keys bei Web-Usern gefunden."$'\n'
else
  ok "Nur Plesk-eigene SSH-Keys bei Web-Usern (keine Fremd-Key-Persistenz)"
fi

h2 "13.4 Privilege-Escalation (sudo/su durch Nicht-Root)"
# WICHTIG — nur der CALLER zählt: Eskalation ist ein Web-/Systemnutzer, der sudo
# AUFRUFT (Caller = webNN). Die alte Regex 'sudo:.*web[0-9]' traf auch 'USER=webNN'
# in der Ziel-Angabe und meldete damit jeden gewoehnlichen Plesk-Aufruf.
# im TARGET-Feld — das ist root, der Rechte an einen Web-User ABGIBT (legitim),
# u.a. NT-Forensik selbst (`sudo -u webNN wp core verify-checksums` in §11) und
# jeder Plesk-interne root→User-Aufruf. Ergebnis war ein Root-Fehlalarm auf
# sauberen Servern (Self-Kontamination). Wir ankern daher auf die Caller-Position.
SUDO_ESC=$(grep -hE "sudo:[[:space:]]+(www-data|psacln|psaserv|web[0-9]+)[[:space:]]+:" /var/log/auth.log* /var/log/secure* 2>/dev/null | head -20 || true)
SU_ESC=$(grep -hE "su(\[[0-9]+\])?:.*session opened for user root by (www-data|psacln|psaserv|web[0-9]+)" /var/log/auth.log* /var/log/secure* 2>/dev/null | head -20 || true)
if [[ -n "$SUDO_ESC" || -n "$SU_ESC" ]]; then
  crit "Rechteausweitung durch Web-/Systemnutzer erkannt"
  code "$SUDO_ESC
$SU_ESC"
  evidence "privilege_escalation" "$SUDO_ESC
$SU_ESC"
  ROOT_FLAGS=$((ROOT_FLAGS+1))
  ROOT_NOTES+="- sudo/su-Eskalation durch Nicht-Root-Nutzer in Logs."$'\n'
else
  ok "Keine sudo/su-Rechteausweitung durch Web-/Systemnutzer in Logs"
fi

h2 "13.5 Binär-Integrität als Rootkit-Indikator (Rückverweis 8.6)"
if [[ -n "${PKG_MODIFIED:-}" ]]; then
  crit "System-Binaries weichen von Paketdatenbank ab (siehe 8.6) — Rootkit-Verdacht"
  ROOT_FLAGS=$((ROOT_FLAGS+1))
  ROOT_NOTES+="- Manipulierte System-Binaries (dpkg -V)."$'\n'
else
  ok "Kern-Binaries unverändert (dpkg -V, siehe 8.6) — kein Rootkit-Hinweis"
fi
# ld.so.preload-Ergebnis aus 6.7 fließt bereits in die Warnungen ein.

h2 "13.6 Root-Verdikt"
if [[ "$ROOT_FLAGS" -eq 0 ]]; then
  ROOT_VERDICT="🟢 **Keine Hinweise auf Root-Kompromittierung.** Erfolgreiche Root-Logins nur von bekannten/legitimen Quellen, keine Fremd-SSH-Keys (root oder Web-User), keine Rechteausweitung durch Web-Nutzer, System-Binaries unverändert. Ein etwaiger Vorfall ist nach aktueller Beweislage auf Web-User-Ebene begrenzt."
  ok "ROOT-VERDIKT: keine Root-Kompromittierung nachweisbar"
else
  ROOT_VERDICT="🔴 **Root-Kompromittierung NICHT ausgeschlossen** (${ROOT_FLAGS} Indikator(en)). Sofort: Server als kompromittiert behandeln, Neuaufsetzen erwägen, alle Root-Zugänge rotieren."
  crit "ROOT-VERDIKT: Root-Kompromittierung möglich ($ROOT_FLAGS Indikatoren)"
fi
echo -e "\n$ROOT_VERDICT\n" >> "$REPORT_FILE"
[[ -n "$ROOT_NOTES" ]] && code "$ROOT_NOTES"
evidence "root_verdikt" "Flags: $ROOT_FLAGS
$ROOT_VERDICT

$ROOT_NOTES"

# Kunden-taugliche Root-Aussage (v3.5): im Kundenbericht dürfen KEINE
# Root-Details stehen (keine IPs, Pfade, Indikatorenzahl, keine
# „Server-neu-aufsetzen"-Anweisung — das ist Sache des Betreibers). Nur die
# generische Aussage betroffen/nicht betroffen. Der volle ROOT_VERDICT bleibt
# in Technik- und BSI-Bericht.
if [[ "$ROOT_FLAGS" -eq 0 ]]; then
  ROOT_CUSTOMER_HINT="🟢 Die Prüfung ergab **keine Hinweise**, dass über Ihren Webauftritt hinaus die Serverebene betroffen ist. Ein etwaiger Vorfall ist nach aktueller Beweislage auf Ihre Website begrenzt."
else
  ROOT_CUSTOMER_HINT="🟠 Es bestehen Hinweise, dass **auch die Serverebene betroffen** sein könnte. Diese liegen dem Serverbetreiber vor und werden dort gesondert behandelt. Für Ihren Webauftritt gelten die Sofortmaßnahmen in Abschnitt 2."
fi


# Konsolidiert alle Relay-/Prozess-Befunde zu einer klaren Aussage —
# analog zum bestehenden ROOT_VERDICT.
RELAY_FLAGS=0
[[ -n "$GSOCKET_HITS"       ]] && RELAY_FLAGS=$((RELAY_FLAGS+3))
[[ -n "$MASQ_BINARIES"      ]] && RELAY_FLAGS=$((RELAY_FLAGS+3))
[[ -n "$FILELESS_PROCS"     ]] && RELAY_FLAGS=$((RELAY_FLAGS+3))
[[ -n "$KTHREAD_FAKES"      ]] && RELAY_FLAGS=$((RELAY_FLAGS+2))
[[ -n "$YARA_HITS"          ]] && RELAY_FLAGS=$((RELAY_FLAGS+2))
[[ -n "$SSH_LOGIN_HOOKS"    ]] && RELAY_FLAGS=$((RELAY_FLAGS+2))
[[ -n "$RELAY_CONNECTIONS"  ]] && RELAY_FLAGS=$((RELAY_FLAGS+1))
[[ -n "$ORPHAN_SHELLS"      ]] && RELAY_FLAGS=$((RELAY_FLAGS+1))

if   [[ "$RELAY_FLAGS" -ge 3 ]]; then
    RELAY_VERDICT="🔴 **Interaktive Backdoor nachgewiesen.** Es bestehen Hinweise auf einen aktiven, ausgehenden Fernzugriffskanal (Relay-Backdoor). Ein solcher Kanal umgeht Firewall und NAT vollständig und ist von außen nicht als offener Port sichtbar. Das System ist als vollständig kompromittiert zu behandeln; ein Entfernen einzelner Dateien genügt nicht."
elif [[ "$RELAY_FLAGS" -ge 1 ]]; then
    RELAY_VERDICT="🟡 **Backdoor-Verdacht.** Einzelne Indikatoren für einen Fernzugriffskanal gefunden, aber keine eindeutige Signatur. Befunde manuell verifizieren, bevor bereinigt wird."
else
    RELAY_VERDICT="🟢 **Kein Hinweis auf eine Relay-Backdoor.** Weder Signaturen, getarnte Binaries, fileless Prozesse noch untypische ausgehende Verbindungen gefunden. (Kein Ausschluss: ein inaktiver Kanal ist zum Scanzeitpunkt unsichtbar — dauerhafte Erkennung nur über auditd, siehe haertung/audit-backdoor.rules.)"
fi

echo -e "\n### Verdikt Relay-Backdoor\n\n${RELAY_VERDICT}\n" >> "$REPORT_FILE"

# ============================================================
# BEFUND-KLASSIFIKATION & DETAILDATEI (v3.6)
# ------------------------------------------------------------
# Ordnet alle datei-basierten Schadcode-Funde grob einer Familie zu (was es ist
# + Geschäftsmodell), schreibt die Fundstellen mit Pfaden RELATIV zum
# Kundenverzeichnis in befunde_details.md und liefert eine Grobstatistik für
# Bericht und PDF-Deckblatt. Details bewusst NICHT in den laienlesbaren
# Kundenbericht, sondern in die referenzierte Extradatei.
# ============================================================
DETAILS_FILE="${KUNDE_DIR}/befunde_details.md"
CUST_ROOT="$SCAN_PATH"
# Pfad relativ zum Kundenverzeichnis (nie absolut im Bericht/PDF)
relpath(){ local p="$1"
  if [[ -n "$CUST_ROOT" && "$CUST_ROOT" != "$VHOSTS_DIR" ]]; then printf '%s' "${p#"$CUST_ROOT"/}"
  else printf '%s' "${p#"$VHOSTS_DIR"/}"; fi; }
# Familie aus Imunify-Signaturname
imu_family(){ local t; t="$(printf '%s' "$1" | tr 'A-Z' 'a-z')"
  case "$t" in
    *deface*) echo "Defacement" ;;
    *backdoor*|*bkdr*|*shell*|*webshell*) echo "Backdoor/Webshell" ;;
    *phish*) echo "Phishing" ;;
    *spam*|*seo*|*doorway*|*pharma*) echo "SEO-Spam/Doorway" ;;
    *redir*) echo "Redirect/Malvertising" ;;
    *mailer*) echo "Spam-Mailer" ;;
    # VOR der Miner-Regel: "adminer" enthaelt "miner". Ein Adminer im
    # wp-includes-Verzeichnis wurde dadurch als Cryptominer ausgewiesen und
    # dem Kunden als "Diebstahl von Rechenleistung" erklaert — waehrend es
    # tatsaechlich ein offener Vollzugriff auf seine Datenbank war. Fuer die
    # DSGVO-Einschaetzung ist das der Unterschied zwischen Sachschaden und
    # Zugriff auf personenbezogene Daten.
    *adminer*|*admin.tool.db*|*phpmyadmin*|*sqlbuddy*) echo "Datenbank-Zugriffswerkzeug" ;;
    *miner*|*coin*|*xmr*) echo "Cryptominer" ;;
    *inject*) echo "Code-Injection" ;;
    *) echo "Sonstige/Unklar" ;;
  esac; }
# Geschäftsmodell je Familie (eine Zeile, laienverständlich)
fam_biz(){ case "$1" in
    "Defacement")            echo "Verunstaltung der Seite — Reputationsschaden, oft Hacktivismus" ;;
    "Backdoor/Webshell")     echo "Dauerhafter Fernzugriff — Basis für Wiederkehr & weitere Angriffe" ;;
    "SEO-Spam/Doorway")      echo "Suchmaschinen-Spam (Pharma, Fake-Shops) über Ihre Domain-Reputation" ;;
    "Phishing")              echo "Datendiebstahl über gefälschte Login-/Bezahlseiten" ;;
    "Redirect/Malvertising") echo "Weiterverkauf Ihrer Besucher / Schadwerbung" ;;
    "Spam-Mailer")           echo "Massen-Mailversand — Blacklisting Ihrer Domain/IP" ;;
    "Cryptominer")           echo "Diebstahl von Server-Rechenleistung" ;;
    "Datenbank-Zugriffswerkzeug") echo "Direkter Zugriff auf die Datenbank — Auslesen, Ändern und Löschen aller gespeicherten Daten, auch personenbezogener" ;;
    "Code-Injection")        echo "Schadcode in legitime Dateien eingeschleust" ;;
    "Relay-Backdoor")        echo "Portloser Fernzugriffskanal (umgeht Firewall/NAT)" ;;
    "Getarnte Binary")       echo "Als harmlose Datei getarntes Angriffswerkzeug" ;;
    "Getarnte Payload")      echo "Nachladbarer Schadcode in Nicht-PHP-Datei" ;;
    "Joomla-Webshell")       echo "Über eine Joomla-Lücke abgelegte Hintertür (meist als Bild getarnt)" ;;
    "Kernfremde Datei")      echo "Datei im Programmkern, die dort nicht hingehört — Hintertür oder Update-Altlast" ;;
    *)                       echo "Einordnung offen — manuelle Prüfung nötig" ;;
  esac; }

declare -A FAM_COUNT FAM_FILES
add_finding(){ local fam="$1" rel="$2" detail="$3"
  FAM_COUNT["$fam"]=$(( ${FAM_COUNT["$fam"]:-0} + 1 ))
  FAM_FILES["$fam"]+="- \`${rel}\`${detail:+  — ${detail}}"$'\n'; }

MAL_PATHS=""   # absolute Fund-Pfade (für Mail-Kontext: Bereich + Zeitraum)
# Quelle 1: Imunify-Treffer (Zeilen "pfad  [type]  hash")
if [[ -n "${IMUNIFY_HITS:-}" ]]; then
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    p="${line%%  \[*}"
    t="$(printf '%s' "$line" | sed -E 's/.*\[([^]]*)\].*/\1/')"
    add_finding "$(imu_family "$t")" "$(relpath "$p")" "Imunify-Signatur: ${t}"
    MAL_PATHS+="$p"$'\n'
  done <<< "$IMUNIFY_HITS"
fi
# Quelle 2: eigene datei-basierte Kategorien (je eine Pfadliste)
_addcat(){ local fam="$1" list="$2"
  while IFS= read -r p; do [[ -n "$p" ]] && { add_finding "$fam" "$(relpath "$p")" ""; MAL_PATHS+="$p"$'\n'; }; done <<< "$list"; }
[[ -n "${MASQ_BINARIES:-}"      ]] && _addcat "Getarnte Binary"   "$MASQ_BINARIES"
[[ -n "${GSOCKET_HITS:-}"       ]] && _addcat "Relay-Backdoor"    "$GSOCKET_HITS"
[[ -n "${DISGUISED_PAYLOADS:-}" ]] && _addcat "Getarnte Payload"  "$DISGUISED_PAYLOADS"
[[ -n "${CORE_INJECT_HITS:-}"   ]] && _addcat "Code-Injection"    "$CORE_INJECT_HITS"
[[ -n "${DOORWAY_DIRS:-}"       ]] && _addcat "SEO-Spam/Doorway"  "$DOORWAY_DIRS"
# v3.8 Joomla. NUR Variablen mit nackten, absoluten Pfaden je Zeile — _addcat
# ruft relpath() und füllt MAL_PATHS. JOOMLA_VERSIONS, _ROGUE_SUPER und
# _VULN_EXT tragen Tabulatoren und "=== site ==="-Kopfzeilen und dürfen hier
# NICHT durch.
[[ -n "${JOOMLA_MALWARE:-}"       ]] && _addcat "Joomla-Webshell"  "$JOOMLA_MALWARE"
[[ -n "${JOOMLA_CORE_MODIFIED:-}" ]] && _addcat "Code-Injection"   "$JOOMLA_CORE_MODIFIED"
[[ -n "${JOOMLA_CORE_UNKNOWN:-}"  ]] && _addcat "Kernfremde Datei" "$JOOMLA_CORE_UNKNOWN"

# Grobstatistik + Detaildatei zusammensetzen
MALWARE_TOTAL=0; MALWARE_FAMILY_ROWS=""; MALWARE_CARD=""
# Mail-Kontext (v3.7) für den Anschreiben-Generator — Defaults für set -u
MAIL_AREA=""; MAIL_FINDING=""; MAIL_TIMEFRAME=""; MAIL_NEWEST=""; MAIL_FAMILIES_JSON="{}"
for fam in "${!FAM_COUNT[@]}"; do MALWARE_TOTAL=$(( MALWARE_TOTAL + FAM_COUNT[$fam] )); done
if [[ "$MALWARE_TOTAL" -gt 0 ]]; then
  # betroffener Bereich aus den Pfaden (grob, laienverständlich)
  # Reihenfolge und Regex bewusst geändert (v3.8): die frühere Joomla-Regex
  # traf schon bei einem blanken "/administrator" und damit auch bei
  # Nicht-Joomla; jetzt ist der volle Joomla-Pfadkontext nötig. WordPress
  # steht VOR Shop, weil WooCommerce immer unter wp-content liegt und sonst
  # als "Shop-Bereich" statt "WordPress-Bereich" beschriftet würde.
  # Der Anschreiben-Generator leitet aus dem Wort "Shop" ab, ob er den Absatz
  # zu Zahlungsdaten aufnimmt. Deshalb bei Joomla die verbreiteten
  # Shop-Komponenten gezielt erkennen, statt Joomla wie früher pauschal als
  # Shop zu behandeln.
  if   printf '%s' "$MAL_PATHS" | grep -qiE 'com_(virtuemart|hikashop|eshop|j2store|redshop|phocacart|jshopping)'; then MAIL_AREA="Joomla-Shop-Bereich"
  elif printf '%s' "$MAL_PATHS" | grep -qiE '/(administrator/components|components/com_[a-z]+|modules/mod_[a-z]+|plugins/(system|content|authentication|editors)/|libraries/(joomla|src)/|media/com_[a-z]+)'; then MAIL_AREA="Joomla-Bereich"
  elif printf '%s' "$MAL_PATHS" | grep -qiE 'wp-content|wp-admin|wp-includes'; then MAIL_AREA="WordPress-Bereich"
  elif printf '%s' "$MAL_PATHS" | grep -qiE '/(shop2?|warenkorb|checkout|xtcommerce|woocommerce|magento)'; then MAIL_AREA="Shop-Bereich"
  else MAIL_AREA="Webbereich"; fi
  # neueste mtime der Fundstellen -> Zeitbezug
  _newest=0
  while IFS= read -r _p; do [[ -f "$_p" ]] || continue; _m=$(stat -c %Y "$_p" 2>/dev/null || echo 0); (( _m > _newest )) && _newest=$_m; done <<< "$MAL_PATHS"
  if [[ "$_newest" -gt 0 ]]; then
    _y=$(date -d "@$_newest" +%Y 2>/dev/null || echo ""); _mo=$(date -d "@$_newest" +%m 2>/dev/null || echo ""); _cy=$(date +%Y)
    case "$_mo" in 12|01|02) _s="Winter";; 03|04|05) _s="Frühjahr";; 06|07|08) _s="Sommer";; *) _s="Herbst";; esac
    if [[ -n "$_y" && "$_y" == "$_cy" ]]; then MAIL_TIMEFRAME="erst in diesem $_s"
    elif [[ -n "$_y" ]]; then MAIL_TIMEFRAME="im $_s $_y"
    else MAIL_TIMEFRAME="in den letzten Monaten"; fi
    MAIL_NEWEST=$(date -d "@$_newest" +%Y-%m-%d 2>/dev/null || echo "")
  else MAIL_TIMEFRAME="in den letzten Monaten"; fi
  # dominante Familie -> Fund-Formulierung (Singular/Plural)
  _domfam=$(for fam in "${!FAM_COUNT[@]}"; do echo "${FAM_COUNT[$fam]}|$fam"; done | sort -rn | head -1 | cut -d'|' -f2)
  case "$_domfam" in
    "Backdoor/Webshell"|"Relay-Backdoor") _ns="eine versteckte Hintertür"; _np="mehrere versteckte Hintertüren";;
    "Defacement")                          _ns="eine verunstaltete Seite"; _np="mehrere verunstaltete Seiten";;
    "SEO-Spam/Doorway")                    _ns="eine versteckte Spam-Seite"; _np="mehrere versteckte Spam-Seiten";;
    *)                                     _ns="eine Schaddatei"; _np="mehrere Schaddateien";;
  esac
  [[ "$MALWARE_TOTAL" -eq 1 ]] && MAIL_FINDING="$_ns" || MAIL_FINDING="$_np"
  # Familien als JSON-Objekt (Namen ohne Sonderzeichen -> keine Escapes nötig)
  MAIL_FAMILIES_JSON="{"; _f1=1
  for fam in "${!FAM_COUNT[@]}"; do [[ $_f1 -eq 0 ]] && MAIL_FAMILIES_JSON+=","; MAIL_FAMILIES_JSON+="\"${fam}\":${FAM_COUNT[$fam]}"; _f1=0; done
  MAIL_FAMILIES_JSON+="}"
  {
    echo "# Fundstellen-Details${DOMAIN:+ — ${DOMAIN}}"
    echo
    echo "> Pfade **relativ zum Kundenverzeichnis** (nicht der absolute Serverpfad)."
    echo "> Erzeugt: $(date +"%d.%m.%Y, %H:%M Uhr") · Prüfung \`${RUN_LABEL}\` · $MALWARE_TOTAL Fundstelle(n)."
    echo
    echo "| Familie | Anzahl | Geschäftsmodell |"
    echo "|---|---|---|"
  } > "$DETAILS_FILE"
  # nach Anzahl absteigend (einfacher Bubble über Keys)
  for fam in "${!FAM_COUNT[@]}"; do echo "${FAM_COUNT[$fam]}|$fam"; done | sort -rn | while IFS='|' read -r n f; do
    printf '| %s | %s | %s |\n' "$f" "$n" "$(fam_biz "$f")" >> "$DETAILS_FILE"
  done
  echo >> "$DETAILS_FILE"
  for fam in "${!FAM_COUNT[@]}"; do
    {
      echo "## ${fam} (${FAM_COUNT[$fam]}) — $(fam_biz "$fam")"
      echo
      printf '%s\n' "${FAM_FILES[$fam]}"
    } >> "$DETAILS_FILE"
  done
  # Kompakte Zeilen für Bericht-Tabelle + PDF-Card (Top nach Anzahl)
  while IFS='|' read -r n f; do
    MALWARE_FAMILY_ROWS+="| ${f} | ${n} | $(fam_biz "$f") |"$'\n'
    MALWARE_CARD+="- **${n}** ${f}"$'\n'
  done < <(for fam in "${!FAM_COUNT[@]}"; do echo "${FAM_COUNT[$fam]}|$fam"; done | sort -rn)
  echo "  Fundstellen-Details: $DETAILS_FILE ($MALWARE_TOTAL Fund(e), $(printf '%s' "$MALWARE_CARD" | grep -c .) Familien)" >> "$REPORT_FILE"
fi

# ============================================================