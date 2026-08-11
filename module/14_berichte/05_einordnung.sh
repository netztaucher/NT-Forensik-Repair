# shellcheck shell=bash
# NT-Forensik — Abschnitt 14, Teil: Befund-Klassifikation & Detaildatei
#
# Unterabschnitt von module/14_berichte.sh. Wird vom Runner nach dem
# Hauptmodul geladen (siehe modul_teile_laden in wp_plesk_forensik.sh) und
# teilt sich dessen Variablen. Nicht einzeln ausfuehrbar.
#
# ------------------------------------------------------------
# WARUM DIESER TEIL SEIT v3.12 HIER LIEGT UND NICHT MEHR IN ABSCHNITT 13
#
# Die Einordnung stand bis v3.11 am Ende der Root-Pruefung. Abschnitt 13 traegt
# die Ebene `system` — bei `--nur-website` laeuft er nicht. Also entstand
# ausgerechnet im haeufigsten Fall, der Pruefung EINES Kundenauftritts, gar
# keine befunde_details.md: der Kundenbericht verwies auf eine Datei, die es
# nicht gab, MALWARE_TOTAL blieb ungesetzt, und findings.json meldete
# `schadcode_gesamt: 0` neben einer gefuellten Fundliste.
#
# Die Einordnung liest ausschliesslich Befundvariablen und schreibt
# ausschliesslich Berichtstext. Sie gehoert damit zu Abschnitt 14, nicht zur
# Root-Pruefung. Die Nummer 05 stellt sie VOR den Kundenbericht (20) und vor
# findings.json (50), die beide MALWARE_TOTAL lesen.
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
    # v3.12 (#3): die Familien der übrigen dateibasierten Fundquellen. Ohne sie
    # fielen deren Funde in den Sammelzweig und der Kunde las neben der Datei
    # "Einordnung offen" — obwohl die Quelle sehr wohl weiss, was sie gefunden hat.
    "Bekannte Schaddatei")   echo "Nach Namensmuster erkanntes Angriffswerkzeug (Dateimanager, Uploader, Shell)" ;;
    "Verändertes Plugin")    echo "Fremder Code in einem legitimen Plugin — nachträglich eingebaute Hintertür" ;;
    "Manipulierte .htaccess") echo "Zugriffsregeln zugunsten des Angreifers — hält seine Dateien erreichbar und sperrt Mitbewerber aus" ;;
    "Tarnstruktur")          echo "Angelegte Verzeichnisse, die echte nachahmen — Ablage für Nutzlasten" ;;
    "PHP im Upload-Verzeichnis") echo "Ausführbarer Code dort, wo nur Dateien liegen sollen — der klassische Weg einer hochgeladenen Shell" ;;
    "Signaturtreffer (YARA)") echo "Treffer eines Regelwerks für bekannte Schadcode-Merkmale" ;;
    "Immer aktives mu-Plugin") echo "Läuft bei jedem Aufruf, ohne Aktivierung und ohne in der Pluginliste zu erscheinen — meist gewollt, gelegentlich der Anker eines Angreifers" ;;
    "Ausführbares in /tmp")  echo "Ausführbare Datei im Ablageverzeichnis — meist ein Sicherungsprogramm, gelegentlich nachgeladenes Werkzeug" ;;
    *)                       echo "Einordnung offen — manuelle Prüfung nötig" ;;
  esac; }

# ── Ablage: eine Zeile je Fundstelle, familie<TAB>pfad<TAB>anmerkung ────────
#
# Bis v3.11 standen hier vier assoziative Arrays (`declare -A`). Die gibt es
# erst ab bash 4, und sie waren die EINZIGE bash-4-Abhängigkeit des ganzen
# Werkzeugs. Aufgefallen ist das nie: der Block hing an Abschnitt 13, Abschnitt
# 13 hat die Ebene `system`, und auf dem Entwicklungsrechner (macOS, bash 3.2)
# lief er deshalb nie mit. Beim Umzug hierher brach der erste Lauf sofort mit
# `declare: -A: invalid option` ab — auf einem Zielsystem mit bash 3.2 hätte
# derselbe Fehler mitten im Bericht gestanden.
#
# Gruppiert und gezählt wird beim Schreiben, mit awk. Das ist portabel, kürzer
# und macht die Sortierung nachvollziehbar.
FUNDE=""        # belegter Schadcode
# Zweiter Rang: Fundstellen, deren Quelle selbst nur `warn` meldet. Sie gehören
# in die Erklärung — aber nicht in die Schadcode-Zahl. Eine kernfremde Datei in
# wp-includes ist oft eine Update-Altlast, ein mu-Plugin ist meistens gewollt,
# und ein Skript in /tmp gehört einem Sicherungsprogramm. Wer sie mitzählt,
# baut die Übertreibung ein, die #2 in der Gegenrichtung beklagt.
PRUEFUNGEN=""
# Jede Fundstelle nur EINMAL. Die Quellen überschneiden sich von Haus aus: eine
# Webshell in uploads/ steht in PHP_IN_UPLOADS, im Signaturtreffer und
# womöglich zusätzlich bei Imunify. Ohne diese Sperre zählte sie dreifach, und
# die Zahl im Kundenbericht wäre wieder falsch — nur diesmal nach oben.
SEEN_PATHS=""
_schon_gesehen(){   # <relpfad> — 0 = schon erfasst
  printf '%s' "$SEEN_PATHS" | grep -qxF "$1"; }
add_finding(){ local fam="$1" rel="$2" detail="$3"
  _schon_gesehen "$rel" && return 0
  SEEN_PATHS+="${rel}"$'\n'
  FUNDE+="${fam}"$'\t'"${rel}"$'\t'"${detail}"$'\n'; }
add_pruef(){ local fam="$1" rel="$2" detail="$3"
  _schon_gesehen "$rel" && return 0
  SEEN_PATHS+="${rel}"$'\n'
  PRUEFUNGEN+="${fam}"$'\t'"${rel}"$'\t'"${detail}"$'\n'; }

# Familien nach Anzahl absteigend, Format "anzahl<TAB>familie". Bei gleicher
# Anzahl alphabetisch — sonst entscheidet die Reihenfolge der Eingabe, und
# zwei Läufe über denselben Baum lieferten verschiedene Berichte.
_fam_rangliste(){   # <TSV auf stdin>
  awk -F'\t' 'NF{n[$1]++} END{for(f in n) printf "%s\t%s\n", n[f], f}' \
    | sort -k1,1nr -k2,2; }
_fam_zeilen(){      # <familie> <TSV-Variable>
  printf '%s' "$2" | awk -F'\t' -v f="$1" '$1==f{
      printf "- `%s`", $2; if ($3 != "") printf "  — %s", $3; printf "\n" }'; }

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

# Quelle 3 (v3.12, #3): die übrigen dateibasierten Fundquellen.
#
# Bis hierher erklärte befunde_details.md ausschliesslich Imunify-Treffer und
# eine Handvoll Sonderfälle. In einem echten Vorfall waren das 6 von 10
# Dateien; die vier anderen standen unerklärt in derselben Quarantänetabelle.
# Der Grund lag tiefer als gedacht: beim Umzug der WordPress- und
# Nextcloud-Prüfungen nach rezepte/ hörten CORE_INJECTED, DOORWAY_DIRS,
# MU_PLUGINS und die übrigen auf, gefüllt zu werden — die Zeilen darüber liefen
# jahrelang über leere Variablen. Die Rezepte füllen sie seit v3.12 wieder
# (siehe lib/befunde.sh).
#
# Weiterhin gilt die Regel aus dem Joomla-Absatz: NUR Variablen mit nackten,
# absoluten Pfaden je Zeile. ROGUE_ADMINS, SUSPECT_ADMINS und NC_INTEGRITY
# tragen Tabulatoren und "=== instanz ==="-Kopfzeilen und dürfen hier NICHT
# durch.
[[ -n "${SIGNATUR_TREFFER:-}"     ]] && _addcat "Bekannte Schaddatei"      "$SIGNATUR_TREFFER"
[[ -n "${PLUGIN_VERAENDERT:-}"    ]] && _addcat "Verändertes Plugin"       "$PLUGIN_VERAENDERT"
[[ -n "${CORE_INJECTED:-}"        ]] && _addcat "Code-Injection"           "$CORE_INJECTED"
[[ -n "${TAMPERED_HTACCESS:-}"    ]] && _addcat "Manipulierte .htaccess"   "$TAMPERED_HTACCESS"
[[ -n "${HTACCESS_FREMD:-}"       ]] && _addcat "Manipulierte .htaccess"   "$HTACCESS_FREMD"
[[ -n "${NC_HTACCESS_MAL:-}"      ]] && _addcat "Manipulierte .htaccess"   "$NC_HTACCESS_MAL"
[[ -n "${NC_MALWARE:-}"           ]] && _addcat "Code-Injection"           "$NC_MALWARE"
[[ -n "${NC_NESTED:-}"            ]] && _addcat "Tarnstruktur"             "$NC_NESTED"
[[ -n "${PHP_IN_UPLOADS:-}"       ]] && _addcat "PHP im Upload-Verzeichnis" "$PHP_IN_UPLOADS"
[[ -n "${YARA_HITS:-}"            ]] && _addcat "Signaturtreffer (YARA)"   "$YARA_HITS"

# Zweiter Rang — erklärt, aber nicht als Schadcode gezählt (siehe add_pruef).
# Bewusst OHNE MAL_PATHS: daraus leitet der Anschreiben-Generator den
# betroffenen Bereich und den Zeitraum ab. Ein mu-Plugin von 2019 würde den
# Vorfall damit auf 2019 datieren.
_addpruef(){ local fam="$1" list="$2"
  while IFS= read -r p; do [[ -n "$p" ]] && add_pruef "$fam" "$(relpath "$p")" ""; done <<< "$list"; }
[[ -n "${CORE_SNE:-}"             ]] && _addpruef "Kernfremde Datei"        "$CORE_SNE"
[[ -n "${JOOMLA_CORE_UNKNOWN:-}"  ]] && _addpruef "Kernfremde Datei"        "$JOOMLA_CORE_UNKNOWN"
[[ -n "${MU_PLUGINS:-}"           ]] && _addpruef "Immer aktives mu-Plugin" "$MU_PLUGINS"
[[ -n "${TMP_EXECS:-}"            ]] && _addpruef "Ausführbares in /tmp"    "$TMP_EXECS"

# Grobstatistik + Detaildatei zusammensetzen
MALWARE_TOTAL=0; MALWARE_FAMILY_ROWS=""; MALWARE_CARD=""
# Mail-Kontext (v3.7) für den Anschreiben-Generator — Defaults für set -u
MAIL_AREA=""; MAIL_FINDING=""; MAIL_TIMEFRAME=""; MAIL_NEWEST=""; MAIL_FAMILIES_JSON="{}"
PRUEF_TOTAL=0
MALWARE_TOTAL=$(printf '%s' "$FUNDE"      | grep -c . || true)
PRUEF_TOTAL=$(printf   '%s' "$PRUEFUNGEN" | grep -c . || true)
# Die Ranglisten einmal bilden und weiterreichen — jede Auswertung unten liest
# sie, statt sie erneut zu berechnen.
FAM_RANG=$(printf   '%s' "$FUNDE"      | _fam_rangliste)
PRUEF_RANG=$(printf '%s' "$PRUEFUNGEN" | _fam_rangliste)
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
  _domfam=$(printf '%s\n' "$FAM_RANG" | head -1 | cut -f2)
  case "$_domfam" in
    "Backdoor/Webshell"|"Relay-Backdoor") _ns="eine versteckte Hintertür"; _np="mehrere versteckte Hintertüren";;
    "Defacement")                          _ns="eine verunstaltete Seite"; _np="mehrere verunstaltete Seiten";;
    "SEO-Spam/Doorway")                    _ns="eine versteckte Spam-Seite"; _np="mehrere versteckte Spam-Seiten";;
    *)                                     _ns="eine Schaddatei"; _np="mehrere Schaddateien";;
  esac
  [[ "$MALWARE_TOTAL" -eq 1 ]] && MAIL_FINDING="$_ns" || MAIL_FINDING="$_np"
  # Familien als JSON-Objekt (Namen ohne Sonderzeichen -> keine Escapes nötig)
  MAIL_FAMILIES_JSON="{"; _f1=1
  # Kompakte Zeilen für Bericht-Tabelle + PDF-Card, in einem Durchgang mit dem
  # JSON-Objekt — dieselbe Rangliste, damit beide dieselbe Reihenfolge tragen.
  while IFS=$'\t' read -r n f; do
    [[ -n "$f" ]] || continue
    [[ $_f1 -eq 0 ]] && MAIL_FAMILIES_JSON+=","
    MAIL_FAMILIES_JSON+="\"${f}\":${n}"; _f1=0
    MALWARE_FAMILY_ROWS+="| ${f} | ${n} | $(fam_biz "$f") |"$'\n'
    MALWARE_CARD+="- **${n}** ${f}"$'\n'
  done <<< "$FAM_RANG"
  MAIL_FAMILIES_JSON+="}"
fi

# Die Detaildatei entsteht, sobald ES ETWAS ZU ERKLÄREN GIBT — auch dann, wenn
# ausschliesslich Fundstellen des zweiten Rangs vorliegen. Bis v3.11 hing sie
# allein an MALWARE_TOTAL; ein Lauf mit drei kernfremden Dateien und keinem
# belegten Schadcode schrieb gar keine Erklärung, und der Kundenbericht
# verwies auf eine Datei, die es nicht gab.
if [[ "$MALWARE_TOTAL" -gt 0 || "$PRUEF_TOTAL" -gt 0 ]]; then
  {
    echo "# Fundstellen-Details${DOMAIN:+ — ${DOMAIN}}"
    echo
    echo "> Pfade **relativ zum Kundenverzeichnis** (nicht der absolute Serverpfad)."
    echo "> Erzeugt: $(date +"%d.%m.%Y, %H:%M Uhr") · Prüfung \`${RUN_LABEL}\` · ${MALWARE_TOTAL} Fundstelle(n), ${PRUEF_TOTAL} zu prüfen."
    echo
  } > "$DETAILS_FILE"

  if [[ "$MALWARE_TOTAL" -gt 0 ]]; then
    {
      echo "| Familie | Anzahl | Geschäftsmodell |"
      echo "|---|---|---|"
    } >> "$DETAILS_FILE"
    while IFS=$'\t' read -r n f; do
      [[ -n "$f" ]] || continue
      printf '| %s | %s | %s |\n' "$f" "$n" "$(fam_biz "$f")" >> "$DETAILS_FILE"
    done <<< "$FAM_RANG"
    echo >> "$DETAILS_FILE"
    while IFS=$'\t' read -r n f; do
      [[ -n "$f" ]] || continue
      {
        echo "## ${f} (${n}) — $(fam_biz "$f")"
        echo
        _fam_zeilen "$f" "$FUNDE"
        echo
      } >> "$DETAILS_FILE"
    done <<< "$FAM_RANG"
  fi

  # Zweiter Rang, ausdrücklich abgesetzt. Wer diese Liste liest, soll nicht
  # denken, hier stünden bestätigte Funde — und wer sie NICHT sieht, soll nicht
  # denken, es habe niemand hingesehen.
  if [[ "$PRUEF_TOTAL" -gt 0 ]]; then
    {
      echo "---"
      echo
      echo "# Zu prüfen — Einordnung offen (${PRUEF_TOTAL})"
      echo
      echo "> Diese Fundstellen sind **kein belegter Schadcode** und zählen nicht in die"
      echo "> Zahl oben. Ihre Quelle meldet sie als prüfenswert, nicht als bestätigt:"
      echo "> eine kernfremde Datei ist oft eine Update-Altlast, ein mu-Plugin meistens"
      echo "> gewollt. Ungeprüft bleiben sollten sie trotzdem nicht."
      echo
    } >> "$DETAILS_FILE"
    while IFS=$'\t' read -r n f; do
      [[ -n "$f" ]] || continue
      {
        echo "## ${f} (${n}) — $(fam_biz "$f")"
        echo
        _fam_zeilen "$f" "$PRUEFUNGEN"
        echo
      } >> "$DETAILS_FILE"
    done <<< "$PRUEF_RANG"
  fi

  echo "  Fundstellen-Details: $DETAILS_FILE (${MALWARE_TOTAL} Fund(e), $(printf '%s' "$MALWARE_CARD" | grep -c .) Familien, ${PRUEF_TOTAL} zu prüfen)" >> "$REPORT_FILE"
fi
