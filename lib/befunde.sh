# shellcheck shell=bash
# ============================================================
# NT-Forensik — Befund-Variablen (das Modul-Interface)
# ------------------------------------------------------------
# Jede Variable, die ein Pruefabschnitt fuellt und der Berichtsteil liest,
# wird hier mit einem neutralen Vorgabewert angelegt. Das ist der Vertrag
# zwischen den Modulen: ein uebersprungener Abschnitt hinterlaesst seinen
# Vorgabewert, und der Bericht laeuft unter 'set -u' trotzdem durch.
# 
# Neuen Befund ergaenzen heisst: hier eine Zeile eintragen.
# ============================================================

# ── Zähler & Befund-Sammlung für Kunden-/BSI-Bericht ─────────
N_CRIT=0; N_WARN=0; N_OK=0
# Vierter Zustand (v3.11): die Pruefung lief, lieferte aber keine Aussage —
# Werkzeug fehlt, Zugang verweigert, Antwort unlesbar. Getrennt gezaehlt, weil
# das weder eine bestandene Pruefung noch eine Auffaelligkeit ist. Solange er
# ueber 0 steht, kann die Kundenampel nicht auf gruen springen.
N_UNKNOWN=0
CRIT_LIST=""   # Markdown-Bullets (alle Befunde — Technik/Betreiber)
WARN_LIST=""
UNKNOWN_LIST=""
CUST_CRIT_LIST=""   # nur WEBSITE-Befunde (Kundenbericht) — via crit "…" web
CUST_WARN_LIST=""
CUST_UNKNOWN_LIST=""

# ── Generisches Befundschema (v3.12) ─────────────────────────
# Eine Zeile je Befund: app <TAB> kategorie <TAB> schwere <TAB> text <TAB> pfad.
# Loest die rund zwanzig anwendungsspezifischen Variablen weiter unten ab —
# schrittweise, je Modul, sobald es ohnehin angefasst wird.
BEFUNDE=""
VERDIKTE=""
KANAL_VERWEIGERT=""   # Befunde, denen die Kundenspur verwehrt wurde (ab v3.13)
MASKIERUNG_FEHLER=""  # Dokumente, deren Maskierung scheiterte. Fruehere
                      # Fassungen meldeten das als "(nichts zu maskieren)"
                      # und lieferten den unmaskierten Bericht aus.
EVIDENCE_IDX=0
WPDB_FLAGS=0
WPDB_VERDICT="⚪ Keine WordPress-Installation im Scan-Pfad gefunden — keine Datenbank-Prüfung durchgeführt."
ROOT_VERDICT="⚪ Root-Prüfung nicht durchgeführt."
# WP-Integritäts-/Doorway-Befunde (v3.3) — für findings.json
CORE_INJECTED=""       # veränderte Core-Dateien (verify-checksums "doesn't verify")
CORE_SNE=""            # Core-fremde Dateien (verify-checksums "should not exist")
DOORWAY_DIRS=""        # Verzeichnisse mit Doorway-.htaccess-Signatur
CORE_INJECT_HITS=""    # Dateien mit @include base64_decode() (Bootstrap-Injektion)
# Dateien, die in einer .htaccess NAMENTLICH freigegeben sind, zu keinem
# bekannten Einstiegspunkt gehoeren — und dort liegen. Fuer dieses Muster gibt
# es keinen legitimen Fall: wer seine Ablage haertet, muss seinen eigenen
# Dateinamen eintragen, sonst sperrt er sich selbst aus (Abschnitt 7.6b, #46).
WEBSHELL_NAMEN=""
DISGUISED_PAYLOADS=""  # als Nicht-PHP getarnte Payloads (<?php in .ttf/.png/.gif/.css…)
ROGUE_ADMINS=""        # via wp-cli-Fallback gefundene Angreifer-Admins
# ── Handlungsfaehige Fassung derselben Konten ────────────────
# ROGUE_ADMINS traegt den Instanznamen in einer Kopfzeile "=== kurz ===".
# findings.json filtert die beim Bauen der Liste heraus — in
# actionable.rogue_wp_admins standen deshalb Benutzernamen OHNE Installation.
# Auf einem Server mit 475 vhosts ist das nicht handlungsfaehig, sondern
# gefaehrlich: derselbe Name existiert dort vielfach.
#
# Genau daran scheiterte die Bereinigung: die Aktionsart rogue_admin_removed
# war im Berichtsgenerator vorgesehen, wurde aber nie erzeugt, weil ihr die
# Daten fehlten.
#
# Diese beiden Sammler fuehren je Zeile den VOLLEN Pfad mit:
#   <pfad>\t<benutzer>\t<email>\t<angelegt>
ROGUE_ADMINS_DETAIL=""    # belegt: nach dem Vorfall angelegt
SUSPECT_ADMINS_DETAIL=""  # Verdacht: angreifertypischer Name/Adresse
NC_HTACCESS_MAL=""     # Nextcloud: .htaccess mit Angreifer-Merkmalen
NC_MALWARE=""          # Nextcloud: bekannte Schaddateien und aufgeblaehte index.php
NC_NESTED=""           # Nextcloud: verschachtelte Verzeichnisse (config/config)
NC_INTEGRITY=""        # Nextcloud: Abweichungen laut occ integrity:check-core
NC_HAERTUNG=""         # Nextcloud: Härtungslücken (Abschnitt 12c). Bewusst
                       # getrennt von den Befunden oben: eine Lücke sagt, wie
                       # leicht ein Zugriff wäre, nicht dass einer stattfand.
SUSPECT_ADMINS=""      # Admins mit angreifertypischem Namen/Adresse — Verdacht,
                       # kein Beweis. Bewusst getrennt von ROGUE_ADMINS, damit
                       # eine automatische Bereinigung sie nie anfasst.
SUSP_PLUGINS=""        # verdächtige Plugins/mu-Plugins (alle bewertet, auch inaktive)
MU_PLUGINS=""          # alle mu-Plugins (laufen immer, ohne Aktivierung)
TAMPERED_HTACCESS=""   # manipulierte .htaccess (Malware-Whitelist, bricht Admin/403)

# ── v3.12: Fundlisten der Rezepte ────────────────────────────
# Beim Umzug der WordPress- und Nextcloud-Pruefungen von module/11 und
# module/12b nach rezepte/ blieben die Variablen darueber stehen, wurden aber
# von niemandem mehr gefuellt. Auffallen konnte das nirgends: findings.json
# gibt sie weiter aus, nur eben als leere Listen — und eine leere Liste liest
# sich wie "nichts gefunden". Der Reparaturteil bekam damit keine
# Quarantaene-Kandidaten mehr, und metrics.rogue_wp_admins stand dauerhaft auf
# 0, auch wenn im selben Bericht Angreifer-Admins benannt waren (#2).
#
# Die Rezepte fuellen sie seit v3.12 wieder. Zwei Listen kamen neu hinzu, weil
# es ihre Quelle vorher nicht gab:
PLUGIN_VERAENDERT=""   # Plugin-Codedateien, die von wordpress.org abweichen
SIGNATUR_TREFFER=""    # Treffer aus rezepte/*/signaturen.tsv (alle Anwendungen)
WP_COUNT=0             # gefundene WordPress-Installationen. Wurde nach dem
                       # Umzug nach rezepte/ nirgends mehr gesetzt und stand
                       # dauerhaft auf 0 — auch in findings.json (#2).

# ── v3.11: Abschnitt 16 (.htaccess) ──────────────────────────
HTACCESS_FREMD=""      # .htaccess mit Angreifer-Direktiven
HTACCESS_UNWIRKSAM=""  # Grund, warum .htaccess-Dateien gar nicht ausgewertet
                       # werden (AllowOverride None, nginx ohne Apache). Eine
                       # Datei, die niemand liest, gibt falsche Sicherheit.

# ── v3.4: Relay-Backdoors — Variablen & Selbstausschluss ─────
GSOCKET_HITS=""          # Dateien/Prozesse mit gsocket-Signatur
MASQ_BINARIES=""         # ELF-Binaries getarnt als Schlüssel-/Konfigdatei
FILELESS_PROCS=""        # Prozesse aus memfd (nur im RAM)
KTHREAD_FAKES=""         # als Kernel-Thread getarnte User-Prozesse
ORPHAN_SHELLS=""         # verwaiste Interpreter ohne TTY
SSH_LOGIN_HOOKS=""       # ~/.ssh/rc und /etc/ssh/sshrc
RELAY_CONNECTIONS=""     # ausgehende 443/7350 durch untypische Prozesse
YARA_HITS=""             # YARA-Treffer (falls yara installiert)
RELAY_VERDICT="⚪ Relay-Backdoor-Prüfung nicht durchgeführt."
# v3.6 System-Integrität & autoritative Scanner-Taps — für findings.json
TIMESTOMP=""           # Dateien mit zurückdatiertem mtime (Timestomping)
RECENT_SYS=""          # kürzlich veränderte Dateien in stabilen Systemdirs
IMUNIFY_HITS=""        # offene Imunify-Malware-Treffer im Scope
WPTK_INFECTED=""       # vom WP Toolkit als infiziert markierte Instanzen

# ── v3.8: Joomla-Prüfung (Abschnitt 12) ──────────────────────
JOOMLA_FLAGS=0
JOOMLA_COUNT=0
JOOMLA_SKIPPED=0         # übersprungene Backup-/Quarantäne-Kopien
JOOMLA_VERDICT="⚪ Keine Joomla-Installation im Scan-Pfad gefunden — keine Joomla-Prüfung durchgeführt."
JOOMLA_CONFIGS=""        # gefundene configuration.php (mit class JConfig)
JOOMLA_VERSIONS=""       # "site<TAB>version<TAB>quelle" je Installation
JOOMLA_CORE_MODIFIED=""  # veränderte Kern-Dateien (Prüfsummen-Diff, ab v3.8.1)
JOOMLA_CORE_UNKNOWN=""   # kernfremde Dateien in reinen Kern-Verzeichnissen
JOOMLA_SYS_PLUGINS=""    # System-Plugins ohne Paket/Verzeichnis (DB-Persistenz)
JOOMLA_ROGUE_SUPER=""    # neu angelegte, nie benutzte Super-User
JOOMLA_SESSION_HITS=""   # Deserialisierungs-Payloads in #__session.data
JOOMLA_MOD_CUSTOM=""     # mod_custom-Module mit Fremd-/Obfuskations-Injektion
JOOMLA_TPL_PARAMS=""     # #__template_styles.params-Injektionen (Helix3-Muster)
JOOMLA_USER_KEYS=""      # #__user_keys (Remember-Me-Token als Backdoor)
JOOMLA_VULN_EXT=""       # verwundbare Erweiterungen (VEL/CVE-Abgleich)
JOOMLA_CONFIG_WEAK=""    # Härtungsbefunde aus configuration.php
JOOMLA_MALWARE=""        # Joomla-typische Schaddateien (Bild-Magic + PHP u.a.)
JOOMLA_LOG_IOC=""        # Access-Log-Indikatoren (JCE-Bot, API-Leak-Abrufe)
JOOMLA_DATA_DIR="${BASE_DIR}/daten/joomla"
J_DATA_STAMP=""          # Stand des Offline-Datenbestands (YYYY-MM-DD)
JOOMLA_DATA_AGE=0        # Alter des Offline-Datenbestands in Tagen
ONLINE_FETCHES=""        # Protokoll aller Netzabrufe (forensische Transparenz)

# Aus Abschnitt 13 hochgezogen: der Kundenbericht und die PDF-Zusammenfassung
# lesen ROOT_CUSTOMER_HINT ungeschützt. Ohne Default bricht jeder Lauf ab,
# bei dem die Root-Prüfung nicht gelaufen ist.
ROOT_CUSTOMER_HINT="Die Reichweite auf Serverebene wurde in diesem Lauf nicht geprüft."
MALWARE_TOTAL=0          # Grobstatistik der Schadcode-Familien (Abschnitt 13)