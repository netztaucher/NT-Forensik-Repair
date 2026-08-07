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
CRIT_LIST=""   # Markdown-Bullets (alle Befunde — Technik/Betreiber)
WARN_LIST=""
CUST_CRIT_LIST=""   # nur WEBSITE-Befunde (Kundenbericht) — via crit "…" web
CUST_WARN_LIST=""
EVIDENCE_IDX=0
WPDB_FLAGS=0
WPDB_VERDICT="⚪ Keine WordPress-Installation im Scan-Pfad gefunden — keine Datenbank-Prüfung durchgeführt."
ROOT_VERDICT="⚪ Root-Prüfung nicht durchgeführt."
# WP-Integritäts-/Doorway-Befunde (v3.3) — für findings.json
CORE_INJECTED=""       # veränderte Core-Dateien (verify-checksums "doesn't verify")
CORE_SNE=""            # Core-fremde Dateien (verify-checksums "should not exist")
DOORWAY_DIRS=""        # Verzeichnisse mit Doorway-.htaccess-Signatur
CORE_INJECT_HITS=""    # Dateien mit @include base64_decode() (Bootstrap-Injektion)
DISGUISED_PAYLOADS=""  # als Nicht-PHP getarnte Payloads (<?php in .ttf/.png/.gif/.css…)
ROGUE_ADMINS=""        # via wp-cli-Fallback gefundene Angreifer-Admins
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
