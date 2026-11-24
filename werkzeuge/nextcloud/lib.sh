#!/usr/bin/env bash
# =============================================================================
# werkzeuge/nextcloud/lib.sh — gemeinsame Helfer der Nextcloud-IR-Werkzeuge
# =============================================================================
# Test:     ja - werkzeuge/nextcloud/nextcloud_selbsttest.sh (Attrappen, CI) · NT-Forensik-Repair#162
# Rueckweg: entfällt - nur Funktionen, ändert selbst nichts
#
# Wird von den Skripten in diesem Ordner per `source` geladen. Annahmen: Plesk,
# Nextcloud unter <vhosts>/<domain>/httpdocs, occ läuft als Systembenutzer des Abos.
#
# Geheimnisse: Werte stehen nur in Variablen, Umgebung einzelner Prozesse
# (MYSQL_PWD, PSA_PASSWORD, OC_PASS) oder Pipes (curl -K -). Nie als Argument,
# nie in einer Ausgabe. Belege nur als sha256-12 (nc_fp).
#
# Pfade lassen sich für den Selbsttest umlenken (Vorgaben = Plesk-Server):
#   NC_VHOSTS=/var/www/vhosts  NC_CHANGELOG=/root/changelog.md
#   NC_PSA_SHADOW=/etc/psa/.psa.shadow  NC_PHP_WURZEL=/opt/plesk/php
# =============================================================================
# shellcheck shell=bash

NC_VHOSTS=${NC_VHOSTS:-/var/www/vhosts}
NC_CHANGELOG=${NC_CHANGELOG:-/root/changelog.md}
NC_PSA_SHADOW=${NC_PSA_SHADOW:-/etc/psa/.psa.shadow}
NC_PHP_WURZEL=${NC_PHP_WURZEL:-/opt/plesk/php}
NC_MEM=${NC_MEM:-1536M}
NC_KUERZEL=${NC_KUERZEL:-nc}

nc_abbruch(){ echo "ABBRUCH: $1" >&2; exit "${2:-1}"; }
nc_h(){ echo; echo "===== $(date -u +%T) $* ====="; }
nc_log(){ echo "$(date -u +%FT%TZ) nc-ir $NC_KUERZEL: $*" | tee -a "$NC_CHANGELOG" >&2; }

# sha256-12 eines Werts. printf ist ein Builtin: der Wert erscheint in keiner Prozessliste.
nc_fp(){
  if command -v sha256sum >/dev/null 2>&1; then printf '%s' "$1" | sha256sum | cut -c1-12
  else printf '%s' "$1" | shasum -a 256 | cut -c1-12; fi
}

# Zufallswert, 32 Zeichen A-Za-z0-9
nc_neuwert(){ openssl rand -base64 64 | tr -dc 'A-Za-z0-9' | cut -c1-32; }

# curl-Konfigurationszeile `user = "<name>:<wert>"` für `curl -K -` (Wert nie als Argument)
nc_curl_user(){
  local v="$1:$2"; v=${v//\\/\\\\}; v=${v//\"/\\\"}
  printf 'user = "%s"\n' "$v"
}

# Hilfe = Kopfkommentar des aufrufenden Skripts
nc_hilfe(){ sed -n '2,/^set /{/^#/p;}' "$0" | sed -E 's/^# ?//'; }

# Gemeinsame Schalter. Unbekanntes landet in NC_REST.
nc_args(){
  NC_LOS=0; NC_D=${NC_D:-}; NC_U=${NC_U:-}; NC_IP=${NC_IP:-}; NC_REST=()
  while [ $# -gt 0 ]; do
    case "$1" in
      --domain|--abo|--ip|--arbeit|--quarantaene)
        [ $# -ge 2 ] || nc_abbruch "Wert fehlt für $1"
        case "$1" in
          --domain) NC_D=$2;; --abo) NC_U=$2;; --ip) NC_IP=$2;;
          --arbeit) NC_ARBEIT=$2;; --quarantaene) NC_Q=$2;;
        esac; shift 2;;
      --ausfuehren) NC_LOS=1; shift;;
      -h|--help) nc_hilfe; exit 0;;
      *) NC_REST+=("$1"); shift;;
    esac
  done
}

# Namen prüfen, bevor sie in SQL oder Pfade gehen
nc_pruefe_namen(){
  [ -n "$NC_D" ] || nc_abbruch "--domain fehlt"
  printf '%s' "$NC_D" | grep -Eq '^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$' || nc_abbruch "Domain ungültig: $NC_D"
  [ -n "$NC_U" ] || nc_abbruch "--abo fehlt (Systembenutzer des Plesk-Abos)"
  printf '%s' "$NC_U" | grep -Eq '^[a-z_][a-z0-9_.-]*$' || nc_abbruch "Abo-Benutzer ungültig: $NC_U"
  [ -z "$NC_IP" ] || printf '%s' "$NC_IP" | grep -Eq '^[0-9a-fA-F.:]+$' || nc_abbruch "IP ungültig: $NC_IP"
}

# Pfade, PHP-Handler, ini-Verzeichnis. Danach sind nc_occ, nc_ver, nc_web_ok nutzbar.
nc_init(){
  nc_pruefe_namen
  NC_V=$NC_VHOSTS/$NC_D; NC_W=$NC_V/httpdocs; NC_C=$NC_W/config/config.php
  NC_ARBEIT=${NC_ARBEIT:-/root/nc-ir/$NC_D}; NC_Q=${NC_Q:-/root/quarantaene/nc-$NC_D}
  [ -f "$NC_C" ] || nc_abbruch "keine Nextcloud unter $NC_W (config/config.php fehlt)" 2
  NC_RESOLVE=(); [ -z "$NC_IP" ] || NC_RESOLVE=(--resolve "$NC_D:443:$NC_IP")
  NC_PHPV=$(plesk db -Ne "SELECT h.php_handler_id FROM hosting h JOIN domains d ON d.id=h.dom_id WHERE d.name='$NC_D'")
  NC_INI=$(mktemp -d "${TMPDIR:-/tmp}/nc-ir-ini.XXXXXX")
  printf 'memory_limit=%s\napc.enable_cli=1\n' "$NC_MEM" > "$NC_INI/99-nc-ir.ini"
  chmod 755 "$NC_INI"; chmod 644 "$NC_INI/99-nc-ir.ini"
  # shellcheck disable=SC2064
  trap "rm -rf '$NC_INI'" EXIT
}

# PHP-Version aus der Handler-Kennung (plesk-php83-fastcgi -> 8.3)
nc_phpversion(){ printf '%s' "${1:-$NC_PHPV}" | sed -nE 's/.*php-?([0-9])([0-9]+).*/\1.\2/p'; }
nc_phpbin(){ local v; v=$(nc_phpversion); echo "$NC_PHP_WURZEL/${v:-8.2}/bin/php"; }

nc_php(){ runuser -u "$NC_U" -- env PHP_INI_SCAN_DIR=":$NC_INI" "$(nc_phpbin)" -d memory_limit="$NC_MEM" -d apc.enable_cli=1 "$@"; }
nc_occ(){ ( cd "$NC_W" && nc_php occ --no-interaction "$@" ); }

nc_cfg(){ sed -nE "s/^[[:space:]]*'$1'[[:space:]]*=>[[:space:]]*'([^']*)'.*/\1/p" "${2:-$NC_C}" | head -1; }
nc_ver(){ sed -nE "s/.*OC_VersionString[[:space:]]*=[[:space:]]*'([^']+)'.*/\1/p" "$NC_W/version.php" | head -1; }

# Gesund = installiert, keine Wartung, kein offenes DB-Upgrade, Login-Seite 200
nc_web_ok(){
  local st lc
  st=$(curl -sk --max-time 30 ${NC_RESOLVE[@]+"${NC_RESOLVE[@]}"} "https://$NC_D/status.php")
  lc=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 30 ${NC_RESOLVE[@]+"${NC_RESOLVE[@]}"} "https://$NC_D/index.php/login")
  echo "  status.php: $(printf '%s' "$st" | grep -oE '"(installed|maintenance|needsDbUpgrade|versionstring)":[^,}]*' | tr '\n' ' ')· Login HTTP $lc"
  printf '%s' "$st" | grep -q '"installed":true' && printf '%s' "$st" | grep -q '"maintenance":false' \
    && printf '%s' "$st" | grep -q '"needsDbUpgrade":false' && [ "$lc" = 200 ]
}

# MySQL-Admin auf Plesk: Wert nur in MYSQL_PWD, --no-defaults gegen /root/.my.cnf
nc_mysql_admin(){ MYSQL_PWD="$(cat "$NC_PSA_SHADOW")" mysql --no-defaults -u admin "$@"; }
nc_dump(){ MYSQL_PWD="$(cat "$NC_PSA_SHADOW")" mysqldump --no-defaults -u admin --single-transaction --routines --add-drop-database --databases "$2" | gzip > "$1"; }
nc_restore(){ gunzip -c "$1" | nc_mysql_admin; }

# Prüft einen Wert (stdin) gegen einen crypt-Hash ($5$/$6$). 0 passt, 1 passt nicht, 2 nicht prüfbar.
nc_shadow_passt(){
  local h="$1" id salt neu
  id=$(printf '%s' "$h" | cut -d'$' -f2); salt=$(printf '%s' "$h" | cut -d'$' -f3)
  case "$id" in 5|6) ;; *) cat >/dev/null; return 2;; esac
  case "$salt" in rounds=*) cat >/dev/null; return 2;; esac
  neu=$(openssl passwd -"$id" -salt "$salt" -stdin 2>/dev/null) || return 2
  [ "$neu" = "$h" ]
}
