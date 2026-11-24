#!/usr/bin/env bash
# =============================================================================
# nextcloud_selbsttest.sh — Selbsttest der Nextcloud-IR-Werkzeuge (#162), ohne Netz und ohne root
# =============================================================================
# Test:     ja - dieser Lauf selbst (CI-Schritt „Selbsttest Nextcloud-IR-Werkzeuge") · NT-Forensik-Repair#162
# Rueckweg: entfällt - liest nur (Arbeitsdateien in mktemp)
#
#   bash werkzeuge/nextcloud/nextcloud_selbsttest.sh
#
# Attrappen für plesk, php (occ, updater.phar, cron.php, php -r), mysql, mysqldump, curl
# (status.php, Login, WebDAV, IMAP, Plesk-API), runuser, sudo, getent, pgrep, shred, ssh, scp
# und op halten den Zustand in Dateien. ssh führt den Befehl lokal aus: der Treiber läuft
# damit Ende zu Ende bis in das Server-Skript.
#
# Geprüft wird in beide Richtungen, und für jeden Lauf zusätzlich: kein Geheimnis steht in
# einem Argument (Protokoll aller Attrappen-Aufrufe), in einer Ausgabe oder im changelog.
# =============================================================================
set -uo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
PASS=0; FAILS=0
ok()  { PASS=$((PASS+1)); }
nok() { FAILS=$((FAILS+1)); echo "FEHLER: $*"; }
eq()  { if [ "$1" = "$2" ]; then ok; else nok "$3"$'\n'"  erwartet: $2"$'\n'"  erhalten: $1"; fi; }
ja()  { if eval "$1"; then ok; else nok "$2"; fi; }
sha() { openssl dgst -sha256 -r | cut -c1-64; }

BIN=$TMP/bin; ST=$TMP/st; RTMP=$TMP/rtmp
export ST RTMP
mkdir -p "$BIN" "$RTMP" "$TMP/php/8.2/bin" "$TMP/php/8.3/bin"

# ── Attrappen ───────────────────────────────────────────────────────────────
cat > "$BIN/plesk" <<'EOF'
#!/usr/bin/env bash
sha(){ openssl dgst -sha256 -r | cut -c1-64; }
echo "plesk $*" >> "$ST/aufrufe"
if [ "$1" = db ] && [ $# -eq 1 ]; then
  sql=$(cat); pw=$(printf '%s' "$sql" | sed -nE "s/.*IDENTIFIED BY '(.*)';\$/\1/p" | head -1); pw=${pw//\'\'/\'}
  printf '%s' "$pw" | sha > "$ST/db-pw"; printf '%s' "$pw" > "$ST/db-pw-roh"; exit 0
fi
if [ "$1" = db ]; then
  case "$3" in
    *php_handler_id*) cat "$ST/handler";;
    *"FROM mysql.user"*) echo localhost;;
    *"SELECT password FROM"*) uid=$(printf '%s' "$3" | sed -nE "s/.*uid='(.*)'\$/\1/p"); cat "$ST/nc-hash.$uid" 2>/dev/null; true;;
    *"FROM accounts"*) echo "1 $(cut -c1-12 "$ST/admin-pw")";;
    *COUNT*) echo 3;;
    *) echo 1;;
  esac; exit 0
fi
case "$1 $2" in
  "bin subscription") [ -f "$ST/plesk-lehnt-ab" ] && exit 1
    printf '%s' "$PSA_PASSWORD" | openssl passwd -6 -salt "$(openssl rand -hex 4)" -stdin > "$ST/shadow";;
  "bin mail") [ -f "$ST/mail-setzt-nicht" ] && exit 0; printf '%s' "$PSA_PASSWORD" | sha > "$ST/postfach-pw";;
  "bin admin") printf '%s' "$PSA_PASSWORD" | sha > "$ST/admin-pw";;
  "bin domain") h=""; p=""; for x; do [ "$p" = -php_handler_id ] && h=$x; p=$x; done; echo "$h" > "$ST/handler";;
esac
EOF

cat > "$TMP/php/8.2/bin/php" <<'EOF'
#!/usr/bin/env bash
sha(){ openssl dgst -sha256 -r | cut -c1-64; }
echo "php $*" >> "$ST/aufrufe"
a=(); while [ $# -gt 0 ]; do case "$1" in -d) shift 2;; *) a+=("$1"); shift;; esac; done
set -- "${a[@]}"
ver(){ sed -nE "s/.*OC_VersionString = '([^']+)'.*/\1/p" version.php; }
case "$1" in
  -m) printf 'Core\nctype\ncurl\nmysqli\n';;
  -r) cat >/dev/null; echo "neuer App-Wert fp 000000000000, zurückgelesen gleich" >&2
      [ -f "$ST/mailapp-kaputt" ] && exit 4; echo "${NC_POSTFACH:-}" > "$ST/mailapp-gesetzt";;
  -f) [ -f "$ST/cron-fehler" ] && { echo "Cannot declare class RepairMisplacedTrashItemsJob"; exit 255; }
      echo $(( $(cat "$ST/lastcron") + 60 )) > "$ST/lastcron";;
  occ) shift; [ "${1:-}" = --no-interaction ] && shift
    case "$1" in
      status) echo "  - versionstring: $(ver)";;
      app:list) printf 'Enabled:\n  - foo: 1.0\nDisabled:\n';;
      app:update) if [ "${2:-}" = --showonly ]; then [ -f "$ST/app-updates" ] && echo "groupfolders new version available: 23.0.2"; true
                  else [ -f "$ST/appupdate-kaputt" ] && exit 1; rm -f "$ST/app-updates" "$ST/cron-fehler"; echo "groupfolders updated"; fi;;
      user:list) echo '{"alice":"Alice","bob":"Bob"}';;
      group:list) echo '{"admin":["alice"],"users":["bob"]}';;
      user:resetpassword) uid=""; for x; do uid=$x; done; [ -n "${OC_PASS:-}" ] || exit 1; printf '%s' "$OC_PASS" | sha > "$ST/nc-hash.$uid";;
      list) [ -f "$ST/nc27" ] || echo "  user:auth-tokens:delete";;
      user:auth-tokens:delete) echo "$2" >> "$ST/abgemeldet";;
      config:app:get) if [ "$3" = lastcron ]; then cat "$ST/lastcron"; else echo cron; fi;;
      *) echo "ok $1";;
    esac;;
  updater/updater.phar)
    [ -f "$ST/updater-kaputt" ] && { echo "Fatal error: Allowed memory size exhausted"; exit 1; }
    for s in "$NC_TEST_DATA"/updater-*/.step; do [ -f "$s" ] && { echo "update of code successful"; exit 0; }; done
    n=$(head -1 "$ST/updater-plan" 2>/dev/null)
    [ -n "$n" ] || { echo "No update available."; exit 0; }
    [ -f "$ST/updater-ohne-wirkung" ] && { echo "update of code successful"; exit 0; }
    tail -n +2 "$ST/updater-plan" > "$ST/p.n"; mv "$ST/p.n" "$ST/updater-plan"
    printf "<?php\n\$OC_VersionString = '%s';\n" "$n" > version.php
    echo "update of code successful";;
esac
EOF
ln -s ../../8.2/bin/php "$TMP/php/8.3/bin/php"

cat > "$BIN/curl" <<'EOF'
#!/usr/bin/env bash
sha(){ openssl dgst -sha256 -r | cut -c1-64; }
echo "curl $*" >> "$ST/aufrufe"
url=""; kfg=0; p_=""
for x; do case "$x" in http*|imaps*) url=$x;; esac; [ "$p_" = -K ] && [ "$x" = - ] && kfg=1; p_=$x; done
u=""; p=""
if [ $kfg = 1 ]; then
  v=$(python3 -c 'import re,sys
m=re.search(r"^user = \"((?:[^\"\\]|\\.)*)\"", sys.stdin.read(), re.M)
print(re.sub(r"\\(.)", r"\1", m.group(1)) if m else "", end="")')
  u=${v%%:*}; p=${v#*:}
fi
ver=$(sed -nE "s/.*OC_VersionString = '([^']+)'.*/\1/p" "$NC_TEST_W/version.php" 2>/dev/null)
g=1; [ -f "$ST/kaputt-$ver" ] && g=0; [ -f "$ST/kaputt" ] && g=0
case "$url" in
  */status.php) if [ $g = 1 ]; then echo "{\"installed\":true,\"maintenance\":false,\"needsDbUpgrade\":false,\"versionstring\":\"$ver\"}"
                else echo '{"installed":true,"maintenance":false,"needsDbUpgrade":true}'; fi;;
  */index.php/login) [ $g = 1 ] && printf 200 || printf 500;;
  */remote.php/dav/*) [ "$(printf '%s' "$p" | sha)" = "$(cat "$ST/nc-hash.$u" 2>/dev/null)" ] && printf 207 || printf 401;;
  imaps://*) [ "$(printf '%s' "$p" | sha)" = "$(cat "$ST/postfach-pw" 2>/dev/null)" ] && exit 0; exit 67;;
  *:8443/*) [ "$(printf '%s' "$p" | sha)" = "$(cat "$ST/admin-pw" 2>/dev/null)" ] && printf 200 || printf 401;;
esac
EOF

cat > "$BIN/mysql" <<'EOF'
#!/usr/bin/env bash
sha(){ openssl dgst -sha256 -r | cut -c1-64; }
echo "mysql $*" >> "$ST/aufrufe"
u=""; q=0; p_=""; for x; do [ "$p_" = -u ] && u=$x; case "$x" in -Nse|-Ne|-e) q=1;; esac; p_=$x; done
if [ "$u" = admin ]; then
  [ "${MYSQL_PWD:-}" = "$(cat "$NC_PSA_SHADOW")" ] || { echo "ERROR 1045 (28000): Access denied for user 'admin'" >&2; exit 1; }
  if [ $q = 1 ]; then echo 1; else cat >/dev/null; echo restore >> "$ST/restores"; fi; exit 0
fi
s=$(printf '%s' "${MYSQL_PWD:-}" | sha)
[ "$s" = "$(cat "$ST/db-pw")" ] && { echo 1; exit 0; }
[ -f "$ST/db-alt-bleibt" ] && [ "$s" = "$(cat "$ST/db-pw-start")" ] && { echo 1; exit 0; }
echo "ERROR 1045 (28000): Access denied for user '$u'@'localhost' (using password: YES)" >&2; exit 1
EOF

cat > "$BIN/mysqldump" <<'EOF'
#!/usr/bin/env bash
echo "mysqldump $*" >> "$ST/aufrufe"; [ -f "$ST/dump-kaputt" ] && exit 2; echo "-- dump"
EOF
cat > "$BIN/runuser" <<'EOF'
#!/usr/bin/env bash
echo "runuser $*" >> "$ST/aufrufe"
while [ $# -gt 0 ]; do [ "$1" = -- ] && { shift; break; }; shift; done; exec "$@"
EOF
cat > "$BIN/sudo" <<'EOF'
#!/usr/bin/env bash
[ "$1" = -n ] && shift; exec "$@"
EOF
cat > "$BIN/getent" <<'EOF'
#!/usr/bin/env bash
[ "$1" = shadow ] && echo "$2:$(cat "$ST/shadow"):19000:0:99999:7:::"
EOF
cat > "$BIN/pgrep" <<'EOF'
#!/usr/bin/env bash
[ -f "$ST/pgrep-treffer" ]
EOF
cat > "$BIN/shred" <<'EOF'
#!/usr/bin/env bash
echo "shred $*" >> "$ST/aufrufe"; [ "$1" = -u ] && rm -f "$2"
EOF
cat > "$BIN/scp" <<'EOF'
#!/usr/bin/env bash
echo "scp $*" >> "$ST/aufrufe"; [ "$1" = -q ] && shift; cp "$1" "$RTMP/${2#*:/tmp/}"
EOF
cat > "$BIN/ssh" <<'EOF'
#!/usr/bin/env bash
echo "ssh $*" >> "$ST/aufrufe"; h=$1; shift; c="$*"
case "$c" in *nc-rotation-server.sh*) echo "ssh $h $(printf '%s' "$c" | sed -E 's/.*nc-rotation-server.sh ([a-z]+).*/\1/')" >> "$ST/reihenfolge";; esac
c=${c//\/tmp\//$RTMP/}; exec bash -c "$c"
EOF
cat > "$BIN/op" <<'EOF'
#!/usr/bin/env bash
echo "op $*" >> "$ST/aufrufe"
case "$1" in
  whoami) [ -f "$ST/op-abgemeldet" ] && exit 1; exit 0;;
  vault) echo '{"name":"Testtresor","items":3}';;
  item) case "$2" in
    create) n=$(ls "$ST/op" | wc -l | tr -d ' '); id="id$n"
            python3 -c 'import json,os,sys
d=json.load(sys.stdin); d["id"]=sys.argv[1]
if os.path.exists(sys.argv[2]) and d.get("fields"): d["fields"].pop()
print(json.dumps(d))' "$id" "$ST/op-verliert-feld" > "$ST/op/$id.json"
            echo "create $id" >> "$ST/reihenfolge"; cat "$ST/op/$id.json";;
    edit) echo "edit $3" >> "$ST/reihenfolge"; t=""; p_=""; for x; do [ "$p_" = --title ] && t=$x; p_=$x; done; echo "$t" > "$ST/op/$3.titel";;
    list) python3 -c 'import json,glob,os,sys
print(json.dumps([{"id":os.path.basename(f)[:-5],"title":json.load(open(f))["title"]} for f in sorted(glob.glob(sys.argv[1]+"/*.json"))]))' "$ST/opq";;
    get) cat "$ST/opq/$3.json";;
  esac;;
esac
EOF
chmod +x "$BIN"/* "$TMP/php/8.2/bin/php"
export PATH="$BIN:$PATH"

# ── Ausgangslage ────────────────────────────────────────────────────────────
D=nc.example.test; U=ncabo
VH=$TMP/vhosts; W=$VH/$D/httpdocs
ALTDB='AltDbWert0123456789abcdefGHIJ'; ALTSMTP='AltSmtp"Wert\0123456789abcdef'; PSAW='PsaAdminWert0123456789abcdef'
export NC_VHOSTS=$VH NC_CHANGELOG=$TMP/changelog.md NC_PSA_SHADOW=$TMP/psa.shadow NC_PHP_WURZEL=$TMP/php
export NC_PAUSE=0 NC_CRON_D=$TMP/cron.d NC_CRON_DENY=$TMP/cron.deny NC_TEST_W=$W NC_TEST_DATA=$W/data
export NC_REMOTE_DIR=$TMP/remote; unset OP_SERVICE_ACCOUNT_TOKEN
COMMON=(--domain "$D" --abo "$U" --arbeit "$TMP/arbeit" --quarantaene "$TMP/q")

aufbau(){
  rm -rf "$ST" "$VH" "$TMP/arbeit" "$TMP/q" "$TMP/cron.d" "$TMP/remote" "$NC_CHANGELOG" "$TMP"/out.*
  mkdir -p "$ST/op" "$ST/opq" "$W/config" "$W/apps/richdocumentscode" "$W/apps/files" "$W/cgi-bin" "$W/data/updater-oc1" "$W/updater" "$TMP/cron.d"
  touch "$W/occ" "$W/cron.php" "$W/updater/updater.phar" "$NC_CHANGELOG"
  echo 'proxy' > "$W/apps/richdocumentscode/proxy.php"; echo '#!/bin/sh' > "$W/cgi-bin/x.cgi"
  echo '{"state":"end","step":12}' > "$W/data/updater-oc1/.step"
  printf "<?php\n\$OC_VersionString = '27.1.11';\n" > "$W/version.php"
  {
    echo "<?php"; echo "\$CONFIG = array ("
    echo "  'dbtype' => 'mysql',"; echo "  'dbname' => 'nc_db',"; echo "  'dbhost' => 'localhost',"
    echo "  'dbuser' => 'ncuser',"; echo "  'dbpassword' => '$ALTDB',"; echo "  'dbtableprefix' => 'oc_',"
    echo "  'datadirectory' => '$W/data',"; echo "  'mail_smtphost' => 'mail.example.test',"
    echo "  'mail_smtpname' => 'postmaster@$D',"; echo "  'mail_smtppassword' => '${ALTSMTP//\'/}',"
    echo "  'mail_smtpauth' => '',"; echo "  'secret' => 'GeheimesSecret0123456789abcdef',"; echo ");"
  } > "$W/config/config.php"
  printf '%s' "$PSAW" > "$NC_PSA_SHADOW"
  echo plesk-php82-fastcgi > "$ST/handler"; echo 1000 > "$ST/lastcron"; echo "$U" > "$NC_CRON_DENY"
  printf '%s' "$ALTDB" | sha > "$ST/db-pw"; cp "$ST/db-pw" "$ST/db-pw-start"
  printf '%s' "$ALTSMTP" | sha > "$ST/postfach-pw"
  printf '%s' 'AltAbo0123456789abcdefghij' | openssl passwd -6 -salt abcd1234 -stdin > "$ST/shadow"
  printf '%s' 'AltAdmin0123456789abcdefgh' | sha > "$ST/admin-pw"
  printf '28.0.14\n29.0.16\n' > "$ST/updater-plan"
  : > "$ST/aufrufe"; : > "$ST/reihenfolge"
}
# lauf <name> <skript> args...  -> rc in $RC, Ausgabe in $TMP/out.<name>
lauf(){ local n=$1 s=$2; shift 2; bash "$DIR/$s" "$@" > "$TMP/out.$n" 2>&1; RC=$?; }
# Kein Geheimnis in Argumenten, Ausgaben, changelog
dicht(){   # <name> <wert>...
  local n=$1 v; shift
  for v in "$@"; do
    [ -n "$v" ] || continue
    if grep -qF -- "$v" "$ST/aufrufe" "$NC_CHANGELOG" "$TMP"/out.* 2>/dev/null; then nok "$n: Geheimnis (fp $(printf '%s' "$v" | sha | cut -c1-12)) steht in Argument/Ausgabe/changelog"; else ok; fi
  done
}
aendernd(){ grep -E 'plesk bin|updater\.phar|user:resetpassword|auth-tokens:delete|shred|op item create|app:update --all|maintenance:mode' "$ST/aufrufe"; }
cfgwert(){ sed -nE "s/^[[:space:]]*'$1'[[:space:]]*=>[[:space:]]*'([^']*)'.*/\1/p" "$W/config/config.php"; }

# ── 1. Lex Probatio ─────────────────────────────────────────────────────────
for f in "$DIR"/*.sh; do
  grep -qE '^# Test: +(ja|nein) - ' "$f" && grep -qE '^# Rueckweg: +(ja|nein|entfällt) - ' "$f" || nok "Kopfzeilen Test/Rueckweg fehlen: $(basename "$f")"
done; ok

# ── 2. Trockenläufe ändern nichts ───────────────────────────────────────────
aufbau; vor=$(cat "$W/config/config.php" "$W/version.php" "$ST/handler" | sha)
lauf tr-update nc-stufenupdate.sh "${COMMON[@]}" --app-entfernen richdocumentscode
eq "$RC" 0 "Trockenlauf Update rc"
ja 'grep -q "zu entfernen: .*richdocumentscode" "$TMP/out.tr-update"' "Trockenlauf Update nennt die App"
ja 'grep -q "liegengebliebener Updater-Zustand" "$TMP/out.tr-update"' "Trockenlauf Update nennt .step"
for t in inventur db abmelden; do lauf "tr-folge-$t" nc-folgelauf.sh "$t" "${COMMON[@]}"; eq "$RC" 0 "Trockenlauf folgelauf $t rc"; done
for t in cron appupdate quarantaene; do lauf "tr-abschluss-$t" nc-abschluss.sh "$t" "${COMMON[@]}"; eq "$RC" 0 "Trockenlauf abschluss $t rc"; done
lauf tr-mac nc-rotation-mac.sh "${COMMON[@]:0:4}" --server srv1 --mailserver mail1 --postfach "postmaster@$D" --tresor T --tag t
eq "$RC" 0 "Trockenlauf Treiber rc"
ja 'grep -q "TROCKENLAUF: nichts erzeugt" "$TMP/out.tr-mac"' "Trockenlauf Treiber endet als Trockenlauf"
eq "$(cat "$W/config/config.php" "$W/version.php" "$ST/handler" | sha)" "$vor" "Trockenläufe: config.php/version.php/Handler unverändert"
eq "$(aendernd)" "" "Trockenläufe: kein ändernder Aufruf"
ja '[ -d "$W/apps/richdocumentscode" ] && [ -d "$W/cgi-bin" ] && [ ! -e "$TMP/cron.d/nextcloud-$U" ]' "Trockenläufe: Dateien unberührt"
dicht trockenlauf "$ALTDB" "${ALTSMTP}" "$PSAW" GeheimesSecret0123456789abcdef

# ── 3. Stufen-Update: zwei Stufen, PHP-Wechsel bei 28, .step beiseite ───────
aufbau
lauf update nc-stufenupdate.sh "${COMMON[@]}" --app-entfernen richdocumentscode --ausfuehren
eq "$RC" 0 "Update rc"; [ "$RC" = 0 ] || tail -20 "$TMP/out.update"
eq "$(sed -nE "s/.*'([0-9.]+)'.*/\1/p" "$W/version.php")" 29.0.16 "Update: Endversion"
eq "$(cat "$ST/handler")" plesk-php83-fastcgi "Update: PHP-Handler 8.3 ab Hauptversion 28"
ja '[ ! -e "$W/apps/richdocumentscode" ] && ls "$TMP/q" | grep -q "^richdocumentscode-"' "Update: Einfallstor in Quarantäne"
ja '[ ! -e "$W/cgi-bin" ] && ls "$TMP/q" | grep -q "^httpdocs-cgi-bin-"' "Update: cgi-bin in Quarantäne"
ja '[ ! -e "$W/data/updater-oc1/.step" ] && ls -a "$W/data/updater-oc1" | grep -q "^.step.nc-ir-"' "Update: .step beiseitegelegt"
eq "$(ls "$TMP/arbeit/update-sicherung" | grep -c 'httpdocs-.*\.tgz$')" 3 "Update: Sicherung je Stufe (3 Stufen inkl. letzter Prüfung)"
ja 'grep -q "U Abschluss: Nextcloud 29.0.16" "$NC_CHANGELOG"' "Update: Abschluss im changelog"
dicht update "$ALTDB" "$PSAW"

# ── 4. Updater meldet Erfolg ohne Wirkung -> exit 5, kein Abschluss ─────────
aufbau; touch "$ST/updater-ohne-wirkung"
lauf update-ohne nc-stufenupdate.sh "${COMMON[@]}" --ausfuehren
eq "$RC" 5 "Updater ohne Wirkung: exit 5"
ja '! grep -q "U Abschluss" "$NC_CHANGELOG"' "Updater ohne Wirkung: kein Abschluss"

# ── 5. Stufe bricht -> Rückweg dieser Stufe, gesund -> exit 4 ───────────────
aufbau; touch "$ST/kaputt-29.0.16"
lauf update-rb nc-stufenupdate.sh "${COMMON[@]}" --ausfuehren
eq "$RC" 4 "Rückweg: exit 4"
eq "$(sed -nE "s/.*'([0-9.]+)'.*/\1/p" "$W/version.php")" 28.0.14 "Rückweg: Version der Stufe davor"
ja '[ -s "$ST/restores" ] && ls "$VH/$D" | grep -q "^httpdocs.fehlschlag-2-"' "Rückweg: DB eingespielt, kaputtes httpdocs beiseite"
aufbau; touch "$ST/kaputt"
lauf update-krank nc-stufenupdate.sh "${COMMON[@]}" --ausfuehren
eq "$RC" 2 "vorher ungesund: exit 2"
eq "$(aendernd)" "" "vorher ungesund: nichts geändert"

# ── 6. Folgelauf: DB-Passwort mit Kill-Proof 1045, Abmelden ─────────────────
aufbau
lauf db nc-folgelauf.sh db "${COMMON[@]}" --ausfuehren
eq "$RC" 0 "DB-Rotation rc"; [ "$RC" = 0 ] || tail -15 "$TMP/out.db"
NEUDB=$(cat "$ST/db-pw-roh" 2>/dev/null)
eq "$(cfgwert dbpassword)" "$NEUDB" "DB-Rotation: config.php trägt den neuen Wert"
ja 'grep -q "Kill-Proof bestanden" "$TMP/out.db" && grep -q "ERROR 1045" "$NC_CHANGELOG"' "DB-Rotation: Kill-Proof 1045 belegt"
ja '[ -f "$TMP/q/config.php.vor-rotation" ]' "DB-Rotation: Sicherung config.php"
dicht db "$ALTDB" "$NEUDB" "$PSAW"
aufbau; touch "$ST/db-alt-bleibt"
lauf db-rb nc-folgelauf.sh db "${COMMON[@]}" --ausfuehren
eq "$RC" 6 "DB-Rotation, alter Wert bleibt gültig: Rückweg exit 6"
eq "$(cfgwert dbpassword)" "$ALTDB" "DB-Rückweg: config.php wieder alt"
eq "$(cat "$ST/db-pw")" "$(cat "$ST/db-pw-start")" "DB-Rückweg: MariaDB wieder alt"
dicht db-rb "$ALTDB" "$(cat "$ST/db-pw-roh")"
aufbau
lauf ab nc-folgelauf.sh abmelden "${COMMON[@]}" --ausfuehren
eq "$RC" 0 "Abmelden rc"; eq "$(sort "$ST/abgemeldet" | tr '\n' ' ')" "alice bob " "Abmelden: alle Konten"
aufbau; touch "$ST/nc27"
lauf ab27 nc-folgelauf.sh abmelden "${COMMON[@]}" --ausfuehren
eq "$RC" 3 "Abmelden auf NC 27: Abbruch exit 3"
aufbau
lauf inv nc-folgelauf.sh inventur "${COMMON[@]}"
ja 'grep -q "Geheimnis-Schlüssel in config.php: .*dbpassword" "$TMP/out.inv"' "Inventur nennt Schlüssel"
dicht inventur "$ALTDB" "$ALTSMTP" GeheimesSecret0123456789abcdef

# ── 7. Treiber -> ssh -> Server: alle Teile, Ende zu Ende ───────────────────
aufbau
lauf mac nc-rotation-mac.sh --domain "$D" --abo "$U" --server srv1 --mailserver mail1 --postfach "postmaster@$D" --tresor T --tag t --ausfuehren
eq "$RC" 0 "Treiber rc"; [ "$RC" = 0 ] || tail -25 "$TMP/out.mac"
wert(){ python3 -c 'import json,glob,sys
for f in sorted(glob.glob(sys.argv[1]+"/id*.json")):
    d=json.load(open(f))
    if d["title"]==sys.argv[2]: print([x["value"] for x in d["fields"] if x["id"]=="password"][0])' "$ST/op" "$1"; }
W_ABO=$(wert "$D Systembenutzer $U"); W_PF=$(wert "postmaster@$D Postfach"); W_AL=$(wert "Nextcloud $D alice"); W_BO=$(wert "Nextcloud $D bob"); W_AD=$(wert "Plesk srv1 admin")
eq "$(ls "$ST/op" | grep -c '\.json$')" 5 "Treiber: fünf 1Password-Einträge"
ja 'printf "%s" "$W_ABO" | openssl passwd -6 -salt "$(cut -d\$ -f3 "$ST/shadow")" -stdin | grep -qxF "$(cat "$ST/shadow")"' "Treiber: Systembenutzer trägt den 1Password-Wert"
eq "$(printf '%s' "$W_PF" | sha)" "$(cat "$ST/postfach-pw")" "Treiber: Postfach trägt den 1Password-Wert"
eq "$(cfgwert mail_smtppassword)" "$W_PF" "Treiber: config.php mail_smtppassword neu"
eq "$(cat "$ST/mailapp-gesetzt" 2>/dev/null)" "postmaster@$D" "Treiber: Mail-App-Konto gesetzt"
eq "$(printf '%s' "$W_AL" | sha)" "$(cat "$ST/nc-hash.alice")" "Treiber: Konto alice trägt den 1Password-Wert"
eq "$(printf '%s' "$W_BO" | sha)" "$(cat "$ST/nc-hash.bob")" "Treiber: Konto bob trägt den 1Password-Wert"
eq "$(printf '%s' "$W_AD" | sha)" "$(cat "$ST/admin-pw")" "Treiber: Plesk-Admin trägt den 1Password-Wert"
ja 'grep -q "Kill-Proof bestanden" "$NC_CHANGELOG"' "Treiber: IMAP-Kill-Proof des Postfachs"
ja 'grep -q "nicht feststellbar" "$NC_CHANGELOG"' "Treiber: Plesk-Admin alter Wert als nicht feststellbar"
# 1Password zuerst: jede Erzeugung steht vor dem ssh-Aufruf, der den Wert setzt
eq "$(grep -nE '^(create|ssh)' "$ST/reihenfolge" | awk -F: '/create/{c=$1} /ssh srv1 abo/{print (c && c<$1)?"ok":"falsch"; exit}')" ok "Treiber: 1Password vor dem Setzen"
dicht treiber "$W_ABO" "$W_PF" "$W_AL" "$W_BO" "$W_AD" "$ALTSMTP" "$PSAW"

# ── 8. Treiber: Setzen scheitert -> VERWORFEN; Postfach: neuer Wert scheitert -> alter zurück
aufbau; touch "$ST/plesk-lehnt-ab" "$ST/mail-setzt-nicht"
lauf mac-f nc-rotation-mac.sh --domain "$D" --abo "$U" --server srv1 --mailserver mail1 --postfach "postmaster@$D" --tresor T --tag t --teile abo,postfach --ausfuehren
eq "$RC" 4 "Treiber mit Fehlern: exit 4"
eq "$(cat "$ST"/op/*.titel 2>/dev/null | sort | tr '\n' '|')" "VERWORFEN $D Systembenutzer $U|VERWORFEN postmaster@$D Postfach|" "Treiber: gescheiterte Werte VERWORFEN"
eq "$(printf '%s' "$ALTSMTP" | sha)" "$(cat "$ST/postfach-pw")" "Postfach: alter Wert wieder aktiv"
eq "$(cfgwert mail_smtppassword)" "${ALTSMTP//\'/}" "Postfach gescheitert: config.php unberührt"
aufbau; touch "$ST/op-abgemeldet"
lauf mac-op nc-rotation-mac.sh --domain "$D" --abo "$U" --server srv1 --tresor T --tag t --teile abo --ausfuehren
[ "$RC" = 2 ] || cat "$TMP/out.mac-op"; eq "$RC" 2 "Treiber ohne 1Password-Anmeldung: exit 2"; eq "$(aendernd)" "" "ohne 1Password: nichts geändert"

# ── 9. Abschluss: cron, appupdate, quarantaene ──────────────────────────────
aufbau
lauf cron nc-abschluss.sh cron "${COMMON[@]}" --ausfuehren
eq "$RC" 0 "cron rc"
ja 'grep -q "^\*/5 \* \* \* \* root runuser -u $U -- .*/8.2/bin/php .*-f $W/cron.php" "$TMP/cron.d/nextcloud-$U"' "cron: Datei mit runuser"
ja 'grep -qx "$U" "$NC_CRON_DENY"' "cron: Abo bleibt in cron.deny"
aufbau; touch "$ST/cron-fehler"
lauf cron-f nc-abschluss.sh cron "${COMMON[@]}" --ausfuehren
eq "$RC" 3 "cron mit brechendem cron.php: exit 3"
touch "$ST/app-updates"
lauf app nc-abschluss.sh appupdate "${COMMON[@]}" --ausfuehren
eq "$RC" 0 "appupdate rc (behebt cron.php)"
ja 'ls "$TMP/arbeit/update-sicherung" | grep -q "apps.tgz$"' "appupdate: Sicherung apps"
aufbau; touch "$ST/app-updates" "$ST/appupdate-kaputt"; echo alt > "$W/apps/files/marke"
lauf app-f nc-abschluss.sh appupdate "${COMMON[@]}" --ausfuehren
eq "$RC" 4 "appupdate scheitert: Rückweg exit 4"
ja '[ -f "$W/apps/files/marke" ] && [ -d "$W/apps.fehlschlag-"* ] && [ -s "$ST/restores" ]' "appupdate: apps und DB zurück"
aufbau; mkdir -p "$TMP/q"; echo x > "$TMP/q/config.php.vor-rotation"; echo x > "$TMP/q/psa.shadow.vor-admin-1"; echo beweis > "$TMP/q/crontab.abo"
lauf q nc-abschluss.sh quarantaene "${COMMON[@]}" --ausfuehren
eq "$RC" 0 "quarantaene rc"
eq "$(ls "$TMP/q" | tr '\n' ' ')" "crontab.abo " "quarantaene: nur Geheimnis-Kopien gelöscht, Beweis bleibt"

# ── 10. 1Password-Sammel-Item ───────────────────────────────────────────────
opq(){ python3 -c 'import json,sys
json.dump({"title":sys.argv[2],"category":"LOGIN","urls":[{"href":"https://x.example.test"}],"fields":[
 {"id":"username","type":"STRING","purpose":"USERNAME","label":"username","value":sys.argv[2]},
 {"id":"password","type":"CONCEALED","purpose":"PASSWORD","label":"password","value":sys.argv[3]},
 {"id":"notesPlain","type":"STRING","purpose":"NOTES","label":"notesPlain","value":""}]},open(sys.argv[1],"w"))' "$ST/opq/$1.json" "$2" "$3"; }
aufbau; opq q1 "Nextcloud alice" SammelWertA0123456789abcdef; opq q2 "Postfach info" SammelWertB0123456789abcdef; opq q3 "Plesk srv admin" SammelWertC0123456789abcdef
lauf op-tr op-sammel-item.sh --tresor T --ausschluss '^Plesk' --erwartet 2
eq "$RC" 0 "Sammel-Item Trockenlauf rc"; eq "$(aendernd)" "" "Sammel-Item Trockenlauf legt nichts an"
lauf op-falsch op-sammel-item.sh --tresor T --ausschluss '^Plesk' --erwartet 3 --ausfuehren
eq "$RC" 4 "Sammel-Item: Anzahl ungleich exit 4"; eq "$(aendernd)" "" "Sammel-Item: bei falscher Anzahl nichts angelegt"
lauf op op-sammel-item.sh --tresor T --titel Übergabe --tag vorfall-test --ausschluss '^Plesk' --erwartet 2 --ausfuehren
eq "$RC" 0 "Sammel-Item rc"; [ "$RC" = 0 ] || tail -8 "$TMP/out.op"
ja 'grep -q "Gegenprobe bestanden" "$TMP/out.op"' "Sammel-Item: Fingerabdruck vorher = nachher"
eq "$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(len(d["sections"]), ",".join(d["tags"]))' "$ST/op/id0.json")" "2 sammel-item,vorfall-test" "Sammel-Item: zwei Abschnitte, Tags"
touch "$ST/op-verliert-feld"
lauf op-verl op-sammel-item.sh --tresor T --ausschluss '^Plesk' --ausfuehren
eq "$RC" 5 "Sammel-Item: Abweichung erkannt exit 5"
dicht sammel SammelWertA0123456789abcdef SammelWertB0123456789abcdef SammelWertC0123456789abcdef

echo "nextcloud_selbsttest: $PASS ok, $FAILS Fehler"
[ "$FAILS" = 0 ]
