#!/usr/bin/env bash
# =============================================================================
# nc-rotation-mac.sh — Treiber auf dem Arbeitsplatz: Werte erzeugen, ZUERST in 1Password, dann per stdin an den Server
# =============================================================================
# Test:     ja - werkzeuge/nextcloud/nextcloud_selbsttest.sh (Attrappen für ssh/scp/op, CI) · NT-Forensik-Repair#162
# Rueckweg: nein - Werte stehen in 1Password, Rückweg = erneut setzen; gescheiterte Einträge heissen "VERWORFEN …" (nur im Selbsttest gelaufen) · NT-Forensik-Repair#165
#
#   nc-rotation-mac.sh --server <ssh-ziel> --domain <domain> --abo <systembenutzer> [--ip <ip>]
#                      --tresor <1password-tresor> --tag <tag>
#                      [--mailserver <ssh-ziel> --postfach <adresse>]
#                      [--teile abo,postfach,nutzer,pleskadmin,mailapp] [--ausfuehren]
#
# Ablauf je Wert (Lex Clavis): auf diesem Rechner erzeugen -> als Login-Item in 1Password
# ablegen (op item create, JSON über stdin) -> per stdin über ssh an nc-rotation-server.sh
# -> dort setzen, prüfen, Kill-Proof. Scheitert das Setzen, bekommt der Eintrag das Präfix
# "VERWORFEN". Ein Wert steht nie in einem Argument und nie in einer Ausgabe.
#
#   abo         Systembenutzer des Plesk-Abos
#   postfach    SMTP-Postfach der Nextcloud auf --mailserver (alter Wert aus config.php per Pipe,
#               IMAP-Kill-Proof), danach mail_smtppassword in config.php
#   nutzer      alle Nextcloud-Konten (ein 1Password-Eintrag je Konto)
#   pleskadmin  Plesk-Administrator des Servers
#   mailapp     derselbe neue Postfach-Wert im Konto der Mail-App (nur zusammen mit postfach)
#
# Ohne --ausfuehren: Trockenlauf — prüft 1Password-Anmeldung und ssh, kopiert die
# Server-Skripte, zeigt die Konten. Erzeugt und setzt nichts.
# Die Server-Skripte liegen danach unter NC_REMOTE_DIR (Vorgabe /root/nc-ir-werkzeuge).
# =============================================================================
set -u
HIER="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=werkzeuge/nextcloud/lib.sh
. "$HIER/lib.sh"
RD=${NC_REMOTE_DIR:-/root/nc-ir-werkzeuge}

nc_args "$@"
SRV=""; MSRV=""; VAULT=""; TAG=""; POSTFACH=""; TEILE=abo,postfach,nutzer,pleskadmin,mailapp
set -- ${NC_REST[@]+"${NC_REST[@]}"}
while [ $# -gt 0 ]; do
  [ $# -ge 2 ] || nc_abbruch "Wert fehlt für $1"
  case "$1" in
    --server) SRV=$2;; --mailserver) MSRV=$2;; --tresor) VAULT=$2;; --tag) TAG=$2;;
    --postfach) POSTFACH=$2;; --teile) TEILE=$2;;
    *) nc_abbruch "unbekannter Schalter: $1";;
  esac; shift 2
done
nc_pruefe_namen
[ -n "$SRV" ] && [ -n "$VAULT" ] && [ -n "$TAG" ] || nc_abbruch "--server, --tresor und --tag sind Pflicht"
for x in "$SRV" "$MSRV"; do [ -z "$x" ] || printf '%s' "$x" | grep -Eq '^[A-Za-z0-9@._-]*$' || nc_abbruch "ssh-Ziel ungültig: $x"; done
teil(){ case ",$TEILE," in *",$1,"*) return 0;; esac; return 1; }
if teil postfach || teil mailapp; then
  [ -n "$MSRV" ] && [ -n "$POSTFACH" ] || nc_abbruch "postfach/mailapp brauchen --mailserver und --postfach"
  printf '%s' "$POSTFACH" | grep -Eq '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+$' || nc_abbruch "Postfach ungültig"
fi
LOS=""; [ "$NC_LOS" = 1 ] && LOS=--ausfuehren
ARGS="--domain $NC_D --abo $NC_U${NC_IP:+ --ip $NC_IP}"
srv(){ ssh "$SRV" "sudo -n bash $RD/nc-rotation-server.sh $1 $ARGS ${2:-}"; }
h(){ echo; echo "===== $(date -u +%T) $* ====="; }

# op_put TITEL BENUTZER URL NOTIZ  (Wert auf stdin) -> gibt nur die Item-ID aus
op_put(){
  python3 -c 'import json,sys
t,u,url,n,tag=sys.argv[1:6]; p=sys.stdin.read()
print(json.dumps({"title":t,"category":"LOGIN","tags":[tag],"urls":[{"href":url,"primary":True}],
 "fields":[{"id":"username","type":"STRING","purpose":"USERNAME","label":"username","value":u},
           {"id":"password","type":"CONCEALED","purpose":"PASSWORD","label":"password","value":p},
           {"id":"notesPlain","type":"STRING","purpose":"NOTES","label":"notesPlain","value":n}]}))' "$1" "$2" "$3" "$4" "$TAG" \
  | op item create --vault "$VAULT" --format json | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])'
}
verwerfen(){ op item edit "$1" --title "VERWORFEN $2" >/dev/null 2>&1; echo "  1Password $1 als VERWORFEN markiert"; FEHLER=1; }
FEHLER=0

h "0 Vorbedingungen ($([ "$NC_LOS" = 1 ] && echo AUSFUEHREN || echo TROCKENLAUF)) · Teile: $TEILE"
[ -z "${OP_SERVICE_ACCOUNT_TOKEN:-}" ] || echo "Hinweis: 1Password-Dienstkonto aktiv — Einträge landen nur in Tresoren, die es schreiben darf"
op whoami >/dev/null 2>&1 || nc_abbruch "1Password-CLI nicht angemeldet" 2
kopiere(){   # <ssh-ziel>
  local f; for f in lib.sh nc-rotation-server.sh; do
    scp -q "$HIER/$f" "$1:/tmp/nc-ir-$f" || return 1
  done
  ssh "$1" "sudo -n install -d -m 700 $RD && sudo -n install -m 700 /tmp/nc-ir-lib.sh $RD/lib.sh && sudo -n install -m 700 /tmp/nc-ir-nc-rotation-server.sh $RD/nc-rotation-server.sh && rm -f /tmp/nc-ir-lib.sh /tmp/nc-ir-nc-rotation-server.sh"
}
kopiere "$SRV" || nc_abbruch "Kopie nach $SRV" 2
if [ -n "$MSRV" ]; then kopiere "$MSRV" || nc_abbruch "Kopie nach $MSRV" 2; fi
L=$(srv liste </dev/null) || nc_abbruch "Kontenliste von $SRV" 2
echo "Nextcloud-Konten: $(printf '%s\n' "$L" | grep -c .) · Admins: $(printf '%s\n' "$L" | grep -c "$(printf '\t')admin\$")"
if [ "$NC_LOS" != 1 ]; then
  for t in abo nutzer pleskadmin; do teil $t && srv "$t" </dev/null; done
  teil postfach && ssh "$MSRV" "sudo -n bash $RD/nc-rotation-server.sh postfach --postfach $POSTFACH" </dev/null
  echo "TROCKENLAUF: nichts erzeugt, nichts gesetzt. Mit --ausfuehren starten."; exit 0
fi

if teil abo; then
  h "Systembenutzer $NC_U"
  N=$(nc_neuwert); id=$(printf '%s' "$N" | op_put "$NC_D Systembenutzer $NC_U" "$NC_U" "sftp://$SRV" "Plesk-Abo $NC_D, rotiert ($TAG)") || nc_abbruch "1Password" 3
  echo "  1Password $id · fp $(nc_fp "$N")"
  printf '%s\n' "$N" | srv abo "$LOS" || verwerfen "$id" "$NC_D Systembenutzer $NC_U"
fi

if teil postfach; then
  h "Postfach $POSTFACH ($MSRV) + config.php"
  A=$(srv smtpalt "$LOS" </dev/null); echo "  alter Wert gelesen: fp $(nc_fp "$A")"
  N=$(nc_neuwert); id=$(printf '%s' "$N" | op_put "$POSTFACH Postfach" "$POSTFACH" "imaps://$MSRV" "SMTP-Konto der Nextcloud $NC_D, rotiert ($TAG)") || nc_abbruch "1Password" 3
  echo "  1Password $id · fp $(nc_fp "$N")"
  if printf '%s\n%s\n' "$N" "$A" | ssh "$MSRV" "sudo -n bash $RD/nc-rotation-server.sh postfach --postfach $POSTFACH $LOS"; then
    printf '%s\n' "$N" | srv smtpcfg "$LOS" || { echo "  WARNUNG: Postfach neu, config.php nicht -> Mailversand der Nextcloud prüfen"; FEHLER=1; }
    if teil mailapp; then
      h "Mail-App-Konto $POSTFACH"
      printf '%s\n' "$N" | srv mailapp "--postfach $POSTFACH $LOS" || { echo "  WARNUNG: Mail-App-Konto nicht gesetzt"; FEHLER=1; }
    fi
  else verwerfen "$id" "$POSTFACH Postfach"; fi
  unset A
elif teil mailapp; then echo "mailapp übersprungen: nur zusammen mit postfach (derselbe neue Wert)"; fi

if teil nutzer; then
  h "Nextcloud-Konten"
  B=""
  while IFS=$'\t' read -r u r; do
    [ -n "$u" ] || continue
    N=$(nc_neuwert); id=$(printf '%s' "$N" | op_put "Nextcloud $NC_D $u" "$u" "https://$NC_D" "Rolle: $r. Rotiert ($TAG), an Nutzer weitergeben") \
      || { echo "  $u: 1Password FEHLER, übersprungen"; FEHLER=1; continue; }
    echo "  $u ($r): 1Password $id"; B+="$u"$'\t'"$N"$'\n'
  done <<< "$L"
  printf '%s' "$B" | srv nutzer "$LOS" || { echo "  WARNUNG: nicht alle Konten bestätigt — Ausgabe oben prüfen"; FEHLER=1; }
  unset B
fi

if teil pleskadmin; then
  h "Plesk-Administrator $SRV"
  N=$(nc_neuwert); id=$(printf '%s' "$N" | op_put "Plesk $SRV admin" admin "https://$SRV:8443" "Plesk-Administrator, rotiert ($TAG)") || nc_abbruch "1Password" 3
  echo "  1Password $id · fp $(nc_fp "$N")"
  printf '%s\n' "$N" | srv pleskadmin "$LOS" || verwerfen "$id" "Plesk $SRV admin"
fi
unset N
h "fertig — Belege: /root/changelog.md auf den Servern, 1Password Tag $TAG"
exit $((FEHLER * 4))
