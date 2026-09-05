#!/usr/bin/env bash
# ============================================================
# NT-Forensik — Selbsttest der Zerlegte-Funktionsnamen-Erkennung (7.16)
# ------------------------------------------------------------
#   werkzeuge/zerlegte_selbsttest.sh
#
# WOZU
#
# 7.16 findet Code, der Funktions-/Funktionsnamen aus gequoteten Stuecken
# zusammensetzt, um jeder Signatur ueber Funktionsnamen zu entgehen. Am
# 05.09.2026 (krusty) zerlegte die OVA-Kampagne in VERSCHIEDEN LANGE Brocken
# ('s'.'tr'.'_re'.'place'); die alte Regex verlangte drei Einzelzeichen am
# Stueck und fand nur 151 von 1.131 Shells.
#
# Geprueft wird in BEIDE Richtungen und mit den ECHTEN Faellen des Vorfalls:
# beide Zerlegungsarten muessen treffen, und die legitimen Dateien, die
# andere (Name-/Primitiv-)Filter faelschlich trafen, duerfen NICHT treffen —
# PEAR Text_Diff, Smarty function.eval.php, WPForms shell.php-Template.
#
# Laeuft ohne Netz und ohne WordPress: die Proben stehen inline.
# ============================================================
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
# Die Regex genauso beziehen, wie der Lauf sie benutzt.
_zq="[\"']"; RX="(${_zq}[A-Za-z0-9_]{1,8}${_zq}\\.){3,}"
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
fail=0

treffen() { grep -qE "$RX" "$1" 2>/dev/null; }
pruefe() {  # <datei> <soll: JA|NEIN> <beschreibung>
  local ist=NEIN; treffen "$1" && ist=JA
  if [[ "$ist" == "$2" ]]; then printf '  OK     %-46s -> %s\n' "$3" "$ist"
  else printf '  FEHLER %-46s -> %s (erwartet %s)\n' "$3" "$ist" "$2"; fail=1; fi
}

# ── POSITIV: beide Zerlegungsarten ──────────────────────────
printf '<?php $o="f"."o"."p"."e"."n"; $o($x);\n' > "$TMP/einzel.php"
printf "<?php \$x='s'.'tr'.'_re'.'place';\$y='gzuncom'.'press';eval(\$y(\$x('a','b','c')));\n" > "$TMP/varlaenge.php"
printf "<?php \$DesQW='base'.'64'.'_'.'decode';\$LNuWx='gzinflat'.'e';\n" > "$TMP/ova.php"
pruefe "$TMP/einzel.php"    JA "Einzelzeichen (alte Machart)"
pruefe "$TMP/varlaenge.php" JA "variabel lange Stuecke (OVA-Machart)"
pruefe "$TMP/ova.php"       JA "OVA base64/gzinflate-Kopf"

# ── NEGATIV: legitime Faelle, die andere Filter faelschlich trafen ──
cat > "$TMP/text_diff_shell.php" <<'PHP'
<?php
/** Class used internally by Diff to actually compute the diffs. */
class Text_Diff_Engine_shell {
    var $_diff_command = 'diff';
    function diff($from_lines, $to_lines) {
        $descriptorspec = array(1 => array('pipe', 'w'));
        $process = proc_open($this->_diff_command . ' ' . escapeshellarg($from), $descriptorspec, $pipes);
    }
}
PHP
cat > "$TMP/function.eval.php" <<'PHP'
<?php
/** Smarty plugin: {eval} */
function smarty_function_eval($params, &$smarty) {
    $smarty->_compile_source('evaluated template', $params['var'], $_var_compiled);
    ob_start();
    $smarty->_eval('?>' . $_var_compiled);
}
PHP
# legitime String-Verkettung aus WORTEN (nicht aus Fragmenten) darf nicht triggern
printf '<?php $msg = "Hallo " . $name . ", willkommen bei " . $seite . ".";\n' > "$TMP/legit_concat.php"
printf '<?php $sql = "SELECT * FROM " . $t . " WHERE id = " . intval($id);\n' > "$TMP/legit_sql.php"
pruefe "$TMP/text_diff_shell.php" NEIN "PEAR Text_Diff shell.php (proc_open/diff)"
pruefe "$TMP/function.eval.php"   NEIN "Smarty function.eval.php"
pruefe "$TMP/legit_concat.php"    NEIN "legitime Wort-Verkettung"
pruefe "$TMP/legit_sql.php"       NEIN "legitimer SQL-Aufbau"

[[ $fail -eq 0 ]] && echo "=> ALLE BESTANDEN" || echo "=> FEHLGESCHLAGEN"
exit $fail
