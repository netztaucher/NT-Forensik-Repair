#!/usr/bin/env bash
# ============================================================
# NT-Forensik — Gegentest des Versionsvergleichs
# ------------------------------------------------------------
# Vergleicht lib/wp_schwachstellen.py Zeichen fuer Zeichen mit der echten
# PHP-Funktion version_compare(). Laeuft auf der Entwicklungsmaschine, braucht
# php auf dem PATH und wird deshalb NICHT mit ausgeliefert.
#
#   werkzeuge/version_compare_gegentest.sh [anzahl]
#
# WOZU
#
# Der Abgleich installierter Plugin-Fassungen gegen Verwundbarkeitsbereiche
# steht und faellt mit der Ordnung der Versionen. Ist sie an einer Stelle
# falsch, meldet das Werkzeug entweder eine Luecke, die geschlossen ist, oder
# schweigt zu einer, die offen ist. Beides faellt im Betrieb nicht auf, weil
# das Ergebnis in beiden Faellen plausibel aussieht.
#
# Deshalb wird nicht gegen eine Erwartungstabelle geprueft, die jemand von Hand
# geschrieben hat, sondern gegen die Umsetzung, die WordPress selbst benutzt.
# Die Faelle entstehen aus einem festen Grundstock echter Plugin-Fassungen und
# aus zufaelligen Kombinationen der Bausteine, aus denen solche Fassungen
# gebaut sind.
# ============================================================
set -uo pipefail

HIER="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ANZAHL="${1:-4000}"

command -v php >/dev/null || { echo "php nicht gefunden — Gegentest nicht möglich"; exit 3; }

FAELLE=$(mktemp); trap 'rm -f "$FAELLE" "$FAELLE.php" "$FAELLE.py"' EXIT

# Fassungen erzeugen: fester Grundstock plus zufaellige Kombinationen.
# Der Zufall ist mit fester Saat gezogen, damit ein Fehlschlag reproduzierbar
# bleibt — ein Test, dessen Faelle sich bei jedem Lauf aendern, laesst sich
# nicht nachstellen.
python3 - "$ANZAHL" > "$FAELLE" <<'PY'
import random, sys
random.seed(20260807)
grund = ["1.0", "1.0.0", "0.9", "1.2.3.4", "5.3.3", "6.4.1", "22.6", "8.9.1",
         "1.0-beta", "1.0-alpha", "1.0-rc1", "1.0RC2", "1.0a1", "1.0b2",
         "1.0pl1", "1.0-dev", "2.0", "2.0.1", "10.0", "1.01", "1.10",
         "3.1.0.1", "0.0.1", "1", "1.0.0.0", "2026.01", "1.0+build3",
         "1.0_2", "v1.0", "1.0.x", "1.0-", "1..0", ".1", "1.0 "]
zahl = [str(n) for n in (0,1,2,3,9,10,11,99,100,2026)]
kennung = ["", "dev", "alpha", "a", "beta", "b", "RC", "rc", "pl", "p", "x", "final"]
trenn = [".", "-", "_", "+", ""]

def zufall():
    teile = [random.choice(zahl)]
    for _ in range(random.randint(0, 3)):
        teile.append(random.choice(trenn) + random.choice(zahl))
    k = random.choice(kennung)
    if k:
        teile.append(random.choice(trenn) + k)
        if random.random() < 0.6:
            teile.append(random.choice(["", "."]) + random.choice(zahl))
    return "".join(teile)

paare = set()
for a in grund:
    for b in grund:
        paare.add((a, b))
n = int(sys.argv[1])
while len(paare) < n:
    paare.add((zufall(), zufall()))
for a, b in sorted(paare):
    print("%s\t%s" % (a, b))
PY

echo "  Fälle: $(wc -l < "$FAELLE" | tr -d ' ')"

php -r '
$fh = fopen($argv[1], "r");
while (($z = fgets($fh)) !== false) {
    $z = rtrim($z, "\n");
    $t = explode("\t", $z);
    if (count($t) != 2) continue;
    echo version_compare($t[0], $t[1]), "\n";
}
' "$FAELLE" > "$FAELLE.php"

python3 - "$FAELLE" "${HIER}/lib" <<'PY' > "$FAELLE.py"
import sys
sys.path.insert(0, sys.argv[2])
from wp_schwachstellen import version_vergleich
for zeile in open(sys.argv[1], encoding="utf-8").read().split("\n"):
    if not zeile:
        continue
    t = zeile.split("\t")
    if len(t) != 2:
        continue
    print(version_vergleich(t[0], t[1]))
PY

if diff -q "$FAELLE.php" "$FAELLE.py" >/dev/null; then
    echo "  ✅ Kein Unterschied zu PHP version_compare()"
    exit 0
fi

echo "  ❌ Abweichungen:"
paste "$FAELLE" "$FAELLE.php" "$FAELLE.py" \
  | awk -F'\t' '$3 != $4 { printf "     %-22s %-22s php=%-3s py=%-3s\n", $1, $2, $3, $4 }' \
  | head -40
echo "     Abweichende Fälle gesamt: $(paste "$FAELLE.php" "$FAELLE.py" | awk -F'\t' '$1!=$2' | wc -l | tr -d ' ')"
exit 1
