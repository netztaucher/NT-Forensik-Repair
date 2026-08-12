#!/usr/bin/env python3
"""NT-Forensik — Injektion in grosse Dateien erkennen, ohne Referenz.

    lib/injektion_pruefen.py <datei…>
    pfad<TAB>punkte<TAB>merkmal[,merkmal…]

Ausgegeben wird nur, was mindestens INJEKTION_PUNKTE_MIN erreicht.

WOZU
====

Abschnitt 7.3 trennt zweistufig nach DATEIGROESSE: Muster plus Datei unter
DROPPER_MAX_BYTES (3000) ist kritisch, alles darueber geht in die
Sichtungsstufe. Die Begruendung traegt — ein Dropper ist fast nur Obfuskation
und deshalb winzig, legitimes `eval` steckt eingebettet in grossen Dateien.

Sie ist nur blind fuer den umgekehrten Fall: eine INJEKTION IN EINE GROSSE,
LEGITIME DATEI. Eine kommerzielle Plugin-Datei hat 50-400 kB. Wird dort Code
eingeschleust, landet sie bestenfalls in der Sichtungsstufe — zusammen mit
jeder Krypto-Bibliothek und jeder Template-Engine des Servers. Ohne
Mustertreffer sagt das Werkzeug ueberhaupt nichts.

Genau diese Dateien lassen sich nicht gegen eine amtliche Pruefsumme haltern:
fuer kommerzielle Plugins veroeffentlicht niemand welche. Deshalb hier ein
Mass, das OHNE jede Referenz auskommt.

DIE IDEE
========

Nicht die Datei als Ganzes bewerten, sondern die VERTEILUNG darin. Ein
300-Byte-Fremdkoerper in 400 kB verschwindet in jedem Durchschnitt ueber die
ganze Datei — aber nicht in der laengsten Zeile, nicht in der Lage, und nicht
in der Dichte des Fensters, in dem er steht.

GRENZEN, DIE HIER HINGEHOEREN
=============================

Das Mass kann eine Datei BELASTEN, nie entlasten. Es ersetzt keine Pruefsumme.

Wer sauberen, umbrochenen Code mitten in eine grosse Datei schreibt, bleibt
unsichtbar. Das ist keine Schwaeche der Umsetzung, sondern die Grenze des
Verfahrens, und sie gehoert so in den Bericht.

Die Schwellen sind bis zu einer Messung an einem echten Server GERATEN. Der
aufrufende Abschnitt meldet deshalb `info` und keinen Befund — dieselbe
Zurueckhaltung wie beim EXTRA-Zweig der Plugin-Integritaet. Ein Filter ohne
Messung wird sonst die naechste Geraeuschquelle; genau so ist der fremde
Regelsatz mit 359 Treffern unbrauchbar geworden.
"""

import os
import re
import sys

# ── Schwellen ───────────────────────────────────────────────────────────────
# Ueberschreibbar aus der Umgebung, damit lib/konfig.sh sie fuehren kann und
# eine Messung sie ohne Codeaenderung verschieben darf.
def _zahl(name, vorgabe):
    try:
        return int(os.environ.get(name, "") or vorgabe)
    except ValueError:
        return vorgabe


# Ab welcher Groesse eine Datei ueberhaupt als "gross" gilt. Darunter greift
# bereits die Dropper-Regel aus 7.3, und ein zweites Mass waere Doppelarbeit.
GROSS_AB       = _zahl("INJEKTION_GROSS_AB", 3000)
# Laengste Zeile. Gepflegter PHP-Code bleibt weit darunter; eine Nutzlast ist
# regelmaessig EINE enorme Zeile.
ZEILE_MAX      = _zahl("INJEKTION_ZEILE_MAX", 2000)
# Rand der Datei in Prozent. Injektionen sitzen vorn oder hinten, legitimes
# `eval` steckt mitten in einer Klasse.
RANDLAGE_PCT   = _zahl("INJEKTION_RANDLAGE_PCT", 5)
# Ab wieviel Punkten eine Datei ueberhaupt genannt wird.
PUNKTE_MIN     = _zahl("INJEKTION_PUNKTE_MIN", 3)

# Ein Fenster, in dem die Dichte kodierter Zeichen gemessen wird. Ueber die
# ganze Datei gemittelt verschwindet jede kleine Nutzlast.
FENSTER = 512

# ── Merkmale ────────────────────────────────────────────────────────────────
# Kurze Kennungen, damit der Beleg lesbar bleibt und die Zuordnung im Bericht
# nicht verrutscht.

# `\xNN`, oktale Escapes, chr()-Ketten, lange Base64-Token.
KODIERT = re.compile(rb"\\x[0-9a-fA-F]{2}|\\[0-7]{3}|chr\s*\(\s*\d+\s*\)")
BASE64_LANG = re.compile(rb"[A-Za-z0-9+/]{120,}={0,2}")
PHP_AUF = re.compile(rb"<\?php\b")

# Minifiziertes JavaScript und eingebettete Datenblobs haben von Natur aus
# lange Zeilen und hohe Dichte. Sie hier auszunehmen ist kein Aufweichen der
# Erkennung — es ist die Voraussetzung dafuer, dass die uebrigen Treffer
# ueberhaupt gelesen werden.
UNVERDAECHTIG_PFAD = re.compile(
    r"\.min\.(js|css)$|/languages?/|/node_modules/|\.mo$|\.po$", re.I
)


def _lies(pfad):
    try:
        with open(pfad, "rb") as fh:
            return fh.read()
    except OSError:
        return None


def pruefen(pfad, roh):
    """Punkte und Merkmale fuer eine Datei. Nie ein Urteil, nur ein Mass."""
    punkte, merkmale = 0, []
    n = len(roh)

    # ── Angehaengter Code ────────────────────────────────────────────────
    # Der klassische Fall: die Nutzlast wird hinten drangehaengt, hinter dem
    # letzten schliessenden Tag der Originaldatei. Ein zweiter `<?php` nach
    # Code ist dasselbe Muster von vorn.
    letzter_zu = roh.rfind(b"?>")
    if letzter_zu != -1 and letzter_zu < n - 3:
        rest = roh[letzter_zu + 2:].strip()
        # Ein Zeilenumbruch nach `?>` ist normal. Code dahinter nicht.
        if len(rest) > 20 and PHP_AUF.search(rest):
            punkte += 3
            merkmale.append("ANHANG")
    # KEIN Merkmal fuer "mehr als ein <?php". Gemessen an einer
    # Template-Datei mit 401 Oeffnern: Themes und View-Dateien wechseln
    # staendig zwischen PHP und HTML, das ist ihre Bauform. Das Merkmal haette
    # auf jeder von ihnen Druck erzeugt und trug nichts, was DICHTE und
    # RANDLAGE nicht schon tragen — eine angehaengte Nutzlast ist nicht
    # dadurch auffaellig, DASS sie PHP oeffnet, sondern womit.

    # ── Laengste Zeile ───────────────────────────────────────────────────
    laengste = 0
    for zeile in roh.split(b"\n"):
        if len(zeile) > laengste:
            laengste = len(zeile)
    if laengste >= ZEILE_MAX:
        # Verhaeltnis zur Datei: eine 2000er Zeile in 4 kB ist etwas anderes
        # als dieselbe Zeile in 400 kB. Im zweiten Fall ist sie ein
        # Fremdkoerper zwischen umbrochenem Code.
        punkte += 3 if laengste * 20 < n else 2
        merkmale.append("LANGZEILE=%d" % laengste)

    # ── Dichte kodierter Zeichen im Fenster ──────────────────────────────
    # Nicht der Durchschnitt ueber die Datei, sondern das dichteste Fenster.
    dichte_max, pos_max = 0, 0
    for treffer in KODIERT.finditer(roh):
        anfang = max(0, treffer.start() - FENSTER // 2)
        fenster = roh[anfang:anfang + FENSTER]
        d = len(KODIERT.findall(fenster))
        if d > dichte_max:
            dichte_max, pos_max = d, treffer.start()
    if dichte_max >= 8:
        punkte += 2
        merkmale.append("DICHTE=%d" % dichte_max)

    b64 = BASE64_LANG.search(roh)
    if b64:
        punkte += 2
        merkmale.append("BASE64=%d" % (b64.end() - b64.start()))

    # ── Lage ─────────────────────────────────────────────────────────────
    # Nur sinnvoll, wenn ueberhaupt etwas gefunden wurde: die Lage allein
    # sagt nichts.
    if merkmale and n > 0:
        rand = max(1, n * RANDLAGE_PCT // 100)
        stelle = pos_max if dichte_max else (b64.start() if b64 else None)
        if stelle is not None and (stelle <= rand or stelle >= n - rand):
            punkte += 2
            merkmale.append("RANDLAGE")

    return punkte, merkmale


# ── Selbsttest ──────────────────────────────────────────────────────────────
# Die Faelle, an denen das Mass gebaut wurde. Sie stehen hier und nicht in
# einem Pruefstand daneben, weil sie das Verfahren SELBST beschreiben: was
# anschlagen muss und was schweigen muss. Ein Mass ohne den zweiten Teil ist
# wertlos — es waere durch "meldet immer" zu bestehen.
def _bau_gross(zusatz="", einschub=""):
    t = "<?php\n/*\nPlugin Name: Beispiel\n*/\nclass Beispiel {\n" + einschub
    for i in range(900):
        t += ("    public function methode_%d($wert) {\n"
              "        return trim($wert) . '_%d';\n    }\n" % (i, i))
    return (t + "}\n" + zusatz).encode()


def selbsttest():
    fehler = 0
    nutzlast = ("?>\n<?php $x='\\x65\\x76\\x61\\x6c';"
                + "".join("\\x%02x" % (65 + i % 26) for i in range(300))
                + " eval($_POST['c']); ?>\n")
    angehaengt = "?>\n<?php $c=$_COOKIE['x']; if($c){ @eval($c); }\n"
    # Eine Template-Datei, wie Themes sie bauen: staendiger Wechsel zwischen
    # PHP und HTML. Sie hat 401 Oeffner und muss trotzdem schweigen.
    tpl = "<?php\n/* Template */\n?>\n"
    for i in range(400):
        tpl += ("<div class='zeile-%d'>\n  <?php echo esc_html($werte[%d]); ?>\n"
                "</div>\n" % (i, i))

    faelle = (
        ("grosse Datei mit angehaengter Nutzlast", _bau_gross(nutzlast),      True),
        ("grosse Datei, Nutzlast ohne Schlusstag", _bau_gross(angehaengt),    True),
        ("grosse Datei, unauffaellig",             _bau_gross(),              False),
        ("legitimes eval mitten in der Datei",
         _bau_gross(einschub="    public function f(){ return eval('return 1;'); }\n"), False),
        ("Template mit 401 PHP-Oeffnern",          tpl.encode(),              False),
        ("kleine Datei — 7.3 ist zustaendig",      b"<?php eval($_POST['c']);", False),
    )
    for name, roh, soll in faelle:
        if len(roh) < GROSS_AB:
            ist = False
        else:
            punkte, _m = pruefen("pruefstand.php", roh)
            ist = punkte >= PUNKTE_MIN
        if ist != soll:
            print("FEHLER  %s: %s, erwartet %s"
                  % (name, "meldet" if ist else "schweigt",
                     "meldet" if soll else "schweigt"))
            fehler += 1

    # Pfade, die von Natur aus lange Zeilen und hohe Dichte tragen. Ohne diese
    # Ausnahme waere jede minifizierte Datei ein Treffer.
    for pfad in ("/x/app.min.js", "/x/languages/de_DE.mo", "/x/node_modules/a.php"):
        if not UNVERDAECHTIG_PFAD.search(pfad):
            print("FEHLER  %s wird nicht ausgenommen" % pfad)
            fehler += 1

    gesamt = len(faelle) + 3
    if fehler:
        print("Selbsttest: %d von %d Faellen fehlgeschlagen" % (fehler, gesamt))
        return 1
    print("Selbsttest: %d Faelle, alle bestanden" % gesamt)
    return 0


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--selbsttest":
        return selbsttest()
    if len(sys.argv) < 2:
        return 0
    for pfad in sys.argv[1:]:
        if UNVERDAECHTIG_PFAD.search(pfad):
            continue
        roh = _lies(pfad)
        if roh is None or len(roh) < GROSS_AB:
            continue
        punkte, merkmale = pruefen(pfad, roh)
        if punkte >= PUNKTE_MIN:
            print("%s\t%d\t%s" % (pfad, punkte, ",".join(merkmale)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
