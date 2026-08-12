#!/usr/bin/env python3
"""Entlastet Pfade, die gegen eine amtliche Pruefsumme bestaetigt sind.

    lib/pruefsummen_filter.py <datei-mit-pfaden>
    -> je Zeile:  WEG<TAB><pfad>   oder   BLEIBT<TAB><pfad>

Aus der Umgebung:
    PMF_WL         Datei: je Zeile eine bestaetigt unveraenderte Datei
                   (Plugins, aus wordpress.org-Pruefsummen)
    PMF_WL_KERN    Datei: je Zeile eine Installation, deren Kern
                   `wp core verify-checksums` bestanden hat
    PMF_AUSNAHMEN  mehrzeilig: Pfade, die trotz Kernfreigabe NICHT
                   entlastet werden (die Abweichungen selbst)

WARUM DAS EINE EIGENE DATEI IST

Bis v3.14 stand diese Entscheidung nur in Abschnitt 13c. Der Fehlalarm vom
12.08.2026 entstand genau daran: Abschnitt 7.3 meldete eine unveraenderte
Kern-Datei als Webshell, weil er dieselbe Entscheidung nicht treffen konnte.
Eine zweite Kopie waere die naechste Gelegenheit zum Auseinanderlaufen.

WAS DIESE ENTSCHEIDUNG NICHT IST

Keine Heuristik. Entlastet wird ausschliesslich, wofuer eine amtliche
Pruefsumme vorliegt — nie, weil eine Datei unauffaellig aussieht. Und nie
gegen eine Pruefung, die gar nicht gelaufen ist: die Listen entstehen nur bei
nachweislich durchgefuehrter Pruefung (rezept_kern), sonst bleiben sie leer,
und dann entlastet dieser Filter nichts.
"""
import os
import sys


def _zeilen(pfad):
    try:
        with open(pfad, encoding="utf-8", errors="replace") as fh:
            return {z.strip() for z in fh if z.strip()}
    except OSError:
        return set()


def freigabe_bauen(wl="", wl_kern="", ausnahmen=""):
    """Liefert eine Funktion pfad -> bool (True = entlastet)."""
    bestaetigt = _zeilen(wl)
    kerne = _zeilen(wl_kern)
    ausnahmen = {z.strip() for z in ausnahmen.splitlines() if z.strip()}

    # Der Kern ist als VERZEICHNIS bestaetigt, nicht Datei fuer Datei:
    # verify-checksums nennt ausschliesslich die Abweichungen. Alles unter
    # wp-admin/ und wp-includes/ einer geprueften Instanz, das nicht selbst
    # als Abweichung gemeldet wurde, ist damit bestaetigt.
    kern_praefixe = tuple(
        os.path.join(k, teil) + os.sep
        for k in kerne for teil in ("wp-admin", "wp-includes")
    )

    def freigegeben(pfad):
        if pfad in ausnahmen:
            return False
        if pfad in bestaetigt:
            return True
        return bool(kern_praefixe) and pfad.startswith(kern_praefixe)

    return freigegeben


def _selbsttest():
    import tempfile
    fehler = 0
    with tempfile.TemporaryDirectory() as t:
        wl = os.path.join(t, "wl");   open(wl, "w").write("/a/plugins/p/x.php\n")
        wk = os.path.join(t, "wk");   open(wk, "w").write("/a\n")
        frei = freigabe_bauen(wl, wk, "/a/wp-includes/boese.php")
        faelle = (
            ("/a/plugins/p/x.php",        True,  "bestaetigte Plugin-Datei"),
            ("/a/wp-includes/gut.php",    True,  "unter geprueftem Kern"),
            ("/a/wp-admin/gut.php",       True,  "wp-admin ebenso"),
            ("/a/wp-includes/boese.php",  False, "Abweichung trotz Kernfreigabe"),
            ("/a/wp-content/fremd.php",   False, "ausserhalb Kern und Liste"),
            ("/b/wp-includes/gut.php",    False, "andere Installation"),
            ("/a/wp-includesXY/gut.php",  False, "Praefix ohne Trenner zaehlt nicht"),
        )
        for pfad, soll, was in faelle:
            ist = frei(pfad)
            if ist != soll:
                print("FEHLER  %-28s = %s, erwartet %s (%s)" % (pfad, ist, soll, was))
                fehler += 1
        # Ohne Listen darf NICHTS entlastet werden. Sonst wuerde ein
        # Werkzeugausfall zur Freigabe des ganzen Baums.
        leer = freigabe_bauen("/nicht/vorhanden", "/nicht/vorhanden", "")
        for pfad in ("/a/wp-includes/gut.php", "/a/plugins/p/x.php"):
            if leer(pfad):
                print("FEHLER  ohne Listen wurde %s entlastet" % pfad)
                fehler += 1
    gesamt = len(faelle) + 2
    if fehler:
        print("Selbsttest: %d von %d Fällen fehlgeschlagen" % (fehler, gesamt))
        return 1
    print("Selbsttest: %d Fälle, alle bestanden" % gesamt)
    return 0


def main():
    if "--selbsttest" in sys.argv:
        return _selbsttest()
    if len(sys.argv) < 2:
        print("Aufruf: pruefsummen_filter.py <datei-mit-pfaden>", file=sys.stderr)
        return 2
    frei = freigabe_bauen(os.environ.get("PMF_WL", ""),
                          os.environ.get("PMF_WL_KERN", ""),
                          os.environ.get("PMF_AUSNAHMEN", ""))
    with open(sys.argv[1], encoding="utf-8", errors="replace") as fh:
        for zeile in fh.read().splitlines():
            pfad = zeile.strip()
            if not pfad:
                continue
            print("%s\t%s" % ("WEG" if frei(pfad) else "BLEIBT", pfad))
    return 0


if __name__ == "__main__":
    sys.exit(main())
