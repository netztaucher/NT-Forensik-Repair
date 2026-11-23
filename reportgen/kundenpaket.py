#!/usr/bin/env python3
# kundenpaket.py - Kundenpaket im Berichtslayout NT Dokumente aus einem Forensik-Lauf
#
# Test:     ja - werkzeuge/kundenpaket-pruefstand.sh (Fixture: drei PDFs, Seiten, Interna, Entwurf-Sperre) · NT-Forensik-Repair#149, #160
# Rueckweg: entfaellt - schreibt nur neue Dateien in --ziel und --pruefung, aendert den Lauf nicht
#
# Aufruf:
#   kundenpaket.py --lauf <lauf-ordner> --ziel <ordner> [--fall fall.json]
#                  [--pruefung <ordner>] [--entwurf fall.entwurf.json]
#
# Erzeugt die drei Kundendokumente (Standard vom 21.10.2026, NT-Forensik-Repair#149,
# #150) im Berichtslayout des Designsystems NT Dokumente (Komponente Bericht),
# freigegeben am 23.11.2026:
#   NT-Sicherheitsbericht_<Kunde>_<Datum>.pdf          Briefkopf, Abschnitte 1-6, Anhang Technisches Protokoll
#   NT-Dokumentation_DSGVO-Art33_<Kunde>_<Datum>.pdf   2 Seiten, Art. 33 Abs. 3 a-d, Unterschrift
#   NT-Einordnung_BSI-Meldung_<Kunde>_<Datum>.pdf      2 Seiten, Einordnung, Angaben, IOC
#
# Inhalt in zwei Schichten:
#   1. aus dem Lauf (findings.json, kundenpaket_funde.tsv): Websites, Funde mit
#      Pfad im Kunden-Webspace und SHA-256, Angreifer-Adressen, Einstiegsweg,
#      Zeitachse. Nur was im Pruefumfang liegt; andere Kunden des Servers
#      kommen nicht vor.
#   2. aus der Fall-Datei (--fall): Kunde, Erzaehlung, Bereinigung, Aufgaben,
#      Meldepflicht. Jeder Schluessel ueberschreibt den Wert aus Schicht 1.
#      --entwurf schreibt die zusammengefuehrte Fassung als Vorlage dafuer.
#
# Rueckgabe: 0 = alle Dokumente regelgerecht und ohne Interna,
#            1 = Aufruf- oder Lauffehler, 2 = Satz- oder Regelfehler,
#            3 = Interna-Waechter schlaegt an,
#            4 = Entwurf: der Anhang (Protokoll) kommt ungeprueft aus dem Lauf, weil
#                die Fall-Datei weder bericht.protokoll liefert noch
#                bericht.protokoll_geprueft bestaetigt (ohne --fall immer).
#            Die PDFs liegen auch bei 2/3/4 vor, zur Ansicht, nicht zur Auslieferung;
#            werkzeuge/kundenpaket.sh nimmt Entwuerfe nicht ins Paket.

import argparse
import copy
import datetime as dt
import hashlib
import json
import pathlib
import posixpath
import re
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import bericht_satz as S  # noqa: E402

WAECHTER = HERE.parent / "werkzeuge" / "interna-waechter.sh"

ANSPRECHPARTNER = {"name": "Marco Neuber", "funktion": "Geschäftsführer", "firma": "die netztaucher GmbH",
                   "telefon": "+49 3331 252520", "email": "team@netztaucher.com"}

# Familien aus module/14_berichte/05_einordnung.sh, Erklaerung fuer Kunden
FAMILIE = {
    "Backdoor/Webshell": "Hintertür, über die ein Angreifer Befehle ausführen kann",
    "Getarnte Payload": "Schadcode, als Bild oder andere harmlose Datei getarnt",
    "Code-Injection": "fremder Code in einer echten Programmdatei",
    "Verändertes Plugin": "nachträglich eingebauter Code in einem Plugin",
    "Manipulierte .htaccess": "geänderte Zugriffsregeln zugunsten des Angreifers",
    "PHP im Upload-Verzeichnis": "ausführbarer Code im Ordner für hochgeladene Dateien",
    "Bekannte Schaddatei": "bekanntes Angriffswerkzeug (Dateimanager, Uploader)",
    "Tarnstruktur": "angelegte Ordner, die echte nachahmen",
    "SEO-Spam/Doorway": "Spam-Seiten für Suchmaschinen unter Ihrer Adresse",
    "Kernfremde Datei": "Datei im Programmkern, die dort nicht hingehört",
    "Immer aktives mu-Plugin": "Zusatz, der bei jedem Aufruf läuft, ohne in der Liste zu stehen",
    "Joomla-Webshell": "Hintertür in Joomla",
    "Phishing": "gefälschte Anmelde- oder Bezahlseite",
    "Spam-Mailer": "Programm zum Versand von Spam",
    "Redirect/Malvertising": "Umleitung Ihrer Besucher auf fremde Seiten",
}
# Pfadlisten in findings.json -> Familie (falls kundenpaket_funde.tsv fehlt)
LISTE_FAMILIE = [
    ("webshell_dropper", "Backdoor/Webshell"), ("disguised_payloads", "Getarnte Payload"),
    ("injected_core", "Code-Injection"), ("core_include_injection", "Code-Injection"),
    ("signatur_treffer", "Bekannte Schaddatei"), ("plugin_veraendert", "Verändertes Plugin"),
    ("php_in_uploads", "PHP im Upload-Verzeichnis"), ("zerlegte_funktionsnamen", "Tarnstruktur"),
    ("htaccess_fremd", "Manipulierte .htaccess"), ("doorway_dirs", "SEO-Spam/Doorway"),
    ("wp_autologin_plugins", "Backdoor/Webshell"), ("nextcloud_malware", "Backdoor/Webshell"),
    ("joomla_malware", "Joomla-Webshell"),
]


class Lauffehler(Exception):
    pass


# ── Lauf lesen ──────────────────────────────────────────────────────────────
def lauf_lesen(lauf):
    lauf = pathlib.Path(lauf)
    fj = lauf / "betreiber" / "findings.json"
    if not fj.is_file():
        raise Lauffehler(f"findings.json fehlt: {fj}")
    d = json.loads(fj.read_text(encoding="utf-8"))
    r = d.get("run") or {}
    if r.get("scope_mode") == "global":
        raise Lauffehler("Betreiberlauf über alle vhosts (scope_mode=global): kein einzelner Kunde, kein Kundenpaket.")
    scan = [pathlib.Path(p) for p in (r.get("scan_paths") or [])]
    if not scan:
        raise Lauffehler("findings.json nennt keinen Prüfumfang (run.scan_paths).")
    vhosts = {p.name for p in scan}
    basis = {p.name: p for p in scan}

    def im_webspace(pfad):
        """(website, pfad im Webspace, absoluter Pfad) oder None, wenn ausserhalb des Umfangs."""
        p = str(pfad)
        if p.startswith("/"):
            # Doppelte Schraegstriche (TMPDIR endet auf / , Basis + / + Pfad) normalisieren,
            # sonst passt der Pfad nicht zum Pruefumfang, den pathlib schon bereinigt hat.
            p = posixpath.normpath(p)
            for sp in scan:
                s = str(sp).rstrip("/") + "/"
                if p.startswith(s):
                    return sp.name, _webspace(p[len(s):]), pathlib.Path(p)
            return None
        teile = p.split("/", 1)
        if len(teile) == 2 and teile[0] in vhosts:
            return teile[0], _webspace(teile[1]), basis[teile[0]] / teile[1]
        return None

    funde, gesehen = [], set()
    tsv = lauf / "betreiber" / "kundenpaket_funde.tsv"
    if tsv.is_file():
        tsv_basis = ""
        for zeile in tsv.read_text(encoding="utf-8").splitlines():
            f = zeile.split("\t")
            if f[0] == "#basis":
                tsv_basis = f[1].rstrip("/") if len(f) > 1 else ""
                continue
            if len(f) < 2 or not f[1]:
                continue
            pfad = f[1] if f[1].startswith("/") or not tsv_basis else f"{tsv_basis}/{f[1]}"
            w = im_webspace(pfad)
            if w and w[1] not in gesehen:
                gesehen.add(w[1])
                funde.append({"familie": f[0], "website": w[0], "pfad": w[1], "abs": w[2]})
    else:
        a = d.get("actionable") or {}
        for key, fam in LISTE_FAMILIE:
            for p in a.get(key) or []:
                if not isinstance(p, str):
                    continue
                w = im_webspace(p)
                if w and w[1] not in gesehen:
                    gesehen.add(w[1])
                    funde.append({"familie": fam, "website": w[0], "pfad": w[1], "abs": w[2]})
    for f in funde:
        f["sha256"] = _sha256(f.pop("abs"))

    u = d.get("ursache") or {}
    zeitachse = []
    for z in u.get("zeitachse") or []:
        w = im_webspace(z.get("pfad", ""))
        if w and z.get("ctime"):
            zeitachse.append({"zeit": int(z["ctime"]), "pfad": w[1], "website": w[0]})
    einstieg = []
    for e in u.get("einstiegsweg") or []:
        w = im_webspace(e.get("datei", "")) if e.get("datei") else None
        if e.get("datei") and not w:
            continue  # Einstieg in fremdem Webspace: gehoert nicht in dieses Paket
        einstieg.append({"kanal": e.get("kanal", ""), "zeit": e.get("zeit", ""), "ip": e.get("ip", ""),
                         "datei": w[1] if w else ""})
    a = d.get("actionable") or {}
    m = d.get("metrics") or {}
    websites = [d["domain"]] if d.get("domain") else sorted(vhosts)
    return {
        "websites": websites,
        "erzeugt": d.get("generated_utc", ""),
        "funde": funde,
        "familien": _familien(funde),
        "angreifer_ips": list((a.get("ioc_ips") or {}).get("attacker") or []),
        "einstieg": einstieg,
        "zeitachse": zeitachse,
        "fremde_admins": len(a.get("rogue_wp_admins") or []),
        "wp_installationen": int(m.get("wp_installs") or 0),
        "ohne_ergebnis": len(r.get("nicht_messbar") or []),
        "lauf_vollstaendig": bool(r.get("vollstaendig")),
    }


def _webspace(rel):
    """Pfad ab Dokumentenwurzel: httpdocs/ faellt weg, alles andere bleibt."""
    return rel[len("httpdocs/"):] if rel.startswith("httpdocs/") else rel


def _sha256(p):
    try:
        if p.is_file() and p.stat().st_size < 64 * 1024 * 1024:
            h = hashlib.sha256()
            with open(p, "rb") as f:
                for b in iter(lambda: f.read(1 << 20), b""):
                    h.update(b)
            return h.hexdigest()
    except OSError:
        pass
    return ""


def _familien(funde):
    n = {}
    for f in funde:
        n[f["familie"]] = n.get(f["familie"], 0) + 1
    return sorted(n.items(), key=lambda x: (-x[1], x[0]))


# ── Zeit und Sprache ────────────────────────────────────────────────────────
def _lokal(ts):
    if isinstance(ts, (int, float)):
        return dt.datetime.fromtimestamp(ts)
    try:
        return dt.datetime.fromisoformat(str(ts).replace("Z", "+00:00")).astimezone().replace(tzinfo=None)
    except ValueError:
        return dt.datetime.now()


def _datum(x):
    return x.strftime("%d.%m.%Y")


def _uhr(x):
    return x.strftime("%d.%m.%Y, %H:%M Uhr")


def _aufzaehlen(namen):
    namen = list(namen)
    if len(namen) <= 1:
        return "".join(namen)
    return ", ".join(namen[:-1]) + " und " + namen[-1]


def _anzahl(n, ein, mehr):
    return f"{n} {ein if n == 1 else mehr}"


def _ascii(s):
    s = s.replace("ä", "ae").replace("ö", "oe").replace("ü", "ue").replace("Ä", "Ae") \
         .replace("Ö", "Oe").replace("Ü", "Ue").replace("ß", "ss")
    return re.sub(r"[^A-Za-z0-9._-]+", "-", s).strip("-")


def _kurz_hash(h):
    return f"{h[:16]}…{h[-16:]}" if len(h) == 64 else h


# ── Fall: Vorgaben aus dem Lauf ─────────────────────────────────────────────
def fall_aus_lauf(L, bereinigt=False):
    jetzt = _lokal(L["erzeugt"]) if L["erzeugt"] else dt.datetime.now()
    seiten = L["websites"]
    mehrere = len(seiten) > 1
    n = len(L["funde"])
    die_seite = "Die Websites" if mehrere else "Die Website"
    top = L["familien"][0][0] if L["familien"] else ""
    frist = jetzt + dt.timedelta(hours=72)

    if n and not bereinigt:
        titel = ("Schadcode", "gefunden", ".")
        lede = (f"Untersuchung von {_aufzaehlen(seiten)} am {_datum(jetzt)}. "
                f"{_anzahl(n, 'Fund', 'Funde')} im Webspace, die Bereinigung steht aus.")
    elif n:
        titel = (f"{die_seite} {'sind' if mehrere else 'ist'}", "sauber", ".")
        lede = f"Schadcode auf {_aufzaehlen(seiten)} gefunden und entfernt. Stand {_datum(jetzt)}."
    else:
        titel = ("Kein Schadcode", "gefunden", ".")
        lede = f"Untersuchung von {_aufzaehlen(seiten)} am {_datum(jetzt)}."

    einst = L["einstieg"]
    status = [
        ({"art": "ok", "titel": "bereinigt", "text": "kein Schadcode mehr gefunden",
          "regel": f"{_anzahl(n, 'Fund', 'Funde')} in Quarantäne"} if bereinigt else
         {"art": "warn" if n else "ok", "titel": _anzahl(n, "Fund", "Funde") if n else "kein Fund",
          "text": "Schadcode im Webspace, Bereinigung steht aus" if n else "kein Schadcode im Webspace",
          "regel": top}),
        ({"art": "warn", "titel": "Einfallstor belegt", "text": f"{einst[0]['kanal']} am {einst[0]['zeit']}",
          "regel": einst[0]["ip"]} if einst else
         {"art": "info", "titel": "Einfallstor offen", "text": "aus den vorhandenen Protokollen nicht belegt",
          "regel": ""}),
        ({"art": "ok", "titel": "Zugänge erneuert", "text": "Passwörter von WordPress, Datenbank und FTP",
          "regel": "altes Passwort abgewiesen"} if bereinigt else
         {"art": "warn", "titel": "Zugänge erneuern", "text": "Passwörter von WordPress, Datenbank und FTP",
          "regel": "heute"}),
    ]
    wichtigste = []
    for fam, k in L["familien"][:3]:
        wichtigste.append({"art": "warn", "titel": f"{fam} ({k})", "text": FAMILIE.get(fam, "Einordnung im Anhang") + "."})
    if L["fremde_admins"]:
        wichtigste.append({"art": "warn", "titel": "Fremdes Administratorkonto",
                           "text": f"{_anzahl(L['fremde_admins'], 'Konto', 'Konten')} ohne erkennbaren Inhaber."})
    if L["ohne_ergebnis"]:
        wichtigste.append({"art": "warn", "titel": "Nicht alles prüfbar",
                           "text": f"{_anzahl(L['ohne_ergebnis'], 'Prüfung', 'Prüfungen')} ohne Ergebnis. Das ist keine Entwarnung."})
    if not wichtigste:
        wichtigste.append({"art": "ok", "titel": "Kein Schadcode", "text": "Im Webspace wurde kein Schadcode gefunden."})
    wichtigste = wichtigste[:4]

    ablauf = []
    if L["zeitachse"]:
        z0, z1 = L["zeitachse"][0], L["zeitachse"][-1]
        ablauf.append([_uhr(_lokal(z0["zeit"])), f"Älteste belastete Datei angelegt: `{z0['pfad']}`."])
        for e in einst[:4]:
            ablauf.append([str(e["zeit"]), f"Zugriff über {e['kanal']} von `{e['ip']}`."])
        if z1 is not z0:
            ablauf.append([_uhr(_lokal(z1["zeit"])), f"Jüngste belastete Datei angelegt: `{z1['pfad']}`."])
    ablauf.append([_datum(jetzt), "Untersuchung der Website durch die netztaucher GmbH, Belege mit Prüfsummen gesichert."])

    erledigt = [{"titel": "Untersuchung", "text": "Webspace vollständig untersucht, nur lesend, nichts verändert."},
                {"titel": "Belege gesichert", "text": "Jeder Fund ist mit Pfad und Prüfsumme festgehalten."}]
    aufgaben = [
        {"frist": "sofort", "art": "warn", "text": "**Passwörter Ihrer WordPress-Konten ändern.** Dasselbe Passwort überall sonst ändern, wo Sie es nutzen."},
        {"frist": "sofort", "art": "warn", "text": "**Nichts löschen**, bevor die Bereinigung abgeschlossen ist. Sonst gehen Spuren verloren."},
        {"frist": "diese Woche", "art": "info", "text": "Plugins und Themes auf den neuesten Stand bringen, nicht genutzte entfernen."},
    ]
    dsgvo_pflicht = bool(n)
    meldung_text = ("Eine Verletzung des Schutzes personenbezogener Daten ist nicht auszuschliessen. "
                    "Die Entscheidung liegt bei Ihnen als Verantwortlichem. Wir sind keine Rechtsberatung.")
    return {
        "kunde": {"name": seiten[0], "kurz": seiten[0].split(".")[0], "zeilen": seiten, "rolle": "Betreiber der Website"},
        "ansprechpartner": dict(ANSPRECHPARTNER),
        "websites": seiten,
        "datum": _datum(jetzt),
        "stand": _uhr(jetzt),
        "kenntnis": _uhr(jetzt),
        "frist_72h": frist.strftime("%d.%m.%Y, %H:%M Uhr"),
        "bereinigt": bereinigt,
        "bericht": {
            "meta": ["Sicherheitsvorfall", f"Stand {_uhr(jetzt)}"],
            "kicker": "Sicherheitsvorfall · Untersuchungsbericht",
            "titel": list(titel),
            "lede": lede,
            "status": status,
            "wichtigste": wichtigste,
            "jetzt": "**Heute** die Passwörter Ihrer WordPress-Konten ändern und nichts löschen, bevor die Bereinigung abgeschlossen ist.",
            "kurz": {"absaetze": [lede] + _kurz_funde(L), "hinweis": None},
            "bewertung": _bewertung(L, bereinigt),
            "bewertung_text": "",
            "ablauf": ablauf,
            "erledigt": erledigt,
            "aufgaben": aufgaben,
            "aufgaben_hinweis": "Neue Passwörter schicken wir nicht per E-Mail.",
            "meldepflichten": {
                "einschaetzung": ("**Meldung an die Datenschutzaufsicht prüfen.** " if dsgvo_pflicht else
                                  "**Keine Meldung an die Datenschutzaufsicht nötig, aber dokumentieren.** ") + meldung_text,
                "punkte": [
                    {"art": "warn" if dsgvo_pflicht else "ok", "titel": "Frist nach Art. 33 DSGVO",
                     "text": f"72 Stunden ab Kenntnis, also bis **{frist.strftime('%d.%m.%Y, %H:%M Uhr')}**. Einzelheiten in der beiliegenden Dokumentation."},
                    {"art": "warn", "titel": "Pflicht bleibt die Dokumentation",
                     "text": "Art. 33 Abs. 5 DSGVO: Bitte legen Sie die Dokumentation unterschrieben zu Ihren Datenschutzunterlagen."},
                    {"art": "ok", "titel": "BSI", "text": "Einordnung in der beiliegenden Einordnung zur BSI-Meldung."},
                ],
            },
            "protokoll": _protokoll(L, jetzt, bereinigt),
        },
        "dsgvo": {
            "titel": ["Meldung", "nötig", "."] if dsgvo_pflicht else ["Keine", "Meldung", " nötig."],
            "kicker": "Dokumentation nach Art. 33 Abs. 5 DSGVO",
            "lede": f"Vorfall auf {_aufzaehlen(seiten)}. " + ("Ein Abruf personenbezogener Daten ist nicht ausgeschlossen." if dsgvo_pflicht else "Personenbezogene Daten wurden nach allen Belegen nicht abgerufen."),
            "status": [
                {"art": "warn" if n else "ok", "titel": _anzahl(n, "Fund", "Funde") if n else "kein Fund", "text": "Schadcode im Webspace", "regel": top},
                {"art": "info", "titel": _anzahl(L["wp_installationen"], "Installation", "Installationen"), "text": "mit personenbezogenen Daten möglich", "regel": "Datenbestand zählen"},
                {"art": "warn" if dsgvo_pflicht else "ok", "titel": "Risiko offen" if dsgvo_pflicht else "kein Risiko", "text": "für Personen" + ("" if dsgvo_pflicht else ", voraussichtlich"), "regel": "Art. 33 Abs. 1"},
            ],
            "pruefliste": [
                {"art": "warn" if n else "ok", "titel": "Schadcode im Webspace", "text": f"{_anzahl(n, 'Fund', 'Funde')}, Einzelheiten im Sicherheitsbericht."},
                {"art": "warn", "titel": "Abruf von Daten", "text": "Aus den vorhandenen Protokollen weder belegt noch ausgeschlossen."},
                {"art": "warn", "titel": "Datenbestand der Website", "text": "Benutzerkonten, Kommentare mit E-Mail, Formular-, Newsletter- und Bestelldaten zählen."},
            ],
            "einordnung": (f"Voraussichtlich **ein Risiko** für Personen, damit Meldung an die Aufsicht bis **{frist.strftime('%d.%m.%Y, %H:%M Uhr')}**. " if dsgvo_pflicht else
                           f"Voraussichtlich **kein Risiko** für Personen, damit keine Meldung an die Aufsicht. Wer trotzdem meldet: Frist bis **{frist.strftime('%d.%m.%Y, %H:%M Uhr')}**. ")
                          + "Die Einschätzung beruht auf der technischen Untersuchung und ist keine Rechtsberatung, die Entscheidung trifft der Verantwortliche.",
            "art": f"Integrität: {_anzahl(n, 'Datei', 'Dateien')} mit Schadcode im Webspace. Vertraulichkeit: nicht belegt, nicht ausgeschlossen. Kenntnis {_uhr(jetzt)}.",
            "personen": {"kopf": ["Website", "Personen", "Daten"], "zeilen": [[w, "noch zu zählen", "Benutzerkonten, Kommentare, Formulardaten"] for w in seiten]},
            "personen_text": "Besondere Kategorien nach Art. 9 DSGVO sind nach der Untersuchung nicht berührt.",
            "massnahmen": "Untersuchung mit gesicherten Belegen. Bereinigung, Erneuerung aller Zugänge und erneute Prüfung folgen.",
            "abwaegung": [
                ["Meldung an die Aufsichtsbehörde (Art. 33 Abs. 1)", "warn" if dsgvo_pflicht else "ok", "erforderlich" if dsgvo_pflicht else "nicht erforderlich"],
                ["Benachrichtigung der Betroffenen (Art. 34)", "info", "nach Datenbestand prüfen"],
                ["Dokumentation (Art. 33 Abs. 5)", "ok", "mit diesem Dokument"],
            ],
        },
        "bsi": {
            "titel": ["Meldepflicht", "prüfen", "."],
            "kicker": "Meldepflicht nach BSIG und NIS2",
            "lede": f"Einordnung für {_aufzaehlen(seiten)}: kritische Infrastruktur, NIS2 und freiwillige Meldung.",
            "status": [
                {"art": "ok", "titel": "kein KRITIS", "text": "keine kritische Infrastruktur betroffen", "regel": "BSI-KritisV"},
                {"art": "info", "titel": "NIS2 prüfen", "text": "Schwellenwerte des Betreibers prüfen", "regel": "ab 50 MA oder 10 Mio. €"},
                {"art": "info", "titel": "freiwillig", "text": "Meldung beim BSI jederzeit möglich", "regel": "Allianz für Cybersicherheit"},
            ],
            "gruende": [
                {"art": "ok", "titel": "Pflicht nach § 32 BSIG", "text": "Gilt für besonders wichtige und wichtige Einrichtungen in den Sektoren der Anlagen 1 und 2 BSIG."},
                {"art": "warn", "titel": "Grösse", "text": "Erfasst sind seit 06.12.2025 Unternehmen ab 50 Beschäftigten oder mehr als 10 Mio. € Umsatz und Bilanzsumme in diesen Sektoren."},
                {"art": "ok", "titel": "Hosting", "text": "Die Server betreibt die netztaucher GmbH. Der Befund betrifft den Webspace der Website."},
            ],
            "hinweis": "Meldeweg: Eine freiwillige Meldung nimmt das BSI über die Allianz für Cybersicherheit an. Eine Strafanzeige ist bei der Zentralen Ansprechstelle Cybercrime (ZAC) der Landespolizei möglich. Stand der Rechtslage: Oktober 2026.",
            "angaben": [
                ["Art", "Kompromittierung des Webspace einer Website" if n else "Prüfung ohne Schadcode-Fund"],
                ["Erster Nachweis", _uhr(_lokal(L["zeitachse"][0]["zeit"])) if L["zeitachse"] else "nicht bestimmbar"],
                ["Festgestellt", _uhr(jetzt)],
                ["Beendet", "bereinigt und geprüft" if bereinigt else "Bereinigung steht aus"],
            ],
            "merkmale": _merkmale(L),
            "auswirkung": [
                ["Integrität", "warn" if n else "ok", _anzahl(n, "Datei", "Dateien") + " verändert" if n else "keine Veränderung"],
                ["Vertraulichkeit", "info", "kein Abfluss belegt"],
                ["Ausbreitung auf den Server", "info", "nicht Teil dieser Einordnung"],
            ],
            "massnahmen": "Untersuchung mit gesicherten Belegen. Bereinigung, Erneuerung aller Zugänge und erneute Prüfung." if not bereinigt else "Schadcode in Quarantäne, alle Zugänge erneuert, erneut geprüft.",
        },
        "mail": {},
    }


def _kurz_funde(L):
    """Zusammenfassung ohne Fall-Datei: die haeufigsten Fundarten in einem Satz."""
    if not L["familien"]:
        return []
    teile = [f"{fam} ({k}): {FAMILIE.get(fam, 'Einordnung im Anhang')}" for fam, k in L["familien"][:3]]
    s = "Gefunden: " + "; ".join(teile) + "."
    if L["ohne_ergebnis"]:
        s += f" {_anzahl(L['ohne_ergebnis'], 'Prüfung', 'Prüfungen')} ohne Ergebnis, das ist keine Entwarnung."
    return [s]


def _bewertung(L, bereinigt):
    seiten = L["websites"]
    zeilen = []
    zeilen.append(["Einstufung"] + [{"art": "warn", "text": "kompromittiert", "nach": " jetzt bereinigt" if bereinigt else ""}
                                     if any(f["website"] == w or len(seiten) == 1 for f in L["funde"]) else {"art": "ok", "text": "unauffällig"}
                                     for w in seiten])
    zeilen.append(["Schadcode"] + [_anzahl(sum(1 for f in L["funde"] if f["website"] == w or len(seiten) == 1), "Fund", "Funde") for w in seiten])
    zeilen.append(["Einfallstor"] + [L["einstieg"][0]["kanal"] if L["einstieg"] else "aus dem Lauf nicht ermittelt" for _ in seiten])
    zeilen.append(["fremdes Admin-Konto"] + [{"art": "warn", "text": "ja"} if L["fremde_admins"] else {"art": "ok", "text": "nein"} for _ in seiten])
    zeilen.append(["Datenabfluss"] + ["nicht belegt, nicht ausgeschlossen" for _ in seiten])
    return {"spalten": seiten, "zeilen": zeilen}


def _merkmale(L):
    z = [["Angreifer-Adresse", f"`{ip}`"] for ip in L["angreifer_ips"][:4]]
    for e in L["einstieg"][:2]:
        z.append(["Einstieg", f"{e['kanal']}, `{e['datei']}`" if e["datei"] else e["kanal"]])
    for f in [f for f in L["funde"] if f["sha256"]][:5]:
        z.append([f"SHA-256 {pathlib.PurePosixPath(f['pfad']).name}", f"`{_kurz_hash(f['sha256'])}`"])
    if not z:
        z.append(["Merkmale", "keine Angreifer-Merkmale erhoben"])
    return z


def _protokoll(L, jetzt, bereinigt):
    n = len(L["funde"])
    abschnitte = [{
        "titel": "Umfang",
        "meta": [["Websites", _aufzaehlen(L["websites"])],
                 ["Untersucht", _uhr(jetzt)],
                 ["Umfang", "Webspace der Website, Dateien und Konfiguration, nur lesend"],
                 ["Ohne Ergebnis", _anzahl(L["ohne_ergebnis"], "Prüfung", "Prüfungen") if L["ohne_ergebnis"] else "keine"]],
    }]
    if n:
        abschnitte.append({
            "titel": "Schadcode",
            "absaetze": [f"{_anzahl(n, 'Fund', 'Funde')} im Webspace. Pfade ab der Dokumentenwurzel der Website, Prüfsumme SHA-256."],
            "tabelle": {"kopf": ["Datei", "Art"],
                        "zeilen": [[f"`{f['pfad']}`" + (f"\n`{f['sha256']}`" if f["sha256"] else ""), f["familie"]] for f in L["funde"]]},
        })
    if L["einstieg"]:
        abschnitte.append({"titel": "Einfallstor",
                           "tabelle": {"kopf": ["Zeit", "Weg", "Adresse", "Datei"], "erste_fest": True,
                                       "zeilen": [[e["zeit"], e["kanal"], f"`{e['ip']}`", f"`{e['datei']}`" if e["datei"] else ""] for e in L["einstieg"]]}})
    else:
        abschnitte.append({"titel": "Einfallstor",
                           "absaetze": ["Aus dem Lauf nicht ermittelt: kein Zugriff mit Fernwartungs-, Upload- oder Installationskennung in derselben Sekunde wie die Anlage einer belasteten Datei. Andere Wege sind damit nicht ausgeschlossen."]})
    if L["zeitachse"]:
        abschnitte.append({"titel": "Zeitachse",
                           "absaetze": ["Anlagezeit der belasteten Dateien laut Dateisystem."],
                           "tabelle": {"kopf": ["Zeit", "Datei"], "erste_fest": True,
                                       "zeilen": [[_uhr(_lokal(z["zeit"])), f"`{z['pfad']}`"] for z in L["zeitachse"][:40]]}})
    if L["angreifer_ips"]:
        abschnitte.append({"titel": "Angreifer-Adressen",
                           "tabelle": {"kopf": ["Adresse", "Herkunft"],
                                       "zeilen": [[f"`{ip}`", "Zugriffsprotokoll der Website"] for ip in L["angreifer_ips"]]}})
    abschnitte.append({"titel": "Bereinigung",
                       "absaetze": ["Schadcode in Quarantäne verschoben, nichts gelöscht, erneut geprüft."] if bereinigt else
                                   ["Steht aus. Die Funde sind erhoben, aber noch nicht entfernt."]})
    offen = []
    if not bereinigt and n:
        offen.append(["Bereinigung und erneute Prüfung", "netztaucher"])
    if not bereinigt:
        offen.append(["Zugänge erneuern (WordPress, Datenbank, FTP)", "netztaucher und Sie"])
    if L["ohne_ergebnis"]:
        offen.append([f"{_anzahl(L['ohne_ergebnis'], 'Prüfung', 'Prüfungen')} ohne Ergebnis nachholen", "netztaucher"])
    abschnitte.append({"titel": "Offene Punkte", "tabelle": {"kopf": ["Punkt", "Wer"], "zeilen": offen}})
    kacheln = [
        {"label": "Websites", "wert": str(len(L["websites"])), "text": "untersucht", "key": True},
        {"label": "Schadcode", "wert": str(n), "text": "Funde im Webspace"},
        {"label": "Adressen", "wert": str(len(L["angreifer_ips"])), "text": "des Angreifers"},
        {"label": "Konten", "wert": str(L["fremde_admins"]), "text": "fremde Admin-Konten"},
    ]
    return {"kacheln": kacheln, "abschnitte": abschnitte}


def zusammenfuehren(basis, ueber):
    """Fall-Datei ueber die Vorgaben legen: Objekte rekursiv, Listen und Werte ersetzen."""
    out = copy.deepcopy(basis)
    for k, v in (ueber or {}).items():
        if k.startswith("_"):
            continue
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = zusammenfuehren(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


# ── Berichtslayout NT Dokumente ─────────────────────────────────────────────
ENTWURF_VERMERK = "Entwurf · Anhang automatisch aus dem Lauf, ungeprüft · nicht zur Auslieferung"
ENTWURF_TEXT = ("Dieser Anhang ist automatisch aus der Untersuchung übernommen und nicht von Hand geprüft. "
                "Einzelne Einordnungen können Fehlalarme sein, etwa ein gewöhnliches Dokument als Schadcode "
                "oder ein Einfallstor als nicht ermittelt, obwohl es bekannt ist. Vor der Auslieferung prüfen "
                "und bestätigen.")


def _titel(teile):
    """["Die Website ist", "sauber", "."] -> "Die Website ist sauber." (Feld titel der Fall-Datei)."""
    vor, mark, nach = (list(teile) + ["", "", ""])[:3]
    s = " ".join(x.strip() for x in (vor, mark) if x and x.strip())
    if nach:
        s += nach if nach.startswith((".", ",", "!", "?")) else " " + nach.strip()
    return s


def _vorgang(F):
    if F.get("vorgang"):
        return F["vorgang"]
    return "SV-" + dt.datetime.strptime(F["datum"], "%d.%m.%Y").strftime("%Y-%m-%d") + "-01"


def karten_kunde(F, mit_kenntnis=True):
    k, a = F["kunde"], F["ansprechpartner"]
    links = S.adresskarte("Auftraggeber", k.get("name"), k.get("zeilen") or [], [k.get("rolle"), k.get("email")])
    bearbeitung = ", ".join(x for x in (a.get("name"), a.get("funktion")) if x)
    kontakt = " · ".join(x for x in (a.get("telefon"), a.get("email")) if x)
    roh = f"<b>Vorgang:</b> {S.t(_vorgang(F))}<br>"
    if mit_kenntnis and F.get("kenntnis"):
        roh += f'<span class="sub">Kenntnis: {S.t(F["kenntnis"])}</span>'
    rechts = S.adresskarte("Ersteller", a.get("firma") or S.FIRMA, S.ANSCHRIFT,
                           [f"Bearbeitung: {bearbeitung}" if bearbeitung else "", kontakt], roh)
    return S.adresskarten(links, rechts)


def _abschnitt_anhang(i, a):
    h = f"<h3>A.{i} {S.t(a.get('titel'))}</h3>"
    if a.get("meta"):
        h += S.tabelle([], a["meta"], kv=True)
    h += S.absaetze(a.get("absaetze"))
    if a.get("tabelle"):
        tb = a["tabelle"]
        h += S.tabelle(tb.get("kopf") or [], tb.get("zeilen") or [], erste_fest=bool(tb.get("erste_fest")))
    if a.get("checks"):
        h += S.tabelle([], [[x[0], {"art": x[1], "text": x[2]}] for x in a["checks"]], kv=True)
    if a.get("fussnote"):
        h += f'<p class="note">{S.t(a["fussnote"])}</p>'
    return h


def _unterschrift_ersteller(F):
    a = F["ansprechpartner"]
    return S.unterschrift("Angermünde, " + F["datum"], f"{a.get('name')}, {a.get('firma') or S.FIRMA}")


def dok_bericht(F, entwurf=False):
    B = F["bericht"]
    kurz = B.get("kurz") or {}
    kicker = B.get("kicker") or ""
    art = kicker.split("·")[-1].strip() if "·" in kicker else "Bericht"
    untertitel = B.get("untertitel") or f"{art} · Stand {F['stand']}"
    vermerk = ENTWURF_VERMERK if entwurf else B.get("vermerk") or "Vertraulich · nur für den Auftraggeber"

    h = karten_kunde(F)
    h += f'<h1 class="doctitle">{S.t(B.get("ueberschrift") or _titel(B["titel"]))}</h1><p class="lead">{S.t(B["lede"])}</p>'
    h += S.h2("1", "Zusammenfassung") + S.absaetze(kurz.get("absaetze"))
    if kurz.get("hinweis"):
        h += S.karte(kurz["hinweis"].get("text", ""), kurz["hinweis"].get("label"))
    h += S.absaetze(kurz.get("nach"))

    bw = B["bewertung"]
    if len(bw.get("spalten") or []) <= 1:
        bew = S.tabelle([], [r[:2] for r in bw["zeilen"]], kv=True)
    else:
        bew = S.tabelle([""] + list(bw["spalten"]), bw["zeilen"])
    h += S.h2("2", "Bewertung") + bew + S.absaetze([B.get("bewertung_text")])
    h += S.h2("3", "Ablauf") + S.tabelle(["Zeitpunkt", "Ereignis"], B["ablauf"])
    h += S.h2("4", "Ergriffene Massnahmen") + S.tabelle(
        ["Massnahme", "Umsetzung"], [[f"**{e['titel']}**", e.get("text", "")] for e in B["erledigt"]])
    h += S.h2("5", "Erforderliche nächste Schritte") + S.angebot("Vordringlich", B["jetzt"])
    h += S.tabelle(["Frist", "Massnahme"], [[x["frist"], x["text"]] for x in B["aufgaben"]])
    if B.get("aufgaben_hinweis"):
        h += f'<p class="note">{S.t(B["aufgaben_hinweis"])}</p>'
    M = B["meldepflichten"]
    h += S.h2("6", "Meldepflichten") + f"<p>{S.t(M['einschaetzung'])}</p>"
    h += S.tabelle(["Punkt", "Einordnung"], [[f"**{p['titel']}**", p.get("text", "")] for p in M["punkte"]])
    h += ("<p>Die Dokumentation nach Art. 33 Abs. 5 DSGVO und die Einordnung zur BSI-Meldung "
          "liegen als gesonderte Dokumente bei.</p>")
    h += _unterschrift_ersteller(F)

    P = B["protokoll"]
    h += S.h2("A", "Anhang: Technisches Protokoll", anhang=True)
    if entwurf:
        h += S.karte(ENTWURF_TEXT, "Automatisch, ungeprüft", art="entwurf")
    h += f"<p>{S.t(P.get('einleitung') or 'Alle Zeiten in Ortszeit. Belege mit SHA-256 gesichert, Rohdaten beim Ersteller hinterlegt.')}</p>"
    h += "".join(_abschnitt_anhang(i, a) for i, a in enumerate(P.get("abschnitte") or [], 1))
    return "Sicherheitsbericht", S.dokument("Sicherheitsbericht", untertitel, vermerk, h, entwurf), None


def _personen(D):
    zeilen = (D.get("personen") or {}).get("zeilen") or []
    mehrere = len(zeilen) > 1
    pers = "; ".join(f"{r[1]} ({r[0]})" if mehrere else str(r[1]) for r in zeilen if len(r) > 1)
    daten = "; ".join(dict.fromkeys(str(r[2]) for r in zeilen if len(r) > 2))
    return pers, daten


def dok_dsgvo(F, entwurf=False):
    D, k, a = F["dsgvo"], F["kunde"], F["ansprechpartner"]
    vermerk = ENTWURF_VERMERK if entwurf else D.get("vermerk") or "Vertraulich · zu den Datenschutzunterlagen der Verantwortlichen"
    links = S.adresskarte("Verantwortliche (Art. 4 Nr. 7)", k.get("name"), k.get("zeilen") or [],
                          [f"Datenschutz: {D.get('kontakt') or '____________________'}"])
    kontakt = " · ".join(x for x in (a.get("name"), a.get("telefon"), a.get("email")) if x)
    rechts = S.adresskarte("Auftragsverarbeiter (Hosting)", a.get("firma") or S.FIRMA, [", ".join(S.ANSCHRIFT)],
                           [kontakt, f"Unterrichtung nach Art. 33 Abs. 2: {F['datum']}"])
    h = S.adresskarten(links, rechts)
    h += (f'<h1 class="doctitle">{S.t(D.get("ergebnis") or "Ergebnis: " + _titel(D["titel"]))}</h1>'
          f'<p class="lead">{S.t(D["lede"])}</p>')

    beginn = D.get("beginn") or next((v for kk, v in F["bsi"].get("angaben") or [] if str(kk).startswith("Erst")),
                                     "aus den Protokollen nicht bestimmbar")
    zeit = D.get("zeitpunkte") or [["Beginn der Verletzung", beginn], ["Kenntnis", F["kenntnis"]],
                                   ["Frist Meldung (72 Stunden)", f"**{F['frist_72h']}**"]]
    h += S.h2("1", "Zeitpunkte") + S.tabelle([], zeit, kv=True)

    pers, daten = _personen(D)
    angaben = [
        ["a) Art der Verletzung", D["art"]],
        ["a) Kategorien betroffener Personen", " ".join(x for x in (pers + "." if pers else "", D.get("personen_text")) if x)],
        ["a) Kategorien personenbezogener Daten", daten or "____________________"],
        ["a) Ungefähre Zahl", D.get("zahl") or "Personen: ______ · Datensätze: ______ (ergänzt die Verantwortliche)"],
        ["b) Kontakt Datenschutz", D.get("kontakt") or "____________________"],
        ["c) Wahrscheinliche Folgen", D.get("folgen") or "Ein Abfluss personenbezogener Daten ist nicht belegt. "
                                                      "Mögliche Folgen hängen vom Datenbestand ab, die Verantwortliche bewertet sie."],
        ["d) Ergriffene Massnahmen", D["massnahmen"]],
    ]
    h += S.h2("2", "Angaben nach Art. 33 Abs. 3 DSGVO") + S.tabelle([], angaben, kv=True)
    h += S.h2("3", "Prüfung") + S.tabelle(["Prüfpunkt", "Ergebnis"], [[f"**{p['titel']}**", p.get("text", "")] for p in D["pruefliste"]])
    h += S.h2("4", "Abwägung") + S.tabelle(["Pflicht", "Einschätzung"], [[x[0], {"art": x[1], "text": x[2]}] for x in D["abwaegung"]])
    h += S.karte(D["einordnung"])
    box = '<span class="box"></span>'
    h += (S.h2("5", "Entscheidung der Verantwortlichen")
          + f"<p>{box}Meldung an die Aufsichtsbehörde erfolgt am __________ &nbsp;&nbsp; {box}keine Meldung, Begründung: ______________________________</p>"
          + f"<p>{box}Benachrichtigung der Betroffenen nach Art. 34 erfolgt am __________ &nbsp;&nbsp; {box}nicht erforderlich</p>"
          + S.unterschrift("Ort, Datum", f"Unterschrift {k.get('name')}"))
    return ("Dokumentation Art. 33 DSGVO",
            S.dokument("Dokumentation Datenschutzverletzung", f"nach Art. 33 Abs. 5 DSGVO · {F['datum']}", vermerk, h, entwurf), 2)


def dok_bsi(F, entwurf=False):
    B = F["bsi"]
    vermerk = ENTWURF_VERMERK if entwurf else B.get("vermerk") or "Vertraulich · Angaben für eine freiwillige Meldung"
    h = karten_kunde(F, mit_kenntnis=False)
    h += (f'<h1 class="doctitle">{S.t(B.get("ergebnis") or "Ergebnis: " + _titel(B["titel"]))}</h1>'
          f'<p class="lead">{S.t(B["lede"])}</p>')
    h += S.h2("1", "Einordnung") + S.tabelle(
        ["Prüfung", "Ergebnis", "Begründung"],
        [[x.get("regel", ""), {"art": x.get("art"), "text": x.get("titel", "")}, x.get("text", "")] for x in B["status"]])
    h += S.tabelle(["Kriterium", "Erläuterung"], [[f"**{g['titel']}**", g.get("text", "")] for g in B["gruende"]])
    h += S.h2("2", "Angaben für eine freiwillige Meldung") + S.tabelle([], B["angaben"], kv=True)
    h += S.tabelle(["Schutzziel", "Auswirkung"], [[x[0], {"art": x[1], "text": x[2]}] for x in B["auswirkung"]])
    h += f"<p><strong>Massnahmen:</strong> {S.t(B['massnahmen'])}</p>"
    h += S.h2("3", "Indikatoren (IOC)") + S.tabelle(["Art", "Wert"], B.get("iocs") or B.get("merkmale") or [])
    if B.get("hinweis"):
        h += f'<p class="note">{S.t(B["hinweis"])}</p>'
    h += _unterschrift_ersteller(F)
    return ("Einordnung BSI-Meldung",
            S.dokument("Einordnung BSI-Meldung", f"BSIG / NIS2 · {F['datum']}", vermerk, h, entwurf), 2)


def protokoll_geprueft(eigen):
    """Der Anhang gilt als geprueft, wenn die Fall-Datei ihn liefert (bericht.protokoll)
    oder den Stand aus dem Lauf ausdruecklich bestaetigt (bericht.protokoll_geprueft).
    Ohne das uebernimmt er ungeprueft, was der Lauf einordnet, Fehlalarme eingeschlossen
    (Vorfall vom 23.11.2026: ein Dokument als Schadcode, Einfallstor als nicht belegt)."""
    b = (eigen or {}).get("bericht") or {}
    return bool(b.get("protokoll")) or b.get("protokoll_geprueft") is True


def dateinamen(F):
    k = _ascii(F["kunde"].get("datei") or F["kunde"]["kurz"])
    d = dt.datetime.strptime(F["datum"], "%d.%m.%Y").strftime("%Y-%m-%d")
    return {"bericht": f"NT-Sicherheitsbericht_{k}_{d}.pdf",
            "dsgvo": f"NT-Dokumentation_DSGVO-Art33_{k}_{d}.pdf",
            "bsi": f"NT-Einordnung_BSI-Meldung_{k}_{d}.pdf"}


def interna_pruefen(pdfs):
    if not WAECHTER.is_file():
        return 0, f"Interna-Wächter fehlt: {WAECHTER}"
    r = subprocess.run(["bash", str(WAECHTER), *map(str, pdfs)], capture_output=True, text=True)
    return r.returncode, (r.stdout + r.stderr).rstrip()


def main(argv=None):
    ap = argparse.ArgumentParser(description="Kundenpaket im Berichtslayout NT Dokumente aus einem Forensik-Lauf")
    ap.add_argument("--lauf", required=True)
    ap.add_argument("--ziel", required=True, help="Ordner für die drei Kunden-PDFs")
    ap.add_argument("--fall", help="Fall-Datei (JSON), überschreibt die Vorgaben aus dem Lauf")
    ap.add_argument("--pruefung", help="Ordner für Seitenbilder und Prüfbericht (nicht beim Kunden ablegen)")
    ap.add_argument("--entwurf", help="zusammengeführte Fall-Datei hierhin schreiben (Vorlage zum Bearbeiten)")
    a = ap.parse_args(argv)
    try:
        L = lauf_lesen(a.lauf)
    except Lauffehler as e:
        print(f"kundenpaket: {e}", file=sys.stderr)
        return 1
    eigen = json.loads(pathlib.Path(a.fall).read_text(encoding="utf-8")) if a.fall else {}
    F = zusammenfuehren(fall_aus_lauf(L, bool(eigen.get("bereinigt"))), eigen)
    entwurf = not protokoll_geprueft(eigen)
    if a.entwurf:
        pathlib.Path(a.entwurf).parent.mkdir(parents=True, exist_ok=True)
        pathlib.Path(a.entwurf).write_text(json.dumps(F, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    ziel = pathlib.Path(a.ziel)
    ziel.mkdir(parents=True, exist_ok=True)
    pruef = pathlib.Path(a.pruefung) if a.pruefung else None
    namen = dateinamen(F)
    berichte, pdfs, rc = [], [], 0
    for key, bauen in (("bericht", dok_bericht), ("dsgvo", dok_dsgvo), ("bsi", dok_bsi)):
        name, html, soll = bauen(F, entwurf)
        try:
            b = S.schreiben(name, html, ziel / namen[key], soll_seiten=soll,
                            png_ordner=pruef / "seiten" if pruef else None)
        except S.SatzFehler as e:
            print(f"kundenpaket: {e}", file=sys.stderr)
            return 1
        if pruef:
            (pruef / "html").mkdir(parents=True, exist_ok=True)
            (pruef / "html" / (pathlib.Path(namen[key]).stem + ".html")).write_text(html, encoding="utf-8")
        berichte.append(b)
        pdfs.append(ziel / namen[key])
        zeichen = "ok" if not (b["fehler"] or b["regelverstoesse"]) else "FEHLER"
        print(f"  {zeichen:6} {namen[key]}  {b['seiten']} Seite(n)")
        for f in b["fehler"]:
            print(f"         {f}")
        for f in b["regelverstoesse"]:
            print(f"         Regel: {f}")
        if b["fehler"] or b["regelverstoesse"]:
            rc = 2
    irc, itext = interna_pruefen(pdfs)
    if itext:
        print(itext)
    if irc != 0:
        rc = 3
    if entwurf:
        print("  ENTWURF: Anhang automatisch aus dem Lauf, ungeprüft. Nicht ausliefern, bevor die Fall-Datei "
              "bericht.protokoll liefert oder bericht.protokoll_geprueft bestätigt.")
        if rc == 0:
            rc = 4
    if pruef:
        pruef.mkdir(parents=True, exist_ok=True)
        (pruef / "pruefung.json").write_text(json.dumps(
            {"dokumente": berichte, "interna": {"rc": irc, "ausgabe": itext}, "entwurf": entwurf, "rc": rc},
            ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return rc


if __name__ == "__main__":
    sys.exit(main())
