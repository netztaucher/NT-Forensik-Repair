#!/usr/bin/env python3
# kundenpaket.py - Kundenpaket im Designsystem NT Docs aus einem Forensik-Lauf
#
# Test:     ja - werkzeuge/kundenpaket-pruefstand.sh (Fixture: drei PDFs, Seiten, Interna) · NT-Forensik-Repair#149
# Rueckweg: entfaellt - schreibt nur neue Dateien in --ziel und --pruefung, aendert den Lauf nicht
#
# Aufruf:
#   kundenpaket.py --lauf <lauf-ordner> --ziel <ordner> [--fall fall.json]
#                  [--pruefung <ordner>] [--entwurf fall.entwurf.json]
#
# Erzeugt den Standard vom 21.10.2026 (NT-Forensik-Repair#149, #150):
#   NT-Sicherheitsbericht_<Kunde>_<Datum>.pdf          Seite 1 Ergebnis, Teil 1 Kundenbericht, Teil 2 Protokoll
#   NT-Dokumentation_DSGVO-Art33_<Kunde>_<Datum>.pdf   2 Seiten
#   NT-Einordnung_BSI-Meldung_<Kunde>_<Datum>.pdf      2 Seiten
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
#            3 = Interna-Waechter schlaegt an. Die PDFs liegen auch bei 2/3 vor,
#            zur Ansicht, nicht zur Auslieferung.

import argparse
import copy
import datetime as dt
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import ntdocs_satz as S  # noqa: E402
from ntdocs_satz import Atom, Zeilen, Abschnitt, Kapitel, Dokument, t  # noqa: E402

WAECHTER = HERE.parent / "werkzeuge" / "interna-waechter.sh"

ANSPRECHPARTNER = {"name": "Marco Neuber", "firma": "die netztaucher GmbH",
                   "telefon": "03331 252520", "email": "neuber@netztaucher.com"}

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
        wichtigste.append({"art": "warn", "titel": f"{fam} ({k})", "text": FAMILIE.get(fam, "Einordnung im Protokoll, Teil 2") + "."})
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
            "jetzt": "**Heute** die Passwörter Ihrer WordPress-Konten ändern und nichts löschen, bevor die Bereinigung abgeschlossen ist. Alle Schritte mit Frist stehen in Teil 1.",
            "kurz": {"absaetze": [lede], "hinweis": None},
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
            "hinweis": "Eine freiwillige Meldung nimmt das BSI über die Allianz für Cybersicherheit an. Eine Strafanzeige ist bei der Zentralen Ansprechstelle Cybercrime (ZAC) der Landespolizei möglich. Die Angaben dafür stehen auf Seite 2. Stand der Rechtslage: Oktober 2026.",
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


def _bewertung(L, bereinigt):
    seiten = L["websites"]
    zeilen = []
    zeilen.append(["Einstufung"] + [{"art": "warn", "text": "kompromittiert", "nach": " jetzt bereinigt" if bereinigt else ""}
                                     if any(f["website"] == w or len(seiten) == 1 for f in L["funde"]) else {"art": "ok", "text": "unauffällig"}
                                     for w in seiten])
    zeilen.append(["Schadcode"] + [_anzahl(sum(1 for f in L["funde"] if f["website"] == w or len(seiten) == 1), "Fund", "Funde") for w in seiten])
    zeilen.append(["Einfallstor"] + [L["einstieg"][0]["kanal"] if L["einstieg"] else "nicht belegt" for _ in seiten])
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
                           "absaetze": ["Aus den vorhandenen Protokollen nicht belegt. Kein Zugriff mit Fernwartungs-, Upload- oder Installationskennung in derselben Sekunde wie die Anlage einer belasteten Datei."]})
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


# ── HTML-Bausteine ──────────────────────────────────────────────────────────
ICON = {"ok": "status-ok.svg", "warn": "status-warn.svg", "info": "status-info.svg"}
DOT = {"ok": "dot-ok.svg", "warn": "dot-warn.svg", "info": "dot-ok.svg"}


def _zelle(x):
    if isinstance(x, dict):
        art = x.get("art", "info")
        cls = {"ok": "nt-state is-ok", "warn": "nt-state is-warn"}.get(art, "nt-state")
        return f'<span class="{cls}"><img src="img/{ICON.get(art, ICON["info"])}" alt="">{t(x.get("text", ""))}</span>{t(x.get("nach", ""))}'
    return "<br>".join(t(z) for z in str(x).split("\n"))


def h_kopfband(meta, kicker, titel, lede):
    vor, mark, nach = (list(titel) + ["", "", ""])[:3]
    mark_html = f' <span class="nt-mark">{t(mark)}</span>' if mark else ""
    if nach and not nach.startswith((".", ",", "!", "?")):
        nach = " " + nach.lstrip()
    return (f'<header class="nt-band"><div class="nt-band-top">{S.MARKE_BAND}'
            f'<div class="nt-band-meta">{"<br>".join(t(m) for m in meta)}</div></div>'
            f'<p class="nt-kicker">{t(kicker)}</p><h1 class="nt-display">{t(vor)}{mark_html}{t(nach)}</h1>'
            f'<p class="nt-lede">{t(lede)}</p><img class="nt-edge" src="img/kante.svg" alt=""></header>')


def h_status(status):
    karten = []
    for s in status[:3]:
        art = s.get("art", "info")
        cls = {"ok": "nt-status is-ok", "warn": "nt-status is-warn"}.get(art, "nt-status")
        regel = f'<span class="nt-status-rule">{t(s["regel"])}</span>' if s.get("regel") else ""
        karten.append(f'<div class="{cls}"><img class="nt-status-icon" src="img/{ICON.get(art, ICON["info"])}" alt="">'
                      f'<span class="nt-status-title">{t(s.get("titel"))}</span>'
                      f'<span class="nt-status-text">{t(s.get("text"))}</span>{regel}</div>')
    return f'<div class="nt-status-row">{"".join(karten)}</div>'


def h_li(p):
    art = p.get("art", "ok")
    return (f'<li><img class="nt-dot" src="img/{DOT.get(art, DOT["ok"])}" alt=""><div>'
            f'<span class="nt-item-title">{t(p.get("titel"))}</span>'
            f'<span class="nt-item-text">{t(p.get("text"))}</span></div></li>')


def h_checkliste(punkte):
    return f'<ul class="nt-checklist">{"".join(h_li(p) for p in punkte)}</ul>'


def h_infokarte(label, name, zeilen):
    return (f'<div class="nt-infocard"><p class="nt-label">{t(label)}</p>'
            f'<span class="nt-infocard-name">{t(name)}</span>{"<br>".join(t(z) for z in zeilen if z)}</div>')


def h_person(label, p):
    return h_infokarte(label, p.get("name"), [p.get("firma"), p.get("telefon"), p.get("email")])


def h_hinweis(label, text, art="warn", icon=None):
    cls = "nt-notice" if art == "warn" else "nt-notice is-info"
    icon = icon or ("idea.svg" if art == "warn" else "status-info.svg")
    return (f'<div class="{cls}"><img class="nt-notice-icon" src="img/{icon}" alt=""><div>'
            f'<p class="nt-label">{t(label)}</p><p>{t(text)}</p></div></div>')


def h_seite1(kopf, status, links_label, links, rechts, hinweis):
    return (kopf + '<div class="nt-body">' + h_status(status)
            + '<div class="nt-cols nt-gap"><div class="nt-col-2of3">'
            + f'<p class="nt-label">{t(links_label)}</p>{h_checkliste(links)}</div>'
            + f'<div class="nt-col-1of3">{"".join(rechts)}</div></div>'
            + S._mit_gap_html(hinweis, "gap") + '</div>')


def b_tabelle(kopf, zeilen, gap="gap", erste_fest=False):
    """erste_fest: erste Spalte bricht nicht um und steht fett (Wann, Frist)."""
    k = "<tr>" + "".join(f"<th>{t(x)}</th>" for x in kopf) + "</tr>"
    z = []
    for r in zeilen:
        zellen = []
        for i, c in enumerate(r):
            if i == 0 and erste_fest:
                inhalt = _zelle(c) if isinstance(c, dict) else f"<b>{_zelle(c)}</b>"
                zellen.append(f'<td class="nt-nb">{inhalt}</td>')
            else:
                zellen.append(f"<td>{_zelle(c)}</td>")
        z.append("<tr>" + "".join(zellen) + "</tr>")
    return Zeilen('<table class="nt-table">', z, "</table>", kopf=k, gap=gap)


def b_checkliste(punkte, gap="gap"):
    return Zeilen('<ul class="nt-checklist">', [h_li(p) for p in punkte], "</ul>", gap=gap)


def b_meta(paare, gap="gap"):
    return Atom('<dl class="nt-meta">' + "".join(f"<dt>{t(k)}</dt><dd>{_zelle(v)}</dd>" for k, v in paare) + "</dl>", gap=gap)


def b_prosa(absaetze, lede=False, gap="gap"):
    ps = []
    for i, a in enumerate(absaetze):
        cls = ' class="nt-lede"' if lede and i == 0 else ""
        ps.append(f"<p{cls}>{t(a)}</p>")
    return Atom(f'<div class="nt-prose">{"".join(ps)}</div>', gap=gap)


def b_checks(zeilen, gap=""):
    rows = "".join(f'<div><dt>{t(a)}</dt><dd>{_zelle({"art": art, "text": txt})}</dd></div>' for a, art, txt in zeilen)
    return Atom(f'<dl class="nt-checks">{rows}</dl>', gap=gap)


def b_abschnitt(nr, a):
    kinder = []
    for p in a.get("absaetze") or []:
        kinder.append(Atom(f"<p>{t(p)}</p>", gap=""))
    if a.get("meta"):
        kinder.append(b_meta(a["meta"], gap=""))
    if a.get("tabelle"):
        kinder.append(b_tabelle(a["tabelle"]["kopf"], a["tabelle"]["zeilen"], gap="",
                                erste_fest=bool(a["tabelle"].get("erste_fest"))))
    if a.get("checks"):
        kinder.append(b_checks(a["checks"]))
    if a.get("fussnote"):
        kinder.append(Atom(f'<p class="nt-footnote">{t(a["fussnote"])}</p>', gap=""))
    return Abschnitt(f"{nr:02d}", a["titel"], kinder)


def b_kacheln(kacheln):
    k = "".join(f'<div class="nt-tile{" is-key" if x.get("key") else ""}"><p class="nt-label">{t(x["label"])}</p>'
                f'<span class="nt-tile-value">{t(x["wert"])}</span><span class="nt-tile-text">{t(x["text"])}</span></div>'
                for x in kacheln[:4])
    return Atom(f'<div class="nt-tiles is-linie">{k}</div>', gap="")


# ── Dokumente ───────────────────────────────────────────────────────────────
def kunde_rechts(F, label="Kunde"):
    k = F["kunde"]
    return h_infokarte(label, k.get("name"), list(k.get("zeilen") or []) + [k.get("email")])


def dok_bericht(F):
    B = F["bericht"]
    s1 = h_seite1(h_kopfband(B["meta"], B["kicker"], B["titel"], B["lede"]), B["status"], "Das Wichtigste",
                  B["wichtigste"], [kunde_rechts(F), h_person("Ansprechpartner", F["ansprechpartner"])],
                  h_hinweis("Was Sie jetzt tun sollten", B["jetzt"], icon="status-warn.svg"))
    T1 = "Teil 1 · Kundenbericht"
    kap = []
    kurz = [b_meta([["Betroffen", _aufzaehlen(F["websites"])], ["Stand", F["stand"]]], gap=""),
            b_prosa(B["kurz"]["absaetze"], lede=True)]
    if B["kurz"].get("hinweis"):
        h = B["kurz"]["hinweis"]
        kurz.append(Atom(h_hinweis(h.get("label", "Hinweis"), h.get("text", "")), gap="gap"))
    for p in B["kurz"].get("nach") or []:
        kurz.append(b_prosa([p]))
    kap.append(Kapitel(T1, "Das Wichtigste in Kürze", kurz))
    bw = B["bewertung"]
    bl = [b_tabelle([""] + list(bw["spalten"]), bw["zeilen"], gap="")]
    if B.get("bewertung_text"):
        bl.append(b_prosa([B["bewertung_text"]]))
    kap.append(Kapitel(T1, "Bewertung je Website", bl))
    kap.append(Kapitel(T1, "Was passiert ist", [b_tabelle(["Wann", "Was"], B["ablauf"], gap="", erste_fest=True)]))
    kap.append(Kapitel(T1, "Was wir getan haben", [b_checkliste([dict(p, art=p.get("art", "ok")) for p in B["erledigt"]], gap="")]))
    auf = [b_tabelle(["Frist", "Massnahme"], [[{"art": a.get("art", "info"), "text": a["frist"]}, a["text"]] for a in B["aufgaben"]], gap="", erste_fest=True)]
    if B.get("aufgaben_hinweis"):
        auf.append(Atom(h_hinweis("Bereits erledigt" if F.get("bereinigt") else "Hinweis", B["aufgaben_hinweis"], art="info")))
    kap.append(Kapitel(T1, "Was Sie jetzt tun sollten", auf))
    M = B["meldepflichten"]
    kap.append(Kapitel(T1, "Meldepflichten", [Atom(h_hinweis("Unsere Einschätzung", M["einschaetzung"]), gap=""),
                                              b_checkliste(M["punkte"])]))
    P = B["protokoll"]
    t2 = [b_kacheln(P["kacheln"])] + [b_abschnitt(i, a) for i, a in enumerate(P["abschnitte"], 1)]
    if len(t2) > 1:
        t2[1].gap = "gap"
    kap.append(Kapitel("Teil 2 · Anlage zum Bericht", "Forensik- und Bereinigungsprotokoll", t2, linie=True))
    return Dokument("Sicherheitsbericht", f"Sicherheitsbericht · {F['kunde']['kurz']} · {F['datum']}", s1, kap)


def dok_dsgvo(F):
    D = F["dsgvo"]
    s1 = h_seite1(h_kopfband(["Datenschutzverletzung · Dokumentation", F["datum"]], D["kicker"], D["titel"], D["lede"]),
                  D["status"], "Was wir geprüft haben", D["pruefliste"],
                  [h_infokarte("Verantwortlicher", F["kunde"]["name"], [F["kunde"].get("rolle"), F["kunde"].get("email")]),
                   h_person("Auftragsverarbeiter", F["ansprechpartner"])],
                  h_hinweis("Einordnung", D["einordnung"]))
    a = [
        b_abschnitt(1, {"titel": "Art der Verletzung", "absaetze": [D["art"]]}),
        b_abschnitt(2, {"titel": "Betroffene Personen und Daten", "tabelle": D["personen"], "absaetze": []}),
        b_abschnitt(3, {"titel": "Ergriffene Massnahmen", "absaetze": [D["massnahmen"]]}),
        b_abschnitt(4, {"titel": "Abwägung und Entscheidung", "checks": D["abwaegung"]}),
    ]
    if D.get("personen_text"):
        a[1].kinder.append(Atom(f"<p>{t(D['personen_text'])}</p>", gap=""))
    sign = Atom('<div class="nt-sign"><p class="nt-label">Entscheidung des Verantwortlichen</p><div class="nt-sign-row">'
                '<div><div class="nt-sign-line"></div><small>Ort, Datum</small></div>'
                f'<div><div class="nt-sign-line"></div><small><b>{t(F["kunde"]["name"])}</b> · Verantwortlicher</small></div>'
                '</div></div>', gap="gap")
    kap = [Kapitel("Angaben nach Art. 33 Abs. 3 DSGVO", "Sachverhalt, Folgen und Massnahmen", a + [sign])]
    return Dokument("Dokumentation Art. 33 DSGVO", f"Dokumentation Art. 33 DSGVO · {F['kunde']['kurz']} · {F['datum']}",
                    s1, kap, soll_seiten=2)


def dok_bsi(F):
    B = F["bsi"]
    s1 = h_seite1(h_kopfband(["IT-Sicherheitsvorfall · Einordnung BSI", F["datum"]], B["kicker"], B["titel"], B["lede"]),
                  B["status"], "Warum", B["gruende"],
                  [h_infokarte("Betreiber", F["kunde"]["name"], F["websites"]), h_person("Ansprechpartner", F["ansprechpartner"])],
                  h_hinweis("Falls Sie melden möchten", B["hinweis"], art="info"))
    a = [b_meta(B["angaben"], gap=""),
         b_abschnitt(1, {"titel": "Merkmale des Angriffs", "tabelle": {"kopf": ["Merkmal", "Wert"], "zeilen": B["merkmale"]}}),
         b_abschnitt(2, {"titel": "Auswirkung", "checks": B["auswirkung"]}),
         b_abschnitt(3, {"titel": "Massnahmen", "absaetze": [B["massnahmen"]]})]
    a[1].gap = "gap"
    kap = [Kapitel("Angaben für eine freiwillige Meldung", "Vorfall, Merkmale und Auswirkung", a)]
    return Dokument("Einordnung BSI-Meldung", f"Einordnung BSI-Meldung · {F['kunde']['kurz']} · {F['datum']}",
                    s1, kap, soll_seiten=2)


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
    ap = argparse.ArgumentParser(description="Kundenpaket im Designsystem NT Docs aus einem Forensik-Lauf")
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
    if a.entwurf:
        pathlib.Path(a.entwurf).parent.mkdir(parents=True, exist_ok=True)
        pathlib.Path(a.entwurf).write_text(json.dumps(F, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    ziel = pathlib.Path(a.ziel)
    ziel.mkdir(parents=True, exist_ok=True)
    pruef = pathlib.Path(a.pruefung) if a.pruefung else None
    namen = dateinamen(F)
    berichte, pdfs, rc = [], [], 0
    for key, bauen in (("bericht", dok_bericht), ("dsgvo", dok_dsgvo), ("bsi", dok_bsi)):
        try:
            b, html = S.schreiben(bauen(F), ziel / namen[key], png_ordner=pruef / "seiten" if pruef else None)
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
    if pruef:
        pruef.mkdir(parents=True, exist_ok=True)
        (pruef / "pruefung.json").write_text(json.dumps(
            {"dokumente": berichte, "interna": {"rc": irc, "ausgabe": itext}, "rc": rc},
            ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return rc


if __name__ == "__main__":
    sys.exit(main())
