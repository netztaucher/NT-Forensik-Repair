#!/usr/bin/env python3
# anschreiben.py - kurzes HTML-Anschreiben zum Kundenpaket (Standard 21.10.2026)
#
# Test:     ja - werkzeuge/kundenpaket-pruefstand.sh (Fixture: Mail, Wortzahl, Anhänge, Interna) · NT-Forensik-Repair#151
# Rueckweg: entfällt - schreibt nur neue Dateien in --ziel; Apple Mail nur mit --apple-mail, legt dort einen Entwurf an (löschbar), sendet nie
#
# Aufruf:
#   anschreiben.py --fall fall.json --anhang <pdf> [--anhang <pdf> ...]
#                  [--bild <png> ...] [--bildschirmfoto <https://domain>] --ziel <ordner>
#                  [--apple-mail]
#
# Ergebnis in --ziel:
#   anschreiben.html        HTML-Teil (Tabellen, Inline-Stile, kein Kopf, kein Logo)
#   anschreiben.txt         Text-Alternative, gleicher Inhalt
#   anschreiben.eml         vollständige Nachricht mit allen Anhängen (Archiv, Ansicht)
#   anschreiben_entwurf.applescript   legt den Entwurf in Apple Mail in EINEM Lauf an
#
# Warum ein AppleScript und nicht die .eml: Mail öffnet eine .eml mit X-Unsent
# nur als Ansicht. Ein Entwurf entsteht nur über `make new outgoing message`,
# HTML und ALLE Anhänge im selben Skriptlauf, dann genau ein `save`. Jeder
# weitere Speicherlauf behält nur die Anhänge dieses Laufs (gemessen 21.10.2026).
#
# Sprache: Sie-Form, normale Gross-/Kleinschreibung (Entscheidung Marco für
# Sie-Kunden mit Vorfall), kein ß, keine Gedankenstriche. Rund 150 Wörter.
#
# Rückgabe: 0 = Mail regelgerecht, 2 = Regelverstoss (Länge, Zeichen, mehr als
#           drei Punkte), 3 = Interna-Wächter schlägt an, 1 = Aufruffehler.

import argparse
import html as _html
import json
import mimetypes
import pathlib
import re
import shutil
import subprocess
import sys
from email.message import EmailMessage
from email.utils import formataddr, formatdate, make_msgid

HERE = pathlib.Path(__file__).resolve().parent
WAECHTER = HERE.parent / "werkzeuge" / "interna-waechter.sh"

ABSENDER = ("Marco Neuber", "neuber@netztaucher.com")
GRUSS = "Mit einem schönen Gruss aus Angermünde in der Uckermark"
ADRESSE = "die netztaucher GmbH · Am Gutshof 36 · 16278 Angermünde · 03331 252520"
# Farben aus NT Docs (tokens.css)
INK, ORANGE_SOFT, ORANGE_INK, NAVY, INK3 = "#1b2533", "#fff1e0", "#a85400", "#003366", "#626b78"
MAX_WOERTER = 190      # Ziel ~150; darüber ist es kein kurzes Anschreiben mehr
MAX_PUNKTE = 3

ZAHLWORT = {1: "das", 2: "die zwei", 3: "die drei", 4: "die vier"}


def _plain(s):
    return re.sub(r"\*\*(.+?)\*\*", r"\1", str(s))


def _h(s):
    s = _html.escape(str(s), quote=False)
    return re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", s)


def inhalt(F, n_bilder):
    """Mail-Inhalt aus der Fall-Datei: mail-Abschnitt, sonst Vorgaben aus dem Bericht."""
    M = F.get("mail") or {}
    k = F.get("kunde") or {}
    seiten = F.get("websites") or []
    mehr = len(seiten) > 1
    anrede = M.get("anrede") or (k.get("anrede") + "," if k.get("anrede") else "Guten Tag,")
    if M.get("ergebnis"):
        ergebnis = M["ergebnis"]
    elif F.get("bereinigt"):
        subj = "beide Websites sind" if len(seiten) == 2 else ("die Websites sind" if mehr else "Ihre Website ist")
        lauf = "laufen" if mehr else "läuft"
        foto = (f", wie {ZAHLWORT.get(n_bilder, str(n_bilder))} Bildschirmfoto{'s' if n_bilder > 1 else ''} "
                f"von heute im Anhang {'zeigen' if n_bilder > 1 else 'zeigt'}") if n_bilder else ""
        ergebnis = (f"{subj} bereinigt und {lauf} wieder{foto}. Alle Zugänge, die wir verwalten, sind erneuert. "
                    "Im Anhang finden Sie den vollständigen Bericht und zwei kurze Dokumente zur Meldepflicht.")
    else:
        ergebnis = ("wir haben Ihre Website untersucht und Schadcode gefunden. Die Bereinigung steht noch aus. "
                    "Im Anhang finden Sie den Bericht und zwei kurze Dokumente zur Meldepflicht.")
    ursache = M.get("ursache") or ""
    punkte = M.get("bitte_heute")
    if punkte is None:
        punkte = [_plain(a["text"]).split(".")[0] for a in (F.get("bericht") or {}).get("aufgaben", [])
                  if a.get("frist") == "sofort"]
    melde = M.get("meldepflicht") or ""
    if not melde:
        D = F.get("dsgvo") or {}
        keine = (D.get("titel") or [""])[0].startswith("Keine")
        melde = ("Sie müssen nichts melden. Bitte unterschreiben Sie die Dokumentation nach Art. 33 DSGVO und legen "
                 "Sie sie mit dem Bericht zu Ihren Datenschutzunterlagen." if keine else
                 f"Eine Meldung an die Datenschutzaufsicht ist nach unserer Einschätzung nötig, Frist bis "
                 f"{F.get('frist_72h', '')}. Die Einzelheiten stehen in der Dokumentation nach Art. 33 DSGVO.")
    an = M.get("an") or {"name": k.get("name", ""), "email": k.get("email", "")}
    betreff = M.get("betreff") or f"Sicherheitsvorfall {', '.join(seiten)}: Abschluss und Ihre nächsten Schritte"
    return {"an": an, "betreff": betreff, "anrede": anrede, "absaetze": [ergebnis] + ([ursache] if ursache else []),
            "punkte": list(punkte), "meldepflicht": melde, "gruss": M.get("gruss") or GRUSS}


def html_mail(c):
    p = 'style="margin:0 0 14px;"'
    abs_html = "".join(f"<p {p}>{_h(a)}</p>" for a in c["absaetze"])
    punkte = "<br>\n".join(f"» {_h(x)}" for x in c["punkte"])
    label = 'style="font-size:12px;font-weight:700;letter-spacing:0.5px;text-transform:uppercase;color:{};"'
    return f"""<!doctype html>
<html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"></head>
<body style="margin:0;padding:0;background:#ffffff;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"><tr><td style="padding:20px 16px;">
<table role="presentation" width="600" cellpadding="0" cellspacing="0" border="0" style="width:600px;max-width:100%;font-family:-apple-system,'Segoe UI',Helvetica,Arial,sans-serif;font-size:15px;line-height:1.55;color:{INK};">
<tr><td>
<p {p}>{_h(c["anrede"])}</p>
{abs_html}
</td></tr>
<tr><td style="background:{ORANGE_SOFT};border-radius:10px;padding:14px 18px;">
<div {label.format(ORANGE_INK)}>Bitte heute</div>
<div style="margin-top:6px;">{punkte}</div>
</td></tr>
<tr><td style="padding-top:20px;">
<div {label.format(NAVY)}>Meldepflicht</div>
<p style="margin:6px 0 0;">{_h(c["meldepflicht"])}</p>
</td></tr>
<tr><td style="padding-top:22px;">
<p {p}>Ich freue mich auf Ihre Rückmeldung.</p>
<p style="margin:0;">{_h(c["gruss"])}<br><b>{_h(ABSENDER[0])}</b></p>
<p style="margin:18px 0 0;font-size:12px;color:{INK3};">{_h(ADRESSE)}</p>
</td></tr>
</table>
</td></tr></table>
</body></html>
"""


def text_mail(c):
    z = [c["anrede"], ""]
    for a in c["absaetze"]:
        z += [_plain(a), ""]
    z += ["BITTE HEUTE"] + [f"» {_plain(x)}" for x in c["punkte"]] + [""]
    z += ["MELDEPFLICHT", _plain(c["meldepflicht"]), ""]
    z += ["Ich freue mich auf Ihre Rückmeldung.", "", c["gruss"], ABSENDER[0], ADRESSE, ""]
    return "\n".join(z)


def woerter(c):
    t = " ".join([c["anrede"], *c["absaetze"], *c["punkte"], c["meldepflicht"]])
    return len(re.findall(r"\w+", _plain(t)))


def pruefen(c, html, text):
    fehler = []
    n = woerter(c)
    if n > MAX_WOERTER:
        fehler.append(f"{n} Wörter, Ziel rund 150 (höchstens {MAX_WOERTER})")
    if len(c["punkte"]) > MAX_PUNKTE:
        fehler.append(f"{len(c['punkte'])} Punkte unter „Bitte heute“, höchstens {MAX_PUNKTE}")
    if not c["punkte"]:
        fehler.append("kein Punkt unter „Bitte heute“")
    for name, z in (("Gedankenstrich –", "–"), ("Gedankenstrich —", "—"), ("ß statt ss", "ß")):
        if z in text:
            fehler.append(name)
    if re.search(r"<img\b", html, re.I):
        fehler.append("Bild oder Logo im HTML (Standard: kein Kopf, kein Logo)")
    return n, fehler


def bildschirmfoto(url, ziel):
    """Startseite mit Chrome headless, 1440×1000 (Standard 21.10.2026)."""
    chrome = shutil.which("google-chrome") or shutil.which("chromium") or \
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
    if not pathlib.Path(chrome).exists() and not shutil.which(chrome):
        raise RuntimeError("Chrome nicht gefunden")
    subprocess.run([chrome, "--headless=new", "--hide-scrollbars", "--window-size=1440,1000",
                    f"--screenshot={ziel}", url], check=True, capture_output=True, timeout=90)
    return ziel


def eml(c, html, text, anhaenge):
    m = EmailMessage()
    m["From"] = formataddr(ABSENDER)
    m["To"] = formataddr((c["an"].get("name", ""), c["an"]["email"]))
    m["Subject"] = c["betreff"]
    m["Date"] = formatdate(localtime=True)
    m["Message-Id"] = make_msgid(domain="netztaucher.com")
    m.set_content(text)
    m.add_alternative(html, subtype="html")
    for a in anhaenge:
        typ = (mimetypes.guess_type(a.name)[0] or "application/octet-stream").split("/")
        m.add_attachment(a.read_bytes(), maintype=typ[0], subtype=typ[1], filename=a.name)
    return m


def _as(s):
    return '"' + str(s).replace("\\", "\\\\").replace('"', '\\"') + '"'


def applescript(c, html_pfad, text_pfad, anhaenge):
    z = [f"set theHtml to read POSIX file {_as(html_pfad)} as «class utf8»",
         f"set theText to read POSIX file {_as(text_pfad)} as «class utf8»",
         'tell application "Mail"',
         f"\tset m to make new outgoing message with properties {{subject:{_as(c['betreff'])}, content:theText, visible:false}}",
         "\ttell m",
         f"\t\tset sender to {_as(formataddr(ABSENDER))}",
         f"\t\tmake new to recipient at end of to recipients with properties {{name:{_as(c['an'].get('name', ''))}, address:{_as(c['an']['email'])}}}",
         "\tend tell",
         "\tset html content of m to theHtml",
         "\t-- Alle Anhänge im selben Lauf, danach genau ein save (siehe Kopf von mailgen/anschreiben.py)"]
    for a in anhaenge:
        z.append(f"\ttell m to make new attachment with properties {{file name:(POSIX file {_as(a)}) as alias}} at after the last paragraph")
    z += ["\tset visible of m to true", "\tdelay 3", "\tsave m",
          '\treturn "Entwurf gespeichert, Anhänge: " & (count of attachments of m)', "end tell", ""]
    return "\n".join(z)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Kurzes HTML-Anschreiben zum Kundenpaket")
    ap.add_argument("--fall", required=True, help="Fall-Datei (z. B. fall.entwurf.json aus reportgen/kundenpaket.py)")
    ap.add_argument("--ziel", required=True)
    ap.add_argument("--anhang", action="append", default=[], help="PDF des Kundenpakets (mehrfach)")
    ap.add_argument("--bild", action="append", default=[], help="vorhandenes Bildschirmfoto (PNG, mehrfach)")
    ap.add_argument("--bildschirmfoto", action="append", default=[], help="URL, wird mit Chrome headless aufgenommen")
    ap.add_argument("--apple-mail", action="store_true", help="Entwurf in Apple Mail anlegen (sendet nicht)")
    a = ap.parse_args(argv)
    F = json.loads(pathlib.Path(a.fall).read_text(encoding="utf-8"))
    ziel = pathlib.Path(a.ziel)
    ziel.mkdir(parents=True, exist_ok=True)
    bilder = [pathlib.Path(b) for b in a.bild]
    for url in a.bildschirmfoto:
        name = re.sub(r"^https?://", "", url).strip("/").replace("/", "_")
        datum = (F.get("datum") or "").split(".")
        stempel = "-".join(reversed(datum)) if len(datum) == 3 else ""
        try:
            bilder.append(bildschirmfoto(url, ziel / f"Screenshot_{name}_{stempel}.png"))
        except (RuntimeError, OSError, subprocess.SubprocessError) as e:
            print(f"anschreiben: Bildschirmfoto {url} nicht aufgenommen: {e}", file=sys.stderr)
            return 1
    anhaenge = [pathlib.Path(x) for x in a.anhang] + bilder
    for x in anhaenge:
        if not x.is_file():
            print(f"anschreiben: Anhang fehlt: {x}", file=sys.stderr)
            return 1
    c = inhalt(F, len(bilder))
    h, txt = html_mail(c), text_mail(c)
    (ziel / "anschreiben.html").write_text(h, encoding="utf-8")
    (ziel / "anschreiben.txt").write_text(txt, encoding="utf-8")
    (ziel / "anschreiben.eml").write_bytes(bytes(eml(c, h, txt, anhaenge)))
    skript = ziel / "anschreiben_entwurf.applescript"
    skript.write_text(applescript(c, (ziel / "anschreiben.html").resolve(), (ziel / "anschreiben.txt").resolve(),
                                  [x.resolve() for x in anhaenge]), encoding="utf-8")
    n, fehler = pruefen(c, h, txt)
    rc = 0
    print(f"  {'ok' if not fehler else 'FEHLER':6} anschreiben  {n} Wörter, {len(c['punkte'])} Punkt(e), {len(anhaenge)} Anhang/Anhänge")
    for f in fehler:
        print(f"         {f}")
        rc = 2
    if WAECHTER.is_file():
        r = subprocess.run(["bash", str(WAECHTER), str(ziel / "anschreiben.eml")], capture_output=True, text=True)
        print((r.stdout + r.stderr).rstrip())
        if r.returncode != 0:
            rc = 3
    if a.apple_mail:
        if rc != 0:
            print("anschreiben: kein Entwurf in Apple Mail, solange die Prüfung nicht grün ist", file=sys.stderr)
            return rc
        r = subprocess.run(["osascript", str(skript)], capture_output=True, text=True)
        print(f"  Apple Mail: {(r.stdout or r.stderr).strip()}")
        if r.returncode != 0:
            return 1
    return rc


if __name__ == "__main__":
    sys.exit(main())
